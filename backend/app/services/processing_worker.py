"""Independent durable background worker consuming PostgreSQL/SQLite processing runs."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import timedelta
import logging
import random
import signal
import threading
import time
from typing import Any

from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.core.constants import ProcessingStatus, ProcessingStepType, StorageDriver
from app.core.logging import LOGGER_NAME, build_safe_log_extra
from app.db.base import utc_now
from app.repositories.institutional import (
    ClaimedProcessingRunRecord,
    LeaseOwnershipError,
    ProcessingQueueRepository,
    sanitize_technical_error_detail,
)
from app.services.pdf_extraction import (
    DocumentTextExtractionResult,
    PdfExtractionError,
    PdfExtractionLimits,
    extract_pdf_document,
    extract_png_abstention_result,
)
from app.services.storage import (
    DocumentStoragePort,
    StorageIntegrityError,
    StorageObjectNotFoundError,
    StoragePayloadTooLargeError,
    StorageUnavailableError,
    StorageUnsupportedFormatError,
    StorageValidationError,
)

logger = logging.getLogger(LOGGER_NAME)


class TransientProcessingError(RuntimeError):
    """Error indicating a temporary failure safe for exponential-backoff retry."""

    def __init__(self, error_code: str, error_detail: str) -> None:
        self.error_code = error_code
        self.error_detail = error_detail
        super().__init__(error_detail)


class PermanentProcessingError(RuntimeError):
    """Error indicating an unrecoverable technical mismatch or corrupted object."""

    def __init__(
        self,
        error_code: str,
        error_detail: str,
        *,
        extra_result: dict[str, Any] | None = None,
    ) -> None:
        self.error_code = error_code
        self.error_detail = error_detail
        self.extra_result = dict(extra_result) if extra_result else None
        super().__init__(error_detail)


@dataclass(frozen=True, slots=True)
class ExtractionStepExecution:
    """Prepared atomic persistence bundle emitted by execute_extract_pdf_text_step."""

    readable: bool
    result_json: dict[str, Any]
    extracted_fields: list[dict[str, Any]]
    audit_event_type: str
    derived_artifact_key: str | None = None


@dataclass(frozen=True, slots=True)
class WorkerCycleStats:
    """Telemetry returned by a single bounded worker poll cycle."""

    reclaimed_leases: int = 0
    claimed: int = 0
    succeeded: int = 0
    retried: int = 0
    failed: int = 0
    lease_lost: int = 0


StepExecutorFn = Callable[[ClaimedProcessingRunRecord, DocumentStoragePort, Settings], dict[str, Any]]


def execute_verify_object_integrity_step(
    claimed: ClaimedProcessingRunRecord,
    storage: DocumentStoragePort,
    _settings: Settings,
) -> dict[str, Any]:
    """Deterministic technical step verifying existence, SHA-256, byte size, and file structure."""
    if claimed.storage_driver != StorageDriver.LOCAL_CONTROLLED_SYNTHETIC.value:
        raise PermanentProcessingError(
            "UNSUPPORTED_STORAGE_DRIVER",
            f"Unsupported storage driver '{claimed.storage_driver}'.",
        )
    if len(claimed.sha256_hex) != 64 or claimed.byte_size <= 0:
        raise PermanentProcessingError(
            "INVALID_DOCUMENT_METADATA",
            "Registered document version checksum or byte_size metadata is invalid.",
        )

    report = storage.verify_object_integrity(
        organization_id=claimed.organization_id,
        storage_key=claimed.storage_key,
        expected_sha256_hex=claimed.sha256_hex,
        expected_byte_size=claimed.byte_size,
        mime_type=claimed.mime_type,
    )
    return {
        "step_type": claimed.step_type,
        "verified_at": utc_now().isoformat(),
        "object_exists": True,
        "sha256_verified": report.sha256_verified,
        "byte_size_verified": report.byte_size_verified,
        "expected_byte_size": report.expected_byte_size,
        "observed_byte_size": report.observed_byte_size,
        "mime_type": report.mime_type,
        "structural_validation_passed": report.structural_validation_passed,
        "page_count": claimed.page_count,
        "administrative_only": True,
        "clinical_approval": False,
    }


def _build_extraction_persistence_bundle(
    *,
    claimed: ClaimedProcessingRunRecord,
    extraction: DocumentTextExtractionResult,
    derived_artifact_sha256: str | None,
    derived_artifact_key: str | None,
) -> ExtractionStepExecution:
    fields_payload: list[dict[str, Any]] = []
    evidences_count = 0
    extracted_count = 0
    ambiguous_count = 0
    abstained_count = 0

    for item in extraction.fields:
        ev_list: list[dict[str, Any]] = []
        for ev in item.evidences:
            ev_list.append(
                {
                    "page_number": ev.page_number,
                    "bbox_x": ev.bbox.x,
                    "bbox_y": ev.bbox.y,
                    "bbox_w": ev.bbox.w,
                    "bbox_h": ev.bbox.h,
                    "quote_excerpt": ev.quote_excerpt,
                    "extraction_method": ev.extraction_method,
                }
            )
            evidences_count += 1

        if item.status.value == "extracted":
            extracted_count += 1
        elif item.status.value == "ambiguous":
            ambiguous_count += 1
        else:
            abstained_count += 1

        meta = dict(item.metadata_json)
        meta["extractor_version"] = claimed.extractor_version
        meta["source_sha256_hex"] = claimed.sha256_hex
        if derived_artifact_sha256 is not None:
            meta["derived_artifact_sha256"] = derived_artifact_sha256

        fields_payload.append(
            {
                "field_key": item.field_key,
                "raw_value": item.raw_value,
                "normalized_value": item.normalized_value,
                "status": item.status.value,
                "abstained": item.abstained,
                "metadata_json": meta,
                "evidences": ev_list,
            }
        )

    pages_summary = [
        {
            "page_number": pg.page_number,
            "status": pg.status,
            "reason_code": pg.reason_code,
            "rotation": pg.rotation,
            "viewport_width": round(pg.viewport_width, 3),
            "viewport_height": round(pg.viewport_height, 3),
            "char_count": pg.char_count,
            "word_count": pg.word_count,
            "line_count": pg.line_count,
            "block_count": pg.block_count,
            "invalid_bbox_count": pg.invalid_bbox_count,
            "has_image_objects": pg.has_image_objects,
        }
        for pg in extraction.pages
    ]

    result_json: dict[str, Any] = {
        "step_type": claimed.step_type,
        "document_version_id": claimed.document_version_id,
        "source_sha256_hex": claimed.sha256_hex,
        "extractor_version": claimed.extractor_version,
        "engine_name": extraction.engine_name,
        "engine_version": extraction.engine_version,
        "mime_type": extraction.mime_type,
        "outcome": extraction.outcome,
        "reason_code": extraction.reason_code,
        "readable": extraction.readable,
        "partial": extraction.partial,
        "abstained": extraction.abstained,
        "ocr_available": extraction.ocr_available,
        "corrupted": False,
        "page_count": extraction.page_count,
        "readable_page_count": extraction.readable_page_count,
        "abstained_pages": extraction.abstained_pages,
        "total_chars": extraction.total_chars,
        "total_words": extraction.total_words,
        "total_lines": extraction.total_lines,
        "fields_count": len(fields_payload),
        "extracted_fields_count": extracted_count,
        "ambiguous_fields_count": ambiguous_count,
        "abstained_fields_count": abstained_count,
        "evidences_count": evidences_count,
        "present_field_keys": extraction.present_field_keys,
        "absent_field_keys": extraction.absent_field_keys,
        "unrecognized_label_count": len(extraction.unrecognized_prefixed_labels),
        "pages_summary": pages_summary,
        "derived_artifact_sha256": derived_artifact_sha256,
        "human_review_required": True,
        "administrative_only": True,
        "clinical_approval": False,
    }
    audit_event_type = (
        "processing_run.abstained"
        if extraction.outcome in ("abstained", "partial")
        else "processing_run.succeeded"
    )
    return ExtractionStepExecution(
        readable=extraction.readable,
        result_json=result_json,
        extracted_fields=fields_payload,
        audit_event_type=audit_event_type,
        derived_artifact_key=derived_artifact_key,
    )


def execute_extract_pdf_text_step(
    claimed: ClaimedProcessingRunRecord,
    storage: DocumentStoragePort,
    settings: Settings,
) -> ExtractionStepExecution:
    """Deterministic text/evidence extraction step reading exclusively verified version bytes."""
    if claimed.storage_driver != StorageDriver.LOCAL_CONTROLLED_SYNTHETIC.value:
        raise PermanentProcessingError(
            "UNSUPPORTED_STORAGE_DRIVER",
            f"Unsupported storage driver '{claimed.storage_driver}'.",
        )
    if len(claimed.sha256_hex) != 64 or claimed.byte_size <= 0:
        raise PermanentProcessingError(
            "INVALID_DOCUMENT_METADATA",
            "Registered document version checksum or byte_size metadata is invalid.",
        )

    raw_bytes = storage.read_synthetic_bytes(
        organization_id=claimed.organization_id,
        storage_key=claimed.storage_key,
        expected_sha256_hex=claimed.sha256_hex,
    )
    if len(raw_bytes) != claimed.byte_size:
        raise PermanentProcessingError(
            "INTEGRITY_MISMATCH",
            "Stored object byte length differs from registered document version.",
        )

    if claimed.mime_type == "image/png":
        extraction = extract_png_abstention_result(
            extractor_version=claimed.extractor_version,
            source_sha256_hex=claimed.sha256_hex,
        )
        return _build_extraction_persistence_bundle(
            claimed=claimed,
            extraction=extraction,
            derived_artifact_sha256=None,
            derived_artifact_key=None,
        )

    if claimed.mime_type != "application/pdf":
        raise PermanentProcessingError(
            "UNSUPPORTED_MIME_TYPE",
            f"Unsupported mime_type '{claimed.mime_type}' for PDF text extraction.",
        )

    limits = PdfExtractionLimits(
        max_pages=settings.pdf_max_pages,
        max_extracted_chars=settings.pdf_max_extracted_chars,
        max_words=settings.pdf_max_words_per_doc,
        max_blocks_per_page=settings.pdf_max_blocks_per_page,
        timeout_seconds=settings.pdf_extraction_timeout_seconds,
        max_complexity_objects=settings.pdf_max_complexity_objects,
    )
    try:
        extraction = extract_pdf_document(
            raw_bytes,
            limits=limits,
            extractor_version=claimed.extractor_version,
            source_sha256_hex=claimed.sha256_hex,
        )
    except PdfExtractionError as exc:
        raise PermanentProcessingError(
            exc.error_code,
            exc.error_detail,
            extra_result={
                "outcome": "abstained",
                "reason_code": exc.error_code,
                "abstained": True,
                "readable": False,
                "ocr_available": False,
                "extractor_version": claimed.extractor_version,
                "document_version_id": claimed.document_version_id,
                "source_sha256_hex": claimed.sha256_hex,
            },
        ) from exc

    artifact = storage.store_derived_text_artifact(
        organization_id=claimed.organization_id,
        processing_run_id=claimed.run_id,
        payload_bytes=extraction.to_derived_artifact_json_bytes(),
    )
    return _build_extraction_persistence_bundle(
        claimed=claimed,
        extraction=extraction,
        derived_artifact_sha256=artifact.sha256_hex,
        derived_artifact_key=artifact.artifact_key,
    )


_DEFAULT_STEP_HANDLERS: dict[str, Callable[[ClaimedProcessingRunRecord, DocumentStoragePort, Settings], Any]] = {
    ProcessingStepType.VERIFY_OBJECT_INTEGRITY.value: execute_verify_object_integrity_step,
    ProcessingStepType.EXTRACT_PDF_TEXT.value: execute_extract_pdf_text_step,
}


def classify_step_exception(exc: Exception) -> tuple[bool, str, str]:
    """Classify an execution exception into (is_transient, error_code, sanitized_detail)."""
    if isinstance(exc, TransientProcessingError):
        return True, exc.error_code, sanitize_technical_error_detail(exc.error_detail)
    if isinstance(exc, PermanentProcessingError):
        return False, exc.error_code, sanitize_technical_error_detail(exc.error_detail)
    if isinstance(exc, StorageUnavailableError):
        return True, "STORAGE_UNAVAILABLE", sanitize_technical_error_detail(str(exc))
    if isinstance(exc, StorageObjectNotFoundError):
        return False, "OBJECT_NOT_FOUND", sanitize_technical_error_detail(str(exc))
    if isinstance(exc, StorageIntegrityError):
        return False, "INTEGRITY_MISMATCH", sanitize_technical_error_detail(str(exc))
    if isinstance(exc, StorageUnsupportedFormatError):
        return False, "STRUCTURAL_VALIDATION_FAILED", sanitize_technical_error_detail(str(exc))
    if isinstance(exc, StoragePayloadTooLargeError):
        return False, "OBJECT_EXCEEDS_MAX_BYTES", sanitize_technical_error_detail(str(exc))
    if isinstance(exc, StorageValidationError):
        return False, "INVALID_STORAGE_REFERENCE", sanitize_technical_error_detail(str(exc))
    if isinstance(exc, FileNotFoundError):
        return False, "OBJECT_NOT_FOUND", "Stored binary object is missing."
    if isinstance(exc, (TimeoutError, ConnectionError, OperationalError, OSError)):
        return True, "TRANSIENT_IO_OR_DB_ERROR", sanitize_technical_error_detail(
            f"{type(exc).__name__}: {exc}"
        )
    if isinstance(exc, (ValueError, LookupError)):
        return False, "INVALID_DOCUMENT_METADATA", sanitize_technical_error_detail(str(exc))
    return True, "UNEXPECTED_STEP_ERROR", f"Unexpected technical error ({type(exc).__name__})."


class ProcessingWorker:
    """Durable standalone worker consuming leased ProcessingRun jobs with retry and fencing."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        storage: DocumentStoragePort,
        settings: Settings,
        *,
        worker_id: str | None = None,
        rng: random.Random | None = None,
        step_executor: StepExecutorFn | None = None,
        step_types: Sequence[str] | str | None = None,
    ) -> None:
        self.session_factory = session_factory
        self.storage = storage
        self.settings = settings
        self.worker_id = (worker_id or settings.worker_id).strip()
        self._rng = rng or random.Random()
        self._custom_step_executor = step_executor
        if step_types is None:
            self._claim_step_type = "any"
        elif isinstance(step_types, str):
            self._claim_step_type = step_types.strip() or "any"
        else:
            vals = [str(s).strip() for s in step_types if str(s).strip()]
            self._claim_step_type = vals[0] if len(vals) == 1 else "any"
        self._stop_event = threading.Event()

    def request_stop(self) -> None:
        """Signal the worker loop to exit cleanly after the current unit of work."""
        self._stop_event.set()

    @property
    def stop_requested(self) -> bool:
        return self._stop_event.is_set()

    def compute_retry_delay_seconds(self, *, attempt_count: int) -> float:
        base = float(self.settings.worker_retry_backoff_min_seconds)
        maximum = float(self.settings.worker_retry_backoff_max_seconds)
        raw_delay = min(maximum, base * (2 ** max(0, attempt_count - 1)))
        jitter_ratio = float(self.settings.worker_retry_jitter_ratio)
        if jitter_ratio > 0.0 and raw_delay > 0.0:
            jitter = raw_delay * jitter_ratio * self._rng.uniform(-1.0, 1.0)
            raw_delay = max(0.05, min(maximum, raw_delay + jitter))
        return raw_delay

    def _execute_step(self, claimed: ClaimedProcessingRunRecord) -> Any:
        if self._custom_step_executor is not None:
            return self._custom_step_executor(claimed, self.storage, self.settings)
        handler = _DEFAULT_STEP_HANDLERS.get(claimed.step_type)
        if handler is None:
            raise PermanentProcessingError(
                "UNSUPPORTED_STEP_TYPE",
                f"Unsupported processing step '{claimed.step_type}'.",
            )
        return handler(claimed, self.storage, self.settings)

    def _claim_one(self) -> ClaimedProcessingRunRecord | None:
        _raw_token, lease_token_hash = ProcessingQueueRepository.generate_lease_proof()
        session = self.session_factory()
        try:
            return ProcessingQueueRepository.claim_next_run(
                session,
                worker_id=self.worker_id,
                lease_token_hash=lease_token_hash,
                lease_seconds=self.settings.worker_lease_seconds,
                step_type=self._claim_step_type,
            )
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def process_one_cycle(self, *, max_jobs: int | None = None) -> WorkerCycleStats:
        reclaimed = ProcessingQueueRepository.reclaim_expired_leases(
            self.session_factory,
            reclaimer_worker_id=self.worker_id,
            limit=max(1, max_jobs or self.settings.worker_max_jobs_per_cycle),
        )
        claimed_count = 0
        succeeded_count = 0
        retried_count = 0
        failed_count = 0
        lease_lost_count = 0

        limit = max(1, max_jobs or self.settings.worker_max_jobs_per_cycle)
        for _ in range(limit):
            if self._stop_event.is_set():
                break

            claimed = self._claim_one()
            if claimed is None:
                break
            claimed_count += 1

            try:
                step_output = self._execute_step(claimed)
            except Exception as exc:
                is_transient, error_code, error_detail = classify_step_exception(exc)
                can_retry = is_transient and claimed.attempt_count < claimed.max_attempts
                if can_retry:
                    delay = self.compute_retry_delay_seconds(attempt_count=claimed.attempt_count)
                    target_status = ProcessingStatus.RETRY_WAIT.value
                    next_available = utc_now() + timedelta(seconds=delay)
                else:
                    target_status = ProcessingStatus.FAILED.value
                    next_available = utc_now()

                failure_result: dict[str, Any] = {
                    "step_type": claimed.step_type,
                    "verified": False,
                    "error_code": error_code,
                    "administrative_only": True,
                    "clinical_approval": False,
                }
                if isinstance(exc, PermanentProcessingError) and exc.extra_result:
                    failure_result.update(exc.extra_result)

                session = self.session_factory()
                try:
                    ProcessingQueueRepository.fail_or_retry_run(
                        session,
                        run_id=claimed.run_id,
                        worker_id=self.worker_id,
                        lease_token_hash=claimed.lease_token_hash,
                        target_status=target_status,
                        available_at=next_available,
                        error_code=error_code,
                        error_detail=error_detail,
                        result_json=failure_result,
                    )
                    if target_status == ProcessingStatus.RETRY_WAIT.value:
                        retried_count += 1
                    else:
                        failed_count += 1
                    logger.warning(
                        "Processing run execution failed or scheduled retry.",
                        extra=build_safe_log_extra(
                            organization_id=claimed.organization_id,
                            processing_run_id=claimed.run_id,
                            document_version_id=claimed.document_version_id,
                            step_type=claimed.step_type,
                            attempt_count=claimed.attempt_count,
                            target_status=target_status,
                            error_code=error_code,
                        ),
                    )
                except LeaseOwnershipError:
                    lease_lost_count += 1
                    logger.warning(
                        "Worker lost lease before recording failure transition.",
                        extra=build_safe_log_extra(
                            organization_id=claimed.organization_id,
                            processing_run_id=claimed.run_id,
                            worker_id=self.worker_id,
                        ),
                    )
                finally:
                    session.close()
                continue

            session = self.session_factory()
            derived_key_to_cleanup: str | None = (
                step_output.derived_artifact_key
                if isinstance(step_output, ExtractionStepExecution)
                else None
            )
            try:
                if isinstance(step_output, ExtractionStepExecution):
                    ProcessingQueueRepository.complete_extraction_run(
                        session,
                        run_id=claimed.run_id,
                        worker_id=self.worker_id,
                        lease_token_hash=claimed.lease_token_hash,
                        readable=step_output.readable,
                        result_json=step_output.result_json,
                        extracted_fields=step_output.extracted_fields,
                        audit_event_type=step_output.audit_event_type,
                    )
                    derived_key_to_cleanup = None
                    succeeded_count += 1
                    logger.info(
                        "Processing run deterministic PDF text extraction completed.",
                        extra=build_safe_log_extra(
                            organization_id=claimed.organization_id,
                            processing_run_id=claimed.run_id,
                            document_version_id=claimed.document_version_id,
                            step_type=claimed.step_type,
                            attempt_count=claimed.attempt_count,
                            outcome=step_output.result_json.get("outcome"),
                            fields_count=step_output.result_json.get("fields_count"),
                            evidences_count=step_output.result_json.get("evidences_count"),
                        ),
                    )
                else:
                    ProcessingQueueRepository.complete_run(
                        session,
                        run_id=claimed.run_id,
                        worker_id=self.worker_id,
                        lease_token_hash=claimed.lease_token_hash,
                        result_json=step_output,
                        chain_extract_extractor_version=(
                            self.settings.worker_extract_pdf_text_extractor_version
                        ),
                    )
                    succeeded_count += 1
                    logger.info(
                        "Processing run technical integrity verification succeeded.",
                        extra=build_safe_log_extra(
                            organization_id=claimed.organization_id,
                            processing_run_id=claimed.run_id,
                            document_version_id=claimed.document_version_id,
                            step_type=claimed.step_type,
                            attempt_count=claimed.attempt_count,
                        ),
                    )
            except LeaseOwnershipError:
                lease_lost_count += 1
                if derived_key_to_cleanup is not None:
                    self.storage.delete_derived_artifact(
                        organization_id=claimed.organization_id,
                        artifact_key=derived_key_to_cleanup,
                    )
                logger.warning(
                    "Worker lost lease before committing completion.",
                    extra=build_safe_log_extra(
                        organization_id=claimed.organization_id,
                        processing_run_id=claimed.run_id,
                        worker_id=self.worker_id,
                    ),
                )
            except Exception:
                if derived_key_to_cleanup is not None:
                    self.storage.delete_derived_artifact(
                        organization_id=claimed.organization_id,
                        artifact_key=derived_key_to_cleanup,
                    )
                raise
            finally:
                session.close()

        return WorkerCycleStats(
            reclaimed_leases=reclaimed,
            claimed=claimed_count,
            succeeded=succeeded_count,
            retried=retried_count,
            failed=failed_count,
            lease_lost=lease_lost_count,
        )

    def install_signal_handlers(self) -> None:
        if threading.current_thread() is not threading.main_thread():
            return

        def _handle_stop(_signum: int, _frame: Any) -> None:
            self.request_stop()

        signal.signal(signal.SIGINT, _handle_stop)
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, _handle_stop)

    def run_loop(
        self,
        *,
        max_cycles: int | None = None,
        handle_signals: bool = True,
    ) -> WorkerCycleStats:
        if handle_signals:
            self.install_signal_handlers()

        totals = {
            "reclaimed_leases": 0,
            "claimed": 0,
            "succeeded": 0,
            "retried": 0,
            "failed": 0,
            "lease_lost": 0,
        }
        cycles = 0
        while not self._stop_event.is_set():
            if max_cycles is not None and cycles >= max_cycles:
                break
            cycles += 1
            try:
                stats = self.process_one_cycle()
            except OperationalError as exc:
                logger.warning(
                    "Transient database operational error in worker poll cycle (%s).",
                    type(exc).__name__,
                    extra=build_safe_log_extra(worker_id=self.worker_id),
                )
                stats = WorkerCycleStats()
            totals["reclaimed_leases"] += stats.reclaimed_leases
            totals["claimed"] += stats.claimed
            totals["succeeded"] += stats.succeeded
            totals["retried"] += stats.retried
            totals["failed"] += stats.failed
            totals["lease_lost"] += stats.lease_lost

            if max_cycles is not None and cycles >= max_cycles:
                break
            if stats.claimed == 0 and stats.reclaimed_leases == 0:
                self._stop_event.wait(timeout=self.settings.worker_poll_interval_seconds)
            else:
                # Yield momentarily to avoid tight spin while continuing through queued backlog
                time.sleep(0.01)

        return WorkerCycleStats(**totals)
