"""Internal domain services enforcing tenant boundaries and append-only audit logs."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import json
import logging

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.core.constants import (
    DEFAULT_INTEGRITY_EXTRACTOR_VERSION,
    DEFAULT_PROCESSING_MAX_ATTEMPTS,
    DEFAULT_PROCESSING_POLICY_VERSION,
    DocumentKind,
    OrganizationRole,
    ProcessingStepType,
)
from app.core.logging import LOGGER_NAME, build_safe_log_extra
from app.core.processing_contracts import compute_processing_idempotency_key
from app.core.rbac import AuthorizationDeniedError, RbacPermission, permissions_for_role
from app.db.base import new_uuid
from app.models.entities import (
    AuditEvent,
    Document,
    DocumentCase,
    DocumentVersion,
    EvidenceReference,
    ExtractedField,
    HumanReview,
    Organization,
    OrganizationMembership,
    ProcessingRun,
    User,
)
from app.repositories.institutional import (
    AuditChainVerificationResult,
    AuditEventRepository,
    CaseAndDocumentRepository,
    OrganizationRepository,
    ProcessingQueueRepository,
    TenantScopeError,
)
from app.schemas.tenant import (
    DocumentCaseCreateInput,
    DocumentCreateInput,
    DocumentVersionCreateInput,
    EvidenceReferenceCreateInput,
    ExtractedFieldCreateInput,
    HumanReviewCreateInput,
    MembershipAssignInput,
    OrganizationCreateInput,
    ProcessingRunCreateInput,
    TenantContext,
    UserCreateInput,
)
from app.services.storage import DocumentStoragePort, StoredObjectMetadata

logger = logging.getLogger(LOGGER_NAME)


class IdempotencyConflictError(ValueError):
    """Raised when an Idempotency-Key is reused with different file content or metadata."""


class DocumentNotFoundError(LookupError):
    """Raised when a target case, document, or version does not exist in the active organization."""


class ProcessingRunActiveConflictError(ValueError):
    """Raised when an active processing run already exists for the target document version."""


@dataclass(frozen=True, slots=True)
class DocumentIngestionResult:
    document: Document
    version: DocumentVersion
    idempotent_replay: bool = False
    initial_processing_run: ProcessingRun | None = None


@dataclass(frozen=True, slots=True)
class ProcessingRunDetailResult:
    processing_run: ProcessingRun
    document_id: str
    case_id: str | None
    idempotent_replay: bool = False


@dataclass(frozen=True, slots=True)
class CaseProcessingRunsPageResult:
    case: DocumentCase
    total: int
    limit: int
    offset: int
    items: list[tuple[ProcessingRun, str, str | None]]


@dataclass(frozen=True, slots=True)
class DocumentWithVersionsResult:
    document: Document
    current_version: DocumentVersion | None
    versions: list[DocumentVersion]


@dataclass(frozen=True, slots=True)
class CaseDocumentsPageResult:
    case: DocumentCase
    total: int
    limit: int
    offset: int
    items: list[tuple[Document, DocumentVersion | None]]


@dataclass(frozen=True, slots=True)
class DocumentVersionContentResult:
    document: Document
    version: DocumentVersion
    content: bytes
    download_filename: str


@dataclass(frozen=True, slots=True)
class DocumentVersionExtractedFieldsResult:
    document: Document
    version: DocumentVersion
    latest_extract_run: ProcessingRun | None
    items: list[tuple[ExtractedField, ProcessingRun, list[EvidenceReference]]]


@dataclass(frozen=True, slots=True)
class DocumentVersionEvidenceResult:
    document: Document
    version: DocumentVersion
    latest_extract_run: ProcessingRun | None
    items: list[tuple[EvidenceReference, ExtractedField, ProcessingRun]]


def _verify_actor_membership(session: Session, ctx: TenantContext) -> None:
    if ctx.actor_user_id is None:
        return
    membership = OrganizationRepository.get_active_membership(
        session, ctx, user_id=ctx.actor_user_id
    )
    if membership is None:
        raise TenantScopeError(
            f"Actor '{ctx.actor_user_id}' has no active membership in organization '{ctx.organization_id}'."
        )


def _require_actor_permission(
    session: Session, ctx: TenantContext, required_permission: RbacPermission
) -> OrganizationRole:
    if not ctx.actor_user_id:
        raise AuthorizationDeniedError("Authenticated actor user context is required.")
    membership = OrganizationRepository.get_active_membership(
        session, ctx, user_id=ctx.actor_user_id
    )
    if membership is None:
        raise AuthorizationDeniedError(
            "Actor lacks an active membership in target organization."
        )
    role = OrganizationRole(membership.role)
    if required_permission not in permissions_for_role(role):
        raise AuthorizationDeniedError(
            f"Role '{role.value}' lacks required permission '{required_permission.value}'."
        )
    return role


def compute_upload_idempotency_fingerprint(
    *,
    organization_id: str,
    case_id: str,
    sha256_hex: str,
    mime_type: str,
    byte_size: int,
    document_kind: str,
    document_subfamily: str | None,
    source_label: str,
    external_reference: str | None,
    description: str | None,
) -> str:
    canonical = json.dumps(
        {
            "organization_id": organization_id,
            "case_id": case_id,
            "sha256_hex": sha256_hex,
            "mime_type": mime_type,
            "byte_size": byte_size,
            "document_kind": document_kind,
            "document_subfamily": document_subfamily,
            "source_label": source_label,
            "external_reference": external_reference,
            "description": description,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class InstitutionalService:
    """Internal institutional workflows guarded by explicit TenantContext boundaries."""

    @staticmethod
    def create_organization(session: Session, payload: OrganizationCreateInput) -> Organization:
        org = OrganizationRepository.create_organization(
            session, slug=payload.slug, name=payload.name
        )
        logger.info(
            "Organization created.",
            extra=build_safe_log_extra(organization_id=org.id, slug=org.slug),
        )
        return org

    @staticmethod
    def create_user(session: Session, payload: UserCreateInput) -> User:
        user = OrganizationRepository.create_user(
            session,
            email=payload.email,
            display_name=payload.display_name,
            external_subject=payload.external_subject,
            mfa_enrolled=payload.mfa_enrolled,
        )
        logger.info("Institutional user created.", extra=build_safe_log_extra(user_id=user.id))
        return user

    @staticmethod
    def assign_membership(
        session: Session, ctx: TenantContext, payload: MembershipAssignInput
    ) -> OrganizationMembership:
        membership = OrganizationRepository.assign_membership(
            session, ctx, user_id=payload.user_id, role=payload.role.value
        )
        AuditEventRepository.append_event(
            session,
            ctx,
            event_type="membership.assigned",
            target_entity_type="organization_membership",
            target_entity_id=membership.id,
            payload_json={"user_id": payload.user_id, "role": payload.role.value},
        )
        return membership

    @staticmethod
    def create_case(
        session: Session, ctx: TenantContext, payload: DocumentCaseCreateInput
    ) -> DocumentCase:
        _verify_actor_membership(session, ctx)
        case = CaseAndDocumentRepository.create_case(
            session,
            ctx,
            case_code=payload.case_code,
            external_reference=payload.external_reference,
            procedure_reference=payload.procedure_reference,
            declared_laterality=payload.declared_laterality,
            readiness_state=payload.readiness_state.value,
        )
        AuditEventRepository.append_event(
            session,
            ctx,
            event_type="case.created",
            target_entity_type="document_case",
            target_entity_id=case.id,
            payload_json={
                "case_code": case.case_code,
                "readiness_state": case.readiness_state,
            },
        )
        return case

    @staticmethod
    def get_case(session: Session, ctx: TenantContext, case_id: str) -> DocumentCase | None:
        return CaseAndDocumentRepository.get_case(session, ctx, case_id)

    @staticmethod
    def list_cases(session: Session, ctx: TenantContext) -> list[DocumentCase]:
        return CaseAndDocumentRepository.list_cases(session, ctx)

    @staticmethod
    def register_document(
        session: Session, ctx: TenantContext, payload: DocumentCreateInput
    ) -> Document:
        _verify_actor_membership(session, ctx)
        doc = CaseAndDocumentRepository.create_document(
            session,
            ctx,
            case_id=payload.case_id,
            document_kind=payload.document_kind.value,
            document_subfamily=payload.document_subfamily,
            source_label=payload.source_label,
            external_reference=payload.external_reference,
            description=payload.description,
            idempotency_key=payload.idempotency_key,
            idempotency_fingerprint=payload.idempotency_fingerprint,
            quarantined=payload.quarantined,
            quarantine_reason=payload.quarantine_reason,
        )
        AuditEventRepository.append_event(
            session,
            ctx,
            event_type="document.registered",
            target_entity_type="document",
            target_entity_id=doc.id,
            payload_json={
                "case_id": doc.case_id,
                "document_kind": doc.document_kind,
                "quarantined": doc.quarantined,
            },
        )
        return doc

    @staticmethod
    def get_document(session: Session, ctx: TenantContext, document_id: str) -> Document | None:
        return CaseAndDocumentRepository.get_document(session, ctx, document_id)

    @staticmethod
    def ingest_case_document(
        session: Session,
        ctx: TenantContext,
        *,
        storage: DocumentStoragePort,
        case_id: str,
        stored_object: StoredObjectMetadata | None = None,
        content: bytes | None = None,
        mime_type: str | None = None,
        original_filename: str | None = None,
        document_kind: DocumentKind = DocumentKind.DESCONHECIDO,
        document_subfamily: str | None = None,
        source_label: str = "institutional_upload",
        external_reference: str | None = None,
        description: str | None = None,
        idempotency_key: str | None = None,
    ) -> DocumentIngestionResult:
        """Ingest a validated binary document into an organization's case with transactional compensating cleanup."""
        stored = stored_object
        try:
            _require_actor_permission(session, ctx, RbacPermission.DOCUMENT_UPLOAD)
            case = CaseAndDocumentRepository.get_case(session, ctx, case_id)
            if case is None:
                raise DocumentNotFoundError(
                    f"DocumentCase '{case_id}' was not found inside active organization."
                )

            if stored is None:
                if content is None or mime_type is None:
                    raise ValueError("Either stored_object or (content, mime_type) must be provided.")
                stored = storage.store_synthetic_bytes(
                    organization_id=ctx.organization_id,
                    mime_type=mime_type,
                    content=content,
                    original_filename=original_filename,
                )

            fingerprint: str | None = None
            if idempotency_key is not None:
                fingerprint = compute_upload_idempotency_fingerprint(
                    organization_id=ctx.organization_id,
                    case_id=case.id,
                    sha256_hex=stored.sha256_hex,
                    mime_type=stored.mime_type,
                    byte_size=stored.byte_size,
                    document_kind=document_kind.value,
                    document_subfamily=document_subfamily,
                    source_label=source_label,
                    external_reference=external_reference,
                    description=description,
                )

            validated_doc_input = DocumentCreateInput(
                case_id=case.id,
                document_kind=document_kind,
                document_subfamily=document_subfamily,
                source_label=source_label,
                external_reference=external_reference,
                description=description,
                idempotency_key=idempotency_key,
                idempotency_fingerprint=fingerprint,
            )

            if validated_doc_input.idempotency_key is not None:
                existing_doc = CaseAndDocumentRepository.get_document_by_idempotency_key(
                    session,
                    ctx,
                    case_id=case.id,
                    idempotency_key=validated_doc_input.idempotency_key,
                )
                if existing_doc is not None:
                    storage.delete_uncommitted_object(
                        organization_id=ctx.organization_id,
                        storage_key=stored.storage_key,
                    )
                    stored = None
                    if existing_doc.idempotency_fingerprint != fingerprint:
                        raise IdempotencyConflictError(
                            "Idempotency-Key was already used with different document content or metadata."
                        )
                    existing_versions = CaseAndDocumentRepository.list_document_versions(
                        session, ctx, document_id=existing_doc.id
                    )
                    if not existing_versions:
                        raise DocumentNotFoundError("Idempotent document lacks registered version.")
                    existing_run = ProcessingQueueRepository.get_latest_run_for_version(
                        session, ctx, document_version_id=existing_versions[0].id
                    )
                    return DocumentIngestionResult(
                        document=existing_doc,
                        version=existing_versions[0],
                        idempotent_replay=True,
                        initial_processing_run=existing_run,
                    )

            doc = CaseAndDocumentRepository.create_document(
                session,
                ctx,
                case_id=case.id,
                document_kind=validated_doc_input.document_kind.value,
                document_subfamily=validated_doc_input.document_subfamily,
                source_label=validated_doc_input.source_label,
                external_reference=validated_doc_input.external_reference,
                description=validated_doc_input.description,
                idempotency_key=validated_doc_input.idempotency_key,
                idempotency_fingerprint=validated_doc_input.idempotency_fingerprint,
                quarantined=False,
                quarantine_reason=None,
            )
            version_input = DocumentVersionCreateInput(
                document_id=doc.id,
                version_number=1,
                sha256_hex=stored.sha256_hex,
                mime_type=stored.mime_type,  # type: ignore[arg-type]
                byte_size=stored.byte_size,
                page_count=None,
                original_filename=stored.original_filename,
                storage_key=stored.storage_key,
            )
            version = CaseAndDocumentRepository.create_document_version(
                session,
                ctx,
                document_id=doc.id,
                version_number=version_input.version_number,
                sha256_hex=version_input.sha256_hex,
                mime_type=version_input.mime_type,
                byte_size=version_input.byte_size,
                page_count=version_input.page_count,
                original_filename=version_input.original_filename,
                storage_driver=version_input.storage_driver.value,
                storage_key=version_input.storage_key,
            )
            queue_idempotency_key = compute_processing_idempotency_key(
                organization_id=ctx.organization_id,
                document_version_id=version.id,
                sha256_hex=version.sha256_hex,
                extractor_version=DEFAULT_INTEGRITY_EXTRACTOR_VERSION,
                policy_version=DEFAULT_PROCESSING_POLICY_VERSION,
            )
            initial_run = ProcessingQueueRepository.enqueue_run(
                session,
                ctx,
                document_version_id=version.id,
                step_type=ProcessingStepType.VERIFY_OBJECT_INTEGRITY.value,
                policy_version=DEFAULT_PROCESSING_POLICY_VERSION,
                extractor_version=DEFAULT_INTEGRITY_EXTRACTOR_VERSION,
                idempotency_key=queue_idempotency_key,
                max_attempts=DEFAULT_PROCESSING_MAX_ATTEMPTS,
            )
            AuditEventRepository.append_event(
                session,
                ctx,
                event_type="document.ingested",
                target_entity_type="document",
                target_entity_id=doc.id,
                payload_json={
                    "operation": "document_upload_ingested",
                    "case_id": case.id,
                    "document_id": doc.id,
                    "document_version_id": version.id,
                    "version_number": version.version_number,
                    "document_kind": doc.document_kind,
                    "sha256_hex": version.sha256_hex,
                    "byte_size": version.byte_size,
                    "mime_type": version.mime_type,
                    "storage_driver": version.storage_driver,
                },
            )
            AuditEventRepository.append_event(
                session,
                ctx,
                event_type="processing_run.queued",
                target_entity_type="processing_run",
                target_entity_id=initial_run.id,
                payload_json={
                    "operation": "processing_run_queued",
                    "case_id": case.id,
                    "document_id": doc.id,
                    "document_version_id": version.id,
                    "processing_run_id": initial_run.id,
                    "step_type": initial_run.step_type,
                    "status": initial_run.status,
                    "policy_version": initial_run.policy_version,
                    "extractor_version": initial_run.extractor_version,
                    "max_attempts": initial_run.max_attempts,
                    "administrative_only": True,
                    "clinical_approval": False,
                },
            )
            session.commit()
            return DocumentIngestionResult(
                document=doc,
                version=version,
                idempotent_replay=False,
                initial_processing_run=initial_run,
            )
        except IntegrityError:
            session.rollback()
            if stored is not None:
                storage.delete_uncommitted_object(
                    organization_id=ctx.organization_id,
                    storage_key=stored.storage_key,
                )
                stored = None
            if idempotency_key is not None and fingerprint is not None:
                winner = CaseAndDocumentRepository.get_document_by_idempotency_key(
                    session,
                    ctx,
                    case_id=case_id,
                    idempotency_key=idempotency_key.strip(),
                )
                if winner is not None:
                    if winner.idempotency_fingerprint == fingerprint:
                        winner_versions = CaseAndDocumentRepository.list_document_versions(
                            session, ctx, document_id=winner.id
                        )
                        if winner_versions:
                            winner_run = ProcessingQueueRepository.get_latest_run_for_version(
                                session, ctx, document_version_id=winner_versions[0].id
                            )
                            return DocumentIngestionResult(
                                document=winner,
                                version=winner_versions[0],
                                idempotent_replay=True,
                                initial_processing_run=winner_run,
                            )
                    raise IdempotencyConflictError(
                        "Idempotency-Key was concurrently used with different document content or metadata."
                    )
            raise
        except Exception:
            session.rollback()
            if stored is not None:
                storage.delete_uncommitted_object(
                    organization_id=ctx.organization_id,
                    storage_key=stored.storage_key,
                )
            raise

    @staticmethod
    def list_case_documents_with_versions(
        session: Session,
        ctx: TenantContext,
        *,
        case_id: str,
        limit: int = 50,
        offset: int = 0,
    ) -> CaseDocumentsPageResult:
        _require_actor_permission(session, ctx, RbacPermission.DOCUMENT_READ)
        case = CaseAndDocumentRepository.get_case(session, ctx, case_id)
        if case is None:
            raise DocumentNotFoundError(
                f"DocumentCase '{case_id}' was not found inside active organization."
            )
        docs, total = CaseAndDocumentRepository.list_case_documents(
            session, ctx, case_id=case.id, limit=limit, offset=offset
        )
        items: list[tuple[Document, DocumentVersion | None]] = []
        for doc in docs:
            versions = CaseAndDocumentRepository.list_document_versions(
                session, ctx, document_id=doc.id
            )
            current_ver = next((v for v in reversed(versions) if v.is_current), None)
            if current_ver is None and versions:
                current_ver = versions[-1]
            items.append((doc, current_ver))
        return CaseDocumentsPageResult(
            case=case,
            total=total,
            limit=limit,
            offset=offset,
            items=items,
        )

    @staticmethod
    def get_document_with_versions(
        session: Session,
        ctx: TenantContext,
        *,
        document_id: str,
    ) -> DocumentWithVersionsResult:
        _require_actor_permission(session, ctx, RbacPermission.DOCUMENT_READ)
        doc = CaseAndDocumentRepository.get_document(session, ctx, document_id)
        if doc is None:
            raise DocumentNotFoundError(
                f"Document '{document_id}' was not found inside active organization."
            )
        versions = CaseAndDocumentRepository.list_document_versions(
            session, ctx, document_id=doc.id
        )
        current_ver = next((v for v in reversed(versions) if v.is_current), None)
        if current_ver is None and versions:
            current_ver = versions[-1]
        return DocumentWithVersionsResult(
            document=doc,
            current_version=current_ver,
            versions=versions,
        )

    @staticmethod
    def retrieve_document_version_content(
        session: Session,
        ctx: TenantContext,
        *,
        storage: DocumentStoragePort,
        document_id: str,
        version_id: str,
    ) -> DocumentVersionContentResult:
        _require_actor_permission(session, ctx, RbacPermission.DOCUMENT_READ)
        doc = CaseAndDocumentRepository.get_document(session, ctx, document_id)
        if doc is None:
            raise DocumentNotFoundError(
                f"Document '{document_id}' was not found inside active organization."
            )
        version = CaseAndDocumentRepository.get_document_version_for_document(
            session,
            ctx,
            document_id=doc.id,
            version_id=version_id,
        )
        if version is None:
            raise DocumentNotFoundError(
                f"DocumentVersion '{version_id}' was not found for document '{document_id}'."
            )
        content = storage.read_synthetic_bytes(
            organization_id=ctx.organization_id,
            storage_key=version.storage_key,
            expected_sha256_hex=version.sha256_hex,
        )
        ext = "pdf" if version.mime_type == "application/pdf" else "png"
        download_filename = (
            version.original_filename
            if version.original_filename
            else f"document-{doc.id[:8]}-v{version.version_number}.{ext}"
        )
        return DocumentVersionContentResult(
            document=doc,
            version=version,
            content=content,
            download_filename=download_filename,
        )

    @staticmethod
    def register_document_version(
        session: Session,
        ctx: TenantContext,
        payload: DocumentVersionCreateInput,
        *,
        enqueue_processing: bool = False,
        processing_max_attempts: int = DEFAULT_PROCESSING_MAX_ATTEMPTS,
    ) -> DocumentVersion:
        _verify_actor_membership(session, ctx)
        version = CaseAndDocumentRepository.create_document_version(
            session,
            ctx,
            document_id=payload.document_id,
            version_number=payload.version_number,
            sha256_hex=payload.sha256_hex,
            mime_type=payload.mime_type,
            byte_size=payload.byte_size,
            page_count=payload.page_count,
            original_filename=payload.original_filename,
            storage_driver=payload.storage_driver.value,
            storage_key=payload.storage_key,
        )
        AuditEventRepository.append_event(
            session,
            ctx,
            event_type="document_version.created",
            target_entity_type="document_version",
            target_entity_id=version.id,
            payload_json={
                "document_id": version.document_id,
                "version_number": version.version_number,
                "sha256_hex": version.sha256_hex,
                "mime_type": version.mime_type,
            },
        )
        if enqueue_processing:
            queue_idemp = compute_processing_idempotency_key(
                organization_id=ctx.organization_id,
                document_version_id=version.id,
                sha256_hex=version.sha256_hex,
                extractor_version=DEFAULT_INTEGRITY_EXTRACTOR_VERSION,
                policy_version=DEFAULT_PROCESSING_POLICY_VERSION,
            )
            run = ProcessingQueueRepository.enqueue_run(
                session,
                ctx,
                document_version_id=version.id,
                step_type=ProcessingStepType.VERIFY_OBJECT_INTEGRITY.value,
                policy_version=DEFAULT_PROCESSING_POLICY_VERSION,
                extractor_version=DEFAULT_INTEGRITY_EXTRACTOR_VERSION,
                idempotency_key=queue_idemp,
                max_attempts=processing_max_attempts,
            )
            AuditEventRepository.append_event(
                session,
                ctx,
                event_type="processing_run.queued",
                target_entity_type="processing_run",
                target_entity_id=run.id,
                payload_json={
                    "operation": "processing_run_queued",
                    "document_id": version.document_id,
                    "document_version_id": version.id,
                    "processing_run_id": run.id,
                    "step_type": run.step_type,
                    "status": run.status,
                    "policy_version": run.policy_version,
                    "extractor_version": run.extractor_version,
                    "max_attempts": run.max_attempts,
                    "administrative_only": True,
                    "clinical_approval": False,
                },
            )
        return version

    @staticmethod
    def store_and_register_document_version(
        session: Session,
        ctx: TenantContext,
        *,
        storage: DocumentStoragePort,
        document_id: str,
        version_number: int,
        mime_type: str,
        content: bytes,
        page_count: int | None = None,
        original_filename: str | None = None,
        enqueue_processing: bool = False,
        processing_max_attempts: int = DEFAULT_PROCESSING_MAX_ATTEMPTS,
    ) -> DocumentVersion:
        stored = storage.store_synthetic_bytes(
            organization_id=ctx.organization_id,
            mime_type=mime_type,
            content=content,
            original_filename=original_filename,
        )
        return InstitutionalService.register_document_version(
            session,
            ctx,
            DocumentVersionCreateInput(
                document_id=document_id,
                version_number=version_number,
                sha256_hex=stored.sha256_hex,
                mime_type=mime_type,  # type: ignore[arg-type]
                byte_size=stored.byte_size,
                page_count=page_count,
                original_filename=stored.original_filename,
                storage_key=stored.storage_key,
            ),
            enqueue_processing=enqueue_processing,
            processing_max_attempts=processing_max_attempts,
        )

    @staticmethod
    def record_processing_run(
        session: Session, ctx: TenantContext, payload: ProcessingRunCreateInput
    ) -> ProcessingRun:
        _verify_actor_membership(session, ctx)
        run = CaseAndDocumentRepository.create_processing_run(
            session,
            ctx,
            document_version_id=payload.document_version_id,
            policy_version=payload.policy_version,
            extractor_version=payload.extractor_version,
            idempotency_key=payload.idempotency_key,
            status=payload.status.value,
            readable=payload.readable,
            readiness_state=payload.readiness_state.value if payload.readiness_state else None,
            axes_summary=payload.axes_summary,
            started_at=payload.started_at,
            finished_at=payload.finished_at,
            step_type=payload.step_type.value,
            triggered_by_user_id=payload.triggered_by_user_id,
            max_attempts=payload.max_attempts,
            available_at=payload.available_at,
            result_json=payload.result_json,
        )
        AuditEventRepository.append_event(
            session,
            ctx,
            event_type="processing_run.recorded",
            target_entity_type="processing_run",
            target_entity_id=run.id,
            payload_json={
                "document_version_id": run.document_version_id,
                "status": run.status,
                "policy_version": run.policy_version,
            },
        )
        return run

    @staticmethod
    def list_case_processing_runs(
        session: Session,
        ctx: TenantContext,
        *,
        case_id: str,
        document_version_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> CaseProcessingRunsPageResult:
        _require_actor_permission(session, ctx, RbacPermission.DOCUMENT_READ)
        case = CaseAndDocumentRepository.get_case(session, ctx, case_id)
        if case is None:
            raise DocumentNotFoundError(
                f"DocumentCase '{case_id}' was not found in organization."
            )
        items, total = ProcessingQueueRepository.list_case_runs(
            session,
            ctx,
            case_id=case.id,
            document_version_id=document_version_id,
            limit=limit,
            offset=offset,
        )
        return CaseProcessingRunsPageResult(
            case=case,
            total=total,
            limit=limit,
            offset=offset,
            items=items,
        )

    @staticmethod
    def get_processing_run(
        session: Session,
        ctx: TenantContext,
        *,
        processing_run_id: str,
    ) -> ProcessingRunDetailResult:
        _require_actor_permission(session, ctx, RbacPermission.DOCUMENT_READ)
        row = ProcessingQueueRepository.get_run_with_document_context(
            session, ctx, processing_run_id=processing_run_id
        )
        if row is None:
            raise DocumentNotFoundError(
                f"ProcessingRun '{processing_run_id}' was not found in organization."
            )
        run, document_id, case_id = row
        return ProcessingRunDetailResult(
            processing_run=run,
            document_id=document_id,
            case_id=case_id,
        )

    @staticmethod
    def enqueue_document_version_reprocessing(
        session: Session,
        ctx: TenantContext,
        *,
        document_id: str,
        version_id: str,
        idempotency_key: str | None = None,
        max_attempts: int = DEFAULT_PROCESSING_MAX_ATTEMPTS,
    ) -> ProcessingRunDetailResult:
        _require_actor_permission(session, ctx, RbacPermission.DOCUMENT_UPLOAD)
        doc = CaseAndDocumentRepository.get_document(session, ctx, document_id)
        if doc is None:
            raise DocumentNotFoundError(
                f"Document '{document_id}' was not found in organization."
            )
        version = CaseAndDocumentRepository.get_document_version_for_document(
            session, ctx, document_id=doc.id, version_id=version_id
        )
        if version is None:
            raise DocumentNotFoundError(
                f"DocumentVersion '{version_id}' was not found for document '{document_id}'."
            )

        scoped_idemp_key: str | None = None
        if idempotency_key is not None:
            raw_key = idempotency_key.strip()
            scoped_idemp_key = f"reprocess:{version.id}:{raw_key}"[:128]
            existing_by_idemp = ProcessingQueueRepository.get_by_idempotency_key(
                session, ctx, idempotency_key=scoped_idemp_key
            )
            if existing_by_idemp is not None:
                if existing_by_idemp.document_version_id != version.id:
                    raise IdempotencyConflictError(
                        "Idempotency-Key was already used for another document version."
                    )
                return ProcessingRunDetailResult(
                    processing_run=existing_by_idemp,
                    document_id=doc.id,
                    case_id=doc.case_id,
                    idempotent_replay=True,
                )

        active = ProcessingQueueRepository.get_active_run_for_version(
            session,
            ctx,
            document_version_id=version.id,
            step_type=None,
        )
        if active is not None:
            raise ProcessingRunActiveConflictError(
                "An active processing run already exists for this document version."
            )

        final_idemp_key = scoped_idemp_key or f"reprocess:{version.id}:{new_uuid()}"[:128]
        try:
            run = ProcessingQueueRepository.enqueue_run(
                session,
                ctx,
                document_version_id=version.id,
                step_type=ProcessingStepType.VERIFY_OBJECT_INTEGRITY.value,
                policy_version=DEFAULT_PROCESSING_POLICY_VERSION,
                extractor_version=DEFAULT_INTEGRITY_EXTRACTOR_VERSION,
                idempotency_key=final_idemp_key,
                max_attempts=max_attempts,
            )
            AuditEventRepository.append_event(
                session,
                ctx,
                event_type="processing_run.reprocess_queued",
                target_entity_type="processing_run",
                target_entity_id=run.id,
                payload_json={
                    "operation": "processing_run_reprocess_queued",
                    "case_id": doc.case_id,
                    "document_id": doc.id,
                    "document_version_id": version.id,
                    "processing_run_id": run.id,
                    "step_type": run.step_type,
                    "status": run.status,
                    "policy_version": run.policy_version,
                    "extractor_version": run.extractor_version,
                    "max_attempts": run.max_attempts,
                    "administrative_only": True,
                    "clinical_approval": False,
                },
            )
            session.commit()
            return ProcessingRunDetailResult(
                processing_run=run,
                document_id=doc.id,
                case_id=doc.case_id,
                idempotent_replay=False,
            )
        except IntegrityError as exc:
            session.rollback()
            if scoped_idemp_key is not None:
                winner = ProcessingQueueRepository.get_by_idempotency_key(
                    session, ctx, idempotency_key=scoped_idemp_key
                )
                if winner is not None and winner.document_version_id == version.id:
                    return ProcessingRunDetailResult(
                        processing_run=winner,
                        document_id=doc.id,
                        case_id=doc.case_id,
                        idempotent_replay=True,
                    )
            raise ProcessingRunActiveConflictError(
                "Concurrent processing run registration conflicted with active queue state."
            ) from exc

    @staticmethod
    def record_extracted_field(
        session: Session, ctx: TenantContext, payload: ExtractedFieldCreateInput
    ) -> ExtractedField:
        _verify_actor_membership(session, ctx)
        field = CaseAndDocumentRepository.create_extracted_field(
            session,
            ctx,
            processing_run_id=payload.processing_run_id,
            document_version_id=payload.document_version_id,
            field_key=payload.field_key,
            raw_value=payload.raw_value,
            normalized_value=payload.normalized_value,
            status=payload.status.value,
            abstained=payload.abstained,
            metadata_json=payload.metadata_json,
        )
        logger.info(
            "Extracted field persisted.",
            extra=build_safe_log_extra(
                organization_id=ctx.organization_id,
                field_key=field.field_key,
                status=field.status,
                abstained=field.abstained,
            ),
        )
        return field

    @staticmethod
    def record_evidence_reference(
        session: Session, ctx: TenantContext, payload: EvidenceReferenceCreateInput
    ) -> EvidenceReference:
        _verify_actor_membership(session, ctx)
        return CaseAndDocumentRepository.create_evidence_reference(
            session,
            ctx,
            extracted_field_id=payload.extracted_field_id,
            document_version_id=payload.document_version_id,
            page_number=payload.page_number,
            bbox_x=payload.bbox_x,
            bbox_y=payload.bbox_y,
            bbox_w=payload.bbox_w,
            bbox_h=payload.bbox_h,
            quote_excerpt=payload.quote_excerpt,
            extraction_method=payload.extraction_method,
        )

    @staticmethod
    def list_document_version_extracted_fields(
        session: Session,
        ctx: TenantContext,
        *,
        document_id: str,
        version_id: str,
        processing_run_id: str | None = None,
        latest_only: bool = False,
    ) -> DocumentVersionExtractedFieldsResult:
        _require_actor_permission(session, ctx, RbacPermission.DOCUMENT_READ)
        doc = CaseAndDocumentRepository.get_document(session, ctx, document_id)
        if doc is None:
            raise DocumentNotFoundError(
                f"Document '{document_id}' was not found inside active organization."
            )
        version = CaseAndDocumentRepository.get_document_version_for_document(
            session, ctx, document_id=doc.id, version_id=version_id
        )
        if version is None:
            raise DocumentNotFoundError(
                f"DocumentVersion '{version_id}' was not found for document '{document_id}'."
            )
        items, latest_run = ProcessingQueueRepository.list_document_version_extracted_fields(
            session,
            ctx,
            document_version_id=version.id,
            processing_run_id=processing_run_id,
            latest_only=latest_only,
        )
        return DocumentVersionExtractedFieldsResult(
            document=doc,
            version=version,
            latest_extract_run=latest_run,
            items=items,
        )

    @staticmethod
    def list_document_version_evidence(
        session: Session,
        ctx: TenantContext,
        *,
        document_id: str,
        version_id: str,
        processing_run_id: str | None = None,
        page_number: int | None = None,
        field_key: str | None = None,
        latest_only: bool = False,
    ) -> DocumentVersionEvidenceResult:
        _require_actor_permission(session, ctx, RbacPermission.DOCUMENT_READ)
        doc = CaseAndDocumentRepository.get_document(session, ctx, document_id)
        if doc is None:
            raise DocumentNotFoundError(
                f"Document '{document_id}' was not found inside active organization."
            )
        version = CaseAndDocumentRepository.get_document_version_for_document(
            session, ctx, document_id=doc.id, version_id=version_id
        )
        if version is None:
            raise DocumentNotFoundError(
                f"DocumentVersion '{version_id}' was not found for document '{document_id}'."
            )
        items, latest_run = ProcessingQueueRepository.list_document_version_evidence_references(
            session,
            ctx,
            document_version_id=version.id,
            processing_run_id=processing_run_id,
            page_number=page_number,
            field_key=field_key,
            latest_only=latest_only,
        )
        return DocumentVersionEvidenceResult(
            document=doc,
            version=version,
            latest_extract_run=latest_run,
            items=items,
        )

    @staticmethod
    def record_human_review(
        session: Session, ctx: TenantContext, payload: HumanReviewCreateInput
    ) -> HumanReview:
        _verify_actor_membership(session, ctx)
        review = CaseAndDocumentRepository.create_human_review(
            session,
            ctx,
            document_version_id=payload.document_version_id,
            reviewer_user_id=payload.reviewer_user_id,
            action_type=payload.action_type.value,
            field_key=payload.field_key,
            original_value=payload.original_value,
            revised_value=payload.revised_value,
            justification=payload.justification,
            evidence_reference_id=payload.evidence_reference_id,
            policy_version=payload.policy_version,
        )
        AuditEventRepository.append_event(
            session,
            ctx,
            event_type="human_review.recorded",
            target_entity_type="human_review",
            target_entity_id=review.id,
            payload_json={
                "action_type": review.action_type,
                "field_key": review.field_key,
                "policy_version": review.policy_version,
            },
        )
        return review

    @staticmethod
    def append_audit_event_atomic(
        session_factory: sessionmaker[Session] | Callable[[], Session],
        ctx: TenantContext,
        *,
        event_type: str,
        target_entity_type: str,
        target_entity_id: str,
        payload_json: dict[str, str | int | bool | None],
    ) -> AuditEvent:
        return AuditEventRepository.append_event_atomic(
            session_factory,
            ctx,
            event_type=event_type,
            target_entity_type=target_entity_type,
            target_entity_id=target_entity_id,
            payload_json=dict(payload_json),
        )

    @staticmethod
    def list_audit_events(session: Session, ctx: TenantContext) -> list[AuditEvent]:
        return AuditEventRepository.list_events(session, ctx)

    @staticmethod
    def verify_audit_chain(session: Session, ctx: TenantContext) -> bool:
        return AuditEventRepository.verify_chain(session, ctx)

    @staticmethod
    def verify_audit_chain_detailed(
        session: Session, ctx: TenantContext
    ) -> AuditChainVerificationResult:
        return AuditEventRepository.verify_chain_detailed(session, ctx)
