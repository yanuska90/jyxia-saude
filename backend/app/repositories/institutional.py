"""Explicitly tenant-scoped repositories for organizations, cases, documents and audit chains."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import threading
import time
from collections import defaultdict
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol, TypeVar

from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session, sessionmaker

from app.core.constants import (
    ACTIVE_PROCESSING_STATUSES,
    DEFAULT_INTEGRITY_EXTRACTOR_VERSION,
    DEFAULT_PDF_TEXT_EXTRACTOR_VERSION,
    DEFAULT_PROCESSING_MAX_ATTEMPTS,
    DEFAULT_PROCESSING_POLICY_VERSION,
    MembershipStatus,
    OrganizationRole,
    ProcessingStatus,
    ProcessingStepType,
)
from app.core.logging import FORBIDDEN_LOG_KEYS, redact_sensitive_text
from app.db.base import new_uuid, utc_now
from app.db.session import apply_pg_identity_context, apply_pg_rls_context
from app.models.entities import (
    AUDIT_SCHEMA_VERSION,
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
from app.schemas.tenant import TenantContext

GENESIS_AUDIT_HASH = "0" * 64
ModelT = TypeVar("ModelT")
_SQLITE_ORG_LOCKS: dict[str, threading.RLock] = defaultdict(threading.RLock)
_SQLITE_LOCK_GUARD = threading.Lock()


def _sqlite_lock_for(organization_id: str) -> threading.RLock:
    with _SQLITE_LOCK_GUARD:
        return _SQLITE_ORG_LOCKS[organization_id]

_FORBIDDEN_AUDIT_PAYLOAD_KEYS: frozenset[str] = FORBIDDEN_LOG_KEYS | frozenset(
    {
        "cpf",
        "original_value",
        "revised_value",
        "normalized_value",
        "client_secret",
        "oidc_token",
    }
)


class TenantScopeError(LookupError):
    """Raised when a requested record is missing or outside the caller's TenantContext."""


class AuditPayloadError(ValueError):
    """Raised when an audit payload contains prohibited sensitive or malformed keys."""


class LeaseOwnershipError(RuntimeError):
    """Raised when a worker attempts to update a run without a valid active lease."""


class ProcessingQueueConflictError(ValueError):
    """Raised when an active processing run or conflicting idempotency key already exists."""


def sanitize_technical_error_detail(raw: str | None, *, max_len: int = 400) -> str:
    """Redact credentials, tokens, PII patterns, and local filesystem paths from error diagnostics."""
    if not raw:
        return "Technical verification error."
    cleaned = redact_sensitive_text(raw)
    cleaned = re.sub(r"(?:[A-Za-z]:)?(?:[/\\][^\s/\\]+){2,}", "[PATH_REDACTED]", cleaned)
    cleaned = " ".join(cleaned.split())
    return cleaned[:max_len] or "Technical verification error."


def _as_utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def _is_pg_session(session: Session) -> bool:
    bind = session.get_bind()
    return bind is not None and bind.dialect.name == "postgresql"


@dataclass(frozen=True, slots=True)
class AuditChainVerificationResult:
    valid: bool
    event_count: int
    failure_reason: str | None = None
    broken_sequence: int | None = None


class AuditEventRecordLike(Protocol):
    @property
    def organization_id(self) -> str: ...
    @property
    def schema_version(self) -> str: ...
    @property
    def sequence_number(self) -> int: ...
    @property
    def actor_user_id(self) -> str | None: ...
    @property
    def event_type(self) -> str: ...
    @property
    def target_entity_type(self) -> str: ...
    @property
    def target_entity_id(self) -> str: ...
    @property
    def payload_json(self) -> dict[str, Any]: ...
    @property
    def prev_event_hash(self) -> str: ...
    @property
    def event_hash(self) -> str: ...
    @property
    def created_at(self) -> datetime: ...


def normalize_audit_timestamp(dt: datetime) -> str:
    """Normalize timestamp deterministically across PostgreSQL and SQLite UTC representations."""
    utc_dt = dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
    return utc_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def assert_safe_audit_payload(payload: Any) -> dict[str, Any]:
    """Validate audit payload metadata contains no forbidden document/PII/secret keys."""
    if not isinstance(payload, dict):
        raise AuditPayloadError("Audit event payload_json must be a JSON object.")

    def _walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, val in node.items():
                key_lower = str(key).lower()
                if key_lower in _FORBIDDEN_AUDIT_PAYLOAD_KEYS:
                    raise AuditPayloadError(f"Prohibited audit payload key: {key}")
                _walk(val)
        elif isinstance(node, list):
            for item in node:
                _walk(item)
        elif isinstance(node, str):
            if redact_sensitive_text(node) != node:
                raise AuditPayloadError("Audit payload contains secret or CPF-shaped literal.")

    _walk(payload)
    return payload


def compute_audit_event_hash(
    *,
    schema_version: str = AUDIT_SCHEMA_VERSION,
    organization_id: str,
    sequence_number: int,
    actor_user_id: str | None,
    event_type: str,
    target_entity_type: str,
    target_entity_id: str,
    created_at: datetime,
    payload_json: dict[str, Any],
    prev_event_hash: str,
) -> str:
    """Compute canonical SHA-256 hash covering full event metadata and predecessor link."""
    canonical = json.dumps(
        {
            "schema_version": schema_version,
            "organization_id": organization_id,
            "sequence_number": sequence_number,
            "actor_user_id": actor_user_id,
            "event_type": event_type,
            "target_entity_type": target_entity_type,
            "target_entity_id": target_entity_id,
            "created_at": normalize_audit_timestamp(created_at),
            "payload_json": payload_json,
            "prev_event_hash": prev_event_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def verify_event_sequence(
    events: Sequence[AuditEventRecordLike], *, organization_id: str
) -> AuditChainVerificationResult:
    """Verify sequence continuity, genesis hash, link continuity and canonical event hashes."""
    expected_prev = GENESIS_AUDIT_HASH
    for expected_seq, ev in enumerate(events, start=1):
        if ev.organization_id != organization_id:
            return AuditChainVerificationResult(
                valid=False,
                event_count=len(events),
                failure_reason="cross_organization_event_detected",
                broken_sequence=ev.sequence_number,
            )
        if ev.schema_version != AUDIT_SCHEMA_VERSION:
            return AuditChainVerificationResult(
                valid=False,
                event_count=len(events),
                failure_reason="unsupported_schema_version",
                broken_sequence=ev.sequence_number,
            )
        if ev.sequence_number != expected_seq:
            return AuditChainVerificationResult(
                valid=False,
                event_count=len(events),
                failure_reason="sequence_gap_or_reorder",
                broken_sequence=expected_seq,
            )
        if ev.prev_event_hash != expected_prev:
            return AuditChainVerificationResult(
                valid=False,
                event_count=len(events),
                failure_reason="prev_event_hash_mismatch",
                broken_sequence=expected_seq,
            )
        recomputed = compute_audit_event_hash(
            schema_version=ev.schema_version,
            organization_id=ev.organization_id,
            sequence_number=ev.sequence_number,
            actor_user_id=ev.actor_user_id,
            event_type=ev.event_type,
            target_entity_type=ev.target_entity_type,
            target_entity_id=ev.target_entity_id,
            created_at=ev.created_at,
            payload_json=ev.payload_json,
            prev_event_hash=ev.prev_event_hash,
        )
        if ev.event_hash != recomputed:
            return AuditChainVerificationResult(
                valid=False,
                event_count=len(events),
                failure_reason="event_hash_mismatch",
                broken_sequence=expected_seq,
            )
        expected_prev = ev.event_hash
    return AuditChainVerificationResult(valid=True, event_count=len(events))


def _require_tenant_row(
    session: Session,
    model: type[ModelT],
    ctx: TenantContext,
    record_id: str,
    label: str,
) -> ModelT:
    apply_pg_rls_context(
        session,
        organization_id=ctx.organization_id,
        user_id=ctx.actor_user_id,
    )
    row = session.scalar(
        select(model).where(
            getattr(model, "id") == record_id,
            getattr(model, "organization_id") == ctx.organization_id,
        )
    )
    if row is None:
        raise TenantScopeError(f"{label} '{record_id}' was not found inside active organization.")
    return row


class OrganizationRepository:
    """Repository managing organizations, users and memberships."""

    @staticmethod
    def create_organization(session: Session, *, slug: str, name: str) -> Organization:
        org = Organization(slug=slug, name=name)
        session.add(org)
        session.flush()
        return org

    @staticmethod
    def get_organization(session: Session, organization_id: str) -> Organization | None:
        return session.get(Organization, organization_id)

    @staticmethod
    def create_user(
        session: Session,
        *,
        email: str,
        display_name: str,
        external_subject: str | None = None,
        mfa_enrolled: bool = False,
    ) -> User:
        user = User(
            email=email,
            display_name=display_name,
            external_subject=external_subject,
            mfa_enrolled=mfa_enrolled,
        )
        session.add(user)
        session.flush()
        return user

    @staticmethod
    def assign_membership(
        session: Session,
        ctx: TenantContext,
        *,
        user_id: str,
        role: str,
    ) -> OrganizationMembership:
        apply_pg_rls_context(
            session, organization_id=ctx.organization_id, user_id=ctx.actor_user_id
        )
        org = session.get(Organization, ctx.organization_id)
        if org is None:
            raise TenantScopeError(f"Organization '{ctx.organization_id}' does not exist.")
        user = session.get(User, user_id)
        if user is None:
            raise TenantScopeError(f"User '{user_id}' does not exist.")
        try:
            normalized_role = OrganizationRole(role).value
        except ValueError:
            normalized_role = role
        membership = OrganizationMembership(
            organization_id=ctx.organization_id,
            user_id=user_id,
            role=normalized_role,
        )
        session.add(membership)
        session.flush()
        return membership

    @staticmethod
    def get_active_membership(
        session: Session, ctx: TenantContext, *, user_id: str
    ) -> OrganizationMembership | None:
        apply_pg_rls_context(
            session,
            organization_id=ctx.organization_id,
            user_id=ctx.actor_user_id or user_id,
        )
        return session.scalar(
            select(OrganizationMembership).where(
                OrganizationMembership.organization_id == ctx.organization_id,
                OrganizationMembership.user_id == user_id,
                OrganizationMembership.status == MembershipStatus.ACTIVE.value,
            )
        )

    @staticmethod
    def list_memberships(session: Session, ctx: TenantContext) -> list[OrganizationMembership]:
        apply_pg_rls_context(
            session, organization_id=ctx.organization_id, user_id=ctx.actor_user_id
        )
        return list(
            session.scalars(
                select(OrganizationMembership)
                .where(OrganizationMembership.organization_id == ctx.organization_id)
                .order_by(OrganizationMembership.created_at.asc())
            )
        )

    @staticmethod
    def list_memberships_with_users(
        session: Session, ctx: TenantContext
    ) -> list[tuple[OrganizationMembership, User]]:
        apply_pg_rls_context(
            session, organization_id=ctx.organization_id, user_id=ctx.actor_user_id
        )
        rows = session.execute(
            select(OrganizationMembership, User)
            .join(User, User.id == OrganizationMembership.user_id)
            .where(OrganizationMembership.organization_id == ctx.organization_id)
            .order_by(OrganizationMembership.created_at.asc())
        ).all()
        return [(membership, user) for membership, user in rows]


class CaseAndDocumentRepository:
    """Tenant-scoped persistence for cases, documents, versions, runs, fields, evidence and reviews."""

    @staticmethod
    def create_case(
        session: Session,
        ctx: TenantContext,
        *,
        case_code: str,
        external_reference: str | None,
        procedure_reference: str | None,
        declared_laterality: str | None,
        readiness_state: str,
    ) -> DocumentCase:
        apply_pg_rls_context(
            session, organization_id=ctx.organization_id, user_id=ctx.actor_user_id
        )
        case = DocumentCase(
            organization_id=ctx.organization_id,
            case_code=case_code,
            external_reference=external_reference,
            procedure_reference=procedure_reference,
            declared_laterality=declared_laterality,
            readiness_state=readiness_state,
            created_by_user_id=ctx.actor_user_id,
            administrative_only=True,
            clinical_approval=False,
        )
        session.add(case)
        session.flush()
        return case

    @staticmethod
    def get_case(session: Session, ctx: TenantContext, case_id: str) -> DocumentCase | None:
        apply_pg_rls_context(
            session, organization_id=ctx.organization_id, user_id=ctx.actor_user_id
        )
        return session.scalar(
            select(DocumentCase).where(
                DocumentCase.id == case_id,
                DocumentCase.organization_id == ctx.organization_id,
            )
        )

    @staticmethod
    def list_cases(session: Session, ctx: TenantContext) -> list[DocumentCase]:
        apply_pg_rls_context(
            session, organization_id=ctx.organization_id, user_id=ctx.actor_user_id
        )
        return list(
            session.scalars(
                select(DocumentCase)
                .where(DocumentCase.organization_id == ctx.organization_id)
                .order_by(DocumentCase.created_at.asc())
            )
        )

    @staticmethod
    def create_document(
        session: Session,
        ctx: TenantContext,
        *,
        case_id: str | None,
        document_kind: str,
        document_subfamily: str | None,
        source_label: str,
        quarantined: bool,
        quarantine_reason: str | None,
        external_reference: str | None = None,
        description: str | None = None,
        idempotency_key: str | None = None,
        idempotency_fingerprint: str | None = None,
    ) -> Document:
        apply_pg_rls_context(
            session, organization_id=ctx.organization_id, user_id=ctx.actor_user_id
        )
        if case_id is not None:
            _require_tenant_row(session, DocumentCase, ctx, case_id, "DocumentCase")
        document = Document(
            organization_id=ctx.organization_id,
            case_id=case_id,
            document_kind=document_kind,
            document_subfamily=document_subfamily,
            source_label=source_label,
            external_reference=external_reference,
            description=description,
            created_by_user_id=ctx.actor_user_id,
            idempotency_key=idempotency_key,
            idempotency_fingerprint=idempotency_fingerprint,
            quarantined=quarantined,
            quarantine_reason=quarantine_reason,
        )
        session.add(document)
        session.flush()
        return document

    @staticmethod
    def get_document(session: Session, ctx: TenantContext, document_id: str) -> Document | None:
        apply_pg_rls_context(
            session, organization_id=ctx.organization_id, user_id=ctx.actor_user_id
        )
        return session.scalar(
            select(Document).where(
                Document.id == document_id,
                Document.organization_id == ctx.organization_id,
                Document.discarded_at.is_(None),
            )
        )

    @staticmethod
    def get_document_by_idempotency_key(
        session: Session,
        ctx: TenantContext,
        *,
        case_id: str,
        idempotency_key: str,
    ) -> Document | None:
        apply_pg_rls_context(
            session, organization_id=ctx.organization_id, user_id=ctx.actor_user_id
        )
        return session.scalar(
            select(Document).where(
                Document.organization_id == ctx.organization_id,
                Document.case_id == case_id,
                Document.idempotency_key == idempotency_key,
                Document.discarded_at.is_(None),
            )
        )

    @staticmethod
    def list_case_documents(
        session: Session,
        ctx: TenantContext,
        *,
        case_id: str,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[Document], int]:
        apply_pg_rls_context(
            session, organization_id=ctx.organization_id, user_id=ctx.actor_user_id
        )
        _require_tenant_row(session, DocumentCase, ctx, case_id, "DocumentCase")
        total = int(
            session.scalar(
                select(func.count(Document.id)).where(
                    Document.organization_id == ctx.organization_id,
                    Document.case_id == case_id,
                    Document.discarded_at.is_(None),
                )
            )
            or 0
        )
        rows = list(
            session.scalars(
                select(Document)
                .where(
                    Document.organization_id == ctx.organization_id,
                    Document.case_id == case_id,
                    Document.discarded_at.is_(None),
                )
                .order_by(Document.created_at.asc(), Document.id.asc())
                .limit(limit)
                .offset(offset)
            )
        )
        return rows, total

    @staticmethod
    def create_document_version(
        session: Session,
        ctx: TenantContext,
        *,
        document_id: str,
        version_number: int,
        sha256_hex: str,
        mime_type: str,
        byte_size: int,
        page_count: int | None,
        original_filename: str | None,
        storage_driver: str,
        storage_key: str,
    ) -> DocumentVersion:
        _require_tenant_row(session, Document, ctx, document_id, "Document")
        version = DocumentVersion(
            organization_id=ctx.organization_id,
            document_id=document_id,
            version_number=version_number,
            sha256_hex=sha256_hex,
            mime_type=mime_type,
            byte_size=byte_size,
            page_count=page_count,
            original_filename=original_filename,
            storage_driver=storage_driver,
            storage_key=storage_key,
            created_by_user_id=ctx.actor_user_id,
        )
        session.add(version)
        session.flush()
        return version

    @staticmethod
    def get_document_version(
        session: Session, ctx: TenantContext, version_id: str
    ) -> DocumentVersion | None:
        apply_pg_rls_context(
            session, organization_id=ctx.organization_id, user_id=ctx.actor_user_id
        )
        return session.scalar(
            select(DocumentVersion).where(
                DocumentVersion.id == version_id,
                DocumentVersion.organization_id == ctx.organization_id,
            )
        )

    @staticmethod
    def get_document_version_for_document(
        session: Session,
        ctx: TenantContext,
        *,
        document_id: str,
        version_id: str,
    ) -> DocumentVersion | None:
        apply_pg_rls_context(
            session, organization_id=ctx.organization_id, user_id=ctx.actor_user_id
        )
        return session.scalar(
            select(DocumentVersion).where(
                DocumentVersion.id == version_id,
                DocumentVersion.document_id == document_id,
                DocumentVersion.organization_id == ctx.organization_id,
            )
        )

    @staticmethod
    def list_document_versions(
        session: Session,
        ctx: TenantContext,
        *,
        document_id: str,
    ) -> list[DocumentVersion]:
        apply_pg_rls_context(
            session, organization_id=ctx.organization_id, user_id=ctx.actor_user_id
        )
        return list(
            session.scalars(
                select(DocumentVersion)
                .where(
                    DocumentVersion.organization_id == ctx.organization_id,
                    DocumentVersion.document_id == document_id,
                )
                .order_by(DocumentVersion.version_number.asc())
            )
        )

    @staticmethod
    def create_processing_run(
        session: Session,
        ctx: TenantContext,
        *,
        document_version_id: str,
        policy_version: str,
        extractor_version: str,
        idempotency_key: str | None,
        status: str,
        readable: bool,
        readiness_state: str | None,
        axes_summary: dict[str, Any] | None,
        started_at: datetime | None,
        finished_at: datetime | None,
        step_type: str = ProcessingStepType.VERIFY_OBJECT_INTEGRITY.value,
        triggered_by_user_id: str | None = None,
        max_attempts: int = DEFAULT_PROCESSING_MAX_ATTEMPTS,
        available_at: datetime | None = None,
        result_json: dict[str, Any] | None = None,
    ) -> ProcessingRun:
        _require_tenant_row(session, DocumentVersion, ctx, document_version_id, "DocumentVersion")
        now = utc_now()
        effective_started_at = (
            started_at if status in ACTIVE_PROCESSING_STATUSES else (started_at or now)
        )
        run = ProcessingRun(
            organization_id=ctx.organization_id,
            document_version_id=document_version_id,
            step_type=step_type,
            triggered_by_user_id=triggered_by_user_id
            if triggered_by_user_id is not None
            else ctx.actor_user_id,
            policy_version=policy_version,
            extractor_version=extractor_version,
            idempotency_key=idempotency_key,
            status=status,
            attempt_count=0,
            max_attempts=max_attempts,
            available_at=available_at or now,
            result_json=result_json,
            readable=readable,
            readiness_state=readiness_state,
            axes_summary=axes_summary,
            started_at=effective_started_at,
            finished_at=finished_at,
            created_at=now,
            updated_at=now,
        )
        session.add(run)
        session.flush()
        return run

    @staticmethod
    def create_extracted_field(
        session: Session,
        ctx: TenantContext,
        *,
        processing_run_id: str,
        document_version_id: str,
        field_key: str,
        raw_value: str | None,
        normalized_value: str | None,
        status: str,
        abstained: bool,
        metadata_json: dict[str, Any] | None,
    ) -> ExtractedField:
        run = _require_tenant_row(session, ProcessingRun, ctx, processing_run_id, "ProcessingRun")
        if run.document_version_id != document_version_id:
            raise TenantScopeError("ProcessingRun does not belong to target DocumentVersion.")
        field = ExtractedField(
            organization_id=ctx.organization_id,
            processing_run_id=processing_run_id,
            document_version_id=document_version_id,
            field_key=field_key,
            raw_value=raw_value,
            normalized_value=normalized_value,
            status=status,
            abstained=abstained,
            metadata_json=metadata_json,
        )
        session.add(field)
        session.flush()
        return field

    @staticmethod
    def create_evidence_reference(
        session: Session,
        ctx: TenantContext,
        *,
        extracted_field_id: str,
        document_version_id: str,
        page_number: int,
        bbox_x: float,
        bbox_y: float,
        bbox_w: float,
        bbox_h: float,
        quote_excerpt: str | None,
        extraction_method: str,
    ) -> EvidenceReference:
        field = _require_tenant_row(session, ExtractedField, ctx, extracted_field_id, "ExtractedField")
        if field.document_version_id != document_version_id:
            raise TenantScopeError("ExtractedField does not belong to target DocumentVersion.")
        evidence = EvidenceReference(
            organization_id=ctx.organization_id,
            extracted_field_id=extracted_field_id,
            document_version_id=document_version_id,
            page_number=page_number,
            bbox_x=bbox_x,
            bbox_y=bbox_y,
            bbox_w=bbox_w,
            bbox_h=bbox_h,
            quote_excerpt=quote_excerpt,
            extraction_method=extraction_method,
        )
        session.add(evidence)
        session.flush()
        return evidence

    @staticmethod
    def create_human_review(
        session: Session,
        ctx: TenantContext,
        *,
        document_version_id: str,
        reviewer_user_id: str,
        action_type: str,
        field_key: str | None,
        original_value: str | None,
        revised_value: str | None,
        justification: str,
        evidence_reference_id: str | None,
        policy_version: str,
    ) -> HumanReview:
        _require_tenant_row(session, DocumentVersion, ctx, document_version_id, "DocumentVersion")
        membership = OrganizationRepository.get_active_membership(
            session, ctx, user_id=reviewer_user_id
        )
        if membership is None:
            raise TenantScopeError(
                f"Reviewer '{reviewer_user_id}' lacks active membership in organization."
            )
        if evidence_reference_id is not None:
            evidence = _require_tenant_row(
                session, EvidenceReference, ctx, evidence_reference_id, "EvidenceReference"
            )
            if evidence.document_version_id != document_version_id:
                raise TenantScopeError(
                    "EvidenceReference does not belong to target DocumentVersion."
                )
        review = HumanReview(
            organization_id=ctx.organization_id,
            document_version_id=document_version_id,
            reviewer_user_id=reviewer_user_id,
            action_type=action_type,
            field_key=field_key,
            original_value=original_value,
            revised_value=revised_value,
            justification=justification,
            evidence_reference_id=evidence_reference_id,
            policy_version=policy_version,
        )
        session.add(review)
        session.flush()
        return review


class AuditEventRepository:
    """Append-only organization-scoped audit ledger with per-tenant serialization."""

    @staticmethod
    def append_event(
        session: Session,
        ctx: TenantContext,
        *,
        event_type: str,
        target_entity_type: str,
        target_entity_id: str,
        payload_json: dict[str, Any],
        created_at: datetime | None = None,
    ) -> AuditEvent:
        safe_payload = assert_safe_audit_payload(payload_json)
        apply_pg_rls_context(
            session, organization_id=ctx.organization_id, user_id=ctx.actor_user_id
        )
        if ctx.session_token_hash is not None:
            apply_pg_identity_context(
                session, session_token_hash=ctx.session_token_hash
            )
        bind = session.get_bind()
        is_pg = bind is not None and bind.dialect.name == "postgresql"

        if is_pg:
            session.execute(
                text("SELECT pg_advisory_xact_lock(hashtext('audit:' || :org_id))"),
                {"org_id": ctx.organization_id},
            )
            org_exists = session.scalar(
                select(Organization.id).where(Organization.id == ctx.organization_id)
            )
            if org_exists is None:
                raise TenantScopeError(f"Organization '{ctx.organization_id}' does not exist.")
        else:
            locked_org_id = session.scalar(
                select(Organization.id)
                .where(Organization.id == ctx.organization_id)
                .with_for_update()
            )
            if locked_org_id is None:
                raise TenantScopeError(f"Organization '{ctx.organization_id}' does not exist.")

        if ctx.actor_user_id is not None:
            actor_membership = OrganizationRepository.get_active_membership(
                session, ctx, user_id=ctx.actor_user_id
            )
            if actor_membership is None:
                raise TenantScopeError(
                    f"Actor '{ctx.actor_user_id}' lacks active membership in organization."
                )

        latest = session.scalar(
            select(AuditEvent)
            .where(AuditEvent.organization_id == ctx.organization_id)
            .order_by(AuditEvent.sequence_number.desc())
            .limit(1)
        )
        next_seq = 1 if latest is None else latest.sequence_number + 1
        prev_hash = GENESIS_AUDIT_HASH if latest is None else latest.event_hash
        timestamp = (created_at or utc_now()).astimezone(timezone.utc)
        event_hash = compute_audit_event_hash(
            schema_version=AUDIT_SCHEMA_VERSION,
            organization_id=ctx.organization_id,
            sequence_number=next_seq,
            actor_user_id=ctx.actor_user_id,
            event_type=event_type,
            target_entity_type=target_entity_type,
            target_entity_id=target_entity_id,
            created_at=timestamp,
            payload_json=safe_payload,
            prev_event_hash=prev_hash,
        )
        if is_pg:
            event_id = new_uuid()
            session.execute(
                text(
                    "SELECT public.jyxia_append_audit_event("
                    ":p_id, :p_organization_id, :p_schema_version, :p_sequence_number, "
                    ":p_actor_user_id, :p_event_type, :p_target_entity_type, "
                    ":p_target_entity_id, :p_payload_json, :p_prev_event_hash, "
                    ":p_event_hash, :p_created_at)"
                ),
                {
                    "p_id": event_id,
                    "p_organization_id": ctx.organization_id,
                    "p_schema_version": AUDIT_SCHEMA_VERSION,
                    "p_sequence_number": next_seq,
                    "p_actor_user_id": ctx.actor_user_id,
                    "p_event_type": event_type,
                    "p_target_entity_type": target_entity_type,
                    "p_target_entity_id": target_entity_id,
                    "p_payload_json": json.dumps(safe_payload, ensure_ascii=True),
                    "p_prev_event_hash": prev_hash,
                    "p_event_hash": event_hash,
                    "p_created_at": timestamp,
                },
            )
            inserted = session.scalar(select(AuditEvent).where(AuditEvent.id == event_id))
            assert inserted is not None
            return inserted

        row = AuditEvent(
            organization_id=ctx.organization_id,
            schema_version=AUDIT_SCHEMA_VERSION,
            sequence_number=next_seq,
            actor_user_id=ctx.actor_user_id,
            event_type=event_type,
            target_entity_type=target_entity_type,
            target_entity_id=target_entity_id,
            payload_json=safe_payload,
            prev_event_hash=prev_hash,
            event_hash=event_hash,
            created_at=timestamp,
        )
        session.add(row)
        session.flush()
        return row

    @staticmethod
    def append_event_atomic(
        session_factory: sessionmaker[Session] | Callable[[], Session],
        ctx: TenantContext,
        *,
        event_type: str,
        target_entity_type: str,
        target_entity_id: str,
        payload_json: dict[str, Any],
        max_attempts: int = 8,
    ) -> AuditEvent:
        """Execute an isolated committed audit append using DB locking (PG) or local lock (SQLite)."""
        last_error: Exception | None = None
        for attempt in range(1, max_attempts + 1):
            session = session_factory()
            bind = session.get_bind()
            is_sqlite = bind is not None and bind.dialect.name == "sqlite"
            lock_cm = _sqlite_lock_for(ctx.organization_id) if is_sqlite else None
            try:
                if lock_cm is not None:
                    lock_cm.acquire()
                row = AuditEventRepository.append_event(
                    session,
                    ctx,
                    event_type=event_type,
                    target_entity_type=target_entity_type,
                    target_entity_id=target_entity_id,
                    payload_json=payload_json,
                )
                session.commit()
                return row
            except (IntegrityError, OperationalError) as exc:
                session.rollback()
                last_error = exc
                if attempt < max_attempts:
                    time.sleep(0.01 * attempt)
            finally:
                if lock_cm is not None:
                    lock_cm.release()
                session.close()
        assert last_error is not None
        raise last_error

    @staticmethod
    def list_events(session: Session, ctx: TenantContext) -> list[AuditEvent]:
        apply_pg_rls_context(
            session, organization_id=ctx.organization_id, user_id=ctx.actor_user_id
        )
        return list(
            session.scalars(
                select(AuditEvent)
                .where(AuditEvent.organization_id == ctx.organization_id)
                .order_by(AuditEvent.sequence_number.asc())
            )
        )

    @staticmethod
    def count_events(session: Session, ctx: TenantContext) -> int:
        apply_pg_rls_context(
            session, organization_id=ctx.organization_id, user_id=ctx.actor_user_id
        )
        return int(
            session.scalar(
                select(func.count(AuditEvent.id)).where(
                    AuditEvent.organization_id == ctx.organization_id
                )
            )
            or 0
        )

    @staticmethod
    def verify_chain_detailed(
        session: Session, ctx: TenantContext
    ) -> AuditChainVerificationResult:
        events = AuditEventRepository.list_events(session, ctx)
        return verify_event_sequence(events, organization_id=ctx.organization_id)

    @staticmethod
    def verify_chain(session: Session, ctx: TenantContext) -> bool:
        return AuditEventRepository.verify_chain_detailed(session, ctx).valid


@dataclass(frozen=True, slots=True)
class ClaimedProcessingRunRecord:
    """Claimed queued/retry processing run bound to a single lease proof."""

    run_id: str
    organization_id: str
    document_version_id: str
    document_id: str
    case_id: str | None
    step_type: str
    policy_version: str
    extractor_version: str
    idempotency_key: str | None
    triggered_by_user_id: str | None
    attempt_count: int
    max_attempts: int
    started_at: datetime
    available_at: datetime
    lease_expires_at: datetime
    sha256_hex: str
    mime_type: str
    byte_size: int
    page_count: int | None
    storage_driver: str
    storage_key: str
    lease_token_hash: str


class ProcessingQueueRepository:
    """PostgreSQL durable FIFO/lease queue and SQLite-compatible repository for ProcessingRun."""

    _WORKER_QUEUE_LOCK_KEY = "__worker_queue__"

    @staticmethod
    def hash_lease_token(raw_lease_token: str) -> str:
        return hashlib.sha256(raw_lease_token.encode("utf-8")).hexdigest()

    @staticmethod
    def generate_lease_proof() -> tuple[str, str]:
        raw_token = secrets.token_urlsafe(32)
        return raw_token, ProcessingQueueRepository.hash_lease_token(raw_token)

    @staticmethod
    def enqueue_run(
        session: Session,
        ctx: TenantContext,
        *,
        document_version_id: str,
        step_type: str = ProcessingStepType.VERIFY_OBJECT_INTEGRITY.value,
        policy_version: str = DEFAULT_PROCESSING_POLICY_VERSION,
        extractor_version: str = DEFAULT_INTEGRITY_EXTRACTOR_VERSION,
        idempotency_key: str | None = None,
        max_attempts: int = DEFAULT_PROCESSING_MAX_ATTEMPTS,
        available_at: datetime | None = None,
    ) -> ProcessingRun:
        return CaseAndDocumentRepository.create_processing_run(
            session,
            ctx,
            document_version_id=document_version_id,
            step_type=step_type,
            triggered_by_user_id=ctx.actor_user_id,
            policy_version=policy_version,
            extractor_version=extractor_version,
            idempotency_key=idempotency_key,
            status=ProcessingStatus.QUEUED.value,
            readable=False,
            readiness_state=None,
            axes_summary=None,
            started_at=None,
            finished_at=None,
            max_attempts=max_attempts,
            available_at=available_at,
        )

    @staticmethod
    def get_by_idempotency_key(
        session: Session,
        ctx: TenantContext,
        *,
        idempotency_key: str,
    ) -> ProcessingRun | None:
        apply_pg_rls_context(
            session, organization_id=ctx.organization_id, user_id=ctx.actor_user_id
        )
        return session.scalar(
            select(ProcessingRun).where(
                ProcessingRun.organization_id == ctx.organization_id,
                ProcessingRun.idempotency_key == idempotency_key,
            )
        )

    @staticmethod
    def get_active_run_for_version(
        session: Session,
        ctx: TenantContext,
        *,
        document_version_id: str,
        step_type: str | None = ProcessingStepType.VERIFY_OBJECT_INTEGRITY.value,
    ) -> ProcessingRun | None:
        apply_pg_rls_context(
            session, organization_id=ctx.organization_id, user_id=ctx.actor_user_id
        )
        filters = [
            ProcessingRun.organization_id == ctx.organization_id,
            ProcessingRun.document_version_id == document_version_id,
            ProcessingRun.status.in_(ACTIVE_PROCESSING_STATUSES),
        ]
        if step_type is not None:
            filters.append(ProcessingRun.step_type == step_type)
        return session.scalar(select(ProcessingRun).where(*filters).limit(1))

    @staticmethod
    def has_succeeded_step_for_version(
        session: Session,
        ctx: TenantContext,
        *,
        document_version_id: str,
        step_type: str,
    ) -> bool:
        apply_pg_rls_context(
            session, organization_id=ctx.organization_id, user_id=ctx.actor_user_id
        )
        row_id = session.scalar(
            select(ProcessingRun.id)
            .where(
                ProcessingRun.organization_id == ctx.organization_id,
                ProcessingRun.document_version_id == document_version_id,
                ProcessingRun.step_type == step_type,
                ProcessingRun.status == ProcessingStatus.SUCCEEDED.value,
            )
            .limit(1)
        )
        return row_id is not None

    @staticmethod
    def list_document_version_extracted_fields(
        session: Session,
        ctx: TenantContext,
        *,
        document_version_id: str,
        processing_run_id: str | None = None,
        latest_only: bool = False,
    ) -> tuple[list[tuple[ExtractedField, ProcessingRun, list[EvidenceReference]]], ProcessingRun | None]:
        apply_pg_rls_context(
            session, organization_id=ctx.organization_id, user_id=ctx.actor_user_id
        )
        latest_extract_run = session.scalar(
            select(ProcessingRun)
            .where(
                ProcessingRun.organization_id == ctx.organization_id,
                ProcessingRun.document_version_id == document_version_id,
                ProcessingRun.step_type == ProcessingStepType.EXTRACT_PDF_TEXT.value,
            )
            .order_by(ProcessingRun.created_at.desc(), ProcessingRun.id.desc())
            .limit(1)
        )
        filters = [
            ExtractedField.organization_id == ctx.organization_id,
            ExtractedField.document_version_id == document_version_id,
            ProcessingRun.organization_id == ctx.organization_id,
        ]
        if processing_run_id is not None:
            filters.append(ExtractedField.processing_run_id == processing_run_id)
        elif latest_only:
            if latest_extract_run is None:
                return [], None
            filters.append(ExtractedField.processing_run_id == latest_extract_run.id)

        rows = session.execute(
            select(ExtractedField, ProcessingRun)
            .join(ProcessingRun, ProcessingRun.id == ExtractedField.processing_run_id)
            .where(*filters)
            .order_by(
                ProcessingRun.created_at.desc(),
                ExtractedField.created_at.asc(),
                ExtractedField.field_key.asc(),
            )
        ).all()
        if not rows:
            return [], latest_extract_run

        field_ids = [row[0].id for row in rows]
        ev_rows = list(
            session.scalars(
                select(EvidenceReference)
                .where(
                    EvidenceReference.organization_id == ctx.organization_id,
                    EvidenceReference.document_version_id == document_version_id,
                    EvidenceReference.extracted_field_id.in_(field_ids),
                )
                .order_by(
                    EvidenceReference.page_number.asc(),
                    EvidenceReference.bbox_y.asc(),
                    EvidenceReference.bbox_x.asc(),
                    EvidenceReference.created_at.asc(),
                )
            )
        )
        ev_by_field: dict[str, list[EvidenceReference]] = defaultdict(list)
        for ev in ev_rows:
            ev_by_field[ev.extracted_field_id].append(ev)

        return (
            [(row[0], row[1], ev_by_field.get(row[0].id, [])) for row in rows],
            latest_extract_run,
        )

    @staticmethod
    def list_document_version_evidence_references(
        session: Session,
        ctx: TenantContext,
        *,
        document_version_id: str,
        processing_run_id: str | None = None,
        page_number: int | None = None,
        field_key: str | None = None,
        latest_only: bool = False,
    ) -> tuple[
        list[tuple[EvidenceReference, ExtractedField, ProcessingRun]],
        ProcessingRun | None,
    ]:
        apply_pg_rls_context(
            session, organization_id=ctx.organization_id, user_id=ctx.actor_user_id
        )
        latest_extract_run = session.scalar(
            select(ProcessingRun)
            .where(
                ProcessingRun.organization_id == ctx.organization_id,
                ProcessingRun.document_version_id == document_version_id,
                ProcessingRun.step_type == ProcessingStepType.EXTRACT_PDF_TEXT.value,
            )
            .order_by(ProcessingRun.created_at.desc(), ProcessingRun.id.desc())
            .limit(1)
        )
        filters = [
            EvidenceReference.organization_id == ctx.organization_id,
            EvidenceReference.document_version_id == document_version_id,
            ExtractedField.organization_id == ctx.organization_id,
            ProcessingRun.organization_id == ctx.organization_id,
        ]
        if processing_run_id is not None:
            filters.append(ProcessingRun.id == processing_run_id)
        elif latest_only:
            if latest_extract_run is None:
                return [], None
            filters.append(ProcessingRun.id == latest_extract_run.id)
        if page_number is not None:
            filters.append(EvidenceReference.page_number == page_number)
        if field_key is not None:
            filters.append(ExtractedField.field_key == field_key)

        rows = session.execute(
            select(EvidenceReference, ExtractedField, ProcessingRun)
            .join(ExtractedField, ExtractedField.id == EvidenceReference.extracted_field_id)
            .join(ProcessingRun, ProcessingRun.id == ExtractedField.processing_run_id)
            .where(*filters)
            .order_by(
                ProcessingRun.created_at.desc(),
                EvidenceReference.page_number.asc(),
                EvidenceReference.bbox_y.asc(),
                EvidenceReference.bbox_x.asc(),
                EvidenceReference.created_at.asc(),
            )
        ).all()
        return [(row[0], row[1], row[2]) for row in rows], latest_extract_run

    @staticmethod
    def get_latest_run_for_version(
        session: Session,
        ctx: TenantContext,
        *,
        document_version_id: str,
        step_type: str = ProcessingStepType.VERIFY_OBJECT_INTEGRITY.value,
    ) -> ProcessingRun | None:
        apply_pg_rls_context(
            session, organization_id=ctx.organization_id, user_id=ctx.actor_user_id
        )
        return session.scalar(
            select(ProcessingRun)
            .where(
                ProcessingRun.organization_id == ctx.organization_id,
                ProcessingRun.document_version_id == document_version_id,
                ProcessingRun.step_type == step_type,
            )
            .order_by(ProcessingRun.created_at.desc(), ProcessingRun.id.desc())
            .limit(1)
        )

    @staticmethod
    def list_case_runs(
        session: Session,
        ctx: TenantContext,
        *,
        case_id: str,
        document_version_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[tuple[ProcessingRun, str, str | None]], int]:
        apply_pg_rls_context(
            session, organization_id=ctx.organization_id, user_id=ctx.actor_user_id
        )
        filters = [
            ProcessingRun.organization_id == ctx.organization_id,
            Document.organization_id == ctx.organization_id,
            Document.case_id == case_id,
        ]
        if document_version_id is not None:
            filters.append(ProcessingRun.document_version_id == document_version_id)

        total = int(
            session.scalar(
                select(func.count(ProcessingRun.id))
                .select_from(ProcessingRun)
                .join(DocumentVersion, DocumentVersion.id == ProcessingRun.document_version_id)
                .join(Document, Document.id == DocumentVersion.document_id)
                .where(*filters)
            )
            or 0
        )
        rows = session.execute(
            select(ProcessingRun, DocumentVersion.document_id, Document.case_id)
            .join(DocumentVersion, DocumentVersion.id == ProcessingRun.document_version_id)
            .join(Document, Document.id == DocumentVersion.document_id)
            .where(*filters)
            .order_by(ProcessingRun.created_at.desc(), ProcessingRun.id.desc())
            .limit(limit)
            .offset(offset)
        ).all()
        return [(row[0], str(row[1]), row[2]) for row in rows], total

    @staticmethod
    def get_run_with_document_context(
        session: Session,
        ctx: TenantContext,
        *,
        processing_run_id: str,
    ) -> tuple[ProcessingRun, str, str | None] | None:
        apply_pg_rls_context(
            session, organization_id=ctx.organization_id, user_id=ctx.actor_user_id
        )
        row = session.execute(
            select(ProcessingRun, DocumentVersion.document_id, Document.case_id)
            .join(DocumentVersion, DocumentVersion.id == ProcessingRun.document_version_id)
            .join(Document, Document.id == DocumentVersion.document_id)
            .where(
                ProcessingRun.id == processing_run_id,
                ProcessingRun.organization_id == ctx.organization_id,
            )
        ).first()
        if row is None:
            return None
        return row[0], str(row[1]), row[2]

    @staticmethod
    def _build_worker_audit_metadata(
        *,
        organization_id: str,
        run_id: str,
        last_sequence: int,
        last_event_hash: str,
        event_type: str,
        payload_json: dict[str, Any],
    ) -> tuple[str, int, str, str, datetime, dict[str, Any]]:
        safe_payload = assert_safe_audit_payload(payload_json)
        next_seq = last_sequence + 1
        prev_hash = GENESIS_AUDIT_HASH if last_sequence == 0 else last_event_hash
        created_at = utc_now()
        event_hash = compute_audit_event_hash(
            schema_version=AUDIT_SCHEMA_VERSION,
            organization_id=organization_id,
            sequence_number=next_seq,
            actor_user_id=None,
            event_type=event_type,
            target_entity_type="processing_run",
            target_entity_id=run_id,
            created_at=created_at,
            payload_json=safe_payload,
            prev_event_hash=prev_hash,
        )
        return new_uuid(), next_seq, prev_hash, event_hash, created_at, safe_payload

    @staticmethod
    def claim_next_run(
        session: Session,
        *,
        worker_id: str,
        lease_token_hash: str,
        lease_seconds: int,
        step_type: str | None = "any",
    ) -> ClaimedProcessingRunRecord | None:
        from datetime import timedelta

        requested_step = (step_type or "any").strip() or "any"
        allowed_steps = (
            ProcessingStepType.VERIFY_OBJECT_INTEGRITY.value,
            ProcessingStepType.EXTRACT_PDF_TEXT.value,
        )
        if requested_step != "any" and requested_step not in allowed_steps:
            raise ValueError(f"Unsupported worker claim step_type: {requested_step}")

        if _is_pg_session(session):
            row = (
                session.execute(
                    text(
                        "SELECT * FROM public.jyxia_worker_claim_next_run("
                        ":p_worker_id, :p_lease_token_hash, :p_lease_seconds, :p_step_type)"
                    ),
                    {
                        "p_worker_id": worker_id,
                        "p_lease_token_hash": lease_token_hash,
                        "p_lease_seconds": lease_seconds,
                        "p_step_type": requested_step,
                    },
                )
                .mappings()
                .first()
            )
            if row is None:
                session.rollback()
                return None

            audit_id, next_seq, prev_hash, event_hash, created_at, safe_payload = (
                ProcessingQueueRepository._build_worker_audit_metadata(
                    organization_id=str(row["organization_id"]),
                    run_id=str(row["run_id"]),
                    last_sequence=int(row["last_audit_sequence"]),
                    last_event_hash=str(row["last_audit_event_hash"]),
                    event_type="processing_run.started",
                    payload_json={
                        "operation": "processing_run_started",
                        "processing_run_id": str(row["run_id"]),
                        "case_id": row["case_id"],
                        "document_id": str(row["document_id"]),
                        "document_version_id": str(row["document_version_id"]),
                        "step_type": str(row["step_type"]),
                        "extractor_version": str(row["extractor_version"]),
                        "policy_version": str(row["policy_version"]),
                        "attempt_count": int(row["attempt_count"]),
                        "max_attempts": int(row["max_attempts"]),
                        "worker_id": worker_id,
                        "triggered_by_user_id": row["triggered_by_user_id"],
                        "administrative_only": True,
                        "clinical_approval": False,
                    },
                )
            )
            session.execute(
                text(
                    "SELECT public.jyxia_worker_append_started_audit("
                    ":p_run_id, :p_worker_id, :p_lease_token_hash, :p_audit_id, "
                    ":p_audit_sequence_number, :p_audit_payload_json, "
                    ":p_audit_prev_event_hash, :p_audit_event_hash, :p_audit_created_at)"
                ),
                {
                    "p_run_id": str(row["run_id"]),
                    "p_worker_id": worker_id,
                    "p_lease_token_hash": lease_token_hash,
                    "p_audit_id": audit_id,
                    "p_audit_sequence_number": next_seq,
                    "p_audit_payload_json": json.dumps(safe_payload, ensure_ascii=True),
                    "p_audit_prev_event_hash": prev_hash,
                    "p_audit_event_hash": event_hash,
                    "p_audit_created_at": created_at,
                },
            )
            session.commit()
            return ClaimedProcessingRunRecord(
                run_id=str(row["run_id"]),
                organization_id=str(row["organization_id"]),
                document_version_id=str(row["document_version_id"]),
                document_id=str(row["document_id"]),
                case_id=row["case_id"],
                step_type=str(row["step_type"]),
                policy_version=str(row["policy_version"]),
                extractor_version=str(row["extractor_version"]),
                idempotency_key=row["idempotency_key"],
                triggered_by_user_id=row["triggered_by_user_id"],
                attempt_count=int(row["attempt_count"]),
                max_attempts=int(row["max_attempts"]),
                started_at=_as_utc(row["started_at"]),
                available_at=_as_utc(row["available_at"]),
                lease_expires_at=_as_utc(row["lease_expires_at"]),
                sha256_hex=str(row["sha256_hex"]),
                mime_type=str(row["mime_type"]),
                byte_size=int(row["byte_size"]),
                page_count=int(row["page_count"]) if row["page_count"] is not None else None,
                storage_driver=str(row["storage_driver"]),
                storage_key=str(row["storage_key"]),
                lease_token_hash=lease_token_hash,
            )

        lock_cm = _sqlite_lock_for(ProcessingQueueRepository._WORKER_QUEUE_LOCK_KEY)
        with lock_cm:
            now = utc_now()
            step_filter = (
                ProcessingRun.step_type.in_(allowed_steps)
                if requested_step == "any"
                else ProcessingRun.step_type == requested_step
            )
            candidates = list(
                session.scalars(
                    select(ProcessingRun)
                    .join(Organization, Organization.id == ProcessingRun.organization_id)
                    .where(
                        ProcessingRun.status.in_(
                            (ProcessingStatus.QUEUED.value, ProcessingStatus.RETRY_WAIT.value)
                        ),
                        step_filter,
                        Organization.status == "active",
                    )
                    .order_by(ProcessingRun.available_at.asc(), ProcessingRun.created_at.asc())
                )
            )
            chosen: ProcessingRun | None = None
            for cand in candidates:
                if _as_utc(cand.available_at) <= now and cand.attempt_count < cand.max_attempts:
                    if cand.step_type == ProcessingStepType.EXTRACT_PDF_TEXT.value:
                        integrity_ok = session.scalar(
                            select(ProcessingRun.id)
                            .where(
                                ProcessingRun.organization_id == cand.organization_id,
                                ProcessingRun.document_version_id == cand.document_version_id,
                                ProcessingRun.step_type
                                == ProcessingStepType.VERIFY_OBJECT_INTEGRITY.value,
                                ProcessingRun.status == ProcessingStatus.SUCCEEDED.value,
                            )
                            .limit(1)
                        )
                        if integrity_ok is None:
                            continue
                    chosen = cand
                    break
            if chosen is None:
                session.rollback()
                return None

            chosen.status = ProcessingStatus.RUNNING.value
            chosen.attempt_count = chosen.attempt_count + 1
            if chosen.started_at is None:
                chosen.started_at = now
            chosen.worker_id = worker_id
            chosen.lease_token_hash = lease_token_hash
            chosen.lease_expires_at = now + timedelta(seconds=lease_seconds)
            chosen.updated_at = max(now, _as_utc(chosen.created_at))
            session.flush()

            doc_row = session.execute(
                select(DocumentVersion, Document.case_id)
                .join(Document, Document.id == DocumentVersion.document_id)
                .where(
                    DocumentVersion.id == chosen.document_version_id,
                    DocumentVersion.organization_id == chosen.organization_id,
                )
            ).first()
            assert doc_row is not None
            ver: DocumentVersion = doc_row[0]
            case_id: str | None = doc_row[1]

            AuditEventRepository.append_event(
                session,
                TenantContext(
                    organization_id=chosen.organization_id,
                    actor_user_id=None,
                    source="worker",
                ),
                event_type="processing_run.started",
                target_entity_type="processing_run",
                target_entity_id=chosen.id,
                payload_json={
                    "operation": "processing_run_started",
                    "processing_run_id": chosen.id,
                    "case_id": case_id,
                    "document_id": ver.document_id,
                    "document_version_id": ver.id,
                    "step_type": chosen.step_type,
                    "extractor_version": chosen.extractor_version,
                    "policy_version": chosen.policy_version,
                    "attempt_count": chosen.attempt_count,
                    "max_attempts": chosen.max_attempts,
                    "worker_id": worker_id,
                    "triggered_by_user_id": chosen.triggered_by_user_id,
                    "administrative_only": True,
                    "clinical_approval": False,
                },
            )
            session.commit()
            return ClaimedProcessingRunRecord(
                run_id=chosen.id,
                organization_id=chosen.organization_id,
                document_version_id=chosen.document_version_id,
                document_id=ver.document_id,
                case_id=case_id,
                step_type=chosen.step_type,
                policy_version=chosen.policy_version,
                extractor_version=chosen.extractor_version,
                idempotency_key=chosen.idempotency_key,
                triggered_by_user_id=chosen.triggered_by_user_id,
                attempt_count=chosen.attempt_count,
                max_attempts=chosen.max_attempts,
                started_at=_as_utc(chosen.started_at),
                available_at=_as_utc(chosen.available_at),
                lease_expires_at=_as_utc(chosen.lease_expires_at),
                sha256_hex=ver.sha256_hex,
                mime_type=ver.mime_type,
                byte_size=ver.byte_size,
                page_count=ver.page_count,
                storage_driver=ver.storage_driver,
                storage_key=ver.storage_key,
                lease_token_hash=lease_token_hash,
            )

    @staticmethod
    def complete_run(
        session: Session,
        *,
        run_id: str,
        worker_id: str,
        lease_token_hash: str,
        result_json: dict[str, Any],
        chain_extract_extractor_version: str | None = DEFAULT_PDF_TEXT_EXTRACTOR_VERSION,
    ) -> str | None:
        safe_result = assert_safe_audit_payload(result_json)
        if _is_pg_session(session):
            try:
                ctx_row = (
                    session.execute(
                        text(
                            "SELECT * FROM public.jyxia_worker_prepare_completion_context("
                            ":p_run_id, :p_worker_id, :p_lease_token_hash)"
                        ),
                        {
                            "p_run_id": run_id,
                            "p_worker_id": worker_id,
                            "p_lease_token_hash": lease_token_hash,
                        },
                    )
                    .mappings()
                    .one()
                )
            except Exception as exc:
                session.rollback()
                if "lease invalid or expired" in str(exc).lower():
                    raise LeaseOwnershipError("Worker lease is invalid or expired.") from exc
                raise

            audit_id, next_seq, prev_hash, event_hash, created_at, safe_payload = (
                ProcessingQueueRepository._build_worker_audit_metadata(
                    organization_id=str(ctx_row["organization_id"]),
                    run_id=run_id,
                    last_sequence=int(ctx_row["last_sequence"]),
                    last_event_hash=str(ctx_row["last_event_hash"]),
                    event_type="processing_run.succeeded",
                    payload_json={
                        "operation": "processing_run_succeeded",
                        "processing_run_id": run_id,
                        "worker_id": worker_id,
                        **safe_result,
                        "administrative_only": True,
                        "clinical_approval": False,
                    },
                )
            )

            should_chain = (
                str(ctx_row["step_type"]) == ProcessingStepType.VERIFY_OBJECT_INTEGRITY.value
                and chain_extract_extractor_version is not None
                and not bool(ctx_row["has_active_extract_run"])
            )
            chained_run_id: str | None = new_uuid() if should_chain else None
            if should_chain and chained_run_id is not None:
                chain_idemp = f"chain:{run_id}:extract_pdf_text"[:128]
                chain_audit_id, chain_seq, chain_prev, chain_hash, chain_ts, chain_payload = (
                    ProcessingQueueRepository._build_worker_audit_metadata(
                        organization_id=str(ctx_row["organization_id"]),
                        run_id=chained_run_id,
                        last_sequence=next_seq,
                        last_event_hash=event_hash,
                        event_type="processing_run.queued",
                        payload_json={
                            "operation": "processing_run_queued",
                            "case_id": ctx_row["case_id"],
                            "document_id": str(ctx_row["document_id"]),
                            "document_version_id": str(ctx_row["document_version_id"]),
                            "processing_run_id": chained_run_id,
                            "parent_processing_run_id": run_id,
                            "step_type": ProcessingStepType.EXTRACT_PDF_TEXT.value,
                            "status": ProcessingStatus.QUEUED.value,
                            "policy_version": str(ctx_row["policy_version"]),
                            "extractor_version": chain_extract_extractor_version,
                            "max_attempts": int(ctx_row["max_attempts"]),
                            "administrative_only": True,
                            "clinical_approval": False,
                        },
                    )
                )
                try:
                    session.execute(
                        text(
                            "SELECT public.jyxia_worker_complete_integrity_and_chain_extract("
                            ":p_run_id, :p_worker_id, :p_lease_token_hash, :p_result_json, "
                            ":p_audit_id, :p_audit_sequence_number, :p_audit_payload_json, "
                            ":p_audit_prev_event_hash, :p_audit_event_hash, :p_audit_created_at, "
                            ":p_chain_run_id, :p_chain_extractor_version, :p_chain_idempotency_key, "
                            ":p_chain_audit_id, :p_chain_audit_sequence_number, "
                            ":p_chain_audit_payload_json, :p_chain_audit_prev_event_hash, "
                            ":p_chain_audit_event_hash, :p_chain_audit_created_at)"
                        ),
                        {
                            "p_run_id": run_id,
                            "p_worker_id": worker_id,
                            "p_lease_token_hash": lease_token_hash,
                            "p_result_json": json.dumps(safe_result, ensure_ascii=True),
                            "p_audit_id": audit_id,
                            "p_audit_sequence_number": next_seq,
                            "p_audit_payload_json": json.dumps(safe_payload, ensure_ascii=True),
                            "p_audit_prev_event_hash": prev_hash,
                            "p_audit_event_hash": event_hash,
                            "p_audit_created_at": created_at,
                            "p_chain_run_id": chained_run_id,
                            "p_chain_extractor_version": chain_extract_extractor_version,
                            "p_chain_idempotency_key": chain_idemp,
                            "p_chain_audit_id": chain_audit_id,
                            "p_chain_audit_sequence_number": chain_seq,
                            "p_chain_audit_payload_json": json.dumps(chain_payload, ensure_ascii=True),
                            "p_chain_audit_prev_event_hash": chain_prev,
                            "p_chain_audit_event_hash": chain_hash,
                            "p_chain_audit_created_at": chain_ts,
                        },
                    )
                except Exception as exc:
                    session.rollback()
                    if "lease invalid or expired" in str(exc).lower():
                        raise LeaseOwnershipError("Worker lease is invalid or expired.") from exc
                    raise
                session.commit()
                return chained_run_id

            try:
                session.execute(
                    text(
                        "SELECT public.jyxia_worker_complete_run("
                        ":p_run_id, :p_worker_id, :p_lease_token_hash, :p_result_json, "
                        ":p_audit_id, :p_audit_sequence_number, :p_audit_payload_json, "
                        ":p_audit_prev_event_hash, :p_audit_event_hash, :p_audit_created_at)"
                    ),
                    {
                        "p_run_id": run_id,
                        "p_worker_id": worker_id,
                        "p_lease_token_hash": lease_token_hash,
                        "p_result_json": json.dumps(safe_result, ensure_ascii=True),
                        "p_audit_id": audit_id,
                        "p_audit_sequence_number": next_seq,
                        "p_audit_payload_json": json.dumps(safe_payload, ensure_ascii=True),
                        "p_audit_prev_event_hash": prev_hash,
                        "p_audit_event_hash": event_hash,
                        "p_audit_created_at": created_at,
                    },
                )
            except Exception as exc:
                session.rollback()
                if "lease invalid or expired" in str(exc).lower():
                    raise LeaseOwnershipError("Worker lease is invalid or expired.") from exc
                raise
            session.commit()
            return None

        lock_cm = _sqlite_lock_for(ProcessingQueueRepository._WORKER_QUEUE_LOCK_KEY)
        with lock_cm:
            now = utc_now()
            run = session.scalar(select(ProcessingRun).where(ProcessingRun.id == run_id))
            if (
                run is None
                or run.status != ProcessingStatus.RUNNING.value
                or run.worker_id != worker_id
                or run.lease_token_hash != lease_token_hash
                or run.lease_expires_at is None
                or _as_utc(run.lease_expires_at) < now
            ):
                session.rollback()
                raise LeaseOwnershipError("Worker lease is invalid or expired.")

            run.status = ProcessingStatus.SUCCEEDED.value
            run.lease_expires_at = None
            run.lease_token_hash = None
            run.last_error_code = None
            run.last_error_detail = None
            run.result_json = safe_result
            run.readable = False
            run.readiness_state = None
            started_utc = _as_utc(run.started_at) if run.started_at is not None else now
            run.finished_at = max(now, started_utc)
            run.updated_at = max(now, _as_utc(run.created_at))
            session.flush()

            AuditEventRepository.append_event(
                session,
                TenantContext(
                    organization_id=run.organization_id,
                    actor_user_id=None,
                    source="worker",
                ),
                event_type="processing_run.succeeded",
                target_entity_type="processing_run",
                target_entity_id=run.id,
                payload_json={
                    "operation": "processing_run_succeeded",
                    "processing_run_id": run.id,
                    "worker_id": worker_id,
                    **safe_result,
                    "administrative_only": True,
                    "clinical_approval": False,
                },
            )

            chained_run_id = None
            if (
                run.step_type == ProcessingStepType.VERIFY_OBJECT_INTEGRITY.value
                and chain_extract_extractor_version is not None
            ):
                existing_active_extract = session.scalar(
                    select(ProcessingRun.id)
                    .where(
                        ProcessingRun.organization_id == run.organization_id,
                        ProcessingRun.document_version_id == run.document_version_id,
                        ProcessingRun.step_type == ProcessingStepType.EXTRACT_PDF_TEXT.value,
                        ProcessingRun.status.in_(ACTIVE_PROCESSING_STATUSES),
                    )
                    .limit(1)
                )
                if existing_active_extract is None:
                    doc_row = session.execute(
                        select(DocumentVersion.document_id, Document.case_id)
                        .join(Document, Document.id == DocumentVersion.document_id)
                        .where(
                            DocumentVersion.id == run.document_version_id,
                            DocumentVersion.organization_id == run.organization_id,
                        )
                    ).first()
                    chained_run = ProcessingRun(
                        organization_id=run.organization_id,
                        document_version_id=run.document_version_id,
                        step_type=ProcessingStepType.EXTRACT_PDF_TEXT.value,
                        triggered_by_user_id=run.triggered_by_user_id,
                        policy_version=run.policy_version,
                        extractor_version=chain_extract_extractor_version,
                        idempotency_key=f"chain:{run.id}:extract_pdf_text"[:128],
                        status=ProcessingStatus.QUEUED.value,
                        attempt_count=0,
                        max_attempts=run.max_attempts,
                        available_at=now,
                        readable=False,
                        readiness_state=None,
                        started_at=None,
                        finished_at=None,
                        created_at=now,
                        updated_at=now,
                    )
                    session.add(chained_run)
                    session.flush()
                    chained_run_id = chained_run.id

                    AuditEventRepository.append_event(
                        session,
                        TenantContext(
                            organization_id=run.organization_id,
                            actor_user_id=None,
                            source="worker",
                        ),
                        event_type="processing_run.queued",
                        target_entity_type="processing_run",
                        target_entity_id=chained_run.id,
                        payload_json={
                            "operation": "processing_run_queued",
                            "case_id": doc_row[1] if doc_row else None,
                            "document_id": str(doc_row[0]) if doc_row else None,
                            "document_version_id": run.document_version_id,
                            "processing_run_id": chained_run.id,
                            "parent_processing_run_id": run.id,
                            "step_type": chained_run.step_type,
                            "status": chained_run.status,
                            "policy_version": chained_run.policy_version,
                            "extractor_version": chained_run.extractor_version,
                            "max_attempts": chained_run.max_attempts,
                            "administrative_only": True,
                            "clinical_approval": False,
                        },
                    )

            session.commit()
            return chained_run_id

    @staticmethod
    def complete_extraction_run(
        session: Session,
        *,
        run_id: str,
        worker_id: str,
        lease_token_hash: str,
        readable: bool,
        result_json: dict[str, Any],
        extracted_fields: list[dict[str, Any]],
        audit_event_type: str,
    ) -> None:
        """Atomically persist ExtractedField, EvidenceReference, ProcessingRun completion and AuditEvent."""
        if audit_event_type not in ("processing_run.succeeded", "processing_run.abstained"):
            raise ValueError(f"Unsupported extraction audit_event_type: {audit_event_type}")

        safe_result = assert_safe_audit_payload(result_json)
        prepared_fields: list[dict[str, Any]] = []
        for field_item in extracted_fields:
            field_id = new_uuid()
            prepared_evs: list[dict[str, Any]] = []
            for ev in field_item.get("evidences", ()):
                prepared_evs.append(
                    {
                        "id": new_uuid(),
                        "page_number": int(ev["page_number"]),
                        "bbox_x": float(ev["bbox_x"]),
                        "bbox_y": float(ev["bbox_y"]),
                        "bbox_w": float(ev["bbox_w"]),
                        "bbox_h": float(ev["bbox_h"]),
                        "quote_excerpt": ev.get("quote_excerpt"),
                        "extraction_method": str(ev["extraction_method"]),
                    }
                )
            prepared_fields.append(
                {
                    "id": field_id,
                    "field_key": str(field_item["field_key"]),
                    "raw_value": field_item.get("raw_value"),
                    "normalized_value": field_item.get("normalized_value"),
                    "status": str(field_item["status"]),
                    "abstained": bool(field_item["abstained"]),
                    "metadata_json": field_item.get("metadata_json"),
                    "evidences": prepared_evs,
                }
            )

        if _is_pg_session(session):
            try:
                head = (
                    session.execute(
                        text(
                            "SELECT * FROM public.jyxia_worker_prepare_run_audit_head("
                            ":p_run_id, :p_worker_id, :p_lease_token_hash)"
                        ),
                        {
                            "p_run_id": run_id,
                            "p_worker_id": worker_id,
                            "p_lease_token_hash": lease_token_hash,
                        },
                    )
                    .mappings()
                    .one()
                )
            except Exception as exc:
                session.rollback()
                if "lease invalid or expired" in str(exc).lower():
                    raise LeaseOwnershipError("Worker lease is invalid or expired.") from exc
                raise

            audit_id, next_seq, prev_hash, event_hash, created_at, safe_payload = (
                ProcessingQueueRepository._build_worker_audit_metadata(
                    organization_id=str(head["organization_id"]),
                    run_id=run_id,
                    last_sequence=int(head["last_sequence"]),
                    last_event_hash=str(head["last_event_hash"]),
                    event_type=audit_event_type,
                    payload_json={
                        "operation": audit_event_type.replace(".", "_"),
                        "processing_run_id": run_id,
                        "worker_id": worker_id,
                        **safe_result,
                        "administrative_only": True,
                        "clinical_approval": False,
                    },
                )
            )
            try:
                session.execute(
                    text(
                        "SELECT public.jyxia_worker_complete_extraction_run("
                        ":p_run_id, :p_worker_id, :p_lease_token_hash, :p_readable, "
                        ":p_result_json, :p_fields_json, :p_audit_id, "
                        ":p_audit_sequence_number, :p_audit_event_type, "
                        ":p_audit_payload_json, :p_audit_prev_event_hash, "
                        ":p_audit_event_hash, :p_audit_created_at)"
                    ),
                    {
                        "p_run_id": run_id,
                        "p_worker_id": worker_id,
                        "p_lease_token_hash": lease_token_hash,
                        "p_readable": bool(readable),
                        "p_result_json": json.dumps(safe_result, ensure_ascii=True),
                        "p_fields_json": json.dumps(prepared_fields, ensure_ascii=True),
                        "p_audit_id": audit_id,
                        "p_audit_sequence_number": next_seq,
                        "p_audit_event_type": audit_event_type,
                        "p_audit_payload_json": json.dumps(safe_payload, ensure_ascii=True),
                        "p_audit_prev_event_hash": prev_hash,
                        "p_audit_event_hash": event_hash,
                        "p_audit_created_at": created_at,
                    },
                )
            except Exception as exc:
                session.rollback()
                if "lease invalid or expired" in str(exc).lower():
                    raise LeaseOwnershipError("Worker lease is invalid or expired.") from exc
                raise
            session.commit()
            return

        lock_cm = _sqlite_lock_for(ProcessingQueueRepository._WORKER_QUEUE_LOCK_KEY)
        with lock_cm:
            now = utc_now()
            run = session.scalar(select(ProcessingRun).where(ProcessingRun.id == run_id))
            if (
                run is None
                or run.status != ProcessingStatus.RUNNING.value
                or run.worker_id != worker_id
                or run.lease_token_hash != lease_token_hash
                or run.lease_expires_at is None
                or _as_utc(run.lease_expires_at) < now
            ):
                session.rollback()
                raise LeaseOwnershipError("Worker lease is invalid or expired.")
            if run.step_type != ProcessingStepType.EXTRACT_PDF_TEXT.value:
                session.rollback()
                raise ValueError("complete_extraction_run requires extract_pdf_text step_type.")

            integrity_ok = session.scalar(
                select(ProcessingRun.id)
                .where(
                    ProcessingRun.organization_id == run.organization_id,
                    ProcessingRun.document_version_id == run.document_version_id,
                    ProcessingRun.step_type == ProcessingStepType.VERIFY_OBJECT_INTEGRITY.value,
                    ProcessingRun.status == ProcessingStatus.SUCCEEDED.value,
                )
                .limit(1)
            )
            if integrity_ok is None:
                session.rollback()
                raise LeaseOwnershipError(
                    "Extraction prerequisite verify_object_integrity has not succeeded."
                )

            for f_item in prepared_fields:
                field_row = ExtractedField(
                    id=f_item["id"],
                    organization_id=run.organization_id,
                    processing_run_id=run.id,
                    document_version_id=run.document_version_id,
                    field_key=f_item["field_key"],
                    raw_value=f_item["raw_value"],
                    normalized_value=f_item["normalized_value"],
                    status=f_item["status"],
                    abstained=f_item["abstained"],
                    metadata_json=f_item["metadata_json"],
                    created_at=now,
                )
                session.add(field_row)
                session.flush()
                for ev in f_item["evidences"]:
                    ev_row = EvidenceReference(
                        id=ev["id"],
                        organization_id=run.organization_id,
                        extracted_field_id=field_row.id,
                        document_version_id=run.document_version_id,
                        page_number=ev["page_number"],
                        bbox_x=ev["bbox_x"],
                        bbox_y=ev["bbox_y"],
                        bbox_w=ev["bbox_w"],
                        bbox_h=ev["bbox_h"],
                        quote_excerpt=ev["quote_excerpt"],
                        extraction_method=ev["extraction_method"],
                        created_at=now,
                    )
                    session.add(ev_row)

            run.status = ProcessingStatus.SUCCEEDED.value
            run.lease_expires_at = None
            run.lease_token_hash = None
            run.last_error_code = None
            run.last_error_detail = None
            run.result_json = safe_result
            run.readable = bool(readable)
            run.readiness_state = None
            started_utc = _as_utc(run.started_at) if run.started_at is not None else now
            run.finished_at = max(now, started_utc)
            run.updated_at = max(now, _as_utc(run.created_at))
            session.flush()

            AuditEventRepository.append_event(
                session,
                TenantContext(
                    organization_id=run.organization_id,
                    actor_user_id=None,
                    source="worker",
                ),
                event_type=audit_event_type,
                target_entity_type="processing_run",
                target_entity_id=run.id,
                payload_json={
                    "operation": audit_event_type.replace(".", "_"),
                    "processing_run_id": run.id,
                    "worker_id": worker_id,
                    **safe_result,
                    "administrative_only": True,
                    "clinical_approval": False,
                },
            )
            session.commit()

    @staticmethod
    def fail_or_retry_run(
        session: Session,
        *,
        run_id: str,
        worker_id: str,
        lease_token_hash: str,
        target_status: str,
        available_at: datetime,
        error_code: str,
        error_detail: str,
        result_json: dict[str, Any] | None = None,
    ) -> None:
        if target_status not in (
            ProcessingStatus.RETRY_WAIT.value,
            ProcessingStatus.FAILED.value,
        ):
            raise ValueError(f"Unsupported worker failure target_status: {target_status}")

        sanitized_detail = sanitize_technical_error_detail(error_detail)
        safe_code = re.sub(r"[^A-Z0-9_]", "_", error_code.strip().upper())[:64] or "WORKER_ERROR"
        safe_result = assert_safe_audit_payload(result_json) if result_json is not None else None
        audit_event_type = (
            "processing_run.retry_scheduled"
            if target_status == ProcessingStatus.RETRY_WAIT.value
            else "processing_run.failed"
        )

        if _is_pg_session(session):
            try:
                head = (
                    session.execute(
                        text(
                            "SELECT * FROM public.jyxia_worker_prepare_run_audit_head("
                            ":p_run_id, :p_worker_id, :p_lease_token_hash)"
                        ),
                        {
                            "p_run_id": run_id,
                            "p_worker_id": worker_id,
                            "p_lease_token_hash": lease_token_hash,
                        },
                    )
                    .mappings()
                    .one()
                )
            except Exception as exc:
                session.rollback()
                if "lease invalid or expired" in str(exc).lower():
                    raise LeaseOwnershipError("Worker lease is invalid or expired.") from exc
                raise

            audit_id, next_seq, prev_hash, event_hash, created_at, safe_payload = (
                ProcessingQueueRepository._build_worker_audit_metadata(
                    organization_id=str(head["organization_id"]),
                    run_id=run_id,
                    last_sequence=int(head["last_sequence"]),
                    last_event_hash=str(head["last_event_hash"]),
                    event_type=audit_event_type,
                    payload_json={
                        "operation": audit_event_type.replace(".", "_"),
                        "processing_run_id": run_id,
                        "target_status": target_status,
                        "worker_id": worker_id,
                        "error_code": safe_code,
                        "error_detail": sanitized_detail,
                        "administrative_only": True,
                        "clinical_approval": False,
                    },
                )
            )
            try:
                session.execute(
                    text(
                        "SELECT public.jyxia_worker_fail_or_retry_run("
                        ":p_run_id, :p_worker_id, :p_lease_token_hash, :p_target_status, "
                        ":p_available_at, :p_error_code, :p_error_detail, :p_result_json, "
                        ":p_audit_id, :p_audit_sequence_number, :p_audit_event_type, "
                        ":p_audit_payload_json, :p_audit_prev_event_hash, :p_audit_event_hash, "
                        ":p_audit_created_at)"
                    ),
                    {
                        "p_run_id": run_id,
                        "p_worker_id": worker_id,
                        "p_lease_token_hash": lease_token_hash,
                        "p_target_status": target_status,
                        "p_available_at": available_at,
                        "p_error_code": safe_code,
                        "p_error_detail": sanitized_detail,
                        "p_result_json": (
                            json.dumps(safe_result, ensure_ascii=True)
                            if safe_result is not None
                            else None
                        ),
                        "p_audit_id": audit_id,
                        "p_audit_sequence_number": next_seq,
                        "p_audit_event_type": audit_event_type,
                        "p_audit_payload_json": json.dumps(safe_payload, ensure_ascii=True),
                        "p_audit_prev_event_hash": prev_hash,
                        "p_audit_event_hash": event_hash,
                        "p_audit_created_at": created_at,
                    },
                )
            except Exception as exc:
                session.rollback()
                if "lease invalid or expired" in str(exc).lower():
                    raise LeaseOwnershipError("Worker lease is invalid or expired.") from exc
                raise
            session.commit()
            return

        lock_cm = _sqlite_lock_for(ProcessingQueueRepository._WORKER_QUEUE_LOCK_KEY)
        with lock_cm:
            now = utc_now()
            run = session.scalar(select(ProcessingRun).where(ProcessingRun.id == run_id))
            if (
                run is None
                or run.status != ProcessingStatus.RUNNING.value
                or run.worker_id != worker_id
                or run.lease_token_hash != lease_token_hash
                or run.lease_expires_at is None
                or _as_utc(run.lease_expires_at) < now
            ):
                session.rollback()
                raise LeaseOwnershipError("Worker lease is invalid or expired.")
            if (
                target_status == ProcessingStatus.RETRY_WAIT.value
                and run.attempt_count >= run.max_attempts
            ):
                session.rollback()
                raise ValueError("Cannot schedule retry_wait when attempt_count >= max_attempts.")

            run.status = target_status
            run.available_at = _as_utc(available_at)
            run.lease_expires_at = None
            run.lease_token_hash = None
            run.last_error_code = safe_code
            run.last_error_detail = sanitized_detail
            run.result_json = safe_result
            run.readable = False
            run.readiness_state = None
            if target_status == ProcessingStatus.FAILED.value:
                started_utc = _as_utc(run.started_at) if run.started_at is not None else now
                run.finished_at = max(now, started_utc)
            else:
                run.finished_at = None
            run.updated_at = max(now, _as_utc(run.created_at))
            session.flush()

            AuditEventRepository.append_event(
                session,
                TenantContext(
                    organization_id=run.organization_id,
                    actor_user_id=None,
                    source="worker",
                ),
                event_type=audit_event_type,
                target_entity_type="processing_run",
                target_entity_id=run.id,
                payload_json={
                    "operation": audit_event_type.replace(".", "_"),
                    "processing_run_id": run.id,
                    "target_status": target_status,
                    "worker_id": worker_id,
                    "error_code": safe_code,
                    "error_detail": sanitized_detail,
                    "administrative_only": True,
                    "clinical_approval": False,
                },
            )
            session.commit()

    @staticmethod
    def reclaim_expired_leases(
        session_factory: sessionmaker[Session],
        *,
        reclaimer_worker_id: str,
        limit: int = 20,
    ) -> int:
        reclaimed = 0
        for _ in range(limit):
            session = session_factory()
            try:
                now = utc_now()
                if _is_pg_session(session):
                    row = (
                        session.execute(
                            text("SELECT * FROM public.jyxia_worker_begin_expired_reclaim()")
                        )
                        .mappings()
                        .first()
                    )
                    if row is None:
                        session.rollback()
                        return reclaimed

                    attempt_count = int(row["attempt_count"])
                    max_attempts = int(row["max_attempts"])
                    if attempt_count >= max_attempts:
                        target_status = ProcessingStatus.FAILED.value
                        audit_event_type = "processing_run.failed"
                        error_code = "LEASE_EXPIRED_MAX_ATTEMPTS"
                        error_detail = (
                            "Worker lease expired after reaching maximum configured attempts."
                        )
                    else:
                        target_status = ProcessingStatus.QUEUED.value
                        audit_event_type = "processing_run.lease_reclaimed"
                        error_code = "LEASE_EXPIRED"
                        error_detail = (
                            "Expired worker lease reclaimed for safe re-execution."
                        )

                    audit_id, next_seq, prev_hash, event_hash, created_at, safe_payload = (
                        ProcessingQueueRepository._build_worker_audit_metadata(
                            organization_id=str(row["organization_id"]),
                            run_id=str(row["run_id"]),
                            last_sequence=int(row["last_audit_sequence"]),
                            last_event_hash=str(row["last_audit_event_hash"]),
                            event_type=audit_event_type,
                            payload_json={
                                "operation": audit_event_type.replace(".", "_"),
                                "processing_run_id": str(row["run_id"]),
                                "document_version_id": str(row["document_version_id"]),
                                "step_type": str(row["step_type"]),
                                "attempt_count": attempt_count,
                                "max_attempts": max_attempts,
                                "previous_worker_id": row["previous_worker_id"],
                                "reclaimed_by_worker_id": reclaimer_worker_id,
                                "target_status": target_status,
                                "error_code": error_code,
                                "administrative_only": True,
                                "clinical_approval": False,
                            },
                        )
                    )
                    session.execute(
                        text(
                            "SELECT public.jyxia_worker_finish_expired_reclaim("
                            ":p_run_id, :p_target_status, :p_available_at, "
                            ":p_error_code, :p_error_detail, :p_audit_id, "
                            ":p_audit_sequence_number, :p_audit_event_type, "
                            ":p_audit_payload_json, :p_audit_prev_event_hash, "
                            ":p_audit_event_hash, :p_audit_created_at)"
                        ),
                        {
                            "p_run_id": str(row["run_id"]),
                            "p_target_status": target_status,
                            "p_available_at": now,
                            "p_error_code": error_code,
                            "p_error_detail": error_detail,
                            "p_audit_id": audit_id,
                            "p_audit_sequence_number": next_seq,
                            "p_audit_event_type": audit_event_type,
                            "p_audit_payload_json": json.dumps(safe_payload, ensure_ascii=True),
                            "p_audit_prev_event_hash": prev_hash,
                            "p_audit_event_hash": event_hash,
                            "p_audit_created_at": created_at,
                        },
                    )
                    session.commit()
                    reclaimed += 1
                    continue

                lock_cm = _sqlite_lock_for(ProcessingQueueRepository._WORKER_QUEUE_LOCK_KEY)
                with lock_cm:
                    running = list(
                        session.scalars(
                            select(ProcessingRun)
                            .where(
                                ProcessingRun.status == ProcessingStatus.RUNNING.value,
                                ProcessingRun.lease_expires_at.is_not(None),
                            )
                            .order_by(ProcessingRun.lease_expires_at.asc())
                        )
                    )
                    expired: ProcessingRun | None = None
                    for cand in running:
                        if cand.lease_expires_at is not None and _as_utc(cand.lease_expires_at) < now:
                            expired = cand
                            break
                    if expired is None:
                        session.rollback()
                        return reclaimed

                    prev_worker = expired.worker_id
                    if expired.attempt_count >= expired.max_attempts:
                        target_status = ProcessingStatus.FAILED.value
                        audit_event_type = "processing_run.failed"
                        error_code = "LEASE_EXPIRED_MAX_ATTEMPTS"
                        error_detail = (
                            "Worker lease expired after reaching maximum configured attempts."
                        )
                        started_utc = (
                            _as_utc(expired.started_at)
                            if expired.started_at is not None
                            else now
                        )
                        expired.finished_at = max(now, started_utc)
                    else:
                        target_status = ProcessingStatus.QUEUED.value
                        audit_event_type = "processing_run.lease_reclaimed"
                        error_code = "LEASE_EXPIRED"
                        error_detail = (
                            "Expired worker lease reclaimed for safe re-execution."
                        )
                        expired.finished_at = None

                    expired.status = target_status
                    expired.available_at = now
                    expired.lease_expires_at = None
                    expired.lease_token_hash = None
                    expired.worker_id = None
                    expired.last_error_code = error_code
                    expired.last_error_detail = error_detail
                    expired.updated_at = max(now, _as_utc(expired.created_at))
                    session.flush()

                    AuditEventRepository.append_event(
                        session,
                        TenantContext(
                            organization_id=expired.organization_id,
                            actor_user_id=None,
                            source="worker",
                        ),
                        event_type=audit_event_type,
                        target_entity_type="processing_run",
                        target_entity_id=expired.id,
                        payload_json={
                            "operation": audit_event_type.replace(".", "_"),
                            "processing_run_id": expired.id,
                            "document_version_id": expired.document_version_id,
                            "step_type": expired.step_type,
                            "attempt_count": expired.attempt_count,
                            "max_attempts": expired.max_attempts,
                            "previous_worker_id": prev_worker,
                            "reclaimed_by_worker_id": reclaimer_worker_id,
                            "target_status": target_status,
                            "error_code": error_code,
                            "administrative_only": True,
                            "clinical_approval": False,
                        },
                    )
                    session.commit()
                    reclaimed += 1
            except Exception:
                session.rollback()
                raise
            finally:
                session.close()
        return reclaimed
