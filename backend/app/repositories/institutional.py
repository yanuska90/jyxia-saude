"""Explicitly tenant-scoped repositories for organizations, cases, documents and audit chains."""

from __future__ import annotations

import hashlib
import json
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

from app.core.constants import MembershipStatus, OrganizationRole
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
    ) -> ProcessingRun:
        _require_tenant_row(session, DocumentVersion, ctx, document_version_id, "DocumentVersion")
        run = ProcessingRun(
            organization_id=ctx.organization_id,
            document_version_id=document_version_id,
            policy_version=policy_version,
            extractor_version=extractor_version,
            idempotency_key=idempotency_key,
            status=status,
            readable=readable,
            readiness_state=readiness_state,
            axes_summary=axes_summary,
            started_at=started_at or utc_now(),
            finished_at=finished_at,
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
