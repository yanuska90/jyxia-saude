"""Explicitly tenant-scoped repositories for organizations, cases, documents and audit chains."""

from __future__ import annotations

import hashlib
import json
from typing import Any, TypeVar

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.constants import MembershipStatus
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
from app.schemas.tenant import TenantContext

GENESIS_AUDIT_HASH = "0" * 64
ModelT = TypeVar("ModelT")


class TenantScopeError(LookupError):
    """Raised when a requested record is missing or outside the caller's TenantContext."""


def compute_audit_event_hash(
    *,
    organization_id: str,
    sequence_number: int,
    event_type: str,
    target_entity_type: str,
    target_entity_id: str,
    payload_json: dict[str, Any],
    prev_event_hash: str,
) -> str:
    """Compute canonical SHA-256 hash linking an organization audit event to its predecessor."""
    canonical = json.dumps(
        {
            "organization_id": organization_id,
            "sequence_number": sequence_number,
            "event_type": event_type,
            "target_entity_type": target_entity_type,
            "target_entity_id": target_entity_id,
            "payload_json": payload_json,
            "prev_event_hash": prev_event_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _require_tenant_row(
    session: Session,
    model: type[ModelT],
    ctx: TenantContext,
    record_id: str,
    label: str,
) -> ModelT:
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
        org = session.get(Organization, ctx.organization_id)
        if org is None:
            raise TenantScopeError(f"Organization '{ctx.organization_id}' does not exist.")
        user = session.get(User, user_id)
        if user is None:
            raise TenantScopeError(f"User '{user_id}' does not exist.")
        membership = OrganizationMembership(
            organization_id=ctx.organization_id,
            user_id=user_id,
            role=role,
        )
        session.add(membership)
        session.flush()
        return membership

    @staticmethod
    def get_active_membership(
        session: Session, ctx: TenantContext, *, user_id: str
    ) -> OrganizationMembership | None:
        return session.scalar(
            select(OrganizationMembership).where(
                OrganizationMembership.organization_id == ctx.organization_id,
                OrganizationMembership.user_id == user_id,
                OrganizationMembership.status == MembershipStatus.ACTIVE.value,
            )
        )

    @staticmethod
    def list_memberships(session: Session, ctx: TenantContext) -> list[OrganizationMembership]:
        return list(
            session.scalars(
                select(OrganizationMembership)
                .where(OrganizationMembership.organization_id == ctx.organization_id)
                .order_by(OrganizationMembership.created_at.asc())
            )
        )


class CaseAndDocumentRepository:
    """Tenant-scoped persistence for cases, documents, versions, runs, fields, evidence and reviews."""

    @staticmethod
    def create_case(
        session: Session,
        ctx: TenantContext,
        *,
        case_code: str,
        procedure_reference: str | None,
        declared_laterality: str | None,
        readiness_state: str,
    ) -> DocumentCase:
        case = DocumentCase(
            organization_id=ctx.organization_id,
            case_code=case_code,
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
        return session.scalar(
            select(DocumentCase).where(
                DocumentCase.id == case_id,
                DocumentCase.organization_id == ctx.organization_id,
            )
        )

    @staticmethod
    def list_cases(session: Session, ctx: TenantContext) -> list[DocumentCase]:
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
    ) -> Document:
        if case_id is not None:
            _require_tenant_row(session, DocumentCase, ctx, case_id, "DocumentCase")
        document = Document(
            organization_id=ctx.organization_id,
            case_id=case_id,
            document_kind=document_kind,
            document_subfamily=document_subfamily,
            source_label=source_label,
            quarantined=quarantined,
            quarantine_reason=quarantine_reason,
        )
        session.add(document)
        session.flush()
        return document

    @staticmethod
    def get_document(session: Session, ctx: TenantContext, document_id: str) -> Document | None:
        return session.scalar(
            select(Document).where(
                Document.id == document_id,
                Document.organization_id == ctx.organization_id,
            )
        )

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
            storage_driver=storage_driver,
            storage_key=storage_key,
        )
        session.add(version)
        session.flush()
        return version

    @staticmethod
    def get_document_version(
        session: Session, ctx: TenantContext, version_id: str
    ) -> DocumentVersion | None:
        return session.scalar(
            select(DocumentVersion).where(
                DocumentVersion.id == version_id,
                DocumentVersion.organization_id == ctx.organization_id,
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
        status: str,
        readable: bool,
        readiness_state: str | None,
        axes_summary: dict[str, Any] | None,
    ) -> ProcessingRun:
        _require_tenant_row(session, DocumentVersion, ctx, document_version_id, "DocumentVersion")
        run = ProcessingRun(
            organization_id=ctx.organization_id,
            document_version_id=document_version_id,
            policy_version=policy_version,
            extractor_version=extractor_version,
            status=status,
            readable=readable,
            readiness_state=readiness_state,
            axes_summary=axes_summary,
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
    """Append-only organization-scoped audit ledger."""

    @staticmethod
    def append_event(
        session: Session,
        ctx: TenantContext,
        *,
        event_type: str,
        target_entity_type: str,
        target_entity_id: str,
        payload_json: dict[str, Any],
    ) -> AuditEvent:
        latest = session.scalar(
            select(AuditEvent)
            .where(AuditEvent.organization_id == ctx.organization_id)
            .order_by(AuditEvent.sequence_number.desc())
            .limit(1)
        )
        next_seq = 1 if latest is None else latest.sequence_number + 1
        prev_hash = GENESIS_AUDIT_HASH if latest is None else latest.event_hash
        event_hash = compute_audit_event_hash(
            organization_id=ctx.organization_id,
            sequence_number=next_seq,
            event_type=event_type,
            target_entity_type=target_entity_type,
            target_entity_id=target_entity_id,
            payload_json=payload_json,
            prev_event_hash=prev_hash,
        )
        row = AuditEvent(
            organization_id=ctx.organization_id,
            sequence_number=next_seq,
            actor_user_id=ctx.actor_user_id,
            event_type=event_type,
            target_entity_type=target_entity_type,
            target_entity_id=target_entity_id,
            payload_json=payload_json,
            prev_event_hash=prev_hash,
            event_hash=event_hash,
        )
        session.add(row)
        session.flush()
        return row

    @staticmethod
    def list_events(session: Session, ctx: TenantContext) -> list[AuditEvent]:
        return list(
            session.scalars(
                select(AuditEvent)
                .where(AuditEvent.organization_id == ctx.organization_id)
                .order_by(AuditEvent.sequence_number.asc())
            )
        )

    @staticmethod
    def count_events(session: Session, ctx: TenantContext) -> int:
        return int(
            session.scalar(
                select(func.count(AuditEvent.id)).where(
                    AuditEvent.organization_id == ctx.organization_id
                )
            )
            or 0
        )

    @staticmethod
    def verify_chain(session: Session, ctx: TenantContext) -> bool:
        events = AuditEventRepository.list_events(session, ctx)
        expected_prev = GENESIS_AUDIT_HASH
        for idx, ev in enumerate(events, start=1):
            if ev.sequence_number != idx or ev.prev_event_hash != expected_prev:
                return False
            recomputed = compute_audit_event_hash(
                organization_id=ctx.organization_id,
                sequence_number=ev.sequence_number,
                event_type=ev.event_type,
                target_entity_type=ev.target_entity_type,
                target_entity_id=ev.target_entity_id,
                payload_json=ev.payload_json,
                prev_event_hash=ev.prev_event_hash,
            )
            if ev.event_hash != recomputed:
                return False
            expected_prev = ev.event_hash
        return True
