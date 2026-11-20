"""Internal domain services enforcing tenant boundaries and append-only audit logs."""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from app.core.logging import LOGGER_NAME, build_safe_log_extra
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
    AuditEventRepository,
    CaseAndDocumentRepository,
    OrganizationRepository,
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
from app.services.storage import DocumentStoragePort

logger = logging.getLogger(LOGGER_NAME)


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
    def register_document_version(
        session: Session, ctx: TenantContext, payload: DocumentVersionCreateInput
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
    ) -> DocumentVersion:
        stored = storage.store_synthetic_bytes(
            organization_id=ctx.organization_id,
            mime_type=mime_type,
            content=content,
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
                storage_key=stored.storage_key,
            ),
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
            status=payload.status.value,
            readable=payload.readable,
            readiness_state=payload.readiness_state.value if payload.readiness_state else None,
            axes_summary=payload.axes_summary,
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
        # Do not log raw field text values into structured application logs.
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
    def list_audit_events(session: Session, ctx: TenantContext) -> list[AuditEvent]:
        return AuditEventRepository.list_events(session, ctx)

    @staticmethod
    def verify_audit_chain(session: Session, ctx: TenantContext) -> bool:
        return AuditEventRepository.verify_chain(session, ctx)
