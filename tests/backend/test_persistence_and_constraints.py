"""Tests for persistence across all 11 institutional models and relational constraints."""

from __future__ import annotations

import hashlib

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.constants import (
    CaseReadinessState,
    DocumentKind,
    ExtractedFieldStatus,
    HumanReviewAction,
    OrganizationRole,
    ProcessingStatus,
)
from app.models.entities import (
    AuditEvent,
    Document,
    DocumentCase,
    DocumentVersion,
    EvidenceReference,
    ExtractedField,
    HumanReview,
    Organization,
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
from app.services.institutional_service import InstitutionalService


def _sha256_hex(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def test_full_institutional_workflow_persists_with_audit_chain(db_session: Session) -> None:
    org = InstitutionalService.create_organization(
        db_session,
        OrganizationCreateInput(slug="clinica-sintetica-01", name="Clinica Sintetica Um"),
    )
    reviewer = InstitutionalService.create_user(
        db_session,
        UserCreateInput(
            email="revisor.sintetico@exemplo.invalid",
            display_name="Revisor Sintetico",
            external_subject="oidc|syn-001",
            mfa_enrolled=True,
        ),
    )
    bootstrap_ctx = TenantContext(organization_id=org.id)
    membership = InstitutionalService.assign_membership(
        db_session,
        bootstrap_ctx,
        MembershipAssignInput(user_id=reviewer.id, role=OrganizationRole.CLINICAL_REVIEWER),
    )
    assert membership.organization_id == org.id

    ctx = TenantContext(organization_id=org.id, actor_user_id=reviewer.id)
    case = InstitutionalService.create_case(
        db_session,
        ctx,
        DocumentCaseCreateInput(
            case_code="SYN-CASE-001",
            procedure_reference="Facoemulsificacao (sintetico)",
            declared_laterality="OD",
            readiness_state=CaseReadinessState.PENDENTE,
        ),
    )
    assert case.administrative_only is True
    assert case.clinical_approval is False

    doc = InstitutionalService.register_document(
        db_session,
        ctx,
        DocumentCreateInput(
            case_id=case.id,
            document_kind=DocumentKind.LAUDO,
            document_subfamily="laudo_oftalmologia",
            source_label="exemplo_sintetico_unidade_a",
        ),
    )
    version = InstitutionalService.register_document_version(
        db_session,
        ctx,
        DocumentVersionCreateInput(
            document_id=doc.id,
            version_number=1,
            sha256_hex=_sha256_hex(b"%PDF-1.4 synthetic"),
            mime_type="application/pdf",
            byte_size=18,
            page_count=1,
            storage_key=f"{org.id}/{'a' * 32}.pdf",
        ),
    )
    run = InstitutionalService.record_processing_run(
        db_session,
        ctx,
        ProcessingRunCreateInput(
            document_version_id=version.id,
            policy_version="3.2.0",
            extractor_version="pdfjs-test-1",
            status=ProcessingStatus.COMPLETED,
            readable=True,
            readiness_state=CaseReadinessState.CONFERIDA,
            axes_summary={"identidade": "ok", "lateralidade": "ok"},
        ),
    )
    field = InstitutionalService.record_extracted_field(
        db_session,
        ctx,
        ExtractedFieldCreateInput(
            processing_run_id=run.id,
            document_version_id=version.id,
            field_key="laterality",
            raw_value="OD",
            normalized_value="OD",
            status=ExtractedFieldStatus.EXTRACTED,
            abstained=False,
        ),
    )
    evidence = InstitutionalService.record_evidence_reference(
        db_session,
        ctx,
        EvidenceReferenceCreateInput(
            extracted_field_id=field.id,
            document_version_id=version.id,
            page_number=1,
            bbox_x=0.12,
            bbox_y=0.34,
            bbox_w=0.25,
            bbox_h=0.04,
            quote_excerpt="Lateralidade: OD",
        ),
    )
    review = InstitutionalService.record_human_review(
        db_session,
        ctx,
        HumanReviewCreateInput(
            document_version_id=version.id,
            reviewer_user_id=reviewer.id,
            action_type=HumanReviewAction.OBSERVED,
            field_key="laterality",
            original_value="OD",
            revised_value="OD",
            justification="Conferencia visual confirmada em exemplo sintetico.",
            evidence_reference_id=evidence.id,
            policy_version="3.2.0",
        ),
    )
    db_session.commit()

    assert db_session.get(HumanReview, review.id) is not None
    events = InstitutionalService.list_audit_events(db_session, ctx)
    assert len(events) == 6
    assert [e.sequence_number for e in events] == [1, 2, 3, 4, 5, 6]
    assert InstitutionalService.verify_audit_chain(db_session, ctx) is True


def test_relational_constraints_and_audit_immutability(db_session: Session) -> None:
    org = InstitutionalService.create_organization(
        db_session,
        OrganizationCreateInput(slug="hosp-sintetico-constraints", name="Hospital Constraints"),
    )
    user = InstitutionalService.create_user(
        db_session,
        UserCreateInput(email="audit.sintetico@exemplo.invalid", display_name="Auditor"),
    )
    ctx = TenantContext(organization_id=org.id)
    InstitutionalService.assign_membership(
        db_session, ctx, MembershipAssignInput(user_id=user.id, role=OrganizationRole.ORG_ADMIN)
    )
    case = InstitutionalService.create_case(
        db_session, ctx, DocumentCaseCreateInput(case_code="SYN-DUP-1")
    )
    doc = InstitutionalService.register_document(
        db_session, ctx, DocumentCreateInput(case_id=case.id, source_label="origem_a")
    )
    db_session.commit()

    with pytest.raises(ValueError):
        UserCreateInput(email="not-an-email", display_name="Bad")
    with pytest.raises(ValueError):
        HumanReviewCreateInput(
            document_version_id="v1",
            reviewer_user_id="u1",
            action_type=HumanReviewAction.OBSERVED,
            justification="ok",
            policy_version="3.2.0",
        )
    with pytest.raises(ValueError):
        EvidenceReferenceCreateInput(
            extracted_field_id="f1",
            document_version_id="v1",
            page_number=1,
            bbox_x=-0.1,
            bbox_y=0.2,
            bbox_w=0.1,
            bbox_h=0.1,
        )

    # Duplicate case_code inside same org must fail unique constraint
    with pytest.raises(IntegrityError):
        InstitutionalService.create_case(
            db_session, ctx, DocumentCaseCreateInput(case_code="SYN-DUP-1")
        )
    db_session.rollback()

    # Invalid clinical_approval=True violates DB check constraint even if bypassing Pydantic
    invalid_case = DocumentCase(
        organization_id=org.id,
        case_code="SYN-FORBIDDEN-APPROVAL",
        readiness_state=CaseReadinessState.CONFERIDA.value,
        administrative_only=True,
        clinical_approval=True,
    )
    db_session.add(invalid_case)
    with pytest.raises(IntegrityError):
        db_session.flush()
    db_session.rollback()

    # Invalid byte_size / sha256 fails check constraint
    bad_ver = DocumentVersion(
        organization_id=org.id,
        document_id=doc.id,
        version_number=1,
        sha256_hex="short",
        mime_type="application/pdf",
        byte_size=0,
        storage_key=f"{org.id}/{'b' * 32}.pdf",
    )
    db_session.add(bad_ver)
    with pytest.raises(IntegrityError):
        db_session.flush()
    db_session.rollback()

    # AuditEvent is strictly append-only
    audit_row = db_session.scalar(
        select(AuditEvent).where(AuditEvent.organization_id == org.id).limit(1)
    )
    assert audit_row is not None
    audit_row.event_type = "tampered"
    with pytest.raises(ValueError, match="append-only"):
        db_session.flush()
    db_session.rollback()

    audit_row = db_session.scalar(
        select(AuditEvent).where(AuditEvent.organization_id == org.id).limit(1)
    )
    db_session.delete(audit_row)
    with pytest.raises(ValueError, match="append-only"):
        db_session.flush()
    db_session.rollback()
