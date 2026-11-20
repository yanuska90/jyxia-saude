"""Tests for persistence across all 11 institutional models and hardened DB constraints."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

import pytest
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
    Document,
    DocumentCase,
    DocumentVersion,
    EvidenceReference,
    ExtractedField,
    HumanReview,
    ProcessingRun,
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
            external_reference="EXT-REF-001",
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
    pdf_bytes = b"%PDF-1.4\n% synthetic\n%%EOF\n"
    version = InstitutionalService.register_document_version(
        db_session,
        ctx,
        DocumentVersionCreateInput(
            document_id=doc.id,
            version_number=1,
            sha256_hex=_sha256_hex(pdf_bytes),
            mime_type="application/pdf",
            byte_size=len(pdf_bytes),
            page_count=1,
            original_filename="laudo-sintetico.pdf",
            storage_key=f"{org.id}/{'a' * 32}.pdf",
        ),
    )
    now = datetime.now(timezone.utc)
    run = InstitutionalService.record_processing_run(
        db_session,
        ctx,
        ProcessingRunCreateInput(
            document_version_id=version.id,
            policy_version="3.2.0",
            extractor_version="pdfjs-test-1",
            idempotency_key="idem-syn-case-001-v1",
            status=ProcessingStatus.COMPLETED,
            readable=True,
            readiness_state=CaseReadinessState.CONFERIDA,
            axes_summary={"identidade": "ok", "lateralidade": "ok"},
            started_at=now,
            finished_at=now + timedelta(seconds=1),
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


def test_relational_integrity_and_same_org_cross_version_blocking(db_session: Session) -> None:
    org = InstitutionalService.create_organization(
        db_session,
        OrganizationCreateInput(slug="hosp-sintetico-constraints", name="Hospital Constraints"),
    )
    user = InstitutionalService.create_user(
        db_session,
        UserCreateInput(email="audit.sintetico@exemplo.invalid", display_name="Auditor"),
    )
    outsider = InstitutionalService.create_user(
        db_session,
        UserCreateInput(email="outsider@exemplo.invalid", display_name="Sem Vinculo"),
    )
    ctx = TenantContext(organization_id=org.id)
    InstitutionalService.assign_membership(
        db_session, ctx, MembershipAssignInput(user_id=user.id, role=OrganizationRole.ORG_ADMIN)
    )
    case1 = InstitutionalService.create_case(
        db_session, ctx, DocumentCaseCreateInput(case_code="SYN-DUP-1", external_reference="EXT-1")
    )
    # Multiple nullable external_reference values are allowed in same org
    case2 = InstitutionalService.create_case(
        db_session, ctx, DocumentCaseCreateInput(case_code="SYN-DUP-2", external_reference=None)
    )
    case3 = InstitutionalService.create_case(
        db_session, ctx, DocumentCaseCreateInput(case_code="SYN-DUP-3", external_reference=None)
    )
    assert case2.id != case3.id

    doc1 = InstitutionalService.register_document(
        db_session, ctx, DocumentCreateInput(case_id=case1.id, source_label="origem_a")
    )
    doc2 = InstitutionalService.register_document(
        db_session, ctx, DocumentCreateInput(case_id=case2.id, source_label="origem_b")
    )
    v1 = InstitutionalService.register_document_version(
        db_session,
        ctx,
        DocumentVersionCreateInput(
            document_id=doc1.id,
            version_number=1,
            sha256_hex="1" * 64,
            mime_type="application/pdf",
            byte_size=100,
            storage_key=f"{org.id}/{'1' * 32}.pdf",
        ),
    )
    v2 = InstitutionalService.register_document_version(
        db_session,
        ctx,
        DocumentVersionCreateInput(
            document_id=doc2.id,
            version_number=1,
            sha256_hex="2" * 64,
            mime_type="application/pdf",
            byte_size=100,
            storage_key=f"{org.id}/{'2' * 32}.pdf",
        ),
    )
    run_v1 = InstitutionalService.record_processing_run(
        db_session,
        ctx,
        ProcessingRunCreateInput(
            document_version_id=v1.id,
            policy_version="3.2.0",
            extractor_version="ext-1",
            idempotency_key="idem-key-1",
        ),
    )
    field_v1 = InstitutionalService.record_extracted_field(
        db_session,
        ctx,
        ExtractedFieldCreateInput(
            processing_run_id=run_v1.id,
            document_version_id=v1.id,
            field_key="procedure",
            raw_value="Facoemulsificacao",
            status=ExtractedFieldStatus.EXTRACTED,
        ),
    )
    ev_v1 = InstitutionalService.record_evidence_reference(
        db_session,
        ctx,
        EvidenceReferenceCreateInput(
            extracted_field_id=field_v1.id,
            document_version_id=v1.id,
            page_number=1,
            bbox_x=0.1,
            bbox_y=0.1,
            bbox_w=0.2,
            bbox_h=0.1,
        ),
    )
    db_session.commit()

    # Pydantic validation rejections
    with pytest.raises(ValueError):
        UserCreateInput(email="not-an-email", display_name="Bad")
    with pytest.raises(ValueError):
        HumanReviewCreateInput(
            document_version_id=v1.id,
            reviewer_user_id=user.id,
            action_type=HumanReviewAction.OBSERVED,
            justification="ok",
            policy_version="3.2.0",
        )
    with pytest.raises(ValueError):
        EvidenceReferenceCreateInput(
            extracted_field_id=field_v1.id,
            document_version_id=v1.id,
            page_number=1,
            bbox_x=0.75,
            bbox_y=0.2,
            bbox_w=0.5,
            bbox_h=0.1,
        )

    # Duplicate non-null external_reference inside same org fails partial unique index
    with pytest.raises(IntegrityError):
        InstitutionalService.create_case(
            db_session, ctx, DocumentCaseCreateInput(case_code="SYN-DUP-EXT", external_reference="EXT-1")
        )
    db_session.rollback()

    # Duplicate idempotency_key inside same org fails unique constraint
    with pytest.raises(IntegrityError):
        InstitutionalService.record_processing_run(
            db_session,
            ctx,
            ProcessingRunCreateInput(
                document_version_id=v2.id,
                policy_version="3.2.0",
                extractor_version="ext-1",
                idempotency_key="idem-key-1",
            ),
        )
    db_session.rollback()

    # Raw DB constraint tests bypassing Pydantic
    now = datetime.now(timezone.utc)
    raw_failures = [
        DocumentCase(
            organization_id=org.id,
            case_code="SYN-FORBIDDEN-APPROVAL",
            readiness_state=CaseReadinessState.CONFERIDA.value,
            administrative_only=True,
            clinical_approval=True,
        ),
        Document(
            organization_id=org.id,
            source_label="orig",
            discarded_at=now,
            discard_reason="no",  # < 3 chars
        ),
        DocumentVersion(
            organization_id=org.id,
            document_id=doc1.id,
            version_number=2,
            sha256_hex="3" * 64,
            mime_type="application/pdf",
            byte_size=10,
            storage_key=f"{org.id}/{'3' * 32}.pdf",
            superseded_by_version_id=v2.id,  # Version of OTHER document!
        ),
        DocumentVersion(
            organization_id=org.id,
            document_id=doc1.id,
            version_number=3,
            sha256_hex="A" * 64,  # uppercase sha256 rejected
            mime_type="application/pdf",
            byte_size=10,
            storage_key=f"{org.id}/{'4' * 32}.pdf",
        ),
        ProcessingRun(
            organization_id=org.id,
            document_version_id=v1.id,
            policy_version="3.2.0",
            extractor_version="e1",
            started_at=now,
            finished_at=now - timedelta(seconds=5),
        ),
        ExtractedField(
            organization_id=org.id,
            processing_run_id=run_v1.id,
            document_version_id=v2.id,  # Mismatched version vs run!
            field_key="laterality",
            status=ExtractedFieldStatus.EXTRACTED.value,
            abstained=False,
        ),
        ExtractedField(
            organization_id=org.id,
            processing_run_id=run_v1.id,
            document_version_id=v1.id,
            field_key="laterality",
            status=ExtractedFieldStatus.ABSTAINED.value,
            abstained=False,  # Coherent abstained flag check!
        ),
        EvidenceReference(
            organization_id=org.id,
            extracted_field_id=field_v1.id,
            document_version_id=v2.id,  # Mismatched version vs field!
            page_number=1,
            bbox_x=0.1,
            bbox_y=0.1,
            bbox_w=0.1,
            bbox_h=0.1,
            extraction_method="test",
        ),
        EvidenceReference(
            organization_id=org.id,
            extracted_field_id=field_v1.id,
            document_version_id=v1.id,
            page_number=1,
            bbox_x=0.8,
            bbox_y=0.1,
            bbox_w=0.4,  # x + w > 1.0!
            bbox_h=0.1,
            extraction_method="test",
        ),
        HumanReview(
            organization_id=org.id,
            document_version_id=v1.id,
            reviewer_user_id=outsider.id,  # User lacks org membership!
            action_type=HumanReviewAction.OBSERVED.value,
            justification="Revisor externo sem vinculo na org",
            policy_version="3.2.0",
        ),
        HumanReview(
            organization_id=org.id,
            document_version_id=v2.id,
            reviewer_user_id=user.id,
            action_type=HumanReviewAction.OBSERVED.value,
            justification="Evidencia cruzada entre versoes",
            evidence_reference_id=ev_v1.id,  # Evidencia de v1 em review de v2!
            policy_version="3.2.0",
        ),
    ]
    for bad_obj in raw_failures:
        db_session.add(bad_obj)
        with pytest.raises(IntegrityError):
            db_session.flush()
        db_session.rollback()
