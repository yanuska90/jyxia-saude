"""Tests for multi-tenant isolation (DB + service + storage) and hardened synthetic storage."""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.constants import ExtractedFieldStatus, HumanReviewAction, OrganizationRole
from app.models.entities import (
    Document,
    DocumentVersion,
    EvidenceReference,
    ExtractedField,
    HumanReview,
    ProcessingRun,
)
from app.repositories.institutional import TenantScopeError
from app.schemas.tenant import (
    DocumentCaseCreateInput,
    DocumentCreateInput,
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
from app.services.storage import LocalControlledSyntheticStorage, StorageValidationError

VALID_SYNTHETIC_PDF = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF\n"
REPO_ROOT = Path(__file__).resolve().parents[2]


def test_cross_tenant_queries_and_all_composite_fks_are_blocked(
    db_session: Session, tmp_path: Path
) -> None:
    org_a = InstitutionalService.create_organization(
        db_session, OrganizationCreateInput(slug="tenant-a", name="Tenant Alpha")
    )
    org_b = InstitutionalService.create_organization(
        db_session, OrganizationCreateInput(slug="tenant-b", name="Tenant Beta")
    )
    user_a = InstitutionalService.create_user(
        db_session,
        UserCreateInput(email="op.alpha@exemplo.invalid", display_name="Operador Alpha"),
    )
    user_b = InstitutionalService.create_user(
        db_session,
        UserCreateInput(email="op.beta@exemplo.invalid", display_name="Operador Beta"),
    )
    InstitutionalService.assign_membership(
        db_session,
        TenantContext(organization_id=org_a.id),
        MembershipAssignInput(user_id=user_a.id, role=OrganizationRole.CLINICAL_REVIEWER),
    )
    InstitutionalService.assign_membership(
        db_session,
        TenantContext(organization_id=org_b.id),
        MembershipAssignInput(user_id=user_b.id, role=OrganizationRole.ORG_ADMIN),
    )

    ctx_a = TenantContext(organization_id=org_a.id, actor_user_id=user_a.id)
    ctx_b = TenantContext(organization_id=org_b.id, actor_user_id=user_b.id)

    case_a = InstitutionalService.create_case(
        db_session, ctx_a, DocumentCaseCreateInput(case_code="SHARED-SYN-01")
    )
    doc_a = InstitutionalService.register_document(
        db_session, ctx_a, DocumentCreateInput(case_id=case_a.id, source_label="fonte_alpha")
    )
    ver_a = InstitutionalService.store_and_register_document_version(
        db_session,
        ctx_a,
        storage=LocalControlledSyntheticStorage(tmp_path / "syn_store"),
        document_id=doc_a.id,
        version_number=1,
        mime_type="application/pdf",
        content=VALID_SYNTHETIC_PDF,
        original_filename="laudo-alpha.pdf",
    )
    run_a = InstitutionalService.record_processing_run(
        db_session,
        ctx_a,
        ProcessingRunCreateInput(
            document_version_id=ver_a.id, policy_version="3.2.0", extractor_version="ext-1"
        ),
    )
    field_a = InstitutionalService.record_extracted_field(
        db_session,
        ctx_a,
        ExtractedFieldCreateInput(
            processing_run_id=run_a.id,
            document_version_id=ver_a.id,
            field_key="laterality",
            raw_value="OD",
            status=ExtractedFieldStatus.EXTRACTED,
        ),
    )
    ev_a = InstitutionalService.record_evidence_reference(
        db_session,
        ctx_a,
        EvidenceReferenceCreateInput(
            extracted_field_id=field_a.id,
            document_version_id=ver_a.id,
            page_number=1,
            bbox_x=0.1,
            bbox_y=0.1,
            bbox_w=0.2,
            bbox_h=0.05,
        ),
    )
    db_session.commit()

    # Tenant B cannot read or list Tenant A records
    assert InstitutionalService.get_case(db_session, ctx_b, case_a.id) is None
    assert InstitutionalService.list_cases(db_session, ctx_b) == []
    assert InstitutionalService.get_document(db_session, ctx_b, doc_a.id) is None
    assert all(
        ev.organization_id == org_b.id
        for ev in InstitutionalService.list_audit_events(db_session, ctx_b)
    )

    # Tenant B creates own case with same case_code safely
    case_b = InstitutionalService.create_case(
        db_session, ctx_b, DocumentCaseCreateInput(case_code="SHARED-SYN-01")
    )
    assert case_b.id != case_a.id

    # Tenant B service boundary blocks cross-tenant links
    with pytest.raises(TenantScopeError):
        InstitutionalService.register_document(
            db_session, ctx_b, DocumentCreateInput(case_id=case_a.id, source_label="cross_org_try")
        )
    with pytest.raises(TenantScopeError):
        InstitutionalService.record_human_review(
            db_session,
            ctx_b,
            HumanReviewCreateInput(
                document_version_id=ver_a.id,
                reviewer_user_id=user_b.id,
                action_type=HumanReviewAction.OBSERVED,
                justification="Tentativa bloqueada entre organizacoes",
                policy_version="3.2.0",
            ),
        )

    # Raw DB composite FK enforcement across every multi-tenant table bypassing services:
    cross_attempts = [
        Document(organization_id=org_b.id, case_id=case_a.id, source_label="cross_case"),
        DocumentVersion(
            organization_id=org_b.id,
            document_id=doc_a.id,
            version_number=1,
            sha256_hex="e" * 64,
            mime_type="application/pdf",
            byte_size=40,
            storage_key=f"{org_b.id}/{'e' * 32}.pdf",
        ),
        ProcessingRun(
            organization_id=org_b.id,
            document_version_id=ver_a.id,
            policy_version="3.2.0",
            extractor_version="ext-1",
        ),
        ExtractedField(
            organization_id=org_b.id,
            processing_run_id=run_a.id,
            document_version_id=ver_a.id,
            field_key="laterality",
            status=ExtractedFieldStatus.EXTRACTED.value,
        ),
        EvidenceReference(
            organization_id=org_b.id,
            extracted_field_id=field_a.id,
            document_version_id=ver_a.id,
            page_number=1,
            bbox_x=0.1,
            bbox_y=0.1,
            bbox_w=0.1,
            bbox_h=0.1,
            extraction_method="test",
        ),
        HumanReview(
            organization_id=org_b.id,
            document_version_id=ver_a.id,
            reviewer_user_id=user_b.id,
            action_type=HumanReviewAction.OBSERVED.value,
            justification="Bypass raw ORM cross-tenant review",
            evidence_reference_id=ev_a.id,
            policy_version="3.2.0",
        ),
        HumanReview(
            organization_id=org_a.id,
            document_version_id=ver_a.id,
            reviewer_user_id=user_b.id,  # User B lacks Org A membership
            action_type=HumanReviewAction.OBSERVED.value,
            justification="Bypass raw ORM foreign reviewer",
            policy_version="3.2.0",
        ),
    ]
    for obj in cross_attempts:
        db_session.add(obj)
        with pytest.raises(IntegrityError):
            db_session.flush()
        db_session.rollback()


def test_controlled_synthetic_storage_hardening_boundaries(tmp_path: Path) -> None:
    repo_like_dir = tmp_path / "repo"
    repo_like_dir.mkdir()
    with pytest.raises(StorageValidationError):
        LocalControlledSyntheticStorage(
            repo_like_dir / "synthetic_storage",
            forbidden_parent_dir=repo_like_dir,
        )

    storage = LocalControlledSyntheticStorage(
        tmp_path / "JYXIA_LOCAL_WORK" / "synthetic_storage",
        enabled=True,
        max_bytes=65536,
        forbidden_parent_dir=repo_like_dir,
    )

    # Real synthetic PDF & PNG fixtures pass structural validation and checksum roundtrip
    real_png = (REPO_ROOT / "frontend" / "public" / "fixtures" / "imagem-ilegivel.png").read_bytes()
    stored_png = storage.store_synthetic_bytes(
        organization_id="org-alpha-1",
        mime_type="image/png",
        content=real_png,
        original_filename="imagem-ilegivel.png",
    )
    assert (
        storage.read_synthetic_bytes(
            organization_id="org-alpha-1",
            storage_key=stored_png.storage_key,
            expected_sha256_hex=stored_png.sha256_hex,
        )
        == real_png
    )

    stored_pdf = storage.store_synthetic_bytes(
        organization_id="org-alpha-1",
        mime_type="application/pdf",
        content=VALID_SYNTHETIC_PDF,
        original_filename="laudo.pdf",
    )
    assert stored_pdf.sha256_hex == hashlib.sha256(VALID_SYNTHETIC_PDF).hexdigest()

    # Wrong checksum check on read fails closed
    with pytest.raises(StorageValidationError):
        storage.read_synthetic_bytes(
            organization_id="org-alpha-1",
            storage_key=stored_pdf.storage_key,
            expected_sha256_hex="f" * 64,
        )

    # Cross-tenant read & traversal attempts blocked
    for bad_key in [
        stored_pdf.storage_key,  # queried as org-beta-2 below
        "org-beta-2/../../secret.pdf",
        "org-beta-2\\..\\secret.pdf",
        "/etc/passwd",
        "org-beta-2/\x00evil.pdf",
    ]:
        with pytest.raises(StorageValidationError):
            storage.read_synthetic_bytes(organization_id="org-beta-2", storage_key=bad_key)

    for bad_org in ["../escape", "..\\escape", "org/sub", "C:\\temp", "org\x00x", ""]:
        with pytest.raises(StorageValidationError):
            storage.store_synthetic_bytes(
                organization_id=bad_org, mime_type="application/pdf", content=VALID_SYNTHETIC_PDF
            )

    # Malicious original filenames or misleading extensions rejected
    for bad_name in ["../x.pdf", "dir/x.pdf", "win\\x.pdf", "x\n.pdf", "misleading.png"]:
        with pytest.raises(StorageValidationError):
            storage.store_synthetic_bytes(
                organization_id="org-alpha-1",
                mime_type="application/pdf",
                content=VALID_SYNTHETIC_PDF,
                original_filename=bad_name,
            )

    # Empty, spoofed, truncated PDF and corrupt PNG rejected
    for bad_mime, bad_bytes in [
        ("application/pdf", b""),
        ("application/pdf", b"NOT_A_PDF"),
        ("application/pdf", b"%PDF-1.4 truncated without trailer"),
        ("image/png", VALID_SYNTHETIC_PDF),
        ("image/png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 30),
        ("image/png", real_png[:-4]),  # truncated PNG missing terminal CRC/boundary
        ("text/plain", b"hello"),
        ("application/pdf", b"%PDF-1.4\n" + b"0" * 70000 + b"\n%%EOF"),
    ]:
        with pytest.raises(StorageValidationError):
            storage.store_synthetic_bytes(
                organization_id="org-alpha-1", mime_type=bad_mime, content=bad_bytes
            )


def test_storage_rejects_symlinks_junctions_and_cleans_up_failed_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    root_dir = tmp_path / "syn_root"
    root_dir.mkdir()
    storage = LocalControlledSyntheticStorage(root_dir, enabled=True, max_bytes=4096)

    # Symlink / Windows NTFS junction escape test
    org_escape = root_dir / "org-link"
    created_link = False
    try:
        os.symlink(outside, org_escape, target_is_directory=True)
        created_link = True
    except OSError:
        if sys.platform == "win32":
            import _winapi

            _winapi.CreateJunction(str(outside), str(org_escape))
            created_link = True

    if created_link:
        with pytest.raises(StorageValidationError):
            storage.store_synthetic_bytes(
                organization_id="org-link",
                mime_type="application/pdf",
                content=VALID_SYNTHETIC_PDF,
            )
        assert not any(outside.iterdir())

    # Mid-write atomic replacement failure cleans up temporary file with zero partial artifacts
    def _failing_replace(_src, _dst):
        raise OSError("Simulated disk failure during atomic replace")

    monkeypatch.setattr(os, "replace", _failing_replace)
    with pytest.raises(StorageValidationError, match="write failed"):
        storage.store_synthetic_bytes(
            organization_id="org-atom",
            mime_type="application/pdf",
            content=VALID_SYNTHETIC_PDF,
        )
    org_atom_dir = root_dir / "org-atom"
    assert org_atom_dir.exists()
    assert list(org_atom_dir.iterdir()) == [], "Partial temp files must be cleaned up on write error."
