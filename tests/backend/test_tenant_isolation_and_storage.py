"""Tests for multi-tenant isolation (DB + service + storage) and synthetic storage."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.constants import OrganizationRole
from app.models.entities import Document
from app.repositories.institutional import TenantScopeError
from app.schemas.tenant import (
    DocumentCaseCreateInput,
    DocumentCreateInput,
    HumanReviewCreateInput,
    MembershipAssignInput,
    OrganizationCreateInput,
    TenantContext,
    UserCreateInput,
)
from app.services.institutional_service import InstitutionalService
from app.services.storage import LocalControlledSyntheticStorage, StorageValidationError


def test_cross_tenant_queries_and_composite_fks_are_blocked(
    db_session: Session, tmp_path: Path
) -> None:
    org_a = InstitutionalService.create_organization(
        db_session, OrganizationCreateInput(slug="tenant-a", name="Tenant Alpha")
    )
    org_b = InstitutionalService.create_organization(
        db_session, OrganizationCreateInput(slug="tenant-b", name="Tenant Beta")
    )
    user_b = InstitutionalService.create_user(
        db_session,
        UserCreateInput(email="op.beta@exemplo.invalid", display_name="Operador Beta"),
    )
    ctx_a = TenantContext(organization_id=org_a.id)
    ctx_b = TenantContext(organization_id=org_b.id)
    InstitutionalService.assign_membership(
        db_session, ctx_b, MembershipAssignInput(user_id=user_b.id, role=OrganizationRole.ORG_ADMIN)
    )

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
        content=b"%PDF-1.4 tenant alpha synthetic",
    )
    db_session.commit()

    # Tenant B cannot read or list Tenant A records
    assert InstitutionalService.get_case(db_session, ctx_b, case_a.id) is None
    assert InstitutionalService.list_cases(db_session, ctx_b) == []
    assert InstitutionalService.get_document(db_session, ctx_b, doc_a.id) is None
    assert all(ev.organization_id == org_b.id for ev in InstitutionalService.list_audit_events(db_session, ctx_b))

    # Same case_code in different orgs succeeds because uniqueness is scoped by organization_id
    case_b = InstitutionalService.create_case(
        db_session, ctx_b, DocumentCaseCreateInput(case_code="SHARED-SYN-01")
    )
    assert case_b.id != case_a.id

    # Tenant B cannot link a document or review to Tenant A entities via service
    with pytest.raises(TenantScopeError):
        InstitutionalService.register_document(
            db_session, ctx_b, DocumentCreateInput(case_id=case_a.id, source_label="cross_org_try")
        )
    with pytest.raises(TenantScopeError):
        InstitutionalService.record_human_review(
            db_session,
            TenantContext(organization_id=org_b.id, actor_user_id=user_b.id),
            HumanReviewCreateInput(
                document_version_id=ver_a.id,
                reviewer_user_id=user_b.id,
                action_type="observed",
                justification="Tentativa bloqueada entre organizacoes",
                policy_version="3.2.0",
            ),
        )

    # Even bypassing services directly with SQLAlchemy ORM, DB composite FK (organization_id, case_id) blocks linking!
    cross_doc = Document(
        organization_id=org_b.id,
        case_id=case_a.id,
        source_label="raw_orm_cross_org_attempt",
    )
    db_session.add(cross_doc)
    with pytest.raises(IntegrityError):
        db_session.flush()
    db_session.rollback()


def test_controlled_synthetic_storage_boundaries_and_magic_bytes(tmp_path: Path) -> None:
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
        max_bytes=1024,
        forbidden_parent_dir=repo_like_dir,
    )
    pdf_bytes = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n"
    stored = storage.store_synthetic_bytes(
        organization_id="org-alpha-1",
        mime_type="application/pdf",
        content=pdf_bytes,
    )
    assert stored.sha256_hex == hashlib.sha256(pdf_bytes).hexdigest()
    assert stored.storage_key.startswith("org-alpha-1/")
    assert storage.read_synthetic_bytes(
        organization_id="org-alpha-1", storage_key=stored.storage_key
    ) == pdf_bytes

    # Cross-tenant read blocked
    with pytest.raises(StorageValidationError):
        storage.read_synthetic_bytes(
            organization_id="org-beta-2", storage_key=stored.storage_key
        )

    # Path traversal blocked
    with pytest.raises(StorageValidationError):
        storage.store_synthetic_bytes(
            organization_id="../escape", mime_type="application/pdf", content=pdf_bytes
        )
    with pytest.raises(StorageValidationError):
        storage.read_synthetic_bytes(
            organization_id="org-alpha-1", storage_key="org-alpha-1/../../secret.pdf"
        )

    # Spoofed magic bytes and unsupported MIME blocked
    with pytest.raises(StorageValidationError):
        storage.store_synthetic_bytes(
            organization_id="org-alpha-1", mime_type="application/pdf", content=b"NOT_A_PDF"
        )
    with pytest.raises(StorageValidationError):
        storage.store_synthetic_bytes(
            organization_id="org-alpha-1", mime_type="image/png", content=pdf_bytes
        )
    with pytest.raises(StorageValidationError):
        storage.store_synthetic_bytes(
            organization_id="org-alpha-1", mime_type="text/plain", content=b"hello"
        )
    with pytest.raises(StorageValidationError):
        storage.store_synthetic_bytes(
            organization_id="org-alpha-1",
            mime_type="application/pdf",
            content=b"%PDF-1.4" + b"0" * 2048,
        )
