"""Tests for Alembic incremental upgrade/downgrade lifecycle and PostgreSQL DDL compatibility."""

from __future__ import annotations

import os
from pathlib import Path

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
import pytest
from sqlalchemy import CheckConstraint, inspect, text
from sqlalchemy.dialects import postgresql
from sqlalchemy.exc import IntegrityError
from sqlalchemy.schema import CreateTable

from app.core.constants import ExternalIdentityStatus, MembershipStatus, OrganizationRole
from app.db.base import Base
from app.db.session import create_db_engine, create_session_factory
from app.repositories.identity import IdentityAndSessionRepository
from app.repositories.institutional import OrganizationRepository
from app.schemas.tenant import TenantContext

EXPECTED_TABLES = {
    "organizations",
    "users",
    "organization_memberships",
    "document_cases",
    "documents",
    "document_versions",
    "processing_runs",
    "extracted_fields",
    "evidence_references",
    "human_reviews",
    "audit_events",
    "external_identities",
    "oidc_auth_states",
    "auth_sessions",
    "security_auth_events",
}


def test_alembic_incremental_upgrade_downgrade_and_reupgrade_clean(
    tmp_path: Path, alembic_config_builder
) -> None:
    external_url = (
        os.environ.get("JYXIA_TEST_MIGRATION_DATABASE_URL", "").strip()
        or os.environ.get("JYXIA_TEST_DATABASE_URL", "").strip()
    )
    url = external_url or f"sqlite:///{(tmp_path / 'migration_cycle.sqlite3').as_posix()}"
    cfg = alembic_config_builder(url)
    engine = create_db_engine(url)

    try:
        if external_url:
            command.downgrade(cfg, "base")
        command.upgrade(cfg, "head")

        with engine.connect() as conn:
            inspector = inspect(conn)
            tables_after_up = set(inspector.get_table_names())
            assert EXPECTED_TABLES.issubset(tables_after_up)
            case_cols = {c["name"] for c in inspector.get_columns("document_cases")}
            assert "external_reference" in case_cols
            ver_cols = {c["name"] for c in inspector.get_columns("document_versions")}
            assert "original_filename" in ver_cols
            audit_cols = {c["name"] for c in inspector.get_columns("audit_events")}
            assert "schema_version" in audit_cols
            run_cols = {c["name"] for c in inspector.get_columns("processing_runs")}
            assert {"step_type", "attempt_count", "max_attempts", "available_at", "lease_token_hash"}.issubset(
                run_cols
            )

            mc = MigrationContext.configure(conn)
            diffs = compare_metadata(mc, Base.metadata)
            assert diffs == [], f"Unexpected metadata drift between models and migration: {diffs}"

        # Incremental downgrade 0007 -> 0006
        command.downgrade(cfg, "20261122_0006")
        with engine.connect() as conn:
            ver_0006 = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
            assert ver_0006 == "20261122_0006"
            assert "step_type" not in {
                c["name"] for c in inspect(conn).get_columns("processing_runs")
            }

        # Incremental downgrade 0006 -> 0005
        command.downgrade(cfg, "20261122_0005")
        with engine.connect() as conn:
            ver_0005 = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
            assert ver_0005 == "20261122_0005"

        # Incremental downgrade 0005 -> 0004
        command.downgrade(cfg, "20261121_0004")
        with engine.connect() as conn:
            ver_0004 = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
            assert ver_0004 == "20261121_0004"

        # Incremental downgrade 0004 -> 0003
        command.downgrade(cfg, "20261120_0003")
        with engine.connect() as conn:
            ver_0003 = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
            assert ver_0003 == "20261120_0003"
            assert EXPECTED_TABLES.issubset(set(inspect(conn).get_table_names()))

        # Incremental downgrade 0003 -> 0002
        command.downgrade(cfg, "20261120_0002")
        with engine.connect() as conn:
            tables_0002 = set(inspect(conn).get_table_names())
            assert "external_identities" not in tables_0002
            assert "security_auth_events" not in tables_0002
            assert "external_reference" in {
                c["name"] for c in inspect(conn).get_columns("document_cases")
            }

        # Incremental downgrade 0002 -> 0001
        command.downgrade(cfg, "20261120_0001")
        with engine.connect() as conn:
            inspector = inspect(conn)
            assert "external_reference" not in {
                c["name"] for c in inspector.get_columns("document_cases")
            }
            assert "schema_version" not in {
                c["name"] for c in inspector.get_columns("audit_events")
            }

        # Full downgrade -> base
        command.downgrade(cfg, "base")
        with engine.connect() as conn:
            tables_after_down = set(inspect(conn).get_table_names())
            assert not (EXPECTED_TABLES & tables_after_down)

        # Clean re-upgrade from empty DB to head (0004)
        command.upgrade(cfg, "head")
        with engine.connect() as conn:
            assert EXPECTED_TABLES.issubset(set(inspect(conn).get_table_names()))
            diffs = compare_metadata(MigrationContext.configure(conn), Base.metadata)
            assert diffs == []
    finally:
        engine.dispose()


def test_populated_db_upgrade_0003_to_0004_and_enum_check_constraint_parity(
    tmp_path: Path, alembic_config_builder
) -> None:
    external_url = (
        os.environ.get("JYXIA_TEST_MIGRATION_DATABASE_URL", "").strip()
        or os.environ.get("JYXIA_TEST_DATABASE_URL", "").strip()
    )
    url = external_url or f"sqlite:///{(tmp_path / 'populated_migration.sqlite3').as_posix()}"
    cfg = alembic_config_builder(url)
    engine = create_db_engine(url)
    factory = create_session_factory(engine)

    try:
        if external_url:
            command.downgrade(cfg, "base")
        command.upgrade(cfg, "20261120_0003")

        # Populate synthetic records at 0003 including 'suspended' ExternalIdentity & 'clinical_reviewer'
        session = factory()
        try:
            org = OrganizationRepository.create_organization(
                session, slug="mig-pop-org", name="Populated Migration Org"
            )
            u_active = OrganizationRepository.create_user(
                session, email="active.mig@jyxia.local", display_name="Active Mig", mfa_enrolled=True
            )
            u_susp = OrganizationRepository.create_user(
                session, email="susp.mig@jyxia.local", display_name="Susp Mig", mfa_enrolled=True
            )
            from app.models.entities import OrganizationMembership as OrgMembershipModel

            m_active = OrgMembershipModel(
                organization_id=org.id,
                user_id=u_active.id,
                role="clinical_reviewer",
                status=MembershipStatus.ACTIVE.value,
            )
            session.add(m_active)
            session.flush()
            m_susp = OrganizationRepository.assign_membership(
                session,
                TenantContext(organization_id=org.id),
                user_id=u_susp.id,
                role=OrganizationRole.READ_ONLY.value,
            )
            m_susp.status = MembershipStatus.SUSPENDED.value
            ext_active = IdentityAndSessionRepository.bind_external_identity(
                session,
                user_id=u_active.id,
                issuer="https://idp.jyxia.local/realms/mig",
                subject="sub-mig-active",
                status=ExternalIdentityStatus.ACTIVE.value,
            )
            ext_susp = IdentityAndSessionRepository.bind_external_identity(
                session,
                user_id=u_susp.id,
                issuer="https://idp.jyxia.local/realms/mig",
                subject="sub-mig-suspended",
                status=ExternalIdentityStatus.SUSPENDED.value,
            )
            ext_rev = IdentityAndSessionRepository.bind_external_identity(
                session,
                user_id=u_susp.id,
                issuer="https://idp.jyxia.local/realms/mig-2",
                subject="sub-mig-revoked",
                status=ExternalIdentityStatus.REVOKED.value,
            )
            session.commit()
            ext_active_id, ext_susp_id, ext_rev_id = ext_active.id, ext_susp.id, ext_rev.id
            m_active_id = m_active.id
        finally:
            session.close()

        # Upgrade populated DB from 0003 -> 0004 -> 0005 (head) and verify zero data loss & role migration
        command.upgrade(cfg, "head")
        session_verify = factory()
        try:
            from app.models.entities import ExternalIdentity, OrganizationMembership

            assert session_verify.get(ExternalIdentity, ext_active_id).status == "active"  # type: ignore[union-attr]
            assert session_verify.get(ExternalIdentity, ext_susp_id).status == "suspended"  # type: ignore[union-attr]
            assert session_verify.get(ExternalIdentity, ext_rev_id).status == "revoked"  # type: ignore[union-attr]
            assert session_verify.get(OrganizationMembership, m_active_id).role == "document_reviewer"  # type: ignore[union-attr]

            # Invalid ExternalIdentity status must be rejected by DB CheckConstraint
            with pytest.raises(IntegrityError):
                IdentityAndSessionRepository.bind_external_identity(
                    session_verify,
                    user_id=u_active.id,
                    issuer="https://idp.jyxia.local/realms/mig",
                    subject="sub-mig-invalid",
                    status="invalid_status_val",
                )
            session_verify.rollback()
        finally:
            session_verify.close()

        # Populate a queued ProcessingRun at head (0007), then verify downgrade 0007 -> 0006 -> 0007
        session_run = factory()
        try:
            from app.core.constants import DocumentKind, ProcessingStatus
            from app.models.entities import Document, DocumentCase, DocumentVersion, ProcessingRun

            case_mig = DocumentCase(
                organization_id=org.id,
                case_code="MIG-CASE-01",
                procedure_reference="Migration Populated Run Case",
                created_by_user_id=u_active.id,
            )
            session_run.add(case_mig)
            session_run.flush()
            doc_mig = Document(
                organization_id=org.id,
                case_id=case_mig.id,
                document_kind=DocumentKind.LAUDO.value,
                source_label="migration_check",
                created_by_user_id=u_active.id,
            )
            session_run.add(doc_mig)
            session_run.flush()
            ver_mig = DocumentVersion(
                organization_id=org.id,
                document_id=doc_mig.id,
                version_number=1,
                sha256_hex="a" * 64,
                mime_type="application/pdf",
                byte_size=128,
                storage_key=f"{org.id}/synthetic/mig.pdf",
                created_by_user_id=u_active.id,
            )
            session_run.add(ver_mig)
            session_run.flush()
            queued_run = ProcessingRun(
                organization_id=org.id,
                document_version_id=ver_mig.id,
                policy_version="3.3.2",
                extractor_version="integrity-verifier-3.3.2",
                status=ProcessingStatus.QUEUED.value,
                started_at=None,
            )
            session_run.add(queued_run)
            session_run.commit()
            queued_run_id = queued_run.id
        finally:
            session_run.close()

        command.downgrade(cfg, "20261122_0006")
        session_down = factory()
        try:
            migrated_row = session_down.execute(
                text("SELECT status, started_at FROM processing_runs WHERE id = :id"),
                {"id": queued_run_id},
            ).first()
            assert migrated_row is not None
            assert migrated_row[0] == "pending"
            assert migrated_row[1] is not None
        finally:
            session_down.close()

        command.upgrade(cfg, "head")
        session_reup = factory()
        try:
            from app.models.entities import ProcessingRun as ReupProcessingRun

            reup_run = session_reup.get(ReupProcessingRun, queued_run_id)
            assert reup_run is not None
            assert reup_run.step_type == "verify_object_integrity"
            assert reup_run.attempt_count == 0
            assert reup_run.max_attempts == 5
        finally:
            session_reup.close()

        # Downgrade 0005 -> 0004 -> 0003 on populated DB preserves all records, then re-upgrade to head
        command.downgrade(cfg, "20261121_0004")
        command.downgrade(cfg, "20261120_0003")
        command.upgrade(cfg, "head")

        # Verify CheckConstraint parity between SQLAlchemy Base.metadata and migrated database
        with engine.connect() as conn:
            for table_name, table in Base.metadata.tables.items():
                model_checks = [
                    str(c.sqltext.text)
                    for c in table.constraints
                    if isinstance(c, CheckConstraint)
                ]
                if engine.dialect.name == "sqlite":
                    ddl = conn.execute(
                        text("SELECT sql FROM sqlite_master WHERE type='table' AND name=:t"),
                        {"t": table_name},
                    ).scalar()
                    assert ddl is not None
                    for expected_sql in model_checks:
                        assert expected_sql in ddl, (
                            f"CheckConstraint drift on table {table_name}: {expected_sql!r} not in {ddl!r}"
                        )
                else:
                    pg_checks = (
                        conn.execute(
                            text(
                                "SELECT pg_get_constraintdef(c.oid) "
                                "FROM pg_constraint c "
                                "JOIN pg_class t ON c.conrelid = t.oid "
                                "WHERE t.relname = :t AND c.contype = 'c'"
                            ),
                            {"t": table_name},
                        )
                        .scalars()
                        .all()
                    )
                    assert len(pg_checks) == len(model_checks), (
                        f"CheckConstraint count mismatch on {table_name}: PG={pg_checks} vs Model={model_checks}"
                    )
            assert [e.value for e in ExternalIdentityStatus] == ["active", "suspended", "revoked"]
    finally:
        engine.dispose()


def test_postgresql_dialect_ddl_compiles_for_all_hardened_tables() -> None:
    pg_dialect = postgresql.dialect()
    compiled_tables: dict[str, str] = {}
    for table_name, table in Base.metadata.tables.items():
        ddl = str(CreateTable(table).compile(dialect=pg_dialect))
        compiled_tables[table_name] = ddl

    assert set(compiled_tables) == EXPECTED_TABLES
    assert "JSONB" in compiled_tables["processing_runs"]
    assert "JSONB" in compiled_tables["audit_events"]
    assert "TIMESTAMP WITH TIME ZONE" in compiled_tables["document_cases"]
    assert "fk_document_cases_org_creator" in compiled_tables["document_cases"]
    assert "fk_doc_versions_org_doc_supersede" in compiled_tables["document_versions"]
    assert "fk_extracted_fields_org_ver_run" in compiled_tables["extracted_fields"]
    assert "fk_evidence_refs_org_ver_field" in compiled_tables["evidence_references"]
    assert "bbox_x_w_within_page" in compiled_tables["evidence_references"]
    assert "fk_human_reviews_org_reviewer" in compiled_tables["human_reviews"]
    assert "fk_audit_events_org_actor" in compiled_tables["audit_events"]
