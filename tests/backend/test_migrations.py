"""Tests for Alembic incremental upgrade/downgrade lifecycle and PostgreSQL DDL compatibility."""

from __future__ import annotations

import os
from pathlib import Path

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import inspect
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateTable

from app.db.base import Base
from app.db.session import create_db_engine

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

            mc = MigrationContext.configure(conn)
            diffs = compare_metadata(mc, Base.metadata)
            assert diffs == [], f"Unexpected metadata drift between models and migration: {diffs}"

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

        # Clean re-upgrade from empty DB to head (0003)
        command.upgrade(cfg, "head")
        with engine.connect() as conn:
            assert EXPECTED_TABLES.issubset(set(inspect(conn).get_table_names()))
            diffs = compare_metadata(MigrationContext.configure(conn), Base.metadata)
            assert diffs == []
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
