"""Tests for Alembic upgrade/downgrade lifecycle and PostgreSQL DDL compatibility."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
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
}


def test_alembic_upgrade_downgrade_and_reupgrade_clean(
    tmp_path: Path, alembic_config_builder
) -> None:
    external_url = os.environ.get("JYXIA_TEST_DATABASE_URL", "").strip()
    url = external_url or f"sqlite:///{(tmp_path / 'migration_cycle.sqlite3').as_posix()}"
    cfg = alembic_config_builder(url)
    engine = create_db_engine(url)

    try:
        if external_url:
            command.downgrade(cfg, "base")
        command.upgrade(cfg, "head")

        with engine.connect() as conn:
            tables_after_up = set(inspect(conn).get_table_names())
            assert EXPECTED_TABLES.issubset(tables_after_up)

            mc = MigrationContext.configure(conn)
            diffs = compare_metadata(mc, Base.metadata)
            assert diffs == [], f"Unexpected metadata drift between models and migration: {diffs}"

        command.downgrade(cfg, "base")
        with engine.connect() as conn:
            tables_after_down = set(inspect(conn).get_table_names())
            assert not (EXPECTED_TABLES & tables_after_down)

        command.upgrade(cfg, "head")
        with engine.connect() as conn:
            assert EXPECTED_TABLES.issubset(set(inspect(conn).get_table_names()))
    finally:
        engine.dispose()


def test_postgresql_dialect_ddl_compiles_for_all_tables() -> None:
    pg_dialect = postgresql.dialect()
    compiled_tables: dict[str, str] = {}
    for table_name, table in Base.metadata.tables.items():
        ddl = str(CreateTable(table).compile(dialect=pg_dialect))
        compiled_tables[table_name] = ddl

    assert set(compiled_tables) == EXPECTED_TABLES
    assert "JSONB" in compiled_tables["processing_runs"]
    assert "JSONB" in compiled_tables["audit_events"]
    assert "TIMESTAMP WITH TIME ZONE" in compiled_tables["document_cases"]
    assert "uq_document_cases_org_id" in compiled_tables["document_cases"]
    assert "fk_documents_org_case" in compiled_tables["documents"]
