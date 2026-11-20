"""Shared fixtures supporting isolated SQLite runs locally and PostgreSQL role separation in CI."""

from __future__ import annotations

import os
import sys
from collections.abc import Generator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = REPO_ROOT / "backend"
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.db.session import create_db_engine, create_session_factory  # noqa: E402


def build_alembic_config(database_url: str) -> Config:
    os.environ["JYXIA_MIGRATION_DATABASE_URL"] = database_url
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    cfg.set_main_option("sqlalchemy.url", database_url)
    return cfg


@pytest.fixture()
def alembic_config_builder():
    return build_alembic_config


@pytest.fixture()
def database_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    external_mig = os.environ.get("JYXIA_TEST_MIGRATION_DATABASE_URL", "").strip()
    external_url = external_mig or os.environ.get("JYXIA_TEST_DATABASE_URL", "").strip()
    if external_url:
        monkeypatch.setenv("JYXIA_MIGRATION_DATABASE_URL", external_url)
        monkeypatch.setenv("JYXIA_DATABASE_URL", external_url)
        return external_url
    db_file = tmp_path / "jyxia_test.sqlite3"
    local_url = f"sqlite:///{db_file.as_posix()}"
    monkeypatch.setenv("JYXIA_MIGRATION_DATABASE_URL", local_url)
    monkeypatch.setenv("JYXIA_DATABASE_URL", local_url)
    return local_url


@pytest.fixture()
def migrated_engine(database_url: str) -> Generator[Engine, None, None]:
    cfg = build_alembic_config(database_url)
    engine = create_db_engine(database_url)

    # Ensure PostgreSQL CI test runs start cleanly even when reusing one shared database.
    if not database_url.startswith("sqlite"):
        command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")

    try:
        yield engine
    finally:
        if not database_url.startswith("sqlite"):
            with engine.begin() as conn:
                conn.execute(
                    text(
                        "ALTER TABLE audit_events DISABLE TRIGGER trg_audit_events_no_truncate; "
                        "ALTER TABLE security_auth_events DISABLE TRIGGER trg_security_auth_events_no_truncate; "
                        "TRUNCATE TABLE security_auth_events, auth_sessions, oidc_auth_states, "
                        "external_identities, audit_events, human_reviews, evidence_references, "
                        "extracted_fields, processing_runs, document_versions, documents, "
                        "document_cases, organization_memberships, users, organizations CASCADE; "
                        "ALTER TABLE security_auth_events ENABLE TRIGGER trg_security_auth_events_no_truncate; "
                        "ALTER TABLE audit_events ENABLE TRIGGER trg_audit_events_no_truncate;"
                    )
                )
        engine.dispose()


@pytest.fixture()
def app_engine(migrated_engine: Engine) -> Generator[Engine, None, None]:
    """Return runtime `jyxia_app` engine in PG CI, or `migrated_engine` locally on SQLite."""
    app_url = os.environ.get("JYXIA_TEST_APP_DATABASE_URL", "").strip()
    if not app_url:
        yield migrated_engine
        return
    engine = create_db_engine(app_url)
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture()
def db_session(migrated_engine: Engine) -> Generator[Session, None, None]:
    session_factory = create_session_factory(migrated_engine)
    session = session_factory()
    try:
        yield session
    finally:
        session.rollback()
        session.close()
