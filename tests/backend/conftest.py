"""Shared fixtures supporting isolated SQLite runs locally and PostgreSQL role separation in CI."""

from __future__ import annotations

import os
import sys
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, event, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = REPO_ROOT / "backend"
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.db.session import create_db_engine, create_session_factory  # noqa: E402

_PG_TRUNCATE_STATEMENTS: tuple[str, ...] = (
    "SET LOCAL lock_timeout = '8s'",
    "ALTER TABLE audit_events DISABLE TRIGGER trg_audit_events_no_truncate",
    "ALTER TABLE security_auth_events DISABLE TRIGGER trg_security_auth_events_no_truncate",
    (
        "TRUNCATE TABLE security_auth_events, auth_sessions, oidc_auth_states, "
        "external_identities, audit_events, human_reviews, evidence_references, "
        "extracted_fields, processing_runs, document_versions, documents, "
        "document_cases, organization_memberships, users, organizations CASCADE"
    ),
    "ALTER TABLE security_auth_events ENABLE TRIGGER trg_security_auth_events_no_truncate",
    "ALTER TABLE audit_events ENABLE TRIGGER trg_audit_events_no_truncate",
)


def _truncate_pg_tables(engine: Engine) -> None:
    with engine.begin() as conn:
        for stmt in _PG_TRUNCATE_STATEMENTS:
            conn.execute(text(stmt))


def _attach_pg_test_timeouts(engine: Engine) -> None:
    if engine.dialect.name != "postgresql":
        return

    @event.listens_for(engine, "connect")
    def _set_pg_timeouts(dbapi_connection: Any, _connection_record: Any) -> None:
        with dbapi_connection.cursor() as cur:
            cur.execute("SET SESSION lock_timeout = '8s'")
            cur.execute("SET SESSION statement_timeout = '30s'")
        dbapi_connection.commit()


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
    _attach_pg_test_timeouts(engine)

    if database_url.startswith("sqlite"):
        command.upgrade(cfg, "head")
    else:
        already_head = False
        try:
            with engine.begin() as conn:
                ver = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
                already_head = ver == "20261122_0006"
        except SQLAlchemyError:
            already_head = False

        if already_head:
            _truncate_pg_tables(engine)
        else:
            command.downgrade(cfg, "base")
            command.upgrade(cfg, "head")

    try:
        yield engine
    finally:
        if not database_url.startswith("sqlite"):
            _truncate_pg_tables(engine)
        engine.dispose()


@pytest.fixture()
def app_engine(migrated_engine: Engine) -> Generator[Engine, None, None]:
    """Return runtime `jyxia_app` engine in PG CI, or `migrated_engine` locally on SQLite."""
    app_url = os.environ.get("JYXIA_TEST_APP_DATABASE_URL", "").strip()
    if not app_url:
        yield migrated_engine
        return
    engine = create_db_engine(app_url)
    _attach_pg_test_timeouts(engine)
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
