"""Shared fixtures supporting isolated SQLite runs locally and PostgreSQL in CI."""

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
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.db.session import create_db_engine, create_session_factory  # noqa: E402


def build_alembic_config(database_url: str) -> Config:
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    cfg.set_main_option("sqlalchemy.url", database_url)
    return cfg


@pytest.fixture()
def alembic_config_builder():
    return build_alembic_config


@pytest.fixture()
def database_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    external_url = os.environ.get("JYXIA_TEST_DATABASE_URL", "").strip()
    if external_url:
        monkeypatch.setenv("JYXIA_DATABASE_URL", external_url)
        return external_url
    db_file = tmp_path / "jyxia_test.sqlite3"
    local_url = f"sqlite:///{db_file.as_posix()}"
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
                        "TRUNCATE TABLE audit_events, human_reviews, evidence_references, "
                        "extracted_fields, processing_runs, document_versions, documents, "
                        "document_cases, organization_memberships, users, organizations CASCADE"
                    )
                )
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
