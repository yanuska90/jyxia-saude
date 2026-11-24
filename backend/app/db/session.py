"""SQLAlchemy engine creation, SQLite FK pragma wiring and safe readiness check."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Engine, create_engine, event, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.core.logging import LOGGER_NAME

logger = logging.getLogger(LOGGER_NAME)


@dataclass(frozen=True, slots=True)
class DatabaseConnectivityStatus:
    """Sanitized health probe result without DSN or internal exception strings."""

    ok: bool
    status: str


def _is_sqlite_url(database_url: str) -> bool:
    return database_url.startswith("sqlite")


def create_db_engine(database_url: str, *, echo: bool = False) -> Engine:
    """Create a configured SQLAlchemy Engine supporting PostgreSQL and SQLite tests."""
    connect_args: dict[str, Any] = {}
    engine_kwargs: dict[str, Any] = {"echo": echo, "future": True}

    if _is_sqlite_url(database_url):
        connect_args["check_same_thread"] = False
    else:
        connect_args["connect_timeout"] = 2
        engine_kwargs["pool_pre_ping"] = True

    engine = create_engine(database_url, connect_args=connect_args, **engine_kwargs)

    if _is_sqlite_url(database_url):
        @event.listens_for(engine, "connect")
        def _set_sqlite_pragmas(dbapi_connection: Any, _connection_record: Any) -> None:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA busy_timeout=5000")
            cursor.close()

    return engine


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Build an explicit sessionmaker with safe commit/flush semantics."""
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, class_=Session)


def apply_pg_rls_context(
    session: Session,
    *,
    organization_id: str | None = None,
    user_id: str | None = None,
) -> None:
    """Bind transaction-local PostgreSQL session GUCs used by Row-Level Security policies."""
    bind = session.get_bind()
    if bind is None or bind.dialect.name != "postgresql":
        return
    session.execute(
        text(
            "SELECT set_config('app.current_organization_id', :org_id, true), "
            "set_config('app.current_user_id', :user_id, true)"
        ),
        {"org_id": organization_id or "", "user_id": user_id or ""},
    )


def apply_pg_identity_context(
    session: Session,
    *,
    session_token_hash: str | None = None,
    prev_session_token_hash: str | None = None,
    oidc_state_hash: str | None = None,
    oidc_issuer: str | None = None,
    oidc_subject: str | None = None,
) -> None:
    """Bind transaction-local PostgreSQL session/identity lookup GUCs for RLS on auth tables."""
    bind = session.get_bind()
    if bind is None or bind.dialect.name != "postgresql":
        return
    if session_token_hash is not None:
        session.execute(
            text("SELECT set_config('app.current_session_token_hash', :val, true)"),
            {"val": session_token_hash},
        )
    if prev_session_token_hash is not None:
        session.execute(
            text("SELECT set_config('app.current_prev_session_token_hash', :val, true)"),
            {"val": prev_session_token_hash},
        )
    if oidc_state_hash is not None:
        session.execute(
            text("SELECT set_config('app.current_oidc_state_hash', :val, true)"),
            {"val": oidc_state_hash},
        )
    if oidc_issuer is not None:
        session.execute(
            text("SELECT set_config('app.current_oidc_issuer', :val, true)"),
            {"val": oidc_issuer},
        )
    if oidc_subject is not None:
        session.execute(
            text("SELECT set_config('app.current_oidc_subject', :val, true)"),
            {"val": oidc_subject},
        )


def clear_pg_rls_context(session: Session) -> None:
    """Reset PostgreSQL transaction-local tenant, user, and identity RLS context to empty strings."""
    bind = session.get_bind()
    if bind is None or bind.dialect.name != "postgresql":
        return
    session.execute(
        text(
            "SELECT set_config('app.current_organization_id', '', true), "
            "set_config('app.current_user_id', '', true), "
            "set_config('app.current_session_token_hash', '', true), "
            "set_config('app.current_prev_session_token_hash', '', true), "
            "set_config('app.current_oidc_state_hash', '', true), "
            "set_config('app.current_oidc_issuer', '', true), "
            "set_config('app.current_oidc_subject', '', true)"
        )
    )


def check_db_connectivity(engine: Engine | None) -> DatabaseConnectivityStatus:
    """Execute lightweight connectivity probe without leaking credentials or DSN details."""
    if engine is None:
        return DatabaseConnectivityStatus(ok=False, status="unconfigured")
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return DatabaseConnectivityStatus(ok=True, status="reachable")
    except SQLAlchemyError as exc:
        logger.warning(
            "Database readiness check failed with %s.",
            type(exc).__name__,
        )
        return DatabaseConnectivityStatus(ok=False, status="unavailable")
