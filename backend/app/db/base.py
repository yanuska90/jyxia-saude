"""SQLAlchemy DeclarativeBase with deterministic naming conventions."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import JSON, MetaData
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase

NAMING_CONVENTION: dict[str, str] = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

JSON_VARIANT = JSON().with_variant(JSONB(), "postgresql")


def utc_now() -> datetime:
    """Return timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


def new_uuid() -> str:
    """Return canonical lowercase UUID4 string."""
    return str(uuid4())


class Base(DeclarativeBase):
    """Shared declarative base for all institutional domain tables."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)
