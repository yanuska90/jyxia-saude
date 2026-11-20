"""Environment configuration loading and fail-closed validation."""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Literal
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from app.core.constants import APP_NAME, APP_VERSION, DEFAULT_MAX_DOCUMENT_BYTES

_WEAK_PASSWORDS: frozenset[str] = frozenset(
    {
        "changeme",
        "change_me",
        "synthetic_local_only_change_me",
        "password",
        "postgres",
        "jyxia",
        "admin",
        "123456",
        "test",
        "secret",
    }
)


class ConfigurationError(ValueError):
    """Raised when application environment settings are invalid or unsafe."""


def _parse_bool(raw: str | None, *, default: bool, field_name: str) -> bool:
    if raw is None or raw.strip() == "":
        return default
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ConfigurationError(f"Invalid boolean value for {field_name}.")


def _parse_int(raw: str | None, *, default: int, field_name: str) -> int:
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw.strip())
    except ValueError as exc:
        raise ConfigurationError(f"Invalid integer value for {field_name}.") from exc


def _parse_origins(raw: str | None) -> tuple[str, ...]:
    if raw is None or not raw.strip():
        return ()
    return tuple(part.strip() for part in raw.split(",") if part.strip())


def mask_database_url(database_url: str | None) -> str:
    """Return a non-sensitive representation of database_url with credentials/query removed."""
    if not database_url:
        return "<unconfigured>"
    try:
        parsed = urlparse(database_url)
    except ValueError:
        return "<invalid-url>"
    scheme = parsed.scheme or "unknown"
    if scheme.startswith("sqlite"):
        return f"{scheme}://<local>"
    host = parsed.hostname or "<unknown-host>"
    port = f":{parsed.port}" if parsed.port else ""
    db_name = parsed.path.lstrip("/") or "<default>"
    return f"{scheme}://{host}{port}/{db_name}"


class Settings(BaseModel):
    """Immutable validated configuration for the JYXIA institutional backend."""

    model_config = ConfigDict(frozen=True)

    app_name: str = Field(default=APP_NAME, min_length=1, max_length=120)
    app_version: str = Field(default=APP_VERSION, min_length=1, max_length=32)
    env: Literal["development", "test", "staging", "production"] = "development"
    debug: bool = False
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    database_url: str | None = None
    storage_root: str = Field(default="../JYXIA_LOCAL_WORK/synthetic_storage", min_length=1)
    allow_local_synthetic_storage: bool = True
    max_document_bytes: int = Field(default=DEFAULT_MAX_DOCUMENT_BYTES, ge=1024, le=52_428_800)
    oidc_enabled: bool = False
    oidc_issuer: str | None = None
    oidc_client_id: str | None = None
    cors_allowed_origins: tuple[str, ...] = ()

    @field_validator("database_url")
    @classmethod
    def _validate_database_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        if not cleaned:
            return None
        parsed = urlparse(cleaned)
        allowed_schemes = {"postgresql+psycopg", "sqlite", "sqlite+pysqlite"}
        if parsed.scheme not in allowed_schemes:
            raise ValueError(
                f"Unsupported database scheme '{parsed.scheme}'. Allowed: {sorted(allowed_schemes)}."
            )
        if parsed.scheme == "postgresql+psycopg" and not parsed.hostname:
            raise ValueError("PostgreSQL database URL must declare a hostname.")
        return cleaned

    @field_validator("cors_allowed_origins")
    @classmethod
    def _validate_cors_origins(cls, origins: tuple[str, ...]) -> tuple[str, ...]:
        for origin in origins:
            if origin == "*":
                continue
            parsed = urlparse(origin)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise ValueError(f"Invalid CORS origin format: {origin}")
        return origins

    @model_validator(mode="after")
    def _validate_cross_field_policy(self) -> Settings:
        if self.oidc_enabled:
            if not self.oidc_issuer or not self.oidc_client_id:
                raise ValueError(
                    "Enabling OIDC requires both JYXIA_OIDC_ISSUER and JYXIA_OIDC_CLIENT_ID."
                )
            parsed_issuer = urlparse(self.oidc_issuer)
            if parsed_issuer.scheme != "https" or not parsed_issuer.netloc:
                raise ValueError("JYXIA_OIDC_ISSUER must be a valid HTTPS URL.")

        if self.env == "production":
            if self.debug or self.log_level == "DEBUG":
                raise ValueError("Debug mode and DEBUG logging are prohibited in production.")
            if not self.database_url:
                raise ValueError("Production environment requires JYXIA_DATABASE_URL.")
            if self.database_url.startswith("sqlite"):
                raise ValueError("SQLite is prohibited when JYXIA_ENV=production.")
            parsed_db = urlparse(self.database_url)
            pw = parsed_db.password or ""
            if (
                not pw
                or len(pw) < 12
                or pw.lower() in _WEAK_PASSWORDS
                or "change_me" in pw.lower()
                or "synthetic" in pw.lower()
            ):
                raise ValueError("Production database credentials must be strong non-placeholder secrets.")
            if self.allow_local_synthetic_storage:
                raise ValueError(
                    "Local synthetic disk storage must be disabled when JYXIA_ENV=production."
                )
            if not self.oidc_enabled:
                raise ValueError(
                    "Production environment requires active OIDC configuration (not available in 0.1.0)."
                )
            if "*" in self.cors_allowed_origins or any(
                urlparse(o).scheme != "https" for o in self.cors_allowed_origins
            ):
                raise ValueError("Production CORS origins must be explicit HTTPS URLs (never '*').")
        return self

    def masked_database_url(self) -> str:
        return mask_database_url(self.database_url)

    def __repr__(self) -> str:
        return (
            f"Settings(app_name={self.app_name!r}, app_version={self.app_version!r}, "
            f"env={self.env!r}, debug={self.debug!r}, "
            f"database_url={self.masked_database_url()!r}, oidc_enabled={self.oidc_enabled!r})"
        )


def load_settings(
    environ: Mapping[str, str] | None = None,
    *,
    strict_database: bool = False,
) -> Settings:
    """Build and validate Settings from an environment mapping without mutating globals."""
    source = os.environ if environ is None else environ
    raw_db = source.get("JYXIA_DATABASE_URL")
    raw_issuer = source.get("JYXIA_OIDC_ISSUER")
    raw_client = source.get("JYXIA_OIDC_CLIENT_ID")
    try:
        settings = Settings(
            app_name=(source.get("JYXIA_APP_NAME") or APP_NAME).strip(),
            env=(source.get("JYXIA_ENV") or "development").strip().lower(),  # type: ignore[arg-type]
            debug=_parse_bool(
                source.get("JYXIA_DEBUG"),
                default=False,
                field_name="JYXIA_DEBUG",
            ),
            log_level=(source.get("JYXIA_LOG_LEVEL") or "INFO").strip().upper(),  # type: ignore[arg-type]
            database_url=raw_db.strip() if raw_db and raw_db.strip() else None,
            storage_root=(
                source.get("JYXIA_STORAGE_ROOT") or "../JYXIA_LOCAL_WORK/synthetic_storage"
            ).strip(),
            allow_local_synthetic_storage=_parse_bool(
                source.get("JYXIA_ALLOW_LOCAL_SYNTHETIC_STORAGE"),
                default=True,
                field_name="JYXIA_ALLOW_LOCAL_SYNTHETIC_STORAGE",
            ),
            max_document_bytes=_parse_int(
                source.get("JYXIA_MAX_DOCUMENT_BYTES"),
                default=DEFAULT_MAX_DOCUMENT_BYTES,
                field_name="JYXIA_MAX_DOCUMENT_BYTES",
            ),
            oidc_enabled=_parse_bool(
                source.get("JYXIA_OIDC_ENABLED"),
                default=False,
                field_name="JYXIA_OIDC_ENABLED",
            ),
            oidc_issuer=raw_issuer.strip() if raw_issuer and raw_issuer.strip() else None,
            oidc_client_id=raw_client.strip() if raw_client and raw_client.strip() else None,
            cors_allowed_origins=_parse_origins(source.get("JYXIA_CORS_ALLOWED_ORIGINS")),
        )
    except ValidationError as exc:
        raise ConfigurationError(f"Invalid JYXIA backend configuration: {exc}") from exc

    if strict_database and not settings.database_url:
        raise ConfigurationError("JYXIA_DATABASE_URL must be configured when strict_database=True.")
    return settings
