"""Environment configuration loading and fail-closed validation."""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Literal
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from app.core.constants import APP_NAME, APP_VERSION, DEFAULT_MAX_DOCUMENT_BYTES

_WEAK_SECRET_FRAGMENTS: tuple[str, ...] = (
    "changeme",
    "change_me",
    "synthetic_local_only",
    "placeholder",
    "dev_only",
    "example",
)

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

_LOOPBACK_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "localhost", "::1", "keycloak"})


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


def _parse_csv(raw: str | None, *, lowercase: bool = False) -> tuple[str, ...]:
    if raw is None or not raw.strip():
        return ()
    items = []
    for part in raw.split(","):
        cleaned = part.strip()
        if cleaned:
            items.append(cleaned.lower() if lowercase else cleaned)
    return tuple(items)


def _is_weak_secret(value: str | None, *, min_len: int = 32) -> bool:
    if not value or len(value) < min_len:
        return True
    lowered = value.lower()
    if lowered in _WEAK_PASSWORDS:
        return True
    return any(frag in lowered for frag in _WEAK_SECRET_FRAGMENTS)


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
    migration_database_url: str | None = None
    storage_root: str = Field(default="../JYXIA_LOCAL_WORK/synthetic_storage", min_length=1)
    allow_local_synthetic_storage: bool = True
    max_document_bytes: int = Field(default=DEFAULT_MAX_DOCUMENT_BYTES, ge=1024, le=52_428_800)

    app_base_url: str = "http://127.0.0.1:8000"
    cors_allowed_origins: tuple[str, ...] = ()

    # OIDC & MFA policy
    oidc_enabled: bool = False
    oidc_issuer: str | None = None
    oidc_client_id: str | None = None
    oidc_client_secret: str | None = None
    oidc_redirect_uri: str | None = None
    oidc_post_logout_redirect_uri: str | None = None
    oidc_audience: str | None = None
    oidc_allowed_algorithms: tuple[str, ...] = ("RS256", "ES256")
    oidc_mfa_required: bool = True
    oidc_allowed_acr: tuple[str, ...] = ("urn:jyxia:loa:mfa", "2", "aal2")
    oidc_allowed_amr: tuple[str, ...] = ("otp", "totp", "webauthn", "hwk", "mfa")
    oidc_require_both_acr_and_amr: bool = False
    oidc_max_auth_age_seconds: int = Field(default=3600, ge=60, le=86400)
    oidc_clock_skew_seconds: int = Field(default=30, ge=0, le=120)
    oidc_http_timeout_seconds: float = Field(default=5.0, ge=1.0, le=30.0)
    oidc_jwks_cache_ttl_seconds: int = Field(default=300, ge=30, le=3600)
    oidc_jwks_refresh_cooldown_seconds: int = Field(default=15, ge=1, le=300)
    oidc_allow_http_dev: bool = False

    # Session & CSRF
    session_secret: str = "jyxia-dev-only-ephemeral-session-secret-not-for-production"
    csrf_secret: str = "jyxia-dev-only-ephemeral-csrf-secret-not-for-production"
    session_cookie_secure: bool = True
    session_idle_timeout_seconds: int = Field(default=1800, ge=60, le=86400)
    session_absolute_timeout_seconds: int = Field(default=28800, ge=300, le=604800)

    @field_validator("database_url", "migration_database_url")
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

    @field_validator("oidc_allowed_algorithms")
    @classmethod
    def _validate_algorithms(cls, algs: tuple[str, ...]) -> tuple[str, ...]:
        allowed_asymmetric = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}
        if not algs:
            raise ValueError("OIDC allowed algorithms list cannot be empty.")
        for alg in algs:
            if alg not in allowed_asymmetric:
                raise ValueError(
                    f"Prohibited JWT algorithm '{alg}'. Allowed asymmetric: {sorted(allowed_asymmetric)}."
                )
        return algs

    @model_validator(mode="after")
    def _validate_cross_field_policy(self) -> Settings:
        if self.session_idle_timeout_seconds > self.session_absolute_timeout_seconds:
            raise ValueError("session_idle_timeout_seconds cannot exceed absolute timeout.")

        if self.oidc_allow_http_dev and self.env not in {"development", "test"}:
            raise ValueError("oidc_allow_http_dev is strictly prohibited in staging/production.")

        if self.oidc_enabled:
            if not self.oidc_issuer or not self.oidc_client_id or not self.oidc_redirect_uri:
                raise ValueError(
                    "Enabling OIDC requires JYXIA_OIDC_ISSUER, CLIENT_ID and REDIRECT_URI."
                )
            parsed_issuer = urlparse(self.oidc_issuer)
            parsed_redirect = urlparse(self.oidc_redirect_uri)
            if parsed_issuer.scheme == "http":
                if not (self.oidc_allow_http_dev and parsed_issuer.hostname in _LOOPBACK_HOSTS):
                    raise ValueError(
                        "HTTP OIDC issuer is only permitted in dev/test with loopback/keycloak host."
                    )
            elif parsed_issuer.scheme != "https" or not parsed_issuer.netloc:
                raise ValueError("JYXIA_OIDC_ISSUER must be a valid HTTPS URL.")
            if parsed_redirect.scheme == "http":
                if not (self.oidc_allow_http_dev and parsed_redirect.hostname in _LOOPBACK_HOSTS):
                    raise ValueError("HTTP redirect_uri is only permitted in dev/test on loopback.")
            elif parsed_redirect.scheme != "https" or not parsed_redirect.netloc:
                raise ValueError("JYXIA_OIDC_REDIRECT_URI must be a valid HTTPS URL.")

        if self.env == "production":
            if self.debug or self.log_level == "DEBUG":
                raise ValueError("Debug mode and DEBUG logging are prohibited in production.")
            if not self.database_url:
                raise ValueError("Production environment requires JYXIA_DATABASE_URL.")
            if self.database_url.startswith("sqlite"):
                raise ValueError("SQLite is prohibited when JYXIA_ENV=production.")
            parsed_db = urlparse(self.database_url)
            pw = parsed_db.password or ""
            if _is_weak_secret(pw, min_len=12):
                raise ValueError("Production database credentials must be strong non-placeholder secrets.")
            if self.migration_database_url:
                parsed_mig = urlparse(self.migration_database_url)
                if parsed_mig.username and parsed_mig.username == parsed_db.username:
                    raise ValueError(
                        "Production runtime database role must differ from migration database role."
                    )
            if self.allow_local_synthetic_storage:
                raise ValueError(
                    "Local synthetic disk storage must be disabled when JYXIA_ENV=production."
                )
            if not self.oidc_enabled or not self.oidc_mfa_required:
                raise ValueError("Production requires active OIDC and mandatory MFA enforcement.")
            if _is_weak_secret(self.oidc_client_secret, min_len=16):
                raise ValueError("Production requires a strong non-placeholder OIDC client secret.")
            if _is_weak_secret(self.session_secret, min_len=32) or _is_weak_secret(
                self.csrf_secret, min_len=32
            ):
                raise ValueError("Production requires strong non-placeholder session/CSRF secrets.")
            if not self.session_cookie_secure:
                raise ValueError("JYXIA_SESSION_COOKIE_SECURE must be true in production.")
            if urlparse(self.app_base_url).scheme != "https":
                raise ValueError("JYXIA_APP_BASE_URL must use HTTPS in production.")
            if "*" in self.cors_allowed_origins or any(
                urlparse(o).scheme != "https" for o in self.cors_allowed_origins
            ):
                raise ValueError("Production CORS origins must be explicit HTTPS URLs (never '*').")
        return self

    def effective_oidc_audience(self) -> str:
        return self.oidc_audience or (self.oidc_client_id or "")

    def masked_database_url(self) -> str:
        return mask_database_url(self.database_url)

    def __repr__(self) -> str:
        return (
            f"Settings(app_name={self.app_name!r}, app_version={self.app_version!r}, "
            f"env={self.env!r}, debug={self.debug!r}, "
            f"database_url={self.masked_database_url()!r}, oidc_enabled={self.oidc_enabled!r}, "
            f"oidc_mfa_required={self.oidc_mfa_required!r})"
        )


def load_settings(
    environ: Mapping[str, str] | None = None,
    *,
    strict_database: bool = False,
) -> Settings:
    """Build and validate Settings from an environment mapping without mutating globals."""
    source = os.environ if environ is None else environ
    raw_db = source.get("JYXIA_DATABASE_URL") or source.get("APP_DATABASE_URL")
    raw_mig_db = source.get("JYXIA_MIGRATION_DATABASE_URL") or source.get("MIGRATION_DATABASE_URL")
    raw_issuer = source.get("JYXIA_OIDC_ISSUER") or source.get("OIDC_ISSUER")
    raw_client = source.get("JYXIA_OIDC_CLIENT_ID") or source.get("OIDC_CLIENT_ID")
    raw_secret = source.get("JYXIA_OIDC_CLIENT_SECRET") or source.get("OIDC_CLIENT_SECRET")
    raw_redirect = source.get("JYXIA_OIDC_REDIRECT_URI") or source.get("OIDC_REDIRECT_URI")
    raw_post_logout = source.get("JYXIA_OIDC_POST_LOGOUT_REDIRECT_URI")
    raw_audience = source.get("JYXIA_OIDC_AUDIENCE") or source.get("OIDC_AUDIENCE")
    env_name = (source.get("JYXIA_ENV") or "development").strip().lower()
    default_secure_cookie = env_name in {"staging", "production"}

    try:
        acr_raw = source.get("JYXIA_OIDC_ALLOWED_ACR") or source.get("OIDC_ALLOWED_ACR")
        amr_raw = source.get("JYXIA_OIDC_ALLOWED_AMR") or source.get("OIDC_ALLOWED_AMR")
        algs_raw = source.get("JYXIA_OIDC_ALLOWED_ALGORITHMS")
        settings = Settings(
            app_name=(source.get("JYXIA_APP_NAME") or APP_NAME).strip(),
            env=env_name,  # type: ignore[arg-type]
            debug=_parse_bool(source.get("JYXIA_DEBUG"), default=False, field_name="JYXIA_DEBUG"),
            log_level=(source.get("JYXIA_LOG_LEVEL") or "INFO").strip().upper(),  # type: ignore[arg-type]
            database_url=raw_db.strip() if raw_db and raw_db.strip() else None,
            migration_database_url=raw_mig_db.strip() if raw_mig_db and raw_mig_db.strip() else None,
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
            app_base_url=(source.get("JYXIA_APP_BASE_URL") or "http://127.0.0.1:8000").strip().rstrip("/"),
            cors_allowed_origins=_parse_csv(source.get("JYXIA_CORS_ALLOWED_ORIGINS")),
            oidc_enabled=_parse_bool(
                source.get("JYXIA_OIDC_ENABLED"),
                default=False,
                field_name="JYXIA_OIDC_ENABLED",
            ),
            oidc_issuer=raw_issuer.strip().rstrip("/") if raw_issuer and raw_issuer.strip() else None,
            oidc_client_id=raw_client.strip() if raw_client and raw_client.strip() else None,
            oidc_client_secret=raw_secret.strip() if raw_secret and raw_secret.strip() else None,
            oidc_redirect_uri=raw_redirect.strip() if raw_redirect and raw_redirect.strip() else None,
            oidc_post_logout_redirect_uri=(
                raw_post_logout.strip() if raw_post_logout and raw_post_logout.strip() else None
            ),
            oidc_audience=raw_audience.strip() if raw_audience and raw_audience.strip() else None,
            oidc_allowed_algorithms=_parse_csv(algs_raw) or ("RS256", "ES256"),
            oidc_mfa_required=_parse_bool(
                source.get("JYXIA_OIDC_MFA_REQUIRED") or source.get("OIDC_MFA_REQUIRED"),
                default=True,
                field_name="JYXIA_OIDC_MFA_REQUIRED",
            ),
            oidc_allowed_acr=_parse_csv(acr_raw) or ("urn:jyxia:loa:mfa", "2", "aal2"),
            oidc_allowed_amr=_parse_csv(amr_raw, lowercase=True)
            or ("otp", "totp", "webauthn", "hwk", "mfa"),
            oidc_require_both_acr_and_amr=_parse_bool(
                source.get("JYXIA_OIDC_REQUIRE_BOTH_ACR_AND_AMR"),
                default=False,
                field_name="JYXIA_OIDC_REQUIRE_BOTH_ACR_AND_AMR",
            ),
            oidc_max_auth_age_seconds=_parse_int(
                source.get("JYXIA_OIDC_MAX_AUTH_AGE_SECONDS"),
                default=3600,
                field_name="JYXIA_OIDC_MAX_AUTH_AGE_SECONDS",
            ),
            oidc_clock_skew_seconds=_parse_int(
                source.get("JYXIA_OIDC_CLOCK_SKEW_SECONDS"),
                default=30,
                field_name="JYXIA_OIDC_CLOCK_SKEW_SECONDS",
            ),
            oidc_allow_http_dev=_parse_bool(
                source.get("JYXIA_OIDC_ALLOW_HTTP_DEV"),
                default=False,
                field_name="JYXIA_OIDC_ALLOW_HTTP_DEV",
            ),
            session_secret=(
                source.get("JYXIA_SESSION_SECRET")
                or "jyxia-dev-only-ephemeral-session-secret-not-for-production"
            ).strip(),
            csrf_secret=(
                source.get("JYXIA_CSRF_SECRET")
                or source.get("CSRF_SECRET")
                or "jyxia-dev-only-ephemeral-csrf-secret-not-for-production"
            ).strip(),
            session_cookie_secure=_parse_bool(
                source.get("JYXIA_SESSION_COOKIE_SECURE") or source.get("SESSION_COOKIE_SECURE"),
                default=default_secure_cookie,
                field_name="JYXIA_SESSION_COOKIE_SECURE",
            ),
            session_idle_timeout_seconds=_parse_int(
                source.get("JYXIA_SESSION_IDLE_TIMEOUT_SECONDS")
                or source.get("SESSION_IDLE_TIMEOUT"),
                default=1800,
                field_name="JYXIA_SESSION_IDLE_TIMEOUT_SECONDS",
            ),
            session_absolute_timeout_seconds=_parse_int(
                source.get("JYXIA_SESSION_ABSOLUTE_TIMEOUT_SECONDS")
                or source.get("SESSION_ABSOLUTE_TIMEOUT"),
                default=28800,
                field_name="JYXIA_SESSION_ABSOLUTE_TIMEOUT_SECONDS",
            ),
        )
    except ValidationError as exc:
        raise ConfigurationError(f"Invalid JYXIA backend configuration: {exc}") from exc

    if strict_database and not settings.database_url:
        raise ConfigurationError("JYXIA_DATABASE_URL must be configured when strict_database=True.")
    return settings
