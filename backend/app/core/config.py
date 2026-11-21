"""Environment configuration loading and fail-closed validation."""

from __future__ import annotations

import ipaddress
import os
import re
from collections.abc import Mapping
from typing import Literal
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from app.core.constants import APP_NAME, APP_VERSION, DEFAULT_MAX_DOCUMENT_BYTES

_DEFAULT_DEV_SESSION_SECRET = "jyxia-dev-only-ephemeral-session-secret-not-for-production"
_DEFAULT_DEV_CSRF_SECRET = "jyxia-dev-only-ephemeral-csrf-secret-not-for-production"

_WEAK_SECRET_FRAGMENTS: tuple[str, ...] = (
    "changeme",
    "change_me",
    "synthetic_local_only",
    "synthetic_dev",
    "synthetic_app",
    "synthetic_kc",
    "placeholder",
    "dev_only",
    "not_for_production",
    "ephemeral_session_secret",
    "ephemeral_csrf_secret",
    "default_secret",
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
        _DEFAULT_DEV_SESSION_SECRET,
        _DEFAULT_DEV_CSRF_SECRET,
    }
)

_FORBIDDEN_RUNTIME_DB_USERS: frozenset[str] = frozenset(
    {
        "postgres",
        "jyxia_migrator",
        "migration_owner",
        "root",
        "admin",
        "superuser",
    }
)

_WEAK_FIRST_FACTOR_AMR: frozenset[str] = frozenset(
    {
        "pwd",
        "password",
        "email",
        "sms",
        "kba",
        "none",
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


def _normalize_secret_for_comparison(value: str) -> tuple[str, str, str]:
    lowered = value.strip().lower()
    snake = re.sub(r"[\s\-_.]+", "_", lowered)
    compact = re.sub(r"[^a-z0-9]+", "", lowered)
    return lowered, snake, compact


def _is_weak_secret(value: str | None, *, min_len: int = 32) -> bool:
    if not value:
        return True
    cleaned = value.strip()
    if len(cleaned) < min_len:
        return True
    lowered, snake, compact = _normalize_secret_for_comparison(cleaned)
    if lowered in _WEAK_PASSWORDS or snake in _WEAK_PASSWORDS:
        return True
    for frag in _WEAK_SECRET_FRAGMENTS:
        frag_compact = re.sub(r"[^a-z0-9]+", "", frag)
        if frag in lowered or frag in snake or (frag_compact and frag_compact in compact):
            return True
    return False


def _is_non_global_or_loopback_host(hostname: str | None) -> bool:
    if not hostname:
        return True
    lowered = hostname.strip().lower().strip("[]")
    if lowered in _LOOPBACK_HOSTS or lowered.endswith(".localhost"):
        return True
    try:
        ip_obj = ipaddress.ip_address(lowered)
    except ValueError:
        return False
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
        ip_obj = ip_obj.ipv4_mapped
    return bool(
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_unspecified
        or ip_obj.is_reserved
        or not ip_obj.is_global
    )


def _has_url_userinfo(raw_url: str) -> bool:
    parsed = urlparse(raw_url)
    return bool(parsed.username is not None or parsed.password is not None or "@" in parsed.netloc)


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
    oidc_require_both_acr_and_amr: bool = True
    oidc_max_auth_age_seconds: int = Field(default=3600, ge=60, le=86400)
    oidc_clock_skew_seconds: int = Field(default=30, ge=0, le=120)
    oidc_http_timeout_seconds: float = Field(default=5.0, ge=1.0, le=30.0)
    oidc_jwks_cache_ttl_seconds: int = Field(default=300, ge=30, le=3600)
    oidc_jwks_refresh_cooldown_seconds: int = Field(default=15, ge=1, le=300)
    oidc_allow_http_dev: bool = False

    # Session & CSRF
    session_secret: str = _DEFAULT_DEV_SESSION_SECRET
    csrf_secret: str = _DEFAULT_DEV_CSRF_SECRET
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
            if _has_url_userinfo(self.oidc_issuer) or _has_url_userinfo(self.oidc_redirect_uri):
                raise ValueError("OIDC issuer and redirect_uri must not contain URL userinfo.")
            parsed_issuer = urlparse(self.oidc_issuer)
            parsed_redirect = urlparse(self.oidc_redirect_uri)
            if parsed_issuer.scheme == "http":
                if not (
                    self.oidc_allow_http_dev
                    and self.env in {"development", "test"}
                    and parsed_issuer.hostname in _LOOPBACK_HOSTS
                ):
                    raise ValueError(
                        "HTTP OIDC issuer is only permitted in dev/test with loopback/keycloak host."
                    )
            elif parsed_issuer.scheme != "https" or not parsed_issuer.netloc:
                raise ValueError("JYXIA_OIDC_ISSUER must be a valid HTTPS URL.")
            if parsed_redirect.scheme == "http":
                if not (
                    self.oidc_allow_http_dev
                    and self.env in {"development", "test"}
                    and parsed_redirect.hostname in _LOOPBACK_HOSTS
                ):
                    raise ValueError("HTTP redirect_uri is only permitted in dev/test on loopback.")
            elif parsed_redirect.scheme != "https" or not parsed_redirect.netloc:
                raise ValueError("JYXIA_OIDC_REDIRECT_URI must be a valid HTTPS URL.")

        if self.oidc_mfa_required:
            if not self.oidc_allowed_amr:
                raise ValueError("Mandatory MFA requires at least one allowed second-factor AMR.")
            normalized_amr = {item.strip().lower() for item in self.oidc_allowed_amr if item.strip()}
            if not normalized_amr or (normalized_amr & _WEAK_FIRST_FACTOR_AMR):
                raise ValueError(
                    "JYXIA_OIDC_ALLOWED_AMR cannot include first-factor or weak methods (pwd, email, sms)."
                )
            if not self.oidc_allowed_acr:
                raise ValueError("Mandatory MFA requires at least one allowed ACR assurance value.")

        if self.env in {"production", "staging"}:
            env_label = self.env.capitalize()
            if self.debug or self.log_level == "DEBUG":
                raise ValueError(f"Debug mode and DEBUG logging are prohibited in {self.env}.")
            if not self.database_url:
                raise ValueError(f"{env_label} environment requires JYXIA_DATABASE_URL.")
            if self.database_url.startswith("sqlite"):
                raise ValueError(f"SQLite is prohibited when JYXIA_ENV={self.env}.")
            parsed_db = urlparse(self.database_url)
            db_user = (parsed_db.username or "").strip().lower()
            pw = parsed_db.password or ""
            if not db_user or db_user in _FORBIDDEN_RUNTIME_DB_USERS:
                raise ValueError(
                    f"{env_label} runtime database URL cannot use privileged/default role '{db_user}'."
                )
            if _is_weak_secret(pw, min_len=12):
                raise ValueError(
                    f"{env_label} database credentials must be strong non-placeholder secrets."
                )
            if self.migration_database_url:
                parsed_mig = urlparse(self.migration_database_url)
                if parsed_mig.username and parsed_mig.username == parsed_db.username:
                    raise ValueError(
                        f"{env_label} runtime database role must differ from migration database role."
                    )
            if self.allow_local_synthetic_storage:
                raise ValueError(
                    f"Local synthetic disk storage must be disabled when JYXIA_ENV={self.env}."
                )
            if (
                not self.oidc_enabled
                or not self.oidc_mfa_required
                or not self.oidc_require_both_acr_and_amr
            ):
                raise ValueError(
                    f"{env_label} requires active OIDC and mandatory MFA with both ACR and AMR enforcement."
                )
            assert self.oidc_issuer is not None and self.oidc_redirect_uri is not None
            if _is_non_global_or_loopback_host(urlparse(self.oidc_issuer).hostname):
                raise ValueError(
                    f"{env_label} JYXIA_OIDC_ISSUER cannot target loopback, private, or non-global hosts."
                )
            if _is_non_global_or_loopback_host(urlparse(self.oidc_redirect_uri).hostname):
                raise ValueError(
                    f"{env_label} JYXIA_OIDC_REDIRECT_URI cannot target loopback or private hosts."
                )
            if _is_weak_secret(self.oidc_client_secret, min_len=16):
                raise ValueError(
                    f"{env_label} requires a strong non-placeholder OIDC client secret."
                )
            if _is_weak_secret(self.session_secret, min_len=32) or _is_weak_secret(
                self.csrf_secret, min_len=32
            ):
                raise ValueError(
                    f"{env_label} requires strong non-placeholder session/CSRF secrets."
                )
            if self.session_secret.strip() == self.csrf_secret.strip():
                raise ValueError(
                    f"{env_label} requires distinct JYXIA_SESSION_SECRET and JYXIA_CSRF_SECRET values."
                )
            if not self.session_cookie_secure:
                raise ValueError(f"JYXIA_SESSION_COOKIE_SECURE must be true in {self.env}.")
            parsed_base = urlparse(self.app_base_url)
            if (
                parsed_base.scheme != "https"
                or not parsed_base.hostname
                or _has_url_userinfo(self.app_base_url)
                or _is_non_global_or_loopback_host(parsed_base.hostname)
            ):
                raise ValueError(
                    f"JYXIA_APP_BASE_URL must use a public HTTPS origin without userinfo in {self.env}."
                )
            if (
                "*" in self.cors_allowed_origins
                or any(
                    urlparse(o).scheme != "https"
                    or _has_url_userinfo(o)
                    or _is_non_global_or_loopback_host(urlparse(o).hostname)
                    for o in self.cors_allowed_origins
                )
            ):
                raise ValueError(
                    f"{env_label} CORS origins must be explicit non-local HTTPS URLs (never '*')."
                )
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
                default=True,
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
                (source.get("JYXIA_SESSION_SECRET") or "").strip()
                if env_name in {"production", "staging"}
                else (
                    source.get("JYXIA_SESSION_SECRET") or _DEFAULT_DEV_SESSION_SECRET
                ).strip()
            ),
            csrf_secret=(
                (source.get("JYXIA_CSRF_SECRET") or source.get("CSRF_SECRET") or "").strip()
                if env_name in {"production", "staging"}
                else (
                    source.get("JYXIA_CSRF_SECRET")
                    or source.get("CSRF_SECRET")
                    or _DEFAULT_DEV_CSRF_SECRET
                ).strip()
            ),
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
