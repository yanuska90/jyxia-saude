"""Sanitized structured logging preventing secrets, DSNs, tokens or PII payloads in logs."""

from __future__ import annotations

import logging
import re
from typing import Any

LOGGER_NAME = "jyxia.backend"

_SECRET_AND_PII_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE), "Bearer [REDACTED]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]*)?"), "[JWT_REDACTED]"),
    (
        re.compile(r"((?:postgresql|sqlite)(?:\+[a-z]+)?://[^:\s/]+):[^\s@]+@", re.IGNORECASE),
        r"\1:[REDACTED]@",
    ),
    (re.compile(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b"), "[CPF_REDACTED]"),
    (
        re.compile(
            r"(password|secret|client_secret|token|oidc_token|dsn|cpf|patient_name|birth_date|raw_value|quote_excerpt|extracted_text)\s*[=:]\s*([^\s,;]+)",
            re.IGNORECASE,
        ),
        r"\1=[REDACTED]",
    ),
)

FORBIDDEN_LOG_KEYS: frozenset[str] = frozenset(
    {
        "document_text",
        "extracted_text",
        "raw_bytes",
        "pdf_content",
        "patient_name",
        "birth_date",
        "cpf",
        "raw_value",
        "quote_excerpt",
        "password",
        "token",
        "oidc_token",
        "secret",
        "client_secret",
        "dsn",
        "database_url",
        "authorization",
    }
)


def redact_sensitive_text(text: str) -> str:
    """Mask connection credentials, bearer/JWT tokens, CPF-shaped patterns and PII keys."""
    sanitized = text
    for pattern, replacement in _SECRET_AND_PII_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


def _sanitize_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_sensitive_text(value)
    if isinstance(value, dict):
        return {
            k: ("[REDACTED]" if str(k).lower() in FORBIDDEN_LOG_KEYS else _sanitize_value(v))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_sanitize_value(item) for item in value]
    return value


def build_safe_log_extra(**fields: Any) -> dict[str, Any]:
    """Return a whitelisted extra dictionary with forbidden payload keys stripped recursively."""
    cleaned: dict[str, Any] = {}
    for key, value in fields.items():
        if key.lower() in FORBIDDEN_LOG_KEYS:
            cleaned[key] = "[REDACTED]"
        else:
            cleaned[key] = _sanitize_value(value)
    return cleaned


class SanitizingFilter(logging.Filter):
    """Filter that strips sensitive attributes and redacts patterns before log emission."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            rendered = record.getMessage()
        except Exception:
            rendered = str(record.msg)
        record.msg = redact_sensitive_text(rendered)
        record.args = ()
        for attr_name in list(vars(record).keys()):
            if attr_name.lower() in FORBIDDEN_LOG_KEYS:
                setattr(record, attr_name, "[REDACTED]")
        return True


def configure_logging(level: str = "INFO") -> logging.Logger:
    """Configure and return the module logger with idempotent sanitizing handlers."""
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    if not any(isinstance(f, SanitizingFilter) for f in logger.filters):
        logger.addFilter(SanitizingFilter())
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
        )
        handler.addFilter(SanitizingFilter())
        logger.addHandler(handler)
    logger.propagate = False
    return logger
