"""Sanitized structured logging preventing secrets, DSNs or document payloads in logs."""

from __future__ import annotations

import logging
import re
from typing import Any

LOGGER_NAME = "jyxia.backend"

_SECRET_AND_PII_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE), "Bearer [REDACTED]"),
    (
        re.compile(r"(postgresql(?:\+psycopg)?://[^:\s/]+):[^@\s]+@", re.IGNORECASE),
        r"\1:[REDACTED]@",
    ),
    (re.compile(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b"), "[CPF_REDACTED]"),
    (
        re.compile(r"(password|secret|token|dsn)\s*=\s*\S+", re.IGNORECASE),
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
        "raw_value",
        "quote_excerpt",
        "password",
        "token",
        "secret",
        "dsn",
        "database_url",
    }
)


def redact_sensitive_text(text: str) -> str:
    """Mask connection credentials, bearer tokens and CPF-shaped patterns."""
    sanitized = text
    for pattern, replacement in _SECRET_AND_PII_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


def build_safe_log_extra(**fields: Any) -> dict[str, Any]:
    """Return a whitelisted extra dictionary with forbidden payload keys stripped."""
    cleaned: dict[str, Any] = {}
    for key, value in fields.items():
        if key.lower() in FORBIDDEN_LOG_KEYS:
            cleaned[key] = "[REDACTED]"
        elif isinstance(value, str):
            cleaned[key] = redact_sensitive_text(value)
        else:
            cleaned[key] = value
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
        for forbidden in FORBIDDEN_LOG_KEYS:
            if hasattr(record, forbidden):
                setattr(record, forbidden, "[REDACTED]")
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
