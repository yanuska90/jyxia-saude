"""Controlled binary storage abstraction confined to synthetic/isolated paths."""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from uuid import uuid4

from app.core.constants import ALLOWED_MIME_TYPES, DEFAULT_MAX_DOCUMENT_BYTES, StorageDriver
from app.core.logging import LOGGER_NAME, build_safe_log_extra

logger = logging.getLogger(LOGGER_NAME)

_PDF_MAGIC = b"%PDF-"
_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_SAFE_ORG_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9\-_]{0,63}$")
_SAFE_KEY_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9\-_]{0,63}/[a-f0-9]{32}\.(pdf|png)$")


class StorageValidationError(ValueError):
    """Raised fail-closed on unsupported MIME, magic bytes, traversal or disabled storage."""


@dataclass(frozen=True, slots=True)
class StoredObjectMetadata:
    storage_driver: str
    storage_key: str
    sha256_hex: str
    mime_type: str
    byte_size: int


class DocumentStoragePort(Protocol):
    """Abstract storage boundary separating persistence metadata from binary storage backend."""

    def store_synthetic_bytes(
        self,
        *,
        organization_id: str,
        mime_type: str,
        content: bytes,
    ) -> StoredObjectMetadata:
        ...

    def read_synthetic_bytes(self, *, organization_id: str, storage_key: str) -> bytes:
        ...


def validate_magic_bytes(content: bytes, mime_type: str) -> str:
    """Validate binary payload size, MIME allowlist and file signature bytes."""
    if mime_type not in ALLOWED_MIME_TYPES:
        raise StorageValidationError(f"Unsupported MIME type '{mime_type}'.")
    if not content:
        raise StorageValidationError("Empty payload cannot be stored.")
    if mime_type == "application/pdf":
        if not content.startswith(_PDF_MAGIC):
            raise StorageValidationError("PDF payload failed %PDF- magic bytes validation.")
        return "pdf"
    if not content.startswith(_PNG_MAGIC):
        raise StorageValidationError("PNG payload failed binary header validation.")
    return "png"


def _validate_organization_segment(organization_id: str) -> str:
    if (
        not organization_id
        or ".." in organization_id
        or "/" in organization_id
        or "\\" in organization_id
        or not _SAFE_ORG_ID_PATTERN.fullmatch(organization_id)
    ):
        raise StorageValidationError("Invalid organization identifier for storage path.")
    return organization_id


class LocalControlledSyntheticStorage:
    """Controlled filesystem storage strictly scoped outside active source trees."""

    def __init__(
        self,
        root_dir: str | Path,
        *,
        enabled: bool = True,
        max_bytes: int = DEFAULT_MAX_DOCUMENT_BYTES,
        forbidden_parent_dir: str | Path | None = None,
    ) -> None:
        self.enabled = enabled
        self.max_bytes = max_bytes
        self.root_dir = Path(root_dir).resolve()
        if forbidden_parent_dir is not None:
            forbidden_resolved = Path(forbidden_parent_dir).resolve()
            if self.root_dir == forbidden_resolved or self.root_dir.is_relative_to(
                forbidden_resolved
            ):
                raise StorageValidationError(
                    "Storage root must stay outside the tracked Git repository tree."
                )

    def store_synthetic_bytes(
        self,
        *,
        organization_id: str,
        mime_type: str,
        content: bytes,
    ) -> StoredObjectMetadata:
        if not self.enabled:
            raise StorageValidationError("Local synthetic storage is disabled by configuration.")
        if len(content) > self.max_bytes:
            raise StorageValidationError(
                f"Payload exceeds maximum allowed bytes ({self.max_bytes})."
            )
        ext = validate_magic_bytes(content, mime_type)
        safe_org = _validate_organization_segment(organization_id)

        storage_key = f"{safe_org}/{uuid4().hex}.{ext}"
        target_path = (self.root_dir / storage_key).resolve()
        org_dir = (self.root_dir / safe_org).resolve()
        if not target_path.is_relative_to(org_dir) or not org_dir.is_relative_to(self.root_dir):
            raise StorageValidationError("Path traversal attempt rejected by storage boundary.")

        org_dir.mkdir(parents=True, exist_ok=True)
        target_path.write_bytes(content)

        sha256_hex = hashlib.sha256(content).hexdigest()
        logger.info(
            "Stored synthetic binary object safely.",
            extra=build_safe_log_extra(
                organization_id=safe_org,
                mime_type=mime_type,
                byte_size=len(content),
                sha256_prefix=sha256_hex[:12],
            ),
        )
        return StoredObjectMetadata(
            storage_driver=StorageDriver.LOCAL_CONTROLLED_SYNTHETIC.value,
            storage_key=storage_key,
            sha256_hex=sha256_hex,
            mime_type=mime_type,
            byte_size=len(content),
        )

    def read_synthetic_bytes(self, *, organization_id: str, storage_key: str) -> bytes:
        if not self.enabled:
            raise StorageValidationError("Local synthetic storage is disabled by configuration.")
        safe_org = _validate_organization_segment(organization_id)
        if (
            ".." in storage_key
            or "\\" in storage_key
            or not _SAFE_KEY_PATTERN.fullmatch(storage_key)
            or not storage_key.startswith(f"{safe_org}/")
        ):
            raise StorageValidationError("Storage key rejected by tenant boundary or format check.")
        target_path = (self.root_dir / storage_key).resolve()
        org_dir = (self.root_dir / safe_org).resolve()
        if not target_path.is_relative_to(org_dir) or not target_path.is_file():
            raise StorageValidationError("Requested synthetic object is unavailable within tenant scope.")
        return target_path.read_bytes()
