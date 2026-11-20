"""Controlled binary storage abstraction confined to synthetic/isolated paths.

Provides symlink checks, structural PDF/PNG signature validation, streaming size checks,
atomic temp-file writes with fsync, post-write SHA-256 verification and tenant path isolation.
Intended strictly for controlled synthetic files during development/tests — NOT production storage.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import struct
import tempfile
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from uuid import uuid4

from app.core.constants import ALLOWED_MIME_TYPES, DEFAULT_MAX_DOCUMENT_BYTES, StorageDriver
from app.core.logging import LOGGER_NAME, build_safe_log_extra
from app.schemas.tenant import validate_safe_original_filename

logger = logging.getLogger(LOGGER_NAME)

_PDF_HEADER_RE = re.compile(rb"^%PDF-(?:1\.[0-7]|2\.0)[\r\n\s]")
_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_SAFE_ORG_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9\-_]{0,63}$")
_SAFE_KEY_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9\-_]{0,63}/[a-f0-9]{32}\.(pdf|png)$")


class StorageValidationError(ValueError):
    """Raised fail-closed on unsupported MIME, magic bytes, truncation, symlink or traversal."""


@dataclass(frozen=True, slots=True)
class StoredObjectMetadata:
    storage_driver: str
    storage_key: str
    sha256_hex: str
    mime_type: str
    byte_size: int
    original_filename: str | None = None


class DocumentStoragePort(Protocol):
    """Abstract storage boundary separating persistence metadata from binary storage backend."""

    def store_synthetic_bytes(
        self,
        *,
        organization_id: str,
        mime_type: str,
        content: bytes,
        original_filename: str | None = None,
    ) -> StoredObjectMetadata:
        ...

    def read_synthetic_bytes(
        self,
        *,
        organization_id: str,
        storage_key: str,
        expected_sha256_hex: str | None = None,
    ) -> bytes:
        ...


def _validate_pdf_bytes(content: bytes) -> None:
    if len(content) < 20 or not _PDF_HEADER_RE.match(content):
        raise StorageValidationError("PDF payload failed %PDF- version header validation.")
    tail = content[-1024:]
    if b"%%EOF" not in tail:
        raise StorageValidationError("PDF payload appears truncated (missing %%EOF trailer).")


def _validate_png_bytes(content: bytes) -> None:
    if len(content) < 33 or not content.startswith(_PNG_MAGIC):
        raise StorageValidationError("PNG payload failed binary header validation.")
    pos = len(_PNG_MAGIC)
    chunk_count = 0
    saw_iend = False
    while pos + 12 <= len(content):
        length, ctype = struct.unpack("!I4s", content[pos : pos + 8])
        end_data = pos + 8 + length
        if end_data + 4 > len(content):
            raise StorageValidationError("PNG payload truncated mid-chunk.")
        chunk_data = content[pos + 8 : end_data]
        (crc,) = struct.unpack("!I", content[end_data : end_data + 4])
        if (zlib.crc32(ctype + chunk_data) & 0xFFFFFFFF) != crc:
            raise StorageValidationError("PNG chunk CRC mismatch.")
        if chunk_count == 0:
            if ctype != b"IHDR" or length != 13:
                raise StorageValidationError("PNG must start with valid IHDR chunk.")
            width, height = struct.unpack("!II", chunk_data[:8])
            if width == 0 or height == 0:
                raise StorageValidationError("PNG dimensions must be positive.")
        chunk_count += 1
        pos = end_data + 4
        if ctype == b"IEND":
            if length != 0:
                raise StorageValidationError("PNG IEND chunk must have zero length.")
            saw_iend = True
            break
    if not saw_iend or pos != len(content):
        raise StorageValidationError("PNG payload missing valid terminal IEND boundary.")


def validate_magic_bytes(content: bytes, mime_type: str) -> str:
    """Validate binary payload size, MIME allowlist and structural file integrity."""
    if mime_type not in ALLOWED_MIME_TYPES:
        raise StorageValidationError(f"Unsupported MIME type '{mime_type}'.")
    if not content:
        raise StorageValidationError("Empty payload cannot be stored.")
    if mime_type == "application/pdf":
        _validate_pdf_bytes(content)
        return "pdf"
    _validate_png_bytes(content)
    return "png"


def _validate_organization_segment(organization_id: str) -> str:
    if (
        not organization_id
        or ".." in organization_id
        or "/" in organization_id
        or "\\" in organization_id
        or "\x00" in organization_id
        or not _SAFE_ORG_ID_PATTERN.fullmatch(organization_id)
    ):
        raise StorageValidationError("Invalid organization identifier for storage path.")
    return organization_id


def _reject_symlink_chain(path: Path, *, boundary: Path | None = None) -> None:
    """Reject symlinks on existing paths/components before resolving or traversing."""
    probe = Path(path)
    to_check: list[Path] = []
    if boundary is not None:
        cur = probe
        while True:
            to_check.append(cur)
            if cur == boundary or cur.parent == cur:
                break
            cur = cur.parent
    else:
        to_check.append(probe)
        for parent in probe.parents:
            to_check.append(parent)
            if parent.parent == parent:
                break

    for candidate in to_check:
        if candidate.is_symlink() or (hasattr(candidate, "is_junction") and candidate.is_junction()):
            raise StorageValidationError("Symlink or junction detected in controlled synthetic storage path.")


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
        raw_root = Path(root_dir)
        _reject_symlink_chain(raw_root)
        self.root_dir = raw_root.resolve()
        if forbidden_parent_dir is not None:
            forbidden_resolved = Path(forbidden_parent_dir).resolve()
            if self.root_dir == forbidden_resolved or self.root_dir.is_relative_to(
                forbidden_resolved
            ):
                raise StorageValidationError(
                    "Storage root must stay outside the tracked Git repository tree."
                )

    def _validate_extension_match(self, filename: str | None, expected_ext: str) -> str | None:
        if filename is None:
            return None
        try:
            safe_name = validate_safe_original_filename(filename)
        except ValueError as exc:
            raise StorageValidationError(str(exc)) from exc
        if safe_name is None:
            return None
        lower_ext = Path(safe_name).suffix.lower()
        if lower_ext and lower_ext != f".{expected_ext}":
            raise StorageValidationError("Filename extension disagrees with validated MIME signature.")
        return safe_name

    def store_synthetic_bytes(
        self,
        *,
        organization_id: str,
        mime_type: str,
        content: bytes,
        original_filename: str | None = None,
    ) -> StoredObjectMetadata:
        if not self.enabled:
            raise StorageValidationError("Local synthetic storage is disabled by configuration.")
        if len(content) > self.max_bytes:
            raise StorageValidationError(
                f"Payload exceeds maximum allowed bytes ({self.max_bytes})."
            )
        ext = validate_magic_bytes(content, mime_type)
        safe_filename = self._validate_extension_match(original_filename, ext)
        safe_org = _validate_organization_segment(organization_id)

        _reject_symlink_chain(self.root_dir)
        org_raw = self.root_dir / safe_org
        _reject_symlink_chain(org_raw, boundary=self.root_dir)
        org_dir = org_raw.resolve()
        if not org_dir.is_relative_to(self.root_dir):
            raise StorageValidationError("Organization directory escaped storage boundary.")
        org_dir.mkdir(parents=True, exist_ok=True)
        _reject_symlink_chain(org_dir, boundary=self.root_dir)

        storage_key = f"{safe_org}/{uuid4().hex}.{ext}"
        target_raw = self.root_dir / storage_key
        if target_raw.exists() or target_raw.is_symlink():
            raise StorageValidationError("Generated storage key unexpectedly exists; refusing overwrite.")
        target_path = target_raw.resolve()
        if not target_path.is_relative_to(org_dir):
            raise StorageValidationError("Path traversal attempt rejected by storage boundary.")

        expected_sha = hashlib.sha256(content).hexdigest()
        tmp_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=org_dir,
                prefix=".tmp_",
                suffix=f".{ext}",
                delete=False,
            ) as tmp:
                tmp_path = Path(tmp.name)
                written = 0
                hasher = hashlib.sha256()
                chunk_size = 65536
                for offset in range(0, len(content), chunk_size):
                    chunk = content[offset : offset + chunk_size]
                    written += len(chunk)
                    if written > self.max_bytes:
                        raise StorageValidationError("Written stream exceeded max_bytes ceiling.")
                    tmp.write(chunk)
                    hasher.update(chunk)
                tmp.flush()
                os.fsync(tmp.fileno())

            if hasher.hexdigest() != expected_sha or tmp_path.stat().st_size != len(content):
                raise StorageValidationError("Post-write digest/size verification failed.")

            os.replace(tmp_path, target_path)
            tmp_path = None
            _reject_symlink_chain(target_path, boundary=self.root_dir)
        except OSError as exc:
            raise StorageValidationError(f"Controlled synthetic storage write failed: {type(exc).__name__}") from exc
        finally:
            if tmp_path is not None and tmp_path.exists():
                tmp_path.unlink(missing_ok=True)

        logger.info(
            "Stored synthetic binary object safely.",
            extra=build_safe_log_extra(
                organization_id=safe_org,
                mime_type=mime_type,
                byte_size=len(content),
                sha256_prefix=expected_sha[:12],
            ),
        )
        return StoredObjectMetadata(
            storage_driver=StorageDriver.LOCAL_CONTROLLED_SYNTHETIC.value,
            storage_key=storage_key,
            sha256_hex=expected_sha,
            mime_type=mime_type,
            byte_size=len(content),
            original_filename=safe_filename,
        )

    def read_synthetic_bytes(
        self,
        *,
        organization_id: str,
        storage_key: str,
        expected_sha256_hex: str | None = None,
    ) -> bytes:
        if not self.enabled:
            raise StorageValidationError("Local synthetic storage is disabled by configuration.")
        safe_org = _validate_organization_segment(organization_id)
        if (
            not storage_key
            or "\x00" in storage_key
            or ".." in storage_key
            or "\\" in storage_key
            or not _SAFE_KEY_PATTERN.fullmatch(storage_key)
            or not storage_key.startswith(f"{safe_org}/")
        ):
            raise StorageValidationError("Storage key rejected by tenant boundary or format check.")

        _reject_symlink_chain(self.root_dir)
        target_raw = self.root_dir / storage_key
        org_raw = self.root_dir / safe_org
        _reject_symlink_chain(target_raw, boundary=self.root_dir)
        org_dir = org_raw.resolve()
        target_path = target_raw.resolve()
        if not org_dir.is_relative_to(self.root_dir) or not target_path.is_relative_to(org_dir):
            raise StorageValidationError("Requested synthetic object escaped tenant boundary.")
        if not target_path.is_file():
            raise StorageValidationError("Requested synthetic object is unavailable within tenant scope.")

        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(target_path, flags)
            with os.fdopen(fd, "rb") as handle:
                data = handle.read(self.max_bytes + 1)
        except OSError as exc:
            raise StorageValidationError("Unable to open controlled synthetic object.") from exc

        if len(data) > self.max_bytes:
            raise StorageValidationError("Stored object exceeds max_bytes safety ceiling.")
        if expected_sha256_hex is not None and hashlib.sha256(data).hexdigest() != expected_sha256_hex:
            raise StorageValidationError("Stored binary checksum mismatch.")
        return data
