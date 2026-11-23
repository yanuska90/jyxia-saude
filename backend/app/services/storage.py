"""Controlled binary storage abstraction confined to synthetic/isolated paths.

Provides symlink checks, structural PDF/PNG signature validation, streaming size checks,
atomic temp-file writes with fsync, post-write SHA-256 verification, compensating rollback
deletion and tenant path isolation.
Intended strictly for controlled synthetic files during development/tests — NOT production storage.
"""

from __future__ import annotations

from collections.abc import Iterable
import hashlib
import logging
import os
import re
import struct
import tempfile
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Protocol
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


class StorageUnavailableError(StorageValidationError):
    """Raised when local controlled synthetic storage is disabled by environment policy."""


class StoragePayloadTooLargeError(StorageValidationError):
    """Raised during streaming or byte validation when payload exceeds max_bytes ceiling."""


class StorageUnsupportedFormatError(StorageValidationError):
    """Raised when MIME type, magic signature or file extension is unsupported or mismatched."""


class StorageObjectNotFoundError(StorageValidationError):
    """Raised when a requested storage object does not exist within the tenant boundary."""


class StorageIntegrityError(StorageValidationError):
    """Raised when a stored object fails post-write or post-read SHA-256/size verification."""


@dataclass(frozen=True, slots=True)
class StoredObjectMetadata:
    storage_driver: str
    storage_key: str
    sha256_hex: str
    mime_type: str
    byte_size: int
    original_filename: str | None = None


@dataclass(frozen=True, slots=True)
class StoredObjectIntegrityReport:
    organization_id: str
    mime_type: str
    expected_sha256_hex: str
    observed_sha256_hex: str
    expected_byte_size: int
    observed_byte_size: int
    sha256_verified: bool
    byte_size_verified: bool
    structural_validation_passed: bool


class StorageWriteStream(Protocol):
    """Streaming writer protocol for chunked validation and atomic storage ingestion."""

    def write_chunk(self, chunk: bytes) -> None: ...
    def finalize(self) -> StoredObjectMetadata: ...
    def abort(self) -> None: ...


class DocumentStoragePort(Protocol):
    """Abstract storage boundary separating persistence metadata from binary storage backend."""

    @property
    def enabled(self) -> bool: ...

    @property
    def max_bytes(self) -> int: ...

    def store_synthetic_bytes(
        self,
        *,
        organization_id: str,
        mime_type: str,
        content: bytes,
        original_filename: str | None = None,
    ) -> StoredObjectMetadata: ...

    def open_write_stream(
        self,
        *,
        organization_id: str,
        declared_mime_type: str | None = None,
        original_filename: str | None = None,
    ) -> StorageWriteStream: ...

    def read_synthetic_bytes(
        self,
        *,
        organization_id: str,
        storage_key: str,
        expected_sha256_hex: str | None = None,
    ) -> bytes: ...

    def verify_object_integrity(
        self,
        *,
        organization_id: str,
        storage_key: str,
        expected_sha256_hex: str,
        expected_byte_size: int,
        mime_type: str,
    ) -> StoredObjectIntegrityReport: ...

    def delete_uncommitted_object(
        self,
        *,
        organization_id: str,
        storage_key: str,
    ) -> None: ...


def _validate_pdf_bytes(content: bytes) -> None:
    if len(content) < 20 or not _PDF_HEADER_RE.match(content):
        raise StorageValidationError("PDF payload failed %PDF- version header validation.")
    tail = content[-1024:]
    eof_idx = tail.rfind(b"%%EOF")
    if eof_idx == -1:
        raise StorageValidationError("PDF payload appears truncated (missing %%EOF trailer).")
    trailing_after_eof = tail[eof_idx + 5 :]
    if trailing_after_eof.strip(b" \t\r\n"):
        raise StorageValidationError("PDF payload contains trailing non-whitespace bytes after %%EOF.")


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


class _PdfStreamValidator:
    """Incremental O(1)-memory validator for PDF header and terminal %%EOF trailer structure."""

    def __init__(self) -> None:
        self._header = bytearray()
        self._tail = bytearray()
        self._total_len = 0
        self._header_checked = False

    def feed(self, chunk: bytes) -> None:
        if not chunk:
            return
        self._total_len += len(chunk)
        if len(self._header) < 64:
            need = 64 - len(self._header)
            self._header.extend(chunk[:need])
        if not self._header_checked and len(self._header) >= 9:
            if not _PDF_HEADER_RE.match(bytes(self._header)):
                raise StorageValidationError("PDF payload failed %PDF- version header validation.")
            self._header_checked = True
        self._tail.extend(chunk)
        if len(self._tail) > 2048:
            del self._tail[:-1024]

    def finalize(self) -> None:
        if self._total_len < 20 or not _PDF_HEADER_RE.match(bytes(self._header)):
            raise StorageValidationError("PDF payload failed %PDF- version header validation.")
        tail_bytes = bytes(self._tail[-1024:])
        eof_idx = tail_bytes.rfind(b"%%EOF")
        if eof_idx == -1:
            raise StorageValidationError("PDF payload appears truncated (missing %%EOF trailer).")
        trailing_after_eof = tail_bytes[eof_idx + 5 :]
        if trailing_after_eof.strip(b" \t\r\n"):
            raise StorageValidationError(
                "PDF payload contains trailing non-whitespace bytes after %%EOF."
            )


class _PngStreamValidator:
    """Incremental O(1)-memory chunk and CRC-32 state machine validator for PNG streams."""

    _STATE_MAGIC = 0
    _STATE_CHUNK_HEADER = 1
    _STATE_CHUNK_DATA = 2
    _STATE_CHUNK_CRC = 3
    _STATE_DONE = 4

    def __init__(self) -> None:
        self._state = self._STATE_MAGIC
        self._buf = bytearray()
        self._chunk_count = 0
        self._chunk_len = 0
        self._chunk_type = b""
        self._chunk_remaining = 0
        self._chunk_crc = 0
        self._ihdr_buf = bytearray()
        self._saw_iend = False
        self._total_len = 0

    def feed(self, chunk: bytes) -> None:
        if not chunk:
            return
        self._total_len += len(chunk)
        mv = memoryview(chunk)
        idx = 0
        n = len(mv)

        while idx < n:
            if self._state == self._STATE_MAGIC:
                need = len(_PNG_MAGIC) - len(self._buf)
                take = min(need, n - idx)
                self._buf.extend(mv[idx : idx + take])
                idx += take
                if len(self._buf) == len(_PNG_MAGIC):
                    if bytes(self._buf) != _PNG_MAGIC:
                        raise StorageValidationError("PNG payload failed binary header validation.")
                    self._buf.clear()
                    self._state = self._STATE_CHUNK_HEADER

            elif self._state == self._STATE_CHUNK_HEADER:
                need = 8 - len(self._buf)
                take = min(need, n - idx)
                self._buf.extend(mv[idx : idx + take])
                idx += take
                if len(self._buf) == 8:
                    length, ctype = struct.unpack("!I4s", bytes(self._buf))
                    self._buf.clear()
                    if self._chunk_count == 0:
                        if ctype != b"IHDR" or length != 13:
                            raise StorageValidationError("PNG must start with valid IHDR chunk.")
                    if ctype == b"IEND" and length != 0:
                        raise StorageValidationError("PNG IEND chunk must have zero length.")
                    self._chunk_len = length
                    self._chunk_type = ctype
                    self._chunk_remaining = length
                    self._chunk_crc = zlib.crc32(ctype)
                    self._ihdr_buf.clear()
                    self._state = (
                        self._STATE_CHUNK_DATA if length > 0 else self._STATE_CHUNK_CRC
                    )

            elif self._state == self._STATE_CHUNK_DATA:
                take = min(self._chunk_remaining, n - idx)
                piece = mv[idx : idx + take]
                self._chunk_crc = zlib.crc32(piece, self._chunk_crc)
                if self._chunk_count == 0:
                    self._ihdr_buf.extend(piece)
                self._chunk_remaining -= take
                idx += take
                if self._chunk_remaining == 0:
                    if self._chunk_count == 0:
                        width, height = struct.unpack("!II", bytes(self._ihdr_buf[:8]))
                        if width == 0 or height == 0:
                            raise StorageValidationError("PNG dimensions must be positive.")
                    self._state = self._STATE_CHUNK_CRC

            elif self._state == self._STATE_CHUNK_CRC:
                need = 4 - len(self._buf)
                take = min(need, n - idx)
                self._buf.extend(mv[idx : idx + take])
                idx += take
                if len(self._buf) == 4:
                    (expected_crc,) = struct.unpack("!I", bytes(self._buf))
                    self._buf.clear()
                    if (self._chunk_crc & 0xFFFFFFFF) != expected_crc:
                        raise StorageValidationError("PNG chunk CRC mismatch.")
                    self._chunk_count += 1
                    if self._chunk_type == b"IEND":
                        self._saw_iend = True
                        self._state = self._STATE_DONE
                    else:
                        self._state = self._STATE_CHUNK_HEADER

            elif self._state == self._STATE_DONE:
                raise StorageValidationError("PNG payload missing valid terminal IEND boundary.")

    def finalize(self) -> None:
        if self._total_len < 33 or not self._saw_iend or self._state != self._STATE_DONE:
            raise StorageValidationError("PNG payload missing valid terminal IEND boundary.")


def sniff_magic_mime_type(prefix: bytes) -> tuple[str, str]:
    """Detect canonical MIME type and extension from file header magic bytes."""
    if not prefix:
        raise StorageValidationError("Empty payload cannot be stored.")
    if prefix.startswith(b"%PDF-"):
        return "application/pdf", "pdf"
    if prefix.startswith(_PNG_MAGIC):
        return "image/png", "png"
    raise StorageUnsupportedFormatError(
        "File signature does not match any supported format (allowed: PDF, PNG)."
    )


def validate_magic_bytes(content: bytes, mime_type: str) -> str:
    """Validate binary payload size, MIME allowlist and structural file integrity."""
    if mime_type not in ALLOWED_MIME_TYPES:
        raise StorageUnsupportedFormatError(f"Unsupported MIME type '{mime_type}'.")
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
            raise StorageValidationError(
                "Symlink or junction detected in controlled synthetic storage path."
            )


class _ControlledStorageStreamWriter:
    """Incremental chunk writer enforcing size limits, magic/structural validation and atomic replace."""

    def __init__(
        self,
        *,
        storage: LocalControlledSyntheticStorage,
        organization_id: str,
        org_dir: Path,
        declared_mime_type: str | None,
        original_filename: str | None,
    ) -> None:
        self._storage = storage
        self._safe_org = organization_id
        self._org_dir = org_dir
        self._declared_mime = (
            declared_mime_type.split(";", 1)[0].strip().lower()
            if declared_mime_type and declared_mime_type.strip()
            else None
        )
        if self._declared_mime and self._declared_mime not in (
            ALLOWED_MIME_TYPES | {"application/octet-stream"}
        ):
            raise StorageUnsupportedFormatError(
                f"Unsupported declared MIME type '{self._declared_mime}'."
            )
        self._raw_original_filename = original_filename
        self._safe_filename: str | None = None
        if original_filename is not None:
            try:
                self._safe_filename = validate_safe_original_filename(original_filename)
            except ValueError as exc:
                raise StorageValidationError(str(exc)) from exc
            if self._safe_filename is not None:
                ext_candidate = Path(self._safe_filename).suffix.lower()
                if ext_candidate and ext_candidate not in {".pdf", ".png"}:
                    raise StorageUnsupportedFormatError(
                        "Unsupported file extension (only .pdf and .png are permitted)."
                    )

        self._tmp_handle: BinaryIO | None = None
        self._tmp_path: Path | None = None
        self._hasher = hashlib.sha256()
        self._bytes_written = 0
        self._header_buf = bytearray()
        self._detected_mime: str | None = None
        self._detected_ext: str | None = None
        self._validator: _PdfStreamValidator | _PngStreamValidator | None = None
        self._closed = False

        try:
            tmp = tempfile.NamedTemporaryFile(
                mode="wb",
                dir=self._org_dir,
                prefix=".tmp_stream_",
                suffix=".part",
                delete=False,
            )
            self._tmp_handle = tmp  # type: ignore[assignment]
            self._tmp_path = Path(tmp.name)
        except OSError as exc:
            raise StorageValidationError(
                f"Controlled synthetic storage temp initialization failed: {type(exc).__name__}"
            ) from exc

    def _ensure_format_initialized(self) -> None:
        if self._validator is not None:
            return
        detected_mime, detected_ext = sniff_magic_mime_type(bytes(self._header_buf))
        if (
            self._declared_mime
            and self._declared_mime != "application/octet-stream"
            and self._declared_mime != detected_mime
        ):
            raise StorageUnsupportedFormatError(
                "Declared Content-Type disagrees with actual file magic signature."
            )
        if self._safe_filename is not None:
            lower_ext = Path(self._safe_filename).suffix.lower()
            if lower_ext and lower_ext != f".{detected_ext}":
                raise StorageUnsupportedFormatError(
                    "Filename extension disagrees with validated MIME signature."
                )
        self._detected_mime = detected_mime
        self._detected_ext = detected_ext
        self._validator = (
            _PdfStreamValidator() if detected_ext == "pdf" else _PngStreamValidator()
        )
        self._validator.feed(bytes(self._header_buf))

    def write_chunk(self, chunk: bytes) -> None:
        if self._closed:
            raise StorageValidationError("Cannot write to a closed storage stream.")
        if not chunk:
            return
        try:
            next_total = self._bytes_written + len(chunk)
            if next_total > self._storage.max_bytes:
                raise StoragePayloadTooLargeError(
                    f"Payload exceeds maximum allowed bytes ({self._storage.max_bytes})."
                )
            if self._validator is None:
                need = max(0, 16 - len(self._header_buf))
                take = min(need, len(chunk))
                self._header_buf.extend(chunk[:take])
                remainder = chunk[take:]
                if len(self._header_buf) >= 8:
                    self._ensure_format_initialized()
                    if remainder and self._validator is not None:
                        self._validator.feed(remainder)
            else:
                self._validator.feed(chunk)

            assert self._tmp_handle is not None
            self._tmp_handle.write(chunk)
            self._hasher.update(chunk)
            self._bytes_written = next_total
        except Exception:
            self.abort()
            raise

    def finalize(self) -> StoredObjectMetadata:
        if self._closed:
            raise StorageValidationError("Storage stream already finalized or aborted.")
        try:
            if self._bytes_written == 0:
                raise StorageValidationError("Empty payload cannot be stored.")
            if self._validator is None:
                self._ensure_format_initialized()
            assert self._validator is not None
            assert self._detected_mime is not None
            assert self._detected_ext is not None
            self._validator.finalize()

            assert self._tmp_handle is not None and self._tmp_path is not None
            self._tmp_handle.flush()
            os.fsync(self._tmp_handle.fileno())
            self._tmp_handle.close()
            self._tmp_handle = None

            expected_sha = self._hasher.hexdigest()
            if self._tmp_path.stat().st_size != self._bytes_written:
                raise StorageIntegrityError("Post-write size verification failed.")

            storage_key = f"{self._safe_org}/{uuid4().hex}.{self._detected_ext}"
            target_raw = self._storage.root_dir / storage_key
            if target_raw.exists() or target_raw.is_symlink():
                raise StorageValidationError(
                    "Generated storage key unexpectedly exists; refusing overwrite."
                )
            target_path = target_raw.resolve()
            if not target_path.is_relative_to(self._org_dir):
                raise StorageValidationError("Path traversal attempt rejected by storage boundary.")

            os.replace(self._tmp_path, target_path)
            self._tmp_path = None
            self._closed = True
            _reject_symlink_chain(target_path, boundary=self._storage.root_dir)

            # Verify stored object checksum on disk matches streamed SHA-256
            verify_hasher = hashlib.sha256()
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(target_path, flags)
            with os.fdopen(fd, "rb") as vf:
                while True:
                    block = vf.read(65536)
                    if not block:
                        break
                    verify_hasher.update(block)
            if verify_hasher.hexdigest() != expected_sha:
                target_path.unlink(missing_ok=True)
                raise StorageIntegrityError("Post-write digest verification failed.")

            logger.info(
                "Stored synthetic binary object safely.",
                extra=build_safe_log_extra(
                    organization_id=self._safe_org,
                    mime_type=self._detected_mime,
                    byte_size=self._bytes_written,
                    sha256_prefix=expected_sha[:12],
                ),
            )
            return StoredObjectMetadata(
                storage_driver=StorageDriver.LOCAL_CONTROLLED_SYNTHETIC.value,
                storage_key=storage_key,
                sha256_hex=expected_sha,
                mime_type=self._detected_mime,
                byte_size=self._bytes_written,
                original_filename=self._safe_filename,
            )
        except StorageValidationError:
            self.abort()
            raise
        except OSError as exc:
            self.abort()
            raise StorageValidationError(
                f"Controlled synthetic storage write failed: {type(exc).__name__}"
            ) from exc
        except Exception:
            self.abort()
            raise

    def abort(self) -> None:
        self._closed = True
        if self._tmp_handle is not None:
            try:
                self._tmp_handle.close()
            except OSError:
                pass
            self._tmp_handle = None
        if self._tmp_path is not None:
            try:
                if self._tmp_path.exists():
                    self._tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
            self._tmp_path = None


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
            raise StorageUnsupportedFormatError(
                "Filename extension disagrees with validated MIME signature."
            )
        return safe_name

    def _prepare_org_dir(self, organization_id: str) -> tuple[str, Path]:
        if not self.enabled:
            raise StorageUnavailableError("Local synthetic storage is disabled by configuration.")
        safe_org = _validate_organization_segment(organization_id)
        _reject_symlink_chain(self.root_dir)
        org_raw = self.root_dir / safe_org
        _reject_symlink_chain(org_raw, boundary=self.root_dir)
        org_dir = org_raw.resolve()
        if not org_dir.is_relative_to(self.root_dir):
            raise StorageValidationError("Organization directory escaped storage boundary.")
        org_dir.mkdir(parents=True, exist_ok=True)
        _reject_symlink_chain(org_dir, boundary=self.root_dir)
        return safe_org, org_dir

    def open_write_stream(
        self,
        *,
        organization_id: str,
        declared_mime_type: str | None = None,
        original_filename: str | None = None,
    ) -> _ControlledStorageStreamWriter:
        """Open a streaming chunk writer with incremental magic/structure and size enforcement."""
        safe_org, org_dir = self._prepare_org_dir(organization_id)
        return _ControlledStorageStreamWriter(
            storage=self,
            organization_id=safe_org,
            org_dir=org_dir,
            declared_mime_type=declared_mime_type,
            original_filename=original_filename,
        )

    def store_synthetic_chunks(
        self,
        *,
        organization_id: str,
        chunks: Iterable[bytes],
        declared_mime_type: str | None = None,
        original_filename: str | None = None,
    ) -> StoredObjectMetadata:
        writer = self.open_write_stream(
            organization_id=organization_id,
            declared_mime_type=declared_mime_type,
            original_filename=original_filename,
        )
        try:
            for chunk in chunks:
                writer.write_chunk(chunk)
            return writer.finalize()
        except Exception:
            writer.abort()
            raise

    def store_synthetic_bytes(
        self,
        *,
        organization_id: str,
        mime_type: str,
        content: bytes,
        original_filename: str | None = None,
    ) -> StoredObjectMetadata:
        if not self.enabled:
            raise StorageUnavailableError("Local synthetic storage is disabled by configuration.")
        if len(content) > self.max_bytes:
            raise StoragePayloadTooLargeError(
                f"Payload exceeds maximum allowed bytes ({self.max_bytes})."
            )
        ext = validate_magic_bytes(content, mime_type)
        safe_filename = self._validate_extension_match(original_filename, ext)
        safe_org, org_dir = self._prepare_org_dir(organization_id)

        storage_key = f"{safe_org}/{uuid4().hex}.{ext}"
        target_raw = self.root_dir / storage_key
        if target_raw.exists() or target_raw.is_symlink():
            raise StorageValidationError(
                "Generated storage key unexpectedly exists; refusing overwrite."
            )
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
                        raise StoragePayloadTooLargeError("Written stream exceeded max_bytes ceiling.")
                    tmp.write(chunk)
                    hasher.update(chunk)
                tmp.flush()
                os.fsync(tmp.fileno())

            if hasher.hexdigest() != expected_sha or tmp_path.stat().st_size != len(content):
                raise StorageIntegrityError("Post-write digest/size verification failed.")

            os.replace(tmp_path, target_path)
            tmp_path = None
            _reject_symlink_chain(target_path, boundary=self.root_dir)
        except OSError as exc:
            raise StorageValidationError(
                f"Controlled synthetic storage write failed: {type(exc).__name__}"
            ) from exc
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
            raise StorageUnavailableError("Local synthetic storage is disabled by configuration.")
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
            raise StorageObjectNotFoundError(
                "Requested synthetic object is unavailable within tenant scope."
            )

        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(target_path, flags)
            with os.fdopen(fd, "rb") as handle:
                data = handle.read(self.max_bytes + 1)
        except OSError as exc:
            raise StorageValidationError("Unable to open controlled synthetic object.") from exc

        if len(data) > self.max_bytes:
            raise StoragePayloadTooLargeError("Stored object exceeds max_bytes safety ceiling.")
        if (
            expected_sha256_hex is not None
            and hashlib.sha256(data).hexdigest() != expected_sha256_hex
        ):
            raise StorageIntegrityError("Stored binary checksum mismatch.")
        return data

    def verify_object_integrity(
        self,
        *,
        organization_id: str,
        storage_key: str,
        expected_sha256_hex: str,
        expected_byte_size: int,
        mime_type: str,
    ) -> StoredObjectIntegrityReport:
        """Stream-verify object existence, SHA-256 checksum, byte size, and structural format."""
        if not self.enabled:
            raise StorageUnavailableError("Controlled storage is currently unavailable.")

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

        if mime_type not in {"application/pdf", "image/png"}:
            raise StorageUnsupportedFormatError(
                f"Unsupported mime_type '{mime_type}' for structural verification."
            )

        if not self.root_dir.exists():
            raise StorageUnavailableError("Controlled storage directory is currently unavailable.")

        _reject_symlink_chain(self.root_dir)
        target_raw = self.root_dir / storage_key
        org_raw = self.root_dir / safe_org
        _reject_symlink_chain(target_raw, boundary=self.root_dir)
        org_dir = org_raw.resolve()
        target_path = target_raw.resolve()
        if not org_dir.is_relative_to(self.root_dir) or not target_path.is_relative_to(org_dir):
            raise StorageValidationError("Requested synthetic object escaped tenant boundary.")
        if not target_path.is_file():
            raise StorageObjectNotFoundError(
                "Requested synthetic object is missing within tenant storage scope."
            )

        validator: _PdfStreamValidator | _PngStreamValidator = (
            _PdfStreamValidator() if mime_type == "application/pdf" else _PngStreamValidator()
        )
        hasher = hashlib.sha256()
        observed_byte_size = 0
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(target_path, flags)
            with os.fdopen(fd, "rb") as handle:
                while True:
                    chunk = handle.read(65536)
                    if not chunk:
                        break
                    observed_byte_size += len(chunk)
                    if observed_byte_size > self.max_bytes:
                        raise StoragePayloadTooLargeError(
                            "Stored object exceeds max_bytes safety ceiling."
                        )
                    hasher.update(chunk)
                    try:
                        validator.feed(chunk)
                    except StorageUnsupportedFormatError:
                        raise
                    except StorageValidationError as exc:
                        raise StorageUnsupportedFormatError(str(exc)) from exc
        except FileNotFoundError as exc:
            raise StorageObjectNotFoundError(
                "Requested synthetic object vanished during verification."
            ) from exc
        except (
            StorageObjectNotFoundError,
            StoragePayloadTooLargeError,
            StorageUnsupportedFormatError,
            StorageValidationError,
        ):
            raise
        except OSError as exc:
            raise StorageUnavailableError(
                "Controlled storage I/O unavailable during integrity verification."
            ) from exc

        if observed_byte_size <= 0:
            raise StorageIntegrityError("Stored binary object is empty.")

        try:
            validator.finalize()
        except StorageUnsupportedFormatError:
            raise
        except StorageValidationError as exc:
            raise StorageUnsupportedFormatError(str(exc)) from exc
        observed_sha256_hex = hasher.hexdigest()
        if observed_byte_size != expected_byte_size:
            raise StorageIntegrityError(
                "Stored binary byte size differs from registered document version."
            )
        if observed_sha256_hex != expected_sha256_hex:
            raise StorageIntegrityError(
                "Stored binary SHA-256 differs from registered document version."
            )

        return StoredObjectIntegrityReport(
            organization_id=safe_org,
            mime_type=mime_type,
            expected_sha256_hex=expected_sha256_hex,
            observed_sha256_hex=observed_sha256_hex,
            expected_byte_size=expected_byte_size,
            observed_byte_size=observed_byte_size,
            sha256_verified=True,
            byte_size_verified=True,
            structural_validation_passed=True,
        )

    def delete_uncommitted_object(
        self,
        *,
        organization_id: str,
        storage_key: str,
    ) -> None:
        """Compensating cleanup for newly written objects whose DB transaction rolled back."""
        if not self.enabled:
            return
        safe_org = _validate_organization_segment(organization_id)
        if (
            not storage_key
            or "\x00" in storage_key
            or ".." in storage_key
            or "\\" in storage_key
            or not _SAFE_KEY_PATTERN.fullmatch(storage_key)
            or not storage_key.startswith(f"{safe_org}/")
        ):
            return
        try:
            _reject_symlink_chain(self.root_dir)
            target_raw = self.root_dir / storage_key
            org_raw = self.root_dir / safe_org
            _reject_symlink_chain(target_raw, boundary=self.root_dir)
            org_dir = org_raw.resolve()
            target_path = target_raw.resolve()
            if org_dir.is_relative_to(self.root_dir) and target_path.is_relative_to(org_dir):
                if target_path.is_file():
                    target_path.unlink(missing_ok=True)
        except (OSError, StorageValidationError):
            logger.warning(
                "Compensating cleanup could not unlink uncommitted object.",
                extra=build_safe_log_extra(organization_id=safe_org),
            )
