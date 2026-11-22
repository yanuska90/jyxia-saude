"""Zero-dependency streaming RFC 7578 multipart/form-data parser for controlled document uploads.

Streams binary file parts directly into DocumentStoragePort.open_write_stream chunk-by-chunk
so payload size limits are enforced during network read (independent of Content-Length) without
buffering large files in memory.
"""

from __future__ import annotations

from collections.abc import AsyncIterable
from dataclasses import dataclass
import re

from app.services.storage import (
    DocumentStoragePort,
    StoragePayloadTooLargeError,
    StorageUnsupportedFormatError,
    StorageValidationError,
    StorageWriteStream,
    StoredObjectMetadata,
)

_MAX_MULTIPART_HEADER_BYTES = 8 * 1024
_MAX_TOTAL_TEXT_FIELD_BYTES = 16 * 1024
_ALLOWED_FORM_FIELDS: frozenset[str] = frozenset(
    {
        "document_kind",
        "document_subfamily",
        "source_label",
        "external_reference",
        "description",
        "original_filename",
    }
)
_BOUNDARY_PARAM_RE = re.compile(r'boundary=(?:"([^"]+)"|([^\s;]+))', re.IGNORECASE)
_DISPOSITION_PARAM_RE = re.compile(r'([a-zA-Z0-9_\-]+)\s*=\s*(?:"([^"]*)"|([^\s;]*))')


class MultipartUploadError(ValueError):
    """Raised when a multipart/form-data upload request is malformed, incomplete or missing file."""


@dataclass(frozen=True, slots=True)
class ParsedMultipartUpload:
    stored_object: StoredObjectMetadata
    fields: dict[str, str]


def _extract_boundary(content_type: str | None) -> bytes:
    if not content_type or not content_type.strip():
        raise StorageUnsupportedFormatError("Missing Content-Type header; expected multipart/form-data.")
    lower = content_type.strip().lower()
    if not lower.startswith("multipart/form-data"):
        raise StorageUnsupportedFormatError(
            "Unsupported request Content-Type; expected multipart/form-data."
        )
    match = _BOUNDARY_PARAM_RE.search(content_type)
    if not match:
        raise MultipartUploadError("Missing boundary parameter in multipart/form-data Content-Type.")
    boundary_str = (match.group(1) or match.group(2) or "").strip()
    if not boundary_str or len(boundary_str) > 200:
        raise MultipartUploadError("Invalid multipart boundary length.")
    try:
        return boundary_str.encode("ascii")
    except UnicodeEncodeError as exc:
        raise MultipartUploadError("Multipart boundary must be ASCII.") from exc


def _parse_part_headers(raw_header_block: bytes) -> tuple[str, str | None, str | None]:
    """Return (field_name, filename, content_type) from a multipart part header block."""
    try:
        header_text = raw_header_block.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise MultipartUploadError("Invalid UTF-8 in multipart headers.") from exc

    disposition_line: str | None = None
    part_content_type: str | None = None
    for line in header_text.split("\r\n"):
        if not line.strip():
            continue
        if ":" not in line:
            raise MultipartUploadError("Malformed header line in multipart part.")
        h_name, h_val = line.split(":", 1)
        h_name_lower = h_name.strip().lower()
        h_val_clean = h_val.strip()
        if h_name_lower == "content-disposition":
            disposition_line = h_val_clean
        elif h_name_lower == "content-type":
            part_content_type = h_val_clean

    if not disposition_line or not disposition_line.lower().startswith("form-data"):
        raise MultipartUploadError("Multipart part missing form-data Content-Disposition.")

    params: dict[str, str] = {}
    for m in _DISPOSITION_PARAM_RE.finditer(disposition_line):
        key = m.group(1).lower()
        val = m.group(2) if m.group(2) is not None else (m.group(3) or "")
        params[key] = val

    field_name = params.get("name", "").strip()
    if not field_name:
        raise MultipartUploadError("Multipart part missing field name.")
    filename = params.get("filename")
    return field_name, filename, part_content_type


async def parse_multipart_document_upload(
    *,
    content_type: str | None,
    body_stream: AsyncIterable[bytes],
    storage: DocumentStoragePort,
    organization_id: str,
) -> ParsedMultipartUpload:
    """Stream-parse multipart/form-data and write the 'file' part directly to controlled storage."""
    boundary = _extract_boundary(content_type)
    dash_boundary = b"--" + boundary
    delimiter = b"\r\n--" + boundary
    max_stream_bytes = storage.max_bytes + _MAX_TOTAL_TEXT_FIELD_BYTES + 65536

    buffer = bytearray()
    total_stream_bytes = 0
    total_text_bytes = 0
    fields: dict[str, str] = {}

    state = "PREAMBLE"
    current_field_name: str = ""
    current_is_file: bool = False
    current_text_buf = bytearray()
    active_writer: StorageWriteStream | None = None
    stored_object: StoredObjectMetadata | None = None
    saw_closing_boundary = False

    try:
        async for chunk in body_stream:
            if not chunk:
                continue
            total_stream_bytes += len(chunk)
            if total_stream_bytes > max_stream_bytes and active_writer is None:
                raise StoragePayloadTooLargeError(
                    f"Multipart request body exceeds maximum allowed size ({storage.max_bytes} bytes)."
                )
            buffer.extend(chunk)

            while True:
                if state == "PREAMBLE":
                    pos = buffer.find(dash_boundary)
                    if pos == -1:
                        if len(buffer) > len(dash_boundary) + 1024:
                            raise MultipartUploadError("Multipart stream missing initial boundary.")
                        break
                    after = pos + len(dash_boundary)
                    if len(buffer) < after + 2:
                        break
                    suffix = bytes(buffer[after : after + 2])
                    if suffix == b"--":
                        del buffer[: after + 2]
                        saw_closing_boundary = True
                        state = "DONE"
                        break
                    if suffix != b"\r\n":
                        raise MultipartUploadError("Malformed multipart initial boundary line.")
                    del buffer[: after + 2]
                    state = "HEADERS"

                elif state == "HEADERS":
                    hdr_end = buffer.find(b"\r\n\r\n")
                    if hdr_end == -1:
                        if len(buffer) > _MAX_MULTIPART_HEADER_BYTES:
                            raise MultipartUploadError("Multipart part headers exceed size limit.")
                        break
                    raw_headers = bytes(buffer[:hdr_end])
                    del buffer[: hdr_end + 4]
                    field_name, filename, part_ct = _parse_part_headers(raw_headers)
                    current_field_name = field_name

                    if filename is not None or field_name == "file":
                        if field_name != "file":
                            raise MultipartUploadError(
                                f"Unexpected file part '{field_name}'; use field name 'file'."
                            )
                        if stored_object is not None or active_writer is not None:
                            raise MultipartUploadError("Multiple file parts are not permitted.")
                        effective_filename = fields.get("original_filename") or filename
                        active_writer = storage.open_write_stream(
                            organization_id=organization_id,
                            declared_mime_type=part_ct,
                            original_filename=effective_filename if effective_filename else None,
                        )
                        current_is_file = True
                    else:
                        if field_name not in _ALLOWED_FORM_FIELDS:
                            raise MultipartUploadError(f"Unsupported form field '{field_name}'.")
                        if field_name in fields:
                            raise MultipartUploadError(f"Duplicate form field '{field_name}'.")
                        current_is_file = False
                        current_text_buf.clear()
                    state = "BODY"

                elif state == "BODY":
                    delim_pos = buffer.find(delimiter)
                    if delim_pos == -1:
                        # Flush safe prefix to writer/buffer keeping tail that could match delimiter
                        keep_tail = len(delimiter) + 4
                        if len(buffer) > keep_tail:
                            flush_len = len(buffer) - keep_tail
                            piece = bytes(buffer[:flush_len])
                            del buffer[:flush_len]
                            if current_is_file:
                                assert active_writer is not None
                                active_writer.write_chunk(piece)
                            else:
                                total_text_bytes += len(piece)
                                if total_text_bytes > _MAX_TOTAL_TEXT_FIELD_BYTES:
                                    raise MultipartUploadError("Form metadata fields exceed size limit.")
                                current_text_buf.extend(piece)
                        break

                    # Delimiter found; verify we have the 2 bytes after delimiter (\r\n or --)
                    after_delim = delim_pos + len(delimiter)
                    if len(buffer) < after_delim + 2:
                        break
                    tail_marker = bytes(buffer[after_delim : after_delim + 2])
                    if tail_marker not in (b"\r\n", b"--"):
                        # False positive delimiter prefix inside binary payload; flush up to delim_pos + 2
                        piece = bytes(buffer[: delim_pos + 2])
                        del buffer[: delim_pos + 2]
                        if current_is_file:
                            assert active_writer is not None
                            active_writer.write_chunk(piece)
                        else:
                            total_text_bytes += len(piece)
                            if total_text_bytes > _MAX_TOTAL_TEXT_FIELD_BYTES:
                                raise MultipartUploadError("Form metadata fields exceed size limit.")
                            current_text_buf.extend(piece)
                        continue

                    final_piece = bytes(buffer[:delim_pos])
                    del buffer[: after_delim + 2]

                    if current_is_file:
                        assert active_writer is not None
                        if final_piece:
                            active_writer.write_chunk(final_piece)
                        stored_object = active_writer.finalize()
                        active_writer = None
                    else:
                        total_text_bytes += len(final_piece)
                        if total_text_bytes > _MAX_TOTAL_TEXT_FIELD_BYTES:
                            raise MultipartUploadError("Form metadata fields exceed size limit.")
                        current_text_buf.extend(final_piece)
                        try:
                            text_val = current_text_buf.decode("utf-8", errors="strict")
                        except UnicodeDecodeError as exc:
                            raise MultipartUploadError(
                                f"Form field '{current_field_name}' contains invalid UTF-8."
                            ) from exc
                        fields[current_field_name] = text_val
                        current_text_buf.clear()

                    if tail_marker == b"--":
                        saw_closing_boundary = True
                        state = "DONE"
                    else:
                        state = "HEADERS"

                elif state == "DONE":
                    break

        if not saw_closing_boundary or state != "DONE":
            raise MultipartUploadError("Incomplete or interrupted multipart upload stream.")
        if stored_object is None:
            raise MultipartUploadError("Multipart request must include a 'file' part.")
        if "original_filename" in fields:
            from pathlib import Path
            from app.schemas.tenant import validate_safe_original_filename

            try:
                safe_override = validate_safe_original_filename(fields["original_filename"])
            except ValueError as exc:
                raise StorageValidationError(str(exc)) from exc
            if safe_override is not None:
                expected_ext = ".pdf" if stored_object.mime_type == "application/pdf" else ".png"
                lower_ext = Path(safe_override).suffix.lower()
                if lower_ext and lower_ext != expected_ext:
                    raise StorageUnsupportedFormatError(
                        "Filename extension disagrees with validated MIME signature."
                    )
                stored_object = StoredObjectMetadata(
                    storage_driver=stored_object.storage_driver,
                    storage_key=stored_object.storage_key,
                    sha256_hex=stored_object.sha256_hex,
                    mime_type=stored_object.mime_type,
                    byte_size=stored_object.byte_size,
                    original_filename=safe_override,
                )
        return ParsedMultipartUpload(stored_object=stored_object, fields=fields)
    except Exception:
        if active_writer is not None:
            active_writer.abort()
            active_writer = None
        if stored_object is not None:
            storage.delete_uncommitted_object(
                organization_id=organization_id,
                storage_key=stored_object.storage_key,
            )
            stored_object = None
        raise
