"""Deterministic offline PDF text extraction, allowlist field parsing and spatial evidence mapping.

Strictly non-clinical, offline, zero-network, zero-JavaScript, pure-Python extraction using
pdfminer.six. Never invents values, never infers clinical equivalences, never silently clips
invalid bounding boxes, and abstains explicitly whenever textual evidence is missing or invalid.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
import io
import json
import math
import re
import time
import unicodedata
from typing import Any

from pdfminer.converter import PDFPageAggregator
from pdfminer.layout import (
    LAParams,
    LTAnno,
    LTChar,
    LTFigure,
    LTImage,
    LTPage,
    LTTextBox,
    LTTextLine,
)
from pdfminer.pdfdocument import (
    PDFDocument,
    PDFEncryptionError,
    PDFNoValidXRef,
    PDFPasswordIncorrect,
    PDFTextExtractionNotAllowed,
)
from pdfminer.pdfinterp import PDFPageInterpreter, PDFResourceManager
from pdfminer.pdfpage import PDFPage
from pdfminer.pdfparser import PDFParser, PDFSyntaxError
from pdfminer.pdftypes import PDFException
from pdfminer.psparser import PSException

from app.core.constants import (
    DEFAULT_PDF_EXTRACTION_TIMEOUT_SECONDS,
    DEFAULT_PDF_MAX_BLOCKS_PER_PAGE,
    DEFAULT_PDF_MAX_COMPLEXITY_OBJECTS,
    DEFAULT_PDF_MAX_EXTRACTED_CHARS,
    DEFAULT_PDF_MAX_PAGES,
    DEFAULT_PDF_MAX_WORDS_PER_DOC,
    DEFAULT_PDF_TEXT_EXTRACTOR_VERSION,
    EXPLICIT_ALLOWLIST_FIELD_KEYS,
    ExtractedFieldStatus,
)
from app.core.processing_contracts import NormalizedBoundingBox

EXTRACTOR_ENGINE_NAME = "pdfminer.six"
EXTRACTOR_ENGINE_VERSION = "20260107"
EVIDENCE_METHOD_PDF_TEXT = "pdf_text_geometry_pdfminer"
EVIDENCE_METHOD_ABSTAINED_MARKER = "pdf_text_marker_abstained"

_FLOAT_SNAP_EPS = 1e-6
_BBOX_SUM_EPS = 1.00001
_INLINE_CODE_SYSTEM_RE = re.compile(r"^\[([A-Za-z0-9][A-Za-z0-9._-]{1,39})\]\s*(.+)$")
_DATE_DMY_SLASH_RE = re.compile(r"^(\d{2})/(\d{2})/(\d{4})$")
_DATE_DMY_DASH_RE = re.compile(r"^(\d{2})-(\d{2})-(\d{4})$")
_DATE_ISO_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})$")

# Explicit prefix allowlist anchored strictly at line start before ':' — zero fuzzy matching.
_PREFIX_TO_FIELD_KEY: dict[str, str] = {
    "paciente": "patient",
    "nascimento": "birth_date",
    "data de nascimento": "birth_date",
    "identificador": "identifier",
    "emissao": "issue_date",
    "data de emissao": "issue_date",
    "tipo": "document_type",
    "tipo documental": "document_type",
    "origem": "origin",
    "subfamilia": "subfamily",
    "procedimento": "procedure",
    "sistema": "procedure_code_system",
    "sistema de codificacao": "procedure_code_system",
    "sistemacodigo": "procedure_code_system",
    "tabelacodigo": "procedure_code_system",
    "codigo": "procedure_code",
    "lateralidade": "laterality",
}

_KNOWN_DOC_TYPES: dict[str, str] = {
    "solicitacao": "solicitacao",
    "avaliacao": "avaliacao",
    "laudo": "laudo",
    "termo": "termo",
}

_LATERALITY_CANONICAL: dict[str, str] = {
    "od": "OD",
    "olho direito": "OD",
    "olho direito (od)": "OD",
    "oe": "OE",
    "olho esquerdo": "OE",
    "olho esquerdo (oe)": "OE",
    "ao": "AO",
    "ambos os olhos": "AO",
    "ambos olhos": "AO",
    "bilateral": "AO",
    "ao (ambos os olhos)": "AO",
    "od e oe": "AO",
    "nao aplicavel": "NA",
    "nao se aplica": "NA",
}


class PdfExtractionError(RuntimeError):
    """Sanitized technical extraction failure preventing arbitrary retry on invalid PDFs."""

    def __init__(self, error_code: str, error_detail: str) -> None:
        self.error_code = error_code
        self.error_detail = error_detail
        super().__init__(error_detail)


class InvalidBoundingBoxError(ValueError):
    """Raised when transformed page geometry violates [0, 1] normalized bounds."""


@dataclass(frozen=True, slots=True)
class PdfExtractionLimits:
    """Conservative resource ceilings guarding the worker against hostile PDFs."""

    max_pages: int = DEFAULT_PDF_MAX_PAGES
    max_extracted_chars: int = DEFAULT_PDF_MAX_EXTRACTED_CHARS
    max_words: int = DEFAULT_PDF_MAX_WORDS_PER_DOC
    max_blocks_per_page: int = DEFAULT_PDF_MAX_BLOCKS_PER_PAGE
    timeout_seconds: float = DEFAULT_PDF_EXTRACTION_TIMEOUT_SECONDS
    max_complexity_objects: int = DEFAULT_PDF_MAX_COMPLEXITY_OBJECTS


@dataclass(frozen=True, slots=True)
class ExtractedWordElement:
    text: str
    raw_bbox: tuple[float, float, float, float]
    normalized_bbox: NormalizedBoundingBox | None
    bbox_valid: bool
    bbox_error: str | None = None
    reading_order: int = 0


@dataclass(frozen=True, slots=True)
class ExtractedLineElement:
    page_number: int
    block_index: int
    reading_order: int
    text: str
    raw_text: str
    raw_bbox: tuple[float, float, float, float]
    normalized_bbox: NormalizedBoundingBox | None
    bbox_valid: bool
    bbox_error: str | None = None
    words: list[ExtractedWordElement] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class ExtractedBlockElement:
    page_number: int
    block_index: int
    text: str
    raw_bbox: tuple[float, float, float, float]
    normalized_bbox: NormalizedBoundingBox | None
    bbox_valid: bool
    bbox_error: str | None = None


@dataclass(frozen=True, slots=True)
class ExtractedPageData:
    page_number: int
    mediabox: tuple[float, float, float, float]
    cropbox: tuple[float, float, float, float]
    rotation: int
    viewport_width: float
    viewport_height: float
    status: str  # "extracted" | "abstained"
    reason_code: str | None
    has_image_objects: bool
    char_count: int
    word_count: int
    line_count: int
    block_count: int
    invalid_bbox_count: int
    blocks: list[ExtractedBlockElement]
    lines: list[ExtractedLineElement]
    full_text: str


@dataclass(frozen=True, slots=True)
class EvidenceCandidatePayload:
    page_number: int
    bbox: NormalizedBoundingBox
    quote_excerpt: str
    extraction_method: str


@dataclass(frozen=True, slots=True)
class ExtractedFieldPayload:
    field_key: str
    status: ExtractedFieldStatus
    abstained: bool
    raw_value: str | None
    normalized_value: str | None
    metadata_json: dict[str, Any]
    evidences: list[EvidenceCandidatePayload]


@dataclass(frozen=True, slots=True)
class DocumentTextExtractionResult:
    extractor_version: str
    engine_name: str
    engine_version: str
    source_sha256_hex: str | None
    mime_type: str
    outcome: str  # "executed" | "partial" | "abstained"
    reason_code: str | None
    readable: bool
    partial: bool
    abstained: bool
    ocr_available: bool
    page_count: int
    readable_page_count: int
    abstained_pages: list[int]
    total_chars: int
    total_words: int
    total_lines: int
    pages: list[ExtractedPageData]
    fields: list[ExtractedFieldPayload]
    present_field_keys: list[str]
    absent_field_keys: list[str]
    unrecognized_prefixed_labels: list[str]
    administrative_only: bool = True
    clinical_approval: bool = False

    def to_derived_artifact_json_bytes(self) -> bytes:
        """Serialize complete per-page structured extraction without mutating result_json size."""
        payload = {
            "schema": "jyxia.pdf_extraction_artifact.v1",
            "extractor_version": self.extractor_version,
            "engine_name": self.engine_name,
            "engine_version": self.engine_version,
            "source_sha256_hex": self.source_sha256_hex,
            "mime_type": self.mime_type,
            "outcome": self.outcome,
            "reason_code": self.reason_code,
            "readable": self.readable,
            "partial": self.partial,
            "abstained": self.abstained,
            "ocr_available": self.ocr_available,
            "page_count": self.page_count,
            "readable_page_count": self.readable_page_count,
            "abstained_pages": self.abstained_pages,
            "administrative_only": True,
            "clinical_approval": False,
            "pages": [
                {
                    "page_number": pg.page_number,
                    "mediabox": list(pg.mediabox),
                    "cropbox": list(pg.cropbox),
                    "rotation": pg.rotation,
                    "viewport_width": pg.viewport_width,
                    "viewport_height": pg.viewport_height,
                    "status": pg.status,
                    "reason_code": pg.reason_code,
                    "has_image_objects": pg.has_image_objects,
                    "char_count": pg.char_count,
                    "word_count": pg.word_count,
                    "line_count": pg.line_count,
                    "block_count": pg.block_count,
                    "invalid_bbox_count": pg.invalid_bbox_count,
                    "text": pg.full_text,
                    "blocks": [
                        {
                            "block_index": b.block_index,
                            "text": b.text,
                            "raw_bbox": list(b.raw_bbox),
                            "bbox": (
                                [b.normalized_bbox.x, b.normalized_bbox.y, b.normalized_bbox.w, b.normalized_bbox.h]
                                if b.normalized_bbox is not None
                                else None
                            ),
                            "bbox_valid": b.bbox_valid,
                            "bbox_error": b.bbox_error,
                        }
                        for b in pg.blocks
                    ],
                    "lines": [
                        {
                            "reading_order": ln.reading_order,
                            "block_index": ln.block_index,
                            "text": ln.text,
                            "raw_bbox": list(ln.raw_bbox),
                            "bbox": (
                                [ln.normalized_bbox.x, ln.normalized_bbox.y, ln.normalized_bbox.w, ln.normalized_bbox.h]
                                if ln.normalized_bbox is not None
                                else None
                            ),
                            "bbox_valid": ln.bbox_valid,
                            "bbox_error": ln.bbox_error,
                            "words": [
                                {
                                    "reading_order": w.reading_order,
                                    "text": w.text,
                                    "raw_bbox": list(w.raw_bbox),
                                    "bbox": (
                                        [
                                            w.normalized_bbox.x,
                                            w.normalized_bbox.y,
                                            w.normalized_bbox.w,
                                            w.normalized_bbox.h,
                                        ]
                                        if w.normalized_bbox is not None
                                        else None
                                    ),
                                    "bbox_valid": w.bbox_valid,
                                    "bbox_error": w.bbox_error,
                                }
                                for w in ln.words
                            ],
                        }
                        for ln in pg.lines
                    ],
                }
                for pg in self.pages
            ],
        }
        return json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")


def _strip_diacritics_lower(text: str) -> str:
    decomposed = unicodedata.normalize("NFD", text)
    stripped = "".join(ch for ch in decomposed if unicodedata.category(ch) != "Mn")
    return " ".join(stripped.lower().split())


def _normalize_whitespace_nfc(value: str) -> str:
    return " ".join(unicodedata.normalize("NFC", value).split())


def _contains_corrupt_control_chars(value: str) -> bool:
    for ch in value:
        if ch == "\ufffd":
            return True
        code = ord(ch)
        if code < 32 and ch not in ("\t", "\n", "\r"):
            return True
        if code == 127:
            return True
    return False


_UNMAPPED_CID_RE = re.compile(r"\(cid:\d+\)")


def _has_meaningful_printable_text(text: str) -> bool:
    without_cids = _UNMAPPED_CID_RE.sub("", text)
    return any(ch.isalnum() for ch in without_cids)


def _is_garbled_text_layer(text: str) -> bool:
    if _contains_corrupt_control_chars(text):
        return True
    return not _has_meaningful_printable_text(text)


def _compute_crop_in_ltpage_space(
    *,
    mediabox: tuple[float, float, float, float],
    cropbox: tuple[float, float, float, float],
    rotation: int,
) -> tuple[float, float, float, float]:
    """Map effective CropBox∩MediaBox into pdfminer LTPage coordinates for 0/90/180/270°."""
    mx0, my0, mx1, my1 = mediabox
    rx0, ry0, rx1, ry1 = cropbox
    if rotation not in (0, 90, 180, 270):
        raise PdfExtractionError("UNSUPPORTED_PAGE_ROTATION", f"Unsupported PDF rotation {rotation}.")
    cx0 = max(mx0, rx0)
    cy0 = max(my0, ry0)
    cx1 = min(mx1, rx1)
    cy1 = min(my1, ry1)
    if not all(math.isfinite(v) for v in (mx0, my0, mx1, my1, cx0, cy0, cx1, cy1)):
        raise PdfExtractionError("PDF_CORRUPTED", "PDF page contains non-finite box coordinates.")
    if cx1 <= cx0 or cy1 <= cy0:
        raise PdfExtractionError("PDF_CORRUPTED", "PDF page CropBox has empty or inverted dimensions.")

    if rotation == 0:
        return (cx0 - mx0, cy0 - my0, cx1 - mx0, cy1 - my0)
    if rotation == 90:
        return (cy0 - my0, mx1 - cx1, cy1 - my0, mx1 - cx0)
    if rotation == 180:
        return (mx1 - cx1, my1 - cy1, mx1 - cx0, my1 - cy0)
    # rotation == 270
    return (my1 - cy1, cx0 - mx0, my1 - cy0, cx1 - mx0)


def normalize_ltpage_bbox_to_viewport(
    *,
    raw_bbox: tuple[float, float, float, float],
    crop_lt_bbox: tuple[float, float, float, float],
) -> NormalizedBoundingBox:
    """Transform an LTPage bottom-up box into validated top-left [x, y, w, h] in [0, 1].

    Never silently clips out-of-bounds boxes: raises InvalidBoundingBoxError instead.
    """
    if len(raw_bbox) != 4 or not all(math.isfinite(float(v)) for v in raw_bbox):
        raise InvalidBoundingBoxError("Bounding box contains non-finite coordinates.")

    bx0, by0, bx1, by1 = (float(raw_bbox[0]), float(raw_bbox[1]), float(raw_bbox[2]), float(raw_bbox[3]))
    cb_lx0, cb_ly0, cb_lx1, cb_ly1 = crop_lt_bbox
    vp_w = cb_lx1 - cb_lx0
    vp_h = cb_ly1 - cb_ly0
    if vp_w <= 0.0 or vp_h <= 0.0:
        raise InvalidBoundingBoxError("Viewport width/height must be strictly positive.")

    x = (bx0 - cb_lx0) / vp_w
    y = (cb_ly1 - by1) / vp_h
    w = (bx1 - bx0) / vp_w
    h = (by1 - by0) / vp_h

    # Reject genuinely out-of-bounds coordinates; snap only sub-1e-6 IEEE-754 edge noise.
    if x < -_FLOAT_SNAP_EPS or y < -_FLOAT_SNAP_EPS:
        raise InvalidBoundingBoxError("Normalized bounding box origin precedes visible page edge.")
    if w <= 0.0 or h <= 0.0:
        raise InvalidBoundingBoxError("Normalized bounding box width/height must be positive.")
    if x + w > _BBOX_SUM_EPS or y + h > _BBOX_SUM_EPS:
        raise InvalidBoundingBoxError("Normalized bounding box extends past visible page bounds.")

    if -_FLOAT_SNAP_EPS <= x < 0.0:
        x = 0.0
    if -_FLOAT_SNAP_EPS <= y < 0.0:
        y = 0.0
    if 1.0 < x + w <= _BBOX_SUM_EPS:
        w = 1.0 - x
    if 1.0 < y + h <= _BBOX_SUM_EPS:
        h = 1.0 - y

    return NormalizedBoundingBox(
        x=round(x, 6),
        y=round(y, 6),
        w=round(w, 6),
        h=round(h, 6),
    )


def _extract_words_from_lt_line(
    line: LTTextLine,
    *,
    crop_lt_bbox: tuple[float, float, float, float],
) -> list[ExtractedWordElement]:
    words: list[ExtractedWordElement] = []
    cur_chars: list[LTChar] = []

    def _flush() -> None:
        nonlocal cur_chars
        if not cur_chars:
            return
        text_val = "".join(c.get_text() for c in cur_chars).strip()
        if text_val:
            wx0 = min(float(c.bbox[0]) for c in cur_chars)
            wy0 = min(float(c.bbox[1]) for c in cur_chars)
            wx1 = max(float(c.bbox[2]) for c in cur_chars)
            wy1 = max(float(c.bbox[3]) for c in cur_chars)
            raw_box = (wx0, wy0, wx1, wy1)
            try:
                norm_box = normalize_ltpage_bbox_to_viewport(
                    raw_bbox=raw_box,
                    crop_lt_bbox=crop_lt_bbox,
                )
                words.append(
                    ExtractedWordElement(
                        text=text_val,
                        raw_bbox=raw_box,
                        normalized_bbox=norm_box,
                        bbox_valid=True,
                        reading_order=len(words),
                    )
                )
            except (InvalidBoundingBoxError, ValueError) as exc:
                words.append(
                    ExtractedWordElement(
                        text=text_val,
                        raw_bbox=raw_box,
                        normalized_bbox=None,
                        bbox_valid=False,
                        bbox_error=str(exc)[:160],
                        reading_order=len(words),
                    )
                )
        cur_chars = []

    for child in line:
        if isinstance(child, LTChar):
            ch_txt = child.get_text()
            if ch_txt.isspace():
                _flush()
            else:
                cur_chars.append(child)
        elif isinstance(child, LTAnno):
            if child.get_text().isspace() or child.get_text() == "":
                _flush()
    _flush()
    return words


def _contains_image_object(item: Any, *, depth: int = 0) -> bool:
    if depth > 8:
        return False
    if isinstance(item, LTImage):
        return True
    if isinstance(item, LTFigure):
        return any(_contains_image_object(sub, depth=depth + 1) for sub in item) or True
    if hasattr(item, "__iter__") and not isinstance(item, (LTChar, LTAnno)):
        return any(_contains_image_object(sub, depth=depth + 1) for sub in item)
    return False


def _parse_conservative_date(raw_value: str) -> tuple[str | None, bool, str | None]:
    cleaned = _normalize_whitespace_nfc(raw_value)
    if not cleaned:
        return None, False, "EMPTY_VALUE"
    if _contains_corrupt_control_chars(cleaned):
        return None, False, "INVALID_CHARACTERS"

    m_slash = _DATE_DMY_SLASH_RE.fullmatch(cleaned)
    if m_slash:
        day, month, year = int(m_slash.group(1)), int(m_slash.group(2)), int(m_slash.group(3))
        try:
            return date(year, month, day).isoformat(), True, None
        except ValueError:
            return None, False, "MALFORMED_DATE"

    m_dash = _DATE_DMY_DASH_RE.fullmatch(cleaned)
    if m_dash:
        day, month, year = int(m_dash.group(1)), int(m_dash.group(2)), int(m_dash.group(3))
        try:
            return date(year, month, day).isoformat(), True, None
        except ValueError:
            return None, False, "MALFORMED_DATE"

    m_iso = _DATE_ISO_RE.fullmatch(cleaned)
    if m_iso:
        year, month, day = int(m_iso.group(1)), int(m_iso.group(2)), int(m_iso.group(3))
        try:
            return date(year, month, day).isoformat(), True, None
        except ValueError:
            return None, False, "MALFORMED_DATE"

    return None, False, "MALFORMED_OR_AMBIGUOUS_DATE"


def _parse_conservative_laterality(raw_value: str) -> tuple[str | None, bool, str | None]:
    cleaned = _normalize_whitespace_nfc(raw_value)
    if not cleaned:
        return None, False, "EMPTY_VALUE"
    if _contains_corrupt_control_chars(cleaned):
        return None, False, "INVALID_CHARACTERS"
    folded = _strip_diacritics_lower(cleaned)
    mapped = _LATERALITY_CANONICAL.get(folded)
    if mapped is not None:
        return mapped, True, None
    return None, False, "UNRECOGNIZED_LATERALITY"


def _parse_conservative_document_type(raw_value: str) -> tuple[str | None, bool, str | None]:
    cleaned = _normalize_whitespace_nfc(raw_value)
    if not cleaned:
        return None, False, "EMPTY_VALUE"
    if _contains_corrupt_control_chars(cleaned):
        return None, False, "INVALID_CHARACTERS"
    folded = _strip_diacritics_lower(cleaned)
    if folded in _KNOWN_DOC_TYPES:
        return _KNOWN_DOC_TYPES[folded], True, None
    return unicodedata.normalize("NFC", cleaned).lower(), True, None


def _parse_conservative_text_value(raw_value: str) -> tuple[str | None, bool, str | None]:
    cleaned = _normalize_whitespace_nfc(raw_value)
    if not cleaned:
        return None, False, "EMPTY_VALUE"
    if _contains_corrupt_control_chars(cleaned):
        return None, False, "INVALID_CHARACTERS"
    return cleaned, True, None


@dataclass(frozen=True, slots=True)
class _ParsedCandidateLine:
    field_key: str
    raw_value: str
    normalized_value: str | None
    norm_ok: bool
    norm_reason: str | None
    inline_system: str | None
    line: ExtractedLineElement


def _parse_explicit_fields_from_pages(
    pages: list[ExtractedPageData],
) -> tuple[list[ExtractedFieldPayload], list[str], list[str], list[str]]:
    candidates_by_key: dict[str, list[_ParsedCandidateLine]] = {}
    unrecognized_labels: list[str] = []

    for page in pages:
        if page.status != "extracted":
            continue
        for line in page.lines:
            candidate_line_text = line.raw_text or line.text
            if ":" not in candidate_line_text:
                continue
            prefix_raw, rest = candidate_line_text.split(":", 1)
            prefix_norm = _strip_diacritics_lower(prefix_raw)
            if not prefix_norm or len(prefix_norm) > 64:
                continue

            field_key = _PREFIX_TO_FIELD_KEY.get(prefix_norm)
            if field_key is None:
                if prefix_norm not in unrecognized_labels and len(unrecognized_labels) < 40:
                    unrecognized_labels.append(prefix_norm)
                continue

            raw_val = rest.rstrip("\r\n")
            if raw_val.startswith(" "):
                raw_val = raw_val[1:]

            inline_sys: str | None = None
            if field_key == "birth_date" or field_key == "issue_date":
                norm_val, norm_ok, norm_reason = _parse_conservative_date(raw_val)
            elif field_key == "laterality":
                norm_val, norm_ok, norm_reason = _parse_conservative_laterality(raw_val)
            elif field_key == "document_type":
                norm_val, norm_ok, norm_reason = _parse_conservative_document_type(raw_val)
            elif field_key == "procedure_code":
                stripped_raw = _normalize_whitespace_nfc(raw_val)
                inline_match = _INLINE_CODE_SYSTEM_RE.fullmatch(stripped_raw)
                if inline_match:
                    inline_sys = inline_match.group(1).strip()
                    code_body = _normalize_whitespace_nfc(inline_match.group(2))
                    norm_val, norm_ok, norm_reason = _parse_conservative_text_value(code_body)
                else:
                    norm_val, norm_ok, norm_reason = _parse_conservative_text_value(raw_val)
            else:
                norm_val, norm_ok, norm_reason = _parse_conservative_text_value(raw_val)

            candidates_by_key.setdefault(field_key, []).append(
                _ParsedCandidateLine(
                    field_key=field_key,
                    raw_value=raw_val,
                    normalized_value=norm_val,
                    norm_ok=norm_ok,
                    norm_reason=norm_reason,
                    inline_system=inline_sys,
                    line=line,
                )
            )

    resolved_system: str | None = None
    system_ambiguous = False
    if "procedure_code_system" in candidates_by_key:
        sys_cands = candidates_by_key["procedure_code_system"]
        sys_norms = {c.normalized_value for c in sys_cands if c.norm_ok and c.normalized_value}
        if len(sys_norms) == 1 and all(c.norm_ok for c in sys_cands):
            resolved_system = next(iter(sys_norms))
        elif len(sys_norms) > 1:
            system_ambiguous = True

    fields: list[ExtractedFieldPayload] = []
    for field_key in EXPLICIT_ALLOWLIST_FIELD_KEYS:
        cands = candidates_by_key.get(field_key)
        if not cands:
            continue

        evidences: list[EvidenceCandidatePayload] = []
        invalid_bbox_count = 0
        for cand in cands:
            if cand.line.bbox_valid and cand.line.normalized_bbox is not None:
                evidences.append(
                    EvidenceCandidatePayload(
                        page_number=cand.line.page_number,
                        bbox=cand.line.normalized_bbox,
                        quote_excerpt=cand.line.text[:500],
                        extraction_method=(
                            EVIDENCE_METHOD_PDF_TEXT
                            if cand.norm_ok
                            else EVIDENCE_METHOD_ABSTAINED_MARKER
                        ),
                    )
                )
            else:
                invalid_bbox_count += 1

        if invalid_bbox_count > 0 and not evidences:
            fields.append(
                ExtractedFieldPayload(
                    field_key=field_key,
                    status=ExtractedFieldStatus.ABSTAINED,
                    abstained=True,
                    raw_value=cands[0].raw_value if len(cands) == 1 else " | ".join(c.raw_value for c in cands),
                    normalized_value=None,
                    metadata_json={
                        "reason_code": "INVALID_BOUNDING_BOX",
                        "invalid_bbox_count": invalid_bbox_count,
                        "candidate_count": len(cands),
                        "administrative_only": True,
                        "clinical_approval": False,
                    },
                    evidences=[],
                )
            )
            continue

        distinct_norm_or_raw = {
            (c.normalized_value if c.norm_ok else _normalize_whitespace_nfc(c.raw_value))
            for c in cands
        }
        has_empty_only = all(not c.raw_value.strip() for c in cands)
        if has_empty_only:
            fields.append(
                ExtractedFieldPayload(
                    field_key=field_key,
                    status=ExtractedFieldStatus.ABSTAINED,
                    abstained=True,
                    raw_value=cands[0].raw_value,
                    normalized_value=None,
                    metadata_json={
                        "reason_code": "EMPTY_VALUE",
                        "candidate_count": len(cands),
                        "administrative_only": True,
                        "clinical_approval": False,
                    },
                    evidences=evidences,
                )
            )
            continue

        if len(distinct_norm_or_raw) > 1:
            fields.append(
                ExtractedFieldPayload(
                    field_key=field_key,
                    status=ExtractedFieldStatus.AMBIGUOUS,
                    abstained=True,
                    raw_value=" | ".join(c.raw_value for c in cands),
                    normalized_value=None,
                    metadata_json={
                        "reason_code": "MULTIPLE_INCOMPATIBLE_VALUES",
                        "candidate_count": len(cands),
                        "candidate_raw_values": [c.raw_value for c in cands],
                        "administrative_only": True,
                        "clinical_approval": False,
                    },
                    evidences=evidences,
                )
            )
            continue

        # All occurrences agree on the candidate content.
        primary = cands[0]
        if not primary.norm_ok:
            fields.append(
                ExtractedFieldPayload(
                    field_key=field_key,
                    status=ExtractedFieldStatus.ABSTAINED,
                    abstained=True,
                    raw_value=primary.raw_value,
                    normalized_value=None,
                    metadata_json={
                        "reason_code": primary.norm_reason or "UNNORMALIZABLE_VALUE",
                        "candidate_count": len(cands),
                        "occurrence_count": len(cands),
                        "administrative_only": True,
                        "clinical_approval": False,
                    },
                    evidences=evidences,
                )
            )
            continue

        # Cross-field non-inference invariant: never transform codes without identified system.
        if field_key == "procedure_code":
            inline_systems = {c.inline_system for c in cands if c.inline_system}
            effective_system = resolved_system
            if effective_system is None and len(inline_systems) == 1:
                effective_system = next(iter(inline_systems))

            if system_ambiguous or len(inline_systems) > 1 or (
                resolved_system is not None
                and inline_systems
                and resolved_system not in inline_systems
            ):
                fields.append(
                    ExtractedFieldPayload(
                        field_key=field_key,
                        status=ExtractedFieldStatus.AMBIGUOUS,
                        abstained=True,
                        raw_value=primary.raw_value,
                        normalized_value=None,
                        metadata_json={
                            "reason_code": "CONFLICTING_CODE_SYSTEM",
                            "system_identified": False,
                            "candidate_count": len(cands),
                            "administrative_only": True,
                            "clinical_approval": False,
                        },
                        evidences=evidences,
                    )
                )
                continue

            if not effective_system:
                fields.append(
                    ExtractedFieldPayload(
                        field_key=field_key,
                        status=ExtractedFieldStatus.ABSTAINED,
                        abstained=True,
                        raw_value=primary.raw_value,
                        normalized_value=None,
                        metadata_json={
                            "reason_code": "CODE_SYSTEM_UNIDENTIFIED",
                            "system_identified": False,
                            "candidate_count": len(cands),
                            "occurrence_count": len(cands),
                            "administrative_only": True,
                            "clinical_approval": False,
                        },
                        evidences=evidences,
                    )
                )
                continue

            fields.append(
                ExtractedFieldPayload(
                    field_key=field_key,
                    status=ExtractedFieldStatus.EXTRACTED,
                    abstained=False,
                    raw_value=primary.raw_value,
                    normalized_value=primary.normalized_value,
                    metadata_json={
                        "system_identified": True,
                        "code_system": effective_system,
                        "occurrence_count": len(cands),
                        "administrative_only": True,
                        "clinical_approval": False,
                    },
                    evidences=evidences,
                )
            )
            continue

        fields.append(
            ExtractedFieldPayload(
                field_key=field_key,
                status=ExtractedFieldStatus.EXTRACTED,
                abstained=False,
                raw_value=primary.raw_value,
                normalized_value=primary.normalized_value,
                metadata_json={
                    "occurrence_count": len(cands),
                    "administrative_only": True,
                    "clinical_approval": False,
                },
                evidences=evidences,
            )
        )

    present_keys = [f.field_key for f in fields]
    present_set = set(present_keys)
    absent_keys = [k for k in EXPLICIT_ALLOWLIST_FIELD_KEYS if k not in present_set]
    return fields, present_keys, absent_keys, unrecognized_labels


def extract_png_abstention_result(
    *,
    extractor_version: str = DEFAULT_PDF_TEXT_EXTRACTOR_VERSION,
    source_sha256_hex: str | None = None,
) -> DocumentTextExtractionResult:
    """Explicit abstention result for PNG images while OCR remains unimplemented."""
    return DocumentTextExtractionResult(
        extractor_version=extractor_version,
        engine_name="no-ocr",
        engine_version="disabled",
        source_sha256_hex=source_sha256_hex,
        mime_type="image/png",
        outcome="abstained",
        reason_code="OCR_NOT_IMPLEMENTED",
        readable=False,
        partial=False,
        abstained=True,
        ocr_available=False,
        page_count=0,
        readable_page_count=0,
        abstained_pages=[],
        total_chars=0,
        total_words=0,
        total_lines=0,
        pages=[],
        fields=[],
        present_field_keys=[],
        absent_field_keys=list(EXPLICIT_ALLOWLIST_FIELD_KEYS),
        unrecognized_prefixed_labels=[],
        administrative_only=True,
        clinical_approval=False,
    )


def extract_pdf_document(
    content: bytes,
    *,
    limits: PdfExtractionLimits | None = None,
    extractor_version: str = DEFAULT_PDF_TEXT_EXTRACTOR_VERSION,
    source_sha256_hex: str | None = None,
) -> DocumentTextExtractionResult:
    """Deterministically extract per-page text, coordinates, allowlisted fields and abstentions."""
    cfg = limits or PdfExtractionLimits()
    started = time.monotonic()

    if not content or not content.lstrip().startswith(b"%PDF-"):
        raise PdfExtractionError("PDF_CORRUPTED", "Payload does not start with a valid %PDF- header.")

    stream = io.BytesIO(content)
    try:
        parser = PDFParser(stream)
        doc = PDFDocument(parser)
    except (PDFPasswordIncorrect, PDFEncryptionError, PDFTextExtractionNotAllowed) as exc:
        raise PdfExtractionError(
            "PDF_ENCRYPTED",
            "Encrypted or extraction-protected PDF cannot be read deterministically.",
        ) from exc
    except (PDFNoValidXRef, PDFSyntaxError, PDFException, PSException, ValueError, TypeError, OverflowError) as exc:
        raise PdfExtractionError(
            "PDF_CORRUPTED",
            f"Malformed PDF structure ({type(exc).__name__}).",
        ) from exc

    if getattr(doc, "encryption", None) is not None or not doc.is_extractable:
        raise PdfExtractionError(
            "PDF_ENCRYPTED",
            "Encrypted or extraction-protected PDF requires decryption/OCR not enabled.",
        )

    laparams = LAParams(
        line_overlap=0.5,
        char_margin=2.0,
        word_margin=0.1,
        boxes_flow=0.5,
        detect_vertical=True,
    )
    rsrcmgr = PDFResourceManager(caching=True)
    device = PDFPageAggregator(rsrcmgr, laparams=laparams)
    interpreter = PDFPageInterpreter(rsrcmgr, device)

    pages_out: list[ExtractedPageData] = []
    total_chars = 0
    total_words = 0
    total_lines = 0
    complexity_count = 0

    def _check_timeout() -> None:
        if (time.monotonic() - started) > cfg.timeout_seconds:
            raise PdfExtractionError(
                "PDF_EXTRACTION_TIMEOUT",
                "PDF extraction exceeded configured processing time limit.",
            )

    try:
        raw_pages = PDFPage.create_pages(doc)
        for page_index, pdf_page in enumerate(raw_pages, start=1):
            _check_timeout()
            if page_index > cfg.max_pages:
                raise PdfExtractionError(
                    "PDF_PAGE_LIMIT_EXCEEDED",
                    f"PDF exceeds maximum allowed page count ({cfg.max_pages}).",
                )

            mediabox = tuple(float(v) for v in pdf_page.mediabox)
            cropbox_raw = tuple(float(v) for v in (pdf_page.cropbox or pdf_page.mediabox))
            rotation = (int(pdf_page.rotate or 0) + 360) % 360
            crop_lt_bbox = _compute_crop_in_ltpage_space(
                mediabox=mediabox,
                cropbox=cropbox_raw,
                rotation=rotation,
            )
            eff_cropbox = (
                max(mediabox[0], cropbox_raw[0]),
                max(mediabox[1], cropbox_raw[1]),
                min(mediabox[2], cropbox_raw[2]),
                min(mediabox[3], cropbox_raw[3]),
            )
            vp_width = crop_lt_bbox[2] - crop_lt_bbox[0]
            vp_height = crop_lt_bbox[3] - crop_lt_bbox[1]

            interpreter.process_page(pdf_page)
            lt_page: LTPage = device.get_result()

            page_blocks: list[ExtractedBlockElement] = []
            page_lines: list[ExtractedLineElement] = []
            has_image = False
            page_char_count = 0
            page_word_count = 0
            page_invalid_bboxes = 0
            raw_line_items: list[tuple[int, LTTextLine]] = []

            for element in lt_page:
                complexity_count += 1
                if complexity_count > cfg.max_complexity_objects:
                    raise PdfExtractionError(
                        "PDF_COMPLEXITY_LIMIT_EXCEEDED",
                        "PDF layout complexity exceeds maximum configured object ceiling.",
                    )
                _check_timeout()

                if _contains_image_object(element):
                    has_image = True

                if isinstance(element, LTTextBox):
                    block_idx = len(page_blocks)
                    if block_idx >= cfg.max_blocks_per_page:
                        raise PdfExtractionError(
                            "PDF_BLOCK_LIMIT_EXCEEDED",
                            "PDF page exceeds maximum configured text blocks ceiling.",
                        )
                    block_text = _normalize_whitespace_nfc(element.get_text())
                    block_raw_box = tuple(float(v) for v in element.bbox)
                    try:
                        block_norm_box = normalize_ltpage_bbox_to_viewport(
                            raw_bbox=block_raw_box,
                            crop_lt_bbox=crop_lt_bbox,
                        )
                        page_blocks.append(
                            ExtractedBlockElement(
                                page_number=page_index,
                                block_index=block_idx,
                                text=block_text,
                                raw_bbox=block_raw_box,
                                normalized_bbox=block_norm_box,
                                bbox_valid=True,
                            )
                        )
                    except (InvalidBoundingBoxError, ValueError) as exc:
                        page_invalid_bboxes += 1
                        page_blocks.append(
                            ExtractedBlockElement(
                                page_number=page_index,
                                block_index=block_idx,
                                text=block_text,
                                raw_bbox=block_raw_box,
                                normalized_bbox=None,
                                bbox_valid=False,
                                bbox_error=str(exc)[:160],
                            )
                        )

                    for sub in element:
                        if isinstance(sub, LTTextLine):
                            raw_line_items.append((block_idx, sub))
                elif isinstance(element, LTTextLine):
                    raw_line_items.append((-1, element))

            collected_lines: list[ExtractedLineElement] = []
            for block_idx, lt_line in raw_line_items:
                for ch in lt_line:
                    complexity_count += 1
                    if complexity_count > cfg.max_complexity_objects:
                        raise PdfExtractionError(
                            "PDF_COMPLEXITY_LIMIT_EXCEEDED",
                            "PDF character complexity exceeds maximum configured ceiling.",
                        )

                line_raw_text = unicodedata.normalize("NFC", lt_line.get_text().rstrip("\r\n"))
                line_text = _normalize_whitespace_nfc(line_raw_text)
                if not line_text:
                    continue

                page_char_count += len(line_text)
                total_chars += len(line_text)
                if total_chars > cfg.max_extracted_chars:
                    raise PdfExtractionError(
                        "PDF_CHAR_LIMIT_EXCEEDED",
                        "Extracted PDF text exceeds maximum allowed character limit.",
                    )

                words = _extract_words_from_lt_line(lt_line, crop_lt_bbox=crop_lt_bbox)
                page_word_count += len(words)
                total_words += len(words)
                if total_words > cfg.max_words:
                    raise PdfExtractionError(
                        "PDF_WORD_LIMIT_EXCEEDED",
                        "Extracted PDF word count exceeds maximum allowed limit.",
                    )

                line_raw_box = tuple(float(v) for v in lt_line.bbox)
                try:
                    line_norm_box = normalize_ltpage_bbox_to_viewport(
                        raw_bbox=line_raw_box,
                        crop_lt_bbox=crop_lt_bbox,
                    )
                    collected_lines.append(
                        ExtractedLineElement(
                            page_number=page_index,
                            block_index=block_idx,
                            reading_order=0,
                            text=line_text,
                            raw_text=line_raw_text,
                            raw_bbox=line_raw_box,
                            normalized_bbox=line_norm_box,
                            bbox_valid=True,
                            words=words,
                        )
                    )
                except (InvalidBoundingBoxError, ValueError) as exc:
                    page_invalid_bboxes += 1
                    collected_lines.append(
                        ExtractedLineElement(
                            page_number=page_index,
                            block_index=block_idx,
                            reading_order=0,
                            text=line_text,
                            raw_text=line_raw_text,
                            raw_bbox=line_raw_box,
                            normalized_bbox=None,
                            bbox_valid=False,
                            bbox_error=str(exc)[:160],
                            words=words,
                        )
                    )

            # Deterministic display reading order: top-to-bottom (y), left-to-right (x)
            def _line_sort_key(item: ExtractedLineElement) -> tuple[float, float]:
                if item.normalized_bbox is not None:
                    return (round(item.normalized_bbox.y, 3), round(item.normalized_bbox.x, 3))
                # Fallback raw order if normalized box failed validation
                return (-round(item.raw_bbox[3], 3), round(item.raw_bbox[0], 3))

            collected_lines.sort(key=_line_sort_key)
            for ord_idx, ln in enumerate(collected_lines):
                page_lines.append(
                    ExtractedLineElement(
                        page_number=ln.page_number,
                        block_index=ln.block_index,
                        reading_order=ord_idx,
                        text=ln.text,
                        raw_text=ln.raw_text,
                        raw_bbox=ln.raw_bbox,
                        normalized_bbox=ln.normalized_bbox,
                        bbox_valid=ln.bbox_valid,
                        bbox_error=ln.bbox_error,
                        words=ln.words,
                    )
                )

            total_lines += len(page_lines)
            combined_page_text = "\n".join(ln.text for ln in page_lines)

            if not page_lines or page_char_count == 0:
                pg_status = "abstained"
                pg_reason = "IMAGE_ONLY_OCR_NOT_IMPLEMENTED" if has_image else "EMPTY_PAGE"
            elif _is_garbled_text_layer(combined_page_text):
                pg_status = "abstained"
                pg_reason = "INVALID_TEXT_LAYER"
            elif all(not ln.bbox_valid for ln in page_lines):
                pg_status = "abstained"
                pg_reason = "INVALID_BOUNDING_BOX"
            else:
                pg_status = "extracted"
                pg_reason = None

            pages_out.append(
                ExtractedPageData(
                    page_number=page_index,
                    mediabox=mediabox,
                    cropbox=eff_cropbox,
                    rotation=rotation,
                    viewport_width=vp_width,
                    viewport_height=vp_height,
                    status=pg_status,
                    reason_code=pg_reason,
                    has_image_objects=has_image,
                    char_count=page_char_count,
                    word_count=page_word_count,
                    line_count=len(page_lines),
                    block_count=len(page_blocks),
                    invalid_bbox_count=page_invalid_bboxes,
                    blocks=page_blocks,
                    lines=page_lines,
                    full_text=combined_page_text,
                )
            )
    except PdfExtractionError:
        raise
    except (PDFPasswordIncorrect, PDFEncryptionError, PDFTextExtractionNotAllowed) as exc:
        raise PdfExtractionError(
            "PDF_ENCRYPTED",
            "Encrypted PDF cannot be extracted without authorized decryption.",
        ) from exc
    except (PDFNoValidXRef, PDFSyntaxError, PDFException, PSException, ValueError, TypeError, OverflowError, KeyError, IndexError, EOFError) as exc:
        raise PdfExtractionError(
            "PDF_CORRUPTED",
            f"Corrupted or malformed PDF content ({type(exc).__name__}).",
        ) from exc

    if not pages_out:
        raise PdfExtractionError("PDF_CORRUPTED", "PDF contains zero readable page descriptors.")

    abstained_pages = [pg.page_number for pg in pages_out if pg.status != "extracted"]
    readable_page_count = len(pages_out) - len(abstained_pages)

    fields_out, present_keys, absent_keys, unrecognized_labels = _parse_explicit_fields_from_pages(
        pages_out
    )

    if readable_page_count == 0:
        outcome = "abstained"
        reason_code: str | None = (
            pages_out[0].reason_code if len(pages_out) == 1 else "NO_SELECTABLE_TEXT_OCR_REQUIRED"
        )
        if reason_code == "IMAGE_ONLY_OCR_NOT_IMPLEMENTED":
            reason_code = "NO_SELECTABLE_TEXT_OCR_REQUIRED"
        readable_flag = False
        partial_flag = False
        abstained_flag = True
        # Never fabricate empty field rows for unreadable/scanned documents
        fields_out = []
        present_keys = []
        absent_keys = list(EXPLICIT_ALLOWLIST_FIELD_KEYS)
    elif abstained_pages:
        outcome = "partial"
        reason_code = "PARTIAL_TEXTUAL_COVERAGE_OCR_REQUIRED"
        readable_flag = True
        partial_flag = True
        abstained_flag = True
    else:
        outcome = "executed"
        reason_code = None
        readable_flag = True
        partial_flag = False
        abstained_flag = False

    return DocumentTextExtractionResult(
        extractor_version=extractor_version,
        engine_name=EXTRACTOR_ENGINE_NAME,
        engine_version=EXTRACTOR_ENGINE_VERSION,
        source_sha256_hex=source_sha256_hex,
        mime_type="application/pdf",
        outcome=outcome,
        reason_code=reason_code,
        readable=readable_flag,
        partial=partial_flag,
        abstained=abstained_flag,
        ocr_available=False,
        page_count=len(pages_out),
        readable_page_count=readable_page_count,
        abstained_pages=abstained_pages,
        total_chars=total_chars,
        total_words=total_words,
        total_lines=total_lines,
        pages=pages_out,
        fields=fields_out,
        present_field_keys=present_keys,
        absent_field_keys=absent_keys,
        unrecognized_prefixed_labels=unrecognized_labels,
        administrative_only=True,
        clinical_approval=False,
    )
