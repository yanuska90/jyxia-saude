"""Deterministic, framework-independent 4-axis documentary consistency engine (Etapa 3.3.4).

Strictly administrative evaluation over persisted ExtractedField and EvidenceReference records.
Zero probabilistic inference, zero fuzzy matching, zero LLM/network calls, and zero clinical
equivalence or medical decision claims.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
import hashlib
import json
import math
import re
import unicodedata
from typing import Any

from app.core.constants import (
    ACTIVE_PROCESSING_STATUSES,
    AxisName,
    AxisStatus,
    CaseReadinessState,
    DEFAULT_CONSISTENCY_ENGINE_NAME,
    DEFAULT_CONSISTENCY_ENGINE_VERSION,
    DEFAULT_CONSISTENCY_POLICY_VERSION,
    DEFAULT_CONSISTENCY_TEMPORALITY_MAX_AGE_DAYS,
    ExtractedFieldStatus,
    ProcessingStatus,
)

_TYPED_SYN_ID_RE = re.compile(r"^SYN-[A-Z0-9]+(?:-[A-Z0-9]+)*$", re.IGNORECASE)
_TYPED_PREFIX_RE = re.compile(
    r"^(SYN|CNS|CPF|RG|PRONTUARIO|MATRICULA|REGISTRO|PASSAPORTE|ID[_-]CONTRATO)[:/\s-]+(.+)$",
    re.IGNORECASE,
)

_CANONICAL_LATERALITY_MAP: dict[str, tuple[str, str]] = {
    "od": ("OD", "Olho Direito (OD)"),
    "oe": ("OE", "Olho Esquerdo (OE)"),
    "ao": ("AO", "Bilateral (AO)"),
    "bilateral": ("AO", "Bilateral (AO)"),
    "ambos os olhos": ("AO", "Bilateral (AO)"),
    "na": ("NA", "Nao aplicavel"),
    "nao aplicavel": ("NA", "Nao aplicavel"),
    "nao se aplica": ("NA", "Nao aplicavel"),
    "n/a": ("NA", "Nao aplicavel"),
}

_CLINICAL_OUT_OF_SCOPE_NOTICE = (
    "JYXIA realiza apenas conferencia documental administrativa deterministica; "
    "decisao clinica, indicacao cirurgica, diagnostico e autorizacao de procedimento "
    "permanecem exclusivamente fora do escopo e cabem ao profissional habilitado."
)


@dataclass(frozen=True, slots=True)
class EvidenceInput:
    """Persisted spatial evidence reference linked to an extracted field and document version."""

    evidence_id: str
    organization_id: str
    document_version_id: str
    extracted_field_id: str
    page_number: int
    bbox: tuple[float, float, float, float]
    quote_excerpt: str | None
    extraction_method: str


@dataclass(frozen=True, slots=True)
class ExtractedFieldInput:
    """Persisted extracted field belonging to a specific extraction ProcessingRun."""

    extracted_field_id: str
    organization_id: str
    document_version_id: str
    processing_run_id: str
    field_key: str
    raw_value: str | None
    normalized_value: str | None
    status: str
    abstained: bool
    metadata_json: dict[str, Any] = field(default_factory=dict)
    evidences: tuple[EvidenceInput, ...] = ()


@dataclass(frozen=True, slots=True)
class HumanReviewInput:
    """Recorded human administrative review associated with a document version."""

    review_id: str
    document_version_id: str
    action_type: str
    field_key: str | None
    policy_version: str
    created_at: datetime


@dataclass(frozen=True, slots=True)
class DocumentVersionInput:
    """Version snapshot metadata, extraction status, fields, and reviews."""

    version_id: str
    document_id: str
    version_number: int
    sha256_hex: str
    mime_type: str
    created_at: datetime
    is_current: bool
    superseded_by_version_id: str | None
    integrity_status: str | None
    extraction_run_id: str | None
    extraction_status: str | None
    extractor_version: str | None
    extraction_readable: bool | None
    extraction_outcome: str | None
    extracted_fields: tuple[ExtractedFieldInput, ...] = ()
    human_reviews: tuple[HumanReviewInput, ...] = ()


@dataclass(frozen=True, slots=True)
class CaseDocumentInput:
    """Document belonging to the case along with version lineage."""

    document_id: str
    document_kind: str
    document_subfamily: str | None
    source_label: str
    quarantined: bool
    discarded_at: datetime | None
    versions: tuple[DocumentVersionInput, ...]


@dataclass(frozen=True, slots=True)
class CaseConsistencyInput:
    """Complete deterministic input snapshot for a DocumentCase consistency evaluation."""

    organization_id: str
    case_id: str
    case_code: str
    procedure_reference: str | None = None
    declared_laterality: str | None = None
    engine_name: str = DEFAULT_CONSISTENCY_ENGINE_NAME
    engine_version: str = DEFAULT_CONSISTENCY_ENGINE_VERSION
    policy_version: str = DEFAULT_CONSISTENCY_POLICY_VERSION
    max_issue_date_spread_days: int = DEFAULT_CONSISTENCY_TEMPORALITY_MAX_AGE_DAYS
    reference_date: date | None = None
    evaluated_axes: tuple[AxisName, ...] | None = None
    documents: tuple[CaseDocumentInput, ...] = ()


@dataclass(frozen=True, slots=True)
class EvidenceLinkOutput:
    """Validated foreign-key link tying an axis finding back to a persisted EvidenceReference."""

    evidence_reference_id: str
    document_version_id: str
    extracted_field_id: str


@dataclass(frozen=True, slots=True)
class AxisEvaluationResult:
    """Deterministic explanation and evidence trace for a single consistency axis."""

    axis: AxisName
    status: AxisStatus
    rule_code: str
    justification: str
    fields_used: tuple[str, ...]
    compared_document_ids: tuple[str, ...]
    compared_version_ids: tuple[str, ...]
    evidence_reference_ids: tuple[str, ...]
    evidence_links: tuple[EvidenceLinkOutput, ...]
    comparison_items: tuple[dict[str, Any], ...]
    limitations: tuple[str, ...]
    engine_version: str
    administrative_only: bool = True
    clinical_approval: bool = False


@dataclass(frozen=True, slots=True)
class CaseConsistencyResult:
    """Full deterministic assessment across the 4 axes and conservative global state."""

    organization_id: str
    case_id: str
    engine_name: str
    engine_version: str
    policy_version: str
    input_fingerprint_sha256: str
    automated_axes_outcome: str
    readiness_state: CaseReadinessState
    human_review_completed: bool
    human_review_required: bool
    compared_documents_count: int
    compared_snapshot: tuple[dict[str, Any], ...]
    extraction_run_ids: tuple[str, ...]
    axes: dict[AxisName, AxisEvaluationResult]
    limitations: tuple[str, ...]
    summary: dict[str, Any]
    administrative_only: bool = True
    clinical_approval: bool = False


@dataclass(slots=True)
class _ActiveVersionContext:
    doc: CaseDocumentInput
    version: DocumentVersionInput
    superseded_versions: tuple[DocumentVersionInput, ...]
    fields_by_key: dict[str, ExtractedFieldInput]
    valid_evidences_by_field_id: dict[str, tuple[EvidenceInput, ...]]
    invalid_evidence_reasons: list[str]
    extraction_state: str  # "ready", "pending", "unreadable_or_abstained", "integrity_failed"


def _collapse_whitespace(raw: str) -> str:
    return " ".join(unicodedata.normalize("NFC", raw).strip().split())


def _conservative_text_key(raw: str) -> str:
    """Superficial whitespace/case folding WITHOUT phonetic matching, fuzzy edit distance, or accent removal."""
    return _collapse_whitespace(raw).casefold()


def _as_utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def _is_valid_bbox(bbox: tuple[float, float, float, float]) -> bool:
    if len(bbox) != 4:
        return False
    x, y, w, h = bbox
    vals = (x, y, w, h)
    if not all(isinstance(v, (int, float)) and math.isfinite(float(v)) for v in vals):
        return False
    return (
        0.0 <= x <= 1.0
        and 0.0 <= y <= 1.0
        and 0.0 < w <= 1.0
        and 0.0 < h <= 1.0
        and (x + w) <= 1.00001
        and (y + h) <= 1.00001
    )


def _validate_field_evidences(
    *,
    expected_org_id: str,
    expected_version_id: str,
    field_item: ExtractedFieldInput,
) -> tuple[tuple[EvidenceInput, ...], list[str]]:
    reasons: list[str] = []
    if field_item.organization_id != expected_org_id:
        reasons.append(
            f"FIELD_CROSS_TENANT_MISMATCH:{field_item.field_key}"
        )
        return (), reasons
    if field_item.document_version_id != expected_version_id:
        reasons.append(
            f"FIELD_VERSION_MISMATCH:{field_item.field_key}"
        )
        return (), reasons

    valid: list[EvidenceInput] = []
    for ev in field_item.evidences:
        if ev.organization_id != expected_org_id:
            reasons.append(f"EVIDENCE_CROSS_TENANT_MISMATCH:{ev.evidence_id}")
            continue
        if ev.document_version_id != expected_version_id:
            reasons.append(f"EVIDENCE_VERSION_MISMATCH:{ev.evidence_id}")
            continue
        if ev.extracted_field_id != field_item.extracted_field_id:
            reasons.append(f"EVIDENCE_FIELD_MISMATCH:{ev.evidence_id}")
            continue
        if ev.page_number < 1 or not _is_valid_bbox(ev.bbox):
            reasons.append(f"EVIDENCE_INVALID_COORDINATES:{ev.evidence_id}")
            continue
        valid.append(ev)

    if (
        field_item.status in (ExtractedFieldStatus.EXTRACTED.value, ExtractedFieldStatus.AMBIGUOUS.value)
        and not valid
        and not reasons
    ):
        reasons.append(f"EVIDENCE_MISSING_FOR_EXTRACTED_FIELD:{field_item.field_key}")

    return tuple(valid), reasons


def _make_comparison_item(
    *,
    ctx: _ActiveVersionContext,
    field_key: str,
    field_item: ExtractedFieldInput | None,
    ev: EvidenceInput | None,
    role_in_comparison: str,
    override_value: str | None = None,
    override_raw: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    raw_val = override_raw if override_raw is not None else (field_item.raw_value if field_item else None)
    norm_val = (
        override_value
        if override_value is not None
        else (field_item.normalized_value if field_item else None)
    )
    item: dict[str, Any] = {
        "document_id": ctx.doc.document_id,
        "document_version_id": ctx.version.version_id,
        "document_kind": ctx.doc.document_kind,
        "source_label": ctx.doc.source_label,
        "version_number": ctx.version.version_number,
        "sha256_hex": ctx.version.sha256_hex,
        "upload_created_at": _as_utc(ctx.version.created_at).isoformat(),
        "field_key": field_key,
        "extracted_field_id": field_item.extracted_field_id if field_item else None,
        "raw_value": raw_val,
        "normalized_value": norm_val,
        "value": norm_val if norm_val is not None else raw_val,
        "field_status": field_item.status if field_item else "missing",
        "evidence_id": ev.evidence_id if ev else None,
        "page": ev.page_number if ev else None,
        "page_number": ev.page_number if ev else None,
        "bbox": [round(float(v), 6) for v in ev.bbox] if ev else None,
        "quote_excerpt": ev.quote_excerpt if ev else None,
        "extraction_method": ev.extraction_method if ev else None,
        "role_in_comparison": role_in_comparison,
    }
    if extra:
        item.update(extra)
    return item


def _append_field_comparison_items(
    items: list[dict[str, Any]],
    *,
    ctx: _ActiveVersionContext,
    field_key: str,
    field_item: ExtractedFieldInput | None,
    default_role: str = "compared_value",
) -> None:
    """Append comparison items preserving raw_value, abstention reason and available evidence links."""
    if field_item is None:
        return
    is_abstained = (
        field_item.status == ExtractedFieldStatus.ABSTAINED.value or field_item.abstained
    )
    is_ambiguous = field_item.status == ExtractedFieldStatus.AMBIGUOUS.value
    role = "abstained_source" if (is_abstained and not is_ambiguous) else default_role
    reason_code = (
        field_item.metadata_json.get("reason_code") if (is_abstained or is_ambiguous) else None
    )
    extra = {"reason_code": reason_code} if reason_code is not None else None
    evs = _all_evs(ctx, field_item)
    if evs:
        for ev in evs:
            items.append(
                _make_comparison_item(
                    ctx=ctx,
                    field_key=field_key,
                    field_item=field_item,
                    ev=ev,
                    role_in_comparison=role,
                    extra=extra,
                )
            )
    elif is_abstained or is_ambiguous:
        items.append(
            _make_comparison_item(
                ctx=ctx,
                field_key=field_key,
                field_item=field_item,
                ev=None,
                role_in_comparison=role,
                extra=extra,
            )
        )


def _collect_links(
    contexts: list[_ActiveVersionContext],
    field_keys: tuple[str, ...],
) -> tuple[tuple[str, ...], tuple[EvidenceLinkOutput, ...]]:
    ids: list[str] = []
    links: list[EvidenceLinkOutput] = []
    seen: set[str] = set()
    for ctx in contexts:
        for fk in field_keys:
            f_item = ctx.fields_by_key.get(fk)
            if f_item is None:
                continue
            for ev in ctx.valid_evidences_by_field_id.get(f_item.extracted_field_id, ()):
                if ev.evidence_id not in seen:
                    seen.add(ev.evidence_id)
                    ids.append(ev.evidence_id)
                    links.append(
                        EvidenceLinkOutput(
                            evidence_reference_id=ev.evidence_id,
                            document_version_id=ev.document_version_id,
                            extracted_field_id=ev.extracted_field_id,
                        )
                    )
    return tuple(ids), tuple(links)


def _links_from_items(
    items: list[dict[str, Any]], contexts: list[_ActiveVersionContext]
) -> tuple[tuple[str, ...], tuple[EvidenceLinkOutput, ...]]:
    ev_index: dict[str, EvidenceInput] = {}
    for ctx in contexts:
        for evs in ctx.valid_evidences_by_field_id.values():
            for ev in evs:
                ev_index[ev.evidence_id] = ev

    ids: list[str] = []
    links: list[EvidenceLinkOutput] = []
    seen: set[str] = set()
    for it in items:
        ev_id = it.get("evidence_id")
        if ev_id and ev_id in ev_index and ev_id not in seen:
            ev = ev_index[ev_id]
            seen.add(ev_id)
            ids.append(ev_id)
            links.append(
                EvidenceLinkOutput(
                    evidence_reference_id=ev.evidence_id,
                    document_version_id=ev.document_version_id,
                    extracted_field_id=ev.extracted_field_id,
                )
            )
    return tuple(ids), tuple(links)


def _first_ev(ctx: _ActiveVersionContext, field_item: ExtractedFieldInput | None) -> EvidenceInput | None:
    if field_item is None:
        return None
    evs = ctx.valid_evidences_by_field_id.get(field_item.extracted_field_id, ())
    return evs[0] if evs else None


def _all_evs(ctx: _ActiveVersionContext, field_item: ExtractedFieldInput | None) -> tuple[EvidenceInput, ...]:
    if field_item is None:
        return ()
    return ctx.valid_evidences_by_field_id.get(field_item.extracted_field_id, ())


def _parse_typed_identifier(field_item: ExtractedFieldInput) -> tuple[bool, str | None, str | None]:
    """Return (is_typed, identifier_type, canonical_value).

    Never accepts bare untyped strings unless contract identifier_type metadata or
    explicit allowed prefix/contract token (`SYN-...`, `CNS:...`, etc.) is present.
    """
    raw_or_norm = field_item.normalized_value or field_item.raw_value
    if not raw_or_norm:
        return False, None, None
    cleaned = _collapse_whitespace(raw_or_norm)
    meta_type = field_item.metadata_json.get("identifier_type")
    if isinstance(meta_type, str) and meta_type.strip():
        return True, meta_type.strip().upper(), cleaned.upper()

    if _TYPED_SYN_ID_RE.fullmatch(cleaned):
        return True, "SYNTHETIC_CASE_ID", cleaned.upper()

    prefix_match = _TYPED_PREFIX_RE.fullmatch(cleaned)
    if prefix_match:
        id_type = prefix_match.group(1).strip().upper().replace("-", "_")
        id_val = _collapse_whitespace(prefix_match.group(2)).upper()
        return True, id_type, id_val

    return False, None, cleaned


def _parse_canonical_laterality(raw_or_norm: str | None) -> str | None:
    if not raw_or_norm:
        return None
    folded = (
        "".join(
            ch for ch in unicodedata.normalize("NFKD", _collapse_whitespace(raw_or_norm))
            if not unicodedata.combining(ch)
        )
        .lower()
    )
    mapped = _CANONICAL_LATERALITY_MAP.get(folded)
    return mapped[0] if mapped else None


def _parse_iso_date(value: str | None) -> date | None:
    if not value:
        return None
    cleaned = value.strip()
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", cleaned):
        return None
    try:
        return date.fromisoformat(cleaned)
    except ValueError:
        return None


def _compute_input_fingerprint(data: CaseConsistencyInput) -> str:
    payload = {
        "organization_id": data.organization_id,
        "case_id": data.case_id,
        "case_code": data.case_code,
        "procedure_reference": data.procedure_reference,
        "declared_laterality": data.declared_laterality,
        "engine_name": data.engine_name,
        "engine_version": data.engine_version,
        "policy_version": data.policy_version,
        "max_issue_date_spread_days": data.max_issue_date_spread_days,
        "reference_date": data.reference_date.isoformat() if data.reference_date else None,
        "evaluated_axes": [ax.value for ax in data.evaluated_axes] if data.evaluated_axes is not None else None,
        "documents": [
            {
                "document_id": doc.document_id,
                "document_kind": doc.document_kind,
                "document_subfamily": doc.document_subfamily,
                "quarantined": doc.quarantined,
                "discarded_at": _as_utc(doc.discarded_at).isoformat() if doc.discarded_at else None,
                "versions": [
                    {
                        "version_id": ver.version_id,
                        "version_number": ver.version_number,
                        "sha256_hex": ver.sha256_hex,
                        "mime_type": ver.mime_type,
                        "created_at": _as_utc(ver.created_at).isoformat(),
                        "is_current": ver.is_current,
                        "superseded_by_version_id": ver.superseded_by_version_id,
                        "integrity_status": ver.integrity_status,
                        "extraction_run_id": ver.extraction_run_id,
                        "extraction_status": ver.extraction_status,
                        "extractor_version": ver.extractor_version,
                        "extraction_readable": ver.extraction_readable,
                        "extraction_outcome": ver.extraction_outcome,
                        "extracted_fields": [
                            {
                                "extracted_field_id": f.extracted_field_id,
                                "field_key": f.field_key,
                                "raw_value": f.raw_value,
                                "normalized_value": f.normalized_value,
                                "status": f.status,
                                "abstained": f.abstained,
                                "metadata_json": f.metadata_json,
                                "evidences": [
                                    {
                                        "evidence_id": e.evidence_id,
                                        "page_number": e.page_number,
                                        "bbox": [round(float(x), 6) for x in e.bbox],
                                        "extraction_method": e.extraction_method,
                                    }
                                    for e in sorted(f.evidences, key=lambda item: item.evidence_id)
                                ],
                            }
                            for f in sorted(ver.extracted_fields, key=lambda item: item.field_key)
                        ],
                        "human_reviews": [
                            {
                                "review_id": r.review_id,
                                "action_type": r.action_type,
                                "field_key": r.field_key,
                                "policy_version": r.policy_version,
                            }
                            for r in sorted(ver.human_reviews, key=lambda item: item.review_id)
                        ],
                    }
                    for ver in sorted(
                        doc.versions, key=lambda v: (v.version_number, _as_utc(v.created_at), v.version_id)
                    )
                ],
            }
            for doc in sorted(data.documents, key=lambda d: d.document_id)
        ],
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()


def _prepare_contexts(
    data: CaseConsistencyInput,
) -> tuple[list[_ActiveVersionContext], list[dict[str, Any]], list[str]]:
    active_contexts: list[_ActiveVersionContext] = []
    snapshot: list[dict[str, Any]] = []
    extraction_run_ids: list[str] = []

    for doc in sorted(data.documents, key=lambda d: d.document_id):
        sorted_versions = sorted(
            doc.versions, key=lambda v: (v.version_number, _as_utc(v.created_at), v.version_id)
        )
        if doc.discarded_at is not None:
            latest_ver = sorted_versions[-1] if sorted_versions else None
            snapshot.append(
                {
                    "document_id": doc.document_id,
                    "document_kind": doc.document_kind,
                    "document_subfamily": doc.document_subfamily,
                    "source_label": doc.source_label,
                    "version_id": latest_ver.version_id if latest_ver else None,
                    "version_number": latest_ver.version_number if latest_ver else None,
                    "sha256_hex": latest_ver.sha256_hex if latest_ver else None,
                    "is_current": False,
                    "superseded_by_version_id": (
                        latest_ver.superseded_by_version_id if latest_ver else None
                    ),
                    "created_at": _as_utc(latest_ver.created_at).isoformat() if latest_ver else None,
                    "extract_run_id": latest_ver.extraction_run_id if latest_ver else None,
                    "extractor_version": latest_ver.extractor_version if latest_ver else None,
                    "extract_outcome": latest_ver.extraction_outcome if latest_ver else None,
                    "extract_readable": latest_ver.extraction_readable if latest_ver else None,
                    "quarantined": doc.quarantined,
                    "comparable": False,
                    "exclusion_reason": "DOCUMENT_DISCARDED",
                }
            )
            continue

        if not sorted_versions:
            snapshot.append(
                {
                    "document_id": doc.document_id,
                    "document_kind": doc.document_kind,
                    "document_subfamily": doc.document_subfamily,
                    "source_label": doc.source_label,
                    "version_id": None,
                    "version_number": None,
                    "sha256_hex": None,
                    "is_current": False,
                    "superseded_by_version_id": None,
                    "created_at": None,
                    "extract_run_id": None,
                    "extractor_version": None,
                    "extract_outcome": None,
                    "extract_readable": False,
                    "quarantined": doc.quarantined,
                    "comparable": False,
                    "exclusion_reason": "NO_DOCUMENT_VERSION",
                }
            )
            continue

        current_candidates = [
            v for v in sorted_versions if v.is_current and v.superseded_by_version_id is None
        ]
        current_ver = current_candidates[-1] if current_candidates else sorted_versions[-1]
        superseded = tuple(v for v in sorted_versions if v.version_id != current_ver.version_id)

        fields_by_key: dict[str, ExtractedFieldInput] = {}
        valid_evidences: dict[str, tuple[EvidenceInput, ...]] = {}
        invalid_reasons: list[str] = []
        for f_item in current_ver.extracted_fields:
            fields_by_key[f_item.field_key] = f_item
            valid_evs, f_reasons = _validate_field_evidences(
                expected_org_id=data.organization_id,
                expected_version_id=current_ver.version_id,
                field_item=f_item,
            )
            valid_evidences[f_item.extracted_field_id] = valid_evs
            invalid_reasons.extend(f_reasons)

        if current_ver.integrity_status == ProcessingStatus.FAILED.value:
            ext_state = "integrity_failed"
        elif current_ver.extraction_status in ACTIVE_PROCESSING_STATUSES or (
            current_ver.extraction_status is None and current_ver.integrity_status in ACTIVE_PROCESSING_STATUSES
        ):
            ext_state = "pending"
        elif current_ver.extraction_status == ProcessingStatus.SUCCEEDED.value and bool(
            current_ver.extraction_readable
        ):
            ext_state = "ready"
        elif current_ver.extraction_status is None and not current_ver.extracted_fields:
            ext_state = "pending"
        else:
            ext_state = "unreadable_or_abstained"

        if current_ver.extraction_run_id:
            extraction_run_ids.append(current_ver.extraction_run_id)

        ctx = _ActiveVersionContext(
            doc=doc,
            version=current_ver,
            superseded_versions=superseded,
            fields_by_key=fields_by_key,
            valid_evidences_by_field_id=valid_evidences,
            invalid_evidence_reasons=invalid_reasons,
            extraction_state=ext_state,
        )
        active_contexts.append(ctx)

        snapshot.append(
            {
                "document_id": doc.document_id,
                "document_kind": doc.document_kind,
                "document_subfamily": doc.document_subfamily,
                "source_label": doc.source_label,
                "version_id": current_ver.version_id,
                "version_number": current_ver.version_number,
                "sha256_hex": current_ver.sha256_hex,
                "is_current": current_ver.is_current,
                "superseded_by_version_id": current_ver.superseded_by_version_id,
                "superseded_version_ids": [v.version_id for v in superseded],
                "created_at": _as_utc(current_ver.created_at).isoformat(),
                "extract_run_id": current_ver.extraction_run_id,
                "extractor_version": current_ver.extractor_version,
                "extract_status": current_ver.extraction_status,
                "extract_outcome": current_ver.extraction_outcome,
                "extract_readable": current_ver.extraction_readable,
                "extraction_state": ext_state,
                "quarantined": doc.quarantined,
                "comparable": ext_state == "ready" and not invalid_reasons,
                "exclusion_reason": (
                    invalid_reasons[0]
                    if invalid_reasons
                    else (None if ext_state == "ready" else f"EXTRACTION_{ext_state.upper()}")
                ),
            }
        )

    return active_contexts, snapshot, extraction_run_ids


def _evaluate_common_preconditions(
    *,
    axis: AxisName,
    contexts: list[_ActiveVersionContext],
    field_keys: tuple[str, ...],
    engine_version: str,
    limitations: list[str],
) -> tuple[bool, list[str], list[_ActiveVersionContext], list[_ActiveVersionContext], list[_ActiveVersionContext]]:
    has_invalid_ev = [c for c in contexts if c.invalid_evidence_reasons]
    for c in has_invalid_ev:
        limitations.extend(c.invalid_evidence_reasons)

    unreadable = [
        c for c in contexts if c.extraction_state in ("unreadable_or_abstained", "integrity_failed")
    ]
    pending = [c for c in contexts if c.extraction_state == "pending"]
    ready = [c for c in contexts if c.extraction_state == "ready" and not c.invalid_evidence_reasons]
    _ = axis, field_keys, engine_version
    return bool(has_invalid_ev), limitations, unreadable, pending, ready


def _build_axis_result(
    *,
    axis: AxisName,
    status: AxisStatus,
    rule_code: str,
    justification: str,
    fields_used: tuple[str, ...],
    contexts: list[_ActiveVersionContext],
    items: list[dict[str, Any]],
    limitations: list[str],
    engine_version: str,
) -> AxisEvaluationResult:
    ev_ids, ev_links = _links_from_items(items, contexts)
    doc_ids = tuple(dict.fromkeys(c.doc.document_id for c in contexts))
    ver_ids = tuple(dict.fromkeys(c.version.version_id for c in contexts))
    dedup_limits = tuple(dict.fromkeys(limitations))
    return AxisEvaluationResult(
        axis=axis,
        status=status,
        rule_code=rule_code,
        justification=justification,
        fields_used=fields_used,
        compared_document_ids=doc_ids,
        compared_version_ids=ver_ids,
        evidence_reference_ids=ev_ids,
        evidence_links=ev_links,
        comparison_items=tuple(items),
        limitations=dedup_limits,
        engine_version=engine_version,
        administrative_only=True,
        clinical_approval=False,
    )


def _evaluate_identity_axis(
    contexts: list[_ActiveVersionContext],
    *,
    engine_version: str,
) -> AxisEvaluationResult:
    axis = AxisName.IDENTIDADE
    fields_used = ("patient", "birth_date", "identifier")
    limitations: list[str] = [
        "NO_FUZZY_NAME_MATCHING",
        "NAME_ALONE_NEVER_SUFFICIENT_FOR_IDENTITY",
    ]
    has_invalid_ev, limitations, unreadable, pending, ready = _evaluate_common_preconditions(
        axis=axis,
        contexts=contexts,
        field_keys=fields_used,
        engine_version=engine_version,
        limitations=limitations,
    )

    items: list[dict[str, Any]] = []
    # Collect explicit candidate values across ready docs to ensure explicit conflicts are never masked.
    ambiguous_intra_items: list[dict[str, Any]] = []
    id_entries: list[tuple[_ActiveVersionContext, ExtractedFieldInput, str, str]] = []
    untyped_ids: list[tuple[_ActiveVersionContext, ExtractedFieldInput]] = []
    abstained_id_fields: list[tuple[_ActiveVersionContext, ExtractedFieldInput]] = []
    birth_entries: list[tuple[_ActiveVersionContext, ExtractedFieldInput, date]] = []
    abstained_births: list[tuple[_ActiveVersionContext, ExtractedFieldInput]] = []
    patient_entries: list[tuple[_ActiveVersionContext, ExtractedFieldInput, str]] = []
    abstained_patients: list[tuple[_ActiveVersionContext, ExtractedFieldInput]] = []
    missing_docs_notes: list[str] = []

    for ctx in ready:
        p_field = ctx.fields_by_key.get("patient")
        b_field = ctx.fields_by_key.get("birth_date")
        i_field = ctx.fields_by_key.get("identifier")

        if p_field is not None:
            _append_field_comparison_items(
                items, ctx=ctx, field_key="patient", field_item=p_field
            )
            if p_field.status == ExtractedFieldStatus.AMBIGUOUS.value:
                for ev in _all_evs(ctx, p_field) or (None,):
                    ambiguous_intra_items.append(
                        _make_comparison_item(
                            ctx=ctx,
                            field_key="patient",
                            field_item=p_field,
                            ev=ev,
                            role_in_comparison="intra_document_ambiguous",
                        )
                    )
            elif (
                p_field.status == ExtractedFieldStatus.EXTRACTED.value
                and not p_field.abstained
            ):
                p_norm = _conservative_text_key(p_field.normalized_value or p_field.raw_value or "")
                if not p_norm:
                    abstained_patients.append((ctx, p_field))
                else:
                    patient_entries.append((ctx, p_field, p_norm))
            else:
                abstained_patients.append((ctx, p_field))
        else:
            missing_docs_notes.append(f"patient_missing:{ctx.doc.document_id}")
            items.append(
                _make_comparison_item(
                    ctx=ctx,
                    field_key="patient",
                    field_item=None,
                    ev=None,
                    role_in_comparison="missing_field",
                )
            )

        if b_field is not None:
            _append_field_comparison_items(
                items, ctx=ctx, field_key="birth_date", field_item=b_field
            )
            if b_field.status == ExtractedFieldStatus.AMBIGUOUS.value:
                for ev in _all_evs(ctx, b_field) or (None,):
                    ambiguous_intra_items.append(
                        _make_comparison_item(
                            ctx=ctx,
                            field_key="birth_date",
                            field_item=b_field,
                            ev=ev,
                            role_in_comparison="intra_document_ambiguous",
                        )
                    )
            elif (
                b_field.status == ExtractedFieldStatus.EXTRACTED.value
                and not b_field.abstained
            ):
                dt_val = _parse_iso_date(b_field.normalized_value)
                if dt_val is None:
                    abstained_births.append((ctx, b_field))
                else:
                    birth_entries.append((ctx, b_field, dt_val))
            else:
                abstained_births.append((ctx, b_field))
        else:
            missing_docs_notes.append(f"birth_date_missing:{ctx.doc.document_id}")
            items.append(
                _make_comparison_item(
                    ctx=ctx,
                    field_key="birth_date",
                    field_item=None,
                    ev=None,
                    role_in_comparison="missing_field",
                )
            )

        if i_field is not None:
            _append_field_comparison_items(
                items, ctx=ctx, field_key="identifier", field_item=i_field
            )
            if i_field.status == ExtractedFieldStatus.AMBIGUOUS.value:
                for ev in _all_evs(ctx, i_field) or (None,):
                    ambiguous_intra_items.append(
                        _make_comparison_item(
                            ctx=ctx,
                            field_key="identifier",
                            field_item=i_field,
                            ev=ev,
                            role_in_comparison="intra_document_ambiguous",
                        )
                    )
            elif (
                i_field.status == ExtractedFieldStatus.EXTRACTED.value
                and not i_field.abstained
            ):
                is_typed, id_type, id_val = _parse_typed_identifier(i_field)
                if not is_typed or id_type is None or not id_val:
                    untyped_ids.append((ctx, i_field))
                else:
                    id_entries.append((ctx, i_field, id_type, id_val))
            else:
                abstained_id_fields.append((ctx, i_field))
        else:
            missing_docs_notes.append(f"identifier_missing:{ctx.doc.document_id}")
            items.append(
                _make_comparison_item(
                    ctx=ctx,
                    field_key="identifier",
                    field_item=None,
                    ev=None,
                    role_in_comparison="missing_field",
                )
            )

    # 1. Explicit conflicts NEVER suppressed by missing fields in other docs.
    if ambiguous_intra_items:
        return _build_axis_result(
            axis=axis,
            status=AxisStatus.CONFLITO,
            rule_code="IDENTITY_AMBIGUOUS_INTRA_DOCUMENT",
            justification=(
                "Multiplos valores incompativeis de identidade encontrados dentro do mesmo documento; "
                "exige revisao humana com base nas evidencias originais."
            ),
            fields_used=fields_used,
            contexts=contexts,
            items=items,
            limitations=limitations,
            engine_version=engine_version,
        )

    id_types = {id_t for _, _, id_t, _ in id_entries}
    if len(id_types) == 1 and len({id_v for _, _, _, id_v in id_entries}) > 1:
        distinct_vals = sorted({id_v for _, _, _, id_v in id_entries})
        return _build_axis_result(
            axis=axis,
            status=AxisStatus.CONFLITO,
            rule_code="IDENTITY_IDENTIFIER_CONFLICT",
            justification=(
                f"Conflito explicito de identificador tipado entre documentos do caso: {distinct_vals}. "
                "Mesmo que nome coincida, identificadores distintos impedem atribuicao de consistencia."
            ),
            fields_used=fields_used,
            contexts=contexts,
            items=items,
            limitations=limitations,
            engine_version=engine_version,
        )

    if len({dt for _, _, dt in birth_entries}) > 1:
        distinct_dates = sorted({dt.isoformat() for _, _, dt in birth_entries})
        return _build_axis_result(
            axis=axis,
            status=AxisStatus.CONFLITO,
            rule_code="IDENTITY_BIRTH_DATE_CONFLICT",
            justification=(
                f"Datas de nascimento incompativeis entre os documentos do caso: {distinct_dates}."
            ),
            fields_used=fields_used,
            contexts=contexts,
            items=items,
            limitations=limitations,
            engine_version=engine_version,
        )

    if len({nm for _, _, nm in patient_entries}) > 1:
        distinct_names = sorted({f.normalized_value or f.raw_value or "" for _, f, _ in patient_entries})
        return _build_axis_result(
            axis=axis,
            status=AxisStatus.CONFLITO,
            rule_code="IDENTITY_PATIENT_NAME_CONFLICT",
            justification=(
                f"Nomes de paciente divergentes entre documentos sem uso de matching aproximado: {distinct_names}."
            ),
            fields_used=fields_used,
            contexts=contexts,
            items=items,
            limitations=limitations,
            engine_version=engine_version,
        )

    # 2. Invalid evidence, unreadable documents, or untyped/heterogeneous identifiers -> abstencao.
    if has_invalid_ev:
        return _build_axis_result(
            axis=axis,
            status=AxisStatus.ABSTENCAO,
            rule_code="IDENTITY_INVALID_EVIDENCE",
            justification=(
                "Abstencao obrigatoria: referencia espacial de evidencia ausente, corrompida "
                "ou pertencente a versao/organizacao incompatível."
            ),
            fields_used=fields_used,
            contexts=contexts,
            items=items,
            limitations=limitations,
            engine_version=engine_version,
        )

    if len(id_types) > 1:
        limitations.append("HETEROGENEOUS_IDENTIFIER_TYPES_CANNOT_BE_EQUATED")
        return _build_axis_result(
            axis=axis,
            status=AxisStatus.ABSTENCAO,
            rule_code="IDENTITY_HETEROGENEOUS_IDENTIFIER_TYPES",
            justification=(
                f"Tipos distintos de identificadores encontrados ({sorted(id_types)}); "
                "nao e permitido presumir equivalencia entre identificadores de tipos diferentes."
            ),
            fields_used=fields_used,
            contexts=contexts,
            items=items,
            limitations=limitations,
            engine_version=engine_version,
        )

    if abstained_patients:
        patient_reasons = sorted(
            {
                str(f.metadata_json.get("reason_code") or "ABSTAINED_PATIENT_FIELD")
                for _, f in abstained_patients
            }
        )
        limitations.append("PATIENT_FIELD_ABSTAINED_CANNOT_BE_SKIPPED")
        for r_code in patient_reasons:
            limitations.append(f"PATIENT_ABSTENTION_REASON:{r_code}")
        return _build_axis_result(
            axis=axis,
            status=AxisStatus.ABSTENCAO,
            rule_code="IDENTITY_PATIENT_ABSTAINED",
            justification=(
                f"Campo de paciente presente com extracao abstida/invalida ({patient_reasons}); "
                "coincidencia de nascimento ou identificador nao elimina abstencao em paciente."
            ),
            fields_used=fields_used,
            contexts=contexts,
            items=items,
            limitations=limitations,
            engine_version=engine_version,
        )

    if untyped_ids or abstained_id_fields or abstained_births:
        limitations.append("UNTYPED_OR_UNPARSED_IDENTITY_FIELD")
        for _, f_item in abstained_id_fields + abstained_births:
            r_code = f_item.metadata_json.get("reason_code")
            if r_code:
                limitations.append(f"IDENTITY_ABSTENTION_REASON:{r_code}")
        return _build_axis_result(
            axis=axis,
            status=AxisStatus.ABSTENCAO,
            rule_code="IDENTITY_UNTYPED_OR_INVALID_FIELD",
            justification=(
                "Identificador sem tipo definido em contrato ou campo de identidade abstido/invalido "
                "impede conclusao deterministica no eixo de identidade."
            ),
            fields_used=fields_used,
            contexts=contexts,
            items=items,
            limitations=limitations,
            engine_version=engine_version,
        )

    if unreadable:
        for u in unreadable:
            items.append(
                _make_comparison_item(
                    ctx=u,
                    field_key="document_version",
                    field_item=None,
                    ev=None,
                    role_in_comparison="unreadable_document",
                    override_value=u.version.extraction_outcome or u.extraction_state,
                )
            )
        return _build_axis_result(
            axis=axis,
            status=AxisStatus.ABSTENCAO,
            rule_code="IDENTITY_UNREADABLE_SOURCE_DOCUMENT",
            justification=(
                "Ha documento(s) ativo(s) ilegivel(is) ou com extracao abstida/falha no caso; "
                "a ausencia de leitura nao e ignorada nem convertida em consistencia."
            ),
            fields_used=fields_used,
            contexts=contexts,
            items=items,
            limitations=limitations,
            engine_version=engine_version,
        )

    # 3. Missing / pending items -> pendente.
    if pending or len(ready) < 2 or missing_docs_notes:
        rule = (
            "IDENTITY_EXTRACTION_PENDING"
            if pending
            else ("IDENTITY_AWAITING_COMPARABLE_DOCUMENTS" if len(ready) < 2 else "IDENTITY_MISSING_REQUIRED_FIELDS")
        )
        return _build_axis_result(
            axis=axis,
            status=AxisStatus.PENDENTE,
            rule_code=rule,
            justification=(
                "Faltam documentos comparaveis com extracao concluida ou campos minimos completos "
                "(paciente, nascimento e identificador tipado) em todos os documentos."
            ),
            fields_used=fields_used,
            contexts=contexts,
            items=items,
            limitations=limitations,
            engine_version=engine_version,
        )

    if (
        len(patient_entries) != len(ready)
        or len(birth_entries) != len(ready)
        or len(id_entries) != len(ready)
    ):
        return _build_axis_result(
            axis=axis,
            status=AxisStatus.ABSTENCAO,
            rule_code="IDENTITY_INCOMPLETE_EXTRACTED_EVIDENCE",
            justification=(
                "Cobertura deterministica incompleta nos campos extraidos de identidade impede atribuicao de 'ok'."
            ),
            fields_used=fields_used,
            contexts=contexts,
            items=items,
            limitations=limitations,
            engine_version=engine_version,
        )

    return _build_axis_result(
        axis=axis,
        status=AxisStatus.OK,
        rule_code="IDENTITY_EXACT_MATCH",
        justification=(
            f"Identificador tipado ({next(iter(id_types))}), paciente e data de nascimento coincidem "
            f"exatamente entre todos os {len(ready)} documentos comparados dentro do escopo administrativo."
        ),
        fields_used=fields_used,
        contexts=contexts,
        items=items,
        limitations=limitations,
        engine_version=engine_version,
    )


def _evaluate_procedure_axis(
    contexts: list[_ActiveVersionContext],
    *,
    procedure_reference: str | None,
    engine_version: str,
) -> AxisEvaluationResult:
    axis = AxisName.PROCEDIMENTO_CODIGO
    fields_used = ("procedure", "procedure_code_system", "procedure_code")
    limitations: list[str] = [
        "NO_CLINICAL_EQUIVALENCE_INFERENCE",
        "NO_CROSS_SYSTEM_CODE_MAPPING",
    ]
    has_invalid_ev, limitations, unreadable, pending, ready = _evaluate_common_preconditions(
        axis=axis,
        contexts=contexts,
        field_keys=fields_used,
        engine_version=engine_version,
        limitations=limitations,
    )

    items: list[dict[str, Any]] = []
    if procedure_reference:
        limitations.append("CASE_PROCEDURE_REFERENCE_RECORDED_AS_CONTEXT_ONLY")

    ambiguous_intra_proc: list[dict[str, Any]] = []
    conflicting_code_system_intra: list[dict[str, Any]] = []
    proc_desc_entries: list[tuple[_ActiveVersionContext, ExtractedFieldInput, str]] = []
    abstained_proc_descs: list[tuple[_ActiveVersionContext, ExtractedFieldInput]] = []
    code_with_sys_entries: list[tuple[_ActiveVersionContext, ExtractedFieldInput, str, str]] = []
    code_without_sys: list[tuple[_ActiveVersionContext, ExtractedFieldInput]] = []
    abstained_codes: list[tuple[_ActiveVersionContext, ExtractedFieldInput]] = []
    abstained_code_systems: list[tuple[_ActiveVersionContext, ExtractedFieldInput]] = []
    missing_proc_docs: list[_ActiveVersionContext] = []

    for ctx in ready:
        p_field = ctx.fields_by_key.get("procedure")
        sys_field = ctx.fields_by_key.get("procedure_code_system")
        code_field = ctx.fields_by_key.get("procedure_code")

        for fk_name, f_obj in (
            ("procedure", p_field),
            ("procedure_code_system", sys_field),
            ("procedure_code", code_field),
        ):
            _append_field_comparison_items(
                items, ctx=ctx, field_key=fk_name, field_item=f_obj
            )

        if p_field is not None:
            if p_field.status == ExtractedFieldStatus.AMBIGUOUS.value:
                ambiguous_intra_proc.append(
                    _make_comparison_item(
                        ctx=ctx,
                        field_key="procedure",
                        field_item=p_field,
                        ev=_first_ev(ctx, p_field),
                        role_in_comparison="intra_document_ambiguous",
                    )
                )
            elif (
                p_field.status == ExtractedFieldStatus.EXTRACTED.value
                and not p_field.abstained
            ):
                p_norm = _conservative_text_key(
                    p_field.normalized_value or p_field.raw_value or ""
                )
                if not p_norm:
                    abstained_proc_descs.append((ctx, p_field))
                else:
                    proc_desc_entries.append((ctx, p_field, p_norm))
            else:
                abstained_proc_descs.append((ctx, p_field))

        explicit_sys: str | None = None
        if sys_field is not None:
            if sys_field.status == ExtractedFieldStatus.AMBIGUOUS.value:
                conflicting_code_system_intra.append(
                    _make_comparison_item(
                        ctx=ctx,
                        field_key="procedure_code_system",
                        field_item=sys_field,
                        ev=_first_ev(ctx, sys_field),
                        role_in_comparison="conflicting_code_system",
                    )
                )
            elif (
                sys_field.status == ExtractedFieldStatus.EXTRACTED.value
                and not sys_field.abstained
            ):
                raw_sys = sys_field.normalized_value or sys_field.raw_value
                if raw_sys and _collapse_whitespace(raw_sys):
                    explicit_sys = _collapse_whitespace(raw_sys).upper()
                else:
                    abstained_code_systems.append((ctx, sys_field))
            else:
                abstained_code_systems.append((ctx, sys_field))

        if code_field is not None:
            reason_code = str(code_field.metadata_json.get("reason_code") or "")
            sys_identified = code_field.metadata_json.get("system_identified")
            meta_sys = code_field.metadata_json.get("code_system")
            if explicit_sys is None and isinstance(meta_sys, str) and meta_sys.strip():
                explicit_sys = _collapse_whitespace(meta_sys).upper()

            if code_field.status == ExtractedFieldStatus.AMBIGUOUS.value:
                if reason_code == "CONFLICTING_CODE_SYSTEM":
                    conflicting_code_system_intra.append(
                        _make_comparison_item(
                            ctx=ctx,
                            field_key="procedure_code",
                            field_item=code_field,
                            ev=_first_ev(ctx, code_field),
                            role_in_comparison="conflicting_code_system",
                        )
                    )
                else:
                    ambiguous_intra_proc.append(
                        _make_comparison_item(
                            ctx=ctx,
                            field_key="procedure_code",
                            field_item=code_field,
                            ev=_first_ev(ctx, code_field),
                            role_in_comparison="intra_document_ambiguous",
                        )
                    )
            elif (
                code_field.status == ExtractedFieldStatus.ABSTAINED.value
                or code_field.abstained
            ):
                if (
                    reason_code in ("MISSING_CODE_SYSTEM", "CODE_SYSTEM_UNIDENTIFIED")
                    or sys_identified is False
                ):
                    code_without_sys.append((ctx, code_field))
                else:
                    abstained_codes.append((ctx, code_field))
            elif code_field.status == ExtractedFieldStatus.EXTRACTED.value:
                code_val = _collapse_whitespace(
                    code_field.normalized_value or code_field.raw_value or ""
                ).upper()
                if not code_val:
                    abstained_codes.append((ctx, code_field))
                elif not explicit_sys or sys_identified is False:
                    code_without_sys.append((ctx, code_field))
                else:
                    code_with_sys_entries.append((ctx, code_field, explicit_sys, code_val))
            else:
                abstained_codes.append((ctx, code_field))

        if p_field is None and code_field is None:
            missing_proc_docs.append(ctx)
            items.append(
                _make_comparison_item(
                    ctx=ctx,
                    field_key="procedure",
                    field_item=None,
                    ev=None,
                    role_in_comparison="missing_field",
                )
            )

    if ambiguous_intra_proc:
        return _build_axis_result(
            axis=axis,
            status=AxisStatus.CONFLITO,
            rule_code="PROCEDURE_AMBIGUOUS_INTRA_DOCUMENT",
            justification=(
                "Multiplas ocorrencias incompativeis de procedimento ou codigo no mesmo documento."
            ),
            fields_used=fields_used,
            contexts=contexts,
            items=items,
            limitations=limitations,
            engine_version=engine_version,
        )

    # Check intra-system code conflicts BEFORE heterogeneous/missing checks
    codes_by_sys: dict[str, set[str]] = {}
    for _, _, sys_name, code_val in code_with_sys_entries:
        codes_by_sys.setdefault(sys_name, set()).add(code_val)
    conflicting_sys = [sys_name for sys_name, vals in codes_by_sys.items() if len(vals) > 1]
    if conflicting_sys:
        return _build_axis_result(
            axis=axis,
            status=AxisStatus.CONFLITO,
            rule_code="PROCEDURE_CODE_CONFLICT_SAME_SYSTEM",
            justification=(
                f"Codigos de procedimento distintos dentro do mesmo sistema ({conflicting_sys})."
            ),
            fields_used=fields_used,
            contexts=contexts,
            items=items,
            limitations=limitations,
            engine_version=engine_version,
        )

    distinct_proc_descs = {norm for _, _, norm in proc_desc_entries}
    if len(distinct_proc_descs) > 1:
        raw_descs = sorted({f.normalized_value or f.raw_value or "" for _, f, _ in proc_desc_entries})
        return _build_axis_result(
            axis=axis,
            status=AxisStatus.CONFLITO,
            rule_code="PROCEDURE_DESCRIPTION_CONFLICT",
            justification=(
                f"Descricoes textuais de procedimento divergentes entre documentos: {raw_descs}. "
                "Nenhuma equivalencia clinica e inferida automaticamente."
            ),
            fields_used=fields_used,
            contexts=contexts,
            items=items,
            limitations=limitations,
            engine_version=engine_version,
        )

    if has_invalid_ev:
        return _build_axis_result(
            axis=axis,
            status=AxisStatus.ABSTENCAO,
            rule_code="PROCEDURE_INVALID_EVIDENCE",
            justification="Evidencia documental de procedimento invalida ou de versao incorreta impede conclusao.",
            fields_used=fields_used,
            contexts=contexts,
            items=items,
            limitations=limitations,
            engine_version=engine_version,
        )

    if conflicting_code_system_intra:
        return _build_axis_result(
            axis=axis,
            status=AxisStatus.ABSTENCAO,
            rule_code="PROCEDURE_CONFLICTING_CODE_SYSTEM",
            justification="Sistema de codificacao conflitante dentro do mesmo documento impede comparacao segura.",
            fields_used=fields_used,
            contexts=contexts,
            items=items,
            limitations=limitations,
            engine_version=engine_version,
        )

    if code_without_sys:
        return _build_axis_result(
            axis=axis,
            status=AxisStatus.ABSTENCAO,
            rule_code="PROCEDURE_CODE_WITHOUT_SYSTEM",
            justification=(
                "Codigo de procedimento extraido sem identificacao explicita do sistema de codificacao; "
                "e proibido presumir tabela de codificacao."
            ),
            fields_used=fields_used,
            contexts=contexts,
            items=items,
            limitations=limitations,
            engine_version=engine_version,
        )

    if len(codes_by_sys) > 1:
        code_values_set = {code_v for _, _, _, code_v in code_with_sys_entries}
        same_code_diff_sys = any(
            sum(1 for sys_n, vals in codes_by_sys.items() if code_v in vals) > 1
            for code_v in code_values_set
        )
        limitations.append("HETEROGENEOUS_CODE_SYSTEMS_NOT_EQUATED")
        rule = (
            "PROCEDURE_CODE_EQUAL_DIFFERENT_SYSTEMS"
            if same_code_diff_sys
            else "PROCEDURE_HETEROGENEOUS_CODE_SYSTEMS"
        )
        return _build_axis_result(
            axis=axis,
            status=AxisStatus.ABSTENCAO,
            rule_code=rule,
            justification=(
                f"Sistemas de codificacao distintos entre documentos ({sorted(codes_by_sys.keys())}); "
                "codigos nao sao comparaveis nem equivalentes entre sistemas diferentes sem tabela/revisao."
            ),
            fields_used=fields_used,
            contexts=contexts,
            items=items,
            limitations=limitations,
            engine_version=engine_version,
        )

    if abstained_proc_descs:
        desc_reasons = sorted(
            {
                str(f.metadata_json.get("reason_code") or "ABSTAINED_PROCEDURE_DESCRIPTION")
                for _, f in abstained_proc_descs
            }
        )
        limitations.append("PROCEDURE_DESCRIPTION_ABSTAINED_CANNOT_BE_SKIPPED")
        for r_code in desc_reasons:
            limitations.append(f"PROCEDURE_ABSTENTION_REASON:{r_code}")
        return _build_axis_result(
            axis=axis,
            status=AxisStatus.ABSTENCAO,
            rule_code="PROCEDURE_DESCRIPTION_ABSTAINED",
            justification=(
                f"Descricao de procedimento presente com extracao abstida/invalida ({desc_reasons}); "
                "coincidencia de codigo e sistema nao elimina abstencao na descricao."
            ),
            fields_used=fields_used,
            contexts=contexts,
            items=items,
            limitations=limitations,
            engine_version=engine_version,
        )

    if abstained_codes:
        code_reasons = sorted(
            {
                str(f.metadata_json.get("reason_code") or "ABSTAINED_PROCEDURE_CODE")
                for _, f in abstained_codes
            }
        )
        limitations.append("PROCEDURE_CODE_ABSTAINED_CANNOT_BE_SKIPPED")
        for r_code in code_reasons:
            limitations.append(f"PROCEDURE_ABSTENTION_REASON:{r_code}")
        return _build_axis_result(
            axis=axis,
            status=AxisStatus.ABSTENCAO,
            rule_code="PROCEDURE_CODE_ABSTAINED",
            justification=(
                f"Codigo de procedimento presente com extracao abstida/invalida ({code_reasons}); "
                "concordancia textual nao ignora nem omite codigo invalido."
            ),
            fields_used=fields_used,
            contexts=contexts,
            items=items,
            limitations=limitations,
            engine_version=engine_version,
        )

    if abstained_code_systems:
        sys_reasons = sorted(
            {
                str(f.metadata_json.get("reason_code") or "ABSTAINED_PROCEDURE_CODE_SYSTEM")
                for _, f in abstained_code_systems
            }
        )
        limitations.append("PROCEDURE_CODE_SYSTEM_ABSTAINED_CANNOT_BE_SKIPPED")
        for r_code in sys_reasons:
            limitations.append(f"PROCEDURE_ABSTENTION_REASON:{r_code}")
        return _build_axis_result(
            axis=axis,
            status=AxisStatus.ABSTENCAO,
            rule_code="PROCEDURE_CODE_SYSTEM_ABSTAINED",
            justification=(
                f"Sistema de codificacao presente com extracao abstida/invalida ({sys_reasons}); "
                "nao e permitido presumir concordancia com sistema invalidado."
            ),
            fields_used=fields_used,
            contexts=contexts,
            items=items,
            limitations=limitations,
            engine_version=engine_version,
        )

    if unreadable:
        for u in unreadable:
            items.append(
                _make_comparison_item(
                    ctx=u,
                    field_key="document_version",
                    field_item=None,
                    ev=None,
                    role_in_comparison="unreadable_document",
                    override_value=u.version.extraction_outcome or u.extraction_state,
                )
            )
        return _build_axis_result(
            axis=axis,
            status=AxisStatus.ABSTENCAO,
            rule_code="PROCEDURE_UNREADABLE_SOURCE_DOCUMENT",
            justification="Documento ilegivel ou sem extracao valida impede confirmacao de procedimento.",
            fields_used=fields_used,
            contexts=contexts,
            items=items,
            limitations=limitations,
            engine_version=engine_version,
        )

    if pending or len(ready) < 2 or missing_proc_docs:
        rule = (
            "PROCEDURE_EXTRACTION_PENDING"
            if pending
            else (
                "PROCEDURE_AWAITING_COMPARABLE_DOCUMENTS"
                if len(ready) < 2
                else "PROCEDURE_MISSING_IN_DOCUMENT"
            )
        )
        return _build_axis_result(
            axis=axis,
            status=AxisStatus.PENDENTE,
            rule_code=rule,
            justification=(
                "Campo de procedimento ou codigo ausente em parte dos documentos ou extracao ainda pendente."
            ),
            fields_used=fields_used,
            contexts=contexts,
            items=items,
            limitations=limitations,
            engine_version=engine_version,
        )

    # All ready documents (>= 2) have procedure or (system + code), and none disagree.
    has_code_match = len(code_with_sys_entries) >= 2 and len(codes_by_sys) == 1
    has_desc_match = len(proc_desc_entries) == len(ready) and len(distinct_proc_descs) == 1
    if not has_code_match and not has_desc_match:
        return _build_axis_result(
            axis=axis,
            status=AxisStatus.PENDENTE,
            rule_code="PROCEDURE_INCOMPLETE_ACROSS_DOCUMENTS",
            justification="Dados de procedimento insuficientes em todos os documentos para confirmacao deterministica.",
            fields_used=fields_used,
            contexts=contexts,
            items=items,
            limitations=limitations,
            engine_version=engine_version,
        )

    if has_code_match and has_desc_match and len(code_with_sys_entries) == len(ready):
        rule_code = "PROCEDURE_CODE_AND_DESCRIPTION_MATCH"
        just = (
            f"Descricao e codigo ({next(iter(codes_by_sys.keys()))}) coincidem exatamente nos {len(ready)} documentos."
        )
    elif has_code_match and len(code_with_sys_entries) == len(ready):
        rule_code = "PROCEDURE_CODE_EXACT_MATCH"
        just = (
            f"Codigo e sistema ({next(iter(codes_by_sys.keys()))}) coincidem nos {len(ready)} documentos."
        )
    else:
        rule_code = "PROCEDURE_TEXTUAL_MATCH_NO_COMMON_CODE"
        limitations.append("CODE_NOT_PRESENT_IN_ALL_DOCUMENTS_TEXTUAL_ONLY")
        just = (
            f"Descricao textual de procedimento coincide exatamente apos normalizacao superficial nos "
            f"{len(ready)} documentos (sem equivalencia clinica)."
        )

    return _build_axis_result(
        axis=axis,
        status=AxisStatus.OK,
        rule_code=rule_code,
        justification=just,
        fields_used=fields_used,
        contexts=contexts,
        items=items,
        limitations=limitations,
        engine_version=engine_version,
    )


def _evaluate_laterality_axis(
    contexts: list[_ActiveVersionContext],
    *,
    declared_laterality: str | None,
    engine_version: str,
) -> AxisEvaluationResult:
    axis = AxisName.LATERALIDADE
    fields_used = ("laterality",)
    limitations: list[str] = ["NO_CONTEXTUAL_LATERALITY_INFERENCE", "MISSING_NEVER_COERCED_TO_NA"]
    has_invalid_ev, limitations, unreadable, pending, ready = _evaluate_common_preconditions(
        axis=axis,
        contexts=contexts,
        field_keys=fields_used,
        engine_version=engine_version,
        limitations=limitations,
    )

    items: list[dict[str, Any]] = []
    ambiguous_intra_lat: list[dict[str, Any]] = []
    abstained_lat: list[tuple[_ActiveVersionContext, ExtractedFieldInput]] = []
    valid_lats: list[tuple[_ActiveVersionContext, ExtractedFieldInput, str]] = []
    missing_lat_docs: list[_ActiveVersionContext] = []

    declared_canon = _parse_canonical_laterality(declared_laterality) if declared_laterality else None
    if declared_laterality and declared_canon is None:
        limitations.append("UNRECOGNIZED_CASE_DECLARED_LATERALITY")

    for ctx in ready:
        l_field = ctx.fields_by_key.get("laterality")
        if l_field is None:
            missing_lat_docs.append(ctx)
            items.append(
                _make_comparison_item(
                    ctx=ctx,
                    field_key="laterality",
                    field_item=None,
                    ev=None,
                    role_in_comparison="missing_field",
                )
            )
            continue

        for ev in _all_evs(ctx, l_field):
            items.append(
                _make_comparison_item(
                    ctx=ctx, field_key="laterality", field_item=l_field, ev=ev, role_in_comparison="compared_value"
                )
            )

        if l_field.status == ExtractedFieldStatus.AMBIGUOUS.value:
            ambiguous_intra_lat.append(
                _make_comparison_item(
                    ctx=ctx,
                    field_key="laterality",
                    field_item=l_field,
                    ev=_first_ev(ctx, l_field),
                    role_in_comparison="intra_document_ambiguous",
                )
            )
            continue

        if l_field.status == ExtractedFieldStatus.EXTRACTED.value:
            canon = _parse_canonical_laterality(l_field.normalized_value or l_field.raw_value)
            if canon is None:
                abstained_lat.append((ctx, l_field))
            else:
                valid_lats.append((ctx, l_field, canon))
        else:
            abstained_lat.append((ctx, l_field))

    if ambiguous_intra_lat:
        return _build_axis_result(
            axis=axis,
            status=AxisStatus.CONFLITO,
            rule_code="LATERALITY_AMBIGUOUS_INTRA_DOCUMENT",
            justification="Multiplas lateralidades conflitantes declaradas dentro do mesmo documento.",
            fields_used=fields_used,
            contexts=contexts,
            items=items,
            limitations=limitations,
            engine_version=engine_version,
        )

    distinct_lats = {code for _, _, code in valid_lats}
    if len(distinct_lats) > 1:
        if "AO" in distinct_lats and ("OD" in distinct_lats or "OE" in distinct_lats):
            rule_code = "BILATERAL_VS_UNILATERAL_CONFLICT"
            just = (
                f"Conflito entre lateralidade bilateral (AO) e unilateral ({sorted(distinct_lats)}); "
                "nao ha regra contratual de subordinacao automatica."
            )
        elif "NA" in distinct_lats:
            rule_code = "LATERALITY_NA_VS_LATERAL_CONFLICT"
            just = (
                f"Conflito entre declaracao 'Nao aplicavel' (NA) e lateralidade explicita ({sorted(distinct_lats)})."
            )
        else:
            rule_code = "EXPLICIT_LATERALITY_MISMATCH"
            just = f"Lateralidades explicitas incompativeis entre os documentos: {sorted(distinct_lats)}."
        return _build_axis_result(
            axis=axis,
            status=AxisStatus.CONFLITO,
            rule_code=rule_code,
            justification=just,
            fields_used=fields_used,
            contexts=contexts,
            items=items,
            limitations=limitations,
            engine_version=engine_version,
        )

    if declared_canon is not None and distinct_lats and declared_canon not in distinct_lats:
        items.append(
            {
                "document_id": None,
                "document_version_id": None,
                "source_label": "case_declared_laterality",
                "field_key": "declared_laterality",
                "raw_value": declared_laterality,
                "normalized_value": declared_canon,
                "value": declared_canon,
                "field_status": "case_metadata",
                "evidence_id": None,
                "page": None,
                "page_number": None,
                "bbox": None,
                "role_in_comparison": "declared_case_context",
            }
        )
        return _build_axis_result(
            axis=axis,
            status=AxisStatus.CONFLITO,
            rule_code="LATERALITY_CONFLICTS_WITH_CASE_DECLARATION",
            justification=(
                f"Lateralidade extraida ({sorted(distinct_lats)}) diverge da declarada no caso ({declared_canon})."
            ),
            fields_used=fields_used,
            contexts=contexts,
            items=items,
            limitations=limitations,
            engine_version=engine_version,
        )

    if has_invalid_ev:
        return _build_axis_result(
            axis=axis,
            status=AxisStatus.ABSTENCAO,
            rule_code="LATERALITY_INVALID_EVIDENCE",
            justification="Evidencia documental de lateralidade invalida impede avaliacao segura.",
            fields_used=fields_used,
            contexts=contexts,
            items=items,
            limitations=limitations,
            engine_version=engine_version,
        )

    if abstained_lat:
        return _build_axis_result(
            axis=axis,
            status=AxisStatus.ABSTENCAO,
            rule_code="LATERALITY_UNRECOGNIZED_VALUE",
            justification=(
                "Valor de lateralidade nao reconhecido na taxonomia explicita; "
                "valores desconhecidos nunca sao convertidos em 'Nao aplicavel'."
            ),
            fields_used=fields_used,
            contexts=contexts,
            items=items,
            limitations=limitations,
            engine_version=engine_version,
        )

    if unreadable:
        for u in unreadable:
            items.append(
                _make_comparison_item(
                    ctx=u,
                    field_key="document_version",
                    field_item=None,
                    ev=None,
                    role_in_comparison="unreadable_document",
                    override_value=u.version.extraction_outcome or u.extraction_state,
                )
            )
        return _build_axis_result(
            axis=axis,
            status=AxisStatus.ABSTENCAO,
            rule_code="LATERALITY_UNREADABLE_SOURCE_DOCUMENT",
            justification="Documento ilegivel ou abstido impede confirmacao de lateralidade no caso.",
            fields_used=fields_used,
            contexts=contexts,
            items=items,
            limitations=limitations,
            engine_version=engine_version,
        )

    if pending or len(ready) < 2 or missing_lat_docs:
        rule = (
            "LATERALITY_EXTRACTION_PENDING"
            if pending
            else (
                "LATERALITY_AWAITING_COMPARABLE_DOCUMENTS"
                if len(ready) < 2
                else "LATERALITY_MISSING_IN_DOCUMENT"
            )
        )
        return _build_axis_result(
            axis=axis,
            status=AxisStatus.PENDENTE,
            rule_code=rule,
            justification=(
                "Lateralidade ausente em ao menos um documento ou extracao pendente; "
                "ausencia de lateralidade nao equivale a 'Nao aplicavel'."
            ),
            fields_used=fields_used,
            contexts=contexts,
            items=items,
            limitations=limitations,
            engine_version=engine_version,
        )

    single_code = next(iter(distinct_lats))
    if single_code == "NA":
        limitations.append("LATERALITY_DECLARED_NOT_APPLICABLE_SCOPED")
        return _build_axis_result(
            axis=axis,
            status=AxisStatus.NAO_APLICAVEL,
            rule_code="LATERALITY_EXPLICITLY_NOT_APPLICABLE",
            justification=(
                f"Todos os {len(ready)} documentos comparados declaram explicitamente lateralidade 'Nao aplicavel' (NA)."
            ),
            fields_used=fields_used,
            contexts=contexts,
            items=items,
            limitations=limitations,
            engine_version=engine_version,
        )

    return _build_axis_result(
        axis=axis,
        status=AxisStatus.OK,
        rule_code="LATERALITY_EXACT_MATCH",
        justification=f"Lateralidade '{single_code}' coincide explicitamente em todos os {len(ready)} documentos.",
        fields_used=fields_used,
        contexts=contexts,
        items=items,
        limitations=limitations,
        engine_version=engine_version,
    )


def _evaluate_temporality_axis(
    contexts: list[_ActiveVersionContext],
    *,
    max_spread_days: int,
    reference_date: date | None,
    engine_version: str,
) -> AxisEvaluationResult:
    axis = AxisName.TEMPORALIDADE
    fields_used = ("issue_date", "document_version.version_number", "document_version.created_at")
    limitations: list[str] = [
        "UPLOAD_TIMESTAMP_DISTINGUISHED_FROM_ISSUE_DATE",
        "VERSION_ORDER_NEVER_INFERS_CLINICAL_VALIDITY",
    ]
    has_invalid_ev, limitations, unreadable, pending, ready = _evaluate_common_preconditions(
        axis=axis,
        contexts=contexts,
        field_keys=("issue_date",),
        engine_version=engine_version,
        limitations=limitations,
    )

    items: list[dict[str, Any]] = []
    ambiguous_intra_dates: list[dict[str, Any]] = []
    abstained_dates: list[tuple[_ActiveVersionContext, ExtractedFieldInput]] = []
    valid_dates: list[tuple[_ActiveVersionContext, ExtractedFieldInput, date]] = []
    missing_dates_docs: list[_ActiveVersionContext] = []
    future_vs_upload_conflicts: list[str] = []
    version_regression_conflicts: list[str] = []

    for ctx in ready:
        d_field = ctx.fields_by_key.get("issue_date")
        # Include version lineage trace for superseded versions if present
        if ctx.superseded_versions:
            limitations.append("SUPERSEDED_VERSIONS_EXCLUDED_FROM_ACTIVE_SCOPE_PRESERVED_IN_HISTORY")
            prior_dates: list[tuple[DocumentVersionInput, date]] = []
            for sv in ctx.superseded_versions:
                sv_issue = next((f for f in sv.extracted_fields if f.field_key == "issue_date"), None)
                sv_parsed = _parse_iso_date(sv_issue.normalized_value) if sv_issue else None
                items.append(
                    {
                        "document_id": ctx.doc.document_id,
                        "document_version_id": sv.version_id,
                        "document_kind": ctx.doc.document_kind,
                        "source_label": ctx.doc.source_label,
                        "version_number": sv.version_number,
                        "sha256_hex": sv.sha256_hex,
                        "superseded_by_version_id": sv.superseded_by_version_id,
                        "upload_created_at": _as_utc(sv.created_at).isoformat(),
                        "field_key": "issue_date",
                        "extracted_field_id": sv_issue.extracted_field_id if sv_issue else None,
                        "raw_value": sv_issue.raw_value if sv_issue else None,
                        "normalized_value": sv_issue.normalized_value if sv_issue else None,
                        "value": sv_issue.normalized_value if sv_issue else None,
                        "field_status": sv_issue.status if sv_issue else "historical_superseded",
                        "evidence_id": None,
                        "page": None,
                        "page_number": None,
                        "bbox": None,
                        "role_in_comparison": "superseded_version_lineage",
                    }
                )
                if sv_parsed is not None:
                    prior_dates.append((sv, sv_parsed))
        else:
            prior_dates = []

        if d_field is None:
            missing_dates_docs.append(ctx)
            items.append(
                _make_comparison_item(
                    ctx=ctx,
                    field_key="issue_date",
                    field_item=None,
                    ev=None,
                    role_in_comparison="missing_field",
                )
            )
            continue

        if d_field.status == ExtractedFieldStatus.AMBIGUOUS.value:
            for ev in _all_evs(ctx, d_field):
                items.append(
                    _make_comparison_item(
                        ctx=ctx,
                        field_key="issue_date",
                        field_item=d_field,
                        ev=ev,
                        role_in_comparison="intra_document_ambiguous",
                    )
                )
            ambiguous_intra_dates.append(items[-1])
            continue

        if d_field.status == ExtractedFieldStatus.EXTRACTED.value:
            parsed_d = _parse_iso_date(d_field.normalized_value)
            if parsed_d is None:
                for ev in _all_evs(ctx, d_field):
                    items.append(
                        _make_comparison_item(
                            ctx=ctx,
                            field_key="issue_date",
                            field_item=d_field,
                            ev=ev,
                            role_in_comparison="abstained_source",
                        )
                    )
                abstained_dates.append((ctx, d_field))
                continue

            valid_dates.append((ctx, d_field, parsed_d))
            upload_date_tol = (_as_utc(ctx.version.created_at) + timedelta(days=1)).date()
            if parsed_d > upload_date_tol:
                future_vs_upload_conflicts.append(
                    f"{ctx.doc.document_id}:issue({parsed_d.isoformat()})>upload({_as_utc(ctx.version.created_at).date().isoformat()})"
                )
            for sv, sv_d in prior_dates:
                if ctx.version.version_number > sv.version_number and parsed_d < sv_d:
                    version_regression_conflicts.append(
                        f"{ctx.doc.document_id}:v{ctx.version.version_number}({parsed_d})<v{sv.version_number}({sv_d})"
                    )
        else:
            for ev in _all_evs(ctx, d_field):
                items.append(
                    _make_comparison_item(
                        ctx=ctx,
                        field_key="issue_date",
                        field_item=d_field,
                        ev=ev,
                        role_in_comparison="abstained_source",
                    )
                )
            abstained_dates.append((ctx, d_field))

    # Deterministic chronological sort by clinical issue_date (NOT upload order!)
    for ctx, d_field, parsed_d in sorted(
        valid_dates, key=lambda tup: (tup[2], tup[0].version.version_number, tup[0].doc.document_id)
    ):
        for ev in _all_evs(ctx, d_field):
            items.append(
                _make_comparison_item(
                    ctx=ctx,
                    field_key="issue_date",
                    field_item=d_field,
                    ev=ev,
                    role_in_comparison="compared_value",
                )
            )

    if ambiguous_intra_dates:
        return _build_axis_result(
            axis=axis,
            status=AxisStatus.CONFLITO,
            rule_code="TEMPORALITY_AMBIGUOUS_INTRA_DOCUMENT",
            justification="Multiplas datas de emissao conflitantes no mesmo documento.",
            fields_used=fields_used,
            contexts=contexts,
            items=items,
            limitations=limitations,
            engine_version=engine_version,
        )

    if future_vs_upload_conflicts:
        return _build_axis_result(
            axis=axis,
            status=AxisStatus.CONFLITO,
            rule_code="TEMPORALITY_ISSUE_DATE_AFTER_UPLOAD",
            justification=(
                f"Data de emissao posterior a data fisica de upload registrada: {future_vs_upload_conflicts}."
            ),
            fields_used=fields_used,
            contexts=contexts,
            items=items,
            limitations=limitations,
            engine_version=engine_version,
        )

    if version_regression_conflicts:
        return _build_axis_result(
            axis=axis,
            status=AxisStatus.CONFLITO,
            rule_code="TEMPORALITY_VERSION_DATE_REGRESSION",
            justification=(
                f"Nova versao documental apresenta emissao anterior a versao substituida: {version_regression_conflicts}. "
                "Sistema nao elege automaticamente qual versao deve prevalecer."
            ),
            fields_used=fields_used,
            contexts=contexts,
            items=items,
            limitations=limitations,
            engine_version=engine_version,
        )

    # Competing active documents of the SAME explicit document_kind with different dates
    dates_by_kind: dict[str, set[date]] = {}
    for ctx, _, parsed_d in valid_dates:
        if ctx.doc.document_kind and ctx.doc.document_kind != "desconhecido":
            dates_by_kind.setdefault(ctx.doc.document_kind, set()).add(parsed_d)
    competing_kinds = [k for k, ds in dates_by_kind.items() if len(ds) > 1]
    if competing_kinds:
        return _build_axis_result(
            axis=axis,
            status=AxisStatus.CONFLITO,
            rule_code="TEMPORALITY_COMPETING_ACTIVE_DOCUMENT_DATES",
            justification=(
                f"Documentos ativos concorrentes do mesmo tipo ({competing_kinds}) possuem datas de emissao distintas "
                "sem substituicao formal; o motor nao escolhe automaticamente qual documento prevalece."
            ),
            fields_used=fields_used,
            contexts=contexts,
            items=items,
            limitations=limitations,
            engine_version=engine_version,
        )

    if reference_date is not None and valid_dates:
        future_ref = [
            f"{ctx.doc.document_id}({d.isoformat()})" for ctx, _, d in valid_dates if d > reference_date
        ]
        if future_ref:
            return _build_axis_result(
                axis=axis,
                status=AxisStatus.CONFLITO,
                rule_code="TEMPORALITY_FUTURE_ISSUE_DATE_VS_REFERENCE",
                justification=(
                    f"Data de emissao posterior a data de referencia da politica ({reference_date.isoformat()}): {future_ref}."
                ),
                fields_used=fields_used,
                contexts=contexts,
                items=items,
                limitations=limitations,
                engine_version=engine_version,
            )
        stale_ref = [
            f"{ctx.doc.document_id}({d.isoformat()})"
            for ctx, _, d in valid_dates
            if (reference_date - d).days > max_spread_days
        ]
        if stale_ref:
            return _build_axis_result(
                axis=axis,
                status=AxisStatus.CONFLITO,
                rule_code="TEMPORALITY_STALE_ISSUE_DATE_EXCEEDS_POLICY",
                justification=(
                    f"Documento(s) excedem a janela maxima de {max_spread_days} dias frente a referencia "
                    f"{reference_date.isoformat()}: {stale_ref}."
                ),
                fields_used=fields_used,
                contexts=contexts,
                items=items,
                limitations=limitations,
                engine_version=engine_version,
            )

    if len(valid_dates) >= 2:
        min_d = min(d for _, _, d in valid_dates)
        max_d = max(d for _, _, d in valid_dates)
        spread_days = (max_d - min_d).days
        if spread_days > max_spread_days:
            return _build_axis_result(
                axis=axis,
                status=AxisStatus.CONFLITO,
                rule_code="TEMPORALITY_ISSUE_DATE_SPREAD_EXCEEDED",
                justification=(
                    f"Diferenca entre datas de emissao ({min_d.isoformat()} a {max_d.isoformat()}, "
                    f"{spread_days} dias) excede o limite documental configurado de {max_spread_days} dias."
                ),
                fields_used=fields_used,
                contexts=contexts,
                items=items,
                limitations=limitations,
                engine_version=engine_version,
            )

    if has_invalid_ev:
        return _build_axis_result(
            axis=axis,
            status=AxisStatus.ABSTENCAO,
            rule_code="TEMPORALITY_INVALID_EVIDENCE",
            justification="Evidencia temporal invalida ou de versao incorreta impede avaliacao.",
            fields_used=fields_used,
            contexts=contexts,
            items=items,
            limitations=limitations,
            engine_version=engine_version,
        )

    if abstained_dates:
        return _build_axis_result(
            axis=axis,
            status=AxisStatus.ABSTENCAO,
            rule_code="TEMPORALITY_INVALID_ISSUE_DATE",
            justification="Data de emissao invalida, ambigua ou inequivocamente incompleta impede ordenacao temporal.",
            fields_used=fields_used,
            contexts=contexts,
            items=items,
            limitations=limitations,
            engine_version=engine_version,
        )

    if unreadable:
        for u in unreadable:
            items.append(
                _make_comparison_item(
                    ctx=u,
                    field_key="document_version",
                    field_item=None,
                    ev=None,
                    role_in_comparison="unreadable_document",
                    override_value=u.version.extraction_outcome or u.extraction_state,
                )
            )
        return _build_axis_result(
            axis=axis,
            status=AxisStatus.ABSTENCAO,
            rule_code="TEMPORALITY_UNREADABLE_SOURCE_DOCUMENT",
            justification="Documento ilegivel impede confirmacao temporal completa no caso.",
            fields_used=fields_used,
            contexts=contexts,
            items=items,
            limitations=limitations,
            engine_version=engine_version,
        )

    if pending or len(ready) < 2 or missing_dates_docs:
        rule = (
            "TEMPORALITY_EXTRACTION_PENDING"
            if pending
            else (
                "TEMPORALITY_AWAITING_COMPARABLE_DOCUMENTS"
                if len(ready) < 2
                else "TEMPORALITY_MISSING_ISSUE_DATE"
            )
        )
        return _build_axis_result(
            axis=axis,
            status=AxisStatus.PENDENTE,
            rule_code=rule,
            justification=(
                "Data de emissao ausente em ao menos um documento ou extracao pendente; "
                "data de upload nunca substitui data de emissao."
            ),
            fields_used=fields_used,
            contexts=contexts,
            items=items,
            limitations=limitations,
            engine_version=engine_version,
        )

    # Check if upload timestamp ordering diverges from issue_date ordering
    upload_sorted = sorted(
        valid_dates, key=lambda t: (_as_utc(t[0].version.created_at), t[0].doc.document_id)
    )
    issue_sorted = sorted(valid_dates, key=lambda t: (t[2], _as_utc(t[0].version.created_at), t[0].doc.document_id))
    for idx in range(len(upload_sorted) - 1):
        later_ctx, _, later_issue = upload_sorted[idx + 1]
        earlier_ctx, _, earlier_issue = upload_sorted[idx]
        if (
            (_as_utc(later_ctx.version.created_at) - _as_utc(earlier_ctx.version.created_at)).total_seconds() > 1.0
            and later_issue < earlier_issue
        ):
            limitations.append("UPLOAD_ORDER_DIFFERS_FROM_ISSUE_ORDER")
            break
    if [x[0].version.version_id for x in upload_sorted] != [x[0].version.version_id for x in issue_sorted]:
        limitations.append("DOCUMENTS_OUT_OF_UPLOAD_CHRONOLOGICAL_ORDER_SORTED_BY_ISSUE_DATE")

    distinct_dates = {d for _, _, d in valid_dates}
    if len(distinct_dates) == 1:
        rule_code = "TEMPORALITY_DATES_CONSISTENT"
        just = (
            f"Datas de emissao identicas ({next(iter(distinct_dates)).isoformat()}) e coerentes "
            f"com os uploads nos {len(ready)} documentos comparados."
        )
    else:
        min_d = min(distinct_dates)
        max_d = max(distinct_dates)
        spread = (max_d - min_d).days
        rule_code = "TEMPORALITY_DATES_WITHIN_WINDOW"
        just = (
            f"Datas de emissao distintas ({min_d.isoformat()} a {max_d.isoformat()}, janela de {spread} dias <= "
            f"{max_spread_days} dias) ordenadas deterministicamente por emissao, sem escolha clinica."
        )

    return _build_axis_result(
        axis=axis,
        status=AxisStatus.OK,
        rule_code=rule_code,
        justification=just,
        fields_used=fields_used,
        contexts=contexts,
        items=items,
        limitations=limitations,
        engine_version=engine_version,
    )


def evaluate_case_consistency(data: CaseConsistencyInput) -> CaseConsistencyResult:
    """Execute deterministic 4-axis comparison over a DocumentCase snapshot."""
    fingerprint = _compute_input_fingerprint(data)
    active_contexts, snapshot, extraction_run_ids = _prepare_contexts(data)
    requested_axes = set(data.evaluated_axes) if data.evaluated_axes is not None else set(AxisName)

    def _unevaluated_axis(ax: AxisName, fields_used: tuple[str, ...]) -> AxisEvaluationResult:
        return _build_axis_result(
            axis=ax,
            status=AxisStatus.NAO_AVALIADO,
            rule_code="AXIS_OUT_OF_EXECUTION_SCOPE",
            justification=(
                f"Eixo '{ax.value}' nao avaliado nesta execucao; "
                "eixo nao avaliado nunca e convertido em 'ok'."
            ),
            fields_used=fields_used,
            contexts=active_contexts,
            items=[],
            limitations=["AXIS_NOT_EVALUATED_CANNOT_BE_TREATED_AS_OK"],
            engine_version=data.engine_version,
        )

    axis_identidade = (
        _evaluate_identity_axis(active_contexts, engine_version=data.engine_version)
        if AxisName.IDENTIDADE in requested_axes
        else _unevaluated_axis(AxisName.IDENTIDADE, ("patient", "birth_date", "identifier"))
    )
    axis_procedimento = (
        _evaluate_procedure_axis(
            active_contexts,
            procedure_reference=data.procedure_reference,
            engine_version=data.engine_version,
        )
        if AxisName.PROCEDIMENTO_CODIGO in requested_axes
        else _unevaluated_axis(
            AxisName.PROCEDIMENTO_CODIGO, ("procedure", "procedure_code_system", "procedure_code")
        )
    )
    axis_lateralidade = (
        _evaluate_laterality_axis(
            active_contexts,
            declared_laterality=data.declared_laterality,
            engine_version=data.engine_version,
        )
        if AxisName.LATERALIDADE in requested_axes
        else _unevaluated_axis(AxisName.LATERALIDADE, ("laterality",))
    )
    axis_temporalidade = (
        _evaluate_temporality_axis(
            active_contexts,
            max_spread_days=data.max_issue_date_spread_days,
            reference_date=data.reference_date,
            engine_version=data.engine_version,
        )
        if AxisName.TEMPORALIDADE in requested_axes
        else _unevaluated_axis(
            AxisName.TEMPORALIDADE,
            ("issue_date", "document_version.version_number", "document_version.created_at"),
        )
    )

    axes: dict[AxisName, AxisEvaluationResult] = {
        AxisName.IDENTIDADE: axis_identidade,
        AxisName.PROCEDIMENTO_CODIGO: axis_procedimento,
        AxisName.LATERALIDADE: axis_lateralidade,
        AxisName.TEMPORALIDADE: axis_temporalidade,
    }
    axis_statuses = [axes[ax].status for ax in (
        AxisName.IDENTIDADE,
        AxisName.PROCEDIMENTO_CODIGO,
        AxisName.LATERALIDADE,
        AxisName.TEMPORALIDADE,
    )]

    # Evaluate human review coverage without inferring missing reviews or clinical approval
    pending_review_version_ids = [
        c.version.version_id for c in active_contexts if len(c.version.human_reviews) == 0
    ]
    human_review_completed = bool(active_contexts) and len(pending_review_version_ids) == 0
    quarantined_doc_ids = [c.doc.document_id for c in active_contexts if c.doc.quarantined]

    global_limitations: list[str] = [
        "ADMINISTRATIVE_CONSISTENCY_ONLY_NO_CLINICAL_DECISION",
        "ABSENCE_OF_CONFLICT_DOES_NOT_PROVE_ABSENCE_OF_DOCUMENT_ERRORS",
        "AUTOMATED_EXECUTION_DOES_NOT_SUBSTITUTE_HUMAN_REVIEW",
    ]
    for ax_res in axes.values():
        global_limitations.extend(ax_res.limitations)

    if not active_contexts:
        automated_outcome = "pending"
        readiness_state = CaseReadinessState.PENDENTE
        global_limitations.append("NO_ACTIVE_DOCUMENTS_IN_CASE")
    elif quarantined_doc_ids or AxisStatus.CONFLITO in axis_statuses:
        automated_outcome = "conflict_detected"
        readiness_state = CaseReadinessState.BLOQUEADO
    elif AxisStatus.ABSTENCAO in axis_statuses or AxisStatus.NAO_AVALIADO in axis_statuses:
        automated_outcome = "abstained"
        readiness_state = CaseReadinessState.ABSTENCAO
    elif AxisStatus.PENDENTE in axis_statuses:
        automated_outcome = "pending"
        readiness_state = CaseReadinessState.PENDENTE
    else:
        # All 4 axes are in {OK, NAO_APLICAVEL}. Never assign CONFERIDA without completed human review!
        has_na = AxisStatus.NAO_APLICAVEL in axis_statuses
        automated_outcome = "limited_scope" if has_na else "all_ok"
        if not human_review_completed:
            readiness_state = CaseReadinessState.PENDENTE
            global_limitations.append("AWAITING_HUMAN_ADMINISTRATIVE_REVIEW")
        elif has_na:
            readiness_state = CaseReadinessState.CONFERIDA_COM_ESCOPO_LIMITADO
        else:
            readiness_state = CaseReadinessState.CONFERIDA

    summary = {
        "automated_result": {
            "outcome": automated_outcome,
            "all_axes_ok": all(st == AxisStatus.OK for st in axis_statuses),
            "limited_scope": AxisStatus.NAO_APLICAVEL in axis_statuses,
            "axis_statuses": {ax.value: res.status.value for ax, res in axes.items()},
            "quarantined_document_ids": quarantined_doc_ids,
            "engine_name": data.engine_name,
            "engine_version": data.engine_version,
            "policy_version": data.policy_version,
        },
        "human_review_status": {
            "completed": human_review_completed,
            "human_review_required": True,
            "reviewed_versions_count": len(active_contexts) - len(pending_review_version_ids),
            "total_active_versions_count": len(active_contexts),
            "pending_review_version_ids": pending_review_version_ids,
        },
        "clinical_decision": {
            "out_of_scope": True,
            "clinical_approval": False,
            "administrative_only": True,
            "notice": _CLINICAL_OUT_OF_SCOPE_NOTICE,
        },
    }

    return CaseConsistencyResult(
        organization_id=data.organization_id,
        case_id=data.case_id,
        engine_name=data.engine_name,
        engine_version=data.engine_version,
        policy_version=data.policy_version,
        input_fingerprint_sha256=fingerprint,
        automated_axes_outcome=automated_outcome,
        readiness_state=readiness_state,
        human_review_completed=human_review_completed,
        human_review_required=True,
        compared_documents_count=len(active_contexts),
        compared_snapshot=tuple(snapshot),
        extraction_run_ids=tuple(extraction_run_ids),
        axes=axes,
        limitations=tuple(dict.fromkeys(global_limitations)),
        summary=summary,
        administrative_only=True,
        clinical_approval=False,
    )
