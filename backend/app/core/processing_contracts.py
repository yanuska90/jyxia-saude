"""Pipeline interface contracts separating extraction, evidence, axes, idempotency and OCR.

Pure domain interfaces/contracts decoupling future processing workers from the static
v3.2.0 demonstration and keeping legacy/v2 completely excluded.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Literal, Protocol

from app.core.constants import (
    AxisName,
    AxisStatus,
    CaseReadinessState,
    ExtractedFieldStatus,
)


class ExtractionOutcomeStatus(StrEnum):
    EXECUTED = "executed"
    FAILED = "failed"
    INCOMPLETE = "incomplete"
    UNREADABLE = "unreadable"
    OCR_UNAVAILABLE = "ocr_unavailable"


@dataclass(frozen=True, slots=True)
class NormalizedBoundingBox:
    """Normalized top-left page-relative box [x, y, w, h] within [0.0, 1.0]."""

    x: float
    y: float
    w: float
    h: float

    def __post_init__(self) -> None:
        if not (0.0 <= self.x <= 1.0 and 0.0 <= self.y <= 1.0):
            raise ValueError("Bounding box origin must be within [0.0, 1.0].")
        if not (0.0 < self.w <= 1.0 and 0.0 < self.h <= 1.0):
            raise ValueError("Bounding box dimensions must be in (0.0, 1.0].")
        if self.x + self.w > 1.00001 or self.y + self.h > 1.00001:
            raise ValueError("Bounding box extends beyond normalized page limits [0.0, 1.0].")


@dataclass(frozen=True, slots=True)
class ExtractedLineContract:
    page_number: int
    text: str
    bbox: NormalizedBoundingBox


@dataclass(frozen=True, slots=True)
class FieldCandidateContract:
    field_key: str
    status: ExtractedFieldStatus
    abstained: bool
    raw_value: str | None
    normalized_value: str | None
    evidence_page: int | None = None
    evidence_bbox: NormalizedBoundingBox | None = None
    extraction_method: str = "deterministic"
    human_review_required: bool = False
    human_reviewed: Literal[False] = False


@dataclass(frozen=True, slots=True)
class ExtractionBatchResultContract:
    outcome: ExtractionOutcomeStatus
    extractor_name: str
    extractor_version: str
    readable: bool
    human_review_required: bool
    lines: list[ExtractedLineContract] = field(default_factory=list)
    fields: list[FieldCandidateContract] = field(default_factory=list)
    failure_code: str | None = None


@dataclass(frozen=True, slots=True)
class ConsistencyEvaluationContract:
    readiness_state: CaseReadinessState
    policy_version: str
    axes: dict[AxisName, AxisStatus] = field(default_factory=dict)
    human_review_required: bool = True
    administrative_only: Literal[True] = True
    clinical_approval: Literal[False] = False


@dataclass(frozen=True, slots=True)
class ReprocessingPolicyContract:
    preserve_prior_runs: Literal[True] = True
    preserve_human_reviews: Literal[True] = True
    require_new_run_record: Literal[True] = True


def compute_processing_idempotency_key(
    *,
    organization_id: str,
    document_version_id: str,
    sha256_hex: str,
    extractor_version: str,
    policy_version: str,
) -> str:
    """Compute deterministic idempotency key scoping document version, content hash and versions."""
    payload = "|".join(
        (organization_id, document_version_id, sha256_hex, extractor_version, policy_version)
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class TextExtractionPort(Protocol):
    """Contract for selectable-text PDF extraction with spatial coordinates."""

    def extract(self, content: bytes, *, mime_type: str) -> ExtractionBatchResultContract:
        ...


class AxisEvaluationPort(Protocol):
    """Contract for deterministic administrative consistency evaluation."""

    def evaluate(
        self,
        *,
        fields: list[FieldCandidateContract],
        policy_version: str,
    ) -> ConsistencyEvaluationContract:
        ...


class OcrPipelinePort(Protocol):
    """Contract reserved for future audited OCR after benchmark/field validation."""

    def extract_ocr(self, content: bytes, *, mime_type: str) -> ExtractionBatchResultContract:
        ...


class UnimplementedOcrAdapter:
    """Explicit placeholder refusing OCR calls until audited Phase 3 onboarding."""

    def extract_ocr(self, content: bytes, *, mime_type: str) -> ExtractionBatchResultContract:
        raise NotImplementedError(
            "OCR ingestion is not implemented in JYXIA 0.1.0; unreadable documents must abstain/quarantine."
        )
