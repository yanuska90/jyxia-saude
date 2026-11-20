"""Pipeline interface contracts separating extraction, evidence, axes and future OCR.

Implemented as pure interfaces/contracts so Modalidade C processing workers can be
plugged in cleanly without copying legacy v2 code and without overclaiming OCR/LLM today.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Protocol

from app.core.constants import (
    AxisName,
    AxisStatus,
    CaseReadinessState,
    ExtractedFieldStatus,
)


@dataclass(frozen=True, slots=True)
class NormalizedBoundingBox:
    """Normalized page-relative box [x, y, w, h] in [0.0, 1.0]."""

    x: float
    y: float
    w: float
    h: float

    def __post_init__(self) -> None:
        if not (0.0 <= self.x <= 1.0 and 0.0 <= self.y <= 1.0):
            raise ValueError("Bounding box origin must be within [0.0, 1.0].")
        if not (0.0 < self.w <= 1.0 and 0.0 < self.h <= 1.0):
            raise ValueError("Bounding box dimensions must be in (0.0, 1.0].")


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


@dataclass(frozen=True, slots=True)
class ConsistencyEvaluationContract:
    readiness_state: CaseReadinessState
    policy_version: str
    axes: dict[AxisName, AxisStatus] = field(default_factory=dict)
    administrative_only: Literal[True] = True
    clinical_approval: Literal[False] = False


class TextExtractionPort(Protocol):
    """Contract for selectable-text PDF extraction with spatial coordinates."""

    def extract_lines(self, content: bytes, *, mime_type: str) -> list[ExtractedLineContract]:
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

    def extract_ocr_lines(self, content: bytes, *, mime_type: str) -> list[ExtractedLineContract]:
        ...


class UnimplementedOcrAdapter:
    """Explicit placeholder refusing OCR calls until audited Phase 3 onboarding."""

    def extract_ocr_lines(self, content: bytes, *, mime_type: str) -> list[ExtractedLineContract]:
        raise NotImplementedError(
            "OCR ingestion is not implemented in JYXIA 0.1.0; unreadable documents must abstain/quarantine."
        )
