"""Validated internal domain schemas and mandatory TenantContext boundary."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.constants import (
    CaseReadinessState,
    DocumentKind,
    ExtractedFieldStatus,
    HumanReviewAction,
    OrganizationRole,
    ProcessingStatus,
    StorageDriver,
)


def validate_safe_original_filename(filename: str | None) -> str | None:
    """Validate optional descriptive basename without path traversal or control chars."""
    if filename is None:
        return None
    cleaned = filename.strip()
    if not cleaned:
        return None
    if (
        len(cleaned) > 255
        or "/" in cleaned
        or "\\" in cleaned
        or ".." in cleaned
        or "\x00" in cleaned
        or any(ord(ch) < 32 for ch in cleaned)
    ):
        raise ValueError("Invalid original_filename metadata.")
    return cleaned


class TenantContext(BaseModel):
    """Explicit organization context required by all tenant-scoped repositories and services."""

    model_config = ConfigDict(frozen=True)

    organization_id: str = Field(min_length=1, max_length=36)
    actor_user_id: str | None = Field(default=None, min_length=1, max_length=36)
    source: Literal["internal_service", "test", "cli"] = "internal_service"


class OrganizationCreateInput(BaseModel):
    model_config = ConfigDict(frozen=True)

    slug: str = Field(min_length=2, max_length=80, pattern=r"^[a-z0-9][a-z0-9\-]{1,79}$")
    name: str = Field(min_length=2, max_length=200)


class UserCreateInput(BaseModel):
    model_config = ConfigDict(frozen=True)

    email: str = Field(min_length=5, max_length=255)
    display_name: str = Field(min_length=1, max_length=200)
    external_subject: str | None = Field(default=None, min_length=1, max_length=255)
    mfa_enrolled: bool = False

    @field_validator("email")
    @classmethod
    def _normalize_email(cls, value: str) -> str:
        normalized = value.strip().lower()
        if "@" not in normalized or "." not in normalized.split("@")[-1]:
            raise ValueError("Invalid email format.")
        return normalized


class MembershipAssignInput(BaseModel):
    model_config = ConfigDict(frozen=True)

    user_id: str = Field(min_length=1, max_length=36)
    role: OrganizationRole


class DocumentCaseCreateInput(BaseModel):
    model_config = ConfigDict(frozen=True)

    case_code: str = Field(min_length=2, max_length=100)
    external_reference: str | None = Field(default=None, min_length=2, max_length=128)
    procedure_reference: str | None = Field(default=None, max_length=200)
    declared_laterality: str | None = Field(default=None, max_length=32)
    readiness_state: CaseReadinessState = CaseReadinessState.PENDENTE


class DocumentCreateInput(BaseModel):
    model_config = ConfigDict(frozen=True)

    case_id: str | None = Field(default=None, min_length=1, max_length=36)
    document_kind: DocumentKind = DocumentKind.DESCONHECIDO
    document_subfamily: str | None = Field(default=None, max_length=80)
    source_label: str = Field(min_length=1, max_length=160)
    quarantined: bool = False
    quarantine_reason: str | None = Field(default=None, max_length=500)


class DocumentVersionCreateInput(BaseModel):
    model_config = ConfigDict(frozen=True)

    document_id: str = Field(min_length=1, max_length=36)
    version_number: int = Field(default=1, ge=1)
    sha256_hex: str = Field(min_length=64, max_length=64, pattern=r"^[a-f0-9]{64}$")
    mime_type: Literal["application/pdf", "image/png"]
    byte_size: int = Field(gt=0)
    page_count: int | None = Field(default=None, ge=1)
    original_filename: str | None = None
    storage_driver: StorageDriver = StorageDriver.LOCAL_CONTROLLED_SYNTHETIC
    storage_key: str = Field(min_length=8, max_length=255)

    @field_validator("original_filename")
    @classmethod
    def _validate_filename(cls, value: str | None) -> str | None:
        return validate_safe_original_filename(value)


class ProcessingRunCreateInput(BaseModel):
    model_config = ConfigDict(frozen=True)

    document_version_id: str = Field(min_length=1, max_length=36)
    policy_version: str = Field(min_length=1, max_length=64)
    extractor_version: str = Field(min_length=1, max_length=64)
    idempotency_key: str | None = Field(default=None, min_length=4, max_length=128)
    status: ProcessingStatus = ProcessingStatus.COMPLETED
    readable: bool = True
    readiness_state: CaseReadinessState | None = None
    axes_summary: dict[str, Any] | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None

    @model_validator(mode="after")
    def _validate_timestamps(self) -> ProcessingRunCreateInput:
        if self.started_at is not None and self.finished_at is not None:
            if self.finished_at < self.started_at:
                raise ValueError("finished_at cannot precede started_at.")
        return self


class ExtractedFieldCreateInput(BaseModel):
    model_config = ConfigDict(frozen=True)

    processing_run_id: str = Field(min_length=1, max_length=36)
    document_version_id: str = Field(min_length=1, max_length=36)
    field_key: str = Field(min_length=1, max_length=64)
    raw_value: str | None = None
    normalized_value: str | None = None
    status: ExtractedFieldStatus
    abstained: bool = False
    metadata_json: dict[str, Any] | None = None

    @model_validator(mode="after")
    def _validate_abstention_coherence(self) -> ExtractedFieldCreateInput:
        if self.status == ExtractedFieldStatus.ABSTAINED and not self.abstained:
            raise ValueError("abstained must be True when status is 'abstained'.")
        return self


class EvidenceReferenceCreateInput(BaseModel):
    model_config = ConfigDict(frozen=True)

    extracted_field_id: str = Field(min_length=1, max_length=36)
    document_version_id: str = Field(min_length=1, max_length=36)
    page_number: int = Field(ge=1)
    bbox_x: float = Field(ge=0.0, le=1.0)
    bbox_y: float = Field(ge=0.0, le=1.0)
    bbox_w: float = Field(gt=0.0, le=1.0)
    bbox_h: float = Field(gt=0.0, le=1.0)
    quote_excerpt: str | None = Field(default=None, max_length=500)
    extraction_method: str = Field(default="pdf_text_geometry", min_length=1, max_length=64)

    @model_validator(mode="after")
    def _validate_page_bounds(self) -> EvidenceReferenceCreateInput:
        if self.bbox_x + self.bbox_w > 1.00001 or self.bbox_y + self.bbox_h > 1.00001:
            raise ValueError("Normalized bounding box exceeds page limits [0.0, 1.0].")
        return self


class HumanReviewCreateInput(BaseModel):
    model_config = ConfigDict(frozen=True)

    document_version_id: str = Field(min_length=1, max_length=36)
    reviewer_user_id: str = Field(min_length=1, max_length=36)
    action_type: HumanReviewAction
    field_key: str | None = Field(default=None, max_length=64)
    original_value: str | None = None
    revised_value: str | None = None
    justification: str = Field(min_length=5, max_length=2000)
    evidence_reference_id: str | None = Field(default=None, min_length=1, max_length=36)
    policy_version: str = Field(min_length=1, max_length=64)
