"""Validated HTTP response and request schemas for identity, session, and RBAC routes."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.core.constants import OrganizationRole


class UserOrganizationMembershipSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    organization_id: str
    organization_slug: str
    organization_name: str
    role: OrganizationRole
    permissions: list[str]
    is_active_organization: bool


class UserProfileResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    user_id: str
    email: str
    display_name: str
    active_organization_id: str | None
    mfa_verified_at: datetime
    acr: str | None
    amr: list[str]


class SessionStatusResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    authenticated: bool
    session_id: str
    user_id: str
    active_organization_id: str | None
    mfa_verified_at: datetime
    acr: str | None
    amr: list[str]
    idle_expires_at: datetime | None
    absolute_expires_at: datetime | None
    csrf_cookie_name: str
    csrf_header_name: str


class UserOrganizationsResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    user_id: str
    active_organization_id: str | None
    organizations: list[UserOrganizationMembershipSummary]


class SelectOrganizationRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    organization_id: str = Field(min_length=1, max_length=36)


class SelectOrganizationResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    active_organization_id: str
    organization_slug: str
    organization_name: str
    role: OrganizationRole
    permissions: list[str]


class LogoutResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    logged_out: bool
    end_session_url: str | None = None


class AccessContextResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    organization_id: str
    organization_slug: str
    organization_name: str
    user_id: str
    role: OrganizationRole
    permissions: list[str]
    mfa_verified_at: datetime
    administrative_only: bool = True
    clinical_approval: bool = False


class CaseSummaryResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    case_id: str
    organization_id: str
    case_code: str
    external_reference: str | None
    procedure_reference: str | None
    readiness_state: str
    administrative_only: bool
    clinical_approval: bool
    created_at: datetime


class OrganizationCasesResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    organization_id: str
    role: OrganizationRole
    cases: list[CaseSummaryResponse]


class MemberSummaryResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    membership_id: str
    user_id: str
    display_name: str
    email: str
    role: OrganizationRole
    status: str
    created_at: datetime


class OrganizationMembersResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    organization_id: str
    members: list[MemberSummaryResponse]


class AuditEventSummaryResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    sequence_number: int
    event_type: str
    actor_user_id: str | None
    target_entity_type: str
    target_entity_id: str
    payload_json: dict[str, Any]
    event_hash: str
    created_at: datetime


class SecurityAuditEventSummaryResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    sequence_number: int
    event_type: str
    outcome: str
    user_id: str | None
    organization_id: str | None
    reason_code: str
    event_hash: str
    created_at: datetime


class OrganizationAuditEventsResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    organization_id: str
    audit_events: list[AuditEventSummaryResponse]
    security_events: list[SecurityAuditEventSummaryResponse]


class DocumentVersionSummaryResponse(BaseModel):
    """Public metadata for a document version without exposing storage keys or filesystem paths."""

    model_config = ConfigDict(frozen=True)

    version_id: str
    document_id: str
    organization_id: str
    version_number: int
    sha256_hex: str
    mime_type: str
    byte_size: int
    page_count: int | None = None
    original_filename: str | None = None
    created_by_user_id: str | None = None
    is_current: bool
    created_at: datetime


class DocumentSummaryResponse(BaseModel):
    """Administrative summary of a case document and its current version."""

    model_config = ConfigDict(frozen=True)

    document_id: str
    organization_id: str
    case_id: str | None
    document_kind: str
    document_subfamily: str | None = None
    source_label: str
    external_reference: str | None = None
    description: str | None = None
    created_by_user_id: str | None = None
    quarantined: bool
    administrative_only: bool = True
    clinical_approval: bool = False
    created_at: datetime
    updated_at: datetime
    current_version: DocumentVersionSummaryResponse | None = None


class ProcessingRunSummaryResponse(BaseModel):
    """Sanitized processing execution state without exposing lease secrets or storage paths."""

    model_config = ConfigDict(frozen=True)

    processing_run_id: str
    organization_id: str
    document_version_id: str
    document_id: str | None = None
    case_id: str | None = None
    step_type: str
    status: str
    policy_version: str
    extractor_version: str
    attempt_count: int
    max_attempts: int
    available_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime
    updated_at: datetime
    last_error_code: str | None = None
    last_error_detail: str | None = None
    result_json: dict[str, Any] | None = None
    readable: bool = False
    readiness_state: str | None = None
    administrative_only: bool = True
    clinical_approval: bool = False


class CaseProcessingRunsListResponse(BaseModel):
    """Paginated list of processing runs belonging to an organization's document case."""

    model_config = ConfigDict(frozen=True)

    organization_id: str
    case_id: str
    total: int
    limit: int
    offset: int
    processing_runs: list[ProcessingRunSummaryResponse]


class DocumentIngestionResponse(BaseModel):
    """Response returned upon authenticated document upload and initial version registration."""

    model_config = ConfigDict(frozen=True)

    document_id: str
    organization_id: str
    case_id: str
    document_kind: str
    document_subfamily: str | None = None
    source_label: str
    external_reference: str | None = None
    description: str | None = None
    created_by_user_id: str | None = None
    quarantined: bool
    idempotent_replay: bool = False
    administrative_only: bool = True
    clinical_approval: bool = False
    created_at: datetime
    current_version: DocumentVersionSummaryResponse
    initial_processing_run: ProcessingRunSummaryResponse | None = None


class CaseDocumentsListResponse(BaseModel):
    """Paginated list of documents belonging to an organization's document case."""

    model_config = ConfigDict(frozen=True)

    organization_id: str
    case_id: str
    total: int
    limit: int
    offset: int
    documents: list[DocumentSummaryResponse]


class DocumentDetailResponse(BaseModel):
    """Full administrative metadata and version history for an organization document."""

    model_config = ConfigDict(frozen=True)

    document_id: str
    organization_id: str
    case_id: str | None
    document_kind: str
    document_subfamily: str | None = None
    source_label: str
    external_reference: str | None = None
    description: str | None = None
    created_by_user_id: str | None = None
    quarantined: bool
    quarantine_reason: str | None = None
    administrative_only: bool = True
    clinical_approval: bool = False
    created_at: datetime
    updated_at: datetime
    current_version: DocumentVersionSummaryResponse | None = None
    versions: list[DocumentVersionSummaryResponse]


class EvidenceReferenceSummaryResponse(BaseModel):
    """Sanitized spatial evidence reference anchored to page geometry and source run."""

    model_config = ConfigDict(frozen=True)

    evidence_reference_id: str
    organization_id: str
    extracted_field_id: str
    field_key: str
    document_id: str
    document_version_id: str
    source_sha256_hex: str
    processing_run_id: str
    extractor_version: str
    policy_version: str
    page_number: int
    bbox: list[float]
    bbox_x: float
    bbox_y: float
    bbox_w: float
    bbox_h: float
    quote_excerpt: str | None = None
    extraction_method: str
    created_at: datetime
    administrative_only: bool = True
    clinical_approval: bool = False


class ExtractedFieldItemResponse(BaseModel):
    """Canonical extracted field preserving raw value, conservative normalization and origins."""

    model_config = ConfigDict(frozen=True)

    extracted_field_id: str
    organization_id: str
    document_id: str
    document_version_id: str
    source_sha256_hex: str
    processing_run_id: str
    extractor_version: str
    policy_version: str
    field_key: str
    raw_value: str | None = None
    normalized_value: str | None = None
    status: str
    abstained: bool
    metadata_json: dict[str, Any] | None = None
    evidences: list[EvidenceReferenceSummaryResponse]
    created_at: datetime
    administrative_only: bool = True
    clinical_approval: bool = False


class ExtractedFieldsListResponse(BaseModel):
    """Collection of explicit extracted fields for a specific DocumentVersion."""

    model_config = ConfigDict(frozen=True)

    organization_id: str
    document_id: str
    document_version_id: str
    source_sha256_hex: str
    total: int
    latest_processing_run_id: str | None = None
    latest_extractor_version: str | None = None
    latest_outcome: str | None = None
    extracted_fields: list[ExtractedFieldItemResponse]
    administrative_only: bool = True
    clinical_approval: bool = False


class EvidenceReferencesListResponse(BaseModel):
    """Collection of spatial evidence references for a specific DocumentVersion."""

    model_config = ConfigDict(frozen=True)

    organization_id: str
    document_id: str
    document_version_id: str
    source_sha256_hex: str
    total: int
    latest_processing_run_id: str | None = None
    latest_extractor_version: str | None = None
    evidence_references: list[EvidenceReferenceSummaryResponse]
    administrative_only: bool = True
    clinical_approval: bool = False
