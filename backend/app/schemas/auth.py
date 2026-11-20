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
