"""RBAC-protected and tenant-isolated institutional organization endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session

from app.api.dependencies import get_db_session, require_org_permission
from app.core.constants import OrganizationRole
from app.core.rbac import RbacPermission, permissions_for_role
from app.repositories.identity import SecurityAuditRepository
from app.repositories.institutional import (
    AuditEventRepository,
    CaseAndDocumentRepository,
    OrganizationRepository,
)
from app.schemas.auth import (
    AccessContextResponse,
    AuditEventSummaryResponse,
    CaseSummaryResponse,
    MemberSummaryResponse,
    OrganizationAuditEventsResponse,
    OrganizationCasesResponse,
    OrganizationMembersResponse,
    SecurityAuditEventSummaryResponse,
)
from app.schemas.tenant import TenantContext
from app.services.auth_service import AuthorizedMembershipContext

router = APIRouter(prefix="/organizations", tags=["organizations"])

_NO_STORE_HEADERS = {
    "Cache-Control": "no-store, no-cache, must-revalidate",
    "Pragma": "no-cache",
}


def _set_no_store(response: Response) -> None:
    for key, val in _NO_STORE_HEADERS.items():
        response.headers[key] = val


def _to_tenant_ctx(auth_ctx: AuthorizedMembershipContext) -> TenantContext:
    return TenantContext(
        organization_id=auth_ctx.principal.organization_id,
        actor_user_id=auth_ctx.principal.user_id,
        session_token_hash=auth_ctx.principal.session.session_token_hash,
        source="authenticated_request",
    )


@router.get("/{organization_id}/access-context", response_model=AccessContextResponse)
def get_organization_access_context(
    response: Response,
    auth_ctx: Annotated[
        AuthorizedMembershipContext,
        Depends(require_org_permission(RbacPermission.ORGANIZATION_READ)),
    ],
) -> AccessContextResponse:
    """Return server-verified multi-tenant RBAC access context for the caller."""
    _set_no_store(response)
    role = auth_ctx.principal.role
    return AccessContextResponse(
        organization_id=auth_ctx.organization.id,
        organization_slug=auth_ctx.organization.slug,
        organization_name=auth_ctx.organization.name,
        user_id=auth_ctx.principal.user_id,
        role=role,
        permissions=sorted(perm.value for perm in permissions_for_role(role)),
        mfa_verified_at=auth_ctx.principal.session.mfa_verified_at,
        administrative_only=True,
        clinical_approval=False,
    )


@router.get("/{organization_id}/cases", response_model=OrganizationCasesResponse)
def list_organization_cases(
    response: Response,
    session: Annotated[Session, Depends(get_db_session)],
    auth_ctx: Annotated[
        AuthorizedMembershipContext,
        Depends(require_org_permission(RbacPermission.CASE_READ)),
    ],
) -> OrganizationCasesResponse:
    """List tenant-scoped administrative cases for an authorized organization member."""
    _set_no_store(response)
    ctx = _to_tenant_ctx(auth_ctx)
    cases = CaseAndDocumentRepository.list_cases(session, ctx)
    return OrganizationCasesResponse(
        organization_id=auth_ctx.organization.id,
        role=auth_ctx.principal.role,
        cases=[
            CaseSummaryResponse(
                case_id=c.id,
                organization_id=c.organization_id,
                case_code=c.case_code,
                external_reference=c.external_reference,
                procedure_reference=c.procedure_reference,
                readiness_state=c.readiness_state,
                administrative_only=c.administrative_only,
                clinical_approval=c.clinical_approval,
                created_at=c.created_at,
            )
            for c in cases
        ],
    )


@router.get("/{organization_id}/members", response_model=OrganizationMembersResponse)
def list_organization_members(
    response: Response,
    session: Annotated[Session, Depends(get_db_session)],
    auth_ctx: Annotated[
        AuthorizedMembershipContext,
        Depends(require_org_permission(RbacPermission.MEMBERSHIP_READ)),
    ],
) -> OrganizationMembersResponse:
    """List memberships of the active organization (RBAC-restricted to authorized roles)."""
    _set_no_store(response)
    ctx = _to_tenant_ctx(auth_ctx)
    rows = OrganizationRepository.list_memberships_with_users(session, ctx)
    return OrganizationMembersResponse(
        organization_id=auth_ctx.organization.id,
        members=[
            MemberSummaryResponse(
                membership_id=m.id,
                user_id=u.id,
                display_name=u.display_name,
                email=u.email,
                role=OrganizationRole(m.role),
                status=m.status,
                created_at=m.created_at,
            )
            for m, u in rows
        ],
    )


@router.get("/{organization_id}/audit-events", response_model=OrganizationAuditEventsResponse)
def list_organization_audit_events(
    response: Response,
    session: Annotated[Session, Depends(get_db_session)],
    auth_ctx: Annotated[
        AuthorizedMembershipContext,
        Depends(require_org_permission(RbacPermission.AUDIT_READ)),
    ],
) -> OrganizationAuditEventsResponse:
    """List tenant-scoped immutable audit ledger and org security events (org_admin / auditor)."""
    _set_no_store(response)
    ctx = _to_tenant_ctx(auth_ctx)
    audit_rows = AuditEventRepository.list_events(session, ctx)
    sec_rows = SecurityAuditRepository.list_org_events(session, ctx)
    return OrganizationAuditEventsResponse(
        organization_id=auth_ctx.organization.id,
        audit_events=[
            AuditEventSummaryResponse(
                id=ev.id,
                sequence_number=ev.sequence_number,
                event_type=ev.event_type,
                actor_user_id=ev.actor_user_id,
                target_entity_type=ev.target_entity_type,
                target_entity_id=ev.target_entity_id,
                payload_json=ev.payload_json,
                event_hash=ev.event_hash,
                created_at=ev.created_at,
            )
            for ev in audit_rows
        ],
        security_events=[
            SecurityAuditEventSummaryResponse(
                id=ev.id,
                sequence_number=ev.sequence_number,
                event_type=ev.event_type,
                outcome=ev.outcome,
                user_id=ev.user_id,
                organization_id=ev.organization_id,
                reason_code=ev.reason_code,
                event_hash=ev.event_hash,
                created_at=ev.created_at,
            )
            for ev in sec_rows
        ],
    )
