"""Centralized institutional RBAC policy and multi-tenant principal model.

Strict separation: JYXIA permissions govern administrative document preparation, review
of extracted fields and audit visibility only — never clinical approval, surgical release,
diagnosis or prescribing decisions.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from app.core.constants import OrganizationRole


class AuthenticationRequiredError(PermissionError):
    """Raised when authentication is absent, expired, revoked or lacks valid session."""


class AuthorizationDeniedError(PermissionError):
    """Raised fail-closed when principal lacks tenant access, MFA verification or RBAC permission."""


class RbacPermission(StrEnum):
    ORGANIZATION_READ = "organization:read"
    ORGANIZATION_MANAGE = "organization:manage"
    ORG_MANAGE = "organization:manage"
    MEMBERSHIP_READ = "membership:read"
    MEMBERSHIP_MANAGE = "membership:manage"
    CASE_READ = "case:read"
    CASE_WRITE = "case:write"
    DOCUMENT_PREPARE = "document:prepare"
    DOCUMENT_UPLOAD = "document:prepare"
    FIELD_REVIEW = "field:review"
    HUMAN_REVIEW_WRITE = "field:review"
    AUDIT_READ = "audit:read"


ROLE_DESCRIPTIONS: dict[OrganizationRole, str] = {
    OrganizationRole.ORG_ADMIN: "Organization Admin — manages organization settings, memberships and audit review.",
    OrganizationRole.ADMIN_OPERATOR: "Document Operator — prepares administrative cases and documents without audit/admin control.",
    OrganizationRole.CLINICAL_REVIEWER: "Document Reviewer (compatibility enum 'clinical_reviewer') — reviews fields/evidences without clinical approval authority.",
    OrganizationRole.AUDITOR_READONLY: "Auditor Read Only — read-only inspection of organization access context, memberships, cases and audit events.",
    OrganizationRole.READ_ONLY: "Read Only — strictly read-only organization and administrative case metadata access.",
}

ROLE_PERMISSIONS: dict[OrganizationRole, frozenset[RbacPermission]] = {
    OrganizationRole.ORG_ADMIN: frozenset(
        {
            RbacPermission.ORGANIZATION_READ,
            RbacPermission.ORGANIZATION_MANAGE,
            RbacPermission.MEMBERSHIP_READ,
            RbacPermission.MEMBERSHIP_MANAGE,
            RbacPermission.CASE_READ,
            RbacPermission.CASE_WRITE,
            RbacPermission.DOCUMENT_PREPARE,
            RbacPermission.FIELD_REVIEW,
            RbacPermission.AUDIT_READ,
        }
    ),
    OrganizationRole.ADMIN_OPERATOR: frozenset(
        {
            RbacPermission.ORGANIZATION_READ,
            RbacPermission.MEMBERSHIP_READ,
            RbacPermission.CASE_READ,
            RbacPermission.CASE_WRITE,
            RbacPermission.DOCUMENT_PREPARE,
        }
    ),
    OrganizationRole.CLINICAL_REVIEWER: frozenset(
        {
            RbacPermission.ORGANIZATION_READ,
            RbacPermission.CASE_READ,
            RbacPermission.CASE_WRITE,
            RbacPermission.FIELD_REVIEW,
        }
    ),
    OrganizationRole.AUDITOR_READONLY: frozenset(
        {
            RbacPermission.ORGANIZATION_READ,
            RbacPermission.MEMBERSHIP_READ,
            RbacPermission.CASE_READ,
            RbacPermission.AUDIT_READ,
        }
    ),
    OrganizationRole.READ_ONLY: frozenset(
        {
            RbacPermission.ORGANIZATION_READ,
            RbacPermission.CASE_READ,
        }
    ),
}


@dataclass(frozen=True, slots=True)
class AuthenticatedSessionPrincipal:
    """Verified server-side authenticated session user (before or alongside tenant resolution)."""

    session_id: str
    user_id: str
    external_identity_id: str
    issuer: str
    subject: str
    email: str
    display_name: str
    mfa_verified: bool
    mfa_verified_at: datetime
    auth_time: datetime
    acr: str | None
    amr: tuple[str, ...]
    selected_organization_id: str | None = None
    idle_expires_at: datetime | None = None
    absolute_expires_at: datetime | None = None
    csrf_token_hash: str | None = None


@dataclass(frozen=True, slots=True)
class AuthorizedTenantPrincipal:
    """Principal proven to hold an active membership and RBAC role inside target organization."""

    session: AuthenticatedSessionPrincipal
    organization_id: str
    membership_id: str
    role: OrganizationRole
    permissions: frozenset[RbacPermission]

    @property
    def user_id(self) -> str:
        return self.session.user_id

    @property
    def mfa_verified(self) -> bool:
        return self.session.mfa_verified


def permissions_for_role(role: OrganizationRole) -> frozenset[RbacPermission]:
    return ROLE_PERMISSIONS.get(role, frozenset())


def require_tenant_permission(
    principal: AuthorizedTenantPrincipal | None,
    permission: RbacPermission,
    *,
    target_organization_id: str,
) -> None:
    """Enforce fail-closed session, MFA, tenant scope and RBAC policy."""
    if principal is None:
        raise AuthenticationRequiredError("Authenticated tenant session is required.")
    if principal.organization_id != target_organization_id:
        raise AuthorizationDeniedError(
            "Cross-organization access denied by tenant authorization boundary."
        )
    if not principal.mfa_verified:
        raise AuthorizationDeniedError("Verified MFA authentication is required.")
    if permission not in principal.permissions:
        raise AuthorizationDeniedError(
            f"Role '{principal.role.value}' lacks required permission '{permission.value}'."
        )
