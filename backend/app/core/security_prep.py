"""Preparation contracts for OIDC + MFA authentication and RBAC/ABAC authorization.

NOTE: Live authentication and public clinical routes are intentionally NOT active in
version 0.1.0. Any attempt to authenticate a token here fails closed explicitly rather
than impersonating a synthetic or administrative user.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from app.core.constants import OrganizationRole


class AuthenticationNotConfiguredError(RuntimeError):
    """Raised whenever live token verification is requested before OIDC integration."""


class AuthorizationDeniedError(PermissionError):
    """Raised fail-closed when a principal lacks tenant or role authorization."""


class RbacPermission(StrEnum):
    CASE_READ = "case:read"
    CASE_WRITE = "case:write"
    DOCUMENT_UPLOAD = "document:upload"
    HUMAN_REVIEW_WRITE = "human_review:write"
    AUDIT_READ = "audit:read"
    ORG_MANAGE = "organization:manage"


ROLE_PERMISSIONS: dict[OrganizationRole, frozenset[RbacPermission]] = {
    OrganizationRole.ORG_ADMIN: frozenset(RbacPermission),
    OrganizationRole.CLINICAL_REVIEWER: frozenset(
        {
            RbacPermission.CASE_READ,
            RbacPermission.CASE_WRITE,
            RbacPermission.DOCUMENT_UPLOAD,
            RbacPermission.HUMAN_REVIEW_WRITE,
        }
    ),
    OrganizationRole.ADMIN_OPERATOR: frozenset(
        {
            RbacPermission.CASE_READ,
            RbacPermission.CASE_WRITE,
            RbacPermission.DOCUMENT_UPLOAD,
        }
    ),
    OrganizationRole.AUDITOR_READONLY: frozenset(
        {
            RbacPermission.CASE_READ,
            RbacPermission.AUDIT_READ,
        }
    ),
}


@dataclass(frozen=True, slots=True)
class OidcSecurityRequirements:
    """Target OIDC + MFA contract for Modalidade C evolution."""

    require_mfa_acr: bool = True
    allowed_algorithms: tuple[str, ...] = ("RS256", "ES256")
    require_verified_subject_binding: bool = True
    require_active_org_membership: bool = True


@dataclass(frozen=True, slots=True)
class AuthenticatedPrincipal:
    """Verified identity context bound strictly to a single organization membership."""

    user_id: str
    organization_id: str
    role: OrganizationRole
    mfa_verified: bool
    auth_method: str = "oidc_mfa"


def require_permission(
    principal: AuthenticatedPrincipal | None,
    permission: RbacPermission,
    *,
    target_organization_id: str,
) -> None:
    """Enforce fail-closed tenant and RBAC boundaries for privileged actions."""
    if principal is None:
        raise AuthorizationDeniedError("Unauthenticated principal cannot access tenant resources.")
    if principal.organization_id != target_organization_id:
        raise AuthorizationDeniedError(
            "Cross-organization access denied by tenant authorization boundary."
        )
    if permission in {
        RbacPermission.HUMAN_REVIEW_WRITE,
        RbacPermission.ORG_MANAGE,
    } and not principal.mfa_verified:
        raise AuthorizationDeniedError("MFA verification is required for review or admin actions.")
    allowed = ROLE_PERMISSIONS.get(principal.role, frozenset())
    if permission not in allowed:
        raise AuthorizationDeniedError(
            f"Role '{principal.role.value}' lacks required permission '{permission.value}'."
        )


class StubOidcAuthenticator:
    """Explicitly inactive OIDC verifier ensuring no fake authentication path exists."""

    requirements = OidcSecurityRequirements()

    def authenticate_bearer_token(self, token: str) -> AuthenticatedPrincipal:
        raise AuthenticationNotConfiguredError(
            "OIDC token verification is intentionally inactive in JYXIA backend 0.1.0."
        )
