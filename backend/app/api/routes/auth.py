"""Institutional OIDC BFF login, callback, session, logout, and self-context endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Cookie, Depends, Query, Response
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session, sessionmaker

from app.api.dependencies import (
    get_correlation_id,
    get_current_session_principal,
    get_db_session,
    get_oidc_adapter,
    get_session_factory,
    get_settings,
    require_csrf_protection,
)
from app.core.config import Settings
from app.core.constants import (
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    OIDC_TX_COOKIE_NAME,
    SESSION_COOKIE_NAME,
    OrganizationRole,
)
from app.core.oidc import OidcProviderAdapter
from app.core.rbac import AuthenticatedSessionPrincipal, permissions_for_role
from app.repositories.identity import IdentityAndSessionRepository
from app.schemas.auth import (
    LogoutResponse,
    SelectOrganizationRequest,
    SelectOrganizationResponse,
    SessionStatusResponse,
    UserOrganizationMembershipSummary,
    UserOrganizationsResponse,
    UserProfileResponse,
)
from app.services.auth_service import (
    complete_oidc_callback,
    logout_session,
    select_active_organization,
    start_oidc_login,
)

router = APIRouter(tags=["identity-and-sessions"])

_NO_STORE_HEADERS = {
    "Cache-Control": "no-store, no-cache, must-revalidate",
    "Pragma": "no-cache",
}


def _effective_cookie_secure(settings: Settings) -> bool:
    return bool(settings.session_cookie_secure or settings.env == "production")


@router.get("/auth/login")
def auth_login(
    session_factory: Annotated[sessionmaker[Session], Depends(get_session_factory)],
    settings: Annotated[Settings, Depends(get_settings)],
    oidc_adapter: Annotated[OidcProviderAdapter, Depends(get_oidc_adapter)],
    correlation_id: Annotated[str, Depends(get_correlation_id)],
    next_path: Annotated[str | None, Query(alias="next")] = None,
) -> RedirectResponse:
    """Start Authorization Code + PKCE S256 login flow with institutional OIDC provider."""
    initiation = start_oidc_login(
        session_factory,
        settings=settings,
        oidc_adapter=oidc_adapter,
        next_path=next_path,
        correlation_id=correlation_id,
    )
    response = RedirectResponse(
        url=initiation.authorization_url,
        status_code=302,
        headers=_NO_STORE_HEADERS,
    )
    response.set_cookie(
        key=OIDC_TX_COOKIE_NAME,
        value=initiation.tx_cookie_value,
        max_age=600,
        path="/api/v1/auth",
        httponly=True,
        secure=_effective_cookie_secure(settings),
        samesite="lax",
    )
    return response


@router.get("/auth/callback")
def auth_callback(
    session_factory: Annotated[sessionmaker[Session], Depends(get_session_factory)],
    settings: Annotated[Settings, Depends(get_settings)],
    oidc_adapter: Annotated[OidcProviderAdapter, Depends(get_oidc_adapter)],
    correlation_id: Annotated[str, Depends(get_correlation_id)],
    code: Annotated[str | None, Query()] = None,
    state: Annotated[str | None, Query()] = None,
    error: Annotated[str | None, Query()] = None,
    tx_cookie: Annotated[str | None, Cookie(alias=OIDC_TX_COOKIE_NAME)] = None,
) -> RedirectResponse:
    """Handle OIDC authorization callback, enforce MFA, bind (iss, sub), and issue cookie session."""
    result = complete_oidc_callback(
        session_factory,
        settings=settings,
        oidc_adapter=oidc_adapter,
        code=code,
        state=state,
        tx_cookie_value=tx_cookie,
        idp_error=error,
        correlation_id=correlation_id,
    )
    secure = _effective_cookie_secure(settings)
    response = RedirectResponse(
        url=result.redirect_path,
        status_code=302,
        headers=_NO_STORE_HEADERS,
    )
    response.delete_cookie(key=OIDC_TX_COOKIE_NAME, path="/api/v1/auth")
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=result.session_token,
        max_age=settings.session_absolute_timeout_seconds,
        path="/",
        httponly=True,
        secure=secure,
        samesite="lax",
    )
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=result.csrf_token,
        max_age=settings.session_absolute_timeout_seconds,
        path="/",
        httponly=False,
        secure=secure,
        samesite="lax",
    )
    return response


@router.post("/auth/logout", response_model=LogoutResponse)
def auth_logout(
    response: Response,
    session: Annotated[Session, Depends(get_db_session)],
    principal: Annotated[AuthenticatedSessionPrincipal, Depends(require_csrf_protection)],
    oidc_adapter: Annotated[OidcProviderAdapter, Depends(get_oidc_adapter)],
    correlation_id: Annotated[str, Depends(get_correlation_id)],
) -> JSONResponse:
    """Revoke server-side session and clear HttpOnly session + CSRF cookies."""
    end_session_url = logout_session(
        session,
        principal=principal,
        oidc_adapter=oidc_adapter,
        correlation_id=correlation_id,
    )
    payload = LogoutResponse(logged_out=True, end_session_url=end_session_url)
    json_resp = JSONResponse(content=payload.model_dump(mode="json"), headers=_NO_STORE_HEADERS)
    json_resp.delete_cookie(key=SESSION_COOKIE_NAME, path="/")
    json_resp.delete_cookie(key=CSRF_COOKIE_NAME, path="/")
    json_resp.delete_cookie(key=OIDC_TX_COOKIE_NAME, path="/api/v1/auth")
    return json_resp


@router.get("/auth/session", response_model=SessionStatusResponse)
def auth_session_status(
    response: Response,
    principal: Annotated[AuthenticatedSessionPrincipal, Depends(get_current_session_principal)],
) -> SessionStatusResponse:
    """Return authenticated server-side session metadata without tokens or secrets."""
    for key, val in _NO_STORE_HEADERS.items():
        response.headers[key] = val
    return SessionStatusResponse(
        authenticated=True,
        session_id=principal.session_id,
        user_id=principal.user_id,
        active_organization_id=principal.selected_organization_id,
        mfa_verified_at=principal.mfa_verified_at,
        acr=principal.acr,
        amr=list(principal.amr),
        idle_expires_at=principal.idle_expires_at,
        absolute_expires_at=principal.absolute_expires_at,
        csrf_cookie_name=CSRF_COOKIE_NAME,
        csrf_header_name=CSRF_HEADER_NAME,
    )


@router.post("/auth/select-organization", response_model=SelectOrganizationResponse)
def auth_select_organization(
    body: SelectOrganizationRequest,
    response: Response,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    principal: Annotated[AuthenticatedSessionPrincipal, Depends(require_csrf_protection)],
    correlation_id: Annotated[str, Depends(get_correlation_id)],
) -> SelectOrganizationResponse:
    """Switch session's active organization and rotate session/CSRF cookies upon verified DB membership."""
    for key, val in _NO_STORE_HEADERS.items():
        response.headers[key] = val
    selection = select_active_organization(
        session,
        principal=principal,
        organization_id=body.organization_id,
        settings=settings,
        correlation_id=correlation_id,
    )
    secure = _effective_cookie_secure(settings)
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=selection.session_token,
        max_age=settings.session_absolute_timeout_seconds,
        path="/",
        httponly=True,
        secure=secure,
        samesite="lax",
    )
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=selection.csrf_token,
        max_age=settings.session_absolute_timeout_seconds,
        path="/",
        httponly=False,
        secure=secure,
        samesite="lax",
    )
    return SelectOrganizationResponse(
        active_organization_id=selection.organization.id,
        organization_slug=selection.organization.slug,
        organization_name=selection.organization.name,
        role=selection.role,
        permissions=selection.permissions,
    )


@router.get("/me", response_model=UserProfileResponse)
def get_me(
    response: Response,
    principal: Annotated[AuthenticatedSessionPrincipal, Depends(get_current_session_principal)],
) -> UserProfileResponse:
    """Return authenticated user profile and MFA assurance metadata."""
    for key, val in _NO_STORE_HEADERS.items():
        response.headers[key] = val
    return UserProfileResponse(
        user_id=principal.user_id,
        email=principal.email,
        display_name=principal.display_name,
        active_organization_id=principal.selected_organization_id,
        mfa_verified_at=principal.mfa_verified_at,
        acr=principal.acr,
        amr=list(principal.amr),
    )


@router.get("/me/organizations", response_model=UserOrganizationsResponse)
def get_my_organizations(
    response: Response,
    session: Annotated[Session, Depends(get_db_session)],
    principal: Annotated[AuthenticatedSessionPrincipal, Depends(get_current_session_principal)],
) -> UserOrganizationsResponse:
    """List organizations where the authenticated user currently holds an active membership."""
    for key, val in _NO_STORE_HEADERS.items():
        response.headers[key] = val
    rows = IdentityAndSessionRepository.list_user_active_memberships(
        session, user_id=principal.user_id
    )
    summaries: list[UserOrganizationMembershipSummary] = []
    for membership, org in rows:
        role = OrganizationRole(membership.role)
        summaries.append(
            UserOrganizationMembershipSummary(
                organization_id=org.id,
                organization_slug=org.slug,
                organization_name=org.name,
                role=role,
                permissions=sorted(perm.value for perm in permissions_for_role(role)),
                is_active_organization=(org.id == principal.selected_organization_id),
            )
        )
    return UserOrganizationsResponse(
        user_id=principal.user_id,
        active_organization_id=principal.selected_organization_id,
        organizations=summaries,
    )
