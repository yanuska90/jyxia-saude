"""FastAPI dependency injection for DB sessions, OIDC adapter, session auth, CSRF, and RBAC."""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterator
from typing import Annotated

from fastapi import Cookie, Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.core.constants import CSRF_COOKIE_NAME, CSRF_HEADER_NAME, SESSION_COOKIE_NAME
from app.core.oidc import OidcProviderAdapter
from app.core.rbac import (
    AuthenticatedSessionPrincipal,
    AuthenticationRequiredError,
    RbacPermission,
)
from app.services.auth_service import (
    AuthorizedMembershipContext,
    authenticate_session_cookie,
    resolve_authorized_tenant_principal,
    verify_csrf_and_origin,
)
from app.services.storage import DocumentStoragePort


def get_settings(request: Request) -> Settings:
    settings: Settings | None = getattr(request.app.state, "settings", None)
    if settings is None:
        raise HTTPException(status_code=503, detail="Backend settings unavailable.")
    return settings


def get_session_factory(request: Request) -> sessionmaker[Session]:
    factory: sessionmaker[Session] | None = getattr(request.app.state, "session_factory", None)
    if factory is None:
        raise HTTPException(status_code=503, detail="Institutional database is not configured.")
    return factory


def get_db_session(
    factory: Annotated[sessionmaker[Session], Depends(get_session_factory)],
) -> Iterator[Session]:
    session = factory()
    try:
        yield session
    except Exception:
        session.rollback()
        raise
    finally:
        session.rollback()
        session.close()


def get_oidc_adapter(request: Request) -> OidcProviderAdapter:
    adapter: OidcProviderAdapter | None = getattr(request.app.state, "oidc_adapter", None)
    if adapter is None:
        raise HTTPException(status_code=503, detail="OIDC adapter is unavailable.")
    return adapter


def get_document_storage(request: Request) -> DocumentStoragePort:
    storage: DocumentStoragePort | None = getattr(request.app.state, "storage", None)
    if storage is None or not storage.enabled:
        raise HTTPException(
            status_code=503,
            detail="Controlled synthetic document storage is unavailable in this environment.",
        )
    return storage


def get_correlation_id(
    x_request_id: Annotated[str | None, Header(alias="X-Request-ID")] = None,
) -> str:
    if x_request_id:
        cleaned = x_request_id.strip()
        if cleaned and len(cleaned) <= 64 and all(ch.isprintable() for ch in cleaned):
            return cleaned
    return str(uuid.uuid4())


def get_current_session_principal(
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    correlation_id: Annotated[str, Depends(get_correlation_id)],
    raw_session_cookie: Annotated[str | None, Cookie(alias=SESSION_COOKIE_NAME)] = None,
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
) -> AuthenticatedSessionPrincipal:
    # Browser BFF authenticates strictly via HttpOnly server-bound cookie, never Bearer tokens.
    if authorization and authorization.lower().startswith("bearer "):
        raise AuthenticationRequiredError(
            "Direct Bearer token authentication is not accepted; use institutional cookie session."
        )
    return authenticate_session_cookie(
        session,
        settings=settings,
        raw_session_token=raw_session_cookie,
        correlation_id=correlation_id,
    )


def require_csrf_protection(
    request: Request,
    principal: Annotated[AuthenticatedSessionPrincipal, Depends(get_current_session_principal)],
    settings: Annotated[Settings, Depends(get_settings)],
    correlation_id: Annotated[str, Depends(get_correlation_id)],
    csrf_cookie: Annotated[str | None, Cookie(alias=CSRF_COOKIE_NAME)] = None,
    csrf_header: Annotated[str | None, Header(alias=CSRF_HEADER_NAME)] = None,
    origin_header: Annotated[str | None, Header(alias="Origin")] = None,
    referer_header: Annotated[str | None, Header(alias="Referer")] = None,
) -> AuthenticatedSessionPrincipal:
    factory: sessionmaker[Session] | None = getattr(request.app.state, "session_factory", None)
    verify_csrf_and_origin(
        settings=settings,
        session_factory=factory,
        principal=principal,
        csrf_cookie=csrf_cookie,
        csrf_header=csrf_header,
        origin_header=origin_header,
        referer_header=referer_header,
        correlation_id=correlation_id,
    )
    return principal


def require_org_permission(
    permission: RbacPermission,
) -> Callable[..., AuthorizedMembershipContext]:
    """Dependency factory enforcing active membership, active org, RLS bind, and RBAC."""

    def _dependency(
        organization_id: str,
        session: Annotated[Session, Depends(get_db_session)],
        principal: Annotated[AuthenticatedSessionPrincipal, Depends(get_current_session_principal)],
        correlation_id: Annotated[str, Depends(get_correlation_id)],
        x_organization_id: Annotated[str | None, Header(alias="X-Organization-ID")] = None,
    ) -> AuthorizedMembershipContext:
        return resolve_authorized_tenant_principal(
            session,
            principal=principal,
            organization_id=organization_id,
            required_permission=permission,
            spoofed_org_header=x_organization_id,
            correlation_id=correlation_id,
        )

    return _dependency
