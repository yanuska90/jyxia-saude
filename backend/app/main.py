"""FastAPI application factory for JYXIA Institutional Foundation (0.2.0)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import Engine

from app.api.router import api_router
from app.core.config import Settings, load_settings
from app.core.constants import CSRF_HEADER_NAME
from app.core.logging import configure_logging, redact_sensitive_text
from app.core.oidc import (
    OidcNotConfiguredError,
    OidcProviderAdapter,
    OidcProviderUnavailableError,
    StandardOidcProviderAdapter,
)
from app.core.rbac import AuthenticationRequiredError, AuthorizationDeniedError
from app.db.session import create_db_engine, create_session_factory


def create_app(
    settings: Settings | None = None,
    *,
    engine: Engine | None = None,
    oidc_adapter: OidcProviderAdapter | None = None,
) -> FastAPI:
    """Instantiate configured FastAPI app with OIDC/RBAC security and sanitized errors."""
    resolved_settings = settings if settings is not None else load_settings(strict_database=False)
    logger = configure_logging(resolved_settings.log_level)

    owns_engine = False
    resolved_engine = engine
    if resolved_engine is None and resolved_settings.database_url:
        resolved_engine = create_db_engine(resolved_settings.database_url)
        owns_engine = True

    owns_oidc = oidc_adapter is None
    resolved_oidc: OidcProviderAdapter = (
        oidc_adapter
        if oidc_adapter is not None
        else StandardOidcProviderAdapter(resolved_settings)
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            if owns_oidc and isinstance(resolved_oidc, StandardOidcProviderAdapter):
                resolved_oidc.close()
            if owns_engine and getattr(app.state, "engine", None) is not None:
                app.state.engine.dispose()

    is_prod = resolved_settings.env == "production"
    application = FastAPI(
        title=resolved_settings.app_name,
        version=resolved_settings.app_version,
        docs_url=None if is_prod else "/docs",
        openapi_url=None if is_prod else "/openapi.json",
        redoc_url=None,
        lifespan=lifespan,
    )
    application.state.settings = resolved_settings
    application.state.engine = resolved_engine
    application.state.oidc_adapter = resolved_oidc
    application.state.session_factory = (
        create_session_factory(resolved_engine) if resolved_engine is not None else None
    )

    if resolved_settings.cors_allowed_origins:
        application.add_middleware(
            CORSMiddleware,
            allow_origins=list(resolved_settings.cors_allowed_origins),
            allow_credentials=True,
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["Content-Type", CSRF_HEADER_NAME, "X-Request-ID"],
        )

    @application.exception_handler(AuthenticationRequiredError)
    async def _auth_required_handler(
        _request: Request, exc: AuthenticationRequiredError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=401,
            content={"detail": redact_sensitive_text(str(exc))},
            headers={"Cache-Control": "no-store"},
        )

    @application.exception_handler(AuthorizationDeniedError)
    async def _authz_denied_handler(
        _request: Request, exc: AuthorizationDeniedError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=403,
            content={"detail": redact_sensitive_text(str(exc))},
            headers={"Cache-Control": "no-store"},
        )

    @application.exception_handler(OidcNotConfiguredError)
    @application.exception_handler(OidcProviderUnavailableError)
    async def _oidc_unavailable_handler(
        _request: Request, exc: Exception
    ) -> JSONResponse:
        return JSONResponse(
            status_code=503,
            content={"detail": redact_sensitive_text(str(exc))},
            headers={"Cache-Control": "no-store"},
        )

    @application.exception_handler(HTTPException)
    async def _http_exception_handler(_request: Request, exc: HTTPException) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": redact_sensitive_text(str(exc.detail))},
        )

    @application.exception_handler(Exception)
    async def _unhandled_exception_handler(_request: Request, exc: Exception) -> JSONResponse:
        logger.error("Unhandled backend exception type=%s.", type(exc).__name__)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error."},
        )

    application.include_router(api_router)
    return application


app = create_app()
