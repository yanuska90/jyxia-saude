"""FastAPI application factory for JYXIA Institutional Foundation (0.1.0)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy import Engine

from app.api.router import api_router
from app.core.config import Settings, load_settings
from app.core.logging import configure_logging, redact_sensitive_text
from app.db.session import create_db_engine, create_session_factory


def create_app(
    settings: Settings | None = None,
    *,
    engine: Engine | None = None,
) -> FastAPI:
    """Instantiate configured FastAPI app with sanitized error boundaries."""
    resolved_settings = settings if settings is not None else load_settings(strict_database=False)
    logger = configure_logging(resolved_settings.log_level)

    owns_engine = False
    resolved_engine = engine
    if resolved_engine is None and resolved_settings.database_url:
        resolved_engine = create_db_engine(resolved_settings.database_url)
        owns_engine = True

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
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
    application.state.session_factory = (
        create_session_factory(resolved_engine) if resolved_engine is not None else None
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
