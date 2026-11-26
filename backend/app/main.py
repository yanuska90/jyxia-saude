"""FastAPI application factory for JYXIA Institutional Foundation (0.2.0)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy import Engine

from app.api.router import api_router
from app.core.config import Settings, load_settings
from app.core.constants import CSRF_HEADER_NAME, IDEMPOTENCY_KEY_HEADER_NAME
from app.core.logging import configure_logging, redact_sensitive_text
from app.core.oidc import (
    OidcNotConfiguredError,
    OidcProviderAdapter,
    OidcProviderUnavailableError,
    StandardOidcProviderAdapter,
)
from app.core.rbac import AuthenticationRequiredError, AuthorizationDeniedError
from app.db.session import create_db_engine, create_session_factory
from app.services.storage import DocumentStoragePort, LocalControlledSyntheticStorage

_REPO_ROOT = Path(__file__).resolve().parents[2]
_INSTITUTIONAL_FRONTEND_DIR = _REPO_ROOT / "frontend" / "institutional"
_PUBLIC_FRONTEND_DIR = _REPO_ROOT / "frontend" / "public"

_INSTITUTIONAL_UI_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "worker-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' blob: data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "form-action 'none'; "
    "frame-ancestors 'none'"
)

_INSTITUTIONAL_ASSET_ALLOWLIST: dict[str, tuple[Path, str]] = {
    "index.html": (_INSTITUTIONAL_FRONTEND_DIR / "index.html", "text/html; charset=utf-8"),
    "institutional.css": (
        _INSTITUTIONAL_FRONTEND_DIR / "institutional.css",
        "text/css; charset=utf-8",
    ),
    "institutional-core.mjs": (
        _INSTITUTIONAL_FRONTEND_DIR / "institutional-core.mjs",
        "text/javascript; charset=utf-8",
    ),
    "institutional-ui.mjs": (
        _INSTITUTIONAL_FRONTEND_DIR / "institutional-ui.mjs",
        "text/javascript; charset=utf-8",
    ),
    "assets/favicon.svg": (
        _PUBLIC_FRONTEND_DIR / "assets" / "favicon.svg",
        "image/svg+xml",
    ),
    "vendor/pdf.min.mjs": (
        _PUBLIC_FRONTEND_DIR / "vendor" / "pdf.min.mjs",
        "text/javascript; charset=utf-8",
    ),
    "vendor/pdf.worker.min.mjs": (
        _PUBLIC_FRONTEND_DIR / "vendor" / "pdf.worker.min.mjs",
        "text/javascript; charset=utf-8",
    ),
    "vendor/PDFJS-LICENSE.txt": (
        _PUBLIC_FRONTEND_DIR / "vendor" / "PDFJS-LICENSE.txt",
        "text/plain; charset=utf-8",
    ),
}


def _build_default_storage(settings: Settings) -> LocalControlledSyntheticStorage:
    raw_root = Path(settings.storage_root)
    resolved_root = raw_root if raw_root.is_absolute() else (_REPO_ROOT / raw_root)
    storage_enabled = bool(
        settings.allow_local_synthetic_storage and settings.env in {"development", "test"}
    )
    return LocalControlledSyntheticStorage(
        resolved_root,
        enabled=storage_enabled,
        max_bytes=settings.max_document_bytes,
        forbidden_parent_dir=_REPO_ROOT,
    )


def create_app(
    settings: Settings | None = None,
    *,
    engine: Engine | None = None,
    oidc_adapter: OidcProviderAdapter | None = None,
    storage: DocumentStoragePort | None = None,
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
    application.state.storage = (
        storage if storage is not None else _build_default_storage(resolved_settings)
    )
    application.state.session_factory = (
        create_session_factory(resolved_engine) if resolved_engine is not None else None
    )

    if resolved_settings.cors_allowed_origins:
        application.add_middleware(
            CORSMiddleware,
            allow_origins=list(resolved_settings.cors_allowed_origins),
            allow_credentials=True,
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=[
                "Content-Type",
                CSRF_HEADER_NAME,
                "X-Request-ID",
                IDEMPOTENCY_KEY_HEADER_NAME,
            ],
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

    def _serve_institutional_asset(asset_key: str) -> FileResponse:
        target = _INSTITUTIONAL_ASSET_ALLOWLIST.get(asset_key)
        if target is None:
            raise HTTPException(status_code=404, detail="Institutional UI asset not found.")
        file_path, media_type = target
        if not file_path.is_file():
            raise HTTPException(status_code=404, detail="Institutional UI asset not found.")
        return FileResponse(
            path=str(file_path),
            media_type=media_type,
            headers={
                "Cache-Control": "no-store, no-cache, must-revalidate",
                "Pragma": "no-cache",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "no-referrer",
                "Content-Security-Policy": _INSTITUTIONAL_UI_CSP,
            },
        )

    @application.get("/institutional", include_in_schema=False)
    @application.get("/institutional/", include_in_schema=False)
    def get_institutional_index() -> FileResponse:
        return _serve_institutional_asset("index.html")

    @application.get("/institutional/{asset_path:path}", include_in_schema=False)
    def get_institutional_asset(asset_path: str) -> FileResponse:
        cleaned = asset_path.strip().lstrip("/")
        if not cleaned or cleaned == "index.html":
            return _serve_institutional_asset("index.html")
        return _serve_institutional_asset(cleaned)

    application.include_router(api_router)
    return application


app = create_app()
