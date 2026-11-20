"""Tests for FastAPI app lifecycle, health endpoints and sanitized error handling."""

from __future__ import annotations

from pathlib import Path

from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app


def test_app_initialization_exposes_only_health_routes(tmp_path: Path) -> None:
    app = create_app(
        Settings(
            env="test",
            database_url=f"sqlite:///{(tmp_path / 'init.sqlite3').as_posix()}",
        )
    )
    assert app.version == "0.1.0"
    paths = set(app.openapi()["paths"].keys())
    assert paths == {"/api/v1/health/live", "/api/v1/health/ready"}


def test_production_mode_disables_all_interactive_and_openapi_docs() -> None:
    app = create_app(
        Settings(
            env="production",
            debug=False,
            log_level="INFO",
            database_url="postgresql+psycopg://jyxia_prod:Str0ng_Prod_T3st_Secr3t!@127.0.0.1:5432/jyxia_prod",
            allow_local_synthetic_storage=False,
            oidc_enabled=True,
            oidc_issuer="https://idp.exemplo.invalid",
            oidc_client_id="jyxia-prod-client",
            cors_allowed_origins=("https://app.exemplo.invalid",),
        )
    )
    assert app.docs_url is None
    assert app.redoc_url is None
    assert app.openapi_url is None
    with TestClient(app) as client:
        assert client.get("/docs").status_code == 404
        assert client.get("/openapi.json").status_code == 404


def test_health_live_and_ready_success(migrated_engine) -> None:
    app = create_app(Settings(env="test"), engine=migrated_engine)
    with TestClient(app) as client:
        live = client.get("/api/v1/health/live")
        assert live.status_code == 200
        assert live.json() == {
            "status": "alive",
            "service": "JYXIA Institutional Foundation",
            "version": "0.1.0",
        }

        ready = client.get("/api/v1/health/ready")
        assert ready.status_code == 200
        assert ready.json()["status"] == "ready"
        assert ready.json()["database"] == "reachable"


def test_health_ready_returns_503_and_error_handlers_sanitize_payloads() -> None:
    app_unconfigured = create_app(Settings(env="test", database_url=None))
    with TestClient(app_unconfigured) as client:
        resp = client.get("/api/v1/health/ready")
        assert resp.status_code == 503
        assert resp.json()["status"] == "not_ready"
        assert resp.json()["database"] == "unconfigured"

    secret_token = "SUPER_SECRET_LOCAL_ONLY_TOKEN_9981"
    broken_dsn = f"postgresql+psycopg://jyxia_user:{secret_token}@127.0.0.1:1/unavailable_db"
    app_broken = create_app(Settings(env="test", database_url=broken_dsn))

    @app_broken.get("/_test_internal_crash")
    def _boom() -> None:
        raise RuntimeError(f"leak postgresql+psycopg://u:{secret_token}@127.0.0.1:5432/db")

    @app_broken.get("/_test_http_secret")
    def _http_err() -> None:
        raise HTTPException(status_code=400, detail="bad Bearer tok_secret_9911")

    with TestClient(app_broken, raise_server_exceptions=False) as client:
        resp = client.get("/api/v1/health/ready")
        assert resp.status_code == 503
        assert resp.json()["status"] == "not_ready"
        assert resp.json()["database"] == "unavailable"
        assert secret_token not in resp.text
        assert "127.0.0.1" not in resp.text
        assert "postgresql" not in resp.text

        crash_resp = client.get("/_test_internal_crash")
        assert crash_resp.status_code == 500
        assert crash_resp.json() == {"detail": "Internal server error."}

        http_resp = client.get("/_test_http_secret")
        assert http_resp.status_code == 400
        assert "tok_secret_9911" not in http_resp.text
        assert "Bearer [REDACTED]" in http_resp.text
