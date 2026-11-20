"""Tests for FastAPI app lifecycle, health endpoints and sanitized error handling."""

from __future__ import annotations

from pathlib import Path

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


def test_production_mode_disables_interactive_docs() -> None:
    app = create_app(
        Settings(
            env="production",
            database_url="postgresql+psycopg://jyxia:local_only@127.0.0.1:5432/jyxia_prod",
            allow_local_synthetic_storage=False,
        )
    )
    assert app.docs_url is None
    assert app.redoc_url is None


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


def test_health_ready_returns_503_without_leaking_dsn_or_secrets() -> None:
    app_unconfigured = create_app(Settings(env="test", database_url=None))
    with TestClient(app_unconfigured) as client:
        resp = client.get("/api/v1/health/ready")
        assert resp.status_code == 503
        assert resp.json()["status"] == "not_ready"
        assert resp.json()["database"] == "unconfigured"

    secret_token = "SUPER_SECRET_LOCAL_ONLY_TOKEN_9981"
    broken_dsn = f"postgresql+psycopg://jyxia_user:{secret_token}@127.0.0.1:1/unavailable_db"
    app_broken = create_app(Settings(env="test", database_url=broken_dsn))
    with TestClient(app_broken) as client:
        resp = client.get("/api/v1/health/ready")
        assert resp.status_code == 503
        assert resp.json()["status"] == "not_ready"
        assert resp.json()["database"] == "unavailable"
        assert secret_token not in resp.text
        assert "127.0.0.1" not in resp.text
        assert "postgresql" not in resp.text
