"""Liveness and database readiness endpoints without sensitive payload disclosure."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.core.config import Settings
from app.schemas.health import LiveHealthResponse
from app.services.health_service import get_live_health, get_ready_health

router = APIRouter(prefix="/health", tags=["health"])


@router.get("/live", response_model=LiveHealthResponse)
def health_live(request: Request) -> LiveHealthResponse:
    """Confirm FastAPI process responsiveness."""
    settings: Settings = request.app.state.settings
    return get_live_health(settings)


@router.get("/ready")
def health_ready(request: Request) -> JSONResponse:
    """Confirm relational database connectivity without leaking DSN or error internals."""
    settings: Settings = request.app.state.settings
    engine = getattr(request.app.state, "engine", None)
    status_code, payload = get_ready_health(settings, engine)
    return JSONResponse(status_code=status_code, content=payload.model_dump())
