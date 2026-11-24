"""Health service diagnostics without exposing DSNs or environment secrets."""

from __future__ import annotations

from sqlalchemy import Engine

from app.core.config import Settings
from app.db.session import check_db_connectivity
from app.schemas.health import LiveHealthResponse, ReadyHealthResponse


def get_live_health(settings: Settings) -> LiveHealthResponse:
    """Return lightweight liveness payload confirming process health only."""
    return LiveHealthResponse(
        status="alive",
        service=settings.app_name,
        version=settings.app_version,
    )


def get_ready_health(settings: Settings, engine: Engine | None) -> tuple[int, ReadyHealthResponse]:
    """Check relational database readiness without exposing secrets or stacktraces."""
    connectivity = check_db_connectivity(engine)
    status_code = 200 if connectivity.ok else 503
    db_state = connectivity.status
    if db_state not in {"reachable", "unconfigured", "unavailable"}:
        db_state = "unavailable"
    return status_code, ReadyHealthResponse(
        status="ready" if connectivity.ok else "not_ready",
        service=settings.app_name,
        version=settings.app_version,
        database=db_state,  # type: ignore[arg-type]
    )
