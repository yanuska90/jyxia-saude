"""Response schemas for health endpoints."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict


class LiveHealthResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    status: Literal["alive"]
    service: str
    version: str


class ReadyHealthResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    status: Literal["ready", "not_ready"]
    service: str
    version: str
    database: Literal["reachable", "unconfigured", "unavailable"]
    auth_mode: str = "oidc_inactive_phase_0_1"
