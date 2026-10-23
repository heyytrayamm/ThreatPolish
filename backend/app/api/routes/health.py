"""System health check endpoint."""

from datetime import datetime, timezone
from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.core.config import settings

router = APIRouter(prefix="/health", tags=["Health"])


class HealthResponse(BaseModel):
    """Health check response schema."""

    status: str = Field(default="ok", description="Operational health status of the service")
    service: str = Field(..., description="Service name")
    version: str = Field(..., description="Current semantic version")
    environment: str = Field(..., description="Runtime environment")
    timestamp: str = Field(..., description="Current UTC timestamp in ISO 8601 format")
    phase: str = Field(default="Phase 1: Scaffolding", description="Active implementation milestone")


@router.get("", response_model=HealthResponse)
async def get_health() -> HealthResponse:
    """Return system operational status and metadata.

    Used by dashboard monitoring, container orchestrators, and uptime probes.
    """
    return HealthResponse(
        status="ok",
        service=settings.APP_NAME,
        version=settings.APP_VERSION,
        environment=settings.ENVIRONMENT,
        timestamp=datetime.now(timezone.utc).isoformat(),
        phase="Phase 1: Scaffolding & Health Monitoring",
    )
