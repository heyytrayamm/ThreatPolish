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
    phase: str = Field(default="Phase 2: Event Schema & DB Foundation", description="Active implementation milestone")
    db_ready: bool = Field(default=False, description="True when a SELECT 1 to the database succeeds")


@router.get("", response_model=HealthResponse)
async def get_health() -> HealthResponse:
    """Return system operational status and metadata.

    Used by dashboard monitoring, container orchestrators, and uptime probes.

    The endpoint always returns HTTP 200 for basic liveness.  The
    ``db_ready`` field honestly reports whether the database connection
    actually works — it is NOT just assumed True.
    """
    # Attempt a real database check; gracefully handle missing DB
    db_ready = False
    try:
        from app.db.session import check_db_ready
        db_ready = check_db_ready()
    except Exception:
        db_ready = False

    return HealthResponse(
        status="ok",
        service=settings.APP_NAME,
        version=settings.APP_VERSION,
        environment=settings.ENVIRONMENT,
        timestamp=datetime.now(timezone.utc).isoformat(),
        phase="Phase 2: Event Schema & DB Foundation",
        db_ready=db_ready,
    )

