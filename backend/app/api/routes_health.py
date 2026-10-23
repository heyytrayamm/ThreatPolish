"""Health and readiness endpoints (unauthenticated, no sensitive detail)."""

from __future__ import annotations

import time
from datetime import datetime, timezone

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlalchemy import text

from .. import __version__
from ..db.database import connection, schema_version

router = APIRouter(tags=["health"])
_STARTED = time.time()


@router.get("/health")
def health() -> dict[str, object]:
    return {
        "status": "ok",
        "version": __version__,
        "uptime_seconds": round(time.time() - _STARTED, 3),
        "time": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/health/ready")
def readiness() -> JSONResponse:
    checks: dict[str, object] = {}
    healthy = True
    try:
        with connection() as conn:
            conn.execute(text("SELECT 1"))
        checks["database"] = "ok"
        checks["schema_version"] = schema_version()
    except Exception as exc:
        healthy = False
        checks["database"] = f"error: {type(exc).__name__}"

    body = {
        "status": "ready" if healthy else "not_ready",
        "checks": checks,
        "version": __version__,
    }
    return JSONResponse(status_code=200 if healthy else 503, content=body)
