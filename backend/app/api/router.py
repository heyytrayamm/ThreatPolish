"""Central API router aggregating all versioned endpoints."""

from fastapi import APIRouter
from app.api.routes import health

api_router = APIRouter(prefix="/api/v1")

# Mount health routes
api_router.include_router(health.router)
