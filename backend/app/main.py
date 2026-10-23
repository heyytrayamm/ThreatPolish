"""Main entry point for the ThreatPolish FastAPI backend."""

from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.router import api_router
from app.core.config import settings


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Lifespan event handler for application startup and shutdown."""
    # Startup actions
    print(f"[ThreatPolish] Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    print(f"[ThreatPolish] Mode: {settings.ENVIRONMENT} (Debug: {settings.DEBUG})")
    print(f"[ThreatPolish] Allowed CORS origins: {settings.cors_origins}")
    yield
    # Shutdown actions
    print(f"[ThreatPolish] Shutting down {settings.APP_NAME}")


def create_application() -> FastAPI:
    """Application factory for FastAPI instance."""
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description=(
            "ThreatPolish is a defensive honeypot platform designed to capture, "
            "normalize, detect, and correlate simulated cyber threats across multiple decoy services."
        ),
        lifespan=lifespan,
    )

    # Configure CORS for local development
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Mount API v1 router
    app.include_router(api_router)

    @app.get("/", tags=["Root"])
    async def root() -> dict[str, str]:
        """Root endpoint redirecting to interactive documentation."""
        return {
            "message": f"Welcome to {settings.APP_NAME}",
            "version": settings.APP_VERSION,
            "docs": "/docs",
            "health": "/api/v1/health",
        }

    return app


app = create_application()
