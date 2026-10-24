"""ThreatPolish API application factory."""

from __future__ import annotations

import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from . import __version__
from .core.config import get_settings
from .core.errors import RateLimited, ThreatPolishError
from .core.logging import configure_logging, get_logger

log = get_logger(__name__)

DASHBOARD_CSP = (
    "default-src 'self'; connect-src 'self'; img-src 'self' data:; "
    "style-src 'self' 'unsafe-inline'; script-src 'self'; base-uri 'none'; "
    "form-action 'self'; frame-ancestors 'none'"
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    configure_logging(settings.log_level)
    if settings.generated_secret:
        log.warning(
            "TP_JWT_SECRET was not set; an ephemeral signing key is in use. "
            "Sessions will be invalidated on restart. Set TP_JWT_SECRET before production use."
        )
    from .db.database import init_db

    init_db()

    from .auth.users import count_users, ensure_bootstrap_admin

    created = ensure_bootstrap_admin()
    if created:
        log.info("bootstrap administrator created", extra={"email": created})
    elif count_users() == 0:
        log.warning(
            "no user accounts exist. Create one with: python -m app.cli create-admin "
            "--email you@example.com"
        )

    from .deception.profiles import seed_default_profiles

    seed_default_profiles()
    log.info("threatpolish ready", extra={"version": __version__, "schema": "current"})
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level)
    app = FastAPI(
        title="ThreatPolish",
        version=__version__,
        description=(
            "Evidence-guided campaign correlation with uncertainty-aware adaptive "
            "deception. API documentation is available at /docs."
        ),
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.allow_origins),
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Agent-Token"],
        max_age=600,
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next: Any) -> Any:
        started = time.perf_counter()
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = response.headers.get(
            "Cache-Control", "no-store"
        )
        response.headers["X-Process-Time-Ms"] = f"{(time.perf_counter() - started) * 1000:.1f}"
        path = request.url.path
        if path in {"/", "/index.html"} or path.startswith("/assets/"):
            # Only the dashboard gets the CSP; API docs load their own assets
            # and are not part of the analyst-facing single-page application.
            response.headers["Content-Security-Policy"] = DASHBOARD_CSP
        return response

    @app.exception_handler(ThreatPolishError)
    async def handle_app_error(_: Request, exc: ThreatPolishError) -> JSONResponse:
        headers = {}
        if isinstance(exc, RateLimited) and "retry_after_seconds" in exc.details:
            headers["Retry-After"] = str(exc.details["retry_after_seconds"])
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": {"code": exc.code, "message": exc.message, "details": exc.details}},
            headers=headers,
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation(_: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "validation_failed",
                    "message": "request validation failed",
                    "details": {"errors": _validation_errors(exc)},
                }
            },
        )

    @app.exception_handler(Exception)
    async def handle_unexpected(_: Request, exc: Exception) -> JSONResponse:
        log.error("unhandled exception", extra={"error": str(exc), "type": type(exc).__name__})
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": "internal_error",
                    "message": "an unexpected error occurred",
                    "details": {},
                }
            },
        )

    from .api import (
        routes_audit,
        routes_auth,
        routes_events,
        routes_graph,
        routes_crypto,
        routes_health,
        routes_honeypot,
        routes_investigations,
        routes_ops,
        routes_responses,
        routes_websec,
    )

    app.include_router(routes_health.router, prefix="/api/v1")
    app.include_router(routes_auth.router, prefix="/api/v1")
    app.include_router(routes_events.router, prefix="/api/v1")
    app.include_router(routes_graph.router, prefix="/api/v1")
    app.include_router(routes_investigations.router, prefix="/api/v1")
    app.include_router(routes_websec.router, prefix="/api/v1")
    app.include_router(routes_crypto.router, prefix="/api/v1")
    app.include_router(routes_responses.router, prefix="/api/v1")
    app.include_router(routes_honeypot.router, prefix="/api/v1")
    app.include_router(routes_audit.router, prefix="/api/v1")
    app.include_router(routes_ops.router, prefix="/api/v1")

    dist = Path(__file__).resolve().parents[2] / "frontend" / "dist"
    if dist.is_dir():
        app.mount("/", StaticFiles(directory=str(dist), html=True), name="dashboard")

    return app


def _validation_errors(exc: RequestValidationError) -> list[dict[str, Any]]:
    errors = []
    for error in exc.errors()[:10]:
        errors.append(
            {
                "loc": [str(part) for part in error.get("loc", [])],
                "msg": str(error.get("msg", "invalid value")),
                "type": str(error.get("type", "value_error")),
            }
        )
    return errors


app = create_app()
