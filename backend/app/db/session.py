"""
Database engine and async-safe session factory for ThreatPolish.

Design decisions
────────────────
• The engine is created **lazily** via ``get_engine()`` — nothing connects
  at module import time.
• ``get_session()`` is an async-generator dependency suitable for FastAPI's
  ``Depends()`` (but also usable in plain scripts via ``next()``).
• Sessions are committed on success, rolled back on error, and always
  closed — database errors are never silently swallowed.
• ``check_db_ready()`` actually executes ``SELECT 1`` so the health probe
  can distinguish "app alive" from "database reachable".
"""

from __future__ import annotations

from typing import Generator

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings

# ---------------------------------------------------------------------------
# Module-level cache (lazy initialisation, not at import time)
# ---------------------------------------------------------------------------
_engine: Engine | None = None
_SessionLocal: sessionmaker[Session] | None = None


def get_engine() -> Engine:
    """
    Return a (cached) SQLAlchemy engine using the configured DATABASE_URL.

    The engine is created on first call, not at module import.
    ``pool_pre_ping=True`` lets SQLAlchemy transparently reconnect after
    transient database restarts.
    """
    global _engine
    if _engine is None:
        connect_args = {}
        if "postgresql" in settings.DATABASE_URL or "postgres" in settings.DATABASE_URL:
            # Set a 3-second connection timeout so unreachable databases fail fast
            connect_args["connect_timeout"] = 3
        _engine = create_engine(
            settings.DATABASE_URL,
            pool_pre_ping=True,
            pool_size=5,
            max_overflow=10,
            echo=settings.DEBUG,
            connect_args=connect_args,
        )
    return _engine


def get_session_factory() -> sessionmaker[Session]:
    """Return a (cached) sessionmaker bound to the current engine."""
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(
            bind=get_engine(),
            autocommit=False,
            autoflush=False,
            expire_on_commit=False,
        )
    return _SessionLocal


def get_session() -> Generator[Session, None, None]:
    """
    Yield a database session and guarantee cleanup.

    Usage as a FastAPI dependency::

        @router.get("/events")
        def list_events(db: Session = Depends(get_session)):
            ...

    The session is:
    • committed if the request handler returns normally,
    • rolled back if any exception occurs,
    • always closed.
    """
    factory = get_session_factory()
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def check_db_ready() -> bool:
    """
    Execute ``SELECT 1`` against the configured database.

    Returns ``True`` if the query succeeds, ``False`` otherwise.
    This gives the health endpoint an honest "database reachable" signal
    rather than just "app process alive".
    """
    try:
        engine = get_engine()
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


def dispose_engine() -> None:
    """
    Dispose the cached engine and session factory.

    Useful in tests and during application shutdown to release all
    pooled connections cleanly.
    """
    global _engine, _SessionLocal
    if _engine is not None:
        _engine.dispose()
        _engine = None
    _SessionLocal = None
