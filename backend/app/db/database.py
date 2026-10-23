"""Engine creation, connection helpers and a small ordered migration runner."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator

from sqlalchemy import Engine, create_engine, event, select, text
from sqlalchemy.engine import Connection
from sqlalchemy.pool import StaticPool

from ..core.config import get_settings
from ..core.logging import get_logger
from ..core.security import iso, utcnow
from .schema import metadata, schema_migrations

log = get_logger(__name__)
_engine: Engine | None = None
_engine_url: str | None = None


def _make_engine(url: str) -> Engine:
    connect_args: dict[str, Any] = {}
    kwargs: dict[str, Any] = {"future": True, "pool_pre_ping": True}
    if url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
        connect_args["timeout"] = 15
        if ":memory:" in url:
            kwargs["poolclass"] = StaticPool
    engine = create_engine(url, connect_args=connect_args, **kwargs)

    if url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(dbapi_connection: Any, _record: Any) -> None:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA busy_timeout=15000")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.close()

    return engine


def get_engine(url: str | None = None) -> Engine:
    global _engine, _engine_url
    target = url or get_settings().db_url
    if _engine is not None and _engine_url == target:
        return _engine
    if _engine is not None:
        _engine.dispose()
    if target.startswith("sqlite:///"):
        path = target.replace("sqlite:///", "", 1)
        if path and path != ":memory:":
            Path(path).expanduser().parent.mkdir(parents=True, exist_ok=True)
    _engine = _make_engine(target)
    _engine_url = target
    return _engine


def dispose_engine() -> None:
    global _engine, _engine_url
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _engine_url = None


@contextmanager
def connection() -> Iterator[Connection]:
    engine = get_engine()
    with engine.begin() as conn:
        yield conn


def query_all(conn: Connection, sql: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    result = conn.execute(text(sql), params or {})
    return [dict(row._mapping) for row in result]


def query_one(conn: Connection, sql: str, params: dict[str, Any] | None = None) -> dict[str, Any] | None:
    rows = query_all(conn, sql, params)
    return rows[0] if rows else None


def dumps(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), default=str, sort_keys=True)


def loads(value: str | None, fallback: Any = None) -> Any:
    if not value:
        return fallback
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return fallback


# --------------------------------------------------------------------------- #
# Migrations
# --------------------------------------------------------------------------- #
def _migration_001_initial(conn: Connection) -> None:
    metadata.create_all(conn, checkfirst=True)


def _migration_002_events_retention_index(conn: Connection) -> None:
    conn.execute(text("CREATE INDEX IF NOT EXISTS ix_events_retention ON events (retention_until)"))


MIGRATIONS: list[tuple[int, str, Any]] = [
    (1, "initial schema", _migration_001_initial),
    (2, "event retention index", _migration_002_events_retention_index),
]


def init_db(url: str | None = None) -> Engine:
    engine = get_engine(url)
    with engine.begin() as conn:
        schema_migrations.create(bind=conn, checkfirst=True)
        applied = {
            row[0]
            for row in conn.execute(select(schema_migrations.c.version)).fetchall()
        }
        for version, name, apply in MIGRATIONS:
            if version in applied:
                continue
            log.info("applying migration", extra={"version": version, "migration": name})
            apply(conn)
            conn.execute(
                schema_migrations.insert().values(
                    version=version, name=name, applied_at=iso(utcnow())
                )
            )
    return engine


def schema_version() -> int:
    with connection() as conn:
        row = conn.execute(text("SELECT MAX(version) FROM schema_migrations")).fetchone()
    return int(row[0]) if row and row[0] is not None else 0


def sqlite_version() -> str:
    return sqlite3.sqlite_version


def utc_stamp(ts: datetime | None = None) -> str:
    return iso(ts or utcnow())
