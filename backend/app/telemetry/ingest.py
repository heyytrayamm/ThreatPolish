"""Event ingestion.

Guarantees:
* Every payload is validated against the versioned contract before storage.
* Invalid payloads are quarantined with a machine-readable reason, never
  silently dropped.
* Re-sent events are reported as duplicates instead of being counted twice.
* A single bad record cannot roll back the rest of a batch.
"""

from __future__ import annotations

import hashlib
import json
from datetime import timedelta
from typing import Any, Iterable

from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from ..core.config import Settings, get_settings
from ..core.logging import get_logger
from ..core.security import iso, new_id, utcnow
from ..db.database import connection, dumps, loads
from ..db.schema import events
from ..schemas.event import EventIn, IngestItemResult, IngestReport
from .normalize import normalize_event

log = get_logger(__name__)
MAX_QUARANTINE_PAYLOAD = 32_000


class Ingestor:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def ingest(self, payloads: Iterable[dict[str, Any]], *, actor: str) -> IngestReport:
        items = list(payloads)
        results: list[IngestItemResult] = []
        accepted = duplicates = rejected = 0

        with connection() as conn:
            for index, payload in enumerate(items):
                result, outcome = self._process(conn, index, payload, actor)
                results.append(result)
                if outcome == "accepted":
                    accepted += 1
                elif outcome == "duplicate":
                    duplicates += 1
                else:
                    rejected += 1

        if rejected:
            log.warning("ingest batch contained rejected events", extra={"rejected": rejected})
        return IngestReport(
            received=len(items),
            accepted=accepted,
            duplicates=duplicates,
            rejected=rejected,
            results=results,
        )

    def submit(self, event: EventIn, *, actor: str) -> str | None:
        report = self.ingest([event.model_dump(mode="json")], actor=actor)
        result = report.results[0]
        return result.event_id if result.status in {"accepted", "duplicate"} else None

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #
    def _process(
        self, conn: Any, index: int, payload: Any, actor: str
    ) -> tuple[IngestItemResult, str]:
        if not isinstance(payload, dict):
            reason = "event payload must be a JSON object"
            qid = self._quarantine(conn, payload, "invalid_shape", reason, actor)
            return (
                IngestItemResult(index=index, event_id=None, status="rejected", reason=reason, quarantine_id=qid),
                "rejected",
            )

        try:
            event = EventIn.model_validate(payload)
        except ValidationError as exc:
            errors = exc.errors(include_url=False)
            reason = "; ".join(
                f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}" for error in errors[:5]
            )
            qid = self._quarantine(conn, payload, "schema_validation", reason, actor)
            return (
                IngestItemResult(index=index, event_id=None, status="rejected", reason=reason, quarantine_id=qid),
                "rejected",
            )

        normalized = normalize_event(event)
        event_id = event.event_id or new_id("evt")
        dedup_key = _dedup_key(event, normalized)

        existing = conn.execute(
            text("SELECT id, dedup_key FROM events WHERE id = :id OR dedup_key = :key LIMIT 1"),
            {"id": event_id, "key": dedup_key},
        ).fetchone()
        if existing:
            existing_id = existing[0]
            return (
                IngestItemResult(
                    index=index,
                    event_id=existing_id,
                    status="duplicate",
                    reason="an equivalent event is already stored",
                ),
                "duplicate",
            )

        occurred = event.occurred_at
        received = utcnow()
        row = {
            "id": event_id,
            "schema_version": event.schema_version,
            "occurred_at": iso(occurred),
            "received_at": iso(received),
            "source_module": event.source_module,
            "event_type": event.event_type,
            "source_ip": event.source_ip,
            "session_id": event.session_id,
            "target_id": event.target_id,
            "severity": event.severity,
            "provenance": dumps(event.provenance.model_dump(mode="json")),
            "features": dumps(normalized),
            "evidence_refs": dumps(event.evidence_refs),
            "raw": dumps(event.raw),
            "dedup_key": dedup_key,
            "status": "processed",
            "correlation_state": "pending",
            "synthetic": 1 if event.provenance.synthetic else 0,
            "retention_until": iso(occurred + timedelta(days=self.settings.retention_days)),
        }

        try:
            with conn.begin_nested():
                conn.execute(events.insert().values(**row))
        except IntegrityError:
            return (
                IngestItemResult(
                    index=index,
                    event_id=event_id,
                    status="duplicate",
                    reason="concurrent insert detected; event already stored",
                ),
                "duplicate",
            )
        except SQLAlchemyError as exc:
            log.error("event persistence failed", extra={"error": str(exc)})
            qid = self._quarantine(conn, payload, "storage_failure", str(exc)[:500], actor)
            return (
                IngestItemResult(
                    index=index,
                    event_id=None,
                    status="rejected",
                    reason="storage failure; payload quarantined",
                    quarantine_id=qid,
                ),
                "rejected",
            )

        self._touch_source(conn, event, ok=True)
        return (
            IngestItemResult(index=index, event_id=event_id, status="accepted"),
            "accepted",
        )

    def _quarantine(
        self, conn: Any, payload: Any, reason_code: str, reason: str, actor: str
    ) -> str:
        quarantine_id = new_id("qtn")
        encoded = json.dumps(payload, default=str)[:MAX_QUARANTINE_PAYLOAD]
        module = payload.get("source_module") if isinstance(payload, dict) else None
        try:
            with conn.begin_nested():
                conn.execute(
                    text(
                        "INSERT INTO event_quarantine "
                        "(id, received_at, source_module, actor, reason_code, reason, payload, "
                        "payload_bytes, status) VALUES (:id, :ts, :module, :actor, :code, :reason, "
                        ":payload, :bytes, 'quarantined')"
                    ),
                    {
                        "id": quarantine_id,
                        "ts": iso(utcnow()),
                        "module": str(module)[:64] if module else None,
                        "actor": actor[:120],
                        "code": reason_code[:48],
                        "reason": reason[:2000],
                        "payload": encoded,
                        "bytes": len(encoded.encode("utf-8")),
                    },
                )
        except SQLAlchemyError as exc:  # pragma: no cover - storage is already failing
            log.error("quarantine write failed", extra={"error": str(exc)})
        return quarantine_id

    def _touch_source(self, conn: Any, event: EventIn, *, ok: bool) -> None:
        source = f"{event.source_module}:{event.provenance.collector}"[:120]
        now = iso(utcnow())
        detail = dumps(
            {
                "last_event_type": event.event_type,
                "last_event_id": event.event_id,
                "synthetic": event.provenance.synthetic,
            }
        )
        try:
            with conn.begin_nested():
                result = conn.execute(
                    text(
                        "UPDATE source_health SET last_event_at = :now, last_success_at = :now, "
                        "ok = :ok, detail = :detail WHERE source = :source"
                    ),
                    {"now": now, "ok": 1 if ok else 0, "detail": detail, "source": source},
                )
                if result.rowcount == 0:
                    conn.execute(
                        text(
                            "INSERT INTO source_health "
                            "(source, last_event_at, last_success_at, last_error_at, error_count, ok, detail) "
                            "VALUES (:source, :now, :success, NULL, 0, :ok, :detail)"
                        ),
                        {
                            "source": source,
                            "now": now,
                            "success": now if ok else None,
                            "ok": 1 if ok else 0,
                            "detail": detail,
                        },
                    )
        except SQLAlchemyError as exc:  # pragma: no cover
            log.warning("source health update failed", extra={"error": str(exc)})


def _dedup_key(event: EventIn, normalized: dict[str, Any]) -> str:
    material = {
        "event_id": event.event_id or "",
        "module": event.source_module,
        "type": event.event_type,
        "occurred_at": iso(event.occurred_at),
        "source_ip": event.source_ip,
        "session_id": event.session_id,
        "target_id": event.target_id,
        "severity": event.severity,
        "features": normalized,
        "raw": event.raw,
        "refs": sorted(event.evidence_refs),
    }
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()


def source_health() -> list[dict[str, Any]]:
    with connection() as conn:
        rows = conn.execute(
            text(
                "SELECT source, last_event_at, last_success_at, last_error_at, error_count, ok, detail "
                "FROM source_health ORDER BY source"
            )
        ).fetchall()
    return [
        {
            "source": row[0],
            "last_event_at": row[1],
            "last_success_at": row[2],
            "last_error_at": row[3],
            "error_count": int(row[4]),
            "ok": bool(row[5]),
            "detail": loads(row[6], {}),
        }
        for row in rows
    ]
