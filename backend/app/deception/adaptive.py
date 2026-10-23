"""Uncertainty-aware adaptive investigation.

The engine may only *observe more*.  It cannot invent events, edit evidence or
raise a confidence score without new telemetry.  Every investigation records a
before/after snapshot so a reviewer can see whether the additional observation
helped, did nothing, or weakened the hypothesis.

Safety limits enforced here:

* only profiles seeded in the database, of kind ``http``, and enabled may be
  selected;
* at most one active investigation per campaign or edge;
* activations expire (15 minutes by default, 60 maximum);
* a persisted active-investigation ceiling prevents a loop from continuously
  re-targeting decoys across API and decoy processes.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy import or_, select, text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from ..core.errors import Conflict, NotFound, PolicyDenied, ValidationFailure
from ..core.logging import get_logger
from ..core.security import iso, new_id, utcnow
from ..db.database import connection, dumps, loads, query_one
from ..db.schema import investigations
from ..correlation.engine import correlate
from ..correlation.repository import get_campaign, get_edge
from ..correlation.scoring import ALGORITHM_VERSION
from .profiles import get_profile, list_profiles

log = get_logger(__name__)

OBSERVABLE_FAMILIES = {"behavior", "targeting", "identity", "toolchain", "timing"}
PROFILE_BY_FAMILY = {
    "identity": "http-admin-console",
    "targeting": "http-api-gateway",
    "behavior": "http-wordpress",
    "toolchain": "http-wordpress",
    "timing": "http-wordpress",
}
DEFAULT_TTL_MINUTES = 15
MAX_TTL_MINUTES = 60
MAX_ACTIVE = 50


def active_override(ip: str) -> dict[str, Any] | None:
    """Load the active decoy override from the database.

    The API and the decoy listener are separate processes, so an in-memory
    registry cannot carry an activation between them. The investigation row is
    the shared source of truth; expiry is enforced on the read path.
    """
    try:
        with connection() as conn:
            row = query_one(
                conn,
                "SELECT id, chosen_profile, expires_at FROM investigations "
                "WHERE status = 'active' AND source_ip = :ip AND expires_at > :now "
                "ORDER BY updated_at DESC LIMIT 1",
                {"ip": ip, "now": iso(utcnow())},
            )
    except SQLAlchemyError as exc:
        log.warning("active override lookup failed", extra={"error": str(exc)})
        return None
    if not row:
        return None
    return {
        "profile": row["chosen_profile"],
        "investigation_id": row["id"],
        "expires_at": row["expires_at"],
    }


def _expire_activations() -> int:
    """Mark activations whose TTL has elapsed so they stop reserving a subject."""
    now = iso(utcnow())
    with connection() as conn:
        result = conn.execute(
            investigations.update()
            .where(
                investigations.c.status == "active",
                or_(
                    investigations.c.expires_at.is_(None),
                    investigations.c.expires_at < now,
                ),
            )
            .values(status="expired", updated_at=now)
        )
    return int(result.rowcount or 0)


def _active_count() -> int:
    with connection() as conn:
        row = conn.execute(
            text(
                "SELECT COUNT(*) FROM investigations "
                "WHERE status = 'active' AND expires_at > :now"
            ),
            {"now": iso(utcnow())},
        ).fetchone()
    return int(row[0]) if row else 0


def plan_investigation(
    *,
    edge_id: str | None = None,
    campaign_id: str | None = None,
    profile_name: str | None = None,
    actor: str = "system",
    ttl_minutes: int = DEFAULT_TTL_MINUTES,
) -> dict[str, Any]:
    if not edge_id and not campaign_id:
        raise ValidationFailure("provide either edge_id or campaign_id")
    if edge_id and campaign_id:
        raise ValidationFailure("provide only one of edge_id or campaign_id")
    ttl = max(5, min(MAX_TTL_MINUTES, ttl_minutes))
    _expire_activations()

    if edge_id:
        edge = get_edge(edge_id)
        evidence = edge.get("evidence", {})
        confidence = float(edge["confidence"])
        subject = edge_id
        subject_type = "edge"
    else:
        campaign = get_campaign(campaign_id or "")
        edges = campaign.get("edges", [])
        if not edges:
            raise ValidationFailure("campaign has no relationship edges to investigate")
        edge = min(edges, key=lambda item: item["confidence"])
        evidence = edge.get("evidence", {})
        confidence = float(edge["confidence"])
        subject = campaign_id or ""
        subject_type = "campaign"
        edge_id = edge["id"]

    missing = [family for family in evidence.get("missing_evidence", [])]
    observable = [family for family in missing if family in OBSERVABLE_FAMILIES]
    chosen = _select_profile(profile_name, observable)
    useful = bool(observable) and 0.40 <= confidence < 0.90
    expected_gain = round(min(0.20, 0.06 * len(observable)), 3) if useful else 0.0

    hypothesis_before = {
        "edge_id": edge_id,
        "confidence": confidence,
        "decision": evidence.get("explanation", ""),
        "missing_evidence": missing,
        "at": iso(utcnow()),
    }
    notes = (
        "Additional observation is recommended because "
        + ", ".join(observable)
        + " evidence is missing and within the decoy's observation scope."
        if useful
        else "No additional observation is warranted at this confidence level "
        "or the missing evidence cannot be collected by a decoy."
    )

    investigation_id = new_id("inv")
    now = utcnow()
    try:
        with connection() as conn:
            conn.execute(
                investigations.insert().values(
                    id=investigation_id,
                    created_at=iso(now),
                    updated_at=iso(now),
                    campaign_id=campaign_id,
                    edge_id=edge_id,
                    status="planned",
                    missing_evidence=dumps(missing),
                    chosen_profile=chosen["name"] if chosen else None,
                    hypothesis_before=dumps(hypothesis_before),
                    hypothesis_after=None,
                    outcome=None,
                    notes=notes,
                    algorithm_version=ALGORITHM_VERSION,
                )
            )
    except IntegrityError as exc:
        # The partial unique indexes on edge_id and campaign_id decide the
        # conflict atomically.  A read-then-insert check could let two
        # concurrent planners both pass, leaving duplicate investigations and
        # two decoy activations for the same campaign.
        existing = _open_investigation_id(edge_id=edge_id, campaign_id=campaign_id)
        raise Conflict(
            "an investigation is already planned or active for this subject",
            details={"investigation_id": existing} if existing else {},
        ) from exc

    return {
        "id": investigation_id,
        "subject": {"type": subject_type, "id": subject},
        "edge_id": edge_id,
        "campaign_id": campaign_id,
        "status": "planned",
        "missing_evidence": missing,
        "observable_evidence": observable,
        "profile": chosen["name"] if chosen else None,
        "expected_information_gain": expected_gain,
        "recommended": useful,
        "ttl_minutes": ttl,
        "rationale": notes,
        "hypothesis_before": hypothesis_before,
        "safety": {
            "profile_source": "database allow-list",
            "expires_in_minutes": ttl,
            "code_execution": "none",
            "outbound_network_access": "none",
            "note": "Activation is audited. The decoy records real interactions only.",
        },
    }


def activate_investigation(
    investigation_id: str, *, source_ip: str, actor: str, ttl_minutes: int | None = None
) -> dict[str, Any]:
    _expire_activations()
    record = get_investigation(investigation_id)
    if record["status"] not in {"planned", "active"}:
        raise Conflict(f"investigation is {record['status']} and cannot be activated")
    if _active_count() >= MAX_ACTIVE and record["status"] != "active":
        raise PolicyDenied("active investigation capacity reached")

    profile = get_profile(record["chosen_profile"] or "")
    if not profile or not profile["enabled"] or profile["kind"] != "http":
        raise PolicyDenied("selected profile is not an enabled HTTP decoy profile")

    ttl = max(5, min(MAX_TTL_MINUTES, ttl_minutes or DEFAULT_TTL_MINUTES))
    expires = utcnow() + timedelta(minutes=ttl)

    now = utcnow()
    with connection() as conn:
        conn.execute(
            investigations.update()
            .where(investigations.c.id == investigation_id)
            .values(
                status="active",
                updated_at=iso(now),
                source_ip=source_ip,
                expires_at=iso(expires),
                notes=record["notes"],
            )
        )
    log.info(
        "adaptive investigation activated",
        extra={
            "investigation": investigation_id,
            "profile": profile["name"],
            "source_ip": source_ip,
            "actor": actor,
            "expires_at": iso(expires),
        },
    )
    return {
        "id": investigation_id,
        "status": "active",
        "profile": profile["name"],
        "source_ip": source_ip,
        "expires_at": iso(expires),
        "ttl_minutes": ttl,
    }


def evaluate_investigation(investigation_id: str, *, actor: str) -> dict[str, Any]:
    record = get_investigation(investigation_id)
    before = record["hypothesis_before"] or {}
    edge_id = record["edge_id"]
    if not edge_id:
        raise ValidationFailure("investigation has no relationship edge to re-evaluate")

    since = record["created_at"]
    new_events = _events_since(since)

    run = correlate(trigger="adaptive_investigation", actor=actor)
    try:
        after = get_edge(edge_id)
    except NotFound:
        after = None

    if after is None:
        outcome = "relationship_removed"
        after_confidence = 0.0
        after_payload: dict[str, Any] = {
            "edge_id": edge_id,
            "confidence": 0.0,
            "explanation": "the relationship no longer meets the storage threshold",
            "at": iso(utcnow()),
        }
    else:
        after_confidence = float(after["confidence"])
        after_payload = {
            "edge_id": edge_id,
            "confidence": after_confidence,
            "decision": after["evidence"].get("explanation", ""),
            "missing_evidence": after["evidence"].get("missing_evidence", []),
            "at": iso(utcnow()),
        }

    if new_events == 0:
        outcome = "insufficient_evidence"
        delta = 0.0
    else:
        delta = round(after_confidence - float(before.get("confidence", 0.0)), 4)
        if delta >= 0.05:
            outcome = "strengthened"
        elif delta <= -0.05:
            outcome = "weakened"
        else:
            outcome = "unchanged"

    now = utcnow()
    with connection() as conn:
        conn.execute(
            investigations.update()
            .where(investigations.c.id == investigation_id)
            .values(
                status="evaluated",
                updated_at=iso(now),
                hypothesis_after=dumps(after_payload),
                outcome=outcome,
                expires_at=None,
            )
        )
    return {
        "id": investigation_id,
        "outcome": outcome,
        "confidence_before": before.get("confidence"),
        "confidence_after": after_confidence,
        "delta": delta,
        "new_events_observed": new_events,
        "hypothesis_before": before,
        "hypothesis_after": after_payload,
        "correlation_run": run["run_id"],
        "note": (
            "Outcome is computed from persisted telemetry only. Adaptive observation "
            "cannot increase confidence without new evidence."
        ),
    }


def get_investigation(investigation_id: str) -> dict[str, Any]:
    _expire_activations()
    with connection() as conn:
        row = conn.execute(
            select(investigations).where(investigations.c.id == investigation_id)
        ).fetchone()
    if not row:
        raise NotFound("investigation not found")
    data = dict(row._mapping)
    data["missing_evidence"] = loads(data["missing_evidence"], [])
    data["hypothesis_before"] = loads(data["hypothesis_before"], {})
    data["hypothesis_after"] = loads(data.get("hypothesis_after"), None)
    return data


def list_investigations(limit: int = 50) -> list[dict[str, Any]]:
    _expire_activations()
    with connection() as conn:
        rows = conn.execute(
            select(investigations).order_by(investigations.c.created_at.desc()).limit(limit)
        ).fetchall()
    result = []
    for row in rows:
        data = dict(row._mapping)
        data["missing_evidence"] = loads(data["missing_evidence"], [])
        data["hypothesis_before"] = loads(data["hypothesis_before"], {})
        data["hypothesis_after"] = loads(data.get("hypothesis_after"), None)
        result.append(data)
    return result


def _open_investigation_id(*, edge_id: str | None, campaign_id: str | None) -> str | None:
    """Find the open investigation that blocked an insert, for the error detail."""
    clauses: list[str] = []
    params: dict[str, Any] = {}
    if edge_id:
        clauses.append("edge_id = :edge")
        params["edge"] = edge_id
    if campaign_id:
        clauses.append("campaign_id = :campaign")
        params["campaign"] = campaign_id
    if not clauses:
        return None
    with connection() as conn:
        row = conn.execute(
            text(
                "SELECT id FROM investigations WHERE status IN ('planned', 'active') "
                f"AND ({' OR '.join(clauses)}) ORDER BY updated_at DESC LIMIT 1"
            ),
            params,
        ).fetchone()
    return str(row[0]) if row else None


def _select_profile(requested: str | None, observable: list[str]) -> dict[str, Any] | None:
    if requested:
        profile = get_profile(requested)
        if not profile:
            raise ValidationFailure(f"unknown decoy profile '{requested}'")
        if not profile["enabled"] or profile["kind"] != "http":
            raise PolicyDenied("requested profile is not an enabled HTTP decoy profile")
        return profile
    for family in observable:
        name = PROFILE_BY_FAMILY.get(family)
        if not name:
            continue
        profile = get_profile(name)
        if profile and profile["enabled"] and profile["kind"] == "http":
            return profile
    enabled = [p for p in list_profiles(enabled_only=True) if p["kind"] == "http"]
    return enabled[0] if enabled else None


def _events_since(since_iso: str) -> int:
    with connection() as conn:
        row = conn.execute(
            text("SELECT COUNT(*) FROM events WHERE received_at >= :since"),
            {"since": since_iso},
        ).fetchone()
    return int(row[0]) if row else 0
