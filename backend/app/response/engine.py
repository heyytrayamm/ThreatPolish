"""Controlled response engine.

Applied rules are stored with an expiry and can be rolled back.  Enforcement is
delegated to a firewall adapter.  The shipped adapter is local (no external
infrastructure is touched); a real edge controller can be wired in behind the
same interface after its own configuration and authorization review.
"""

from __future__ import annotations

import ipaddress
from datetime import timedelta
from typing import Any, Protocol

from sqlalchemy import select, text

from ..core.config import get_settings
from ..core.errors import Conflict, NotFound, PolicyDenied, ValidationFailure
from ..core.logging import get_logger
from ..core.security import iso, new_id, utcnow
from ..db.database import connection, dumps, loads
from ..db.schema import responses
from .policy import POLICY_VERSION, decide

log = get_logger(__name__)

APPLICABLE_ACTIONS = {"apply_rate_limit"}
DEFAULT_TTL_MINUTES = 30


class FirewallAdapter(Protocol):
    def apply(self, *, target: str, params: dict[str, Any]) -> dict[str, Any]: ...
    def remove(self, *, target: str, params: dict[str, Any]) -> dict[str, Any]: ...


class LocalAdapter:
    """Records enforcement intent; does not change network state.

    This is the default and is intentionally inert.  It exists so that the
    response workflow, audit trail, expiry and rollback can be exercised and
    tested without any chance of affecting production traffic.
    """

    name = "local-recording"

    def apply(self, *, target: str, params: dict[str, Any]) -> dict[str, Any]:
        return {"adapter": self.name, "enforced": False, "target": target, "params": params}

    def remove(self, *, target: str, params: dict[str, Any]) -> dict[str, Any]:
        return {"adapter": self.name, "enforced": False, "reverted": True, "target": target}


ADAPTER: FirewallAdapter = LocalAdapter()


def _observed_target(target: str) -> bool:
    normalized = target.strip()
    with connection() as conn:
        row = conn.execute(
            text(
                "SELECT 1 FROM events WHERE source_ip = :target "
                "OR target_id = :target LIMIT 1"
            ),
            {"target": normalized},
        ).fetchone()
    return row is not None


def evaluate_policy(
    *, severity: str, confidence: float, risk_level: str, risk_score: float
) -> dict[str, Any]:
    return decide(
        severity=severity,
        confidence=confidence,
        risk_level=risk_level,
        risk_score=risk_score,
        auto_apply_enabled=get_settings().response_auto_apply,
    )


def create_response(
    *,
    action: str,
    target: str,
    actor: str,
    role: str,
    campaign_id: str | None = None,
    confidence: float = 0.0,
    reason: str = "",
    risk_level: str = "medium",
    risk_score: float = 0.0,
    severity: str = "medium",
    ttl_minutes: int | None = None,
) -> dict[str, Any]:
    decision = evaluate_policy(
        severity=severity, confidence=confidence, risk_level=risk_level, risk_score=risk_score
    )
    if action not in decision["permitted_actions"]:
        raise PolicyDenied(
            f"policy '{decision['policy_id']}' does not permit '{action}' at this evidence level",
            details={
                "permitted_actions": decision["permitted_actions"],
                "rationale": decision["rationale"],
            },
        )
    target = target.strip()
    if not target or len(target) > 200:
        raise ValidationFailure("a target is required")
    if action in APPLICABLE_ACTIONS:
        try:
            # Event ingestion stores the canonical text form, so compare the
            # same form here; an expanded IPv6 address is the same observer.
            target = str(ipaddress.ip_address(target))
        except ValueError as exc:
            raise ValidationFailure("only IP addresses can be rate limited") from exc
        if not _observed_target(target):
            raise PolicyDenied(
                "the target has not been observed by this platform; refusing to act on it",
                details={"target": target},
            )
        ttl = max(5, min(1440, ttl_minutes or DEFAULT_TTL_MINUTES))
    else:
        ttl = ttl_minutes

    response_id = new_id("rsp")
    now = utcnow()
    status = "pending_approval" if action in APPLICABLE_ACTIONS else "open"
    with connection() as conn:
        conn.execute(
            responses.insert().values(
                id=response_id,
                created_at=iso(now),
                action=action,
                target=target,
                params=dumps({"policy": decision}),
                status=status,
                policy_id=decision["policy_id"],
                reason=reason[:1000] or decision["rationale"],
                requested_by=actor[:64],
                approved_by=None,
                approved_at=None,
                expires_at=iso(now + timedelta(minutes=ttl)) if ttl else None,
                applied_at=None,
                rolled_back_at=None,
                rollback_detail=None,
                confidence=decision["inputs"]["confidence"],
                campaign_id=campaign_id,
            )
        )
    return get_response(response_id)


def approve_response(response_id: str, *, actor: str) -> dict[str, Any]:
    record = get_response(response_id)
    if record["status"] != "pending_approval":
        raise Conflict(f"response is {record['status']} and cannot be approved")
    now = utcnow()
    if not record.get("expires_at") or record["expires_at"] <= iso(now):
        raise PolicyDenied("this response request has expired")

    # Claim the approval atomically. Two analysts clicking approve at the same
    # time must not both invoke the execution adapter.
    with connection() as conn:
        claimed = conn.execute(
            responses.update()
            .where(
                responses.c.id == response_id,
                responses.c.status == "pending_approval",
                responses.c.expires_at > iso(now),
            )
            .values(
                status="applying",
                approved_by=actor[:64],
                approved_at=iso(now),
            )
        )
    if claimed.rowcount != 1:
        raise Conflict("response is no longer pending approval")

    try:
        result = ADAPTER.apply(target=record["target"], params=loads(record["params"], {}))
    except Exception:
        with connection() as conn:
            conn.execute(
                responses.update()
                .where(responses.c.id == response_id, responses.c.status == "applying")
                .values(status="pending_approval", approved_by=None, approved_at=None)
            )
        raise

    with connection() as conn:
        conn.execute(
            responses.update()
            .where(responses.c.id == response_id, responses.c.status == "applying")
            .values(
                status="applied",
                applied_at=iso(now),
                rollback_detail=dumps({"apply": result}),
            )
        )
    log.info(
        "response applied",
        extra={"response_id": response_id, "action": record["action"], "target": record["target"]},
    )
    return get_response(response_id)


def rollback_response(response_id: str, *, actor: str) -> dict[str, Any]:
    record = get_response(response_id)
    if record["status"] != "applied":
        raise Conflict(f"response is {record['status']} and cannot be rolled back")
    with connection() as conn:
        claimed = conn.execute(
            responses.update()
            .where(responses.c.id == response_id, responses.c.status == "applied")
            .values(status="rolling_back")
        )
    if claimed.rowcount != 1:
        raise Conflict("response is no longer in an applied state")

    try:
        result = ADAPTER.remove(target=record["target"], params=loads(record["params"], {}))
    except Exception:
        with connection() as conn:
            conn.execute(
                responses.update()
                .where(responses.c.id == response_id, responses.c.status == "rolling_back")
                .values(status="applied")
            )
        raise

    now = utcnow()
    with connection() as conn:
        conn.execute(
            responses.update()
            .where(responses.c.id == response_id, responses.c.status == "rolling_back")
            .values(
                status="rolled_back",
                rolled_back_at=iso(now),
                rollback_detail=dumps(
                    {"apply": loads(record.get("rollback_detail"), {}).get("apply"), "remove": result}
                ),
            )
        )
    return get_response(response_id)


def expire_due() -> int:
    now = iso(utcnow())
    with connection() as conn:
        rows = conn.execute(
            text(
                "SELECT id, target, params FROM responses "
                "WHERE status = 'applied' AND expires_at IS NOT NULL AND expires_at < :now"
            ),
            {"now": now},
        ).fetchall()
    count = 0
    for response_id, target, params in rows:
        result = ADAPTER.remove(target=target, params=loads(params, {}))
        with connection() as conn:
            conn.execute(
                responses.update()
                .where(responses.c.id == response_id)
                .values(
                    status="expired",
                    rolled_back_at=iso(utcnow()),
                    rollback_detail=dumps({"reason": "expired", "remove": result}),
                )
            )
        count += 1
    return count


def disable_all(*, actor: str) -> int:
    """Emergency rollback of every applied rule."""
    expire_due()
    with connection() as conn:
        rows = conn.execute(
            text("SELECT id FROM responses WHERE status = 'applied'")
        ).fetchall()
    count = 0
    for (response_id,) in rows:
        record = get_response(response_id)
        ADAPTER.remove(target=record["target"], params=loads(record["params"], {}))
        with connection() as conn:
            conn.execute(
                responses.update()
                .where(responses.c.id == response_id)
                .values(
                    status="rolled_back",
                    rolled_back_at=iso(utcnow()),
                    rollback_detail=dumps({"reason": f"emergency disable by {actor}"}),
                )
            )
        count += 1
    log.warning("emergency response disable executed", extra={"actor": actor, "count": count})
    return count


def get_response(response_id: str) -> dict[str, Any]:
    with connection() as conn:
        row = conn.execute(select(responses).where(responses.c.id == response_id)).fetchone()
    if not row:
        raise NotFound("response not found")
    data = dict(row._mapping)
    data["params"] = loads(data["params"], {})
    data["rollback_detail"] = loads(data.get("rollback_detail"), None)
    return data


def list_responses(*, limit: int = 100, status: str | None = None) -> list[dict[str, Any]]:
    expire_due()
    clauses = ["1 = 1"]
    params: dict[str, Any] = {"limit": limit}
    if status:
        clauses.append("status = :status")
        params["status"] = status
    with connection() as conn:
        rows = conn.execute(
            text(
                "SELECT * FROM responses WHERE " + " AND ".join(clauses) +
                " ORDER BY created_at DESC LIMIT :limit"
            ),
            params,
        ).fetchall()
    result = []
    for row in rows:
        data = dict(row._mapping)
        data["params"] = loads(data["params"], {})
        data["rollback_detail"] = loads(data.get("rollback_detail"), None)
        result.append(data)
    return result


def policy_document() -> dict[str, Any]:
    from .policy import APPLY_MIN_CONFIDENCE, APPLY_MIN_RISK, POLICIES

    return {
        "version": POLICY_VERSION,
        "rules": POLICIES,
        "apply_requires": {
            "confidence": APPLY_MIN_CONFIDENCE,
            "risk_score": APPLY_MIN_RISK,
            "observed_target": True,
            "administrator_approval": True,
        },
        "adapter": {
            "name": ADAPTER.name,
            "enforced": False,
            "note": (
                "The shipped adapter records intent only. Wire a reviewed edge "
                "controller behind FirewallAdapter to enforce rules."
            ),
        },
        "auto_apply": get_settings().response_auto_apply,
        "rollback": "available for every applied rule; expiry is enforced on read",
    }
