"""Per-account session history.

The platform does not log every request a token is used for: that would turn the
audit trail into a browsing record and grow without bound.  What it does record
is every credential event for an account — sign-ins, password changes and
administrative revocations — together with the client address and the session
version in force at the time.  Comparing that version with the account's current
version is enough to say whether a sign-in is still usable, because a token is
refused as soon as its version falls behind.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy import text

from ..core.audit import parse_detail
from ..core.security import iso, parse_iso, utcnow
from ..db.database import connection

SIGN_IN = "auth.login"
CHANGE_PASSWORD = "auth.password.change"
REVOKE_SESSIONS = "auth.sessions.revoke"

EVENT_NAMES = {
    SIGN_IN: "sign_in",
    CHANGE_PASSWORD: "password_changed",
    REVOKE_SESSIONS: "sessions_revoked",
}

NOTE = (
    "Sign-ins and credential changes recorded for this account. Individual "
    "requests are not logged; a token stays usable until its version is revoked "
    "or it expires."
)


def session_history(
    user_id: str, *, current_version: int, ttl_minutes: int, limit: int = 20
) -> list[dict[str, Any]]:
    with connection() as conn:
        rows = conn.execute(
            text(
                "SELECT id, ts, action, request_ip, outcome, detail FROM audit_log "
                "WHERE actor_id = :actor "
                "AND action IN (:sign_in, :change_password, :revoke) "
                "ORDER BY ts DESC, id DESC LIMIT :limit"
            ),
            {
                "actor": user_id,
                "sign_in": SIGN_IN,
                "change_password": CHANGE_PASSWORD,
                "revoke": REVOKE_SESSIONS,
                "limit": max(1, min(100, limit)),
            },
        ).fetchall()

    now = utcnow()
    history: list[dict[str, Any]] = []
    for audit_id, ts, action, request_ip, outcome, raw_detail in rows:
        detail = parse_detail(raw_detail)
        version = detail.get("session_version")
        entry: dict[str, Any] = {
            "id": audit_id,
            "occurred_at": ts,
            "event": EVENT_NAMES.get(action, action),
            "ip": request_ip,
            "client": detail.get("client"),
            "outcome": outcome,
            "session_version": version if isinstance(version, int) else None,
        }
        if action == SIGN_IN:
            entry["state"] = _sign_in_state(ts, version, current_version, ttl_minutes, now)
            entry["expires_at"] = (
                expiry_for(ts, ttl_minutes)
                if entry["state"] in {"active", "expired"}
                else None
            )
        history.append(entry)
    return history


def _sign_in_state(
    occurred_at: str,
    version: Any,
    current_version: int,
    ttl_minutes: int,
    now: Any,
) -> str:
    if not isinstance(version, int):
        # Sign-ins recorded before session versions existed cannot be judged.
        return "unknown"
    if version != current_version:
        return "revoked"
    try:
        expires = parse_iso(occurred_at) + timedelta(minutes=ttl_minutes)
    except ValueError:
        return "unknown"
    return "expired" if expires <= now else "active"


def expiry_for(occurred_at: str, ttl_minutes: int) -> str | None:
    """Expose the derived expiry so callers can show it without duplicating rules."""
    try:
        return iso(parse_iso(occurred_at) + timedelta(minutes=ttl_minutes))
    except ValueError:
        return None
