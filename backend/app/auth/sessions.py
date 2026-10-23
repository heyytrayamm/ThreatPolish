"""Per-account session history and single-session revocation.

The platform does not log every request a token is used for: that would turn the
audit trail into a browsing record and grow without bound.  What it does record
is every credential event for an account — sign-ins, password changes and
revocations — together with the client address, the token identifier and the
session version in force at the time.  Comparing that version with the account's
current version says whether a token is still usable; the identifier says which
token it was, so one device can be signed out on its own.

Revoked identifiers are kept in `revoked_sessions` until they would have expired
anyway, which is the only state a stateless token needs in order to be
individually revocable.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from ..core.audit import parse_detail
from ..core.errors import NotFound, ValidationFailure
from ..core.security import iso, parse_iso, utcnow
from ..db.database import connection
from ..db.schema import revoked_sessions

SIGN_IN = "auth.login"
CHANGE_PASSWORD = "auth.password.change"
REVOKE_SESSIONS = "auth.sessions.revoke"
REVOKE_SESSION = "auth.session.revoke"

EVENT_NAMES = {
    SIGN_IN: "sign_in",
    CHANGE_PASSWORD: "password_changed",
    REVOKE_SESSIONS: "sessions_revoked",
    REVOKE_SESSION: "session_revoked",
}

NOTE = (
    "Sign-ins and credential changes recorded for this account. Individual "
    "requests are not logged; a token stays usable until its version is revoked, "
    "its session is signed out, or it expires."
)


def session_history(
    user_id: str,
    *,
    current_version: int,
    ttl_minutes: int,
    limit: int = 20,
    current_jti: str | None = None,
) -> list[dict[str, Any]]:
    with connection() as conn:
        rows = conn.execute(
            text(
                "SELECT id, ts, action, request_ip, outcome, detail FROM audit_log "
                "WHERE actor_id = :actor "
                "AND action IN (:sign_in, :change_password, :revoke, :revoke_one) "
                "ORDER BY ts DESC, id DESC LIMIT :limit"
            ),
            {
                "actor": user_id,
                "sign_in": SIGN_IN,
                "change_password": CHANGE_PASSWORD,
                "revoke": REVOKE_SESSIONS,
                "revoke_one": REVOKE_SESSION,
                "limit": max(1, min(100, limit)),
            },
        ).fetchall()
        revoked = {
            row[0]
            for row in conn.execute(
                text(
                    "SELECT jti FROM revoked_sessions "
                    "WHERE user_id = :actor AND expires_at > :now"
                ),
                {"actor": user_id, "now": iso(utcnow())},
            ).fetchall()
        }

    now = utcnow()
    history: list[dict[str, Any]] = []
    for audit_id, ts, action, request_ip, outcome, raw_detail in rows:
        detail = parse_detail(raw_detail)
        version = detail.get("session_version")
        jti = detail.get("jti")
        entry: dict[str, Any] = {
            "id": audit_id,
            "occurred_at": ts,
            "event": EVENT_NAMES.get(action, action),
            "ip": request_ip,
            "client": detail.get("client"),
            "outcome": outcome,
            "session_version": version if isinstance(version, int) else None,
            "jti": jti if isinstance(jti, str) else None,
            "current": bool(current_jti and jti == current_jti),
        }
        if action == SIGN_IN:
            state = _sign_in_state(ts, version, current_version, ttl_minutes, now)
            if isinstance(jti, str) and jti in revoked:
                state = "revoked"
            entry["state"] = state
            entry["expires_at"] = (
                expiry_for(ts, ttl_minutes) if state in {"active", "expired"} else None
            )
            anomaly = detail.get("anomaly")
            entry["anomaly"] = anomaly if isinstance(anomaly, dict) else None
        elif action == REVOKE_SESSION:
            entry["revoked_jti"] = detail.get("jti")
        history.append(entry)
    return history


def revoke_session(user_id: str, jti: str, *, ttl_minutes: int) -> str:
    """Sign one device out without touching the account's other sessions."""
    if not jti:
        raise ValidationFailure("a session identifier is required")
    now = utcnow()
    try:
        with connection() as conn:
            owned = any(
                parse_detail(raw_detail).get("jti") == jti
                for (raw_detail,) in conn.execute(
                    text(
                        "SELECT detail FROM audit_log WHERE actor_id = :actor "
                        "AND action = :action ORDER BY ts DESC LIMIT 50"
                    ),
                    {"actor": user_id, "action": SIGN_IN},
                ).fetchall()
            )
            if not owned:
                raise NotFound("session not found")
            # Keep the table bounded: a revoked identifier is only interesting
            # until the token carrying it would have expired anyway.
            conn.execute(
                text("DELETE FROM revoked_sessions WHERE expires_at < :now"),
                {"now": iso(now)},
            )
            conn.execute(
                revoked_sessions.insert().values(
                    jti=jti,
                    user_id=user_id,
                    revoked_at=iso(now),
                    expires_at=iso(now + timedelta(minutes=ttl_minutes)),
                    reason="user_request",
                )
            )
    except IntegrityError:
        # Already revoked; the result is the same.
        pass
    return jti


def session_is_revoked(jti: str) -> bool:
    with connection() as conn:
        row = conn.execute(
            text(
                "SELECT 1 FROM revoked_sessions WHERE jti = :jti AND expires_at > :now"
            ),
            {"jti": jti, "now": iso(utcnow())},
        ).fetchone()
    return row is not None


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
