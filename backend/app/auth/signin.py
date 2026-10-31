"""Sign-in anomaly detection.

A credential cannot be in two places at once.  When an account signs in from a
different network while an earlier session is still valid, either the analyst
moved or someone else has the token.  The check runs at sign-in time, compares
against earlier sign-ins inside a short window and records the finding on the
sign-in itself.

Distance is only reported when `TP_GEO_API_URL` is configured; without location
data the alert says "new network", which is what the platform can actually
observe.  Calling a network change "impossible travel" without coordinates would
be an invented signal.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from ..core.audit import parse_detail
from ..core.config import Settings, get_settings
from ..core.logging import get_logger
from ..core.security import iso, utcnow
from ..db.database import connection
from .geo import distance_km, locate, network_of, parse_address, same_network

log = get_logger(__name__)

RECENT_SIGN_INS = (
    "SELECT ts, request_ip, detail FROM audit_log "
    "WHERE actor_id = :actor AND action = 'auth.login' AND outcome = 'success' "
    "AND ts >= :since ORDER BY ts DESC LIMIT 20"
)


def detect_signin_anomaly(
    *,
    user_id: str,
    ip: str,
    session_version: int,
    now: datetime | None = None,
) -> dict[str, Any] | None:
    """Return an alert when this sign-in joins a session from another network."""
    if parse_address(ip) is None:
        return None
    settings = get_settings()
    moment = now or utcnow()
    since = iso(moment - timedelta(minutes=settings.signin_alert_window_minutes))

    try:
        with connection() as conn:
            rows = conn.execute(
                text(RECENT_SIGN_INS), {"actor": user_id, "since": since}
            ).fetchall()
    except SQLAlchemyError as exc:
        # Detection must never block a legitimate sign-in.
        log.warning("sign-in anomaly lookup failed", extra={"error": str(exc)})
        return None

    for previous_at, previous_ip, raw_detail in rows:
        if parse_address(previous_ip) is None:
            # A test client or Unix socket has no address to compare against.
            continue
        detail = parse_detail(raw_detail)
        if detail.get("session_version") != session_version:
            # A revoked or older session is not a parallel session.
            continue
        if same_network(ip, previous_ip):
            continue
        alert = _compare(ip, previous_ip, previous_at, moment, settings)
        if alert:
            return alert
    return None


def _compare(
    ip: str,
    previous_ip: str | None,
    previous_at: str,
    moment: datetime,
    settings: Settings,
) -> dict[str, Any] | None:
    base = {
        "previous_ip": previous_ip,
        "previous_at": previous_at,
        "detected_at": iso(moment),
        "window_minutes": settings.signin_alert_window_minutes,
    }
    if settings.geo_api_url:
        here = locate(
            ip,
            url=settings.geo_api_url,
            token=settings.geo_api_token,
            timeout=settings.geo_timeout_seconds,
        )
        there = locate(
            previous_ip,
            url=settings.geo_api_url,
            token=settings.geo_api_token,
            timeout=settings.geo_timeout_seconds,
        )
        if here and there:
            distance = round(distance_km(here, there))
            if distance < settings.signin_alert_distance_km:
                # Same neighbourhood, for example a second ISP in one city.
                return None
            return {
                "kind": "distant_signin",
                "distance_km": distance,
                "threshold_km": settings.signin_alert_distance_km,
                **base,
            }
    network = network_of(ip)
    return {
        "kind": "new_network",
        "network": str(network) if network else None,
        **base,
    }
