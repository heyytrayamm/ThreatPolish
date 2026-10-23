"""Authorized assessment scopes.

A target may only be assessed when an unexpired scope covers its hostname and
the hostname resolves exclusively to public addresses.  The loopback escape
hatch exists for local test environments and is disabled by default.
"""

from __future__ import annotations

import ipaddress
import socket
from datetime import timedelta
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import select

from ..core.config import get_settings
from ..core.errors import AuthorizationFailure, Conflict, NotFound, ValidationFailure
from ..core.security import iso, new_id, utcnow
from ..db.database import connection, loads
from ..db.schema import watch_scopes


def normalize_domain(value: str) -> str:
    raw = value.strip().lower()
    if "://" in raw:
        parts = urlsplit(raw)
        raw = parts.hostname or ""
    raw = raw.split("/", 1)[0].split(":", 1)[0].strip(".")
    if not raw or len(raw) > 253:
        raise ValidationFailure("invalid domain")
    try:
        ipaddress.ip_address(raw)
        return raw
    except ValueError:
        pass
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-.")
    if not set(raw) <= allowed or ".." in raw or raw.startswith("-") or raw.endswith("-"):
        raise ValidationFailure("invalid domain")
    if "." not in raw:
        raise ValidationFailure("domain must be qualified")
    return raw


def create_scope(
    *,
    domain: str,
    authorized_by: str,
    expires_in_days: int = 7,
    allow_active: bool = False,
    notes: str = "",
    actor: str | None = None,
) -> dict[str, Any]:
    normalized = normalize_domain(domain)
    if not authorized_by.strip():
        raise ValidationFailure("authorized_by is required: record who approved the assessment")
    now = utcnow()
    scope_id = new_id("scp")
    try:
        with connection() as conn:
            conn.execute(
                watch_scopes.insert().values(
                    id=scope_id,
                    domain=normalized,
                    authorized_by=authorized_by.strip()[:200],
                    authorized_at=iso(now),
                    expires_at=iso(now + timedelta(days=expires_in_days)),
                    allow_active=1 if allow_active else 0,
                    notes=notes[:2000],
                )
            )
    except Exception as exc:  # noqa: BLE001
        if "UNIQUE" in str(exc).upper() or "unique" in str(exc):
            raise Conflict("an authorization already exists for this domain") from exc
        raise
    return get_scope_by_domain(normalized)


def get_scope_by_domain(domain: str) -> dict[str, Any]:
    with connection() as conn:
        row = conn.execute(
            select(watch_scopes).where(watch_scopes.c.domain == domain)
        ).fetchone()
    if not row:
        raise NotFound("authorization scope not found")
    data = dict(row._mapping)
    data["allow_active"] = bool(data["allow_active"])
    return data


def list_scopes() -> list[dict[str, Any]]:
    with connection() as conn:
        rows = conn.execute(select(watch_scopes).order_by(watch_scopes.c.authorized_at.desc())).fetchall()
    result = []
    for row in rows:
        data = dict(row._mapping)
        data["allow_active"] = bool(data["allow_active"])
        data["expired"] = data["expires_at"] <= iso(utcnow())
        result.append(data)
    return result


def find_active_scope(host: str) -> dict[str, Any]:
    normalized = normalize_domain(host)
    now = iso(utcnow())
    with connection() as conn:
        rows = conn.execute(select(watch_scopes)).fetchall()
    for row in rows:
        domain = row.domain
        if normalized == domain or normalized.endswith("." + domain):
            if row.expires_at <= now:
                continue
            data = dict(row._mapping)
            data["allow_active"] = bool(data["allow_active"])
            return data
    raise AuthorizationFailure(
        "no active assessment authorization covers this host",
        details={"host": normalized, "hint": "create a scope with an explicit authorizer first"},
    )


def validate_target(target: str, *, allow_active: bool) -> tuple[str, str, str]:
    """Return (host, url, scheme) after authorization and SSRF checks."""
    raw = target.strip()
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlsplit(raw)
    if parsed.scheme not in {"http", "https"}:
        raise ValidationFailure("only http and https targets are supported")
    if parsed.username or parsed.password:
        raise ValidationFailure("credentials in target URLs are not allowed")
    if not parsed.hostname:
        raise ValidationFailure("target hostname is required")
    host = parsed.hostname.lower()
    port = parsed.port
    if port is not None and not (1 <= port <= 65535):
        raise ValidationFailure("target port is outside the valid range")

    scope = find_active_scope(host)
    if allow_active and not scope["allow_active"]:
        raise AuthorizationFailure(
            "active checks are not authorized for this scope",
            details={"scope_id": scope["id"]},
        )
    _assert_public_host(host)
    url = f"{parsed.scheme}://{host}" + (f":{port}" if port else "") + (parsed.path or "/")
    return host, url, parsed.scheme


def _assert_public_host(host: str) -> None:
    settings = get_settings()
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise ValidationFailure(f"target hostname did not resolve: {host}") from exc
    addresses = {info[4][0] for info in infos}
    if not addresses:
        raise ValidationFailure("target hostname did not resolve")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if settings.websec_allow_loopback and ip.is_loopback:
            # Local test environments only; private and link-local ranges stay blocked.
            continue
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            raise AuthorizationFailure(
                "target resolves to a non-public address; refusing to connect",
                details={"host": host, "address": str(ip)},
            )


def parse_expires(raw: str) -> Any:
    return loads(raw, raw)
