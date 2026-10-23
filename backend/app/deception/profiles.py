"""Approved decoy profiles.

Profiles are declarative data: banners, headers, page bodies and endpoint lists.
Nothing in a profile is executable, so switching profiles can never turn the
decoy into a code-execution surface.  Only these seeded profiles may be
selected by the adaptive investigation engine.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select

from ..core.security import iso, new_id, utcnow
from ..db.database import connection, dumps, loads
from ..db.schema import decoy_profiles

DEFAULT_PROFILES: list[dict[str, Any]] = [
    {
        "name": "ssh-bastion",
        "kind": "ssh",
        "description": "OpenSSH bastion host banner with a small, plausible credential surface.",
        "is_default": True,
        "config": {
            "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
            "hostname": "bastion-prod-01",
            "max_auth_attempts": 4,
            "fake_users": ["deploy", "ubuntu", "backup", "admin"],
            "motd": "Authorized access only. Activity is monitored.",
        },
    },
    {
        "name": "http-wordpress",
        "kind": "http",
        "description": "WordPress-style login page that records credential attempts.",
        "is_default": False,
        "config": {
            "server": "nginx/1.24.0",
            "title": "Sign In \u2039 Corporate Site",
            "theme": "wordpress",
            "login_path": "/wp-login.php",
            "probe_paths": ["/wp-admin/", "/xmlrpc.php", "/wp-config.php.bak", "/.env"],
        },
    },
    {
        "name": "http-api-gateway",
        "kind": "http",
        "description": "Internal JSON API gateway exposing decoy metadata endpoints.",
        "is_default": False,
        "config": {
            "server": "envoy",
            "title": "Service API",
            "theme": "api",
            "login_path": "/api/v1/auth/token",
            "probe_paths": ["/api/v1/health", "/api/v1/users", "/metrics", "/.git/HEAD"],
        },
    },
    {
        "name": "http-admin-console",
        "kind": "http",
        "description": "Administrative console decoy for credential-stuffing and probe traffic.",
        "is_default": False,
        "config": {
            "server": "Apache/2.4.58",
            "title": "Operations Console",
            "theme": "console",
            "login_path": "/login",
            "probe_paths": ["/admin", "/console", "/actuator/env", "/server-status"],
        },
    },
]


def seed_default_profiles() -> int:
    created = 0
    now = iso(utcnow())
    with connection() as conn:
        existing = {
            row[0] for row in conn.execute(select(decoy_profiles.c.name)).fetchall()
        }
        for profile in DEFAULT_PROFILES:
            if profile["name"] in existing:
                continue
            conn.execute(
                decoy_profiles.insert().values(
                    id=new_id("dpr"),
                    name=profile["name"],
                    kind=profile["kind"],
                    description=profile["description"],
                    config=dumps(profile["config"]),
                    enabled=1,
                    is_default=1 if profile["is_default"] else 0,
                    created_at=now,
                )
            )
            created += 1
    return created


def list_profiles(*, enabled_only: bool = False) -> list[dict[str, Any]]:
    with connection() as conn:
        rows = conn.execute(select(decoy_profiles).order_by(decoy_profiles.c.name)).fetchall()
    profiles = []
    for row in rows:
        if enabled_only and not row.enabled:
            continue
        profiles.append(
            {
                "id": row.id,
                "name": row.name,
                "kind": row.kind,
                "description": row.description,
                "config": loads(row.config, {}),
                "enabled": bool(row.enabled),
                "is_default": bool(row.is_default),
            }
        )
    return profiles


def get_profile(name: str) -> dict[str, Any] | None:
    with connection() as conn:
        row = conn.execute(
            select(decoy_profiles).where(decoy_profiles.c.name == name)
        ).fetchone()
    if not row:
        return None
    return {
        "id": row.id,
        "name": row.name,
        "kind": row.kind,
        "description": row.description,
        "config": loads(row.config, {}),
        "enabled": bool(row.enabled),
        "is_default": bool(row.is_default),
    }


def default_http_profile() -> dict[str, Any]:
    profiles = [p for p in list_profiles(enabled_only=True) if p["kind"] == "http"]
    for profile in profiles:
        if profile["is_default"]:
            return profile
    return profiles[0] if profiles else {
        "name": "http-wordpress",
        "kind": "http",
        "config": DEFAULT_PROFILES[1]["config"],
    }


def set_enabled(name: str, enabled: bool) -> bool:
    with connection() as conn:
        result = conn.execute(
            decoy_profiles.update()
            .where(decoy_profiles.c.name == name)
            .values(enabled=1 if enabled else 0)
        )
        return bool(result.rowcount)
