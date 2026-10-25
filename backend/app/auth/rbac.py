"""Role-based access control.

Least privilege is the default: a viewer can read, a sensor can only ingest, and
only analysts and administrators can create or change investigations,
assessments and responses.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from ..core.errors import AuthorizationFailure

ROLES: dict[str, frozenset[str]] = {
    "admin": frozenset({"*"}),
    "analyst": frozenset(
        {
            "events:read",
            "graph:read",
            "campaigns:read",
            "campaigns:write",
            "correlate:run",
            "feedback:write",
            "findings:read",
            "findings:scan",
            "crypto:read",
            "crypto:refresh",
            "honeypot:read",
            "honeypot:write",
            "investigations:write",
            "responses:read",
            "responses:request",
            "scopes:read",
            "sources:read",
            "risk:read",
            "retention:read",
        }
    ),
    "viewer": frozenset(
        {
            "events:read",
            "graph:read",
            "campaigns:read",
            "findings:read",
            "crypto:read",
            "honeypot:read",
            "responses:read",
            "scopes:read",
            "sources:read",
            "risk:read",
        }
    ),
    "sensor": frozenset({"ingest:write", "honeypot:read", "sources:read"}),
}


@dataclass(frozen=True)
class Principal:
    user_id: str
    role: str
    name: str
    email: str
    via: str  # "session" or "agent_token"
    jti: str | None = None

    @property
    def is_agent(self) -> bool:
        return self.via == "agent_token"


def permissions_for(role: str) -> frozenset[str]:
    return ROLES.get(role, frozenset())


def has_permission(role: str, permission: str) -> bool:
    granted = permissions_for(role)
    return "*" in granted or permission in granted


def require_permission(principal: Principal, permission: str) -> None:
    if not has_permission(principal.role, permission):
        raise AuthorizationFailure(
            f"role '{principal.role}' is not permitted to perform '{permission}'",
            details={"required_permission": permission, "role": principal.role},
        )


def validate_role(role: str) -> str:
    if role not in ROLES:
        raise AuthorizationFailure(
            f"unknown role '{role}'", details={"allowed": sorted(ROLES)}
        )
    return role


def all_roles() -> Iterable[str]:
    return sorted(ROLES)
