"""FastAPI dependencies: authentication, authorization and rate limiting."""

from __future__ import annotations

from functools import lru_cache
from typing import Callable

from fastapi import Depends, Header, Request

from ..auth.rbac import Principal, require_permission
from ..auth.users import get_user, resolve_agent_token
from ..core.config import get_settings
from ..core.errors import AuthenticationFailure
from ..core.limits import SlidingWindowLimiter
from ..core.security import decode_access_token


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def get_principal(
    request: Request,
    authorization: str | None = Header(default=None),
    x_agent_token: str | None = Header(default=None),
) -> Principal:
    if authorization:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise AuthenticationFailure("expected 'Authorization: Bearer <token>'")
        payload = decode_access_token(token.strip(), secret=get_settings().jwt_secret)
        user_id = str(payload.get("sub", ""))
        user = get_user(user_id)
        if not user["is_active"]:
            raise AuthenticationFailure("account is disabled")
        return Principal(
            user_id=user["id"],
            role=user["role"],
            name=user["name"],
            email=user["email"],
            via="session",
        )

    if x_agent_token:
        record = resolve_agent_token(x_agent_token)
        if not record:
            raise AuthenticationFailure("invalid or revoked agent token")
        return Principal(
            user_id=record["id"],
            role=record["role"],
            name=record["name"],
            email="",
            via="agent_token",
        )

    raise AuthenticationFailure("authentication required")


def require(permission: str) -> Callable[..., Principal]:
    def dependency(principal: Principal = Depends(get_principal)) -> Principal:
        require_permission(principal, permission)
        return principal

    return dependency


@lru_cache(maxsize=1)
def ingest_limiter() -> SlidingWindowLimiter:
    settings = get_settings()
    return SlidingWindowLimiter(settings.ingest_rate_limit_per_minute, 60.0)


@lru_cache(maxsize=1)
def login_limiter() -> SlidingWindowLimiter:
    return SlidingWindowLimiter(10, 60.0, max_keys=10_000)


@lru_cache(maxsize=1)
def decoy_limiter() -> SlidingWindowLimiter:
    return SlidingWindowLimiter(get_settings().decoy_max_sessions_per_hour, 3600.0)
