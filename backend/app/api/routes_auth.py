"""Authentication and account administration."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from ..auth.rbac import Principal, all_roles
from ..auth.users import (
    authenticate,
    change_password,
    create_agent_token,
    create_user,
    list_agent_tokens,
    list_users,
    revoke_agent_token,
)
from ..core.audit import audit_standalone
from ..core.config import get_settings
from ..core.errors import AuthenticationFailure, RateLimited
from ..core.security import create_access_token
from ..schemas.api import (
    AgentTokenCreateRequest,
    LoginRequest,
    PasswordChangeRequest,
    UserCreateRequest,
)
from .deps import client_ip, get_principal, login_limiter, require

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login")
def login(payload: LoginRequest, request: Request) -> dict[str, object]:
    ip = client_ip(request)
    allowed, retry_after = login_limiter().allow(f"login:{ip}:{payload.email.lower()}")
    if not allowed:
        raise RateLimited("too many login attempts", details={"retry_after_seconds": retry_after})
    try:
        user = authenticate(payload.email, payload.password)
    except AuthenticationFailure:
        audit_standalone(
            action="auth.login",
            outcome="failure",
            object_type="user",
            object_id=payload.email.lower()[:64],
            detail={"reason": "invalid_credentials"},
            request_ip=ip,
        )
        raise
    token, expires_at = create_access_token(
        subject=user["id"],
        role=user["role"],
        secret=get_settings().jwt_secret,
        ttl_minutes=get_settings().jwt_ttl_minutes,
    )
    audit_standalone(
        action="auth.login",
        outcome="success",
        actor_id=user["id"],
        actor_role=user["role"],
        object_type="user",
        object_id=user["id"],
        request_ip=ip,
    )
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_at": expires_at.isoformat(),
        "user": user,
    }


@router.get("/me")
def me(principal: Principal = Depends(get_principal)) -> dict[str, object]:
    return {
        "id": principal.user_id,
        "name": principal.name,
        "email": principal.email,
        "role": principal.role,
        "via": principal.via,
    }


@router.get("/roles")
def roles(principal: Principal = Depends(require("events:read"))) -> dict[str, object]:
    return {"roles": list(all_roles())}


@router.get("/users")
def users(principal: Principal = Depends(require("users:manage"))) -> dict[str, object]:
    return {"users": list_users()}


@router.post("/users", status_code=201)
def add_user(payload: UserCreateRequest, principal: Principal = Depends(require("users:manage"))) -> dict[str, object]:
    user = create_user(
        email=payload.email, name=payload.name, role=payload.role, password=payload.password
    )
    audit_standalone(
        action="auth.user.create",
        actor_id=principal.user_id,
        actor_role=principal.role,
        object_type="user",
        object_id=user["id"],
        detail={"role": user["role"], "email": user["email"]},
    )
    return user


@router.post("/password")
def update_password(
    payload: PasswordChangeRequest, principal: Principal = Depends(get_principal)
) -> dict[str, str]:
    if principal.is_agent:
        raise AuthenticationFailure("agent tokens cannot change passwords")
    current = authenticate(principal.email, payload.current_password)
    change_password(current["id"], payload.new_password)
    audit_standalone(
        action="auth.password.change",
        actor_id=principal.user_id,
        actor_role=principal.role,
        object_type="user",
        object_id=principal.user_id,
    )
    return {"status": "changed"}


@router.get("/tokens")
def tokens(principal: Principal = Depends(require("tokens:manage"))) -> dict[str, object]:
    return {"tokens": list_agent_tokens()}


@router.post("/tokens", status_code=201)
def add_token(
    payload: AgentTokenCreateRequest, principal: Principal = Depends(require("tokens:manage"))
) -> dict[str, object]:
    token = create_agent_token(name=payload.name, role=payload.role)
    audit_standalone(
        action="auth.token.create",
        actor_id=principal.user_id,
        actor_role=principal.role,
        object_type="agent_token",
        object_id=token["id"],
        detail={"name": payload.name, "role": payload.role},
    )
    return token


@router.delete("/tokens/{token_id}")
def delete_token(token_id: str, principal: Principal = Depends(require("tokens:manage"))) -> dict[str, str]:
    revoke_agent_token(token_id)
    audit_standalone(
        action="auth.token.revoke",
        actor_id=principal.user_id,
        actor_role=principal.role,
        object_type="agent_token",
        object_id=token_id,
    )
    return {"status": "revoked"}
