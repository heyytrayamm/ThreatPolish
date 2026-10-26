"""Authentication and account administration."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from ..auth.rbac import Principal, all_roles
from ..auth.sessions import NOTE as SESSION_NOTE
from ..auth.sessions import revoke_session, session_history
from ..auth.signin import detect_signin_anomaly
from ..auth.users import (
    authenticate,
    change_password,
    create_agent_token,
    create_user,
    get_user_with_session,
    list_agent_tokens,
    list_users,
    revoke_agent_token,
    revoke_sessions,
    verify_credentials,
)
from ..core.audit import audit_standalone
from ..core.config import get_settings
from ..core.errors import AuthenticationFailure, RateLimited
from ..core.security import create_access_token, new_id
from ..schemas.api import (
    AgentTokenCreateRequest,
    LoginRequest,
    PasswordChangeRequest,
    UserCreateRequest,
)
from .deps import client_ip, get_principal, login_ip_limiter, login_limiter, require

router = APIRouter(prefix="/auth", tags=["auth"])


def _client_label(user_agent: str | None) -> str:
    """Short printable description of the signing-in client for the history."""
    if not user_agent:
        return "unknown"
    printable = "".join(char for char in user_agent if char.isprintable())
    return " ".join(printable.split())[:120] or "unknown"


@router.post("/login")
def login(payload: LoginRequest, request: Request) -> dict[str, object]:
    ip = client_ip(request)
    # Check the address budget first: it is the only bucket an attacker cannot
    # avoid by choosing a new email address for every attempt.
    allowed, retry_after = login_ip_limiter().allow(f"ip:{ip}")
    if not allowed:
        raise RateLimited(
            "too many login attempts from this address",
            details={"retry_after_seconds": retry_after},
        )
    allowed, retry_after = login_limiter().allow(f"login:{ip}:{payload.email.strip().lower()}")
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
    session_version = get_user_with_session(user["id"])[1]
    anomaly = detect_signin_anomaly(
        user_id=user["id"], ip=ip, session_version=session_version
    )
    jti = new_id("jti")
    token, expires_at = create_access_token(
        subject=user["id"],
        role=user["role"],
        secret=get_settings().jwt_secret,
        ttl_minutes=get_settings().jwt_ttl_minutes,
        token_version=session_version,
        token_id=jti,
    )
    audit_standalone(
        action="auth.login",
        outcome="success",
        actor_id=user["id"],
        actor_role=user["role"],
        object_type="user",
        object_id=user["id"],
        request_ip=ip,
        detail={
            "session_version": session_version,
            "jti": jti,
            "client": _client_label(request.headers.get("user-agent")),
            **({"anomaly": anomaly} if anomaly else {}),
        },
    )
    if anomaly:
        # A separate entry makes the alert findable in the audit trail without
        # changing the meaning of the sign-in record itself.
        audit_standalone(
            action="auth.signin.anomaly",
            outcome="alert",
            actor_id=user["id"],
            actor_role=user["role"],
            object_type="user",
            object_id=user["id"],
            request_ip=ip,
            detail=anomaly,
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


def _session_payload(user_id: str, limit: int, current_jti: str | None = None) -> dict[str, object]:
    _, current_version = get_user_with_session(user_id)
    return {
        "user_id": user_id,
        "sessions": session_history(
            user_id,
            current_version=current_version,
            ttl_minutes=get_settings().jwt_ttl_minutes,
            limit=limit,
            current_jti=current_jti,
        ),
        "current_session_version": current_version,
        "note": SESSION_NOTE,
    }


@router.get("/sessions")
def own_sessions(
    limit: int = 20, principal: Principal = Depends(get_principal)
) -> dict[str, object]:
    if principal.is_agent:
        raise AuthenticationFailure("agent tokens have no session history")
    return _session_payload(principal.user_id, limit, principal.jti)


@router.delete("/sessions/{jti}")
def sign_out_session(
    jti: str, principal: Principal = Depends(get_principal)
) -> dict[str, str]:
    if principal.is_agent:
        raise AuthenticationFailure("agent tokens have no sessions to sign out")
    revoke_session(
        principal.user_id, jti, ttl_minutes=get_settings().jwt_ttl_minutes
    )
    audit_standalone(
        action="auth.session.revoke",
        actor_id=principal.user_id,
        actor_role=principal.role,
        object_type="user",
        object_id=principal.user_id,
        detail={"jti": jti},
    )
    return {"status": "revoked", "jti": jti}


@router.delete("/users/{user_id}/sessions/{jti}")
def admin_sign_out_session(
    user_id: str, jti: str, principal: Principal = Depends(require("users:manage"))
) -> dict[str, str]:
    """Sign one device out of another account.

    Shared workstations and help-desk calls need the narrow action: the account
    keeps its password and its other sessions, and only the named token dies.
    """
    revoke_session(user_id, jti, ttl_minutes=get_settings().jwt_ttl_minutes)
    audit_standalone(
        action="auth.session.revoke",
        actor_id=principal.user_id,
        actor_role=principal.role,
        object_type="user",
        object_id=user_id,
        detail={"jti": jti, "on_behalf_of": user_id},
    )
    return {"status": "revoked", "jti": jti}


@router.get("/users/{user_id}/sessions")
def user_sessions(
    user_id: str,
    limit: int = 20,
    principal: Principal = Depends(require("users:manage")),
) -> dict[str, object]:
    current = principal.jti if principal.user_id == user_id else None
    return _session_payload(user_id, limit, current)


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
) -> dict[str, object]:
    if principal.is_agent:
        raise AuthenticationFailure("agent tokens cannot change passwords")
    current = verify_credentials(principal.email, payload.current_password)
    # Every token minted before this call carries the old session version and
    # is rejected on its next use.  The caller receives a replacement token so
    # the session performing the change is not logged out mid-action.
    session_version = change_password(current["id"], payload.new_password)
    jti = new_id("jti")
    token, expires_at = create_access_token(
        subject=current["id"],
        role=current["role"],
        secret=get_settings().jwt_secret,
        ttl_minutes=get_settings().jwt_ttl_minutes,
        token_version=session_version,
        token_id=jti,
    )
    audit_standalone(
        action="auth.password.change",
        actor_id=principal.user_id,
        actor_role=principal.role,
        object_type="user",
        object_id=principal.user_id,
        detail={
            "other_sessions_revoked": True,
            "session_version": session_version,
            "jti": jti,
        },
    )
    return {
        "status": "changed",
        "access_token": token,
        "token_type": "bearer",
        "expires_at": expires_at.isoformat(),
        "other_sessions_revoked": True,
    }


@router.post("/users/{user_id}/revoke-sessions")
def revoke_user_sessions(
    user_id: str, principal: Principal = Depends(require("users:manage"))
) -> dict[str, object]:
    version = revoke_sessions(user_id)
    audit_standalone(
        action="auth.sessions.revoke",
        actor_id=principal.user_id,
        actor_role=principal.role,
        object_type="user",
        object_id=user_id,
        detail={"session_version": version},
    )
    return {"status": "revoked", "user_id": user_id, "session_version": version}


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
