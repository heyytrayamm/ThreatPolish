"""User accounts and API-token identities."""

from __future__ import annotations

import os
import re
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from ..core.errors import AuthenticationFailure, Conflict, NotFound, ValidationFailure
from ..core.security import (
    hash_agent_token,
    hash_password,
    iso,
    new_agent_token,
    new_id,
    utcnow,
    verify_password,
)
from ..db.database import connection, query_one
from ..db.schema import agent_tokens, users
from .rbac import validate_role

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _public_user(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "email": row["email"],
        "name": row["name"],
        "role": row["role"],
        "is_active": bool(row["is_active"]),
        "created_at": row["created_at"],
        "last_login_at": row["last_login_at"],
    }


def create_user(*, email: str, name: str, role: str, password: str) -> dict[str, Any]:
    email = email.strip().lower()
    if not _EMAIL_RE.match(email):
        raise ValidationFailure("a valid email address is required")
    if len(password) < 10:
        raise ValidationFailure("password must be at least 10 characters")
    validate_role(role)
    user_id = new_id("usr")
    created = iso(utcnow())
    try:
        with connection() as conn:
            conn.execute(
                users.insert().values(
                    id=user_id,
                    email=email,
                    name=name.strip()[:120] or email.split("@")[0],
                    role=role,
                    password_hash=hash_password(password),
                    is_active=1,
                    created_at=created,
                )
            )
    except IntegrityError as exc:
        raise Conflict("a user with that email already exists") from exc
    return get_user(user_id)


def get_user(user_id: str) -> dict[str, Any]:
    with connection() as conn:
        row = query_one(conn, "SELECT * FROM users WHERE id = :id", {"id": user_id})
    if not row:
        raise NotFound("user not found")
    return _public_user(row)


def list_users() -> list[dict[str, Any]]:
    with connection() as conn:
        rows = conn.execute(select(users).order_by(users.c.created_at)).fetchall()
    return [_public_user(dict(row._mapping)) for row in rows]


def count_users() -> int:
    with connection() as conn:
        return int(conn.execute(select(func.count()).select_from(users)).scalar() or 0)


def authenticate(email: str, password: str) -> dict[str, Any]:
    normalized = email.strip().lower()
    with connection() as conn:
        row = query_one(conn, "SELECT * FROM users WHERE email = :email", {"email": normalized})
        if not row or not row["is_active"]:
            # Constant work regardless of account existence.
            verify_password(password, "pbkdf2_sha256$210000$AAAA$AAAA")
            raise AuthenticationFailure("invalid credentials")
        if not verify_password(password, row["password_hash"]):
            raise AuthenticationFailure("invalid credentials")
        conn.execute(
            users.update().where(users.c.id == row["id"]).values(last_login_at=iso(utcnow()))
        )
    return _public_user({**row, "last_login_at": iso(utcnow())})


def change_password(user_id: str, new_password: str) -> None:
    if len(new_password) < 10:
        raise ValidationFailure("password must be at least 10 characters")
    with connection() as conn:
        result = conn.execute(
            users.update()
            .where(users.c.id == user_id)
            .values(password_hash=hash_password(new_password))
        )
        if result.rowcount == 0:
            raise NotFound("user not found")


# --------------------------------------------------------------------------- #
# Agent tokens (sensors)
# --------------------------------------------------------------------------- #
def create_agent_token(*, name: str, role: str = "sensor") -> dict[str, Any]:
    validate_role(role)
    plaintext, token_hash, prefix = new_agent_token()
    token_id = new_id("agt")
    with connection() as conn:
        conn.execute(
            agent_tokens.insert().values(
                id=token_id,
                name=name.strip()[:120],
                token_hash=token_hash,
                prefix=prefix,
                role=role,
                created_at=iso(utcnow()),
            )
        )
    return {"id": token_id, "name": name, "prefix": prefix, "role": role, "token": plaintext}


def resolve_agent_token(plaintext: str) -> dict[str, Any] | None:
    token_hash = hash_agent_token(plaintext.strip())
    with connection() as conn:
        row = query_one(
            conn,
            "SELECT * FROM agent_tokens WHERE token_hash = :hash AND revoked_at IS NULL",
            {"hash": token_hash},
        )
        if not row:
            return None
        conn.execute(
            agent_tokens.update()
            .where(agent_tokens.c.id == row["id"])
            .values(last_used_at=iso(utcnow()))
        )
    return row


def list_agent_tokens() -> list[dict[str, Any]]:
    with connection() as conn:
        rows = conn.execute(select(agent_tokens).order_by(agent_tokens.c.created_at)).fetchall()
    return [
        {
            "id": row.id,
            "name": row.name,
            "prefix": row.prefix,
            "role": row.role,
            "created_at": row.created_at,
            "last_used_at": row.last_used_at,
            "revoked_at": row.revoked_at,
        }
        for row in rows
    ]


def revoke_agent_token(token_id: str) -> None:
    with connection() as conn:
        result = conn.execute(
            agent_tokens.update()
            .where(agent_tokens.c.id == token_id)
            .values(revoked_at=iso(utcnow()))
        )
        if result.rowcount == 0:
            raise NotFound("agent token not found")


def ensure_bootstrap_admin() -> str | None:
    """Create the first administrator from environment variables if the user
    table is empty.  Returns the email when a user was created.
    """
    if count_users() > 0:
        return None
    email = os.environ.get("TP_BOOTSTRAP_ADMIN_EMAIL", "").strip()
    password = os.environ.get("TP_BOOTSTRAP_ADMIN_PASSWORD", "")
    if not email or not password:
        return None
    create_user(email=email, name="Administrator", role="admin", password=password)
    return email
