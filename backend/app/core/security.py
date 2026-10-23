"""Password, token and signing primitives.

The project deliberately avoids heavy auth dependencies: PBKDF2-HMAC-SHA256 and
HMAC-SHA256 JWS are implemented with the standard library.  Both are well
understood, auditable and sufficient for this deployment model.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from .errors import AuthenticationFailure

PASSWORD_ITERATIONS = 210_000
_PASSWORD_ALG = "pbkdf2_sha256"
_TOKEN_ISSUER = "threatpolish"
_TOKEN_VERSION = 1


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(ts: datetime) -> str:
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc).isoformat()


def parse_iso(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


# --------------------------------------------------------------------------- #
# Passwords
# --------------------------------------------------------------------------- #
def hash_password(password: str, *, iterations: int = PASSWORD_ITERATIONS) -> str:
    if not password or len(password) < 8:
        raise ValueError("password must be at least 8 characters")
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "$".join(
        [
            _PASSWORD_ALG,
            str(iterations),
            _b64e(salt),
            _b64e(digest),
        ]
    )


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt_b64, digest_b64 = encoded.split("$")
        if algorithm != _PASSWORD_ALG:
            return False
        salt = _b64d(salt_b64)
        expected = _b64d(digest_b64)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iterations))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


# --------------------------------------------------------------------------- #
# Access tokens (JWT-compatible HS256)
# --------------------------------------------------------------------------- #
def create_access_token(
    *,
    subject: str,
    role: str,
    secret: str,
    ttl_minutes: int,
    now: datetime | None = None,
    token_id: str | None = None,
) -> tuple[str, datetime]:
    issued = now or utcnow()
    expires = issued + timedelta(minutes=ttl_minutes)
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "iss": _TOKEN_ISSUER,
        "ver": _TOKEN_VERSION,
        "sub": subject,
        "role": role,
        "iat": int(issued.timestamp()),
        "exp": int(expires.timestamp()),
        "jti": token_id or secrets.token_hex(12),
    }
    signing_input = f"{_json_b64(header)}.{_json_b64(payload)}"
    signature = hmac.new(secret.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256).digest()
    return f"{signing_input}.{_b64e(signature)}", expires


def decode_access_token(token: str, *, secret: str, now: datetime | None = None) -> dict[str, Any]:
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
    except ValueError as exc:
        raise AuthenticationFailure("malformed token") from exc

    signing_input = f"{header_b64}.{payload_b64}"
    expected = hmac.new(secret.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256).digest()
    try:
        provided = _b64d(signature_b64)
    except ValueError as exc:
        raise AuthenticationFailure("malformed token signature") from exc
    if not hmac.compare_digest(expected, provided):
        raise AuthenticationFailure("invalid token signature")

    try:
        header = json.loads(_b64d(header_b64))
        payload = json.loads(_b64d(payload_b64))
    except (ValueError, json.JSONDecodeError) as exc:
        raise AuthenticationFailure("malformed token body") from exc

    if header.get("alg") != "HS256" or header.get("typ") != "JWT":
        raise AuthenticationFailure("unsupported token algorithm")
    if payload.get("iss") != _TOKEN_ISSUER or payload.get("ver") != _TOKEN_VERSION:
        raise AuthenticationFailure("unexpected token issuer")
    current = int((now or utcnow()).timestamp())
    if int(payload.get("exp", 0)) <= current:
        raise AuthenticationFailure("token expired")
    if int(payload.get("iat", 0)) > current + 300:
        raise AuthenticationFailure("token issued in the future")
    return payload


# --------------------------------------------------------------------------- #
# Sensor / agent API tokens
# --------------------------------------------------------------------------- #
def new_agent_token() -> tuple[str, str, str]:
    """Return (plaintext, sha256 hash, display prefix).

    The plaintext is shown exactly once.  Only the hash is persisted so a
    database leak does not hand an attacker a working ingestion credential.
    """
    plaintext = "tp_" + secrets.token_urlsafe(32)
    return plaintext, hash_agent_token(plaintext), plaintext[:11]


def hash_agent_token(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def constant_time_equals(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(12)}"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _json_b64(payload: dict[str, Any]) -> str:
    return _b64e(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
