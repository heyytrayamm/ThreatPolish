"""Central configuration for ThreatPolish.

All runtime configuration is supplied through environment variables so that no
secret is ever committed.  Development defaults are safe-but-loud: the service
refuses to start in production without an explicitly supplied signing secret.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from .errors import ConfigurationError

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}

DEFAULT_ORIGINS = ("http://localhost:5173", "http://127.0.0.1:5173")


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    value = raw.strip().lower()
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    raise ConfigurationError(f"{name} must be a boolean, got {raw!r}")


def _int(name: str, default: int, minimum: int | None = None, maximum: int | None = None) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be an integer, got {raw!r}") from exc
    if minimum is not None and value < minimum:
        raise ConfigurationError(f"{name} must be >= {minimum}")
    if maximum is not None and value > maximum:
        raise ConfigurationError(f"{name} must be <= {maximum}")
    return value


def _float(name: str, default: float, minimum: float | None = None, maximum: float | None = None) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be a number, got {raw!r}") from exc
    if minimum is not None and value < minimum:
        raise ConfigurationError(f"{name} must be >= {minimum}")
    if maximum is not None and value > maximum:
        raise ConfigurationError(f"{name} must be <= {maximum}")
    return value


def _origins() -> tuple[str, ...]:
    raw = os.environ.get("TP_ALLOWED_ORIGINS")
    if not raw:
        return DEFAULT_ORIGINS
    return tuple(item.strip() for item in raw.split(",") if item.strip())


@dataclass(frozen=True)
class Settings:
    env: str
    db_url: str
    jwt_secret: str
    jwt_ttl_minutes: int
    allow_origins: tuple[str, ...]
    decoy_enabled: bool
    decoy_port: int
    retention_days: int
    log_level: str
    max_event_bytes: int
    correlation_window_hours: int
    response_auto_apply: bool
    ingest_rate_limit_per_minute: int
    decoy_max_sessions_per_hour: int
    websec_max_requests_per_host: int
    websec_allow_loopback: bool
    websec_timeout_seconds: float
    crypto_provider: str
    crypto_api_base: str
    crypto_timeout_seconds: float
    crypto_min_refresh_seconds: int
    data_dir: Path
    generated_secret: bool = field(default=False)

    @property
    def is_production(self) -> bool:
        return self.env == "production"


def build_settings() -> Settings:
    env = os.environ.get("TP_ENV", "development").strip().lower()
    if env not in {"development", "test", "production"}:
        raise ConfigurationError("TP_ENV must be development, test or production")

    secret = os.environ.get("TP_JWT_SECRET", "").strip()
    generated = False
    if not secret:
        if env == "production":
            raise ConfigurationError("TP_JWT_SECRET is required when TP_ENV=production")
        secret = secrets.token_urlsafe(48)
        generated = True
    elif len(secret) < 32:
        raise ConfigurationError("TP_JWT_SECRET must be at least 32 characters")

    data_dir = Path(os.environ.get("TP_DATA_DIR", "./data")).expanduser()
    db_url = os.environ.get("TP_DB_URL", f"sqlite:///{data_dir / 'threatpolish.db'}")

    return Settings(
        env=env,
        db_url=db_url,
        jwt_secret=secret,
        jwt_ttl_minutes=_int("TP_JWT_TTL_MINUTES", 60, 5, 24 * 60),
        allow_origins=_origins(),
        decoy_enabled=_bool("TP_DECOY_ENABLED", True),
        decoy_port=_int("TP_DECOY_PORT", 8022, 1, 65535),
        retention_days=_int("TP_RETENTION_DAYS", 90, 1, 3650),
        log_level=os.environ.get("TP_LOG_LEVEL", "INFO").upper(),
        max_event_bytes=_int("TP_MAX_EVENT_BYTES", 65536, 1024, 1_048_576),
        correlation_window_hours=_int("TP_CORRELATION_WINDOW_HOURS", 72, 1, 24 * 30),
        response_auto_apply=_bool("TP_RESPONSE_AUTO_APPLY", False),
        ingest_rate_limit_per_minute=_int("TP_INGEST_RATE_LIMIT_PER_MINUTE", 6000, 1, 1_000_000),
        decoy_max_sessions_per_hour=_int("TP_DECOY_MAX_SESSIONS_PER_HOUR", 120, 1, 100_000),
        websec_max_requests_per_host=_int("TP_WEB_SEC_MAX_REQUESTS_PER_HOST", 10, 1, 100),
        websec_allow_loopback=_bool("TP_WEB_SEC_ALLOW_LOOPBACK", False),
        websec_timeout_seconds=_float("TP_WEB_SEC_TIMEOUT_SECONDS", 10.0, 1.0, 60.0),
        crypto_provider=os.environ.get("TP_CRYPTO_PROVIDER", "coingecko").strip().lower(),
        crypto_api_base=os.environ.get("TP_CRYPTO_API_BASE", "https://api.coingecko.com/api/v3").rstrip("/"),
        crypto_timeout_seconds=_float("TP_CRYPTO_TIMEOUT_SECONDS", 8.0, 0.5, 60.0),
        crypto_min_refresh_seconds=_int("TP_CRYPTO_MIN_REFRESH_SECONDS", 60, 5, 86400),
        data_dir=data_dir,
        generated_secret=generated,
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return build_settings()


def reset_settings_cache() -> None:
    """Used by tests after changing the environment."""
    get_settings.cache_clear()
