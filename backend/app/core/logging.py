"""Structured JSON logging with redaction of credential-bearing fields."""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any

_SENSITIVE_KEYS = {
    "authorization",
    "password",
    "passwd",
    "token",
    "access_token",
    "refresh_token",
    "secret",
    "jwt",
    "api_key",
    "set-cookie",
    "cookie",
    "private_key",
    "seed_phrase",
    "mnemonic",
}

_REDACTED = "[redacted]"


def redact(value: Any, *, _depth: int = 0) -> Any:
    if _depth > 6:
        return "[truncated]"
    if isinstance(value, dict):
        return {
            key: (_REDACTED if str(key).lower() in _SENSITIVE_KEYS else redact(item, _depth=_depth + 1))
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(item, _depth=_depth + 1) for item in value][:100]
    if isinstance(value, str) and len(value) > 2000:
        return value[:2000] + "…"
    return value


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        extra = getattr(record, "context", None)
        if isinstance(extra, dict):
            payload.update(redact(extra))
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, separators=(",", ":"))


class ContextAdapter(logging.LoggerAdapter):
    def process(self, msg: str, kwargs: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        context = dict(self.extra or {})
        context.update(kwargs.pop("extra", {}) or {})
        kwargs["extra"] = {"context": context}
        return msg, kwargs


def configure_logging(level: str = "INFO") -> None:
    root = logging.getLogger()
    if getattr(root, "_threatpolish_configured", False):
        root.setLevel(level.upper())
        return
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root.handlers = [handler]
    root.setLevel(level.upper())
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    root._threatpolish_configured = True  # type: ignore[attr-defined]


def get_logger(name: str, **context: Any) -> ContextAdapter:
    return ContextAdapter(logging.getLogger(name), context)
