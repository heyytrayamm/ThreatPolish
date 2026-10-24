"""Versioned event contract shared by every module.

Every event that enters ThreatPolish is validated against this model before it
touches storage.  Unknown fields are rejected so a sensor cannot smuggle an
unexpected structure into the pipeline, and payload size is bounded to protect
the ingestion path.
"""

from __future__ import annotations

import ipaddress
import json
import math
import re
import unicodedata
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..core.config import get_settings

SCHEMA_VERSION = "1.0"
SUPPORTED_SCHEMA_VERSIONS = {"1.0"}

SourceModule = Literal["honeypot", "websec", "cryptointel", "app", "correlation", "manual"]
Severity = Literal["info", "low", "medium", "high", "critical"]

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

_EVENT_TYPE_RE = re.compile(r"^[a-z][a-z0-9_.-]{2,63}$")
_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,120}$")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_MAX_STRING = 4000


def _identifier(value: str | None, *, limit: int, field: str) -> str | None:
    """Validate an identifier that later becomes part of a storage key.

    Session identifiers are joined into relationship keys, so a control
    character — specifically the pair separator — would let two different
    session pairs share one key and overwrite each other's evidence.  Sensors
    choose these values, so they are rejected at the contract boundary rather
    than sanitized: rewriting an identifier could make two distinct sessions
    collide, which is the same defect with a quieter failure mode.
    """
    if value is None:
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    if _CONTROL_RE.search(cleaned):
        raise ValueError(f"{field} contains control characters")
    if len(cleaned) > limit:
        raise ValueError(f"{field} is longer than {limit} characters")
    return cleaned


def _clean(value: str, *, limit: int = _MAX_STRING) -> str:
    normalized = unicodedata.normalize("NFC", value)
    normalized = _CONTROL_RE.sub("", normalized)
    # Lone surrogates can arrive through a JSON escape (``\ud800``).  Python's
    # stdlib JSON parser accepts them, but they cannot be encoded back to UTF-8,
    # so a stored value would break every later response that contains it.
    if any(0xD800 <= ord(character) <= 0xDFFF for character in normalized):
        normalized = "".join(
            "\ufffd" if 0xD800 <= ord(character) <= 0xDFFF else character
            for character in normalized
        )
    return normalized.strip()[:limit]


def _clean_obj(value: Any, depth: int = 0) -> Any:
    """Normalize strings recursively and bound nesting."""
    if depth > 8:
        raise ValueError("feature payload nesting too deep")
    if isinstance(value, str):
        return _clean(value)
    if isinstance(value, dict):
        if len(value) > 200:
            raise ValueError("feature object has too many keys")
        return {_clean(str(k), limit=100): _clean_obj(v, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        if len(value) > 500:
            raise ValueError("feature array too long")
        return [_clean_obj(v, depth + 1) for v in value]
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        # JSON parsers commonly accept ``NaN`` and ``Infinity`` even though they
        # are not valid JSON.  Persisting them would make the stored payload and
        # the API response unparseable for strict clients, so they are rejected
        # at the contract boundary.
        if not math.isfinite(value):
            raise ValueError("non-finite numbers are not supported")
        return value
    raise ValueError(f"unsupported feature value type: {type(value).__name__}")


class Provenance(BaseModel):
    model_config = ConfigDict(extra="forbid")

    collector: str = Field(min_length=1, max_length=120)
    source: str = Field(min_length=1, max_length=120)
    reliability: float = Field(default=0.6, ge=0.0, le=1.0)
    synthetic: bool = Field(
        default=False,
        description="True when the event was produced by a test/fixture, never by a live sensor.",
    )
    external_refs: list[str] = Field(default_factory=list, max_length=20)
    indicators: list[str] = Field(
        default_factory=list,
        max_length=50,
        description="Verified indicators observed in this event (key fingerprints, JA3, hashes).",
    )

    @field_validator("collector", "source")
    @classmethod
    def _clean_text(cls, value: str) -> str:
        return _clean(value, limit=120)

    @field_validator("external_refs", "indicators")
    @classmethod
    def _clean_list(cls, values: list[str]) -> list[str]:
        return [_clean(item, limit=200) for item in values if item and item.strip()]


class EventIn(BaseModel):
    """An event as submitted by a sensor or module."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"]
    event_id: str | None = None
    occurred_at: datetime
    source_module: SourceModule
    event_type: str
    source_ip: str | None = None
    session_id: str | None = Field(default=None, max_length=120)
    target_id: str | None = Field(default=None, max_length=200)
    severity: Severity = "info"
    provenance: Provenance
    features: dict[str, Any] = Field(default_factory=dict)
    evidence_refs: list[str] = Field(default_factory=list, max_length=50)
    raw: dict[str, Any] = Field(default_factory=dict)

    @field_validator("session_id")
    @classmethod
    def _valid_session_id(cls, value: str | None) -> str | None:
        return _identifier(value, limit=120, field="session_id")

    @field_validator("target_id")
    @classmethod
    def _valid_target_id(cls, value: str | None) -> str | None:
        return _identifier(value, limit=200, field="target_id")

    @field_validator("event_id")
    @classmethod
    def _valid_event_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _ID_RE.match(value):
            raise ValueError("event_id contains unsupported characters")
        return value

    @field_validator("event_type")
    @classmethod
    def _valid_event_type(cls, value: str) -> str:
        if not _EVENT_TYPE_RE.match(value):
            raise ValueError("event_type must match ^[a-z][a-z0-9_.-]{2,63}$")
        return value

    @field_validator("occurred_at")
    @classmethod
    def _utc_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("occurred_at must include a UTC offset")
        value = value.astimezone(timezone.utc)
        now = datetime.now(timezone.utc)
        if value > now + timedelta(minutes=10):
            raise ValueError("occurred_at is in the future beyond allowed clock skew")
        if value < now - timedelta(days=400):
            raise ValueError("occurred_at is older than the accepted retention horizon")
        return value

    @field_validator("source_ip")
    @classmethod
    def _valid_ip(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            return str(ipaddress.ip_address(value.strip()))
        except ValueError as exc:
            raise ValueError("source_ip is not a valid IP address") from exc

    @field_validator("session_id", "target_id")
    @classmethod
    def _clean_ids(cls, value: str | None) -> str | None:
        return _clean(value, limit=200) if value else None

    @field_validator("features", "raw")
    @classmethod
    def _clean_payload(cls, value: dict[str, Any]) -> dict[str, Any]:
        cleaned = _clean_obj(value)
        if not isinstance(cleaned, dict):
            raise ValueError("payload must be an object")
        return cleaned

    @field_validator("evidence_refs")
    @classmethod
    def _clean_refs(cls, values: list[str]) -> list[str]:
        return [_clean(item, limit=200) for item in values if item.strip()]

    @model_validator(mode="after")
    def _bounded_payload(self) -> "EventIn":
        limit = get_settings().max_event_bytes
        encoded = json.dumps(self.model_dump(mode="json"), default=str).encode("utf-8")
        if len(encoded) > limit:
            raise ValueError(f"event exceeds maximum size of {limit} bytes")
        return self


class EventRecord(BaseModel):
    """A persisted event, including pipeline metadata."""

    id: str
    schema_version: str
    occurred_at: datetime
    received_at: datetime
    source_module: str
    event_type: str
    source_ip: str | None
    session_id: str | None
    target_id: str | None
    severity: str
    provenance: dict[str, Any]
    features: dict[str, Any]
    evidence_refs: list[str]
    raw: dict[str, Any]
    status: str
    correlation_state: str
    synthetic: bool


class IngestItemResult(BaseModel):
    index: int
    event_id: str | None
    status: Literal["accepted", "duplicate", "rejected"]
    reason: str | None = None
    quarantine_id: str | None = None


class IngestReport(BaseModel):
    received: int
    accepted: int
    duplicates: int
    rejected: int
    results: list[IngestItemResult]

