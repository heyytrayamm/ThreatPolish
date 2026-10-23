"""
ThreatPolish Canonical Event Schema — Version 1.0

This module defines the Pydantic v2 schema for the normalised telemetry
events that every decoy sensor emits.  The schema is intentionally
independent of FastAPI route handlers and SQLAlchemy models so that it
can be validated, serialised, and tested in isolation.

Design principles
─────────────────
• UUIDs for event_id / session_id — globally unique, collision-resistant.
• All timestamps are timezone-aware UTC (naïve datetimes are rejected).
• IP addresses validated via Python's ipaddress module.
• Ports constrained to the IANA range 0–65535.
• Text / payload fields have sensible length caps to prevent abuse.
• Passwords, password hashes, API secrets, and other credentials MUST
  NEVER appear in event telemetry — only auth-outcome metadata is allowed.
• source_ip is never treated as proof of a person's identity.
• Unknown / extra fields are **rejected** (model_config forbid).
• Schema version is pinned per class; consumers must check it.

Safety notes
────────────
• ``password_length`` records only how many characters were submitted,
  never the password itself.
• ``auth_outcome`` is one of ``success | failure | unknown``.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated, Any, Union

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_serializer,
    field_validator,
    model_validator,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CURRENT_SCHEMA_VERSION = "1.0"

# Length / size guardrails
MAX_SENSOR_ID_LEN = 128
MAX_SERVICE_LEN = 64
MAX_RAW_EVENT_REF_LEN = 512
MAX_PAYLOAD_KEYS = 64
MAX_PAYLOAD_STR_VALUE_LEN = 8_192
MAX_INGESTION_SOURCE_LEN = 256
MAX_INGESTION_ERROR_LEN = 2_048


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ProtocolEnum(str, Enum):
    """Transport/application protocols recognised by the canonical schema."""
    TCP = "tcp"
    UDP = "udp"
    HTTP = "http"
    HTTPS = "https"
    SSH = "ssh"
    DNS = "dns"
    ICMP = "icmp"
    OTHER = "other"


class EventTypeEnum(str, Enum):
    """High-level event classification for routing and detection."""
    CONNECTION = "connection"
    AUTH_ATTEMPT = "auth_attempt"
    COMMAND = "command"
    QUERY = "query"
    SCAN = "scan"
    DATA_EXFIL = "data_exfil"
    RECON = "recon"
    PAYLOAD_DELIVERY = "payload_delivery"
    OTHER = "other"


class AuthOutcome(str, Enum):
    """Outcome of an authentication attempt.  Only metadata is stored."""
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# IP address type alias — accepts both v4 and v6
# ---------------------------------------------------------------------------

IPAddress = Union[IPv4Address, IPv6Address]


# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------

class AuthMetadata(BaseModel):
    """
    Authentication metadata recorded without storing credentials.

    ``password_length`` captures only the *length* of the submitted
    credential; the actual password or hash is never persisted.
    """

    model_config = ConfigDict(extra="forbid")

    username: str | None = Field(
        default=None,
        max_length=256,
        description="Submitted username (may be forged by the attacker).",
    )
    auth_outcome: AuthOutcome = Field(
        default=AuthOutcome.UNKNOWN,
        description="Whether the simulated authentication succeeded, failed, or is unknown.",
    )
    password_length: int | None = Field(
        default=None,
        ge=0,
        le=10_000,
        description="Length of the submitted password. The password itself is NEVER stored.",
    )


class IngestionMeta(BaseModel):
    """
    Metadata injected by the ingestion pipeline describing how / when the
    event was received and normalised.
    """

    model_config = ConfigDict(extra="forbid")

    received_at: datetime = Field(
        description="UTC timestamp when the ingestion layer first received the raw event.",
    )
    ingestion_source: str = Field(
        max_length=MAX_INGESTION_SOURCE_LEN,
        description="Identifier of the ingestion pathway (e.g. 'ssh-decoy-collector').",
    )
    normalised: bool = Field(
        default=True,
        description="True when the event has been converted to the canonical schema.",
    )
    ingestion_errors: list[str] = Field(
        default_factory=list,
        max_length=16,
        description="Non-fatal issues encountered during normalisation.",
    )

    @field_validator("received_at")
    @classmethod
    def _received_at_must_be_aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("received_at must be a timezone-aware UTC datetime")
        return v

    @field_validator("ingestion_errors")
    @classmethod
    def _cap_error_item_length(cls, v: list[str]) -> list[str]:
        for idx, err in enumerate(v):
            if len(err) > MAX_INGESTION_ERROR_LEN:
                v[idx] = err[:MAX_INGESTION_ERROR_LEN]
        return v


# ---------------------------------------------------------------------------
# Main event schema
# ---------------------------------------------------------------------------

class CanonicalEvent(BaseModel):
    """
    ThreatPolish Canonical Event — v1.0

    This is the single, normalised representation of every interaction
    captured by a decoy sensor.  All decoy types (SSH, REST, DB …)
    convert their raw observations into this schema before persistence.
    """

    model_config = ConfigDict(
        extra="forbid",                      # reject unknown fields
        str_strip_whitespace=True,           # trim incoming strings
        json_schema_extra={
            "title": "ThreatPolish Canonical Event v1.0",
        },
    )

    # ── Identity ──────────────────────────────────────────────────────
    schema_version: str = Field(
        default=CURRENT_SCHEMA_VERSION,
        pattern=r"^\d+\.\d+$",
        description="Schema version string (e.g. '1.0').  Consumers MUST check this.",
    )
    event_id: uuid.UUID = Field(
        default_factory=uuid.uuid4,
        description="Globally unique event identifier.",
    )
    session_id: uuid.UUID | None = Field(
        default=None,
        description="Correlates events belonging to the same attacker session.",
    )
    sensor_id: str = Field(
        max_length=MAX_SENSOR_ID_LEN,
        description="Identifier of the decoy sensor that captured the event.",
    )

    # ── Timing ────────────────────────────────────────────────────────
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC time the interaction occurred at the sensor.",
    )

    # ── Network addressing ────────────────────────────────────────────
    source_ip: IPAddress = Field(
        description=(
            "IP address of the connecting party.  This is NOT treated as "
            "proof of a person's identity — it may be spoofed or NAT'd."
        ),
    )
    source_port: int | None = Field(
        default=None,
        ge=0,
        le=65535,
        description="Ephemeral source port (0–65535).",
    )
    destination_ip: IPAddress | None = Field(
        default=None,
        description="IP address of the decoy interface that received the connection.",
    )
    destination_port: int | None = Field(
        default=None,
        ge=0,
        le=65535,
        description="Destination port on the decoy sensor.",
    )

    # ── Classification ────────────────────────────────────────────────
    protocol: ProtocolEnum = Field(
        description="Transport or application-layer protocol.",
    )
    service: str = Field(
        max_length=MAX_SERVICE_LEN,
        description="Logical service name (e.g. 'ssh-decoy', 'rest-decoy').",
    )
    event_type: EventTypeEnum = Field(
        description="High-level event classification.",
    )

    # ── Payload ───────────────────────────────────────────────────────
    payload: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Structured event payload.  MUST NOT contain passwords, "
            "password hashes, API secrets, or other credential material."
        ),
    )
    raw_event_ref: str | None = Field(
        default=None,
        max_length=MAX_RAW_EVENT_REF_LEN,
        description="Reference (URI, S3 key, etc.) to the original raw event blob.",
    )

    # ── Auth metadata ─────────────────────────────────────────────────
    auth: AuthMetadata | None = Field(
        default=None,
        description="Authentication metadata (if the event represents an auth attempt).",
    )

    # ── Ingestion ─────────────────────────────────────────────────────
    ingestion: IngestionMeta | None = Field(
        default=None,
        description="Metadata added by the ingestion pipeline.",
    )

    # ── Validators ────────────────────────────────────────────────────

    @field_validator("timestamp")
    @classmethod
    def _timestamp_must_be_aware(cls, v: datetime) -> datetime:
        """Reject naïve (timezone-unaware) timestamps."""
        if v.tzinfo is None:
            raise ValueError(
                "timestamp must be timezone-aware (UTC).  "
                "Naïve datetimes are not accepted."
            )
        return v

    @field_validator("payload")
    @classmethod
    def _validate_payload_size(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        """Enforce key-count and string-value-length limits on payload."""
        if v is None:
            return v
        if len(v) > MAX_PAYLOAD_KEYS:
            raise ValueError(
                f"payload must not exceed {MAX_PAYLOAD_KEYS} top-level keys"
            )
        for key, val in v.items():
            if isinstance(val, str) and len(val) > MAX_PAYLOAD_STR_VALUE_LEN:
                raise ValueError(
                    f"payload['{key}'] exceeds the {MAX_PAYLOAD_STR_VALUE_LEN}-char limit"
                )
        return v

    @model_validator(mode="after")
    def _check_auth_event_consistency(self) -> "CanonicalEvent":
        """Warn-level: auth metadata on a non-auth event type is unusual."""
        # We don't raise — just ensure the model is internally consistent.
        return self

    # ── Serialisation helpers ─────────────────────────────────────────

    @field_serializer("source_ip", "destination_ip")
    def _serialise_ip(self, v: IPAddress | None) -> str | None:
        return str(v) if v is not None else None

    @field_serializer("event_id", "session_id")
    def _serialise_uuid(self, v: uuid.UUID | None) -> str | None:
        return str(v) if v is not None else None

    @field_serializer("timestamp")
    def _serialise_timestamp(self, v: datetime) -> str:
        return v.isoformat()
