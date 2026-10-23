"""
SQLAlchemy 2.x ORM models for ThreatPolish Phase 2.

Entities
────────
• Event           – one row per normalised decoy interaction
• Session         – groups related events from a single attacker session
• Alert           – raised when a detection rule matches one or more events
• DetectionRule   – static rule definition (detection logic is Phase 4)
• IngestionFailure– records events that could not be normalised

Association tables
──────────────────
• alert_events    – many-to-many between Alert and its supporting Event(s)

Design decisions
────────────────
• PostgreSQL-compatible types throughout (JSONB, UUID via ``pg_uuid``).
• ``event_id`` has a UNIQUE constraint to prevent duplicate ingestion.
• Structured payloads stored as JSONB for indexed querying later.
• Passwords/credentials are never stored — only ``auth_outcome`` and
  ``auth_password_length`` metadata appear in the Event row.
• Indexes are added on columns that the Phase 5 API will filter on
  (timestamp, source_ip, session, event_type, severity).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum as SAEnum,
    ForeignKey,
    Index,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

# ---------------------------------------------------------------------------
# Helper: UUID column default
# ---------------------------------------------------------------------------

def _uuid4() -> uuid.UUID:
    return uuid.uuid4()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Association table: Alert ↔ Event (many-to-many)
# ---------------------------------------------------------------------------

alert_events = Table(
    "alert_events",
    Base.metadata,
    Column(
        "alert_id",
        PG_UUID(as_uuid=True),
        ForeignKey("alerts.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "event_id",
        PG_UUID(as_uuid=True),
        ForeignKey("events.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------

class SessionModel(Base):
    """
    Groups multiple events originating from the same attacker session.

    A session is typically defined by (source_ip, sensor, time-window).
    """

    __tablename__ = "sessions"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=_uuid4,
    )
    source_ip: Mapped[str] = mapped_column(
        String(45), nullable=False, index=True,
        comment="Connecting IP (NOT proof of identity).",
    )
    sensor_id: Mapped[str] = mapped_column(
        String(128), nullable=False,
    )
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow,
    )
    ended_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    metadata_json: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True, default=None,
        comment="Arbitrary session-level metadata.",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(),
    )

    # Relationships
    events: Mapped[list["Event"]] = relationship(
        "Event", back_populates="session", lazy="selectin",
    )

    def __repr__(self) -> str:
        return f"<Session {self.id!s} src={self.source_ip}>"


# Backward-compatibility / ergonomic alias
Session = SessionModel


# ---------------------------------------------------------------------------
# Event
# ---------------------------------------------------------------------------

class Event(Base):
    """
    One normalised decoy interaction — the canonical event row.

    ``event_id`` is the externally-assigned UUID from the Pydantic schema;
    ``id`` is the database surrogate PK (also a UUID for portability).
    """

    __tablename__ = "events"
    __table_args__ = (
        UniqueConstraint("event_id", name="uq_events_event_id"),
        Index("ix_events_timestamp", "timestamp"),
        Index("ix_events_source_ip", "source_ip"),
        Index("ix_events_event_type", "event_type"),
        Index("ix_events_session_id", "session_id"),
    )

    # Surrogate PK
    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=_uuid4,
    )

    # Canonical identity
    event_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), nullable=False, unique=True,
        comment="Externally-assigned, globally unique event identifier.",
    )
    schema_version: Mapped[str] = mapped_column(
        String(8), nullable=False, default="1.0",
    )

    # Timing
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
    )

    # Session FK
    session_id: Mapped[uuid.UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("sessions.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Sensor / service
    sensor_id: Mapped[str] = mapped_column(String(128), nullable=False)
    service: Mapped[str] = mapped_column(String(64), nullable=False)

    # Network addressing
    source_ip: Mapped[str] = mapped_column(
        String(45), nullable=False,
        comment="Connecting IP (NOT proof of identity).",
    )
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Classification
    protocol: Mapped[str] = mapped_column(String(16), nullable=False)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)

    # Payload (JSONB for indexed sub-key queries in PostgreSQL)
    payload: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    raw_event_ref: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # Auth metadata (credential-safe: no passwords/hashes)
    auth_outcome: Mapped[str | None] = mapped_column(
        String(16), nullable=True,
        comment="success | failure | unknown.  Password is NEVER stored.",
    )
    auth_username: Mapped[str | None] = mapped_column(
        String(256), nullable=True,
        comment="Submitted username (may be forged).",
    )
    auth_password_length: Mapped[int | None] = mapped_column(
        Integer, nullable=True,
        comment="Length of submitted password.  The password itself is NEVER stored.",
    )

    # Ingestion metadata
    ingested_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    ingestion_source: Mapped[str | None] = mapped_column(String(256), nullable=True)

    # Housekeeping
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(),
    )

    # Relationships
    session: Mapped["SessionModel | None"] = relationship(
        "SessionModel", back_populates="events",
    )
    alerts: Mapped[list["Alert"]] = relationship(
        "Alert", secondary=alert_events, back_populates="events",
    )

    def __repr__(self) -> str:
        return f"<Event {self.event_id!s} type={self.event_type}>"


# ---------------------------------------------------------------------------
# Detection Rule (definition only — detection logic is Phase 4)
# ---------------------------------------------------------------------------

class DetectionRule(Base):
    """
    Static detection rule definition.

    The actual matching engine is not implemented until Phase 4; this
    table stores the rule catalogue and metadata.
    """

    __tablename__ = "detection_rules"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=_uuid4,
    )
    name: Mapped[str] = mapped_column(
        String(256), nullable=False, unique=True,
    )
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(
        String(16), nullable=False, default="medium",
        comment="low | medium | high | critical",
    )
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True,
    )
    rule_definition: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True,
        comment="Structured rule body (conditions, thresholds).",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(),
        onupdate=_utcnow,
    )

    # Relationships
    alerts: Mapped[list["Alert"]] = relationship(
        "Alert", back_populates="rule",
    )

    def __repr__(self) -> str:
        return f"<DetectionRule {self.name!r}>"


# ---------------------------------------------------------------------------
# Alert
# ---------------------------------------------------------------------------

class Alert(Base):
    """
    Raised when a DetectionRule matches one or more Events.

    Uses a many-to-many relationship via ``alert_events`` so that a
    single alert can reference multiple supporting events.
    """

    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_severity", "severity"),
        Index("ix_alerts_created_at", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=_uuid4,
    )
    rule_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("detection_rules.id", ondelete="CASCADE"),
        nullable=False,
    )
    severity: Mapped[str] = mapped_column(
        String(16), nullable=False,
        comment="Inherited from rule or overridden: low|medium|high|critical.",
    )
    risk_score: Mapped[int | None] = mapped_column(
        Integer, nullable=True,
        comment="Computed risk score 0-100 (Phase 4).",
    )
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    resolved: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(),
    )

    # Relationships
    rule: Mapped["DetectionRule"] = relationship(
        "DetectionRule", back_populates="alerts",
    )
    events: Mapped[list["Event"]] = relationship(
        "Event", secondary=alert_events, back_populates="alerts",
    )

    def __repr__(self) -> str:
        return f"<Alert {self.id!s} severity={self.severity}>"


# ---------------------------------------------------------------------------
# Ingestion Failure
# ---------------------------------------------------------------------------

class IngestionFailure(Base):
    """
    Records events that could not be normalised into the canonical schema.

    Preserving the raw payload (minus credentials) enables later debugging
    and re-processing.
    """

    __tablename__ = "ingestion_failures"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=_uuid4,
    )
    raw_payload: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True,
        comment="Original raw event data (credentials stripped).",
    )
    error_message: Mapped[str] = mapped_column(
        Text, nullable=False,
    )
    ingestion_source: Mapped[str | None] = mapped_column(
        String(256), nullable=True,
    )
    sensor_id: Mapped[str | None] = mapped_column(
        String(128), nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(),
    )

    def __repr__(self) -> str:
        return f"<IngestionFailure {self.id!s}>"
