"""create phase2 tables

Revision ID: 788521f801f7
Revises:
Create Date: 2026-10-23

Creates the initial ThreatPolish Phase 2 database tables:
  - sessions
  - events (with unique event_id constraint)
  - detection_rules
  - alerts
  - alert_events (many-to-many association)
  - ingestion_failures
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "788521f801f7"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- sessions ---
    op.create_table(
        "sessions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("source_ip", sa.String(45), nullable=False, comment="Connecting IP (NOT proof of identity)."),
        sa.Column("sensor_id", sa.String(128), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("metadata_json", postgresql.JSONB, nullable=True, comment="Arbitrary session-level metadata."),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_sessions_source_ip", "sessions", ["source_ip"])

    # --- events ---
    op.create_table(
        "events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("event_id", postgresql.UUID(as_uuid=True), nullable=False, comment="Externally-assigned, globally unique event identifier."),
        sa.Column("schema_version", sa.String(8), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("session_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("sessions.id", ondelete="SET NULL"), nullable=True),
        sa.Column("sensor_id", sa.String(128), nullable=False),
        sa.Column("service", sa.String(64), nullable=False),
        sa.Column("source_ip", sa.String(45), nullable=False, comment="Connecting IP (NOT proof of identity)."),
        sa.Column("source_port", sa.Integer, nullable=True),
        sa.Column("destination_ip", sa.String(45), nullable=True),
        sa.Column("destination_port", sa.Integer, nullable=True),
        sa.Column("protocol", sa.String(16), nullable=False),
        sa.Column("event_type", sa.String(32), nullable=False),
        sa.Column("payload", postgresql.JSONB, nullable=True),
        sa.Column("raw_event_ref", sa.String(512), nullable=True),
        sa.Column("auth_outcome", sa.String(16), nullable=True, comment="success | failure | unknown.  Password is NEVER stored."),
        sa.Column("auth_username", sa.String(256), nullable=True, comment="Submitted username (may be forged)."),
        sa.Column("auth_password_length", sa.Integer, nullable=True, comment="Length of submitted password.  The password itself is NEVER stored."),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ingestion_source", sa.String(256), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("event_id", name="uq_events_event_id"),
    )
    op.create_index("ix_events_timestamp", "events", ["timestamp"])
    op.create_index("ix_events_source_ip", "events", ["source_ip"])
    op.create_index("ix_events_event_type", "events", ["event_type"])
    op.create_index("ix_events_session_id", "events", ["session_id"])

    # --- detection_rules ---
    op.create_table(
        "detection_rules",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(256), nullable=False, unique=True),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("severity", sa.String(16), nullable=False, comment="low | medium | high | critical"),
        sa.Column("enabled", sa.Boolean, nullable=False),
        sa.Column("rule_definition", postgresql.JSONB, nullable=True, comment="Structured rule body (conditions, thresholds)."),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    # --- alerts ---
    op.create_table(
        "alerts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("rule_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("detection_rules.id", ondelete="CASCADE"), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False, comment="Inherited from rule or overridden: low|medium|high|critical."),
        sa.Column("risk_score", sa.Integer, nullable=True, comment="Computed risk score 0-100 (Phase 4)."),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("resolved", sa.Boolean, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_alerts_severity", "alerts", ["severity"])
    op.create_index("ix_alerts_created_at", "alerts", ["created_at"])

    # --- alert_events (M2M association) ---
    op.create_table(
        "alert_events",
        sa.Column("alert_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("event_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("events.id", ondelete="CASCADE"), primary_key=True),
    )

    # --- ingestion_failures ---
    op.create_table(
        "ingestion_failures",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("raw_payload", postgresql.JSONB, nullable=True, comment="Original raw event data (credentials stripped)."),
        sa.Column("error_message", sa.Text, nullable=False),
        sa.Column("ingestion_source", sa.String(256), nullable=True),
        sa.Column("sensor_id", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("alert_events")
    op.drop_table("alerts")
    op.drop_table("detection_rules")
    op.drop_table("ingestion_failures")
    op.drop_index("ix_events_session_id", table_name="events")
    op.drop_index("ix_events_event_type", table_name="events")
    op.drop_index("ix_events_source_ip", table_name="events")
    op.drop_index("ix_events_timestamp", table_name="events")
    op.drop_table("events")
    op.drop_index("ix_sessions_source_ip", table_name="sessions")
    op.drop_table("sessions")
