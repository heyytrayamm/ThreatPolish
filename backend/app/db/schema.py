"""Relational schema.

The schema is intentionally portable between SQLite (development, tests) and
PostgreSQL (production).  Timestamps are stored as ISO-8601 UTC text, which
sorts correctly in both engines.  Structured payloads are JSON text: the
database is not asked to query inside them except for the fields that are
promoted to columns.
"""

from __future__ import annotations

from sqlalchemy import (
    Column,
    Float,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
    text,
)

metadata = MetaData()

users = Table(
    "users",
    metadata,
    Column("id", String(40), primary_key=True),
    Column("email", String(255), nullable=False, unique=True),
    Column("name", String(120), nullable=False),
    Column("role", String(20), nullable=False),
    Column("password_hash", Text, nullable=False),
    Column("is_active", Integer, nullable=False, default=1),
    Column("token_version", Integer, nullable=False, default=0),
    Column("created_at", String(40), nullable=False),
    Column("last_login_at", String(40), nullable=True),
)

agent_tokens = Table(
    "agent_tokens",
    metadata,
    Column("id", String(40), primary_key=True),
    Column("name", String(120), nullable=False),
    Column("token_hash", String(64), nullable=False, unique=True),
    Column("prefix", String(16), nullable=False),
    Column("role", String(20), nullable=False, default="sensor"),
    Column("created_at", String(40), nullable=False),
    Column("last_used_at", String(40), nullable=True),
    Column("revoked_at", String(40), nullable=True),
)

revoked_sessions = Table(
    "revoked_sessions",
    metadata,
    Column("jti", String(64), primary_key=True),
    Column("user_id", String(64), nullable=False),
    Column("revoked_at", String(40), nullable=False),
    Column("expires_at", String(40), nullable=False),
    Column("reason", String(120), nullable=False, default="user_request"),
    Index("ix_revoked_sessions_user", "user_id"),
)

events = Table(
    "events",
    metadata,
    Column("id", String(120), primary_key=True),
    Column("schema_version", String(12), nullable=False),
    Column("occurred_at", String(40), nullable=False),
    Column("received_at", String(40), nullable=False),
    Column("source_module", String(32), nullable=False),
    Column("event_type", String(64), nullable=False),
    Column("source_ip", String(64), nullable=True),
    Column("session_id", String(120), nullable=True),
    Column("target_id", String(200), nullable=True),
    Column("severity", String(16), nullable=False),
    Column("provenance", Text, nullable=False),
    Column("features", Text, nullable=False),
    Column("evidence_refs", Text, nullable=False),
    Column("raw", Text, nullable=False),
    Column("dedup_key", String(64), nullable=False, unique=True),
    Column("status", String(24), nullable=False),
    Column("correlation_state", String(24), nullable=False, default="pending"),
    Column("synthetic", Integer, nullable=False, default=0),
    Column("retention_until", String(40), nullable=True),
    Index("ix_events_occurred_at", "occurred_at"),
    Index("ix_events_session", "session_id"),
    Index("ix_events_source_ip", "source_ip"),
    Index("ix_events_module", "source_module"),
)

quarantine = Table(
    "event_quarantine",
    metadata,
    Column("id", String(40), primary_key=True),
    Column("received_at", String(40), nullable=False),
    Column("source_module", String(64), nullable=True),
    Column("actor", String(120), nullable=True),
    Column("reason_code", String(48), nullable=False),
    Column("reason", Text, nullable=False),
    Column("payload", Text, nullable=False),
    Column("payload_bytes", Integer, nullable=False),
    Column("status", String(24), nullable=False, default="quarantined"),
)

audit_log = Table(
    "audit_log",
    metadata,
    Column("id", String(40), primary_key=True),
    Column("ts", String(40), nullable=False),
    Column("actor_id", String(64), nullable=True),
    Column("actor_role", String(20), nullable=True),
    Column("action", String(80), nullable=False),
    Column("object_type", String(48), nullable=True),
    Column("object_id", String(64), nullable=True),
    Column("outcome", String(16), nullable=False),
    Column("detail", Text, nullable=False),
    Column("request_ip", String(64), nullable=True),
    Index("ix_audit_ts", "ts"),
    Index("ix_audit_actor", "actor_id"),
)

assets = Table(
    "assets",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("name", String(200), nullable=False, unique=True),
    Column("kind", String(32), nullable=False),
    Column("criticality", String(16), nullable=False, default="medium"),
    Column("metadata", Text, nullable=False, default="{}"),
    Column("created_at", String(40), nullable=False),
)

watch_scopes = Table(
    "watch_scopes",
    metadata,
    Column("id", String(40), primary_key=True),
    Column("domain", String(255), nullable=False, unique=True),
    Column("authorized_by", String(200), nullable=False),
    Column("authorized_at", String(40), nullable=False),
    Column("expires_at", String(40), nullable=False),
    Column("allow_active", Integer, nullable=False, default=0),
    Column("notes", Text, nullable=False, default=""),
)

scans = Table(
    "scans",
    metadata,
    Column("id", String(40), primary_key=True),
    Column("started_at", String(40), nullable=False),
    Column("finished_at", String(40), nullable=True),
    Column("scope_id", String(40), nullable=False),
    Column("target", String(255), nullable=False),
    Column("status", String(24), nullable=False),
    Column("requested_by", String(64), nullable=True),
    Column("error", Text, nullable=True),
    Column("finding_count", Integer, nullable=False, default=0),
)

findings = Table(
    "findings",
    metadata,
    Column("id", String(40), primary_key=True),
    Column("ts", String(40), nullable=False),
    Column("scan_id", String(40), nullable=True),
    Column("scope_id", String(40), nullable=True),
    Column("target", String(255), nullable=False),
    Column("check_id", String(64), nullable=False),
    Column("title", String(200), nullable=False),
    Column("severity", String(16), nullable=False),
    Column("confidence", String(16), nullable=False, default="high"),
    Column("evidence", Text, nullable=False),
    Column("remediation", Text, nullable=False),
    Column("status", String(24), nullable=False, default="open"),
    Column("event_id", String(64), nullable=True),
    Index("ix_findings_target", "target"),
    Index("ix_findings_ts", "ts"),
)

crypto_snapshots = Table(
    "crypto_snapshots",
    metadata,
    Column("id", String(40), primary_key=True),
    Column("asset_symbol", String(32), nullable=False),
    Column("provider_asset_id", String(64), nullable=False),
    Column("fetched_at", String(40), nullable=False),
    Column("source", String(64), nullable=False),
    Column("price_usd", Float, nullable=True),
    Column("change_24h_pct", Float, nullable=True),
    Column("change_7d_pct", Float, nullable=True),
    Column("market_cap_usd", Float, nullable=True),
    Column("volume_24h_usd", Float, nullable=True),
    Column("stale", Integer, nullable=False, default=0),
    Column("raw_digest", String(64), nullable=False),
    Column("details", Text, nullable=False, default="{}"),
    Index("ix_crypto_symbol_ts", "asset_symbol", "fetched_at"),
)

crypto_risk = Table(
    "crypto_risk",
    metadata,
    Column("id", String(40), nullable=False, primary_key=True),
    Column("asset_symbol", String(32), nullable=False),
    Column("computed_at", String(40), nullable=False),
    Column("score", Float, nullable=False),
    Column("severity", String(16), nullable=False),
    Column("confidence", Float, nullable=False),
    Column("reasons", Text, nullable=False),
    Column("data_freshness_seconds", Integer, nullable=True),
    Column("snapshot_id", String(40), nullable=True),
    Column("algorithm_version", String(24), nullable=False),
)

graph_nodes = Table(
    "graph_nodes",
    metadata,
    Column("id", String(255), primary_key=True),
    Column("kind", String(24), nullable=False),
    Column("label", String(255), nullable=False),
    Column("props", Text, nullable=False, default="{}"),
    Column("first_seen", String(40), nullable=False),
    Column("last_seen", String(40), nullable=False),
    Index("ix_nodes_kind", "kind"),
    Index("ix_nodes_last_seen", "last_seen"),
)

graph_edges = Table(
    "graph_edges",
    metadata,
    Column("id", String(80), primary_key=True),
    Column("kind", String(40), nullable=False),
    Column("src_id", String(255), nullable=False),
    Column("dst_id", String(255), nullable=False),
    Column("confidence", Float, nullable=False),
    Column("score", Float, nullable=False),
    Column("evidence", Text, nullable=False),
    Column("contradictions", Text, nullable=False, default="[]"),
    Column("algorithm_version", String(24), nullable=False),
    Column("created_at", String(40), nullable=False),
    Column("updated_at", String(40), nullable=False),
    Column("expires_at", String(40), nullable=True),
    Column("status", String(24), nullable=False, default="active"),
    Column("campaign_id", String(40), nullable=True),
    UniqueConstraint("src_id", "dst_id", "kind", name="uq_edge"),
    Index("ix_edges_campaign", "campaign_id"),
    # Retention walks endpoints and age; the uniqueness index already covers
    # ``src_id`` as a prefix, but not ``dst_id`` or the status filter.
    Index("ix_edges_dst", "dst_id"),
    Index("ix_edges_status_updated", "status", "updated_at"),
)

campaigns = Table(
    "campaigns",
    metadata,
    Column("id", String(40), primary_key=True),
    Column("name", String(120), nullable=False),
    Column("status", String(24), nullable=False, default="candidate"),
    Column("confidence", Float, nullable=False),
    Column("summary", Text, nullable=False),
    Column("evidence", Text, nullable=False, default="{}"),
    Column("created_at", String(40), nullable=False),
    Column("updated_at", String(40), nullable=False),
    Column("algorithm_version", String(24), nullable=False),
    Column("member_count", Integer, nullable=False, default=0),
    Column("ip_count", Integer, nullable=False, default=0),
    # Lifecycle.  A campaign keeps its identifier while membership evolves, so
    # analyst feedback keeps pointing at it.  When membership changes
    # materially the old row is archived rather than deleted, and when two
    # campaigns merge the absorbed row records which one took over.
    Column("status_updated_at", String(40), nullable=True),
    Column("superseded_by", String(40), nullable=True),
    Column("archived_at", String(40), nullable=True),
    Index("ix_campaigns_archived", "archived_at"),
)

feedback = Table(
    "feedback",
    metadata,
    Column("id", String(40), primary_key=True),
    Column("ts", String(40), nullable=False),
    Column("actor_id", String(64), nullable=False),
    Column("object_type", String(24), nullable=False),
    Column("object_id", String(64), nullable=False),
    Column("label", String(24), nullable=False),
    Column("note", Text, nullable=False, default=""),
    Column("algorithm_version", String(24), nullable=False),
    Index("ix_feedback_object", "object_type", "object_id"),
)

responses = Table(
    "responses",
    metadata,
    Column("id", String(40), primary_key=True),
    Column("created_at", String(40), nullable=False),
    Column("action", String(40), nullable=False),
    Column("target", String(200), nullable=False),
    Column("params", Text, nullable=False, default="{}"),
    Column("status", String(24), nullable=False),
    Column("policy_id", String(64), nullable=False),
    Column("reason", Text, nullable=False),
    Column("requested_by", String(64), nullable=True),
    Column("approved_by", String(64), nullable=True),
    Column("approved_at", String(40), nullable=True),
    Column("expires_at", String(40), nullable=True),
    Column("applied_at", String(40), nullable=True),
    Column("rolled_back_at", String(40), nullable=True),
    Column("rollback_detail", Text, nullable=True),
    Column("confidence", Float, nullable=False, default=0.0),
    Column("campaign_id", String(40), nullable=True),
    Index("ix_responses_status", "status"),
)

decoy_profiles = Table(
    "decoy_profiles",
    metadata,
    Column("id", String(40), primary_key=True),
    Column("name", String(80), nullable=False, unique=True),
    Column("kind", String(32), nullable=False),
    Column("description", Text, nullable=False, default=""),
    Column("config", Text, nullable=False, default="{}"),
    Column("enabled", Integer, nullable=False, default=1),
    Column("is_default", Integer, nullable=False, default=0),
    Column("created_at", String(40), nullable=False),
)

investigations = Table(
    "investigations",
    metadata,
    Column("id", String(40), primary_key=True),
    Column("created_at", String(40), nullable=False),
    Column("updated_at", String(40), nullable=False),
    Column("campaign_id", String(40), nullable=True),
    Column("edge_id", String(80), nullable=True),
    Column("status", String(24), nullable=False),
    Column("missing_evidence", Text, nullable=False),
    Column("chosen_profile", String(80), nullable=True),
    Column("hypothesis_before", Text, nullable=False),
    Column("hypothesis_after", Text, nullable=True),
    Column("outcome", String(24), nullable=True),
    Column("notes", Text, nullable=False, default=""),
    Column("algorithm_version", String(24), nullable=False),
    Column("source_ip", String(64), nullable=True),
    Column("expires_at", String(40), nullable=True),
    Index("ix_investigations_campaign", "campaign_id"),
    Index("ix_investigations_active", "status", "source_ip"),
    # At most one open investigation per subject.  A partial index makes the
    # check atomic: of two concurrent planners only one insert commits, and the
    # loser is rejected by the database instead of by a read that saw no row.
    Index(
        "uq_investigations_active_edge",
        "edge_id",
        unique=True,
        sqlite_where=text("status IN ('planned', 'active') AND edge_id IS NOT NULL"),
        postgresql_where=text("status IN ('planned', 'active') AND edge_id IS NOT NULL"),
    ),
    Index(
        "uq_investigations_active_campaign",
        "campaign_id",
        unique=True,
        sqlite_where=text("status IN ('planned', 'active') AND campaign_id IS NOT NULL"),
        postgresql_where=text("status IN ('planned', 'active') AND campaign_id IS NOT NULL"),
    ),
)

source_health = Table(
    "source_health",
    metadata,
    Column("source", String(120), primary_key=True),
    Column("last_event_at", String(40), nullable=True),
    Column("last_success_at", String(40), nullable=True),
    Column("last_error_at", String(40), nullable=True),
    Column("error_count", Integer, nullable=False, default=0),
    Column("ok", Integer, nullable=False, default=1),
    Column("detail", Text, nullable=False, default="{}"),
)

correlation_runs = Table(
    "correlation_runs",
    metadata,
    Column("id", String(40), primary_key=True),
    Column("started_at", String(40), nullable=False),
    Column("finished_at", String(40), nullable=False),
    Column("window_start", String(40), nullable=False),
    Column("window_end", String(40), nullable=False),
    Column("sessions", Integer, nullable=False, default=0),
    Column("edges_created", Integer, nullable=False, default=0),
    Column("edges_updated", Integer, nullable=False, default=0),
    Column("edges_expired", Integer, nullable=False, default=0),
    Column("campaigns", Integer, nullable=False, default=0),
    Column("algorithm_version", String(24), nullable=False),
    Column("status", String(24), nullable=False),
    Column("error", Text, nullable=True),
    Column("metrics", Text, nullable=False, default="{}"),
    Column("trigger", String(32), nullable=False, default="manual"),
)

retention_runs = Table(
    "retention_runs",
    metadata,
    Column("id", String(40), primary_key=True),
    Column("ran_at", String(40), nullable=False),
    Column("trigger", String(24), nullable=False),
    Column("duration_ms", Integer, nullable=False, default=0),
    Column("events_removed", Integer, nullable=False, default=0),
    Column("edges_removed", Integer, nullable=False, default=0),
    Column("observations_removed", Integer, nullable=False, default=0),
    Column("nodes_removed", Integer, nullable=False, default=0),
    # Backlog seen before the run, so the dashboard can show a trend rather
    # than an always-zero count after cleanup.
    Column("events_expired", Integer, nullable=False, default=0),
    Column("retired_edges", Integer, nullable=False, default=0),
    Column("stale_observations", Integer, nullable=False, default=0),
    Column("graph_nodes", Integer, nullable=False, default=0),
    Column("graph_edges", Integer, nullable=False, default=0),
    Column("overdue", Integer, nullable=False, default=0),
    Index("ix_retention_runs_ran_at", "ran_at"),
)

schema_migrations = Table(
    "schema_migrations",
    MetaData(),
    Column("version", Integer, primary_key=True),
    Column("name", String(120), nullable=False),
    Column("applied_at", String(40), nullable=False),
)
