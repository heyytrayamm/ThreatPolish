"""
Tests for SQLAlchemy model metadata and Alembic migration configuration.

These tests verify:
  • All expected tables are registered in Base.metadata
  • Expected columns and constraints exist on each table
  • The Alembic configuration loads correctly and can resolve the DB URL
  • The migration history chain is valid

These tests do NOT require a running PostgreSQL database — they inspect
metadata and config objects in-memory.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import inspect as sa_inspect, create_engine
from sqlalchemy.orm import Session as SASession

from app.db.base import Base

# Import models to register them with Base.metadata
import app.models.event as models  # noqa: F401
from app.models.event import (
    Event,
    SessionModel,
    Alert,
    DetectionRule,
    IngestionFailure,
    alert_events,
)


# ===================================================================
# 1. Table registration — all models visible in metadata
# ===================================================================

class TestTableRegistration:
    """Every model table must appear in Base.metadata."""

    EXPECTED_TABLES = {
        "sessions",
        "events",
        "alerts",
        "detection_rules",
        "alert_events",
        "ingestion_failures",
    }

    def test_all_expected_tables_registered(self):
        registered = set(Base.metadata.tables.keys())
        for table in self.EXPECTED_TABLES:
            assert table in registered, f"Table '{table}' missing from metadata"

    def test_no_unexpected_tables(self):
        """Guard against accidentally adding extra tables in this phase."""
        registered = set(Base.metadata.tables.keys())
        assert registered == self.EXPECTED_TABLES


# ===================================================================
# 2. Column and constraint checks
# ===================================================================

class TestEventTableStructure:
    """The 'events' table must have the expected columns and constraints."""

    def test_events_has_event_id_column(self):
        table = Base.metadata.tables["events"]
        col_names = {c.name for c in table.columns}
        assert "event_id" in col_names

    def test_events_event_id_is_unique(self):
        table = Base.metadata.tables["events"]
        unique_names = {c.name for c in table.constraints if hasattr(c, "name")}
        # The constraint name we set in the model
        assert "uq_events_event_id" in unique_names

    def test_events_has_expected_columns(self):
        table = Base.metadata.tables["events"]
        col_names = {c.name for c in table.columns}
        expected = {
            "id", "event_id", "schema_version", "timestamp",
            "session_id", "sensor_id", "service",
            "source_ip", "source_port", "destination_ip", "destination_port",
            "protocol", "event_type", "payload", "raw_event_ref",
            "auth_outcome", "auth_username", "auth_password_length",
            "ingested_at", "ingestion_source", "created_at",
        }
        for col in expected:
            assert col in col_names, f"Column '{col}' missing from events table"

    def test_events_no_password_column(self):
        """Credentials must NEVER be stored in the events table."""
        table = Base.metadata.tables["events"]
        col_names = {c.name for c in table.columns}
        forbidden = {"password", "password_hash", "api_secret", "credential"}
        found = forbidden & col_names
        assert not found, f"Forbidden credential columns found: {found}"


class TestSessionTableStructure:
    def test_sessions_has_source_ip(self):
        table = Base.metadata.tables["sessions"]
        col_names = {c.name for c in table.columns}
        assert "source_ip" in col_names


class TestAlertTableStructure:
    def test_alerts_has_rule_fk(self):
        table = Base.metadata.tables["alerts"]
        fk_cols = {fk.parent.name for fk in table.foreign_keys}
        assert "rule_id" in fk_cols

    def test_alert_events_association(self):
        table = Base.metadata.tables["alert_events"]
        col_names = {c.name for c in table.columns}
        assert col_names == {"alert_id", "event_id"}


# ===================================================================
# 3. In-memory SQLite smoke test for model instantiation
# ===================================================================

class TestModelInstantiationSQLite:
    """
    Create tables in an in-memory SQLite database and verify that
    model instances can be created.  This does NOT test PostgreSQL-
    specific features (JSONB, UUID) but validates the ORM wiring.
    """

    @pytest.fixture(autouse=True)
    def setup_sqlite(self):
        """Create all tables in a disposable SQLite database."""
        # SQLite doesn't support PG_UUID natively, but SQLAlchemy
        # gracefully degrades it.  Good enough for structural smoke tests.
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.session = SASession(self.engine)
        yield
        self.session.close()
        Base.metadata.drop_all(self.engine)
        self.engine.dispose()

    def test_create_session_model(self):
        s = SessionModel(
            id=uuid.uuid4(),
            source_ip="192.0.2.1",
            sensor_id="test-sensor",
            started_at=datetime.now(timezone.utc),
        )
        self.session.add(s)
        self.session.commit()
        assert self.session.get(SessionModel, s.id) is not None

    def test_create_event(self):
        ev = Event(
            id=uuid.uuid4(),
            event_id=uuid.uuid4(),
            schema_version="1.0",
            timestamp=datetime.now(timezone.utc),
            sensor_id="test-sensor",
            service="ssh-decoy",
            source_ip="192.0.2.1",
            protocol="ssh",
            event_type="auth_attempt",
        )
        self.session.add(ev)
        self.session.commit()
        assert self.session.get(Event, ev.id) is not None

    def test_duplicate_event_id_rejected(self):
        """Two events with the same event_id must violate the unique constraint."""
        eid = uuid.uuid4()
        ev1 = Event(
            id=uuid.uuid4(), event_id=eid, schema_version="1.0",
            timestamp=datetime.now(timezone.utc),
            sensor_id="s", service="svc", source_ip="192.0.2.1",
            protocol="tcp", event_type="connection",
        )
        ev2 = Event(
            id=uuid.uuid4(), event_id=eid, schema_version="1.0",
            timestamp=datetime.now(timezone.utc),
            sensor_id="s", service="svc", source_ip="192.0.2.2",
            protocol="tcp", event_type="connection",
        )
        self.session.add(ev1)
        self.session.commit()
        self.session.add(ev2)
        with pytest.raises(Exception):  # IntegrityError
            self.session.commit()
        self.session.rollback()

    def test_create_detection_rule(self):
        rule = DetectionRule(
            id=uuid.uuid4(),
            name="test-rule",
            severity="high",
            enabled=True,
        )
        self.session.add(rule)
        self.session.commit()
        assert self.session.get(DetectionRule, rule.id) is not None

    def test_create_alert_with_rule(self):
        rule = DetectionRule(
            id=uuid.uuid4(),
            name="alert-test-rule",
            severity="medium",
            enabled=True,
        )
        self.session.add(rule)
        self.session.commit()

        alert = Alert(
            id=uuid.uuid4(),
            rule_id=rule.id,
            severity="medium",
            title="Test alert",
            resolved=False,
        )
        self.session.add(alert)
        self.session.commit()
        assert self.session.get(Alert, alert.id) is not None
        assert alert.rule_id == rule.id

    def test_create_ingestion_failure(self):
        failure = IngestionFailure(
            id=uuid.uuid4(),
            error_message="Failed to parse raw event",
            ingestion_source="test-collector",
        )
        self.session.add(failure)
        self.session.commit()
        assert self.session.get(IngestionFailure, failure.id) is not None

    def test_event_session_relationship(self):
        """An event linked to a session should be accessible via the relationship."""
        sess = SessionModel(
            id=uuid.uuid4(),
            source_ip="192.0.2.5",
            sensor_id="test",
            started_at=datetime.now(timezone.utc),
        )
        self.session.add(sess)
        self.session.commit()

        ev = Event(
            id=uuid.uuid4(), event_id=uuid.uuid4(), schema_version="1.0",
            timestamp=datetime.now(timezone.utc),
            session_id=sess.id,
            sensor_id="test", service="svc", source_ip="192.0.2.5",
            protocol="tcp", event_type="scan",
        )
        self.session.add(ev)
        self.session.commit()

        # Refresh to load relationships
        self.session.refresh(sess)
        assert len(sess.events) == 1
        assert sess.events[0].event_id == ev.event_id

    def test_alert_event_relationship(self):
        """Verify the many-to-many relationship between Alert and Event."""
        rule = DetectionRule(
            id=uuid.uuid4(),
            name="m2m-test-rule",
            severity="high",
            enabled=True,
        )
        self.session.add(rule)
        self.session.commit()

        ev1 = Event(
            id=uuid.uuid4(), event_id=uuid.uuid4(), schema_version="1.0",
            timestamp=datetime.now(timezone.utc),
            sensor_id="test", service="svc", source_ip="192.0.2.10",
            protocol="tcp", event_type="scan",
        )
        ev2 = Event(
            id=uuid.uuid4(), event_id=uuid.uuid4(), schema_version="1.0",
            timestamp=datetime.now(timezone.utc),
            sensor_id="test", service="svc", source_ip="192.0.2.11",
            protocol="tcp", event_type="scan",
        )
        self.session.add_all([ev1, ev2])
        self.session.commit()

        alert = Alert(
            id=uuid.uuid4(),
            rule_id=rule.id,
            severity="high",
            title="M2M Alert",
            resolved=False,
        )
        alert.events.append(ev1)
        alert.events.append(ev2)
        self.session.add(alert)
        self.session.commit()

        self.session.refresh(alert)
        assert len(alert.events) == 2
        event_ids = {e.event_id for e in alert.events}
        assert ev1.event_id in event_ids
        assert ev2.event_id in event_ids

        # Back-reference
        self.session.refresh(ev1)
        assert len(ev1.alerts) == 1
        assert ev1.alerts[0].id == alert.id

    def test_package_exports_all_models(self):
        """Confirm app.models exports all models including Session alias."""
        import app.models as pkg
        for name in ["Event", "Session", "SessionModel", "Alert", "DetectionRule", "IngestionFailure", "alert_events"]:
            assert hasattr(pkg, name), f"Model '{name}' not exported from app.models"
            assert getattr(pkg, name) is not None


# ===================================================================
# 4. Alembic configuration
# ===================================================================

class TestAlembicConfig:
    """Verify Alembic can load its configuration and find migration scripts."""

    def test_alembic_config_loads(self):
        from alembic.config import Config
        cfg = Config("alembic.ini")
        assert cfg.get_main_option("script_location") is not None

    def test_alembic_has_migration_scripts(self):
        from alembic.config import Config
        from alembic.script import ScriptDirectory
        cfg = Config("alembic.ini")
        script_dir = ScriptDirectory.from_config(cfg)
        heads = script_dir.get_heads()
        assert len(heads) >= 1, "No migration heads found"

    def test_alembic_revision_chain(self):
        """The migration chain from base to head must be unbroken."""
        from alembic.config import Config
        from alembic.script import ScriptDirectory
        cfg = Config("alembic.ini")
        script_dir = ScriptDirectory.from_config(cfg)
        revisions = list(script_dir.walk_revisions())
        assert len(revisions) >= 1
        # The last revision's down_revision should be None (it's the first)
        first = revisions[-1]
        assert first.down_revision is None


# ===================================================================
# 5. Database session module
# ===================================================================

class TestDBSessionModule:
    """Verify the session module structure without needing a live database."""

    def test_get_engine_is_callable(self):
        from app.db.session import get_engine
        assert callable(get_engine)

    def test_get_session_is_generator(self):
        import inspect
        from app.db.session import get_session
        assert inspect.isgeneratorfunction(get_session)

    def test_check_db_ready_is_callable(self):
        from app.db.session import check_db_ready
        assert callable(check_db_ready)

    def test_dispose_engine_is_callable(self):
        from app.db.session import dispose_engine
        assert callable(dispose_engine)


# ===================================================================
# 6. Database URL Resolution (Local Windows vs Docker Container)
# ===================================================================

class TestDatabaseUrlConfiguration:
    """Verify that DATABASE_URL is correctly resolved for both local development and Docker."""

    def test_local_default_uses_localhost(self, monkeypatch):
        from app.core.config import Settings
        monkeypatch.delenv("POSTGRES_HOST", raising=False)
        monkeypatch.delenv("DATABASE_URL", raising=False)
        s = Settings(_env_file=None)
        assert s.POSTGRES_HOST == "127.0.0.1"
        assert "@127.0.0.1:5432" in s.DATABASE_URL

    def test_docker_postgres_host_updates_database_url(self, monkeypatch):
        from app.core.config import Settings
        monkeypatch.setenv("POSTGRES_HOST", "db")
        monkeypatch.delenv("DATABASE_URL", raising=False)
        s = Settings(_env_file=None)
        assert s.POSTGRES_HOST == "db"
        assert "@db:5432" in s.DATABASE_URL

    def test_docker_host_overrides_localhost_database_url_from_env(self, monkeypatch):
        """If a shared .env provides localhost DATABASE_URL, POSTGRES_HOST=db must not be ignored."""
        from app.core.config import Settings
        monkeypatch.setenv("POSTGRES_HOST", "db")
        monkeypatch.setenv(
            "DATABASE_URL",
            "postgresql+psycopg://user:pass@127.0.0.1:5432/threatpolish_db",
        )
        s = Settings(_env_file=None)
        assert s.POSTGRES_HOST == "db"
        assert "@db:5432" in s.DATABASE_URL

    def test_custom_remote_database_url_preserved(self, monkeypatch):
        """Custom non-localhost URLs (e.g. AWS RDS) should be preserved as-is."""
        from app.core.config import Settings
        remote_url = "postgresql+psycopg://user:pass@rds.us-east-1.amazonaws.com:5432/proddb"
        monkeypatch.setenv("DATABASE_URL", remote_url)
        s = Settings(_env_file=None)
        assert s.DATABASE_URL == remote_url

