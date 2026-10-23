"""
Tests for the ThreatPolish Telemetry Ingestion Pipeline.

Verifies:
  • Event validation and schema normalization.
  • UTC timestamp normalization.
  • Database persistence into the Event model.
  • Idempotent handling of duplicate event IDs.
  • SessionModel automatic creation and foreign-key linking.
  • Validation failure handling and IngestionFailure table recording.
  • Database error propagation and transaction rollback.
  • Credential stripping from error logs and failure payloads.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session as SASession

from app.db.base import Base
from app.models.event import Event, IngestionFailure, SessionModel
from app.schemas.event import (
    AuthMetadata,
    AuthOutcome,
    CanonicalEvent,
    EventTypeEnum,
    ProtocolEnum,
)
from app.services.ingestion import (
    IngestionResult,
    TelemetryIngestionService,
    sanitize_dict_for_logging,
)


@pytest.fixture
def db_session():
    """Create an isolated, in-memory SQLite database for testing."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = SASession(engine)
    yield session
    session.close()
    Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture
def ingestion_service(db_session):
    return TelemetryIngestionService(db_session=db_session)


def make_valid_canonical_event(
    event_id: uuid.UUID | None = None,
    session_id: uuid.UUID | None = None,
    source_ip: str = "192.0.2.1",
    timestamp: datetime | None = None,
) -> CanonicalEvent:
    return CanonicalEvent(
        event_id=event_id or uuid.uuid4(),
        session_id=session_id,
        sensor_id="test-sensor-01",
        service="ssh-decoy",
        source_ip=source_ip,
        source_port=54321,
        destination_port=22,
        protocol=ProtocolEnum.SSH,
        event_type=EventTypeEnum.AUTH_ATTEMPT,
        timestamp=timestamp or datetime.now(timezone.utc),
        auth=AuthMetadata(
            username="analyst_test",
            auth_outcome=AuthOutcome.FAILURE,
            password_length=12,
        ),
        payload={"client_version": "SSH-2.0-OpenSSH_8.9p1"},
    )


class TestTelemetryIngestionSuccess:
    """Tests for successful event ingestion and persistence."""

    def test_ingest_canonical_event_persists_to_db(self, ingestion_service, db_session):
        event = make_valid_canonical_event()
        result = ingestion_service.ingest(event)

        assert result.success is True
        assert result.event_id == event.event_id
        assert result.is_duplicate is False

        # Query database to confirm row exists
        saved = db_session.query(Event).filter(Event.event_id == event.event_id).first()
        assert saved is not None
        assert saved.event_id == event.event_id
        assert saved.service == "ssh-decoy"
        assert saved.source_ip == "192.0.2.1"
        assert saved.auth_username == "analyst_test"
        assert saved.auth_outcome == "failure"
        assert saved.auth_password_length == 12

    def test_ingest_raw_dict_persists_to_db(self, ingestion_service, db_session):
        raw_data = {
            "sensor_id": "rest-sensor-01",
            "service": "rest-decoy",
            "source_ip": "198.51.100.25",
            "protocol": "http",
            "event_type": "recon",
            "payload": {"method": "GET", "path": "/admin"},
        }
        result = ingestion_service.ingest(raw_data, ingestion_source="rest-decoy")

        assert result.success is True
        assert result.event_id is not None
        saved = db_session.query(Event).filter(Event.event_id == result.event_id).first()
        assert saved is not None
        assert saved.source_ip == "198.51.100.25"
        assert saved.service == "rest-decoy"

    def test_timezone_normalization_to_utc(self, ingestion_service, db_session):
        # Timezone with +05:30 offset
        tz_offset = timezone(timedelta(hours=5, minutes=30))
        local_time = datetime(2026, 10, 23, 12, 0, 0, tzinfo=tz_offset)
        event = make_valid_canonical_event(timestamp=local_time)

        result = ingestion_service.ingest(event)
        assert result.success is True

        # In SQLite, DateTime values roundtrip as naive UTC; verify time was converted to 06:30 UTC
        saved = db_session.query(Event).filter(Event.event_id == event.event_id).first()
        assert saved.timestamp.hour == 6
        assert saved.timestamp.minute == 30


class TestIdempotentDuplicateHandling:
    """Tests for duplicate event_id handling."""

    def test_duplicate_event_id_is_idempotent(self, ingestion_service, db_session):
        shared_id = uuid.uuid4()
        event1 = make_valid_canonical_event(event_id=shared_id)
        event2 = make_valid_canonical_event(event_id=shared_id)

        res1 = ingestion_service.ingest(event1)
        assert res1.success is True
        assert res1.is_duplicate is False

        # Ingesting the same event_id again
        res2 = ingestion_service.ingest(event2)
        assert res2.success is True
        assert res2.is_duplicate is True
        assert res2.event_id == shared_id

        # Database should only contain ONE row with this event_id
        count = db_session.query(Event).filter(Event.event_id == shared_id).count()
        assert count == 1


class TestSessionHandling:
    """Tests for session creation and foreign key integrity."""

    def test_session_automatically_created_if_missing(self, ingestion_service, db_session):
        sess_id = uuid.uuid4()
        event = make_valid_canonical_event(session_id=sess_id)

        result = ingestion_service.ingest(event)
        assert result.success is True

        # Confirm session row exists
        session_row = db_session.get(SessionModel, sess_id)
        assert session_row is not None
        assert session_row.id == sess_id
        assert session_row.source_ip == "192.0.2.1"

    def test_multiple_events_share_same_session(self, ingestion_service, db_session):
        sess_id = uuid.uuid4()
        ev1 = make_valid_canonical_event(session_id=sess_id)
        ev2 = make_valid_canonical_event(session_id=sess_id)

        res1 = ingestion_service.ingest(ev1)
        res2 = ingestion_service.ingest(ev2)
        assert res1.success is True
        assert res2.success is True

        session_row = db_session.get(SessionModel, sess_id)
        assert session_row is not None
        assert len(session_row.events) == 2


class TestIngestionFailuresAndSafety:
    """Tests for invalid payloads and failure recording."""

    def test_invalid_payload_records_ingestion_failure(self, ingestion_service, db_session):
        # Missing required fields like source_ip, protocol, service
        invalid_data = {
            "sensor_id": "test-sensor",
            "bad_field": "unknown",
        }
        result = ingestion_service.ingest(invalid_data, ingestion_source="bad-sensor")

        assert result.success is False
        assert "Schema validation error" in result.error

        # Confirm entry recorded in ingestion_failures table
        failures = db_session.query(IngestionFailure).all()
        assert len(failures) == 1
        assert failures[0].sensor_id == "test-sensor"
        assert failures[0].ingestion_source == "bad-sensor"
        assert "validation" in failures[0].error_message.lower()

    def test_credentials_sanitized_in_failure_records(self, ingestion_service, db_session):
        # Attacker submitted raw password in payload
        bad_data_with_secret = {
            "sensor_id": "secret-trap",
            "password": "SuperSecretPassword123!",
            "api_key": "raw-api-token-value",
        }
        result = ingestion_service.ingest(bad_data_with_secret, ingestion_source="leak-test")
        assert result.success is False

        failure = db_session.query(IngestionFailure).first()
        assert failure is not None
        raw_recorded = str(failure.raw_payload)
        assert "SuperSecretPassword123!" not in raw_recorded
        assert "raw-api-token-value" not in raw_recorded
        assert "[REDACTED]" in raw_recorded

    def test_database_error_triggers_rollback(self, db_session):
        """Simulate an unexpected database error and verify rollback and failure result."""
        failing_session = MagicMock()
        failing_session.query.side_effect = Exception("Simulated DB connection lost")

        service = TelemetryIngestionService(db_session=failing_session)
        event = make_valid_canonical_event()

        result = service.ingest(event)
        assert result.success is False
        assert "Simulated DB connection lost" in result.error
        failing_session.rollback.assert_called_once()


class TestSanitizeHelper:
    def test_sanitize_dict_for_logging(self):
        sample = {
            "username": "admin",
            "password": "mypassword",
            "nested": {
                "token": "secret_token",
                "normal": "value",
            },
            "list_items": [{"key": "secret_key", "visible": "ok"}],
        }
        clean = sanitize_dict_for_logging(sample)
        assert clean["username"] == "admin"
        assert clean["password"] == "[REDACTED]"
        assert clean["nested"]["token"] == "[REDACTED]"
        assert clean["nested"]["normal"] == "value"
        assert clean["list_items"][0]["key"] == "[REDACTED]"
        assert clean["list_items"][0]["visible"] == "ok"
