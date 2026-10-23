"""
Tests for ThreatPolish Decoy Simulators:
  • SSHDecoySimulator
  • RESTDecoySimulator
  • DatabaseDecoySimulator

Verifies:
  • Correct harmless simulated responses.
  • Canonical event generation adhering to schema v1.0.
  • Strict credential exclusion (no passwords or secrets stored).
  • Traps for reconnaissance (/.env, /admin, SQL injection probes).
  • Zero command execution and zero real database connections.
  • Ingestion pipeline integration and session tracking.
"""

from __future__ import annotations

import os
import uuid
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session as SASession

from app.db.base import Base
from app.decoys.database import DatabaseDecoySimulator
from app.decoys.rest import RESTDecoySimulator
from app.decoys.ssh import SSHDecoySimulator
from app.models.event import Event, SessionModel
from app.schemas.event import AuthOutcome, EventTypeEnum, ProtocolEnum
from app.services.ingestion import TelemetryIngestionService


@pytest.fixture
def db_session():
    """Isolated in-memory SQLite database for simulator telemetry verification."""
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


# ==============================================================================
# 1. SSH Decoy Simulator Tests
# ==============================================================================

class TestSSHDecoySimulator:
    """Verifies safe simulation of SSH authentication attempts."""

    def test_ssh_login_simulation_normal_behavior(self):
        sim = SSHDecoySimulator(sensor_id="ssh-test-01")
        result = sim.simulate_login(
            source_ip="192.0.2.10",
            username="root",
            password="AttackerPassword2026!",
        )

        # 1. Check simulated response returned to caller
        assert result.simulated_response["status"] == "failure"
        assert "Permission denied" in result.simulated_response["message"]
        assert "publickey" in result.simulated_response["allowed_auth_methods"]

        # 2. Check canonical telemetry event
        event = result.event
        assert event.protocol == ProtocolEnum.SSH
        assert event.event_type == EventTypeEnum.AUTH_ATTEMPT
        assert str(event.source_ip) == "192.0.2.10"
        assert event.destination_port == 22
        assert event.auth is not None
        assert event.auth.username == "root"
        assert event.auth.auth_outcome == AuthOutcome.FAILURE

        # 3. CRITICAL: Raw password must NEVER appear in event or payload
        assert event.auth.password_length == len("AttackerPassword2026!")
        assert "AttackerPassword2026!" not in str(event.model_dump())

    def test_ssh_no_command_execution_capability(self):
        """Confirm simulator has no interface or capability to execute commands."""
        sim = SSHDecoySimulator()
        assert not hasattr(sim, "execute_command")
        assert not hasattr(sim, "run_shell")
        assert not hasattr(sim, "exec")

    def test_ssh_ingestion_integration(self, ingestion_service, db_session):
        sim = SSHDecoySimulator(ingestion_service=ingestion_service)
        session_id = uuid.uuid4()

        result = sim.simulate_login(
            source_ip="192.0.2.11",
            username="admin",
            password="SecretPassword123",
            session_id=session_id,
        )

        assert result.ingestion_result is not None
        assert result.ingestion_result.success is True

        # Verify event saved in database
        db_event = db_session.query(Event).filter(Event.event_id == result.event.event_id).first()
        assert db_event is not None
        assert db_event.service == "ssh-decoy"
        assert db_event.session_id == session_id
        assert db_event.auth_password_length == len("SecretPassword123")
        assert "SecretPassword123" not in str(db_event.payload)


# ==============================================================================
# 2. REST API Decoy Simulator Tests
# ==============================================================================

class TestRESTDecoySimulator:
    """Verifies safe simulation of Web/REST decoy endpoints."""

    def test_rest_admin_trap_endpoint(self):
        sim = RESTDecoySimulator()
        result = sim.simulate_request(
            method="GET",
            path="/admin",
            source_ip="198.51.100.5",
        )

        assert result.simulated_response["status_code"] == 401
        assert "WWW-Authenticate" in result.simulated_response["headers"]
        assert result.event.event_type == EventTypeEnum.RECON
        assert result.event.payload["is_trap_path"] is True

    def test_rest_env_file_trap_never_exposes_real_env(self):
        """/.env request returns 404 and NEVER exposes actual server environment variables."""
        sim = RESTDecoySimulator()
        result = sim.simulate_request(
            method="GET",
            path="/.env",
            source_ip="198.51.100.12",
        )

        resp = result.simulated_response
        assert resp["status_code"] == 404
        assert "The requested configuration file does not exist" in resp["body"]["message"]

        # Ensure no real system env vars leaked in response or payload
        for env_key in ("PATH", "DATABASE_URL", "POSTGRES_PASSWORD", "SECRET_KEY"):
            val = os.getenv(env_key)
            if val and len(val) > 4:
                assert val not in str(resp)
                assert val not in str(result.event.payload)

    def test_rest_strips_sensitive_headers_and_body_tokens(self):
        sim = RESTDecoySimulator()
        result = sim.simulate_request(
            method="POST",
            path="/api/login",
            source_ip="198.51.100.44",
            headers={
                "Authorization": "Bearer super-secret-jwt-token-12345",
                "Cookie": "session_id=private-session-token",
                "User-Agent": "AttackerProbe/1.0",
            },
            body={"user": "attacker", "password": "TargetPassword999"},
        )

        payload = result.event.payload
        payload_str = str(payload)
        assert "super-secret-jwt-token-12345" not in payload_str
        assert "private-session-token" not in payload_str
        assert "TargetPassword999" not in payload_str
        assert payload["user_agent"] == "AttackerProbe/1.0"

    def test_rest_redacts_sensitive_query_parameters_in_path(self):
        """Sensitive query params like ?password=... or ?token=... in the URL path must be redacted."""
        sim = RESTDecoySimulator()
        result = sim.simulate_request(
            method="GET",
            path="/login?username=victim&password=SuperSecretPassword123&api_key=my_raw_key",
            source_ip="198.51.100.33",
        )

        path_recorded = result.event.payload["path"]
        assert "SuperSecretPassword123" not in path_recorded
        assert "my_raw_key" not in path_recorded
        assert "password=%5BREDACTED%5D" in path_recorded or "password=[REDACTED]" in path_recorded
        assert "username=victim" in path_recorded

    def test_rest_ingestion_integration(self, ingestion_service, db_session):
        sim = RESTDecoySimulator(ingestion_service=ingestion_service)
        result = sim.simulate_request(
            method="GET",
            path="/wp-admin",
            source_ip="198.51.100.99",
        )

        assert result.ingestion_result is not None
        assert result.ingestion_result.success is True

        db_event = db_session.query(Event).filter(Event.event_id == result.event.event_id).first()
        assert db_event is not None
        assert db_event.service == "rest-decoy"
        assert db_event.payload["path"] == "/wp-admin"
        assert db_event.payload["response_status"] == 403


# ==============================================================================
# 3. Database Decoy Simulator Tests
# ==============================================================================

class TestDatabaseDecoySimulator:
    """Verifies safe simulation of database interactions and SQL injection detection."""

    def test_database_connection_simulation(self):
        sim = DatabaseDecoySimulator()
        result = sim.simulate_connection_attempt(
            source_ip="203.0.113.15",
            username="postgres",
            password="leaked_db_password_attempt",
            database_name="customer_data",
        )

        # 1. Simulated response matches PostgreSQL fatal auth error
        resp = result.simulated_response
        assert resp["status"] == "fatal"
        assert resp["sqlstate"] == "28P01"
        assert 'password authentication failed for user "postgres"' in resp["message"]

        # 2. Telemetry event
        event = result.event
        assert event.protocol == ProtocolEnum.TCP
        assert event.event_type == EventTypeEnum.AUTH_ATTEMPT
        assert event.auth.username == "postgres"
        assert event.auth.auth_outcome == AuthOutcome.FAILURE
        assert event.auth.password_length == len("leaked_db_password_attempt")

        # 3. Password excluded
        assert "leaked_db_password_attempt" not in str(event.model_dump())

    def test_database_query_sql_injection_detection(self):
        """Suspicious SQL queries are detected and flagged in payload without being executed."""
        sim = DatabaseDecoySimulator()
        injected_query = "SELECT * FROM users WHERE username = 'admin' OR '1'='1';"

        result = sim.simulate_query(
            source_ip="203.0.113.50",
            raw_query=injected_query,
        )

        # Simulated response is a harmless DB permission error
        assert result.simulated_response["sqlstate"] == "42501"

        # Check telemetry flagged the pattern
        event = result.event
        assert event.event_type == EventTypeEnum.COMMAND
        assert "sql_injection_tautology" in event.payload["detected_patterns"]
        assert event.payload["query_length"] == len(injected_query)

    def test_database_destructive_query_never_executed(self, db_session):
        """Simulating a destructive DROP TABLE query must NEVER alter the actual database."""
        # Ensure our test SQLite database has an 'events' table
        assert "events" in Base.metadata.tables

        sim = DatabaseDecoySimulator()
        destructive_sql = "DROP TABLE events; TRUNCATE sessions;"

        result = sim.simulate_query(
            source_ip="203.0.113.99",
            raw_query=destructive_sql,
        )

        # Confirm destructive DDL pattern was flagged
        assert "destructive_ddl" in result.event.payload["detected_patterns"]

        # Confirm actual tables are intact and not dropped
        assert db_session.query(Event).count() == 0  # Table still exists and is queryable!

    def test_database_union_select_recon_pattern(self):
        sim = DatabaseDecoySimulator()
        union_query = "UNION SELECT null, username, password FROM information_schema.tables--"

        result = sim.simulate_query(
            source_ip="203.0.113.60",
            raw_query=union_query,
        )

        detected = result.event.payload["detected_patterns"]
        assert "union_select" in detected
        assert "schema_recon" in detected

    def test_database_query_redacts_credentials_in_query_sample(self):
        """SQL statements containing literal passwords/tokens must be redacted before persistence."""
        sim = DatabaseDecoySimulator()
        sql_with_secret = (
            "INSERT INTO accounts (user, password, api_key) "
            "VALUES ('alice', 'SuperSecretPass2026!', 'sk_live_12345abcdef');"
        )
        result = sim.simulate_query(
            source_ip="203.0.113.88",
            raw_query=sql_with_secret,
        )

        sample = result.event.payload["query_sample"]
        assert "SuperSecretPass2026!" not in sample
        assert "sk_live_12345abcdef" not in sample
        assert "[REDACTED]" in sample

    def test_database_ingestion_and_session_continuity(self, ingestion_service, db_session):
        """An attacker establishing connection and then issuing queries shares the same session_id."""
        sim = DatabaseDecoySimulator(ingestion_service=ingestion_service)
        session_id = uuid.uuid4()
        ip = "203.0.113.77"

        # Step 1: Failed connection attempt
        res1 = sim.simulate_connection_attempt(
            source_ip=ip,
            username="sa",
            password="123",
            session_id=session_id,
        )
        assert res1.ingestion_result.success is True

        # Step 2: Probing query attempt
        res2 = sim.simulate_query(
            source_ip=ip,
            raw_query="SELECT pg_sleep(5);",
            session_id=session_id,
        )
        assert res2.ingestion_result.success is True

        # Verify session groups both events in database
        sess_record = db_session.get(SessionModel, session_id)
        assert sess_record is not None
        assert len(sess_record.events) == 2
        event_types = {e.event_type for e in sess_record.events}
        assert "auth_attempt" in event_types
        assert "command" in event_types
