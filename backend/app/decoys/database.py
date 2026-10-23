"""
Database Interaction Simulator for ThreatPolish.

Simulates database service interactions safely:
  • Accepts synthetic database connection and query interactions.
  • Analyzes query patterns for SQL injection signatures without executing them.
  • Returns simulated database error responses (e.g. PostgreSQL 28P01 / 42501).
  • NEVER connects the simulated caller to any real database engine.
  • NEVER executes submitted SQL queries.
  • NEVER logs or persists connection passwords or credentials.
"""

from __future__ import annotations

import logging
import re
import uuid
from typing import Any

from app.decoys.base import BaseDecoySimulator, DecoyInteractionResult
from app.schemas.event import (
    AuthMetadata,
    AuthOutcome,
    CanonicalEvent,
    EventTypeEnum,
    ProtocolEnum,
)
from app.services.ingestion import TelemetryIngestionService

logger = logging.getLogger("threatpolish.decoys.database")

# Suspicious SQL keywords / patterns to flag in telemetry without executing
SUSPICIOUS_SQL_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("sql_injection_tautology", re.compile(r"('\s*OR\s*'1'\s*=\s*'1|1\s*=\s*1|'\s*OR\s*1\s*=\s*1)", re.IGNORECASE)),
    ("union_select", re.compile(r"UNION\s+(ALL\s+)?SELECT", re.IGNORECASE)),
    ("schema_recon", re.compile(r"(information_schema|pg_catalog|sys\.tables|sqlite_master)", re.IGNORECASE)),
    ("time_based_blind", re.compile(r"(pg_sleep|sleep\s*\(|benchmark\s*\(|waitfor\s+delay)", re.IGNORECASE)),
    ("destructive_ddl", re.compile(r"(DROP\s+TABLE|TRUNCATE|DELETE\s+FROM|ALTER\s+TABLE)", re.IGNORECASE)),
    ("stacked_query", re.compile(r";\s*(SELECT|INSERT|UPDATE|DELETE|DROP|EXEC)", re.IGNORECASE)),
]


def sanitize_sql_query(query: str) -> str:
    """
    Sanitize an SQL query sample to prevent storing raw secrets or sensitive literal values.
    Redacts string literals following sensitive column names/clauses like password, token, secret.
    """
    sanitized = query
    # If the statement mentions sensitive columns in an INSERT ... VALUES statement:
    if re.search(r"(?i)\b(password|passwd|pwd|token|secret|key|credential)\b", sanitized) and re.search(r"(?i)\bVALUES\s*\(", sanitized):
        def _redact_values(match: re.Match) -> str:
            val_clause = match.group(0)
            return re.sub(r"('[^']*'|\"[^\"]*\")", "'[REDACTED]'", val_clause)
        sanitized = re.sub(r"(?i)\bVALUES\s*\([^)]*\)", _redact_values, sanitized)

    # Redact assignments or comparisons: e.g. password = '...', SET token = '...'
    sanitized = re.sub(
        r"(?i)\b(password|passwd|pwd|token|secret|api_key|apikey|credential|auth|key)\s*(=|LIKE|:\s*=)\s*('[^']*'|\"[^\"]*\")",
        r"\1 \2 '[REDACTED]'",
        sanitized,
    )
    # Redact SET clauses (e.g. SET password = '...')
    sanitized = re.sub(
        r"(?i)(SET\s+[^;]*\b(password|token|secret|key|credential)\s*=\s*)('[^']*'|\"[^\"]*\")",
        r"\1'[REDACTED]'",
        sanitized,
    )
    return sanitized


class DatabaseDecoySimulator(BaseDecoySimulator):
    """
    Simulates a database listener/service (PostgreSQL/MySQL style) safely in-process.
    """

    def __init__(
        self,
        sensor_id: str = "db-decoy-01",
        service_name: str = "postgres-decoy",
        db_dialect: str = "postgresql",
        ingestion_service: TelemetryIngestionService | None = None,
    ) -> None:
        super().__init__(
            sensor_id=sensor_id,
            service_name=service_name,
            ingestion_service=ingestion_service,
        )
        self.db_dialect = db_dialect

    def simulate_connection_attempt(
        self,
        source_ip: str,
        username: str,
        password: str | None = None,
        password_length: int | None = None,
        database_name: str = "threatpolish_prod",
        source_port: int = 49876,
        destination_port: int = 5432,
        session_id: uuid.UUID | None = None,
    ) -> DecoyInteractionResult:
        """
        Simulate an unauthorized database connection / handshake attempt.

        Computes password length without retaining credentials on the instance or event.
        Returns a mock FATAL authentication error and emits a CanonicalEvent.
        """
        if password is not None:
            resolved_pw_len = len(password)
            del password  # Remove local reference; do not store on event or instance
        elif password_length is not None:
            resolved_pw_len = max(0, password_length)
        else:
            resolved_pw_len = 0

        logger.info(
            "Simulating DB connection from %s user '%s' db '%s' (pw_len=%d)",
            source_ip,
            username,
            database_name,
            resolved_pw_len,
        )

        event = CanonicalEvent(
            event_id=self._new_uuid(),
            session_id=session_id,
            sensor_id=self.sensor_id,
            timestamp=self._utcnow(),
            source_ip=source_ip,
            source_port=source_port,
            destination_port=destination_port,
            protocol=ProtocolEnum.TCP,
            service=self.service_name,
            event_type=EventTypeEnum.AUTH_ATTEMPT,
            auth=AuthMetadata(
                username=username[:256] if username else None,
                auth_outcome=AuthOutcome.FAILURE,
                password_length=resolved_pw_len,
            ),
            payload={
                "db_name": database_name[:64],
                "db_dialect": self.db_dialect,
                "client_encoding": "UTF8",
            },
        )

        simulated_response: dict[str, Any] = {
            "status": "fatal",
            "sqlstate": "28P01",
            "message": f'FATAL: password authentication failed for user "{username}"',
            "severity": "FATAL",
        }

        ingestion_result = self._ingest_event(event)

        return DecoyInteractionResult(
            simulated_response=simulated_response,
            event=event,
            ingestion_result=ingestion_result,
        )

    def simulate_query(
        self,
        source_ip: str,
        raw_query: str,
        database_name: str = "threatpolish_prod",
        source_port: int = 49876,
        destination_port: int = 5432,
        session_id: uuid.UUID | None = None,
    ) -> DecoyInteractionResult:
        """
        Simulate an unauthorized or suspicious database query.

        Analyzes the query string for SQL injection or reconnaissance patterns
        without EVER passing the query to any database engine or executing it.
        """
        # Detect signatures defensively
        detected_patterns: list[str] = []
        for name, pattern in SUSPICIOUS_SQL_PATTERNS:
            if pattern.search(raw_query):
                detected_patterns.append(name)

        is_suspicious = len(detected_patterns) > 0
        event_type = EventTypeEnum.COMMAND if is_suspicious else EventTypeEnum.QUERY

        logger.info(
            "Simulating DB query from %s: '%s' (detected: %s)",
            source_ip,
            raw_query[:60],
            detected_patterns,
        )

        event = CanonicalEvent(
            event_id=self._new_uuid(),
            session_id=session_id,
            sensor_id=self.sensor_id,
            timestamp=self._utcnow(),
            source_ip=source_ip,
            source_port=source_port,
            destination_port=destination_port,
            protocol=ProtocolEnum.TCP,
            service=self.service_name,
            event_type=event_type,
            payload={
                "query_sample": sanitize_sql_query(raw_query)[:256],
                "query_length": len(raw_query),
                "detected_patterns": detected_patterns,
                "db_name": database_name[:64],
            },
        )

        # Standard simulated database error returned to simulated attacker
        simulated_response: dict[str, Any] = {
            "status": "error",
            "sqlstate": "42501",
            "message": "ERROR: permission denied for relation or table",
            "severity": "ERROR",
        }

        ingestion_result = self._ingest_event(event)

        return DecoyInteractionResult(
            simulated_response=simulated_response,
            event=event,
            ingestion_result=ingestion_result,
        )
