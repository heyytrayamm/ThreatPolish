"""
Telemetry Ingestion Pipeline for ThreatPolish.

This service validates raw or structured telemetry from decoy sensors,
normalises timestamps, enforces canonical schema invariants, and safely
persists events to the database.

Defensive design guarantees:
  • Passwords, secrets, and raw credentials are NEVER logged or persisted.
  • Timestamps are strictly normalised to timezone-aware UTC.
  • Duplicate event_ids are handled idempotently without throwing unhandled exceptions.
  • Invalid payloads are logged safely and recorded in ingestion_failures.
  • Persistence errors rollback transactions and notify the caller.
  • Independent of FastAPI routes and decoy simulator implementations.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.db.session import get_session_factory
from app.models.event import Event, IngestionFailure, SessionModel
from app.schemas.event import CanonicalEvent

logger = logging.getLogger("threatpolish.ingestion")

# Substrings and keywords that identify sensitive credentials
SENSITIVE_KEY_SUBSTRINGS = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "key",
    "api_key",
    "apikey",
    "authorization",
    "auth",
    "cookie",
    "credential",
    "private_key",
)


def is_sensitive_key(key: str) -> bool:
    """Check if a dictionary key or header name represents credential material."""
    k = str(key).lower().replace("-", "_")
    return any(term in k for term in SENSITIVE_KEY_SUBSTRINGS)


def sanitize_dict_for_logging(data: Any) -> Any:
    """
    Recursively remove sensitive credential fields from dictionaries, lists,
    or strings before logging or writing to the ingestion_failures table.
    """
    if isinstance(data, Mapping):
        sanitized = {}
        for k, v in data.items():
            if is_sensitive_key(str(k)):
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = sanitize_dict_for_logging(v)
        return sanitized
    elif isinstance(data, list):
        return [sanitize_dict_for_logging(item) for item in data]
    elif isinstance(data, str):
        # Attempt to parse and sanitize embedded JSON strings
        stripped = data.strip()
        if (stripped.startswith("{") and stripped.endswith("}")) or (
            stripped.startswith("[") and stripped.endswith("]")
        ):
            try:
                parsed = json.loads(stripped)
                return json.dumps(sanitize_dict_for_logging(parsed))
            except Exception:
                pass
        # Redact Bearer tokens in strings
        sanitized_str = re.sub(
            r"(?i)\b(bearer\s+)[A-Za-z0-9_\-\.~+/]+=*",
            r"\1[REDACTED]",
            data,
        )
        # Redact key=value sensitive pairs (e.g. in query strings or form data)
        sanitized_str = re.sub(
            r"(?i)\b(password|passwd|pwd|token|secret|key|api_key|credential|cookie)=[^&\s]+",
            r"\1=[REDACTED]",
            sanitized_str,
        )
        return sanitized_str
    return data


@dataclass
class IngestionResult:
    """Result object returned after processing a telemetry event."""

    success: bool
    event_id: uuid.UUID | None = None
    event: Event | None = None
    is_duplicate: bool = False
    error: str | None = None
    message: str | None = None


class TelemetryIngestionService:
    """
    Shared, reusable ingestion service for ThreatPolish telemetry.

    Can be instantiated with a pre-existing SQLAlchemy ``Session`` (ideal for
    unit tests and transactions) or will lazily acquire sessions from the
    configured engine factory.
    """

    def __init__(self, db_session: Session | None = None) -> None:
        self._db_session = db_session

    def _get_session(self) -> tuple[Session, bool]:
        """
        Return an active session and a flag indicating whether this call
        owns the session lifecycle (and must commit/close it).
        """
        if self._db_session is not None:
            return self._db_session, False
        factory = get_session_factory()
        return factory(), True

    def ingest(
        self,
        event_input: CanonicalEvent | dict[str, Any],
        ingestion_source: str = "decoy-pipeline",
    ) -> IngestionResult:
        """
        Ingest, validate, and persist a single telemetry event.

        Args:
            event_input: Either an already-validated CanonicalEvent instance or
                         a raw dictionary payload to be validated.
            ingestion_source: String identifier of the decoy or sensor pipeline.

        Returns:
            IngestionResult describing success, failure, or duplicate status.
        """
        # 1. Validation & Schema Normalization
        canonical_event: CanonicalEvent
        if isinstance(event_input, CanonicalEvent):
            canonical_event = event_input
        elif isinstance(event_input, dict):
            try:
                canonical_event = CanonicalEvent.model_validate(event_input)
            except (ValidationError, ValueError) as val_err:
                sanitized_input = sanitize_dict_for_logging(event_input)
                err_msg = str(val_err)
                logger.warning(
                    "Telemetry validation failed from source '%s': %s (input keys: %s)",
                    ingestion_source,
                    err_msg,
                    list(sanitized_input.keys()) if isinstance(sanitized_input, dict) else [],
                )
                self._record_failure(
                    raw_payload=sanitized_input,
                    error_message=err_msg,
                    ingestion_source=ingestion_source,
                    sensor_id=event_input.get("sensor_id") if isinstance(event_input, dict) else None,
                )
                return IngestionResult(
                    success=False,
                    error=f"Schema validation error: {err_msg}",
                    is_duplicate=False,
                )
        else:
            err_msg = f"Unsupported event input type: {type(event_input).__name__}"
            logger.error(err_msg)
            return IngestionResult(success=False, error=err_msg)

        # 2. Timestamp Normalization (ensure UTC timezone awareness)
        norm_timestamp = canonical_event.timestamp
        if norm_timestamp.tzinfo is None:
            norm_timestamp = norm_timestamp.replace(tzinfo=timezone.utc)
        else:
            norm_timestamp = norm_timestamp.astimezone(timezone.utc)

        # 3. Persistence
        session, should_close = self._get_session()
        try:
            # Check for existing duplicate event_id (idempotency)
            existing_event = (
                session.query(Event)
                .filter(Event.event_id == canonical_event.event_id)
                .first()
            )
            if existing_event is not None:
                logger.info(
                    "Duplicate event_id '%s' ignored (already ingested)",
                    canonical_event.event_id,
                )
                return IngestionResult(
                    success=True,
                    event_id=canonical_event.event_id,
                    event=existing_event,
                    is_duplicate=True,
                    message="Event already ingested",
                )

            # Ensure referenced SessionModel exists to satisfy foreign key constraint
            if canonical_event.session_id is not None:
                existing_sess = session.get(SessionModel, canonical_event.session_id)
                if existing_sess is None:
                    new_sess = SessionModel(
                        id=canonical_event.session_id,
                        source_ip=str(canonical_event.source_ip),
                        sensor_id=canonical_event.sensor_id,
                        started_at=norm_timestamp,
                    )
                    session.add(new_sess)
                    session.flush()

            # Map canonical fields to SQLAlchemy Event model
            auth_outcome_val = None
            auth_username_val = None
            auth_pw_len_val = None
            if canonical_event.auth is not None:
                outcome = canonical_event.auth.auth_outcome
                auth_outcome_val = outcome.value if hasattr(outcome, "value") else str(outcome)
                auth_username_val = canonical_event.auth.username
                auth_pw_len_val = canonical_event.auth.password_length

            db_event = Event(
                id=uuid.uuid4(),
                event_id=canonical_event.event_id,
                schema_version=canonical_event.schema_version,
                timestamp=norm_timestamp,
                session_id=canonical_event.session_id,
                sensor_id=canonical_event.sensor_id,
                service=canonical_event.service,
                source_ip=str(canonical_event.source_ip),
                source_port=canonical_event.source_port,
                destination_ip=str(canonical_event.destination_ip) if canonical_event.destination_ip else None,
                destination_port=canonical_event.destination_port,
                protocol=canonical_event.protocol.value if hasattr(canonical_event.protocol, "value") else str(canonical_event.protocol),
                event_type=canonical_event.event_type.value if hasattr(canonical_event.event_type, "value") else str(canonical_event.event_type),
                payload=canonical_event.payload,
                raw_event_ref=canonical_event.raw_event_ref,
                auth_outcome=auth_outcome_val,
                auth_username=auth_username_val,
                auth_password_length=auth_pw_len_val,
                ingested_at=datetime.now(timezone.utc),
                ingestion_source=ingestion_source,
            )

            session.add(db_event)
            session.commit()

            logger.debug(
                "Successfully ingested event %s from %s (%s)",
                db_event.event_id,
                db_event.source_ip,
                db_event.service,
            )
            return IngestionResult(
                success=True,
                event_id=db_event.event_id,
                event=db_event,
                is_duplicate=False,
            )

        except IntegrityError as ie:
            session.rollback()
            # If a race condition occurred on unique event_id, handle idempotently
            if "uq_events_event_id" in str(ie) or "event_id" in str(ie):
                existing_event = (
                    session.query(Event)
                    .filter(Event.event_id == canonical_event.event_id)
                    .first()
                )
                if existing_event:
                    return IngestionResult(
                        success=True,
                        event_id=canonical_event.event_id,
                        event=existing_event,
                        is_duplicate=True,
                        message="Event already ingested (concurrent race handled)",
                    )
            logger.error("Database integrity error during event ingestion: %s", ie)
            return IngestionResult(
                success=False,
                event_id=canonical_event.event_id,
                error=f"Database integrity error: {ie}",
            )
        except SQLAlchemyError as sa_err:
            session.rollback()
            logger.error("Database error during event ingestion: %s", sa_err)
            return IngestionResult(
                success=False,
                event_id=canonical_event.event_id,
                error=f"Database error: {sa_err}",
            )
        except Exception as exc:
            session.rollback()
            logger.exception("Unexpected error during event ingestion: %s", exc)
            return IngestionResult(
                success=False,
                event_id=canonical_event.event_id,
                error=f"Internal ingestion error: {exc}",
            )
        finally:
            if should_close:
                session.close()

    def _record_failure(
        self,
        raw_payload: dict[str, Any] | None,
        error_message: str,
        ingestion_source: str,
        sensor_id: str | None,
    ) -> None:
        """Record an ingestion failure in the ingestion_failures table."""
        session, should_close = self._get_session()
        try:
            clean_payload = sanitize_dict_for_logging(raw_payload) if raw_payload is not None else None
            clean_err = str(sanitize_dict_for_logging(error_message))[:2048]
            failure = IngestionFailure(
                id=uuid.uuid4(),
                raw_payload=clean_payload,
                error_message=clean_err,
                ingestion_source=ingestion_source[:256] if ingestion_source else None,
                sensor_id=sensor_id[:128] if sensor_id else None,
                created_at=datetime.now(timezone.utc),
            )
            session.add(failure)
            session.commit()
        except Exception as exc:
            session.rollback()
            logger.error("Failed to persist ingestion failure record: %s", exc)
        finally:
            if should_close:
                session.close()
