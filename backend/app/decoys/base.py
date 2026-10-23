"""
Base Decoy Simulator interface and shared types for ThreatPolish.

All simulated decoys inherit from ``BaseDecoySimulator`` to maintain a
consistent, predictable interaction interface.
"""

from __future__ import annotations

import uuid
from abc import ABC
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from app.schemas.event import CanonicalEvent
from app.services.ingestion import IngestionResult, TelemetryIngestionService


@dataclass
class DecoyInteractionResult:
    """
    Result returned by any decoy simulator interaction.

    Attributes:
        simulated_response: The mock response returned to the simulated attacker.
        event: The canonical telemetry event produced by the interaction.
        ingestion_result: Optional result from the ingestion pipeline (if persisted).
    """

    simulated_response: dict[str, Any]
    event: CanonicalEvent
    ingestion_result: IngestionResult | None = None


class BaseDecoySimulator(ABC):
    """
    Abstract base class for all simulated decoys.

    Subclasses must implement safe simulation logic without ever opening
    public network sockets, executing commands, or contacting real databases.
    """

    def __init__(
        self,
        sensor_id: str,
        service_name: str,
        ingestion_service: TelemetryIngestionService | None = None,
    ) -> None:
        self.sensor_id = sensor_id
        self.service_name = service_name
        self.ingestion_service = ingestion_service

    def _ingest_event(self, event: CanonicalEvent) -> IngestionResult | None:
        """Forward the event to the telemetry pipeline if configured."""
        if self.ingestion_service is not None:
            return self.ingestion_service.ingest(
                event_input=event,
                ingestion_source=self.service_name,
            )
        return None

    @staticmethod
    def _utcnow() -> datetime:
        return datetime.now(timezone.utc)

    @staticmethod
    def _new_uuid() -> uuid.UUID:
        return uuid.uuid4()
