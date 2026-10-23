"""
SSH Interaction Simulator for ThreatPolish.

Simulates SSH authentication attempts safely:
  • Accepts synthetic login attempts via local Python calls.
  • Records attacker username, simulated outcome, timestamps, and metadata.
  • Returns a simulated authentication rejection.
  • NEVER opens a real SSH daemon or network socket.
  • NEVER runs a shell or executes submitted commands.
  • NEVER saves or logs raw passwords or hashes.
"""

from __future__ import annotations

import logging
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

logger = logging.getLogger("threatpolish.decoys.ssh")

DEFAULT_SSH_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"


class SSHDecoySimulator(BaseDecoySimulator):
    """
    Simulates an SSH service interaction in-process without network sockets.
    """

    def __init__(
        self,
        sensor_id: str = "ssh-decoy-01",
        service_name: str = "ssh-decoy",
        ingestion_service: TelemetryIngestionService | None = None,
        server_banner: str = DEFAULT_SSH_BANNER,
    ) -> None:
        super().__init__(
            sensor_id=sensor_id,
            service_name=service_name,
            ingestion_service=ingestion_service,
        )
        self.server_banner = server_banner

    def simulate_login(
        self,
        source_ip: str,
        username: str,
        password: str | None = None,
        password_length: int | None = None,
        source_port: int = 54321,
        destination_port: int = 22,
        session_id: uuid.UUID | None = None,
        client_version: str = "SSH-2.0-OpenSSH_8.9p1",
    ) -> DecoyInteractionResult:
        """
        Simulate an incoming SSH authentication attempt.

        Computes password length and immediately discards the raw password.
        Returns a simulated failure response and emits a CanonicalEvent.
        """
        # Calculate password length safely; never store or log password
        if password is not None:
            resolved_pw_len = len(password)
            del password  # Remove local reference; do not store on event or instance
        elif password_length is not None:
            resolved_pw_len = max(0, password_length)
        else:
            resolved_pw_len = 0

        logger.info(
            "Simulating SSH login attempt from %s for username '%s' (pw_len=%d)",
            source_ip,
            username,
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
            protocol=ProtocolEnum.SSH,
            service=self.service_name,
            event_type=EventTypeEnum.AUTH_ATTEMPT,
            auth=AuthMetadata(
                username=username[:256] if username else None,
                auth_outcome=AuthOutcome.FAILURE,
                password_length=resolved_pw_len,
            ),
            payload={
                "client_version": client_version[:128],
                "server_banner": self.server_banner,
                "auth_method": "password",
            },
        )

        simulated_response: dict[str, Any] = {
            "status": "failure",
            "message": "Permission denied (publickey,password).",
            "allowed_auth_methods": ["publickey", "password"],
            "server_banner": self.server_banner,
        }

        ingestion_result = self._ingest_event(event)

        return DecoyInteractionResult(
            simulated_response=simulated_response,
            event=event,
            ingestion_result=ingestion_result,
        )
