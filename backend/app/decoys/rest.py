"""
REST API Decoy Simulator for ThreatPolish.

Simulates HTTP/REST application decoys safely:
  • Accepts synthetic HTTP requests via local Python calls.
  • Simulates trap endpoints such as /admin, /wp-admin, and /.env.
  • Returns harmless simulated responses (401, 403, 404).
  • NEVER exposes real environment variables, local files, or application secrets.
  • NEVER opens a public network port or binds to non-localhost.
  • Sanitizes incoming headers and request bodies before emitting telemetry.
"""

from __future__ import annotations

import logging
import uuid
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from typing import Any, Mapping

from app.decoys.base import BaseDecoySimulator, DecoyInteractionResult
from app.schemas.event import (
    CanonicalEvent,
    EventTypeEnum,
    ProtocolEnum,
)
from app.services.ingestion import (
    TelemetryIngestionService,
    is_sensitive_key,
    sanitize_dict_for_logging,
)

logger = logging.getLogger("threatpolish.decoys.rest")


def sanitize_url_path(url_path: str) -> str:
    """
    Sanitize URL path and query parameters, redacting sensitive query parameter values.
    """
    split = urlsplit(url_path)
    if not split.query:
        return url_path

    query_params = parse_qsl(split.query, keep_blank_values=True)
    sanitized_params = []
    for k, v in query_params:
        if is_sensitive_key(k):
            sanitized_params.append((k, "[REDACTED]"))
        else:
            sanitized_params.append((k, v))

    sanitized_query = urlencode(sanitized_params)
    return urlunsplit((split.scheme, split.netloc, split.path, sanitized_query, split.fragment))


# Default simulated decoy responses for common attacker probe paths
DEFAULT_ENDPOINT_RESPONSES: dict[str, dict[str, Any]] = {
    "/admin": {
        "status_code": 401,
        "headers": {"WWW-Authenticate": 'Basic realm="Decoy Admin Portal"'},
        "body": {"error": "Unauthorized", "message": "Administrative authentication required."},
    },
    "/wp-admin": {
        "status_code": 403,
        "headers": {"Content-Type": "application/json"},
        "body": {"error": "Forbidden", "message": "Access to management console is restricted."},
    },
    "/.env": {
        "status_code": 404,
        "headers": {"Content-Type": "application/json"},
        "body": {"error": "Not Found", "message": "The requested configuration file does not exist."},
    },
    "/actuator/env": {
        "status_code": 404,
        "headers": {"Content-Type": "application/json"},
        "body": {"error": "Not Found", "message": "Actuator endpoints disabled."},
    },
    "/phpmyadmin": {
        "status_code": 404,
        "headers": {"Content-Type": "application/json"},
        "body": {"error": "Not Found"},
    },
}


class RESTDecoySimulator(BaseDecoySimulator):
    """
    Simulates a Web/REST decoy service in-process without network listeners.
    """

    def __init__(
        self,
        sensor_id: str = "rest-decoy-01",
        service_name: str = "rest-decoy",
        ingestion_service: TelemetryIngestionService | None = None,
        endpoint_responses: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        super().__init__(
            sensor_id=sensor_id,
            service_name=service_name,
            ingestion_service=ingestion_service,
        )
        self.endpoint_responses = (
            endpoint_responses.copy()
            if endpoint_responses is not None
            else DEFAULT_ENDPOINT_RESPONSES.copy()
        )

    def simulate_request(
        self,
        method: str,
        path: str,
        source_ip: str,
        headers: Mapping[str, str] | None = None,
        body: dict[str, Any] | str | None = None,
        source_port: int = 49152,
        destination_port: int = 8000,
        session_id: uuid.UUID | None = None,
    ) -> DecoyInteractionResult:
        """
        Simulate an incoming HTTP request against the decoy endpoints.

        Normalizes path, redacts sensitive query parameters, strips sensitive
        credential headers/body, determines a harmless response, and emits a CanonicalEvent.
        """
        norm_method = method.strip().upper()
        raw_path = path.strip()
        if not raw_path.startswith("/"):
            raw_path = "/" + raw_path

        # Split path from query string for endpoint matching
        path_only = raw_path.split("?", 1)[0]
        sanitized_path = sanitize_url_path(raw_path)

        # Determine harmless simulated response (never returns actual env or server files!)
        mock_resp = self.endpoint_responses.get(
            path_only,
            {
                "status_code": 404,
                "headers": {"Content-Type": "application/json"},
                "body": {"error": "Not Found", "path": path_only},
            },
        )

        # Sanitize headers (strip Authorization, Cookie, Api-Key tokens)
        sanitized_headers: dict[str, str] = {}
        if headers:
            for k, v in headers.items():
                if is_sensitive_key(k):
                    sanitized_headers[k] = "[REDACTED]"
                else:
                    sanitized_headers[k] = str(v)[:256]

        # Sanitize request body if provided
        sanitized_body_repr: str | None = None
        if body is not None:
            sanitized_body = sanitize_dict_for_logging(body)
            sanitized_body_repr = str(sanitized_body)[:512]

        # Classify the interaction event type
        is_sensitive_path = any(
            p in path_only for p in ("/admin", "/wp-admin", "/.env", "/phpmyadmin", "/actuator")
        )
        event_type = EventTypeEnum.RECON if is_sensitive_path else EventTypeEnum.CONNECTION

        logger.info(
            "Simulating REST request: %s %s from %s -> status %d",
            norm_method,
            path_only,
            source_ip,
            mock_resp["status_code"],
        )

        payload: dict[str, Any] = {
            "method": norm_method,
            "path": sanitized_path[:256],
            "response_status": mock_resp["status_code"],
            "user_agent": sanitized_headers.get("User-Agent") or sanitized_headers.get("user-agent", "Unknown"),
            "is_trap_path": is_sensitive_path,
        }
        if sanitized_body_repr:
            payload["body_sample"] = sanitized_body_repr

        event = CanonicalEvent(
            event_id=self._new_uuid(),
            session_id=session_id,
            sensor_id=self.sensor_id,
            timestamp=self._utcnow(),
            source_ip=source_ip,
            source_port=source_port,
            destination_port=destination_port,
            protocol=ProtocolEnum.HTTP,
            service=self.service_name,
            event_type=event_type,
            payload=payload,
        )

        ingestion_result = self._ingest_event(event)

        return DecoyInteractionResult(
            simulated_response=mock_resp,
            event=event,
            ingestion_result=ingestion_result,
        )
