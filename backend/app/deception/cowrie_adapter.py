"""Cowrie integration.

Cowrie writes one JSON object per line.  This adapter maps the events we care
about onto the shared contract and tails the file with a persisted offset so a
restart does not silently lose records.

Passwords attempted by attackers are **never stored in plaintext**: only a
truncated SHA-256 digest and the length are retained, which is enough to spot
credential reuse without retaining working secrets.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from ..core.logging import get_logger
from ..core.security import iso, utcnow
from ..telemetry.ingest import Ingestor

log = get_logger(__name__)

EVENT_MAP = {
    "cowrie.session.connect": "honeypot.ssh.session_start",
    "cowrie.client.version": "honeypot.ssh.client_version",
    "cowrie.client.fingerprint": "honeypot.ssh.client_fingerprint",
    "cowrie.login.failed": "honeypot.ssh.login_failed",
    "cowrie.login.success": "honeypot.ssh.login_success",
    "cowrie.command.input": "honeypot.ssh.command",
    "cowrie.session.params": "honeypot.ssh.session_params",
    "cowrie.session.closed": "honeypot.ssh.session_end",
}

SEVERITY = {
    "honeypot.ssh.session_start": "info",
    "honeypot.ssh.client_version": "info",
    "honeypot.ssh.client_fingerprint": "info",
    "honeypot.ssh.login_failed": "low",
    "honeypot.ssh.login_success": "high",
    "honeypot.ssh.command": "medium",
    "honeypot.ssh.session_params": "low",
    "honeypot.ssh.session_end": "info",
}

MAX_COMMAND = 2000


def password_fingerprint(password: str) -> dict[str, Any]:
    if not password:
        return {}
    digest = hashlib.sha256(password.encode("utf-8", "replace")).hexdigest()
    return {"password_sha256_prefix": digest[:16], "password_length": len(password)}


def parse_cowrie_line(line: str) -> dict[str, Any] | None:
    """Map one Cowrie JSON line to an event payload, or None if unsupported."""
    line = line.strip()
    if not line:
        return None
    try:
        record = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(record, dict):
        return None

    cowrie_event = str(record.get("eventid", ""))
    event_type = EVENT_MAP.get(cowrie_event)
    if not event_type:
        return None

    session = str(record.get("session", "") or "")[:120]
    if not session:
        return None

    occurred = _parse_timestamp(record.get("timestamp"))
    source_ip = record.get("src_ip")
    features: dict[str, Any] = {
        "cowrie_eventid": cowrie_event,
        "client_version": str(record.get("version", "") or "")[:120],
    }
    for key in ("username", "password"):
        value = record.get(key)
        if key == "password":
            features.update(password_fingerprint(str(value or "")))
        elif value is not None:
            features["username"] = str(value)[:64]

    if cowrie_event == "cowrie.command.input":
        command = str(record.get("input", "") or "")[:MAX_COMMAND]
        if not command:
            return None
        features["command"] = command
        features["success"] = True
    if cowrie_event == "cowrie.login.success":
        features["success"] = True
    elif cowrie_event == "cowrie.login.failed":
        features["success"] = False
    if cowrie_event == "cowrie.client.fingerprint":
        fingerprint = record.get("fingerprint")
        if fingerprint:
            features["indicator"] = f"ssh-key:{str(fingerprint)[:120]}"
    if cowrie_event == "cowrie.session.closed":
        features["duration_seconds"] = record.get("duration")

    indicators = []
    if features.get("indicator"):
        indicators.append(str(features["indicator"]))

    return {
        "schema_version": "1.0",
        "occurred_at": occurred.isoformat(),
        "source_module": "honeypot",
        "event_type": event_type,
        "source_ip": source_ip,
        "session_id": f"cowrie:{session}",
        "target_id": str(record.get("sensor", "cowrie"))[:200],
        "severity": SEVERITY[event_type],
        "provenance": {
            "collector": "cowrie",
            "source": str(record.get("sensor", "cowrie"))[:120],
            "reliability": 0.9,
            "synthetic": bool(record.get("synthetic", False)),
            "indicators": indicators,
        },
        "features": features,
        "raw": {"cowrie_eventid": cowrie_event, "protocol": record.get("protocol", "ssh")},
    }


def _parse_timestamp(value: Any) -> datetime:
    if isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            parsed = parsed.astimezone(timezone.utc)
            if parsed <= utcnow():
                return parsed
        except ValueError:
            pass
    return utcnow()


class CowrieTailer:
    """Incremental reader that survives restarts and log rotation."""

    def __init__(self, path: str | Path, *, state_path: str | Path | None = None, ingestor: Ingestor | None = None):
        self.path = Path(path)
        state = Path(state_path) if state_path else self.path.with_suffix(self.path.suffix + ".offset")
        self.state_path = state
        self.ingestor = ingestor or Ingestor()

    def poll(self, *, max_bytes: int = 1_000_000) -> dict[str, int]:
        offset = self._load_offset()
        if not self.path.exists():
            return {"read": 0, "accepted": 0, "duplicates": 0, "rejected": 0, "offset": offset}
        size = self.path.stat().st_size
        if size < offset:
            # Log was rotated or truncated: start over without losing new data.
            offset = 0
        if size == offset:
            return {"read": 0, "accepted": 0, "duplicates": 0, "rejected": 0, "offset": offset}

        with self.path.open("rb") as handle:
            handle.seek(offset)
            chunk = handle.read(max_bytes)
            consumed = offset + len(chunk)
            if size > consumed:
                # Only advance to the last complete line; leave the partial tail.
                last_newline = chunk.rfind(b"\n")
                if last_newline == -1:
                    return {"read": 0, "accepted": 0, "duplicates": 0, "rejected": 0, "offset": offset}
                chunk = chunk[: last_newline + 1]
                consumed = offset + len(chunk)

        payloads = []
        for raw_line in chunk.decode("utf-8", "replace").splitlines():
            event = parse_cowrie_line(raw_line)
            if event is not None:
                payloads.append(event)

        report = self.ingestor.ingest(payloads, actor="sensor:cowrie") if payloads else None
        self._save_offset(consumed)
        return {
            "read": len(payloads),
            "accepted": report.accepted if report else 0,
            "duplicates": report.duplicates if report else 0,
            "rejected": report.rejected if report else 0,
            "offset": consumed,
        }

    def tail_forever(self, interval: float = 2.0) -> Iterator[dict[str, int]]:
        while True:
            try:
                yield self.poll()
            except Exception as exc:  # noqa: BLE001 - a tailer must keep running
                log.error("cowrie tail failed", extra={"error": str(exc)})
            time.sleep(interval)

    def _load_offset(self) -> int:
        try:
            data = json.loads(self.state_path.read_text("utf-8"))
            return int(data.get("offset", 0))
        except (OSError, ValueError, TypeError):
            return 0

    def _save_offset(self, offset: int) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.state_path.with_suffix(self.state_path.suffix + ".tmp")
        tmp.write_text(json.dumps({"offset": offset, "saved_at": iso(utcnow())}), "utf-8")
        os.replace(tmp, self.state_path)
