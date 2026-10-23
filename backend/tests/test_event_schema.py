"""
Tests for the ThreatPolish Canonical Event Schema (Pydantic v2).

Covers:
  • Valid event construction and serialisation
  • Missing required fields
  • Invalid UUIDs, IPs, ports
  • Naïve (timezone-unaware) timestamps rejected
  • Schema version validation
  • Payload size limits
  • Extra-field rejection (model_config extra="forbid")
  • Auth metadata safety (no passwords stored)
  • Ingestion metadata validation
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta

import pytest

from app.schemas.event import (
    AuthMetadata,
    AuthOutcome,
    CanonicalEvent,
    CURRENT_SCHEMA_VERSION,
    EventTypeEnum,
    IngestionMeta,
    MAX_PAYLOAD_KEYS,
    MAX_PAYLOAD_STR_VALUE_LEN,
    ProtocolEnum,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _valid_event_data(**overrides) -> dict:
    """Return a minimal valid event dict, applying any overrides."""
    base = {
        "sensor_id": "ssh-decoy-01",
        "source_ip": "192.0.2.1",
        "protocol": "ssh",
        "service": "ssh-decoy",
        "event_type": "auth_attempt",
        "timestamp": datetime.now(timezone.utc),
    }
    base.update(overrides)
    return base


# ===================================================================
# 1. Valid canonical event
# ===================================================================

class TestValidEvent:
    """Constructing a well-formed canonical event must succeed."""

    def test_minimal_valid_event(self):
        event = CanonicalEvent(**_valid_event_data())
        assert event.schema_version == CURRENT_SCHEMA_VERSION
        assert event.event_id is not None
        assert isinstance(event.event_id, uuid.UUID)
        assert event.source_ip is not None

    def test_full_event_with_all_optional_fields(self):
        event = CanonicalEvent(**_valid_event_data(
            session_id=uuid.uuid4(),
            source_port=12345,
            destination_ip="10.0.0.1",
            destination_port=22,
            payload={"command": "ls -la"},
            raw_event_ref="s3://bucket/raw/event-001.json",
            auth=AuthMetadata(
                username="admin",
                auth_outcome=AuthOutcome.FAILURE,
                password_length=8,
            ),
            ingestion=IngestionMeta(
                received_at=datetime.now(timezone.utc),
                ingestion_source="ssh-decoy-collector",
            ),
        ))
        assert event.session_id is not None
        assert event.source_port == 12345
        assert event.auth is not None
        assert event.auth.password_length == 8
        assert event.ingestion is not None

    def test_ipv6_source_ip(self):
        event = CanonicalEvent(**_valid_event_data(source_ip="::1"))
        assert str(event.source_ip) == "::1"

    def test_ipv6_full_address(self):
        event = CanonicalEvent(**_valid_event_data(
            source_ip="2001:db8::1",
            destination_ip="fe80::1",
        ))
        assert str(event.source_ip) == "2001:db8::1"


# ===================================================================
# 2. Missing required fields
# ===================================================================

class TestMissingRequiredFields:
    """Required fields must be present or the model must reject the data."""

    def test_missing_sensor_id(self):
        data = _valid_event_data()
        del data["sensor_id"]
        with pytest.raises(Exception):
            CanonicalEvent(**data)

    def test_missing_source_ip(self):
        data = _valid_event_data()
        del data["source_ip"]
        with pytest.raises(Exception):
            CanonicalEvent(**data)

    def test_missing_protocol(self):
        data = _valid_event_data()
        del data["protocol"]
        with pytest.raises(Exception):
            CanonicalEvent(**data)

    def test_missing_service(self):
        data = _valid_event_data()
        del data["service"]
        with pytest.raises(Exception):
            CanonicalEvent(**data)

    def test_missing_event_type(self):
        data = _valid_event_data()
        del data["event_type"]
        with pytest.raises(Exception):
            CanonicalEvent(**data)


# ===================================================================
# 3. Invalid UUIDs
# ===================================================================

class TestInvalidUUIDs:
    """UUIDs must be valid RFC 4122 or rejected."""

    def test_invalid_event_id(self):
        with pytest.raises(Exception):
            CanonicalEvent(**_valid_event_data(event_id="not-a-uuid"))

    def test_invalid_session_id(self):
        with pytest.raises(Exception):
            CanonicalEvent(**_valid_event_data(session_id="bad-uuid"))


# ===================================================================
# 4. Invalid IP addresses and ports
# ===================================================================

class TestInvalidIPsAndPorts:
    """IP addresses must be valid; ports must be 0–65535."""

    def test_invalid_source_ip(self):
        with pytest.raises(Exception):
            CanonicalEvent(**_valid_event_data(source_ip="999.999.999.999"))

    def test_invalid_source_ip_string(self):
        with pytest.raises(Exception):
            CanonicalEvent(**_valid_event_data(source_ip="not-an-ip"))

    def test_invalid_destination_ip(self):
        with pytest.raises(Exception):
            CanonicalEvent(**_valid_event_data(destination_ip="junk"))

    def test_port_too_high(self):
        with pytest.raises(Exception):
            CanonicalEvent(**_valid_event_data(source_port=70000))

    def test_port_negative(self):
        with pytest.raises(Exception):
            CanonicalEvent(**_valid_event_data(source_port=-1))

    def test_port_zero_is_valid(self):
        event = CanonicalEvent(**_valid_event_data(source_port=0))
        assert event.source_port == 0

    def test_port_65535_is_valid(self):
        event = CanonicalEvent(**_valid_event_data(source_port=65535))
        assert event.source_port == 65535


# ===================================================================
# 5. Naïve vs timezone-aware timestamps
# ===================================================================

class TestTimestamps:
    """Only timezone-aware UTC timestamps are accepted."""

    def test_naive_timestamp_rejected(self):
        with pytest.raises(Exception, match="timezone-aware"):
            CanonicalEvent(**_valid_event_data(
                timestamp=datetime(2026, 1, 1, 12, 0, 0),  # no tz
            ))

    def test_utc_timestamp_accepted(self):
        ts = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        event = CanonicalEvent(**_valid_event_data(timestamp=ts))
        assert event.timestamp.tzinfo is not None

    def test_non_utc_timezone_accepted(self):
        """Non-UTC aware timestamps are still valid (they carry tz info)."""
        ts = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone(timedelta(hours=5, minutes=30)))
        event = CanonicalEvent(**_valid_event_data(timestamp=ts))
        assert event.timestamp.tzinfo is not None

    def test_naive_ingestion_received_at_rejected(self):
        with pytest.raises(Exception, match="timezone-aware"):
            CanonicalEvent(**_valid_event_data(
                ingestion=IngestionMeta(
                    received_at=datetime(2026, 1, 1),  # naive
                    ingestion_source="test",
                ),
            ))


# ===================================================================
# 6. Event serialisation and schema version
# ===================================================================

class TestSerialisation:
    """Events must serialise cleanly to JSON-compatible dicts."""

    def test_schema_version_in_output(self):
        event = CanonicalEvent(**_valid_event_data())
        data = event.model_dump()
        assert data["schema_version"] == "1.0"

    def test_event_id_serialised_as_string(self):
        event = CanonicalEvent(**_valid_event_data())
        data = event.model_dump()
        assert isinstance(data["event_id"], str)
        # Roundtrip check
        assert uuid.UUID(data["event_id"]) == event.event_id

    def test_ip_serialised_as_string(self):
        event = CanonicalEvent(**_valid_event_data())
        data = event.model_dump()
        assert isinstance(data["source_ip"], str)

    def test_timestamp_serialised_as_iso_string(self):
        event = CanonicalEvent(**_valid_event_data())
        data = event.model_dump()
        assert isinstance(data["timestamp"], str)
        # Parseable
        datetime.fromisoformat(data["timestamp"])

    def test_json_roundtrip(self):
        event = CanonicalEvent(**_valid_event_data())
        json_str = event.model_dump_json()
        assert isinstance(json_str, str)
        assert '"schema_version":"1.0"' in json_str or '"schema_version": "1.0"' in json_str

    def test_invalid_schema_version_pattern(self):
        with pytest.raises(Exception):
            CanonicalEvent(**_valid_event_data(schema_version="abc"))

    def test_schema_version_two_digits(self):
        event = CanonicalEvent(**_valid_event_data(schema_version="2.0"))
        assert event.schema_version == "2.0"


# ===================================================================
# 7. Extra-field rejection
# ===================================================================

class TestExtraFields:
    """Unknown/extra fields must be rejected (forbid mode)."""

    def test_extra_field_rejected(self):
        with pytest.raises(Exception):
            CanonicalEvent(**_valid_event_data(totally_unknown_field="hack"))

    def test_extra_field_in_auth_rejected(self):
        with pytest.raises(Exception):
            AuthMetadata(password="secret123")  # forbidden field


# ===================================================================
# 8. Payload limits
# ===================================================================

class TestPayloadLimits:
    """Payload must not exceed key count or string value length limits."""

    def test_payload_too_many_keys(self):
        big_payload = {f"key_{i}": "value" for i in range(MAX_PAYLOAD_KEYS + 1)}
        with pytest.raises(Exception, match="must not exceed"):
            CanonicalEvent(**_valid_event_data(payload=big_payload))

    def test_payload_string_value_too_long(self):
        long_val = "x" * (MAX_PAYLOAD_STR_VALUE_LEN + 1)
        with pytest.raises(Exception, match="char limit"):
            CanonicalEvent(**_valid_event_data(payload={"big": long_val}))

    def test_payload_within_limits(self):
        ok_payload = {f"k{i}": f"v{i}" for i in range(10)}
        event = CanonicalEvent(**_valid_event_data(payload=ok_payload))
        assert len(event.payload) == 10


# ===================================================================
# 9. Auth metadata — credential safety
# ===================================================================

class TestAuthSafety:
    """Auth metadata must never store actual passwords."""

    def test_auth_password_length_only(self):
        auth = AuthMetadata(
            username="root",
            auth_outcome=AuthOutcome.FAILURE,
            password_length=12,
        )
        data = auth.model_dump()
        # No "password" key in the output
        assert "password" not in data
        assert data["password_length"] == 12

    def test_auth_rejects_password_field(self):
        """AuthMetadata has extra='forbid', so 'password' is not allowed."""
        with pytest.raises(Exception):
            AuthMetadata(username="root", password="secret")


# ===================================================================
# 10. Enum validation
# ===================================================================

class TestEnums:
    """Protocol and event_type enums must match known values."""

    def test_invalid_protocol(self):
        with pytest.raises(Exception):
            CanonicalEvent(**_valid_event_data(protocol="ftp_invalid"))

    def test_valid_protocols(self):
        for proto in ProtocolEnum:
            event = CanonicalEvent(**_valid_event_data(protocol=proto.value))
            assert event.protocol == proto

    def test_invalid_event_type(self):
        with pytest.raises(Exception):
            CanonicalEvent(**_valid_event_data(event_type="nonexistent"))

    def test_valid_event_types(self):
        for et in EventTypeEnum:
            event = CanonicalEvent(**_valid_event_data(event_type=et.value))
            assert event.event_type == et
