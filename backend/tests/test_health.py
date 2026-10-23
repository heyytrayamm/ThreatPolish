"""Tests for system health and root endpoints."""

from datetime import datetime
import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_root_endpoint() -> None:
    """Ensure the root endpoint returns operational metadata."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "Welcome to ThreatPolish" in data["message"]
    assert data["docs"] == "/docs"
    assert data["health"] == "/api/v1/health"


def test_health_endpoint() -> None:
    """Ensure the /api/v1/health endpoint returns 200 OK and valid health telemetry."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "ThreatPolish Honeypot Platform"
    assert data["version"] == "0.1.0"
    assert data["environment"] == "development"
    assert "Phase" in data["phase"]

    # Validate that timestamp is parseable ISO-8601
    parsed_time = datetime.fromisoformat(data["timestamp"])
    assert parsed_time is not None

    # db_ready is present (may be False if PostgreSQL isn't running)
    assert "db_ready" in data
    assert isinstance(data["db_ready"], bool)
