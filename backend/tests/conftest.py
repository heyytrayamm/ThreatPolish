from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

ADMIN_EMAIL = "admin@threatpolish.test"
ADMIN_PASSWORD = "correct-horse-battery-staple"


@pytest.fixture(autouse=True)
def _environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("TP_ENV", "test")
    monkeypatch.setenv("TP_DB_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("TP_JWT_SECRET", "test-secret-that-is-long-enough-for-hs256")
    monkeypatch.setenv("TP_BOOTSTRAP_ADMIN_EMAIL", ADMIN_EMAIL)
    monkeypatch.setenv("TP_BOOTSTRAP_ADMIN_PASSWORD", ADMIN_PASSWORD)
    monkeypatch.setenv("TP_RESPONSE_AUTO_APPLY", "false")
    monkeypatch.setenv("TP_WEB_SEC_ALLOW_LOOPBACK", "true")
    monkeypatch.setenv("TP_DATA_DIR", str(tmp_path))

    from app.api import deps
    from app.core.config import reset_settings_cache
    from app.db import database

    reset_settings_cache()
    deps.ingest_limiter.cache_clear()
    deps.login_limiter.cache_clear()
    deps.decoy_limiter.cache_clear()
    database.dispose_engine()
    yield
    deps.ingest_limiter.cache_clear()
    deps.login_limiter.cache_clear()
    deps.decoy_limiter.cache_clear()
    database.dispose_engine()
    reset_settings_cache()
    os.environ.pop("TP_DB_URL", None)


@pytest.fixture()
def client():
    from fastapi.testclient import TestClient

    from app.main import create_app

    with TestClient(create_app()) as test_client:
        yield test_client


@pytest.fixture()
def admin_token(client) -> str:
    response = client.post(
        "/api/v1/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}
    )
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


@pytest.fixture()
def admin_headers(admin_token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture()
def viewer(admin_headers):
    from app.auth.users import create_user

    create_user(
        email="viewer@threatpolish.test",
        name="Viewer",
        role="viewer",
        password="viewer-password-123",
    )
    return {"email": "viewer@threatpolish.test", "password": "viewer-password-123"}


@pytest.fixture()
def viewer_headers(client, viewer) -> dict[str, str]:
    response = client.post("/api/v1/auth/login", json=viewer)
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


@pytest.fixture()
def sensor_headers(admin_headers) -> dict[str, str]:
    from app.auth.users import create_agent_token

    token = create_agent_token(name="test-sensor", role="sensor")
    return {"X-Agent-Token": token["token"]}


def make_event(**overrides):
    from datetime import datetime, timezone

    event = {
        "schema_version": "1.0",
        "occurred_at": datetime.now(timezone.utc).isoformat(),
        "source_module": "honeypot",
        "event_type": "honeypot.ssh.command",
        "source_ip": "203.0.113.10",
        "session_id": "sess-alpha",
        "target_id": "decoy-ssh-1",
        "severity": "low",
        "provenance": {
            "collector": "test-collector",
            "source": "pytest",
            "reliability": 0.8,
            "synthetic": True,
        },
        "features": {"command": "uname -a", "username": "root"},
    }
    event.update(overrides)
    return event
