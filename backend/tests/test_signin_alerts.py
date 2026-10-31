"""Sign-in anomaly detection.

The ASGI test client reports a single synthetic address for every request, so the
detector is exercised directly with the addresses an operator would see.
"""

from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest


def _record_sign_in(
    user_id: str,
    ip: str,
    session_version: int = 0,
    *,
    minutes_ago: float = 0,
) -> str:
    from sqlalchemy import text

    from app.db.database import connection

    ts = (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat()
    with connection() as conn:
        conn.execute(
            text(
                "INSERT INTO audit_log (id, ts, actor_id, actor_role, action, object_type, "
                "object_id, outcome, detail, request_ip) VALUES (:id, :ts, :actor, 'admin', "
                "'auth.login', 'user', :actor, 'success', :detail, :ip)"
            ),
            {
                "id": f"aud_{uuid.uuid4().hex[:12]}",
                "ts": ts,
                "actor": user_id,
                "detail": json.dumps({"session_version": session_version, "client": "pytest"}),
                "ip": ip,
            },
        )
    return ts


def _admin_id(client, admin_headers) -> str:
    return client.get("/api/v1/auth/me", headers=admin_headers).json()["id"]


def _detect(user_id: str, ip: str, session_version: int = 0):
    from app.auth.signin import detect_signin_anomaly

    return detect_signin_anomaly(user_id=user_id, ip=ip, session_version=session_version)


def test_a_sign_in_from_the_same_network_is_not_an_alert(client, admin_headers):
    user_id = _admin_id(client, admin_headers)
    _record_sign_in(user_id, "203.0.113.10")
    assert _detect(user_id, "203.0.113.11") is None


def test_a_sign_in_from_another_network_is_flagged(client, admin_headers):
    user_id = _admin_id(client, admin_headers)
    previous = _record_sign_in(user_id, "203.0.113.10", minutes_ago=2)

    alert = _detect(user_id, "198.51.100.7")
    assert alert is not None
    assert alert["kind"] == "new_network"
    assert alert["previous_ip"] == "203.0.113.10"
    assert alert["previous_at"] == previous
    assert alert["detected_at"]
    assert alert["network"] == "198.51.100.0/24"


def test_sign_ins_outside_the_window_or_from_a_revoked_session_are_ignored(client, admin_headers):
    user_id = _admin_id(client, admin_headers)
    _record_sign_in(user_id, "203.0.113.10", minutes_ago=90)
    assert _detect(user_id, "198.51.100.7") is None

    _record_sign_in(user_id, "203.0.113.10", session_version=0, minutes_ago=1)
    # The account has since changed credentials; the older token is not live.
    assert _detect(user_id, "198.51.100.7", session_version=1) is None


def test_unparseable_client_addresses_are_ignored(client, admin_headers):
    user_id = _admin_id(client, admin_headers)
    _record_sign_in(user_id, "203.0.113.10")
    assert _detect(user_id, "testclient") is None


class _GeoHandler(BaseHTTPRequestHandler):
    locations: dict[str, str] = {}

    def log_message(self, *args):  # noqa: N802 - stdlib naming
        return

    def do_GET(self):  # noqa: N802 - stdlib naming
        ip = self.path.strip("/").split("?")[0]
        loc = self.locations.get(ip)
        if loc is None:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = json.dumps({"loc": loc}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def geo_server(monkeypatch):
    from app.auth import geo
    from app.core.config import reset_settings_cache

    _GeoHandler.locations = {}
    server = ThreadingHTTPServer(("127.0.0.1", 0), _GeoHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("TP_GEO_API_URL", f"http://127.0.0.1:{server.server_address[1]}/{{ip}}")
    reset_settings_cache()
    geo.clear_cache()
    try:
        yield _GeoHandler.locations
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        geo.clear_cache()


def test_distant_sign_ins_are_flagged_with_a_measured_distance(
    client, admin_headers, geo_server
):
    user_id = _admin_id(client, admin_headers)
    geo_server["8.8.8.8"] = "51.5074,-0.1278"  # London
    geo_server["1.1.1.1"] = "40.7128,-74.0060"  # New York
    _record_sign_in(user_id, "8.8.8.8", minutes_ago=1)

    alert = _detect(user_id, "1.1.1.1")
    assert alert is not None
    assert alert["kind"] == "distant_signin"
    assert 5000 < alert["distance_km"] < 6000, alert
    assert alert["threshold_km"] == 500


def test_nearby_sign_ins_are_not_flagged_when_geolocation_is_available(
    client, admin_headers, geo_server
):
    user_id = _admin_id(client, admin_headers)
    geo_server["8.8.8.8"] = "51.5074,-0.1278"
    geo_server["1.1.1.1"] = "51.5090,-0.1300"
    _record_sign_in(user_id, "8.8.8.8", minutes_ago=1)

    assert _detect(user_id, "1.1.1.1") is None


def test_unlocatable_addresses_fall_back_to_a_network_change(client, admin_headers, geo_server):
    user_id = _admin_id(client, admin_headers)
    geo_server["1.1.1.1"] = "40.7128,-74.0060"
    _record_sign_in(user_id, "10.0.0.5", minutes_ago=1)

    alert = _detect(user_id, "1.1.1.1")
    assert alert is not None
    assert alert["kind"] == "new_network"
    assert alert["previous_ip"] == "10.0.0.5"
