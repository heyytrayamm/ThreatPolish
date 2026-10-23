from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest


class _TargetHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        return

    def do_GET(self):
        if self.path == "/redirect-private":
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path == "/redirect-credentials":
            port = self.server.server_address[1]
            self.send_response(302)
            self.send_header("Location", f"http://user:pass@127.0.0.1:{port}/")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path == "/huge":
            body = b"x" * 1_000_001
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/.env":
            body = b"DB_PASSWORD=super-secret-value\nAPP_KEY=abc123\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        body = b"<html><body>ok</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "TestServer/1.2.3")
        self.send_header("Set-Cookie", "session=abc; Path=/")
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def target_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _TargetHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _create_scope(client, admin_headers, domain: str, allow_active: bool = True):
    response = client.post(
        "/api/v1/websec/scopes",
        headers=admin_headers,
        json={
            "domain": domain,
            "authorized_by": "Trayam Roy (written authorization #42)",
            "expires_in_days": 7,
            "allow_active": allow_active,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_ipv6_hosts_normalize_without_losing_segments():
    from app.websec.scope import normalize_domain

    assert normalize_domain("[2001:db8::1]:8443") == "2001:db8::1"
    assert normalize_domain("https://[2001:db8::1]/admin") == "2001:db8::1"


def test_invalid_port_is_rejected_with_validation_error(client, admin_headers):
    response = client.post(
        "/api/v1/websec/assess",
        headers=admin_headers,
        json={"target": "https://example.com:not-a-port/", "active_checks": False},
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_failed"


def test_assessment_requires_authorization(client, admin_headers):
    response = client.post(
        "/api/v1/websec/assess",
        headers=admin_headers,
        json={"target": "https://not-authorized.example", "active_checks": False},
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "forbidden"


def test_assessment_produces_real_findings(client, admin_headers, target_server):
    scope = _create_scope(client, admin_headers, target_server, allow_active=True)
    assert scope["domain"] == target_server.split(":")[0]

    response = client.post(
        "/api/v1/websec/assess",
        headers=admin_headers,
        json={"target": f"http://{target_server}/", "active_checks": True},
    )
    assert response.status_code == 200, response.text
    report = response.json()
    assert report["status"] == "completed"
    assert report["http_status"] == 200
    checks = {finding["check_id"] for finding in report["findings"]}
    assert {"missing_csp", "missing_nosniff", "cookie_flags", "no_https"} <= checks
    assert "exposed_sensitive_path" in checks
    assert report["event_ids"]

    env_finding = next(
        finding for finding in report["findings"] if finding["check_id"] == "exposed_sensitive_path"
    )
    assert env_finding["severity"] == "high"
    assert "DB_PASSWORD" in env_finding["evidence"]["keys"]
    assert "super-secret-value" not in str(env_finding["evidence"])

    findings = client.get("/api/v1/websec/findings", headers=admin_headers).json()["items"]
    assert findings
    assert all(item["remediation"] for item in findings)

    events = client.get("/api/v1/events?module=websec", headers=admin_headers).json()
    assert events["total"] == report["finding_count"]
    assert events["items"][0]["session_id"].startswith("scan:")


def test_active_checks_require_scope_flag(client, admin_headers, target_server):
    _create_scope(client, admin_headers, target_server, allow_active=False)
    response = client.post(
        "/api/v1/websec/assess",
        headers=admin_headers,
        json={"target": f"http://{target_server}/", "active_checks": True},
    )
    assert response.status_code == 403
    assert "active checks" in response.json()["error"]["message"]

    passive = client.post(
        "/api/v1/websec/assess",
        headers=admin_headers,
        json={"target": f"http://{target_server}/", "active_checks": False},
    )
    assert passive.status_code == 200
    assert "active path probes were not requested" in passive.json()["limitations"]


def test_link_local_targets_are_refused(client, admin_headers):
    _create_scope(client, admin_headers, "169.254.169.254", allow_active=True)
    response = client.post(
        "/api/v1/websec/assess",
        headers=admin_headers,
        json={"target": "http://169.254.169.254/latest/meta-data/", "active_checks": False},
    )
    assert response.status_code == 403
    assert "non-public" in response.json()["error"]["message"]


def test_redirect_to_a_link_local_address_is_refused(client, admin_headers, target_server):
    _create_scope(client, admin_headers, target_server, allow_active=False)
    _create_scope(client, admin_headers, "169.254.169.254", allow_active=False)

    response = client.post(
        "/api/v1/websec/assess",
        headers=admin_headers,
        json={"target": f"http://{target_server}/redirect-private", "active_checks": False},
    )
    assert response.status_code == 200, response.text
    report = response.json()
    assert report["status"] == "partial"
    assert any("non-public" in item for item in report["limitations"])
    assert not any(
        finding["check_id"] == "exposed_sensitive_path" for finding in report["findings"]
    )


def test_oversized_target_response_is_bounded(client, admin_headers, target_server):
    _create_scope(client, admin_headers, target_server, allow_active=False)
    response = client.post(
        "/api/v1/websec/assess",
        headers=admin_headers,
        json={"target": f"http://{target_server}/huge", "active_checks": False},
    )
    assert response.status_code == 200, response.text
    report = response.json()
    assert report["status"] == "partial"
    assert any("assessment limit" in item for item in report["limitations"])


def test_redirect_with_embedded_credentials_is_refused(client, admin_headers, target_server):
    _create_scope(client, admin_headers, target_server, allow_active=False)
    response = client.post(
        "/api/v1/websec/assess",
        headers=admin_headers,
        json={"target": f"http://{target_server}/redirect-credentials", "active_checks": False},
    )
    assert response.status_code == 200, response.text
    assert any("credentials" in item for item in response.json()["limitations"])


def test_viewer_cannot_scan(client, viewer_headers):
    response = client.post(
        "/api/v1/websec/assess",
        headers=viewer_headers,
        json={"target": "https://example.com", "active_checks": False},
    )
    assert response.status_code == 403
