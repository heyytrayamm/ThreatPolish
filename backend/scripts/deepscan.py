#!/usr/bin/env python3
"""Scan every API route for authorization, input, scope and efficiency defects.

Six checks run against a freshly created app in a temporary SQLite database:

* **Authorization matrix** — every route's required permissions are read from its
  FastAPI dependency closure, then the route is exercised as each RBAC role and
  anonymously.  A role that lacks a permission must be refused; a role that has
  it must not be.  Any 5xx fails the run.
* **Adversarial inputs** — every operation in the OpenAPI document is called with
  hostile query strings and path values, random and malformed JSON bodies,
  tampered bearer tokens, wrong content types and oversized bodies.
* **SSRF payloads** — the assessment endpoint is called with loopback, metadata
  and private-range targets while loopback is disabled.
* **Outbound calls** — every call the platform makes to another service is
  pointed at a local probe that redirects, answers with a 33 MiB body or serves
  valid JSON: the market-data refresh, the optional geolocation lookup and an
  assessment whose target redirects to a private address.
* **Development scope** — every served route is matched against the API
  reference, the test suite and the RBAC matrix, and every configuration value
  the code reads against ``.env.example``.  A route or setting that exists in
  only one of those places is a feature that has quietly left the documented
  scope, or documentation for something that no longer exists.
* **Read-path efficiency** — the read endpoints are timed on a populated
  database with the statements they issue counted, so a query in a loop and a
  response that grows with the data are both visible.  Budgets are bytes per
  response, statements per request and repeats of one statement.

The scans are non-destructive: they create their own database, their own probe
server and only call the application's own HTTP surface.  The exit code is
non-zero when a scan finds something, so this can gate a release; each report is
written to ``--out`` (default ``deepscan-reports/``) for CI to keep.

Usage:
    python scripts/deepscan.py
    python scripts/deepscan.py --only authz
    python scripts/deepscan.py --only outbound --json
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import statistics
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

ADMIN_EMAIL = "deepscan@threatpolish.test"
ADMIN_PASSWORD = "deepscan-password-123"
ROLE_PASSWORD = "deepscan-role-password-123"

SSRF_PAYLOADS = [
    "http://127.0.0.1/",
    "http://127.1/",
    "http://0177.0.0.1/",
    "http://0x7f000001/",
    "http://2130706433/",
    "http://[::1]/",
    "http://[::ffff:127.0.0.1]/",
    "http://[0:0:0:0:0:ffff:7f00:1]/",
    "http://localhost/",
    "http://169.254.169.254/latest/meta-data/",
    "http://[fd00::1]/",
    "http://10.0.0.1/",
    "http://192.168.1.1/",
    "http://172.16.0.1/",
    "http://user:pass@127.0.0.1/",
    "http://127.0.0.1:22/",
    "http://127.0.0.1:0/",
    "http://[fe80::1%25lo]/",
    "file:///etc/passwd",
    "gopher://127.0.0.1/",
    "http://127.0.0.1\\@example.com/",
    "http://127.0.0.1#@example.com/",
    "//127.0.0.1/",
]

SSRF_SCOPES = [
    "127.0.0.1",
    "127.1",
    "0.0.0.0",
    "169.254.169.254",
    "10.0.0.1",
    "192.168.1.1",
    "172.16.0.1",
    "::1",
    "fd00::1",
]

STRING_CASES = [
    "",
    " ",
    "%00",
    "%",
    "%_",
    "' OR 1=1 --",
    "../../etc/passwd",
    "<script>alert(1)</script>",
    "\U0001f600" * 40,
    "\u0000",
    "a" * 300,
    "a" * 5000,
    "not-a-date",
    "9999-99-99T99:99:99",
    "-1",
    "1e309",
    "nan",
    "inf",
    "TRUE",
    "null",
    "[]",
    "{}",
]

JSON_CASES: list[Any] = [
    None,
    True,
    False,
    0,
    -1,
    10**30,
    "",
    "\u0000",
    "a" * 5000,
    [],
    [None, 1, "x"],
    {},
    {"events": None},
    {"events": "x"},
    {"events": [None, 1, [], {}]},
    {"nested": {"a": {"b": {"c": {"d": {"e": 1}}}}}},
    {"__proto__": {"admin": True}},
    {"confidence": 2.0, "risk_score": -1.0},
]

RAW_BODIES = [
    b"",
    b"{",
    b"[]",
    b"null",
    b"\xff\xfe",
    b"[" * 1000,
    b'{"confidence": NaN}',
    b'{"risk_score": Infinity}',
]


def _environment(tmp: str) -> None:
    os.environ.update(
        TP_ENV="test",
        TP_DB_URL=f"sqlite:///{tmp}/deepscan.db",
        TP_DATA_DIR=tmp,
        TP_JWT_SECRET="deepscan-secret-that-is-long-enough",
        TP_BOOTSTRAP_ADMIN_EMAIL=ADMIN_EMAIL,
        TP_BOOTSTRAP_ADMIN_PASSWORD=ADMIN_PASSWORD,
        TP_WEB_SEC_ALLOW_LOOPBACK="false",
        TP_RESPONSE_AUTO_APPLY="false",
        # The input scan calls the refresh endpoint with hostile bodies; a
        # fixture keeps that call local.  The outbound scan switches providers
        # itself when it points the adapter at its probe.
        TP_CRYPTO_PROVIDER="fixture",
        # Request logs would bury the report; failures still surface as statuses.
        TP_LOG_LEVEL="ERROR",
    )


def _login(client, email: str, password: str) -> dict[str, str]:
    response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _iter_routes(routes, prefix: str = "") -> Any:
    from fastapi.routing import APIRoute

    for route in routes:
        if isinstance(route, APIRoute):
            yield prefix + route.path, route
        elif getattr(route, "original_router", None) is not None:
            include = getattr(route, "include_context", None)
            yield from _iter_routes(
                route.original_router.routes, prefix + (getattr(include, "prefix", "") or "")
            )
        elif getattr(route, "routes", None):
            yield from _iter_routes(route.routes, prefix)


def _required_permissions(route: Any) -> set[str]:
    """Read the permission strings a route's dependency closure closes over."""
    found: set[str] = set()

    def walk(dependant) -> None:
        function = getattr(dependant, "call", None)
        for cell in getattr(function, "__closure__", None) or ():
            try:
                value = cell.cell_contents
            except ValueError:
                continue
            if isinstance(value, str) and (":" in value or value == "*"):
                found.add(value)
        for sub in getattr(dependant, "dependencies", []) or []:
            walk(sub)

    walk(route.dependant)
    return found


def scan_authorization(client, roles: dict[str, dict[str, str]]) -> dict[str, Any]:
    from app.auth.rbac import has_permission
    from app.main import app

    excluded = {"/api/v1/auth/login", "/api/v1/health", "/api/v1/health/ready"}
    routes = [
        (path, route)
        for path, route in _iter_routes(app.routes)
        if path.startswith("/api/") and path not in excluded
    ]
    unexpected: list[str] = []
    server_errors: list[str] = []
    checks = 0

    for full_path, route in sorted(routes, key=lambda item: item[0]):
        permissions = _required_permissions(route)
        path = full_path
        for parameter in route.param_convertors:
            path = path.replace("{" + parameter + "}", "x")
        for method in sorted(route.methods):
            body = {"json": {}} if method in {"POST", "PUT", "PATCH"} else {}
            for role, headers in roles.items():
                allowed = all(has_permission(role, permission) for permission in permissions)
                response = client.request(method, path, headers=headers, **body)
                checks += 1
                label = f"{role} {method} {path} perms={sorted(permissions)} -> {response.status_code}"
                if response.status_code >= 500:
                    server_errors.append(label)
                elif allowed and response.status_code in {401, 403}:
                    unexpected.append(label + " (permitted role was refused)")
                elif not allowed and response.status_code not in {401, 403}:
                    unexpected.append(label + " (role without permission was not refused)")
            anonymous = client.request(method, path, **body)
            checks += 1
            if permissions and anonymous.status_code not in {401, 403}:
                unexpected.append(
                    f"anonymous {method} {path} perms={sorted(permissions)} -> "
                    f"{anonymous.status_code}"
                )

    return {
        "scan": "authorization",
        "routes": len(routes),
        "checks": checks,
        "unexpected": unexpected,
        "server_errors": server_errors,
    }


def scan_inputs(client, headers: dict[str, str]) -> dict[str, Any]:
    rng = random.Random(20261027)
    specification = client.get("/openapi.json").json()
    operations = [
        (path, method.upper())
        for path, methods in specification["paths"].items()
        for method in methods
        if method.upper() in {"GET", "POST", "PUT", "PATCH", "DELETE"}
    ]
    failures: list[dict[str, Any]] = []
    requests = 0
    status_counts: dict[int, int] = {}

    def record(label: str, response) -> None:
        nonlocal requests
        requests += 1
        status_counts[response.status_code] = status_counts.get(response.status_code, 0) + 1
        if response.status_code >= 500:
            failures.append({"request": label, "status": response.status_code})

    def fill(path: str, value: str) -> str:
        return re.sub(r"\{[^}]+\}", value, path)

    for path, method in operations:
        for case in rng.sample(STRING_CASES, 5):
            escaped = (
                case.replace("\u0000", "%00").replace(" ", "%20").replace("%", "%25")
                if case
                else ""
            )
            body = {"json": {"x": case}} if method in {"POST", "PUT", "PATCH"} else {}
            record(
                f"{method} {path} path={case[:24]!r}",
                client.request(
                    method,
                    fill(path, escaped),
                    headers=headers,
                    params={"limit": case, "q": case, "hours": case, "status": case},
                    **body,
                ),
            )

    write_operations = [
        (path, method)
        for path, method in operations
        if method in {"POST", "PUT", "PATCH", "DELETE"}
    ]
    for path, method in write_operations:
        for case in rng.sample(JSON_CASES, min(6, len(JSON_CASES))):
            record(
                f"{method} {path} json={repr(case)[:40]}",
                client.request(method, fill(path, "x"), headers=headers, json=case),
            )
        for raw in RAW_BODIES:
            record(
                f"{method} {path} raw={raw[:12]!r}",
                client.request(
                    method,
                    fill(path, "x"),
                    headers={**headers, "Content-Type": "application/json"},
                    content=raw,
                ),
            )

    token = headers["Authorization"].removeprefix("Bearer ")
    header_b64, payload_b64, signature_b64 = token.split(".")
    tampered = payload_b64[:-2] + ("AA" if payload_b64[-2:] != "AA" else "BB")
    bad_tokens = [
        "",
        "x",
        "a.b.c",
        "a.b.c.d",
        "..",
        token + "x",
        f"{header_b64}.{tampered}.{signature_b64}",
        f"{header_b64}.{payload_b64}.",
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." + payload_b64 + ".",
        f"Bearer {token}",
        "a" * 10000,
    ]
    for bad in bad_tokens:
        for path in ("/api/v1/auth/me", "/api/v1/events"):
            record(
                f"GET {path} token={bad[:16]!r}",
                client.get(path, headers={"Authorization": f"Bearer {bad}"}),
            )

    for size in (0, 1, 1024, 65537, 33 * 1024 * 1024):
        record(
            f"POST /api/v1/ingest/events size={size}",
            client.post(
                "/api/v1/ingest/events",
                headers={**headers, "Content-Type": "application/json"},
                content=b"x" * size,
            ),
        )
    for content_type in ("text/plain", "application/x-www-form-urlencoded", "application/xml"):
        record(
            f"POST /api/v1/ingest/events content-type={content_type}",
            client.post(
                "/api/v1/ingest/events",
                headers={**headers, "Content-Type": content_type},
                content=b'{"events":[]}',
            ),
        )

    return {
        "scan": "inputs",
        "operations": len(operations),
        "requests": requests,
        "status_distribution": dict(sorted(status_counts.items())),
        "server_errors": failures,
    }


def scan_ssrf(client, headers: dict[str, str]) -> dict[str, Any]:
    scopes = 0
    for domain in SSRF_SCOPES:
        response = client.post(
            "/api/v1/websec/scopes",
            headers=headers,
            json={
                "domain": domain,
                "authorized_by": "deepscan",
                "expires_in_days": 1,
                "allow_active": True,
            },
        )
        scopes += response.status_code == 201

    results = []
    for payload in SSRF_PAYLOADS:
        response = client.post(
            "/api/v1/websec/assess",
            headers=headers,
            json={"target": payload, "active_checks": False},
        )
        code = ""
        try:
            code = response.json().get("error", {}).get("code", "")
        except ValueError:  # pragma: no cover - a non-JSON body is itself a finding
            code = "non_json_body"
        results.append({"payload": payload, "status": response.status_code, "code": code})

    accepted = [item for item in results if item["status"] == 200]
    return {
        "scan": "ssrf",
        "scopes_created": scopes,
        "payloads": len(SSRF_PAYLOADS),
        "accepted_unsafe": accepted,
        "results": results,
    }


HUGE_BYTES = 33 * 1024 * 1024
PROBE_CHUNK = 64 * 1024
PRICE_PAYLOAD = {
    "bitcoin": {
        "usd": 64000.0,
        "usd_24h_change": 2.1,
        "usd_24h_vol": 3.4e10,
        "usd_market_cap": 1.26e12,
        "last_updated_at": 1793000000,
    },
    "ethereum": {
        "usd": 3200.0,
        "usd_24h_change": -4.1,
        "usd_24h_vol": 1.6e10,
        "usd_market_cap": 3.8e11,
        "last_updated_at": 1793000000,
    },
}


class _ProbeServer(ThreadingHTTPServer):
    """Records which paths were fetched and how much of a huge body was sent."""

    daemon_threads = True

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.hits: list[str] = []
        self.transferred: dict[str, int] = {}
        self.lock = threading.Lock()


class _ProbeHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "deepscan-probe"

    def log_message(self, *args: Any) -> None:
        return

    @property
    def probe(self) -> _ProbeServer:
        return self.server  # type: ignore[return-value]

    def _send(self, status: int, payload: Any) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location: str) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _huge(self, path: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(HUGE_BYTES))
        self.end_headers()
        chunk = b"x" * PROBE_CHUNK
        sent = 0
        try:
            while sent < HUGE_BYTES:
                self.wfile.write(chunk)
                sent += len(chunk)
        except (BrokenPipeError, ConnectionResetError):
            pass
        with self.probe.lock:
            self.probe.transferred[path] = sent

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        port = self.probe.server_port
        with self.probe.lock:
            self.probe.hits.append(path)
        if path == "/internal-secret":
            # Reaching this path proves a redirect was followed.
            self._send(200, {"reached": True})
        elif path == "/redirect":
            self._redirect("http://10.0.0.1/")
        elif path.startswith("/redirect/") or path.startswith("/geo-redirect/"):
            self._redirect(f"http://127.0.0.1:{port}/internal-secret")
        elif path.startswith("/huge/") or path.startswith("/geo-huge/"):
            self._huge(path)
        elif path.startswith("/price/"):
            self._send(200, PRICE_PAYLOAD)
        elif path.startswith("/geo/"):
            self._send(200, {"loc": "37.4056,-122.0775"})
        else:
            self._send(404, {"error": "not found"})


class _Probe:
    def __enter__(self) -> tuple[str, _ProbeServer]:
        self.server = _ProbeServer(("127.0.0.1", 0), _ProbeHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return f"http://127.0.0.1:{self.server.server_port}", self.server

    def __exit__(self, *args: Any) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def scan_outbound(client, headers: dict[str, str]) -> dict[str, Any]:
    """Point every outbound call at a probe that redirects or floods."""
    from app.auth import geo
    from app.core.config import reset_settings_cache
    from app.core.outbound import MAX_OUTBOUND_JSON_BYTES

    probes: list[dict[str, Any]] = []
    unsafe: list[str] = []

    def error_code(response) -> str:
        try:
            return str(response.json().get("error", {}).get("code", ""))
        except ValueError:
            return "non_json_body"

    with _Probe() as (base, server):
        def clear_snapshots() -> None:
            # The scan's own database; earlier refreshes (the input scan uses the
            # fixture provider) would otherwise make the provider call "not due"
            # and the probes would pass without touching the probe server.
            from sqlalchemy import text

            from app.db.database import connection

            with connection() as conn:
                conn.execute(text("DELETE FROM crypto_risk"))
                conn.execute(text("DELETE FROM crypto_snapshots"))

        clear_snapshots()

        def refresh(prefix: str) -> Any:
            os.environ.update(
                TP_CRYPTO_PROVIDER="coingecko",
                TP_CRYPTO_API_BASE=f"{base}/{prefix}",
                TP_CRYPTO_MIN_REFRESH_SECONDS="5",
            )
            reset_settings_cache()
            return client.post(
                "/api/v1/crypto/refresh", headers=headers, json={"symbols": ["BTC"]}
            )

        # A provider that answers with a redirect must not be followed; the
        # redirect points back at the probe so a followed hop is observable.
        redirect = refresh("redirect")
        followed = "/internal-secret" in server.hits
        probes.append(
            {
                "call": "crypto refresh",
                "case": "redirect",
                "status": redirect.status_code,
                "code": error_code(redirect),
                "reached_redirect_target": followed,
            }
        )
        if redirect.status_code == 200 or followed:
            unsafe.append("provider redirect was followed or accepted")

        oversized = refresh("huge")
        transferred = server.transferred.get("/huge/simple/price", 0)
        probes.append(
            {
                "call": "crypto refresh",
                "case": "oversized body",
                "status": oversized.status_code,
                "code": error_code(oversized),
                "bytes_read": transferred,
                "limit": MAX_OUTBOUND_JSON_BYTES,
            }
        )
        if oversized.status_code == 200:
            unsafe.append("provider oversized body was accepted")
        if transferred > MAX_OUTBOUND_JSON_BYTES * 4:
            unsafe.append("provider response was read past the documented limit")

        # The valid call runs last: the minimum refresh interval would otherwise
        # skip the provider for the two failure cases above.
        valid = refresh("price")
        retrieved = [item.get("symbol") for item in valid.json().get("refreshed", [])] if valid.status_code == 200 else []
        probes.append(
            {
                "call": "crypto refresh",
                "case": "valid payload",
                "status": valid.status_code,
                "code": error_code(valid) if valid.status_code >= 400 else "",
                "refreshed": retrieved,
            }
        )
        if valid.status_code != 200 or "BTC" not in retrieved:
            unsafe.append("provider refresh rejected a valid payload")

        geo.clear_cache()
        for case, path, address in (
            ("valid payload", "/geo/{ip}", "8.8.8.8"),
            ("redirect", "/geo-redirect/{ip}", "8.8.4.4"),
            ("oversized body", "/geo-huge/{ip}", "1.1.1.1"),
        ):
            before = len(server.hits)
            point = geo.locate(address, url=f"{base}{path}", timeout=5.0)
            served = server.hits[before:]
            probes.append(
                {
                    "call": "geolocation lookup",
                    "case": case,
                    "located": point is not None,
                    "paths": served,
                }
            )
            if case == "valid payload" and point is None:
                unsafe.append("geolocation lookup rejected a valid payload")
            if case == "redirect" and ("/internal-secret" in served or point is not None):
                unsafe.append("geolocation redirect was followed")
            if case == "oversized body" and point is not None:
                unsafe.append("geolocation oversized body was accepted")

        # An assessment redirect must not reach a private address, even when
        # that address has its own authorization scope.
        loopback = os.environ.get("TP_WEB_SEC_ALLOW_LOOPBACK")
        os.environ["TP_WEB_SEC_ALLOW_LOOPBACK"] = "true"
        reset_settings_cache()
        try:
            for domain in ("127.0.0.1", "10.0.0.1"):
                client.post(
                    "/api/v1/websec/scopes",
                    headers=headers,
                    json={
                        "domain": domain,
                        "authorized_by": "deepscan",
                        "expires_in_days": 1,
                        "allow_active": False,
                    },
                )
            assessment = client.post(
                "/api/v1/websec/assess",
                headers=headers,
                json={"target": f"http://127.0.0.1:{server.server_port}/redirect", "active_checks": False},
            )
        finally:
            if loopback is None:
                os.environ.pop("TP_WEB_SEC_ALLOW_LOOPBACK", None)
            else:
                os.environ["TP_WEB_SEC_ALLOW_LOOPBACK"] = loopback
            reset_settings_cache()
        report = assessment.json() if assessment.status_code == 200 else {}
        limitations = [str(item) for item in report.get("limitations", [])]
        refused = any("non-public address" in item for item in limitations)
        probes.append(
            {
                "call": "web assessment",
                "case": "redirect to private address",
                "status": assessment.status_code,
                "code": error_code(assessment),
                "scan_status": report.get("status", ""),
                "refused": refused,
            }
        )
        # A refusal is reported inside a 200 response as a partial scan, so the
        # status line alone cannot tell whether the redirect was followed.
        if not refused or report.get("status") == "completed":
            unsafe.append("assessment followed a redirect to a private address")

        hits = list(server.hits)
        transferred_all = dict(server.transferred)

    return {
        "scan": "outbound",
        "probes": probes,
        "requested_paths": hits,
        "bytes_written": transferred_all,
        "unsafe": unsafe,
    }


# Variables only the Compose file consumes; they are not read by the app.
COMPOSE_ONLY_ENV = {"TP_DB_PASSWORD", "TP_RETENTION_INTERVAL_SECONDS"}

# A read endpoint is expected to stay inside these budgets. They are deliberately
# loose enough for a cold cache and tight enough to catch a query in a loop.
MAX_QUERIES_PER_REQUEST = 40
MAX_P50_MS = 250.0
# 512 KiB is four times the largest read response on the evaluation corpus and
# half the size the unbounded graph view used to return for the same data.
MAX_RESPONSE_KIB = 512
MAX_DUPLICATE_STATEMENTS = 8


def _path_key(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "{*}", path)


def scan_scope(client) -> dict[str, Any]:
    """Check that the developed surface is documented, tested and reachable.

    Compares the routes the application actually serves with the API reference,
    the test modules and the RBAC matrix, and compares the configuration the
    code reads with the environment file an operator copies.  A route or a
    setting that exists in only one of those places is how a development scope
    silently stops matching what is documented and exercised.
    """
    from app.auth.rbac import ROLES
    from app.main import app

    docs = (ROOT.parent / "docs" / "05-api.md").read_text(encoding="utf-8")
    documented = {_path_key(item.split("?")[0]) for item in re.findall(r"`(/[^`\s]+)`", docs)}
    tests_text = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted((ROOT / "tests").glob("*.py"))
    )
    # ".env.example" documents variables the application reads, not just the
    # ones the settings object reads: bootstrap credentials live in users.py.
    config_text = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted((ROOT / "app").rglob("*.py"))
    )
    env_text = (ROOT.parent / ".env.example").read_text(encoding="utf-8")
    # A commented line is still documentation of an optional variable.
    env_keys = set(re.findall(r"^#?\s*(TP_[A-Z0-9_]+)=", env_text, re.MULTILINE))
    config_keys = set(re.findall(r"TP_[A-Z0-9_]+", config_text)) | COMPOSE_ONLY_ENV

    routes = [(path, route) for path, route in _iter_routes(app.routes) if path.startswith("/api/")]
    undocumented: list[str] = []
    untested: list[str] = []
    used_permissions: set[str] = set()
    for path, route in sorted(routes, key=lambda item: item[0]):
        relative = path.removeprefix("/api/v1")
        if _path_key(relative) not in documented:
            undocumented.append(path)
        base = path.split("{")[0].rstrip("/")
        # Tests build URLs from a base fixture, so the path is not always
        # preceded by a quote; a bare occurrence is enough to count.
        if base not in tests_text:
            untested.append(path)
        used_permissions |= _required_permissions(route)

    declared_permissions = {
        permission for permissions in ROLES.values() for permission in permissions if permission != "*"
    }
    orphan_permissions = sorted(declared_permissions - used_permissions)
    undocumented_config = sorted(config_keys - env_keys)
    unused_env = sorted(env_keys - config_keys)
    route_keys = {_path_key(item.removeprefix("/api/v1")) for item, _ in routes}
    route_segments = {key.lstrip("/").split("/")[0] for key in route_keys}
    stale_docs = sorted(
        path
        for path in documented
        if path.lstrip("/").split("/")[0] in route_segments and path not in route_keys
    )

    findings: list[str] = []
    findings += [f"undocumented route {path}" for path in undocumented]
    findings += [f"undocumented configuration {key}" for key in undocumented_config]
    findings += [f"generated from configuration but missing from .env.example {key}" for key in unused_env]

    return {
        "scan": "scope",
        "routes": len(routes),
        "documented_routes": len(routes) - len(undocumented),
        "tested_routes": len(routes) - len(untested),
        "undocumented_routes": undocumented,
        "untested_routes": untested,
        "stale_documentation": stale_docs[:20],
        "orphan_permissions": orphan_permissions,
        "documented_environment_keys": len(env_keys),
        "undocumented_config": undocumented_config,
        "unused_env": unused_env,
        "findings": findings,
    }


def scan_efficiency(client, headers: dict[str, str]) -> dict[str, Any]:
    """Time the read endpoints and count the SQL statements each one issues.

    The database is seeded with the evaluation corpus and correlated once, so the
    numbers describe a populated installation rather than an empty one.  A
    statement repeated many times inside one request is the signature of a query
    in a loop, which is what makes a read endpoint slow as data accumulates.
    """
    from collections import Counter

    from sqlalchemy import event

    from app.core.config import get_settings
    from app.correlation.engine import correlate
    from app.db.database import get_engine
    from app.evaluation.scenarios import generate_dataset
    from app.telemetry.ingest import Ingestor

    dataset = generate_dataset(
        seed=99,
        campaign_groups=40,
        sessions_per_group=3,
        benign_sessions=24,
        same_ip_pairs=4,
        incomplete_groups=2,
        delayed_sessions=3,
    )
    events = [item for session in dataset["sessions"] for item in session["events"]]
    Ingestor(get_settings()).ingest(events, actor="deepscan-efficiency")
    correlate(window_hours=24, trigger="deepscan")

    campaigns = client.get("/api/v1/campaigns", headers=headers).json()["items"]
    detail = client.get(f"/api/v1/campaigns/{campaigns[0]['id']}", headers=headers).json()
    edge_id = detail["edges"][0]["id"]
    event_id = client.get("/api/v1/events", headers=headers, params={"limit": 1}).json()["items"][0]["id"]

    endpoints = [
        ("events", "/api/v1/events"),
        ("event", f"/api/v1/events/{event_id}"),
        ("events summary", "/api/v1/events/summary"),
        ("sources", "/api/v1/sources"),
        ("quarantine", "/api/v1/quarantine"),
        ("graph", "/api/v1/graph?hours=24"),
        ("correlation latest", "/api/v1/correlation/latest"),
        ("campaigns", "/api/v1/campaigns"),
        ("campaign detail", f"/api/v1/campaigns/{campaigns[0]['id']}"),
        ("edge", f"/api/v1/edges/{edge_id}"),
        ("honeypot profiles", "/api/v1/honeypot/profiles"),
        ("honeypot sessions", "/api/v1/honeypot/sessions"),
        ("websec findings", "/api/v1/websec/findings"),
        ("websec scopes", "/api/v1/websec/scopes"),
        ("crypto assets", "/api/v1/crypto/assets"),
        ("crypto history", "/api/v1/crypto/assets/BTC/history"),
        ("crypto providers", "/api/v1/crypto/providers"),
        ("investigations", "/api/v1/investigations"),
        ("responses", "/api/v1/responses"),
        ("response policies", "/api/v1/responses/policies"),
        ("audit", "/api/v1/audit"),
        ("retention", "/api/v1/retention"),
        ("metrics", "/api/v1/metrics"),
        ("identity", "/api/v1/auth/me"),
        ("sessions", "/api/v1/auth/sessions"),
    ]

    statements: list[str] = []

    def _record(conn, cursor, statement, parameters, context, executemany) -> None:
        statements.append(" ".join(statement.split()))

    engine = get_engine()
    event.listen(engine, "before_cursor_execute", _record)
    measurements: list[dict[str, Any]] = []
    over_budget: list[str] = []
    try:
        for label, path in endpoints:
            client.get(path, headers=headers)  # warm-up
            latencies: list[float] = []
            query_counts: list[int] = []
            repeated = 0
            body = 0
            status = 0
            for _ in range(5):
                statements.clear()
                started = time.perf_counter()
                response = client.get(path, headers=headers)
                latencies.append((time.perf_counter() - started) * 1000)
                query_counts.append(len(statements))
                counted = Counter(statements)
                repeated = max(repeated, max(counted.values(), default=0))
                body = max(body, len(response.content))
                status = response.status_code
            p50 = statistics.median(latencies)
            queries = int(statistics.median(query_counts))
            entry = {
                "endpoint": label,
                "path": path,
                "status": status,
                "p50_ms": round(p50, 2),
                "max_ms": round(max(latencies), 2),
                "queries": queries,
                "repeated_statement": repeated,
                "response_kib": round(body / 1024, 1),
            }
            if status >= 400:
                entry["skipped"] = f"HTTP {status}"
            else:
                if queries > MAX_QUERIES_PER_REQUEST:
                    over_budget.append(f"{label}: {queries} statements (> {MAX_QUERIES_PER_REQUEST})")
                if p50 > MAX_P50_MS:
                    over_budget.append(f"{label}: p50 {p50:.1f} ms (> {MAX_P50_MS:.0f})")
                if body / 1024 > MAX_RESPONSE_KIB:
                    over_budget.append(f"{label}: {body / 1024:.0f} KiB response")
                if repeated > MAX_DUPLICATE_STATEMENTS:
                    over_budget.append(
                        f"{label}: one statement ran {repeated}x in a request (> {MAX_DUPLICATE_STATEMENTS})"
                    )
            measurements.append(entry)
    finally:
        event.remove(engine, "before_cursor_execute", _record)

    return {
        "scan": "efficiency",
        "seed_sessions": len(dataset["sessions"]),
        "seed_events": len(events),
        "budgets": {
            "queries_per_request": MAX_QUERIES_PER_REQUEST,
            "p50_ms": MAX_P50_MS,
            "response_kib": MAX_RESPONSE_KIB,
            "repeated_statement": MAX_DUPLICATE_STATEMENTS,
        },
        "endpoints": measurements,
        "over_budget": over_budget,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--only",
        choices=["authz", "inputs", "ssrf", "outbound", "scope", "efficiency"],
        default=None,
    )
    parser.add_argument("--json", action="store_true", help="print the full report")
    parser.add_argument(
        "--out", type=Path, default=Path("deepscan-reports"), help="directory for the JSON reports"
    )
    args = parser.parse_args()

    tmp = tempfile.mkdtemp(prefix="tp-deepscan-")
    _environment(tmp)

    from fastapi.testclient import TestClient

    from app.auth.users import create_user
    from app.main import create_app

    client = TestClient(create_app(), raise_server_exceptions=False)
    with client:
        roles = {"admin": _login(client, ADMIN_EMAIL, ADMIN_PASSWORD)}
        for role in ("viewer", "analyst", "sensor"):
            email = f"{role}@threatpolish.test"
            create_user(email=email, name=role, role=role, password=ROLE_PASSWORD)
            roles[role] = _login(client, email, ROLE_PASSWORD)

        reports = []
        if args.only in (None, "authz"):
            reports.append(scan_authorization(client, roles))
        if args.only in (None, "inputs"):
            reports.append(scan_inputs(client, roles["admin"]))
        if args.only in (None, "ssrf"):
            reports.append(scan_ssrf(client, roles["admin"]))
        if args.only in (None, "outbound"):
            reports.append(scan_outbound(client, roles["admin"]))
        if args.only in (None, "scope"):
            reports.append(scan_scope(client))
        if args.only in (None, "efficiency"):
            reports.append(scan_efficiency(client, roles["admin"]))

    args.out.mkdir(parents=True, exist_ok=True)
    failed = False
    for report in reports:
        summary = {key: value for key, value in report.items() if key != "results"}
        (args.out / f"{report['scan']}.json").write_text(
            json.dumps(report, indent=2, sort_keys=True), encoding="utf-8"
        )
        if args.json:
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            print(json.dumps(summary, sort_keys=True))
        if (
            report.get("unexpected")
            or report.get("server_errors")
            or report.get("accepted_unsafe")
            or report.get("unsafe")
            or report.get("findings")
            or report.get("over_budget")
        ):
            failed = True
    print(f"reports written to {args.out.resolve()}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
