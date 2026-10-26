#!/usr/bin/env python3
"""Scan every API route for authorization and input-handling defects.

Three checks run against a freshly created app in a temporary SQLite database:

* **Authorization matrix** — every route's required permissions are read from its
  FastAPI dependency closure, then the route is exercised as each RBAC role and
  anonymously.  A role that lacks a permission must be refused; a role that has
  it must not be.  Any 5xx fails the run.
* **Adversarial inputs** — every operation in the OpenAPI document is called with
  hostile query strings and path values, random and malformed JSON bodies,
  tampered bearer tokens, wrong content types and oversized bodies.
* **SSRF payloads** — the assessment endpoint is called with loopback, metadata
  and private-range targets while loopback is disabled.

The scans are non-destructive: they create their own database and only call the
application's own HTTP surface.  Output is a JSON report per scan; the exit code
is non-zero when a scan finds something, so this can gate a release.

Usage:
    python scripts/deepscan.py
    python scripts/deepscan.py --only authz
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", choices=["authz", "inputs", "ssrf"], default=None)
    parser.add_argument("--json", action="store_true", help="print the full report")
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

    failed = False
    for report in reports:
        summary = {key: value for key, value in report.items() if key != "results"}
        if args.json:
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            print(json.dumps(summary, sort_keys=True))
        if report.get("unexpected") or report.get("server_errors") or report.get(
            "accepted_unsafe"
        ):
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
