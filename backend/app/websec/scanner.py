"""Scope-limited web security assessment.

The scanner performs a small set of non-destructive checks against explicitly
authorized hosts.  It never fuzzes, never submits credentials, never attempts
exploitation, and refuses to connect to private, loopback or link-local
addresses unless the local-test switch is enabled.

Findings are persisted and also flow through the shared telemetry pipeline as
``websec.finding`` events so that everything else can reason about them.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import socket
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx
from sqlalchemy import select, text

from ..core.config import get_settings
from ..core.errors import AuthorizationFailure, NotFound, UpstreamFailure
from ..core.limits import SlidingWindowLimiter
from ..core.logging import get_logger
from ..core.security import iso, new_id, utcnow
from ..db.database import connection, dumps, loads
from ..db.schema import findings as findings_table
from ..db.schema import scans
from ..telemetry.ingest import Ingestor
from .scope import find_active_scope, validate_target

log = get_logger(__name__)

USER_AGENT = "ThreatPolish-Assessor/1.0 (+authorized-assessment)"
ACTIVE_PATHS = ("/.git/HEAD", "/.env", "/server-status", "/actuator/env")
_host_limiters: dict[str, SlidingWindowLimiter] = {}


@dataclass
class Finding:
    check_id: str
    title: str
    severity: str
    confidence: str
    evidence: dict[str, Any]
    remediation: str


REMEDIATION = {
    "missing_hsts": "Send Strict-Transport-Security with a max-age of at least six months on HTTPS responses.",
    "missing_csp": "Define a Content-Security-Policy that restricts script and frame sources.",
    "missing_frame_protection": "Set X-Frame-Options: DENY or a CSP frame-ancestors directive.",
    "missing_nosniff": "Set X-Content-Type-Options: nosniff on all responses.",
    "missing_referrer_policy": "Set Referrer-Policy to strict-origin-when-cross-origin or stricter.",
    "missing_permissions_policy": "Disable unused browser features with Permissions-Policy.",
    "server_banner": "Suppress detailed server and framework version banners.",
    "cors_wildcard": "Replace wildcard CORS origins with an explicit allow-list; never combine '*' with credentials.",
    "cookie_flags": "Set Secure, HttpOnly and SameSite on session cookies.",
    "no_https": "Redirect all plaintext HTTP traffic to HTTPS and enable HSTS.",
    "tls_expiring": "Renew the TLS certificate before expiry and automate renewal monitoring.",
    "tls_invalid": "Replace the certificate with one that chains to a trusted CA and matches the hostname.",
    "exposed_sensitive_path": "Remove the file or restrict access at the edge; rotate any credentials it contained.",
}


def assess(
    *, target: str, active_checks: bool = False, actor: str = "system"
) -> dict[str, Any]:
    settings = get_settings()
    host, url, scheme = validate_target(target, allow_active=active_checks)
    scope = find_active_scope(host)
    scan_id = new_id("scn")
    started = utcnow()
    started_perf = time.perf_counter()

    with connection() as conn:
        conn.execute(
            scans.insert().values(
                id=scan_id,
                started_at=iso(started),
                scope_id=scope["id"],
                target=host[:255],
                status="running",
                requested_by=actor[:64],
                finding_count=0,
            )
        )

    collected: list[Finding] = []
    limitations: list[str] = []
    final_url = url
    status_code: int | None = None
    error: str | None = None

    try:
        if scheme == "https":
            collected.extend(_tls_checks(host, urlsplit(url).port or 443))
        response, final_url = _fetch(url)
        status_code = response.status_code
        collected.extend(_passive_checks(response, final_url, scheme))
        if active_checks:
            origin = f"{urlsplit(final_url).scheme}://{urlsplit(final_url).netloc}"
            collected.extend(_active_checks(origin))
    except (AuthorizationFailure, UpstreamFailure) as exc:
        error = exc.message
        limitations.append(error)
    except httpx.HTTPError as exc:
        error = f"target request failed: {type(exc).__name__}"
        limitations.append(error)
    except ssl.SSLError as exc:
        error = f"TLS error: {type(exc).__name__}"
        limitations.append(error)
        collected.append(
            Finding(
                "tls_invalid",
                "TLS certificate could not be validated",
                "high",
                "high",
                {"error": type(exc).__name__},
                REMEDIATION["tls_invalid"],
            )
        )

    if not active_checks:
        limitations.append("active path probes were not requested")
    elif not scope["allow_active"]:
        limitations.append("active path probes are not authorized for this scope")

    event_ids: list[str] = []
    ingestor = Ingestor(settings)
    for finding in collected:
        finding_id = new_id("fnd")
        event_id = _emit_finding(ingestor, scan_id, host, finding)
        event_ids.append(event_id)
        with connection() as conn:
            conn.execute(
                findings_table.insert().values(
                    id=finding_id,
                    ts=iso(utcnow()),
                    scan_id=scan_id,
                    scope_id=scope["id"],
                    target=host[:255],
                    check_id=finding.check_id,
                    title=finding.title[:200],
                    severity=finding.severity,
                    confidence=finding.confidence,
                    evidence=dumps(finding.evidence),
                    remediation=finding.remediation,
                    status="open",
                    event_id=event_id,
                )
            )

    finished = utcnow()
    duration_ms = round((time.perf_counter() - started_perf) * 1000, 2)
    with connection() as conn:
        conn.execute(
            scans.update()
            .where(scans.c.id == scan_id)
            .values(
                finished_at=iso(finished),
                status="completed" if error is None else "partial",
                error=error[:1000] if error else None,
                finding_count=len(collected),
            )
        )

    by_severity: dict[str, int] = {}
    for finding in collected:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

    return {
        "scan_id": scan_id,
        "target": host,
        "url": final_url,
        "scope_id": scope["id"],
        "authorized_by": scope["authorized_by"],
        "status": "completed" if error is None else "partial",
        "http_status": status_code,
        "duration_ms": duration_ms,
        "active_checks": active_checks,
        "findings": [
            {
                "check_id": finding.check_id,
                "title": finding.title,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "evidence": finding.evidence,
                "remediation": finding.remediation,
            }
            for finding in collected
        ],
        "finding_count": len(collected),
        "by_severity": by_severity,
        "event_ids": [event_id for event_id in event_ids if event_id],
        "limitations": limitations,
        "note": (
            "Checks are non-destructive and limited to the authorized host. "
            "Absence of a finding is not proof that the target is secure."
        ),
    }


def _fetch(url: str) -> tuple[httpx.Response, str]:
    settings = get_settings()
    headers = {"User-Agent": USER_AGENT, "Accept": "text/html,application/json;q=0.9,*/*;q=0.8"}
    current = url
    with httpx.Client(
        timeout=settings.websec_timeout_seconds,
        follow_redirects=False,
        verify=True,
        headers=headers,
    ) as client:
        for _ in range(4):
            host = urlsplit(current).hostname or ""
            find_active_scope(host)
            _rate_limit(host)
            response = client.get(current)
            if response.is_redirect and response.headers.get("location"):
                target = urljoin(current, response.headers["location"])
                parsed = urlsplit(target)
                if parsed.scheme not in {"http", "https"}:
                    raise AuthorizationFailure("redirect left the http(s) scheme")
                find_active_scope(parsed.hostname or "")
                if parsed.scheme == "http" and urlsplit(current).scheme == "https":
                    # Downgrade is reported by the passive checks when observed.
                    pass
                current = target
                continue
            return response, str(response.url)
    raise UpstreamFailure("too many redirects while assessing the target")


def _rate_limit(host: str) -> None:
    settings = get_settings()
    limiter = _host_limiters.get(host)
    if limiter is None:
        limiter = SlidingWindowLimiter(settings.websec_max_requests_per_host, 60.0)
        _host_limiters[host] = limiter
    allowed, retry_after = limiter.allow(host)
    if not allowed:
        raise UpstreamFailure(
            "assessment rate limit reached for this host",
            details={"retry_after_seconds": retry_after},
        )


def _passive_checks(response: httpx.Response, url: str, scheme: str) -> list[Finding]:
    headers = {key.lower(): value for key, value in response.headers.items()}
    results: list[Finding] = []
    if scheme == "https" and "strict-transport-security" not in headers:
        results.append(
            Finding(
                "missing_hsts",
                "HSTS header is missing",
                "medium",
                "high",
                {"header": "Strict-Transport-Security", "present": False},
                REMEDIATION["missing_hsts"],
            )
        )
    if "content-security-policy" not in headers:
        results.append(
            Finding(
                "missing_csp",
                "Content-Security-Policy is missing",
                "low",
                "high",
                {"header": "Content-Security-Policy", "present": False},
                REMEDIATION["missing_csp"],
            )
        )
    if "x-frame-options" not in headers and "frame-ancestors" not in headers.get(
        "content-security-policy", ""
    ):
        results.append(
            Finding(
                "missing_frame_protection",
                "Clickjacking protection is missing",
                "low",
                "medium",
                {"headers_checked": ["X-Frame-Options", "Content-Security-Policy"]},
                REMEDIATION["missing_frame_protection"],
            )
        )
    if headers.get("x-content-type-options", "").lower() != "nosniff":
        results.append(
            Finding(
                "missing_nosniff",
                "X-Content-Type-Options is not nosniff",
                "low",
                "high",
                {"value": headers.get("x-content-type-options", "")},
                REMEDIATION["missing_nosniff"],
            )
        )
    if "referrer-policy" not in headers:
        results.append(
            Finding(
                "missing_referrer_policy",
                "Referrer-Policy is missing",
                "info",
                "high",
                {"header": "Referrer-Policy", "present": False},
                REMEDIATION["missing_referrer_policy"],
            )
        )
    if "permissions-policy" not in headers:
        results.append(
            Finding(
                "missing_permissions_policy",
                "Permissions-Policy is missing",
                "info",
                "high",
                {"header": "Permissions-Policy", "present": False},
                REMEDIATION["missing_permissions_policy"],
            )
        )
    server = headers.get("server", "")
    if server and re.search(r"\d+\.\d+", server):
        results.append(
            Finding(
                "server_banner",
                "Server banner discloses version information",
                "info",
                "high",
                {"server": server[:120]},
                REMEDIATION["server_banner"],
            )
        )
    if headers.get("access-control-allow-origin") == "*":
        results.append(
            Finding(
                "cors_wildcard",
                "CORS allows any origin",
                "medium",
                "high",
                {"access_control_allow_origin": "*"},
                REMEDIATION["cors_wildcard"],
            )
        )

    for cookie in response.headers.get_list("set-cookie"):
        name = cookie.split("=", 1)[0].strip()
        lower = cookie.lower()
        issues = []
        if "secure" not in lower:
            issues.append("Secure")
        if "httponly" not in lower:
            issues.append("HttpOnly")
        if "samesite" not in lower:
            issues.append("SameSite")
        if issues:
            results.append(
                Finding(
                    "cookie_flags",
                    f"Cookie '{name}' is missing security attributes",
                    "medium",
                    "high",
                    {"cookie_name": name, "missing": issues},
                    REMEDIATION["cookie_flags"],
                )
            )

    if urlsplit(url).scheme == "http":
        results.append(
            Finding(
                "no_https",
                "Assessed endpoint is served over plaintext HTTP",
                "medium",
                "high",
                {"url_scheme": "http", "host": urlsplit(url).hostname},
                REMEDIATION["no_https"],
            )
        )
    return results


def _tls_checks(host: str, port: int = 443) -> list[Finding]:
    results: list[Finding] = []
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                certificate = tls.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        return [
            Finding(
                "tls_invalid",
                "TLS certificate failed validation",
                "high",
                "high",
                {"reason": exc.verify_message[:200]},
                REMEDIATION["tls_invalid"],
            )
        ]
    except (OSError, ssl.SSLError) as exc:
        return [
            Finding(
                "tls_invalid",
                "TLS endpoint could not be reached",
                "medium",
                "medium",
                {"error": type(exc).__name__},
                REMEDIATION["tls_invalid"],
            )
        ]

    not_after = certificate.get("notAfter") if certificate else None
    if not_after:
        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), tz=timezone.utc)
        days_left = (expires - datetime.now(timezone.utc)).days
        if days_left < 30:
            results.append(
                Finding(
                    "tls_expiring",
                    "TLS certificate expires soon",
                    "medium" if days_left >= 0 else "high",
                    "high",
                    {"not_after": expires.isoformat(), "days_remaining": days_left},
                    REMEDIATION["tls_expiring"],
                )
            )
    return results


def _active_checks(base: str) -> list[Finding]:
    settings = get_settings()
    results: list[Finding] = []
    host = urlsplit(base).hostname or base
    with httpx.Client(
        timeout=settings.websec_timeout_seconds,
        follow_redirects=False,
        verify=True,
        headers={"User-Agent": USER_AGENT},
    ) as client:
        for path in ACTIVE_PATHS:
            _rate_limit(host)
            try:
                response = client.get(base + path)
            except httpx.HTTPError:
                continue
            if response.status_code != 200:
                continue
            body = response.text[:4000]
            evidence: dict[str, Any] | None = None
            title = ""
            if path == "/.git/HEAD" and body.startswith("ref:"):
                title = "Exposed git metadata"
                evidence = {"path": path, "excerpt": body[:80]}
            elif path == "/.env" and re.search(r"^[A-Z0-9_]+=", body, re.MULTILINE):
                keys = sorted(
                    {
                        line.split("=", 1)[0]
                        for line in body.splitlines()
                        if "=" in line and not line.strip().startswith("#")
                    }
                )[:10]
                title = "Exposed environment file"
                evidence = {"path": path, "keys": keys}
            elif path == "/server-status" and "Server Version" in body:
                title = "Exposed server-status page"
                evidence = {"path": path, "excerpt": body[:120]}
            elif path == "/actuator/env" and body.strip().startswith("{"):
                title = "Exposed actuator environment endpoint"
                evidence = {"path": path, "content_type": response.headers.get("content-type", "")}
            if evidence:
                results.append(
                    Finding(
                        "exposed_sensitive_path",
                        title,
                        "high",
                        "high",
                        evidence,
                        REMEDIATION["exposed_sensitive_path"],
                    )
                )
    return results


def _emit_finding(ingestor: Ingestor, scan_id: str, host: str, finding: Finding) -> str | None:
    payload = {
        "schema_version": "1.0",
        "occurred_at": iso(utcnow()),
        "source_module": "websec",
        "event_type": "websec.finding",
        "source_ip": None,
        "session_id": f"scan:{scan_id}",
        "target_id": host[:200],
        "severity": finding.severity,
        "provenance": {
            "collector": "websec-assessor",
            "source": "threatpolish-websec",
            "reliability": 0.9,
            "synthetic": False,
            "external_refs": [f"scan:{scan_id}"],
        },
        "features": {
            "check_id": finding.check_id,
            "title": finding.title,
            "confidence": finding.confidence,
            "evidence_digest": hashlib.sha256(
                json.dumps(finding.evidence, sort_keys=True).encode("utf-8")
            ).hexdigest()[:16],
        },
        "raw": {},
    }
    return ingestor.submit(_as_event(payload), actor="sensor:websec")


def _as_event(payload: dict[str, Any]) -> Any:
    from ..schemas.event import EventIn

    return EventIn.model_validate(payload)


def list_findings(*, limit: int = 100, severity: str | None = None, target: str | None = None) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: dict[str, Any] = {"limit": limit}
    if severity:
        clauses.append("severity = :severity")
        params["severity"] = severity
    if target:
        clauses.append("target = :target")
        params["target"] = target
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with connection() as conn:
        rows = conn.execute(
            text(
                "SELECT id, ts, scan_id, target, check_id, title, severity, confidence, "
                f"evidence, remediation, status FROM findings {where} "
                "ORDER BY ts DESC LIMIT :limit"
            ),
            params,
        ).fetchall()
    return [
        {
            "id": row[0],
            "ts": row[1],
            "scan_id": row[2],
            "target": row[3],
            "check_id": row[4],
            "title": row[5],
            "severity": row[6],
            "confidence": row[7],
            "evidence": loads(row[8], {}),
            "remediation": row[9],
            "status": row[10],
        }
        for row in rows
    ]


def list_scans(limit: int = 50) -> list[dict[str, Any]]:
    with connection() as conn:
        rows = conn.execute(select(scans).order_by(scans.c.started_at.desc()).limit(limit)).fetchall()
    return [dict(row._mapping) for row in rows]


def get_scan(scan_id: str) -> dict[str, Any]:
    with connection() as conn:
        row = conn.execute(select(scans).where(scans.c.id == scan_id)).fetchone()
    if not row:
        raise NotFound("scan not found")
    return dict(row._mapping)
