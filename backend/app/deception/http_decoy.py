"""HTTP/API decoy service.

Design constraints:

* It serves only a fixed set of decoy pages and a synthetic 404.  There is no
  file serving, proxying, templating engine or command execution.
* Request bodies are bounded and only a bounded digest of a submitted password
  is retained.
* Every interaction becomes a telemetry event.  If the pipeline is unavailable,
  the event is written to a local spool file instead of being dropped.
* It never initiates outbound connections.
"""

from __future__ import annotations

import hashlib
import html
import json
import secrets
import threading
from datetime import datetime, timezone
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from ..core.config import Settings, get_settings
from ..core.limits import SlidingWindowLimiter
from ..core.logging import get_logger
from ..core.security import iso, utcnow
from ..db.database import init_db
from ..telemetry.ingest import Ingestor
from ..telemetry.normalize import normalize_path_template
from .adaptive import active_override
from .profiles import default_http_profile, get_profile

log = get_logger(__name__)

MAX_BODY_BYTES = 8192
SESSION_COOKIE = "tp_sid"
SAFE_METHODS = {"GET", "HEAD", "POST"}


class DecoyHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], decoy: "DecoyService") -> None:
        self.decoy = decoy
        super().__init__(address, DecoyHandler)


class DecoyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "nginx"
    sys_version = ""

    @property
    def decoy(self) -> "DecoyService":
        return self.server.decoy  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:
        log.debug("decoy request", extra={"detail": fmt % args})

    # ------------------------------------------------------------------ #
    def do_GET(self) -> None:
        self._handle("GET")

    def do_HEAD(self) -> None:
        self._handle("HEAD")

    def do_POST(self) -> None:
        self._handle("POST")

    def do_PUT(self) -> None:
        self._reject_method()

    def do_DELETE(self) -> None:
        self._reject_method()

    def do_PATCH(self) -> None:
        self._reject_method()

    # ------------------------------------------------------------------ #
    def _reject_method(self) -> None:
        self._respond(
            HTTPStatus.METHOD_NOT_ALLOWED,
            "Method Not Allowed",
            "text/plain",
            close=True,
        )

    def _handle(self, method: str) -> None:
        if method not in SAFE_METHODS:
            self._reject_method()
            return

        client_ip = self.client_address[0]
        allowed, retry_after = self.decoy.limiter.allow(client_ip)
        if not allowed:
            if self.decoy.limiter_throttled(client_ip):
                self._emit(
                    method=method,
                    path=self.path,
                    status=429,
                    user_agent=self.headers.get("User-Agent", ""),
                    session_id="throttled",
                    severity="low",
                    extra={"throttled": True},
                )
            # Any unread request body would be parsed as the next request on
            # this keep-alive socket, so close instead of reusing it.
            self.close_connection = True
            self.send_response(HTTPStatus.TOO_MANY_REQUESTS)
            self.send_header("Retry-After", str(int(retry_after) + 1))
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            return

        self._current_profile = self.decoy.profile
        self._investigation_id: str | None = None
        override = active_override(client_ip)
        if override:
            candidate = get_profile(override.get("profile", ""))
            if candidate and candidate["enabled"] and candidate["kind"] == "http":
                self._current_profile = candidate
                self._investigation_id = override.get("investigation_id")

        parsed = urlparse(self.path)
        raw_path = parsed.path or "/"
        if "\x00" in raw_path or ".." in raw_path:
            self._respond(HTTPStatus.BAD_REQUEST, "Bad Request", "text/plain", close=True)
            return

        # Reject ambiguous message framing.  A request that declares both a
        # Transfer-Encoding and a Content-Length (or two different lengths) can
        # be interpreted differently by a proxy and by this server, which is
        # the classic request-smuggling setup.  There is no legitimate client
        # for the decoy that needs chunked uploads.
        lengths = self.headers.get_all("Content-Length") or []
        if self.headers.get("Transfer-Encoding") or len(lengths) > 1:
            self._respond(HTTPStatus.BAD_REQUEST, "Bad Request", "text/plain", close=True)
            return
        try:
            length = int(lengths[0]) if lengths else 0
        except (TypeError, ValueError):
            self._respond(HTTPStatus.BAD_REQUEST, "Bad Request", "text/plain", close=True)
            return
        if length < 0:
            self._respond(HTTPStatus.BAD_REQUEST, "Bad Request", "text/plain", close=True)
            return

        session_id, cookie_needed = self._session()
        body = b""
        if method != "POST":
            if length:
                # The body is deliberately not read; the connection must not be
                # reused, otherwise the unread bytes become the next request.
                self.close_connection = True
        else:
            if length > MAX_BODY_BYTES:
                self._respond(
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                    "Payload Too Large",
                    "text/plain",
                    close=True,
                )
                return
            body = self.rfile.read(length) if length > 0 else b""

        status, content, content_type, severity, extra = self._route(
            method, raw_path, body, session_id
        )

        # Use the profile that actually routed the request: an active
        # investigation can override it, and the credential path belongs to the
        # active profile, not to the default one.
        login_path = self._current_profile["config"].get("login_path", "/login")
        if method == "POST" and path_matches(raw_path, login_path):
            self._emit_credentials(body, session_id, raw_path)

        self._emit(
            method=method,
            path=raw_path,
            status=status,
            user_agent=self.headers.get("User-Agent", ""),
            session_id=session_id,
            severity=severity,
            extra=extra,
        )
        self._respond(status, content, content_type, cookie_needed=cookie_needed, session_id=session_id)

    def _session(self) -> tuple[str, bool]:
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except Exception:
            cookie = SimpleCookie()
        if SESSION_COOKIE in cookie:
            value = cookie[SESSION_COOKIE].value
            if value and 8 <= len(value) <= 64:
                return value, False
        return secrets.token_hex(16), True

    def _route(
        self, method: str, path: str, body: bytes, session_id: str
    ) -> tuple[int, str, str, str, dict[str, Any]]:
        config = self._current_profile["config"]
        login_path = config.get("login_path", "/login")
        probe_paths = set(config.get("probe_paths", []))

        if method == "POST" and path_matches(path, login_path):
            return (
                HTTPStatus.UNAUTHORIZED,
                _login_page(config, error="Invalid credentials. Please try again."),
                "text/html; charset=utf-8",
                "medium",
                {"login_attempt": True},
            )
        if path_matches(path, login_path) or path in {"/login", "/wp-login.php", "/admin"}:
            return (
                HTTPStatus.OK,
                _login_page(config),
                "text/html; charset=utf-8",
                "low",
                {"probe": True},
            )
        if path in probe_paths:
            return (
                HTTPStatus.OK,
                _decoy_asset(path, config),
                "text/plain; charset=utf-8",
                "medium",
                {"sensitive_probe": True},
            )
        if path in {"/", "/index.html"}:
            return (HTTPStatus.OK, _landing_page(config), "text/html; charset=utf-8", "info", {})
        if path == "/robots.txt":
            return (
                HTTPStatus.OK,
                "User-agent: *\nDisallow: /admin\nDisallow: /backup\n",
                "text/plain; charset=utf-8",
                "info",
                {},
            )
        return (HTTPStatus.NOT_FOUND, _not_found(config), "text/html; charset=utf-8", "info", {})

    def _respond(
        self,
        status: int,
        content: str,
        content_type: str,
        *,
        cookie_needed: bool = False,
        session_id: str | None = None,
        close: bool = False,
    ) -> None:
        encoded = content.encode("utf-8", "replace")
        if close:
            self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        if close:
            self.send_header("Connection", "close")
        if cookie_needed and session_id:
            self.send_header(
                "Set-Cookie", f"{SESSION_COOKIE}={session_id}; Path=/; HttpOnly; SameSite=Lax"
            )
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(encoded)

    def _emit(
        self,
        *,
        method: str,
        path: str,
        status: int,
        user_agent: str,
        session_id: str,
        severity: str,
        extra: dict[str, Any],
    ) -> None:
        payload = {
            "schema_version": "1.0",
            "occurred_at": iso(utcnow()),
            "source_module": "honeypot",
            "event_type": "honeypot.http.request",
            "source_ip": self.client_address[0],
            "session_id": f"decoy:{session_id}",
            "target_id": f"http-decoy:{self._current_profile['name']}",
            "severity": severity,
            "provenance": {
                "collector": "http-decoy",
                "source": "http-decoy",
                "reliability": 0.85,
                "synthetic": False,
            },
            "features": {
                "method": method,
                "path": path[:500],
                "path_template": normalize_path_template(path),
                "status": status,
                "user_agent": user_agent[:300],
                "profile": self._current_profile["name"],
                **extra,
            },
            "raw": {"host_header": (self.headers.get("Host") or "")[:255]},
        }
        if self._investigation_id:
            payload["features"]["investigation_id"] = self._investigation_id
        self.decoy.emit(payload)

    def _emit_credentials(self, body: bytes, session_id: str, path: str) -> None:
        text_body = body.decode("utf-8", "replace")[:MAX_BODY_BYTES]
        username = ""
        password = ""
        try:
            if text_body.strip().startswith("{"):
                parsed = json.loads(text_body)
                if isinstance(parsed, dict):
                    username = str(parsed.get("username") or parsed.get("email") or "")
                    password = str(parsed.get("password") or "")
            else:
                fields = parse_qs(text_body)
                username = (fields.get("username") or fields.get("log") or fields.get("email") or [""])[0]
                password = (fields.get("password") or fields.get("pwd") or [""])[0]
        except (ValueError, TypeError):
            return
        digest = hashlib.sha256(password.encode("utf-8", "replace")).hexdigest()[:16]
        payload = {
            "schema_version": "1.0",
            "occurred_at": iso(utcnow()),
            "source_module": "honeypot",
            "event_type": "honeypot.http.credential_attempt",
            "source_ip": self.client_address[0],
            "session_id": f"decoy:{session_id}",
            "target_id": f"http-decoy:{self._current_profile['name']}",
            "severity": "medium",
            "provenance": {
                "collector": "http-decoy",
                "source": "http-decoy",
                "reliability": 0.9,
                "synthetic": False,
            },
            "features": {
                "username": username[:64],
                "password_sha256_prefix": digest,
                "password_length": len(password),
                "path": path[:200],
                "success": False,
            },
            "raw": {},
        }
        if self._investigation_id:
            payload["features"]["investigation_id"] = self._investigation_id
        self.decoy.emit(payload)


def path_matches(path: str, configured: str) -> bool:
    return path.rstrip("/") == configured.rstrip("/")


def _login_page(config: dict[str, Any], error: str | None = None) -> str:
    title = html.escape(str(config.get("title", "Sign In")))
    action = html.escape(str(config.get("login_path", "/login")))
    notice = f'<p class="error">{html.escape(error)}</p>' if error else ""
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>{title}</title>
<style>body{{font-family:system-ui,sans-serif;background:#f6f7f9;display:flex;justify-content:center;padding-top:12vh}}
.card{{background:#fff;border:1px solid #dcdcde;padding:32px;width:340px;border-radius:6px}}
input{{width:100%;padding:9px;margin:6px 0 14px;border:1px solid #c3c4c7;box-sizing:border-box}}
button{{width:100%;padding:10px;background:#2271b1;color:#fff;border:0;border-radius:3px}}
.error{{color:#b32d2e}}</style></head>
<body><div class="card"><h2>{title}</h2>{notice}
<form method="post" action="{action}">
<label for="username">Username or Email</label>
<input id="username" name="username" autocomplete="username">
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="current-password">
<button type="submit">Log In</button>
</form></div></body></html>"""


def _landing_page(config: dict[str, Any]) -> str:
    title = html.escape(str(config.get("title", "Service")))
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>{title}</title></head>
<body><h1>{title}</h1><p>This service is for authorized operators.</p>
<p><a href="/login">Sign in</a></p></body></html>"""


def _not_found(config: dict[str, Any]) -> str:
    server = html.escape(str(config.get("server", "nginx")))
    return f"""<html><head><title>404 Not Found</title></head>
<body><h1>Not Found</h1><p>The requested resource was not found on this server.</p>
<hr><address>{server}</address></body></html>"""


def _decoy_asset(path: str, config: dict[str, Any]) -> str:
    """Return plausible but non-functional decoy content for probed paths."""
    hostname = str(config.get("hostname", "app-internal-01"))
    if path in {"/.env", "/wp-config.php.bak"}:
        return (
            "APP_ENV=production\n"
            f"APP_HOST={hostname}\n"
            "DB_HOST=db.internal\nDB_NAME=app\nDB_USER=app_ro\n"
            "DB_PASSWORD=revoked-placeholder-value\n"
            "AWS_ACCESS_KEY_ID=AKIADECOY0000000000\n"
            "AWS_SECRET_ACCESS_KEY=decoy-value-not-a-credential\n"
        )
    if path == "/.git/HEAD":
        return "ref: refs/heads/main\n"
    if path in {"/metrics", "/actuator/env"}:
        return "# HELP http_requests_total Total HTTP requests\nhttp_requests_total{status=\"200\"} 1841\n"
    if path == "/server-status":
        return f"Server Version: {config.get('server', 'Apache')}\nCurrent Time: {datetime.now(timezone.utc)}\n"
    if path == "/api/v1/health":
        return json.dumps({"status": "ok", "service": hostname, "version": "3.4.1"})
    if path == "/api/v1/users":
        return json.dumps({"users": [{"id": 1, "name": "operator", "role": "admin"}]})
    return f"<!-- {hostname} -->\naccess denied\n"


class DecoyService:
    def __init__(self, *, profile: dict[str, Any], settings: Settings, ingestor: Ingestor | None = None):
        self.profile = profile
        self.settings = settings
        self.ingestor = ingestor or Ingestor(settings)
        self.limiter = SlidingWindowLimiter(max(60, settings.decoy_max_sessions_per_hour), 60.0)
        self._throttled: set[str] = set()
        self._throttle_lock = threading.Lock()
        self.spool_path = settings.data_dir / "decoy-spool.jsonl"
        self.httpd: DecoyHTTPServer | None = None
        self.thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        return self.httpd.server_address[1] if self.httpd else 0

    def emit(self, payload: dict[str, Any]) -> None:
        try:
            self.ingestor.ingest([payload], actor="sensor:http-decoy")
        except Exception as exc:
            log.error("decoy telemetry spooled after pipeline failure", extra={"error": str(exc)})
            self._spool(payload)

    def _spool(self, payload: dict[str, Any]) -> None:
        try:
            self.spool_path.parent.mkdir(parents=True, exist_ok=True)
            with self.spool_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, default=str) + "\n")
        except OSError as exc:  # pragma: no cover
            log.error("decoy spool write failed", extra={"error": str(exc)})

    def limiter_throttled(self, key: str) -> bool:
        with self._throttle_lock:
            if key in self._throttled:
                return False
            self._throttled.add(key)
            if len(self._throttled) > 10_000:
                self._throttled.clear()
            return True

    def start(self, host: str = "127.0.0.1", port: int | None = None) -> "DecoyService":
        self.httpd = DecoyHTTPServer((host, port if port is not None else self.settings.decoy_port), self)
        self.thread = threading.Thread(
            target=self.httpd.serve_forever, name="tp-http-decoy", daemon=True
        )
        self.thread.start()
        log.info(
            "http decoy listening",
            extra={"host": host, "port": self.port, "profile": self.profile["name"]},
        )
        return self

    def stop(self) -> None:
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
        if self.thread:
            self.thread.join(timeout=5)
        self.httpd = None
        self.thread = None


def start_decoy(
    *, host: str = "127.0.0.1", port: int | None = None, profile_name: str | None = None
) -> DecoyService:
    settings = get_settings()
    init_db()
    profile = get_profile(profile_name) if profile_name else None
    if profile is None:
        profile = default_http_profile()
    service = DecoyService(profile=profile, settings=settings)
    return service.start(host=host, port=port)
