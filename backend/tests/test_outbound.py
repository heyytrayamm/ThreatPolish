"""Outbound fetches must be bounded, redirect-free and still usable.

The market-data provider and the geolocation lookup both leave the deployment.
This module exercises the shared helper against a local probe, so the size and
redirect behaviour is verified without touching the network.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import pytest

from app.auth import geo
from app.core.config import get_settings
from app.core.outbound import MAX_OUTBOUND_JSON_BYTES, OutboundError, get_json

HUGE = 8 * 1024 * 1024
CHUNK = 64 * 1024


class _Probe(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.hits: list[str] = []
        self.lock = threading.Lock()
        # Written before the handler thread starts, so a caller that has already
        # seen the refusal can read the count: the handler records each chunk as
        # it goes and may still be unwinding when the client gives up.
        self.transferred = 0


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args) -> None:
        return

    @property
    def probe(self) -> _Probe:
        return self.server  # type: ignore[return-value]

    def _json(self, payload) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _huge(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(HUGE))
        self.end_headers()
        sent = 0
        try:
            while sent < HUGE:
                self.wfile.write(b"x" * CHUNK)
                sent += CHUNK
                with self.probe.lock:
                    self.probe.transferred = sent
        except (BrokenPipeError, ConnectionResetError):
            pass
        with self.probe.lock:
            self.probe.transferred = sent

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        with self.probe.lock:
            self.probe.hits.append(path)
        if path == "/ok":
            self._json({"bitcoin": {"usd": 64000.0}})
        elif path == "/secret":
            self._json({"reached": True})
        elif path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/secret")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif path.startswith("/huge"):
            self._huge()
        elif path.startswith("/geo/"):
            self._json({"loc": "37.4056,-122.0775"})
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()


@pytest.fixture()
def probe() -> Iterator[tuple[str, _Probe]]:
    server = _Probe(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_valid_json_is_returned(probe: tuple[str, _Probe]) -> None:
    base, _ = probe
    assert get_json(f"{base}/ok", timeout=5.0) == {"bitcoin": {"usd": 64000.0}}


def test_redirect_is_refused_and_not_followed(probe: tuple[str, _Probe]) -> None:
    base, server = probe
    with pytest.raises(OutboundError) as caught:
        get_json(f"{base}/redirect", timeout=5.0)
    assert caught.value.kind == "status"
    assert caught.value.status == 302
    assert "/secret" not in server.hits


def test_oversized_body_is_refused_before_it_is_buffered(probe: tuple[str, _Probe]) -> None:
    base, server = probe
    with pytest.raises(OutboundError) as caught:
        get_json(f"{base}/huge", timeout=5.0)
    assert caught.value.kind == "size"
    # The declared length is refused up front: the probe cannot have written
    # anything close to the body it announced.
    assert server.transferred < MAX_OUTBOUND_JSON_BYTES * 2


def test_geolocation_uses_the_same_bounds(probe: tuple[str, _Probe]) -> None:
    base, server = probe
    geo.clear_cache()
    assert geo.locate("8.8.8.8", url=f"{base}/geo/{{ip}}", timeout=5.0) == (
        37.4056,
        -122.0775,
    )
    assert geo.locate("8.8.4.4", url=f"{base}/redirect", timeout=5.0) is None
    assert "/secret" not in server.hits
    assert geo.locate("1.1.1.1", url=f"{base}/huge", timeout=5.0) is None


def test_market_provider_maps_the_bound_to_an_upstream_error(probe: tuple[str, _Probe]) -> None:
    from app.core.errors import UpstreamFailure
    from app.cryptointel.providers import CoinGeckoProvider

    base, _ = probe
    settings = replace(
        get_settings(),
        crypto_provider="coingecko",
        crypto_api_base=f"{base}/huge",
        crypto_timeout_seconds=5.0,
    )
    provider = CoinGeckoProvider(settings)
    with pytest.raises(UpstreamFailure) as caught:
        provider.fetch(["BTC"])
    assert "size limit" in caught.value.message
