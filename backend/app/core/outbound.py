"""Bounded JSON fetches for the calls that leave the deployment.

Two components reach outside the host: the market-data provider and the
optional geolocation lookup.  Both used ``httpx.get(...).json()``, which buffers
whatever the remote sends before parsing it, so a provider, proxy or DNS hijack
could exhaust the process memory with a large or endless body.  This helper
streams the body, stops at a fixed limit, refuses redirects and turns every
failure into one exception type the callers can classify.

The web assessment path has its own richer version in ``websec.scanner``: it has
to re-authorise every redirect hop, which does not apply to a fixed provider URL.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

MAX_OUTBOUND_JSON_BYTES = 1024 * 1024


class OutboundError(RuntimeError):
    """An outbound fetch failed, exceeded its bound or returned unusable JSON."""

    def __init__(self, message: str, *, kind: str, status: int | None = None):
        super().__init__(message)
        self.kind = kind
        self.status = status


def get_json(
    url: str,
    *,
    params: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout: float,
    max_bytes: int = MAX_OUTBOUND_JSON_BYTES,
) -> Any:
    """Fetch one JSON document, reading at most ``max_bytes`` of the body."""
    try:
        with httpx.Client(timeout=timeout, follow_redirects=False, headers=headers) as client:
            with client.stream("GET", url, params=params) as response:
                if response.status_code != 200:
                    raise OutboundError(
                        f"upstream returned HTTP {response.status_code}",
                        kind="status",
                        status=response.status_code,
                    )
                declared = response.headers.get("content-length", "").strip()
                if declared.isdigit() and int(declared) > max_bytes:
                    raise OutboundError(
                        f"upstream response exceeded {max_bytes} bytes", kind="size"
                    )
                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > max_bytes:
                        raise OutboundError(
                            f"upstream response exceeded {max_bytes} bytes", kind="size"
                        )
    except httpx.HTTPError as exc:
        raise OutboundError("upstream request failed", kind="network") from exc

    try:
        return json.loads(bytes(body))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise OutboundError("upstream returned invalid JSON", kind="json") from exc
