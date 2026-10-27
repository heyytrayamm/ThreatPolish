"""Coarse IP location for sign-in distance checks.

No geolocation data ships with the platform, and sending an analyst's address to
a third party is a decision the operator has to make deliberately.  This module
therefore does nothing unless `TP_GEO_API_URL` is configured.  The endpoint is
templated with `{ip}`; the response may use either ipinfo's `loc` field
("lat,lon") or `latitude` / `longitude`.  Failures are never fatal: an address is
simply treated as unlocatable, and the caller falls back to a network-change
signal.

Addresses that cannot be located on the internet (loopback, private, reserved,
multicast, documentation ranges) are never sent anywhere.
"""

from __future__ import annotations

import ipaddress
import math
from typing import Any

from ..core.logging import get_logger
from ..core.outbound import OutboundError, get_json

log = get_logger(__name__)

_CACHE: dict[str, tuple[float, float] | None] = {}
_CACHE_LIMIT = 512

Address = ipaddress.IPv4Address | ipaddress.IPv6Address
Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def parse_address(value: str | None) -> Address | None:
    if not value:
        return None
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        # Test clients and Unix sockets report a name, not an address.
        return None


def is_locatable(address: Address) -> bool:
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        or address in ipaddress.ip_network("192.0.2.0/24")
        or address in ipaddress.ip_network("198.51.100.0/24")
        or address in ipaddress.ip_network("203.0.113.0/24")
        or address in ipaddress.ip_network("2001:db8::/32")
    )


def network_of(value: str | None) -> Network | None:
    """Group addresses into operator-sized networks: /24 for v4, /48 for v6."""
    address = parse_address(value)
    if address is None:
        return None
    prefix = 24 if address.version == 4 else 48
    return ipaddress.ip_network(f"{address}/{prefix}", strict=False)


def same_network(left: str | None, right: str | None) -> bool:
    left_network = network_of(left)
    right_network = network_of(right)
    if left_network is None or right_network is None:
        return False
    return left_network == right_network


def locate(
    value: str | None, *, url: str, token: str = "", timeout: float = 3.0
) -> tuple[float, float] | None:
    address = parse_address(value)
    if address is None or not url or not is_locatable(address):
        return None
    key = str(address)
    if key in _CACHE:
        return _CACHE[key]

    template = url.replace("{ip}", key) if "{ip}" in url else f"{url.rstrip('/')}/{key}"
    params = {"token": token} if token else None
    point: tuple[float, float] | None = None
    try:
        point = _point(get_json(template, params=params, timeout=timeout))
    except (OutboundError, ValueError, TypeError) as exc:
        log.warning("geolocation lookup failed", extra={"error": str(exc)})

    if len(_CACHE) >= _CACHE_LIMIT:
        _CACHE.clear()
    _CACHE[key] = point
    return point


def distance_km(left: tuple[float, float], right: tuple[float, float]) -> float:
    """Great-circle distance in kilometres."""
    lat1, lon1 = math.radians(left[0]), math.radians(left[1])
    lat2, lon2 = math.radians(right[0]), math.radians(right[1])
    delta_lat = lat2 - lat1
    delta_lon = lon2 - lon1
    haversine = (
        math.sin(delta_lat / 2) ** 2
        + math.cos(lat1) * math.cos(lat2) * math.sin(delta_lon / 2) ** 2
    )
    return 6371.0 * 2 * math.asin(min(1.0, math.sqrt(haversine)))


def clear_cache() -> None:
    _CACHE.clear()


def _point(data: Any) -> tuple[float, float] | None:
    if not isinstance(data, dict):
        return None
    loc = data.get("loc")
    if isinstance(loc, str) and "," in loc:
        latitude, _, longitude = loc.partition(",")
        return _bounded(latitude, longitude)
    latitude = data.get("latitude", data.get("lat"))
    longitude = data.get("longitude", data.get("lon", data.get("lng")))
    return _bounded(latitude, longitude)


def _bounded(latitude: Any, longitude: Any) -> tuple[float, float] | None:
    try:
        lat = float(latitude)
        lon = float(longitude)
    except (TypeError, ValueError):
        return None
    if not (math.isfinite(lat) and math.isfinite(lon)):
        return None
    if not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0):
        return None
    return lat, lon
