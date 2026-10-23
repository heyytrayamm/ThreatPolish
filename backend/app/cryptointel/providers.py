"""Market data adapters.

Only observed facts are stored here: price, change, market capitalisation and
volume, together with the provider, fetch time and a digest of the raw payload.
The provider is replaceable; a fixture provider is used by tests and never
masquerades as live data.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

import httpx

from ..core.config import Settings, get_settings
from ..core.errors import UpstreamFailure, ValidationFailure
from ..core.security import utcnow

# Documented CoinGecko identifiers for the symbols ThreatPolish tracks by default.
COINGECKO_IDS = {
    "BTC": "bitcoin",
    "ETH": "ethereum",
    "SOL": "solana",
    "USDT": "tether",
    "USDC": "usd-coin",
    "XRP": "ripple",
    "ADA": "cardano",
    "DOGE": "dogecoin",
    "LINK": "chainlink",
    "AVAX": "avalanche-2",
}
STABLECOINS = {"USDT", "USDC", "DAI", "TUSD", "FDUSD", "USDP"}

MAX_STALENESS_SECONDS = 900


@dataclass
class Observation:
    symbol: str
    provider_asset_id: str
    fetched_at: datetime
    source: str
    price_usd: float | None
    change_24h_pct: float | None
    change_7d_pct: float | None
    market_cap_usd: float | None
    volume_24h_usd: float | None
    stale: bool
    raw_digest: str
    details: dict[str, Any] = field(default_factory=dict)


class MarketProvider(Protocol):
    name: str

    def fetch(self, symbols: list[str]) -> list[Observation]: ...


def normalize_symbols(symbols: list[str]) -> list[str]:
    cleaned = sorted({str(symbol).strip().upper() for symbol in symbols if str(symbol).strip()})
    if not cleaned:
        raise ValidationFailure("at least one asset symbol is required")
    if len(cleaned) > 10:
        raise ValidationFailure("at most 10 asset symbols may be refreshed at once")
    unknown = [symbol for symbol in cleaned if symbol not in COINGECKO_IDS]
    if unknown:
        raise ValidationFailure(
            "unsupported asset symbols", details={"unsupported": unknown, "supported": sorted(COINGECKO_IDS)}
        )
    return cleaned


class CoinGeckoProvider:
    name = "coingecko"

    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()

    def fetch(self, symbols: list[str]) -> list[Observation]:
        ids = [COINGECKO_IDS[symbol] for symbol in symbols]
        url = f"{self.settings.crypto_api_base}/simple/price"
        params = {
            "ids": ",".join(ids),
            "vs_currencies": "usd",
            "include_24hr_change": "true",
            "include_market_cap": "true",
            "include_24hr_vol": "true",
            "include_last_updated_at": "true",
        }
        try:
            response = httpx.get(
                url,
                params=params,
                timeout=self.settings.crypto_timeout_seconds,
                headers={"Accept": "application/json", "User-Agent": "ThreatPolish/1.0"},
            )
        except httpx.HTTPError as exc:
            raise UpstreamFailure(
                "market data provider could not be reached", details={"provider": self.name}
            ) from exc
        if response.status_code != 200:
            raise UpstreamFailure(
                "market data provider returned an error",
                details={"provider": self.name, "status": response.status_code},
            )
        try:
            payload = response.json()
        except ValueError as exc:
            raise UpstreamFailure("market data provider returned invalid JSON") from exc
        if not isinstance(payload, dict):
            raise UpstreamFailure("market data provider returned an unexpected shape")

        observations: list[Observation] = []
        now = utcnow()
        for symbol in symbols:
            provider_id = COINGECKO_IDS[symbol]
            entry = payload.get(provider_id)
            if not isinstance(entry, dict) or "usd" not in entry:
                continue
            last_updated = entry.get("last_updated_at")
            fetched_at = now
            stale = False
            if isinstance(last_updated, (int, float)):
                provider_time = datetime.fromtimestamp(last_updated, tz=timezone.utc)
                stale = (now - provider_time).total_seconds() > MAX_STALENESS_SECONDS
                fetched_at = provider_time
            digest = hashlib.sha256(
                json.dumps(entry, sort_keys=True).encode("utf-8")
            ).hexdigest()
            observations.append(
                Observation(
                    symbol=symbol,
                    provider_asset_id=provider_id,
                    fetched_at=fetched_at,
                    source=self.name,
                    price_usd=_number(entry.get("usd")),
                    change_24h_pct=_number(entry.get("usd_24h_change")),
                    change_7d_pct=None,
                    market_cap_usd=_number(entry.get("usd_market_cap")),
                    volume_24h_usd=_number(entry.get("usd_24h_vol")),
                    stale=stale,
                    raw_digest=digest,
                    details={"last_updated_at": last_updated, "fetched_at": now.isoformat()},
                )
            )
        if not observations:
            raise UpstreamFailure(
                "market data provider returned no usable observations",
                details={"provider": self.name},
            )
        return observations


class FixtureProvider:
    """Deterministic local provider for tests and offline demonstrations.

    Every observation it returns is marked ``synthetic`` so it can never be
    mistaken for a live market observation.
    """

    name = "fixture"

    VALUES = {
        "BTC": (64000.0, 3.2, 1.26e12, 3.4e10),
        "ETH": (3200.0, -4.1, 3.8e11, 1.6e10),
        "SOL": (150.0, 18.5, 6.8e10, 4.2e9),
        "USDT": (0.87, -0.4, 1.1e11, 5.1e10),
        "USDC": (1.0, 0.01, 3.4e10, 6.0e9),
        "XRP": (0.52, 1.1, 2.9e10, 9.0e8),
        "ADA": (0.44, -2.0, 1.5e10, 3.0e8),
        "DOGE": (0.12, 5.5, 1.7e10, 8.0e8),
        "LINK": (14.2, 0.4, 8.0e9, 3.5e8),
        "AVAX": (27.5, -6.4, 1.0e10, 2.9e8),
    }

    def fetch(self, symbols: list[str]) -> list[Observation]:
        now = utcnow()
        observations = []
        for symbol in symbols:
            price, change, market_cap, volume = self.VALUES.get(symbol, (1.0, 0.0, 0.0, 0.0))
            raw = {"symbol": symbol, "price": price, "change": change, "synthetic": True}
            observations.append(
                Observation(
                    symbol=symbol,
                    provider_asset_id=COINGECKO_IDS.get(symbol, symbol.lower()),
                    fetched_at=now,
                    source=self.name,
                    price_usd=price,
                    change_24h_pct=change,
                    change_7d_pct=None,
                    market_cap_usd=market_cap,
                    volume_24h_usd=volume,
                    stale=False,
                    raw_digest=hashlib.sha256(
                        json.dumps(raw, sort_keys=True).encode("utf-8")
                    ).hexdigest(),
                    details={"synthetic": True, "provider": "fixture"},
                )
            )
        return observations


def get_provider(settings: Settings | None = None) -> MarketProvider:
    settings = settings or get_settings()
    if settings.crypto_provider == "fixture":
        return FixtureProvider()
    if settings.crypto_provider == "coingecko":
        return CoinGeckoProvider(settings)
    raise ValidationFailure(
        f"unknown market data provider '{settings.crypto_provider}'",
        details={"supported": ["coingecko", "fixture"]},
    )


def _number(value: Any) -> float | None:
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    # A provider (or a proxy in front of it) can return ``NaN``/``Infinity``,
    # which Python's JSON parser accepts.  They cannot be stored or served as
    # valid JSON, and comparing against them silently distorts the risk score,
    # so an unusable value is treated as missing data.
    return number if math.isfinite(number) else None
