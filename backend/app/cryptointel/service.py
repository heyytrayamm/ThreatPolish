"""Digital-asset risk intelligence service."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy import select, text

from ..core.config import get_settings
from ..core.errors import NotFound
from ..core.logging import get_logger
from ..core.security import iso, new_id, utcnow
from ..db.database import connection, dumps, loads, query_one
from ..db.schema import crypto_risk, crypto_snapshots
from ..schemas.event import EventIn
from ..telemetry.ingest import Ingestor
from .providers import Observation, get_provider, normalize_symbols
from .scoring import score_observation

log = get_logger(__name__)
DEFAULT_SYMBOLS = ["BTC", "ETH", "SOL", "USDT"]


def refresh(*, symbols: list[str] | None = None, actor: str = "system") -> dict[str, Any]:
    settings = get_settings()
    requested = normalize_symbols(symbols or DEFAULT_SYMBOLS)
    provider = get_provider(settings)
    cutoff = utcnow() - timedelta(seconds=settings.crypto_min_refresh_seconds)

    skipped: list[dict[str, Any]] = []
    due: list[str] = []
    with connection() as conn:
        for symbol in requested:
            row = query_one(
                conn,
                "SELECT fetched_at FROM crypto_snapshots WHERE asset_symbol = :symbol "
                "ORDER BY fetched_at DESC LIMIT 1",
                {"symbol": symbol},
            )
            if row and row["fetched_at"] > iso(cutoff):
                skipped.append(
                    {
                        "symbol": symbol,
                        "reason": "refreshed within the minimum interval",
                        "last_fetched_at": row["fetched_at"],
                    }
                )
            else:
                due.append(symbol)

    if not due:
        return {
            "provider": provider.name,
            "refreshed": [],
            "skipped": skipped,
            "events": [],
            "note": "no provider call was necessary",
        }

    observations = provider.fetch(due)
    ingestor = Ingestor(settings)
    refreshed: list[dict[str, Any]] = []
    event_ids: list[str] = []

    for observation in observations:
        snapshot_id = new_id("snap")
        scored = score_observation(observation)
        risk_id = new_id("crk")
        with connection() as conn:
            conn.execute(
                crypto_snapshots.insert().values(
                    id=snapshot_id,
                    asset_symbol=observation.symbol,
                    provider_asset_id=observation.provider_asset_id,
                    fetched_at=iso(observation.fetched_at),
                    source=observation.source,
                    price_usd=observation.price_usd,
                    change_24h_pct=observation.change_24h_pct,
                    change_7d_pct=observation.change_7d_pct,
                    market_cap_usd=observation.market_cap_usd,
                    volume_24h_usd=observation.volume_24h_usd,
                    stale=1 if observation.stale else 0,
                    raw_digest=observation.raw_digest,
                    details=dumps(observation.details),
                )
            )
            conn.execute(
                crypto_risk.insert().values(
                    id=risk_id,
                    asset_symbol=observation.symbol,
                    computed_at=iso(utcnow()),
                    score=scored["score"],
                    severity=scored["severity"],
                    confidence=scored["confidence"],
                    reasons=dumps(scored["reasons"]),
                    data_freshness_seconds=scored["data_freshness_seconds"],
                    snapshot_id=snapshot_id,
                    algorithm_version=scored["algorithm_version"],
                )
            )

        event_id = ingestor.submit(
            _build_event(observation, scored, snapshot_id, actor), actor=actor
        )
        if event_id:
            event_ids.append(event_id)
        refreshed.append(
            {
                "symbol": observation.symbol,
                "snapshot_id": snapshot_id,
                "risk": scored,
                "event_id": event_id,
            }
        )

    log.info(
        "crypto observations refreshed",
        extra={
            "provider": provider.name,
            "symbols": [item["symbol"] for item in refreshed],
            "actor": actor,
        },
    )
    return {
        "provider": provider.name,
        "refreshed": refreshed,
        "skipped": skipped,
        "events": event_ids,
        "synthetic": provider.name == "fixture",
        "note": (
            "Observed market facts are separated from the inferred risk score. "
            "Fixture data is for tests and offline demonstrations only."
        ),
    }


def _build_event(
    observation: Observation, scored: dict[str, Any], snapshot_id: str, actor: str
) -> EventIn:
    indicator = scored["reasons"][0]["code"] if scored["reasons"] else "asset_risk"
    return EventIn.model_validate(
        {
            "schema_version": "1.0",
            "occurred_at": iso(utcnow()),
            "source_module": "cryptointel",
            "event_type": "cryptointel.risk_observation",
            "source_ip": None,
            "session_id": f"crypto:{observation.symbol}",
            "target_id": observation.symbol,
            "severity": scored["event_severity"],
            "provenance": {
                "collector": "cryptointel",
                "source": observation.source,
                "reliability": 0.5 if observation.source == "fixture" else 0.8,
                "synthetic": observation.source == "fixture",
                "external_refs": [f"snapshot:{snapshot_id}"],
            },
            "features": {
                "asset_symbol": observation.symbol,
                "indicator": indicator,
                "score": scored["score"],
                "confidence": scored["confidence"],
                "provider": observation.source,
            },
            "raw": {},
        }
    )


def latest_assets() -> list[dict[str, Any]]:
    with connection() as conn:
        snapshots = conn.execute(
            text(
                "SELECT s.* FROM crypto_snapshots s WHERE s.fetched_at = "
                "(SELECT MAX(fetched_at) FROM crypto_snapshots WHERE asset_symbol = s.asset_symbol) "
                "ORDER BY s.asset_symbol"
            )
        ).fetchall()
        risks = conn.execute(
            text(
                "SELECT r.* FROM crypto_risk r WHERE r.computed_at = "
                "(SELECT MAX(computed_at) FROM crypto_risk WHERE asset_symbol = r.asset_symbol) "
                "ORDER BY r.asset_symbol"
            )
        ).fetchall()

    risk_by_symbol = {row[1]: row for row in risks}
    result = []
    for row in snapshots:
        snapshot = {
            "id": row[0],
            "symbol": row[1],
            "provider_asset_id": row[2],
            "fetched_at": row[3],
            "source": row[4],
            "price_usd": row[5],
            "change_24h_pct": row[6],
            "change_7d_pct": row[7],
            "market_cap_usd": row[8],
            "volume_24h_usd": row[9],
            "stale": bool(row[10]),
            "raw_digest": row[11],
            "details": loads(row[12], {}),
        }
        risk_row = risk_by_symbol.get(snapshot["symbol"])
        risk = None
        if risk_row:
            risk = {
                "score": risk_row[3],
                "severity": risk_row[4],
                "confidence": risk_row[5],
                "reasons": loads(risk_row[6], []),
                "data_freshness_seconds": risk_row[7],
                "algorithm_version": risk_row[9],
            }
        freshness = _freshness_seconds(snapshot["fetched_at"])
        result.append(
            {
                "symbol": snapshot["symbol"],
                "observed": snapshot,
                "inferred": risk,
                "freshness_seconds": freshness,
                "stale": snapshot["stale"] or freshness > 900,
                "provenance": {
                    "provider": snapshot["source"],
                    "fetched_at": snapshot["fetched_at"],
                    "raw_digest": snapshot["raw_digest"],
                    "synthetic": snapshot["source"] == "fixture",
                },
                "disclaimer": (
                    "Observed facts come from the named provider; the risk score is an "
                    "inference, not a fact."
                ),
            }
        )
    result.sort(key=lambda item: (item["inferred"] or {}).get("score", 0), reverse=True)
    return result


def history(symbol: str, *, limit: int = 100) -> dict[str, Any]:
    normalized = normalize_symbols([symbol])[0]
    with connection() as conn:
        exists = conn.execute(
            select(crypto_snapshots.c.id).where(crypto_snapshots.c.asset_symbol == normalized).limit(1)
        ).fetchone()
        if not exists:
            raise NotFound("no observations stored for this asset")
        rows = conn.execute(
            text(
                "SELECT s.id, s.fetched_at, s.price_usd, s.change_24h_pct, s.source, s.stale, "
                "r.score, r.severity, r.confidence FROM crypto_snapshots s "
                "LEFT JOIN crypto_risk r ON r.snapshot_id = s.id "
                "WHERE s.asset_symbol = :symbol ORDER BY s.fetched_at DESC LIMIT :limit"
            ),
            {"symbol": normalized, "limit": max(1, min(500, limit))},
        ).fetchall()
    return {
        "symbol": normalized,
        "points": [
            {
                "snapshot_id": row[0],
                "fetched_at": row[1],
                "price_usd": row[2],
                "change_24h_pct": row[3],
                "source": row[4],
                "stale": bool(row[5]),
                "risk_score": row[6],
                "risk_level": row[7],
                "confidence": row[8],
            }
            for row in rows
        ],
        "algorithm_version": "crypto-risk-1.0.0",
    }


def _freshness_seconds(fetched_at: str) -> int:
    from ..core.security import parse_iso

    return max(0, int((utcnow() - parse_iso(fetched_at)).total_seconds()))
