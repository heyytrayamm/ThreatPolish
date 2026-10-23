"""Explainable digital-asset risk scoring.

Observed facts (price, change, market cap, volume, provider, fetch time) are
kept separate from the inferred risk score.  Every point in the score has a
named reason and the input value that produced it.  Missing data lowers
confidence rather than silently producing a higher or lower score.

This module never accepts, requests or stores wallet addresses, private keys or
seed phrases.
"""

from __future__ import annotations

from typing import Any

from ..core.security import utcnow
from .providers import STABLECOINS, Observation

ALGORITHM_VERSION = "crypto-risk-1.0.0"

SEVERITY_LEVELS = ((85.0, "critical"), (65.0, "high"), (40.0, "medium"), (18.0, "low"), (0.0, "info"))
EVENT_SEVERITY = {"critical": "high", "high": "medium", "medium": "low", "low": "info", "info": "info"}


def score_observation(observation: Observation) -> dict[str, Any]:
    points = 0.0
    reasons: list[dict[str, Any]] = []
    completeness = 0
    fields = [
        observation.price_usd,
        observation.change_24h_pct,
        observation.market_cap_usd,
        observation.volume_24h_usd,
    ]
    completeness = sum(1 for value in fields if value is not None)

    if observation.stale:
        points += 20
        reasons.append(
            {
                "code": "stale_observation",
                "points": 20,
                "detail": "the provider timestamp is older than the freshness threshold",
            }
        )

    change = observation.change_24h_pct
    if change is not None:
        magnitude = abs(change)
        if magnitude >= 15:
            points += 30
            reasons.append(
                {
                    "code": "high_volatility",
                    "points": 30,
                    "detail": f"24h change of {change:.2f}% exceeds the 15% threshold",
                }
            )
        elif magnitude >= 7:
            points += 15
            reasons.append(
                {
                    "code": "elevated_volatility",
                    "points": 15,
                    "detail": f"24h change of {change:.2f}% exceeds the 7% threshold",
                }
            )

    if observation.symbol in STABLECOINS and observation.price_usd is not None:
        deviation = abs(observation.price_usd - 1.0)
        if deviation >= 0.05:
            points += 45
            reasons.append(
                {
                    "code": "stablecoin_depeg",
                    "points": 45,
                    "detail": f"price ${observation.price_usd:.4f} deviates {deviation * 100:.1f}% from the peg",
                }
            )
        elif deviation >= 0.01:
            points += 15
            reasons.append(
                {
                    "code": "stablecoin_peg_pressure",
                    "points": 15,
                    "detail": f"price ${observation.price_usd:.4f} deviates {deviation * 100:.1f}% from the peg",
                }
            )

    if observation.volume_24h_usd and observation.market_cap_usd:
        turnover = observation.volume_24h_usd / observation.market_cap_usd
        if turnover < 0.005:
            points += 20
            reasons.append(
                {
                    "code": "thin_liquidity",
                    "points": 20,
                    "detail": f"24h turnover is {turnover * 100:.2f}% of market capitalisation",
                }
            )
        elif turnover > 0.60:
            points += 10
            reasons.append(
                {
                    "code": "abnormal_turnover",
                    "points": 10,
                    "detail": f"24h turnover is {turnover * 100:.0f}% of market capitalisation",
                }
            )

    score = min(100.0, round(points, 2))
    severity = next(name for threshold, name in SEVERITY_LEVELS if score >= threshold)
    freshness_seconds = max(
        0, int((utcnow() - observation.fetched_at).total_seconds())
    )
    confidence = round(min(1.0, 0.4 + 0.15 * completeness) * (0.7 if observation.stale else 1.0), 3)

    return {
        "asset_symbol": observation.symbol,
        "algorithm_version": ALGORITHM_VERSION,
        "score": score,
        "severity": severity,
        "event_severity": EVENT_SEVERITY[severity],
        "confidence": confidence,
        "reasons": reasons,
        "observed": {
            "price_usd": observation.price_usd,
            "change_24h_pct": observation.change_24h_pct,
            "change_7d_pct": observation.change_7d_pct,
            "market_cap_usd": observation.market_cap_usd,
            "volume_24h_usd": observation.volume_24h_usd,
            "fetched_at": observation.fetched_at.isoformat(),
            "provider": observation.source,
            "provider_asset_id": observation.provider_asset_id,
            "raw_digest": observation.raw_digest,
        },
        "inferred": {
            "risk_score": score,
            "risk_level": severity,
            "reasons": reasons,
        },
        "data_freshness_seconds": freshness_seconds,
        "data_stale": observation.stale,
        "limitations": [
            "Risk is derived from a small set of market observables, not from a full "
            "asset or counterparty assessment.",
            "Missing fields reduce confidence; they are not treated as zero.",
            "The score is not a price prediction or investment advice.",
        ],
    }
