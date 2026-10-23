"""Crypto and digital-asset risk intelligence API."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query

from ..auth.rbac import Principal
from ..core.audit import audit_standalone
from ..core.config import get_settings
from ..cryptointel.service import history, latest_assets, refresh
from ..schemas.api import CryptoRefreshRequest
from .deps import require

router = APIRouter(tags=["cryptointel"])


@router.get("/crypto/assets")
def assets(principal: Principal = Depends(require("crypto:read"))) -> dict[str, Any]:
    return {
        "items": latest_assets(),
        "provider": get_settings().crypto_provider,
        "note": (
            "Observed facts are sourced and timestamped; risk scores are inferred and "
            "explained. No wallet addresses, private keys or seed phrases are stored."
        ),
    }


@router.post("/crypto/refresh")
def refresh_assets(
    payload: CryptoRefreshRequest | None = None,
    principal: Principal = Depends(require("crypto:refresh")),
) -> dict[str, Any]:
    symbols = payload.symbols if payload and payload.symbols else None
    result = refresh(symbols=symbols, actor=principal.user_id)
    audit_standalone(
        action="crypto.refresh",
        actor_id=principal.user_id,
        actor_role=principal.role,
        object_type="crypto_snapshot",
        detail={
            "provider": result["provider"],
            "symbols": [item["symbol"] for item in result.get("refreshed", [])],
            "skipped": [item["symbol"] for item in result.get("skipped", [])],
        },
    )
    return result


@router.get("/crypto/assets/{symbol}/history")
def asset_history(
    symbol: str,
    limit: int = Query(default=100, ge=1, le=500),
    principal: Principal = Depends(require("crypto:read")),
) -> dict[str, Any]:
    return history(symbol, limit=limit)


@router.get("/crypto/providers")
def providers(principal: Principal = Depends(require("crypto:read"))) -> dict[str, Any]:
    settings = get_settings()
    return {
        "active": settings.crypto_provider,
        "supported": [
            {
                "name": "coingecko",
                "kind": "public market data",
                "notes": "Requires outbound HTTPS to api.coingecko.com; subject to provider rate limits.",
            },
            {
                "name": "fixture",
                "kind": "deterministic test fixture",
                "notes": "Synthetic values, clearly labelled; never used in production configuration.",
            },
        ],
        "freshness_threshold_seconds": 900,
        "minimum_refresh_seconds": settings.crypto_min_refresh_seconds,
        "restrictions": [
            "No wallet addresses, private keys or seed phrases are accepted or stored.",
            "Provider outages surface as upstream errors; stale snapshots are labelled, not silently reused.",
        ],
    }
