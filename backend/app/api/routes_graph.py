"""Evidence graph, campaign candidates and analyst feedback."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query

from ..auth.rbac import Principal
from ..core.audit import audit_standalone
from ..correlation.engine import correlate, latest_run
from ..correlation.repository import (
    add_feedback,
    feedback_summary,
    get_campaign,
    get_edge,
    graph_view,
    list_campaigns,
)
from ..correlation.scoring import ALGORITHM_VERSION, LINK_CONFIDENCE, MIN_SCORE_TO_STORE
from ..schemas.api import CorrelationRequest, FeedbackRequest
from .deps import require

router = APIRouter(tags=["correlation"])


@router.get("/graph")
def graph(
    hours: int = Query(default=24, ge=1, le=720),
    min_confidence: float = Query(default=0.0, ge=0.0, le=1.0),
    kinds: str | None = Query(default=None, max_length=120),
    principal: Principal = Depends(require("graph:read")),
) -> dict[str, Any]:
    selected = [kind.strip() for kind in kinds.split(",") if kind.strip()] if kinds else None
    allowed = {"session", "ip", "asset", "indicator", "campaign"}
    if selected and not set(selected) <= allowed:
        selected = [kind for kind in selected if kind in allowed]
    return graph_view(hours=hours, min_confidence=min_confidence, kinds=selected)


@router.post("/correlate")
def run_correlation(
    payload: CorrelationRequest | None = None,
    principal: Principal = Depends(require("correlate:run")),
) -> dict[str, Any]:
    result = correlate(
        window_hours=payload.window_hours if payload else None,
        trigger="manual",
        actor=principal.user_id,
    )
    audit_standalone(
        action="correlation.run",
        actor_id=principal.user_id,
        actor_role=principal.role,
        object_type="correlation_run",
        object_id=result["run_id"],
        detail={
            "sessions": result["sessions"],
            "campaigns": result["campaigns"],
            "window_hours": result["window_hours"],
        },
    )
    return result


@router.get("/correlation/latest")
def last_run(principal: Principal = Depends(require("graph:read"))) -> dict[str, Any]:
    return {
        "run": latest_run(),
        "algorithm": {
            "version": ALGORITHM_VERSION,
            "link_confidence": LINK_CONFIDENCE,
            "store_threshold": MIN_SCORE_TO_STORE,
            "families": ["behavior", "targeting", "timing", "identity", "intel", "toolchain"],
            "note": (
                "Confidence is a monotone evidence index, not a calibrated probability "
                "of a shared actor."
            ),
        },
    }


@router.get("/campaigns")
def campaigns(
    status: str | None = Query(default=None, max_length=24),
    include_archived: bool = Query(default=False),
    limit: int = Query(default=50, ge=1, le=200),
    principal: Principal = Depends(require("campaigns:read")),
) -> dict[str, Any]:
    return {
        "items": list_campaigns(
            limit=limit, status=status, include_archived=include_archived
        ),
        "algorithm_version": ALGORITHM_VERSION,
    }


@router.get("/campaigns/{campaign_id}")
def campaign_detail(
    campaign_id: str, principal: Principal = Depends(require("campaigns:read"))
) -> dict[str, Any]:
    return get_campaign(campaign_id)


@router.get("/edges/{edge_id}")
def edge_detail(edge_id: str, principal: Principal = Depends(require("graph:read"))) -> dict[str, Any]:
    return get_edge(edge_id)


@router.post("/feedback", status_code=201)
def submit_feedback(
    payload: FeedbackRequest, principal: Principal = Depends(require("feedback:write"))
) -> dict[str, Any]:
    result = add_feedback(
        actor_id=principal.user_id,
        object_type=payload.object_type,
        object_id=payload.object_id,
        label=payload.label,
        note=payload.note,
    )
    audit_standalone(
        action="analyst.feedback",
        actor_id=principal.user_id,
        actor_role=principal.role,
        object_type=payload.object_type,
        object_id=payload.object_id,
        detail={"label": payload.label},
    )
    return result


@router.get("/feedback")
def feedback_overview(principal: Principal = Depends(require("feedback:write"))) -> dict[str, Any]:
    return feedback_summary()
