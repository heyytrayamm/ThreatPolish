"""Controlled response API."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query

from ..auth.rbac import Principal
from ..core.audit import audit_standalone
from ..core.errors import NotFound
from ..correlation.repository import get_campaign
from ..response.engine import (
    approve_response,
    create_response,
    disable_all,
    evaluate_policy,
    get_response,
    list_responses,
    policy_document,
    rollback_response,
)
from ..schemas.api import ResponseRequest
from ..risk.scoring import score_risk
from .deps import require

router = APIRouter(tags=["responses"])


@router.get("/responses/policies")
def policies(principal: Principal = Depends(require("responses:read"))) -> dict[str, Any]:
    return policy_document()


@router.get("/responses")
def responses(
    limit: int = Query(default=100, ge=1, le=500),
    status: str | None = Query(default=None, max_length=24),
    principal: Principal = Depends(require("responses:read")),
) -> dict[str, Any]:
    return {"items": list_responses(limit=limit, status=status)}


@router.get("/responses/{response_id}")
def response_detail(
    response_id: str, principal: Principal = Depends(require("responses:read"))
) -> dict[str, Any]:
    return get_response(response_id)


@router.post("/responses", status_code=201)
def request_response(
    payload: ResponseRequest, principal: Principal = Depends(require("responses:request"))
) -> dict[str, Any]:
    severity = payload.severity
    risk_level = payload.risk_level
    risk_score = payload.risk_score
    confidence = payload.confidence
    target = payload.target

    if payload.campaign_id:
        try:
            campaign = get_campaign(payload.campaign_id)
        except NotFound:
            campaign = None
        if campaign:
            explanation = campaign["explanation"]
            severity = explanation["severity"]
            risk_level = explanation["risk"]["risk_level"]
            risk_score = explanation["risk"]["risk_score"]
            confidence = max(confidence, float(campaign["campaign"]["confidence"]))
            target = target or (campaign["ips"][0] if campaign["ips"] else target)

    if risk_score == 0.0 and confidence > 0:
        risk_score = score_risk(
            severity=severity, confidence=confidence, asset_criticality="medium"
        )["risk_score"]

    record = create_response(
        action=payload.action,
        target=target,
        actor=principal.user_id,
        role=principal.role,
        campaign_id=payload.campaign_id,
        confidence=confidence,
        reason=payload.reason,
        severity=severity,
        risk_level=risk_level,
        risk_score=risk_score,
        ttl_minutes=payload.ttl_minutes,
    )
    audit_standalone(
        action="response.request",
        actor_id=principal.user_id,
        actor_role=principal.role,
        object_type="response",
        object_id=record["id"],
        detail={
            "action": record["action"],
            "target": record["target"],
            "status": record["status"],
            "policy_id": record["policy_id"],
        },
    )
    return record


@router.post("/responses/{response_id}/approve")
def approve(
    response_id: str, principal: Principal = Depends(require("responses:approve"))
) -> dict[str, Any]:
    record = approve_response(response_id, actor=principal.user_id)
    audit_standalone(
        action="response.approve",
        actor_id=principal.user_id,
        actor_role=principal.role,
        object_type="response",
        object_id=response_id,
        detail={"action": record["action"], "target": record["target"], "status": record["status"]},
    )
    return record


@router.post("/responses/{response_id}/rollback")
def rollback(
    response_id: str, principal: Principal = Depends(require("responses:approve"))
) -> dict[str, Any]:
    record = rollback_response(response_id, actor=principal.user_id)
    audit_standalone(
        action="response.rollback",
        actor_id=principal.user_id,
        actor_role=principal.role,
        object_type="response",
        object_id=response_id,
        detail={"target": record["target"], "status": record["status"]},
    )
    return record


@router.post("/responses/emergency-disable")
def emergency_disable(principal: Principal = Depends(require("responses:approve"))) -> dict[str, Any]:
    count = disable_all(actor=principal.user_id)
    audit_standalone(
        action="response.emergency_disable",
        actor_id=principal.user_id,
        actor_role=principal.role,
        object_type="response",
        detail={"rolled_back": count},
    )
    return {"status": "disabled", "rolled_back": count}


@router.post("/responses/evaluate")
def evaluate(
    payload: ResponseRequest, principal: Principal = Depends(require("responses:read"))
) -> dict[str, Any]:
    decision = evaluate_policy(
        severity=payload.severity,
        confidence=payload.confidence,
        risk_level=payload.risk_level,
        risk_score=payload.risk_score,
    )
    return {
        "decision": decision,
        "requested_action_permitted": payload.action in decision["permitted_actions"],
    }
