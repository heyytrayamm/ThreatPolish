"""Uncertainty-aware adaptive investigation endpoints."""

from __future__ import annotations

import ipaddress
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from ..auth.rbac import Principal
from ..core.audit import audit_standalone
from ..core.errors import ValidationFailure
from ..deception.adaptive import (
    activate_investigation,
    evaluate_investigation,
    get_investigation,
    list_investigations,
    plan_investigation,
)
from ..schemas.api import InvestigationRequest
from .deps import require

router = APIRouter(tags=["investigations"])


class ActivateRequest(BaseModel):
    source_ip: str
    ttl_minutes: int = Field(default=15, ge=5, le=60)


@router.post("/investigations", status_code=201)
def plan(
    payload: InvestigationRequest, principal: Principal = Depends(require("investigations:write"))
) -> dict[str, Any]:
    result = plan_investigation(
        edge_id=payload.edge_id,
        campaign_id=payload.campaign_id,
        profile_name=payload.profile,
        actor=principal.user_id,
    )
    audit_standalone(
        action="investigation.plan",
        actor_id=principal.user_id,
        actor_role=principal.role,
        object_type="investigation",
        object_id=result["id"],
        detail={
            "edge_id": result["edge_id"],
            "campaign_id": result["campaign_id"],
            "profile": result["profile"],
            "recommended": result["recommended"],
        },
    )
    return result


@router.get("/investigations")
def list_all(
    limit: int = 50, principal: Principal = Depends(require("campaigns:read"))
) -> dict[str, Any]:
    return {"items": list_investigations(limit=max(1, min(200, limit)))}


@router.get("/investigations/{investigation_id}")
def detail(
    investigation_id: str, principal: Principal = Depends(require("campaigns:read"))
) -> dict[str, Any]:
    return get_investigation(investigation_id)


@router.post("/investigations/{investigation_id}/activate")
def activate(
    investigation_id: str,
    payload: ActivateRequest,
    principal: Principal = Depends(require("investigations:write")),
) -> dict[str, Any]:
    try:
        ipaddress.ip_address(payload.source_ip)
    except ValueError as exc:
        raise ValidationFailure("source_ip must be a valid IP address") from exc
    result = activate_investigation(
        investigation_id,
        source_ip=payload.source_ip,
        actor=principal.user_id,
        ttl_minutes=payload.ttl_minutes,
    )
    audit_standalone(
        action="investigation.activate",
        actor_id=principal.user_id,
        actor_role=principal.role,
        object_type="investigation",
        object_id=investigation_id,
        detail={
            "profile": result["profile"],
            "source_ip": result["source_ip"],
            "expires_at": result["expires_at"],
        },
    )
    return result


@router.post("/investigations/{investigation_id}/evaluate")
def evaluate(
    investigation_id: str, principal: Principal = Depends(require("investigations:write"))
) -> dict[str, Any]:
    result = evaluate_investigation(investigation_id, actor=principal.user_id)
    audit_standalone(
        action="investigation.evaluate",
        actor_id=principal.user_id,
        actor_role=principal.role,
        object_type="investigation",
        object_id=investigation_id,
        detail={
            "outcome": result["outcome"],
            "delta": result["delta"],
            "new_events": result["new_events_observed"],
        },
    )
    return result
