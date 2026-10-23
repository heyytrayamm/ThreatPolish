"""Web security assessment API."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query

from ..auth.rbac import Principal
from ..core.audit import audit_standalone
from ..schemas.api import AssessmentRequest, ScopeCreateRequest
from ..websec.scanner import assess, get_scan, list_findings, list_scans
from ..websec.scope import create_scope, list_scopes
from .deps import require

router = APIRouter(tags=["websec"])


@router.get("/websec/scopes")
def scopes(principal: Principal = Depends(require("scopes:read"))) -> dict[str, Any]:
    return {"items": list_scopes()}


@router.post("/websec/scopes", status_code=201)
def add_scope(
    payload: ScopeCreateRequest, principal: Principal = Depends(require("scopes:manage"))
) -> dict[str, Any]:
    scope = create_scope(
        domain=payload.domain,
        authorized_by=payload.authorized_by,
        expires_in_days=payload.expires_in_days,
        allow_active=payload.allow_active,
        notes=payload.notes,
        actor=principal.user_id,
    )
    audit_standalone(
        action="websec.scope.create",
        actor_id=principal.user_id,
        actor_role=principal.role,
        object_type="watch_scope",
        object_id=scope["id"],
        detail={
            "domain": scope["domain"],
            "authorized_by": scope["authorized_by"],
            "expires_at": scope["expires_at"],
            "allow_active": scope["allow_active"],
        },
    )
    return scope


@router.post("/websec/assess")
def run_assessment(
    payload: AssessmentRequest, principal: Principal = Depends(require("findings:scan"))
) -> dict[str, Any]:
    report = assess(target=payload.target, active_checks=payload.active_checks, actor=principal.user_id)
    audit_standalone(
        action="websec.assess",
        actor_id=principal.user_id,
        actor_role=principal.role,
        object_type="scan",
        object_id=report["scan_id"],
        detail={
            "target": report["target"],
            "findings": report["finding_count"],
            "active_checks": report["active_checks"],
            "status": report["status"],
        },
    )
    return report


@router.get("/websec/findings")
def findings(
    limit: int = Query(default=100, ge=1, le=500),
    severity: str | None = Query(default=None, max_length=16),
    target: str | None = Query(default=None, max_length=255),
    principal: Principal = Depends(require("findings:read")),
) -> dict[str, Any]:
    return {"items": list_findings(limit=limit, severity=severity, target=target)}


@router.get("/websec/scans")
def scans(principal: Principal = Depends(require("findings:read"))) -> dict[str, Any]:
    return {"items": list_scans()}


@router.get("/websec/scans/{scan_id}")
def scan_detail(scan_id: str, principal: Principal = Depends(require("findings:read"))) -> dict[str, Any]:
    return get_scan(scan_id)
