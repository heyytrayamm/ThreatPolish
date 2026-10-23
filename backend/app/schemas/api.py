"""Request and response models for the public API."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=1, max_length=256)


class UserCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str
    name: str = Field(min_length=1, max_length=120)
    role: Literal["admin", "analyst", "viewer", "sensor"]
    password: str = Field(min_length=10, max_length=256)


class PasswordChangeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    current_password: str
    new_password: str = Field(min_length=10, max_length=256)


class AgentTokenCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=120)
    role: Literal["sensor", "analyst"] = "sensor"


class FeedbackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    object_type: Literal["campaign", "edge", "finding", "risk"]
    object_id: str
    label: Literal["supported", "rejected", "uncertain"]
    note: str = Field(default="", max_length=2000)


class ScopeCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    domain: str = Field(min_length=3, max_length=255)
    authorized_by: str = Field(min_length=2, max_length=200)
    expires_in_days: int = Field(default=7, ge=1, le=90)
    allow_active: bool = False
    notes: str = Field(default="", max_length=2000)


class AssessmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target: str = Field(min_length=3, max_length=255)
    active_checks: bool = False


class CryptoRefreshRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    symbols: list[str] = Field(default_factory=list, max_length=20)


class CorrelationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    window_hours: int | None = Field(default=None, ge=1, le=720)


class ResponseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["alert", "request_evidence", "recommend_rate_limit", "apply_rate_limit", "escalate"]
    target: str = Field(min_length=1, max_length=200)
    campaign_id: str | None = None
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    severity: Literal["info", "low", "medium", "high", "critical"] = "medium"
    risk_level: Literal["info", "low", "medium", "high", "critical"] = "medium"
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    reason: str = Field(default="", max_length=1000)
    ttl_minutes: int | None = Field(default=None, ge=5, le=1440)


class InvestigationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    campaign_id: str | None = None
    edge_id: str | None = None
    profile: str | None = None


class ApiError(BaseModel):
    code: str
    message: str
    details: dict[str, Any] = Field(default_factory=dict)
