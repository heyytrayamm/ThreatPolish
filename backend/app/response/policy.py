"""Response policy.

Policy is deliberately conservative:

* nothing is blocked automatically from a weak relationship score;
* applying a rate limit requires high confidence, high risk and an observed
  source address;
* an analyst may request an action, but only an administrator can approve one
  that affects infrastructure;
* every applied rule expires and can be rolled back.
"""

from __future__ import annotations

from typing import Any

POLICY_VERSION = "response-policy-1.0.0"
AUTO_APPLY_MIN_CONFIDENCE = 0.90
APPLY_MIN_CONFIDENCE = 0.85
APPLY_MIN_RISK = 60.0

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
ACTION_RANK = {
    "alert": 0,
    "request_evidence": 1,
    "recommend_rate_limit": 2,
    "apply_rate_limit": 3,
    "escalate": 3,
}

POLICIES: list[dict[str, Any]] = [
    {
        "id": "pol-weak-evidence",
        "when": "confidence < 0.55",
        "action": "request_evidence",
        "rationale": "Evidence is too weak to justify any containment action.",
    },
    {
        "id": "pol-critical-escalate",
        "when": "risk_level == critical and confidence >= 0.80",
        "action": "escalate",
        "rationale": "Critical impact with strong evidence requires human incident response.",
    },
    {
        "id": "pol-high-recommend",
        "when": "risk_level == high and confidence >= 0.70",
        "action": "recommend_rate_limit",
        "rationale": "Containment may be warranted; a human must review before enforcement.",
    },
    {
        "id": "pol-default-alert",
        "when": "otherwise",
        "action": "alert",
        "rationale": "Record the finding and keep it visible without blocking anyone.",
    },
]


def decide(
    *,
    severity: str,
    confidence: float,
    risk_level: str,
    risk_score: float,
    auto_apply_enabled: bool = False,
) -> dict[str, Any]:
    bounded = max(0.0, min(1.0, confidence))
    severity_key = severity if severity in SEVERITY_RANK else "info"
    risk = max(0.0, min(100.0, risk_score))

    permitted: set[str] = {"alert", "request_evidence"}
    if bounded >= 0.55:
        permitted.add("recommend_rate_limit")
    if severity_key in {"high", "critical"} and bounded >= 0.70:
        permitted.add("escalate")
    if (
        bounded >= APPLY_MIN_CONFIDENCE
        and severity_key in {"high", "critical"}
        and risk >= APPLY_MIN_RISK
    ):
        permitted.add("apply_rate_limit")

    if bounded < 0.55:
        policy_id, recommended, rationale = (
            "pol-weak-evidence",
            "request_evidence",
            POLICIES[0]["rationale"],
        )
    elif risk_level == "critical" and bounded >= 0.80:
        policy_id, recommended, rationale = (
            "pol-critical-escalate",
            "escalate",
            POLICIES[1]["rationale"],
        )
    elif risk_level == "high" and bounded >= 0.70:
        policy_id, recommended, rationale = (
            "pol-high-recommend",
            "recommend_rate_limit",
            POLICIES[2]["rationale"],
        )
    else:
        policy_id, recommended, rationale = (
            "pol-default-alert",
            "alert",
            POLICIES[3]["rationale"],
        )

    auto_apply = (
        auto_apply_enabled
        and recommended == "apply_rate_limit"
        and bounded >= AUTO_APPLY_MIN_CONFIDENCE
        and risk_level == "critical"
        and "apply_rate_limit" in permitted
    )

    return {
        "policy_id": policy_id,
        "policy_version": POLICY_VERSION,
        "recommended_action": recommended,
        "permitted_actions": sorted(permitted, key=lambda name: ACTION_RANK.get(name, 0)),
        "auto_apply": auto_apply,
        "auto_apply_enabled": auto_apply_enabled,
        "rationale": rationale,
        "inputs": {
            "severity": severity_key,
            "confidence": round(bounded, 4),
            "risk_level": risk_level,
            "risk_score": round(risk, 2),
        },
        "guardrails": {
            "min_confidence_to_apply": APPLY_MIN_CONFIDENCE,
            "min_risk_to_apply": APPLY_MIN_RISK,
            "auto_apply_min_confidence": AUTO_APPLY_MIN_CONFIDENCE,
            "requires_observed_target": True,
            "requires_approval": True,
            "max_ttl_minutes": 1440,
        },
    }


def is_action_permitted(decision: dict[str, Any], action: str) -> bool:
    return action in decision["permitted_actions"]
