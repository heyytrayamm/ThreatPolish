"""Explainable risk scoring.

Three quantities are deliberately kept apart:

* **Severity** - how damaging the observed activity could be, independent of
  how sure we are or which asset it touched.
* **Confidence** - how strongly the available evidence supports the finding.
* **Risk** - the estimated impact on a specific asset, derived from both.

Risk is a deterministic function with published inputs. It is capped by
evidence: weaker confidence cannot produce a maximum risk score.
"""

from __future__ import annotations

from typing import Any

ALGORITHM_VERSION = "risk-1.0.0"

SEVERITY_BASE = {"info": 5.0, "low": 20.0, "medium": 45.0, "high": 70.0, "critical": 90.0}
CRITICALITY_FACTOR = {"low": 0.80, "medium": 1.00, "high": 1.25, "critical": 1.50}
EXPOSURE_FACTOR = {"internal": 0.90, "partner": 1.00, "internet": 1.10}

LEVELS = ((80.0, "critical"), (60.0, "high"), (35.0, "medium"), (15.0, "low"), (0.0, "info"))

RECOMMENDATIONS = {
    "critical": "Escalate to incident response. Request independent corroboration before any blocking action.",
    "high": "Escalate to an analyst, collect additional evidence, and review related sessions.",
    "medium": "Create an alert and correlate with related sessions; monitor for escalation.",
    "low": "Monitor. No automated action is warranted at this evidence level.",
    "info": "Record for context only.",
}


def score_risk(
    *,
    severity: str,
    confidence: float,
    asset_criticality: str = "medium",
    exposure: str = "internet",
    reasons: list[str] | None = None,
) -> dict[str, Any]:
    severity_key = severity if severity in SEVERITY_BASE else "info"
    criticality_key = asset_criticality if asset_criticality in CRITICALITY_FACTOR else "medium"
    exposure_key = exposure if exposure in EXPOSURE_FACTOR else "internet"
    bounded_confidence = max(0.0, min(1.0, float(confidence)))

    base = SEVERITY_BASE[severity_key]
    criticality = CRITICALITY_FACTOR[criticality_key]
    exposure_factor = EXPOSURE_FACTOR[exposure_key]
    confidence_factor = 0.5 + 0.5 * bounded_confidence
    raw = base * criticality * exposure_factor * confidence_factor
    risk = round(min(100.0, raw), 2)
    level = next(name for threshold, name in LEVELS if risk >= threshold)

    factors = [
        {
            "name": "severity_base",
            "input": severity_key,
            "value": base,
            "note": "intrinsic seriousness of the observed activity",
        },
        {
            "name": "asset_criticality",
            "input": criticality_key,
            "value": criticality,
            "note": "business importance of the affected asset",
        },
        {
            "name": "exposure",
            "input": exposure_key,
            "value": exposure_factor,
            "note": "network exposure of the affected asset",
        },
        {
            "name": "confidence_factor",
            "input": round(bounded_confidence, 3),
            "value": round(confidence_factor, 3),
            "note": "evidence strength; keeps risk below the maximum when evidence is weak",
        },
    ]

    return {
        "algorithm_version": ALGORITHM_VERSION,
        "severity": severity_key,
        "confidence": round(bounded_confidence, 4),
        "risk_score": risk,
        "risk_level": level,
        "asset_criticality": criticality_key,
        "exposure": exposure_key,
        "formula": (
            "risk = min(100, severity_base * asset_criticality * exposure "
            "* (0.5 + 0.5 * confidence))"
        ),
        "factors": factors,
        "reasons": reasons or [],
        "recommended_action": RECOMMENDATIONS[level],
        "caveat": (
            "Risk is a transparent heuristic, not a calibrated probability of loss. "
            "Confidence reflects evidence coverage, not certainty about actor identity."
        ),
    }


def explain_finding(
    *,
    what_happened: str,
    assets: list[str],
    why_flagged: str,
    evidence: list[dict[str, Any]],
    timeline: list[dict[str, Any]],
    severity: str,
    confidence: float,
    asset_criticality: str = "medium",
    exposure: str = "internet",
) -> dict[str, Any]:
    scoring = score_risk(
        severity=severity,
        confidence=confidence,
        asset_criticality=asset_criticality,
        exposure=exposure,
    )
    return {
        "what_happened": what_happened,
        "assets_involved": assets,
        "why_flagged": why_flagged,
        "evidence": evidence,
        "timeline": timeline,
        "confidence": scoring["confidence"],
        "severity": scoring["severity"],
        "risk": scoring,
        "recommended_action": scoring["recommended_action"],
    }
