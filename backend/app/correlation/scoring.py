"""Evidence-weighted correlation.

The score is built from explicitly named, independently inspectable evidence
components.  Components are grouped into *families*; a family is averaged
before it contributes to the total so that many closely related signals
(command text, command categories) cannot outvote one another.

Corpus-relative weighting
-------------------------
When a ``CorrelationContext`` is supplied, tokens (usernames, clients, action
trigrams, endpoints, categories) that appear in most sessions of the analysed
window are treated as uninformative and excluded.  Sharing ``root`` or a
stock SSH client is not evidence of a common actor; sharing a rare command
sequence is stronger.  The algorithm version, the context version and the
threshold are stored with every edge.

Formula
-------
``support``     weighted mean of available family scores
``coverage``    share of total family weight that was observable
``score``       ``clamp(support * coverage**0.5 - contradiction_penalty, 0, 1)``
``confidence``  ``logistic(8 * (score - 0.5))``

The logistic is a monotone presentation of the score.  It is called a
*confidence index*, not a probability: it has not been calibrated against
labelled field data, and the evaluation report states that limitation.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

from .features import (
    CorrelationContext,
    Session,
    action_resolutions,
    histogram_similarity,
    jaccard,
    rhythm_similarity,
    weighted_cosine,
    weighted_jaccard,
)

ALGORITHM_VERSION = "corr-1.1.0"
LINK_CONFIDENCE = 0.70
MIN_SCORE_TO_STORE = 0.30
MIN_INDEPENDENT_FAMILIES = 2
MAX_CONTRADICTION_PENALTY = 0.25


@dataclass(frozen=True)
class Family:
    name: str
    weight: float


FAMILIES: tuple[Family, ...] = (
    Family("behavior", 0.52),
    Family("targeting", 0.18),
    Family("timing", 0.08),
    Family("identity", 0.10),
    Family("intel", 0.12),
    Family("toolchain", 0.08),
)

FAMILY_WEIGHT = {family.name: family.weight for family in FAMILIES}
TOTAL_WEIGHT = sum(FAMILY_WEIGHT.values())


@dataclass
class Component:
    name: str
    family: str
    weight: float
    available: bool
    score: float
    detail: str


def _component(
    name: str, family: str, weight: float, available: bool, score: float, detail: str
) -> Component:
    return Component(
        name=name,
        family=family,
        weight=weight,
        available=available,
        score=round(max(0.0, min(1.0, score)), 4),
        detail=detail,
    )


def _filter_set(values: set[str], field: str, context: CorrelationContext | None) -> set[str]:
    if context is None:
        return set(values)
    return {value for value in values if context.is_informative(field, value)}


def _filter_counter(
    values: Any, field: str, context: CorrelationContext | None
) -> dict[str, int]:
    if context is None:
        return dict(values)
    return {key: count for key, count in values.items() if context.is_informative(field, key)}


def _set_similarity(
    left: set[str], right: set[str], field: str, context: CorrelationContext | None
) -> float:
    if context is None:
        return jaccard(left, right)
    return weighted_jaccard(left, right, lambda token: context.weight(field, token))


def _counter_similarity(
    left: dict[str, int], right: dict[str, int], field: str, context: CorrelationContext | None
) -> float:
    from collections import Counter

    if context is None:
        from .features import cosine_counts

        return cosine_counts(Counter(left), Counter(right))
    return weighted_cosine(Counter(left), Counter(right), lambda token: context.weight(field, token))


def compare(
    left: Session,
    right: Session,
    *,
    disabled_families: set[str] | None = None,
    context: CorrelationContext | None = None,
) -> dict[str, Any]:
    """Compare two sessions.

    ``disabled_families`` supports ablation studies: a disabled family is treated
    as unavailable, which also reduces coverage rather than silently
    redistributing its weight.
    """
    disabled = disabled_families or set()
    components: list[Component] = []

    left_levels = {
        level: _filter_set(values, "action", context)
        for level, values in action_resolutions(left.actions).items()
    }
    right_levels = {
        level: _filter_set(values, "action", context)
        for level, values in action_resolutions(right.actions).items()
    }
    level_weights = {"unigram": 0.45, "bigram": 0.35, "trigram": 0.20}
    level_parts: list[tuple[float, float]] = []
    for level, weight in level_weights.items():
        if left_levels[level] and right_levels[level]:
            level_parts.append(
                (weight, _set_similarity(left_levels[level], right_levels[level], "action", context))
            )
    sequence_available = bool(level_parts)
    sequence_score = (
        sum(weight * value for weight, value in level_parts)
        / sum(weight for weight, _ in level_parts)
        if level_parts
        else 0.0
    )
    components.append(
        _component(
            "action_sequence",
            "behavior",
            0.30,
            sequence_available,
            sequence_score,
            "multi-resolution action overlap: "
            + ", ".join(level for level, _ in [(name, weight) for name, weight in level_weights.items() if left_levels[name] and right_levels[name]])
            if level_parts
            else "no informative action tokens",
        )
    )

    left_shapes = _filter_set(set(left.commands), "command", context)
    right_shapes = _filter_set(set(right.commands), "command", context)
    shapes_available = bool(left_shapes and right_shapes)
    components.append(
        _component(
            "command_shape",
            "behavior",
            0.10,
            shapes_available,
            _set_similarity(left_shapes, right_shapes, "command", context),
            _detail("command shapes", left_shapes, right_shapes, set(left.commands), set(right.commands)),
        )
    )

    left_categories = _filter_counter(left.categories, "category", context)
    right_categories = _filter_counter(right.categories, "category", context)
    categories_available = bool(left_categories and right_categories)
    components.append(
        _component(
            "command_categories",
            "behavior",
            0.12,
            categories_available,
            _counter_similarity(left_categories, right_categories, "category", context),
            _detail(
                "categories",
                set(left_categories),
                set(right_categories),
                set(left.categories),
                set(right.categories),
            ),
        )
    )

    left_endpoints = _filter_counter(left.endpoints, "endpoint", context)
    right_endpoints = _filter_counter(right.endpoints, "endpoint", context)
    endpoints_available = bool(left_endpoints and right_endpoints)
    components.append(
        _component(
            "endpoint_targeting",
            "targeting",
            0.18,
            endpoints_available,
            _counter_similarity(left_endpoints, right_endpoints, "endpoint", context),
            _detail(
                "endpoint templates",
                set(left_endpoints),
                set(right_endpoints),
                set(left.endpoints),
                set(right.endpoints),
            ),
        )
    )

    timing_available, timing_score, timing_detail = _timing_similarity(left, right)
    components.append(
        _component("temporal_rhythm", "timing", 0.08, timing_available, timing_score, timing_detail)
    )

    left_usernames = _filter_set(left.usernames, "username", context)
    right_usernames = _filter_set(right.usernames, "username", context)
    credentials_available = bool(left_usernames and right_usernames)
    components.append(
        _component(
            "credential_choice",
            "identity",
            0.10,
            credentials_available,
            _set_similarity(left_usernames, right_usernames, "username", context),
            _detail("usernames", left_usernames, right_usernames, left.usernames, right.usernames),
        )
    )

    left_indicators = _filter_set(left.indicators, "indicator", context)
    right_indicators = _filter_set(right.indicators, "indicator", context)
    intel_available = bool(left_indicators and right_indicators)
    shared_indicators = left_indicators & right_indicators
    components.append(
        _component(
            "verified_indicator",
            "intel",
            0.12,
            intel_available,
            min(1.0, len(shared_indicators) / 2.0),
            f"{len(shared_indicators)} shared informative indicators",
        )
    )

    left_clients = _filter_set(left.clients, "client", context)
    right_clients = _filter_set(right.clients, "client", context)
    tool_available = bool(left_clients and right_clients)
    components.append(
        _component(
            "client_signature",
            "toolchain",
            0.08,
            tool_available,
            _set_similarity(left_clients, right_clients, "client", context),
            _detail("client signatures", left_clients, right_clients, left.clients, right.clients),
        )
    )

    # ---- family aggregation ------------------------------------------- #
    families: dict[str, dict[str, Any]] = {}
    active_weight = {
        family: weight for family, weight in FAMILY_WEIGHT.items() if family not in disabled
    }
    total_weight = sum(active_weight.values())
    for family, weight in FAMILY_WEIGHT.items():
        if family in disabled:
            families[family] = {
                "weight": 0.0,
                "available": False,
                "score": None,
                "disabled": True,
            }
            continue
        members = [c for c in components if c.family == family]
        available_members = [c for c in members if c.available]
        if not available_members:
            families[family] = {"weight": weight, "available": False, "score": None}
            continue
        member_weight = sum(c.weight for c in available_members)
        score = (
            sum(c.score * c.weight for c in available_members) / member_weight
            if member_weight
            else 0.0
        )
        families[family] = {
            "weight": weight,
            "available": True,
            "score": round(score, 4),
            "members": [c.name for c in available_members],
        }

    available_weight = sum(info["weight"] for info in families.values() if info["available"])
    support = (
        sum(info["weight"] * info["score"] for info in families.values() if info["available"])
        / available_weight
        if available_weight
        else 0.0
    )
    coverage = available_weight / total_weight if total_weight else 0.0

    contradictions = _contradictions(left, right, components, support)
    penalty = min(0.35, sum(item["penalty"] for item in contradictions))
    score = max(0.0, min(1.0, support * math.sqrt(coverage) - penalty))
    confidence = 1.0 / (1.0 + math.exp(-8.0 * (score - 0.5)))

    independent = [
        name
        for name, info in families.items()
        if info["available"] and (info["score"] or 0.0) >= 0.50
    ]
    anchor_reasons = _anchor_evidence(components, families)
    shared_ip_low_behavior = any(
        item["code"] == "shared_ip_disjoint_behavior" for item in contradictions
    )

    threshold_met = (
        confidence >= LINK_CONFIDENCE
        and len(independent) >= MIN_INDEPENDENT_FAMILIES
        and penalty <= MAX_CONTRADICTION_PENALTY
        and not shared_ip_low_behavior
    )
    linked = threshold_met and bool(anchor_reasons)
    if linked:
        decision = "linked"
        decision_reason = "numeric thresholds met and high-specificity evidence present"
    elif threshold_met:
        decision = "hypothesis"
        decision_reason = (
            "numeric thresholds met, but the evidence is generic; a high-specificity "
            "anchor (verified indicator, matching command structure, or shared "
            "credential plus client signature) is required before linking"
        )
    elif score >= MIN_SCORE_TO_STORE:
        decision = "hypothesis"
        decision_reason = "evidence below the linking threshold"
    else:
        decision = "not_linked"
        decision_reason = "insufficient evidence"

    missing = [name for name, info in families.items() if not info["available"]]
    explanation = _explain(
        left,
        right,
        families,
        independent,
        contradictions,
        decision,
        confidence,
        anchor_reasons=anchor_reasons,
        decision_reason=decision_reason,
    )

    return {
        "algorithm_version": ALGORITHM_VERSION,
        "context": context.summary() if context else None,
        "score": round(score, 4),
        "confidence": round(confidence, 4),
        "support": round(support, 4),
        "coverage": round(coverage, 4),
        "penalty": round(penalty, 4),
        "family_scores": {name: info["score"] for name, info in families.items()},
        "families": families,
        "components": [
            {
                "name": c.name,
                "family": c.family,
                "weight": c.weight,
                "available": c.available,
                "score": c.score,
                "detail": c.detail,
            }
            for c in components
        ],
        "independent_families": independent,
        "anchors": anchor_reasons,
        "contradictions": contradictions,
        "missing_evidence": missing,
        "decision": decision,
        "decision_reason": decision_reason,
        "thresholds": {
            "link_confidence": LINK_CONFIDENCE,
            "hypothesis_score": MIN_SCORE_TO_STORE,
            "min_independent_families": MIN_INDEPENDENT_FAMILIES,
        },
        "explanation": explanation,
        "pair": {
            "left": left.id,
            "right": right.id,
            "left_ips": sorted(left.source_ips),
            "right_ips": sorted(right.source_ips),
            "cross_ip": bool(
                left.source_ips and right.source_ips and not (left.source_ips & right.source_ips)
            ),
        },
    }


def _detail(
    label: str,
    left_used: set[str],
    right_used: set[str],
    left_all: set[str],
    right_all: set[str],
) -> str:
    shared = len(left_used & right_used)
    excluded = (len(left_all) - len(left_used)) + (len(right_all) - len(right_used))
    suffix = f"; {excluded} ubiquitous tokens excluded" if excluded else ""
    return f"{shared} shared {label}{suffix}"


def _anchor_evidence(
    components: list[Component], families: dict[str, dict[str, Any]]
) -> list[str]:
    """High-specificity evidence required before a link may be declared.

    Behavioural similarity alone is not enough: benign scanners, default
    usernames and stock clients can all coincide.  One anchor must be present.
    """
    by_name = {component.name: component for component in components}
    reasons: list[str] = []

    intel = by_name["verified_indicator"]
    if intel.available and intel.score >= 0.5:
        reasons.append("shared verified indicator")

    shape = by_name["command_shape"]
    if shape.available and shape.score >= 0.45:
        reasons.append("matching command structure")

    credentials = by_name["credential_choice"]
    toolchain = families.get("toolchain", {})
    if (
        credentials.available
        and credentials.score >= 0.5
        and toolchain.get("available")
        and (toolchain.get("score") or 0.0) >= 0.5
    ):
        reasons.append("shared credential choice and client signature")

    return reasons


def _timing_similarity(left: Session, right: Session) -> tuple[bool, float, str]:
    parts: list[tuple[float, float]] = []
    distinct_hours = len(
        {hour for hour in range(24) if left.hours.get(hour) or right.hours.get(hour)}
    )
    if len(left.event_ids) >= 2 and len(right.event_ids) >= 2 and distinct_hours >= 3:
        parts.append((0.5, histogram_similarity(left.hour_profile(), right.hour_profile())))
    if left.interarrivals and right.interarrivals:
        parts.append((0.5, rhythm_similarity(left.interarrivals, right.interarrivals)))
    if not parts:
        return False, 0.0, "insufficient timestamps or a single activity hour"
    total = sum(weight for weight, _ in parts)
    score = sum(weight * value for weight, value in parts) / total
    detail = "activity rhythm similarity" + (
        " (hour-of-day excluded: single-hour window)" if distinct_hours < 3 else ""
    )
    return True, score, detail


def _contradictions(
    left: Session, right: Session, components: list[Component], support: float
) -> list[dict[str, Any]]:
    by_name = {component.name: component for component in components}
    found: list[dict[str, Any]] = []

    tool = by_name["client_signature"]
    if tool.available and tool.score == 0.0:
        found.append(
            {
                "code": "different_toolchain",
                "penalty": 0.10,
                "detail": "both sessions expose informative client signatures and none overlap",
            }
        )

    sequence = by_name["action_sequence"]
    categories = by_name["command_categories"]
    if (
        sequence.available
        and len(left.actions) >= 3
        and len(right.actions) >= 3
        and sequence.score < 0.15
        and (not categories.available or categories.score < 0.20)
    ):
        found.append(
            {
                "code": "disjoint_behavior",
                "penalty": 0.12,
                "detail": "both sessions have substantial and dissimilar action sequences",
            }
        )

    credentials = by_name["credential_choice"]
    if (
        credentials.available
        and credentials.score == 0.0
        and len(left.usernames) >= 2
        and len(right.usernames) >= 2
    ):
        found.append(
            {
                "code": "disjoint_credentials",
                "penalty": 0.06,
                "detail": "both sessions used informative usernames with no overlap",
            }
        )

    if left.source_ips & right.source_ips and support < 0.45:
        found.append(
            {
                "code": "shared_ip_disjoint_behavior",
                "penalty": 0.05,
                "detail": "the sessions share an IP but their behavior does not support a common actor",
            }
        )
    return found


def _explain(
    left: Session,
    right: Session,
    families: dict[str, dict[str, Any]],
    independent: list[str],
    contradictions: list[dict[str, Any]],
    decision: str,
    confidence: float,
    *,
    anchor_reasons: list[str] | None = None,
    decision_reason: str = "",
) -> str:
    strongest = sorted(
        ((name, info["score"]) for name, info in families.items() if info["available"]),
        key=lambda item: item[1] or 0.0,
        reverse=True,
    )[:3]
    parts = [f"{name} {score:.2f}" for name, score in strongest if score is not None]
    ip_note = (
        "different source IPs"
        if left.source_ips and right.source_ips and not (left.source_ips & right.source_ips)
        else "shared source IP"
    )
    verdict = {
        "linked": "linked as related activity",
        "hypothesis": "retained as an unconfirmed hypothesis",
        "not_linked": "not linked",
    }[decision]
    contradiction_note = (
        f"; contradictions: {', '.join(item['code'] for item in contradictions)}"
        if contradictions
        else "; no contradictions observed"
    )
    anchor_note = (
        f" Anchors: {', '.join(anchor_reasons)}." if anchor_reasons else " No high-specificity anchor."
    )
    return (
        f"Sessions {left.id} and {right.id} ({ip_note}) were {verdict} at confidence "
        f"{confidence:.2f}. Strongest evidence: {', '.join(parts) or 'none'}; "
        f"{len(independent)} independent evidence families{contradiction_note}."
        f"{anchor_note} {decision_reason}."
    )


PAIR_SEPARATOR = "\x1f"


def pair_key(left_id: str, right_id: str) -> str:
    first, second = sorted((left_id, right_id))
    return f"{first}{PAIR_SEPARATOR}{second}"
