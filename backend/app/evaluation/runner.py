"""Evaluation runner.

Measures the proposed correlation method against two simple baselines and
ablations on a labelled synthetic benchmark.  Every number in the report is
computed here; nothing is hard-coded.

Limitations are returned with the results, not buried in prose.
"""

from __future__ import annotations

import itertools
import statistics
import time
import tracemalloc
from datetime import datetime, timezone
from typing import Any

from ..correlation.features import CorrelationContext, Session, build_sessions
from ..correlation.scoring import ALGORITHM_VERSION, PAIR_SEPARATOR, compare, pair_key
from ..schemas.event import EventIn
from ..telemetry.normalize import normalize_event
from .scenarios import adaptive_probe_events, generate_dataset


# The benchmark dataset is anchored to a fixed instant so a seed always describes
# the same telemetry.  Anchored on the wall clock, the hour-of-day features moved
# between runs and the published counts drifted with them.
BENCHMARK_START = datetime(2026, 1, 15, 6, 0, tzinfo=timezone.utc)


def benchmark_dataset(*, seed: int = 7, high_volume: bool = False) -> dict[str, Any]:
    return generate_dataset(
        seed=seed,
        campaign_groups=40 if high_volume else 10,
        sessions_per_group=3,
        benign_sessions=24 if high_volume else 12,
        same_ip_pairs=4,
        incomplete_groups=2,
        delayed_sessions=3,
        now=BENCHMARK_START,
    )


def run(
    *, seed: int = 7, high_volume: bool = False, include_ablations: bool = True
) -> dict[str, Any]:
    dataset = benchmark_dataset(seed=seed, high_volume=high_volume)
    started = time.perf_counter()
    cpu_started = time.process_time()
    tracemalloc.start()
    sessions, order = _build_sessions(dataset["sessions"])
    context = CorrelationContext.from_sessions(sessions.values())
    pairs = list(itertools.combinations(order, 2))
    truth = dataset["truth"]
    labels = {
        pair_key(left, right): 1 if truth[left] == truth[right] else 0 for left, right in pairs
    }
    hard_ids = {session_id for session_id, group in truth.items() if group.startswith("hard-")}
    evaluable_pairs = [
        (left, right) for left, right in pairs if left not in hard_ids and right not in hard_ids
    ]
    hard_pairs = [
        (left, right) for left, right in pairs if left in hard_ids and right in hard_ids
    ]
    evaluable_keys = {pair_key(left, right) for left, right in evaluable_pairs}
    hard_keys = {pair_key(left, right) for left, right in hard_pairs}

    results: dict[str, Any] = {}
    hard_results: dict[str, Any] = {}
    timings: dict[str, float] = {}

    methods: list[str] = ["ip_only", "rule_based", "proposed"]
    if include_ablations:
        methods += [
            "ablation_no_intel",
            "ablation_no_timing",
            "ablation_no_toolchain",
            "ablation_uniform_weights",
            "ablation_jaccard_only",
        ]

    passive_decisions: dict[str, dict[str, Any]] = {}
    for method in methods:
        method_start = time.perf_counter()
        predictions = {}
        for left_id, right_id in pairs:
            key = pair_key(left_id, right_id)
            left, right = sessions[left_id], sessions[right_id]
            if method == "ip_only":
                predictions[key] = bool(left.source_ips & right.source_ips)
            elif method == "rule_based":
                predictions[key] = _rule_based(left, right)
            else:
                disabled = {
                    "ablation_no_intel": {"intel"},
                    "ablation_no_timing": {"timing"},
                    "ablation_no_toolchain": {"toolchain"},
                }.get(method, set())
                result = compare(
                    left,
                    right,
                    disabled_families=disabled,
                    context=context,
                    uniform_family_weights=method == "ablation_uniform_weights",
                    sequence_overlap=method != "ablation_jaccard_only",
                )
                if method == "proposed":
                    passive_decisions[key] = result
                predictions[key] = result["decision"] == "linked"
        timings[method] = round(time.perf_counter() - method_start, 3)
        results[method] = _metrics(predictions, labels, keys=evaluable_keys)
        hard_results[method] = _metrics(predictions, labels, keys=hard_keys)

    # ---- adaptive observation on bounded candidate clusters ---------- #
    adaptive_start = time.perf_counter()
    adaptive_decisions: dict[str, bool] = {
        key: result["decision"] == "linked" for key, result in passive_decisions.items()
    }
    hypothesis_pairs = [
        key
        for key, result in passive_decisions.items()
        if result["decision"] == "hypothesis"
    ]
    components = _hypothesis_components(hypothesis_pairs)
    components.sort(key=len, reverse=True)
    investigated = components[:15]
    enrich_ids = {session_id for component in investigated for session_id in component}
    enriched = {
        session_id: _build_session_with_probes(dataset, session_id, sessions[session_id])
        for session_id in enrich_ids
    }
    resolved_correctly = resolved_incorrectly = evaluated = 0
    lost_correctly = lost_incorrectly = unchanged = 0
    for left_id, right_id in pairs:
        if left_id not in enrich_ids or right_id not in enrich_ids:
            continue
        key = pair_key(left_id, right_id)
        evaluated += 1
        was_linked = adaptive_decisions.get(key, False)
        updated = compare(enriched[left_id], enriched[right_id], context=context)
        now_linked = updated["decision"] == "linked"
        adaptive_decisions[key] = now_linked
        if key not in evaluable_keys:
            continue
        # Additional observation can move a pair either way; both directions are
        # counted, so a promotion cannot be reported without its demotions.
        if now_linked and not was_linked:
            if labels[key] == 1:
                resolved_correctly += 1
            else:
                resolved_incorrectly += 1
        elif was_linked and not now_linked:
            if labels[key] == 1:
                lost_correctly += 1
            else:
                lost_incorrectly += 1
        else:
            unchanged += 1
    timings["proposed_adaptive"] = round(time.perf_counter() - adaptive_start, 3)
    results["proposed_adaptive"] = _metrics(adaptive_decisions, labels, keys=evaluable_keys)

    subsets = _subset_report(passive_decisions, labels, truth, pairs)
    campaign = _campaign_analysis(sessions, passive_decisions, truth, exclude=hard_ids)
    detection = _time_to_detection(sessions, passive_decisions, truth, exclude=hard_ids)
    peak_memory = tracemalloc.get_traced_memory()[1] / (1024 * 1024)
    tracemalloc.stop()
    elapsed = time.perf_counter() - started

    return {
        "algorithm_version": ALGORITHM_VERSION,
        "seed": seed,
        "dataset": dataset["meta"],
        "sessions": len(sessions),
        "pairs": len(pairs),
        "positives": sum(labels.values()),
        "negatives": len(labels) - sum(labels.values()),
        "results": results,
        "hard_subset": {
            "sessions": len(hard_ids),
            "pairs": len(hard_pairs),
            "results": hard_results,
            "note": (
                "Generic scanner groups with no distinguishing artefact. Labels are not "
                "recoverable from the available telemetry; reported separately so they do "
                "not inflate or deflate the headline numbers."
            ),
        },
        "subsets": subsets,
        "campaign_analysis": campaign,
        "time_to_detection": detection,
        "adaptive": {
            "ambiguous_pairs": len(hypothesis_pairs),
            "candidate_components": len(components),
            "components_investigated": len(investigated),
            "sessions_enriched": len(enrich_ids),
            "pairs_recomputed": evaluated,
            "resolved_correctly": resolved_correctly,
            "resolved_incorrectly": resolved_incorrectly,
            "lost_correctly": lost_correctly,
            "lost_incorrectly": lost_incorrectly,
            "unchanged": unchanged,
            "note": (
                "Additional observation is simulated by replaying one command the session "
                "already used, for sessions in the largest uncertain clusters only. The "
                "replay adds only behaviour the actor showed; the earlier simulation also "
                "added a category-derived request path, which manufactured similarity "
                "between unrelated sessions. Counts cover evaluable pairs."
            ),
        },
        "resources": {
            "total_seconds": round(elapsed, 3),
            "cpu_seconds": round(time.process_time() - cpu_started, 3),
            "method_seconds": timings,
            "peak_memory_mb": round(peak_memory, 2),
            "sessions_per_second": round(len(sessions) / elapsed, 1) if elapsed else None,
            "pairs_per_second": round(len(pairs) / elapsed, 1) if elapsed else None,
            "milliseconds_per_pair": round(1000 * elapsed / len(pairs), 3) if pairs else None,
        },
        "limitations": [
            "Synthetic telemetry; absolute scores will differ on production traffic.",
            "Ground truth is scenario membership, not actor identity.",
            "Thresholds were chosen a priori and not tuned on this benchmark.",
            "The confidence index is monotone but has not been probability-calibrated.",
            "Adaptive observation is simulated; it cannot create evidence, only add observations.",
            "No train/test split is reported because the method performs no learning.",
            "Time-to-detection is not measured in this batch benchmark.",
        ],
    }


def _build_sessions(specs: list[dict[str, Any]]) -> tuple[dict[str, Session], list[str]]:
    events = []
    for spec in specs:
        for payload in spec["events"]:
            events.append(_normalize(payload))
    sessions = build_sessions(events)
    order = sorted(sessions)
    return sessions, order


def _build_session_with_probes(dataset: dict[str, Any], session_id: str, base: Session) -> Session:
    spec = next(item for item in dataset["sessions"] if item["id"] == session_id)
    dominant_category = (
        max(base.categories.items(), key=lambda item: item[1])[0] if base.categories else None
    )
    client = sorted(base.clients)[0] if base.clients else None
    probes = adaptive_probe_events(spec, category=dominant_category, client=client)
    events = [_normalize(payload) for payload in spec["events"] + probes]
    rebuilt = build_sessions(events)
    return rebuilt.get(session_id, base)


def _hypothesis_components(pairs: list[str]) -> list[list[str]]:
    parent: dict[str, str] = {}

    def find(item: str) -> str:
        parent.setdefault(item, item)
        while parent[item] != item:
            parent[item] = parent[parent[item]]
            item = parent[item]
        return item

    for key in pairs:
        left, right = key.split(PAIR_SEPARATOR)
        parent[find(left)] = find(right)
    grouped: dict[str, list[str]] = {}
    for item in list(parent):
        grouped.setdefault(find(item), []).append(item)
    return [sorted(members) for members in grouped.values() if len(members) >= 2]


def _normalize(payload: dict[str, Any]) -> dict[str, Any]:
    event = EventIn.model_validate(payload)
    features = normalize_event(event)
    return {
        "id": f"{event.session_id}:{event.occurred_at.timestamp()}:{event.event_type}",
        "occurred_at": event.occurred_at.isoformat(),
        "source_module": event.source_module,
        "source_ip": event.source_ip,
        "session_id": event.session_id,
        "target_id": event.target_id,
        "severity": event.severity,
        "provenance": event.provenance.model_dump(mode="json"),
        "features": features,
    }


def _rule_based(left: Session, right: Session) -> bool:
    """A deliberately simple rule baseline an analyst could write by hand."""
    if left.indicators & right.indicators:
        return True
    if left.usernames & right.usernames and len(left.actions) >= 3 and len(right.actions) >= 3:
        shared_categories = set(left.categories) & set(right.categories)
        if shared_categories:
            return True
    if left.endpoints and right.endpoints:
        overlap = len(set(left.endpoints) & set(right.endpoints)) / len(
            set(left.endpoints) | set(right.endpoints)
        )
        if overlap >= 0.75:
            return True
    return False


def _metrics(
    predictions: dict[str, bool], labels: dict[str, int], *, keys: set[str] | None = None
) -> dict[str, Any]:
    tp = fp = tn = fn = 0
    for key, prediction in predictions.items():
        if keys is not None and key not in keys:
            continue
        actual = labels[key]
        if prediction and actual:
            tp += 1
        elif prediction and not actual:
            fp += 1
        elif not prediction and actual:
            fn += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    fnr = fn / (fn + tp) if fn + tp else 0.0
    accuracy = (tp + tn) / max(1, tp + tn + fp + fn)
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
        "accuracy": round(accuracy, 4),
    }


def _subset_report(
    decisions: dict[str, dict[str, Any]],
    labels: dict[str, int],
    truth: dict[str, str],
    pairs: list[tuple[str, str]],
) -> dict[str, Any]:
    def group(session_id: str) -> str:
        return truth.get(session_id, "")

    subsets: dict[str, list[str]] = {
        "same_campaign": [],
        "cross_campaign": [],
        "benign": [],
        "same_ip": [],
        "incomplete": [],
    }
    for left, right in pairs:
        key = pair_key(left, right)
        if key not in decisions:
            continue
        left_group, right_group = group(left), group(right)
        if left_group.startswith("hard-"):
            continue
        if left_group.startswith("campaign-"):
            subsets["same_campaign" if left_group == right_group else "cross_campaign"].append(key)
        elif left_group.startswith("benign-"):
            subsets["benign"].append(key)
        elif left_group.startswith("sameip-"):
            subsets["same_ip"].append(key)
        elif left_group.startswith("incomplete-"):
            subsets["incomplete"].append(key)
        elif left_group.startswith("delayed-"):
            subsets["benign"].append(key)

    report: dict[str, Any] = {}
    for name, keys in subsets.items():
        key_set = set(keys)
        if not key_set:
            continue
        metrics = _metrics(
            {key: decisions[key]["decision"] == "linked" for key in key_set},
            labels,
            keys=key_set,
        )
        report[name] = {
            "pairs": len(key_set),
            "positives": sum(labels[key] for key in key_set),
            **metrics,
        }
    return report


def _campaign_analysis(
    sessions: dict[str, Session],
    decisions: dict[str, dict[str, Any]],
    truth: dict[str, str],
    *,
    exclude: set[str] | None = None,
) -> dict[str, Any]:
    excluded = exclude or set()
    linked = [key for key, result in decisions.items() if result["decision"] == "linked"]
    parent: dict[str, str] = {
        session_id: session_id for session_id in sessions if session_id not in excluded
    }

    def find(item: str) -> str:
        while parent[item] != item:
            parent[item] = parent[parent[item]]
            item = parent[item]
        return item

    for key in linked:
        left, right = key.split(PAIR_SEPARATOR)
        if left in parent and right in parent:
            parent[find(left)] = find(right)

    clusters: dict[str, set[str]] = {}
    for session_id in sessions:
        if session_id in excluded:
            continue
        clusters.setdefault(find(session_id), set()).add(session_id)
    predicted = [members for members in clusters.values() if len(members) >= 2]

    true_groups: dict[str, set[str]] = {}
    for session_id, group in truth.items():
        if session_id in excluded:
            continue
        true_groups.setdefault(group, set()).add(session_id)
    multi_groups = {group: members for group, members in true_groups.items() if len(members) >= 2}

    recovered = []
    for group, members in multi_groups.items():
        if any(members <= cluster for cluster in predicted):
            recovered.append(group)

    pure = 0
    for cluster in predicted:
        groups = {truth.get(member) for member in cluster}
        if len(groups) == 1:
            pure += 1

    return {
        "true_multi_session_groups": len(multi_groups),
        "predicted_clusters": len(predicted),
        "groups_recovered_exactly": len(recovered),
        "campaign_recall": round(len(recovered) / len(multi_groups), 4) if multi_groups else 0.0,
        "pure_clusters": pure,
        "cluster_purity": round(pure / len(predicted), 4) if predicted else 0.0,
        "note": (
            "Recovery requires every member of a true group to appear in exactly one "
            "predicted cluster (no fragmentation, no contamination)."
        ),
    }


def _time_to_detection(
    sessions: dict[str, Session],
    decisions: dict[str, dict[str, Any]],
    truth: dict[str, str],
    *,
    exclude: set[str] | None = None,
) -> dict[str, Any]:
    """How long a campaign stays invisible before its evidence supports a link.

    Correlation runs in batches, so this measures when the evidence became
    sufficient rather than when a run happened: for each true group, the earliest
    point at which a linked pair of its members had finished emitting.  Groups
    that never link have no time to detection, and scheduling latency is outside
    the measurement.
    """
    excluded = exclude or set()
    groups: dict[str, list[str]] = {}
    for session_id, group in truth.items():
        if session_id in excluded:
            continue
        groups.setdefault(group, []).append(session_id)

    delays: list[float] = []
    measured = 0
    for members in groups.values():
        if len(members) < 2:
            continue
        starts = [sessions[item].first_seen for item in members if sessions[item].first_seen]
        if not starts:
            continue
        measured += 1
        group_start = min(starts)
        available_at: datetime | None = None
        for left, right in itertools.combinations(members, 2):
            result = decisions.get(pair_key(left, right))
            if not result or result["decision"] != "linked":
                continue
            ends = [sessions[item].last_seen for item in (left, right) if sessions[item].last_seen]
            if not ends:
                continue
            moment = max(ends)
            if available_at is None or moment < available_at:
                available_at = moment
        if available_at is None:
            continue
        delays.append(max(0.0, (available_at - group_start).total_seconds()))

    return {
        "groups_with_a_link": len(delays),
        "groups_measured": measured,
        "median_seconds": round(statistics.median(delays), 1) if delays else None,
        "mean_seconds": round(statistics.fmean(delays), 1) if delays else None,
        "max_seconds": round(max(delays), 1) if delays else None,
        "note": (
            "Elapsed campaign time until two members of the same true group had both "
            "finished emitting events that link them. Correlation is batch, so "
            "scheduling latency is excluded, and a group that never links has no "
            "time to detection."
        ),
    }
