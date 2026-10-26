"""Tactic coverage for a campaign, derived from observed session features.

The model is deliberately small. It maps the activity categories produced by
telemetry normalization onto the tactics this platform can actually observe,
gives each tactic an impact weight, and reports two different numbers:

* ``coverage`` — how many tactics were seen at all, ignoring consequence.
* ``risk_weighted_coverage`` — the share of total impact weight that was seen.

A campaign that only probes a web decoy and one that reaches credential access
can therefore be told apart without pretending the second one is "80% of an
attack". Coverage is a reading aid over recorded evidence, not a prediction of
what an actor will do next, and only tactics this telemetry can evidence are
counted (collection and exfiltration are absent by design).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Tactic:
    key: str
    label: str
    weight: int
    evidence_hint: str


# Weights are consequence if the tactic succeeds, on a 1–5 scale. They are
# intentionally coarse: a precise weight would imply a calibration this
# telemetry cannot support.
TACTICS: tuple[Tactic, ...] = (
    Tactic("reconnaissance", "Reconnaissance", 1, "external probing of a decoy surface"),
    Tactic("initial_access", "Initial access", 3, "authentication attempts against a decoy"),
    Tactic("execution", "Execution", 3, "commands executed inside a session"),
    Tactic("persistence", "Persistence", 4, "mechanisms that would survive a restart"),
    Tactic("privilege_escalation", "Privilege escalation", 4, "attempts to raise privileges"),
    Tactic("defense_evasion", "Defense evasion", 2, "removal of traces"),
    Tactic("credential_access", "Credential access", 4, "credential tooling or key manipulation"),
    Tactic("discovery", "Discovery", 2, "host and environment enumeration after access"),
    Tactic("lateral_movement", "Lateral movement", 4, "connections to other hosts"),
    Tactic("command_and_control", "Command and control", 4, "tool transfer or remote channel use"),
    Tactic("impact", "Impact", 5, "destructive or resource-hijacking actions"),
)

BY_KEY = {tactic.key: tactic for tactic in TACTICS}
TOTAL_WEIGHT = sum(tactic.weight for tactic in TACTICS)


def classify(categories: dict[str, int], auth: dict[str, int]) -> dict[str, list[str]]:
    """Map one session's observed categories to tactics with a reason each.

    ``categories`` counts normalized command categories (``recon``,
    ``download``, ...) and non-command activity such as ``http_probe``.
    ``auth`` carries attempt, failure and success counts.
    """
    observed: dict[str, list[str]] = {}

    def note(tactic: str, reason: str) -> None:
        observed.setdefault(tactic, []).append(reason)

    attempts = int(auth.get("attempts") or 0)
    successes = int(auth.get("successes") or 0)
    failures = int(auth.get("failures") or 0)
    if attempts:
        note("initial_access", f"{attempts} authentication attempt(s), {failures} failed")
    if int(categories.get("http_probe") or 0):
        note("reconnaissance", f"{categories['http_probe']} probe request(s)")
    if categories.get("recon"):
        # Enumeration before a successful login is still external
        # reconnaissance; after it, the same commands are discovery.
        if successes:
            note("discovery", f"{categories['recon']} enumeration command(s) after access")
        else:
            note("reconnaissance", f"{categories['recon']} enumeration command(s) without access")
    if categories.get("execution"):
        note("execution", f"{categories['execution']} interpreter invocation(s)")
    if categories.get("other"):
        note("execution", f"{categories['other']} unclassified command(s)")
    if categories.get("persistence"):
        note("persistence", f"{categories['persistence']} persistence command(s)")
    if categories.get("privilege"):
        note("privilege_escalation", f"{categories['privilege']} privilege command(s)")
    if categories.get("cleanup"):
        note("defense_evasion", f"{categories['cleanup']} cleanup command(s)")
    if categories.get("credential"):
        note("credential_access", f"{categories['credential']} credential command(s)")
    if categories.get("lateral"):
        note("lateral_movement", f"{categories['lateral']} lateral-tool invocation(s)")
    if categories.get("download"):
        note("command_and_control", f"{categories['download']} transfer command(s)")
    if categories.get("mining"):
        note("impact", f"{categories['mining']} mining command(s)")
    if categories.get("destruction"):
        note("impact", f"{categories['destruction']} destructive command(s)")
    return observed


def campaign_coverage(sessions: list[dict[str, Any]], *, asset_criticality: str = "medium") -> dict[str, Any]:
    """Aggregate per-session classifications into a campaign view."""
    evidence: dict[str, set[str]] = {}
    session_ids: dict[str, set[str]] = {}
    for session in sessions:
        categories = session.get("categories") or {}
        auth = session.get("auth") or {}
        for tactic, reasons in classify(categories, auth).items():
            evidence.setdefault(tactic, set()).update(reasons)
            session_ids.setdefault(tactic, set()).add(str(session.get("id")))

    tactics = []
    for tactic in TACTICS:
        reasons = sorted(evidence.get(tactic.key, set()))
        members = sorted(session_ids.get(tactic.key, set()))
        tactics.append(
            {
                "key": tactic.key,
                "label": tactic.label,
                "weight": tactic.weight,
                "observed": bool(reasons),
                "sessions": members[:20],
                "session_count": len(members),
                "evidence": reasons[:4],
            }
        )

    covered = [item for item in tactics if item["observed"]]
    observed_weight = sum(item["weight"] for item in covered)
    # Ties go to the later tactic: privilege escalation and C2 carry the same
    # consequence weight, but reaching C2 implies further progression.
    order = {tactic.key: index for index, tactic in enumerate(TACTICS)}
    furthest = max(
        covered,
        key=lambda item: (item["weight"], order[item["key"]]),
        default=None,
    )
    return {
        "tactics": tactics,
        "observed": [item["key"] for item in covered],
        "coverage": round(len(covered) / len(TACTICS), 3),
        "risk_weighted_coverage": round(observed_weight / TOTAL_WEIGHT, 3),
        "observed_weight": observed_weight,
        "total_weight": TOTAL_WEIGHT,
        "furthest": None if furthest is None else {"key": furthest["key"], "label": furthest["label"]},
        "asset_criticality": asset_criticality,
        "note": (
            "Coverage counts only tactics this telemetry can evidence; collection "
            "and exfiltration are not observable from decoy command and request "
            "data. It describes recorded activity, not intent or capability."
        ),
    }
