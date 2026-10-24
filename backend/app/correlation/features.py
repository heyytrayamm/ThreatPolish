"""Behavioral feature extraction for correlation.

A *session* is the unit of analysis: an ordered sequence of events that share a
session identifier.  Events without a session identifier become their own
singleton session rather than being merged on IP address, because co-location
on an IP is not evidence of a common actor.

All features are derived only from fields the pipeline has already normalized,
so this module never interprets raw attacker input directly.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable

from ..core.security import parse_iso

MAX_INTERARRIVALS = 200
MAX_SEQUENCE = 500
CORPUS_MIN_SESSIONS = 10

# Session identifiers become part of relationship keys.  Ingestion rejects
# control characters outright; this is the second line of defence for rows that
# were stored before that check existed, and it degrades to a one-event session
# instead of rewriting the identifier into a value that could collide.
_UNSAFE_ID_RE = re.compile(r"[\x00-\x1f\x7f]")


@dataclass
class CorrelationContext:
    """Corpus-relative evidence weights for one correlation run.

    A username, client signature or command trigram that appears in most
    sessions is not strong evidence that two sessions share an actor.  The
    context records document frequency per feature field and marks tokens as
    informative only when they are not ubiquitous in the current window.

    This is a property of the analysed window, not of the algorithm version,
    and it is recorded in every correlation run for reproducibility.
    """

    n_sessions: int
    document_frequency: dict[str, dict[str, int]]
    informative_threshold: int
    version: str = "corr-context-1.1.0"
    # Memoised per field: the ratio is a property of the window, and scoring
    # asks for it once per compared pair.
    specificity_cache: dict[str, float] = field(default_factory=dict)

    @classmethod
    def from_sessions(cls, sessions: Iterable["Session"]) -> "CorrelationContext":
        items = list(sessions)
        fields: dict[str, dict[str, int]] = {
            "action": {},
            "command": {},
            "category": {},
            "endpoint": {},
            "username": {},
            "indicator": {},
            "client": {},
        }
        for session in items:
            resolutions = action_resolutions(session.actions)
            tokens = {
                "action": set().union(*resolutions.values()) if resolutions else set(),
                "command": set(session.commands),
                "category": set(session.categories),
                "endpoint": set(session.endpoints),
                "username": session.usernames,
                "indicator": session.indicators,
                "client": session.clients,
            }
            for family, values in tokens.items():
                for token in values:
                    fields[family][token] = fields[family].get(token, 0) + 1
        # Document frequency is unreliable on a handful of sessions: with fewer
        # than CORPUS_MIN_SESSIONS, every token in the window would look
        # ubiquitous and the corpus filter would erase all evidence.
        if len(items) < CORPUS_MIN_SESSIONS:
            threshold = len(items)
        else:
            threshold = max(3, int(0.25 * len(items)))
        return cls(
            n_sessions=len(items),
            document_frequency=fields,
            informative_threshold=threshold,
        )

    def specificity(self, fields: Iterable[str]) -> float:
        """Share of this window's tokens that survive the ubiquity filter.

        A field whose tokens are almost all ubiquitous (``uname``, ``root``, a
        stock client) cannot distinguish sessions in this window, however well
        two sessions agree on it.  The ratio says how much a family is worth
        here, so the family weight can follow the corpus instead of assuming
        every deployment has equally informative telemetry.
        """
        ratios = []
        for name in fields:
            if name not in self.specificity_cache:
                tokens = self.document_frequency.get(name) or {}
                if not tokens:
                    continue
                informative = sum(
                    1 for count in tokens.values() if count <= self.informative_threshold
                )
                self.specificity_cache[name] = informative / len(tokens)
            ratios.append(self.specificity_cache[name])
        if not ratios:
            return 1.0
        return sum(ratios) / len(ratios)

    def df(self, field: str, token: str) -> int:
        return self.document_frequency.get(field, {}).get(token, 0)

    def is_informative(self, field: str, token: str) -> bool:
        if self.n_sessions == 0:
            return True
        return self.df(field, token) <= self.informative_threshold

    def weight(self, field: str, token: str) -> float:
        return math.log((self.n_sessions + 1) / (self.df(field, token) + 1)) + 1.0

    def summary(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "n_sessions": self.n_sessions,
            "informative_threshold": self.informative_threshold,
            "token_counts": {
                field: len(values) for field, values in self.document_frequency.items()
            },
            "specificity": {
                field: round(self.specificity([field]), 4)
                for field in self.document_frequency
            },
        }

    def fingerprint(self) -> str:
        """Stable hash of everything a pair score depends on outside the pair.

        Document frequencies, the ubiquity threshold and the number of sessions
        all move every pair's corpus-relative weights, so a change in any of
        them invalidates cached decisions.  The summary only records token
        cardinalities and would not detect a frequency shift, hence the full
        table here.
        """
        payload = {
            "version": self.version,
            "n_sessions": self.n_sessions,
            "informative_threshold": self.informative_threshold,
            "document_frequency": self.document_frequency,
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()


@dataclass
class Session:
    id: str
    source_ips: set[str] = field(default_factory=set)
    modules: set[str] = field(default_factory=set)
    targets: set[str] = field(default_factory=set)
    event_ids: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    categories: Counter[str] = field(default_factory=Counter)
    endpoints: Counter[str] = field(default_factory=Counter)
    usernames: set[str] = field(default_factory=set)
    clients: set[str] = field(default_factory=set)
    indicators: set[str] = field(default_factory=set)
    commands: list[str] = field(default_factory=list)
    auth_attempts: int = 0
    auth_failures: int = 0
    auth_successes: int = 0
    severity_max: str = "info"
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    hours: Counter[int] = field(default_factory=Counter)
    interarrivals: list[float] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        if not self.first_seen or not self.last_seen:
            return 0.0
        return max(0.0, (self.last_seen - self.first_seen).total_seconds())

    @property
    def primary_ip(self) -> str:
        return sorted(self.source_ips)[0] if self.source_ips else ""

    def hour_profile(self) -> list[float]:
        total = sum(self.hours.values())
        if not total:
            return [0.0] * 24
        return [self.hours.get(hour, 0) / total for hour in range(24)]

    def fingerprint(self) -> str:
        """Hash of every field ``compare`` reads from this session.

        Two sessions with the same fingerprint would score identically against
        any third session, which is what makes it safe to reuse a stored pair
        decision.  Fields no scoring component reads (targets, auth counters)
        are omitted so a redundant event does not invalidate the cache.
        """
        payload = {
            "actions": self.actions,
            "commands": self.commands,
            "categories": dict(sorted(self.categories.items())),
            "endpoints": dict(sorted(self.endpoints.items())),
            "usernames": sorted(self.usernames),
            "clients": sorted(self.clients),
            "indicators": sorted(self.indicators),
            "source_ips": sorted(self.source_ips),
            "event_count": len(self.event_ids),
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "hours": dict(sorted(self.hours.items())),
            "interarrivals": self.interarrivals,
            "severity_max": self.severity_max,
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

    def to_summary(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source_ips": sorted(self.source_ips),
            "modules": sorted(self.modules),
            "targets": sorted(self.targets),
            "event_count": len(self.event_ids),
            "event_ids": self.event_ids[:100],
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "duration_seconds": round(self.duration_seconds, 3),
            "actions": self.actions[:200],
            "categories": dict(self.categories),
            "endpoints": dict(self.endpoints),
            "usernames": sorted(self.usernames),
            "auth": {
                "attempts": self.auth_attempts,
                "failures": self.auth_failures,
                "successes": self.auth_successes,
            },
            "severity_max": self.severity_max,
            "indicators": sorted(self.indicators),
            "command_shapes": self.commands[:50],
        }


def build_sessions(events: Iterable[dict[str, Any]]) -> dict[str, Session]:
    sessions: dict[str, Session] = {}
    ordered = sorted(
        events, key=lambda item: (item.get("occurred_at", ""), item.get("id", ""))
    )
    for event in ordered:
        session_id = event.get("session_id")
        if not session_id or _UNSAFE_ID_RE.search(str(session_id)):
            session_id = f"evt:{event['id']}"
        session = sessions.setdefault(session_id, Session(id=session_id))
        session.modules.add(event.get("source_module", "unknown"))
        if event.get("source_ip"):
            session.source_ips.add(event["source_ip"])
        if event.get("target_id"):
            session.targets.add(event["target_id"])
        if event.get("id"):
            session.event_ids.append(event["id"])

        features = event.get("features") or {}
        provenance = event.get("provenance") or {}
        occurred = parse_iso(event["occurred_at"]) if event.get("occurred_at") else None
        if occurred:
            if session.first_seen is None or occurred < session.first_seen:
                session.first_seen = occurred
            if session.last_seen is None or occurred > session.last_seen:
                session.last_seen = occurred
            session.hours[occurred.hour] += 1
            if len(session.interarrivals) < MAX_INTERARRIVALS and len(session.event_ids) > 1:
                previous = _previous_time(session, event["id"])
                if previous is not None:
                    delta = (occurred - previous).total_seconds()
                    if delta >= 0:
                        session.interarrivals.append(min(delta, 86_400.0))

        action = str(features.get("action") or "").strip()
        if action:
            session.actions.append(action[:120])
            if len(session.actions) > MAX_SEQUENCE:
                session.actions = session.actions[-MAX_SEQUENCE:]

        category = str(features.get("category") or "").strip()
        if category:
            session.categories[category] += 1

        endpoint = features.get("path_template") or features.get("check_id")
        if endpoint:
            session.endpoints[str(endpoint)[:120]] += 1

        for name in (features.get("username"),):
            if name:
                session.usernames.add(str(name).lower()[:64])
        for client in (features.get("client"), features.get("user_agent")):
            if client:
                session.clients.add(_normalize_client(str(client)))

        for indicator in provenance.get("indicators") or []:
            if indicator:
                session.indicators.add(str(indicator)[:200])

        command_shape = features.get("command_shape")
        if command_shape:
            session.commands.append(str(command_shape)[:300])

        if features.get("auth_attempt"):
            session.auth_attempts += 1
            if features.get("success"):
                session.auth_successes += 1
            else:
                session.auth_failures += 1

        severity = str(event.get("severity", "info"))
        if _severity_rank(severity) > _severity_rank(session.severity_max):
            session.severity_max = severity

        _recompute_interarrivals(session)
        session._last_event_time = occurred  # type: ignore[attr-defined]

    return dict(sorted(sessions.items()))


def _previous_time(session: Session, current_event_id: str) -> datetime | None:
    return getattr(session, "_last_event_time", None)


def _recompute_interarrivals(session: Session) -> None:
    # Interarrivals are appended incrementally above; this hook exists so the
    # ordering invariant is explicit and testable.
    if len(session.interarrivals) > MAX_INTERARRIVALS:
        session.interarrivals = session.interarrivals[-MAX_INTERARRIVALS:]


def _normalize_client(value: str) -> str:
    lowered = value.strip().lower()[:120]
    for token in ("python-requests", "curl", "wget", "libwww-perl", "go-http-client", "njrat", "masscan", "nmap"):
        if token in lowered:
            return token
    return lowered.split(" ", 1)[0][:60]


def _severity_rank(value: str) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(value, 0)


def action_ngrams(actions: list[str], n: int = 3) -> set[str]:
    if not actions:
        return set()
    if len(actions) < n:
        return {"|".join(actions)}
    return {"|".join(actions[index : index + n]) for index in range(len(actions) - n + 1)}


def action_resolutions(actions: list[str]) -> dict[str, set[str]]:
    """Action sets at one-, two- and three-token resolution.

    Fixed trigrams fragment when a single command is inserted or omitted, so
    sequence comparison blends three resolutions instead of relying on one.
    """
    return {
        "unigram": {f"a1:{action}" for action in actions},
        "bigram": {f"a2:{token}" for token in action_ngrams(actions, 2)},
        "trigram": {f"a3:{token}" for token in action_ngrams(actions, 3)},
    }


def jaccard(left: set[str], right: set[str]) -> float:
    if not left and not right:
        return 0.0
    union = left | right
    return len(left & right) / len(union) if union else 0.0


def weighted_jaccard(left: set[str], right: set[str], weights: Any) -> float:
    if not left or not right:
        return 0.0
    union = left | right
    union_weight = sum(float(weights(token)) for token in union)
    if not union_weight:
        return 0.0
    shared_weight = sum(float(weights(token)) for token in (left & right))
    return max(0.0, min(1.0, shared_weight / union_weight))


def weighted_cosine(left: Counter[str], right: Counter[str], weights: Any) -> float:
    if not left or not right:
        return 0.0
    shared = set(left) & set(right)
    dot = sum(left[key] * right[key] * float(weights(key)) for key in shared)
    left_norm = math.sqrt(sum((value ** 2) * float(weights(key)) for key, value in left.items()))
    right_norm = math.sqrt(sum((value ** 2) * float(weights(key)) for key, value in right.items()))
    if not left_norm or not right_norm:
        return 0.0
    return max(0.0, min(1.0, dot / (left_norm * right_norm)))


def cosine_counts(left: Counter[str], right: Counter[str]) -> float:
    if not left or not right:
        return 0.0
    dot = sum(value * right.get(key, 0) for key, value in left.items())
    left_norm = math.sqrt(sum(value * value for value in left.values()))
    right_norm = math.sqrt(sum(value * value for value in right.values()))
    if not left_norm or not right_norm:
        return 0.0
    return max(0.0, min(1.0, dot / (left_norm * right_norm)))


def histogram_similarity(left: list[float], right: list[float]) -> float:
    """1 - total variation distance between two normalized histograms."""
    if len(left) != len(right) or not left:
        return 0.0
    distance = 0.5 * sum(abs(a - b) for a, b in zip(left, right, strict=True))
    return max(0.0, min(1.0, 1.0 - distance))


def rhythm_similarity(left: list[float], right: list[float]) -> float:
    """Compare median interarrival rhythm on a log scale."""
    if not left or not right:
        return 0.0
    a = math.log1p(_median(left))
    b = math.log1p(_median(right))
    scale = max(a, b, 1.0)
    return max(0.0, 1.0 - abs(a - b) / scale)


def _median(values: list[float]) -> float:
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2
