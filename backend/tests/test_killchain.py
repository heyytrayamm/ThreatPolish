"""Tactic coverage is derived from recorded categories, never assumed."""

from __future__ import annotations

from app.correlation.killchain import TOTAL_WEIGHT, campaign_coverage, classify
from app.correlation.scoring import ALGORITHM_VERSION


def test_recon_is_external_until_access_succeeds():
    probing = classify({"http_probe": 4}, {})
    assert set(probing) == {"reconnaissance"}

    without_access = classify({"recon": 3}, {"attempts": 4, "failures": 4})
    assert "reconnaissance" in without_access
    assert "discovery" not in without_access

    after_access = classify({"recon": 3}, {"attempts": 4, "successes": 1, "failures": 3})
    assert "discovery" in after_access
    assert "reconnaissance" not in after_access


def test_each_command_family_maps_to_its_own_tactic():
    observed = classify(
        {
            "execution": 1,
            "persistence": 2,
            "privilege": 1,
            "cleanup": 1,
            "credential": 2,
            "lateral": 1,
            "download": 3,
            "mining": 1,
            "destruction": 1,
        },
        {"attempts": 2, "failures": 2},
    )
    for tactic in (
        "execution",
        "persistence",
        "privilege_escalation",
        "defense_evasion",
        "credential_access",
        "lateral_movement",
        "command_and_control",
        "impact",
        "initial_access",
    ):
        assert tactic in observed, tactic
    # Mining and destruction collapse into one impact entry with two reasons.
    assert len(observed["impact"]) == 2


def test_unclassified_commands_still_count_as_execution():
    observed = classify({"other": 2}, {})
    assert observed["execution"] == ["2 unclassified command(s)"]


def test_campaign_coverage_reports_breadth_and_weight_separately():
    sessions = [
        {
            "id": "sess-a",
            "categories": {"http_probe": 6},
            "auth": {},
        },
        {
            "id": "sess-b",
            "categories": {"recon": 2, "credential": 1},
            "auth": {"attempts": 5, "failures": 4, "successes": 1},
        },
        {
            "id": "sess-c",
            "categories": {"destruction": 1},
            "auth": {},
        },
    ]
    result = campaign_coverage(sessions, asset_criticality="high")

    assert result["observed"] == [
        "reconnaissance",
        "initial_access",
        "credential_access",
        "discovery",
        "impact",
    ]
    assert result["coverage"] == round(5 / 11, 3)
    assert result["observed_weight"] == 1 + 3 + 4 + 2 + 5
    assert result["total_weight"] == TOTAL_WEIGHT
    assert result["risk_weighted_coverage"] == round(15 / TOTAL_WEIGHT, 3)
    assert result["furthest"] == {"key": "impact", "label": "Impact"}
    assert result["asset_criticality"] == "high"
    assert "collection" in result["note"]

    impact = next(item for item in result["tactics"] if item["key"] == "impact")
    assert impact["session_count"] == 1
    assert impact["sessions"] == ["sess-c"]
    discovery = next(item for item in result["tactics"] if item["key"] == "discovery")
    assert discovery["session_count"] == 1
    assert discovery["observed"] is True


def test_equal_weights_report_the_later_tactic_as_furthest():
    result = campaign_coverage(
        [
            {
                "id": "sess-progress",
                "categories": {"privilege": 1, "lateral": 1, "download": 1},
                "auth": {},
            }
        ]
    )
    assert result["furthest"] == {
        "key": "command_and_control",
        "label": "Command and control",
    }


def test_campaign_without_activity_has_no_coverage_or_furthest_tactic():
    result = campaign_coverage([{"id": "sess-quiet", "categories": {}, "auth": {}}])
    assert result["observed"] == []
    assert result["coverage"] == 0.0
    assert result["risk_weighted_coverage"] == 0.0
    assert result["furthest"] is None
    assert all(not item["observed"] for item in result["tactics"])


def test_campaign_detail_includes_recorded_tactic_coverage(client):
    from app.core.security import iso, utcnow
    from app.correlation.repository import get_campaign
    from app.db.database import connection, dumps
    from app.db.schema import campaigns, graph_edges, graph_nodes

    now = utcnow()
    campaign_id = "cmp_killchain"
    sessions = {
        "alpha": {"categories": {"http_probe": 8}, "auth": {"attempts": 3, "failures": 3}},
        "beta": {"categories": {"download": 2, "recon": 1}, "auth": {"attempts": 3, "successes": 1}},
    }
    with connection() as conn:
        conn.execute(
            campaigns.insert().values(
                id=campaign_id,
                name="tactic test",
                status="candidate",
                confidence=0.88,
                summary="two linked sessions",
                evidence=dumps({"sessions": list(sessions), "ips": ["198.51.100.12"]}),
                created_at=iso(now),
                updated_at=iso(now),
                algorithm_version=ALGORITHM_VERSION,
                member_count=2,
                ip_count=1,
            )
        )
        for label, props in sessions.items():
            conn.execute(
                graph_nodes.insert().values(
                    id=f"session:{label}",
                    kind="session",
                    label=label,
                    props=dumps(
                        {
                            "source_ips": ["198.51.100.12"],
                            "event_count": 5,
                            "severity_max": "medium",
                            **props,
                        }
                    ),
                    first_seen=iso(now),
                    last_seen=iso(now),
                )
            )
        conn.execute(
            graph_edges.insert().values(
                id="edg_killchain",
                kind="session_similarity",
                src_id="session:alpha",
                dst_id="session:beta",
                confidence=0.88,
                score=0.9,
                evidence=dumps({"explanation": "shared transfer tooling"}),
                contradictions=dumps([]),
                algorithm_version=ALGORITHM_VERSION,
                created_at=iso(now),
                updated_at=iso(now),
                expires_at=None,
                status="active",
                campaign_id=campaign_id,
            )
        )

    detail = get_campaign(campaign_id)
    coverage = detail["kill_chain"]
    assert "initial_access" in coverage["observed"]
    assert "command_and_control" in coverage["observed"]
    assert coverage["furthest"] == {
        "key": "command_and_control",
        "label": "Command and control",
    }
    # Four of eleven tactics, carrying ten of the thirty-six impact points.
    assert coverage["coverage"] == round(4 / 11, 3)
    assert coverage["risk_weighted_coverage"] == round(10 / 36, 3)
