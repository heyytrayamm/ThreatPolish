"""Operator CLI.

Examples:
    python -m app.cli create-admin --email you@example.com
    python -m app.cli create-token --name cowrie-1 --role sensor
    python -m app.cli decoy --port 8022
    python -m app.cli cowrie-tail --path /var/log/cowrie/cowrie.json
    python -m app.cli correlate --window-hours 72
    python -m app.cli purge
    python -m app.cli purge-graph
"""

from __future__ import annotations

import argparse
import getpass
import sys

from .core.config import get_settings
from .core.logging import configure_logging, get_logger
from .core.security import iso, utcnow
from .db.database import connection, init_db
from .db.schema import events

log = get_logger("cli")


def _create_admin(args: argparse.Namespace) -> int:
    from .auth.users import create_user

    password = args.password or getpass.getpass("Password: ")
    user = create_user(
        email=args.email, name=args.name, role="admin", password=password
    )
    print(f"created administrator {user['email']} ({user['id']})")
    return 0


def _create_user(args: argparse.Namespace) -> int:
    from .auth.users import create_user

    password = args.password or getpass.getpass("Password: ")
    user = create_user(email=args.email, name=args.name, role=args.role, password=password)
    print(f"created {user['role']} {user['email']} ({user['id']})")
    return 0


def _create_token(args: argparse.Namespace) -> int:
    from .auth.users import create_agent_token

    token = create_agent_token(name=args.name, role=args.role)
    print("Store this token now; it will not be shown again.")
    print(f"id:     {token['id']}")
    print(f"prefix: {token['prefix']}")
    print(f"token:  {token['token']}")
    return 0


def _decoy(args: argparse.Namespace) -> int:
    from .deception.http_decoy import start_decoy

    service = start_decoy(host=args.host, port=args.port, profile_name=args.profile)
    print(f"HTTP decoy listening on http://{args.host}:{service.port} (profile {service.profile['name']})")
    try:
        while True:
            import time

            time.sleep(3600)
    except KeyboardInterrupt:
        service.stop()
        print("decoy stopped")
    return 0


def _cowrie_tail(args: argparse.Namespace) -> int:
    from .deception.cowrie_adapter import CowrieTailer

    init_db()
    tailer = CowrieTailer(args.path, state_path=args.state)
    if args.once:
        print(tailer.poll())
        return 0
    try:
        for report in tailer.tail_forever(interval=args.interval):
            if report["read"]:
                print(report)
    except KeyboardInterrupt:
        print("tailer stopped")
    return 0


def _correlate(args: argparse.Namespace) -> int:
    from .correlation.engine import correlate

    init_db()
    result = correlate(window_hours=args.window_hours, trigger="cli", actor="cli")
    print(
        f"run {result['run_id']}: {result['sessions']} sessions, "
        f"{result['campaigns']} campaign candidates, {result['edges_created']} new edges "
        f"in {result['duration_ms']} ms"
    )
    return 0


def _purge(args: argparse.Namespace) -> int:
    settings = get_settings()
    init_db()
    cutoff = utcnow()
    with connection() as conn:
        result = conn.execute(
            events.delete().where(events.c.retention_until < iso(cutoff))
        )
        removed = int(result.rowcount or 0)
    print(f"removed {removed} events past the {settings.retention_days}-day retention window")
    return 0


def _purge_graph(args: argparse.Namespace) -> int:
    from .correlation.repository import purge_graph

    init_db()
    result = purge_graph(days=args.days)
    print(
        f"removed {result['edges']} retired edges, {result['observations']} stale "
        f"observations and {result['nodes']} orphan nodes older than "
        f"{result['days']} days (cutoff {result['cutoff']})"
    )
    return 0


def _display_db_url(url: str) -> str:
    """Never print a password embedded in a database URL."""
    from sqlalchemy.engine import make_url

    try:
        return make_url(url).render_as_string(hide_password=True)
    except Exception:
        return "<configured database>"


def _status(_: argparse.Namespace) -> int:
    from .db.database import schema_version

    init_db()
    settings = get_settings()
    print(f"environment:   {settings.env}")
    print(f"database:      {_display_db_url(settings.db_url)}")
    print(f"schema:        {schema_version()}")
    print(f"retention:     {settings.retention_days} days")
    print(f"graph:         {settings.graph_retention_days} days")
    print(f"decoy enabled: {settings.decoy_enabled}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="threatpolish", description="ThreatPolish operator CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    admin = sub.add_parser("create-admin", help="create an administrator account")
    admin.add_argument("--email", required=True)
    admin.add_argument("--name", default="Administrator")
    admin.add_argument("--password", default=None)
    admin.set_defaults(func=_create_admin)

    user = sub.add_parser("create-user", help="create an account with an explicit role")
    user.add_argument("--email", required=True)
    user.add_argument("--name", required=True)
    user.add_argument("--role", required=True, choices=["admin", "analyst", "viewer", "sensor"])
    user.add_argument("--password", default=None)
    user.set_defaults(func=_create_user)

    token = sub.add_parser("create-token", help="create a sensor API token")
    token.add_argument("--name", required=True)
    token.add_argument("--role", default="sensor", choices=["sensor", "analyst"])
    token.set_defaults(func=_create_token)

    decoy = sub.add_parser("decoy", help="run the HTTP decoy service")
    decoy.add_argument("--host", default="127.0.0.1")
    decoy.add_argument("--port", type=int, default=None)
    decoy.add_argument("--profile", default=None)
    decoy.set_defaults(func=_decoy)

    tail = sub.add_parser("cowrie-tail", help="ingest a Cowrie JSON log")
    tail.add_argument("--path", required=True)
    tail.add_argument("--state", default=None)
    tail.add_argument("--interval", type=float, default=2.0)
    tail.add_argument("--once", action="store_true")
    tail.set_defaults(func=_cowrie_tail)

    correlate = sub.add_parser("correlate", help="run a correlation window")
    correlate.add_argument("--window-hours", type=int, default=None)
    correlate.set_defaults(func=_correlate)

    purge = sub.add_parser("purge", help="delete events past the retention window")
    purge.set_defaults(func=_purge)

    purge_graph = sub.add_parser(
        "purge-graph", help="delete retired graph evidence past the graph retention window"
    )
    purge_graph.add_argument("--days", type=int, default=None)
    purge_graph.set_defaults(func=_purge_graph)

    status = sub.add_parser("status", help="show configuration and schema state")
    status.set_defaults(func=_status)
    return parser


def main(argv: list[str] | None = None) -> int:
    configure_logging(get_settings().log_level)
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
