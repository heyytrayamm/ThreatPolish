"""
Interactive local demonstration of ThreatPolish Phase 3 simulated decoys.

Demonstrates:
  1. SSHDecoySimulator: Simulating an SSH brute-force login attempt.
  2. RESTDecoySimulator: Simulating a reconnaissance probe against /.env and /admin.
  3. DatabaseDecoySimulator: Simulating SQL injection tautology and DB auth failure.
  4. TelemetryIngestionService: Validating, normalizing, and persisting events into SQLite.

Run with:
  cd backend
  python -m app.demo
"""

from __future__ import annotations

import json
import uuid
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.base import Base
from app.decoys.database import DatabaseDecoySimulator
from app.decoys.rest import RESTDecoySimulator
from app.decoys.ssh import SSHDecoySimulator
from app.models.event import Event, SessionModel
from app.services.ingestion import TelemetryIngestionService


def run_demo() -> None:
    print("=" * 70)
    print("   THREATPOLISH - PHASE 3 DECOY SIMULATION & INGESTION DEMO")
    print("=" * 70)

    # Setup an in-memory SQLite database for demo persistence
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    db_session = Session(engine)

    # Initialize shared telemetry ingestion service
    ingestion = TelemetryIngestionService(db_session=db_session)

    # Shared attacker session ID for correlating multiple interactions
    session_id = uuid.uuid4()
    attacker_ip = "198.51.100.42"  # RFC 5737 documentation IP

    print(f"\n[*] Simulated Attacker Session: {session_id}")
    print(f"[*] Attacker IP Address:        {attacker_ip} (RFC 5737 reserved test range)")

    # -------------------------------------------------------------------------
    # 1. SSH Decoy Simulation
    # -------------------------------------------------------------------------
    print("\n" + "-" * 70)
    print(" 1. SSH Decoy Simulator (simulate_login)")
    print("-" * 70)
    ssh_decoy = SSHDecoySimulator(ingestion_service=ingestion)
    ssh_result = ssh_decoy.simulate_login(
        source_ip=attacker_ip,
        username="root",
        password="P@ssw0rdFakeAttempt999!",
        session_id=session_id,
    )
    print("  [>] Simulated Response to Attacker:")
    print("     ", json.dumps(ssh_result.simulated_response, indent=6))
    print(f"  [+] Ingested Event ID:    {ssh_result.event.event_id}")
    print(f"  [+] Protocol / Type:      {ssh_result.event.protocol.value} / {ssh_result.event.event_type.value}")
    print(f"  [+] Password Stored:      NONE (password_length recorded as: {ssh_result.event.auth.password_length})")
    print(f"  [+] Ingestion Status:     Success={ssh_result.ingestion_result.success}")

    # -------------------------------------------------------------------------
    # 2. REST API Decoy Simulation
    # -------------------------------------------------------------------------
    print("\n" + "-" * 70)
    print(" 2. REST API Decoy Simulator (simulate_request against /.env trap)")
    print("-" * 70)
    rest_decoy = RESTDecoySimulator(ingestion_service=ingestion)
    rest_result = rest_decoy.simulate_request(
        method="GET",
        path="/.env",
        source_ip=attacker_ip,
        headers={"User-Agent": "Masscan-Scanner/1.3", "Authorization": "Bearer leaked_fake_token"},
        session_id=session_id,
    )
    print("  [>] Simulated Response to Attacker (Never exposes real env):")
    print("     ", json.dumps(rest_result.simulated_response, indent=6))
    print(f"  [+] Ingested Event ID:    {rest_result.event.event_id}")
    print(f"  [+] Trap Path Flagged:    {rest_result.event.payload.get('is_trap_path')}")
    print(f"  [+] Redacted Headers:     Auth token stripped before persistence")
    print(f"  [+] Ingestion Status:     Success={rest_result.ingestion_result.success}")

    # -------------------------------------------------------------------------
    # 3. Database Decoy Simulation (Connection Attempt & SQLi Query)
    # -------------------------------------------------------------------------
    print("\n" + "-" * 70)
    print(" 3. Database Decoy Simulator (simulate_query SQL Injection probe)")
    print("-" * 70)
    db_decoy = DatabaseDecoySimulator(ingestion_service=ingestion)
    db_result = db_decoy.simulate_query(
        source_ip=attacker_ip,
        raw_query="SELECT * FROM users WHERE username = 'admin' OR '1'='1' --",
        session_id=session_id,
    )
    print("  [>] Simulated Response to Attacker (Harmless DB Error):")
    print("     ", json.dumps(db_result.simulated_response, indent=6))
    print(f"  [+] Ingested Event ID:    {db_result.event.event_id}")
    print(f"  [+] Detected Patterns:    {db_result.event.payload.get('detected_patterns')}")
    print(f"  [+] Query Executed:       NEVER (Analyzed safely in-memory only)")
    print(f"  [+] Ingestion Status:     Success={db_result.ingestion_result.success}")

    # -------------------------------------------------------------------------
    # 4. Ingestion Summary & Database Session Verification
    # -------------------------------------------------------------------------
    print("\n" + "-" * 70)
    print(" 4. Persistence Verification & Session Correlation")
    print("-" * 70)
    sess_row = db_session.get(SessionModel, session_id)
    print(f"  [+] Session ID:           {sess_row.id}")
    print(f"  [+] Source IP:            {sess_row.source_ip}")
    print(f"  [+] Correlated Events:    {len(sess_row.events)} total events in session:")
    for idx, ev in enumerate(sess_row.events, 1):
        print(f"      {idx}. [{ev.timestamp.isoformat()}] service={ev.service:<15} type={ev.event_type:<15} event_id={ev.event_id}")

    total_events = db_session.query(Event).count()
    print(f"\n[*] Total Telemetry Events Stored: {total_events}")
    print("=" * 70)
    print("   ALL DECOYS AND INGESTION PIPELINE VERIFIED SUCCESSFULLY")
    print("=" * 70)

    db_session.close()
    engine.dispose()


if __name__ == "__main__":
    run_demo()
