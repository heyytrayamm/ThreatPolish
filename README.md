# ThreatPolish

Custom defensive honeypot platform designed for unauthorized interaction capture, attacker telemetry collection, event normalization, and behavioral logging.

---

## Architecture & Implementation Milestones

- **Phase 1: Foundation & Scaffolding**
  - FastAPI application structure, CORS configuration, health and liveness monitoring endpoints.
  - React + Vite dashboard frontend skeleton.
  - Safe Docker Compose configuration bound strictly to `127.0.0.1`.

- **Phase 2: Event Schema & Database Foundation**
  - Pydantic v2 Canonical Event Schema (`CanonicalEvent` v1.0) with UUID validation, strict UTC timezone enforcement, IP/port constraints, and credential exclusion.
  - SQLAlchemy 2.0 ORM models: `Event`, `SessionModel`, `Alert`, `DetectionRule`, `IngestionFailure`, and `alert_events`.
  - Alembic database migration management.

- **Phase 3: Simulated Decoys & Telemetry Ingestion (Current)**
  - **Reusable Telemetry Ingestion Pipeline (`TelemetryIngestionService`):**
    - Validates events against the canonical schema.
    - Normalizes timestamps to timezone-aware UTC.
    - Idempotently deduplicates event IDs.
    - Automatically manages attacker session correlations (`sessions` table).
    - Safely logs validation failures into `ingestion_failures` with sensitive credentials redacted.
  - **In-Process Simulated Decoys:**
    - **SSH Decoy Simulator (`SSHDecoySimulator`):** Simulates SSH authentication attempts, records submitted usernames and password lengths, returns harmless `Permission denied` responses, never opens a real socket, and never executes commands.
    - **REST API Decoy Simulator (`RESTDecoySimulator`):** Simulates reconnaissance trap endpoints (`/admin`, `/wp-admin`, `/.env`, etc.), strips authorization tokens, and returns mock 401/403/404 responses without exposing actual server environment or files.
    - **Database Decoy Simulator (`DatabaseDecoySimulator`):** Simulates database authentication and detects SQL injection signatures (`' OR '1'='1'`, `UNION SELECT`, `DROP TABLE`), returns mock PostgreSQL error codes (`28P01`, `42501`), and never connects to or executes against any real database.

---

## Defensive Security Guarantees

1. **No Real Network Listeners for Decoys:** In this phase, all decoys operate strictly as in-process Python simulators. No open ports or public interfaces are exposed.
2. **Strict Credential Exclusion:** Raw passwords, hashes, API keys, and authorization headers are never logged or persisted. The schema captures only `password_length` and `auth_outcome`.
3. **No Execution:** Shell commands and SQL statements submitted to simulated decoys are analyzed in-memory for signatures and immediately discarded.

---

## Running the Decoy Simulation Demo

To demonstrate the three simulated decoys and verify event ingestion in real time:

```powershell
cd backend
.\.venv\Scripts\python -m app.demo
```

---

## Running Tests

To run the complete backend test suite (93 tests covering schemas, models, migrations, ingestion pipeline, and decoy simulators):

```powershell
cd backend
.\.venv\Scripts\pytest -v --tb=short
```

To run only the Phase 3 simulator and ingestion tests:

```powershell
cd backend
.\.venv\Scripts\pytest -v tests/test_ingestion_service.py tests/test_decoys.py
```
