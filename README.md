# ThreatPolish

Evidence-guided campaign correlation with uncertainty-aware adaptive deception.

ThreatPolish is a self-hosted security platform that ingests telemetry from
authorized decoys and assessments, correlates sessions across IP addresses using
explicit behavioural evidence, explains every relationship it proposes, and can
request additional observation through isolated decoy profiles when the evidence
is genuinely uncertain.

It does not claim to identify attackers. It produces **relationship hypotheses**
with recorded evidence, confidence, contradictions and expiry.

## What is implemented

| Area | Implementation |
| --- | --- |
| Telemetry | Versioned event contract, validation, normalization, enrichment, dedup, quarantine, retention, source health |
| Deception | HTTP/API decoy with real capture, Cowrie JSON adapter with at-least-once tailing, DB-backed decoy profiles |
| Correlation | Session features, corpus-relative evidence weighting, six evidence families, contradictions, anchors, graph, campaign candidates, analyst feedback |
| Adaptive investigation | Uncertainty-driven decoy selection, bounded activation, before/after re-evaluation, honest outcome reporting |
| Risk | Separated severity, confidence and asset risk with a published formula and per-factor explanation |
| Web security | Authorization scopes, SSRF guards, non-destructive passive checks, opt-in active probes, findings with remediation |
| Digital assets | Approved market-data adapter, provenance and freshness, explainable asset risk, no wallet secrets accepted |
| Response | Policy thresholds, approval, expiry, rollback, emergency disable, audit trail |
| Dashboard | React/TypeScript views for events, campaigns, graph, deception, findings, assets, responses and administration |
| Operations | CLI, migrations, Docker/Compose, health checks, runbooks, evaluation harness |

## Quick start (single node, SQLite)

Requirements: Python 3.12+, Node 20+.

```bash
cp .env.example .env
# Edit .env: set TP_JWT_SECRET (32+ chars) and, optionally,
# TP_BOOTSTRAP_ADMIN_EMAIL / TP_BOOTSTRAP_ADMIN_PASSWORD.

cd backend
pip install -r requirements.txt        # FastAPI, SQLAlchemy, Pydantic, httpx
python -m app.cli create-admin --email you@example.com   # or use bootstrap env
uvicorn app.main:app --host 127.0.0.1 --port 8000

# In another terminal
cd frontend
npm install
npm run build
```

The built dashboard is served by the API at `http://127.0.0.1:8000/`.
Interactive API documentation is at `/docs`.

For dashboard development, run `npm run dev` and open `http://127.0.0.1:5173`;
Vite proxies `/api` to the backend.

## Docker Compose

```bash
cp .env.example .env          # set TP_JWT_SECRET, TP_DB_PASSWORD, bootstrap admin
docker compose up --build -d
docker compose --profile honeypot up -d   # optional Cowrie sensor
```

The application listens on `127.0.0.1:8000`; PostgreSQL is used by default in
Compose and is not published. The HTTP decoy runs as a separate process so it
can be isolated:

```bash
cd backend
python -m app.cli decoy --host 0.0.0.0 --port 8022
```

## Connecting sensors

1. Create an ingestion token (shown once):

```bash
cd backend
python -m app.cli create-token --name decoy-1 --role sensor
```

2. Send events:

```bash
curl -s http://127.0.0.1:8000/api/v1/ingest/events \
  -H "X-Agent-Token: tp_..." \
  -H "Content-Type: application/json" \
  -d '{"schema_version":"1.0","occurred_at":"2026-01-01T00:00:00Z","source_module":"honeypot","event_type":"honeypot.ssh.login_failed","source_ip":"203.0.113.9","session_id":"sess-1","severity":"low","provenance":{"collector":"cowrie","source":"decoy-1","reliability":0.8,"synthetic":false},"features":{"username":"root","success":false,"client_version":"SSH-2.0-libssh_0.9.6"}}'
```

3. Cowrie:

```bash
python -m app.cli cowrie-tail --path /var/log/cowrie/cowrie.json
```

The tailer persists its offset, survives rotation and relies on event
deduplication for at-least-once delivery.

4. HTTP decoy:

```bash
python -m app.cli decoy --host 127.0.0.1 --port 8022
```

Decoy interactions become telemetry automatically. The decoy never executes
input, never serves files and never makes outbound connections.

## Roles

| Role | Capability |
| --- | --- |
| `admin` | Users, tokens, scopes, responses approval, audit, all analysis |
| `analyst` | Correlation, investigations, feedback, assessments, response requests |
| `viewer` | Read-only dashboards |
| `sensor` | Event ingestion only |

Scope creation is admin-only by design: an explicit human authorization record
is required before any target can be assessed.

## Testing

```bash
cd backend
python -m pytest -q
```

65 tests cover the event contract, ingestion, deduplication, quarantine,
retention, the decoy, Cowrie parsing, correlation gates, campaign formation,
adaptive investigation, risk separation, web assessment authorization and SSRF
guards, crypto scoring, response policy, authorization boundaries, injection
resistance and the end-to-end journey.

## Research evaluation

```bash
cd backend
python scripts/evaluate.py
```

Results are written to `docs/research/evaluation-results.md` and
`docs/research/evaluation-results.json`. On 63 sessions and 1,953 pairs the
proposed method reaches precision 1.00 / recall 0.78 (seed 7) and precision 1.00
/ recall 0.56 (seed 2026) with no false positives, against a rule baseline at
precision 0.07 / recall 0.94 with roughly 27% false positives. Campaign-level
exact recovery is 8 of 12 and 4 of 12. The deliberately hard subset, the
adaptive experiment and all limitations are reported alongside the headline
numbers. Nothing is hard-coded: the report is generated from a seeded benchmark.

## Documentation

- `docs/00-repository-audit.md` — starting state and constraints
- `docs/01-novelty-review.md` — prior work, gap and falsifiable hypothesis
- `docs/02-architecture.md` — components, data flow and interface contracts
- `docs/03-threat-model.md` — assets, actors, boundaries and controls
- `docs/04-event-contract.md` — versioned schema and normalization
- `docs/05-api.md` — endpoints and permissions
- `docs/06-testing-and-evaluation.md` — strategy, results and known gaps
- `docs/07-operations.md` — deployment, backup, recovery and incident runbooks
- `docs/08-implementation-status.md` — stage-by-stage delivery evidence

## Security and ethics

ThreatPolish is for authorized defensive use. The web assessment module will
only contact hosts covered by an unexpired authorization scope, refuses to
resolve to private/loopback/link-local addresses unless explicitly enabled for
local testing, and performs no exploitation. Decoys must be deployed on isolated
network segments with no route to production systems; the Compose file provides
a starting point, not a substitute for network policy.

## License

Proprietary and confidential. Copyright (c) 2026 ThreatPolish Team. All rights
reserved. No use, copying, modification or distribution is permitted without
prior written permission from the Team. See [LICENSE](LICENSE). Third-party
dependencies remain under their own licenses.

The software includes deception and assessment capability and must be used only
against systems for which the operator has explicit authorisation.
