# Contributing

## Before you start

This repository is proprietary; see [LICENSE](LICENSE). Contributions become the
property of the ThreatPolish Team, and contributors must have the right to assign
them. By opening a pull request you confirm that assignment.

Use the platform only on systems you are authorized to assess. Never add code
that scans, exploits or modifies a target without an explicit scope check.

## Development setup

Requirements: Python 3.12+, Node 20+.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements-dev.txt
npm --prefix frontend ci --no-audit --no-fund
cp .env.example .env
# Set TP_JWT_SECRET and bootstrap credentials in .env.
```

Run the services:

```bash
make serve          # API on 127.0.0.1:8000
make build          # dashboard into frontend/dist, served by the API
```

## Verification

Run these before every pull request:

```bash
cd backend
ruff check app tests scripts --select F,E9
python -m pytest -q
python scripts/evaluate.py --quick   # when correlation changes
cd ../frontend
npm run build
```

If your change touches deployment files, also run:

```bash
docker compose build
docker compose up -d
curl -fsS http://127.0.0.1:8000/api/v1/health/ready
```

Add tests for behaviour changes. Tests use SQLite; when you change raw SQL, run
the container path against PostgreSQL as well, because the two drivers type
parameters differently.

## Conventions

- Keep modules inside their existing boundary (`api`, `correlation`, `deception`,
  `websec`, `response`, `telemetry`). Do not add a new framework for a small
  concern.
- Treat all sensor input as untrusted. Bound lengths, validate structure and use
  parameterized SQL.
- Every response action must remain explainable, approvable, expiring and
  reversible.
- Never log credentials, tokens or full request bodies.
- Update the relevant document in `docs/` when behaviour, configuration or an
  endpoint changes.
- Commit messages state the reason for the change, not a file list.

## Pull requests

Describe the problem, the chosen approach, the verification performed, and any
limitation that remains. Keep unrelated refactors out of a functional change.
Security-sensitive changes need a short note in `SECURITY.md` if they alter an
operational expectation.
