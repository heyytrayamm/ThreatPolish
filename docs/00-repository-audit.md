# Repository audit (Stage 0)

Date: 2026-10-23. Audited commit: `a38b70f` ("Initial commit").

## What existed

```
.
├── LICENSE      MIT, "Copyright (c) 2026 Trayam Roy"
└── README.md    one line: "Custom decoy honeypot built for real-time threat
                 detection, unauthorized interaction capture, and attacker
                 behavioral logging."
```

There were no source files, tests, configuration, dependencies or CI. Git
history contained a single commit. The repository name and description describe
an intent (a custom decoy honeypot), not an implementation.

## Baseline execution

- Test suite: none. `pytest` had nothing to collect.
- Application: nothing to run.
- Dependency audit: no dependencies to audit.
- Resource use: zero.

There was therefore no working functionality to preserve and no execution path
to repair. A greenfield build is justified by the absence of code, not by a
preference for a rewrite.

## Environment constraints measured on the build host

| Constraint | Value | Consequence |
| --- | --- | --- |
| CPU | 16 cores | Parallel test and benchmark runs are practical |
| Memory | 30 GiB | No need for heavyweight models |
| Disk | 113 GiB free | Local datasets and containers fit |
| Python | 3.12.3 | FastAPI, SQLAlchemy 2.x, Pydantic 2.x available |
| Node | 22.16 | Vite/React build available |
| PostgreSQL | not installed | Development and tests run on SQLite; production schema is portable |
| Docker | not installed | Deployment files are provided but could not be executed here |
| Redis | not installed | No cache/broker dependency introduced |

## Decisions

1. **Modular monolith.** One Python service with explicit module boundaries.
   The workload is modest, the data model is shared, and a distributed
   deployment would add failure modes without measured benefit.
2. **SQLite for development and tests, PostgreSQL for production.** The schema
   uses portable types and ISO-8601 UTC text timestamps. This kept the test
   suite fast without pretending SQLite is the production database.
3. **No heavyweight ML.** The contribution is evidence-weighted correlation
   with explicit, auditable rules. A model whose outputs cannot be explained
   would contradict the requirements.
4. **No Redis/Celery.** Correlation runs inline and is bounded; ingestion is
   synchronous with per-record savepoints. A queue can be added later if volume
   demands it.
5. **React + TypeScript dashboard, no UI framework.** Small dependency surface
   and a strict Content-Security-Policy.
6. **CoinGecko public API plus a labelled fixture provider.** The service
   catalog available to this project contained no crypto market-data provider;
   CoinGecko's documented public endpoint is the adapter, with a deterministic
   fixture used by tests and clearly marked as synthetic.

## Feature inventory at audit time

| Capability | Status |
| --- | --- |
| Ingestion pipeline, event contract | missing |
| Honeypot/decoy services | missing |
| Correlation engine, graph, campaigns | missing |
| Adaptive deception | missing |
| Risk scoring | missing |
| Web assessment | missing |
| Digital-asset risk | missing |
| Dashboard | missing |
| Response engine | missing |
| Tests, deployment, documentation | missing |

## Risks identified before building

- **Scope risk.** The specification spans research, engineering and operations.
  The build prioritised a working vertical slice with measured behaviour over
  breadth of unverified features.
- **Evaluation risk.** No public labelled dataset was bundled; the benchmark is
  synthetic and its limitations are reported with the results.
- **Deployment risk.** Docker and PostgreSQL could not be executed on this host,
  so the Compose deployment is documented and statically reviewed but not
  runtime-verified here. The application itself was run against SQLite and
  exercised over HTTP.
