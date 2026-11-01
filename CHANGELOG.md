# Changelog

All notable changes to this project are recorded here. Dates use ISO 8601.

## 2.0.2 — 2026-11-01

The correlation model is unchanged in what it decides; this release makes it
cheaper to run and harder to make wrong.

### Changed

- A session builds its action sets at one-, two- and three-token resolution once
  and reuses them for every pair it takes part in. Rebuilding the same n-grams
  per pair was the largest repeated cost in a run: measured on this host against
  the same inputs in one process, a pair comparison fell from 294 to 172 µs at 50
  actions, 674 to 243 µs at 200 and 1,695 to 364 µs at 500. Every recorded metric
  — precision, recall, F1, cluster recovery, false positives — reproduces exactly
  across the change.

### Fixed

- A non-finite similarity could reach the family average and be clamped to a
  perfect score by `max`/`min`, which would read as proof of a relationship.
  Non-finite component scores and a non-finite total now collapse to zero, so a
  numeric fault can only under-claim. `tests/test_properties.py` covers NaN and
  both infinities.

### Added

- `tests/test_properties.py` asserts the resolution cache is reused, rebuilt
  when the action list changes, and never changes a decision.

## 2.0.1 — 2026-11-01

A follow-up to the interface release: one deployment defect, the artwork after
the version change, and dependency updates handed to Dependabot.

### Added

- `tests/test_deployment.py` fails when the image command, its health check and
  the Compose service disagree about the port, for the default and for an
  assigned one. The container job also starts the image through Compose with
  `PORT=9099` and waits for readiness there, which is the only check that
  catches an image and a probe that disagree.
- `.github/dependabot.yml` asks for weekly pip, npm, GitHub Actions and Docker
  updates. The audits in CI only report an advisory; they never open a bump.

### Fixed

- `docker-compose.yml` published and probed `8000` while the image bound
  `${PORT:-8000}`, so a deployment that assigned a port was reported unhealthy
  on the port it was serving. The app service passes `PORT` through, publishes
  it and probes the same value.

### Changed

- Screenshots regenerated after the version change.
- Suite times are recorded over two runs rather than a single sample.

## 2.0.0 — 2026-11-01

This release rebuilds the interface. The API surface, scoring model and event
contract are unchanged from 1.0.5; everything below is the workspace around
them, the way it is deployed and the way it is documented.

### Added

- A public landing page at the root for signed-out visitors: what the platform
  does, how correlation works, the evidence model, the quick start and the
  sign-in card on the same page. Privacy Policy and Terms and Conditions open
  without an account (`?view=privacy`, `?view=terms`) and lead back to it.
- Administration creates accounts from the console through `POST /auth/users`:
  name, email, role and a temporary password validated by the same rules the
  CLI applies, with the created account listed in the inventory it was created
  from. `create-user` now has a UI counterpart.
- `scripts/capture_screenshots.py` writes `landing.png` for the signed-out view,
  which is what the README shows instead of the retired login form.
- Render-style deployment: the container reads `PORT` in both its command and
  its health check, so a platform that assigns a port needs no image change.
  The README records the `postgresql+psycopg://` form `TP_DB_URL` needs, because
  the driver is psycopg 3 and a hosted URL arrives as `postgresql://`.
- `docker-compose.yml` passes `PORT` through to the container and publishes and
  probes the same value, so the override can be exercised locally as well. The
  container job runs a smoke test that starts the image through Compose with
  `PORT=9099` and waits for readiness on that port, which is the only check that
  fails if the image and its health check disagree about the port.
- `tests/test_browser.py` drives the landing page, the legal pages and the
  create-account flow in Chrome, and signs in as the account it just created.

### Changed

- The analyst workspace is a horizontal top bar — brand, engine status,
  navigation, theme switch and account — instead of a left rail, collapsing to
  a menu button on a narrow screen. The theme switch moved from the ribbon to
  the bar and reads `Daylight Theme` / `Console Theme`.
- Every view was rebuilt on one token set: Overview, Events, Campaigns (with the
  evidence matrix, acquisition plan and kill-chain coverage), Deception, Web
  findings, Crypto, Responses, Retention, Administration and the account page.
- Inter and JetBrains Mono ship with the bundle (OFL-1.1,
  `frontend/public/fonts`) instead of being fetched from a font CDN, and the
  icon set is redrawn in the palette the console uses.
- The README leads with the logo, lists what this release changed, and shows
  regenerated screenshots for both themes.

### Fixed

- The dashboard Content-Security-Policy no longer names `fonts.googleapis.com`
  or `fonts.gstatic.com`. Nothing in the bundle references either origin, so the
  allowance widened what an injected page could reach without serving a font.
- The screenshot pass matched `.card`, which the redesign renamed to `tp-card`,
  so it crashed on the campaign page; it also captured whatever scroll position
  the sign-in click left behind. It matches both panel classes and frames every
  view from its top.
- The landing page's quick start started the API without building the bundle,
  which is the ordering that answers `dashboard_not_built`.
- `POST /auth/users` had no browser coverage; an account created from the form is
  now signed in with the password that was typed into it.

### Verifying

- The suite passes on SQLite and on PostgreSQL 16.15, `ruff` is clean, the deep
  scan reports no authorization disagreement, no 5xx across its hostile
  requests, no accepted SSRF target and no scope or budget finding, and the
  dashboard builds.

## 1.0.5 — 2026-10-27

### Added

- `tests/test_efficiency.py` makes development scope and read-path cost CI
  gates: every route must be documented, exercised and governed by a permission
  some role holds, every configuration value must appear in `.env.example`, and
  no read endpoint may exceed 20 statements in a request or repeat one statement
  per row. The graph view is pinned to a bounded page that reports truncation.
- `scripts/deepscan.py` gains `--only scope` and `--only efficiency`: the first
  compares served routes, permissions and configuration against the reference,
  the suite and `.env.example`; the second times every read endpoint on the
  evaluation corpus with its statements counted, against a 512 KiB response
  budget, 40 statements and 8 repeats of one statement.

- `backend/scripts/deepscan.py` asks the same questions of every route instead of
  the routes a test happened to cover: it derives each route's permissions from
  its FastAPI dependency closure, calls it as every RBAC role and anonymously,
  then sends hostile parameters, malformed bodies, tampered tokens and SSRF
  targets. It fails on a 5xx, on an authorization decision that disagrees with
  the role matrix, or on a target it should have refused.
- `docs/research/deepscan-results.md` records what that scan measured on this
  host — 57 routes, 285 authorization checks and 0 disagreements; 60 operations
  and 652 hostile requests with no 5xx; 23 SSRF payloads across 9 scopes with no
  target reached — together with the cross-engine suite times, the browser run
  and the write latency measured during a correlation run.
- `tests/test_determinism.py` holds the benchmark to its seed: dataset generation
  must not read the wall clock, the same seed must reproduce identical telemetry,
  and different seeds must not.
- The scan has a fourth mode: **outbound calls**. A local probe answers valid
  JSON, redirects, or announces a 33 MiB body, and the market-data refresh, the
  geolocation lookup and an assessment whose target redirects are all pointed at
  it. A followed redirect or a body read past the bound fails the run.
- `backend/scripts/benchmark_write_contention.py` starts the real API with
  `uvicorn --workers N` against PostgreSQL, ingests the evaluation dataset, then
  times single-event writes from six clients while a correlation run scans the
  window, and reconciles the stored event count afterwards. It refuses a SQLite
  target, which would serialise the writers and answer a different question.
- `docs/research/write-contention.md` and `docs/research/deepscan-results.md`
  record the two-run measurement — no write errors, exact reconciliation, p95
  19.0 → 24.5 ms, worst request 43 → 555 ms — and the defects it exposed.
- CI runs the deep scan on every push and keeps its reports as an artifact.

### Changed

- `GET /graph` returns a bounded page instead of the whole window: `limit`
  (default 400, max 2,000) bounds nodes and `edge_limit` (default twice the node
  limit, max 4,000) bounds edges, `limits` echoes both and `truncated` says
  whether anything was cut. Node properties are no longer serialised into the
  payload; the campaign detail endpoint serves them. On the evaluation corpus
  the response fell from 1,020.7 KiB and 54.4 ms to 394.2 KiB and 26.1 ms.
- The dashboard resolves graph nodes through a `Map` rather than scanning the
  node array for every label and every rendered node.
- Campaign graph labels keep the suffix that distinguishes two candidates
  (`cross-IP campaign…4bad6a`), are placed to avoid each other and are kept inside
  the frame instead of running under the graph's edge. A halo keeps them legible
  where they cross an edge.
- The README artwork and screenshots were regenerated: the architecture diagram's
  right-hand panels were widened so no sentence crossed the border, the three
  campaign evidence views are captured as whole cards rather than as a viewport
  slice that repeats the previous card, and all screenshots are framed from the
  top of the card they document.
- The evaluation dataset is anchored to a fixed instant (`runner.BENCHMARK_START`)
  instead of `datetime.now()`. The demo seeder and the runtime benchmark keep the
  wall clock, where "recent" is the point, and `generate_dataset` takes an optional
  `now` for both.
- The evaluation and correlation-runtime reports were regenerated from the
  anchored dataset; headline precision and recall are unchanged.
- The dashboard has a second theme. Every colour, line and glow moved from
the rules into one token set in `frontend/src/styles.css`, and
`[data-theme="daylight"]` restates that set as a bright-room console: cool
paper, dark ink and deepened accents. Components do not know which theme is
active, so the graph, evidence matrix, charts and badges are all readable in
both. `Daylight` in the workspace ribbon toggles it, `frontend/src/theme.ts`
remembers the choice, a host that reports a light colour scheme starts there
and `main.tsx` applies it before the first paint. The graph node colours and
the matrix ramp moved out of the components for the same reason; the matrix
mixes its cell colour from the theme tokens (`--cell-mix` bounds the range and
a flat `--cell-base` is the fallback where `color-mix` is unsupported). The
stylesheet also honours `prefers-reduced-transparency` (opaque panels, no
frosted blur), `prefers-reduced-data` (the field, scan band and aurora are
dropped) and printing, alongside the existing `prefers-reduced-motion`.
- The README artwork was regenerated in the new palette: `render_assets.py`
draws with the dashboard's tokens, and `capture_screenshots.py` now pins
`prefers-color-scheme` per pass so the artwork does not depend on the host, and
captures the daylight overview alongside the console set. It no longer writes
`login-filled.png` and `campaigns-list.png`, which nothing referenced.
- The HTTP decoy bounds what a hostile client can do to it, which it did not
  before. Reads now time out (15 s, `REQUEST_TIMEOUT_SECONDS`), so a client that
  opens a socket and never finishes its request cannot pin a worker thread, and
  a declared body that never arrives is answered once with `408` and closed
  instead of blocking. A client that hangs up mid-response no longer raises out
  of the handler — a scanner could otherwise fill the log with tracebacks for
  free; the write is guarded and disconnects are logged at debug by an
  overridden `handle_error`. Measured against a real decoy process: 200
  concurrent requests all answered, a stalled read closed after exactly 15.0 s,
  a stalled body answered `408`, and ten reset connections left stderr empty
  (`test_deception.py`).
- The dashboard probes the browser for what it actually provides instead of
  assuming it: `matchMedia` and the change-listener registration are feature
  detected, so an engine that only exposes the legacy `addListener` form follows
  the host instead of failing to render, and a browser without `matchMedia`
  falls back to the console rather than throwing before the first paint
  (`theme.ts`).
- The setup documentation states which layer consumes `.env` — Docker Compose
  reads it, the API process reads environment variables directly and does not
  parse it — and that the demo overlay needs `TP_ENV=development`, which
  `.env.example` does not ship. Following the overlay command with a fresh copy
  of that file made the seed service exit 1 with
  `seed-demo is disabled when TP_ENV=production` and left the dashboard empty.
  Re-verified after the change: the Compose quickstart (api, db and retention
  healthy, bootstrap administrator signing in) and the demo overlay (seed exit 0,
  demo login, 121 events, idempotent on a second run) both work, on this host and
  against a throwaway PostgreSQL 16.15 container for the suite.
- The workspace follows the host colour scheme for as long as no switch has been
made, and keeps following it: `theme.ts` separates applying a theme from
remembering one, and `watchHostTheme` reports a live `prefers-color-scheme`
change, so a console left open overnight follows the room as the operating
system flips between light and dark. The first `applyTheme` no longer stores a
choice — which is what had quietly pinned whatever the host said on the first
load and made the preference a one-off decision. A switch made in the ribbon is
still stored and still outranks the host from then on (`test_browser.py`).
- Text and chart contrast are now measured rather than assumed. Both token sets
are audited against the surfaces they are drawn on, compositing the translucent
panels and tinted badges the way the browser does, and the failures were fixed
at the token level: `--faint`, the graph's solid and hypothesis edges, the
legend key (now the same stroke the graph uses), the matrix ramp and three
rule-level opacities that faded text below the floor. Worst text pair is now
4.60:1 against a floor of 4.5:1 (was 4.15:1) and the worst graphical mark is
3.03:1 against 3:1 (was 1.88:1); the console's brightest matrix cell keeps
5.32:1 (was 2.28:1).
- The dashboard was redesigned as a holographic analyst console: a receding
  floor grid and scanning band behind hairline instrument panels with
  calibration ticks, numbered rail navigation, a sticky workspace ribbon with a
  UTC clock, beveled gauges whose charge bars are drawn only where a real
  fraction backs them, and an orbital sign-in screen. The palette moved to
  cyan/azure/violet on near-black. Campaign candidates carry a confidence meter
  and the Events filters read as one filter bank. Panel and gauge ideas live in
  `frontend/src/styles.css`; the shell, login and three page layouts changed in
  `App.tsx`, `Overview.tsx`, `Events.tsx` and `Campaigns.tsx`.

### Fixed

- Setting up from a source checkout no longer ends at a bare 404. The dashboard
  is mounted only when `frontend/dist` exists, and the documented local quickstart
  never built it, so `http://127.0.0.1:8000/` answered `{"detail":"Not Found"}`
  with nothing to say why. The root now answers `dashboard_not_built` with the
  command to run, and the quickstart builds the bundle before starting the API (or
  runs `npm run dev` on 5173). The hint is the router's fallback rather than a
  route, so the served route inventory the deep scan, the scope check and the API
  reference depend on is unchanged — verified with the bundle absent: 57 routes
  and 285 checks, as before (`test_foundation.py`).
- `create-admin` and `create-user` without a terminal printed a `GetPassWarning`
  and then `error: ` with an empty message and exit 1, which is what a setup
  script sees. They now fail with an instruction to pass `--password`, and the
  CLI names the exception class when a failure carries no message of its own
  (`test_foundation.py`).
- The browser tests waited on a JavaScript expression through
  `page.wait_for_function`, which the dashboard's `script-src 'self'` policy
  forbids, because Playwright evaluates a string predicate with `eval`. The theme
  cases now poll the applied theme through `page.evaluate`, which the policy
  permits.
- A four-worker API could not start against a fresh database. `ensure_bootstrap_admin`
  and `seed_default_profiles` counted rows and then inserted, so two workers
  starting together raced and the loser's lifespan aborted with a unique
  constraint; PostgreSQL migrations also ran without a lock. The seeds now treat
  the lost race as the expected outcome, and migrations take a transaction-scoped
  advisory lock (`test_foundation.py`).
- Market-data refresh and geolocation lookup buffered whatever the remote sent
  before parsing it, so a provider, proxy or DNS hijack could exhaust memory with
  a large or endless body. Both now use `app/core/outbound.py`, which streams,
  stops at 1 MiB, refuses redirects and parses only what it read
  (`test_outbound.py`).
- The browser test that steps back from the retention quick range compared the
  day filter's prefix, which collides with "seven days ago" on 2026-10-27; it now
  compares the delimiter, so the assertion means what it says on any date.
- The seeded benchmark was not reproducible. While re-running the evaluation, seed
  7 reported 214, then 213, then 211 ambiguous pairs and seed 2026 reported 208,
  then 205, because the hour-of-day features moved with the time of day the
  benchmark was started. Two consecutive full evaluations now produce identical
  JSON apart from `generated_at` and the resource timings.

## 1.0.4 — 2026-10-26

### Added

- Campaign detail returns an **evidence acquisition plan**. For each evidence
  family it aggregates the components that were unavailable across the campaign's
  active edges, counts the edges affected, ranks the gaps by that count and by the
  weight at stake, and pairs every gap with a concrete collection instruction.
  Families no edge recorded are reported separately, and the weight is labelled an
  upper bound rather than a confidence forecast (`test_correlation.py`).
- Campaign detail reports **observation efficiency**: events observed, observations
  per linked pair and observations per session, so two campaigns of equal
  confidence can be compared by how concentrated their evidence was.
- The Campaigns page renders an **evidence matrix** — the campaign's pairwise
  confidence as a grid with family-contribution bars — so fragmentation, missing
  links and over-connection are visible before an edge is opened. Empty cells are
  explained as a store-threshold finding, not missing UI.
- The Campaigns page renders the acquisition plan with family coverage, weight at
  stake, ranked gaps and absent-family chips.
- Campaign detail reports **kill-chain coverage**: normalized command categories
  and authentication activity map onto the eleven tactics this telemetry can
  evidence (`app/correlation/killchain.py`). Each tactic carries a coarse 1–5
  consequence weight, and the response separates breadth from risk-weighted
  coverage. Ties for the furthest tactic go to the later stage. Collection and
  exfiltration are deliberately absent rather than inferred (`test_killchain.py`).
- The Campaigns page renders a tactic rail with observed sessions and evidence,
  a coverage meter and the furthest observed tactic.
- `backend/scripts/benchmark_evidence_views.py` measures campaign-detail cost and
  what the evidence views report on the evaluation volume dataset and a
  400-session run, writing `docs/research/evidence-views.md` and `.json`.
- The browser suite now exercises the campaign evidence views end to end:
  matrix shape, observation ratio, acquisition plan, eleven-tactic rail, lit
  tactics and the empty-cell explanation.
- `backend/scripts/render_assets.py` regenerates every README figure from the
  recorded evaluation and runtime results; `backend/scripts/capture_screenshots.py`
  regenerates the dashboard screenshots from a seeded demo instance.

### Changed

- The README is rebuilt around the architecture, confidence model, evidence views
  and measured results, with generated figures and tables taken from the recorded
  runs. It adds the kill-chain figure and the measured cost of the evidence views
  at volume, and the test counts now reflect the new suites.

### Fixed

- Correlation runs are serialised in-process: a second concurrent request now
  receives `409` instead of racing the same graph rows and surfacing a unique
  constraint error (`test_correlation.py`).
- The ingestion window kept the **oldest** events when the row cap applied,
  silently correlating a stale prefix of a busy window. It now keeps the newest
  events, reports `events_truncated`, and marks the run truncated
  (`test_pipeline.py`).
- `GET /correlation/latest` exposes `run_id`, and an existing campaign stores the
  current `algorithm_version` when its membership is updated.
- Creating an agent token rejects a blank name and returns the trimmed name that
  was actually stored (`test_advanced.py`).
- A manual retention run records the requesting administrator as its actor rather
  than `system` (`test_retention.py`).
- Response targets are canonicalised before the observed-target lookup, so an
  expanded IPv6 address no longer fails to match the stored form
  (`test_responses.py`).
- Adaptive investigations canonicalise the source address on activation and on
  override lookup, and reject an address that is not an IP
  (`test_adaptive.py`).
- The HTTP decoy initialises per-request state before the rate-limit branch, fixing
  a crash on the first throttled request of a new connection, and refuses to start
  when `TP_DECOY_ENABLED` is false (`test_deception.py`).
- Web assessment classifies an unusable redirect as a scan limitation instead of
  leaving the scan marked running; redirect ports and empty hostnames are
  validated, DNS failures of any kind become validation errors, and duplicate
  scopes are detected from `IntegrityError` rather than database-specific error
  text (`test_websec.py`).
- An unexpected exception during an assessment now marks the scan `failed` and
  records the error instead of leaving the row `running` indefinitely
  (`test_websec.py`).
- Cowrie SSH password attempts keep their truncated digest and length through
  normalization, so the stored event supports credential-reuse analysis; the
  plaintext is still discarded before storage (`test_deception.py`).
- `TP_RESPONSE_AUTO_APPLY=true` is now a configuration error. The shipped
  adapter records intent only, so accepting the flag implied an automatic
  containment path that did not exist (`test_responses.py`).
- Adaptive evaluation counts only telemetry received from the activated source
  address. A platform-wide count credited unrelated ingest traffic with changing
  the hypothesis and could turn an empty observation into a strengthened or
  weakened outcome (`test_adaptive.py`).
- Correlation reads its incremental state on a separate connection and writes
  session nodes only after pair scoring. A long run no longer holds the SQLite
  write lock across the quadratic comparison, which previously blocked
  ingestion and sign-in audits and could fail to upgrade a stale snapshot
  (`test_correlation.py`).
- The dashboard replaces a deep link the signed-in role cannot open, late session
  lookups cannot overwrite the account currently under inspection, an investigation
  only offers activation while it is planned or active, and a fast double click no
  longer starts two retention exports (`test_browser.py`).
- The evidence matrix no longer advertises a hypothesis state campaign detail
  cannot receive, family bars render their real score instead of a full track, and
  the matrix table no longer stretches to the container width.

## 1.0.3 — 2026-10-25

### Added

- Evidence graph retention is separate from event retention. Correlation
  retires stale links, but a deployment that stops correlating kept every edge
  forever; `python -m app.cli purge-graph` now deletes retired edges past
  `TP_GRAPH_RETENTION_DAYS` (default 30), the observation records of sessions
  that old with no live similarity or campaign edge, and nodes nothing
  references. Hypotheses, active evidence, campaign membership and archived
  reviews are kept, so an analyst's decision outlives the evidence behind it
  (`test_correlation.py`).
- `python -m app.cli retention` enforces both horizons in one run. The Compose
  stack gains a `retention` service that waits for the API to be healthy, runs
  at start and then every `TP_RETENTION_INTERVAL_SECONDS` (default 24 hours).
- `GET /retention` (admin) reports expired events, retired edges, stale
  observations, orphan nodes and the current graph size. `overdue` is set only
  when work has waited past `TP_RETENTION_GRACE_DAYS` (default 2), so a normal
  daily backlog does not raise an alarm.
- Administration shows the retention backlog and graph size. The Overview
  raises an alert for administrators once that backlog is overdue.
- Each retention run records its pre-run backlog in `retention_runs`, returns
  the last 14 runs from `GET /retention`, and charts them on the Administration
  page, so an operator can see whether the backlog is growing.
- Scheduled runs are audited as `retention.run` with actor role `system`; the
  Compose service passes `--scheduled` so the trigger is recorded.
- Administrators can run retention from the dashboard (`POST /retention/run`);
  the action asks for confirmation and records history and an audit entry like
  a scheduled run.
- `GET /metrics` exports retention backlog and graph size in Prometheus text
  format. It needs `graph:read` but exposes no event content.
- `python -m app.cli seed-demo` populates development telemetry, correlation
  and a week of retention history, and creates a demo administrator with a
  one-time password when no accounts exist. `make demo` seeds, builds and
  serves the stack in one command; it refuses to run in production. The CLI
  prints the outcome, including a generated login, as one summary block at the
  end so it is not lost between correlation log lines.
- Administration lists each recent retention run with its trigger, backlog,
  removed count, duration and overdue state, reports the total recorded run
  count when the 14-row view is truncated, and exports the history as CSV
  (`GET /retention/history.csv`, oldest first, up to 1,000 runs).
- Run history can be filtered by an inclusive UTC date range from the page or
  with `history_since`/`history_until`, and by a `manual`/`scheduled`
  `history_trigger`; `history_total` and the CSV export follow the same window.
  The page offers 24-hour, 7-day and 30-day quick ranges that send exact
  timestamps and keep the selected trigger.
- Analysts can open a read-only Retention view with the backlog, history,
  filters and CSV export. `GET /retention` and `/retention/history.csv` require
  the new `retention:read` permission; running retention remains admin-only.
  The Overview's overdue alert now appears for analysts too and points them at
  the Retention page.
- Dashboard views and their filters are now shareable through the URL: the
  Events module, severity, window and search use `event_*` parameters, the
  Retention history window and trigger use `history_*`, and a reload keeps both.
  The Events page and the Retention card both copy the current filtered URL,
  with a selected-field fallback when the Clipboard API is unavailable or
  denied. View and committed filter changes push history, so browser back and
  forward restore them together, and malformed or inverted filter values in a
  shared link are explained and removed instead of being sent to the API. The
  card also reports manual and scheduled run totals for that window from
  `history_counts`, even when the table is narrowed to one trigger, and the
  Overview's overdue alert links straight to the Retention page for
  administrators and analysts.
- `test_retention.py` explicitly asserts that viewer accounts are refused the
  status and CSV endpoints; CI runs that file against PostgreSQL after the full
  suite.
- `docker-compose.demo.yml` adds a one-shot `seed` service that waits for the
  API health check, seeds a development database with a one-time demo login,
  and exits. `make demo-docker` starts the overlay; seeding remains idempotent
  and refuses to run in production. CI starts the same overlay against
  PostgreSQL, fails when the seed service exits non-zero or creates no
  telemetry or demo login, then reruns it and checks the row counts are
  unchanged.
- The operations guide includes Prometheus scrape configuration and alert
  rules for an overdue backlog and a stalled retention schedule.
- CI runs `tests/test_retention.py` explicitly against PostgreSQL, after the
  full suite, so a retention regression is attributed to its own step.
- Migration 11 adds the retention run history table.
- Migration 10 adds the indexes retention needs; `IF NOT EXISTS` makes it safe
  on a database that already has them.

## 1.0.2 — 2026-10-24

### Changed

- Campaign identity is now independent of membership. A new component inherits
  an existing campaign when at least half of its member set survives, so adding
  or losing a session no longer produces a new identifier and orphans the
  analyst's review; added and removed sessions are recorded in
  `membership_history`. When two campaigns merge, feedback and response
  references move to the survivor, a single review decision is carried forward
  and conflicting decisions become `uncertain` (`test_correlation.py`).
- Scored pairs are streamed through a bounded heap instead of retained as a
  dictionary of full results. At 800 sessions the previous code held more than
  1.6 GB before writing an edge; peak memory no longer grows with the square of
  the window. The run reports how many candidate pairs and how many links the
  per-run edge cap removed, so the cap can be judged on what it drops.
- The session cap rises from 400 to 800 and the per-run edge cap from 2,000 to
  8,000, from measurements in `docs/research/correlation-runtime.md`: 788
  sessions score 310,078 pairs in about 28 s, and the 2,000-edge cap was
  dropping 2,211 links at that size.

### Added

- `GET /campaigns?include_archived=true` lists archived campaigns. Campaign
  detail returns `status_updated_at`, `superseded_by`, `archived_at`,
  `archived` and the full stored `evidence`, including membership and review
  history.
- A CI job audits dependencies with `pip-audit` over the installed backend
  environment and `npm audit --audit-level=high` over the dashboard lockfile;
  `make audit` runs the same checks locally.
- `backend/scripts/benchmark_correlation.py` measures end-to-end correlation at
  increasing session counts and writes `docs/research/correlation-runtime.md`.
- Migration 9 adds the campaign lifecycle columns.

### Fixed

- A reviewed campaign was deleted, along with the feedback that pointed at it,
  when its links expired or fell below the persistence cut. Reviewed campaigns,
  and those an investigation or response refers to, are archived instead;
  untouched automatic candidates are still removed. Expiry of an edge whose
  sessions were scored in the run is now decided from the stored endpoints, so
  the engine does not need to retain every pair key.
- The synthetic scenario generator produced invalid IP octets above 244
  sessions (`203.0.113.256`), breaking volume benchmarks above that size;
  addresses now come from the benchmark range 198.18.0.0/15.

## 1.0.1 — 2026-10-24

### Changed

- Sequence comparison scores containment as well as Jaccard (`corr-1.3.0`), so a
  session that recorded fewer commands is no longer read as evidence of
  different behaviour. It is measured against a new `ablation_jaccard_only` run
  that reproduces the previous comparison: seed 7 recall 0.812 → 0.906 and seed
  2026 0.562 → 0.812 at unchanged precision, with campaign recovery rising from
  9 to 10 of 12 and from 4 to 8 of 12. The comparison used is recorded as
  `sequence_similarity` on every edge.
- Benchmark tables, campaign recovery, time to detection and cost figures were
  regenerated for `corr-1.3.0` in the README, the traceability map and
  `docs/research/`.

### Fixed

- Campaign views presented hypotheses and expired relationships as campaign
  evidence: an edge that stopped being supported kept its campaign identifier,
  and the campaign detail query did not filter by edge state. Membership is now
  cleared when an edge becomes a hypothesis or expires, and the campaign view
  counts only active links.
- Expiring a pair replaced its stored evidence with a two-key stub, discarding
  the reasons the model had proposed the link. Expiry now keeps the original
  evidence and records when and why the relationship was retired.

### Added

- Tests for containment scoring of truncated sessions, for campaign membership
  after an edge is demoted or expired, and for expiry preserving evidence.

## 1.0.0 — 2026-10-23

Initial release.

### Added

- Versioned telemetry contract with validation, normalization, hashing,
  deduplication, quarantine and retention.
- HTTP decoy, Cowrie JSON adapter and database-backed decoy profiles.
- Cross-IP correlation over six evidence families with corpus-relative
  weighting, specificity anchors, contradictions and per-edge explanations.
- Campaign candidates, graph view, risk separation and analyst feedback.
- Uncertainty-directed investigation with bounded activation and recorded
  before/after evidence.
- Scope-limited web assessment with SSRF guards and non-destructive checks.
- Digital-asset risk with a provider adapter, provenance and freshness.
- Policy-gated response engine with approval, expiry, rollback and audit.
- React/TypeScript analyst dashboard with a strict Content-Security-Policy.
- Account page for password rotation and recent session history, and an
  administrator action that revokes every session of an account without
  changing its password.
- `GET /auth/sessions` reports an account's sign-ins, password changes and
  revocations with client, address and whether each sign-in is still usable,
  derived from the audit trail rather than per-request logging. Administrators
  can open any account's history from the Administration page or
  `GET /auth/users/{id}/sessions`.
- Per-session sign-out: each token carries an identifier, `DELETE /auth/sessions/{jti}`
  revokes just that device, and revoked identifiers are kept only until the token
  would have expired. Administrators can do the same for any account with
  `DELETE /auth/users/{id}/sessions/{jti}`, from the session panel on the
  Administration page, without ending that account's other sessions.
- Administration page manages sensor credentials: it lists agent tokens with
  their prefix, role, last use and state, creates one (plaintext shown once)
  and revokes it, so no shell access is needed to rotate a sensor.
- The operations guide carries a session-compromise runbook that walks from a
  sign-in alert through confirming the device, revoking that one session,
  containing the account or tokens when the scope is unclear, preserving
  evidence and closing out.
- The Overview page raises recent sign-in anomalies as an attention item, for the
  signed-in account and, for administrators, as a count from the audit trail.
- Sign-in anomaly alerts: a second live session from a different network inside
  `TP_SIGNIN_ALERT_WINDOW_MINUTES` is recorded as `auth.signin.anomaly` and shown
  on the account and admin session views. An optional geolocation endpoint adds
  measured distance and the `TP_SIGNIN_ALERT_DISTANCE_KM` threshold; without one
  the alert reports the network change rather than inventing a location.
- The dashboard end-to-end job now also plans and activates an investigation
  through the Campaigns and Deception pages, signs another account's device out
  from the administration session panel, and creates and revokes a sensor token.
- Evidence families are weighted by the corpus, not only tokens (`corr-1.2.0`):
  a family whose tokens are almost all ubiquitous in the analysed window
  contributes less, and the effective weights are recorded on every edge. A
  uniform-weight ablation reproduces the previous model so the effect is
  measured rather than asserted.
- `docs/PRODUCT_SPEC.md` records the authoritative product scope, and
  `docs/REQUIREMENTS_TRACEABILITY.md` maps every stage, module, dashboard view
  and required metric to its implementation, test and measured result, with the
  open gaps stated.
- The evaluation reports time to detection — the elapsed campaign time until two
  members of a true group link — alongside wall and CPU time, peak memory and
  milliseconds per scored pair, so the metrics the specification asks for are
  measured rather than described.
- The Deception page lists decoy sessions from `GET /honeypot/sessions` with
  their addresses, event counts, severity and target, so captured interactions
  are reviewable as sessions rather than as a stream of events.
- `tests/test_properties.py` checks invariants instead of scenarios: symmetric
  and deterministic scoring, bounded outputs, monotone confidence, unique
  relationship keys for every accepted identifier, rejection of control
  characters in identifiers, isolation of legacy corrupt identifiers,
  corpus-relative family weights, and the narrowest authorization governing a
  host.
- Docker/Compose deployment, CLI, schema migrations, backup and recovery
  runbooks.
- CI pipeline covering lint, the full suite on SQLite and PostgreSQL 16, the
  dashboard build and a container image build.
- Seeded evaluation harness with baselines, ablations, adaptive experiment and
  a volume run.
- Dashboard screenshots and a documentation index for review.

### Changed

- The adaptive experiment no longer gives every session in an activity category
  the same synthetic request path. That constant manufactured similarity which
  observation cannot produce, and it inflated the reported benefit. The
  simulation now replays one command the actor already executed, and the report
  counts links gained and lost in both directions. With the corrected
  simulation additional observation moves almost no decisions, so the adaptive
  clause of the hypothesis is stated as unsupported rather than supported.
- Benchmark numbers were regenerated for `corr-1.2.0`: seed 7 recall 0.781 →
  0.812 with precision 1.000, campaign recovery 8 → 9 of 12, and volume recall
  0.836 → 0.853. The same report now includes the cost metrics above.
- Coverage in `docs/06-testing-and-evaluation.md` no longer quotes a single CI
  run as if it were the current count; it names the suite size and states that CI
  runs the same suite on both engines.

### Fixed

- Assessment scopes that overlap were resolved in row order, so a broad
  authorization could re-enable active probes that a scope for the specific host
  forbade. The narrowest live scope now governs, and the choice cannot depend on
  insertion order.
- A sensor could submit a session identifier containing the relationship-key
  separator, which let two different session pairs share one key and overwrite
  each other's evidence. Session and target identifiers now reject control
  characters at ingestion, and identifiers stored before that check degrade to
  one-event sessions instead of being merged.
- Adaptive activation is persisted on the investigation row and loaded by the
  decoy process; expired activations are marked `expired` and release their
  subject instead of blocking it indefinitely.
- Campaign detail now loads exactly its member sessions, so members older than
  the graph window remain visible.
- Assessment redirects are re-authorized and re-checked for private addresses;
  credential-bearing redirects are refused and response bodies are capped.
- Session-pair identifiers use a separator that cannot occur in a session ID;
  migration 5 re-keys legacy edges from their endpoint columns.
- The dashboard now uses the project logo for navigation, sign-in and favicon.
- PostgreSQL rejected optional `NULL` parameters in campaign listing and
  duplicate-investigation lookup; predicates are now built conditionally.
- Cowrie's Compose profile now uses a shared writable log volume, the image's
  actual fake filesystem paths and an offset outside the read-only log mount.
- Correlation preserves evidence in windows smaller than ten sessions instead of
  treating every shared token as ubiquitous.
- Malformed assessment ports return a validation error rather than a server
  error.
- Production refuses example signing secrets; the API runs one worker so
  startup migrations cannot race.
- A sparse event-volume window rendered as one full-width block; bars now cap
  their width and label counts when few buckets exist.
- The container dashboard build used `npm install`; it now uses `npm ci` so the
  lockfile is authoritative.
- Events containing `NaN`/`Infinity` or lone surrogates are quarantined instead
  of being stored; such values would otherwise make later responses invalid for
  strict JSON clients. Non-finite market-data values are treated as missing.
- Ingestion applies a total request-body bound before parsing, returning 413
  rather than buffering an arbitrarily large batch.
- Login attempts are rate limited per client address in addition to per
  account, closing the rotate-the-email bypass for password spraying.
- Active web-assessment probes now require the scope of the final redirect
  target to authorize them.
- The HTTP decoy rejects Transfer-Encoding and duplicate Content-Length
  requests, closes connections with unread bodies, and uses the active
  investigation profile for credential capture.
- Event `since`/`until` filters are validated as timestamps instead of being
  compared as raw strings.
- Changing a password now revokes every token issued before the change, and
  tokens that carry no session version are refused. The caller receives a
  replacement token so the session making the change is not logged out.
- Duplicate investigation planning is decided by partial unique indexes on the
  open rows, so two concurrent requests for the same campaign or edge can no
  longer both create an investigation and activate two decoys. Existing
  duplicates are marked `superseded` by migration 7, and the Deception page
  names the investigation that replaced each closed duplicate.

### Security

- Bearer tokens are kept in tab-scoped storage.
- The dashboard CSP is sent by the API and scoped to dashboard responses.
- Agent tokens are stored as hashes and can be revoked.
- Bearer tokens are bound to an account session version that is checked on
  every request; rotating a password invalidates tokens already issued, and an
  administrator can revoke an account's sessions when theft is suspected.
- Untrusted numeric and Unicode input is bounded at the event and provider
  boundaries before it reaches storage or a JSON response.
- Login endpoints enforce both account-level and address-level attempt budgets.
- Session identifiers are validated at the contract boundary so a crafted id
  cannot corrupt the relationship graph, and overlapping assessment scopes are
  resolved by specificity rather than by row order.
- Web-assessment probes are constrained by the authorization scope of every
  host they touch, including redirect destinations.
- Build context excludes secrets, local data and build artefacts.
- The Vite/esbuild development toolchain was updated to clear the published
  advisories; `npm audit` reports no vulnerabilities.
