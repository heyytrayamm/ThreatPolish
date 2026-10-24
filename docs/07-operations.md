# Operations

## Prerequisites

- Python 3.12+ and Node 20+ for development.
- Docker and Docker Compose for the container deployment.
- A TLS-terminating reverse proxy (Caddy, nginx, or a load balancer) for any
  internet-facing deployment.
- A host with only decoy ports exposed publicly.

## Configuration

Copy `.env.example` to `.env` and replace every placeholder. The authoritative
list is `backend/app/core/config.py`; the table below covers what operators
normally change.

| Variable | Default | Purpose |
| --- | --- | --- |
| `TP_ENV` | `development` | `development`, `test` or `production`; production refuses to start without a signing secret |
| `TP_JWT_SECRET` | generated in dev | JWT signing key, at least 32 characters; changing it invalidates all sessions |
| `TP_JWT_TTL_MINUTES` | `60` | Session lifetime, 5–1440 |
| `TP_DB_URL` | SQLite under `TP_DATA_DIR` | e.g. `postgresql+psycopg://threatpolish:PASSWORD@db:5432/threatpolish` |
| `TP_DB_PASSWORD` | none | Used only by Compose to initialise PostgreSQL; must match `TP_DB_URL` |
| `TP_ALLOWED_ORIGINS` | localhost:5173 | Comma-separated dashboard origins allowed by CORS |
| `TP_BOOTSTRAP_ADMIN_EMAIL` / `TP_BOOTSTRAP_ADMIN_PASSWORD` | none | First admin, created only when the user table is empty; remove afterwards |
| `TP_DATA_DIR` | `./data` | Local state (SQLite file, decoy spool) |
| `TP_DECOY_ENABLED`, `TP_DECOY_PORT` | `true`, `8022` | HTTP decoy listener |
| `TP_DECOY_MAX_SESSIONS_PER_HOUR` | `120` | Decoy admission limit |
| `TP_RETENTION_DAYS` | `90` | Event retention horizon |
| `TP_GRAPH_RETENTION_DAYS` | `30` | Age at which retired graph evidence is deleted |
| `TP_MAX_EVENT_BYTES` | `65536` | Per-event payload cap |
| `TP_INGEST_RATE_LIMIT_PER_MINUTE` | `6000` | Per-principal ingestion limit |
| `TP_CORRELATION_WINDOW_HOURS` | `72` | Default correlation window |
| `TP_RESPONSE_AUTO_APPLY` | `false` | Keep disabled: no reviewed execution adapter exists |
| `TP_WEB_SEC_ALLOW_LOOPBACK` | `false` | Must stay `false` in production |
| `TP_WEB_SEC_TIMEOUT_SECONDS`, `TP_WEB_SEC_MAX_REQUESTS_PER_HOST` | `10`, `10` | Assessment bounds |
| `TP_CRYPTO_PROVIDER`, `TP_CRYPTO_API_BASE` | `coingecko`, public API | Market-data source; `fixture` is available for offline use |
| `TP_SIGNIN_ALERT_WINDOW_MINUTES` | `30` | Two live sign-ins from different networks inside this window are reported |
| `TP_SIGNIN_ALERT_DISTANCE_KM` | `500` | Minimum measured distance for a `distant_signin` alert |
| `TP_GEO_API_URL` | empty | Optional geolocation endpoint; `{ip}` is replaced with the address. Empty means alerts report a network change only and no address leaves the deployment |
| `TP_GEO_API_TOKEN`, `TP_GEO_TIMEOUT_SECONDS` | empty, `3` | Credential and timeout for that endpoint |
| `TP_LOG_LEVEL` | `INFO` | Log verbosity |

Generate secrets with `python3 -c "import secrets;print(secrets.token_urlsafe(48))"`.
Never reuse the example values. The JWT secret is read in production and a
missing or short value stops startup rather than silently generating one.

## Deploy with Compose

```bash
cp .env.example .env
# edit .env: TP_JWT_SECRET, TP_DB_PASSWORD, TP_DB_URL, bootstrap admin
docker compose build
docker compose up -d
docker compose ps
docker compose logs -f app
curl -fsS http://127.0.0.1:8000/api/v1/health/ready
```

The stack contains:

| Service | Role | Exposure |
| --- | --- | --- |
| `db` | PostgreSQL 16 | Internal `backend` network only |
| `app` | API plus the built dashboard | Bound to `127.0.0.1:8000` |
| `cowrie` | Optional SSH/Telnet decoy | Profile `honeypot`, publishes `2222` |

```bash
docker compose --profile honeypot up -d cowrie
```

The HTTP decoy is **not** a Compose service. Run it as a separate process (or
your own unit/container) so it can be placed on an isolated network segment:

```bash
cd backend
TP_ENV=production python -m app.cli decoy --host 0.0.0.0 --port 8022
```

Expose only the decoy ports (2222, 8022) to the internet. Keep 8000 behind the
reverse proxy on the management network and never publish 5432.

## First run

1. Set a strong `TP_BOOTSTRAP_ADMIN_PASSWORD` (and email) before the first
   start; the admin is created only when no users exist. Alternatively create it
   from the CLI: `python -m app.cli create-admin --email you@example.com`.
2. Log in and change the password immediately (`POST /auth/password`).
3. Create analyst and viewer accounts (`POST /auth/users` or
   `python -m app.cli create-user --email ... --name ... --role analyst`).
4. Remove the bootstrap variables and restart.
5. Add authorised web-assessment scopes with an authorization reference.
6. Confirm `GET /api/v1/health/ready` and `GET /api/v1/events/summary` return data.

## Sensors

Create a sensor token (the plaintext is shown once):

```bash
cd backend
python -m app.cli create-token --name decoy-1 --role sensor
```

Send events with `X-Agent-Token: tp_...`. The stored token is a hash and can be
revoked (`DELETE /auth/tokens/{id}`); revocation takes effect immediately.

- **HTTP sensor / generic collectors:** post to `/api/v1/ingest/events` with the
  event contract in `docs/04-event-contract.md`. A single object, an array, or
  `{"events": [...]}` up to 500 records is accepted.
- **Cowrie:** the Compose profile writes to the shared `cowrie-logs` volume,
  mounted read-only in the app at `/var/log/cowrie`. Run
  `docker compose exec app python -m app.cli cowrie-tail --path /var/log/cowrie/cowrie.json`.
  The tailer keeps its offset in `/data` (the log volume is read-only), survives
  rotation, and relies on event deduplication for at-least-once delivery.
- **HTTP decoy:** `python -m app.cli decoy`; interactions become telemetry
  automatically.
- NTP-synchronise every sensor; timing evidence depends on clocks.

## Backup and restore

Backup (nightly, and before upgrades):

```bash
docker compose exec -T db pg_dump -U threatpolish threatpolish \
  | gzip > backup-$(date +%F).sql.gz
```

Restore into a fresh database:

```bash
gunzip -c backup-2026-10-23.sql.gz \
  | docker compose exec -T db psql -U threatpolish -d threatpolish
```

Verify a restore quarterly in a non-production stack. Backups contain attacker
telemetry and must be encrypted at rest.

## Upgrade and rollback

1. Take a backup.
2. Pull the new image, `docker compose up -d app`.
3. Verify `/api/v1/health/ready` and one authenticated read.
4. Keep the previous image tag for 7 days.

Schema changes are applied at startup. The container runs a single API worker
because concurrent workers would race on the migration table; apply migrations
before adding replicas. There is no automatic downgrade: roll back the image
**and** restore the pre-upgrade backup. Treat a change to the
correlation `algorithm_version` as a behavioural change and re-run
`python scripts/evaluate.py` before promoting.

## Monitoring

- Liveness `/api/v1/health` and readiness `/api/v1/health/ready` every 30 s.
- Alert on `authentication_failed` audit events above baseline.
- Alert on ingestion stalls (no events for longer than the expected probe rate).
- Alert on `pending_approval` responses older than the on-call SLA.
- Watch database size against the retention window.

## Runbooks

**Decoy appears compromised / used for egress.** Stop the decoy process, capture
its files and logs, revoke the sensor's agent token, and review `honeypot`
sessions for unexpected outbound behaviour. The decoy has no outbound path by
design; any egress is a deployment error.

**False-positive correlation.** Reject the edge via `POST /feedback`. Re-run
correlation for the window. If false positives recur, inspect the stored
`independent_families` and contradiction list before changing thresholds.

**Bad response action approved.** `POST /responses/{id}/rollback`. If the block
was pushed to an external system manually, revert it there and record the
reversion in the audit log, then review who approved it and why.

**Database unavailable.** The API returns 503 and stores nothing. Restore
service before retrying ingestion; replay is safe because ingestion is
idempotent.

**Suspected token compromise.** If one device is suspect, sign that session out
(`DELETE /auth/sessions/{jti}`, or the Sign out button beside it on the Account
page); the account's other sessions keep working. To end every session at once,
revoke the account's sessions (`POST /auth/users/{id}/revoke-sessions`) or have
the user rotate their password; both act on the account session version and take
effect on the next request. Rotate `TP_JWT_SECRET` to invalidate every session in the deployment,
revoke agent tokens, and review `/audit` and the account's session history.

### Session compromise: from a sign-in alert to a revoked device

Every step below has a dashboard path and an API call, so the same runbook
works for an analyst at the console and for scripted response.

1. **Read the alert.** The Overview page carries a *Sign-in attention* card for
the signed-in account; administrators also see how many
`auth.signin.anomaly` entries the recent audit trail holds. Pull the entries:

   ```bash
   curl -s "$API/audit?limit=200" -H "Authorization: Bearer $T" \
     | jq '.items[] | select(.action == "auth.signin.anomaly")'
   ```

   `kind` is `distant_signin` with a measured distance when
   `TP_GEO_API_URL` is configured, otherwise `new_network`. `previous_ip`,
   `previous_at` and `window_minutes` say what the alert compared against.
2. **Decide whether it is expected.** Ask the account holder whether they
signed in from that network, and open the account's session history — the
Administration page's *Sessions* button, or:

   ```bash
   curl -s "$API/auth/users/usr_.../sessions" -H "Authorization: Bearer $T" \
     | jq '.sessions[] | {occurred_at, client, ip, state, jti}'
   ```

   Each usable sign-in lists its `jti`. Note the one you suspect; the
   identifier, not the address, is what you revoke.
3. **Contain one device.** Administration → *Sessions* for the account →
**Sign out** beside the suspicious row. From the API:

   ```bash
   curl -sX DELETE "$API/auth/users/usr_.../sessions/jti_..." \
     -H "Authorization: Bearer $T"
   ```

   The account keeps its password and every other device keeps working. Verify
   both halves: the suspect token's next call returns 401, and another of that
   account's tokens still returns 200. Repeating the call is harmless.
4. **Contain the whole account when the scope is unclear.** If more than one
   device is suspect, revoke the account's sessions
   (`POST /auth/users/{id}/revoke-sessions`) or have the user change the
   password. Both act on the account session version, so every token issued
   before the action is refused on its next request; the user signs in again
   normally.
5. **Contain the sensor side.** If the exposed credential was an agent token,
   revoke it under Administration → *Agent tokens* → **Revoke**, or
   `DELETE /auth/tokens/{id}`. Revocation is immediate and the token hash stays
   in place for the audit trail. Create the replacement first if the sensor must
   keep reporting; the plaintext is shown once at creation.
6. **Only then consider the signing key.** Rotating `TP_JWT_SECRET` invalidates
   every session in the deployment, so treat it as the last step, not the first:
   it is required only when the key itself, not a token, may be exposed.
7. **Preserve evidence.** The audit trail is append-only in normal operation.
   Export it (`GET /audit`, or a database backup) before cleaning up, and do not
   delete sign-in rows: the session history is derived from them, so deleting
   them erases the incident record too. Revoked-identifier rows prune
   themselves once the token would have expired anyway.
8. **Close out.** Confirm no further `auth.signin.anomaly` entries appear for
   the account. Record which `jti` was revoked, by whom, and the alert that
   triggered it. If the alert fired for a legitimate user arriving through a
   new route, note the network in the ticket rather than disabling the check.

A sign-in from a different network while an earlier session is still live is
recorded as `auth.signin.anomaly` and shown on the account page and in the
admin session view. With `TP_GEO_API_URL` set, the alert also reports the
measured distance and only fires beyond `TP_SIGNIN_ALERT_DISTANCE_KM`; without
it the alert says "new network", which is what the platform can observe. Any
geolocation endpoint you configure receives analyst addresses — choose it with
that in mind. Lookups are cached per process and bounded by
`TP_GEO_TIMEOUT_SECONDS`, so a slow provider adds latency to sign-in but cannot
block it. The platform does not trust `X-Forwarded-For`, so behind a reverse
proxy every sign-in appears to come from the proxy address and no alert fires;
this detection suits deployments where clients reach the API directly.

## Dependency audit

CI audits both dependency sets on every push and pull request: `pip-audit`
against the installed backend environment and `npm audit --audit-level=high`
against the dashboard lockfile. Run the same checks locally after changing a
lockfile or a requirements file:

```bash
make audit
```

A finding fails the job. Read the advisory before acting: upgrade the affected
package inside its compatibility range, or pin the release that fixes it, then
rerun the suite. Do not suppress a finding to get a green build. If no fixed
release exists, record the exposure and the compensating control in the
security notes, and add a dated ignore for that advisory identifier with the
reason it cannot affect this deployment; review it at each upgrade.

## Retention

Events carry `retention_until` (`TP_RETENTION_DAYS`, default 90). Enforce it:

```bash
docker compose exec app python -m app.cli purge
```

The evidence graph outlives the events that produced it, so it has its own
horizon (`TP_GRAPH_RETENTION_DAYS`, default 30). Correlation retires edges when
links stop holding, but a deployment that stops correlating keeps them:

```bash
docker compose exec app python -m app.cli purge-graph
```

This deletes only edges already retired and older than the horizon, plus
observation records (`observed_from`, `targeted_asset`, `matched_indicator`)
for sessions past the horizon that no live similarity or campaign edge still
uses. Nodes are then removed when their last activity is older than the horizon
and nothing references them. Hypotheses, active edges, campaign membership and
archived reviews are kept — an archived campaign is the record of an analyst's
decision, not evidence. Run both commands from the same
schedule and confirm deletions against the database size trend.
`python -m app.cli status` shows configuration, retention and schema state.

## Known limitations

- Cowrie was exercised with connection attempts, not a full interactive shell
  session; validate the fake filesystem against your image version.
- Single-node deployment; correlation does not scale horizontally (it processes
  at most 800 sessions per run), and the API runs one worker so startup
  migrations cannot race.
