# Telemetry event contract

All modules emit the same record. `app/schemas/event.py` is authoritative; this
document explains the intent and the per-module feature conventions.

## Envelope

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `schema_version` | `"1.0"` | yes | Rejected if different |
| `event_id` | string (uuid) | no | Generated server-side when absent |
| `occurred_at` | ISO-8601 datetime | yes | Converted to UTC; future timestamps beyond a small tolerance are rejected |
| `source_module` | enum | yes | `honeypot`, `websec`, `cryptointel`, `app`, `correlation`, `manual` |
| `event_type` | string 3–120 chars | yes | Namespaced verb, e.g. `honeypot.ssh.login_failed` |
| `source_ip` | IPv4/IPv6 string | no | Validated; absent for internal analytical events |
| `session_id` | string ≤120, no control characters | no | Sensor-scoped session key |
| `target_id` | string ≤200, no control characters | no | Asset or host identifier |
| `severity` | enum | no, default `info` | `info`, `low`, `medium`, `high`, `critical` |
| `provenance` | object | yes | See below |
| `features` | object | no | Module-specific, bounded |
| `evidence_refs` | list[str] ≤50 | no | Pointers to raw artefacts (log line ids, file paths) |
| `raw` | object | no | Original payload, truncated |

`provenance`: `collector`, `source`, `reliability` (0–1), `synthetic` (bool),
`external_refs` (≤20), `indicators` (≤50 strings).

`raw` and `features` are size-bounded; oversized values are truncated rather
than rejected, and the truncation is visible in the stored record.

## Validation and outcome

Each record is one of:

- `accepted` — stored.
- `duplicate` — `event_hash` already present; the existing id is returned.
- `rejected` — schema violation with field-level reason; nothing is stored.

Batch ingestion returns a per-item result and an aggregate report.

## Feature conventions per module

Event types are namespaced, and normalization only derives correlation features
for the names it recognises. A custom event type is stored, but it contributes
no behavioural features — use the types below for sensor integration.

**Honeypot SSH** — `honeypot.ssh.session_start`, `honeypot.ssh.client_version`,
`honeypot.ssh.client_fingerprint`, `honeypot.ssh.login_failed`,
`honeypot.ssh.login_success`, `honeypot.ssh.command`, `honeypot.ssh.session_params`,
`honeypot.ssh.session_end`.
Features: `username`, `success`, `command`, `client_version`,
`password_sha256_prefix`, `password_length`.

**Honeypot HTTP** — `honeypot.http.request`, `honeypot.http.credential_attempt`.
Features: `method`, `path`, `status`, `user_agent`, `body_size`, `profile`,
`probe`, `sensitive_probe`, `investigation_id`, `password_sha256_prefix`.

**Web assessment** — `websec.finding`. Features: `check_id`, `title`,
`confidence`, `evidence_digest`.

**Digital assets** — `cryptointel.risk_observation`. Features: `indicator`,
`asset_symbol`.

## Correlation features

`app/correlation/features.py` derives a session feature document from its
events. The families and their relative weights (total 1.08; only the ratio
matters):

| Family | Weight | Signals |
| --- | --- | --- |
| behaviour | 0.52 | Normalised command tokens, technique set |
| targeting | 0.18 | Paths, targets, assets |
| timing | 0.08 | Inter-arrival profile, active hours |
| identity | 0.10 | Usernames, credential hashes, client signatures |
| intel | 0.12 | Verified indicators, malware family |
| toolchain | 0.08 | Client strings, payload hashes, TLS/JA3-like markers |

Tokens are weighted by document frequency over the analysed window; tokens
appearing in more than a quarter of sessions (minimum 3) are dropped as
uninformative. With fewer than 10 sessions in the window the corpus filter is
disabled, because document frequency cannot be estimated reliably and would
otherwise erase every shared token. A family whose evidence is absent is marked
unavailable; it is excluded from support and reduces coverage, so missing data
lowers confidence rather than manufacturing agreement.

## Versioning

`schema_version` is strict within a major API version. Adding an optional field
is backward-compatible; renaming or changing semantics requires `"1.1"` and a
parallel ingest path. Correlation output records its own
`algorithm_version`, so stored edges remain interpretable after upgrades.

## Privacy and sensitivity

- Passwords captured by the decoy are stored as a truncated SHA-256 prefix
  (16 hex characters) and a length, with the plaintext discarded. This supports
  correlation without retaining credentials.
- No plaintext payload bodies beyond the configured cap are persisted.
- Timestamps are UTC; analyst timezone handling is a presentation concern.
- Event retention defaults to 90 days (`TP_RETENTION_DAYS`); each event stores
  its own `retention_until`. `python -m app.cli purge` deletes expired events.
- The database should be treated as sensitive: it contains attacker IPs and
  commands that may include third-party personal data.
