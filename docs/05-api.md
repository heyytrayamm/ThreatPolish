# HTTP API

Base path `/api/v1`. JSON in, JSON out. OpenAPI is served at `/openapi.json`
and the interactive document at `/docs`.

## Authentication

Three surfaces:

| Surface | Mechanism | Examples |
| --- | --- | --- |
| Public | none | `/health`, `/health/ready`, `/auth/login` |
| Sensor | `X-Agent-Token` (hashed, revocable agent token) | `POST /ingest/events` |
| Analyst | `Authorization: Bearer <jwt>` + role | everything else |

Roles: `admin`, `analyst`, `viewer`. Viewer is read-only; analyst can ingest,
correlate, assess and propose; admin manages users, scopes and approvals.
Denied requests return 403 with `{"detail": "..."}`. Authentication failures are
recorded in the audit log.

## Endpoint map

| Method | Path | Role | Purpose |
| --- | --- | --- | --- |
| GET | `/health` | public | Liveness |
| GET | `/health/ready` | public | Readiness, including database check |
| POST | `/auth/login` | public | Obtain a bearer token |
| GET | `/auth/me` | any | Current identity and role |
| POST | `/auth/password` | any | Rotate own password; revokes every other session and returns a replacement token |
| GET | `/auth/sessions` | any | Recent sign-ins and credential events for the caller, with client, address and whether each sign-in is still usable |
| GET/POST | `/auth/users` | admin | List and create users |
| POST | `/auth/users/{id}/revoke-sessions` | admin | Invalidate every token issued to an account |
| GET/POST/DELETE | `/auth/tokens` | admin | Service token management |
| GET | `/auth/roles` | any | Role capability matrix |
| POST | `/ingest/events` | sensor | Batch ingestion |
| GET | `/events` | viewer | Filter by module, severity, source, time |
| GET | `/events/summary` | viewer | Counts for the dashboard |
| GET | `/events/{id}` | viewer | Single record with provenance |
| GET | `/quarantine` | viewer | Rejected records |
| GET | `/sources` | viewer | Known collectors and freshness |
| POST | `/correlate` | analyst | Rebuild edges and campaigns for a window |
| GET | `/correlation/latest` | viewer | Summary of the last run |
| GET | `/graph` | viewer | Nodes and edges for visualisation |
| GET | `/campaigns`, `/campaigns/{id}` | viewer | Campaign list and detail |
| GET | `/edges/{id}` | viewer | Full evidence for one edge |
| POST/GET | `/feedback` | analyst | Confirm or reject an edge |
| GET | `/honeypot/profiles` | viewer | Decoy profile catalogue |
| GET | `/honeypot/sessions` | viewer | Decoy interaction sessions |
| GET/POST | `/websec/scopes` | viewer/admin | Authorised targets |
| POST | `/websec/assess` | analyst | Run an in-scope, non-destructive assessment |
| GET | `/websec/findings`, `/websec/scans`, `/websec/scans/{id}` | viewer | Results |
| GET | `/crypto/assets`, `/crypto/assets/{symbol}/history`, `/crypto/providers` | viewer | Asset data |
| POST | `/crypto/refresh` | analyst | Refresh quotes |
| POST | `/investigations` | analyst | Open an uncertainty-driven investigation |
| POST | `/investigations/{id}/activate`, `/evaluate` | analyst | Observe, then re-score |
| GET | `/investigations`, `/investigations/{id}` | viewer | History with before/after |
| GET/POST | `/responses` | viewer/analyst | Propose actions |
| POST | `/responses/{id}/approve`, `/rollback` | admin/analyst | Approve or reverse |
| POST | `/responses/emergency-disable` | admin | Stop all active actions |
| POST | `/responses/evaluate` | analyst | Dry-run a policy decision |
| GET | `/responses/policies` | viewer | Policy matrix |
| GET | `/audit` | admin | Audit trail |

## Examples

Login:

```bash
curl -sX POST localhost:8000/api/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"admin@example.com","password":"..."}'
# {"access_token":"...","token_type":"bearer","expires_at":"...","user":{...}}
```

Ingest:

```bash
curl -sX POST localhost:8000/api/v1/ingest/events \
  -H 'content-type: application/json' -H "X-Agent-Token: $TP_AGENT_TOKEN" \
  -d '{"events":[{"schema_version":"1.0","occurred_at":"2026-10-23T09:00:00Z",
       "source_module":"honeypot","event_type":"honeypot.ssh.login_failed",
       "source_ip":"203.0.113.9","session_id":"sess-1",
       "provenance":{"collector":"cowrie","source":"decoy-1","synthetic":false},
       "features":{"username":"root","success":false,
                    "client_version":"SSH-2.0-libssh_0.9.6"}}]}'
```

Correlate and read a campaign:

```bash
curl -sX POST localhost:8000/api/v1/correlate -H "Authorization: Bearer $T" \
  -H 'content-type: application/json' -d '{"window_hours":24}'
curl -s localhost:8000/api/v1/campaigns -H "Authorization: Bearer $T"
```

Propose a response. The target must already appear in ingested telemetry;
policy refuses to act on a host the platform has never observed.

```bash
curl -sX POST localhost:8000/api/v1/responses -H "Authorization: Bearer $T" \
  -H 'content-type: application/json' \
  -d '{"action":"apply_rate_limit","target":"203.0.113.9",
       "confidence":0.9,"severity":"high","risk_level":"high",
       "risk_score":70,"ttl_minutes":60}'
# 201 with status "pending_approval" for containment actions;
# allowed actions: alert, request_evidence, recommend_rate_limit,
# apply_rate_limit, escalate
```

## Errors

| Status | Meaning |
| --- | --- |
| 400 | Malformed JSON |
| 401 | Missing or invalid token, sensor secret rejected |
| 403 | Role insufficient, target out of scope, private address refused, or `policy_denied` because the evidence does not permit the requested action |
| 404 | Unknown id |
| 409 | Invalid state transition (e.g. rolling back a completed action) |
| 422 | Validation error with field path; also used for over-cap requests |
| 503 | Database unavailable |

Errors never include secret values. Policy refusals include a reason code
(`out_of_scope`, `private_address`, `approval_required`, `expired`).
