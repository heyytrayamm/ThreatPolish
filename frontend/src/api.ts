export type Role = "admin" | "analyst" | "viewer" | "sensor";

export interface User {
  id: string;
  name: string;
  email: string;
  role: Role;
}

export interface ApiError {
  code: string;
  message: string;
  details: Record<string, unknown>;
}

const TOKEN_KEY = "threatpolish.token";

// Session storage keeps the bearer token out of persistent browser storage:
// it is discarded when the tab closes and is not shared with other tabs.
export function getToken(): string | null {
  return sessionStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string | null): void {
  if (token) sessionStorage.setItem(TOKEN_KEY, token);
  else sessionStorage.removeItem(TOKEN_KEY);
}

export class ApiFailure extends Error {
  status: number;
  code: string;
  details: Record<string, unknown>;
  constructor(status: number, error: ApiError) {
    super(error.message);
    this.status = status;
    this.code = error.code;
    this.details = error.details;
  }
}

function toFailure(response: Response, payload: unknown): ApiFailure {
  const error = (payload as { error?: ApiError } | null)?.error ?? {
    code: "request_failed",
    message: `Request failed with status ${response.status}`,
    details: {},
  };
  if (response.status === 401) setToken(null);
  return new ApiFailure(response.status, error);
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string> | undefined),
  };
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  const response = await fetch(path, { ...options, headers });
  if (response.status === 204) return undefined as T;
  let payload: unknown = null;
  try {
    payload = await response.json();
  } catch {
    payload = null;
  }
  if (!response.ok) throw toFailure(response, payload);
  return payload as T;
}

export interface RetentionQuery {
  since?: string;
  until?: string;
  trigger?: "manual" | "scheduled";
  limit?: number;
}

function retentionQuery(params: RetentionQuery): string {
  const query = new URLSearchParams();
  if (params.since) query.set("history_since", params.since);
  if (params.until) query.set("history_until", params.until);
  if (params.trigger) query.set("history_trigger", params.trigger);
  if (params.limit !== undefined) query.set("limit", String(params.limit));
  const encoded = query.toString();
  return encoded ? `?${encoded}` : "";
}

async function requestBlob(path: string): Promise<Blob> {
  const headers: Record<string, string> = {};
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  const response = await fetch(path, { headers });
  if (!response.ok) {
    let payload: unknown = null;
    try {
      payload = await response.json();
    } catch {
      payload = null;
    }
    throw toFailure(response, payload);
  }
  return response.blob();
}

export const api = {
  login: (email: string, password: string) =>
    request<{ access_token: string; user: User; expires_at: string }>("/api/v1/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),
  me: () => request<User & { via: string }>("/api/v1/auth/me"),
  changePassword: (current_password: string, new_password: string) =>
    request<{
      status: string;
      access_token: string;
      token_type: string;
      expires_at: string;
      other_sessions_revoked: boolean;
    }>("/api/v1/auth/password", {
      method: "POST",
      body: JSON.stringify({ current_password, new_password }),
    }),
  sessions: (limit = 20) =>
    request<SessionHistory>(`/api/v1/auth/sessions?limit=${limit}`),
  userSessions: (userId: string, limit = 20) =>
    request<SessionHistory>(`/api/v1/auth/users/${userId}/sessions?limit=${limit}`),
  revokeSession: (jti: string) =>
    request<{ status: string; jti: string }>(
      `/api/v1/auth/sessions/${encodeURIComponent(jti)}`,
      { method: "DELETE" },
    ),
  revokeSessions: (userId: string) =>
    request<{ status: string; user_id: string; session_version: number }>(
      `/api/v1/auth/users/${userId}/revoke-sessions`,
      { method: "POST" },
    ),
  revokeUserSession: (userId: string, jti: string) =>
    request<{ status: string; jti: string }>(
      `/api/v1/auth/users/${userId}/sessions/${encodeURIComponent(jti)}`,
      { method: "DELETE" },
    ),
  agentTokens: () => request<{ tokens: AgentToken[] }>("/api/v1/auth/tokens"),
  createAgentToken: (name: string, role: "sensor" | "analyst") =>
    request<{ id: string; name: string; prefix: string; role: string; token: string }>(
      "/api/v1/auth/tokens",
      { method: "POST", body: JSON.stringify({ name, role }) },
    ),
  revokeAgentToken: (id: string) =>
    request<{ status: string }>(`/api/v1/auth/tokens/${encodeURIComponent(id)}`, {
      method: "DELETE",
    }),
  summary: (hours: number) =>
    request<{
      total: number;
      by_module: Record<string, number>;
      by_severity: Record<string, number>;
      top_sources: { source_ip: string; count: number }[];
      hourly: { hour: string; count: number }[];
    }>(`/api/v1/events/summary?hours=${hours}`),
  events: (params: Record<string, string | number>) => {
    const query = new URLSearchParams(
      Object.entries(params)
        .filter(([, value]) => value !== "" && value !== undefined && value !== null)
        .map(([key, value]) => [key, String(value)]),
    );
    return request<{ items: EventRecord[]; total: number; limit: number; offset: number }>(
      `/api/v1/events?${query.toString()}`,
    );
  },
  event: (id: string) => request<EventRecord>(`/api/v1/events/${id}`),
  graph: (hours: number) =>
    request<GraphView>(`/api/v1/graph?hours=${hours}`),
  campaigns: () => request<{ items: Campaign[] }>("/api/v1/campaigns"),
  campaign: (id: string) => request<CampaignDetail>(`/api/v1/campaigns/${id}`),
  correlate: (window_hours?: number) =>
    request<Record<string, unknown>>("/api/v1/correlate", {
      method: "POST",
      body: JSON.stringify(window_hours ? { window_hours } : {}),
    }),
  feedback: (object_id: string, label: string, note = "") =>
    request<{ status: string }>("/api/v1/feedback", {
      method: "POST",
      body: JSON.stringify({ object_type: "campaign", object_id, label, note }),
    }),
  findings: () => request<{ items: Finding[] }>("/api/v1/websec/findings"),
  scopes: () => request<{ items: Scope[] }>("/api/v1/websec/scopes"),
  createScope: (body: Record<string, unknown>) =>
    request<Scope>("/api/v1/websec/scopes", { method: "POST", body: JSON.stringify(body) }),
  assess: (target: string, active_checks: boolean) =>
    request<Record<string, unknown>>("/api/v1/websec/assess", {
      method: "POST",
      body: JSON.stringify({ target, active_checks }),
    }),
  cryptoAssets: () => request<{ items: CryptoAsset[]; provider: string }>("/api/v1/crypto/assets"),
  cryptoRefresh: (symbols: string[]) =>
    request<Record<string, unknown>>("/api/v1/crypto/refresh", {
      method: "POST",
      body: JSON.stringify({ symbols }),
    }),
  responses: () => request<{ items: ResponseRecord[] }>("/api/v1/responses"),
  policies: () => request<{ version: string; rules: unknown[]; adapter: { name: string; enforced: boolean } }>(
    "/api/v1/responses/policies",
  ),
  createResponse: (body: Record<string, unknown>) =>
    request<ResponseRecord>("/api/v1/responses", { method: "POST", body: JSON.stringify(body) }),
  approveResponse: (id: string) =>
    request<ResponseRecord>(`/api/v1/responses/${id}/approve`, { method: "POST" }),
  rollbackResponse: (id: string) =>
    request<ResponseRecord>(`/api/v1/responses/${id}/rollback`, { method: "POST" }),
  disableResponses: () =>
    request<{ rolled_back: number }>("/api/v1/responses/emergency-disable", { method: "POST" }),
  sources: () => request<{ sources: SourceHealth[] }>("/api/v1/sources"),
  profiles: () => request<{ items: DecoyProfile[] }>("/api/v1/honeypot/profiles"),
  decoySessions: (hours = 24, limit = 20) =>
    request<{ window_hours: number; items: DecoySession[]; note: string }>(
      `/api/v1/honeypot/sessions?hours=${hours}&limit=${limit}`,
    ),
  investigations: () => request<{ items: Investigation[] }>("/api/v1/investigations"),
  planInvestigation: (body: Record<string, unknown>) =>
    request<Record<string, unknown>>("/api/v1/investigations", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  activateInvestigation: (id: string, source_ip: string) =>
    request<Record<string, unknown>>(`/api/v1/investigations/${id}/activate`, {
      method: "POST",
      body: JSON.stringify({ source_ip, ttl_minutes: 15 }),
    }),
  evaluateInvestigation: (id: string) =>
    request<Record<string, unknown>>(`/api/v1/investigations/${id}/evaluate`, { method: "POST" }),
  users: () => request<{ users: User[] }>("/api/v1/auth/users"),
  createUser: (body: {
    email: string;
    name: string;
    role: Role;
    password: string;
  }) =>
    request<User>("/api/v1/auth/users", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  quarantine: () => request<{ items: QuarantineRecord[] }>("/api/v1/quarantine"),
  audit: () => request<{ items: AuditEntry[] }>("/api/v1/audit"),
  retention: (params: RetentionQuery = {}) =>
    request<RetentionStatus>(`/api/v1/retention${retentionQuery(params)}`),
  retentionHistoryCsv: (params: RetentionQuery = {}) =>
    requestBlob(`/api/v1/retention/history.csv${retentionQuery(params)}`),
  runRetention: () =>
    request<RetentionRunResult>("/api/v1/retention/run", { method: "POST" }),
  latestRun: () =>
    request<{ run: CorrelationRun | null; algorithm: Record<string, unknown> }>(
      "/api/v1/correlation/latest",
    ),
};

export interface EventRecord {
  id: string;
  occurred_at: string;
  received_at: string;
  source_module: string;
  event_type: string;
  source_ip: string | null;
  session_id: string | null;
  target_id: string | null;
  severity: string;
  provenance: Record<string, unknown>;
  features: Record<string, unknown>;
  evidence_refs: string[];
  synthetic: boolean;
}

export interface GraphView {
  window_hours: number;
  // Node props are served by the campaign detail endpoint, not copied into
  // every node of the graph payload.
  nodes: { id: string; kind: string; label: string; first_seen?: string; last_seen: string }[];
  node_count?: number;
  edge_count?: number;
  limits?: { nodes: number; edges: number };
  truncated?: { nodes: boolean; edges: boolean };
  edges: {
    id: string;
    kind: string;
    source: string;
    target: string;
    confidence: number;
    score: number;
    status: string;
    campaign_id: string | null;
    explanation: string;
    contradictions: unknown[];
  }[];
  note: string;
}

export interface Campaign {
  id: string;
  name: string;
  status: string;
  confidence: number;
  summary: string;
  updated_at: string;
  member_count: number;
  ip_count: number;
}

export interface CampaignDetail {
  campaign: Campaign;
  sessions: {
    id: string;
    source_ips: string[];
    event_count: number;
    severity_max: string;
    first_seen: string;
    last_seen: string;
  }[];
  edges: {
    id: string;
    source: string;
    target: string;
    confidence: number;
    score: number;
    status: string;
    updated_at?: string;
    evidence: {
      explanation?: string;
      components?: {
        name: string;
        family: string;
        weight?: number;
        available: boolean;
        score: number;
        detail: string;
      }[];
      missing_evidence?: string[];
      anchors?: string[];
    };
    contradictions: { code: string; detail: string }[];
  }[];
  ips: string[];
  explanation: {
    what_happened: string;
    why_flagged: string;
    assets_involved: string[];
    confidence: number;
    severity: string;
    risk: {
      risk_score: number;
      risk_level: string;
      recommended_action: string;
      formula: string;
      factors: { name: string; input: string | number; value: number; note: string }[];
      caveat: string;
    };
    timeline: { at: string; session: string; event: string }[];
  };
  evidence_plan: {
    items: {
      family: string;
      missing_on_edges: number;
      weight_at_stake: number;
      components: string[];
      guidance: string;
    }[];
    family_coverage: Record<string, number>;
    absent_families: string[];
    note: string;
  };
  observation: {
    observations: number;
    sessions: number;
    source_ips: number;
    linked_pairs: number;
    observations_per_link: number | null;
    observations_per_session: number | null;
    compression: number | null;
    note: string;
  };
  kill_chain: {
    tactics: {
      key: string;
      label: string;
      weight: number;
      observed: boolean;
      sessions: string[];
      session_count: number;
      evidence: string[];
    }[];
    observed: string[];
    coverage: number;
    risk_weighted_coverage: number;
    observed_weight: number;
    total_weight: number;
    furthest: { key: string; label: string } | null;
    asset_criticality: string;
    note: string;
  };
}

export interface Finding {
  id: string;
  ts: string;
  target: string;
  check_id: string;
  title: string;
  severity: string;
  confidence: string;
  evidence: Record<string, unknown>;
  remediation: string;
  status: string;
}

export interface Scope {
  id: string;
  domain: string;
  authorized_by: string;
  authorized_at: string;
  expires_at: string;
  allow_active: boolean;
  expired?: boolean;
}

export interface CryptoAsset {
  symbol: string;
  observed: {
    price_usd: number | null;
    change_24h_pct: number | null;
    market_cap_usd: number | null;
    volume_24h_usd: number | null;
    fetched_at: string;
    source: string;
  };
  inferred: { score: number; severity: string; confidence: number; reasons: { code: string; detail: string }[] } | null;
  freshness_seconds: number;
  stale: boolean;
  provenance: { provider: string; raw_digest: string };
  disclaimer: string;
}

export interface ResponseRecord {
  id: string;
  created_at: string;
  action: string;
  target: string;
  status: string;
  policy_id: string;
  reason: string;
  confidence: number;
  approved_by: string | null;
  expires_at: string | null;
  applied_at: string | null;
  rolled_back_at: string | null;
}

export interface SourceHealth {
  source: string;
  last_event_at: string | null;
  ok: boolean;
  error_count: number;
  detail: Record<string, unknown>;
}

export interface DecoySession {
  session_id: string;
  first_seen: string;
  last_seen: string;
  events: number;
  source_ips: string[];
  severity: string;
  target: string | null;
}

export interface DecoyProfile {
  id: string;
  name: string;
  kind: string;
  description: string;
  enabled: boolean;
}

export interface Investigation {
  id: string;
  created_at: string;
  updated_at?: string;
  campaign_id: string | null;
  edge_id: string | null;
  status: string;
  source_ip?: string | null;
  expires_at?: string | null;
  chosen_profile: string | null;
  missing_evidence: string[];
  outcome: string | null;
  notes: string;
  hypothesis_before?: { confidence?: number; at?: string };
  hypothesis_after?: { confidence?: number; at?: string } | null;
}

export interface SignInAnomaly {
  kind: "new_network" | "distant_signin";
  previous_ip: string | null;
  previous_at: string;
  detected_at: string;
  network?: string | null;
  distance_km?: number;
  threshold_km?: number;
  window_minutes?: number;
}

export interface SessionRecord {
  id: string;
  occurred_at: string;
  event: "sign_in" | "password_changed" | "sessions_revoked" | string;
  ip: string | null;
  client: string | null;
  outcome: string;
  session_version: number | null;
  state?: "active" | "expired" | "revoked" | "unknown";
  expires_at?: string | null;
  anomaly?: SignInAnomaly | null;
  jti?: string | null;
  current?: boolean;
  revoked_jti?: string | null;
}

export interface SessionHistory {
  user_id: string;
  sessions: SessionRecord[];
  current_session_version: number;
  note: string;
}

export interface AgentToken {
  id: string;
  name: string;
  prefix: string;
  role: string;
  created_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
}

export interface QuarantineRecord {
  id: string;
  received_at: string;
  source_module: string | null;
  reason_code: string;
  reason: string;
  status: string;
}

export interface CorrelationRun {
  run_id: string;
  finished_at: string;
  sessions: number;
  campaigns: number;
  edges_created: number;
  edges_updated: number;
  edges_expired: number;
  algorithm_version: string;
  trigger: string;
  metrics: Record<string, unknown>;
}

export interface AuditEntry {
  id: string;
  ts: string;
  actor_id: string | null;
  actor_role: string | null;
  action: string;
  object_type: string | null;
  object_id: string | null;
  outcome: string;
  detail: Record<string, unknown>;
  request_ip: string | null;
}

export interface RetentionRun {
  id: string;
  ran_at: string;
  trigger: "manual" | "scheduled";
  duration_ms: number;
  events_removed: number;
  edges_removed: number;
  observations_removed: number;
  nodes_removed: number;
  events_expired: number;
  retired_edges: number;
  stale_observations: number;
  graph_nodes: number;
  graph_edges: number;
  overdue: boolean;
}

export interface RetentionRunResult {
  run_id: string;
  trigger: string;
  duration_ms: number;
  overdue: boolean;
  events: { days: number; cutoff: string; events: number };
  graph: {
    days: number;
    cutoff: string;
    edges: number;
    observations: number;
    nodes: number;
  };
}

export interface RetentionStatus {
  generated_at: string;
  overdue: boolean;
  grace_days: number;
  history_total: number;
  history_counts: { manual: number; scheduled: number };
  history: RetentionRun[];
  events: {
    retention_days: number;
    total: number;
    expired: number;
    oldest_occurred_at: string | null;
    oldest_retention_until: string | null;
  };
  graph: {
    retention_days: number;
    cutoff: string;
    nodes: number;
    edges: number;
    retired_edges: number;
    stale_observations: number;
    orphan_nodes: number;
  };
}
