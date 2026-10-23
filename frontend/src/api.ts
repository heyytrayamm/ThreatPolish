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

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string | null): void {
  if (token) localStorage.setItem(TOKEN_KEY, token);
  else localStorage.removeItem(TOKEN_KEY);
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
  if (!response.ok) {
    const error = (payload as { error?: ApiError } | null)?.error ?? {
      code: "request_failed",
      message: `Request failed with status ${response.status}`,
      details: {},
    };
    if (response.status === 401) setToken(null);
    throw new ApiFailure(response.status, error);
  }
  return payload as T;
}

export const api = {
  login: (email: string, password: string) =>
    request<{ access_token: string; user: User; expires_at: string }>("/api/v1/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),
  me: () => request<User & { via: string }>("/api/v1/auth/me"),
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
  profiles: () => request<{ items: DecoyProfile[] }>("/api/v1/honeypot/profiles").catch(() => ({ items: [] })),
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
  quarantine: () => request<{ items: QuarantineRecord[] }>("/api/v1/quarantine"),
  audit: () => request<{ items: AuditEntry[] }>("/api/v1/audit"),
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
  nodes: { id: string; kind: string; label: string; props: Record<string, unknown>; last_seen: string }[];
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
    confidence: number;
    score: number;
    status: string;
    evidence: {
      explanation?: string;
      components?: { name: string; family: string; available: boolean; score: number; detail: string }[];
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
  campaign_id: string | null;
  edge_id: string | null;
  status: string;
  chosen_profile: string | null;
  missing_evidence: string[];
  outcome: string | null;
  notes: string;
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
