import { useEffect, useState } from "react";
import { api, EventRecord } from "../api";
import { copyText } from "../clipboard";
import {
  Badge,
  Card,
  Empty,
  ErrorBox,
  Field,
  formatTime,
  JsonBlock,
  Loading,
  useAsync,
} from "../ui";

const PAGE_SIZE = 25;
const MODULES = ["honeypot", "websec", "cryptointel", "app"];
const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const WINDOWS = [1, 24, 72, 168];

type EventFilters = {
  module: string;
  severity: string;
  query: string;
  hours: number;
};

function readFiltersFromUrl(): EventFilters {
  const params = new URLSearchParams(window.location.search);
  const module = params.get("event_module") ?? "";
  const severity = params.get("event_severity") ?? "";
  const hours = Number(params.get("event_hours") ?? 24);
  return {
    module: MODULES.includes(module) ? module : "",
    severity: SEVERITIES.includes(severity) ? severity : "",
    hours: WINDOWS.includes(hours) ? hours : 24,
    query: params.get("event_q") ?? "",
  };
}

function filtersUrl(filters: EventFilters): URL {
  const url = new URL(window.location.href);
  const params = url.searchParams;
  const values: [string, string][] = [
    ["event_module", filters.module],
    ["event_severity", filters.severity],
    ["event_q", filters.query],
    ["event_hours", filters.hours === 24 ? "" : String(filters.hours)],
  ];
  for (const [key, value] of values) {
    if (value) params.set(key, value);
    else params.delete(key);
  }
  return url;
}

function rememberFilters(
  filters: EventFilters,
  mode: "push" | "replace",
): void {
  const url = filtersUrl(filters);
  const next = `${url.pathname}${url.search}${url.hash}`;
  const current = `${window.location.pathname}${window.location.search}${window.location.hash}`;
  if (next === current) return;
  if (mode === "replace") window.history.replaceState(null, "", url);
  else window.history.pushState(null, "", url);
}

export default function Events() {
  const [initial] = useState(readFiltersFromUrl);
  const [module, setModule] = useState(initial.module);
  const [severity, setSeverity] = useState(initial.severity);
  const [query, setQuery] = useState(initial.query);
  const [hours, setHours] = useState(initial.hours);
  const [page, setPage] = useState(0);
  const [live, setLive] = useState(true);
  const [tick, setTick] = useState(0);
  const [selected, setSelected] = useState<EventRecord | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [copyBusy, setCopyBusy] = useState(false);
  const filters: EventFilters = { module, severity, query, hours };

  useEffect(() => {
    if (!live) return;
    const timer = window.setInterval(() => setTick((value) => value + 1), 10000);
    return () => window.clearInterval(timer);
  }, [live]);

  useEffect(() => setPage(0), [module, severity, query, hours]);

  useEffect(() => {
    rememberFilters(initial, "replace");
  }, [initial]);

  useEffect(() => {
    function handlePopState() {
      const next = readFiltersFromUrl();
      setModule(next.module);
      setSeverity(next.severity);
      setQuery(next.query);
      setHours(next.hours);
      setPage(0);
    }
    window.addEventListener("popstate", handlePopState);
    return () => window.removeEventListener("popstate", handlePopState);
  }, []);

  function commitFilters(next: EventFilters) {
    setModule(next.module);
    setSeverity(next.severity);
    setQuery(next.query);
    setHours(next.hours);
    rememberFilters(next, "push");
  }

  async function copyLink() {
    setCopyBusy(true);
    setNotice(null);
    try {
      await copyText(filtersUrl(filters).toString());
      setNotice("Link copied to the clipboard.");
    } catch (error) {
      setNotice(`Could not copy the link: ${(error as Error).message}`);
    } finally {
      setCopyBusy(false);
    }
  }

  const since = new Date(Date.now() - hours * 3600 * 1000).toISOString();
  const result = useAsync(
    () =>
      api.events({
        limit: PAGE_SIZE,
        offset: page * PAGE_SIZE,
        module,
        severity,
        q: query,
        since,
      }),
    [module, severity, query, hours, page, tick],
  );

  const events = result.data?.items ?? [];
  const total = result.data?.total ?? 0;

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <span className="eyebrow">Telemetry Stream</span>
          <h1>Security Event Explorer</h1>
          <p className="muted">Normalized telemetry ingested from decoys, vulnerability assessments and security hooks.</p>
        </div>
        <div className="row">
          <label className="row" style={{ cursor: "pointer", fontSize: "0.85rem" }}>
            <input
              type="checkbox"
              checked={live}
              onChange={(event) => setLive(event.target.checked)}
              style={{ width: "auto" }}
            />
            <span className="muted">Live Stream (10s)</span>
          </label>
        </div>
      </header>

      {/* Filter Control Station */}
      <Card title="Filter Bank" actions={
        <button
          type="button"
          className="secondary small"
          disabled={copyBusy}
          onClick={copyLink}
        >
          {copyBusy ? "Copying..." : "Copy link"}
        </button>
      }>
        <div className="grid" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(170px, 1fr))", gap: "1rem", alignItems: "flex-end" }}>
          <Field label="Module">
            <select
              value={module}
              onChange={(event) =>
                commitFilters({ ...filters, module: event.target.value })
              }
            >
              <option value="">All Modules</option>
              <option value="honeypot">honeypot</option>
              <option value="websec">websec</option>
              <option value="cryptointel">cryptointel</option>
              <option value="app">app</option>
            </select>
          </Field>
          <Field label="Severity">
            <select
              value={severity}
              onChange={(event) =>
                commitFilters({ ...filters, severity: event.target.value })
              }
            >
              <option value="">Any Severity</option>
              <option value="critical">critical</option>
              <option value="high">high</option>
              <option value="medium">medium</option>
              <option value="low">low</option>
              <option value="info">info</option>
            </select>
          </Field>
          <Field label="Window">
            <select
              value={hours}
              onChange={(event) =>
                commitFilters({ ...filters, hours: Number(event.target.value) })
              }
            >
              <option value={1}>1 hour</option>
              <option value={24}>24 hours</option>
              <option value={72}>72 hours</option>
              <option value={168}>7 days</option>
            </select>
          </Field>
          <Field label="Search">
            <div style={{ position: "relative" }}>
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                onBlur={(event) =>
                  commitFilters({ ...filters, query: event.currentTarget.value })
                }
                onKeyDown={(event) => {
                  if (event.key === "Enter") {
                    commitFilters({ ...filters, query: event.currentTarget.value });
                  }
                }}
                placeholder="Session, IP or target..."
              />
            </div>
          </Field>
        </div>
      </Card>

      <ErrorBox message={result.error} />
      {notice && <div className="notice">{notice}</div>}

      {/* Events Table View */}
      <Card
        title={`${total} event${total === 1 ? "" : "s"} observed`}
        actions={
          <div className="row">
            <button
              type="button"
              className="secondary small"
              disabled={page === 0}
              onClick={() => setPage((value) => value - 1)}
            >
              Previous
            </button>
            <span className="mono small muted">
              page {total === 0 ? 0 : page + 1} of {Math.max(1, Math.ceil(total / PAGE_SIZE))}
            </span>
            <button
              type="button"
              className="secondary small"
              disabled={(page + 1) * PAGE_SIZE >= total}
              onClick={() => setPage((value) => value + 1)}
            >
              Next
            </button>
          </div>
        }
      >
        {result.loading && <Loading label="Querying event records" />}
        {!result.loading && events.length === 0 && (
          <Empty title="No matching events">Try adjusting the filter criteria, search term, or time window.</Empty>
        )}
        {events.length > 0 && (
          <div style={{ overflowX: "auto" }}>
            <table>
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Module</th>
                  <th>Event Type</th>
                  <th>Source IP</th>
                  <th>Session ID</th>
                  <th>Severity</th>
                </tr>
              </thead>
              <tbody>
                {events.map((event) => (
                  <tr
                    key={event.id}
                    onClick={() => setSelected(event)}
                    style={{ cursor: "pointer" }}
                    className={selected?.id === event.id ? "row-selected" : ""}
                  >
                    <td className="mono small">{formatTime(event.occurred_at)}</td>
                    <td><span className="mono">{event.source_module}</span></td>
                    <td className="mono"><strong>{event.event_type}</strong></td>
                    <td className="mono text-code">{event.source_ip ?? "-"}</td>
                    <td className="mono small">{event.session_id ? `${event.session_id.slice(0, 14)}...` : "-"}</td>
                    <td><Badge value={event.severity} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Selected Event Inspection Drawer */}
      {selected && (
        <Card
          title={`Event Inspection: ${selected.id}`}
          actions={
            <button
              type="button"
              className="secondary small"
              onClick={() => setSelected(null)}
            >
              Close Inspector
            </button>
          }
        >
          <div className="stack" style={{ gap: "1rem" }}>
            <div className="grid two" style={{ gap: "0.5rem" }}>
              <div className="row" style={{ justifyContent: "space-between" }}>
                <span className="muted">Event Identifier</span>
                <span className="mono">{selected.id}</span>
              </div>
              <div className="row" style={{ justifyContent: "space-between" }}>
                <span className="muted">Occurred Time</span>
                <span className="mono">{formatTime(selected.occurred_at)}</span>
              </div>
              <div className="row" style={{ justifyContent: "space-between" }}>
                <span className="muted">Sensor Module</span>
                <span className="mono">{selected.source_module} / {selected.event_type}</span>
              </div>
              <div className="row" style={{ justifyContent: "space-between" }}>
                <span className="muted">Target Resource</span>
                <span className="mono">{selected.target_id ?? "-"}</span>
              </div>
              <div className="row" style={{ justifyContent: "space-between" }}>
                <span className="muted">Source IP</span>
                <span className="mono text-code">{selected.source_ip ?? "-"}</span>
              </div>
              <div className="row" style={{ justifyContent: "space-between" }}>
                <span className="muted">Session Ref</span>
                <span className="mono">{selected.session_id ?? "-"}</span>
              </div>
              <div className="row" style={{ justifyContent: "space-between" }}>
                <span className="muted">Provenance Mode</span>
                <span className="mono">{selected.provenance.synthetic ? "synthetic fixture" : "verified live sensor"}</span>
              </div>
              <div className="row" style={{ justifyContent: "space-between" }}>
                <span className="muted">Severity Class</span>
                <Badge value={selected.severity} />
              </div>
            </div>

            <h3 style={{ fontSize: "0.9rem", color: "var(--text-bright)", marginTop: "0.5rem" }}>
              Normalized Behavioral Features
            </h3>
            <JsonBlock value={selected.features} />

            <h3 style={{ fontSize: "0.9rem", color: "var(--text-bright)", marginTop: "0.5rem" }}>
              Provenance & Envelope Headers
            </h3>
            <JsonBlock value={selected.provenance} />
          </div>
        </Card>
      )}
    </div>
  );
}


