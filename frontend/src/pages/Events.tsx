import { useEffect, useState } from "react";
import { api, EventRecord } from "../api";
import { copyText } from "../clipboard";
import { Badge, Card, Empty, ErrorBox, Field, formatTime, JsonBlock, Loading, useAsync } from "../ui";

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

  // The committed filter set is shareable and survives a reload, like the
  // Retention window. Invalid URL values are removed on mount; pagination stays
  // out of the URL because it moves with new events.
  useEffect(() => {
    rememberFilters(initial, "replace");
  }, [initial]);

  // Filter changes push history entries; back and forward restore the form and
  // the result window instead of only moving between views.
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
      // Include a search term that has been typed but not committed yet.
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
          <span className="eyebrow">Event stream</span>
          <h1>Events</h1>
          <p className="muted">Normalized telemetry from decoys, assessments and application sources.</p>
        </div>
        <label className="toggle">
          <input type="checkbox" checked={live} onChange={(event) => setLive(event.target.checked)} />
          <span>Auto refresh</span>
        </label>
      </header>

      <div className="filters control-strip">
        <span className="strip-label">Filter bank</span>
        <Field label="Module">
          <select
            value={module}
            onChange={(event) =>
              commitFilters({ ...filters, module: event.target.value })
            }
          >
            <option value="">All</option>
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
            <option value="">Any</option>
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
            placeholder="session, IP or target"
          />
        </Field>
        <button
          type="button"
          className="secondary"
          disabled={copyBusy}
          onClick={copyLink}
        >
          {copyBusy ? "Copying…" : "Copy link"}
        </button>
      </div>

      <ErrorBox message={result.error} />
      {notice && <div className="notice">{notice}</div>}
      <Card
        title={`${total} event${total === 1 ? "" : "s"}`}
        actions={
          <div className="row">
            <button className="secondary" disabled={page === 0} onClick={() => setPage((value) => value - 1)}>
              Previous
            </button>
            <span className="muted small">
              page {total === 0 ? 0 : page + 1} of {Math.max(1, Math.ceil(total / PAGE_SIZE))}
            </span>
            <button className="secondary" disabled={(page + 1) * PAGE_SIZE >= total} onClick={() => setPage((value) => value + 1)}>
              Next
            </button>
          </div>
        }
      >
        {result.loading && <Loading />}
        {!result.loading && events.length === 0 && <Empty>No events match these filters.</Empty>}
        {events.length > 0 && (
          <table className="clickable">
            <thead>
              <tr>
                <th>Time</th><th>Module</th><th>Type</th><th>Source</th><th>Session</th><th>Severity</th>
              </tr>
            </thead>
            <tbody>
              {events.map((event) => (
                <tr key={event.id} onClick={() => setSelected(event)}>
                  <td>{formatTime(event.occurred_at)}</td>
                  <td>{event.source_module}</td>
                  <td className="mono">{event.event_type}</td>
                  <td className="mono">{event.source_ip ?? "—"}</td>
                  <td className="mono">{event.session_id ?? "—"}</td>
                  <td><Badge value={event.severity} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      {selected && (
        <Card
          title="Event detail"
          actions={<button className="secondary" onClick={() => setSelected(null)}>Close</button>}
        >
          <div className="stack">
            <div className="kv"><span>ID</span><strong className="mono">{selected.id}</strong></div>
            <div className="kv"><span>Occurred</span><strong>{formatTime(selected.occurred_at)}</strong></div>
            <div className="kv"><span>Received</span><strong>{formatTime(selected.received_at)}</strong></div>
            <div className="kv"><span>Module / type</span><strong>{selected.source_module} / {selected.event_type}</strong></div>
            <div className="kv"><span>Target</span><strong>{selected.target_id ?? "—"}</strong></div>
            <div className="kv"><span>Provenance</span><strong>{selected.provenance.synthetic ? "synthetic (test/fixture)" : "live sensor"}</strong></div>
            <h3>Normalized features</h3>
            <JsonBlock value={selected.features} />
            <h3>Provenance</h3>
            <JsonBlock value={selected.provenance} />
          </div>
        </Card>
      )}
    </div>
  );
}
