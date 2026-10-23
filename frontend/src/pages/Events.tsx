import { useEffect, useState } from "react";
import { api, EventRecord } from "../api";
import { Badge, Card, Empty, ErrorBox, Field, formatTime, JsonBlock, Loading, useAsync } from "../ui";

const PAGE_SIZE = 25;

export default function Events() {
  const [module, setModule] = useState("");
  const [severity, setSeverity] = useState("");
  const [query, setQuery] = useState("");
  const [hours, setHours] = useState(24);
  const [page, setPage] = useState(0);
  const [live, setLive] = useState(true);
  const [tick, setTick] = useState(0);
  const [selected, setSelected] = useState<EventRecord | null>(null);

  useEffect(() => {
    if (!live) return;
    const timer = window.setInterval(() => setTick((value) => value + 1), 10000);
    return () => window.clearInterval(timer);
  }, [live]);

  useEffect(() => setPage(0), [module, severity, query, hours]);

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
          <h1>Events</h1>
          <p className="muted">Normalized telemetry from decoys, assessments and application sources.</p>
        </div>
        <label className="toggle">
          <input type="checkbox" checked={live} onChange={(event) => setLive(event.target.checked)} />
          <span>Auto refresh</span>
        </label>
      </header>

      <div className="filters">
        <Field label="Module">
          <select value={module} onChange={(event) => setModule(event.target.value)}>
            <option value="">All</option>
            <option value="honeypot">honeypot</option>
            <option value="websec">websec</option>
            <option value="cryptointel">cryptointel</option>
            <option value="app">app</option>
          </select>
        </Field>
        <Field label="Severity">
          <select value={severity} onChange={(event) => setSeverity(event.target.value)}>
            <option value="">Any</option>
            <option value="critical">critical</option>
            <option value="high">high</option>
            <option value="medium">medium</option>
            <option value="low">low</option>
            <option value="info">info</option>
          </select>
        </Field>
        <Field label="Window">
          <select value={hours} onChange={(event) => setHours(Number(event.target.value))}>
            <option value={1}>1 hour</option>
            <option value={24}>24 hours</option>
            <option value={72}>72 hours</option>
            <option value={168}>7 days</option>
          </select>
        </Field>
        <Field label="Search">
          <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="session, IP or target" />
        </Field>
      </div>

      <ErrorBox message={result.error} />
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
