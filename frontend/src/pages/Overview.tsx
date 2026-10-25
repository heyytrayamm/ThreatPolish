import { useEffect, useState } from "react";
import { api, SessionRecord, User } from "../api";
import { describeSignInAnomaly } from "../components/SessionTable";
import { Badge, Card, Empty, ErrorBox, Field, formatTime, Loading, can, useAsync } from "../ui";

export default function Overview({ user }: { user: User }) {
  const [hours, setHours] = useState(24);
  const [tick, setTick] = useState(0);
  const [running, setRunning] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  useEffect(() => {
    const timer = window.setInterval(() => setTick((value) => value + 1), 15000);
    return () => window.clearInterval(timer);
  }, []);

  const summary = useAsync(() => api.summary(hours), [hours, tick]);
  const sources = useAsync(() => api.sources(), [tick]);
  const latest = useAsync(() => api.latestRun(), [tick]);
  const campaigns = useAsync(() => api.campaigns(), [tick]);
  const sessions = useAsync(() => api.sessions(10), [tick]);
  const audit = useAsync(
    () => (user.role === "admin" ? api.audit() : Promise.resolve(null)),
    [user.role, tick],
  );
  // Retention counts scan the event and graph tables, so they refresh far less
  // often than the dashboard metrics. Analysts can read the status without the
  // account and credential panels that Administration exposes.
  const canReadRetention = user.role === "admin" || user.role === "analyst";
  const [retentionTick, setRetentionTick] = useState(0);
  useEffect(() => {
    if (!canReadRetention) return;
    const timer = window.setInterval(() => setRetentionTick((value) => value + 1), 60000);
    return () => window.clearInterval(timer);
  }, [canReadRetention]);
  const retention = useAsync(
    () => (canReadRetention ? api.retention() : Promise.resolve(null)),
    [canReadRetention, retentionTick],
  );

  async function runCorrelation() {
    setRunning(true);
    setNotice(null);
    try {
      const result = await api.correlate();
      setNotice(
        `Correlation finished: ${result.sessions} sessions, ${result.campaigns} campaign candidates, ` +
          `${result.edges_created} new edges.`,
      );
      setTick((value) => value + 1);
    } catch (error) {
      setNotice((error as Error).message);
    } finally {
      setRunning(false);
    }
  }

  const data = summary.data;
  const maxHour = Math.max(1, ...(data?.hourly.map((point) => point.count) ?? [1]));
  const ownAlerts = (sessions.data?.sessions ?? []).filter(
    (entry: SessionRecord) => entry.anomaly,
  );
  const fleetAlerts = (audit.data?.items ?? []).filter(
    (entry) => entry.action === "auth.signin.anomaly",
  );

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>Overview</h1>
          <p className="muted">Live telemetry, correlation status and campaign candidates.</p>
        </div>
        <div className="row">
          <Field label="Window">
            <select value={hours} onChange={(event) => setHours(Number(event.target.value))}>
              <option value={6}>6 hours</option>
              <option value={24}>24 hours</option>
              <option value={72}>72 hours</option>
              <option value={168}>7 days</option>
            </select>
          </Field>
          {can(user.role, "analyse") && (
            <button onClick={runCorrelation} disabled={running}>
              {running ? "Running…" : "Run correlation"}
            </button>
          )}
        </div>
      </header>

      <ErrorBox message={summary.error ?? sources.error ?? campaigns.error} />
      {notice && <div className="notice">{notice}</div>}

      {retention.data?.overdue && (
        <div className="error" role="alert">
          <strong>Retention is overdue.</strong> The backlog is older than the{" "}
          {retention.data.grace_days}-day grace window. Check the scheduled retention service;{" "}
          {user.role === "admin"
            ? "Administration has the counts."
            : "The Retention page has the counts."}
        </div>
      )}

      {(ownAlerts.length > 0 || fleetAlerts.length > 0) && (
        <Card title="Sign-in attention">
          {ownAlerts.length > 0 && (
            <div className="error" role="alert">
              <strong>Unusual sign-in.</strong>{" "}
              {describeSignInAnomaly(ownAlerts[0].anomaly as NonNullable<SessionRecord["anomaly"]>)}
            </div>
          )}
          {fleetAlerts.length > 0 && (
            <p className="muted small">
              {fleetAlerts.length} sign-in {fleetAlerts.length === 1 ? "alert" : "alerts"} recorded in the
              recent audit trail. Open an account's sessions under Administration to review them.
            </p>
          )}
        </Card>
      )}

      <div className="metrics">
        <Metric label="Events" value={data?.total ?? 0} />
        <Metric label="Severe events" value={(data?.by_severity.high ?? 0) + (data?.by_severity.critical ?? 0)} />
        <Metric label="Sessions correlated" value={latest.data?.run?.sessions ?? 0} />
        <Metric label="Campaign candidates" value={campaigns.data?.items.length ?? 0} />
      </div>

      <div className="grid two">
        <Card title={`Event volume (last ${hours}h)`}>
          {summary.loading && <Loading />}
          {data && data.hourly.length === 0 && <Empty>No events have been ingested in this window.</Empty>}
          {data && data.hourly.length > 0 && (
            <svg className="bars" viewBox="0 0 620 120" role="img" aria-label="Hourly event counts">
              <line x1={10} y1={100} x2={610} y2={100} className="bar-axis" />
              {data.hourly.map((point, index) => {
                const slot = 600 / Math.max(1, data.hourly.length);
                const width = Math.max(2, Math.min(44, slot - 4));
                const height = (point.count / maxHour) * 90;
                const x = 10 + index * slot + (slot - width) / 2;
                return (
                  <g key={point.hour}>
                    <rect
                      x={x}
                      y={100 - height}
                      width={width}
                      height={height}
                      rx={2}
                      className="bar"
                    />
                    {data.hourly.length <= 8 && (
                      <text x={x + width / 2} y={Math.max(10, 94 - height)} className="bar-label">
                        {point.count}
                      </text>
                    )}
                    <title>{`${point.hour}:00 — ${point.count} events`}</title>
                  </g>
                );
              })}
            </svg>
          )}
        </Card>

        <Card title="Modules and severity">
          {data && (
            <div className="split">
              <div>
                <h3>By module</h3>
                {Object.entries(data.by_module).map(([name, count]) => (
                  <div className="kv" key={name}>
                    <span>{name}</span>
                    <strong>{count}</strong>
                  </div>
                ))}
                {Object.keys(data.by_module).length === 0 && <Empty>No data</Empty>}
              </div>
              <div>
                <h3>By severity</h3>
                {Object.entries(data.by_severity).map(([name, count]) => (
                  <div className="kv" key={name}>
                    <Badge value={name} />
                    <strong>{count}</strong>
                  </div>
                ))}
                {Object.keys(data.by_severity).length === 0 && <Empty>No data</Empty>}
              </div>
            </div>
          )}
        </Card>
      </div>

      <div className="grid two">
        <Card title="Latest correlation run">
          {latest.loading && <Loading />}
          {latest.data?.run ? (
            <div className="stack">
              <div className="kv"><span>Finished</span><strong>{formatTime(latest.data.run.finished_at)}</strong></div>
              <div className="kv"><span>Trigger</span><strong>{latest.data.run.trigger}</strong></div>
              <div className="kv"><span>Sessions</span><strong>{latest.data.run.sessions}</strong></div>
              <div className="kv"><span>Edges created / updated</span><strong>{latest.data.run.edges_created} / {latest.data.run.edges_updated}</strong></div>
              <div className="kv"><span>Campaign candidates</span><strong>{latest.data.run.campaigns}</strong></div>
              <div className="kv"><span>Algorithm</span><strong>{latest.data.run.algorithm_version}</strong></div>
            </div>
          ) : (
            !latest.loading && <Empty>No correlation run has been recorded yet.</Empty>
          )}
        </Card>

        <Card title="Source health">
          {sources.loading && <Loading />}
          {sources.data && sources.data.sources.length === 0 && <Empty>No sensors have reported yet.</Empty>}
          {sources.data && sources.data.sources.length > 0 && (
            <table>
              <thead>
                <tr><th>Source</th><th>Status</th><th>Last event</th><th>Errors</th></tr>
              </thead>
              <tbody>
                {sources.data.sources.map((source) => (
                  <tr key={source.source}>
                    <td>{source.source}</td>
                    <td>{source.ok ? <span className="ok">ok</span> : <span className="bad">failing</span>}</td>
                    <td>{formatTime(source.last_event_at)}</td>
                    <td>{source.error_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </div>

      <Card title="Recent campaign candidates">
        {campaigns.loading && <Loading />}
        {campaigns.data && campaigns.data.items.length === 0 && (
          <Empty>No campaigns yet. Ingest telemetry and run correlation.</Empty>
        )}
        {campaigns.data && campaigns.data.items.length > 0 && (
          <table>
            <thead>
              <tr><th>Name</th><th>Status</th><th>Confidence</th><th>Sessions</th><th>IPs</th><th>Updated</th></tr>
            </thead>
            <tbody>
              {campaigns.data.items.slice(0, 5).map((campaign) => (
                <tr key={campaign.id}>
                  <td>{campaign.name}</td>
                  <td><Badge value={campaign.status} kind="status" /></td>
                  <td>{campaign.confidence.toFixed(2)}</td>
                  <td>{campaign.member_count}</td>
                  <td>{campaign.ip_count}</td>
                  <td>{formatTime(campaign.updated_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <div className="metric">
      <span className="muted small">{label}</span>
      <strong>{value}</strong>
    </div>
  );
}
