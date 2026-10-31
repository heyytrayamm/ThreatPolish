import { useEffect, useState } from "react";
import { api, SessionRecord, User } from "../api";
import { describeSignInAnomaly } from "../components/SessionTable";
import {
  Badge,
  Card,
  Empty,
  ErrorBox,
  Field,
  formatTime,
  IconActivity,
  IconAlertTriangle,
  IconNetwork,
  IconRefresh,
  IconShield,
  Loading,
  StatMetric,
  can,
  useAsync,
} from "../ui";

export default function Overview({
  user,
  onOpenRetention,
}: {
  user: User;
  onOpenRetention: () => void;
}) {
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
        `Correlation complete: ${result.sessions} sessions analyzed, ${result.campaigns} campaigns identified, ` +
          `${result.edges_created} evidence links verified.`,
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
  const severeEvents = (data?.by_severity.high ?? 0) + (data?.by_severity.critical ?? 0);
  const severeShare = data?.total ? severeEvents / data.total : 0;

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <span className="eyebrow">Telemetry Envelope</span>
          <h1>System Overview</h1>
          <p className="muted">Live sensor telemetry, behavioral correlation status and campaign clusters.</p>
        </div>
        <div className="row">
          <Field label="Window">
            <select value={hours} onChange={(event) => setHours(Number(event.target.value))}>
              <option value={6}>Past 6 hours</option>
              <option value={24}>Past 24 hours</option>
              <option value={72}>Past 72 hours</option>
              <option value={168}>Past 7 days</option>
            </select>
          </Field>
          {can(user.role, "analyse") && (
            <button type="button" className="primary" onClick={runCorrelation} disabled={running}>
              <IconRefresh size={14} />
              {running ? "Correlating..." : "Run Correlation"}
            </button>
          )}
        </div>
      </header>

      <ErrorBox message={summary.error ?? sources.error ?? campaigns.error} />
      {notice && <div className="notice">{notice}</div>}

      {retention.data?.overdue && (
        <div className="tp-alert tp-alert-error" role="alert">
          <IconAlertTriangle />
          <div className="tp-alert-content">
            <strong>Retention Maintenance Overdue</strong>
            <p>
              The event backlog is older than the {retention.data.grace_days}-day grace threshold. Run retention to purge expired telemetry.
            </p>
          </div>
          <button
            type="button"
            className="secondary small"
            onClick={onOpenRetention}
          >
            Open Retention
          </button>
        </div>
      )}

      {(ownAlerts.length > 0 || fleetAlerts.length > 0) && (
        <Card title="Authentication Anomalies" className="attention-card">
          {ownAlerts.length > 0 && (
            <div className="tp-alert tp-alert-error" role="alert">
              <IconAlertTriangle />
              <div className="tp-alert-content">
                <strong>Anomalous Operator Sign-in Detected</strong>
                <p>{describeSignInAnomaly(ownAlerts[0].anomaly as NonNullable<SessionRecord["anomaly"]>)}</p>
              </div>
            </div>
          )}
          {fleetAlerts.length > 0 && (
            <p className="muted small" style={{ marginTop: "0.5rem" }}>
              {fleetAlerts.length} sign-in {fleetAlerts.length === 1 ? "alert" : "alerts"} recorded in the audit trail.
              Inspect user sessions in Administration to revoke compromised devices.
            </p>
          )}
        </Card>
      )}

      {/* KPI Stat Cards */}
      <div className="tp-metric-grid">
        <StatMetric
          label="Total Ingested Events"
          value={data?.total?.toLocaleString() ?? 0}
          subvalue={`Window: past ${hours} hours`}
          icon={<IconActivity size={18} />}
        />
        <StatMetric
          label="High/Critical Events"
          value={severeEvents.toLocaleString()}
          subvalue={data?.total ? `${Math.round(severeShare * 100)}% severe share` : "Zero severe events"}
          trend={severeEvents > 0 ? "elevated" : "nominal"}
          trendPositive={severeEvents === 0}
          icon={<IconAlertTriangle size={18} />}
        />
        <StatMetric
          label="Sessions Correlated"
          value={latest.data?.run?.sessions ?? 0}
          subvalue={latest.data?.run ? `Algorithm: ${latest.data.run.algorithm_version}` : "No run recorded"}
          icon={<IconNetwork size={18} />}
        />
        <StatMetric
          label="Active Campaigns"
          value={campaigns.data?.items.length ?? 0}
          subvalue="Multi-session threat clusters"
          icon={<IconShield size={18} />}
        />
      </div>

      {/* Hourly Event Histogram & Classification Split */}
      <div className="grid two">
        <Card title={`Telemetry Ingestion Distribution (${hours}h Window)`}>
          {summary.loading && <Loading label="Loading event distribution" />}
          {data && data.hourly.length === 0 && <Empty>No events recorded in this time window.</Empty>}
          {data && data.hourly.length > 0 && (
            <div className="chart-wrapper">
              <svg className="bars" viewBox="0 0 620 130" role="img" aria-label="Hourly event distribution">
                <line x1={10} y1={105} x2={610} y2={105} stroke="rgba(56, 189, 248, 0.2)" strokeWidth={1} />
                {data.hourly.map((point, index) => {
                  const slot = 600 / Math.max(1, data.hourly.length);
                  const width = Math.max(3, Math.min(40, slot - 4));
                  const height = Math.max(2, (point.count / maxHour) * 85);
                  const x = 10 + index * slot + (slot - width) / 2;
                  return (
                    <g key={point.hour}>
                      <rect
                        x={x}
                        y={105 - height}
                        width={width}
                        height={height}
                        rx={2}
                        fill="var(--cyan)"
                        opacity={0.85}
                      />
                      {data.hourly.length <= 8 && (
                        <text
                          x={x + width / 2}
                          y={Math.max(12, 98 - height)}
                          textAnchor="middle"
                          fill="var(--text-secondary)"
                          fontSize="10"
                          fontFamily="var(--font-mono)"
                        >
                          {point.count}
                        </text>
                      )}
                      <title>{`${point.hour}:00 - ${point.count} events`}</title>
                    </g>
                  );
                })}
              </svg>
            </div>
          )}
        </Card>

        <Card title="Sensor Modules and Severity Distribution">
          {summary.loading && <Loading label="Loading classifications" />}
          {data && (
            <div className="grid two" style={{ gap: "1rem" }}>
              <div>
                <h3 className="small muted" style={{ marginBottom: "0.5rem", textTransform: "uppercase" }}>By Module</h3>
                <div className="stack" style={{ gap: "0.35rem" }}>
                  {Object.entries(data.by_module).map(([name, count]) => (
                    <div className="row" key={name} style={{ justifyContent: "space-between", padding: "0.25rem 0", borderBottom: "1px solid var(--border-subtle)" }}>
                      <span className="mono small">{name}</span>
                      <strong className="mono">{count}</strong>
                    </div>
                  ))}
                  {Object.keys(data.by_module).length === 0 && <Empty>No module data</Empty>}
                </div>
              </div>
              <div>
                <h3 className="small muted" style={{ marginBottom: "0.5rem", textTransform: "uppercase" }}>By Severity</h3>
                <div className="stack" style={{ gap: "0.35rem" }}>
                  {Object.entries(data.by_severity).map(([name, count]) => (
                    <div className="row" key={name} style={{ justifyContent: "space-between", padding: "0.25rem 0", borderBottom: "1px solid var(--border-subtle)" }}>
                      <Badge value={name} />
                      <strong className="mono">{count}</strong>
                    </div>
                  ))}
                  {Object.keys(data.by_severity).length === 0 && <Empty>No severity data</Empty>}
                </div>
              </div>
            </div>
          )}
        </Card>
      </div>

      {/* Correlation Engine Status & Sensor Cluster */}
      <div className="grid two">
        <Card title="Latest Behavioral Correlation Run">
          {latest.loading && <Loading label="Querying correlation engine" />}
          {latest.data?.run ? (
            <div className="stack" style={{ gap: "0.5rem" }}>
              <div className="row" style={{ justifyContent: "space-between" }}>
                <span className="muted">Completed At</span>
                <strong className="mono">{formatTime(latest.data.run.finished_at)}</strong>
              </div>
              <div className="row" style={{ justifyContent: "space-between" }}>
                <span className="muted">Trigger Origin</span>
                <span className="mono">{latest.data.run.trigger}</span>
              </div>
              <div className="row" style={{ justifyContent: "space-between" }}>
                <span className="muted">Analyzed Sessions</span>
                <strong className="mono">{latest.data.run.sessions}</strong>
              </div>
              <div className="row" style={{ justifyContent: "space-between" }}>
                <span className="muted">Verified Evidence Links</span>
                <span className="mono text-code">{latest.data.run.edges_created} created / {latest.data.run.edges_updated} updated</span>
              </div>
              <div className="row" style={{ justifyContent: "space-between" }}>
                <span className="muted">Candidate Clusters</span>
                <strong className="mono">{latest.data.run.campaigns}</strong>
              </div>
              <div className="row" style={{ justifyContent: "space-between" }}>
                <span className="muted">Algorithm Version</span>
                <span className="mono small">{latest.data.run.algorithm_version}</span>
              </div>
            </div>
          ) : (
            !latest.loading && <Empty>No correlation run recorded yet.</Empty>
          )}
        </Card>

        <Card title="Sensor Fleet Health">
          {sources.loading && <Loading label="Polling sensors" />}
          {sources.data && sources.data.sources.length === 0 && <Empty>No active sensors reporting.</Empty>}
          {sources.data && sources.data.sources.length > 0 && (
            <table>
              <thead>
                <tr><th>Sensor Node</th><th>Operational Status</th><th>Last Signal</th><th>Errors</th></tr>
              </thead>
              <tbody>
                {sources.data.sources.map((source) => (
                  <tr key={source.source}>
                    <td className="mono">{source.source}</td>
                    <td>{source.ok ? <span className="ok">healthy</span> : <span className="bad">error</span>}</td>
                    <td>{formatTime(source.last_event_at)}</td>
                    <td className="mono">{source.error_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </div>

      {/* Campaign Threat Candidates */}
      <Card title="Active Threat Campaign Candidates">
        {campaigns.loading && <Loading label="Loading campaign candidates" />}
        {campaigns.data && campaigns.data.items.length === 0 && (
          <Empty title="No active campaigns">Ingest honeypot telemetry and trigger correlation to cluster threat sessions.</Empty>
        )}
        {campaigns.data && campaigns.data.items.length > 0 && (
          <table>
            <thead>
              <tr>
                <th>Campaign Identifier</th>
                <th>Status</th>
                <th>Confidence Index</th>
                <th>Correlated Sessions</th>
                <th>Observed IPs</th>
                <th>Last Activity</th>
              </tr>
            </thead>
            <tbody>
              {campaigns.data.items.slice(0, 6).map((campaign) => (
                <tr key={campaign.id}>
                  <td className="mono"><strong>{campaign.name}</strong></td>
                  <td><Badge value={campaign.status} kind="status" /></td>
                  <td>
                    <span className="mono">{(campaign.confidence * 100).toFixed(1)}%</span>
                  </td>
                  <td className="mono">{campaign.member_count}</td>
                  <td className="mono">{campaign.ip_count}</td>
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


