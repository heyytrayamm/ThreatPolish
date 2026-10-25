import { FormEvent, useState } from "react";
import { api, SessionHistory, User } from "../api";
import { SessionTable } from "../components/SessionTable";
import { Badge, Card, Empty, ErrorBox, Field, formatTime, Loading, useAsync } from "../ui";

export default function Administration() {
  const [tick, setTick] = useState(0);
  const [notice, setNotice] = useState<string | null>(null);
  const [busyUser, setBusyUser] = useState<string | null>(null);
  const [audited, setAudited] = useState<User | null>(null);
  const [auditedHistory, setAuditedHistory] = useState<SessionHistory | null>(null);
  const [auditError, setAuditError] = useState<string | null>(null);
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [tokenName, setTokenName] = useState("");
  const [tokenRole, setTokenRole] = useState<"sensor" | "analyst">("sensor");
  const [issued, setIssued] = useState<{ name: string; token: string } | null>(null);
  const [tokenBusy, setTokenBusy] = useState(false);
  const [retentionBusy, setRetentionBusy] = useState(false);
  const [exportBusy, setExportBusy] = useState(false);

  const sources = useAsync(() => api.sources(), []);
  const quarantine = useAsync(() => api.quarantine(), []);
  const users = useAsync(() => api.users(), [tick]);
  const audit = useAsync(() => api.audit(), [tick]);
  const tokens = useAsync(() => api.agentTokens(), [tick]);
  const retention = useAsync(() => api.retention(), [tick]);
  // The API returns the newest run first; a chart reads left to right.
  const retentionHistory = [...(retention.data?.history ?? [])].reverse();
  const maxBacklog = Math.max(
    1,
    ...retentionHistory.map(
      (run) => run.events_expired + run.retired_edges + run.stale_observations,
    ),
  );

  async function inspect(user: User) {
    setAudited(user);
    setAuditedHistory(null);
    setAuditError(null);
    setLoadingHistory(true);
    try {
      setAuditedHistory(await api.userSessions(user.id));
    } catch (error) {
      setAuditError((error as Error).message);
    } finally {
      setLoadingHistory(false);
    }
  }

  async function signOutDevice(user: User, jti: string) {
    setNotice(null);
    try {
      await api.revokeUserSession(user.id, jti);
      setNotice(`That device was signed out of ${user.email}. Their other sessions keep working.`);
      setTick((value) => value + 1);
      await inspect(user);
    } catch (error) {
      setNotice((error as Error).message);
    }
  }

  async function createToken(event: FormEvent) {
    event.preventDefault();
    setTokenBusy(true);
    setNotice(null);
    setIssued(null);
    try {
      const created = await api.createAgentToken(tokenName.trim(), tokenRole);
      setIssued({ name: created.name, token: created.token });
      setTokenName("");
      setTick((value) => value + 1);
    } catch (error) {
      setNotice((error as Error).message);
    } finally {
      setTokenBusy(false);
    }
  }

  async function revokeToken(id: string, name: string) {
    setNotice(null);
    try {
      await api.revokeAgentToken(id);
      setNotice(`${name} was revoked. Any sensor still using it is refused from now on.`);
      if (issued?.name === name) setIssued(null);
      setTick((value) => value + 1);
    } catch (error) {
      setNotice((error as Error).message);
    }
  }

  async function runRetentionNow() {
    if (
      !window.confirm(
        "Run retention now? Expired events and graph evidence past the configured horizons will be deleted.",
      )
    ) {
      return;
    }
    setRetentionBusy(true);
    setNotice(null);
    try {
      const result = await api.runRetention();
      const graphChanges =
        result.graph.edges + result.graph.observations + result.graph.nodes;
      setNotice(
        `Retention run ${result.run_id} removed ${result.events.events} events and ` +
          `${graphChanges} graph records.`,
      );
      setTick((value) => value + 1);
    } catch (error) {
      setNotice((error as Error).message);
    } finally {
      setRetentionBusy(false);
    }
  }

  async function exportRetention() {
    if (!retention.data) return;
    setExportBusy(true);
    setNotice(null);
    try {
      const limit = Math.max(1, Math.min(retention.data.history_total, 1000));
      const csv = await api.retentionHistoryCsv(limit);
      const url = URL.createObjectURL(csv);
      const link = document.createElement("a");
      link.href = url;
      link.download = `threatpolish-retention-${new Date().toISOString().slice(0, 10)}.csv`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      setNotice("Retention history exported as CSV.");
    } catch (error) {
      setNotice((error as Error).message);
    } finally {
      setExportBusy(false);
    }
  }

  async function revoke(userId: string, email: string) {
    setBusyUser(userId);
    setNotice(null);
    try {
      await api.revokeSessions(userId);
      setNotice(`Every session for ${email} was revoked. The account keeps its password.`);
      setTick((value) => value + 1);
      if (audited?.id === userId) await inspect(audited);
    } catch (error) {
      setNotice((error as Error).message);
    } finally {
      setBusyUser(null);
    }
  }

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>Administration</h1>
          <p className="muted">Source health, account inventory, sensor credentials and rejected payloads.</p>
        </div>
      </header>

      <ErrorBox
        message={
          sources.error ?? quarantine.error ?? users.error ?? audit.error ?? tokens.error ?? retention.error
        }
      />
      {notice && <div className="notice">{notice}</div>}

      <div className="grid two">
        <Card title="Source health">
          {sources.loading && <Loading />}
          {sources.data && sources.data.sources.length === 0 && <Empty>No sources have reported.</Empty>}
          {sources.data && sources.data.sources.length > 0 && (
            <table>
              <thead><tr><th>Source</th><th>Status</th><th>Last event</th><th>Errors</th></tr></thead>
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

        <Card title="Accounts">
          {users.loading && <Loading />}
          {users.data && (
            <table>
              <thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Sessions</th></tr></thead>
              <tbody>
                {users.data.users.map((user) => (
                  <tr key={user.id}>
                    <td>{user.name}</td>
                    <td>{user.email}</td>
                    <td>{user.role}</td>
                    <td>
                      <div className="row">
                        <button
                          type="button"
                          className="secondary small"
                          onClick={() => inspect(user)}
                        >
                          Sessions
                        </button>
                        <button
                          type="button"
                          className="secondary small"
                          disabled={busyUser === user.id}
                          onClick={() => revoke(user.id, user.email)}
                        >
                          {busyUser === user.id ? "Revoking…" : "Revoke sessions"}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </div>

      {audited && (
        <Card
          title={`Sessions — ${audited.name}`}
          actions={
            <button type="button" className="link" onClick={() => setAudited(null)}>
              Close
            </button>
          }
        >
          {loadingHistory && <Loading />}
          <ErrorBox message={auditError} />
          {auditedHistory && (
            <SessionTable
              history={auditedHistory}
              onRevoke={(jti) => signOutDevice(audited, jti)}
            />
          )}
        </Card>
      )}

      <Card
        title="Retention"
        actions={
          <div className="row">
            <button
              type="button"
              className="secondary small"
              disabled={exportBusy || retentionHistory.length === 0}
              onClick={exportRetention}
            >
              {exportBusy ? "Exporting…" : "Export CSV"}
            </button>
            <button
              type="button"
              className="secondary small"
              disabled={retentionBusy}
              onClick={runRetentionNow}
            >
              {retentionBusy ? "Running…" : "Run retention now"}
            </button>
            <button type="button" className="link" onClick={() => setTick((value) => value + 1)}>
              Refresh
            </button>
          </div>
        }
      >
        {retention.loading && <Loading />}
        {retention.data && (
          <>
            <p className="small">
              <span className={retention.data.overdue ? "bad" : "ok"}>
                {retention.data.overdue ? "overdue" : "current"}
              </span>{" "}
              {retention.data.overdue
                ? `Backlog has waited longer than the ${retention.data.grace_days}-day grace window. Check the retention schedule.`
                : "Within the grace window; the scheduled run will clear the backlog."}
            </p>
            <table>
              <tbody>
                <tr>
                  <th>Events</th>
                  <td>
                    {retention.data.events.total} stored · {retention.data.events.expired} past the{" "}
                    {retention.data.events.retention_days}-day horizon
                  </td>
                </tr>
                <tr>
                  <th>Oldest event</th>
                  <td>{formatTime(retention.data.events.oldest_occurred_at)}</td>
                </tr>
                <tr>
                  <th>Graph</th>
                  <td>
                    {retention.data.graph.nodes} nodes · {retention.data.graph.edges} edges
                  </td>
                </tr>
                <tr>
                  <th>Pending graph work</th>
                  <td>
                    {retention.data.graph.retired_edges} retired edges ·{" "}
                    {retention.data.graph.stale_observations} stale observations ·{" "}
                    {retention.data.graph.orphan_nodes} orphan nodes
                  </td>
                </tr>
                <tr>
                  <th>Graph horizon</th>
                  <td>{retention.data.graph.retention_days} days</td>
                </tr>
              </tbody>
            </table>
            {retentionHistory.length > 0 && (
              <>
                <h3>Backlog before each run</h3>
                <svg
                  className="bars"
                  viewBox="0 0 620 120"
                  role="img"
                  aria-label="Retention backlog before each run"
                >
                  <line x1={10} y1={100} x2={610} y2={100} className="bar-axis" />
                  {retentionHistory.map((run, index) => {
                    const slot = 600 / retentionHistory.length;
                    const width = Math.max(2, Math.min(44, slot - 4));
                    const backlog =
                      run.events_expired + run.retired_edges + run.stale_observations;
                    const height = (backlog / maxBacklog) * 90;
                    const x = 10 + index * slot + (slot - width) / 2;
                    return (
                      <g key={run.id}>
                        <rect
                          x={x}
                          y={100 - height}
                          width={width}
                          height={height}
                          rx={2}
                          className="bar"
                        />
                        <title>
                          {`${formatTime(run.ran_at)} — ${backlog} items (${run.trigger})`}
                        </title>
                      </g>
                    );
                  })}
                </svg>
                <p className="muted small">
                  Expired events plus retired edges and stale observations seen before the last{" "}
                  {retentionHistory.length} runs. Graph size now: {retention.data.graph.nodes} nodes,{" "}
                  {retention.data.graph.edges} edges.
                </p>
                <h3>Recent runs</h3>
                <p className="muted small">
                  {retention.data.history_total > retentionHistory.length
                    ? `Showing the last ${retentionHistory.length} of ${retention.data.history_total} recorded runs. Export includes up to 1,000 runs.`
                    : `${retention.data.history_total} recorded run${
                        retention.data.history_total === 1 ? "" : "s"
                      }.`}
                </p>
                <table>
                  <thead>
                    <tr>
                      <th>Ran</th><th>Trigger</th><th>Backlog</th><th>Removed</th>
                      <th>Duration</th><th>State</th>
                    </tr>
                  </thead>
                  <tbody>
                    {retention.data.history.map((run) => {
                      const backlog =
                        run.events_expired + run.retired_edges + run.stale_observations;
                      const removed =
                        run.events_removed +
                        run.edges_removed +
                        run.observations_removed +
                        run.nodes_removed;
                      return (
                        <tr key={run.id}>
                          <td>{formatTime(run.ran_at)}</td>
                          <td>{run.trigger}</td>
                          <td>{backlog}</td>
                          <td>{removed}</td>
                          <td>{run.duration_ms} ms</td>
                          <td>
                            <span className={run.overdue ? "bad" : "ok"}>
                              {run.overdue ? "overdue" : "current"}
                            </span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </>
            )}
            {retentionHistory.length === 0 && (
              <p className="muted small">
                No retention run has been recorded yet. The scheduled service writes one on each
                run.
              </p>
            )}
          </>
        )}
      </Card>

      <Card title="Agent tokens">
        {issued && (
          <div className="notice">
            <strong>{issued.name}</strong> was created. Copy the token now: it is shown once and
            only its hash is stored.
            <pre className="json mono">{issued.token}</pre>
          </div>
        )}
        {tokens.loading && <Loading />}
        {tokens.data && tokens.data.tokens.length === 0 && <Empty>No sensor tokens yet.</Empty>}
        {tokens.data && tokens.data.tokens.length > 0 && (
          <table>
            <thead>
              <tr>
                <th>Name</th><th>Prefix</th><th>Role</th><th>Created</th><th>Last used</th>
                <th>State</th><th>Token</th>
              </tr>
            </thead>
            <tbody>
              {tokens.data.tokens.map((token) => (
                <tr key={token.id}>
                  <td>{token.name}</td>
                  <td className="mono small">{token.prefix}…</td>
                  <td>{token.role}</td>
                  <td>{formatTime(token.created_at)}</td>
                  <td>{formatTime(token.last_used_at)}</td>
                  <td>
                    <Badge value={token.revoked_at ? "revoked" : "active"} kind="status" />
                  </td>
                  <td>
                    {!token.revoked_at && (
                      <button
                        type="button"
                        className="secondary small"
                        onClick={() => revokeToken(token.id, token.name)}
                      >
                        Revoke
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <form onSubmit={createToken} className="row token-form">
          <Field label="Token name">
            <input
              value={tokenName}
              onChange={(event) => setTokenName(event.target.value)}
              placeholder="decoy-http-2"
              maxLength={120}
              required
            />
          </Field>
          <Field label="Role">
            <select
              value={tokenRole}
              onChange={(event) => setTokenRole(event.target.value as "sensor" | "analyst")}
            >
              <option value="sensor">sensor</option>
              <option value="analyst">analyst</option>
            </select>
          </Field>
          <button type="submit" disabled={tokenBusy || tokenName.trim() === ""}>
            {tokenBusy ? "Creating…" : "Create token"}
          </button>
        </form>
        <p className="muted small">
          Sensor tokens are hashed at rest and cannot be read back. Revoking one takes effect on the
          next request; rotate a token by creating a replacement and revoking the old one.
        </p>
      </Card>

      <Card title="Audit trail">
        {audit.loading && <Loading />}
        {audit.data && audit.data.items.length === 0 && <Empty>No audit entries yet.</Empty>}
        {audit.data && audit.data.items.length > 0 && (
          <table>
            <thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Object</th><th>Outcome</th><th>IP</th></tr></thead>
            <tbody>
              {audit.data.items.map((entry) => (
                <tr key={entry.id}>
                  <td>{formatTime(entry.ts)}</td>
                  <td className="mono small">{entry.actor_id ?? "system"}</td>
                  <td>{entry.action}</td>
                  <td className="mono small">{entry.object_type}:{entry.object_id ?? "—"}</td>
                  <td>{entry.outcome}</td>
                  <td className="mono small">{entry.request_ip ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      <Card title="Quarantined payloads">
        {quarantine.loading && <Loading />}
        {quarantine.data && quarantine.data.items.length === 0 && <Empty>No rejected payloads.</Empty>}
        {quarantine.data && quarantine.data.items.length > 0 && (
          <table>
            <thead><tr><th>Received</th><th>Module</th><th>Reason code</th><th>Reason</th></tr></thead>
            <tbody>
              {quarantine.data.items.map((item) => (
                <tr key={item.id}>
                  <td>{formatTime(item.received_at)}</td>
                  <td>{item.source_module ?? "—"}</td>
                  <td className="mono">{item.reason_code}</td>
                  <td className="small">{item.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
