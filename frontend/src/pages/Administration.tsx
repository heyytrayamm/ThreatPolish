import { api } from "../api";
import { Card, Empty, ErrorBox, formatTime, Loading, useAsync } from "../ui";

export default function Administration() {
  const sources = useAsync(() => api.sources(), []);
  const quarantine = useAsync(() => api.quarantine(), []);
  const users = useAsync(() => api.users(), []);
  const audit = useAsync(() => api.audit(), []);

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>Administration</h1>
          <p className="muted">Source health, rejected payloads and account inventory.</p>
        </div>
      </header>

      <ErrorBox message={sources.error ?? quarantine.error ?? users.error ?? audit.error} />

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
              <thead><tr><th>Name</th><th>Email</th><th>Role</th></tr></thead>
              <tbody>
                {users.data.users.map((user) => (
                  <tr key={user.id}>
                    <td>{user.name}</td>
                    <td>{user.email}</td>
                    <td>{user.role}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </div>

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
