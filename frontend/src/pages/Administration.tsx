import { useState } from "react";
import { api, SessionHistory, User } from "../api";
import { SessionTable } from "../components/SessionTable";
import { Card, Empty, ErrorBox, formatTime, Loading, useAsync } from "../ui";

export default function Administration() {
  const [tick, setTick] = useState(0);
  const [notice, setNotice] = useState<string | null>(null);
  const [busyUser, setBusyUser] = useState<string | null>(null);
  const [audited, setAudited] = useState<User | null>(null);
  const [auditedHistory, setAuditedHistory] = useState<SessionHistory | null>(null);
  const [auditError, setAuditError] = useState<string | null>(null);
  const [loadingHistory, setLoadingHistory] = useState(false);

  const sources = useAsync(() => api.sources(), []);
  const quarantine = useAsync(() => api.quarantine(), []);
  const users = useAsync(() => api.users(), [tick]);
  const audit = useAsync(() => api.audit(), [tick]);

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
          <p className="muted">Source health, rejected payloads and account inventory.</p>
        </div>
      </header>

      <ErrorBox message={sources.error ?? quarantine.error ?? users.error ?? audit.error} />
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
          {auditedHistory && <SessionTable history={auditedHistory} />}
        </Card>
      )}

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
