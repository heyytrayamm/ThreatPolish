
import { FormEvent, useState } from "react";
import { api, Role } from "../api";
import { Card, Empty, ErrorBox, formatTime, Loading, useAsync } from "../ui";

export default function Administration() {
  const [refreshKey, setRefreshKey] = useState(0);
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<Role>("analyst");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const sources = useAsync(() => api.sources(), []);
  const quarantine = useAsync(() => api.quarantine(), []);
  const users = useAsync(() => api.users(), [refreshKey]);
  const audit = useAsync(() => api.audit(), []);

  async function handleCreateUser(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    setSuccess(null);

    try {
      const created = await api.createUser({
        email,
        name,
        role,
        password,
      });

      setSuccess(`Account created successfully for ${created.email}.`);
      setEmail("");
      setName("");
      setPassword("");
      setRole("analyst");
      setRefreshKey((previous) => previous + 1);
    } catch (failure) {
      setError((failure as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>Administration</h1>
          <p className="muted">
            Source health, account management, rejected payloads and audit trail.
          </p>
        </div>
      </header>

      <ErrorBox message={sources.error ?? quarantine.error ?? users.error ?? audit.error} />

      <Card title="Create user account">
        <form onSubmit={handleCreateUser} className="stack">
          {error && <ErrorBox message={error} />}
          {success && <p className="ok" role="status">{success}</p>}

          <label className="field">
            <span>Full name</span>
            <input
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="Friend's name"
              maxLength={120}
              required
            />
          </label>

          <label className="field">
            <span>Email address</span>
            <input
              type="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              placeholder="friend@example.com"
              autoComplete="off"
              required
            />
          </label>

          <label className="field">
            <span>Temporary password</span>
            <input
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              minLength={10}
              maxLength={256}
              autoComplete="new-password"
              required
            />
            <small className="muted">Minimum 10 characters. Share it securely with the new user.</small>
          </label>

          <label className="field">
            <span>Account role</span>
            <select
              value={role}
              onChange={(event) => setRole(event.target.value as Role)}
            >
              <option value="analyst">Analyst</option>
              <option value="viewer">Viewer</option>
              <option value="sensor">Sensor</option>
              <option value="admin">Admin</option>
            </select>
          </label>

          <div>
            <button type="submit" disabled={busy}>
              {busy ? "Creating account..." : "Create user"}
            </button>
          </div>
        </form>
      </Card>

      <div className="grid two">
        <Card title="Source health">
          {sources.loading && <Loading />}
          {sources.data && sources.data.sources.length === 0 && (
            <Empty>No sources have reported.</Empty>
          )}
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

        <Card title="Accounts">
          {users.loading && <Loading />}
          {users.data && users.data.users.length === 0 && (
            <Empty>No accounts found.</Empty>
          )}
          {users.data && users.data.users.length > 0 && (
            <table>
              <thead>
                <tr><th>Name</th><th>Email</th><th>Role</th></tr>
              </thead>
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
        {audit.data && audit.data.items.length === 0 && (
          <Empty>No audit entries yet.</Empty>
        )}
        {audit.data && audit.data.items.length > 0 && (
          <table>
            <thead>
              <tr><th>Time</th><th>Actor</th><th>Action</th><th>Object</th><th>Outcome</th><th>IP</th></tr>
            </thead>
            <tbody>
              {audit.data.items.map((entry) => (
                <tr key={entry.id}>
                  <td>{formatTime(entry.ts)}</td>
                  <td className="mono small">{entry.actor_id ?? "—"}</td>
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
        {quarantine.data && quarantine.data.items.length === 0 && (
          <Empty>No rejected payloads.</Empty>
        )}
        {quarantine.data && quarantine.data.items.length > 0 && (
          <table>
            <thead>
              <tr><th>Received</th><th>Module</th><th>Reason code</th><th>Reason</th></tr>
            </thead>
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
