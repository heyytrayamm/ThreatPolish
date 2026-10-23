import { useState } from "react";
import { api, User } from "../api";
import { Badge, Card, Empty, ErrorBox, Field, formatTime, Loading, can, useAsync } from "../ui";

export default function Findings({ user }: { user: User }) {
  const [tick, setTick] = useState(0);
  const [target, setTarget] = useState("");
  const [activeChecks, setActiveChecks] = useState(false);
  const [domain, setDomain] = useState("");
  const [authorizedBy, setAuthorizedBy] = useState("");
  const [allowActive, setAllowActive] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const findings = useAsync(() => api.findings(), [tick]);
  const scopes = useAsync(() => api.scopes(), [tick]);

  async function assess() {
    setBusy(true);
    setNotice(null);
    try {
      const report = await api.assess(target, activeChecks);
      setNotice(
        `Assessment ${report.status as string}: ${report.finding_count as number} findings for ` +
          `${report.target as string}.`,
      );
      setTick((value) => value + 1);
    } catch (error) {
      setNotice((error as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function createScope() {
    setBusy(true);
    setNotice(null);
    try {
      await api.createScope({
        domain,
        authorized_by: authorizedBy,
        expires_in_days: 7,
        allow_active: allowActive,
        notes: "Created from dashboard",
      });
      setNotice("Authorization recorded.");
      setDomain("");
      setAuthorizedBy("");
      setTick((value) => value + 1);
    } catch (error) {
      setNotice((error as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>Web findings</h1>
          <p className="muted">Only explicitly authorized hosts are assessed. Checks are non-destructive.</p>
        </div>
      </header>

      <ErrorBox message={findings.error ?? scopes.error} />
      {notice && <div className="notice">{notice}</div>}

      <div className="grid two">
        <Card title="Run assessment">
          <Field label="Authorized target">
            <input value={target} onChange={(event) => setTarget(event.target.value)} placeholder="https://authorized.example" />
          </Field>
          <label className="toggle">
            <input type="checkbox" checked={activeChecks} onChange={(event) => setActiveChecks(event.target.checked)} />
            <span>Include active path probes (requires scope permission)</span>
          </label>
          <button onClick={assess} disabled={busy || !can(user.role, "analyse") || !target.trim()}>
            Assess
          </button>
          {!can(user.role, "analyse") && <p className="muted small">Analyst or administrator role required.</p>}
        </Card>

        <Card title="Authorizations">
          {scopes.loading && <Loading />}
          {scopes.data && scopes.data.items.length === 0 && <Empty>No authorization scopes recorded.</Empty>}
          {scopes.data && scopes.data.items.length > 0 && (
            <table>
              <thead><tr><th>Domain</th><th>Authorized by</th><th>Expires</th><th>Active checks</th></tr></thead>
              <tbody>
                {scopes.data.items.map((scope) => (
                  <tr key={scope.id}>
                    <td>{scope.domain}</td>
                    <td>{scope.authorized_by}</td>
                    <td>{formatTime(scope.expires_at)}</td>
                    <td>{scope.allow_active ? "allowed" : "passive only"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {user.role === "admin" && (
            <div className="stack">
              <Field label="New scope domain">
                <input value={domain} onChange={(event) => setDomain(event.target.value)} placeholder="authorized.example" />
              </Field>
              <Field label="Authorized by">
                <input value={authorizedBy} onChange={(event) => setAuthorizedBy(event.target.value)} placeholder="Name / ticket reference" />
              </Field>
              <label className="toggle">
                <input type="checkbox" checked={allowActive} onChange={(event) => setAllowActive(event.target.checked)} />
                <span>Allow active checks</span>
              </label>
              <button onClick={createScope} disabled={busy || !domain.trim() || !authorizedBy.trim()}>
                Record authorization
              </button>
            </div>
          )}
        </Card>
      </div>

      <Card title="Findings">
        {findings.loading && <Loading />}
        {findings.data && findings.data.items.length === 0 && <Empty>No findings recorded.</Empty>}
        {findings.data && findings.data.items.length > 0 && (
          <table>
            <thead><tr><th>Time</th><th>Target</th><th>Check</th><th>Severity</th><th>Status</th><th>Remediation</th></tr></thead>
            <tbody>
              {findings.data.items.map((finding) => (
                <tr key={finding.id}>
                  <td>{formatTime(finding.ts)}</td>
                  <td>{finding.target}</td>
                  <td>{finding.title}</td>
                  <td><Badge value={finding.severity} /></td>
                  <td>{finding.status}</td>
                  <td className="small">{finding.remediation}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
