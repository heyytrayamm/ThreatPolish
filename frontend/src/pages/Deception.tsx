import { useState } from "react";
import { api, Investigation, User } from "../api";
import { Badge, Card, Empty, ErrorBox, Field, formatTime, Loading, can, shortId, useAsync } from "../ui";

export default function Deception({ user }: { user: User }) {
  const [tick, setTick] = useState(0);
  const [activationIp, setActivationIp] = useState("");
  const [notice, setNotice] = useState<string | null>(null);

  const profiles = useAsync(() => api.profiles(), [tick]);
  const investigations = useAsync(() => api.investigations(), [tick]);
  const sessions = useAsync(() => api.decoySessions(24, 20), [tick]);
  const events = useAsync(
    () => api.events({ module: "honeypot", limit: 20, since: new Date(Date.now() - 6 * 3600 * 1000).toISOString() }),
    [tick],
  );

  async function activate(id: string) {
    if (!activationIp.trim()) {
      setNotice("Enter the source IP to observe before activating.");
      return;
    }
    try {
      const result = await api.activateInvestigation(id, activationIp.trim());
      setNotice(`Profile ${result.profile as string} active for ${result.source_ip as string} until ${formatTime(result.expires_at as string)}.`);
      setTick((value) => value + 1);
    } catch (error) {
      setNotice((error as Error).message);
    }
  }

  function replacementFor(item: Investigation, all: Investigation[]): Investigation | undefined {
    // Duplicate rows are closed by the database constraint; the investigation
    // that kept the subject is the newest open row sharing it.
    const subject = item.campaign_id ?? item.edge_id;
    if (!subject) return undefined;
    const later = all
      .filter((other) => other.id !== item.id)
      .filter((other) => (other.campaign_id ?? other.edge_id) === subject)
      .filter((other) => other.created_at > item.created_at)
      .filter((other) => other.status === "planned" || other.status === "active")
      .sort((left, right) => (left.created_at < right.created_at ? 1 : -1));
    return later[0];
  }

  async function evaluate(id: string) {
    try {
      const result = await api.evaluateInvestigation(id);
      setNotice(
        `Outcome: ${result.outcome as string} (${Number(result.confidence_before).toFixed(2)} → ` +
          `${Number(result.confidence_after).toFixed(2)}, ${result.new_events_observed as number} new events).`,
      );
      setTick((value) => value + 1);
    } catch (error) {
      setNotice((error as Error).message);
    }
  }

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>Deception</h1>
          <p className="muted">Decoy profiles, captured interaction traffic and adaptive investigations.</p>
        </div>
      </header>

      <ErrorBox message={profiles.error ?? investigations.error ?? sessions.error ?? events.error} />
      {notice && <div className="notice">{notice}</div>}

      <div className="grid two">
        <Card title="Approved decoy profiles">
          {profiles.loading && <Loading />}
          {profiles.data && profiles.data.items.length === 0 && <Empty>No profiles seeded.</Empty>}
          <div className="list">
            {profiles.data?.items.map((profile) => (
              <div key={profile.id} className="list-item static">
                <div className="row space">
                  <strong>{profile.name}</strong>
                  <Badge value={profile.enabled ? "active" : "disabled"} kind="status" />
                </div>
                <div className="muted small">{profile.kind} · {profile.description}</div>
              </div>
            ))}
          </div>
          <p className="muted small">
            Profiles are declarative data only: no code execution and no outbound network access.
          </p>
        </Card>

        <Card title="Investigations">
          {investigations.loading && <Loading />}
          {investigations.data && investigations.data.items.length === 0 && (
            <Empty>No investigations planned. Open a campaign to plan one.</Empty>
          )}
          <div className="list">
            {investigations.data?.items.map((investigation) => {
              const replacement = replacementFor(investigation, investigations.data?.items ?? []);
              return (
                <div key={investigation.id} className="list-item static">
                  <div className="row space">
                    <strong className="mono">{shortId(investigation.id, 16)}</strong>
                    <Badge value={investigation.status} kind="status" />
                  </div>
                  <div className="muted small">
                    profile {investigation.chosen_profile ?? "—"} · missing {investigation.missing_evidence.join(", ") || "none"}
                    {investigation.outcome ? ` · outcome ${investigation.outcome}` : ""}
                  </div>
                  {investigation.status === "superseded" && (
                    <div className="muted small">
                      Closed because another investigation was already open for this subject
                      {replacement ? ` · replaced by ${shortId(replacement.id, 16)}` : ""}.
                    </div>
                  )}
                  {can(user.role, "analyse") &&
                    (investigation.status === "planned" ||
                      investigation.status === "active") && (
                    <div className="row wrap">
                      <input
                        placeholder="source IP"
                        value={activationIp}
                        onChange={(event) => setActivationIp(event.target.value)}
                        className="compact"
                      />
                      <button className="secondary" onClick={() => activate(investigation.id)}>Activate</button>
                      <button className="secondary" onClick={() => evaluate(investigation.id)}>Evaluate</button>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
          <Field label="Observation target IP">
            <input value={activationIp} onChange={(event) => setActivationIp(event.target.value)} placeholder="203.0.113.10" />
          </Field>
          <p className="muted small">
            Activation expires automatically. The decoy records real interactions only; adaptive observation
            cannot create evidence.
          </p>
        </Card>
      </div>

      <Card title="Decoy sessions (24h)">
        {sessions.loading && <Loading />}
        {sessions.data && sessions.data.items.length === 0 && (
          <Empty>No decoy sessions in the last 24 hours.</Empty>
        )}
        {sessions.data && sessions.data.items.length > 0 && (
          <table>
            <thead>
              <tr>
                <th>Session</th><th>First seen</th><th>Last seen</th><th>Events</th>
                <th>Source IPs</th><th>Severity</th><th>Target</th>
              </tr>
            </thead>
            <tbody>
              {sessions.data.items.map((session) => (
                <tr key={session.session_id}>
                  <td className="mono small">{session.session_id}</td>
                  <td>{formatTime(session.first_seen)}</td>
                  <td>{formatTime(session.last_seen)}</td>
                  <td>{session.events}</td>
                  <td className="mono small">
                    {session.source_ips.length > 0 ? session.source_ips.join(", ") : "—"}
                  </td>
                  <td><Badge value={session.severity} /></td>
                  <td>{session.target ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <p className="muted small">
          Sessions are interactions observed by the decoy services, grouped by the identifier the sensor
          assigned. A session is not an identity.
        </p>
      </Card>

      <Card title="Recent honeypot interactions">
        {events.loading && <Loading />}
        {events.data && events.data.items.length === 0 && <Empty>No decoy traffic in the last six hours.</Empty>}
        {events.data && events.data.items.length > 0 && (
          <table>
            <thead><tr><th>Time</th><th>Type</th><th>Source</th><th>Session</th><th>Severity</th></tr></thead>
            <tbody>
              {events.data.items.map((event) => (
                <tr key={event.id}>
                  <td>{formatTime(event.occurred_at)}</td>
                  <td className="mono">{event.event_type}</td>
                  <td className="mono">{event.source_ip ?? "—"}</td>
                  <td className="mono">{shortId(event.session_id ?? "—", 20)}</td>
                  <td><Badge value={event.severity} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
