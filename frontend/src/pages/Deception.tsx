import { useState } from "react";
import { api, Investigation, User } from "../api";
import {
  Badge,
  Card,
  Empty,
  ErrorBox,
  Field,
  formatTime,
  Loading,
  can,
  shortId,
  useAsync,
} from "../ui";

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
        `Outcome: ${result.outcome as string} (${Number(result.confidence_before).toFixed(2)} -> ` +
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
          <span className="eyebrow">Adaptive Deception Engine</span>
          <h1>Deception Management</h1>
          <p className="muted">Honeypot listener profiles, real interaction telemetry and bounded investigations.</p>
        </div>
      </header>

      <ErrorBox message={profiles.error ?? investigations.error ?? sessions.error ?? events.error} />
      {notice && <div className="notice">{notice}</div>}

      <div className="grid two">
        <Card title="Approved Decoy Profiles">
          {profiles.loading && <Loading label="Loading decoy profiles" />}
          {profiles.data && profiles.data.items.length === 0 && <Empty title="No profiles configured">No active decoy profiles found.</Empty>}
          <div className="list">
            {profiles.data?.items.map((profile) => (
              <div key={profile.id} className="list-item">
                <div className="row" style={{ justifyContent: "space-between" }}>
                  <strong>{profile.name}</strong>
                  <Badge value={profile.enabled ? "active" : "disabled"} kind="status" />
                </div>
                <div className="muted small">{profile.kind} - {profile.description}</div>
              </div>
            ))}
          </div>
          <p className="muted small" style={{ marginTop: "0.75rem" }}>
            Profiles are declarative definitions: no arbitrary execution and no outbound network capability.
          </p>
        </Card>

        <Card title="Active & Planned Investigations">
          {investigations.loading && <Loading label="Querying investigations" />}
          {investigations.data && investigations.data.items.length === 0 && (
            <Empty title="No active investigations">Open a campaign to initiate an adaptive deception investigation.</Empty>
          )}
          <div className="list">
            {investigations.data?.items.map((investigation) => {
              const replacement = replacementFor(investigation, investigations.data?.items ?? []);
              return (
                <div key={investigation.id} className="list-item">
                  <div className="row" style={{ justifyContent: "space-between" }}>
                    <strong className="mono">{shortId(investigation.id, 16)}</strong>
                    <Badge value={investigation.status} kind="status" />
                  </div>
                  <div className="muted small">
                    profile {investigation.chosen_profile ?? "-"} | missing {investigation.missing_evidence.join(", ") || "none"}
                    {investigation.outcome ? ` | outcome ${investigation.outcome}` : ""}
                  </div>
                  {investigation.status === "superseded" && (
                    <div className="muted small">
                      Closed because another investigation was already open for this subject
                      {replacement ? ` | replaced by ${shortId(replacement.id, 16)}` : ""}.
                    </div>
                  )}
                  {can(user.role, "analyse") &&
                    (investigation.status === "planned" ||
                      investigation.status === "active") && (
                    <div className="row" style={{ marginTop: "0.5rem", flexWrap: "wrap" }}>
                      <input
                        placeholder="source IP"
                        value={activationIp}
                        onChange={(event) => setActivationIp(event.target.value)}
                        style={{ maxWidth: "160px" }}
                      />
                      <button type="button" className="secondary small" onClick={() => activate(investigation.id)}>Activate</button>
                      <button type="button" className="secondary small" onClick={() => evaluate(investigation.id)}>Evaluate</button>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
          <div style={{ marginTop: "1rem" }}>
            <Field label="Observation Target IP">
              <input
                value={activationIp}
                onChange={(event) => setActivationIp(event.target.value)}
                placeholder="203.0.113.10"
              />
            </Field>
          </div>
          <p className="muted small" style={{ marginTop: "0.5rem" }}>
            Activation expires automatically. Decoys record genuine adversary telemetry only.
          </p>
        </Card>
      </div>

      <Card title="Decoy Sessions (24h Window)">
        {sessions.loading && <Loading label="Loading decoy sessions" />}
        {sessions.data && sessions.data.items.length === 0 && (
          <Empty title="No decoy sessions">No sessions recorded in the past 24 hours.</Empty>
        )}
        {sessions.data && sessions.data.items.length > 0 && (
          <div style={{ overflowX: "auto" }}>
            <table>
              <thead>
                <tr>
                  <th>Session Identifier</th>
                  <th>First Observed</th>
                  <th>Last Observed</th>
                  <th>Events</th>
                  <th>Source IPs</th>
                  <th>Max Severity</th>
                  <th>Target Port/Service</th>
                </tr>
              </thead>
              <tbody>
                {sessions.data.items.map((session) => (
                  <tr key={session.session_id}>
                    <td className="mono small"><strong>{session.session_id}</strong></td>
                    <td className="mono small">{formatTime(session.first_seen)}</td>
                    <td className="mono small">{formatTime(session.last_seen)}</td>
                    <td className="mono">{session.events}</td>
                    <td className="mono small text-code">
                      {session.source_ips.length > 0 ? session.source_ips.join(", ") : "-"}
                    </td>
                    <td><Badge value={session.severity} /></td>
                    <td className="mono">{session.target ?? "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p className="muted small" style={{ marginTop: "0.75rem" }}>
          Decoy sessions represent grouped interactions recorded by honeypot daemons.
        </p>
      </Card>

      <Card title="Recent Honeypot Inbound Traffic">
        {events.loading && <Loading label="Querying sensor events" />}
        {events.data && events.data.items.length === 0 && <Empty title="No recent traffic">No honeypot events recorded in the last 6 hours.</Empty>}
        {events.data && events.data.items.length > 0 && (
          <div style={{ overflowX: "auto" }}>
            <table>
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Event Type</th>
                  <th>Source IP</th>
                  <th>Session Identifier</th>
                  <th>Severity</th>
                </tr>
              </thead>
              <tbody>
                {events.data.items.map((event) => (
                  <tr key={event.id}>
                    <td className="mono small">{formatTime(event.occurred_at)}</td>
                    <td className="mono"><strong>{event.event_type}</strong></td>
                    <td className="mono text-code">{event.source_ip ?? "-"}</td>
                    <td className="mono small">{shortId(event.session_id ?? "-", 20)}</td>
                    <td><Badge value={event.severity} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
