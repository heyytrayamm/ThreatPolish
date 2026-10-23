import { SessionHistory, SessionRecord, SignInAnomaly } from "../api";
import { Badge, Empty, formatTime } from "../ui";

const EVENT_LABEL: Record<string, string> = {
  sign_in: "Sign-in",
  password_changed: "Password changed",
  sessions_revoked: "Sessions revoked",
};

function describe(anomaly: SignInAnomaly): string {
  const previous = `${anomaly.previous_ip ?? "an unknown address"} at ${formatTime(anomaly.previous_at)}`;
  if (anomaly.kind === "distant_signin") {
    const distance = anomaly.distance_km ?? 0;
    return `This sign-in was ${distance.toLocaleString()} km from the previous session (${previous}), inside ${
      anomaly.window_minutes ?? 30
    } minutes. Confirm it was you before continuing.`;
  }
  return `This sign-in came from a different network (${anomaly.network ?? "unknown"}) than the previous session (${previous}), inside ${
    anomaly.window_minutes ?? 30
  } minutes. Confirm it was you before continuing.`;
}

export function SessionTable({ history }: { history: SessionHistory }) {
  const flagged = history.sessions.filter(
    (entry: SessionRecord) => entry.event === "sign_in" && entry.anomaly,
  );

  return (
    <>
      {flagged.length > 0 && (
        <div className="error" role="alert">
          <strong>Unusual sign-in.</strong> {describe(flagged[0].anomaly as SignInAnomaly)}
        </div>
      )}
      {history.sessions.length === 0 && (
        <Empty>No credential activity recorded for this account.</Empty>
      )}
      {history.sessions.length > 0 && (
        <table>
          <thead>
            <tr><th>When</th><th>Event</th><th>Client</th><th>Address</th><th>State</th></tr>
          </thead>
          <tbody>
            {history.sessions.map((entry) => (
              <tr key={entry.id}>
                <td>{formatTime(entry.occurred_at)}</td>
                <td>{EVENT_LABEL[entry.event] ?? entry.event}</td>
                <td className="small">{entry.client ?? "—"}</td>
                <td className="mono small">
                  {entry.ip ?? "—"}
                  {entry.anomaly ? " · flagged" : ""}
                </td>
                <td>
                  {entry.state ? (
                    <Badge value={entry.state} kind="status" />
                  ) : (
                    <span className="muted small">{entry.outcome}</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <p className="muted small">{history.note}</p>
    </>
  );
}
