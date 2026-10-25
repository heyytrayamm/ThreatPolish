import { RetentionPanel } from "../components/RetentionPanel";

export default function Retention() {
  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>Retention</h1>
          <p className="muted">
            Evidence backlog and maintenance history. Read-only; administrators run retention.
          </p>
        </div>
      </header>
      <RetentionPanel />
    </div>
  );
}
