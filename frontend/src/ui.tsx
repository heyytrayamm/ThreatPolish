import { ReactNode, useEffect, useState } from "react";

export function useAsync<T>(load: () => Promise<T>, deps: unknown[]) {
  const [state, setState] = useState<{ loading: boolean; data: T | null; error: string | null }>({
    loading: true,
    data: null,
    error: null,
  });
  useEffect(() => {
    let alive = true;
    setState((previous) => ({ ...previous, loading: true, error: null }));
    load()
      .then((data) => {
        if (alive) setState({ loading: false, data, error: null });
      })
      .catch((error: Error) => {
        if (alive) setState({ loading: false, data: null, error: error.message });
      });
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  return state;
}

export function Card({ title, actions, children }: { title?: string; actions?: ReactNode; children: ReactNode }) {
  return (
    <section className="card">
      {(title || actions) && (
        <header className="card-head">
          {title && <h2>{title}</h2>}
          {actions && <div className="card-actions">{actions}</div>}
        </header>
      )}
      {children}
    </section>
  );
}

export function Loading({ label = "Loading" }: { label?: string }) {
  return <p className="muted">{label}…</p>;
}

export function ErrorBox({ message }: { message: string | null }) {
  if (!message) return null;
  return (
    <div className="error" role="alert">
      {message}
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="muted empty">{children}</p>;
}

const SEVERITY_CLASS: Record<string, string> = {
  critical: "sev-critical",
  high: "sev-high",
  medium: "sev-medium",
  low: "sev-low",
  info: "sev-info",
};

export function Badge({ value, kind = "severity" }: { value: string; kind?: "severity" | "status" }) {
  const className = kind === "severity" ? SEVERITY_CLASS[value] ?? "sev-info" : `status-${value}`;
  return <span className={`badge ${className}`}>{value}</span>;
}

export function formatTime(value: string | null | undefined): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString(undefined, {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function shortId(value: string, length = 12): string {
  return value.length > length ? `${value.slice(0, length)}…` : value;
}

export function JsonBlock({ value }: { value: unknown }) {
  return <pre className="json">{JSON.stringify(value, null, 2)}</pre>;
}

export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="field">
      <span>{label}</span>
      {children}
    </label>
  );
}

export function can(role: string | undefined, permission: "analyse" | "admin"): boolean {
  if (role === "admin") return true;
  if (role === "analyst") return permission === "analyse";
  return false;
}
