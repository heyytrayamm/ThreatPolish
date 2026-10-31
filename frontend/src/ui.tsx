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

export function Card({
  title,
  subtitle,
  badge,
  actions,
  children,
  className = "",
}: {
  title?: string;
  subtitle?: string;
  badge?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`tp-card ${className}`}>
      {(title || subtitle || actions || badge) && (
        <header className="tp-card-header">
          <div className="tp-card-title-group">
            {title && <h2 className="tp-card-title">{title}</h2>}
            {badge && <div className="tp-card-badge">{badge}</div>}
            {subtitle && <p className="tp-card-subtitle">{subtitle}</p>}
          </div>
          {actions && <div className="tp-card-actions">{actions}</div>}
        </header>
      )}
      <div className="tp-card-body">{children}</div>
    </section>
  );
}

export function StatMetric({
  label,
  value,
  subvalue,
  trend,
  trendPositive,
  icon,
}: {
  label: string;
  value: ReactNode;
  subvalue?: string;
  trend?: string;
  trendPositive?: boolean;
  icon?: ReactNode;
}) {
  return (
    <div className="tp-stat-metric">
      <div className="tp-stat-head">
        <span className="tp-stat-label">{label}</span>
        {icon && <span className="tp-stat-icon">{icon}</span>}
      </div>
      <div className="tp-stat-value">{value}</div>
      {(subvalue || trend) && (
        <div className="tp-stat-meta">
          {trend && (
            <span className={`tp-stat-trend ${trendPositive ? "trend-up" : "trend-down"}`}>
              {trend}
            </span>
          )}
          {subvalue && <span className="tp-stat-subvalue">{subvalue}</span>}
        </div>
      )}
    </div>
  );
}

export function Loading({ label = "Loading data" }: { label?: string }) {
  return (
    <div className="tp-loading-container" role="status">
      <div className="tp-spinner" aria-hidden="true" />
      <span className="tp-loading-text">{label}...</span>
    </div>
  );
}

export function ErrorBox({ message }: { message: string | null }) {
  if (!message) return null;
  return (
    <div className="tp-alert tp-alert-error" role="alert">
      <IconAlertTriangle />
      <div className="tp-alert-content">
        <strong>Error Encountered</strong>
        <p>{message}</p>
      </div>
    </div>
  );
}

export function Empty({
  title = "No data found",
  children,
  action,
}: {
  title?: string;
  children: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="tp-empty-state">
      <div className="tp-empty-icon" aria-hidden="true">
        <IconInbox />
      </div>
      <h3 className="tp-empty-title">{title}</h3>
      <div className="tp-empty-desc">{children}</div>
      {action && <div className="tp-empty-action">{action}</div>}
    </div>
  );
}

const SEVERITY_CLASS: Record<string, string> = {
  critical: "sev-critical",
  high: "sev-high",
  medium: "sev-medium",
  low: "sev-low",
  info: "sev-info",
};

export function Badge({
  value,
  kind = "severity",
  dot = true,
}: {
  value: string;
  kind?: "severity" | "status";
  dot?: boolean;
}) {
  const className = kind === "severity" ? SEVERITY_CLASS[value] ?? "sev-info" : `status-${value}`;
  return (
    <span className={`tp-badge ${className}`}>
      {dot && <span className="tp-badge-dot" aria-hidden="true" />}
      <span className="tp-badge-text">{value}</span>
    </span>
  );
}

export function formatTime(value: string | null | undefined): string {
  if (!value) return "-";
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
  return value.length > length ? `${value.slice(0, length)}...` : value;
}

export function JsonBlock({ value }: { value: unknown }) {
  return (
    <div className="tp-json-wrapper">
      <pre className="tp-code-block">{JSON.stringify(value, null, 2)}</pre>
    </div>
  );
}

export function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: ReactNode;
}) {
  return (
    <label className="tp-field">
      <span className="tp-field-label">
        {label}
        {hint && <span className="tp-field-hint">{hint}</span>}
      </span>
      {children}
    </label>
  );
}

export function PasswordInput({
  value,
  onChange,
  placeholder = "Enter password",
  required = false,
  autoComplete = "current-password",
  minLength,
  maxLength,
}: {
  value: string;
  onChange: (val: string) => void;
  placeholder?: string;
  required?: boolean;
  autoComplete?: string;
  minLength?: number;
  maxLength?: number;
}) {
  const [visible, setVisible] = useState(false);
  return (
    <div className="tp-password-input-wrap">
      <input
        type={visible ? "text" : "password"}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        required={required}
        autoComplete={autoComplete}
        minLength={minLength}
        maxLength={maxLength}
      />
      <button
        type="button"
        className="tp-password-toggle"
        onClick={() => setVisible(!visible)}
        aria-label={visible ? "Hide password" : "Show password"}
        tabIndex={-1}
      >
        {visible ? <IconEyeOff /> : <IconEye />}
      </button>
    </div>
  );
}

export function TerminalWindow({
  title = "threatpolish@sensor-node-01:~",
  lines,
}: {
  title?: string;
  lines: { text: string; type?: "cmd" | "output" | "accent" | "warn" | "error" }[];
}) {
  return (
    <div className="tp-terminal">
      <div className="tp-terminal-bar">
        <div className="tp-terminal-controls" aria-hidden="true">
          <span className="dot red" />
          <span className="dot yellow" />
          <span className="dot green" />
        </div>
        <div className="tp-terminal-title">{title}</div>
        <div className="tp-terminal-action">SSH:2222</div>
      </div>
      <div className="tp-terminal-body">
        {lines.map((line, idx) => (
          <div key={idx} className={`tp-terminal-line line-${line.type ?? "output"}`}>
            {line.type === "cmd" ? (
              <>
                <span className="tp-prompt">$</span> {line.text}
              </>
            ) : (
              line.text
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

export function can(role: string | undefined, permission: "analyse" | "admin"): boolean {
  if (role === "admin") return true;
  if (role === "analyst") return permission === "analyse";
  return false;
}

// -------------------------------------------------------------
// Pure SVG Technical Icons (Zero Dependencies, Ultra Fast)
// -------------------------------------------------------------

export function IconShield({ size = 18 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  );
}

export function IconActivity({ size = 18 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
    </svg>
  );
}

export function IconTerminal({ size = 18 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="4 17 10 11 4 5" />
      <line x1="12" y1="19" x2="20" y2="19" />
    </svg>
  );
}

export function IconAlertTriangle({ size = 18 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" />
      <line x1="12" y1="9" x2="12" y2="13" />
      <line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  );
}

export function IconInbox({ size = 28 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="22 12 16 12 14 15 10 15 8 12 2 12" />
      <path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z" />
    </svg>
  );
}

export function IconEye({ size = 18 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z" />
      <circle cx="12" cy="12" r="3" />
    </svg>
  );
}

export function IconEyeOff({ size = 18 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M9.88 9.88a3 3 0 1 0 4.24 4.24" />
      <path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68" />
      <path d="M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61" />
      <line x1="2" y1="2" x2="22" y2="22" />
    </svg>
  );
}

export function IconRefresh({ size = 16 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67" />
    </svg>
  );
}

export function IconServer({ size = 18 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="2" y="2" width="20" height="8" rx="2" ry="2" />
      <rect x="2" y="14" width="20" height="8" rx="2" ry="2" />
      <line x1="6" y1="6" x2="6.01" y2="6" />
      <line x1="6" y1="18" x2="6.01" y2="18" />
    </svg>
  );
}

export function IconNetwork({ size = 18 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="9" y="2" width="6" height="6" rx="1" />
      <rect x="16" y="16" width="6" height="6" rx="1" />
      <rect x="2" y="16" width="6" height="6" rx="1" />
      <path d="M5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3" />
      <path d="M12 12V8" />
    </svg>
  );
}

export function IconKey({ size = 18 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="7.5" cy="15.5" r="5.5" />
      <path d="m21 2-9.6 9.6" />
      <path d="m15.5 7.5 3 3L22 7l-3-3" />
    </svg>
  );
}

export function IconSearch({ size = 16 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="11" cy="11" r="8" />
      <path d="m21 21-4.3-4.3" />
    </svg>
  );
}

