import React, { useState, useEffect } from 'react';
import { Activity, RefreshCw, CheckCircle2, AlertTriangle, Clock } from 'lucide-react';
import { HealthData } from '../types/health';

export const HealthCard: React.FC = () => {
  const [health, setHealth] = useState<HealthData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [latencyMs, setLatencyMs] = useState<number | null>(null);

  const checkHealth = async () => {
    setLoading(true);
    setError(null);
    const start = performance.now();

    try {
      const response = await fetch('/api/v1/health');
      const duration = Math.round(performance.now() - start);
      setLatencyMs(duration);

      if (!response.ok) {
        throw new Error(`HTTP error ${response.status}: ${response.statusText}`);
      }

      const data: HealthData = await response.json();
      setHealth(data);
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('Unable to connect to backend service.');
      }
      setHealth(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    checkHealth();
  }, []);

  return (
    <div className="card">
      <div className="card-header">
        <div className="card-title">
          <Activity size={20} color="var(--accent-cyan)" />
          <span>Backend Health Telemetry</span>
        </div>
        <button
          className="btn btn-primary"
          onClick={checkHealth}
          disabled={loading}
          title="Refresh health status"
        >
          <RefreshCw size={14} className={loading ? 'badge-pulse' : ''} />
          <span>{loading ? 'Probing...' : 'Ping Backend'}</span>
        </button>
      </div>

      {error ? (
        <div className="callout" style={{ borderColor: 'var(--accent-rose)', background: 'rgba(244, 63, 94, 0.08)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--accent-rose)', fontWeight: 600, marginBottom: '0.4rem' }}>
            <AlertTriangle size={18} />
            <span>Backend Unreachable</span>
          </div>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>{error}</p>
          <p style={{ marginTop: '0.5rem', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            Ensure FastAPI is running on <code className="code-pill">http://127.0.0.1:8000</code>.
          </p>
        </div>
      ) : (
        <div className="stat-list">
          <div className="stat-row">
            <span className="stat-label">Endpoint Status</span>
            <span className="badge badge-emerald">
              <CheckCircle2 size={13} />
              <span>{health?.status ? health.status.toUpperCase() : 'PENDING'}</span>
            </span>
          </div>

          <div className="stat-row">
            <span className="stat-label">Service</span>
            <span className="stat-value">{health?.service || 'Connecting...'}</span>
          </div>

          <div className="stat-row">
            <span className="stat-label">Version</span>
            <span className="stat-value">{health?.version ? `v${health.version}` : '—'}</span>
          </div>

          <div className="stat-row">
            <span className="stat-label">Environment</span>
            <span className="stat-value">{health?.environment || '—'}</span>
          </div>

          <div className="stat-row">
            <span className="stat-label">Roundtrip Latency</span>
            <span className="stat-value" style={{ color: 'var(--accent-cyan)' }}>
              {latencyMs !== null ? `${latencyMs} ms` : '—'}
            </span>
          </div>

          <div className="stat-row">
            <span className="stat-label">Server Timestamp (UTC)</span>
            <span className="stat-value" style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
              <Clock size={13} color="var(--text-muted)" />
              {health?.timestamp ? new Date(health.timestamp).toLocaleTimeString() : '—'}
            </span>
          </div>
        </div>
      )}
    </div>
  );
};
