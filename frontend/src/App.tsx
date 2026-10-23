import React from 'react';
import { Header } from './components/Header';
import { HealthCard } from './components/HealthCard';
import { MilestoneList } from './components/MilestoneList';
import { ShieldAlert, Terminal, Database, Globe } from 'lucide-react';

export const App: React.FC = () => {
  return (
    <div className="container">
      <Header />

      <div className="grid grid-2">
        <HealthCard />
        <MilestoneList />
      </div>

      <div className="card" style={{ marginTop: '1.5rem' }}>
        <div className="card-header">
          <div className="card-title">
            <ShieldAlert size={20} color="var(--accent-amber)" />
            <span>Defensive Honeypot Safety Principles</span>
          </div>
          <span className="badge badge-amber">Strict Safety Controls</span>
        </div>

        <div className="grid grid-3" style={{ marginBottom: '0.5rem' }}>
          <div className="stat-row" style={{ flexDirection: 'column', alignItems: 'flex-start', gap: '0.4rem', padding: '1rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--accent-cyan)', fontWeight: 600 }}>
              <Terminal size={16} />
              <span>Zero Command Execution</span>
            </div>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              Decoys never spawn shells or execute attacker-submitted payloads. Interactions are treated strictly as read-only telemetry.
            </p>
          </div>

          <div className="stat-row" style={{ flexDirection: 'column', alignItems: 'flex-start', gap: '0.4rem', padding: '1rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--accent-emerald)', fontWeight: 600 }}>
              <Database size={16} />
              <span>Sanitized Telemetry</span>
            </div>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              Passwords and password hashes are never stored in plain telemetry. Only authentication outcome and length metrics are recorded.
            </p>
          </div>

          <div className="stat-row" style={{ flexDirection: 'column', alignItems: 'flex-start', gap: '0.4rem', padding: '1rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--accent-amber)', fontWeight: 600 }}>
              <Globe size={16} />
              <span>Localhost Isolation</span>
            </div>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              Services bind strictly to <code className="code-pill">127.0.0.1</code> by default. Test fixtures use RFC 5737 reserved testnet IP ranges.
            </p>
          </div>
        </div>

        <div className="callout">
          <strong>Defensive Architecture Status:</strong> Phase 1 scaffolding is active. Decoys, event persistence, and detection rules remain disabled until respective milestones. All components operate in simulated safe mode.
        </div>
      </div>
    </div>
  );
};

export default App;
