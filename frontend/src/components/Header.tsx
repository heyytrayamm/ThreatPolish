import React from 'react';
import { ShieldCheck, Radio } from 'lucide-react';

export const Header: React.FC = () => {
  return (
    <header className="header">
      <div className="brand">
        <div className="brand-icon">
          <ShieldCheck size={24} />
        </div>
        <div>
          <h1 className="brand-title">ThreatPolish</h1>
          <div className="brand-subtitle">Defensive Honeypot Platform</div>
        </div>
      </div>
      <div className="badge badge-cyan">
        <Radio size={14} className="badge-pulse" />
        <span>Phase 1 Scaffolding</span>
      </div>
    </header>
  );
};
