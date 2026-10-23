import React from 'react';
import { CheckCircle2, Circle, Layers } from 'lucide-react';

interface Milestone {
  id: number;
  title: string;
  desc: string;
  status: 'completed' | 'in_progress' | 'pending';
}

const MILESTONES: Milestone[] = [
  {
    id: 1,
    title: 'Phase 1: Project Scaffolding & Health Probe',
    desc: 'FastAPI foundation, React/Vite starter, Docker Compose, health endpoint & tests.',
    status: 'completed',
  },
  {
    id: 2,
    title: 'Phase 2: Canonical Event Schema & DB Migrations',
    desc: 'Pydantic v2 schemas, PostgreSQL models, Alembic migrations, RFC 5737 compliance.',
    status: 'pending',
  },
  {
    id: 3,
    title: 'Phase 3: Simulated Decoy Services & Telemetry',
    desc: 'Simulated SSH, REST API, Database decoys with zero command execution.',
    status: 'pending',
  },
  {
    id: 4,
    title: 'Phase 4: Rule-Based Detection & Correlation',
    desc: 'Explainable threat detection rules, risk scoring (0-100), session timelines.',
    status: 'pending',
  },
  {
    id: 5,
    title: 'Phase 5: REST API & Querying',
    desc: 'Event exploration endpoints, alert reviews, session correlation APIs.',
    status: 'pending',
  },
  {
    id: 6,
    title: 'Phase 6: Threat Dashboard UI',
    desc: 'Interactive Recharts visualization, live timeline, incident inspection.',
    status: 'pending',
  },
];

export const MilestoneList: React.FC = () => {
  return (
    <div className="card">
      <div className="card-header">
        <div className="card-title">
          <Layers size={20} color="var(--accent-emerald)" />
          <span>Platform Roadmap & Safety Architecture</span>
        </div>
        <span className="badge badge-emerald">Milestone 1/6 Active</span>
      </div>

      <ul className="timeline-list">
        {MILESTONES.map((m) => {
          const isDone = m.status === 'completed';
          return (
            <li key={m.id} className="timeline-item">
              <div className={`timeline-icon ${isDone ? 'timeline-icon-done' : 'timeline-icon-pending'}`}>
                {isDone ? <CheckCircle2 size={14} /> : <Circle size={14} />}
              </div>
              <div>
                <div className="timeline-content-title" style={{ color: isDone ? 'var(--text-primary)' : 'var(--text-muted)' }}>
                  {m.title}
                </div>
                <div className="timeline-content-desc">{m.desc}</div>
              </div>
            </li>
          );
        })}
      </ul>
    </div>
  );
};
