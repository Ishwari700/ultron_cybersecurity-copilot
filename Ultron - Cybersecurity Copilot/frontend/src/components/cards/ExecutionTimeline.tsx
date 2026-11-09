import React from 'react';
import type { TimelineStep } from '../../types';

interface ExecutionTimelineProps {
  steps: TimelineStep[];
  status: string;
}

export const ExecutionTimeline: React.FC<ExecutionTimelineProps> = ({ steps, status }) => {
  return (
    <div style={{ margin: '14px 0', padding: '14px 18px', backgroundColor: 'var(--bg-app)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
        <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-secondary)', letterSpacing: '0.04em' }}>
          DETERMINISTIC BOUNDARY TIMELINE
        </span>
        <span className={`badge ${status === 'EXECUTED' ? 'badge-green' : 'badge-red'}`}>
          {status}
        </span>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
        {steps.map((step, idx) => {
          const isPass = step.status === 'PASS';
          const isFail = step.status === 'FAIL' || step.status === 'BLOCKED';
          return (
            <div key={idx} style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', fontSize: '12.5px' }}>
              <div
                style={{
                  width: '18px',
                  height: '18px',
                  borderRadius: '50%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: '11px',
                  fontWeight: 700,
                  backgroundColor: isPass ? '#EAF4EE' : isFail ? '#FAECEB' : '#F2F1EC',
                  color: isPass ? '#2D6A4F' : isFail ? '#9E2A2B' : '#8C8B87',
                  flexShrink: 0,
                  marginTop: '1px',
                }}
              >
                {isPass ? '✓' : isFail ? '✕' : '○'}
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
                  <span style={{ fontWeight: 500, color: 'var(--text-primary)' }}>{step.step}</span>
                  <span style={{ fontSize: '11px', color: isPass ? '#2D6A4F' : isFail ? '#9E2A2B' : 'var(--text-muted)' }}>
                    {step.status}
                  </span>
                </div>
                <div style={{ fontSize: '11.5px', color: 'var(--text-secondary)', marginTop: '1px' }}>
                  {step.detail}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
