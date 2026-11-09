import React, { useState } from 'react';

interface AuditCardProps {
  data: {
    status: string;
    audit_records?: any[];
  };
}

export const AuditCard: React.FC<AuditCardProps> = ({ data }) => {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="card-base" style={{ padding: '16px 20px', margin: '14px 0', borderLeft: '3px solid #2D6A4F' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-secondary)', letterSpacing: '0.04em' }}>
            CRYPTOGRAPHIC AUDIT CHAIN
          </span>
        </div>
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <span className="badge badge-green">{data.status || 'VERIFIED'}</span>
          <button
            onClick={() => setExpanded(!expanded)}
            style={{ fontSize: '12px', color: 'var(--text-secondary)', textDecoration: 'underline' }}
          >
            {expanded ? 'Hide records' : 'View records'}
          </button>
        </div>
      </div>

      <p style={{ fontSize: '13.5px', color: 'var(--text-primary)', marginBottom: '8px', lineHeight: 1.5 }}>
        All state transitions and experiment approvals are immutably logged with SHA-256 cryptographic hash chaining.
      </p>

      {expanded && data.audit_records && data.audit_records.length > 0 && (
        <div style={{ marginTop: '12px', paddingTop: '10px', borderTop: '1px solid var(--border-subtle)', fontSize: '12px' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {data.audit_records.map((rec: any, idx: number) => (
              <div key={idx} style={{ backgroundColor: 'var(--bg-app)', padding: '8px 10px', borderRadius: 'var(--radius-sm)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontWeight: 600 }}>
                  <span>{rec.event_type}</span>
                  <span style={{ color: 'var(--text-secondary)', fontSize: '11px' }}>{rec.actor}</span>
                </div>
                {rec.current_hash && (
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
                    Hash: {rec.current_hash.slice(0, 24)}...
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
