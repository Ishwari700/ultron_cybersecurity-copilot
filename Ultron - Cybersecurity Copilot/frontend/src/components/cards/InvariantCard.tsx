import React, { useState } from 'react';

interface InvariantCardProps {
  data: {
    invariant_id: string;
    title?: string;
    description: string;
    origin: string;
    confidence: string;
    supporting_facts?: string[];
    status?: string;
  };
  onViewDetails?: () => void;
}

export const InvariantCard: React.FC<InvariantCardProps> = ({ data, onViewDetails }) => {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="card-base" style={{ padding: '16px 20px', margin: '14px 0', borderLeft: '3px solid #3D4A6B' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-secondary)', letterSpacing: '0.04em' }}>
            SECURITY INVARIANT
          </span>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
            {data.invariant_id}
          </span>
        </div>
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <span className="badge badge-blue">{data.origin}</span>
          <button
            onClick={() => setExpanded(!expanded)}
            style={{ fontSize: '12px', color: 'var(--text-secondary)', textDecoration: 'underline' }}
          >
            {expanded ? 'Hide details' : 'Details'}
          </button>
        </div>
      </div>

      <p style={{ fontSize: '14.5px', color: 'var(--text-primary)', fontWeight: 500, lineHeight: 1.5 }}>
        {data.description}
      </p>

      {expanded && (
        <div style={{ marginTop: '12px', paddingTop: '12px', borderTop: '1px solid var(--border-subtle)', fontSize: '13px' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '120px 1fr', gap: '8px', marginBottom: '8px' }}>
            <span style={{ color: 'var(--text-secondary)' }}>Confidence:</span>
            <span style={{ fontWeight: 500 }}>{data.confidence}</span>
            <span style={{ color: 'var(--text-secondary)' }}>Epistemic Origin:</span>
            <span>{data.origin}</span>
            {data.supporting_facts && data.supporting_facts.length > 0 && (
              <>
                <span style={{ color: 'var(--text-secondary)' }}>Supporting Facts:</span>
                <span style={{ fontFamily: 'var(--font-mono)' }}>{data.supporting_facts.join(', ')}</span>
              </>
            )}
          </div>
          {onViewDetails && (
            <button
              onClick={onViewDetails}
              style={{ fontSize: '12px', color: '#2D6A4F', fontWeight: 500, marginTop: '4px' }}
            >
              View evidence in context drawer →
            </button>
          )}
        </div>
      )}
    </div>
  );
};
