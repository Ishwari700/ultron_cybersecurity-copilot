import React, { useState } from 'react';

interface HypothesisCardProps {
  data: {
    hypothesis_id: string;
    category: string;
    target_asset: string;
    statement: string;
    evidence_state: string;
    grounding_status: string;
    epistemic_state: string;
    experiment_id?: string;
    evidence_gap?: string | null;
  };
  onInspectExperiment?: (experimentId: string) => void;
}

export const HypothesisCard: React.FC<HypothesisCardProps> = ({ data, onInspectExperiment }) => {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="card-base" style={{ padding: '16px 20px', margin: '14px 0', borderLeft: '3px solid #9A6B1F' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-secondary)', letterSpacing: '0.04em' }}>
            SECURITY HYPOTHESIS
          </span>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
            {data.hypothesis_id}
          </span>
          <span className="badge badge-amber">{data.category}</span>
        </div>
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <span className="badge badge-muted">{data.epistemic_state || 'UNVERIFIED CANDIDATE'}</span>
          <button
            onClick={() => setExpanded(!expanded)}
            style={{ fontSize: '12px', color: 'var(--text-secondary)', textDecoration: 'underline' }}
          >
            {expanded ? 'Hide details' : 'Details'}
          </button>
        </div>
      </div>

      <p style={{ fontSize: '14.5px', color: 'var(--text-primary)', fontWeight: 500, lineHeight: 1.5, marginBottom: '6px' }}>
        {data.statement}
      </p>

      {/* Structured Evidence Gap Section (Missing Information, not confirmed evidence) */}
      {data.evidence_gap && (
        <div
          style={{
            margin: '10px 0',
            padding: '10px 14px',
            background: 'rgba(217, 119, 6, 0.08)',
            border: '1px dashed #d97706',
            borderRadius: 'var(--radius-sm, 6px)',
          }}
        >
          <div
            style={{
              fontSize: '11px',
              fontWeight: 700,
              textTransform: 'uppercase',
              letterSpacing: '0.05em',
              color: '#b45309',
              marginBottom: '4px',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
            }}
          >
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
              <line x1="12" y1="9" x2="12" y2="13" />
              <line x1="12" y1="17" x2="12.01" y2="17" />
            </svg>
            <span>Evidence Gap (Unverified Missing Information)</span>
          </div>
          <p
            style={{
              fontSize: '13px',
              color: 'var(--text-primary)',
              margin: 0,
              lineHeight: 1.45,
            }}
          >
            {data.evidence_gap}
          </p>
          <div
            style={{
              fontSize: '11px',
              color: 'var(--text-secondary)',
              marginTop: '4px',
              fontStyle: 'italic',
            }}
          >
            Required missing information to distinguish competing explanations. Not confirmed target evidence.
          </div>
        </div>
      )}

      <div style={{ display: 'flex', alignItems: 'center', gap: '12px', fontSize: '12.5px', color: 'var(--text-secondary)', marginTop: '8px' }}>
        <span>Target: <code style={{ color: 'var(--text-primary)' }}>{data.target_asset}</code></span>
        <span>•</span>
        <span>Grounding: <strong style={{ color: '#2D6A4F' }}>{data.grounding_status}</strong></span>
      </div>

      {expanded && (
        <div style={{ marginTop: '12px', paddingTop: '12px', borderTop: '1px solid var(--border-subtle)', fontSize: '13px' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '130px 1fr', gap: '8px', marginBottom: '10px' }}>
            <span style={{ color: 'var(--text-secondary)' }}>Evidence State:</span>
            <span>{data.evidence_state}</span>
            <span style={{ color: 'var(--text-secondary)' }}>Grounding Check:</span>
            <span>{data.grounding_status}</span>
            <span style={{ color: 'var(--text-secondary)' }}>Target Asset:</span>
            <span style={{ fontFamily: 'var(--font-mono)' }}>{data.target_asset}</span>
            {data.evidence_gap && (
              <>
                <span style={{ color: 'var(--text-secondary)' }}>Evidence Gap:</span>
                <span style={{ color: '#b45309' }}>{data.evidence_gap}</span>
              </>
            )}
          </div>

          {data.experiment_id && onInspectExperiment && (
            <button
              onClick={() => onInspectExperiment(data.experiment_id!)}
              style={{
                fontSize: '12.5px',
                color: 'var(--text-primary)',
                fontWeight: 500,
                background: 'var(--bg-surface-muted)',
                padding: '6px 12px',
                borderRadius: 'var(--radius-sm)',
                border: '1px solid var(--border-subtle)',
              }}
            >
              View experiment proposal ({data.experiment_id}) →
            </button>
          )}
        </div>
      )}
    </div>
  );
};
