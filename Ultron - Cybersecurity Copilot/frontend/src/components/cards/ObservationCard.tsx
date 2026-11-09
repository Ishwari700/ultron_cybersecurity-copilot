import React from 'react';

interface ObservationCardProps {
  data: {
    status_code?: number;
    content_type?: string;
    observation_type: string;
    summary: string;
    derived_epistemic_status: string;
    new_evidence_id?: string;
    hypothesis_state?: string;
  };
}

export const ObservationCard: React.FC<ObservationCardProps> = ({ data }) => {
  return (
    <div className="card-base" style={{ padding: '16px 20px', margin: '14px 0', borderLeft: '3px solid #2D6A4F' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-secondary)', letterSpacing: '0.04em' }}>
            OBSERVED EXECUTION RESULT
          </span>
          {data.status_code && (
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', fontWeight: 600, color: '#2D6A4F' }}>
              HTTP {data.status_code}
            </span>
          )}
        </div>
        <span className="badge badge-green">{data.derived_epistemic_status || 'HUMAN_VERIFIED_FINDING'}</span>
      </div>

      <p style={{ fontSize: '14px', color: 'var(--text-primary)', marginBottom: '12px', lineHeight: 1.5 }}>
        {data.summary}
      </p>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '10px', padding: '10px 14px', backgroundColor: 'var(--bg-app)', borderRadius: 'var(--radius-md)', fontSize: '12px' }}>
        <div>
          <span style={{ color: 'var(--text-secondary)', display: 'block', fontSize: '11px' }}>OBSERVATION TYPE</span>
          <strong style={{ color: '#2D6A4F' }}>{data.observation_type}</strong>
        </div>
        {data.new_evidence_id && (
          <div>
            <span style={{ color: 'var(--text-secondary)', display: 'block', fontSize: '11px' }}>EVIDENCE PRODUCED</span>
            <span style={{ fontFamily: 'var(--font-mono)' }}>{data.new_evidence_id}</span>
          </div>
        )}
        {data.hypothesis_state && (
          <div>
            <span style={{ color: 'var(--text-secondary)', display: 'block', fontSize: '11px' }}>HYPOTHESIS STATE</span>
            <span style={{ fontWeight: 600 }}>{data.hypothesis_state}</span>
          </div>
        )}
      </div>

      <div style={{ marginTop: '12px', fontSize: '11.5px', color: 'var(--text-muted)', borderTop: '1px solid var(--border-subtle)', paddingTop: '8px' }}>
        Epistemic Tier: Strict separation maintained between Empirical Fact and AI Deduction.
      </div>
    </div>
  );
};
