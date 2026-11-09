import React, { useState, useEffect, useRef } from 'react';
import { fetchAssessmentObservations } from '../../../api';

interface EvidenceTabProps {
  assessmentId: string;
}

export const EvidenceTab: React.FC<EvidenceTabProps> = ({ assessmentId }) => {
  const [observations, setObservations] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [dataError, setDataError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');

  // Stale request guard
  const activeAssessmentRef = useRef(assessmentId);

  const loadObservations = async () => {
    const currentId = assessmentId;
    setLoading(true);
    setDataError(null);
    try {
      const data = await fetchAssessmentObservations(currentId);
      if (activeAssessmentRef.current !== currentId) return;
      setObservations(data);
    } catch (err: any) {
      if (activeAssessmentRef.current !== currentId) return;
      console.error('Failed to load observations:', err);
      setDataError(err.message || 'Failed to load observations');
    } finally {
      if (activeAssessmentRef.current === currentId) {
        setLoading(false);
      }
    }
  };

  useEffect(() => {
    activeAssessmentRef.current = assessmentId;
    setDataError(null);
    loadObservations();
  }, [assessmentId]);

  const filtered = observations.filter((o) => {
    const text = JSON.stringify(o).toLowerCase();
    return text.includes(searchTerm.toLowerCase());
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div style={{
        padding: '16px 20px',
        borderRadius: 'var(--radius-lg)',
        background: 'var(--bg-surface)',
        border: '1px solid var(--border-subtle)',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
      }}>
        <div>
          <h4 style={{ fontSize: '15px', fontWeight: 600 }}>Canonical Evidence Explorer</h4>
          <p style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
            Immutable observations, network traces, and cryptographic provenance
          </p>
        </div>
        <div style={{
          padding: '4px 10px',
          borderRadius: 'var(--radius-sm)',
          fontSize: '11px',
          background: 'var(--badge-green-bg)',
          color: 'var(--badge-green-text)',
        }}>
          Immutable Lineage & Redacted Vault Protected
        </div>
      </div>

      {/* Search Bar */}
      <input
        type="text"
        placeholder="Filter observations by identifier, tool, or content..."
        value={searchTerm}
        onChange={(e) => setSearchTerm(e.target.value)}
        style={{ padding: '8px 14px', fontSize: '13px' }}
      />

      {/* Error state */}
      {dataError && (
        <div
          role="alert"
          style={{
            padding: '12px 16px',
            borderRadius: 'var(--radius-md)',
            background: 'var(--badge-red-bg)',
            border: '1px solid var(--badge-red-border)',
            color: 'var(--badge-red-text)',
            fontSize: '13px',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
          }}
        >
          <span>Error loading evidence: {dataError}</span>
          <button
            onClick={() => loadObservations()}
            style={{
              padding: '4px 10px',
              borderRadius: 'var(--radius-sm)',
              background: 'var(--bg-surface)',
              border: '1px solid var(--badge-red-border)',
              color: 'var(--badge-red-text)',
              fontSize: '12px',
              cursor: 'pointer',
            }}
          >
            Retry
          </button>
        </div>
      )}

      {loading ? (
        <div style={{ textAlign: 'center', padding: '32px', color: 'var(--text-muted)' }}>
          Loading observations...
        </div>
      ) : filtered.length === 0 ? (
        <div style={{
          textAlign: 'center',
          padding: '40px',
          background: 'var(--bg-surface)',
          borderRadius: 'var(--radius-lg)',
          border: '1px solid var(--border-subtle)',
          color: 'var(--text-muted)',
          fontSize: '13px',
        }}>
          {dataError ? 'Unable to display evidence records due to an error.' : 'No evidence records found. Ingest telemetry or import traffic.'}
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          {filtered.map((obs) => (
            <div
              key={obs.observation_id}
              style={{
                padding: '14px 18px',
                borderRadius: 'var(--radius-md)',
                background: 'var(--bg-surface)',
                border: '1px solid var(--border-subtle)',
                display: 'flex',
                flexDirection: 'column',
                gap: '8px',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span style={{
                    padding: '2px 6px',
                    borderRadius: '4px',
                    fontSize: '10px',
                    fontWeight: 600,
                    background: 'var(--badge-blue-bg)',
                    color: 'var(--badge-blue-text)',
                  }}>
                    {obs.observation_type || 'OBSERVATION'}
                  </span>
                  <span style={{ fontWeight: 600, fontSize: '13px' }}>
                    {obs.canonical_identifier}
                  </span>
                </div>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)' }}>
                  {obs.observation_id}
                </span>
              </div>

              <pre style={{
                fontSize: '12px',
                fontFamily: 'var(--font-mono)',
                background: 'var(--bg-surface-muted)',
                padding: '10px 12px',
                borderRadius: 'var(--radius-sm)',
                whiteSpace: 'pre-wrap',
                maxHeight: '180px',
                overflowY: 'auto',
              }}>
                {typeof obs.content === 'string' ? obs.content : JSON.stringify(obs.content, null, 2)}
              </pre>

              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', color: 'var(--text-muted)' }}>
                <span>Timestamp: {new Date(obs.timestamp).toLocaleString()}</span>
                <span>Provenance: {obs.provenance?.tool_name || 'System Telemetry'}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
