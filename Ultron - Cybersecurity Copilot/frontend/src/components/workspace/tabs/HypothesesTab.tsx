import React, { useState, useEffect, useRef } from 'react';
import { fetchAssessmentHypotheses, generateAssessmentHypotheses } from '../../../api';
import type { HypothesisItem } from '../../../types';

interface HypothesesTabProps {
  assessmentId: string;
  onRefreshOverview: () => void;
  onNavigateSection: (section: string) => void;
}

export const HypothesesTab: React.FC<HypothesesTabProps> = ({
  assessmentId,
  onRefreshOverview,
  onNavigateSection,
}) => {
  const [hypotheses, setHypotheses] = useState<HypothesisItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [dataError, setDataError] = useState<string | null>(null);
  const [generateError, setGenerateError] = useState<string | null>(null);

  // Stale request guard
  const activeAssessmentRef = useRef(assessmentId);

  const loadHypotheses = async () => {
    const currentId = assessmentId;
    setLoading(true);
    setDataError(null);
    try {
      const data = await fetchAssessmentHypotheses(currentId);
      if (activeAssessmentRef.current !== currentId) return;
      setHypotheses(data);
    } catch (err: any) {
      if (activeAssessmentRef.current !== currentId) return;
      console.error('Failed to load hypotheses:', err);
      setDataError(err.message || 'Failed to load hypotheses');
    } finally {
      if (activeAssessmentRef.current === currentId) {
        setLoading(false);
      }
    }
  };

  useEffect(() => {
    activeAssessmentRef.current = assessmentId;
    setDataError(null);
    setGenerateError(null);
    loadHypotheses();
  }, [assessmentId]);

  const handleGenerate = async () => {
    setGenerating(true);
    setGenerateError(null);
    try {
      await generateAssessmentHypotheses(assessmentId);
      await loadHypotheses();
      onRefreshOverview();
    } catch (err: any) {
      console.error('Failed to generate hypotheses:', err);
      setGenerateError(err.message || 'Failed to generate hypotheses');
    } finally {
      setGenerating(false);
    }
  };

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
          <h4 style={{ fontSize: '15px', fontWeight: 600 }}>Security Hypotheses & Evidence Gaps</h4>
          <p style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
            Falsifiable vulnerability hypotheses derived from canonical target observations
          </p>
        </div>
        <button
          onClick={handleGenerate}
          disabled={generating}
          style={{
            padding: '6px 14px',
            borderRadius: 'var(--radius-md)',
            background: 'var(--accent-primary)',
            color: 'var(--text-inverse)',
            fontSize: '13px',
            fontWeight: 500,
            opacity: generating ? 0.7 : 1,
          }}
        >
          {generating ? 'Analyzing Attack Surface...' : 'Generate Hypotheses'}
        </button>
      </div>

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
          <span>Error loading hypotheses: {dataError}</span>
          <button
            onClick={() => loadHypotheses()}
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

      {generateError && (
        <div
          role="alert"
          style={{
            padding: '12px 16px',
            borderRadius: 'var(--radius-md)',
            background: 'var(--badge-red-bg)',
            border: '1px solid var(--badge-red-border)',
            color: 'var(--badge-red-text)',
            fontSize: '13px',
          }}
        >
          {generateError}
        </div>
      )}

      {loading ? (
        <div style={{ textAlign: 'center', padding: '32px', color: 'var(--text-muted)' }}>
          Loading hypotheses...
        </div>
      ) : hypotheses.length === 0 ? (
        <div style={{
          textAlign: 'center',
          padding: '40px',
          background: 'var(--bg-surface)',
          borderRadius: 'var(--radius-lg)',
          border: '1px solid var(--border-subtle)',
          color: 'var(--text-muted)',
          fontSize: '13px',
        }}>
          {dataError ? 'Unable to display hypotheses due to an error.' : 'No hypotheses generated yet. Ingest telemetry or click "Generate Hypotheses" above.'}
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {hypotheses.map((h) => (
            <div
              key={h.hypothesis_id}
              style={{
                padding: '16px 20px',
                borderRadius: 'var(--radius-lg)',
                background: 'var(--bg-surface)',
                border: '1px solid var(--border-subtle)',
                display: 'flex',
                flexDirection: 'column',
                gap: '10px',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span style={{ fontWeight: 600, fontSize: '14px' }}>{h.title}</span>
                  <span style={{
                    padding: '2px 8px',
                    borderRadius: '4px',
                    fontSize: '10px',
                    fontWeight: 600,
                    background: 'var(--badge-amber-bg)',
                    color: 'var(--badge-amber-text)',
                  }}>
                    {h.epistemic_certainty || 'MODEL_HYPOTHESIS'}
                  </span>
                </div>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)' }}>
                  {h.hypothesis_id}
                </span>
              </div>

              <p style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
                {h.description}
              </p>

              <div style={{ display: 'flex', gap: '16px', fontSize: '12px', color: 'var(--text-muted)' }}>
                <span>Target Asset: <strong>{h.target_asset}</strong></span>
                <span>Author: <strong>{h.author}</strong></span>
                <span>Supporting Evidence: <strong>{h.evidence_ids?.length || 0} item(s)</strong></span>
              </div>

              {/* Evidence Gaps */}
              {h.evidence_gaps && h.evidence_gaps.length > 0 && (
                <div style={{
                  padding: '10px 14px',
                  borderRadius: 'var(--radius-md)',
                  background: 'var(--badge-red-bg)',
                  border: '1px solid var(--badge-red-border)',
                  fontSize: '12px',
                  color: 'var(--badge-red-text)',
                }}>
                  <div style={{ fontWeight: 600, marginBottom: '4px' }}>Unresolved Evidence Gaps:</div>
                  <ul style={{ paddingLeft: '20px', margin: 0 }}>
                    {h.evidence_gaps.map((gap, gIdx) => (
                      <li key={gIdx}>{gap}</li>
                    ))}
                  </ul>
                </div>
              )}

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', borderTop: '1px solid var(--border-subtle)', paddingTop: '10px' }}>
                <button
                  onClick={() => onNavigateSection('experiments')}
                  style={{
                    padding: '6px 12px',
                    borderRadius: 'var(--radius-sm)',
                    background: 'var(--accent-primary)',
                    color: '#fff',
                    fontSize: '11px',
                    fontWeight: 600,
                  }}
                >
                  Design Controlled Experiment
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
