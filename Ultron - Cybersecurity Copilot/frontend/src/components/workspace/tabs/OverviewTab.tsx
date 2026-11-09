import React, { useState, useEffect } from 'react';
import type { AssessmentOverview, AssessmentLifecycleState } from '../../../types';
import { updateAssessment } from '../../../api';

interface OverviewTabProps {
  overview: AssessmentOverview;
  warningBanners: string[];
  onNavigateSection: (section: string) => void;
  onRefresh: () => void;
}

export const OverviewTab: React.FC<OverviewTabProps> = ({
  overview,
  warningBanners,
  onNavigateSection,
  onRefresh,
}) => {
  const wf = overview.workflow_status;

  const [targetState, setTargetState] = useState<AssessmentLifecycleState>(overview.state);
  const [transitionNotes, setTransitionNotes] = useState('');
  const [transitioning, setTransitioning] = useState(false);
  const [transitionError, setTransitionError] = useState<string | null>(null);
  const [transitionSuccess, setTransitionSuccess] = useState<string | null>(null);

  useEffect(() => {
    setTargetState(overview.state);
    setTransitionError(null);
    setTransitionSuccess(null);
  }, [overview.assessment_id, overview.state]);

  const handleStateTransition = async (e: React.FormEvent) => {
    e.preventDefault();
    if (targetState === overview.state) return;
    setTransitioning(true);
    setTransitionError(null);
    setTransitionSuccess(null);
    try {
      await updateAssessment(overview.assessment_id, {
        state: targetState,
        notes: transitionNotes.trim() || undefined,
      });
      setTransitionSuccess(`Lifecycle successfully transitioned to ${targetState}`);
      setTransitionNotes('');
      onRefresh();
    } catch (err: any) {
      setTransitionError(err.message || `Failed to transition state to ${targetState}`);
    } finally {
      setTransitioning(false);
    }
  };

  const getStateBadge = (state: string) => {
    switch (state) {
      case 'AUTHORIZED':
      case 'ASSESSMENT_ACTIVE':
      case 'COMPLETED':
        return { bg: 'var(--badge-green-bg)', text: 'var(--badge-green-text)', border: 'var(--badge-green-border)' };
      case 'DRAFT':
      case 'AUTHORIZATION_PENDING':
      case 'SCOPE_DEFINED':
      case 'VALIDATION_PENDING':
      case 'HUMAN_REVIEW':
        return { bg: 'var(--badge-amber-bg)', text: 'var(--badge-amber-text)', border: 'var(--badge-amber-border)' };
      case 'CANCELLED':
      case 'REVOKED':
      case 'EXPIRED':
        return { bg: 'var(--badge-red-bg)', text: 'var(--badge-red-text)', border: 'var(--badge-red-border)' };
      default:
        return { bg: 'var(--bg-surface-muted)', text: 'var(--text-secondary)', border: 'var(--border-subtle)' };
    }
  };

  const stateBadge = getStateBadge(overview.state);

  const checklistItems = [
    { label: 'Authorization Validated', completed: wf.authorization_valid, targetSection: 'overview' },
    { label: 'Scope Defined & Bound', completed: wf.scope_defined, targetSection: 'scope_assets' },
    { label: 'Telemetry & Evidence Ingested', completed: wf.telemetry_ingested, targetSection: 'evidence' },
    { label: 'Attack Surface Mapped', completed: wf.attack_surface_mapped, targetSection: 'attack_surface' },
    { label: 'Hypotheses Formulated & Analyzed', completed: wf.hypotheses_evaluated, targetSection: 'hypotheses' },
    { label: 'Controlled Experiments Executed', completed: wf.experiments_executed, targetSection: 'experiments' },
    { label: 'Findings Formally Reviewed', completed: wf.findings_reviewed, targetSection: 'findings_review' },
    { label: 'Final Report Generated', completed: wf.report_generated, targetSection: 'reports' },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Warning Banners */}
      {warningBanners.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {warningBanners.map((warn, i) => (
            <div
              key={i}
              role="alert"
              style={{
                padding: '10px 16px',
                borderRadius: 'var(--radius-md)',
                background: 'var(--badge-amber-bg)',
                color: 'var(--badge-amber-text)',
                border: '1px solid var(--badge-amber-border)',
                fontSize: '13px',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
              }}
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
                <line x1="12" y1="9" x2="12" y2="13" />
                <line x1="12" y1="17" x2="12.01" y2="17" />
              </svg>
              <span>{warn}</span>
            </div>
          ))}
        </div>
      )}

      {/* Metric Cards Grid */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
        gap: '14px',
      }}>
        <div
          onClick={() => onNavigateSection('scope_assets')}
          style={{
            padding: '16px',
            borderRadius: 'var(--radius-md)',
            background: 'var(--bg-surface)',
            border: '1px solid var(--border-subtle)',
            cursor: 'pointer',
          }}
        >
          <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Target Assets</div>
          <div style={{ fontSize: '24px', fontWeight: 700, margin: '4px 0' }}>{overview.asset_count}</div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            {overview.in_scope_count} in-scope · {overview.out_of_scope_count} out-of-scope
          </div>
        </div>

        <div
          onClick={() => onNavigateSection('evidence')}
          style={{
            padding: '16px',
            borderRadius: 'var(--radius-md)',
            background: 'var(--bg-surface)',
            border: '1px solid var(--border-subtle)',
            cursor: 'pointer',
          }}
        >
          <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Evidence & Observations</div>
          <div style={{ fontSize: '24px', fontWeight: 700, margin: '4px 0' }}>{overview.observation_count}</div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Canonical telemetry items</div>
        </div>

        <div
          onClick={() => onNavigateSection('hypotheses')}
          style={{
            padding: '16px',
            borderRadius: 'var(--radius-md)',
            background: 'var(--bg-surface)',
            border: '1px solid var(--border-subtle)',
            cursor: 'pointer',
          }}
        >
          <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Active Hypotheses</div>
          <div style={{ fontSize: '24px', fontWeight: 700, margin: '4px 0' }}>{overview.hypothesis_count}</div>
          <div style={{ fontSize: '11px', color: 'var(--badge-red-text)' }}>
            {overview.evidence_gap_count} evidence gap(s)
          </div>
        </div>

        <div
          onClick={() => onNavigateSection('experiments')}
          style={{
            padding: '16px',
            borderRadius: 'var(--radius-md)',
            background: 'var(--bg-surface)',
            border: '1px solid var(--border-subtle)',
            cursor: 'pointer',
          }}
        >
          <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Controlled Experiments</div>
          <div style={{ fontSize: '24px', fontWeight: 700, margin: '4px 0' }}>{overview.experiment_count}</div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Safe PoC & reproduction tests</div>
        </div>

        <div
          onClick={() => onNavigateSection('findings_review')}
          style={{
            padding: '16px',
            borderRadius: 'var(--radius-md)',
            background: 'var(--bg-surface)',
            border: '1px solid var(--border-subtle)',
            cursor: 'pointer',
          }}
        >
          <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Human-Verified Findings</div>
          <div style={{ fontSize: '24px', fontWeight: 700, margin: '4px 0', color: 'var(--badge-green-text)' }}>
            {overview.verified_finding_count} / {overview.finding_count}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>13-point verified findings</div>
        </div>
      </div>

      {/* Two Column Layout: Workflow Lifecycle Checklist & Assessment Governance */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.8fr', gap: '20px' }}>
        {/* Workflow Lifecycle Checklist */}
        <div style={{
          padding: '20px',
          borderRadius: 'var(--radius-lg)',
          background: 'var(--bg-surface)',
          border: '1px solid var(--border-subtle)',
        }}>
          <h4 style={{ fontSize: '15px', fontWeight: 600, marginBottom: '6px' }}>
            Assessment Lifecycle Progression
          </h4>
          <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '16px' }}>
            Authoritative milestone gates required for human verification and publication
          </p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {checklistItems.map((item, idx) => (
              <div
                key={idx}
                onClick={() => onNavigateSection(item.targetSection)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '10px 14px',
                  borderRadius: 'var(--radius-md)',
                  background: item.completed ? 'var(--badge-green-bg)' : 'var(--bg-surface-muted)',
                  border: `1px solid ${item.completed ? 'var(--badge-green-border)' : 'var(--border-subtle)'}`,
                  cursor: 'pointer',
                  transition: 'opacity 0.15s ease',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span style={{ fontSize: '13px', fontWeight: 600 }}>
                    {item.completed ? '✓' : '—'}
                  </span>
                  <span style={{
                    fontSize: '13px',
                    fontWeight: 500,
                    color: item.completed ? 'var(--badge-green-text)' : 'var(--text-primary)',
                  }}>
                    {item.label}
                  </span>
                </div>
                <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                  {item.completed ? 'Complete' : 'Pending →'}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Assessment Details Panel */}
        <div style={{
          padding: '20px',
          borderRadius: 'var(--radius-lg)',
          background: 'var(--bg-surface)',
          border: '1px solid var(--border-subtle)',
          display: 'flex',
          flexDirection: 'column',
          gap: '14px',
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h4 style={{ fontSize: '15px', fontWeight: 600 }}>Assessment Governance</h4>
            <span style={{
              padding: '3px 8px',
              borderRadius: 'var(--radius-sm)',
              fontSize: '11px',
              fontWeight: 700,
              background: stateBadge.bg,
              color: stateBadge.text,
              border: `1px solid ${stateBadge.border}`,
            }}>
              {overview.state}
            </span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '13px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-secondary)' }}>Organization:</span>
              <strong>{overview.organization}</strong>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-secondary)' }}>Created By:</span>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px' }}>{overview.created_by}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-secondary)' }}>Created At:</span>
              <span>{new Date(overview.created_at).toLocaleDateString()}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-secondary)' }}>Authorization ID:</span>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
                {overview.authorization_id || 'NOT BOUND'}
              </span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-secondary)' }}>Auth Status:</span>
              <strong style={{ fontSize: '12px' }}>{overview.authorization_status}</strong>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-secondary)' }}>Scope Policy ID:</span>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
                {overview.scope_policy_id || 'NOT DEFINED'}
              </span>
            </div>
          </div>

          {/* Lifecycle State Transition Engine */}
          <div style={{
            borderTop: '1px solid var(--border-subtle)',
            paddingTop: '12px',
            display: 'flex',
            flexDirection: 'column',
            gap: '8px',
          }}>
            <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)' }}>
              Transition Lifecycle State
            </label>
            {transitionError && (
              <div role="alert" style={{ fontSize: '12px', color: 'var(--badge-red-text)', background: 'var(--badge-red-bg)', padding: '6px 10px', borderRadius: 'var(--radius-sm)' }}>
                {transitionError}
              </div>
            )}
            {transitionSuccess && (
              <div role="status" style={{ fontSize: '12px', color: 'var(--badge-green-text)', background: 'var(--badge-green-bg)', padding: '6px 10px', borderRadius: 'var(--radius-sm)' }}>
                {transitionSuccess}
              </div>
            )}
            <form onSubmit={handleStateTransition} style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <div style={{ display: 'flex', gap: '8px' }}>
                <select
                  value={targetState}
                  onChange={(e) => setTargetState(e.target.value as AssessmentLifecycleState)}
                  aria-label="Target lifecycle state"
                  style={{
                    flex: 1,
                    padding: '6px 10px',
                    fontSize: '12px',
                    borderRadius: 'var(--radius-sm)',
                    background: 'var(--bg-surface)',
                    border: '1px solid var(--border-subtle)',
                  }}
                >
                  <option value="DRAFT">DRAFT</option>
                  <option value="AUTHORIZATION_PENDING">AUTHORIZATION_PENDING</option>
                  <option value="AUTHORIZED">AUTHORIZED</option>
                  <option value="SCOPE_DEFINED">SCOPE_DEFINED</option>
                  <option value="ASSESSMENT_ACTIVE">ASSESSMENT_ACTIVE</option>
                  <option value="VALIDATION_PENDING">VALIDATION_PENDING</option>
                  <option value="HUMAN_REVIEW">HUMAN_REVIEW</option>
                  <option value="COMPLETED">COMPLETED</option>
                  <option value="ARCHIVED">ARCHIVED</option>
                  <option value="CANCELLED">CANCELLED</option>
                  <option value="REVOKED">REVOKED</option>
                </select>
                <button
                  type="submit"
                  disabled={transitioning || targetState === overview.state}
                  style={{
                    padding: '6px 12px',
                    borderRadius: 'var(--radius-sm)',
                    background: targetState === overview.state ? 'var(--bg-surface-muted)' : 'var(--accent-primary)',
                    color: targetState === overview.state ? 'var(--text-muted)' : 'var(--text-inverse)',
                    fontSize: '12px',
                    fontWeight: 600,
                    cursor: targetState === overview.state ? 'not-allowed' : 'pointer',
                  }}
                >
                  {transitioning ? 'Saving...' : 'Apply State'}
                </button>
              </div>
              <input
                type="text"
                placeholder="Audit transition reason/notes (optional)..."
                value={transitionNotes}
                onChange={(e) => setTransitionNotes(e.target.value)}
                aria-label="Transition reason notes"
                style={{
                  width: '100%',
                  padding: '6px 10px',
                  fontSize: '11px',
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid var(--border-subtle)',
                }}
              />
            </form>
          </div>

          <div style={{ marginTop: 'auto', borderTop: '1px solid var(--border-subtle)', paddingTop: '14px', display: 'flex', gap: '10px' }}>
            <button
              onClick={() => onNavigateSection('reports')}
              style={{
                flex: 1,
                padding: '8px 12px',
                borderRadius: 'var(--radius-md)',
                background: 'var(--accent-primary)',
                color: 'var(--text-inverse)',
                fontSize: '12px',
                fontWeight: 600,
              }}
            >
              Preview Report
            </button>
            <button
              onClick={onRefresh}
              title="Refresh overview metrics"
              aria-label="Refresh overview metrics"
              style={{
                padding: '8px 12px',
                borderRadius: 'var(--radius-md)',
                background: 'var(--bg-surface-muted)',
                border: '1px solid var(--border-subtle)',
                fontSize: '12px',
                cursor: 'pointer',
              }}
            >
              Refresh
            </button>
            <button
              onClick={() => onNavigateSection('activity_audit')}
              style={{
                padding: '8px 12px',
                borderRadius: 'var(--radius-md)',
                background: 'var(--bg-surface-muted)',
                border: '1px solid var(--border-subtle)',
                fontSize: '12px',
              }}
            >
              Audit History
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
