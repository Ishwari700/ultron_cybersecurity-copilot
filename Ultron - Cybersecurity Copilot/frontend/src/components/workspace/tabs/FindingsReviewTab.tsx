import React, { useState, useEffect, useRef } from 'react';
import {
  fetchAssessmentFindings,
  createAssessmentFinding,
  verifyFindingAuthoritative,
} from '../../../api';
import type { FindingItem } from '../../../types';

interface FindingsReviewTabProps {
  assessmentId: string;
  onRefreshOverview: () => void;
  onNavigateSection: (section: string) => void;
}

export const FindingsReviewTab: React.FC<FindingsReviewTabProps> = ({
  assessmentId,
  onRefreshOverview,
  onNavigateSection,
}) => {
  const [findings, setFindings] = useState<FindingItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [dataError, setDataError] = useState<string | null>(null);
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [filterStatus, setFilterStatus] = useState('ALL');

  // Verify Modal State
  const [verifyingFinding, setVerifyingFinding] = useState<FindingItem | null>(null);
  const [justification, setJustification] = useState('');
  const [verifying, setVerifying] = useState(false);
  const [verificationError, setVerificationError] = useState<string | null>(null);

  // New Finding Modal State
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [title, setTitle] = useState('');
  const [severity, setSeverity] = useState('HIGH');
  const [asset, setAsset] = useState('example.com');
  const [description, setDescription] = useState('');
  const [impact, setImpact] = useState('');
  const [evidenceInput, setEvidenceInput] = useState('');
  const [rootCause, setRootCause] = useState('');
  const [remediation, setRemediation] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

  // Stale state protection
  const activeAssessmentRef = useRef(assessmentId);

  const loadFindings = async () => {
    const currentId = assessmentId;
    setLoading(true);
    setDataError(null);
    try {
      const data = await fetchAssessmentFindings(currentId);
      if (activeAssessmentRef.current !== currentId) return;
      setFindings(data);
    } catch (err: any) {
      if (activeAssessmentRef.current !== currentId) return;
      setDataError(err.message || 'Failed to load findings');
    } finally {
      if (activeAssessmentRef.current === currentId) {
        setLoading(false);
      }
    }
  };

  useEffect(() => {
    activeAssessmentRef.current = assessmentId;
    setDataError(null);
    setVerificationError(null);
    setCreateError(null);
    setVerifyingFinding(null);
    setShowCreateForm(false);
    loadFindings();
  }, [assessmentId]);

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!verifyingFinding || !justification.trim()) return;
    setVerifying(true);
    setVerificationError(null);
    try {
      await verifyFindingAuthoritative(
        verifyingFinding.finding_id,
        justification.trim()
      );
      setVerifyingFinding(null);
      setJustification('');
      await loadFindings();
      onRefreshOverview();
    } catch (err: any) {
      setVerificationError(err.message || '13-point verification failed');
    } finally {
      setVerifying(false);
    }
  };

  const handleCreateFinding = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim() || !asset.trim()) return;
    setSubmitting(true);
    setCreateError(null);
    try {
      const evidenceList = evidenceInput
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);

      await createAssessmentFinding(assessmentId, {
        title: title.trim(),
        severity,
        asset: asset.trim(),
        affected_component: 'API Endpoint',
        description: description.trim(),
        impact: impact.trim() || 'Unauthorized data access',
        evidence: evidenceList,
        reproduction_reference: 'EXP-REF',
        security_invariant: 'INV-AUTH-01',
        root_cause: rootCause.trim() || 'Missing server-side permission check',
        remediation: remediation.trim() || 'Implement role-based authorization validator',
        references: [],
      });
      setShowCreateForm(false);
      setTitle('');
      setDescription('');
      setEvidenceInput('');
      await loadFindings();
      onRefreshOverview();
    } catch (err: any) {
      setCreateError(err.message || 'Failed to create candidate finding');
    } finally {
      setSubmitting(false);
    }
  };

  const filteredFindings = findings.filter((f) => {
    const matchesSev = filterSeverity === 'ALL' || f.severity === filterSeverity;
    const matchesStat = filterStatus === 'ALL' || f.verification_status === filterStatus;
    return matchesSev && matchesStat;
  });

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return { bg: '#FEE2E2', text: '#991B1B' };
      case 'HIGH':
        return { bg: '#FFEDD5', text: '#9A3412' };
      case 'MEDIUM':
        return { bg: '#FEF3C7', text: '#92400E' };
      case 'LOW':
        return { bg: '#DBEAFE', text: '#1E40AF' };
      default:
        return { bg: '#F1F5F9', text: '#475569' };
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
          <h4 style={{ fontSize: '15px', fontWeight: 600 }}>Findings & Human Review Pipeline</h4>
          <p style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
            Authoritative 13-point FindingValidator verification and peer sign-off
          </p>
        </div>
        <div style={{ display: 'flex', gap: '10px' }}>
          <button
            onClick={() => setShowCreateForm(true)}
            style={{
              padding: '6px 14px',
              borderRadius: 'var(--radius-md)',
              background: 'var(--accent-primary)',
              color: 'var(--text-inverse)',
              fontSize: '13px',
              fontWeight: 500,
            }}
          >
            + New Candidate Finding
          </button>
        </div>
      </div>

      {/* Epistemic Verification Notice */}
      <div style={{
        padding: '10px 14px',
        borderRadius: 'var(--radius-md)',
        background: 'var(--badge-green-bg)',
        border: '1px solid var(--badge-green-border)',
        fontSize: '12px',
        color: 'var(--badge-green-text)',
      }}>
        <strong>Rule M13-16:</strong> AI models cannot mark findings verified. Only a human reviewer passing all 13 checklist validation predicates can confirm a finding.
      </div>

      {/* Filter Toolbar */}
      <div style={{ display: 'flex', gap: '12px' }}>
        <select
          value={filterSeverity}
          onChange={(e) => setFilterSeverity(e.target.value)}
          style={{ padding: '6px 10px', fontSize: '13px', borderRadius: 'var(--radius-md)', background: 'var(--bg-surface)' }}
        >
          <option value="ALL">All Severities</option>
          <option value="CRITICAL">CRITICAL</option>
          <option value="HIGH">HIGH</option>
          <option value="MEDIUM">MEDIUM</option>
          <option value="LOW">LOW</option>
          <option value="INFORMATIONAL">INFORMATIONAL</option>
        </select>
        <select
          value={filterStatus}
          onChange={(e) => setFilterStatus(e.target.value)}
          style={{ padding: '6px 10px', fontSize: '13px', borderRadius: 'var(--radius-md)', background: 'var(--bg-surface)' }}
        >
          <option value="ALL">All Verification States</option>
          <option value="UNVERIFIED">UNVERIFIED</option>
          <option value="HUMAN_VERIFIED">HUMAN_VERIFIED</option>
          <option value="EVIDENCE_REVIEW">EVIDENCE_REVIEW</option>
        </select>
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
          <span>Error loading findings: {dataError}</span>
          <button
            onClick={() => loadFindings()}
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

      {/* Findings List */}
      {loading ? (
        <div style={{ textAlign: 'center', padding: '32px', color: 'var(--text-muted)' }}>
          Loading findings pipeline...
        </div>
      ) : filteredFindings.length === 0 ? (
        <div style={{
          textAlign: 'center',
          padding: '40px',
          background: 'var(--bg-surface)',
          borderRadius: 'var(--radius-lg)',
          border: '1px solid var(--border-subtle)',
          color: 'var(--text-muted)',
          fontSize: '13px',
        }}>
          {dataError ? 'Unable to display findings due to an error.' : 'No findings match the current criteria.'}
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {filteredFindings.map((f) => {
            const sevBadge = getSeverityBadge(f.severity);
            const isVerified = f.verification_status === 'HUMAN_VERIFIED';

            return (
              <div
                key={f.finding_id}
                style={{
                  padding: '16px 20px',
                  borderRadius: 'var(--radius-lg)',
                  background: 'var(--bg-surface)',
                  border: isVerified ? '2px solid var(--badge-green-border)' : '1px solid var(--border-subtle)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '10px',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <span style={{
                      padding: '2px 8px',
                      borderRadius: '4px',
                      fontSize: '11px',
                      fontWeight: 700,
                      background: sevBadge.bg,
                      color: sevBadge.text,
                    }}>
                      {f.severity}
                    </span>
                    <span style={{ fontWeight: 600, fontSize: '14px' }}>{f.title}</span>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{
                      padding: '2px 8px',
                      borderRadius: '4px',
                      fontSize: '11px',
                      fontWeight: 700,
                      background: isVerified ? 'var(--badge-green-bg)' : 'var(--bg-surface-muted)',
                      color: isVerified ? 'var(--badge-green-text)' : 'var(--text-secondary)',
                      border: `1px solid ${isVerified ? 'var(--badge-green-border)' : 'var(--border-subtle)'}`,
                    }}>
                      {isVerified ? 'HUMAN VERIFIED' : 'UNVERIFIED CANDIDATE'}
                    </span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)' }}>
                      {f.finding_id}
                    </span>
                  </div>
                </div>

                <p style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
                  {f.description}
                </p>

                <div style={{ display: 'flex', gap: '20px', fontSize: '12px', color: 'var(--text-muted)' }}>
                  <span>Asset: <strong>{f.asset}</strong></span>
                  <span>Impact: <strong>{f.impact}</strong></span>
                  {f.verified_by && <span>Verified By: <strong>{f.verified_by}</strong></span>}
                </div>

                <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', borderTop: '1px solid var(--border-subtle)', paddingTop: '10px' }}>
                  {!isVerified && (
                    <button
                      onClick={() => setVerifyingFinding(f)}
                      style={{
                        padding: '6px 14px',
                        borderRadius: 'var(--radius-sm)',
                        background: 'var(--accent-primary)',
                        color: '#fff',
                        fontSize: '12px',
                        fontWeight: 600,
                      }}
                    >
                      Human Verification Check
                    </button>
                  )}
                  {isVerified && (
                    <button
                      onClick={() => onNavigateSection('reports')}
                      style={{
                        padding: '6px 12px',
                        borderRadius: 'var(--radius-sm)',
                        background: 'var(--bg-surface-muted)',
                        fontSize: '12px',
                      }}
                    >
                      Include in Report →
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Human Verification Modal */}
      {verifyingFinding && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.45)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1100,
        }}>
          <div style={{
            backgroundColor: 'var(--bg-surface)',
            borderRadius: 'var(--radius-lg)',
            width: '520px',
            boxShadow: 'var(--shadow-elevated)',
            border: '1px solid var(--border-subtle)',
            overflow: 'hidden',
          }}>
            <div style={{
              padding: '16px 20px',
              borderBottom: '1px solid var(--border-subtle)',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
            }}>
              <div>
                <h4 style={{ fontSize: '15px', fontWeight: 600 }}>13-Point Human Verification Check</h4>
                <p style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                  Finding: {verifyingFinding.title} ({verifyingFinding.finding_id})
                </p>
              </div>
              <button onClick={() => setVerifyingFinding(null)} aria-label="Close verification dialog" style={{ fontSize: '16px', background: 'transparent', border: 'none', cursor: 'pointer' }}>✕</button>
            </div>

            <form onSubmit={handleVerify} style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
              {verificationError && (
                <div style={{
                  padding: '8px 12px',
                  borderRadius: 'var(--radius-sm)',
                  background: 'var(--badge-red-bg)',
                  color: 'var(--badge-red-text)',
                  fontSize: '12px',
                }}>
                  {verificationError}
                </div>
              )}

              <div style={{
                padding: '8px 12px',
                borderRadius: 'var(--radius-sm)',
                background: 'var(--bg-surface-muted)',
                border: '1px solid var(--border-subtle)',
                fontSize: '11.5px',
                color: 'var(--text-secondary)',
              }}>
                <strong style={{ color: 'var(--text-primary)' }}>Reviewer Authority:</strong> Verification is authoritatively bound to your active authenticated session. No client-supplied reviewer identity is accepted.
              </div>

              <div>
                <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)' }}>
                  Verification Justification & Reproduction Evidence *
                </label>
                <textarea
                  rows={4}
                  placeholder="Detail the confirmed reproduction steps, negative control outcome, and verification audit trail..."
                  value={justification}
                  onChange={(e) => setJustification(e.target.value)}
                  required
                  style={{ width: '100%', padding: '8px', fontSize: '12px', marginTop: '4px' }}
                />
              </div>

              <div style={{
                fontSize: '11px',
                color: 'var(--text-muted)',
                background: 'var(--bg-surface-muted)',
                padding: '8px 12px',
                borderRadius: 'var(--radius-sm)',
              }}>
                Asserts: In-Scope Asset, Non-empty Evidence, Negative Control Checked, No Unverified Gaps, Immutable Provenance.
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
                <button
                  type="button"
                  onClick={() => setVerifyingFinding(null)}
                  style={{ padding: '6px 12px', fontSize: '12px' }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={verifying}
                  style={{
                    padding: '8px 16px',
                    borderRadius: 'var(--radius-md)',
                    background: 'var(--badge-green-text)',
                    color: '#fff',
                    fontSize: '12px',
                    fontWeight: 600,
                  }}
                >
                  {verifying ? 'Evaluating Predicates...' : 'Confirm Human Verification'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Create Finding Modal */}
      {showCreateForm && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.45)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1100,
        }}>
          <div style={{
            backgroundColor: 'var(--bg-surface)',
            borderRadius: 'var(--radius-lg)',
            width: '540px',
            boxShadow: 'var(--shadow-elevated)',
            border: '1px solid var(--border-subtle)',
            overflow: 'hidden',
          }}>
            <div style={{
              padding: '16px 20px',
              borderBottom: '1px solid var(--border-subtle)',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
            }}>
              <h4 style={{ fontSize: '15px', fontWeight: 600 }}>Create Candidate Finding</h4>
              <button onClick={() => setShowCreateForm(false)} aria-label="Close create finding dialog" style={{ fontSize: '16px', background: 'transparent', border: 'none', cursor: 'pointer' }}>✕</button>
            </div>

            <form onSubmit={handleCreateFinding} style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {createError && (
                <div style={{ color: 'var(--badge-red-text)', fontSize: '12px' }}>{createError}</div>
              )}

              <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '10px' }}>
                <input
                  type="text"
                  placeholder="Title (e.g. Remote Code Execution via Insecure Deserialization)"
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  required
                  style={{ padding: '8px 12px', fontSize: '13px' }}
                />
                <select
                  value={severity}
                  onChange={(e) => setSeverity(e.target.value)}
                  style={{ padding: '8px', fontSize: '12px', borderRadius: 'var(--radius-md)' }}
                >
                  <option value="CRITICAL">CRITICAL</option>
                  <option value="HIGH">HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="LOW">LOW</option>
                  <option value="INFORMATIONAL">INFORMATIONAL</option>
                </select>
              </div>

              <input
                type="text"
                placeholder="Affected Target Asset (e.g. api.example.com)"
                value={asset}
                onChange={(e) => setAsset(e.target.value)}
                required
                style={{ padding: '8px 12px', fontSize: '13px' }}
              />

              <textarea
                rows={3}
                placeholder="Description of the vulnerability..."
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                required
                style={{ padding: '8px 12px', fontSize: '12px' }}
              />

              <div>
                <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)' }}>
                  Associated Evidence (comma-separated, e.g. EVID-001, EVID-002)
                </label>
                <input
                  type="text"
                  placeholder="EVID-001, EVID-002 (Required for downstream 13-point verification)"
                  value={evidenceInput}
                  onChange={(e) => setEvidenceInput(e.target.value)}
                  style={{ width: '100%', padding: '8px 12px', fontSize: '13px', marginTop: '4px' }}
                />
              </div>

              <input
                type="text"
                placeholder="Impact..."
                value={impact}
                onChange={(e) => setImpact(e.target.value)}
                style={{ padding: '8px 12px', fontSize: '13px' }}
              />

              <input
                type="text"
                placeholder="Root cause (e.g. Unsanitized reflection, broken access control)..."
                value={rootCause}
                onChange={(e) => setRootCause(e.target.value)}
                style={{ padding: '8px 12px', fontSize: '13px' }}
              />

              <input
                type="text"
                placeholder="Remediation guidance..."
                value={remediation}
                onChange={(e) => setRemediation(e.target.value)}
                style={{ padding: '8px 12px', fontSize: '13px' }}
              />

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', marginTop: '6px' }}>
                <button
                  type="button"
                  onClick={() => setShowCreateForm(false)}
                  style={{ padding: '6px 12px', fontSize: '12px' }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  style={{
                    padding: '8px 16px',
                    borderRadius: 'var(--radius-md)',
                    background: 'var(--accent-primary)',
                    color: '#fff',
                    fontSize: '12px',
                    fontWeight: 600,
                  }}
                >
                  {submitting ? 'Registering...' : 'Register Candidate Finding'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
