import React, { useState, useEffect, useRef } from 'react';
import {
  fetchAssessmentExperiments,
  fetchAssessmentHypotheses,
  proposeAssessmentExperiment,
  approveAssessmentExperiment,
  importAssessmentExperimentResult,
} from '../../../api';
import type { ExperimentItem, HypothesisItem } from '../../../types';

interface ExperimentsTabProps {
  assessmentId: string;
  onRefreshOverview: () => void;
}

export const ExperimentsTab: React.FC<ExperimentsTabProps> = ({
  assessmentId,
  onRefreshOverview,
}) => {
  const [experiments, setExperiments] = useState<ExperimentItem[]>([]);
  const [hypotheses, setHypotheses] = useState<HypothesisItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [dataError, setDataError] = useState<string | null>(null);
  const [showProposeForm, setShowProposeForm] = useState(false);

  // Proposal Form State
  const [hypothesisId, setHypothesisId] = useState('');
  const [objective, setObjective] = useState('');
  const [targetAsset, setTargetAsset] = useState('');
  const [steps, setSteps] = useState('');
  const [expectedSecure, setExpectedSecure] = useState('HTTP 401/403 or sanitized input');
  const [expectedVulnerable, setExpectedVulnerable] = useState('Execution of probe payload without sanitization');
  const [falsification, setFalsification] = useState('Target rejects input or returns benign response');
  const [negativeControl, setNegativeControl] = useState('Send unmutated baseline request');
  const [riskLevel, setRiskLevel] = useState('PASSIVE');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Approve & Result Import State
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);
  const [approvingId, setApprovingId] = useState<string | null>(null);
  const [resultImportExp, setResultImportExp] = useState<ExperimentItem | null>(null);
  const [resultPayloadText, setResultPayloadText] = useState('{\n  "status_code": 200,\n  "payload_executed": true,\n  "evidence_summary": "Observed state alteration upon probe submission"\n}');
  const [importingResult, setImportingResult] = useState(false);

  // Stale state protection
  const activeAssessmentRef = useRef(assessmentId);

  const loadData = async () => {
    const currentId = assessmentId;
    setLoading(true);
    setDataError(null);
    try {
      const [exps, hyps] = await Promise.all([
        fetchAssessmentExperiments(currentId),
        fetchAssessmentHypotheses(currentId),
      ]);
      if (activeAssessmentRef.current !== currentId) return;
      setExperiments(exps);
      setHypotheses(hyps);
      if (hyps.length > 0 && !hypothesisId) {
        setHypothesisId(hyps[0].hypothesis_id);
        setTargetAsset(hyps[0].target_asset);
      }
    } catch (err: any) {
      if (activeAssessmentRef.current !== currentId) return;
      setDataError(err.message || 'Failed to load experiments');
    } finally {
      if (activeAssessmentRef.current === currentId) {
        setLoading(false);
      }
    }
  };

  useEffect(() => {
    activeAssessmentRef.current = assessmentId;
    setDataError(null);
    setActionError(null);
    setActionSuccess(null);
    setResultImportExp(null);
    setShowProposeForm(false);
    loadData();
  }, [assessmentId]);

  const handleApprove = async (expId: string) => {
    const currentId = assessmentId;
    setApprovingId(expId);
    setActionError(null);
    setActionSuccess(null);
    try {
      await approveAssessmentExperiment(currentId, expId);
      if (activeAssessmentRef.current !== currentId) return;
      setActionSuccess(`Experiment ${expId} approved by authoritative session.`);
      await loadData();
      onRefreshOverview();
    } catch (err: any) {
      if (activeAssessmentRef.current !== currentId) return;
      setActionError(err.message || `Approval failed for ${expId}`);
    } finally {
      if (activeAssessmentRef.current === currentId) {
        setApprovingId(null);
      }
    }
  };

  const handleImportResult = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!resultImportExp) return;

    let payload: any;
    try {
      payload = JSON.parse(resultPayloadText);
    } catch {
      setActionError('Result payload must be valid JSON.');
      return;
    }

    setImportingResult(true);
    setActionError(null);
    setActionSuccess(null);
    try {
      await importAssessmentExperimentResult(resultImportExp.experiment_id, payload);
      if (activeAssessmentRef.current !== assessmentId) return;
      setActionSuccess(`Execution result imported for ${resultImportExp.experiment_id}. Status transitioned to EXECUTED.`);
      setResultImportExp(null);
      await loadData();
      onRefreshOverview();
    } catch (err: any) {
      if (activeAssessmentRef.current !== assessmentId) return;
      setActionError(err.message || 'Failed to import experiment result');
    } finally {
      if (activeAssessmentRef.current === assessmentId) {
        setImportingResult(false);
      }
    }
  };

  const handlePropose = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!objective.trim() || !hypothesisId) {
      setError('Objective and associated hypothesis are required.');
      return;
    }

    setSubmitting(true);
    setError(null);
    try {
      const stepList = steps.split('\n').map((s) => s.trim()).filter(Boolean);
      await proposeAssessmentExperiment(assessmentId, {
        hypothesis_id: hypothesisId,
        objective: objective.trim(),
        target_asset: targetAsset.trim(),
        steps: stepList.length > 0 ? stepList : ['1. Send deterministic baseline probe'],
        expected_secure_result: expectedSecure.trim(),
        expected_vulnerable_result: expectedVulnerable.trim(),
        falsification_condition: falsification.trim(),
        negative_control: negativeControl.trim(),
        risk_level: riskLevel,
      });
      setShowProposeForm(false);
      setObjective('');
      setSteps('');
      await loadData();
      onRefreshOverview();
    } catch (err: any) {
      setError(err.message || 'Failed to propose experiment');
    } finally {
      setSubmitting(false);
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
          <h4 style={{ fontSize: '15px', fontWeight: 600 }}>Controlled Security Experiments & Reproducibility</h4>
          <p style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
            Plane A local safe lab execution and Plane B manual reproduction procedure management
          </p>
        </div>
        <button
          onClick={() => setShowProposeForm(!showProposeForm)}
          style={{
            padding: '6px 14px',
            borderRadius: 'var(--radius-md)',
            background: 'var(--accent-primary)',
            color: 'var(--text-inverse)',
            fontSize: '13px',
            fontWeight: 500,
          }}
        >
          {showProposeForm ? 'Cancel' : '+ Propose Experiment'}
        </button>
      </div>

      {/* Safety Gate Banner */}
      <div style={{
        padding: '10px 14px',
        borderRadius: 'var(--radius-md)',
        background: 'var(--bg-surface-muted)',
        border: '1px solid var(--border-subtle)',
        fontSize: '12px',
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        color: 'var(--text-secondary)',
      }}>
        <span>
          <strong>Two-Plane Safety Policy:</strong> Plane A runs under deterministic loopback simulation with human preflight approval. Plane B organizes reproduction steps without autonomous live target exploitation.
        </span>
      </div>

      {/* Proposal Form */}
      {showProposeForm && (
        <form onSubmit={handlePropose} style={{
          padding: '20px',
          borderRadius: 'var(--radius-lg)',
          background: 'var(--bg-surface)',
          border: '1px solid var(--border-subtle)',
          display: 'flex',
          flexDirection: 'column',
          gap: '14px',
        }}>
          <h5 style={{ fontSize: '14px', fontWeight: 600 }}>Propose Controlled Experiment</h5>
          {error && (
            <div style={{ color: 'var(--badge-red-text)', fontSize: '12px' }}>{error}</div>
          )}

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '12px' }}>
            <div>
              <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)' }}>
                Hypothesis *
              </label>
              <select
                value={hypothesisId}
                onChange={(e) => {
                  setHypothesisId(e.target.value);
                  const matched = hypotheses.find((h) => h.hypothesis_id === e.target.value);
                  if (matched) setTargetAsset(matched.target_asset);
                }}
                required
                style={{ width: '100%', padding: '8px', fontSize: '12px', marginTop: '4px' }}
              >
                {hypotheses.map((h) => (
                  <option key={h.hypothesis_id} value={h.hypothesis_id}>
                    {h.title} ({h.hypothesis_id})
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)' }}>
                Target Asset *
              </label>
              <input
                type="text"
                value={targetAsset}
                onChange={(e) => setTargetAsset(e.target.value)}
                required
                style={{ width: '100%', padding: '8px', fontSize: '12px', marginTop: '4px' }}
              />
            </div>

            <div>
              <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)' }}>
                Risk Classification *
              </label>
              <select
                value={riskLevel}
                onChange={(e) => setRiskLevel(e.target.value)}
                style={{ width: '100%', padding: '8px', fontSize: '12px', marginTop: '4px' }}
              >
                <option value="PASSIVE">PASSIVE (Inspection / Headers)</option>
                <option value="ACTIVE_SAFE">ACTIVE_SAFE (Benign Probe / Canary)</option>
                <option value="MUTATIVE">MUTATIVE (Requires Special Sign-Off)</option>
              </select>
            </div>
          </div>

          <div>
            <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)' }}>
              Test Objective *
            </label>
            <input
              type="text"
              placeholder="e.g. Verify whether endpoint responds with reflected payload"
              value={objective}
              onChange={(e) => setObjective(e.target.value)}
              required
              style={{ width: '100%', padding: '8px', fontSize: '13px', marginTop: '4px' }}
            />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
            <div>
              <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)' }}>
                Expected Secure Result
              </label>
              <input
                type="text"
                value={expectedSecure}
                onChange={(e) => setExpectedSecure(e.target.value)}
                style={{ width: '100%', padding: '8px', fontSize: '12px', marginTop: '4px' }}
              />
            </div>
            <div>
              <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)' }}>
                Expected Vulnerable Result
              </label>
              <input
                type="text"
                value={expectedVulnerable}
                onChange={(e) => setExpectedVulnerable(e.target.value)}
                style={{ width: '100%', padding: '8px', fontSize: '12px', marginTop: '4px' }}
              />
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
            <div>
              <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)' }}>
                Falsification Condition
              </label>
              <input
                type="text"
                value={falsification}
                onChange={(e) => setFalsification(e.target.value)}
                style={{ width: '100%', padding: '8px', fontSize: '12px', marginTop: '4px' }}
              />
            </div>
            <div>
              <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)' }}>
                Negative Control
              </label>
              <input
                type="text"
                value={negativeControl}
                onChange={(e) => setNegativeControl(e.target.value)}
                style={{ width: '100%', padding: '8px', fontSize: '12px', marginTop: '4px' }}
              />
            </div>
          </div>

          <div>
            <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)' }}>
              Reproduction Steps (one per line)
            </label>
            <textarea
              rows={3}
              placeholder="Step 1: Execute GET request with harmless parameter..."
              value={steps}
              onChange={(e) => setSteps(e.target.value)}
              style={{ width: '100%', padding: '8px', fontSize: '12px', marginTop: '4px' }}
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
            <button
              type="button"
              onClick={() => setShowProposeForm(false)}
              style={{ padding: '6px 12px', fontSize: '12px' }}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              style={{
                padding: '6px 16px',
                background: 'var(--accent-primary)',
                color: '#fff',
                borderRadius: 'var(--radius-md)',
                fontSize: '12px',
                fontWeight: 600,
              }}
            >
              {submitting ? 'Submitting...' : 'Propose Experiment'}
            </button>
          </div>
        </form>
      )}

      {/* Action Notification Banners */}
      {actionSuccess && (
        <div
          role="status"
          style={{
            padding: '12px 16px',
            borderRadius: 'var(--radius-md)',
            background: 'var(--badge-green-bg)',
            color: 'var(--badge-green-text)',
            border: '1px solid var(--badge-green-border)',
            fontSize: '13px',
          }}
        >
          {actionSuccess}
        </div>
      )}

      {actionError && (
        <div
          role="alert"
          style={{
            padding: '12px 16px',
            borderRadius: 'var(--radius-md)',
            background: 'var(--badge-red-bg)',
            color: 'var(--badge-red-text)',
            border: '1px solid var(--badge-red-border)',
            fontSize: '13px',
          }}
        >
          {actionError}
        </div>
      )}

      {/* Experiment List */}
      {loading ? (
        <div style={{ textAlign: 'center', padding: '32px', color: 'var(--text-muted)' }}>
          Loading experiments...
        </div>
      ) : dataError ? (
        <div
          role="alert"
          style={{
            padding: '20px',
            background: 'var(--badge-red-bg)',
            color: 'var(--badge-red-text)',
            borderRadius: 'var(--radius-lg)',
            border: '1px solid var(--badge-red-border)',
            fontSize: '13px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <span>Error loading experiments: {dataError}</span>
          <button
            onClick={loadData}
            style={{
              padding: '6px 12px',
              borderRadius: 'var(--radius-md)',
              background: 'var(--bg-surface)',
              border: '1px solid var(--border-subtle)',
              fontSize: '12px',
              cursor: 'pointer',
            }}
          >
            Retry
          </button>
        </div>
      ) : experiments.length === 0 ? (
        <div style={{
          textAlign: 'center',
          padding: '40px',
          background: 'var(--bg-surface)',
          borderRadius: 'var(--radius-lg)',
          border: '1px solid var(--border-subtle)',
          color: 'var(--text-muted)',
          fontSize: '13px',
        }}>
          No controlled experiments proposed yet. Propose an experiment to test a hypothesis.
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {experiments.map((exp) => {
            const isApproved = exp.status === 'APPROVED';
            const isExecuted = exp.status === 'EXECUTED';
            const isProposed = exp.status === 'PROPOSED';

            const statusBg = isExecuted
              ? 'var(--badge-green-bg)'
              : isApproved
              ? 'var(--badge-blue-bg)'
              : 'var(--badge-amber-bg)';
            const statusColor = isExecuted
              ? 'var(--badge-green-text)'
              : isApproved
              ? 'var(--badge-blue-text)'
              : 'var(--badge-amber-text)';

            return (
              <div
                key={exp.experiment_id}
                style={{
                  padding: '16px 20px',
                  borderRadius: 'var(--radius-lg)',
                  background: 'var(--bg-surface)',
                  border: isExecuted
                    ? '2px solid var(--badge-green-border)'
                    : '1px solid var(--border-subtle)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '10px',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{
                      padding: '2px 8px',
                      borderRadius: '4px',
                      fontSize: '10px',
                      fontWeight: 700,
                      background: 'var(--badge-blue-bg)',
                      color: 'var(--badge-blue-text)',
                    }}>
                      {exp.risk_level}
                    </span>
                    <span style={{ fontWeight: 600, fontSize: '14px' }}>
                      {exp.objective}
                    </span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{
                      padding: '2px 8px',
                      borderRadius: '4px',
                      fontSize: '11px',
                      fontWeight: 700,
                      background: statusBg,
                      color: statusColor,
                    }}>
                      {exp.status}
                    </span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)' }}>
                      {exp.experiment_id}
                    </span>
                  </div>
                </div>

                <div style={{ display: 'flex', gap: '16px', fontSize: '12px', color: 'var(--text-muted)' }}>
                  <span>Target Asset: <strong>{exp.target_asset}</strong></span>
                  <span>Hypothesis: <strong>{exp.hypothesis_id}</strong></span>
                </div>

                <div style={{
                  background: 'var(--bg-surface-muted)',
                  padding: '10px 12px',
                  borderRadius: 'var(--radius-sm)',
                  fontSize: '12px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '4px',
                }}>
                  <div><strong>Expected Secure:</strong> {exp.expected_secure_result}</div>
                  <div><strong>Expected Vulnerable:</strong> {exp.expected_vulnerable_result}</div>
                  <div><strong>Falsification Condition:</strong> {exp.falsification_condition}</div>
                  <div><strong>Negative Control:</strong> {exp.negative_control}</div>
                </div>

                {/* Experiment Action Controls */}
                <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', borderTop: '1px solid var(--border-subtle)', paddingTop: '10px' }}>
                  {isProposed && (
                    <button
                      onClick={() => handleApprove(exp.experiment_id)}
                      disabled={approvingId === exp.experiment_id}
                      style={{
                        padding: '6px 14px',
                        borderRadius: 'var(--radius-sm)',
                        background: 'var(--accent-primary)',
                        color: '#fff',
                        fontSize: '12px',
                        fontWeight: 600,
                        cursor: approvingId === exp.experiment_id ? 'not-allowed' : 'pointer',
                        opacity: approvingId === exp.experiment_id ? 0.7 : 1,
                      }}
                    >
                      {approvingId === exp.experiment_id ? 'Authorizing...' : 'Approve Experiment Execution'}
                    </button>
                  )}
                  {isApproved && (
                    <button
                      onClick={() => setResultImportExp(exp)}
                      style={{
                        padding: '6px 14px',
                        borderRadius: 'var(--radius-sm)',
                        background: 'var(--badge-blue-text)',
                        color: '#fff',
                        fontSize: '12px',
                        fontWeight: 600,
                        cursor: 'pointer',
                      }}
                    >
                      + Import Execution Result
                    </button>
                  )}
                  {isExecuted && (
                    <span style={{ fontSize: '11px', color: 'var(--badge-green-text)', fontWeight: 600 }}>
                      ✓ Executed & Invariant Validated
                    </span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Result Import Modal */}
      {resultImportExp && (
        <div style={{
          position: 'fixed',
          inset: 0,
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
            maxWidth: '92vw',
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
                <h4 style={{ fontSize: '15px', fontWeight: 600 }}>Import Experiment Execution Result</h4>
                <p style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                  Experiment: {resultImportExp.experiment_id} ({resultImportExp.target_asset})
                </p>
              </div>
              <button
                onClick={() => setResultImportExp(null)}
                style={{ fontSize: '16px', background: 'none', border: 'none', cursor: 'pointer' }}
                aria-label="Close dialog"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleImportResult} style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div style={{
                padding: '8px 12px',
                borderRadius: 'var(--radius-sm)',
                background: 'var(--bg-surface-muted)',
                border: '1px solid var(--border-subtle)',
                fontSize: '11.5px',
                color: 'var(--text-secondary)',
              }}>
                <strong style={{ color: 'var(--text-primary)' }}>Audit Provenance:</strong> Result execution will be authoritatively attributed to your active authenticated session.
              </div>

              <div>
                <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)' }}>
                  Structured Execution Result (JSON) *
                </label>
                <textarea
                  rows={6}
                  value={resultPayloadText}
                  onChange={(e) => setResultPayloadText(e.target.value)}
                  required
                  style={{
                    width: '100%',
                    padding: '8px',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '12px',
                    marginTop: '4px',
                    background: 'var(--bg-surface)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-sm)',
                  }}
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
                <button
                  type="button"
                  onClick={() => setResultImportExp(null)}
                  style={{ padding: '6px 12px', fontSize: '12px' }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={importingResult}
                  style={{
                    padding: '8px 16px',
                    borderRadius: 'var(--radius-md)',
                    background: 'var(--badge-green-text)',
                    color: '#fff',
                    fontSize: '12px',
                    fontWeight: 600,
                    cursor: importingResult ? 'not-allowed' : 'pointer',
                  }}
                >
                  {importingResult ? 'Submitting...' : 'Confirm Result Import'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
