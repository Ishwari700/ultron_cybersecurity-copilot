import React, { useState } from 'react';
import type { ExperimentObject } from '../../types';
import { ApprovalModal } from './ApprovalModal';
import { ExecutionTimeline } from './ExecutionTimeline';
import { ObservationCard } from './ObservationCard';

interface ExperimentCardProps {
  data: ExperimentObject;
  onValidate: (experimentId: string) => Promise<any>;
  onApprove: (experimentId: string, actor: string, acknowledged: boolean, notes: string) => Promise<any>;
  onReject: (experimentId: string) => Promise<any>;
  onExecute: (experimentId: string) => Promise<any>;
}

export const ExperimentCard: React.FC<ExperimentCardProps> = ({
  data,
  onValidate,
  onApprove,
  onReject,
  onExecute,
}) => {
  const [showApprovalModal, setShowApprovalModal] = useState(false);
  const [validating, setValidating] = useState(false);
  const [validationResult, setValidationResult] = useState<any | null>(null);
  const [executing, setExecuting] = useState(false);
  const [executionOutcome, setExecutionOutcome] = useState<any | null>(null);
  const [error, setError] = useState<string | null>(null);

  const isApproved = data.status === 'APPROVED';
  const isExecuted = data.status === 'EXECUTED' || executionOutcome?.status === 'EXECUTED';
  const isStateChanging = data.safety_level === 'STATE_CHANGING_REQUIRES_APPROVAL';

  const handleValidate = async () => {
    setValidating(true);
    setError(null);
    try {
      const res = await onValidate(data.id);
      setValidationResult(res);
    } catch (err: any) {
      setError(err.message || 'Validation failed');
    } finally {
      setValidating(false);
    }
  };

  const handleExecute = async () => {
    setExecuting(true);
    setError(null);
    try {
      const outcome = await onExecute(data.id);
      setExecutionOutcome(outcome);
    } catch (err: any) {
      setError(err.message || 'Execution failed');
    } finally {
      setExecuting(false);
    }
  };

  return (
    <div className="card-base" style={{ padding: '18px 22px', margin: '14px 0', borderLeft: '3px solid #1F1E1D' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-secondary)', letterSpacing: '0.04em' }}>
            EXPERIMENT PROPOSAL
          </span>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '13px', fontWeight: 600 }}>{data.id}</span>
          <span className="badge badge-amber">{data.category}</span>
        </div>
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <span className={`badge ${isExecuted ? 'badge-green' : isApproved ? 'badge-blue' : 'badge-amber'}`}>
            {isExecuted ? 'EXECUTED' : data.status}
          </span>
          <span className="badge badge-muted">{data.safety_level}</span>
        </div>
      </div>

      <p style={{ fontSize: '14.5px', color: 'var(--text-primary)', fontWeight: 500, marginBottom: '12px', lineHeight: 1.5 }}>
        {data.objective}
      </p>

      <div style={{ backgroundColor: 'var(--bg-app)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-md)', padding: '12px 14px', marginBottom: '14px', fontSize: '12.5px' }}>
        <div style={{ display: 'grid', gridTemplateColumns: '130px 1fr', gap: '6px', marginBottom: '8px' }}>
          <span style={{ color: 'var(--text-secondary)' }}>Action Predicate:</span>
          <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>{data.action}</span>
          <span style={{ color: 'var(--text-secondary)' }}>Target Destination:</span>
          <span style={{ fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>{data.target}</span>
          <span style={{ color: 'var(--text-secondary)' }}>Scope Policy:</span>
          <span><span className="badge badge-green">{data.scope}</span></span>
        </div>

        <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: '8px', marginTop: '8px' }}>
          <div style={{ color: 'var(--text-secondary)', fontSize: '11px', fontWeight: 600, marginBottom: '4px' }}>
            EXPECTED DISCRIMINATIVE OBSERVATIONS:
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <div>
              <span style={{ color: '#2D6A4F', fontWeight: 500 }}>Supporting: </span>
              <span>{data.supporting_observation}</span>
            </div>
            <div>
              <span style={{ color: '#9E2A2B', fontWeight: 500 }}>Falsifying: </span>
              <span>{data.contradicting_observation}</span>
            </div>
          </div>
        </div>
      </div>

      {validationResult && (
        <div style={{ padding: '8px 12px', backgroundColor: validationResult.valid ? 'var(--badge-green-bg)' : 'var(--badge-red-bg)', color: validationResult.valid ? 'var(--badge-green-text)' : 'var(--badge-red-text)', borderRadius: 'var(--radius-sm)', fontSize: '12.5px', marginBottom: '14px' }}>
          <strong>Deterministic Validation: {validationResult.valid ? 'PASS' : 'FAIL'}</strong>
          <span style={{ marginLeft: '8px' }}>
            Grounding: {validationResult.grounding_passed ? '✓' : '✕'} | Polarity: {validationResult.polarity_passed ? '✓' : '✕'} | Scope: {validationResult.scope_passed ? '✓' : '✕'}
          </span>
        </div>
      )}

      {error && (
        <div style={{ padding: '8px 12px', backgroundColor: 'var(--badge-red-bg)', color: 'var(--badge-red-text)', borderRadius: 'var(--radius-sm)', fontSize: '12.5px', marginBottom: '14px' }}>
          {error}
        </div>
      )}

      {/* Action Buttons */}
      {!isExecuted && (
        <div style={{ display: 'flex', gap: '10px', alignItems: 'center', marginTop: '10px' }}>
          <button
            onClick={handleValidate}
            disabled={validating}
            style={{
              padding: '6px 14px',
              fontSize: '12.5px',
              backgroundColor: 'var(--bg-surface-muted)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-md)',
              fontWeight: 500,
            }}
          >
            {validating ? 'Validating...' : 'Validate Proposal'}
          </button>

          {isStateChanging && !isApproved && (
            <button
              onClick={() => setShowApprovalModal(true)}
              style={{
                padding: '6px 16px',
                fontSize: '12.5px',
                backgroundColor: 'var(--accent-primary)',
                color: '#FFFFFF',
                borderRadius: 'var(--radius-md)',
                fontWeight: 500,
              }}
            >
              Request Human Approval
            </button>
          )}

          {(!isStateChanging || isApproved) && (
            <button
              onClick={handleExecute}
              disabled={executing}
              style={{
                padding: '6px 18px',
                fontSize: '12.5px',
                backgroundColor: '#2D6A4F',
                color: '#FFFFFF',
                borderRadius: 'var(--radius-md)',
                fontWeight: 500,
                opacity: executing ? 0.7 : 1,
              }}
            >
              {executing ? 'Executing via Engine...' : 'Execute Safe Local Simulation'}
            </button>
          )}

          {!isApproved && (
            <button
              onClick={() => onReject(data.id)}
              style={{
                padding: '6px 12px',
                fontSize: '12.5px',
                color: 'var(--text-muted)',
                borderRadius: 'var(--radius-md)',
              }}
            >
              Reject
            </button>
          )}
        </div>
      )}

      {/* Execution Timeline and Observation Outcome */}
      {executionOutcome?.timeline && (
        <ExecutionTimeline steps={executionOutcome.timeline} status={executionOutcome.status} />
      )}

      {executionOutcome?.observation && (
        <ObservationCard data={executionOutcome.observation} />
      )}

      {showApprovalModal && (
        <ApprovalModal
          experimentId={data.id}
          category={data.category}
          action={data.action}
          target={data.target}
          safetyLevel={data.safety_level}
          onApprove={async (actor, ack, notes) => {
            await onApprove(data.id, actor, ack, notes);
          }}
          onClose={() => setShowApprovalModal(false)}
        />
      )}
    </div>
  );
};
