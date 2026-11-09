import React, { useState } from 'react';

interface ApprovalModalProps {
  experimentId: string;
  category: string;
  action: string;
  target: string;
  safetyLevel: string;
  onApprove: (actor: string, acknowledged: boolean, notes: string) => Promise<void>;
  onClose: () => void;
}

export const ApprovalModal: React.FC<ApprovalModalProps> = ({
  experimentId,
  category,
  action,
  target,
  safetyLevel,
  onApprove,
  onClose,
}) => {
  const [acknowledged, setAcknowledged] = useState(false);
  const [notes, setNotes] = useState('Human verified: isolated test account parameter substitution.');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!acknowledged) {
      setError('You must acknowledge safety requirements for STATE_CHANGING proposals.');
      return;
    }
    setLoading(true);
    setError(null);
    try {
      await onApprove('', acknowledged, notes);
      onClose();
    } catch (err: any) {
      setError(err.message || 'Failed to register approval');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        backgroundColor: 'rgba(31, 30, 29, 0.45)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000,
        backdropFilter: 'blur(2px)',
      }}
    >
      <div
        className="card-base"
        style={{
          width: '540px',
          maxWidth: '92vw',
          padding: '24px 28px',
          boxShadow: 'var(--shadow-elevated)',
          backgroundColor: 'var(--bg-surface)',
          borderRadius: 'var(--radius-xl)',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <div>
            <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-secondary)', letterSpacing: '0.04em' }}>
              HUMAN APPROVAL BOUNDARY
            </span>
            <h3 style={{ fontSize: '18px', fontWeight: 600, color: 'var(--text-primary)', marginTop: '2px' }}>
              Authorize Experiment Execution
            </h3>
          </div>
          <button
            onClick={onClose}
            style={{ fontSize: '18px', color: 'var(--text-muted)', padding: '4px 8px', borderRadius: '4px' }}
          >
            ✕
          </button>
        </div>

        <p style={{ fontSize: '13.5px', color: 'var(--text-secondary)', marginBottom: '16px', lineHeight: 1.5 }}>
          Execution against this endpoint performs state mutations. Server-side policies strictly require an explicit,
          cryptographically bound Human Approval before outbound request dispatch.
        </p>

        <div style={{ backgroundColor: 'var(--bg-app)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-md)', padding: '14px', marginBottom: '18px', fontSize: '12.5px' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '120px 1fr', gap: '6px' }}>
            <span style={{ color: 'var(--text-secondary)' }}>Experiment ID:</span>
            <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>{experimentId}</span>
            <span style={{ color: 'var(--text-secondary)' }}>Category:</span>
            <span>{category}</span>
            <span style={{ color: 'var(--text-secondary)' }}>Action Predicate:</span>
            <span style={{ fontFamily: 'var(--font-mono)' }}>{action}</span>
            <span style={{ color: 'var(--text-secondary)' }}>Target Destination:</span>
            <span style={{ fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>{target}</span>
            <span style={{ color: 'var(--text-secondary)' }}>Safety Level:</span>
            <span><span className="badge badge-amber">{safetyLevel}</span></span>
          </div>
        </div>

        <form onSubmit={handleSubmit}>
          <div style={{
            marginBottom: '14px',
            padding: '10px 12px',
            borderRadius: 'var(--radius-sm)',
            background: 'var(--bg-app)',
            border: '1px solid var(--border-subtle)',
            fontSize: '12px',
            color: 'var(--text-secondary)',
          }}>
            <strong style={{ color: 'var(--text-primary)' }}>Approval Authority:</strong> Cryptographically logged and authoritatively bound to your active authenticated session.
          </div>

          <div style={{ marginBottom: '16px' }}>
            <label style={{ display: 'block', fontSize: '12.5px', fontWeight: 500, color: 'var(--text-primary)', marginBottom: '6px' }}>
              Verification Notes:
            </label>
            <input
              type="text"
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              style={{ width: '100%', padding: '8px 12px', fontSize: '13px' }}
            />
          </div>

          <div style={{ marginBottom: '20px', display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
            <input
              type="checkbox"
              id="safety-ack"
              checked={acknowledged}
              onChange={(e) => setAcknowledged(e.target.checked)}
              style={{ marginTop: '3px', cursor: 'pointer' }}
            />
            <label htmlFor="safety-ack" style={{ fontSize: '12.5px', color: 'var(--text-primary)', lineHeight: 1.4, cursor: 'pointer' }}>
              <strong>Safety Acknowledgment</strong>: I verify that this test target has been reviewed, isolation parameters are bounded, and state-changing side effects are authorized.
            </label>
          </div>

          {error && (
            <div style={{ padding: '8px 12px', backgroundColor: 'var(--badge-red-bg)', color: 'var(--badge-red-text)', borderRadius: 'var(--radius-sm)', fontSize: '12.5px', marginBottom: '16px' }}>
              {error}
            </div>
          )}

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
            <button
              type="button"
              onClick={onClose}
              style={{
                padding: '8px 16px',
                fontSize: '13px',
                color: 'var(--text-secondary)',
                backgroundColor: 'var(--bg-surface-muted)',
                borderRadius: 'var(--radius-md)',
              }}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              style={{
                padding: '8px 20px',
                fontSize: '13px',
                fontWeight: 500,
                color: '#FFFFFF',
                backgroundColor: 'var(--accent-primary)',
                borderRadius: 'var(--radius-md)',
                opacity: loading ? 0.7 : 1,
              }}
            >
              {loading ? 'Binding Digest...' : 'Authorize & Sign Descriptor'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
