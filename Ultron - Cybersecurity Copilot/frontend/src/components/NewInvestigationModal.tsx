import React, { useState } from 'react';

interface NewInvestigationModalProps {
  onCreate: (name: string, targetHost: string) => Promise<void>;
  onClose: () => void;
}

export const NewInvestigationModal: React.FC<NewInvestigationModalProps> = ({ onCreate, onClose }) => {
  const [name, setName] = useState('');
  const [targetHost, setTargetHost] = useState('api.target.local');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim() || !targetHost.trim()) return;
    setLoading(true);
    setError(null);
    try {
      await onCreate(name.trim(), targetHost.trim());
      onClose();
    } catch (err: any) {
      setError(err.message || 'Failed to create investigation');
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
        role="dialog"
        aria-modal="true"
        aria-labelledby="new-investigation-title"
        className="card-base"
        style={{
          width: '460px',
          maxWidth: '90vw',
          padding: '24px 28px',
          backgroundColor: 'var(--bg-surface)',
          borderRadius: 'var(--radius-xl)',
          boxShadow: 'var(--shadow-elevated)',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <div>
            <span style={{ fontSize: '11px', fontWeight: 700, color: 'var(--accent-primary)', letterSpacing: '0.06em' }}>
              ULTRON TARGET INVESTIGATION
            </span>
            <h3 id="new-investigation-title" style={{ fontSize: '18px', fontWeight: 600, color: 'var(--text-primary)', marginTop: '2px' }}>
              Create Investigation
            </h3>
          </div>
          <button
            onClick={onClose}
            aria-label="Close dialog"
            style={{ fontSize: '18px', color: 'var(--text-muted)', padding: '4px 8px', borderRadius: '4px' }}
          >
            ✕
          </button>
        </div>

        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: '14px' }}>
            <label style={{ display: 'block', fontSize: '12.5px', fontWeight: 500, color: 'var(--text-primary)', marginBottom: '6px' }}>
              Investigation Name:
            </label>
            <input
              type="text"
              placeholder="e.g. Acme Billing BOLA Audit"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
              style={{ width: '100%', padding: '8px 12px', fontSize: '13.5px' }}
            />
          </div>

          <div style={{ marginBottom: '18px' }}>
            <label style={{ display: 'block', fontSize: '12.5px', fontWeight: 500, color: 'var(--text-primary)', marginBottom: '6px' }}>
              Target Host:
            </label>
            <input
              type="text"
              placeholder="e.g. api.target.local"
              value={targetHost}
              onChange={(e) => setTargetHost(e.target.value)}
              required
              style={{ width: '100%', padding: '8px 12px', fontSize: '13.5px', fontFamily: 'var(--font-mono)' }}
            />
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
              disabled={loading || !name.trim()}
              style={{
                padding: '8px 20px',
                fontSize: '13px',
                fontWeight: 500,
                color: '#FFFFFF',
                backgroundColor: 'var(--accent-primary)',
                borderRadius: 'var(--radius-md)',
                opacity: loading || !name.trim() ? 0.6 : 1,
              }}
            >
              {loading ? 'Initializing...' : 'Create Run'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
