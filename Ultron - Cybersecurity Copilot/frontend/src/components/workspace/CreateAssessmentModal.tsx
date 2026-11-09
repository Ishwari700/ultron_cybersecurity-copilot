import React, { useState } from 'react';
import { createAssessment } from '../../api';

interface CreateAssessmentModalProps {
  onCreated: (assessmentId: string) => void;
  onClose: () => void;
}

export const CreateAssessmentModal: React.FC<CreateAssessmentModalProps> = ({
  onCreated,
  onClose,
}) => {
  const [organization, setOrganization] = useState('');
  const [assessmentName, setAssessmentName] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!organization.trim() || !assessmentName.trim()) {
      setError('Both organization and assessment name are required.');
      return;
    }

    setSubmitting(true);
    setError(null);
    try {
      const res = await createAssessment(organization.trim(), assessmentName.trim());
      if (res.assessment && res.assessment.assessment_id) {
        onCreated(res.assessment.assessment_id);
        onClose();
      } else {
        throw new Error('Unexpected server response format');
      }
    } catch (err: any) {
      setError(err.message || 'Failed to create assessment');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      backgroundColor: 'rgba(0, 0, 0, 0.4)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 1100,
    }}>
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="create-assessment-title"
        style={{
          backgroundColor: 'var(--bg-surface)',
          borderRadius: 'var(--radius-lg)',
          width: '480px',
          boxShadow: 'var(--shadow-elevated)',
          border: '1px solid var(--border-subtle)',
          overflow: 'hidden',
        }}
      >
        <div style={{
          padding: '16px 20px',
          borderBottom: '1px solid var(--border-subtle)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
        }}>
          <div>
            <h3 id="create-assessment-title" style={{ fontSize: '16px', fontWeight: 600 }}>Create Security Assessment</h3>
            <p style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
              Initialize an isolated assessment container under strict governance
            </p>
          </div>
          <button onClick={onClose} aria-label="Close dialog" style={{ fontSize: '18px', color: 'var(--text-muted)', background: 'transparent', border: 'none', cursor: 'pointer' }}>
            ✕
          </button>
        </div>

        <form onSubmit={handleSubmit} style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {error && (
            <div style={{
              padding: '8px 12px',
              borderRadius: 'var(--radius-sm)',
              background: 'var(--badge-red-bg)',
              color: 'var(--badge-red-text)',
              fontSize: '12px',
              border: '1px solid var(--badge-red-border)',
            }}>
              {error}
            </div>
          )}

          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)' }}>
              Organization / Target Company *
            </label>
            <input
              type="text"
              placeholder="e.g. Acme Corp, HackerOne Target Inc."
              value={organization}
              onChange={(e) => setOrganization(e.target.value)}
              required
              style={{ padding: '8px 12px', fontSize: '13px' }}
            />
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)' }}>
              Assessment Program Name *
            </label>
            <input
              type="text"
              placeholder="e.g. Q4 Web & API Security Review"
              value={assessmentName}
              onChange={(e) => setAssessmentName(e.target.value)}
              required
              style={{ padding: '8px 12px', fontSize: '13px' }}
            />
          </div>

          <div style={{
            padding: '10px 12px',
            borderRadius: 'var(--radius-sm)',
            background: 'var(--bg-surface-muted)',
            border: '1px solid var(--border-subtle)',
            fontSize: '11.5px',
            color: 'var(--text-secondary)',
          }}>
            <strong style={{ color: 'var(--text-primary)' }}>Identity & Audit Governance:</strong> The authenticated session identity is authoritatively recorded as the creator in the immutable audit log. No client-selected actor is permitted.
          </div>

          <div style={{
            display: 'flex',
            justifyContent: 'flex-end',
            gap: '10px',
            marginTop: '8px',
            borderTop: '1px solid var(--border-subtle)',
            paddingTop: '16px',
          }}>
            <button
              type="button"
              onClick={onClose}
              style={{
                padding: '8px 16px',
                borderRadius: 'var(--radius-md)',
                fontSize: '13px',
                border: '1px solid var(--border-subtle)',
                background: 'var(--bg-surface)',
              }}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              style={{
                padding: '8px 18px',
                borderRadius: 'var(--radius-md)',
                fontSize: '13px',
                fontWeight: 600,
                background: 'var(--accent-primary)',
                color: 'var(--text-inverse)',
                opacity: submitting ? 0.7 : 1,
              }}
            >
              {submitting ? 'Creating...' : 'Initialize Assessment'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
