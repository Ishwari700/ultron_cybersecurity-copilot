import React, { useState } from 'react';
import type { AssessmentSummary } from '../../types';

interface AssessmentSwitcherModalProps {
  assessments: AssessmentSummary[];
  activeAssessmentId: string | null;
  onSelect: (assessmentId: string) => void;
  onOpenCreate: () => void;
  onClose: () => void;
}

export const AssessmentSwitcherModal: React.FC<AssessmentSwitcherModalProps> = ({
  assessments,
  activeAssessmentId,
  onSelect,
  onOpenCreate,
  onClose,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [stateFilter, setStateFilter] = useState<string>('ALL');

  const filtered = assessments.filter((a) => {
    const matchesSearch =
      a.assessment_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      a.organization.toLowerCase().includes(searchTerm.toLowerCase()) ||
      a.assessment_id.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesState = stateFilter === 'ALL' || a.state === stateFilter;
    return matchesSearch && matchesState;
  });

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
      zIndex: 1000,
    }}>
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="switch-assessment-title"
        style={{
          backgroundColor: 'var(--bg-surface)',
          borderRadius: 'var(--radius-lg)',
          width: '640px',
          maxHeight: '80vh',
          display: 'flex',
          flexDirection: 'column',
          boxShadow: 'var(--shadow-elevated)',
          border: '1px solid var(--border-subtle)',
          overflow: 'hidden',
        }}
      >
        {/* Header */}
        <div style={{
          padding: '16px 20px',
          borderBottom: '1px solid var(--border-subtle)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
        }}>
          <div>
            <h3 id="switch-assessment-title" style={{ fontSize: '16px', fontWeight: 600 }}>Switch Security Assessment</h3>
            <p style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
              Select an authorized assessment workspace or initiate a new program
            </p>
          </div>
          <button
            onClick={onClose}
            aria-label="Close dialog"
            style={{ fontSize: '18px', color: 'var(--text-muted)', padding: '4px', background: 'transparent', border: 'none', cursor: 'pointer' }}
          >
            ✕
          </button>
        </div>

        {/* Toolbar */}
        <div style={{
          padding: '12px 20px',
          borderBottom: '1px solid var(--border-subtle)',
          display: 'flex',
          gap: '12px',
          background: 'var(--bg-surface-muted)',
        }}>
          <input
            type="text"
            placeholder="Search by name, organization, ID..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{
              flex: 1,
              padding: '6px 12px',
              fontSize: '13px',
            }}
          />
          <select
            value={stateFilter}
            onChange={(e) => setStateFilter(e.target.value)}
            style={{
              padding: '6px 10px',
              fontSize: '13px',
              borderRadius: 'var(--radius-md)',
              border: '1px solid var(--border-subtle)',
              background: 'var(--bg-surface)',
            }}
          >
            <option value="ALL">All States</option>
            <option value="DRAFT">DRAFT</option>
            <option value="AUTHORIZED">AUTHORIZED</option>
            <option value="SCOPE_DEFINED">SCOPE_DEFINED</option>
            <option value="ASSESSMENT_ACTIVE">ASSESSMENT_ACTIVE</option>
            <option value="COMPLETED">COMPLETED</option>
            <option value="ARCHIVED">ARCHIVED</option>
          </select>
          <button
            onClick={onOpenCreate}
            style={{
              padding: '6px 14px',
              background: 'var(--accent-primary)',
              color: 'var(--text-inverse)',
              borderRadius: 'var(--radius-md)',
              fontSize: '13px',
              fontWeight: 500,
              whiteSpace: 'nowrap',
            }}
          >
            + New Assessment
          </button>
        </div>

        {/* Assessment List */}
        <div style={{
          flex: 1,
          overflowY: 'auto',
          padding: '12px 20px',
          display: 'flex',
          flexDirection: 'column',
          gap: '8px',
        }}>
          {filtered.length === 0 ? (
            <div style={{
              textAlign: 'center',
              padding: '40px 20px',
              color: 'var(--text-muted)',
              fontSize: '13px',
            }}>
              No assessments found matching criteria.
            </div>
          ) : (
            filtered.map((a) => {
              const isSelected = a.assessment_id === activeAssessmentId;
              return (
                <div
                  key={a.assessment_id}
                  onClick={() => {
                    onSelect(a.assessment_id);
                    onClose();
                  }}
                  style={{
                    padding: '12px 16px',
                    borderRadius: 'var(--radius-md)',
                    border: isSelected
                      ? '2px solid var(--border-focus)'
                      : '1px solid var(--border-subtle)',
                    background: isSelected ? 'var(--bg-surface-muted)' : 'var(--bg-surface)',
                    cursor: 'pointer',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '6px',
                    transition: 'all 0.15s ease',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span style={{ fontWeight: 600, fontSize: '14px' }}>{a.assessment_name}</span>
                      <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>({a.organization})</span>
                      {isSelected && (
                        <span style={{
                          fontSize: '10px',
                          background: 'var(--accent-primary)',
                          color: '#fff',
                          padding: '2px 6px',
                          borderRadius: '4px',
                        }}>
                          ACTIVE
                        </span>
                      )}
                    </div>
                    <span style={{
                      fontFamily: 'var(--font-mono)',
                      fontSize: '11px',
                      color: 'var(--text-muted)',
                    }}>
                      {a.assessment_id}
                    </span>
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '12px' }}>
                    <div style={{ display: 'flex', gap: '6px' }}>
                      <span style={{
                        padding: '2px 6px',
                        borderRadius: '4px',
                        fontSize: '10px',
                        fontWeight: 600,
                        background: a.state === 'ASSESSMENT_ACTIVE' ? 'var(--badge-green-bg)' : 'var(--badge-amber-bg)',
                        color: a.state === 'ASSESSMENT_ACTIVE' ? 'var(--badge-green-text)' : 'var(--badge-amber-text)',
                      }}>
                        {a.state}
                      </span>
                      <span style={{
                        padding: '2px 6px',
                        borderRadius: '4px',
                        fontSize: '10px',
                        fontWeight: 600,
                        background: a.authorization_status === 'AUTHORIZED' ? 'var(--badge-green-bg)' : 'var(--badge-red-bg)',
                        color: a.authorization_status === 'AUTHORIZED' ? 'var(--badge-green-text)' : 'var(--badge-red-text)',
                      }}>
                        AUTH: {a.authorization_status}
                      </span>
                    </div>

                    <div style={{ display: 'flex', gap: '12px', color: 'var(--text-secondary)' }}>
                      <span>Assets: <strong>{a.asset_count}</strong></span>
                      <span>Obs: <strong>{a.observation_count}</strong></span>
                      <span>Findings: <strong>{a.verified_finding_count}/{a.finding_count}</strong></span>
                    </div>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
};
