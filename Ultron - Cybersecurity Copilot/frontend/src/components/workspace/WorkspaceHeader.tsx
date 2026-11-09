import React from 'react';
import type { AssessmentOverview } from '../../types';

interface WorkspaceHeaderProps {
  overview: AssessmentOverview | null;
  onOpenSwitcher: () => void;
  onOpenSearch: () => void;
  onRefresh: () => void;
}

export const WorkspaceHeader: React.FC<WorkspaceHeaderProps> = ({
  overview,
  onOpenSwitcher,
  onOpenSearch,
  onRefresh,
}) => {
  if (!overview) {
    return (
      <header style={{
        padding: '16px 24px',
        borderBottom: '1px solid var(--border-subtle)',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        background: 'var(--bg-surface)'
      }}>
        <div style={{ fontWeight: 600, fontSize: '16px' }}>Security Assessment Workspace</div>
        <button
          onClick={onOpenSwitcher}
          style={{
            padding: '6px 14px',
            background: 'var(--accent-primary)',
            color: 'var(--text-inverse)',
            borderRadius: 'var(--radius-md)',
            fontSize: '13px',
            fontWeight: 500,
          }}
        >
          Select Assessment
        </button>
      </header>
    );
  }

  const isAuthorized = overview.authorization_status === 'AUTHORIZED';
  const isScopeDefined = overview.workflow_status.scope_defined;

  return (
    <header style={{
      padding: '14px 24px',
      borderBottom: '1px solid var(--border-subtle)',
      background: 'var(--bg-surface)',
      display: 'flex',
      flexDirection: 'column',
      gap: '10px',
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <button
            onClick={onOpenSwitcher}
            title="Switch Assessment"
            style={{
              padding: '6px 12px',
              borderRadius: 'var(--radius-md)',
              border: '1px solid var(--border-strong)',
              background: 'var(--bg-surface-muted)',
              fontSize: '13px',
              fontWeight: 600,
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
            }}
          >
            <span>{overview.assessment_name}</span>
            <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>({overview.organization})</span>
            <span style={{ fontSize: '10px' }}>▼</span>
          </button>

          <span
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: '12px',
              color: 'var(--text-muted)',
              background: 'var(--bg-surface-muted)',
              padding: '4px 8px',
              borderRadius: 'var(--radius-sm)',
            }}
          >
            {overview.assessment_id}
          </span>

          {/* Lifecycle state badge */}
          <span
            style={{
              padding: '3px 8px',
              borderRadius: 'var(--radius-sm)',
              fontSize: '11px',
              fontWeight: 600,
              letterSpacing: '0.04em',
              background: overview.state === 'ASSESSMENT_ACTIVE' ? 'var(--badge-green-bg)' : 'var(--badge-amber-bg)',
              color: overview.state === 'ASSESSMENT_ACTIVE' ? 'var(--badge-green-text)' : 'var(--badge-amber-text)',
              border: `1px solid ${overview.state === 'ASSESSMENT_ACTIVE' ? 'var(--badge-green-border)' : 'var(--badge-amber-border)'}`,
            }}
          >
            {overview.state}
          </span>

          {/* Authorization status badge */}
          <span
            style={{
              padding: '3px 8px',
              borderRadius: 'var(--radius-sm)',
              fontSize: '11px',
              fontWeight: 600,
              background: isAuthorized ? 'var(--badge-green-bg)' : 'var(--badge-red-bg)',
              color: isAuthorized ? 'var(--badge-green-text)' : 'var(--badge-red-text)',
              border: `1px solid ${isAuthorized ? 'var(--badge-green-border)' : 'var(--badge-red-border)'}`,
            }}
          >
            AUTH: {overview.authorization_status}
          </span>

          {/* Scope status badge */}
          <span
            style={{
              padding: '3px 8px',
              borderRadius: 'var(--radius-sm)',
              fontSize: '11px',
              fontWeight: 600,
              background: isScopeDefined ? 'var(--badge-blue-bg)' : 'var(--badge-amber-bg)',
              color: isScopeDefined ? 'var(--badge-blue-text)' : 'var(--badge-amber-text)',
              border: `1px solid ${isScopeDefined ? 'var(--badge-blue-border)' : 'var(--badge-amber-border)'}`,
            }}
          >
            SCOPE: {overview.in_scope_count} IN / {overview.out_of_scope_count} OUT
          </span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <button
            onClick={onOpenSearch}
            title="Global Workspace Search"
            style={{
              padding: '6px 12px',
              borderRadius: 'var(--radius-md)',
              border: '1px solid var(--border-subtle)',
              background: 'var(--bg-surface)',
              fontSize: '12px',
              color: 'var(--text-secondary)',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
            }}
          >
            <span>Search...</span>
            <kbd style={{ fontSize: '10px', background: 'var(--bg-surface-muted)', padding: '2px 4px', borderRadius: '4px' }}>Ctrl+K</kbd>
          </button>

          <button
            onClick={onRefresh}
            title="Refresh assessment metrics"
            style={{
              padding: '6px 10px',
              borderRadius: 'var(--radius-md)',
              border: '1px solid var(--border-subtle)',
              background: 'var(--bg-surface)',
              fontSize: '12px',
              color: 'var(--text-secondary)',
            }}
          >
            Refresh
          </button>
        </div>
      </div>

      {/* Progress Milestone Subheader */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        fontSize: '12px',
        color: 'var(--text-secondary)',
        background: 'var(--bg-surface-muted)',
        padding: '6px 12px',
        borderRadius: 'var(--radius-sm)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>Active Milestone:</span>
          <span style={{
            fontFamily: 'var(--font-mono)',
            fontSize: '11px',
            background: 'var(--bg-surface)',
            padding: '2px 6px',
            borderRadius: '4px',
            border: '1px solid var(--border-subtle)',
          }}>
            {overview.workflow_status.current_milestone}
          </span>
        </div>
        <div style={{ display: 'flex', gap: '16px' }}>
          <span>Assets: <strong>{overview.asset_count}</strong></span>
          <span>Observations: <strong>{overview.observation_count}</strong></span>
          <span>Hypotheses: <strong>{overview.hypothesis_count}</strong></span>
          <span>Verified Findings: <strong>{overview.verified_finding_count} / {overview.finding_count}</strong></span>
        </div>
      </div>
    </header>
  );
};
