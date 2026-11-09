import React, { useState, useEffect } from 'react';

interface InvestigationHeaderProps {
  name: string;
  targetHost: string;
  scopeStatus: string;
  isDemo?: boolean;
  evidenceCount?: number;
  hypothesisCount?: number;
  activeModel?: string;
  onOpenDrawer: (tab: string) => void;
  onOpenImport?: () => void;
  onOpenAddObservation?: () => void;
  onRename?: (newName: string) => void;
  onDelete?: () => void;
}

export const InvestigationHeader: React.FC<InvestigationHeaderProps> = ({
  name,
  targetHost,
  scopeStatus,
  isDemo,
  onOpenDrawer,
  onOpenImport,
  onOpenAddObservation,
  onRename,
  onDelete,
}) => {
  const [isEditing, setIsEditing] = useState(false);
  const [editName, setEditName] = useState(name);

  useEffect(() => {
    setEditName(name);
  }, [name]);

  const handleSaveName = () => {
    setIsEditing(false);
    if (editName.trim() && editName.trim() !== name && onRename) {
      onRename(editName.trim());
    }
  };

  return (
    <header
      style={{
        height: '52px',
        backgroundColor: 'var(--bg-app)',
        borderBottom: '1px solid var(--border-subtle)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '0 28px',
        flexShrink: 0,
        userSelect: 'none',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        {isEditing ? (
          <input
            value={editName}
            onChange={(e) => setEditName(e.target.value)}
            onBlur={handleSaveName}
            onKeyDown={(e) => {
              if (e.key === 'Enter') handleSaveName();
              else if (e.key === 'Escape') {
                setEditName(name);
                setIsEditing(false);
              }
            }}
            autoFocus
            style={{
              fontSize: '14.5px',
              fontWeight: 500,
              padding: '2px 8px',
              borderRadius: 'var(--radius-sm)',
              border: '1px solid var(--border-focus)',
              backgroundColor: 'var(--bg-surface)',
              color: 'var(--text-primary)',
            }}
          />
        ) : (
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <h2
              onClick={() => !isDemo && setIsEditing(true)}
              title={!isDemo ? 'Click to rename' : undefined}
              style={{
                fontSize: '14.5px',
                fontWeight: 500,
                color: 'var(--text-primary)',
                cursor: !isDemo ? 'pointer' : 'default',
              }}
            >
              {name}
            </h2>
            {!isDemo && onRename && (
              <button
                onClick={() => setIsEditing(true)}
                title="Rename investigation"
                style={{
                  fontSize: '11px',
                  color: 'var(--text-muted)',
                  padding: '2px',
                  opacity: 0.6,
                }}
                onMouseEnter={(e) => (e.currentTarget.style.opacity = '1')}
                onMouseLeave={(e) => (e.currentTarget.style.opacity = '0.6')}
              >
                ✎
              </button>
            )}
          </div>
        )}

        {isDemo && (
          <span
            style={{
              fontSize: '9.5px',
              fontWeight: 600,
              color: 'var(--text-secondary)',
              backgroundColor: 'var(--bg-surface-muted)',
              border: '1px solid var(--border-subtle)',
              padding: '1px 6px',
              borderRadius: '3px',
              letterSpacing: '0.04em',
            }}
          >
            DEMO
          </span>
        )}

        <span style={{ color: 'var(--border-subtle)', margin: '0 2px' }}>·</span>

        <span style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
          {targetHost}
        </span>

        <span
          style={{
            fontSize: '11px',
            color: scopeStatus === 'ALLOWED' ? 'var(--text-secondary)' : '#9E2A2B',
            backgroundColor: scopeStatus === 'ALLOWED' ? 'var(--bg-surface-muted)' : '#FAECEB',
            padding: '1px 6px',
            borderRadius: '3px',
          }}
        >
          {scopeStatus === 'ALLOWED' ? 'In scope' : 'Out of scope'}
        </span>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
        {onOpenImport && (
          <button
            onClick={onOpenImport}
            style={{
              padding: '5px 10px',
              fontSize: '12px',
              fontWeight: 500,
              borderRadius: 'var(--radius-sm)',
              backgroundColor: 'var(--bg-surface)',
              border: '1px solid var(--border-subtle)',
              color: 'var(--text-secondary)',
              cursor: 'pointer',
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.backgroundColor = 'var(--bg-surface-hover)';
              e.currentTarget.style.color = 'var(--text-primary)';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.backgroundColor = 'var(--bg-surface)';
              e.currentTarget.style.color = 'var(--text-secondary)';
            }}
          >
            Import Traffic
          </button>
        )}

        {onOpenAddObservation && (
          <button
            onClick={onOpenAddObservation}
            style={{
              padding: '5px 10px',
              fontSize: '12px',
              fontWeight: 500,
              borderRadius: 'var(--radius-sm)',
              backgroundColor: 'var(--bg-surface)',
              border: '1px solid var(--border-subtle)',
              color: 'var(--text-secondary)',
              cursor: 'pointer',
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.backgroundColor = 'var(--bg-surface-hover)';
              e.currentTarget.style.color = 'var(--text-primary)';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.backgroundColor = 'var(--bg-surface)';
              e.currentTarget.style.color = 'var(--text-secondary)';
            }}
          >
            + Observation
          </button>
        )}

        <button
          onClick={() => onOpenDrawer('evidence')}
          style={{
            padding: '5px 12px',
            fontSize: '12px',
            fontWeight: 500,
            borderRadius: 'var(--radius-sm)',
            backgroundColor: 'var(--bg-surface)',
            border: '1px solid var(--border-subtle)',
            color: 'var(--text-secondary)',
            cursor: 'pointer',
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.backgroundColor = 'var(--bg-surface-hover)';
            e.currentTarget.style.color = 'var(--text-primary)';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.backgroundColor = 'var(--bg-surface)';
            e.currentTarget.style.color = 'var(--text-secondary)';
          }}
        >
          Context →
        </button>

        {!isDemo && onDelete && (
          <button
            onClick={onDelete}
            title="Delete investigation"
            style={{
              padding: '5px 10px',
              fontSize: '12px',
              color: 'var(--text-muted)',
              borderRadius: 'var(--radius-sm)',
            }}
            onMouseEnter={(e) => (e.currentTarget.style.color = '#DC2626')}
            onMouseLeave={(e) => (e.currentTarget.style.color = 'var(--text-muted)')}
          >
            Delete
          </button>
        )}
      </div>
    </header>
  );
};
