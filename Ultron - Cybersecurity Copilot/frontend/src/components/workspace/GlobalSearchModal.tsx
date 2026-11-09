import React, { useState, useEffect } from 'react';
import { searchWorkspaceGlobal } from '../../api';
import type { GlobalSearchResultItem } from '../../types';

interface GlobalSearchModalProps {
  assessmentId: string | null;
  onNavigateSection: (section: string) => void;
  onClose: () => void;
}

export const GlobalSearchModal: React.FC<GlobalSearchModalProps> = ({
  assessmentId,
  onNavigateSection,
  onClose,
}) => {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<GlobalSearchResultItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!query.trim()) {
      setResults([]);
      return;
    }

    const timer = setTimeout(async () => {
      setLoading(true);
      setError(null);
      try {
        const res = await searchWorkspaceGlobal(query.trim(), assessmentId || undefined);
        setResults(res);
      } catch (err: any) {
        setError(err.message || 'Search failed');
      } finally {
        setLoading(false);
      }
    }, 250);

    return () => clearTimeout(timer);
  }, [query, assessmentId]);

  const handleSelectResult = (item: GlobalSearchResultItem) => {
    // Map entity_type to section
    const map: Record<string, string> = {
      assessment: 'overview',
      asset: 'scope_assets',
      evidence: 'evidence',
      hypothesis: 'hypotheses',
      experiment: 'experiments',
      finding: 'findings_review',
      artifact: 'artifacts',
    };
    const targetSection = map[item.entity_type] || 'overview';
    onNavigateSection(targetSection);
    onClose();
  };

  const getTypeBadgeColor = (type: string) => {
    switch (type) {
      case 'finding':
        return { bg: 'var(--badge-red-bg)', text: 'var(--badge-red-text)' };
      case 'hypothesis':
        return { bg: 'var(--badge-amber-bg)', text: 'var(--badge-amber-text)' };
      case 'evidence':
        return { bg: 'var(--badge-blue-bg)', text: 'var(--badge-blue-text)' };
      case 'asset':
        return { bg: 'var(--badge-green-bg)', text: 'var(--badge-green-text)' };
      default:
        return { bg: 'var(--bg-surface-muted)', text: 'var(--text-secondary)' };
    }
  };

  return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      backgroundColor: 'rgba(0, 0, 0, 0.45)',
      display: 'flex',
      alignItems: 'flex-start',
      justifyContent: 'center',
      paddingTop: '80px',
      zIndex: 1200,
    }}>
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Global assessment search"
        style={{
          backgroundColor: 'var(--bg-surface)',
          borderRadius: 'var(--radius-lg)',
          width: '680px',
          maxHeight: '70vh',
          display: 'flex',
          flexDirection: 'column',
          boxShadow: 'var(--shadow-elevated)',
          border: '1px solid var(--border-subtle)',
          overflow: 'hidden',
        }}
      >
        {/* Search Input Bar */}
        <div style={{
          padding: '16px 20px',
          borderBottom: '1px solid var(--border-subtle)',
          display: 'flex',
          alignItems: 'center',
          gap: '12px',
        }}>
          <span style={{ fontSize: '16px' }}>🔍</span>
          <input
            type="text"
            placeholder="Search assets, observations, hypotheses, experiments, findings, artifacts..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            autoFocus
            style={{
              flex: 1,
              border: 'none',
              fontSize: '15px',
              background: 'transparent',
              outline: 'none',
            }}
          />
          {query && (
            <button
              onClick={() => setQuery('')}
              aria-label="Clear search query"
              style={{ fontSize: '13px', color: 'var(--text-muted)', background: 'transparent', border: 'none', cursor: 'pointer' }}
            >
              Clear
            </button>
          )}
          <button
            onClick={onClose}
            aria-label="Close dialog"
            style={{ fontSize: '14px', color: 'var(--text-muted)', padding: '2px 6px', background: 'transparent', border: 'none', cursor: 'pointer' }}
          >
            ESC
          </button>
        </div>

        {/* Results Body */}
        <div style={{
          flex: 1,
          overflowY: 'auto',
          padding: '12px 20px',
          display: 'flex',
          flexDirection: 'column',
          gap: '8px',
        }}>
          {loading && (
            <div style={{ textAlign: 'center', padding: '24px', color: 'var(--text-muted)', fontSize: '13px' }}>
              Searching workspace with strict isolation...
            </div>
          )}

          {error && (
            <div style={{ padding: '8px 12px', background: 'var(--badge-red-bg)', color: 'var(--badge-red-text)', fontSize: '12px', borderRadius: 'var(--radius-sm)' }}>
              {error}
            </div>
          )}

          {!loading && !error && query.trim() && results.length === 0 && (
            <div style={{ textAlign: 'center', padding: '32px', color: 'var(--text-muted)', fontSize: '13px' }}>
              No entities found matching "{query}".
            </div>
          )}

          {!loading && !query.trim() && (
            <div style={{ textAlign: 'center', padding: '32px', color: 'var(--text-muted)', fontSize: '12px' }}>
              Type a search query to search across current assessment scope, evidence, and research entities.
            </div>
          )}

          {results.map((item) => {
            const badge = getTypeBadgeColor(item.entity_type);
            return (
              <div
                key={`${item.entity_type}-${item.entity_id}`}
                onClick={() => handleSelectResult(item)}
                style={{
                  padding: '10px 14px',
                  borderRadius: 'var(--radius-md)',
                  border: '1px solid var(--border-subtle)',
                  background: 'var(--bg-surface)',
                  cursor: 'pointer',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '4px',
                  transition: 'background-color 0.1s ease',
                }}
                onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = 'var(--bg-surface-muted)')}
                onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'var(--bg-surface)')}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{
                      padding: '2px 6px',
                      borderRadius: '4px',
                      fontSize: '10px',
                      fontWeight: 700,
                      textTransform: 'uppercase',
                      background: badge.bg,
                      color: badge.text,
                    }}>
                      {item.entity_type}
                    </span>
                    <span style={{ fontWeight: 600, fontSize: '13px' }}>{item.title}</span>
                  </div>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)' }}>
                    {item.entity_id}
                  </span>
                </div>
                <p style={{ fontSize: '12px', color: 'var(--text-secondary)', lineClamp: 2 }}>
                  {item.snippet}
                </p>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
