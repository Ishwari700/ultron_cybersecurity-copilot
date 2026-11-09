import React, { useState } from 'react';
import type { InvestigationSummary, UserSession } from '../types';

interface SidebarProps {
  investigations: InvestigationSummary[];
  activeId: string | null;
  onSelect: (id: string) => void;
  onNewInvestigation: () => void;
  onLoadDemo: () => void;
  onOpenSystemStatus: () => void;
  systemStatusReady: boolean;
  onOpenWorkspace?: () => void;
  onOpenKnowledgeLab?: () => void;
  currentUser?: UserSession | null;
  onLogout?: () => void;
  theme?: 'light' | 'dark';
  onToggleTheme?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  investigations,
  activeId,
  onSelect,
  onNewInvestigation,
  onLoadDemo,
  onOpenSystemStatus,
  systemStatusReady,
  onOpenWorkspace,
  onOpenKnowledgeLab,
  currentUser,
  onLogout,
  theme = 'dark',
  onToggleTheme,
}) => {
  const [search, setSearch] = useState('');

  const filtered = investigations.filter(
    (inv) =>
      inv.name.toLowerCase().includes(search.toLowerCase()) ||
      inv.target_host.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <aside
      style={{
        width: '260px',
        backgroundColor: 'var(--bg-sidebar)',
        borderRight: '1px solid var(--border-subtle)',
        display: 'flex',
        flexDirection: 'column',
        height: '100%',
        flexShrink: 0,
        userSelect: 'none',
      }}
    >
      {/* Platform Branding */}
      <div style={{ padding: '20px 18px 14px 18px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <div
              style={{
                width: '26px',
                height: '26px',
                borderRadius: '6px',
                background: 'linear-gradient(135deg, #E50914 0%, #800008 100%)',
                boxShadow: 'var(--accent-glow-subtle)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#FFF',
                border: '1px solid rgba(255, 255, 255, 0.2)',
              }}
            >
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 2L3 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z" />
                <path d="M12 8v5" stroke="#FFF" strokeWidth="2.5" />
                <circle cx="12" cy="16" r="1" fill="#FFF" />
              </svg>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <span style={{ fontSize: '15px', fontWeight: 700, color: 'var(--text-primary)', letterSpacing: '0.04em' }}>
                ULTRON
              </span>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
            <span className="ultron-pulse-dot" />
            <span style={{ fontSize: '10px', color: 'var(--text-muted)', backgroundColor: 'var(--bg-surface-muted)', padding: '2px 6px', borderRadius: '4px', border: '1px solid var(--border-subtle)', fontWeight: 600, letterSpacing: '0.04em' }}>
              CORE
            </span>
          </div>
        </div>

        {/* Workspace Switcher Button */}
        {onOpenWorkspace && (
          <button
            onClick={onOpenWorkspace}
            style={{
              width: '100%',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '7px',
              marginBottom: '6px',
              padding: '8px 12px',
              backgroundColor: 'rgba(225, 29, 72, 0.08)',
              border: '1px solid rgba(225, 29, 72, 0.28)',
              color: 'var(--text-primary)',
              borderRadius: 'var(--radius-md)',
              fontSize: '12px',
              fontWeight: 600,
              cursor: 'pointer',
              transition: 'all 0.15s ease',
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.backgroundColor = 'rgba(225, 29, 72, 0.16)';
              e.currentTarget.style.borderColor = 'rgba(225, 29, 72, 0.45)';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.backgroundColor = 'rgba(225, 29, 72, 0.08)';
              e.currentTarget.style.borderColor = 'rgba(225, 29, 72, 0.28)';
            }}
          >
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ color: 'var(--accent-primary)' }}>
              <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
              <line x1="8" y1="21" x2="16" y2="21" />
              <line x1="12" y1="17" x2="12" y2="21" />
            </svg>
            <span>Assessment Workspace</span>
          </button>
        )}

        {/* Global Knowledge Lab Switcher Button */}
        {onOpenKnowledgeLab && (
          <button
            onClick={onOpenKnowledgeLab}
            data-testid="sidebar-open-knowledge-lab"
            style={{
              width: '100%',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '7px',
              marginBottom: '10px',
              padding: '8px 12px',
              backgroundColor: 'rgba(59, 130, 246, 0.08)',
              border: '1px solid rgba(59, 130, 246, 0.28)',
              color: 'var(--text-primary)',
              borderRadius: 'var(--radius-md)',
              fontSize: '12px',
              fontWeight: 600,
              cursor: 'pointer',
              transition: 'all 0.15s ease',
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.backgroundColor = 'rgba(59, 130, 246, 0.16)';
              e.currentTarget.style.borderColor = 'rgba(59, 130, 246, 0.45)';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.backgroundColor = 'rgba(59, 130, 246, 0.08)';
              e.currentTarget.style.borderColor = 'rgba(59, 130, 246, 0.28)';
            }}
          >
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ color: 'var(--badge-blue-text)' }}>
              <path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20" />
              <path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z" />
            </svg>
            <span>Knowledge Lab</span>
          </button>
        )}

        {/* New Investigation Button */}
        <button
          onClick={onNewInvestigation}
          style={{
            width: '100%',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '8px',
            padding: '8px 14px',
            backgroundColor: 'var(--bg-surface)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 'var(--radius-md)',
            fontSize: '13px',
            fontWeight: 500,
            color: 'var(--text-primary)',
            boxShadow: 'var(--shadow-subtle)',
            transition: 'background-color 0.15s ease',
          }}
          onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = 'var(--bg-surface-hover)')}
          onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'var(--bg-surface)')}
        >
          <span style={{ fontSize: '15px', lineHeight: 1 }}>+</span>
          <span>New investigation</span>
        </button>

        {/* Subtle Load Demo Fixture Button */}
        <button
          onClick={onLoadDemo}
          style={{
            width: '100%',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '6px',
            marginTop: '8px',
            padding: '6px 12px',
            backgroundColor: 'transparent',
            border: '1px dashed var(--border-subtle)',
            borderRadius: 'var(--radius-md)',
            fontSize: '11.5px',
            color: 'var(--text-secondary)',
            transition: 'all 0.15s ease',
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.backgroundColor = 'var(--bg-surface-hover)';
            e.currentTarget.style.color = 'var(--text-primary)';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.backgroundColor = 'transparent';
            e.currentTarget.style.color = 'var(--text-secondary)';
          }}
        >
          <span>▶</span>
          <span>Load demo fixture</span>
        </button>
      </div>

      {/* Search Filter */}
      <div style={{ padding: '0 18px 12px 18px' }}>
        <input
          type="text"
          placeholder="Search investigations..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{
            width: '100%',
            padding: '6px 10px',
            fontSize: '12.5px',
            backgroundColor: 'var(--bg-surface)',
            borderRadius: 'var(--radius-sm)',
            border: '1px solid var(--border-subtle)',
          }}
        />
      </div>

      {/* Recent Investigations List */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '0 10px' }}>
        <div style={{ padding: '4px 8px', fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)', letterSpacing: '0.04em' }}>
          RECENT
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '2px', marginTop: '4px' }}>
          {filtered.length > 0 ? (
            filtered.map((inv) => {
              const isActive = inv.id === activeId;
              return (
                <div
                  key={inv.id}
                  onClick={() => onSelect(inv.id)}
                  style={{
                    padding: '8px 10px',
                    borderRadius: 'var(--radius-md)',
                    backgroundColor: isActive ? 'var(--bg-surface-active)' : 'transparent',
                    cursor: 'pointer',
                    transition: 'background-color 0.15s ease',
                  }}
                  onMouseEnter={(e) => {
                    if (!isActive) e.currentTarget.style.backgroundColor = 'var(--bg-surface-hover)';
                  }}
                  onMouseLeave={(e) => {
                    if (!isActive) e.currentTarget.style.backgroundColor = 'transparent';
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', overflow: 'hidden' }}>
                    {inv.is_demo && (
                      <span
                        style={{
                          fontSize: '8.5px',
                          fontWeight: 600,
                          color: 'var(--text-secondary)',
                          backgroundColor: 'var(--bg-surface-muted)',
                          padding: '1px 4px',
                          borderRadius: '3px',
                          marginRight: '6px',
                          flexShrink: 0,
                        }}
                      >
                        DEMO
                      </span>
                    )}
                    <span
                      style={{
                        fontSize: '13px',
                        fontWeight: isActive ? 500 : 400,
                        color: 'var(--text-primary)',
                        whiteSpace: 'nowrap',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                      }}
                    >
                      {inv.name}
                    </span>
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
                    {inv.target_host}
                  </div>
                </div>
              );
            })
          ) : (
            <div style={{ padding: '24px 12px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '12px' }}>
              No investigations yet.
            </div>
          )}
        </div>
      </div>

      {/* Sidebar Footer with Theme Switcher & System Status */}
      <div style={{ padding: '10px 16px', borderTop: '1px solid var(--border-subtle)', backgroundColor: 'var(--bg-sidebar)', display: 'flex', flexDirection: 'column', gap: '8px' }}>
        {onToggleTheme && (
          <button
            id="theme-toggle-btn"
            onClick={onToggleTheme}
            aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
            title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
            style={{
              width: '100%',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '7px 10px',
              borderRadius: 'var(--radius-sm)',
              backgroundColor: 'var(--bg-surface)',
              border: '1px solid var(--border-subtle)',
              fontSize: '12px',
              color: 'var(--text-secondary)',
              cursor: 'pointer',
              transition: 'all 0.15s ease',
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
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontSize: '13px', lineHeight: 1 }}>{theme === 'light' ? '☀️' : '🌙'}</span>
              <span style={{ fontWeight: 500 }}>Theme: {theme === 'light' ? 'Light' : 'Dark'}</span>
            </div>
            <span
              style={{
                fontSize: '10px',
                padding: '1px 5px',
                borderRadius: '3px',
                backgroundColor: 'var(--bg-surface-muted)',
                color: 'var(--text-muted)',
                fontWeight: 600,
              }}
            >
              {theme === 'light' ? 'LIGHT' : 'DARK'}
            </span>
          </button>
        )}

        <button
          onClick={onOpenSystemStatus}
          style={{
            width: '100%',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '7px 10px',
            borderRadius: 'var(--radius-sm)',
            backgroundColor: 'var(--bg-surface)',
            border: '1px solid var(--border-subtle)',
            fontSize: '12px',
            color: 'var(--text-secondary)',
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
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span
              style={{
                width: '7px',
                height: '7px',
                borderRadius: '50%',
                backgroundColor: systemStatusReady ? '#34D399' : '#FBBF24',
                boxShadow: systemStatusReady ? '0 0 6px rgba(52, 211, 153, 0.6)' : 'none',
              }}
            />
            <span style={{ fontWeight: 500 }}>System diagnostics</span>
          </div>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>→</span>
        </button>
      </div>

      {/* Authenticated Operator Session Banner */}
      {currentUser && (
        <div style={{
          padding: '12px 16px',
          borderTop: '1px solid var(--border-subtle)',
          backgroundColor: 'var(--bg-sidebar)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}>
          <div style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
            <span style={{
              fontSize: '12px',
              fontWeight: 600,
              color: 'var(--text-primary)',
              whiteSpace: 'nowrap',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
            }}>
              {currentUser.username}
            </span>
            <span style={{
              fontSize: '10.5px',
              color: 'var(--text-secondary)',
              textTransform: 'uppercase',
              letterSpacing: '0.04em',
            }}>
              {currentUser.role}
            </span>
          </div>
          {onLogout && (
            <button
              onClick={onLogout}
              style={{
                padding: '4px 8px',
                fontSize: '11px',
                borderRadius: 'var(--radius-sm)',
                backgroundColor: 'transparent',
                border: '1px solid var(--border-subtle)',
                color: 'var(--text-secondary)',
                cursor: 'pointer',
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.color = 'var(--accent-primary)';
                e.currentTarget.style.borderColor = 'var(--accent-primary)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.color = 'var(--text-secondary)';
                e.currentTarget.style.borderColor = 'var(--border-subtle)';
              }}
            >
              Sign Out
            </button>
          )}
        </div>
      )}
    </aside>
  );
};
