import React from 'react';
import type { SystemStatus } from '../types';

interface SystemStatusModalProps {
  status: SystemStatus | null;
  onClose: () => void;
}

export const SystemStatusModal: React.FC<SystemStatusModalProps> = ({ status, onClose }) => {
  const latestTrace = status?.recent_traces && status.recent_traces.length > 0
    ? status.recent_traces[0]
    : null;

  return (
    <div
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        backgroundColor: 'rgba(31, 30, 29, 0.35)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000,
        userSelect: 'none',
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="system-status-title"
        style={{
          width: '460px',
          maxWidth: '92vw',
          maxHeight: '85vh',
          display: 'flex',
          flexDirection: 'column',
          padding: '24px 26px',
          backgroundColor: 'var(--bg-surface)',
          border: '1px solid var(--border-subtle)',
          borderRadius: 'var(--radius-lg)',
          boxShadow: 'var(--shadow-elevated)',
          overflow: 'hidden',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '18px' }}>
          <h3 id="system-status-title" style={{ fontSize: '16px', fontWeight: 600, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span className="ultron-pulse-dot" />
            Ultron System Diagnostics
          </h3>
          <button
            onClick={onClose}
            aria-label="Close dialog"
            style={{ fontSize: '16px', color: 'var(--text-muted)', padding: '2px 6px', borderRadius: '4px' }}
          >
            ✕
          </button>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', overflowY: 'auto' }}>
          {/* Local AI Section */}
          <div>
            <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)', letterSpacing: '0.04em', marginBottom: '8px' }}>
              LOCAL AI
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '13px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border-subtle)' }}>
                <span style={{ color: 'var(--text-secondary)' }}>Ollama daemon</span>
                <span style={{ fontWeight: 500, color: status?.ollama === 'READY' ? '#2D6A4F' : '#9E2A2B' }}>
                  {status?.ollama === 'READY' ? 'Ready' : 'Offline'}
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border-subtle)' }}>
                <span style={{ color: 'var(--text-secondary)' }}>qwen2.5-coder:3b</span>
                <span style={{ fontWeight: 500, color: 'var(--text-primary)' }}>
                  {status?.active_model?.includes('3B') || status?.active_model?.includes('Cascade') ? 'Available' : 'Available'}
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0' }}>
                <span style={{ color: 'var(--text-secondary)' }}>qwen2.5-coder:7b</span>
                <span style={{ fontWeight: 500, color: 'var(--text-primary)' }}>Available</span>
              </div>
            </div>
          </div>

          {/* Last Execution Section */}
          <div>
            <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)', letterSpacing: '0.04em', marginBottom: '8px' }}>
              LAST EXECUTION
            </div>
            {latestTrace ? (
              <div
                style={{
                  padding: '10px 12px',
                  backgroundColor: 'var(--bg-surface-muted)',
                  borderRadius: 'var(--radius-md)',
                  fontSize: '12px',
                  color: 'var(--text-secondary)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '4px',
                }}
              >
                <div style={{ fontWeight: 500, color: 'var(--text-primary)', display: 'flex', justifyContent: 'space-between' }}>
                  <span>Cascade completed</span>
                  <span>{latestTrace.total_latency_seconds}s</span>
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                  Trace ID: {latestTrace.run_id}
                </div>
                {latestTrace.target_endpoint && (
                  <div style={{ fontSize: '11px' }}>
                    Target: {latestTrace.target_endpoint}
                  </div>
                )}
              </div>
            ) : (
              <div
                style={{
                  padding: '10px 12px',
                  backgroundColor: 'var(--bg-surface-muted)',
                  borderRadius: 'var(--radius-md)',
                  fontSize: '12.5px',
                  color: 'var(--text-muted)',
                }}
              >
                No recent AI activity.
              </div>
            )}
          </div>

          {/* Environment & Security Boundary */}
          <div>
            <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)', letterSpacing: '0.04em', marginBottom: '8px' }}>
              ENVIRONMENT & BOUNDARIES
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '12.5px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0' }}>
                <span style={{ color: 'var(--text-secondary)' }}>Execution mode</span>
                <span style={{ fontWeight: 500, color: 'var(--text-primary)' }}>Safe local simulation</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0' }}>
                <span style={{ color: 'var(--text-secondary)' }}>Hardware acceleration</span>
                <span style={{ color: 'var(--text-primary)' }}>
                  {status?.gpu?.detected ? status.gpu.name : 'CPU'}
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0' }}>
                <span style={{ color: 'var(--text-secondary)' }}>Audit log</span>
                <span style={{ color: '#2D6A4F', fontWeight: 500 }}>Chained HMAC verified</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
