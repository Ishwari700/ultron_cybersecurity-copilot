import React, { useState } from 'react';
import { importTraffic } from '../api';
import type { IngestionResult } from '../types';
import { getImportPresentation } from '../utils/importPresentation';

interface ImportTrafficModalProps {
  investigationId: string;
  targetHost: string;
  onClose: () => void;
  onImportComplete: (result: IngestionResult) => void;
  onViewEvidence: () => void;
  onStartAnalysis: () => void;
}

export const ImportTrafficModal: React.FC<ImportTrafficModalProps> = ({
  investigationId,
  targetHost,
  onClose,
  onImportComplete,
  onViewEvidence,
  onStartAnalysis,
}) => {
  const [format, setFormat] = useState<'har' | 'raw_http'>('har');
  const [content, setContent] = useState('');
  const [filename, setFilename] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<IngestionResult | null>(null);

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setFilename(file.name);
    if (file.name.endsWith('.har')) {
      setFormat('har');
    } else {
      setFormat('raw_http');
    }
    const reader = new FileReader();
    reader.onload = (event) => {
      const text = event.target?.result as string;
      setContent(text || '');
    };
    reader.readAsText(file);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!content.trim() || loading) return;

    setLoading(true);
    setError(null);
    try {
      const res = await importTraffic(investigationId, {
        format,
        content: content.trim(),
        filename: filename || undefined,
      });
      setResult(res);
      onImportComplete(res);
    } catch (err: any) {
      setError(err.message || 'Import failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        backgroundColor: 'rgba(31, 30, 29, 0.45)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 100,
        padding: '20px',
      }}
      onClick={onClose}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="import-traffic-title"
        style={{
          backgroundColor: 'var(--bg-surface)',
          borderRadius: 'var(--radius-lg)',
          width: '100%',
          maxWidth: '620px',
          boxShadow: 'var(--shadow-elevated)',
          border: '1px solid var(--border-subtle)',
          padding: '24px 28px',
          maxHeight: '90vh',
          display: 'flex',
          flexDirection: 'column',
          overflowY: 'auto',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
          <h2 id="import-traffic-title" style={{ fontSize: '18px', fontWeight: 600, color: 'var(--text-primary)', letterSpacing: '-0.01em' }}>
            Import Traffic
          </h2>
          <button
            onClick={onClose}
            aria-label="Close dialog"
            style={{ fontSize: '16px', color: 'var(--text-muted)', padding: '4px 8px', borderRadius: '4px' }}
          >
            ✕
          </button>
        </div>

        <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '16px', lineHeight: 1.5 }}>
          Target Host: <strong style={{ color: 'var(--text-primary)' }}>{targetHost}</strong>.
          Captured HTTP traffic outside this scope is excluded. Sensitive tokens and headers are automatically redacted.
        </p>

        {result ? (() => {
          const presentation = getImportPresentation(result, targetHost);
          const badgeStyles = {
            info: { bg: 'var(--badge-blue-bg)', border: 'var(--badge-blue-border)', text: 'var(--badge-blue-text)' },
            success: { bg: 'var(--badge-green-bg)', border: 'var(--badge-green-border)', text: 'var(--badge-green-text)' },
            warning: { bg: 'var(--badge-amber-bg)', border: 'var(--badge-amber-border)', text: 'var(--badge-amber-text)' },
            error: { bg: 'var(--badge-red-bg)', border: 'var(--badge-red-border)', text: 'var(--badge-red-text)' },
          }[presentation.badgeType];

          return (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              {/* Informative Status Banner */}
              <div
                style={{
                  backgroundColor: badgeStyles.bg,
                  border: `1px solid ${badgeStyles.border}`,
                  borderRadius: 'var(--radius-md)',
                  padding: '14px 18px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '4px',
                }}
              >
                <div style={{ fontSize: '14.5px', fontWeight: 600, color: badgeStyles.text }}>
                  {presentation.headline}
                </div>
                <div style={{ fontSize: '13px', color: badgeStyles.text, opacity: 0.95, lineHeight: 1.45 }}>
                  {presentation.submessage}
                </div>
              </div>

              {/* Structured Summary Card */}
              <div
                style={{
                  backgroundColor: 'var(--bg-app)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-md)',
                  padding: '16px 20px',
                }}
              >
                <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '10px' }}>
                  Import Breakdown
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '13px', color: 'var(--text-secondary)' }}>
                  {presentation.counts.added > 0 && (
                    <div style={{ color: 'var(--badge-green-text)', fontWeight: 500 }}>
                      ✓ <strong>{presentation.counts.added}</strong> new observation{presentation.counts.added === 1 ? '' : 's'} created and indexed
                    </div>
                  )}
                  {presentation.counts.duplicates > 0 && (
                    <div style={{ color: presentation.counts.added === 0 ? 'var(--text-primary)' : 'var(--text-secondary)' }}>
                      <strong>{presentation.counts.duplicates}</strong> duplicate transaction{presentation.counts.duplicates === 1 ? '' : 's'} skipped (already present in evidence)
                    </div>
                  )}
                  {presentation.counts.outOfScope > 0 && (
                    <div style={{ color: 'var(--badge-amber-text)' }}>
                      <strong>{presentation.counts.outOfScope}</strong> out-of-scope transaction{presentation.counts.outOfScope === 1 ? '' : 's'} excluded (target boundary: {targetHost})
                    </div>
                  )}
                  {presentation.counts.parseFailures > 0 && (
                    <div style={{ color: 'var(--badge-red-text)' }}>
                      <strong>{presentation.counts.parseFailures}</strong> parsing error{presentation.counts.parseFailures === 1 ? '' : 's'}
                    </div>
                  )}
                  {presentation.counts.redactedSecrets > 0 && (
                    <div>
                      <strong>{presentation.counts.redactedSecrets}</strong> sensitive token{presentation.counts.redactedSecrets === 1 ? '' : 's'} automatically redacted
                    </div>
                  )}
                  {presentation.counts.added === 0 && presentation.counts.duplicates === 0 && presentation.counts.outOfScope === 0 && presentation.counts.parseFailures === 0 && (
                    <div style={{ fontStyle: 'italic', color: 'var(--text-muted)' }}>
                      No transactions detected in payload.
                    </div>
                  )}
                </div>

                {/* Detailed out-of-scope audit list */}
                {presentation.details.outOfScopeList.length > 0 && (
                  <div
                    style={{
                      marginTop: '14px',
                      padding: '10px 14px',
                      backgroundColor: 'var(--badge-amber-bg)',
                      border: '1px solid var(--badge-amber-border)',
                      borderRadius: 'var(--radius-sm)',
                      fontSize: '12px',
                      color: 'var(--badge-amber-text)',
                    }}
                  >
                    <div style={{ fontWeight: 600, marginBottom: '6px' }}>
                      Excluded Out-of-Scope Transactions:
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      {presentation.details.outOfScopeList.slice(0, 5).map((item, idx) => (
                        <div key={idx} style={{ lineHeight: 1.4 }}>
                          • Transaction #{item.transaction ?? idx + 1}: {item.host ? `host "${item.host}"` : 'Host'} — {item.reason || 'Outside target scope'}
                        </div>
                      ))}
                      {presentation.details.outOfScopeList.length > 5 && (
                        <div style={{ fontStyle: 'italic', marginTop: '2px' }}>
                          ...and {presentation.details.outOfScopeList.length - 5} more out-of-scope transaction{presentation.details.outOfScopeList.length - 5 === 1 ? '' : 's'}
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* Detailed parse errors list */}
                {presentation.details.parseErrorsList.length > 0 && (
                  <div
                    style={{
                      marginTop: '14px',
                      padding: '10px 14px',
                      backgroundColor: 'var(--badge-red-bg)',
                      border: '1px solid var(--badge-red-border)',
                      borderRadius: 'var(--radius-sm)',
                      fontSize: '12px',
                      color: 'var(--badge-red-text)',
                    }}
                  >
                    <div style={{ fontWeight: 600, marginBottom: '6px' }}>
                      Parsing Errors:
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      {presentation.details.parseErrorsList.slice(0, 5).map((err, idx) => (
                        <div key={idx} style={{ lineHeight: 1.4 }}>
                          • {err}
                        </div>
                      ))}
                      {presentation.details.parseErrorsList.length > 5 && (
                        <div style={{ fontStyle: 'italic', marginTop: '2px' }}>
                          ...and {presentation.details.parseErrorsList.length - 5} more error{presentation.details.parseErrorsList.length - 5 === 1 ? '' : 's'}
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>

              {/* Action Buttons */}
              <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end', marginTop: '4px' }}>
                <button
                  type="button"
                  onClick={onClose}
                  style={{
                    padding: '9px 16px',
                    backgroundColor: 'transparent',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-md)',
                    fontSize: '13px',
                    fontWeight: 500,
                    color: 'var(--text-primary)',
                    cursor: 'pointer',
                  }}
                >
                  {presentation.isAllOutOfScope || presentation.isAllParseFailures ? 'Close' : 'Dismiss'}
                </button>

                {(presentation.counts.added > 0 || presentation.isAllDuplicates) && (
                  <button
                    type="button"
                    onClick={onViewEvidence}
                    style={{
                      padding: '9px 16px',
                      backgroundColor: presentation.isAllDuplicates ? 'var(--accent-primary)' : 'transparent',
                      color: presentation.isAllDuplicates ? '#FFFFFF' : 'var(--text-primary)',
                      border: presentation.isAllDuplicates ? 'none' : '1px solid var(--border-subtle)',
                      borderRadius: 'var(--radius-md)',
                      fontSize: '13px',
                      fontWeight: 500,
                      cursor: 'pointer',
                    }}
                  >
                    View Evidence
                  </button>
                )}

                {(presentation.counts.added > 0 || presentation.isAllDuplicates) && (
                  <button
                    type="button"
                    onClick={onStartAnalysis}
                    style={{
                      padding: '9px 18px',
                      backgroundColor: presentation.isAllDuplicates ? 'transparent' : 'var(--accent-primary)',
                      color: presentation.isAllDuplicates ? 'var(--text-primary)' : '#FFFFFF',
                      border: presentation.isAllDuplicates ? '1px solid var(--border-subtle)' : 'none',
                      borderRadius: 'var(--radius-md)',
                      fontSize: '13px',
                      fontWeight: 500,
                      cursor: 'pointer',
                    }}
                  >
                    Start Security Analysis
                  </button>
                )}
              </div>
            </div>
          );
        })() : (
          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            {error && (
              <div
                style={{
                  padding: '10px 14px',
                  backgroundColor: 'var(--badge-red-bg)',
                  border: '1px solid var(--badge-red-border)',
                  color: 'var(--badge-red-text)',
                  borderRadius: 'var(--radius-md)',
                  fontSize: '12.5px',
                }}
              >
                {error}
              </div>
            )}

            {/* Format Selector */}
            <div>
              <label
                id="format-selector-label"
                style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '6px' }}
              >
                FORMAT
              </label>
              <div
                role="radiogroup"
                aria-labelledby="format-selector-label"
                className="format-selector-group"
              >
                <button
                  type="button"
                  role="radio"
                  id="format-har-btn"
                  tabIndex={format === 'har' ? 0 : -1}
                  aria-checked={format === 'har'}
                  className={`format-selector-btn ${format === 'har' ? 'active' : ''}`}
                  onClick={() => setFormat('har')}
                  onKeyDown={(e) => {
                    if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
                      e.preventDefault();
                      setFormat('raw_http');
                      document.getElementById('format-raw-btn')?.focus();
                    }
                  }}
                >
                  <span className="format-radio-dot" aria-hidden="true" />
                  <span>HTTP Archive (HAR)</span>
                </button>
                <button
                  type="button"
                  role="radio"
                  id="format-raw-btn"
                  tabIndex={format === 'raw_http' ? 0 : -1}
                  aria-checked={format === 'raw_http'}
                  className={`format-selector-btn ${format === 'raw_http' ? 'active' : ''}`}
                  onClick={() => setFormat('raw_http')}
                  onKeyDown={(e) => {
                    if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
                      e.preventDefault();
                      setFormat('har');
                      document.getElementById('format-har-btn')?.focus();
                    }
                  }}
                >
                  <span className="format-radio-dot" aria-hidden="true" />
                  <span>Raw HTTP Request / Response</span>
                </button>
              </div>
            </div>

            {/* File Upload Option */}
            <div>
              <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '6px' }}>
                UPLOAD FILE OR PASTE
              </label>
              <input
                type="file"
                accept=".har,.txt,.log,.json"
                onChange={handleFileUpload}
                style={{
                  fontSize: '12.5px',
                  color: 'var(--text-secondary)',
                  border: '1px dashed var(--border-subtle)',
                  padding: '8px 12px',
                  width: '100%',
                  borderRadius: 'var(--radius-md)',
                  backgroundColor: 'var(--bg-app)',
                  cursor: 'pointer',
                  marginBottom: '8px',
                }}
              />
            </div>

            {/* Content Textarea */}
            <div>
              <textarea
                value={content}
                onChange={(e) => setContent(e.target.value)}
                placeholder={
                  format === 'har'
                    ? 'Paste HAR file JSON content here or choose a file above...'
                    : 'GET /api/v1/invoices/4821 HTTP/1.1\nHost: api.target.local\n\nHTTP/1.1 200 OK\nContent-Type: application/json\n\n{"invoice_id": 4821}'
                }
                style={{
                  width: '100%',
                  height: '180px',
                  padding: '12px',
                  fontSize: '12.5px',
                  fontFamily: 'var(--font-mono)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-md)',
                  backgroundColor: 'var(--bg-surface)',
                  resize: 'vertical',
                }}
              />
            </div>

            {/* Actions */}
            <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end', marginTop: '4px' }}>
              <button
                type="button"
                onClick={onClose}
                style={{
                  padding: '8px 16px',
                  backgroundColor: 'transparent',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-md)',
                  fontSize: '13px',
                  color: 'var(--text-secondary)',
                  cursor: 'pointer',
                }}
              >
                Cancel
              </button>

              <button
                type="submit"
                disabled={!content.trim() || loading}
                style={{
                  padding: '8px 18px',
                  backgroundColor: 'var(--accent-primary)',
                  color: '#FFFFFF',
                  borderRadius: 'var(--radius-md)',
                  fontSize: '13px',
                  fontWeight: 500,
                  border: 'none',
                  cursor: !content.trim() || loading ? 'not-allowed' : 'pointer',
                  opacity: !content.trim() || loading ? 0.6 : 1,
                }}
              >
                {loading ? 'Importing…' : 'Import Traffic'}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
};
