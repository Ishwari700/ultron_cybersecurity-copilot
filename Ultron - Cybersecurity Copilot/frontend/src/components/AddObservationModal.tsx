import React, { useState } from 'react';
import { addObservation } from '../api';
import type { IngestionResult } from '../types';

interface AddObservationModalProps {
  investigationId: string;
  targetHost: string;
  onClose: () => void;
  onObservationAdded: (result: IngestionResult) => void;
  onViewEvidence: () => void;
  onStartAnalysis: () => void;
}

export const AddObservationModal: React.FC<AddObservationModalProps> = ({
  investigationId,
  targetHost,
  onClose,
  onObservationAdded,
  onViewEvidence,
  onStartAnalysis,
}) => {
  const [method, setMethod] = useState('GET');
  const [host, setHost] = useState(targetHost);
  const [path, setPath] = useState('/');
  const [statusCode, setStatusCode] = useState(200);
  const [reqHeadersText, setReqHeadersText] = useState('');
  const [reqBody, setReqBody] = useState('');
  const [respHeadersText, setRespHeadersText] = useState('Content-Type: application/json');
  const [respBody, setRespBody] = useState('');
  const [note, setNote] = useState('');

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<IngestionResult | null>(null);

  const parseHeaders = (text: string): Record<string, string> => {
    const headers: Record<string, string> = {};
    text.split('\n').forEach((line) => {
      const idx = line.indexOf(':');
      if (idx > 0) {
        const k = line.substring(0, idx).trim();
        const v = line.substring(idx + 1).trim();
        if (k) headers[k] = v;
      }
    });
    return headers;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!path.trim() || loading) return;

    setLoading(true);
    setError(null);

    try {
      const reqHeaders = parseHeaders(reqHeadersText);
      const respHeaders = parseHeaders(respHeadersText);

      const res = await addObservation(investigationId, {
        method,
        host: host.trim() || targetHost,
        path: path.trim(),
        status_code: Number(statusCode) || 200,
        request_headers: reqHeaders,
        request_body: reqBody.trim() || undefined,
        response_headers: respHeaders,
        response_body: respBody.trim() || undefined,
        researcher_note: note.trim() || undefined,
      });

      setResult(res);
      onObservationAdded(res);
    } catch (err: any) {
      setError(err.message || 'Failed to add observation');
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
        aria-labelledby="add-observation-title"
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
          <h2 id="add-observation-title" style={{ fontSize: '18px', fontWeight: 600, color: 'var(--text-primary)', letterSpacing: '-0.01em' }}>
            Add Target Observation
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
          Record a canonical HTTP interaction observed during security testing.
        </p>

        {result ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div
              style={{
                backgroundColor: 'var(--bg-app)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-md)',
                padding: '16px 20px',
              }}
            >
              <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '8px' }}>
                {result.accepted_count > 0 ? 'Observation Recorded' : (result.duplicate_count > 0 ? 'Observation Already Recorded' : 'Observation Excluded')}
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '13px', color: 'var(--text-secondary)' }}>
                {result.accepted_count > 0 && (
                  <div style={{ color: 'var(--badge-green-text)', fontWeight: 500 }}>
                    ✓ <strong>{result.accepted_count}</strong> observation added to canonical evidence
                  </div>
                )}
                {result.duplicate_count > 0 && (
                  <div>Observation was already present in canonical evidence (duplicate skipped)</div>
                )}
                {result.out_of_scope_count > 0 && (
                  <div style={{ color: 'var(--badge-amber-text)' }}>
                    Target host is outside investigation scope ({targetHost})
                  </div>
                )}
                {result.redacted_secret_count > 0 && (
                  <div><strong>{result.redacted_secret_count}</strong> sensitive values redacted</div>
                )}
              </div>
            </div>

            <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end', marginTop: '8px' }}>
              <button
                type="button"
                onClick={onViewEvidence}
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
                View Evidence
              </button>

              <button
                type="button"
                onClick={onStartAnalysis}
                style={{
                  padding: '9px 18px',
                  backgroundColor: 'var(--accent-primary)',
                  color: '#FFFFFF',
                  borderRadius: 'var(--radius-md)',
                  fontSize: '13px',
                  fontWeight: 500,
                  border: 'none',
                  cursor: 'pointer',
                }}
              >
                Start Security Analysis
              </button>
            </div>
          </div>
        ) : (
          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
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

            {/* Method, Path, Status Code */}
            <div style={{ display: 'grid', gridTemplateColumns: '110px 1fr 100px', gap: '10px' }}>
              <div>
                <label style={{ fontSize: '11.5px', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '4px' }}>
                  METHOD
                </label>
                <select
                  value={method}
                  onChange={(e) => setMethod(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '8px 10px',
                    fontSize: '13px',
                    fontWeight: 500,
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-md)',
                    backgroundColor: 'var(--bg-surface)',
                  }}
                >
                  <option value="GET">GET</option>
                  <option value="POST">POST</option>
                  <option value="PUT">PUT</option>
                  <option value="DELETE">DELETE</option>
                  <option value="PATCH">PATCH</option>
                  <option value="OPTIONS">OPTIONS</option>
                  <option value="HEAD">HEAD</option>
                </select>
              </div>

              <div>
                <label style={{ fontSize: '11.5px', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '4px' }}>
                  PATH
                </label>
                <input
                  type="text"
                  value={path}
                  onChange={(e) => setPath(e.target.value)}
                  placeholder="/api/v1/invoices/4821"
                  required
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    fontSize: '13px',
                    fontFamily: 'var(--font-mono)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-md)',
                    backgroundColor: 'var(--bg-surface)',
                  }}
                />
              </div>

              <div>
                <label style={{ fontSize: '11.5px', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '4px' }}>
                  STATUS
                </label>
                <input
                  type="number"
                  value={statusCode}
                  onChange={(e) => setStatusCode(Number(e.target.value))}
                  style={{
                    width: '100%',
                    padding: '8px 10px',
                    fontSize: '13px',
                    fontFamily: 'var(--font-mono)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-md)',
                    backgroundColor: 'var(--bg-surface)',
                  }}
                />
              </div>
            </div>

            {/* Host */}
            <div>
              <label style={{ fontSize: '11.5px', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '4px' }}>
                TARGET HOST
              </label>
              <input
                type="text"
                value={host}
                onChange={(e) => setHost(e.target.value)}
                placeholder="api.target.local"
                style={{
                  width: '100%',
                  padding: '8px 12px',
                  fontSize: '13px',
                  fontFamily: 'var(--font-mono)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-md)',
                  backgroundColor: 'var(--bg-surface)',
                }}
              />
            </div>

            {/* Researcher Note */}
            <div>
              <label style={{ fontSize: '11.5px', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '4px' }}>
                RESEARCHER NOTE (OPTIONAL)
              </label>
              <input
                type="text"
                value={note}
                onChange={(e) => setNote(e.target.value)}
                placeholder="Observed cross-tenant invoice export with valid token"
                style={{
                  width: '100%',
                  padding: '8px 12px',
                  fontSize: '13px',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-md)',
                  backgroundColor: 'var(--bg-surface)',
                }}
              />
            </div>

            {/* Request & Response Headers */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
              <div>
                <label style={{ fontSize: '11.5px', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '4px' }}>
                  REQUEST HEADERS (OPTIONAL)
                </label>
                <textarea
                  value={reqHeadersText}
                  onChange={(e) => setReqHeadersText(e.target.value)}
                  placeholder="Authorization: Bearer token&#10;Content-Type: application/json"
                  style={{
                    width: '100%',
                    height: '60px',
                    padding: '8px',
                    fontSize: '11.5px',
                    fontFamily: 'var(--font-mono)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-md)',
                    backgroundColor: 'var(--bg-surface)',
                    resize: 'vertical',
                  }}
                />
              </div>

              <div>
                <label style={{ fontSize: '11.5px', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '4px' }}>
                  RESPONSE HEADERS (OPTIONAL)
                </label>
                <textarea
                  value={respHeadersText}
                  onChange={(e) => setRespHeadersText(e.target.value)}
                  placeholder="Content-Type: application/json&#10;X-Request-Id: req_123"
                  style={{
                    width: '100%',
                    height: '60px',
                    padding: '8px',
                    fontSize: '11.5px',
                    fontFamily: 'var(--font-mono)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-md)',
                    backgroundColor: 'var(--bg-surface)',
                    resize: 'vertical',
                  }}
                />
              </div>
            </div>

            {/* Request Body & Response Body */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
              <div>
                <label style={{ fontSize: '11.5px', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '4px' }}>
                  REQUEST BODY (OPTIONAL)
                </label>
                <textarea
                  value={reqBody}
                  onChange={(e) => setReqBody(e.target.value)}
                  placeholder='{"invoice_id": 4821}'
                  style={{
                    width: '100%',
                    height: '80px',
                    padding: '8px',
                    fontSize: '12px',
                    fontFamily: 'var(--font-mono)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-md)',
                    backgroundColor: 'var(--bg-surface)',
                    resize: 'vertical',
                  }}
                />
              </div>

              <div>
                <label style={{ fontSize: '11.5px', fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: '4px' }}>
                  RESPONSE BODY (OPTIONAL)
                </label>
                <textarea
                  value={respBody}
                  onChange={(e) => setRespBody(e.target.value)}
                  placeholder='{"status": "ok", "invoice_data": "..."}'
                  style={{
                    width: '100%',
                    height: '80px',
                    padding: '8px',
                    fontSize: '12px',
                    fontFamily: 'var(--font-mono)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-md)',
                    backgroundColor: 'var(--bg-surface)',
                    resize: 'vertical',
                  }}
                />
              </div>
            </div>

            {/* Actions */}
            <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end', marginTop: '6px' }}>
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
                disabled={!path.trim() || loading}
                style={{
                  padding: '8px 18px',
                  backgroundColor: 'var(--accent-primary)',
                  color: '#FFFFFF',
                  borderRadius: 'var(--radius-md)',
                  fontSize: '13px',
                  fontWeight: 500,
                  border: 'none',
                  cursor: !path.trim() || loading ? 'not-allowed' : 'pointer',
                  opacity: !path.trim() || loading ? 0.6 : 1,
                }}
              >
                {loading ? 'Recording…' : 'Add Observation'}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
};
