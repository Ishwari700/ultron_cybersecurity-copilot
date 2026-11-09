import React, { useState, useEffect, useRef } from 'react';
import { generateAssessmentReport, exportAssessmentReport } from '../../../api';

interface ReportsTabProps {
  assessmentId: string;
}

export const ReportsTab: React.FC<ReportsTabProps> = ({ assessmentId }) => {
  const [reportMarkdown, setReportMarkdown] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);
  const [exportSuccess, setExportSuccess] = useState<string | null>(null);
  const [selectedFormat, setSelectedFormat] = useState<string>('markdown');

  // Track active assessment to discard stale in-flight responses
  const activeAssessmentRef = useRef(assessmentId);

  const handleGenerate = async () => {
    const currentId = assessmentId;
    setLoading(true);
    setError(null);
    try {
      const res = await generateAssessmentReport(currentId, 'markdown');
      if (activeAssessmentRef.current !== currentId) return;
      setReportMarkdown(res.report_markdown || res.content || '');
    } catch (err: any) {
      if (activeAssessmentRef.current !== currentId) return;
      setError(err.message || 'Report generation failed');
    } finally {
      if (activeAssessmentRef.current === currentId) {
        setLoading(false);
      }
    }
  };

  useEffect(() => {
    activeAssessmentRef.current = assessmentId;
    setReportMarkdown(null);
    setError(null);
    setExportError(null);
    setExportSuccess(null);
    handleGenerate();
  }, [assessmentId]);

  const handleExport = async (format: string = selectedFormat) => {
    const currentId = assessmentId;
    setExporting(true);
    setExportError(null);
    setExportSuccess(null);
    try {
      const res = await exportAssessmentReport(currentId, format);
      if (activeAssessmentRef.current !== currentId) return;

      if (!res || !res.content) {
        throw new Error('Server returned an empty or malformed report export artifact.');
      }

      const mimeType = res.mime_type || (
        format === 'json' ? 'application/json; charset=utf-8' :
        format === 'html' ? 'text/html; charset=utf-8' :
        'text/markdown; charset=utf-8'
      );
      const filename = res.filename || `${currentId}_security_assessment_report.${format === 'json' ? 'json' : format === 'html' ? 'html' : 'md'}`;

      const blob = new Blob([res.content], { type: mimeType });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      setExportSuccess(`Report exported successfully as ${filename} (${res.format.toUpperCase()})`);
    } catch (err: any) {
      if (activeAssessmentRef.current !== currentId) return;
      setExportError(err.message || 'Export failed: unexpected server response.');
    } finally {
      if (activeAssessmentRef.current === currentId) {
        setExporting(false);
      }
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div style={{
        padding: '16px 20px',
        borderRadius: 'var(--radius-lg)',
        background: 'var(--bg-surface)',
        border: '1px solid var(--border-subtle)',
        display: 'flex',
        flexWrap: 'wrap',
        justifyContent: 'space-between',
        alignItems: 'center',
        gap: '12px',
      }}>
        <div>
          <h4 style={{ fontSize: '15px', fontWeight: 600 }}>Production Assessment Report Center</h4>
          <p style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
            Traceable reporting over validated scope, target evidence, and human-verified findings
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          <label htmlFor="report-format-select" style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
            Format:
          </label>
          <select
            id="report-format-select"
            value={selectedFormat}
            onChange={(e) => setSelectedFormat(e.target.value)}
            disabled={exporting}
            style={{
              padding: '6px 10px',
              borderRadius: 'var(--radius-md)',
              border: '1px solid var(--border-subtle)',
              background: 'var(--bg-surface)',
              fontSize: '13px',
              fontWeight: 500,
            }}
          >
            <option value="markdown">Markdown (.md)</option>
            <option value="json">Structured JSON (.json)</option>
            <option value="html">Styled HTML (.html)</option>
          </select>

          <button
            onClick={handleGenerate}
            disabled={loading || exporting}
            style={{
              padding: '6px 14px',
              borderRadius: 'var(--radius-md)',
              border: '1px solid var(--border-subtle)',
              background: 'var(--bg-surface)',
              fontSize: '13px',
              fontWeight: 500,
              cursor: loading || exporting ? 'not-allowed' : 'pointer',
            }}
          >
            {loading ? 'Compiling...' : 'Regenerate Draft'}
          </button>
          <button
            onClick={() => handleExport(selectedFormat)}
            disabled={exporting || loading}
            style={{
              padding: '6px 16px',
              borderRadius: 'var(--radius-md)',
              background: 'var(--accent-primary)',
              color: 'var(--text-inverse)',
              fontSize: '13px',
              fontWeight: 600,
              cursor: exporting || loading ? 'not-allowed' : 'pointer',
              opacity: exporting ? 0.7 : 1,
            }}
          >
            {exporting ? `Exporting ${selectedFormat.toUpperCase()}...` : `Export ${selectedFormat.toUpperCase()}`}
          </button>
        </div>
      </div>

      {/* Export Success Notification */}
      {exportSuccess && (
        <div
          role="status"
          style={{
            padding: '12px 16px',
            borderRadius: 'var(--radius-md)',
            background: 'var(--badge-green-bg)',
            color: 'var(--badge-green-text)',
            border: '1px solid var(--badge-green-border)',
            fontSize: '13px',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
          }}
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <polyline points="20 6 9 17 4 12" />
          </svg>
          <span>{exportSuccess}</span>
        </div>
      )}

      {/* Export Error Notification */}
      {exportError && (
        <div
          role="alert"
          style={{
            padding: '12px 16px',
            borderRadius: 'var(--radius-md)',
            background: 'var(--badge-red-bg)',
            color: 'var(--badge-red-text)',
            border: '1px solid var(--badge-red-border)',
            fontSize: '13px',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
          }}
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <circle cx="12" cy="12" r="10" />
            <line x1="12" y1="8" x2="12" y2="12" />
            <line x1="12" y1="16" x2="12.01" y2="16" />
          </svg>
          <span>{exportError}</span>
        </div>
      )}

      {/* Redaction Vault & Invariant Notice */}
      <div style={{
        padding: '10px 14px',
        borderRadius: 'var(--radius-md)',
        background: 'var(--bg-surface-muted)',
        border: '1px solid var(--border-subtle)',
        fontSize: '12px',
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        color: 'var(--text-secondary)',
      }}>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ flexShrink: 0, color: 'var(--accent-primary)' }} aria-hidden="true">
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
          <path d="M7 11V7a5 5 0 0 1 10 0v4" />
        </svg>
        <span>
          <strong>Redaction Vault Active:</strong> Credentials, session cookies, and private API keys are redacted. Unverified candidate findings are marked with clear epistemic disclaimers.
        </span>
      </div>

      {/* Report Preview */}
      <div style={{
        padding: '24px',
        borderRadius: 'var(--radius-lg)',
        background: 'var(--bg-surface)',
        border: '1px solid var(--border-subtle)',
        minHeight: '400px',
        overflowX: 'auto',
      }}>
        {loading ? (
          <div style={{ textAlign: 'center', padding: '60px', color: 'var(--text-muted)' }}>
            Assembling assessment report from canonical findings and scope records...
          </div>
        ) : error ? (
          <div
            role="alert"
            style={{
              padding: '16px',
              background: 'var(--badge-amber-bg)',
              color: 'var(--badge-amber-text)',
              borderRadius: 'var(--radius-md)',
              fontSize: '13px',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
            }}
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
              <line x1="12" y1="9" x2="12" y2="13" />
              <line x1="12" y1="17" x2="12.01" y2="17" />
            </svg>
            <span>{error}</span>
            <button
              onClick={handleGenerate}
              style={{
                marginLeft: 'auto',
                padding: '4px 10px',
                borderRadius: 'var(--radius-sm)',
                background: 'var(--bg-surface)',
                border: '1px solid var(--border-subtle)',
                fontSize: '12px',
                cursor: 'pointer',
              }}
            >
              Retry
            </button>
          </div>
        ) : reportMarkdown ? (
          <pre style={{
            fontFamily: 'var(--font-mono)',
            fontSize: '12px',
            lineHeight: 1.6,
            whiteSpace: 'pre-wrap',
            color: 'var(--text-primary)',
          }}>
            {reportMarkdown}
          </pre>
        ) : (
          <div style={{ textAlign: 'center', padding: '60px', color: 'var(--text-muted)' }}>
            No report generated yet. Click Regenerate Draft.
          </div>
        )}
      </div>
    </div>
  );
};
