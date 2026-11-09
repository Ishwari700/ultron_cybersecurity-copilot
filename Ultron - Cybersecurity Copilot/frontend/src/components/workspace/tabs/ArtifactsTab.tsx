import React, { useState, useEffect, useRef } from 'react';
import { fetchAssessmentArtifacts, uploadAssessmentArtifact, getArtifactDownloadUrl } from '../../../api';
import type { ArtifactItem } from '../../../types';

interface ArtifactsTabProps {
  assessmentId: string;
}

export const ArtifactsTab: React.FC<ArtifactsTabProps> = ({ assessmentId }) => {
  const [artifacts, setArtifacts] = useState<ArtifactItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [dataError, setDataError] = useState<string | null>(null);
  const [showUploadForm, setShowUploadForm] = useState(false);

  // Upload Form State
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [artifactType, setArtifactType] = useState('HAR');
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [uploadSuccess, setUploadSuccess] = useState<string | null>(null);

  // Stale request guard
  const activeAssessmentRef = useRef(assessmentId);

  const loadArtifacts = async () => {
    const currentId = assessmentId;
    setLoading(true);
    setDataError(null);
    try {
      const data = await fetchAssessmentArtifacts(currentId);
      if (activeAssessmentRef.current !== currentId) return;
      setArtifacts(data);
    } catch (err: any) {
      if (activeAssessmentRef.current !== currentId) return;
      console.error('Failed to load artifacts:', err);
      setDataError(err.message || 'Failed to load artifacts');
    } finally {
      if (activeAssessmentRef.current === currentId) {
        setLoading(false);
      }
    }
  };

  useEffect(() => {
    activeAssessmentRef.current = assessmentId;
    setDataError(null);
    setError(null);
    setUploadSuccess(null);
    loadArtifacts();
  }, [assessmentId]);

  const handleUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedFile) {
      setError('Please select a file to upload.');
      return;
    }
    setUploading(true);
    setError(null);
    setUploadSuccess(null);
    try {
      const res = await uploadAssessmentArtifact(assessmentId, selectedFile, artifactType);
      setSelectedFile(null);
      setShowUploadForm(false);
      setUploadSuccess(`Artifact ${res.artifact?.artifact_id || ''} uploaded successfully and quarantined for security scanning.`);
      await loadArtifacts();
    } catch (err: any) {
      setError(err.message || 'Failed to upload artifact');
    } finally {
      setUploading(false);
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
        justifyContent: 'space-between',
        alignItems: 'center',
      }}>
        <div>
          <h4 style={{ fontSize: '15px', fontWeight: 600 }}>Artifact Registry & Ingestion</h4>
          <p style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
            Assessment-scoped security evidence files. All ingested artifacts enter QUARANTINE by default.
          </p>
        </div>
        <button
          onClick={() => setShowUploadForm(!showUploadForm)}
          style={{
            padding: '6px 14px',
            borderRadius: 'var(--radius-md)',
            background: 'var(--accent-primary)',
            color: 'var(--text-inverse)',
            fontSize: '13px',
            fontWeight: 500,
          }}
        >
          {showUploadForm ? 'Cancel' : '+ Upload Artifact'}
        </button>
      </div>

      {uploadSuccess && (
        <div style={{
          padding: '12px 16px',
          borderRadius: 'var(--radius-md)',
          background: 'var(--badge-green-bg)',
          color: 'var(--badge-green-text)',
          fontSize: '13px',
          border: '1px solid var(--badge-green-border)',
        }}>
          {uploadSuccess}
        </div>
      )}

      {showUploadForm && (
        <form onSubmit={handleUpload} style={{
          padding: '16px 20px',
          borderRadius: 'var(--radius-lg)',
          background: 'var(--bg-surface)',
          border: '1px solid var(--border-subtle)',
          display: 'flex',
          flexDirection: 'column',
          gap: '14px',
        }}>
          <h5 style={{ fontSize: '14px', fontWeight: 600 }}>Upload Genuine Security Artifact</h5>
          <p style={{ fontSize: '12px', color: 'var(--text-muted)', margin: 0 }}>
            Upload raw binary/text files. The server computes authoritative SHA-256 digests and enforces storage containment.
          </p>
          {error && (
            <div style={{ color: 'var(--badge-red-text)', fontSize: '12px' }}>{error}</div>
          )}

          <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '12px' }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)' }}>
                Artifact File *
              </label>
              <input
                type="file"
                onChange={(e) => setSelectedFile(e.target.files?.[0] || null)}
                required
                style={{ padding: '6px 0', fontSize: '13px' }}
              />
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)' }}>
                Artifact Type
              </label>
              <select
                value={artifactType}
                onChange={(e) => setArtifactType(e.target.value)}
                style={{ padding: '8px 10px', fontSize: '13px', borderRadius: 'var(--radius-md)', background: 'var(--bg-surface)' }}
              >
                <option value="HAR">HAR Traffic</option>
                <option value="APK">Android APK</option>
                <option value="DEX">DEX / Smali</option>
                <option value="BINARY">PE / ELF Binary</option>
                <option value="OPENAPI">OpenAPI Spec</option>
                <option value="PCAP">Network PCAP</option>
                <option value="TEXT">Text Log / Output</option>
                <option value="OTHER">Other / Binary</option>
              </select>
            </div>
          </div>

          <div style={{
            padding: '10px 14px',
            borderRadius: 'var(--radius-sm)',
            background: 'var(--bg-surface-muted)',
            border: '1px solid var(--border-subtle)',
            fontSize: '12px',
            color: 'var(--text-secondary)',
          }}>
            <strong>Integrity Notice:</strong> Digest (SHA-256) and exact size will be authoritatively derived server-side. Newly uploaded artifacts are quarantined until reviewed or scanned.
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
            <button
              type="button"
              onClick={() => setShowUploadForm(false)}
              style={{ padding: '6px 12px', fontSize: '12px' }}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={uploading}
              style={{
                padding: '6px 16px',
                background: 'var(--accent-primary)',
                color: '#fff',
                borderRadius: 'var(--radius-md)',
                fontSize: '12px',
                fontWeight: 600,
              }}
            >
              {uploading ? 'Uploading & Hashing...' : 'Upload & Quarantine'}
            </button>
          </div>
        </form>
      )}

      {/* Artifact Listing */}
      <div style={{
        padding: '20px',
        borderRadius: 'var(--radius-lg)',
        background: 'var(--bg-surface)',
        border: '1px solid var(--border-subtle)',
      }}>
        {dataError && (
          <div
            role="alert"
            style={{
              marginBottom: '16px',
              padding: '12px 16px',
              borderRadius: 'var(--radius-md)',
              background: 'var(--badge-red-bg)',
              border: '1px solid var(--badge-red-border)',
              color: 'var(--badge-red-text)',
              fontSize: '13px',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
            }}
          >
            <span>Error loading artifacts: {dataError}</span>
            <button
              onClick={() => loadArtifacts()}
              style={{
                padding: '4px 10px',
                borderRadius: 'var(--radius-sm)',
                background: 'var(--bg-surface)',
                border: '1px solid var(--badge-red-border)',
                color: 'var(--badge-red-text)',
                fontSize: '12px',
                cursor: 'pointer',
              }}
            >
              Retry
            </button>
          </div>
        )}

        {loading ? (
          <div style={{ textAlign: 'center', padding: '32px', color: 'var(--text-muted)' }}>
            Loading artifact registry...
          </div>
        ) : artifacts.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '32px', color: 'var(--text-muted)', fontSize: '13px' }}>
            {dataError ? 'Unable to display artifacts due to an error.' : 'No artifacts ingested for this assessment. Use the button above to upload genuine evidence files.'}
          </div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-subtle)', textAlign: 'left', color: 'var(--text-secondary)' }}>
                <th style={{ padding: '10px 8px' }}>Filename</th>
                <th style={{ padding: '10px 8px' }}>Type</th>
                <th style={{ padding: '10px 8px' }}>Server Integrity (SHA-256)</th>
                <th style={{ padding: '10px 8px' }}>Size</th>
                <th style={{ padding: '10px 8px' }}>Quarantine Status</th>
                <th style={{ padding: '10px 8px' }}>Artifact ID</th>
                <th style={{ padding: '10px 8px', textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {artifacts.map((art) => (
                <tr key={art.artifact_id} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                  <td style={{ padding: '10px 8px', fontWeight: 600 }}>{art.filename}</td>
                  <td style={{ padding: '10px 8px' }}>
                    <span style={{
                      padding: '2px 6px',
                      borderRadius: '4px',
                      fontSize: '11px',
                      background: 'var(--bg-surface-muted)',
                    }}>
                      {art.artifact_type}
                    </span>
                  </td>
                  <td style={{ padding: '10px 8px', fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)' }} title={art.sha256}>
                    {art.sha256 ? `${art.sha256.substring(0, 16)}...` : 'N/A'}
                  </td>
                  <td style={{ padding: '10px 8px', color: 'var(--text-secondary)' }}>
                    {art.byte_size} B
                  </td>
                  <td style={{ padding: '10px 8px' }}>
                    <span style={{
                      padding: '2px 6px',
                      borderRadius: '4px',
                      fontSize: '11px',
                      fontWeight: 600,
                      background: art.quarantine_status === 'VALIDATED' || art.quarantine_status === 'CLEARED'
                        ? 'var(--badge-green-bg)'
                        : 'var(--badge-red-bg)',
                      color: art.quarantine_status === 'VALIDATED' || art.quarantine_status === 'CLEARED'
                        ? 'var(--badge-green-text)'
                        : 'var(--badge-red-text)',
                    }}>
                      {art.quarantine_status}
                    </span>
                  </td>
                  <td style={{ padding: '10px 8px', fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)' }}>
                    {art.artifact_id}
                  </td>
                  <td style={{ padding: '10px 8px', textAlign: 'right' }}>
                    <a
                      href={getArtifactDownloadUrl(assessmentId, art.artifact_id)}
                      download={art.filename}
                      style={{
                        padding: '4px 10px',
                        borderRadius: 'var(--radius-sm)',
                        background: 'var(--bg-surface-muted)',
                        color: 'var(--text-primary)',
                        fontSize: '11px',
                        textDecoration: 'none',
                        border: '1px solid var(--border-subtle)',
                      }}
                    >
                      Download
                    </a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};
