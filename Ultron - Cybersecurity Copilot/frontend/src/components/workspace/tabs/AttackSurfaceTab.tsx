import React, { useState, useEffect, useRef } from 'react';
import { fetchAssessmentAssets, fetchAssessmentObservations } from '../../../api';
import type { AssetItem } from '../../../types';

interface AttackSurfaceTabProps {
  assessmentId: string;
}

export const AttackSurfaceTab: React.FC<AttackSurfaceTabProps> = ({ assessmentId }) => {
  const [assets, setAssets] = useState<AssetItem[]>([]);
  const [observations, setObservations] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [dataError, setDataError] = useState<string | null>(null);

  // Stale request guard
  const activeAssessmentRef = useRef(assessmentId);

  useEffect(() => {
    activeAssessmentRef.current = assessmentId;
    setDataError(null);
    loadData();
  }, [assessmentId]);

  async function loadData() {
    const currentId = assessmentId;
    setLoading(true);
    setDataError(null);
    try {
      const [a, o] = await Promise.all([
        fetchAssessmentAssets(currentId),
        fetchAssessmentObservations(currentId),
      ]);
      if (activeAssessmentRef.current !== currentId) return;
      setAssets(a);
      setObservations(o);
    } catch (err: any) {
      if (activeAssessmentRef.current !== currentId) return;
      console.error('Failed to load attack surface data:', err);
      setDataError(err.message || 'Failed to load attack surface data');
    } finally {
      if (activeAssessmentRef.current === currentId) {
        setLoading(false);
      }
    }
  }

  // Aggregate endpoints from observations
  const endpoints = observations
    .filter((o) => o.observation_type === 'HTTP_ENDPOINT' || o.raw_path || o.canonical_identifier)
    .map((o) => ({
      id: o.observation_id,
      target: o.canonical_identifier,
      method: o.content?.method || 'GET',
      path: o.content?.path || '/',
      status: o.content?.status_code || 200,
    }));

  const assetsByType: Record<string, AssetItem[]> = {};
  assets.forEach((a) => {
    if (!assetsByType[a.asset_type]) assetsByType[a.asset_type] = [];
    assetsByType[a.asset_type].push(a);
  });

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
          <h4 style={{ fontSize: '15px', fontWeight: 600 }}>Attack Surface Map</h4>
          <p style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
            Exposed surfaces, web endpoints, API interfaces, and technology footprints
          </p>
        </div>
        <div style={{
          padding: '4px 10px',
          borderRadius: 'var(--radius-sm)',
          fontSize: '11px',
          background: 'var(--badge-blue-bg)',
          color: 'var(--badge-blue-text)',
        }}>
          Epistemic Rule: Observation-backed routes
        </div>
      </div>

      {/* Error state */}
      {dataError && (
        <div
          role="alert"
          style={{
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
          <span>Error loading attack surface: {dataError}</span>
          <button
            onClick={() => loadData()}
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
        <div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
          Computing attack surface map...
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
          {/* Surface Breakdown by Category */}
          <div style={{
            padding: '20px',
            borderRadius: 'var(--radius-lg)',
            background: 'var(--bg-surface)',
            border: '1px solid var(--border-subtle)',
            display: 'flex',
            flexDirection: 'column',
            gap: '12px',
          }}>
            <h5 style={{ fontSize: '14px', fontWeight: 600 }}>Target Surface Classification</h5>
            {Object.keys(assetsByType).length === 0 ? (
              <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>No assets classified yet.</div>
            ) : (
              Object.entries(assetsByType).map(([type, items]) => (
                <div
                  key={type}
                  style={{
                    padding: '10px 14px',
                    borderRadius: 'var(--radius-md)',
                    background: 'var(--bg-surface-muted)',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                  }}
                >
                  <div>
                    <span style={{ fontWeight: 600, fontSize: '13px' }}>{type}</span>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                      {items.map((i) => i.canonical_identifier).slice(0, 3).join(', ')}
                      {items.length > 3 ? ` (+${items.length - 3} more)` : ''}
                    </div>
                  </div>
                  <span style={{
                    fontWeight: 700,
                    fontSize: '14px',
                    background: 'var(--bg-surface)',
                    padding: '2px 8px',
                    borderRadius: 'var(--radius-sm)',
                    border: '1px solid var(--border-subtle)',
                  }}>
                    {items.length}
                  </span>
                </div>
              ))
            )}
          </div>

          {/* Observed Routes & Interfaces */}
          <div style={{
            padding: '20px',
            borderRadius: 'var(--radius-lg)',
            background: 'var(--bg-surface)',
            border: '1px solid var(--border-subtle)',
            display: 'flex',
            flexDirection: 'column',
            gap: '12px',
          }}>
            <h5 style={{ fontSize: '14px', fontWeight: 600 }}>Observed Routes & Endpoints</h5>
            {endpoints.length === 0 ? (
              <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                No HTTP endpoints observed in telemetry yet. Ingest telemetry or import HAR traffic in the Evidence tab.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '350px', overflowY: 'auto' }}>
                {endpoints.map((ep, idx) => (
                  <div
                    key={idx}
                    style={{
                      padding: '8px 12px',
                      borderRadius: 'var(--radius-md)',
                      background: 'var(--bg-surface-muted)',
                      fontSize: '12px',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      fontFamily: 'var(--font-mono)',
                    }}
                  >
                    <div>
                      <strong style={{ color: ep.method === 'GET' ? 'var(--badge-blue-text)' : 'var(--badge-green-text)', marginRight: '6px' }}>
                        {ep.method}
                      </strong>
                      <span>{ep.target}{ep.path}</span>
                    </div>
                    <span style={{
                      fontSize: '11px',
                      padding: '1px 6px',
                      borderRadius: '4px',
                      background: 'var(--bg-surface)',
                      border: '1px solid var(--border-subtle)',
                    }}>
                      {ep.status}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
