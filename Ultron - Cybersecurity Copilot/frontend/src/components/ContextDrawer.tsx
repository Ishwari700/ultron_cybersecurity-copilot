import React, { useEffect, useState } from 'react';
import {
  fetchApplicationModel,
  fetchInvestigationAudit,
  fetchEvidence,
  fetchGaps,
  fetchInvariants,
} from '../api';
import type { AuditRecord, EvidenceGap, SecurityInvariant } from '../types';

interface ContextDrawerProps {
  investigationId: string;
  initialTab?: string;
  onClose: () => void;
  onOpenImport?: () => void;
  onOpenAddObservation?: () => void;
}

export const ContextDrawer: React.FC<ContextDrawerProps> = ({
  investigationId,
  initialTab = 'evidence',
  onClose,
  onOpenImport,
  onOpenAddObservation,
}) => {
  const [activeTab, setActiveTab] = useState(initialTab);
  const [evidence, setEvidence] = useState<any[]>([]);
  const [expandedObs, setExpandedObs] = useState<Record<string, boolean>>({});
  const [model, setModel] = useState<any | null>(null);
  const [invariants, setInvariants] = useState<SecurityInvariant[]>([]);
  const [gaps, setGaps] = useState<EvidenceGap[]>([]);
  const [audit, setAudit] = useState<AuditRecord[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setActiveTab(initialTab);
  }, [initialTab]);

  const loadData = async () => {
    setLoading(true);
    try {
      if (activeTab === 'evidence') {
        const data = await fetchEvidence(investigationId);
        setEvidence(data);
      } else if (activeTab === 'model') {
        const data = await fetchApplicationModel(investigationId);
        setModel(data);
      } else if (activeTab === 'invariants') {
        const data = await fetchInvariants(investigationId);
        setInvariants(data);
      } else if (activeTab === 'gaps') {
        const data = await fetchGaps(investigationId);
        setGaps(data);
      } else if (activeTab === 'audit') {
        const auditRes = await fetchInvestigationAudit(investigationId, 50);
        setAudit(auditRes.records || []);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [investigationId, activeTab]);

  const toggleObs = (id: string) => {
    setExpandedObs((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  return (
    <div
      style={{
        width: '420px',
        backgroundColor: 'var(--bg-surface)',
        borderLeft: '1px solid var(--border-subtle)',
        display: 'flex',
        flexDirection: 'column',
        height: '100%',
        boxShadow: '-4px 0 16px rgba(0,0,0,0.03)',
        zIndex: 50,
      }}
    >
      {/* Drawer Header */}
      <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-secondary)', letterSpacing: '0.04em' }}>
            INVESTIGATION CONTEXT
          </span>
          <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)' }}>
            Research Graph & Data
          </h3>
        </div>
        <button
          onClick={onClose}
          style={{ fontSize: '16px', color: 'var(--text-muted)', padding: '4px 8px', borderRadius: '4px' }}
        >
          ✕
        </button>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', borderBottom: '1px solid var(--border-subtle)', backgroundColor: 'var(--bg-app)' }}>
        {['evidence', 'model', 'invariants', 'gaps', 'audit'].map((tab) => {
          const isActive = activeTab === tab;
          return (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              style={{
                flex: 1,
                padding: '10px 0',
                fontSize: '12px',
                fontWeight: isActive ? 600 : 500,
                color: isActive ? 'var(--text-primary)' : 'var(--text-secondary)',
                borderBottom: isActive ? '2px solid var(--accent-primary)' : '2px solid transparent',
                textTransform: 'capitalize',
              }}
            >
              {tab}
            </button>
          );
        })}
      </div>

      {/* Drawer Content */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '18px 20px' }}>
        {loading ? (
          <div style={{ fontSize: '13px', color: 'var(--text-muted)', textAlign: 'center', marginTop: '24px' }}>
            Loading context records...
          </div>
        ) : (
          <>
            {activeTab === 'evidence' && (
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                    {evidence.length === 0
                      ? 'Target Telemetry & Observations'
                      : `${evidence.length} observation${evidence.length !== 1 ? 's' : ''}`}
                  </div>
                  <div style={{ display: 'flex', gap: '6px' }}>
                    {onOpenImport && (
                      <button
                        onClick={onOpenImport}
                        className="btn-secondary"
                        style={{ fontSize: '11px', padding: '3px 8px' }}
                      >
                        + Import
                      </button>
                    )}
                    {onOpenAddObservation && (
                      <button
                        onClick={onOpenAddObservation}
                        className="btn-secondary"
                        style={{ fontSize: '11px', padding: '3px 8px' }}
                      >
                        + Add Obs
                      </button>
                    )}
                  </div>
                </div>

                {evidence.length === 0 ? (
                  <div
                    style={{
                      textAlign: 'center',
                      padding: '40px 16px',
                      backgroundColor: 'var(--bg-app)',
                      borderRadius: 'var(--radius-md)',
                      border: '1px dashed var(--border-subtle)',
                      marginTop: '8px',
                    }}
                  >
                    <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '6px' }}>
                      No target evidence yet
                    </div>
                    <p style={{ fontSize: '12.5px', color: 'var(--text-secondary)', marginBottom: '18px', lineHeight: 1.5 }}>
                      Import captured HTTP traffic or add an observation to begin.
                    </p>
                    <div style={{ display: 'flex', gap: '8px', justifyContent: 'center' }}>
                      {onOpenImport && (
                        <button
                          onClick={onOpenImport}
                          className="btn-secondary"
                          style={{ fontSize: '12px', padding: '6px 12px' }}
                        >
                          Import Traffic
                        </button>
                      )}
                      {onOpenAddObservation && (
                        <button
                          onClick={onOpenAddObservation}
                          className="btn-secondary"
                          style={{ fontSize: '12px', padding: '6px 12px' }}
                        >
                          Add Observation
                        </button>
                      )}
                    </div>
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    {evidence.map((ev, i) => {
                      const obsId = ev.observation_id || ev.id || ev.fact_id || `ev-${i}`;
                      const isExpanded = expandedObs[obsId];
                      const isHttp = Boolean(ev.method && ev.raw_path);

                      if (!isHttp) {
                        return (
                          <div key={obsId} className="card-base" style={{ padding: '12px 14px', marginBottom: '8px' }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', fontWeight: 600 }}>{ev.fact_id}</span>
                              <span className="badge badge-green">{ev.certainty}</span>
                            </div>
                            <p style={{ fontSize: '13px', color: 'var(--text-primary)' }}>{ev.statement}</p>
                            <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
                              Tool: {ev.source_tool} | Trust: {ev.trust}
                            </div>
                          </div>
                        );
                      }

                      const statusColor =
                        ev.status_code >= 200 && ev.status_code < 300
                          ? 'var(--badge-green-text, #166534)'
                          : ev.status_code >= 400 && ev.status_code < 500
                          ? 'var(--badge-amber-text, #92400E)'
                          : ev.status_code >= 500
                          ? 'var(--badge-red-text, #991B1B)'
                          : 'var(--text-secondary)';

                      const statusBg =
                        ev.status_code >= 200 && ev.status_code < 300
                          ? 'var(--badge-green-bg, #DCFCE7)'
                          : ev.status_code >= 400 && ev.status_code < 500
                          ? 'var(--badge-amber-bg, #FEF3C7)'
                          : ev.status_code >= 500
                          ? 'var(--badge-red-bg, #FEE2E2)'
                          : 'var(--bg-surface-muted)';

                      return (
                        <div
                          key={obsId}
                          className="card-base"
                          style={{
                            padding: '10px 12px',
                            cursor: 'pointer',
                            border: isExpanded ? '1px solid var(--accent-primary)' : '1px solid var(--border-subtle)',
                            transition: 'all 0.15s ease',
                          }}
                          onClick={() => toggleObs(obsId)}
                        >
                          {/* Summary Row */}
                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '8px' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: 0, flex: 1 }}>
                              <span
                                style={{
                                  fontFamily: 'var(--font-mono)',
                                  fontSize: '11px',
                                  fontWeight: 700,
                                  color: 'var(--text-secondary)',
                                  width: '42px',
                                  flexShrink: 0,
                                }}
                              >
                                {ev.method}
                              </span>
                              <span
                                style={{
                                  fontFamily: 'var(--font-mono)',
                                  fontSize: '12px',
                                  color: 'var(--text-primary)',
                                  whiteSpace: 'nowrap',
                                  overflow: 'hidden',
                                  textOverflow: 'ellipsis',
                                }}
                                title={ev.raw_path}
                              >
                                {ev.raw_path}
                              </span>
                            </div>

                            <span
                              style={{
                                fontFamily: 'var(--font-mono)',
                                fontSize: '11px',
                                fontWeight: 600,
                                color: statusColor,
                                backgroundColor: statusBg,
                                padding: '2px 6px',
                                borderRadius: '4px',
                                flexShrink: 0,
                              }}
                            >
                              {ev.status_code}
                            </span>
                          </div>

                          {/* Expanded Details Pane */}
                          {isExpanded && (
                            <div
                              style={{
                                marginTop: '10px',
                                paddingTop: '10px',
                                borderTop: '1px solid var(--border-subtle)',
                                fontSize: '12px',
                                color: 'var(--text-primary)',
                              }}
                              onClick={(e) => e.stopPropagation()}
                            >
                              {/* Metadata / Provenance */}
                              <div
                                style={{
                                  backgroundColor: 'var(--bg-app)',
                                  padding: '8px 10px',
                                  borderRadius: 'var(--radius-sm)',
                                  marginBottom: '8px',
                                  fontSize: '11px',
                                  color: 'var(--text-secondary)',
                                  display: 'flex',
                                  flexDirection: 'column',
                                  gap: '4px',
                                }}
                              >
                                <div>
                                  <strong style={{ color: 'var(--text-primary)' }}>Host:</strong> {ev.host}
                                </div>
                                {ev.normalized_path && ev.normalized_path !== ev.raw_path && (
                                  <div>
                                    <strong style={{ color: 'var(--text-primary)' }}>Route:</strong>{' '}
                                    <span style={{ fontFamily: 'var(--font-mono)' }}>{ev.normalized_path}</span>
                                  </div>
                                )}
                                <div>
                                  <strong style={{ color: 'var(--text-primary)' }}>Provenance:</strong>{' '}
                                  {ev.source_tool || 'Target Traffic Ingestion'}
                                </div>
                                {ev.transaction_digest && (
                                  <div style={{ wordBreak: 'break-all' }}>
                                    <strong style={{ color: 'var(--text-primary)' }}>Digest:</strong>{' '}
                                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: '10px' }}>
                                      {ev.transaction_digest}
                                    </span>
                                  </div>
                                )}
                                <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '2px' }}>
                                  <span>
                                    {ev.redacted_secret_count > 0
                                      ? `${ev.redacted_secret_count} secrets redacted in RedactionVault`
                                      : 'No secrets detected'}
                                  </span>
                                  {ev.created_at && <span>{ev.created_at.slice(0, 19).replace('T', ' ')}</span>}
                                </div>
                              </div>

                              {/* Researcher Note */}
                              {ev.researcher_note && (
                                <div style={{ marginBottom: '8px', fontSize: '11.5px', fontStyle: 'italic', color: 'var(--text-secondary)' }}>
                                  Note: {ev.researcher_note}
                                </div>
                              )}

                              {/* Request Headers */}
                              {ev.request_headers && Object.keys(ev.request_headers).length > 0 && (
                                <div style={{ marginBottom: '8px' }}>
                                  <div style={{ fontSize: '10.5px', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '3px' }}>
                                    REQUEST HEADERS
                                  </div>
                                  <pre
                                    style={{
                                      fontFamily: 'var(--font-mono)',
                                      fontSize: '11px',
                                      backgroundColor: 'var(--bg-app)',
                                      padding: '6px 8px',
                                      borderRadius: '4px',
                                      overflowX: 'auto',
                                      margin: 0,
                                    }}
                                  >
                                    {Object.entries(ev.request_headers)
                                      .map(([k, v]) => `${k}: ${v}`)
                                      .join('\n')}
                                  </pre>
                                </div>
                              )}

                              {/* Request Body */}
                              {ev.request_body && (
                                <div style={{ marginBottom: '8px' }}>
                                  <div style={{ fontSize: '10.5px', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '3px' }}>
                                    REQUEST BODY
                                  </div>
                                  <pre
                                    style={{
                                      fontFamily: 'var(--font-mono)',
                                      fontSize: '11px',
                                      backgroundColor: 'var(--bg-app)',
                                      padding: '6px 8px',
                                      borderRadius: '4px',
                                      overflowX: 'auto',
                                      maxHeight: '120px',
                                      overflowY: 'auto',
                                      margin: 0,
                                    }}
                                  >
                                    {ev.request_body}
                                  </pre>
                                </div>
                              )}

                              {/* Response Body */}
                              {ev.response_body && (
                                <div>
                                  <div style={{ fontSize: '10.5px', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '3px' }}>
                                    RESPONSE BODY
                                  </div>
                                  <pre
                                    style={{
                                      fontFamily: 'var(--font-mono)',
                                      fontSize: '11px',
                                      backgroundColor: 'var(--bg-app)',
                                      padding: '6px 8px',
                                      borderRadius: '4px',
                                      overflowX: 'auto',
                                      maxHeight: '140px',
                                      overflowY: 'auto',
                                      margin: 0,
                                    }}
                                  >
                                    {ev.response_body}
                                  </pre>
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            )}

            {activeTab === 'model' && model && (
              <div>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '12px' }}>
                  Derived application structure and discovered authorization workflows.
                </div>
                <div style={{ marginBottom: '14px' }}>
                  <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-secondary)' }}>DISCOVERED ASSETS</span>
                  {model.assets?.map((a: any, i: number) => (
                    <div key={i} className="card-base" style={{ padding: '10px 12px', margin: '6px 0', fontSize: '12.5px' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                        <span style={{ fontFamily: 'var(--font-mono)' }}>{a.method} {a.normalized_path}</span>
                        <span className="badge badge-amber">{a.application_mutability}</span>
                      </div>
                    </div>
                  ))}
                </div>

                <div>
                  <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-secondary)' }}>DERIVED WORKFLOWS</span>
                  {model.workflows?.map((wf: any, i: number) => (
                    <div key={i} className="card-base" style={{ padding: '10px 12px', margin: '6px 0', fontSize: '12.5px' }}>
                      <div style={{ fontWeight: 600, marginBottom: '2px' }}>{wf.name}</div>
                      <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-secondary)' }}>
                        {wf.sequence?.join(' → ')}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {activeTab === 'invariants' && (
              <div>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '12px' }}>
                  Formally tracked security invariants governing access boundaries.
                </div>
                {invariants.map((inv, i) => (
                  <div key={i} className="card-base" style={{ padding: '12px 14px', marginBottom: '10px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', fontWeight: 600 }}>{inv.invariant_id}</span>
                      <span className="badge badge-blue">{inv.origin}</span>
                    </div>
                    <p style={{ fontSize: '13px', color: 'var(--text-primary)' }}>{inv.description}</p>
                  </div>
                ))}
              </div>
            )}

            {activeTab === 'gaps' && (
              <div>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '12px' }}>
                  Missing empirical facts required to confirm or falsify security boundaries.
                </div>
                {gaps.map((gap, i) => (
                  <div key={i} className="card-base" style={{ padding: '12px 14px', marginBottom: '10px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', fontWeight: 600 }}>{gap.gap_id}</span>
                      <span className="badge badge-amber">{gap.status}</span>
                    </div>
                    <p style={{ fontSize: '13px', color: 'var(--text-primary)' }}>{gap.description}</p>
                    <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '4px' }}>
                      Suggested Action: <code style={{ fontFamily: 'var(--font-mono)' }}>{gap.suggested_action}</code>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {activeTab === 'audit' && (
              <div>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '12px' }}>
                  Cryptographically chained audit trail verifying sequence integrity.
                </div>
                {audit.map((rec, i) => (
                  <div key={i} className="card-base" style={{ padding: '10px 12px', marginBottom: '8px', fontSize: '12px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontWeight: 600 }}>
                      <span>{rec.event_type}</span>
                      <span style={{ color: 'var(--text-secondary)', fontSize: '11px' }}>{rec.actor}</span>
                    </div>
                    <div style={{ color: 'var(--text-muted)', fontSize: '11px', marginTop: '2px' }}>
                      Subject: {rec.subject_id}
                    </div>
                    {rec.current_hash && (
                      <div style={{ fontFamily: 'var(--font-mono)', fontSize: '10.5px', color: 'var(--text-secondary)', marginTop: '2px', wordBreak: 'break-all' }}>
                        Hash: {rec.current_hash.slice(0, 32)}...
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
};
