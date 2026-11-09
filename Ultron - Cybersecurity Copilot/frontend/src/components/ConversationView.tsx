import React, { useEffect, useRef, useState } from 'react';
import type { CascadeExecutionTrace, ChatMessage, ExperimentObject, IngestionResult } from '../types';
import { fetchCascadeTrace } from '../api';
import { InvariantCard } from './cards/InvariantCard';
import { HypothesisCard } from './cards/HypothesisCard';
import { ExperimentCard } from './cards/ExperimentCard';
import { ObservationCard } from './cards/ObservationCard';
import { AuditCard } from './cards/AuditCard';
import { getImportPresentation } from '../utils/importPresentation';
import { LargeResponseView } from './LargeResponseView';

interface ConversationViewProps {
  messages: ChatMessage[];
  loading?: boolean;
  evidenceCount?: number;
  importSummary?: IngestionResult | null;
  targetHost?: string;
  onOpenImport?: () => void;
  onOpenAddObservation?: () => void;
  onViewEvidence?: () => void;
  onStartAnalysis?: () => void;
  onRetryMessage?: (content: string, failedId: string) => Promise<void>;
  onValidateExperiment: (id: string) => Promise<any>;
  onApproveExperiment: (id: string, actor: string, ack: boolean, notes: string) => Promise<any>;
  onRejectExperiment: (id: string) => Promise<any>;
  onExecuteExperiment: (id: string) => Promise<any>;
  onOpenDrawer: (tab: string) => void;
  onSendFollowUp?: (prompt: string) => void;
  onUpdateMessageContent?: (messageId: string, newContent: string) => void;
  onEditPrompt?: (messageId: string, newContent: string) => Promise<void>;
}

export const ConversationView: React.FC<ConversationViewProps> = ({
  messages,
  loading = false,
  evidenceCount = 0,
  importSummary = null,
  targetHost = '',
  onOpenImport,
  onOpenAddObservation,
  onViewEvidence,
  onStartAnalysis,
  onRetryMessage,
  onValidateExperiment,
  onApproveExperiment,
  onRejectExperiment,
  onExecuteExperiment,
  onOpenDrawer,
  onSendFollowUp,
  onUpdateMessageContent,
  onEditPrompt,
}) => {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [expandedTraces, setExpandedTraces] = useState<Record<string, boolean>>({});
  const [loadedTraces, setLoadedTraces] = useState<Record<string, CascadeExecutionTrace>>({});
  const [loadingTraces, setLoadingTraces] = useState<Record<string, boolean>>({});
  const [showDetails, setShowDetails] = useState<Record<string, boolean>>({});
  const [editingMessageId, setEditingMessageId] = useState<string | null>(null);
  const [editPromptContent, setEditPromptContent] = useState<string>('');
  const [isSavingEdit, setIsSavingEdit] = useState(false);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages, loading]);

  const toggleTrace = async (msgId: string, traceId: string) => {
    const willExpand = !expandedTraces[msgId];
    setExpandedTraces((prev) => ({ ...prev, [msgId]: willExpand }));

    if (willExpand && !loadedTraces[traceId]) {
      setLoadingTraces((prev) => ({ ...prev, [traceId]: true }));
      try {
        const trace = await fetchCascadeTrace(traceId);
        setLoadedTraces((prev) => ({ ...prev, [traceId]: trace }));
      } catch (err) {
        console.error(`Failed to load trace ${traceId}:`, err);
      } finally {
        setLoadingTraces((prev) => ({ ...prev, [traceId]: false }));
      }
    }
  };

  if (messages.length === 0) {
    if (importSummary) {
      const presentation = getImportPresentation(importSummary, targetHost);
      const isDupeOnly = presentation.isAllDuplicates;
      const isOutOfScopeOnly = presentation.isAllOutOfScope;
      const isParseErrorOnly = presentation.isAllParseFailures;

      return (
        <div
          style={{
            flex: 1,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '40px 24px',
            textAlign: 'center',
          }}
        >
          <h2
            style={{
              fontSize: '20px',
              fontWeight: 500,
              color: 'var(--text-primary)',
              marginBottom: '12px',
              letterSpacing: '-0.01em',
            }}
          >
            {presentation.headline}
          </h2>
          <div
            style={{
              backgroundColor: 'var(--bg-app)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-md)',
              padding: '16px 22px',
              maxWidth: '420px',
              width: '100%',
              marginBottom: '20px',
              textAlign: 'left',
            }}
          >
            <div style={{ fontSize: '13px', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: '6px' }}>
              {isDupeOnly ? (
                <>
                  <div style={{ color: 'var(--text-primary)', fontWeight: 500 }}>
                    {presentation.submessage}
                  </div>
                  <div><strong>{presentation.counts.duplicates}</strong> duplicate transaction{presentation.counts.duplicates === 1 ? '' : 's'} skipped (already present)</div>
                  {presentation.counts.redactedSecrets > 0 && (
                    <div><strong>{presentation.counts.redactedSecrets}</strong> sensitive tokens redacted</div>
                  )}
                </>
              ) : isOutOfScopeOnly ? (
                <>
                  <div style={{ color: 'var(--badge-amber-text)', fontWeight: 500 }}>
                    {presentation.submessage}
                  </div>
                  <div><strong>{presentation.counts.outOfScope}</strong> out-of-scope transaction{presentation.counts.outOfScope === 1 ? '' : 's'} excluded</div>
                </>
              ) : isParseErrorOnly ? (
                <>
                  <div style={{ color: 'var(--badge-red-text)', fontWeight: 500 }}>
                    {presentation.submessage}
                  </div>
                  <div><strong>{presentation.counts.parseFailures}</strong> parsing failure{presentation.counts.parseFailures === 1 ? '' : 's'}</div>
                </>
              ) : (
                <>
                  {presentation.counts.added > 0 && (
                    <div style={{ color: 'var(--badge-green-text)', fontWeight: 500 }}>
                      ✓ <strong>{presentation.counts.added}</strong> new observation{presentation.counts.added === 1 ? '' : 's'} added
                    </div>
                  )}
                  {presentation.counts.duplicates > 0 && (
                    <div><strong>{presentation.counts.duplicates}</strong> duplicate transaction{presentation.counts.duplicates === 1 ? '' : 's'} skipped</div>
                  )}
                  {presentation.counts.outOfScope > 0 && (
                    <div style={{ color: 'var(--badge-amber-text)' }}>
                      <strong>{presentation.counts.outOfScope}</strong> out-of-scope excluded
                    </div>
                  )}
                  {presentation.counts.redactedSecrets > 0 && (
                    <div><strong>{presentation.counts.redactedSecrets}</strong> sensitive tokens redacted</div>
                  )}
                  {presentation.counts.parseFailures > 0 && (
                    <div style={{ color: 'var(--badge-red-text)' }}>
                      <strong>{presentation.counts.parseFailures}</strong> parsing failures
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
          <div style={{ display: 'flex', gap: '10px' }}>
            {(presentation.counts.added > 0 || isDupeOnly) && onViewEvidence && (
              <button onClick={onViewEvidence} className="btn-secondary" style={{ padding: '8px 16px', fontSize: '13px' }}>
                View Evidence
              </button>
            )}
            {(presentation.counts.added > 0 || isDupeOnly) && onStartAnalysis && (
              <button onClick={onStartAnalysis} className="btn-primary" style={{ padding: '8px 18px', fontSize: '13.5px' }}>
                Start Security Analysis
              </button>
            )}
            {(isOutOfScopeOnly || isParseErrorOnly) && onOpenImport && (
              <button onClick={onOpenImport} className="btn-primary" style={{ padding: '8px 18px', fontSize: '13.5px' }}>
                Import In-Scope Traffic
              </button>
            )}
          </div>
        </div>
      );
    }

    if (evidenceCount > 0) {
      return (
        <div
          style={{
            flex: 1,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '40px 24px',
            textAlign: 'center',
          }}
        >
          <h2
            style={{
              fontSize: '22px',
              fontWeight: 500,
              color: 'var(--text-primary)',
              marginBottom: '8px',
              letterSpacing: '-0.01em',
            }}
          >
            {evidenceCount} Target Observation{evidenceCount !== 1 ? 's' : ''} Ready
          </h2>
          <p
            style={{
              fontSize: '14px',
              color: 'var(--text-muted)',
              maxWidth: '460px',
              lineHeight: 1.6,
              marginBottom: '20px',
            }}
          >
            Ask a security question, analyze invariants, or inspect evidence.
          </p>
          <div style={{ display: 'flex', gap: '10px', justifyContent: 'center' }}>
            {onViewEvidence && (
              <button onClick={onViewEvidence} className="btn-secondary" style={{ padding: '8px 16px', fontSize: '13px' }}>
                View Evidence
              </button>
            )}
            {onStartAnalysis && (
              <button onClick={onStartAnalysis} className="btn-primary" style={{ padding: '8px 18px', fontSize: '13.5px' }}>
                Start Security Analysis
              </button>
            )}
          </div>
        </div>
      );
    }

    return (
      <div
        style={{
          flex: 1,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '40px 24px',
          textAlign: 'center',
        }}
      >
        <div style={{
          width: '52px',
          height: '52px',
          borderRadius: '14px',
          background: 'linear-gradient(135deg, rgba(229, 9, 20, 0.22) 0%, rgba(229, 9, 20, 0.05) 100%)',
          border: '1px solid rgba(229, 9, 20, 0.35)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          marginBottom: '18px',
          boxShadow: 'var(--accent-glow-subtle)',
        }}>
          <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="var(--accent-primary)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 2L3 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z" />
            <path d="M12 8v5" />
            <circle cx="12" cy="16" r="1.2" fill="var(--accent-primary)" />
          </svg>
        </div>
        <h2
          style={{
            fontSize: '22px',
            fontWeight: 600,
            color: 'var(--text-primary)',
            marginBottom: '8px',
            letterSpacing: '-0.01em',
          }}
        >
          Ultron Intelligence Ready
        </h2>
        <p
          style={{
            fontSize: '14px',
            color: 'var(--text-muted)',
            maxWidth: '460px',
            lineHeight: 1.6,
            marginBottom: '20px',
          }}
        >
          Import captured target traffic or add an observation to initiate autonomous security invariant modeling.
        </p>
        <div style={{ display: 'flex', gap: '10px', justifyContent: 'center' }}>
          {onOpenImport && (
            <button
              onClick={onOpenImport}
              className="btn-primary"
              style={{ padding: '8px 18px', fontSize: '13.5px' }}
            >
              Import Traffic
            </button>
          )}
          {onOpenAddObservation && (
            <button
              onClick={onOpenAddObservation}
              className="btn-secondary"
              style={{ padding: '8px 16px', fontSize: '13px' }}
            >
              Add Observation
            </button>
          )}
        </div>
      </div>
    );
  }

  return (
    <div
      ref={scrollRef}
      style={{
        flex: 1,
        overflowY: 'auto',
        padding: '24px 28px',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
      }}
    >
      <div style={{ maxWidth: '780px', width: '100%' }}>
        {importSummary && (() => {
          const presentation = getImportPresentation(importSummary, targetHost);
          return (
            <div
              style={{
                backgroundColor: 'var(--bg-app)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-md)',
                padding: '12px 18px',
                marginBottom: '24px',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
              }}
            >
              <div style={{ fontSize: '12.5px', color: 'var(--text-secondary)' }}>
                {presentation.isAllDuplicates ? (
                  <span>
                    <strong>All imported transactions were already present.</strong> No new observations were created ({presentation.counts.duplicates} duplicate transactions skipped).
                  </span>
                ) : presentation.isAllOutOfScope ? (
                  <span style={{ color: 'var(--badge-amber-text)' }}>
                    All transactions were out of scope for <strong>{targetHost || 'target'}</strong> ({presentation.counts.outOfScope} excluded).
                  </span>
                ) : presentation.isAllParseFailures ? (
                  <span style={{ color: 'var(--badge-red-text)' }}>
                    Import failed due to syntax errors ({presentation.counts.parseFailures} parsing errors).
                  </span>
                ) : (
                  <span>
                    {presentation.counts.added > 0 && (
                      <span style={{ color: 'var(--badge-green-text)', fontWeight: 500 }}>
                        ✓ <strong>{presentation.counts.added}</strong> observations added
                      </span>
                    )}
                    {presentation.counts.duplicates > 0 && (
                      <span> · <strong>{presentation.counts.duplicates}</strong> duplicates skipped</span>
                    )}
                    {presentation.counts.outOfScope > 0 && (
                      <span style={{ color: 'var(--badge-amber-text)' }}> · <strong>{presentation.counts.outOfScope}</strong> out of scope</span>
                    )}
                    {presentation.counts.redactedSecrets > 0 && (
                      <span> · {presentation.counts.redactedSecrets} secrets redacted</span>
                    )}
                    {presentation.counts.parseFailures > 0 && (
                      <span style={{ color: 'var(--badge-red-text)' }}> · {presentation.counts.parseFailures} errors</span>
                    )}
                  </span>
                )}
              </div>
              {onViewEvidence && (
                <button
                  onClick={onViewEvidence}
                  className="btn-secondary"
                  style={{ fontSize: '11.5px', padding: '3px 9px' }}
                >
                  View Evidence
                </button>
              )}
            </div>
          );
        })()}

        {messages.map((msg) => {
          const isUser = msg.sender === 'user';
          const isSystem = msg.sender === 'system';

          if (isSystem) {
            return (
              <div
                key={msg.id}
                style={{
                  textAlign: 'center',
                  fontSize: '12px',
                  color: 'var(--text-muted)',
                  margin: '16px 0',
                  padding: '5px 12px',
                  backgroundColor: 'var(--bg-surface-muted)',
                  borderRadius: 'var(--radius-sm)',
                  display: 'inline-block',
                }}
              >
                {msg.content}
              </div>
            );
          }

          const hasTrace = Boolean(msg.cascade_trace_id);
          const traceId = msg.cascade_trace_id || '';
          const isTraceExpanded = expandedTraces[msg.id];
          const traceData = loadedTraces[traceId];
          const isTraceLoading = loadingTraces[traceId];

          return (
            <div
              key={msg.id}
              style={{
                marginBottom: '28px',
                display: 'flex',
                flexDirection: 'column',
                alignItems: isUser ? 'flex-end' : 'flex-start',
              }}
            >
              {/* Sender label */}
              <div
                style={{
                  fontSize: '11.5px',
                  fontWeight: 500,
                  color: 'var(--text-muted)',
                  marginBottom: '6px',
                }}
              >
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                  {!isUser && <span className="ultron-pulse-dot" style={{ width: '6px', height: '6px' }} />}
                  <span style={{ fontWeight: isUser ? 500 : 700, color: isUser ? 'var(--text-muted)' : '#F87171' }}>
                    {isUser ? 'You' : 'Ultron'}
                  </span>
                </span>
              </div>

              {/* Message Content Container */}
              {isUser ? (
                editingMessageId === msg.id ? (
                  <div
                    style={{
                      width: '100%',
                      maxWidth: '85%',
                      backgroundColor: 'var(--bg-surface)',
                      border: '1px solid var(--accent-primary)',
                      borderRadius: 'var(--radius-lg)',
                      padding: '12px 14px',
                      boxShadow: 'var(--shadow-subtle)',
                    }}
                  >
                    <textarea
                      value={editPromptContent}
                      onChange={(e) => setEditPromptContent(e.target.value)}
                      disabled={isSavingEdit}
                      aria-label="Edit prompt"
                      rows={Math.max(2, editPromptContent.split('\n').length)}
                      style={{
                        width: '100%',
                        border: 'none',
                        outline: 'none',
                        backgroundColor: 'transparent',
                        fontSize: '14.5px',
                        lineHeight: 1.6,
                        color: 'var(--text-primary)',
                        resize: 'vertical',
                        minHeight: '60px',
                        fontFamily: 'inherit',
                        whiteSpace: 'pre-wrap',
                      }}
                    />
                    <div
                      style={{
                        display: 'flex',
                        justifyContent: 'flex-end',
                        gap: '8px',
                        marginTop: '8px',
                      }}
                    >
                      <button
                        type="button"
                        onClick={() => {
                          setEditingMessageId(null);
                          setEditPromptContent('');
                        }}
                        disabled={isSavingEdit}
                        style={{
                          padding: '4px 10px',
                          fontSize: '12px',
                          borderRadius: 'var(--radius-sm)',
                          border: '1px solid var(--border-subtle)',
                          backgroundColor: 'var(--bg-surface-hover)',
                          color: 'var(--text-secondary)',
                          cursor: isSavingEdit ? 'not-allowed' : 'pointer',
                        }}
                      >
                        Cancel
                      </button>
                      <button
                        type="button"
                        onClick={async () => {
                          if (isSavingEdit || !editPromptContent.trim()) return;
                          setIsSavingEdit(true);
                          try {
                            if (onEditPrompt) {
                              await onEditPrompt(msg.id, editPromptContent.trim());
                            }
                            setEditingMessageId(null);
                            setEditPromptContent('');
                          } finally {
                            setIsSavingEdit(false);
                          }
                        }}
                        disabled={isSavingEdit || !editPromptContent.trim()}
                        style={{
                          padding: '4px 12px',
                          fontSize: '12px',
                          fontWeight: 600,
                          borderRadius: 'var(--radius-sm)',
                          border: 'none',
                          backgroundColor: 'var(--accent-primary)',
                          color: '#FFFFFF',
                          cursor: isSavingEdit || !editPromptContent.trim() ? 'not-allowed' : 'pointer',
                        }}
                      >
                        {isSavingEdit ? 'Saving…' : 'Save & Regenerate'}
                      </button>
                    </div>
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', maxWidth: '85%' }}>
                    <div
                      style={{
                        backgroundColor: 'var(--bg-surface-hover)',
                        padding: '10px 16px',
                        borderRadius: 'var(--radius-lg)',
                        fontSize: '14.5px',
                        lineHeight: 1.6,
                        color: 'var(--text-primary)',
                        whiteSpace: 'pre-line',
                        wordBreak: 'break-word',
                      }}
                    >
                      {msg.content}
                    </div>
                    {onEditPrompt && (
                      <button
                        type="button"
                        onClick={() => {
                          setEditingMessageId(msg.id);
                          setEditPromptContent(msg.content);
                        }}
                        aria-label="Edit prompt"
                        style={{
                          marginTop: '4px',
                          background: 'none',
                          border: 'none',
                          color: 'var(--text-muted)',
                          fontSize: '11px',
                          cursor: 'pointer',
                          padding: '2px 4px',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '4px',
                          transition: 'color 0.15s ease',
                        }}
                        onMouseEnter={(e) => {
                          e.currentTarget.style.color = 'var(--text-primary)';
                        }}
                        onMouseLeave={(e) => {
                          e.currentTarget.style.color = 'var(--text-muted)';
                        }}
                      >
                        Edit
                      </button>
                    )}
                  </div>
                )
              ) : (
                <div style={{ width: '100%' }}>
                  <LargeResponseView
                    message={msg}
                    onSendFollowUp={onSendFollowUp}
                    onUpdateMessageContent={onUpdateMessageContent}
                  />
                </div>
              )}

              {/* Delivery status for user messages */}
              {isUser && msg.delivery_status === 'sending' && (
                <div style={{ marginTop: '4px', fontSize: '11px', color: 'var(--text-muted)', fontStyle: 'italic' }}>
                  Sending...
                </div>
              )}
              {isUser && msg.delivery_status === 'failed' && (
                <div style={{ marginTop: '4px', display: 'flex', alignItems: 'center', gap: '8px', fontSize: '11.5px' }}>
                  <span style={{ color: '#DC2626', fontWeight: 500 }}>Not delivered</span>
                  {onRetryMessage && (
                    <button
                      onClick={() => onRetryMessage(msg.content, msg.id)}
                      style={{
                        background: 'none',
                        border: 'none',
                        color: 'var(--accent-primary)',
                        textDecoration: 'underline',
                        cursor: 'pointer',
                        padding: 0,
                        fontSize: '11.5px',
                        fontWeight: 600,
                      }}
                    >
                      Retry
                    </button>
                  )}
                </div>
              )}

              {/* Structured Cards */}
              {!isUser && msg.structured_type === 'INVARIANT' && msg.structured_data && (
                <div style={{ width: '100%', marginTop: '10px' }}>
                  <InvariantCard
                    data={msg.structured_data}
                    onViewDetails={() => onOpenDrawer('invariants')}
                  />
                </div>
              )}

              {!isUser && msg.structured_type === 'HYPOTHESIS' && msg.structured_data && (
                <div style={{ width: '100%', marginTop: '10px' }}>
                  <HypothesisCard
                    data={msg.structured_data}
                    onInspectExperiment={() => onOpenDrawer('experiments')}
                  />
                </div>
              )}

              {!isUser && msg.structured_type === 'EXPERIMENT' && msg.structured_data && (
                <div style={{ width: '100%', marginTop: '10px' }}>
                  <ExperimentCard
                    data={msg.structured_data as ExperimentObject}
                    onValidate={onValidateExperiment}
                    onApprove={onApproveExperiment}
                    onReject={onRejectExperiment}
                    onExecute={onExecuteExperiment}
                  />
                </div>
              )}

              {!isUser && msg.structured_type === 'OBSERVATION' && msg.structured_data && (
                <div style={{ width: '100%', marginTop: '10px' }}>
                  <ObservationCard data={msg.structured_data.observation || msg.structured_data} />
                </div>
              )}

              {!isUser && msg.structured_type === 'AUDIT' && msg.structured_data && (
                <div style={{ width: '100%', marginTop: '10px' }}>
                  <AuditCard data={msg.structured_data} />
                </div>
              )}

              {/* Progressive Disclosure: AI Runtime Observability */}
              {!isUser && hasTrace && (
                <div style={{ marginTop: '8px', display: 'flex', flexDirection: 'column', width: '100%' }}>
                  <div>
                      <button
                        onClick={() => toggleTrace(msg.id, traceId)}
                        style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '6px',
                          fontSize: '11.5px',
                          color: 'var(--text-muted)',
                          padding: '3px 0',
                          cursor: 'pointer',
                          transition: 'color 0.15s ease',
                        }}
                        onMouseEnter={(e) => (e.currentTarget.style.color = 'var(--text-secondary)')}
                        onMouseLeave={(e) => (e.currentTarget.style.color = 'var(--text-muted)')}
                      >
                        <span
                          style={{
                            width: '5px',
                            height: '5px',
                            borderRadius: '50%',
                            backgroundColor: '#2D6A4F',
                          }}
                        />
                        <span>Local AI · Cascade completed</span>
                        <span style={{ fontSize: '10px' }}>{isTraceExpanded ? '▴' : '▾'}</span>
                      </button>

                      {/* Expandable Restrained Activity Sequence */}
                      {isTraceExpanded && (
                        <div
                          style={{
                            marginTop: '6px',
                            padding: '12px 16px',
                            backgroundColor: 'var(--bg-surface-muted)',
                            borderRadius: 'var(--radius-md)',
                            border: '1px solid var(--border-subtle)',
                            maxWidth: '500px',
                            width: '100%',
                          }}
                        >
                          <div
                            style={{
                              fontSize: '11px',
                              fontWeight: 600,
                              color: 'var(--text-muted)',
                              letterSpacing: '0.04em',
                              marginBottom: '8px',
                            }}
                          >
                            AI RUNTIME
                          </div>

                          {isTraceLoading ? (
                            <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                              Loading runtime trace...
                            </div>
                          ) : traceData ? (
                            <div>
                              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                                {traceData.stages && traceData.stages.map((stg, i) => {
                                  let summaryLabel = stg.stage_name;
                                  if (stg.stage_name.includes('3B')) {
                                    summaryLabel = `Analyzed with ${stg.model_name || 'qwen2.5-coder:3b'}`;
                                  } else if (stg.stage_name.includes('Routing')) {
                                    summaryLabel = traceData.escalated
                                      ? 'Routed to deeper reasoning'
                                      : 'Terminated benign at 3B triage';
                                  } else if (stg.stage_name.includes('Handoff')) {
                                    summaryLabel = 'Passed immutable context packet';
                                  } else if (stg.stage_name.includes('7B')) {
                                    summaryLabel = `Completed deeper review with ${stg.model_name || 'qwen2.5-coder:7b'}`;
                                  }

                                  const isOk = stg.status === 'COMPLETED';
                                  const isSkipped = stg.status === 'SKIPPED';

                                  return (
                                    <div
                                      key={i}
                                      style={{
                                        display: 'flex',
                                        alignItems: 'baseline',
                                        justifyContent: 'space-between',
                                        fontSize: '12.5px',
                                        color: 'var(--text-primary)',
                                      }}
                                    >
                                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                        <span style={{ color: isOk ? '#2D6A4F' : isSkipped ? 'var(--text-muted)' : '#9E2A2B', fontSize: '12px' }}>
                                          {isOk ? '✓' : isSkipped ? '–' : '✕'}
                                        </span>
                                        <span>{summaryLabel}</span>
                                      </div>
                                      {stg.latency_seconds > 0 && (
                                        <span style={{ fontSize: '11px', color: 'var(--text-muted)', marginLeft: '12px', flexShrink: 0 }}>
                                          {stg.latency_seconds}s
                                        </span>
                                      )}
                                    </div>
                                  );
                                })}
                              </div>

                              <div
                                style={{
                                  marginTop: '10px',
                                  paddingTop: '8px',
                                  borderTop: '1px solid var(--border-subtle)',
                                  display: 'flex',
                                  justifyContent: 'space-between',
                                  alignItems: 'center',
                                  fontSize: '11px',
                                  color: 'var(--text-muted)',
                                }}
                              >
                                <span>Completed in {traceData.total_latency_seconds}s</span>
                                <button
                                  onClick={() =>
                                    setShowDetails((prev) => ({ ...prev, [msg.id]: !prev[msg.id] }))
                                  }
                                  style={{
                                    textDecoration: 'underline',
                                    cursor: 'pointer',
                                    background: 'none',
                                    border: 'none',
                                    color: 'inherit',
                                    fontSize: '11px',
                                  }}
                                >
                                  {showDetails[msg.id] ? 'Hide technical details' : 'Technical details'}
                                </button>
                              </div>

                              {showDetails[msg.id] && (
                                <div
                                  style={{
                                    marginTop: '8px',
                                    padding: '8px 10px',
                                    backgroundColor: 'var(--bg-surface)',
                                    borderRadius: 'var(--radius-sm)',
                                    fontSize: '11px',
                                    fontFamily: 'var(--font-mono)',
                                    color: 'var(--text-secondary)',
                                    display: 'flex',
                                    flexDirection: 'column',
                                    gap: '3px',
                                  }}
                                >
                                  <div>Trace ID: {traceData.run_id}</div>
                                  {traceData.target_endpoint && <div>Target: {traceData.target_endpoint}</div>}
                                  {traceData.routing_decision && <div>Routing: {traceData.routing_decision}</div>}
                                  {traceData.handoff_provenance_hash && (
                                    <div>Provenance: {traceData.handoff_provenance_hash.slice(0, 16)}...</div>
                                  )}
                                </div>
                              )}
                            </div>
                          ) : (
                            <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                              Trace unavailable.
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                </div>
              )}
            </div>
          );
        })}

        {/* Assistant Thinking / Processing Indicator */}
        {loading && (
          <div
            style={{
              marginBottom: '28px',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'flex-start',
              width: '100%',
            }}
          >
            <div
              style={{
                fontSize: '11.5px',
                fontWeight: 500,
                color: 'var(--text-muted)',
                marginBottom: '6px',
              }}
            >
              <span>Assistant</span>
            </div>
            <div
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '8px',
                padding: '8px 14px',
                backgroundColor: 'var(--bg-surface-muted)',
                borderRadius: 'var(--radius-lg)',
                fontSize: '13.5px',
                color: 'var(--text-secondary)',
              }}
            >
              <span
                style={{
                  width: '6px',
                  height: '6px',
                  borderRadius: '50%',
                  backgroundColor: 'var(--accent-primary)',
                  display: 'inline-block',
                }}
              />
              <span>Reviewing the available evidence…</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
