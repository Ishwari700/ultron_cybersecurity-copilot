import React, { useState, useEffect, useRef } from 'react';
import {
  fetchAssessmentMemory,
  searchAssessmentMemory,
  listKnowledgeSources,
  uploadKnowledgeSource,
  ingestKnowledgeText,
  importLocalKnowledgeSource,
  deactivateKnowledgeSource,
  retryKnowledgeSource,
  extractKnowledgeGraph,
  auditKnowledgeGraph,
  listIngestionJobs,
  cancelIngestionJob,
  retryIngestionJob,
  retryFailedKnowledgeGraph,
  cancelKnowledgeGraph,
  getKnowledgeGraphStatus,
} from '../../../api';
import type {
  KnowledgeSource,
  GraphAuditResponse,
  IngestionJob,
  SourceGraphStatusResponse,
} from '../../../types';

interface MemoryKnowledgeTabProps {
  assessmentId: string;
}

export const MemoryKnowledgeTab: React.FC<MemoryKnowledgeTabProps> = ({ assessmentId }) => {
  // Main view switcher: 'knowledge_corpus' | 'assessment_memory'
  const [activeSubView, setActiveSubView] = useState<'knowledge_corpus' | 'assessment_memory'>('knowledge_corpus');

  // ---------------------------------------------------------------------------
  // Knowledge Sources State
  // ---------------------------------------------------------------------------
  const [sources, setSources] = useState<KnowledgeSource[]>([]);
  const [sourcesLoading, setSourcesLoading] = useState(false);
  const [sourcesError, setSourcesError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [searchFilter, setSearchFilter] = useState<string>('');

  // Intake Modal State
  const [showIngestModal, setShowIngestModal] = useState(false);
  const [ingestMode, setIngestMode] = useState<'upload' | 'text' | 'local'>('upload');
  const [submitting, setSubmitting] = useState(false);
  const [modalError, setModalError] = useState<string | null>(null);

  // Form Fields
  const [formTitle, setFormTitle] = useState('');
  const [formAuthority, setFormAuthority] = useState('USER_OWNED');
  const [formTags, setFormTags] = useState('');
  const [formContent, setFormContent] = useState('');
  const [formFilename, setFormFilename] = useState('');
  const [formLocalPath, setFormLocalPath] = useState('');
  const [formFile, setFormFile] = useState<File | null>(null);

  // ---------------------------------------------------------------------------
  // Assessment Memory State
  // ---------------------------------------------------------------------------
  const [memorySearchQuery, setMemorySearchQuery] = useState('');
  const [selectedNamespace, setSelectedNamespace] = useState<string>('ALL');
  const [memoryItems, setMemoryItems] = useState<any[]>([]);
  const [searchResults, setSearchResults] = useState<any[] | null>(null);
  const [memoryLoading, setMemoryLoading] = useState(false);
  const [memorySearching, setMemorySearching] = useState(false);
  const [memoryError, setMemoryError] = useState<string | null>(null);

  // ---------------------------------------------------------------------------
  // Ingestion Jobs & Graph State
  // ---------------------------------------------------------------------------
  const [ingestionJobs, setIngestionJobs] = useState<IngestionJob[]>([]);
  const [graphStatuses, setGraphStatuses] = useState<Record<string, SourceGraphStatusResponse>>({});

  const activeAssessmentRef = useRef(assessmentId);

  // ---------------------------------------------------------------------------
  // Data Fetching
  // ---------------------------------------------------------------------------
  const loadIngestionJobs = async () => {
    try {
      const jobs = await listIngestionJobs();
      setIngestionJobs(jobs);
    } catch {
      // Non-blocking poll failure
    }
  };

  const loadKnowledgeSources = async () => {
    setSourcesLoading(true);
    setSourcesError(null);
    try {
      const data = await listKnowledgeSources();
      setSources(data);

      // Concurrently load graph statuses for first 30 sources to show chunk progress/failures
      const statuses: Record<string, SourceGraphStatusResponse> = {};
      await Promise.all(
        data.slice(0, 30).map(async (s) => {
          try {
            const gs = await getKnowledgeGraphStatus(s.source_id);
            statuses[s.source_id] = gs;
          } catch {
            // ignore
          }
        })
      );
      setGraphStatuses(statuses);
    } catch (err: any) {
      setSourcesError(err.message || 'Failed to load knowledge sources');
    } finally {
      setSourcesLoading(false);
    }
  };

  const loadMemory = async () => {
    const currentId = assessmentId;
    setMemoryLoading(true);
    setMemoryError(null);
    try {
      const items = await fetchAssessmentMemory(currentId);
      if (activeAssessmentRef.current !== currentId) return;
      setMemoryItems(items);
    } catch (err: any) {
      if (activeAssessmentRef.current !== currentId) return;
      setMemoryError(err.message || 'Failed to load assessment memory');
    } finally {
      if (activeAssessmentRef.current === currentId) {
        setMemoryLoading(false);
      }
    }
  };

  useEffect(() => {
    activeAssessmentRef.current = assessmentId;
    loadKnowledgeSources();
    loadMemory();
    loadIngestionJobs();

    // Poll ingestion jobs every 3 seconds to keep progress updated across reloads
    const interval = setInterval(() => {
      loadIngestionJobs();
    }, 3000);

    return () => clearInterval(interval);
  }, [assessmentId]);

  // ---------------------------------------------------------------------------
  // Knowledge Actions
  // ---------------------------------------------------------------------------
  const handleIngestSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setModalError(null);
    setSubmitting(true);

    const tagsArray = formTags.split(',').map((t) => t.trim()).filter(Boolean);

    try {
      if (ingestMode === 'upload') {
        if (!formFile) {
          throw new Error('Please select a file to upload');
        }
        const formData = new FormData();
        formData.append('file', formFile);
        if (formTitle.trim()) formData.append('title', formTitle.trim());
        formData.append('authority_level', formAuthority);
        if (tagsArray.length > 0) formData.append('tags', tagsArray.join(','));
        formData.append('async_job', 'true');

        await uploadKnowledgeSource(formData);
      } else if (ingestMode === 'text') {
        if (!formContent.trim()) {
          throw new Error('Please enter text content to ingest');
        }
        const filename = formFilename.trim() || 'document.md';
        await ingestKnowledgeText({
          content: formContent,
          filename,
          title: formTitle.trim() || undefined,
          authority_level: formAuthority,
          tags: tagsArray,
        });
      } else if (ingestMode === 'local') {
        if (!formLocalPath.trim()) {
          throw new Error('Please enter the relative path within data/knowledge/imports/');
        }
        await importLocalKnowledgeSource({
          relative_path: formLocalPath.trim(),
          title: formTitle.trim() || undefined,
          authority_level: formAuthority,
          tags: tagsArray,
        });
      }

      // Reset and refresh
      setShowIngestModal(false);
      resetForm();
      await loadIngestionJobs();
      await loadKnowledgeSources();
    } catch (err: any) {
      setModalError(err.message || 'Ingestion failed');
    } finally {
      setSubmitting(false);
    }
  };

  const handleCancelJob = async (jobId: string) => {
    try {
      await cancelIngestionJob(jobId);
      await loadIngestionJobs();
      await loadKnowledgeSources();
    } catch (err: any) {
      setSourcesError(`Cancel job failed: ${err.message}`);
    }
  };

  const handleRetryJob = async (jobId: string) => {
    try {
      await retryIngestionJob(jobId);
      await loadIngestionJobs();
      await loadKnowledgeSources();
    } catch (err: any) {
      setSourcesError(`Retry job failed: ${err.message}`);
    }
  };

  const resetForm = () => {
    setFormTitle('');
    setFormAuthority('USER_OWNED');
    setFormTags('');
    setFormContent('');
    setFormFilename('');
    setFormLocalPath('');
    setFormFile(null);
    setModalError(null);
  };

  const handleDeactivate = async (sourceId: string) => {
    try {
      await deactivateKnowledgeSource(sourceId);
      await loadKnowledgeSources();
    } catch (err: any) {
      setSourcesError(`Deactivation failed: ${err.message}`);
    }
  };

  const handleRetry = async (sourceId: string) => {
    try {
      await retryKnowledgeSource(sourceId);
      await loadKnowledgeSources();
    } catch (err: any) {
      setSourcesError(`Retry failed: ${err.message}`);
    }
  };

  const [extractingSourceId, setExtractingSourceId] = useState<string | null>(null);
  const [graphFeedback, setGraphFeedback] = useState<string | null>(null);

  const handleExtractGraph = async (sourceId: string) => {
    setExtractingSourceId(sourceId);
    setGraphFeedback(`Starting background graph extraction for '${sourceId}'... (Chat requests have priority and will yield execution)`);
    try {
      const res = await extractKnowledgeGraph(sourceId, undefined, false, undefined, true);
      setGraphFeedback(
        `Graph Extraction initiated for '${sourceId}': ${res.message || res.status}. Extraction runs in background and yields to interactive chat.`
      );
      await loadKnowledgeSources();
    } catch (err: any) {
      setGraphFeedback(`Graph Extraction Error: ${err.message || 'Unknown error'}`);
    } finally {
      setExtractingSourceId(null);
    }
  };

  const handleRetryFailedGraph = async (sourceId: string) => {
    setExtractingSourceId(sourceId);
    setGraphFeedback(`Retrying failed chunks for '${sourceId}'...`);
    try {
      const res = await retryFailedKnowledgeGraph(sourceId);
      setGraphFeedback(
        `Retry completed for '${sourceId}': ${res.entities_persisted} entities, ${res.edges_persisted} edges (${res.source_supported_count} source-supported, ${res.inferred_count} inferred, ${res.rejected_count} rejected).`
      );
      await loadKnowledgeSources();
    } catch (err: any) {
      setGraphFeedback(`Retry Failed Chunks Error: ${err.message || 'Unknown error'}`);
    } finally {
      setExtractingSourceId(null);
    }
  };

  const handleCancelGraph = async (sourceId: string) => {
    try {
      await cancelKnowledgeGraph(sourceId);
      setGraphFeedback(`Graph extraction cancelled for '${sourceId}'. Already committed graph records are preserved.`);
      await loadKnowledgeSources();
    } catch (err: any) {
      setGraphFeedback(`Cancel Extraction Error: ${err.message || 'Unknown error'}`);
    }
  };

  // ---------------------------------------------------------------------------
  // Graph Integrity Audit State (Milestone M9 Stage E)
  // ---------------------------------------------------------------------------
  const [auditResult, setAuditResult] = useState<GraphAuditResponse | null>(null);
  const [auditing, setAuditing] = useState(false);
  const [showAuditPanel, setShowAuditPanel] = useState(false);
  const [auditError, setAuditError] = useState<string | null>(null);

  const handleRunAudit = async () => {
    setAuditing(true);
    setAuditError(null);
    try {
      const res = await auditKnowledgeGraph();
      setAuditResult(res);
      setShowAuditPanel(true);
    } catch (err: any) {
      setAuditError(`Audit failed: ${err.message || 'Unknown error'}`);
    } finally {
      setAuditing(false);
    }
  };

  // ---------------------------------------------------------------------------
  // Memory Retrieval
  // ---------------------------------------------------------------------------
  const handleMemorySearch = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!memorySearchQuery.trim()) {
      setSearchResults(null);
      return;
    }

    const currentId = assessmentId;
    setMemorySearching(true);
    setMemoryError(null);
    try {
      const allowed = selectedNamespace === 'ALL' ? undefined : [selectedNamespace];
      const res = await searchAssessmentMemory(currentId, memorySearchQuery.trim(), allowed);
      if (activeAssessmentRef.current !== currentId) return;
      setSearchResults(res.items || res.results || []);
    } catch (err: any) {
      if (activeAssessmentRef.current !== currentId) return;
      setMemoryError(err.message || 'Memory retrieval failed');
    } finally {
      if (activeAssessmentRef.current === currentId) {
        setMemorySearching(false);
      }
    }
  };

  // ---------------------------------------------------------------------------
  // Filtered Knowledge Sources
  // ---------------------------------------------------------------------------
  const filteredSources = sources.filter((s) => {
    if (statusFilter !== 'ALL' && s.status !== statusFilter) return false;
    if (searchFilter.trim()) {
      const q = searchFilter.toLowerCase();
      const matchTitle = s.title?.toLowerCase().includes(q);
      const matchType = s.source_type?.toLowerCase().includes(q);
      const matchFormat = s.format?.toLowerCase().includes(q);
      const matchTags = s.source_metadata?.tags?.some((t) => t.toLowerCase().includes(q));
      return matchTitle || matchType || matchFormat || matchTags;
    }
    return true;
  });

  const totalChunks = sources.reduce((acc, s) => acc + (s.chunk_count || 0), 0);
  const indexedCount = sources.filter((s) => s.status === 'INDEXED').length;
  const pendingCount = sources.filter((s) => ['PENDING', 'EXTRACTING', 'CHUNKING'].includes(s.status)).length;
  const failedCount = sources.filter((s) => s.status === 'FAILED').length;

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  };

  const getStatusBadgeStyle = (status: string) => {
    switch (status) {
      case 'INDEXED':
        return { bg: 'var(--badge-green-bg, #052e16)', text: 'var(--badge-green-text, #4ade80)', border: 'rgba(74, 222, 128, 0.3)' };
      case 'PENDING':
      case 'EXTRACTING':
      case 'CHUNKING':
        return { bg: 'var(--badge-amber-bg, #451a03)', text: 'var(--badge-amber-text, #fde047)', border: 'rgba(253, 224, 71, 0.3)' };
      case 'FAILED':
        return { bg: 'var(--badge-red-bg, #450a0a)', text: 'var(--badge-red-text, #f87171)', border: 'rgba(248, 113, 113, 0.3)' };
      case 'DEACTIVATED':
      default:
        return { bg: 'var(--bg-surface-muted, #1f2937)', text: 'var(--text-muted, #9ca3af)', border: 'var(--border-subtle, #374151)' };
    }
  };

  const getAuthorityBadgeStyle = (level: string) => {
    switch (level) {
      case 'STANDARD':
        return { bg: '#1e3a8a', text: '#93c5fd' };
      case 'VENDOR_OFFICIAL':
        return { bg: '#312e81', text: '#c7d2fe' };
      case 'RESEARCH_COMMUNITY':
        return { bg: '#064e3b', text: '#a7f3d0' };
      case 'USER_OWNED':
      default:
        return { bg: '#374151', text: '#e5e7eb' };
    }
  };

  // Memory Tiers
  const localCount = memoryItems.filter((m) => !m.namespace || m.namespace === 'ASSESSMENT_LOCAL').length;
  const userCount = memoryItems.filter((m) => m.namespace === 'USER_RESEARCH').length;
  const sharedCount = memoryItems.filter((m) => m.namespace === 'SHARED_RESEARCH').length;
  const globalCount = memoryItems.filter((m) => m.namespace === 'GLOBAL_KNOWLEDGE').length;

  const namespaces = [
    {
      id: 'ALL',
      name: 'All Namespaces',
      description: 'Search across all permitted namespace tiers for this assessment.',
      count: memoryItems.length,
      badge: 'Aggregated',
    },
    {
      id: 'ASSESSMENT_LOCAL',
      name: 'Assessment Local',
      description: 'Private research memory strictly bounded to this assessment container.',
      count: localCount,
      badge: 'Isolated',
    },
    {
      id: 'USER_RESEARCH',
      name: 'User Research',
      description: 'Researcher-specific heuristics and personal analytical observations.',
      count: userCount,
      badge: 'Private',
    },
    {
      id: 'SHARED_RESEARCH',
      name: 'Shared Research',
      description: 'Human-promoted, peer-reviewed reusable attack patterns and PoCs.',
      count: sharedCount,
      badge: 'Governed',
    },
    {
      id: 'GLOBAL_KNOWLEDGE',
      name: 'Global Standards',
      description: 'Authoritative cybersecurity references (OWASP ASVS, CWE, CAPEC, NIST).',
      count: globalCount,
      badge: 'External Reference',
    },
  ];

  const displayedMemoryItems = searchResults !== null
    ? searchResults
    : selectedNamespace === 'ALL'
    ? memoryItems
    : memoryItems.filter((m) => m.namespace === selectedNamespace);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Tab Header & Primary Navigation Toggle */}
      <div
        style={{
          padding: '16px 20px',
          borderRadius: 'var(--radius-lg, 12px)',
          background: 'var(--bg-surface, #111827)',
          border: '1px solid var(--border-subtle, #1f2937)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '12px',
        }}
      >
        <div>
          <h4 style={{ fontSize: '16px', fontWeight: 600, margin: '0 0 4px 0', color: 'var(--text-primary, #f9fafb)' }}>
            Cybersecurity Knowledge & Memory Base
          </h4>
          <p style={{ fontSize: '12px', color: 'var(--text-secondary, #9ca3af)', margin: 0 }}>
            Unified intake for authoritative security documents, RFCs, OWASP guides, and multi-tier assessment memory.
          </p>
        </div>

        {/* Sub-view Segmented Toggle */}
        <div
          style={{
            display: 'flex',
            background: 'var(--bg-surface-muted, #1f2937)',
            padding: '3px',
            borderRadius: 'var(--radius-md, 8px)',
            gap: '2px',
          }}
        >
          <button
            onClick={() => setActiveSubView('knowledge_corpus')}
            data-milestone="Knowledge Corpus (M14)"
            style={{
              padding: '6px 14px',
              borderRadius: '6px',
              border: 'none',
              background: activeSubView === 'knowledge_corpus' ? 'var(--accent-primary, #3b82f6)' : 'transparent',
              color: activeSubView === 'knowledge_corpus' ? '#ffffff' : 'var(--text-secondary, #9ca3af)',
              fontSize: '12px',
              fontWeight: 600,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              transition: 'all 0.15s ease',
            }}
          >
            <span>Knowledge Corpus</span>
            <span
              style={{
                fontSize: '10px',
                padding: '1px 5px',
                borderRadius: '10px',
                background: activeSubView === 'knowledge_corpus' ? 'rgba(255,255,255,0.25)' : 'rgba(0,0,0,0.25)',
              }}
            >
              {sources.length}
            </span>
          </button>

          <button
            onClick={() => setActiveSubView('assessment_memory')}
            data-milestone="Assessment Memory Tiers (M12)"
            style={{
              padding: '6px 14px',
              borderRadius: '6px',
              border: 'none',
              background: activeSubView === 'assessment_memory' ? 'var(--accent-primary, #3b82f6)' : 'transparent',
              color: activeSubView === 'assessment_memory' ? '#ffffff' : 'var(--text-secondary, #9ca3af)',
              fontSize: '12px',
              fontWeight: 600,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              transition: 'all 0.15s ease',
            }}
          >
            <span>Assessment Memory</span>
            <span
              style={{
                fontSize: '10px',
                padding: '1px 5px',
                borderRadius: '10px',
                background: activeSubView === 'assessment_memory' ? 'rgba(255,255,255,0.25)' : 'rgba(0,0,0,0.25)',
              }}
            >
              {memoryItems.length}
            </span>
          </button>
        </div>
      </div>

      {/* --------------------------------------------------------------------- */}
      {/* SUBVIEW 1: KNOWLEDGE CORPUS & INGESTION (M14)                         */}
      {/* --------------------------------------------------------------------- */}
      {activeSubView === 'knowledge_corpus' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {/* Metrics summary banner */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
              gap: '12px',
            }}
          >
            <div
              style={{
                padding: '12px 16px',
                background: 'var(--bg-surface, #111827)',
                borderRadius: 'var(--radius-md, 8px)',
                border: '1px solid var(--border-subtle, #1f2937)',
              }}
            >
              <div style={{ fontSize: '11px', color: 'var(--text-muted, #9ca3af)', textTransform: 'uppercase' }}>
                Total Sources
              </div>
              <div style={{ fontSize: '20px', fontWeight: 700, marginTop: '4px', color: 'var(--text-primary, #f9fafb)' }}>
                {sources.length}
              </div>
            </div>

            <div
              style={{
                padding: '12px 16px',
                background: 'var(--bg-surface, #111827)',
                borderRadius: 'var(--radius-md, 8px)',
                border: '1px solid var(--border-subtle, #1f2937)',
              }}
            >
              <div style={{ fontSize: '11px', color: 'var(--text-muted, #9ca3af)', textTransform: 'uppercase' }}>
                Indexed & Ready
              </div>
              <div style={{ fontSize: '20px', fontWeight: 700, marginTop: '4px', color: '#4ade80' }}>
                {indexedCount}
              </div>
            </div>

            <div
              style={{
                padding: '12px 16px',
                background: 'var(--bg-surface, #111827)',
                borderRadius: 'var(--radius-md, 8px)',
                border: '1px solid var(--border-subtle, #1f2937)',
              }}
            >
              <div style={{ fontSize: '11px', color: 'var(--text-muted, #9ca3af)', textTransform: 'uppercase' }}>
                Extracted Chunks
              </div>
              <div style={{ fontSize: '20px', fontWeight: 700, marginTop: '4px', color: 'var(--accent-primary, #3b82f6)' }}>
                {totalChunks}
              </div>
            </div>

            <div
              style={{
                padding: '12px 16px',
                background: 'var(--bg-surface, #111827)',
                borderRadius: 'var(--radius-md, 8px)',
                border: '1px solid var(--border-subtle, #1f2937)',
              }}
            >
              <div style={{ fontSize: '11px', color: 'var(--text-muted, #9ca3af)', textTransform: 'uppercase' }}>
                Pending / Chunking
              </div>
              <div style={{ fontSize: '20px', fontWeight: 700, marginTop: '4px', color: pendingCount > 0 ? '#fde047' : 'var(--text-muted, #9ca3af)' }}>
                {pendingCount}
              </div>
            </div>

            {failedCount > 0 && (
              <div
                style={{
                  padding: '12px 16px',
                  background: 'rgba(239, 68, 68, 0.1)',
                  borderRadius: 'var(--radius-md, 8px)',
                  border: '1px solid rgba(239, 68, 68, 0.3)',
                }}
              >
                <div style={{ fontSize: '11px', color: '#f87171', textTransform: 'uppercase' }}>
                  Ingestion Failures
                </div>
                <div style={{ fontSize: '20px', fontWeight: 700, marginTop: '4px', color: '#f87171' }}>
                  {failedCount}
                </div>
              </div>
            )}
          </div>

          {/* Persistent Ingestion Job Queue */}
          {ingestionJobs.length > 0 && (
            <div
              style={{
                padding: '16px 20px',
                borderRadius: 'var(--radius-md, 8px)',
                background: 'var(--bg-surface, #111827)',
                border: '1px solid var(--border-subtle, #1f2937)',
                display: 'flex',
                flexDirection: 'column',
                gap: '12px',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
                <div>
                  <h5 style={{ fontSize: '13px', fontWeight: 600, margin: '0 0 2px 0', color: 'var(--text-primary, #f9fafb)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span>Persistent Ingestion Job Queue</span>
                    <span
                      style={{
                        padding: '2px 7px',
                        borderRadius: '10px',
                        fontSize: '10.5px',
                        background: 'rgba(59, 130, 246, 0.15)',
                        color: '#93c5fd',
                        border: '1px solid rgba(59, 130, 246, 0.3)',
                      }}
                    >
                      {ingestionJobs.filter((j) => ['QUEUED', 'PROCESSING', 'STAGED'].includes(j.status)).length} Active
                    </span>
                  </h5>
                  <p style={{ fontSize: '11.5px', color: 'var(--text-secondary, #9ca3af)', margin: 0 }}>
                    FIFO single-worker execution &bull; Persists across page reload & server restart &bull; Safe cancellation preserves committed chunks
                  </p>
                </div>

                <button
                  onClick={loadIngestionJobs}
                  style={{
                    padding: '4px 10px',
                    borderRadius: '4px',
                    background: 'var(--bg-surface-muted, #1f2937)',
                    border: '1px solid var(--border-subtle, #374151)',
                    color: 'var(--text-secondary, #9ca3af)',
                    fontSize: '11px',
                    cursor: 'pointer',
                  }}
                >
                  Refresh Queue
                </button>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {ingestionJobs.slice(0, 10).map((job) => {
                  const isProcessing = job.status === 'PROCESSING';
                  const isQueued = job.status === 'QUEUED';
                  const isFailed = job.status === 'FAILED';
                  const isCancelled = job.status === 'CANCELLED';
                  const isCompleted = job.status === 'COMPLETED';

                  let statusBadgeColor = '#9ca3af';
                  let statusBg = 'var(--bg-surface-muted, #1f2937)';
                  let statusBorder = 'var(--border-subtle, #374151)';
                  if (isProcessing) {
                    statusBadgeColor = '#60a5fa';
                    statusBg = 'rgba(59, 130, 246, 0.15)';
                    statusBorder = 'rgba(59, 130, 246, 0.4)';
                  } else if (isQueued) {
                    statusBadgeColor = '#fde047';
                    statusBg = 'rgba(253, 224, 71, 0.1)';
                    statusBorder = 'rgba(253, 224, 71, 0.3)';
                  } else if (isCompleted) {
                    statusBadgeColor = '#4ade80';
                    statusBg = 'rgba(74, 222, 128, 0.1)';
                    statusBorder = 'rgba(74, 222, 128, 0.3)';
                  } else if (isFailed) {
                    statusBadgeColor = '#f87171';
                    statusBg = 'rgba(239, 68, 68, 0.1)';
                    statusBorder = 'rgba(239, 68, 68, 0.3)';
                  } else if (isCancelled) {
                    statusBadgeColor = '#d1d5db';
                    statusBg = 'rgba(107, 114, 128, 0.15)';
                    statusBorder = 'rgba(107, 114, 128, 0.3)';
                  }

                  let progressPct = 0;
                  let progressDesc = job.phase.replace(/_/g, ' ');
                  if (job.phase === 'EXTRACTING_PDF_TEXT' && job.total_pages > 0) {
                    progressPct = Math.min(100, Math.round((job.completed_pages / job.total_pages) * 100));
                    progressDesc = `Extracting PDF text: Page ${job.completed_pages} of ${job.total_pages} (${progressPct}%)`;
                  } else if ((job.phase === 'CHUNKING' || job.phase === 'STORING_CHUNKS') && job.total_chunks > 0) {
                    progressPct = Math.min(100, Math.round((job.completed_chunks / job.total_chunks) * 100));
                    progressDesc = `Chunking & indexing: Chunk ${job.completed_chunks} of ${job.total_chunks} (${progressPct}%)`;
                  } else if (isCompleted) {
                    progressPct = 100;
                    progressDesc = `Completed: ${job.total_chunks} chunks indexed`;
                  } else if (isQueued) {
                    progressDesc = `In queue (Position #${job.queue_position})`;
                  } else if (isCancelled) {
                    progressDesc = `Cancelled by user (Preserved committed chunks: ${job.completed_chunks}/${job.total_chunks})`;
                  } else if (isFailed) {
                    progressDesc = `Failed during ${job.phase}: ${job.error_message || 'Error occurred'}`;
                  }

                  return (
                    <div
                      key={job.job_id}
                      style={{
                        padding: '10px 14px',
                        borderRadius: '6px',
                        background: 'var(--bg-surface-muted, #1f2937)',
                        border: '1px solid var(--border-subtle, #374151)',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '6px',
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <span style={{ fontWeight: 600, fontSize: '13px', color: '#f3f4f6' }}>
                            {job.filename}
                          </span>
                          <span
                            style={{
                              padding: '1px 6px',
                              borderRadius: '3px',
                              fontSize: '10px',
                              fontWeight: 600,
                              background: 'rgba(255,255,255,0.06)',
                              color: 'var(--text-muted, #9ca3af)',
                            }}
                          >
                            {job.file_type}
                          </span>
                          <span
                            style={{
                              padding: '2px 7px',
                              borderRadius: '10px',
                              fontSize: '10px',
                              fontWeight: 600,
                              background: statusBg,
                              color: statusBadgeColor,
                              border: `1px solid ${statusBorder}`,
                            }}
                          >
                            {job.status}
                          </span>
                        </div>

                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          {(isProcessing || isQueued) && (
                            <button
                              onClick={() => handleCancelJob(job.job_id)}
                              style={{
                                padding: '3px 8px',
                                borderRadius: '4px',
                                background: 'rgba(239, 68, 68, 0.1)',
                                border: '1px solid rgba(239, 68, 68, 0.3)',
                                color: '#f87171',
                                fontSize: '11px',
                                cursor: 'pointer',
                              }}
                              title="Stop this job immediately; already committed chunks in SQLite are preserved."
                            >
                              Stop / Cancel
                            </button>
                          )}

                          {(isFailed || isCancelled) && (
                            <button
                              onClick={() => handleRetryJob(job.job_id)}
                              style={{
                                padding: '3px 8px',
                                borderRadius: '4px',
                                background: 'rgba(59, 130, 246, 0.15)',
                                border: '1px solid rgba(59, 130, 246, 0.4)',
                                color: '#93c5fd',
                                fontSize: '11px',
                                cursor: 'pointer',
                              }}
                              title="Re-enqueue this job, resuming from staged file without re-upload."
                            >
                              Retry Ingestion
                            </button>
                          )}
                        </div>
                      </div>

                      {/* Phase description & progress bar */}
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', color: 'var(--text-secondary, #9ca3af)' }}>
                        <span>{progressDesc}</span>
                        {(isProcessing || isCompleted) && <span>{progressPct}%</span>}
                      </div>

                      {(isProcessing || isCompleted) && (
                        <div
                          style={{
                            height: '4px',
                            borderRadius: '2px',
                            background: 'rgba(255,255,255,0.08)',
                            overflow: 'hidden',
                          }}
                        >
                          <div
                            style={{
                              height: '100%',
                              width: `${progressPct}%`,
                              background: isCompleted ? '#4ade80' : 'var(--accent-primary, #3b82f6)',
                              transition: 'width 0.3s ease',
                            }}
                          />
                        </div>
                      )}

                      {/* Error details if failed */}
                      {isFailed && job.error_message && (
                        <div
                          style={{
                            fontSize: '11px',
                            color: '#f87171',
                            fontFamily: 'var(--font-mono, monospace)',
                            background: 'rgba(239, 68, 68, 0.08)',
                            padding: '4px 8px',
                            borderRadius: '4px',
                          }}
                        >
                          Error: {job.error_message}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Controls Bar: Filter, Search & Add Source Button */}
          <div
            style={{
              padding: '14px 18px',
              borderRadius: 'var(--radius-md, 8px)',
              background: 'var(--bg-surface, #111827)',
              border: '1px solid var(--border-subtle, #1f2937)',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              flexWrap: 'wrap',
              gap: '12px',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flex: 1, minWidth: '280px' }}>
              <input
                type="text"
                placeholder="Filter by title, type, format, or tag..."
                value={searchFilter}
                onChange={(e) => setSearchFilter(e.target.value)}
                style={{
                  flex: 1,
                  padding: '7px 12px',
                  borderRadius: '6px',
                  background: 'var(--bg-surface-muted, #1f2937)',
                  border: '1px solid var(--border-subtle, #374151)',
                  color: 'var(--text-primary, #f9fafb)',
                  fontSize: '12.5px',
                }}
              />

              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                style={{
                  padding: '7px 10px',
                  borderRadius: '6px',
                  background: 'var(--bg-surface-muted, #1f2937)',
                  border: '1px solid var(--border-subtle, #374151)',
                  color: 'var(--text-primary, #f9fafb)',
                  fontSize: '12px',
                  cursor: 'pointer',
                }}
              >
                <option value="ALL">All Statuses</option>
                <option value="INDEXED">INDEXED</option>
                <option value="PENDING">PENDING</option>
                <option value="EXTRACTING">EXTRACTING</option>
                <option value="CHUNKING">CHUNKING</option>
                <option value="FAILED">FAILED</option>
                <option value="DEACTIVATED">DEACTIVATED</option>
              </select>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <button
                onClick={loadKnowledgeSources}
                disabled={sourcesLoading}
                style={{
                  padding: '7px 12px',
                  borderRadius: '6px',
                  background: 'var(--bg-surface-muted, #1f2937)',
                  border: '1px solid var(--border-subtle, #374151)',
                  color: 'var(--text-secondary, #9ca3af)',
                  fontSize: '12px',
                  cursor: sourcesLoading ? 'not-allowed' : 'pointer',
                }}
              >
                {sourcesLoading ? 'Refreshing...' : 'Refresh'}
              </button>

              <button
                onClick={handleRunAudit}
                disabled={auditing}
                style={{
                  padding: '7px 14px',
                  borderRadius: '6px',
                  background: 'var(--bg-surface-muted, #1f2937)',
                  border: '1px solid var(--border-subtle, #374151)',
                  color: '#60a5fa',
                  fontSize: '12px',
                  fontWeight: 600,
                  cursor: auditing ? 'not-allowed' : 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                }}
              >
                <span>{auditing ? 'Auditing...' : '🛡️ Audit Graph Integrity'}</span>
              </button>

              <button
                onClick={() => {
                  resetForm();
                  setShowIngestModal(true);
                }}
                style={{
                  padding: '7px 16px',
                  borderRadius: '6px',
                  background: 'var(--accent-primary, #3b82f6)',
                  color: '#ffffff',
                  border: 'none',
                  fontSize: '12.5px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                }}
              >
                <span>+ Ingest Knowledge Source</span>
              </button>
            </div>
          </div>

          {sourcesError && (
            <div
              style={{
                padding: '10px 14px',
                borderRadius: '6px',
                background: 'rgba(239, 68, 68, 0.15)',
                color: '#f87171',
                border: '1px solid rgba(239, 68, 68, 0.3)',
                fontSize: '12px',
              }}
            >
              {sourcesError}
            </div>
          )}

          {graphFeedback && (
            <div
              style={{
                padding: '10px 14px',
                borderRadius: '6px',
                background: graphFeedback.includes('Error') ? 'rgba(239, 68, 68, 0.15)' : 'rgba(59, 130, 246, 0.15)',
                color: graphFeedback.includes('Error') ? '#f87171' : '#93c5fd',
                border: graphFeedback.includes('Error') ? '1px solid rgba(239, 68, 68, 0.3)' : '1px solid rgba(59, 130, 246, 0.3)',
                fontSize: '12px',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
              }}
            >
              <span>{graphFeedback}</span>
              <button
                onClick={() => setGraphFeedback(null)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: 'inherit',
                  cursor: 'pointer',
                  fontSize: '14px',
                  fontWeight: 'bold',
                }}
              >
                &times;
              </button>
            </div>
          )}

          {auditError && (
            <div
              style={{
                padding: '10px 14px',
                borderRadius: '6px',
                background: 'rgba(239, 68, 68, 0.15)',
                color: '#f87171',
                border: '1px solid rgba(239, 68, 68, 0.3)',
                fontSize: '12px',
              }}
            >
              {auditError}
            </div>
          )}

          {/* Graph Integrity Audit Results Panel (Stage E) */}
          {showAuditPanel && auditResult && (
            <div
              style={{
                padding: '16px',
                borderRadius: '8px',
                background: 'var(--bg-surface-elevated, #111827)',
                border: '1px solid var(--border-subtle, #374151)',
                display: 'flex',
                flexDirection: 'column',
                gap: '12px',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span style={{ fontSize: '14px', fontWeight: 700, color: '#f3f4f6' }}>
                    Graph Integrity & Provenance Audit
                  </span>
                  <span
                    style={{
                      padding: '2px 8px',
                      borderRadius: '4px',
                      fontSize: '11px',
                      fontWeight: 700,
                      background:
                        auditResult.summary.status === 'CLEAN'
                          ? 'rgba(34, 197, 94, 0.2)'
                          : auditResult.summary.status === 'WARNINGS_FOUND'
                          ? 'rgba(234, 179, 8, 0.2)'
                          : 'rgba(239, 68, 68, 0.2)',
                      color:
                        auditResult.summary.status === 'CLEAN'
                          ? '#4ade80'
                          : auditResult.summary.status === 'WARNINGS_FOUND'
                          ? '#facc15'
                          : '#f87171',
                      border:
                        auditResult.summary.status === 'CLEAN'
                          ? '1px solid rgba(34, 197, 94, 0.4)'
                          : auditResult.summary.status === 'WARNINGS_FOUND'
                          ? '1px solid rgba(234, 179, 8, 0.4)'
                          : '1px solid rgba(239, 68, 68, 0.4)',
                    }}
                  >
                    {auditResult.summary.status}
                  </span>
                  <span
                    style={{
                      padding: '2px 6px',
                      borderRadius: '4px',
                      fontSize: '10px',
                      background: 'rgba(59, 130, 246, 0.15)',
                      color: '#93c5fd',
                      border: '1px solid rgba(59, 130, 246, 0.3)',
                    }}
                  >
                    🔒 Read-Only Guaranteed (PRAGMA query_only = ON)
                  </span>
                </div>
                <button
                  onClick={() => setShowAuditPanel(false)}
                  style={{
                    background: 'transparent',
                    border: 'none',
                    color: 'var(--text-muted, #9ca3af)',
                    cursor: 'pointer',
                    fontSize: '14px',
                    fontWeight: 'bold',
                  }}
                >
                  &times;
                </button>
              </div>

              {/* Summary Stats Grid */}
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))',
                  gap: '8px',
                }}
              >
                <div style={{ padding: '8px 12px', background: 'var(--bg-surface-muted, #1f2937)', borderRadius: '6px' }}>
                  <div style={{ fontSize: '10.5px', color: 'var(--text-muted, #9ca3af)' }}>Nodes Examined</div>
                  <div style={{ fontSize: '15px', fontWeight: 700, color: '#f3f4f6' }}>{auditResult.summary.nodes_examined}</div>
                </div>
                <div style={{ padding: '8px 12px', background: 'var(--bg-surface-muted, #1f2937)', borderRadius: '6px' }}>
                  <div style={{ fontSize: '10.5px', color: 'var(--text-muted, #9ca3af)' }}>Edges Examined</div>
                  <div style={{ fontSize: '15px', fontWeight: 700, color: '#f3f4f6' }}>{auditResult.summary.edges_examined}</div>
                </div>
                <div style={{ padding: '8px 12px', background: 'var(--bg-surface-muted, #1f2937)', borderRadius: '6px' }}>
                  <div style={{ fontSize: '10.5px', color: 'var(--text-muted, #9ca3af)' }}>Citations Examined</div>
                  <div style={{ fontSize: '15px', fontWeight: 700, color: '#f3f4f6' }}>{auditResult.summary.provenance_citations_examined}</div>
                </div>
                <div style={{ padding: '8px 12px', background: 'var(--bg-surface-muted, #1f2937)', borderRadius: '6px' }}>
                  <div style={{ fontSize: '10.5px', color: 'var(--text-muted, #9ca3af)' }}>Total Issues</div>
                  <div style={{ fontSize: '15px', fontWeight: 700, color: auditResult.summary.total_issues > 0 ? '#facc15' : '#4ade80' }}>
                    {auditResult.summary.total_issues}
                  </div>
                </div>
                <div style={{ padding: '8px 12px', background: 'var(--bg-surface-muted, #1f2937)', borderRadius: '6px' }}>
                  <div style={{ fontSize: '10.5px', color: 'var(--text-muted, #9ca3af)' }}>Critical / Error</div>
                  <div style={{ fontSize: '15px', fontWeight: 700, color: auditResult.summary.critical_count + auditResult.summary.error_count > 0 ? '#f87171' : '#4ade80' }}>
                    {auditResult.summary.critical_count} / {auditResult.summary.error_count}
                  </div>
                </div>
                <div style={{ padding: '8px 12px', background: 'var(--bg-surface-muted, #1f2937)', borderRadius: '6px' }}>
                  <div style={{ fontSize: '10.5px', color: 'var(--text-muted, #9ca3af)' }}>Warning / Info</div>
                  <div style={{ fontSize: '15px', fontWeight: 700, color: '#93c5fd' }}>
                    {auditResult.summary.warning_count} / {auditResult.summary.info_count}
                  </div>
                </div>
              </div>

              {/* Detected Issues List */}
              {auditResult.issues.length > 0 ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '240px', overflowY: 'auto' }}>
                  <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-muted, #9ca3af)', textTransform: 'uppercase' }}>
                    Identified Issues for Human Review (Audit Only — No Automated Mutations)
                  </div>
                  {auditResult.issues.map((iss) => (
                    <div
                      key={iss.issue_id}
                      style={{
                        padding: '8px 12px',
                        borderRadius: '6px',
                        background: 'var(--bg-surface-muted, #1f2937)',
                        borderLeft: `3px solid ${
                          iss.severity === 'CRITICAL'
                            ? '#ef4444'
                            : iss.severity === 'ERROR'
                            ? '#f97316'
                            : iss.severity === 'WARNING'
                            ? '#eab308'
                            : '#3b82f6'
                        }`,
                        fontSize: '12px',
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2px' }}>
                        <span style={{ fontWeight: 600, color: '#f3f4f6' }}>
                          [{iss.category}] {iss.check_code} &mdash; {iss.record_type} <code style={{ color: '#60a5fa' }}>{iss.record_id}</code>
                        </span>
                        <span
                          style={{
                            fontSize: '10px',
                            fontWeight: 700,
                            color:
                              iss.severity === 'CRITICAL'
                                ? '#ef4444'
                                : iss.severity === 'ERROR'
                                ? '#f97316'
                                : iss.severity === 'WARNING'
                                ? '#eab308'
                                : '#3b82f6',
                          }}
                        >
                          {iss.severity}
                        </span>
                      </div>
                      <div style={{ color: 'var(--text-secondary, #9ca3af)', marginBottom: '4px' }}>{iss.description}</div>
                      <div style={{ fontSize: '11px', color: '#6ee7b7' }}>
                        💡 Resolution: {iss.resolution_hint}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div style={{ padding: '8px 12px', color: '#4ade80', fontSize: '12px' }}>
                  ✓ All checked graph nodes, edges, citations, and lifecycle states passed deterministic audit checks.
                </div>
              )}

              {auditResult.limitations.length > 0 && (
                <div style={{ fontSize: '11px', color: 'var(--text-muted, #9ca3af)', fontStyle: 'italic' }}>
                  Limitations: {auditResult.limitations.join(' | ')}
                </div>
              )}
            </div>
          )}

          {/* Sources List / Grid */}
          {sourcesLoading && sources.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted, #9ca3af)' }}>
              Loading knowledge sources registry...
            </div>
          ) : filteredSources.length === 0 ? (
            <div
              style={{
                textAlign: 'center',
                padding: '40px 20px',
                background: 'var(--bg-surface, #111827)',
                borderRadius: 'var(--radius-lg, 12px)',
                border: '1px solid var(--border-subtle, #1f2937)',
                color: 'var(--text-muted, #9ca3af)',
              }}
            >
              <h5 style={{ fontSize: '14px', color: 'var(--text-secondary, #e5e7eb)', margin: '0 0 6px 0' }}>
                No Knowledge Sources Found
              </h5>
              <p style={{ fontSize: '12px', maxWidth: '460px', margin: '0 auto 16px auto' }}>
                {searchFilter || statusFilter !== 'ALL'
                  ? 'No documents match the current search or status filter.'
                  : 'No authoritative security documents, RFCs, or research papers have been ingested yet.'}
              </p>
              <button
                onClick={() => {
                  resetForm();
                  setShowIngestModal(true);
                }}
                style={{
                  padding: '8px 16px',
                  borderRadius: '6px',
                  background: 'var(--accent-primary, #3b82f6)',
                  color: '#ffffff',
                  border: 'none',
                  fontSize: '12px',
                  fontWeight: 600,
                  cursor: 'pointer',
                }}
              >
                Ingest Your First Source
              </button>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {filteredSources.map((source) => {
                const sStyle = getStatusBadgeStyle(source.status);
                const aStyle = getAuthorityBadgeStyle(source.authority_level);
                return (
                  <div
                    key={source.source_id}
                    style={{
                      padding: '14px 18px',
                      borderRadius: 'var(--radius-md, 8px)',
                      background: 'var(--bg-surface, #111827)',
                      border: '1px solid var(--border-subtle, #1f2937)',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '8px',
                      transition: 'border-color 0.15s ease',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '8px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                        <span style={{ fontWeight: 600, fontSize: '14px', color: 'var(--text-primary, #f9fafb)' }}>
                          {source.title}
                        </span>

                        <span
                          style={{
                            padding: '2px 7px',
                            borderRadius: '4px',
                            fontSize: '10px',
                            fontWeight: 600,
                            background: 'var(--bg-surface-muted, #1f2937)',
                            color: 'var(--text-secondary, #9ca3af)',
                            border: '1px solid var(--border-subtle, #374151)',
                          }}
                        >
                          {source.format}
                        </span>

                        <span
                          style={{
                            padding: '2px 7px',
                            borderRadius: '4px',
                            fontSize: '10px',
                            fontWeight: 600,
                            background: aStyle.bg,
                            color: aStyle.text,
                          }}
                        >
                          {source.authority_level.replace('_', ' ')}
                        </span>

                        <span
                          style={{
                            padding: '2px 7px',
                            borderRadius: '4px',
                            fontSize: '10px',
                            fontWeight: 600,
                            background: 'rgba(59, 130, 246, 0.15)',
                            color: '#93c5fd',
                          }}
                        >
                          {source.source_type}
                        </span>
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span
                          style={{
                            padding: '3px 8px',
                            borderRadius: '12px',
                            fontSize: '10.5px',
                            fontWeight: 600,
                            background: sStyle.bg,
                            color: sStyle.text,
                            border: `1px solid ${sStyle.border}`,
                          }}
                        >
                          {source.status}
                        </span>

                        {source.status === 'FAILED' && (
                          <button
                            onClick={() => handleRetry(source.source_id)}
                            style={{
                              padding: '3px 8px',
                              borderRadius: '4px',
                              background: 'var(--bg-surface-muted, #1f2937)',
                              border: '1px solid var(--border-subtle, #374151)',
                              color: 'var(--text-primary, #f9fafb)',
                              fontSize: '11px',
                              cursor: 'pointer',
                            }}
                          >
                            Retry
                          </button>
                        )}

                        {(source.status === 'INDEXED' || source.status === 'PARTIAL' || source.status === 'SUCCESS') && (() => {
                          const gStatus = graphStatuses[source.source_id];
                          const isExtracting = extractingSourceId === source.source_id || gStatus?.status === 'IN_PROGRESS';
                          const hasFailed = (gStatus?.failed_chunks_count || 0) > 0 || gStatus?.status === 'PARTIALLY_COMPLETED';

                          return (
                            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                              {hasFailed && (
                                <button
                                  onClick={() => handleRetryFailedGraph(source.source_id)}
                                  disabled={extractingSourceId === source.source_id}
                                  style={{
                                    padding: '3px 8px',
                                    borderRadius: '4px',
                                    background: 'rgba(253, 224, 71, 0.15)',
                                    border: '1px solid rgba(253, 224, 71, 0.4)',
                                    color: '#fde047',
                                    fontSize: '11px',
                                    cursor: extractingSourceId === source.source_id ? 'not-allowed' : 'pointer',
                                  }}
                                  title="Retry only failed graph chunks without re-processing successful chunks."
                                >
                                  Retry Failed Chunks ({gStatus?.failed_chunks_count || 0})
                                </button>
                              )}

                              {isExtracting ? (
                                <button
                                  onClick={() => handleCancelGraph(source.source_id)}
                                  style={{
                                    padding: '3px 8px',
                                    borderRadius: '4px',
                                    background: 'rgba(239, 68, 68, 0.1)',
                                    border: '1px solid rgba(239, 68, 68, 0.3)',
                                    color: '#f87171',
                                    fontSize: '11px',
                                    cursor: 'pointer',
                                  }}
                                  title="Stop extraction; already extracted entities and edges are preserved."
                                >
                                  Stop Extraction
                                </button>
                              ) : (
                                <button
                                  onClick={() => handleExtractGraph(source.source_id)}
                                  disabled={extractingSourceId === source.source_id}
                                  style={{
                                    padding: '3px 8px',
                                    borderRadius: '4px',
                                    background: 'rgba(59, 130, 246, 0.15)',
                                    border: '1px solid rgba(59, 130, 246, 0.4)',
                                    color: '#93c5fd',
                                    fontSize: '11px',
                                    cursor: extractingSourceId === source.source_id ? 'not-allowed' : 'pointer',
                                  }}
                                  title="Extract Knowledge Graph entities and relationships from indexed chunks. Yields to interactive chat."
                                >
                                  Extract Graph
                                </button>
                              )}
                            </div>
                          );
                        })()}

                        {source.status === 'INDEXED' && (
                          <button
                            onClick={() => handleDeactivate(source.source_id)}
                            style={{
                              padding: '3px 8px',
                              borderRadius: '4px',
                              background: 'transparent',
                              border: '1px solid rgba(239, 68, 68, 0.4)',
                              color: '#f87171',
                              fontSize: '11px',
                              cursor: 'pointer',
                            }}
                          >
                            Deactivate
                          </button>
                        )}
                      </div>
                    </div>

                    {/* Metadata & Stats Strip */}
                    <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap', fontSize: '11.5px', color: 'var(--text-secondary, #9ca3af)' }}>
                      <span>
                        <strong>{source.chunk_count}</strong> {source.chunk_count === 1 ? 'chunk' : 'chunks'}
                      </span>
                      <span>&bull;</span>
                      <span>{formatBytes(source.byte_size)}</span>
                      <span>&bull;</span>
                      <span style={{ fontFamily: 'var(--font-mono, monospace)', fontSize: '11px' }}>
                        SHA256: {source.sha256 ? `${source.sha256.substring(0, 10)}...${source.sha256.substring(58)}` : 'N/A'}
                      </span>
                      <span>&bull;</span>
                      <span>Updated: {new Date(source.updated_at).toLocaleDateString()}</span>
                    </div>

                    {/* Graph Knowledge Extraction Strip */}
                    {graphStatuses[source.source_id] && (
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '11px', color: 'var(--text-secondary, #9ca3af)', marginTop: '2px', flexWrap: 'wrap' }}>
                        <span style={{ fontWeight: 600, color: 'var(--text-primary, #f3f4f6)' }}>Knowledge Graph:</span>
                        <span style={{ color: '#93c5fd' }}>
                          {graphStatuses[source.source_id].total_entities} entities &bull; {graphStatuses[source.source_id].total_edges} edges ({graphStatuses[source.source_id].source_supported_edges} source-supported, {graphStatuses[source.source_id].inferred_edges} inferred)
                        </span>
                        {graphStatuses[source.source_id].status === 'PARTIALLY_COMPLETED' && (
                          <span style={{ color: '#fde047', background: 'rgba(253, 224, 71, 0.12)', border: '1px solid rgba(253, 224, 71, 0.3)', padding: '1px 6px', borderRadius: '4px', fontSize: '10px', fontWeight: 600 }}>
                            Partially Extracted
                          </span>
                        )}
                        {graphStatuses[source.source_id].status === 'IN_PROGRESS' && (
                          <span style={{ color: '#60a5fa', background: 'rgba(59, 130, 246, 0.12)', border: '1px solid rgba(59, 130, 246, 0.3)', padding: '1px 6px', borderRadius: '4px', fontSize: '10px', fontWeight: 600 }}>
                            Extraction in progress (Yields to interactive chat)
                          </span>
                        )}
                      </div>
                    )}

                    {/* Tags */}
                    {source.source_metadata?.tags && source.source_metadata.tags.length > 0 && (
                      <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', marginTop: '2px' }}>
                        {source.source_metadata.tags.map((t, idx) => (
                          <span
                            key={idx}
                            style={{
                              padding: '1px 6px',
                              borderRadius: '3px',
                              fontSize: '10.5px',
                              background: 'var(--bg-surface-muted, #1f2937)',
                              color: 'var(--text-muted, #9ca3af)',
                            }}
                          >
                            #{t}
                          </span>
                        ))}
                      </div>
                    )}

                    {/* Error display if failed */}
                    {source.status === 'FAILED' && source.error_message && (
                      <div
                        style={{
                          marginTop: '4px',
                          padding: '6px 10px',
                          borderRadius: '4px',
                          background: 'rgba(239, 68, 68, 0.1)',
                          color: '#f87171',
                          fontSize: '11px',
                          fontFamily: 'var(--font-mono, monospace)',
                        }}
                      >
                        Error: {source.error_message}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* --------------------------------------------------------------------- */}
      {/* SUBVIEW 2: ASSESSMENT MEMORY TIERS (M12)                              */}
      {/* --------------------------------------------------------------------- */}
      {activeSubView === 'assessment_memory' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
          {/* Namespace Cards Grid */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
              gap: '14px',
            }}
          >
            {namespaces.map((ns) => (
              <div
                key={ns.id}
                onClick={() => {
                  setSelectedNamespace(ns.id);
                  setSearchResults(null);
                }}
                style={{
                  padding: '14px 16px',
                  borderRadius: 'var(--radius-md, 8px)',
                  background: selectedNamespace === ns.id ? 'var(--bg-surface-muted, #1f2937)' : 'var(--bg-surface, #111827)',
                  border: selectedNamespace === ns.id ? '2px solid var(--accent-primary, #3b82f6)' : '1px solid var(--border-subtle, #1f2937)',
                  cursor: 'pointer',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '6px',
                  transition: 'all 0.15s ease',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontWeight: 600, fontSize: '13px', color: 'var(--text-primary, #f9fafb)' }}>
                    {ns.name}
                  </span>
                  <span
                    style={{
                      fontSize: '10px',
                      padding: '2px 6px',
                      borderRadius: '4px',
                      background: 'var(--bg-surface-muted, #1f2937)',
                      color: 'var(--text-secondary, #9ca3af)',
                    }}
                  >
                    {ns.badge}
                  </span>
                </div>
                <p style={{ fontSize: '11px', color: 'var(--text-secondary, #9ca3af)', margin: 0 }}>
                  {ns.description}
                </p>
                <div style={{ marginTop: 'auto', fontSize: '11px', color: 'var(--text-muted, #9ca3af)' }}>
                  Items: <strong>{ns.count}</strong>
                </div>
              </div>
            ))}
          </div>

          {/* Memory Search Bar */}
          <div
            style={{
              padding: '20px',
              borderRadius: 'var(--radius-lg, 12px)',
              background: 'var(--bg-surface, #111827)',
              border: '1px solid var(--border-subtle, #1f2937)',
              display: 'flex',
              flexDirection: 'column',
              gap: '14px',
            }}
          >
            <h5 style={{ fontSize: '14px', fontWeight: 600, margin: 0, color: 'var(--text-primary, #f9fafb)' }}>
              Hybrid Memory & Knowledge Retrieval
            </h5>
            <form onSubmit={handleMemorySearch} style={{ display: 'flex', gap: '10px' }}>
              <input
                type="text"
                placeholder="Search research patterns, negative controls, and prior verified techniques..."
                value={memorySearchQuery}
                onChange={(e) => setMemorySearchQuery(e.target.value)}
                style={{
                  flex: 1,
                  padding: '8px 12px',
                  fontSize: '13px',
                  borderRadius: '6px',
                  background: 'var(--bg-surface-muted, #1f2937)',
                  border: '1px solid var(--border-subtle, #374151)',
                  color: 'var(--text-primary, #f9fafb)',
                }}
              />
              <button
                type="submit"
                disabled={memorySearching}
                style={{
                  padding: '8px 16px',
                  background: 'var(--accent-primary, #3b82f6)',
                  color: '#fff',
                  borderRadius: 'var(--radius-md, 6px)',
                  fontSize: '13px',
                  fontWeight: 600,
                  cursor: memorySearching ? 'not-allowed' : 'pointer',
                  border: 'none',
                }}
              >
                {memorySearching ? 'Retrieving...' : 'Retrieve'}
              </button>
              {searchResults !== null && (
                <button
                  type="button"
                  onClick={() => {
                    setSearchResults(null);
                    setMemorySearchQuery('');
                  }}
                  style={{
                    padding: '8px 12px',
                    background: 'var(--bg-surface, #111827)',
                    border: '1px solid var(--border-subtle, #374151)',
                    borderRadius: 'var(--radius-md, 6px)',
                    fontSize: '12px',
                    color: 'var(--text-secondary, #9ca3af)',
                    cursor: 'pointer',
                  }}
                >
                  Clear Search
                </button>
              )}
            </form>

            {memoryError && (
              <div
                role="alert"
                style={{
                  padding: '12px',
                  borderRadius: 'var(--radius-sm, 6px)',
                  background: 'rgba(239, 68, 68, 0.15)',
                  color: '#f87171',
                  fontSize: '12px',
                }}
              >
                {memoryError}
              </div>
            )}

            <div
              style={{
                fontSize: '12px',
                color: 'var(--text-muted, #9ca3af)',
                background: 'var(--bg-surface-muted, #1f2937)',
                padding: '12px 16px',
                borderRadius: 'var(--radius-sm, 6px)',
              }}
            >
              <strong>Invariant M13-09:</strong> Recalled memory serves as contextual heuristic and research inspiration. It cannot authorize target testing or substitute for canonical target observation.
            </div>

            {/* Memory Item List */}
            <div style={{ marginTop: '10px' }}>
              {memoryLoading ? (
                <div style={{ textAlign: 'center', padding: '24px', color: 'var(--text-muted, #9ca3af)' }}>
                  Loading memory index...
                </div>
              ) : displayedMemoryItems.length === 0 ? (
                <div
                  style={{
                    textAlign: 'center',
                    padding: '24px',
                    background: 'var(--bg-surface-muted, #1f2937)',
                    borderRadius: 'var(--radius-md, 8px)',
                    color: 'var(--text-muted, #9ca3af)',
                    fontSize: '12.5px',
                  }}
                >
                  {searchResults !== null
                    ? 'No memory records match the search query.'
                    : 'No memory items recorded in this namespace.'}
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  {displayedMemoryItems.map((item, idx) => (
                    <div
                      key={item.memory_id || item.id || idx}
                      style={{
                        padding: '12px 16px',
                        borderRadius: 'var(--radius-md, 8px)',
                        background: 'var(--bg-surface, #111827)',
                        border: '1px solid var(--border-subtle, #1f2937)',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '6px',
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span style={{ fontWeight: 600, fontSize: '13px', color: 'var(--text-primary, #f9fafb)' }}>
                          {item.title || item.memory_id || `Memory Item ${idx + 1}`}
                        </span>
                        <span
                          style={{
                            padding: '2px 6px',
                            borderRadius: '4px',
                            fontSize: '10px',
                            background: 'var(--bg-surface-muted, #1f2937)',
                            color: 'var(--text-secondary, #9ca3af)',
                            fontFamily: 'var(--font-mono, monospace)',
                          }}
                        >
                          {item.namespace || 'ASSESSMENT_LOCAL'}
                        </span>
                      </div>
                      <p style={{ fontSize: '12px', color: 'var(--text-secondary, #9ca3af)', margin: 0, whiteSpace: 'pre-wrap' }}>
                        {item.content || item.summary || ''}
                      </p>
                      {item.epistemic_status && (
                        <div style={{ fontSize: '10.5px', color: 'var(--text-muted, #9ca3af)' }}>
                          Epistemic Status: <strong>{item.epistemic_status}</strong> &bull; Authority: {item.authority_level || 'USER'}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* --------------------------------------------------------------------- */}
      {/* INTAKE MODAL (File Upload, Direct Text, Local Import)                 */}
      {/* --------------------------------------------------------------------- */}
      {showIngestModal && (
        <div
          role="dialog"
          aria-modal="true"
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0, 0, 0, 0.75)',
            backdropFilter: 'blur(4px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
            padding: '20px',
          }}
        >
          <div
            style={{
              background: 'var(--bg-surface, #111827)',
              borderRadius: 'var(--radius-lg, 12px)',
              border: '1px solid var(--border-subtle, #374151)',
              width: '100%',
              maxWidth: '600px',
              maxHeight: '90vh',
              overflowY: 'auto',
              display: 'flex',
              flexDirection: 'column',
              boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.5)',
            }}
          >
            {/* Modal Header */}
            <div
              style={{
                padding: '16px 20px',
                borderBottom: '1px solid var(--border-subtle, #1f2937)',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
              }}
            >
              <h3 style={{ fontSize: '16px', fontWeight: 600, margin: 0, color: 'var(--text-primary, #f9fafb)' }}>
                Ingest Cybersecurity Knowledge Source
              </h3>
              <button
                onClick={() => setShowIngestModal(false)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  fontSize: '18px',
                  color: 'var(--text-muted, #9ca3af)',
                  cursor: 'pointer',
                }}
              >
                &times;
              </button>
            </div>

            {/* Modal Body */}
            <form onSubmit={handleIngestSubmit} style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
              {modalError && (
                <div
                  style={{
                    padding: '10px 14px',
                    borderRadius: '6px',
                    background: 'rgba(239, 68, 68, 0.15)',
                    color: '#f87171',
                    border: '1px solid rgba(239, 68, 68, 0.3)',
                    fontSize: '12px',
                  }}
                >
                  {modalError}
                </div>
              )}

              {/* Mode Selector Tabs */}
              <div
                style={{
                  display: 'flex',
                  background: 'var(--bg-surface-muted, #1f2937)',
                  padding: '3px',
                  borderRadius: '6px',
                  gap: '2px',
                }}
              >
                <button
                  type="button"
                  onClick={() => setIngestMode('upload')}
                  style={{
                    flex: 1,
                    padding: '6px 10px',
                    borderRadius: '4px',
                    border: 'none',
                    background: ingestMode === 'upload' ? 'var(--accent-primary, #3b82f6)' : 'transparent',
                    color: ingestMode === 'upload' ? '#ffffff' : 'var(--text-secondary, #9ca3af)',
                    fontSize: '12px',
                    fontWeight: 600,
                    cursor: 'pointer',
                  }}
                >
                  Upload File (PDF / MD / TXT)
                </button>

                <button
                  type="button"
                  onClick={() => setIngestMode('text')}
                  style={{
                    flex: 1,
                    padding: '6px 10px',
                    borderRadius: '4px',
                    border: 'none',
                    background: ingestMode === 'text' ? 'var(--accent-primary, #3b82f6)' : 'transparent',
                    color: ingestMode === 'text' ? '#ffffff' : 'var(--text-secondary, #9ca3af)',
                    fontSize: '12px',
                    fontWeight: 600,
                    cursor: 'pointer',
                  }}
                >
                  Direct Markdown / Text
                </button>

                <button
                  type="button"
                  onClick={() => setIngestMode('local')}
                  style={{
                    flex: 1,
                    padding: '6px 10px',
                    borderRadius: '4px',
                    border: 'none',
                    background: ingestMode === 'local' ? 'var(--accent-primary, #3b82f6)' : 'transparent',
                    color: ingestMode === 'local' ? '#ffffff' : 'var(--text-secondary, #9ca3af)',
                    fontSize: '12px',
                    fontWeight: 600,
                    cursor: 'pointer',
                  }}
                >
                  Local Imports Dir
                </button>
              </div>

              {/* Common Fields: Title & Authority Level */}
              <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '12px' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '11.5px', color: 'var(--text-secondary, #9ca3af)', marginBottom: '4px' }}>
                    Document Title (Optional)
                  </label>
                  <input
                    type="text"
                    placeholder="e.g. RFC 6749: OAuth 2.0 Authorization"
                    value={formTitle}
                    onChange={(e) => setFormTitle(e.target.value)}
                    style={{
                      width: '100%',
                      padding: '8px 10px',
                      borderRadius: '6px',
                      background: 'var(--bg-surface-muted, #1f2937)',
                      border: '1px solid var(--border-subtle, #374151)',
                      color: 'var(--text-primary, #f9fafb)',
                      fontSize: '12px',
                      boxSizing: 'border-box',
                    }}
                  />
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '11.5px', color: 'var(--text-secondary, #9ca3af)', marginBottom: '4px' }}>
                    Authority Level
                  </label>
                  <select
                    value={formAuthority}
                    onChange={(e) => setFormAuthority(e.target.value)}
                    style={{
                      width: '100%',
                      padding: '8px 10px',
                      borderRadius: '6px',
                      background: 'var(--bg-surface-muted, #1f2937)',
                      border: '1px solid var(--border-subtle, #374151)',
                      color: 'var(--text-primary, #f9fafb)',
                      fontSize: '12px',
                      boxSizing: 'border-box',
                      cursor: 'pointer',
                    }}
                  >
                    <option value="STANDARD">STANDARD (RFC, IETF)</option>
                    <option value="VENDOR_OFFICIAL">VENDOR OFFICIAL</option>
                    <option value="RESEARCH_COMMUNITY">RESEARCH COMMUNITY</option>
                    <option value="USER_OWNED">USER OWNED</option>
                  </select>
                </div>
              </div>

              {/* Tags Field */}
              <div>
                <label style={{ display: 'block', fontSize: '11.5px', color: 'var(--text-secondary, #9ca3af)', marginBottom: '4px' }}>
                  Tags (comma-separated)
                </label>
                <input
                  type="text"
                  placeholder="oauth, authentication, rfc, asvs"
                  value={formTags}
                  onChange={(e) => setFormTags(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '8px 10px',
                    borderRadius: '6px',
                    background: 'var(--bg-surface-muted, #1f2937)',
                    border: '1px solid var(--border-subtle, #374151)',
                    color: 'var(--text-primary, #f9fafb)',
                    fontSize: '12px',
                    boxSizing: 'border-box',
                  }}
                />
              </div>

              {/* Ingest Mode 1: File Upload */}
              {ingestMode === 'upload' && (
                <div>
                  <label style={{ display: 'block', fontSize: '11.5px', color: 'var(--text-secondary, #9ca3af)', marginBottom: '4px' }}>
                    Choose Document File (.pdf, .md, .txt, .html)
                  </label>
                  <input
                    type="file"
                    accept=".pdf,.md,.txt,.html,.json"
                    onChange={(e) => setFormFile(e.target.files?.[0] || null)}
                    style={{
                      width: '100%',
                      padding: '10px',
                      borderRadius: '6px',
                      background: 'var(--bg-surface-muted, #1f2937)',
                      border: '1px dashed var(--border-subtle, #374151)',
                      color: 'var(--text-primary, #f9fafb)',
                      fontSize: '12px',
                      boxSizing: 'border-box',
                      cursor: 'pointer',
                    }}
                  />
                  <span style={{ fontSize: '11px', color: 'var(--text-muted, #9ca3af)', display: 'block', marginTop: '4px' }}>
                    Supports raw PDF extraction (pdfplumber/pypdf fallback), Markdown headers, and RFC text.
                  </span>
                </div>
              )}

              {/* Ingest Mode 2: Direct Text */}
              {ingestMode === 'text' && (
                <>
                  <div>
                    <label style={{ display: 'block', fontSize: '11.5px', color: 'var(--text-secondary, #9ca3af)', marginBottom: '4px' }}>
                      Filename / Identifier
                    </label>
                    <input
                      type="text"
                      placeholder="advisory-cve-2024-xxxx.md"
                      value={formFilename}
                      onChange={(e) => setFormFilename(e.target.value)}
                      style={{
                        width: '100%',
                        padding: '8px 10px',
                        borderRadius: '6px',
                        background: 'var(--bg-surface-muted, #1f2937)',
                        border: '1px solid var(--border-subtle, #374151)',
                        color: 'var(--text-primary, #f9fafb)',
                        fontSize: '12px',
                        boxSizing: 'border-box',
                      }}
                    />
                  </div>
                  <div>
                    <label style={{ display: 'block', fontSize: '11.5px', color: 'var(--text-secondary, #9ca3af)', marginBottom: '4px' }}>
                      Content (Markdown or Plain Text)
                    </label>
                    <textarea
                      rows={8}
                      placeholder="# Security Analysis&#10;&#10;Enter security technical specifications, CWE details, or RFC contents here..."
                      value={formContent}
                      onChange={(e) => setFormContent(e.target.value)}
                      style={{
                        width: '100%',
                        padding: '10px',
                        borderRadius: '6px',
                        background: 'var(--bg-surface-muted, #1f2937)',
                        border: '1px solid var(--border-subtle, #374151)',
                        color: 'var(--text-primary, #f9fafb)',
                        fontSize: '12px',
                        fontFamily: 'var(--font-mono, monospace)',
                        boxSizing: 'border-box',
                        resize: 'vertical',
                      }}
                    />
                  </div>
                </>
              )}

              {/* Ingest Mode 3: Local Directory Import */}
              {ingestMode === 'local' && (
                <div>
                  <label style={{ display: 'block', fontSize: '11.5px', color: 'var(--text-secondary, #9ca3af)', marginBottom: '4px' }}>
                    Relative Path inside data/knowledge/imports/
                  </label>
                  <input
                    type="text"
                    placeholder="e.g. rfcs/rfc6749.txt or owasp/asvs-v4.md"
                    value={formLocalPath}
                    onChange={(e) => setFormLocalPath(e.target.value)}
                    style={{
                      width: '100%',
                      padding: '8px 10px',
                      borderRadius: '6px',
                      background: 'var(--bg-surface-muted, #1f2937)',
                      border: '1px solid var(--border-subtle, #374151)',
                      color: 'var(--text-primary, #f9fafb)',
                      fontSize: '12px',
                      boxSizing: 'border-box',
                    }}
                  />
                  <div
                    style={{
                      marginTop: '8px',
                      padding: '8px 12px',
                      borderRadius: '4px',
                      background: 'rgba(59, 130, 246, 0.1)',
                      border: '1px solid rgba(59, 130, 246, 0.25)',
                      fontSize: '11px',
                      color: '#93c5fd',
                    }}
                  >
                    Directory containment enforced. Path traversal (e.g. `../`) will be rejected. Files must reside within `data/knowledge/imports/`.
                  </div>
                </div>
              )}

              {/* Modal Action Buttons */}
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'flex-end',
                  gap: '10px',
                  marginTop: '8px',
                }}
              >
                <button
                  type="button"
                  onClick={() => setShowIngestModal(false)}
                  style={{
                    padding: '8px 16px',
                    borderRadius: '6px',
                    background: 'var(--bg-surface-muted, #1f2937)',
                    border: '1px solid var(--border-subtle, #374151)',
                    color: 'var(--text-secondary, #9ca3af)',
                    fontSize: '12px',
                    cursor: 'pointer',
                  }}
                >
                  Cancel
                </button>

                <button
                  type="submit"
                  disabled={submitting}
                  style={{
                    padding: '8px 20px',
                    borderRadius: '6px',
                    background: 'var(--accent-primary, #3b82f6)',
                    color: '#ffffff',
                    border: 'none',
                    fontSize: '12.5px',
                    fontWeight: 600,
                    cursor: submitting ? 'not-allowed' : 'pointer',
                  }}
                >
                  {submitting ? 'Ingesting & Chunking...' : 'Start Ingestion'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
