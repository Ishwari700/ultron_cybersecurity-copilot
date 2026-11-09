import React, { useEffect, useState } from 'react';
import {
  approveExperiment,
  createInvestigation,
  deleteInvestigation,
  executeExperiment,
  fetchInvestigation,
  fetchInvestigations,
  fetchStatus,
  loadDemoFixture,
  rejectExperiment,
  renameInvestigation,
  sendMessage,
  stopInvestigationGeneration,
  editAndRegeneratePrompt,
  validateExperiment,
  fetchCurrentUser,
  logout,
} from './api';
import { Composer } from './components/Composer';
import { ContextDrawer } from './components/ContextDrawer';
import { ConversationView } from './components/ConversationView';
import { InvestigationHeader } from './components/InvestigationHeader';
import { NewInvestigationModal } from './components/NewInvestigationModal';
import { Sidebar } from './components/Sidebar';
import { SystemStatusModal } from './components/SystemStatusModal';
import { ImportTrafficModal } from './components/ImportTrafficModal';
import { AddObservationModal } from './components/AddObservationModal';
import { WorkspaceShell } from './components/workspace/WorkspaceShell';
import { MemoryKnowledgeTab } from './components/workspace/tabs/MemoryKnowledgeTab';
import { LoginScreen } from './components/LoginScreen';
import type { ChatMessage, IngestionResult, InvestigationDetail, InvestigationSummary, SystemStatus, UserSession } from './types';

export const App: React.FC = () => {
  const getInitialAppMode = (): 'workspace' | 'copilot' | 'knowledge_lab' => {
    const path = window.location.pathname.toLowerCase();
    const hash = window.location.hash.toLowerCase();
    const search = window.location.search.toLowerCase();
    if (path.includes('/knowledge') || hash.includes('knowledge') || search.includes('mode=knowledge')) {
      return 'knowledge_lab';
    }
    if (path.includes('/workspace') || path.includes('/assessment') || hash.includes('workspace') || search.includes('mode=workspace')) {
      return 'workspace';
    }
    return 'copilot';
  };

  const [appMode, setAppMode] = useState<'workspace' | 'copilot' | 'knowledge_lab'>(getInitialAppMode);
  const [investigations, setInvestigations] = useState<InvestigationSummary[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [detail, setDetail] = useState<InvestigationDetail | null>(null);
  const [status, setStatus] = useState<SystemStatus | null>(null);

  const [loadingMessage, setLoadingMessage] = useState(false);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [drawerTab, setDrawerTab] = useState('evidence');
  const [showStatusModal, setShowStatusModal] = useState(false);
  const [showNewModal, setShowNewModal] = useState(false);
  const [showImportModal, setShowImportModal] = useState(false);
  const [showAddObsModal, setShowAddObsModal] = useState(false);
  const [importSummary, setImportSummary] = useState<IngestionResult | null>(null);

  // Authentication & Session State
  const [session, setSession] = useState<UserSession | null>(null);
  const [authLoading, setAuthLoading] = useState<boolean>(true);
  const [appNotification, setAppNotification] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  // Theme Management with Persistent Storage
  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    try {
      const stored = localStorage.getItem('ultron-theme');
      return stored === 'light' ? 'light' : 'dark';
    } catch {
      return 'dark';
    }
  });

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    try {
      localStorage.setItem('ultron-theme', theme);
    } catch {
      // Ignore localStorage restrictions in sandbox
    }
  }, [theme]);

  const handleToggleTheme = () => {
    setTheme((prev) => (prev === 'light' ? 'dark' : 'light'));
  };

  const selectInvestigation = async (id: string) => {
    setActiveId(id);
    setImportSummary(null);
    try {
      const data = await fetchInvestigation(id);
      setDetail(data);
    } catch (err) {
      console.error(`Failed to load investigation ${id}:`, err);
    }
  };

  const initWorkspace = async () => {
    try {
      const [invs, sysStatus] = await Promise.all([
        fetchInvestigations(),
        fetchStatus().catch(() => null),
      ]);
      setInvestigations(invs);
      if (sysStatus) setStatus(sysStatus);

      // Check URL route for direct investigation navigation
      const pathParts = window.location.pathname.split('/');
      const invIndex = pathParts.indexOf('investigations');
      if (invIndex !== -1 && pathParts[invIndex + 1]) {
        selectInvestigation(pathParts[invIndex + 1]);
      } else if (invs && invs.length > 0 && !activeId) {
        // Auto-select first existing investigation so Copilot conversation is immediately ready
        selectInvestigation(invs[0].id);
      }
    } catch (err) {
      console.error('Failed to initialize workspace:', err);
    }
  };

  const checkAuth = React.useCallback(async () => {
    setAuthLoading(true);
    try {
      const user = await fetchCurrentUser();
      setSession(user);
      await initWorkspace();
    } catch {
      setSession(null);
    } finally {
      setAuthLoading(false);
    }
  }, []);

  useEffect(() => {
    checkAuth();
    const handleAuthExpired = () => {
      setSession(null);
      setInvestigations([]);
      setDetail(null);
    };
    window.addEventListener('ultron-auth-expired', handleAuthExpired);
    return () => {
      window.removeEventListener('ultron-auth-expired', handleAuthExpired);
    };
  }, [checkAuth]);

  const handleLogout = async () => {
    try {
      await logout();
    } catch {
      // Ignore network errors on logout
    } finally {
      setSession(null);
      setInvestigations([]);
      setDetail(null);
    }
  };

  const handleImportSuccess = async (result: IngestionResult) => {
    setImportSummary(result);
    if (activeId) {
      const updated = await fetchInvestigation(activeId);
      setDetail(updated);
      fetchInvestigations().then(setInvestigations).catch(() => {});
    }
  };

  const handleAddObservationSuccess = async () => {
    if (activeId) {
      const updated = await fetchInvestigation(activeId);
      setDetail(updated);
      fetchInvestigations().then(setInvestigations).catch(() => {});
    }
  };

  const handleStartAnalysis = async () => {
    await handleSendMessage("Analyze target traffic for security invariants, derived workflows, and evidence gaps.");
  };

  const handleViewEvidence = () => {
    openDrawerWithTab('evidence');
  };

  /**
   * Reconcile local conversation state with server conversation state.
   * Preserves pending or failed local user messages while preventing duplicates.
   */
  const reconcileMessages = (currentMessages: ChatMessage[], serverMessages: ChatMessage[]): ChatMessage[] => {
    const serverIds = new Set(serverMessages.map((m) => m.id));
    const serverUserSignatures = new Set(
      serverMessages
        .filter((m) => m.sender === 'user')
        .map((m) => m.content.trim())
    );

    const unconfirmedLocal = currentMessages.filter(
      (m) =>
        (m.delivery_status === 'sending' || m.delivery_status === 'failed') &&
        !serverIds.has(m.id) &&
        !serverUserSignatures.has(m.content.trim())
    );

    return [...serverMessages, ...unconfirmedLocal];
  };

  const handleSendMessage = async (content: string) => {
    if (!activeId) return;

    // 1. Generate stable client-side ID for optimistic rendering
    const clientMsgId = `USR-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;
    const optimisticUserMsg: ChatMessage = {
      id: clientMsgId,
      investigation_id: activeId,
      sender: 'user',
      content,
      structured_type: 'NONE',
      timestamp: new Date().toISOString(),
      delivery_status: 'sending',
    };

    // 2. Immediately append user message to local state (immutable update)
    setDetail((prev) => {
      if (!prev) return prev;
      return {
        ...prev,
        messages: [...prev.messages, optimisticUserMsg],
      };
    });

    // 3. Set loading state to show processing/thinking indicator
    setLoadingMessage(true);

    try {
      // 4. Perform API request to post message
      const responseMessages = await sendMessage(activeId, content, clientMsgId);

      // 5. Assistant response received: mark user message delivered and append assistant response
      setDetail((prev) => {
        if (!prev) return prev;

        const updatedMessages = prev.messages.map((m) =>
          m.id === clientMsgId ? { ...m, delivery_status: 'delivered' as const } : m
        );

        // Deduplicate incoming messages
        const toAdd = responseMessages.filter((inc) => {
          if (updatedMessages.some((m) => m.id === inc.id)) return false;
          if (inc.sender === 'user' && inc.content.trim() === content.trim()) return false;
          return true;
        });

        return {
          ...prev,
          messages: [...updatedMessages, ...toAdd],
        };
      });

      // Refresh list metadata in background
      fetchInvestigations().then(setInvestigations).catch(() => {});
    } catch (err: any) {
      // 6. On failure: mark user message as failed (retains message in conversation with retry option)
      setDetail((prev) => {
        if (!prev) return prev;
        return {
          ...prev,
          messages: prev.messages.map((m) =>
            m.id === clientMsgId ? { ...m, delivery_status: 'failed' as const } : m
          ),
        };
      });
      console.error('Failed to send message:', err);
    } finally {
      setLoadingMessage(false);
    }
  };

  const handleRetryMessage = async (content: string, failedId: string) => {
    if (!activeId) return;
    setDetail((prev) => {
      if (!prev) return prev;
      return {
        ...prev,
        messages: prev.messages.filter((m) => m.id !== failedId),
      };
    });
    await handleSendMessage(content);
  };

  const handleRenameInvestigation = async (newName: string) => {
    if (!activeId) return;
    try {
      const updated = await renameInvestigation(activeId, newName);
      setInvestigations((prev) => prev.map((inv) => (inv.id === activeId ? updated : inv)));
      setDetail((prev) => (prev ? { ...prev, name: updated.name } : prev));
      setAppNotification({ type: 'success', message: `Investigation renamed to "${updated.name}".` });
    } catch (err: any) {
      console.error('Failed to rename investigation:', err);
      setAppNotification({ type: 'error', message: `Failed to rename investigation: ${err.message}` });
    }
  };

  const handleDeleteInvestigation = async () => {
    if (!activeId) return;
    if (!window.confirm('Delete this investigation and its conversation messages? Canonical evidence remains preserved.')) {
      return;
    }
    try {
      await deleteInvestigation(activeId);
      setInvestigations((prev) => prev.filter((inv) => inv.id !== activeId));
      setActiveId(null);
      setDetail(null);
      setAppNotification({ type: 'success', message: 'Investigation deleted successfully.' });
    } catch (err: any) {
      console.error('Failed to delete investigation:', err);
      setAppNotification({ type: 'error', message: `Failed to delete investigation: ${err.message}` });
    }
  };

  const handleCreateInvestigation = async (name: string, targetHost: string) => {
    const newInv = await createInvestigation(name, targetHost);
    setInvestigations((prev) => [newInv, ...prev]);
    selectInvestigation(newInv.id);
  };

  const handleLoadDemo = async () => {
    try {
      const demoInv = await loadDemoFixture();
      const updatedList = await fetchInvestigations();
      setInvestigations(updatedList);
      selectInvestigation(demoInv.id);
      setAppNotification({ type: 'success', message: `Demo fixture loaded: "${demoInv.name}".` });
    } catch (err: any) {
      console.error('Failed to load demo fixture:', err);
      setAppNotification({ type: 'error', message: `Failed to load demo fixture: ${err.message}` });
    }
  };

  const handleValidateExperiment = async (expId: string) => {
    return await validateExperiment(expId);
  };

  const handleApproveExperiment = async (
    expId: string,
    actor: string,
    ack: boolean,
    notes: string
  ) => {
    const res = await approveExperiment(expId, actor, ack, notes);
    if (activeId) {
      const updated = await fetchInvestigation(activeId);
      setDetail((prev) => {
        if (!prev || prev.id !== updated.id) return updated;
        return {
          ...updated,
          messages: reconcileMessages(prev.messages, updated.messages),
        };
      });
    }
    return res;
  };

  const handleRejectExperiment = async (expId: string) => {
    const res = await rejectExperiment(expId, 'authorized_security_lead', 'Rejected by researcher in workspace.');
    if (activeId) {
      const updated = await fetchInvestigation(activeId);
      setDetail((prev) => {
        if (!prev || prev.id !== updated.id) return updated;
        return {
          ...updated,
          messages: reconcileMessages(prev.messages, updated.messages),
        };
      });
    }
    return res;
  };

  const handleExecuteExperiment = async (expId: string) => {
    const outcome = await executeExperiment(expId);
    if (activeId) {
      const updated = await fetchInvestigation(activeId);
      setDetail((prev) => {
        if (!prev || prev.id !== updated.id) return updated;
        return {
          ...updated,
          messages: reconcileMessages(prev.messages, updated.messages),
        };
      });
      fetchInvestigations().then(setInvestigations).catch(() => {});
    }
    return outcome;
  };

  const openDrawerWithTab = (tab: string) => {
    setDrawerTab(tab);
    setDrawerOpen(true);
  };

  const handleUpdateMessageContent = (messageId: string, newContent: string, newStatus?: string) => {
    setDetail((prev) => {
      if (!prev) return prev;
      return {
        ...prev,
        messages: prev.messages.map((m) =>
          m.id === messageId ? { ...m, content: newContent, ...(newStatus ? { status: newStatus } : {}) } : m
        ),
      };
    });
  };

  const handleStopGeneration = async () => {
    if (!activeId) return;
    try {
      await stopInvestigationGeneration(activeId);
      const updated = await fetchInvestigation(activeId);
      if (updated) {
        setDetail((prev) => prev ? { ...prev, messages: updated.messages } : prev);
      }
    } catch (err) {
      console.error('Failed to stop generation:', err);
    }
  };

  const handleEditPrompt = async (messageId: string, newContent: string) => {
    if (!activeId) return;
    setLoadingMessage(true);
    try {
      const updatedMessages = await editAndRegeneratePrompt(activeId, messageId, newContent);
      setDetail((prev) => prev ? { ...prev, messages: updatedMessages } : prev);
    } catch (err) {
      console.error('Failed to edit prompt:', err);
    } finally {
      setLoadingMessage(false);
    }
  };

  if (authLoading) {
    return (
      <div style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        backgroundColor: 'var(--bg-app)',
        color: 'var(--text-secondary)',
        fontSize: '13px',
        letterSpacing: '0.02em',
      }}>
        Verifying operator session...
      </div>
    );
  }

  if (!session) {
    return (
      <LoginScreen
        onLoginSuccess={(newSession) => {
          setSession(newSession);
          initWorkspace();
        }}
      />
    );
  }

  if (appMode === 'workspace') {
    return (
      <WorkspaceShell
        onBackToCopilot={() => setAppMode('copilot')}
        onOpenKnowledgeLab={() => setAppMode('knowledge_lab')}
        currentUser={session}
        onLogout={handleLogout}
      />
    );
  }

  if (appMode === 'knowledge_lab') {
    return (
      <div
        style={{
          display: 'flex',
          flexDirection: 'column',
          height: '100vh',
          width: '100vw',
          background: 'var(--bg-app)',
          color: 'var(--text-primary)',
          overflow: 'hidden',
        }}
      >
        {/* Top Application Bar */}
        <div
          style={{
            padding: '8px 20px',
            borderBottom: '1px solid var(--border-subtle)',
            background: 'var(--bg-sidebar)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            fontSize: '12px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '8px',
                fontWeight: 800,
                letterSpacing: '0.06em',
                fontSize: '13px',
                color: 'var(--text-primary)',
              }}
            >
              <span style={{ color: 'var(--accent-primary)', textShadow: 'var(--accent-glow)' }}>//</span>
              ULTRON
            </span>
            <span
              style={{
                fontSize: '10px',
                color: 'var(--badge-blue-text)',
                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                border: '1px solid rgba(59, 130, 246, 0.25)',
                padding: '2px 8px',
                borderRadius: '4px',
                letterSpacing: '0.04em',
                fontWeight: 600,
              }}
            >
              KNOWLEDGE LAB
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            {session && (
              <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                Operator: <strong style={{ color: 'var(--text-primary)' }}>{session.username}</strong> ({session.role})
              </span>
            )}
            <button
              onClick={() => setAppMode('copilot')}
              data-testid="knowledge-lab-back-copilot"
              style={{
                padding: '4px 10px',
                borderRadius: 'var(--radius-sm)',
                background: 'var(--bg-surface)',
                border: '1px solid var(--border-subtle)',
                color: 'var(--text-primary)',
                fontSize: '11px',
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              ← Copilot Investigations
            </button>
            <button
              onClick={() => setAppMode('workspace')}
              data-testid="knowledge-lab-open-workspace"
              style={{
                padding: '4px 10px',
                borderRadius: 'var(--radius-sm)',
                background: 'rgba(225, 29, 72, 0.1)',
                border: '1px solid rgba(225, 29, 72, 0.3)',
                color: 'var(--text-primary)',
                fontSize: '11px',
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              Assessment Workspace →
            </button>
          </div>
        </div>

        {/* Knowledge Lab Main Pane */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '20px 24px' }}>
          <MemoryKnowledgeTab assessmentId="GLOBAL" />
        </div>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', width: '100vw', height: '100vh', overflow: 'hidden' }}>
      {/* Sidebar */}
      <Sidebar
        investigations={investigations}
        activeId={activeId}
        onSelect={selectInvestigation}
        onNewInvestigation={() => setShowNewModal(true)}
        onLoadDemo={handleLoadDemo}
        onOpenSystemStatus={() => setShowStatusModal(true)}
        systemStatusReady={status?.local_ai === 'READY'}
        onOpenWorkspace={() => setAppMode('workspace')}
        onOpenKnowledgeLab={() => setAppMode('knowledge_lab')}
        currentUser={session}
        onLogout={handleLogout}
        theme={theme}
        onToggleTheme={handleToggleTheme}
      />

      {/* Main Workspace Column */}
      <main
        style={{
          flex: 1,
          display: 'flex',
          flexDirection: 'column',
          height: '100%',
          overflow: 'hidden',
          backgroundColor: 'var(--bg-app)',
          position: 'relative',
        }}
      >
        {appNotification && (
          <div
            role={appNotification.type === 'error' ? 'alert' : 'status'}
            aria-live="polite"
            data-testid="app-notification-banner"
            style={{
              padding: '10px 18px',
              backgroundColor: appNotification.type === 'error' ? 'rgba(239, 68, 68, 0.12)' : 'rgba(16, 185, 129, 0.12)',
              borderBottom: `1px solid ${appNotification.type === 'error' ? 'rgba(239, 68, 68, 0.3)' : 'rgba(16, 185, 129, 0.3)'}`,
              color: appNotification.type === 'error' ? '#ef4444' : '#10b981',
              fontSize: '13px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              zIndex: 30,
              flexShrink: 0,
            }}
          >
            <span>{appNotification.message}</span>
            <button
              onClick={() => setAppNotification(null)}
              aria-label="Dismiss notification"
              style={{
                background: 'none',
                border: 'none',
                color: 'inherit',
                cursor: 'pointer',
                fontWeight: 600,
                fontSize: '15px',
                padding: '2px 8px',
                lineHeight: 1,
              }}
            >
              ×
            </button>
          </div>
        )}
        {detail ? (
          <>
            <InvestigationHeader
              name={detail.name}
              targetHost={detail.target_host}
              scopeStatus={detail.scope_status}
              isDemo={detail.is_demo}
              evidenceCount={detail.evidence_count}
              hypothesisCount={detail.hypothesis_count}
              activeModel={status?.active_model || 'qwen2.5-coder:7b'}
              onOpenDrawer={openDrawerWithTab}
              onOpenImport={() => setShowImportModal(true)}
              onOpenAddObservation={() => setShowAddObsModal(true)}
              onRename={handleRenameInvestigation}
              onDelete={handleDeleteInvestigation}
            />

            <ConversationView
              messages={detail.messages}
              loading={loadingMessage}
              evidenceCount={detail.evidence_count}
              importSummary={importSummary}
              targetHost={detail.target_host}
              onOpenImport={() => setShowImportModal(true)}
              onOpenAddObservation={() => setShowAddObsModal(true)}
              onViewEvidence={handleViewEvidence}
              onStartAnalysis={handleStartAnalysis}
              onRetryMessage={handleRetryMessage}
              onValidateExperiment={handleValidateExperiment}
              onApproveExperiment={handleApproveExperiment}
              onRejectExperiment={handleRejectExperiment}
              onExecuteExperiment={handleExecuteExperiment}
              onOpenDrawer={openDrawerWithTab}
              onSendFollowUp={handleSendMessage}
              onUpdateMessageContent={handleUpdateMessageContent}
              onEditPrompt={handleEditPrompt}
            />

            <Composer
              onSend={handleSendMessage}
              onStop={handleStopGeneration}
              loading={loadingMessage}
              hasMessages={Boolean(detail.messages && detail.messages.length > 0)}
            />
          </>
        ) : (
          <div
            style={{
              flex: 1,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              padding: '40px 24px',
              maxWidth: '540px',
              margin: '0 auto',
              textAlign: 'center',
            }}
          >
            <h1
              style={{
                fontSize: '24px',
                fontWeight: 500,
                color: 'var(--text-primary)',
                letterSpacing: '-0.015em',
                marginBottom: '10px',
              }}
            >
              What are you investigating?
            </h1>

            <p
              style={{
                fontSize: '14px',
                color: 'var(--text-secondary)',
                marginBottom: '28px',
                lineHeight: 1.6,
              }}
            >
              Select an ongoing investigation from the sidebar, create a new one, or explore the local BOLA fixture.
            </p>

            <div style={{ display: 'flex', gap: '10px', justifyContent: 'center', marginBottom: '32px' }}>
              <button
                onClick={() => setShowNewModal(true)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  padding: '9px 18px',
                  backgroundColor: 'var(--accent-primary)',
                  color: '#FFFFFF',
                  borderRadius: 'var(--radius-md)',
                  fontSize: '13.5px',
                  fontWeight: 500,
                  border: 'none',
                  cursor: 'pointer',
                }}
              >
                <span>+</span>
                <span>New investigation</span>
              </button>

              <button
                onClick={handleLoadDemo}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  padding: '9px 16px',
                  backgroundColor: 'transparent',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-md)',
                  fontSize: '13px',
                  color: 'var(--text-secondary)',
                  cursor: 'pointer',
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.backgroundColor = 'var(--bg-surface)';
                  e.currentTarget.style.color = 'var(--text-primary)';
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.backgroundColor = 'transparent';
                  e.currentTarget.style.color = 'var(--text-secondary)';
                }}
              >
                <span>Load demo fixture</span>
              </button>
            </div>

            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                fontSize: '12px',
                color: 'var(--text-muted)',
              }}
            >
              <span
                style={{
                  width: '6px',
                  height: '6px',
                  borderRadius: '50%',
                  backgroundColor: status?.local_ai === 'READY' ? 'var(--status-success)' : '#B8860B',
                }}
              />
              <span>Local AI: {status?.active_model || 'Connecting...'}</span>
              <span>·</span>
              <span>{status?.execution_mode || 'SAFE_LOCAL_SIMULATION'}</span>
            </div>
          </div>
        )}
      </main>

      {/* Slide-in Context Drawer */}
      {drawerOpen && activeId && (
        <ContextDrawer
          investigationId={activeId}
          initialTab={drawerTab}
          onClose={() => setDrawerOpen(false)}
          onOpenImport={() => setShowImportModal(true)}
          onOpenAddObservation={() => setShowAddObsModal(true)}
        />
      )}

      {/* System Status Modal */}
      {showStatusModal && (
        <SystemStatusModal
          status={status}
          onClose={() => setShowStatusModal(false)}
        />
      )}

      {/* New Investigation Modal */}
      {showNewModal && (
        <NewInvestigationModal
          onCreate={handleCreateInvestigation}
          onClose={() => setShowNewModal(false)}
        />
      )}

      {/* Import Traffic Modal */}
      {showImportModal && activeId && detail && (
        <ImportTrafficModal
          investigationId={activeId}
          targetHost={detail.target_host}
          onClose={() => setShowImportModal(false)}
          onImportComplete={handleImportSuccess}
          onViewEvidence={handleViewEvidence}
          onStartAnalysis={handleStartAnalysis}
        />
      )}

      {/* Add Observation Modal */}
      {showAddObsModal && activeId && detail && (
        <AddObservationModal
          investigationId={activeId}
          targetHost={detail.target_host}
          onClose={() => setShowAddObsModal(false)}
          onObservationAdded={handleAddObservationSuccess}
          onViewEvidence={handleViewEvidence}
          onStartAnalysis={handleStartAnalysis}
        />
      )}
    </div>
  );
};

export default App;
