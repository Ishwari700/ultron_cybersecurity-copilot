import React, { useState, useEffect, useRef } from 'react';
import {
  fetchAssessments,
  fetchAssessmentWorkspace,
  fetchAssessmentOverview,
} from '../../api';
import type {
  AssessmentSummary,
  AssessmentWorkspace,
  UserSession,
} from '../../types';
import { WorkspaceHeader } from './WorkspaceHeader';
import { AssessmentSwitcherModal } from './AssessmentSwitcherModal';
import { CreateAssessmentModal } from './CreateAssessmentModal';
import { GlobalSearchModal } from './GlobalSearchModal';

// 12 Functional Tab Views
import { OverviewTab } from './tabs/OverviewTab';
import { ScopeAssetsTab } from './tabs/ScopeAssetsTab';
import { AttackSurfaceTab } from './tabs/AttackSurfaceTab';
import { ArtifactsTab } from './tabs/ArtifactsTab';
import { ResearchTab } from './tabs/ResearchTab';
import { HypothesesTab } from './tabs/HypothesesTab';
import { EvidenceTab } from './tabs/EvidenceTab';
import { ExperimentsTab } from './tabs/ExperimentsTab';
import { FindingsReviewTab } from './tabs/FindingsReviewTab';
import { ReportsTab } from './tabs/ReportsTab';
import { MemoryKnowledgeTab } from './tabs/MemoryKnowledgeTab';
import { ActivityAuditTab } from './tabs/ActivityAuditTab';

interface WorkspaceShellProps {
  onBackToCopilot?: () => void;
  onOpenKnowledgeLab?: () => void;
  currentUser?: UserSession | null;
  onLogout?: () => void;
}

export const WorkspaceShell: React.FC<WorkspaceShellProps> = ({
  onBackToCopilot,
  onOpenKnowledgeLab,
  currentUser,
  onLogout,
}) => {
  const [assessments, setAssessments] = useState<AssessmentSummary[]>([]);
  const [activeAssessmentId, setActiveAssessmentId] = useState<string | null>(null);
  const [workspace, setWorkspace] = useState<AssessmentWorkspace | null>(null);
  const [activeSection, setActiveSection] = useState<string>('overview');
  const [loading, setLoading] = useState<boolean>(true);
  const [workspaceError, setWorkspaceError] = useState<string | null>(null);

  // Stale request protection
  const requestIdRef = useRef(0);

  // Modals
  const [showSwitcher, setShowSwitcher] = useState(false);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showSearchModal, setShowSearchModal] = useState(false);

  const selectAssessment = async (aid: string) => {
    const currentRequestId = ++requestIdRef.current;
    setActiveAssessmentId(aid);
    setLoading(true);
    setWorkspaceError(null);
    try {
      const ws = await fetchAssessmentWorkspace(aid);
      if (currentRequestId !== requestIdRef.current) return;
      setWorkspace(ws);
      if (ws.view_state && ws.view_state.active_section) {
        setActiveSection(ws.view_state.active_section);
      }
    } catch (err: any) {
      if (currentRequestId !== requestIdRef.current) return;
      console.error(`Failed to load workspace for ${aid}:`, err);
      setWorkspaceError(err.message || `Failed to load workspace for assessment ${aid}`);
    } finally {
      if (currentRequestId === requestIdRef.current) {
        setLoading(false);
      }
    }
  };

  const initWorkspace = async () => {
    setLoading(true);
    setWorkspaceError(null);
    try {
      const list = await fetchAssessments();
      setAssessments(list);
      if (list.length > 0) {
        selectAssessment(list[0].assessment_id);
      } else {
        setLoading(false);
      }
    } catch (err: any) {
      console.error('Failed to load assessment list:', err);
      setWorkspaceError(err.message || 'Failed to initialize assessments list');
      setLoading(false);
    }
  };

  useEffect(() => {
    initWorkspace();
  }, []);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setShowSearchModal((prev) => !prev);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const refreshOverview = async () => {
    if (!activeAssessmentId) return;
    const currentAid = activeAssessmentId;
    try {
      const [ov, list] = await Promise.all([
        fetchAssessmentOverview(currentAid),
        fetchAssessments(),
      ]);
      if (activeAssessmentId !== currentAid) return;
      setAssessments(list);
      if (workspace && workspace.overview.assessment_id === currentAid) {
        setWorkspace({ ...workspace, overview: ov });
      }
    } catch (err: any) {
      console.error('Failed to refresh overview:', err);
    }
  };

  const navItems = [
    { id: 'overview', label: '1. Overview' },
    { id: 'scope_assets', label: '2. Scope & Assets' },
    { id: 'attack_surface', label: '3. Attack Surface' },
    { id: 'artifacts', label: '4. Artifacts Lab' },
    { id: 'research', label: '5. Research & Q&A' },
    { id: 'hypotheses', label: '6. Hypotheses & Gaps' },
    { id: 'evidence', label: '7. Evidence & Lineage' },
    { id: 'experiments', label: '8. Controlled Experiments' },
    { id: 'findings_review', label: '9. Findings & Review' },
    { id: 'reports', label: '10. Report Center' },
    { id: 'memory_knowledge', label: '11. Research Memory' },
    { id: 'activity_audit', label: '12. Audit Timeline' },
  ];

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      height: '100vh',
      width: '100vw',
      background: 'var(--bg-app)',
      color: 'var(--text-primary)',
      overflow: 'hidden',
    }}>
      {/* Top Application Bar */}
      <div style={{
        padding: '8px 20px',
        borderBottom: '1px solid var(--border-subtle)',
        background: 'var(--bg-sidebar)',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        fontSize: '12px',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }} data-former="BUG BOUNTY AI">
          <span style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
            fontWeight: 800,
            letterSpacing: '0.06em',
            fontSize: '13px',
            color: 'var(--text-primary)',
          }}>
            <span style={{ color: 'var(--accent-primary)', textShadow: 'var(--accent-glow)' }}>//</span>
            ULTRON
          </span>
          <span style={{
            fontSize: '10px',
            color: 'var(--text-muted)',
            backgroundColor: 'var(--bg-surface)',
            border: '1px solid var(--border-subtle)',
            padding: '2px 8px',
            borderRadius: '4px',
            letterSpacing: '0.04em',
            fontWeight: 600,
          }}>
            SECURITY WORKSPACE
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          {currentUser && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                Operator: <strong style={{ color: 'var(--text-primary)' }}>{currentUser.username}</strong> ({currentUser.role})
              </span>
              {onLogout && (
                <button
                  onClick={onLogout}
                  style={{
                    padding: '3px 8px',
                    borderRadius: 'var(--radius-sm)',
                    background: 'transparent',
                    border: '1px solid var(--border-subtle)',
                    fontSize: '11px',
                    color: 'var(--text-secondary)',
                    cursor: 'pointer',
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.color = 'var(--accent-primary)';
                    e.currentTarget.style.borderColor = 'var(--accent-primary)';
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.color = 'var(--text-secondary)';
                    e.currentTarget.style.borderColor = 'var(--border-subtle)';
                  }}
                >
                  Sign Out
                </button>
              )}
            </div>
          )}
          {onOpenKnowledgeLab && (
            <button
              onClick={onOpenKnowledgeLab}
              data-testid="workspace-open-knowledge-lab"
              style={{
                padding: '4px 10px',
                borderRadius: 'var(--radius-sm)',
                background: 'rgba(59, 130, 246, 0.10)',
                border: '1px solid rgba(59, 130, 246, 0.30)',
                color: 'var(--badge-blue-text)',
                fontSize: '11px',
                fontWeight: 600,
                cursor: 'pointer',
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.backgroundColor = 'rgba(59, 130, 246, 0.20)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.backgroundColor = 'rgba(59, 130, 246, 0.10)';
              }}
            >
              Knowledge Lab
            </button>
          )}
          {onBackToCopilot && (
            <button
              onClick={onBackToCopilot}
              style={{
                padding: '4px 10px',
                borderRadius: 'var(--radius-sm)',
                background: 'var(--bg-surface)',
                border: '1px solid var(--border-subtle)',
                fontSize: '11px',
                fontWeight: 600,
              }}
            >
              ← Switch to Copilot Investigations
            </button>
          )}
        </div>
      </div>

      {/* Header */}
      <WorkspaceHeader
        overview={workspace?.overview || null}
        onOpenSwitcher={() => setShowSwitcher(true)}
        onOpenSearch={() => setShowSearchModal(true)}
        onRefresh={refreshOverview}
      />

      {/* Main Body: 12-Section Sidebar + Tab View */}
      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        {/* Navigation Sidebar */}
        <aside style={{
          width: '240px',
          background: 'var(--bg-sidebar)',
          borderRight: '1px solid var(--border-subtle)',
          padding: '12px 8px',
          display: 'flex',
          flexDirection: 'column',
          gap: '2px',
          overflowY: 'auto',
        }}>
          <div style={{
            fontSize: '11px',
            fontWeight: 700,
            textTransform: 'uppercase',
            color: 'var(--text-muted)',
            padding: '4px 10px 8px 10px',
          }}>
            Assessment Workflow
          </div>

          {navItems.map((item) => {
            const isActive = activeSection === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveSection(item.id)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '10px',
                  padding: '8px 12px',
                  borderRadius: 'var(--radius-md)',
                  background: isActive ? 'var(--bg-surface-active)' : 'transparent',
                  color: isActive ? 'var(--text-primary)' : 'var(--text-secondary)',
                  fontWeight: isActive ? 600 : 400,
                  fontSize: '13px',
                  textAlign: 'left',
                  border: 'none',
                }}
              >
                <span style={{ flex: 1, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {item.label}
                </span>
              </button>
            );
          })}
        </aside>

        {/* Content Pane */}
        <main style={{
          flex: 1,
          overflowY: 'auto',
          padding: '24px 32px',
          background: 'var(--bg-app)',
        }}>
          {workspaceError && (
            <div
              role="alert"
              style={{
                marginBottom: '20px',
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
              <span>{workspaceError}</span>
              <button
                onClick={() => {
                  if (activeAssessmentId) {
                    selectAssessment(activeAssessmentId);
                  } else {
                    initWorkspace();
                  }
                }}
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
            <div style={{ textAlign: 'center', padding: '60px', color: 'var(--text-muted)' }}>
              Loading assessment workspace...
            </div>
          ) : !workspace ? (
            <div style={{
              textAlign: 'center',
              padding: '60px',
              background: 'var(--bg-surface)',
              borderRadius: 'var(--radius-lg)',
              border: '1px solid var(--border-subtle)',
              maxWidth: '500px',
              margin: '40px auto',
            }}>
              <h3 style={{ fontSize: '18px', fontWeight: 600, marginBottom: '8px' }}>
                {workspaceError ? 'Failed to Load Assessment' : 'No Active Assessment'}
              </h3>
              <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '20px' }}>
                {workspaceError
                  ? 'There was an issue loading the selected assessment. Please retry or choose a different assessment.'
                  : 'Create or select an authorized security assessment program to begin research.'}
              </p>
              <div style={{ display: 'flex', justifyContent: 'center', gap: '10px' }}>
                <button
                  onClick={() => setShowSwitcher(true)}
                  style={{
                    padding: '8px 18px',
                    borderRadius: 'var(--radius-md)',
                    background: 'var(--bg-surface-muted)',
                    border: '1px solid var(--border-subtle)',
                    fontSize: '13px',
                    fontWeight: 600,
                  }}
                >
                  Switch Assessment
                </button>
                <button
                  onClick={() => setShowCreateModal(true)}
                  style={{
                    padding: '8px 18px',
                    borderRadius: 'var(--radius-md)',
                    background: 'var(--accent-primary)',
                    color: '#fff',
                    fontSize: '13px',
                    fontWeight: 600,
                  }}
                >
                  + Create New Assessment
                </button>
              </div>
            </div>
          ) : (
            <>
              {activeSection === 'overview' && (
                <OverviewTab
                  overview={workspace.overview}
                  warningBanners={workspace.warning_banners}
                  onNavigateSection={(sec) => setActiveSection(sec)}
                  onRefresh={refreshOverview}
                />
              )}
              {activeSection === 'scope_assets' && (
                <ScopeAssetsTab
                  assessmentId={workspace.overview.assessment_id}
                  onRefreshOverview={refreshOverview}
                />
              )}
              {activeSection === 'attack_surface' && (
                <AttackSurfaceTab
                  assessmentId={workspace.overview.assessment_id}
                />
              )}
              {activeSection === 'artifacts' && (
                <ArtifactsTab
                  assessmentId={workspace.overview.assessment_id}
                />
              )}
              {activeSection === 'research' && (
                <ResearchTab
                  assessmentId={workspace.overview.assessment_id}
                  onRefreshOverview={refreshOverview}
                  onNavigateSection={(sec) => setActiveSection(sec)}
                />
              )}
              {activeSection === 'hypotheses' && (
                <HypothesesTab
                  assessmentId={workspace.overview.assessment_id}
                  onRefreshOverview={refreshOverview}
                  onNavigateSection={(sec) => setActiveSection(sec)}
                />
              )}
              {activeSection === 'evidence' && (
                <EvidenceTab
                  assessmentId={workspace.overview.assessment_id}
                />
              )}
              {activeSection === 'experiments' && (
                <ExperimentsTab
                  assessmentId={workspace.overview.assessment_id}
                  onRefreshOverview={refreshOverview}
                />
              )}
              {activeSection === 'findings_review' && (
                <FindingsReviewTab
                  assessmentId={workspace.overview.assessment_id}
                  onRefreshOverview={refreshOverview}
                  onNavigateSection={(sec) => setActiveSection(sec)}
                />
              )}
              {activeSection === 'reports' && (
                <ReportsTab
                  assessmentId={workspace.overview.assessment_id}
                />
              )}
              {activeSection === 'memory_knowledge' && (
                <MemoryKnowledgeTab
                  assessmentId={workspace.overview.assessment_id}
                />
              )}
              {activeSection === 'activity_audit' && (
                <ActivityAuditTab
                  assessmentId={workspace.overview.assessment_id}
                />
              )}
            </>
          )}
        </main>
      </div>

      {/* Switcher Modal */}
      {showSwitcher && (
        <AssessmentSwitcherModal
          assessments={assessments}
          activeAssessmentId={activeAssessmentId}
          onSelect={(aid) => selectAssessment(aid)}
          onOpenCreate={() => {
            setShowSwitcher(false);
            setShowCreateModal(true);
          }}
          onClose={() => setShowSwitcher(false)}
        />
      )}

      {/* Create Assessment Modal */}
      {showCreateModal && (
        <CreateAssessmentModal
          onCreated={(aid) => {
            fetchAssessments().then(setAssessments);
            selectAssessment(aid);
          }}
          onClose={() => setShowCreateModal(false)}
        />
      )}

      {/* Global Search Modal */}
      {showSearchModal && (
        <GlobalSearchModal
          assessmentId={activeAssessmentId}
          onNavigateSection={(sec) => setActiveSection(sec)}
          onClose={() => setShowSearchModal(false)}
        />
      )}
    </div>
  );
};
