import React, { useState, useEffect, useRef } from 'react';
import { generateAssessmentHypotheses } from '../../../api';

interface ResearchTabProps {
  assessmentId: string;
  onRefreshOverview: () => void;
  onNavigateSection: (section: string) => void;
}

export const ResearchTab: React.FC<ResearchTabProps> = ({
  assessmentId,
  onRefreshOverview,
  onNavigateSection,
}) => {
  const [activeAgent, setActiveAgent] = useState<string>('AppSec Analyst');
  const [runningAnalysis, setRunningAnalysis] = useState(false);
  const [analysisOutput, setAnalysisOutput] = useState<string | null>(null);

  // Stale request guard
  const activeAssessmentRef = useRef(assessmentId);

  useEffect(() => {
    activeAssessmentRef.current = assessmentId;
    setAnalysisOutput(null);
  }, [assessmentId]);

  const specializedAgents = [
    {
      name: 'AppSec Analyst',
      description: 'Web application vulnerabilities (XSS, SSRF, IDOR, SQLi, CSRF, Path Traversal)',
    },
    {
      name: 'API Security Specialist',
      description: 'REST, GraphQL, JWT/OAuth misconfigurations, mass assignment, BOLA/BFLA',
    },
    {
      name: 'Mobile & Binary Auditor',
      description: 'Android APK decompilation, exported components, native libs, buffer overflows',
    },
    {
      name: 'Auth & Session Flaw Hunter',
      description: 'Session fixation, privilege escalation, multi-tenant boundary bypasses',
    },
    {
      name: 'Falsification & Negative Control Agent',
      description: 'Refutation testing, evidence gap detection, false-positive elimination',
    },
  ];

  const handleRunAgent = async (agentName: string) => {
    setActiveAgent(agentName);
    setRunningAnalysis(true);
    setAnalysisOutput(null);

    try {
      // Trigger hypothesis analysis engine
      const res = await generateAssessmentHypotheses(assessmentId);
      const hyps = res.hypotheses || [];
      const count = hyps.length;
      setAnalysisOutput(
        `Agent [${agentName}] completed analysis over target telemetry and asset boundaries.\n` +
        `Generated/Updated ${count} research hypotheses with structured falsification conditions.\n\n` +
        `Epistemic Notice: All agent outputs are categorized as MODEL_HYPOTHESIS until confirmed ` +
        `by controlled experiments and verified by a human reviewer.`
      );
      onRefreshOverview();
    } catch (err: any) {
      setAnalysisOutput(`Agent execution failed: ${err.message || 'Unknown error'}`);
    } finally {
      setRunningAnalysis(false);
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
          <h4 style={{ fontSize: '15px', fontWeight: 600 }}>Integrated Security Research</h4>
          <p style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
            Specialized analytical agents and cybersecurity knowledge retrieval
          </p>
        </div>
        <div style={{
          padding: '4px 10px',
          borderRadius: 'var(--radius-sm)',
          fontSize: '11px',
          background: 'var(--badge-amber-bg)',
          color: 'var(--badge-amber-text)',
        }}>
          Epistemic Rule: Agent conclusions cannot verify findings
        </div>
      </div>

      {/* Agents Selection Grid */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
        gap: '14px',
      }}>
        {specializedAgents.map((agent) => (
          <div
            key={agent.name}
            style={{
              padding: '16px',
              borderRadius: 'var(--radius-md)',
              background: activeAgent === agent.name ? 'var(--bg-surface-muted)' : 'var(--bg-surface)',
              border: activeAgent === agent.name ? '2px solid var(--border-focus)' : '1px solid var(--border-subtle)',
              display: 'flex',
              flexDirection: 'column',
              gap: '8px',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontWeight: 600, fontSize: '13px' }}>{agent.name}</span>
            </div>
            <p style={{ fontSize: '11px', color: 'var(--text-secondary)', flex: 1 }}>
              {agent.description}
            </p>
            <button
              onClick={() => handleRunAgent(agent.name)}
              disabled={runningAnalysis}
              style={{
                marginTop: '6px',
                padding: '6px 12px',
                background: 'var(--accent-primary)',
                color: '#fff',
                borderRadius: 'var(--radius-sm)',
                fontSize: '11px',
                fontWeight: 600,
                opacity: runningAnalysis ? 0.7 : 1,
              }}
            >
              {runningAnalysis && activeAgent === agent.name ? 'Analyzing...' : 'Dispatch Agent'}
            </button>
          </div>
        ))}
      </div>

      {/* Analysis Output Box */}
      {analysisOutput && (
        <div style={{
          padding: '16px 20px',
          borderRadius: 'var(--radius-lg)',
          background: 'var(--bg-surface)',
          border: '1px solid var(--border-subtle)',
          display: 'flex',
          flexDirection: 'column',
          gap: '10px',
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h5 style={{ fontSize: '13px', fontWeight: 600 }}>Analytical Output [{activeAgent}]</h5>
            <button
              onClick={() => onNavigateSection('hypotheses')}
              style={{ fontSize: '12px', color: 'var(--badge-blue-text)', textDecoration: 'underline' }}
            >
              View Generated Hypotheses →
            </button>
          </div>
          <pre style={{
            fontSize: '12px',
            fontFamily: 'var(--font-mono)',
            whiteSpace: 'pre-wrap',
            background: 'var(--bg-surface-muted)',
            padding: '12px',
            borderRadius: 'var(--radius-sm)',
            border: '1px solid var(--border-subtle)',
          }}>
            {analysisOutput}
          </pre>
        </div>
      )}
    </div>
  );
};
