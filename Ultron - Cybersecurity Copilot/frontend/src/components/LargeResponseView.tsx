import React, { useState, useMemo, useRef } from 'react';
import type { ChatMessage, ResponseChunk, ResponseVersion } from '../types';
import {
  continueResponse,
  exportResponse,
  regenerateResponse,
  stopResponseGeneration,
  fetchResponseChunks,
  fetchResponseVersions,
} from '../api';

interface LargeResponseViewProps {
  message: ChatMessage;
  onSendFollowUp?: (prompt: string) => void;
  onUpdateMessageContent?: (messageId: string, newContent: string) => void;
}

export const LargeResponseView: React.FC<LargeResponseViewProps> = ({
  message,
  onSendFollowUp: _onSendFollowUp,
  onUpdateMessageContent,
}) => {
  const [copiedAll, setCopiedAll] = useState(false);
  const [copiedCodeBlock, setCopiedCodeBlock] = useState<number | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [searchActive, setSearchActive] = useState(false);
  const [showMetadata, setShowMetadata] = useState(false);
  const [showVersions, setShowVersions] = useState(false);
  const [showChunks, setShowChunks] = useState(false);
  const [chunks, setChunks] = useState<ResponseChunk[]>([]);
  const [versions, setVersions] = useState<ResponseVersion[]>([]);
  const [loadingAction, setLoadingAction] = useState<string | null>(null);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  const containerRef = useRef<HTMLDivElement>(null);

  const content = message.content || '';
  const responseId = message.response_id;
  const isGenerating = message.status === 'GENERATING' || message.status === 'CONTINUING';
  const isTokenLimit = message.status === 'TOKEN_LIMIT';
  const isUserStopped = message.status === 'USER_STOPPED';
  const isError = message.status === 'ERROR' || message.status === 'SERVICE_UNAVAILABLE';

  // Format model label for subtle provenance indicator
  const modelDisplay = useMemo(() => {
    const raw = message.model_name || '';
    if (raw.toLowerCase().includes('7b')) return '7B';
    if (raw.toLowerCase().includes('3b')) return '3B';
    if (raw === 'local_knowledge_engine') return 'local_knowledge_engine';
    if (raw === 'local_assistant') return 'local_assistant';
    if (raw === 'system_status') return 'system_status';
    if (raw === 'local_rule_engine') return 'local_rule_engine';
    return raw || 'Local AI';
  }, [message.model_name]);

  const handleCopyAll = async () => {
    try {
      await navigator.clipboard.writeText(content);
      setCopiedAll(true);
      setTimeout(() => setCopiedAll(false), 2000);
    } catch {
      setStatusMessage('Copy failed');
    }
  };

  const handleCopyCode = async (index: number, code: string) => {
    try {
      await navigator.clipboard.writeText(code);
      setCopiedCodeBlock(index);
      setTimeout(() => setCopiedCodeBlock(null), 2000);
    } catch {
      setStatusMessage('Copy code failed');
    }
  };

  const handleDownload = async (format: 'markdown' | 'txt') => {
    try {
      let exportText = content;
      if (responseId) {
        const res = await exportResponse(responseId, format);
        exportText = res.content;
      }
      const blob = new Blob([exportText], { type: format === 'markdown' ? 'text/markdown' : 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `response_${responseId || message.id}.${format === 'markdown' ? 'md' : 'txt'}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err: any) {
      setStatusMessage(`Download failed: ${err.message}`);
    }
  };

  const handleStop = async () => {
    if (!responseId) return;
    try {
      setLoadingAction('stop');
      const res = await stopResponseGeneration(responseId);
      if (res.stopped && onUpdateMessageContent) {
        onUpdateMessageContent(message.id, message.content);
      }
      setStatusMessage('Generation stopped');
    } catch (err: any) {
      setStatusMessage(`Stop failed: ${err.message}`);
    } finally {
      setLoadingAction(null);
    }
  };

  const handleContinue = async () => {
    if (!responseId) return;
    try {
      setLoadingAction('continue');
      setStatusMessage('Continuing answer...');
      const session = await continueResponse(responseId);
      if (onUpdateMessageContent) {
        onUpdateMessageContent(message.id, session.final_content);
      }
      setStatusMessage('Continuation merged');
    } catch (err: any) {
      setStatusMessage(`Continue failed: ${err.message}`);
    } finally {
      setLoadingAction(null);
    }
  };

  const handleRegenerate = async () => {
    if (!responseId) return;
    try {
      setLoadingAction('regenerate');
      setStatusMessage('Regenerating answer...');
      const session = await regenerateResponse(responseId);
      if (onUpdateMessageContent) {
        onUpdateMessageContent(message.id, session.final_content);
      }
      setStatusMessage(`Regenerated (Version ${session.active_version})`);
    } catch (err: any) {
      setStatusMessage(`Regenerate failed: ${err.message}`);
    } finally {
      setLoadingAction(null);
    }
  };

  const handleToggleChunks = async () => {
    if (!showChunks && responseId) {
      try {
        const chunkList = await fetchResponseChunks(responseId);
        setChunks(chunkList);
      } catch (e) {
        console.error(e);
      }
    }
    setShowChunks(!showChunks);
  };

  const handleToggleVersions = async () => {
    if (!showVersions && responseId) {
      try {
        const verList = await fetchResponseVersions(responseId);
        setVersions(verList);
      } catch (e) {
        console.error(e);
      }
    }
    setShowVersions(!showVersions);
  };

  // Safe inline markdown renderer for bold, italic, code, and search match highlights
  const renderInlineMarkdown = (text: string): React.ReactNode => {
    if (searchQuery.trim()) {
      const escaped = searchQuery.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const parts = text.split(new RegExp(`(${escaped})`, 'gi'));
      return parts.map((part, pIdx) =>
        part.toLowerCase() === searchQuery.toLowerCase() ? (
          <mark key={pIdx} style={{ backgroundColor: '#FEF08A', color: '#1F2937', padding: '1px 3px', borderRadius: '2px' }}>
            {part}
          </mark>
        ) : (
          <React.Fragment key={pIdx}>{renderInlineTokens(part)}</React.Fragment>
        )
      );
    }
    return renderInlineTokens(text);
  };

  const renderInlineTokens = (text: string): React.ReactNode => {
    const tokens: React.ReactNode[] = [];
    const regex = /(\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)|\[((?:OBS|FACT-OBS|CHK|HYP|EXP|FND)-[A-Za-z0-9\-_]+)\]|\[((?:CVE-\d{4}-\d+|CWE-\d+))\]|\*\*[^*]+\*\*|`[^`]+`|\*[^*]+\*)/g;
    let lastIndex = 0;
    let match: RegExpExecArray | null;

    while ((match = regex.exec(text)) !== null) {
      if (match.index > lastIndex) {
        tokens.push(text.slice(lastIndex, match.index));
      }
      const fullMatch = match[0];
      const linkText = match[2];
      const linkUrl = match[3];
      const citationId = match[4];
      const standardId = match[5];

      if (linkText && linkUrl) {
        tokens.push(
          <a
            key={`a-${match.index}`}
            href={linkUrl}
            target="_blank"
            rel="noopener noreferrer"
            style={{
              color: 'var(--accent-primary, #3B82F6)',
              textDecoration: 'underline',
              wordBreak: 'break-all',
            }}
          >
            {linkText}
          </a>
        );
      } else if (citationId) {
        const isObs = citationId.startsWith('OBS') || citationId.startsWith('FACT-OBS');
        const badgeColor = isObs ? '#3B82F6' : '#10B981';
        const badgeBg = isObs ? 'rgba(59, 130, 246, 0.12)' : 'rgba(16, 185, 129, 0.12)';
        const badgeBorder = isObs ? 'rgba(59, 130, 246, 0.3)' : 'rgba(16, 185, 129, 0.3)';
        tokens.push(
          <span
            key={`cit-${match.index}`}
            className="citation-badge"
            data-citation-id={citationId}
            title={isObs ? `Target Observation Evidence: ${citationId}` : `Security Artifact: ${citationId}`}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              padding: '1px 6px',
              margin: '0 2px',
              borderRadius: '4px',
              fontSize: '11.5px',
              fontFamily: '"JetBrains Mono", Consolas, Menlo, monospace',
              fontWeight: 600,
              backgroundColor: badgeBg,
              color: badgeColor,
              border: `1px solid ${badgeBorder}`,
              verticalAlign: 'baseline',
            }}
          >
            {citationId}
          </span>
        );
      } else if (standardId) {
        tokens.push(
          <span
            key={`std-${match.index}`}
            className="citation-badge citation-standard"
            data-standard-id={standardId}
            title={`Security Knowledge Standard: ${standardId}`}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              padding: '1px 6px',
              margin: '0 2px',
              borderRadius: '4px',
              fontSize: '11.5px',
              fontFamily: '"JetBrains Mono", Consolas, Menlo, monospace',
              fontWeight: 600,
              backgroundColor: 'rgba(139, 92, 246, 0.12)',
              color: '#8B5CF6',
              border: '1px solid rgba(139, 92, 246, 0.3)',
              verticalAlign: 'baseline',
            }}
          >
            {standardId}
          </span>
        );
      } else if (fullMatch.startsWith('**') && fullMatch.endsWith('**')) {
        tokens.push(
          <strong key={`b-${match.index}`} style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
            {fullMatch.slice(2, -2)}
          </strong>
        );
      } else if (fullMatch.startsWith('`') && fullMatch.endsWith('`')) {
        tokens.push(
          <code
            key={`c-${match.index}`}
            style={{
              backgroundColor: 'var(--bg-surface-muted)',
              padding: '2px 5px',
              borderRadius: '4px',
              fontSize: '12.5px',
              fontFamily: '"JetBrains Mono", Consolas, Menlo, monospace',
              color: 'var(--text-primary)',
              border: '1px solid var(--border-subtle)',
            }}
          >
            {fullMatch.slice(1, -1)}
          </code>
        );
      } else if (fullMatch.startsWith('*') && fullMatch.endsWith('*')) {
        tokens.push(<em key={`i-${match.index}`}>{fullMatch.slice(1, -1)}</em>);
      }
      lastIndex = regex.lastIndex;
    }
    if (lastIndex < text.length) {
      tokens.push(text.slice(lastIndex));
    }
    return tokens.length > 0 ? tokens : text;
  };

  // Safe block-level Markdown parsing
  const renderMarkdownBlocks = () => {
    const lines = content.split('\n');
    const blocks: React.ReactNode[] = [];
    let inCode = false;
    let codeLang = '';
    let codeLines: string[] = [];
    let tableLines: string[] = [];
    let listItems: { ordered: boolean; num?: string; text: string }[] = [];
    let blockquoteLines: string[] = [];

    const flushBlockquote = (key: string) => {
      if (blockquoteLines.length === 0) return;
      const fullQuote = blockquoteLines.join('\n');
      const isUnverifiedDisclaimer =
        fullQuote.includes('General model knowledge') ||
        fullQuote.includes('not verified against ingested sources');

      if (isUnverifiedDisclaimer) {
        blocks.push(
          <div
            key={key}
            data-testid="general-model-knowledge-disclaimer"
            style={{
              margin: '16px 0',
              padding: '12px 16px',
              backgroundColor: 'rgba(225, 29, 72, 0.08)',
              borderLeft: '4px solid var(--accent-primary)',
              borderRadius: '0 var(--radius-md) var(--radius-md) 0',
              color: 'var(--text-primary)',
              boxShadow: 'var(--shadow-subtle)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
              <span style={{ fontSize: '14px' }}>⚠️</span>
              <span
                style={{
                  fontSize: '12px',
                  fontWeight: 700,
                  letterSpacing: '0.04em',
                  textTransform: 'uppercase',
                  color: 'var(--accent-primary)',
                }}
              >
                General Model Knowledge — Not Verified Against Ingested Sources
              </span>
            </div>
            <div style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
              {blockquoteLines.map((bLine, bIdx) => {
                const clean = bLine
                  .replace(/^>\s*/, '')
                  .replace(/^⚠️\s*\*\*General model knowledge[^*]*\*\*\s*/i, '')
                  .trim();
                return clean ? (
                  <p key={bIdx} style={{ margin: '4px 0' }}>
                    {renderInlineMarkdown(clean)}
                  </p>
                ) : null;
              })}
            </div>
          </div>
        );
      } else {
        blocks.push(
          <blockquote
            key={key}
            style={{
              margin: '12px 0',
              padding: '8px 16px',
              borderLeft: '3px solid var(--border-strong)',
              backgroundColor: 'var(--bg-surface-muted)',
              color: 'var(--text-secondary)',
              fontStyle: 'italic',
              borderRadius: '0 var(--radius-sm) var(--radius-sm) 0',
            }}
          >
            {blockquoteLines.map((bLine, bIdx) => (
              <p key={bIdx} style={{ margin: '4px 0' }}>
                {renderInlineMarkdown(bLine.replace(/^>\s*/, ''))}
              </p>
            ))}
          </blockquote>
        );
      }
      blockquoteLines = [];
    };

    const flushList = (key: string) => {
      if (listItems.length === 0) return;
      const isOrdered = listItems[0].ordered;
      const startNum = listItems[0].num ? parseInt(listItems[0].num, 10) : 1;
      blocks.push(
        isOrdered ? (
          <ol
            key={key}
            start={startNum}
            style={{ margin: '8px 0 12px 22px', padding: 0, lineHeight: 1.6 }}
          >
            {listItems.map((item, idx) => (
              <li
                key={idx}
                value={item.num ? parseInt(item.num, 10) : undefined}
                style={{ marginBottom: '6px' }}
              >
                {renderInlineMarkdown(item.text)}
              </li>
            ))}
          </ol>
        ) : (
          <ul key={key} style={{ margin: '8px 0 12px 22px', padding: 0, lineHeight: 1.6 }}>
            {listItems.map((item, idx) => (
              <li key={idx} style={{ marginBottom: '6px' }}>
                {renderInlineMarkdown(item.text)}
              </li>
            ))}
          </ul>
        )
      );
      listItems = [];
    };

    const flushTable = (key: string) => {
      if (tableLines.length === 0) return;
      const rows = tableLines.map((r) => r.split('|').slice(1, -1).map((c) => c.trim()));
      if (rows.length > 0) {
        const header = rows[0];
        const dataRows = rows.slice(rows.length > 1 && rows[1].every((c) => c.match(/^:?-+:?$/)) ? 2 : 1);
        blocks.push(
          <div key={key} style={{ overflowX: 'auto', margin: '14px 0' }}>
            <table style={{ borderCollapse: 'collapse', width: '100%', fontSize: '13px' }}>
              <thead>
                <tr style={{ borderBottom: '2px solid var(--border-strong)', textAlign: 'left' }}>
                  {header.map((th, hIdx) => (
                    <th key={hIdx} style={{ padding: '6px 10px', fontWeight: 600 }}>
                      {renderInlineMarkdown(th)}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {dataRows.map((tr, rIdx) => (
                  <tr key={rIdx} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                    {tr.map((td, dIdx) => (
                      <td key={dIdx} style={{ padding: '6px 10px' }}>
                        {renderInlineMarkdown(td)}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        );
      }
      tableLines = [];
    };

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Code blocks
      if (line.trim().startsWith('```')) {
        flushList(`list-${i}`);
        flushTable(`tbl-${i}`);
        flushBlockquote(`quote-${i}`);
        if (!inCode) {
          inCode = true;
          codeLang = line.trim().replace('```', '').trim() || 'plaintext';
          codeLines = [];
        } else {
          inCode = false;
          const codeText = codeLines.join('\n');
          const codeIdx = i;
          blocks.push(
            <div
              key={`code-${i}`}
              style={{
                margin: '14px 0',
                backgroundColor: '#1E1E1E',
                borderRadius: '6px',
                border: '1px solid #333333',
                overflow: 'hidden',
              }}
            >
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  padding: '5px 12px',
                  backgroundColor: '#2D2D2D',
                  color: '#999999',
                  fontSize: '11px',
                  fontFamily: 'monospace',
                }}
              >
                <span>{codeLang.toUpperCase()}</span>
                <button
                  onClick={() => handleCopyCode(codeIdx, codeText)}
                  style={{
                    background: 'none',
                    border: 'none',
                    color: copiedCodeBlock === codeIdx ? '#4ADE80' : '#CCCCCC',
                    cursor: 'pointer',
                    fontSize: '11px',
                  }}
                >
                  {copiedCodeBlock === codeIdx ? '✓ Copied' : 'Copy'}
                </button>
              </div>
              <pre
                style={{
                  margin: 0,
                  padding: '12px 14px',
                  color: '#D4D4D4',
                  fontSize: '13px',
                  fontFamily: '"JetBrains Mono", Consolas, Menlo, monospace',
                  overflowX: 'auto',
                  lineHeight: 1.5,
                  whiteSpace: 'pre',
                }}
              >
                <code>{codeText}</code>
              </pre>
            </div>
          );
        }
        continue;
      }

      if (inCode) {
        codeLines.push(line);
        continue;
      }

      // Blockquotes (> ...)
      if (line.trim().startsWith('>')) {
        flushList(`list-${i}`);
        flushTable(`tbl-${i}`);
        blockquoteLines.push(line.trim());
        continue;
      } else if (blockquoteLines.length > 0) {
        flushBlockquote(`quote-${i}`);
      }

      // Tables
      if (line.trim().startsWith('|') && line.trim().endsWith('|')) {
        flushList(`list-${i}`);
        tableLines.push(line.trim());
        continue;
      } else if (tableLines.length > 0) {
        flushTable(`tbl-${i}`);
      }

      // Lists
      const orderedMatch = line.match(/^(\d+)\.\s+(.*)$/);
      const unorderedMatch = line.match(/^[-*]\s+(.*)$/);

      if (orderedMatch) {
        if (listItems.length > 0 && !listItems[0].ordered) flushList(`list-${i}`);
        listItems.push({ ordered: true, num: orderedMatch[1], text: orderedMatch[2] });
        continue;
      } else if (unorderedMatch) {
        if (listItems.length > 0 && listItems[0].ordered) flushList(`list-${i}`);
        listItems.push({ ordered: false, text: unorderedMatch[1] });
        continue;
      } else if (line.trim().length === 0 && listItems.length > 0) {
        // Check if the list continues after this blank line (loose list handling)
        let continuesList = false;
        for (let j = i + 1; j < lines.length; j++) {
          const nextTrim = lines[j].trim();
          if (nextTrim.length === 0) continue;
          if (listItems[0].ordered && nextTrim.match(/^\d+\.\s+/)) {
            continuesList = true;
          } else if (!listItems[0].ordered && nextTrim.match(/^[-*]\s+/)) {
            continuesList = true;
          }
          break;
        }
        if (continuesList) {
          continue;
        } else {
          flushList(`list-${i}`);
        }
      } else {
        flushList(`list-${i}`);
      }

      // Headings
      const h1 = line.match(/^#\s+(.*)$/);
      const h2 = line.match(/^##\s+(.*)$/);
      const h3 = line.match(/^###\s+(.*)$/);
      const h4 = line.match(/^####\s+(.*)$/);

      if (h1) {
        blocks.push(
          <h2 key={`h1-${i}`} style={{ fontSize: '18px', fontWeight: 600, margin: '20px 0 8px 0', color: 'var(--text-primary)' }}>
            {renderInlineMarkdown(h1[1])}
          </h2>
        );
      } else if (h2) {
        blocks.push(
          <h3 key={`h2-${i}`} style={{ fontSize: '16px', fontWeight: 600, margin: '18px 0 6px 0', color: 'var(--text-primary)' }}>
            {renderInlineMarkdown(h2[1])}
          </h3>
        );
      } else if (h3) {
        blocks.push(
          <h4 key={`h3-${i}`} style={{ fontSize: '15px', fontWeight: 600, margin: '16px 0 6px 0', color: 'var(--text-primary)' }}>
            {renderInlineMarkdown(h3[1])}
          </h4>
        );
      } else if (h4) {
        blocks.push(
          <h5 key={`h4-${i}`} style={{ fontSize: '14px', fontWeight: 600, margin: '14px 0 4px 0', color: 'var(--text-primary)' }}>
            {renderInlineMarkdown(h4[1])}
          </h5>
        );
      } else if (line.trim().length === 0) {
        blocks.push(<div key={`sp-${i}`} style={{ height: '8px' }} />);
      } else {
        blocks.push(
          <p key={`p-${i}`} style={{ margin: '6px 0', lineHeight: 1.6, color: 'var(--text-primary)', wordBreak: 'break-word' }}>
            {renderInlineMarkdown(line)}
          </p>
        );
      }
    }

    flushList('list-end');
    flushTable('tbl-end');
    flushBlockquote('quote-end');

    if (inCode && codeLines.length > 0) {
      blocks.push(
        <pre key="unclosed-code" style={{ margin: '12px 0', padding: '12px', backgroundColor: '#1E1E1E', color: '#D4D4D4', borderRadius: '6px' }}>
          <code>{codeLines.join('\n')}</code>
        </pre>
      );
    }

    return blocks;
  };

  return (
    <div
      ref={containerRef}
      className="conversational-response-container"
      style={{
        width: '100%',
        display: 'flex',
        flexDirection: 'column',
      }}
    >
      {/* Search Bar if triggered */}
      {searchActive && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            padding: '6px 12px',
            backgroundColor: '#FEF9C3',
            border: '1px solid #FDE047',
            borderRadius: 'var(--radius-sm)',
            marginBottom: '10px',
          }}
        >
          <input
            type="text"
            placeholder="Search in answer..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{
              padding: '4px 8px',
              fontSize: '12px',
              border: '1px solid #FACC15',
              borderRadius: '4px',
              outline: 'none',
              width: '200px',
            }}
          />
          <button
            onClick={() => {
              setSearchQuery('');
              setSearchActive(false);
            }}
            style={{
              marginLeft: 'auto',
              border: 'none',
              background: 'none',
              cursor: 'pointer',
              fontSize: '12px',
              color: '#854D0E',
            }}
          >
            ✕
          </button>
        </div>
      )}

      {/* Main Conversational Markdown Body */}
      <div
        style={{
          fontSize: '14.5px',
          lineHeight: 1.6,
          color: 'var(--text-primary)',
          wordBreak: 'break-word',
        }}
      >
        {renderMarkdownBlocks()}
      </div>

      {/* Subtle Bottom Provenance & Action Row */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          marginTop: '10px',
          paddingTop: '6px',
          fontSize: '11.5px',
          color: 'var(--text-muted)',
          flexWrap: 'wrap',
          gap: '8px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span>• Local AI - {modelDisplay}</span>
          {isGenerating && (
            <span style={{ color: '#2563EB', fontWeight: 500 }}>Generating...</span>
          )}
          {isTokenLimit && (
            <span style={{ color: '#D97706', fontWeight: 500 }}>Token limit reached</span>
          )}
          {isUserStopped && (
            <span style={{ color: '#DC2626' }}>Stopped</span>
          )}
          {isError && (
            <span style={{ color: '#DC2626' }}>Service Unavailable</span>
          )}
          {statusMessage && (
            <span style={{ fontStyle: 'italic', color: 'var(--text-secondary)' }}>({statusMessage})</span>
          )}
        </div>

        {/* Subtle, Unobtrusive Actions */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          {isGenerating && (
            <button
              onClick={handleStop}
              disabled={loadingAction === 'stop'}
              style={{
                padding: '2px 8px',
                fontSize: '11px',
                backgroundColor: '#EF4444',
                color: '#FFF',
                border: 'none',
                borderRadius: '4px',
                cursor: 'pointer',
                fontWeight: 500,
              }}
            >
              Stop
            </button>
          )}

          {isTokenLimit && (
            <button
              onClick={handleContinue}
              disabled={loadingAction === 'continue'}
              style={{
                padding: '2px 8px',
                fontSize: '11px',
                backgroundColor: '#2563EB',
                color: '#FFF',
                border: 'none',
                borderRadius: '4px',
                cursor: 'pointer',
                fontWeight: 500,
              }}
            >
              ▶ Continue
            </button>
          )}

          <button
            onClick={handleCopyAll}
            title="Copy answer"
            style={{
              background: 'none',
              border: 'none',
              color: copiedAll ? '#16A34A' : 'var(--text-muted)',
              cursor: 'pointer',
              padding: '2px 6px',
              fontSize: '11.5px',
            }}
          >
            {copiedAll ? '✓ Copied' : 'Copy'}
          </button>

          <button
            onClick={() => handleDownload('markdown')}
            title="Download as Markdown"
            style={{
              background: 'none',
              border: 'none',
              color: 'var(--text-muted)',
              cursor: 'pointer',
              padding: '2px 6px',
              fontSize: '11.5px',
            }}
          >
            MD ↓
          </button>

          <button
            onClick={() => handleDownload('txt')}
            title="Download as Plain Text"
            style={{
              background: 'none',
              border: 'none',
              color: 'var(--text-muted)',
              cursor: 'pointer',
              padding: '2px 6px',
              fontSize: '11.5px',
            }}
          >
            TXT ↓
          </button>

          <button
            onClick={() => setSearchActive(!searchActive)}
            title="Search in answer"
            style={{
              background: 'none',
              border: 'none',
              color: searchActive ? 'var(--text-primary)' : 'var(--text-muted)',
              cursor: 'pointer',
              padding: '2px 6px',
              fontSize: '11.5px',
            }}
          >
            Search
          </button>

          <button
            onClick={handleRegenerate}
            disabled={loadingAction === 'regenerate'}
            title="Regenerate this answer"
            style={{
              background: 'none',
              border: 'none',
              color: 'var(--text-muted)',
              cursor: 'pointer',
              padding: '2px 6px',
              fontSize: '11.5px',
            }}
          >
            ↻
          </button>

          {responseId && (
            <button
              onClick={() => setShowMetadata(!showMetadata)}
              title="Diagnostics & Chunk Lineage"
              style={{
                background: 'none',
                border: 'none',
                color: showMetadata ? 'var(--text-primary)' : 'var(--text-muted)',
                cursor: 'pointer',
                padding: '2px 6px',
                fontSize: '11.5px',
              }}
            >
              ℹ
            </button>
          )}
        </div>
      </div>

      {/* Expandable Diagnostic Drawer (Only on explicit click) */}
      {showMetadata && (
        <div
          style={{
            marginTop: '10px',
            padding: '10px 14px',
            backgroundColor: 'var(--bg-surface-muted)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 'var(--radius-sm)',
            fontSize: '12px',
            color: 'var(--text-secondary)',
            display: 'flex',
            flexDirection: 'column',
            gap: '8px',
          }}
        >
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '16px' }}>
            <div><strong>Model:</strong> {message.model_name || 'qwen2.5-coder:7b'}</div>
            <div><strong>Response ID:</strong> {responseId || 'N/A'}</div>
            <div><strong>Status:</strong> {message.status || 'COMPLETED'}</div>
            {responseId && (
              <div style={{ display: 'flex', gap: '10px' }}>
                <button
                  onClick={handleToggleChunks}
                  style={{ background: 'none', border: 'none', color: '#2563EB', textDecoration: 'underline', cursor: 'pointer', fontSize: '11.5px' }}
                >
                  {showChunks ? 'Hide Chunks' : 'View Chunks'}
                </button>
                <button
                  onClick={handleToggleVersions}
                  style={{ background: 'none', border: 'none', color: '#2563EB', textDecoration: 'underline', cursor: 'pointer', fontSize: '11.5px' }}
                >
                  {showVersions ? 'Hide Versions' : 'View Versions'}
                </button>
              </div>
            )}
          </div>

          {showChunks && chunks.length > 0 && (
            <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: '8px', fontSize: '11px' }}>
              <div style={{ fontWeight: 600, marginBottom: '4px' }}>Chunk Lineage:</div>
              {chunks.map((c) => (
                <div key={c.chunk_id} style={{ marginBottom: '2px' }}>
                  Chunk #{c.sequence_number} | Tokens: {c.token_count} | Stop: <code>{c.stop_reason}</code> | Time: {c.generation_time}s
                </div>
              ))}
            </div>
          )}

          {showVersions && versions.length > 0 && (
            <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: '8px', fontSize: '11px' }}>
              <div style={{ fontWeight: 600, marginBottom: '4px' }}>Version History:</div>
              {versions.map((v) => (
                <div key={v.version_id} style={{ marginBottom: '2px' }}>
                  Version #{v.version_number} ({v.model}) - {v.status} ({new Date(v.created_at).toLocaleTimeString()})
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
