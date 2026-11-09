import React, { useState, useRef, useEffect } from 'react';

interface ComposerProps {
  onSend: (message: string) => Promise<void>;
  onStop?: () => Promise<void>;
  loading: boolean;
  hasMessages?: boolean;
}

const STARTER_PROMPTS = [
  'Analyze the current target evidence.',
  'Show open evidence gaps and invariants.',
  'Synthesize hypotheses and attack vectors.',
];

export const Composer: React.FC<ComposerProps> = ({ onSend, onStop, loading, hasMessages = false }) => {
  const [input, setInput] = useState('');
  const [stopping, setStopping] = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto';
      textareaRef.current.style.height = `${Math.min(textareaRef.current.scrollHeight, 180)}px`;
    }
  }, [input]);

  const handleSubmit = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const trimmed = input.trim();
    if (!trimmed || loading) return;
    setInput('');
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto';
    }
    await onSend(trimmed);
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSubmit();
    }
  };

  return (
    <div
      style={{
        padding: '12px 28px 24px 28px',
        backgroundColor: 'var(--bg-app)',
        maxWidth: '780px',
        margin: '0 auto',
        width: '100%',
      }}
    >
      {/* Starter Prompts - only shown when conversation is empty */}
      {!hasMessages && (
        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginBottom: '12px' }}>
          {STARTER_PROMPTS.map((prompt, idx) => (
            <button
              key={idx}
              onClick={() => onSend(prompt)}
              disabled={loading}
              style={{
                padding: '5px 12px',
                fontSize: '12px',
                backgroundColor: 'var(--bg-surface)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-sm)',
                color: 'var(--text-secondary)',
                cursor: 'pointer',
                transition: 'all 0.15s ease',
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.backgroundColor = 'var(--bg-surface-hover)';
                e.currentTarget.style.color = 'var(--text-primary)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.backgroundColor = 'var(--bg-surface)';
                e.currentTarget.style.color = 'var(--text-secondary)';
              }}
            >
              {prompt}
            </button>
          ))}
        </div>
      )}

      {/* Main Composer Box */}
      <div
        style={{
          display: 'flex',
          flexDirection: 'column',
          padding: '12px 16px',
          backgroundColor: 'var(--bg-surface)',
          borderRadius: 'var(--radius-lg)',
          border: '1px solid var(--border-subtle)',
          boxShadow: 'var(--shadow-subtle)',
        }}
      >
        <textarea
          ref={textareaRef}
          rows={2}
          placeholder="Ask Ultron a security question or describe target observations..."
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          disabled={loading}
          style={{
            border: 'none',
            resize: 'none',
            fontSize: '14.5px',
            lineHeight: 1.5,
            padding: '2px 0',
            backgroundColor: 'transparent',
            outline: 'none',
            boxShadow: 'none',
            width: '100%',
            color: 'var(--text-primary)',
          }}
        />

        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '8px' }}>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            Enter to send · Shift+Enter for newline
          </span>

          {loading && onStop ? (
            <button
              type="button"
              onClick={async () => {
                if (stopping) return;
                setStopping(true);
                try {
                  await onStop();
                } finally {
                  setStopping(false);
                }
              }}
              disabled={stopping}
              aria-label="Stop generation"
              title="Stop generation"
              style={{
                height: '28px',
                padding: '0 12px',
                borderRadius: 'var(--radius-sm, 6px)',
                backgroundColor: 'rgba(239, 68, 68, 0.15)',
                color: '#EF4444',
                border: '1px solid rgba(239, 68, 68, 0.35)',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                fontSize: '12px',
                fontWeight: 600,
                cursor: stopping ? 'not-allowed' : 'pointer',
                transition: 'all 0.15s ease',
              }}
            >
              <span
                style={{
                  width: '8px',
                  height: '8px',
                  borderRadius: '1px',
                  backgroundColor: '#EF4444',
                  display: 'inline-block',
                }}
              />
              {stopping ? 'Stopping…' : 'Stop'}
            </button>
          ) : (
            <button
              onClick={() => handleSubmit()}
              disabled={!input.trim() || loading}
              aria-label="Send message"
              style={{
                width: '28px',
                height: '28px',
                borderRadius: '50%',
                backgroundColor: input.trim() && !loading ? 'var(--accent-primary)' : 'var(--border-subtle)',
                color: '#FFFFFF',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '14px',
                cursor: input.trim() && !loading ? 'pointer' : 'default',
                transition: 'background-color 0.15s ease',
              }}
            >
              ↑
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
