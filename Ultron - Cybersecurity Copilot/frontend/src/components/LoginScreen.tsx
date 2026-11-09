import React, { useState } from 'react';
import { login } from '../api';
import type { UserSession } from '../types';

interface LoginScreenProps {
  onLoginSuccess: (session: UserSession) => void;
}

export const LoginScreen: React.FC<LoginScreenProps> = ({ onLoginSuccess }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanUsername = username.trim();
    if (!cleanUsername) {
      setError('Username is required.');
      return;
    }
    if (!password) {
      setError('Password is required.');
      return;
    }

    setSubmitting(true);
    setError(null);

    try {
      const session = await login(cleanUsername, password);
      onLoginSuccess(session);
    } catch (err: any) {
      setError(err.message || 'Invalid username or password.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div
      style={{
        width: '100vw',
        minWidth: '100vw',
        minHeight: '100vh',
        flex: '1 0 100%',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'radial-gradient(ellipse 70% 55% at 50% 45%, rgba(225, 29, 72, 0.045) 0%, rgba(11, 15, 23, 0) 70%), var(--bg-app)',
        padding: '24px',
        boxSizing: 'border-box',
      }}
    >
      <div
        className="card-base"
        style={{
          width: '100%',
          maxWidth: '380px',
          backgroundColor: 'rgba(15, 22, 34, 0.78)',
          backdropFilter: 'blur(20px)',
          WebkitBackdropFilter: 'blur(20px)',
          border: '1px solid rgba(255, 255, 255, 0.08)',
          borderRadius: 'var(--radius-xl)',
          padding: '36px 32px 28px 32px',
          boxShadow: '0 24px 48px -12px rgba(0, 0, 0, 0.75), inset 0 1px 0 rgba(255, 255, 255, 0.08)',
          boxSizing: 'border-box',
        }}
      >
        <div style={{ textAlign: 'center', marginBottom: '26px' }}>
          {/* Bespoke Geometric Emblem */}
          <div
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              justifyContent: 'center',
              width: '42px',
              height: '42px',
              borderRadius: '10px',
              background: 'linear-gradient(135deg, rgba(225, 29, 72, 0.16) 0%, rgba(15, 22, 34, 0.8) 100%)',
              border: '1px solid rgba(225, 29, 72, 0.35)',
              boxShadow: '0 0 20px rgba(225, 29, 72, 0.12)',
              marginBottom: '14px',
              color: 'var(--accent-primary)',
            }}
          >
            <svg
              width="20"
              height="20"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M12 2L4 6v6c0 5.5 3.5 10.7 8 12 4.5-1.3 8-6.5 8-12V6l-8-4z" />
              <circle cx="12" cy="11" r="2" fill="var(--accent-primary)" />
              <path d="M12 13v3" stroke="var(--accent-primary)" strokeWidth="1.5" />
            </svg>
          </div>

          <h1
            style={{
              fontSize: '15px',
              fontWeight: 700,
              color: 'var(--text-primary)',
              letterSpacing: '0.12em',
              margin: 0,
            }}
          >
            ULTRON
          </h1>

          <div
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              marginTop: '6px',
              padding: '3px 8px',
              borderRadius: '12px',
              background: 'rgba(255, 255, 255, 0.03)',
              border: '1px solid rgba(255, 255, 255, 0.06)',
            }}
          >
            <span
              style={{
                width: '5px',
                height: '5px',
                borderRadius: '50%',
                backgroundColor: '#10B981',
                boxShadow: '0 0 6px rgba(16, 185, 129, 0.6)',
              }}
            />
            <span
              style={{
                fontSize: '10.5px',
                color: 'var(--text-secondary)',
                letterSpacing: '0.04em',
                textTransform: 'uppercase',
                fontWeight: 500,
              }}
            >
              Security Gateway
            </span>
          </div>
        </div>

        {error && (
          <div
            role="alert"
            style={{
              padding: '10px 12px',
              borderRadius: 'var(--radius-sm)',
              background: 'var(--badge-red-bg)',
              color: 'var(--badge-red-text)',
              fontSize: '12px',
              border: '1px solid var(--badge-red-border)',
              marginBottom: '18px',
              lineHeight: 1.4,
            }}
          >
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>
          <div>
            <label
              htmlFor="username"
              style={{
                display: 'block',
                fontSize: '11px',
                fontWeight: 600,
                color: 'var(--text-secondary)',
                textTransform: 'uppercase',
                letterSpacing: '0.05em',
                marginBottom: '6px',
              }}
            >
              Username
            </label>
            <input
              id="username"
              type="text"
              autoComplete="username"
              autoFocus
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="admin"
              required
              disabled={submitting}
              style={{
                width: '100%',
                padding: '9px 12px',
                fontSize: '13px',
                backgroundColor: 'rgba(22, 32, 48, 0.55)',
                border: '1px solid rgba(255, 255, 255, 0.09)',
                borderRadius: 'var(--radius-md)',
                color: 'var(--text-primary)',
                outline: 'none',
                boxSizing: 'border-box',
              }}
            />
          </div>

          <div>
            <label
              htmlFor="password"
              style={{
                display: 'block',
                fontSize: '11px',
                fontWeight: 600,
                color: 'var(--text-secondary)',
                textTransform: 'uppercase',
                letterSpacing: '0.05em',
                marginBottom: '6px',
              }}
            >
              Password
            </label>
            <input
              id="password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••••••"
              required
              disabled={submitting}
              style={{
                width: '100%',
                padding: '9px 12px',
                fontSize: '13px',
                backgroundColor: 'rgba(22, 32, 48, 0.55)',
                border: '1px solid rgba(255, 255, 255, 0.09)',
                borderRadius: 'var(--radius-md)',
                color: 'var(--text-primary)',
                outline: 'none',
                boxSizing: 'border-box',
              }}
            />
          </div>

          <button
            type="submit"
            disabled={submitting}
            style={{
              marginTop: '6px',
              padding: '10px 16px',
              borderRadius: 'var(--radius-md)',
              background: 'linear-gradient(180deg, #E11D48 0%, #BE123C 100%)',
              boxShadow: '0 2px 8px rgba(225, 29, 72, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.2)',
              color: '#ffffff',
              fontSize: '13px',
              fontWeight: 600,
              letterSpacing: '0.02em',
              border: 'none',
              cursor: submitting ? 'not-allowed' : 'pointer',
              opacity: submitting ? 0.75 : 1,
              transition: 'all 0.15s ease',
            }}
          >
            {submitting ? 'Authenticating...' : 'Sign In'}
          </button>
        </form>

        <div
          style={{
            marginTop: '24px',
            paddingTop: '16px',
            borderTop: '1px solid rgba(255, 255, 255, 0.06)',
            fontSize: '11px',
            color: 'var(--text-muted)',
            textAlign: 'center',
            lineHeight: 1.5,
          }}
        >
          Air-gapped local environment · Scrypt verification
          <br />
          Provision operators via <code style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>src.dashboard.bootstrap</code>
        </div>
      </div>
    </div>
  );
};
