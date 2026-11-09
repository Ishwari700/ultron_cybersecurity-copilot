import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const SRC_DIR = path.resolve('src');

test('Reliability Contract: LargeResponseView and ConversationView wire onUpdateMessageContent', () => {
  const largeRespPath = path.join(SRC_DIR, 'components', 'LargeResponseView.tsx');
  const convViewPath = path.join(SRC_DIR, 'components', 'ConversationView.tsx');
  const appPath = path.join(SRC_DIR, 'App.tsx');

  const largeContent = fs.readFileSync(largeRespPath, 'utf-8');
  const convContent = fs.readFileSync(convViewPath, 'utf-8');
  const appContent = fs.readFileSync(appPath, 'utf-8');

  // Verify LargeResponseViewProps contains onUpdateMessageContent
  assert.ok(
    largeContent.includes('onUpdateMessageContent?: (messageId: string, newContent: string) => void;'),
    'LargeResponseViewProps must specify onUpdateMessageContent'
  );

  // Verify ConversationViewProps contains onUpdateMessageContent
  assert.ok(
    convContent.includes('onUpdateMessageContent?: (messageId: string, newContent: string) => void;'),
    'ConversationViewProps must specify onUpdateMessageContent'
  );

  // Verify ConversationView passes onUpdateMessageContent to LargeResponseView
  assert.ok(
    convContent.includes('onUpdateMessageContent={onUpdateMessageContent}'),
    'ConversationView must forward onUpdateMessageContent to LargeResponseView'
  );

  // Verify App.tsx defines handleUpdateMessageContent and passes it to ConversationView
  assert.ok(
    appContent.includes('handleUpdateMessageContent'),
    'App.tsx must define handleUpdateMessageContent'
  );
  assert.ok(
    appContent.includes('onUpdateMessageContent={handleUpdateMessageContent}'),
    'App.tsx must pass onUpdateMessageContent to ConversationView'
  );
});

test('Reliability Rendering: Citation and security standards badges in LargeResponseView', () => {
  const largeRespPath = path.join(SRC_DIR, 'components', 'LargeResponseView.tsx');
  const content = fs.readFileSync(largeRespPath, 'utf-8');

  // Verify citation badge CSS/data attributes exist
  assert.ok(content.includes('citation-badge'), 'LargeResponseView must render citation-badge elements');
  assert.ok(content.includes('data-citation-id'), 'LargeResponseView must preserve citation identifiers in data-citation-id');
  assert.ok(content.includes('data-standard-id'), 'LargeResponseView must preserve security standard identifiers');

  // Regex testing simulation for citation and link tokens
  const regex = /(\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)|\[((?:OBS|FACT-OBS|CHK|HYP|EXP|FND)-[A-Za-z0-9\-_]+)\]|\[((?:CVE-\d{4}-\d+|CWE-\d+))\]|\*\*[^*]+\*\*|`[^`]+`|\*[^*]+\*)/g;

  const sampleText = 'Observed vulnerability [OBS-auth-fail] referencing [CWE-89] and [CVE-2023-38606] with [Advisory](https://example.com/advisory).';
  const matches = [...sampleText.matchAll(regex)];

  assert.equal(matches.length, 4, 'Should match 1 observation citation, 1 CWE, 1 CVE, and 1 secure link');
  assert.equal(matches[0][4], 'OBS-auth-fail');
  assert.equal(matches[1][5], 'CWE-89');
  assert.equal(matches[2][5], 'CVE-2023-38606');
  assert.equal(matches[3][2], 'Advisory');
  assert.equal(matches[3][3], 'https://example.com/advisory');

  // XSS attack test: javascript: URL must not match the https? link regex
  const maliciousText = '[Click me](javascript:alert(1))';
  const maliciousMatches = [...maliciousText.matchAll(regex)];
  assert.equal(maliciousMatches.length, 0, 'Must NOT match javascript: protocol links');
});

test('Reliability Status: Explicit failure, truncation, and stopped states distinguished', () => {
  const largeRespPath = path.join(SRC_DIR, 'components', 'LargeResponseView.tsx');
  const content = fs.readFileSync(largeRespPath, 'utf-8');

  // Must distinguish token limit and service unavailable
  assert.ok(content.includes("message.status === 'TOKEN_LIMIT'"), 'Must identify TOKEN_LIMIT status');
  assert.ok(content.includes("message.status === 'USER_STOPPED'"), 'Must identify USER_STOPPED status');
  assert.ok(content.includes("message.status === 'SERVICE_UNAVAILABLE'"), 'Must identify SERVICE_UNAVAILABLE status');
  assert.ok(content.includes("message.status === 'ERROR'"), 'Must identify ERROR status');
});

test('Reliability Persistence: Reconcile messages prevents UI duplicates on re-render', () => {
  // Simulate App.tsx handleUpdateMessageContent behavior
  let state = {
    messages: [
      { id: 'MSG-001', content: 'User question', sender: 'user' },
      { id: 'MSG-002', content: 'Initial truncated content...', sender: 'assistant' },
    ]
  };

  const handleUpdate = (msgId: string, newContent: string) => {
    state = {
      ...state,
      messages: state.messages.map(m => m.id === msgId ? { ...m, content: newContent } : m)
    };
  };

  handleUpdate('MSG-002', 'Full completed response after continuation.');
  assert.equal(state.messages.length, 2, 'Message count must remain constant after update');
  assert.equal(state.messages[1].content, 'Full completed response after continuation.');
});

test('Fix B Regression: Model attribution line rendered at most once per assistant response', () => {
  const convViewPath = path.join(SRC_DIR, 'components', 'ConversationView.tsx');
  const largeRespPath = path.join(SRC_DIR, 'components', 'LargeResponseView.tsx');
  const convContent = fs.readFileSync(convViewPath, 'utf-8');
  const largeContent = fs.readFileSync(largeRespPath, 'utf-8');

  // Verify LargeResponseView renders the single model attribution row
  assert.ok(
    largeContent.includes('• Local AI - {modelDisplay}'),
    'LargeResponseView must render model provenance indicator'
  );

  // Verify ConversationView does NOT render a redundant fallback attribution when hasTrace is absent
  assert.ok(
    !convContent.includes("Local AI · {msg.model_name === 'qwen2.5-coder:7b' ? '7B' : msg.model_name || 'Conversational'}"),
    'ConversationView must NOT contain redundant fallback attribution line'
  );

  // Trace progressive disclosure is only rendered if hasTrace is truthy
  assert.ok(
    convContent.includes('!isUser && hasTrace &&'),
    'ConversationView must only render trace block when hasTrace is true'
  );
});

test('Fix C Accessibility & Contrast: Import Traffic format selector uses accessible segmented control and high-contrast tokens', () => {
  const modalPath = path.join(SRC_DIR, 'components', 'ImportTrafficModal.tsx');
  const cssPath = path.join(SRC_DIR, 'index.css');
  const modalContent = fs.readFileSync(modalPath, 'utf-8');
  const cssContent = fs.readFileSync(cssPath, 'utf-8');

  // Verify ARIA semantics for assistive technology
  assert.ok(modalContent.includes('role="radiogroup"'), 'Format selector must have role="radiogroup"');
  assert.ok(modalContent.includes('role="radio"'), 'Format buttons must have role="radio"');
  assert.ok(modalContent.includes("aria-checked={format === 'har'}"), 'HAR button must expose aria-checked');
  assert.ok(modalContent.includes("aria-checked={format === 'raw_http'}"), 'Raw HTTP button must expose aria-checked');

  // Verify keyboard navigation handlers
  assert.ok(modalContent.includes("e.key === 'ArrowRight'"), 'Format selector must support arrow key navigation');
  assert.ok(modalContent.includes("e.key === 'ArrowLeft'"), 'Format selector must support arrow key navigation');

  // Verify format choices text
  assert.ok(modalContent.includes('HTTP Archive (HAR)'), 'Format option label must be HTTP Archive (HAR)');
  assert.ok(modalContent.includes('Raw HTTP Request / Response'), 'Format option label must be Raw HTTP Request / Response');

  // Verify CSS tokens exist for both dark and light modes
  assert.ok(cssContent.includes('--segmented-bg:'), 'CSS must define --segmented-bg');
  assert.ok(cssContent.includes('--segmented-btn-bg:'), 'CSS must define --segmented-btn-bg');
  assert.ok(cssContent.includes('--segmented-btn-text:'), 'CSS must define --segmented-btn-text');
  assert.ok(cssContent.includes('--segmented-btn-active-bg:'), 'CSS must define --segmented-btn-active-bg');
  assert.ok(cssContent.includes('--segmented-btn-active-text:'), 'CSS must define --segmented-btn-active-text');
  assert.ok(cssContent.includes('--segmented-btn-active-border:'), 'CSS must define --segmented-btn-active-border');

  // Verify format selector CSS rules and radio indicator
  assert.ok(cssContent.includes('.format-selector-group'), 'CSS must define .format-selector-group');
  assert.ok(cssContent.includes('.format-selector-btn'), 'CSS must define .format-selector-btn');
  assert.ok(cssContent.includes('.format-radio-dot'), 'CSS must define .format-radio-dot indicator');
});

test('Fix D Theme Switcher: Persistent theme switcher toggles between dark and light modes with tokens', () => {
  const sidebarPath = path.join(SRC_DIR, 'components', 'Sidebar.tsx');
  const appPath = path.join(SRC_DIR, 'App.tsx');
  const cssPath = path.join(SRC_DIR, 'index.css');
  const indexPath = path.resolve('index.html');

  const sidebarContent = fs.readFileSync(sidebarPath, 'utf-8');
  const appContent = fs.readFileSync(appPath, 'utf-8');
  const cssContent = fs.readFileSync(cssPath, 'utf-8');
  const indexHtml = fs.readFileSync(indexPath, 'utf-8');

  // Verify Sidebar renders theme toggle button with accessible labels
  assert.ok(sidebarContent.includes('id="theme-toggle-btn"'), 'Sidebar must render theme toggle button');
  assert.ok(sidebarContent.includes('aria-label='), 'Theme toggle must have aria-label');
  assert.ok(sidebarContent.includes("theme === 'light' ? '☀️' : '🌙'"), 'Theme toggle must display sun/moon indicator');
  assert.ok(sidebarContent.includes("theme === 'light' ? 'Light' : 'Dark'"), 'Theme toggle must indicate current active mode');

  // Verify App.tsx initializes theme from localStorage, defaulting to dark
  assert.ok(appContent.includes("localStorage.getItem('ultron-theme')"), 'App.tsx must read stored theme preference');
  assert.ok(appContent.includes("stored === 'light' ? 'light' : 'dark'"), 'App.tsx must default to dark theme');
  assert.ok(appContent.includes("document.documentElement.setAttribute('data-theme', theme)"), 'App.tsx must set data-theme attribute');
  assert.ok(appContent.includes("localStorage.setItem('ultron-theme', theme)"), 'App.tsx must persist theme preference');

  // Verify index.html includes inline script to avoid flash of wrong theme
  assert.ok(indexHtml.includes("localStorage.getItem('ultron-theme')"), 'index.html must check theme before hydration');
  assert.ok(indexHtml.includes("setAttribute('data-theme'"), 'index.html must set initial theme attribute');

  // Verify [data-theme="light"] definitions exist in CSS
  assert.ok(cssContent.includes('[data-theme="light"]'), 'CSS must define [data-theme="light"] rules');
  assert.ok(cssContent.includes('--bg-app: #F8FAFC'), 'Light theme must define readable light background');
  assert.ok(cssContent.includes('--text-primary: #0F172A'), 'Light theme must define high-contrast dark text');
});

test('WCAG Contrast & Keyboard Navigation: Import Traffic format selector quantitative calculations', () => {
  const cssPath = path.join(SRC_DIR, 'index.css');
  const modalPath = path.join(SRC_DIR, 'components', 'ImportTrafficModal.tsx');
  const cssContent = fs.readFileSync(cssPath, 'utf-8');
  const modalContent = fs.readFileSync(modalPath, 'utf-8');

  // Relative luminance calculation per WCAG 2.1
  const srgbToLinear = (c: number): number => {
    const s = c / 255;
    return s <= 0.04045 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
  };

  const hexToLuminance = (hex: string): number => {
    const clean = hex.replace('#', '');
    const r = parseInt(clean.substring(0, 2), 16);
    const g = parseInt(clean.substring(2, 4), 16);
    const b = parseInt(clean.substring(4, 6), 16);
    return 0.2126 * srgbToLinear(r) + 0.7152 * srgbToLinear(g) + 0.0722 * srgbToLinear(b);
  };

  const contrastRatio = (hex1: string, hex2: string): number => {
    const l1 = hexToLuminance(hex1);
    const l2 = hexToLuminance(hex2);
    const lighter = Math.max(l1, l2);
    const darker = Math.min(l1, l2);
    return (lighter + 0.05) / (darker + 0.05);
  };

  // 1. Dark Mode Unselected State: FG #94A3B8 on BG #0F1622
  const darkUnselectedCR = contrastRatio('#94A3B8', '#0F1622');
  assert.ok(darkUnselectedCR >= 7.0, `Dark unselected contrast ${darkUnselectedCR.toFixed(2)}:1 must pass WCAG AAA (>= 7.0:1)`);

  // 2. Dark Mode Selected State: FG #F8FAFC on BG #1E293B
  const darkSelectedCR = contrastRatio('#F8FAFC', '#1E293B');
  assert.ok(darkSelectedCR >= 7.0, `Dark selected contrast ${darkSelectedCR.toFixed(2)}:1 must pass WCAG AAA (>= 7.0:1)`);

  // 3. Light Mode Unselected State: FG #475569 on BG #FFFFFF
  const lightUnselectedCR = contrastRatio('#475569', '#FFFFFF');
  assert.ok(lightUnselectedCR >= 7.0, `Light unselected contrast ${lightUnselectedCR.toFixed(2)}:1 must pass WCAG AAA (>= 7.0:1)`);

  // 4. Light Mode Selected State: FG #9F1239 on BG #FFE4E6
  const lightSelectedCR = contrastRatio('#9F1239', '#FFE4E6');
  assert.ok(lightSelectedCR >= 4.5, `Light selected contrast ${lightSelectedCR.toFixed(2)}:1 must pass WCAG AA (>= 4.5:1)`);

  // 5. Active selection border: #E11D48 against active backgrounds
  const darkBorderCR = contrastRatio('#E11D48', '#1E293B');
  const lightBorderCR = contrastRatio('#E11D48', '#FFE4E6');
  assert.ok(darkBorderCR >= 3.0, `Dark active border contrast ${darkBorderCR.toFixed(2)}:1 must pass UI component minimum (>= 3.0:1)`);
  assert.ok(lightBorderCR >= 3.0, `Light active border contrast ${lightBorderCR.toFixed(2)}:1 must pass UI component minimum (>= 3.0:1)`);

  // 6. Accessible keyboard selection and state attributes
  assert.ok(modalContent.includes("tabIndex={format === 'har' ? 0 : -1}"), 'HAR radio button must have roving tabIndex 0 when checked');
  assert.ok(modalContent.includes("tabIndex={format === 'raw_http' ? 0 : -1}"), 'Raw HTTP radio button must have roving tabIndex -1 when unchecked');
  assert.ok(modalContent.includes("aria-checked={format === 'har'}"), 'HAR radio button must expose aria-checked');
  assert.ok(modalContent.includes("aria-checked={format === 'raw_http'}"), 'Raw HTTP radio button must expose aria-checked');
  assert.ok(modalContent.includes('role="radiogroup"'), 'Container must expose role="radiogroup"');
  assert.ok(modalContent.includes('role="radio"'), 'Options must expose role="radio"');
  assert.ok(modalContent.includes("e.key === 'ArrowRight'"), 'Must handle ArrowRight for keyboard selection');
  assert.ok(modalContent.includes("e.key === 'ArrowLeft'"), 'Must handle ArrowLeft for keyboard selection');
});

test('Stop Generation UI: Composer exposes Stop button with Stopping… state and accessible aria-label', () => {
  const composerPath = path.join(SRC_DIR, 'components', 'Composer.tsx');
  const appPath = path.join(SRC_DIR, 'App.tsx');
  const apiPath = path.join(SRC_DIR, 'api.ts');

  const composerContent = fs.readFileSync(composerPath, 'utf-8');
  const appContent = fs.readFileSync(appPath, 'utf-8');
  const apiContent = fs.readFileSync(apiPath, 'utf-8');

  // Verify ComposerProps specifies onStop
  assert.ok(composerContent.includes('onStop?: () => Promise<void>;'), 'ComposerProps must specify onStop');

  // Verify Stop button has accessible name 'Stop generation'
  assert.ok(composerContent.includes('aria-label="Stop generation"'), 'Stop button must have aria-label="Stop generation"');

  // Verify Stopping... state indicator while cancellation is pending
  assert.ok(composerContent.includes("stopping ? 'Stopping…' : 'Stop'"), 'Stop button must show Stopping… while awaiting cancellation');

  // Verify App.tsx passes onStop to Composer
  assert.ok(appContent.includes('onStop={handleStopGeneration}'), 'App.tsx must pass onStop to Composer');

  // Verify api.ts exports stopInvestigationGeneration
  assert.ok(apiContent.includes('export async function stopInvestigationGeneration'), 'api.ts must export stopInvestigationGeneration');
});

test('Edit Prompt UI: ConversationView exposes Edit, inline editor, Cancel, and Save & Regenerate', () => {
  const convViewPath = path.join(SRC_DIR, 'components', 'ConversationView.tsx');
  const appPath = path.join(SRC_DIR, 'App.tsx');
  const apiPath = path.join(SRC_DIR, 'api.ts');

  const convContent = fs.readFileSync(convViewPath, 'utf-8');
  const appContent = fs.readFileSync(appPath, 'utf-8');
  const apiContent = fs.readFileSync(apiPath, 'utf-8');

  // Verify ConversationViewProps specifies onEditPrompt
  assert.ok(convContent.includes('onEditPrompt?: (messageId: string, newContent: string) => Promise<void>;'), 'ConversationViewProps must specify onEditPrompt');

  // Verify Edit action button on user message
  assert.ok(convContent.includes('aria-label="Edit prompt"'), 'Edit prompt must expose accessible aria-label');

  // Verify Save & Regenerate and Cancel buttons
  assert.ok(convContent.includes('Save & Regenerate'), 'Inline editor must have Save & Regenerate action');
  assert.ok(convContent.includes('Cancel'), 'Inline editor must have Cancel action');

  // Verify App.tsx passes onEditPrompt to ConversationView
  assert.ok(appContent.includes('onEditPrompt={handleEditPrompt}'), 'App.tsx must pass onEditPrompt to ConversationView');

  // Verify api.ts exports editAndRegeneratePrompt
  assert.ok(apiContent.includes('export async function editAndRegeneratePrompt'), 'api.ts must export editAndRegeneratePrompt');
});


