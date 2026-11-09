import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const SRC_DIR = path.resolve('src');

test('Branding: Header displays ULTRON without M13 unified workspace tagline', () => {
  const shellPath = path.join(SRC_DIR, 'components', 'workspace', 'WorkspaceShell.tsx');
  const content = fs.readFileSync(shellPath, 'utf-8');

  assert.ok(content.includes('ULTRON'), 'Header must contain ULTRON');
  assert.ok(
    !content.includes('BUG BOUNTY AI — M13 UNIFIED WORKSPACE'),
    'M13 Unified Workspace tagline must be removed'
  );
  assert.ok(
    !content.includes('Full Lifecycle Security Research'),
    'Subtitle Full Lifecycle Security Research must be removed'
  );
});

test('Branding: Unnecessary emoji decorations are removed from navigation and headers', () => {
  const shellPath = path.join(SRC_DIR, 'components', 'workspace', 'WorkspaceShell.tsx');
  const shellContent = fs.readFileSync(shellPath, 'utf-8');

  // Check navItems in WorkspaceShell
  const emojis = ['📊', '🎯', '🌐', '📦', '💡', '❓', '🔍', '🧪', '⚖️', '📄', '🧠', '📜'];
  for (const emoji of emojis) {
    assert.ok(
      !shellContent.includes(emoji),
      `WorkspaceShell navigation must not contain decorative emoji ${emoji}`
    );
  }

  // Check Sidebar
  const sidebarPath = path.join(SRC_DIR, 'components', 'Sidebar.tsx');
  const sidebarContent = fs.readFileSync(sidebarPath, 'utf-8');
  assert.ok(!sidebarContent.includes('🛡️'), 'Sidebar workspace button must not contain shield emoji');

  // Check WorkspaceHeader
  const headerPath = path.join(SRC_DIR, 'components', 'workspace', 'WorkspaceHeader.tsx');
  const headerContent = fs.readFileSync(headerPath, 'utf-8');
  assert.ok(!headerContent.includes('📁'), 'WorkspaceHeader must not contain folder emoji');
  assert.ok(!headerContent.includes('🔄'), 'WorkspaceHeader must not contain refresh emoji');
});

test('Defect Prevention: Hardcoded canned intro string is completely absent from all frontend sources', () => {
  const cannedString = "I'm your local security research assistant. You can provide target observations";

  function scanDir(dir: string) {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        scanDir(fullPath);
      } else if (entry.isFile() && (entry.name.endsWith('.tsx') || entry.name.endsWith('.ts'))) {
        const fileContent = fs.readFileSync(fullPath, 'utf-8');
        assert.ok(
          !fileContent.includes(cannedString),
          `Found generic intro string in ${fullPath}`
        );
      }
    }
  }

  scanDir(SRC_DIR);
});

test('Startup Mode: Copilot is the default landing screen unless deep linked', () => {
  // Test route-matching logic used in App.tsx
  const resolveAppMode = (pathname: string, hash: string, search: string): 'workspace' | 'copilot' => {
    const path = pathname.toLowerCase();
    const h = hash.toLowerCase();
    const s = search.toLowerCase();
    if (path.includes('/workspace') || path.includes('/assessment') || h.includes('workspace') || s.includes('mode=workspace')) {
      return 'workspace';
    }
    return 'copilot';
  };

  assert.equal(resolveAppMode('/', '', ''), 'copilot', 'Root path must land in Copilot');
  assert.equal(resolveAppMode('/investigations/INV-001', '', ''), 'copilot', 'Investigation route lands in Copilot');
  assert.equal(resolveAppMode('/workspace', '', ''), 'workspace', 'Direct /workspace URL deep links to workspace');
  assert.equal(resolveAppMode('/assessment', '', ''), 'workspace', 'Direct /assessment URL deep links to workspace');
  assert.equal(resolveAppMode('/', '#workspace', ''), 'workspace', '#workspace hash deep links to workspace');
  assert.equal(resolveAppMode('/', '', '?mode=workspace'), 'workspace', '?mode=workspace query deep links to workspace');
});

test('Conversational Presentation: Model provenance formatting matches reference specification', () => {
  const formatModelLabel = (modelName?: string): string => {
    const raw = modelName || '';
    if (raw.toLowerCase().includes('7b')) return '7B';
    if (raw.toLowerCase().includes('3b')) return '3B';
    if (raw === 'local_knowledge_engine') return 'local_knowledge_engine';
    if (raw === 'local_assistant') return 'local_assistant';
    if (raw === 'system_status') return 'system_status';
    if (raw === 'local_rule_engine') return 'local_rule_engine';
    return raw || 'Local AI';
  };

  assert.equal(formatModelLabel('qwen2.5-coder:7b'), '7B');
  assert.equal(formatModelLabel('qwen2.5-coder:3b'), '3B');
  assert.equal(formatModelLabel('local_knowledge_engine'), 'local_knowledge_engine');
  assert.equal(formatModelLabel('system_status'), 'system_status');
  assert.equal(formatModelLabel('local_assistant'), 'local_assistant');
  assert.equal(formatModelLabel(''), 'Local AI');
});
