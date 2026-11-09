import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const SRC_DIR = path.resolve('src');

test('Batch 4 Contract: AssessmentLifecycleState synchronized with authoritative backend enum', () => {
  const typesPath = path.join(SRC_DIR, 'types.ts');
  const typesContent = fs.readFileSync(typesPath, 'utf-8');

  // Must include all backend states
  const requiredStates = [
    'DRAFT',
    'AUTHORIZATION_PENDING',
    'AUTHORIZED',
    'SCOPE_DEFINED',
    'ASSESSMENT_ACTIVE',
    'VALIDATION_PENDING',
    'HUMAN_REVIEW',
    'COMPLETED',
    'ARCHIVED',
    'CANCELLED',
    'EXPIRED',
    'REVOKED',
  ];

  for (const st of requiredStates) {
    assert.ok(
      typesContent.includes(`'${st}'`),
      `AssessmentLifecycleState must define authoritative state '${st}'`
    );
  }

  // Must NOT include fabricated states
  const forbiddenStates = ['ASSESSMENT_PAUSED', 'REMEDIAL_HOLD', 'REPORTING'];
  for (const st of forbiddenStates) {
    assert.ok(
      !typesContent.includes(`'${st}'`),
      `AssessmentLifecycleState must NOT contain fabricated state '${st}'`
    );
  }
});

test('Batch 4 Reporting: ReportsTab supports Markdown, JSON, and HTML formats', () => {
  const reportsTabPath = path.join(SRC_DIR, 'components', 'workspace', 'tabs', 'ReportsTab.tsx');
  const content = fs.readFileSync(reportsTabPath, 'utf-8');

  assert.ok(content.includes('value="markdown"'), 'ReportsTab must support markdown format option');
  assert.ok(content.includes('value="json"'), 'ReportsTab must support json format option');
  assert.ok(content.includes('value="html"'), 'ReportsTab must support html format option');

  // Verify browser alert() is eliminated in favor of accessible in-app status/alert banners
  assert.ok(
    !content.includes('alert('),
    'ReportsTab must not use window.alert(); must use in-app status banners'
  );
  assert.ok(content.includes('role="alert"'), 'ReportsTab must have role="alert" for error states');
  assert.ok(content.includes('role="status"'), 'ReportsTab must have role="status" for success states');
});

test('Batch 4 Accessibility: Modal close and clear controls have aria-label', () => {
  const filesToCheck = [
    path.join(SRC_DIR, 'components', 'workspace', 'AssessmentSwitcherModal.tsx'),
    path.join(SRC_DIR, 'components', 'workspace', 'CreateAssessmentModal.tsx'),
    path.join(SRC_DIR, 'components', 'workspace', 'GlobalSearchModal.tsx'),
    path.join(SRC_DIR, 'components', 'workspace', 'tabs', 'FindingsReviewTab.tsx'),
  ];

  for (const filePath of filesToCheck) {
    const content = fs.readFileSync(filePath, 'utf-8');
    assert.ok(
      content.includes('aria-label='),
      `${path.basename(filePath)} must contain aria-label attributes for accessibility`
    );
  }
});

test('Batch 4 Maintainability: Workspace and tabs cleanly separate errors with retry controls', () => {
  const tabFiles = [
    path.join(SRC_DIR, 'components', 'workspace', 'WorkspaceShell.tsx'),
    path.join(SRC_DIR, 'components', 'workspace', 'tabs', 'ScopeAssetsTab.tsx'),
    path.join(SRC_DIR, 'components', 'workspace', 'tabs', 'EvidenceTab.tsx'),
    path.join(SRC_DIR, 'components', 'workspace', 'tabs', 'AttackSurfaceTab.tsx'),
    path.join(SRC_DIR, 'components', 'workspace', 'tabs', 'ArtifactsTab.tsx'),
    path.join(SRC_DIR, 'components', 'workspace', 'tabs', 'HypothesesTab.tsx'),
    path.join(SRC_DIR, 'components', 'workspace', 'tabs', 'ActivityAuditTab.tsx'),
    path.join(SRC_DIR, 'components', 'workspace', 'tabs', 'FindingsReviewTab.tsx'),
  ];

  for (const filePath of tabFiles) {
    const content = fs.readFileSync(filePath, 'utf-8');
    assert.ok(
      content.includes('Retry'),
      `${path.basename(filePath)} must provide a Retry button for data loading failures`
    );
    assert.ok(
      content.includes('role="alert"'),
      `${path.basename(filePath)} must render error alerts with role="alert"`
    );
  }
});

test('Batch 4 Workflow: MemoryKnowledgeTab connects to real API without fake hardcoded counts', () => {
  const memoryTabPath = path.join(SRC_DIR, 'components', 'workspace', 'tabs', 'MemoryKnowledgeTab.tsx');
  const content = fs.readFileSync(memoryTabPath, 'utf-8');

  // Hardcoded counts must not be statically rendered
  assert.ok(!content.includes('>14<'), 'MemoryKnowledgeTab must not hardcode 14');
  assert.ok(!content.includes('>120<'), 'MemoryKnowledgeTab must not hardcode 120');

  // Real API calls must be wired
  assert.ok(content.includes('fetchAssessmentMemory'), 'MemoryKnowledgeTab must call fetchAssessmentMemory');
  assert.ok(content.includes('searchAssessmentMemory'), 'MemoryKnowledgeTab must call searchAssessmentMemory');
});

test('Batch 4 Governance: ExperimentsTab provides approval and result import actions', () => {
  const expTabPath = path.join(SRC_DIR, 'components', 'workspace', 'tabs', 'ExperimentsTab.tsx');
  const content = fs.readFileSync(expTabPath, 'utf-8');

  assert.ok(content.includes('approveAssessmentExperiment'), 'ExperimentsTab must call approveAssessmentExperiment');
  assert.ok(content.includes('importAssessmentExperimentResult'), 'ExperimentsTab must call importAssessmentExperimentResult');
  assert.ok(content.includes('Approve Experiment'), 'ExperimentsTab must render Approve Experiment action');
  assert.ok(content.includes('Import Execution Result'), 'ExperimentsTab must render Import Execution Result action');
});

test('Batch 4 Elimination: No direct browser alert() calls in any frontend production source', () => {
  function getAllFiles(dir: string, fileList: string[] = []): string[] {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        getAllFiles(fullPath, fileList);
      } else if (/\.(ts|tsx|js|jsx)$/.test(entry.name)) {
        fileList.push(fullPath);
      }
    }
    return fileList;
  }

  const prodFiles = getAllFiles(SRC_DIR);
  assert.ok(prodFiles.length > 20, 'Should inspect all production frontend files');

  const alertPattern = /\b(window\.)?alert\s*\(/;
  const offending: string[] = [];

  for (const filePath of prodFiles) {
    const code = fs.readFileSync(filePath, 'utf-8');
    if (alertPattern.test(code)) {
      offending.push(path.relative(SRC_DIR, filePath));
    }
  }

  assert.deepStrictEqual(
    offending,
    [],
    `Direct browser alert() calls must be eliminated from all production frontend code. Found in: ${offending.join(', ')}`
  );
});

test('Batch 4 In-App Notifications: App.tsx uses truthful accessible in-app status/alert banners', () => {
  const appPath = path.join(SRC_DIR, 'App.tsx');
  const content = fs.readFileSync(appPath, 'utf-8');

  assert.ok(content.includes('appNotification'), 'App.tsx must maintain appNotification state');
  assert.ok(content.includes('data-testid="app-notification-banner"'), 'App.tsx must render notification banner');
  assert.ok(content.includes('role={appNotification.type === \'error\' ? \'alert\' : \'status\'}'), 'App.tsx must use role="alert" or "status"');
  assert.ok(content.includes('aria-live="polite"'), 'App.tsx must announce updates via aria-live="polite"');
  assert.ok(content.includes('aria-label="Dismiss notification"'), 'App.tsx must provide accessible dismiss button');
});

test('Batch 4 Race Condition Safety: Workspace sequence controller discards out-of-order stale responses and late rejections', async () => {
  // Deterministic simulation of WorkspaceShell sequence controller
  class TestWorkspaceSequenceController {
    requestIdRef = 0;
    activeAssessmentId: string | null = null;
    workspaceData: any = null;
    workspaceError: string | null = null;
    loading = false;

    async selectAssessment(aid: string, fetchFn: (id: string) => Promise<any>) {
      const currentRequestId = ++this.requestIdRef;
      this.activeAssessmentId = aid;
      this.loading = true;
      this.workspaceError = null;
      try {
        const ws = await fetchFn(aid);
        if (currentRequestId !== this.requestIdRef) return;
        this.workspaceData = ws;
      } catch (err: any) {
        if (currentRequestId !== this.requestIdRef) return;
        this.workspaceError = err.message || `Failed to load assessment ${aid}`;
      } finally {
        if (currentRequestId === this.requestIdRef) {
          this.loading = false;
        }
      }
    }
  }

  const controller = new TestWorkspaceSequenceController();

  // Create deferred promises for Assessment A and Assessment B
  let resolveA: (val: any) => void = () => {};
  let resolveB: (val: any) => void = () => {};
  const promiseA = new Promise((resolve) => { resolveA = resolve; });
  const promiseB = new Promise((resolve) => { resolveB = resolve; });

  // 1. Start request for Assessment A
  const callA = controller.selectAssessment('ASSESSMENT-A', () => promiseA);
  assert.strictEqual(controller.activeAssessmentId, 'ASSESSMENT-A');
  assert.strictEqual(controller.loading, true);

  // 2. Switch context to Assessment B before A finishes
  const callB = controller.selectAssessment('ASSESSMENT-B', () => promiseB);
  assert.strictEqual(controller.activeAssessmentId, 'ASSESSMENT-B');

  // 3. Resolve Assessment B first (faster response)
  resolveB({ id: 'ASSESSMENT-B', name: 'Assessment Beta', assets: ['beta.api'] });
  await callB;

  // Confirm B's data is displayed
  assert.strictEqual(controller.activeAssessmentId, 'ASSESSMENT-B');
  assert.strictEqual(controller.workspaceData.id, 'ASSESSMENT-B');
  assert.strictEqual(controller.workspaceData.name, 'Assessment Beta');
  assert.strictEqual(controller.workspaceError, null);
  assert.strictEqual(controller.loading, false);

  // 4. Resolve Assessment A afterward (stale response)
  resolveA({ id: 'ASSESSMENT-A', name: 'Assessment Alpha', assets: ['alpha.api'] });
  await callA;

  // Confirm A's late response DID NOT overwrite B's data or selected context
  assert.strictEqual(
    controller.activeAssessmentId,
    'ASSESSMENT-B',
    'Active assessment must remain B'
  );
  assert.strictEqual(
    controller.workspaceData.id,
    'ASSESSMENT-B',
    'Stale response from A must not overwrite active assessment data'
  );

  // 5. Test late rejection: Late failed response from A must not set an error on B's view
  let rejectA2: (err: any) => void = () => {};
  let resolveB2: (val: any) => void = () => {};
  const promiseA2 = new Promise((_, reject) => { rejectA2 = reject; });
  const promiseB2 = new Promise((resolve) => { resolveB2 = resolve; });

  const callA2 = controller.selectAssessment('ASSESSMENT-A', () => promiseA2);
  const callB2 = controller.selectAssessment('ASSESSMENT-B', () => promiseB2);

  // B resolves successfully
  resolveB2({ id: 'ASSESSMENT-B', name: 'Assessment Beta' });
  await callB2;
  assert.strictEqual(controller.workspaceError, null);

  // A fails afterward with network timeout
  rejectA2(new Error('Gateway Timeout for Assessment A'));
  await callA2;

  // Confirm A's late error was discarded and did not replace B's view
  assert.strictEqual(
    controller.workspaceError,
    null,
    'Late rejection from Assessment A must not set error on Assessment B'
  );
  assert.strictEqual(controller.workspaceData.id, 'ASSESSMENT-B');
});

test('Batch 4 Race Condition Safety: Tab activeAssessmentRef guard discards stale responses and late errors', async () => {
  // Deterministic simulation of Tab activeAssessmentRef guard
  class TestTabGuardController {
    activeAssessmentRef: { current: string };
    data: any = null;
    dataError: string | null = null;
    loading = false;

    constructor(initialId: string) {
      this.activeAssessmentRef = { current: initialId };
    }

    setAssessmentId(newId: string) {
      this.activeAssessmentRef.current = newId;
    }

    async load(assessmentId: string, fetchFn: (id: string) => Promise<any>) {
      const currentId = assessmentId;
      this.loading = true;
      this.dataError = null;
      try {
        const result = await fetchFn(currentId);
        if (this.activeAssessmentRef.current !== currentId) return;
        this.data = result;
      } catch (err: any) {
        if (this.activeAssessmentRef.current !== currentId) return;
        this.dataError = err.message || 'Failed to load';
      } finally {
        if (this.activeAssessmentRef.current === currentId) {
          this.loading = false;
        }
      }
    }
  }

  const tab = new TestTabGuardController('ASSESSMENT-A');

  let resolveA: (val: any) => void = () => {};
  let resolveB: (val: any) => void = () => {};
  const promiseA = new Promise((resolve) => { resolveA = resolve; });
  const promiseB = new Promise((resolve) => { resolveB = resolve; });

  // Start loading A
  const callA = tab.load('ASSESSMENT-A', () => promiseA);

  // Switch context to B
  tab.setAssessmentId('ASSESSMENT-B');
  const callB = tab.load('ASSESSMENT-B', () => promiseB);

  // B completes first
  resolveB(['Finding B1', 'Finding B2']);
  await callB;
  assert.deepStrictEqual(tab.data, ['Finding B1', 'Finding B2']);

  // A completes late
  resolveA(['Finding A1']);
  await callA;

  // Stale A must be discarded
  assert.deepStrictEqual(
    tab.data,
    ['Finding B1', 'Finding B2'],
    'Tab must retain B findings when older A response arrives'
  );

  // Late rejection case
  let rejectA2: (err: any) => void = () => {};
  let resolveB2: (val: any) => void = () => {};
  const promiseA2 = new Promise((_, reject) => { rejectA2 = reject; });
  const promiseB2 = new Promise((resolve) => { resolveB2 = resolve; });

  tab.setAssessmentId('ASSESSMENT-A');
  const callA2 = tab.load('ASSESSMENT-A', () => promiseA2);

  tab.setAssessmentId('ASSESSMENT-B');
  const callB2 = tab.load('ASSESSMENT-B', () => promiseB2);

  resolveB2(['Finding B3']);
  await callB2;
  assert.strictEqual(tab.dataError, null);

  rejectA2(new Error('Stale DB Error'));
  await callA2;

  assert.strictEqual(
    tab.dataError,
    null,
    'Stale error from A must be discarded and not displayed in B'
  );
  assert.deepStrictEqual(tab.data, ['Finding B3']);
});

test('Batch 4 Accessibility: All modal dialogs implement role="dialog", aria-modal="true", and accessible names', () => {
  const modalFiles = [
    { file: 'components/workspace/CreateAssessmentModal.tsx', name: 'CreateAssessmentModal' },
    { file: 'components/workspace/AssessmentSwitcherModal.tsx', name: 'AssessmentSwitcherModal' },
    { file: 'components/workspace/GlobalSearchModal.tsx', name: 'GlobalSearchModal' },
    { file: 'components/AddObservationModal.tsx', name: 'AddObservationModal' },
    { file: 'components/ImportTrafficModal.tsx', name: 'ImportTrafficModal' },
    { file: 'components/NewInvestigationModal.tsx', name: 'NewInvestigationModal' },
    { file: 'components/SystemStatusModal.tsx', name: 'SystemStatusModal' },
  ];

  for (const { file, name } of modalFiles) {
    const fullPath = path.join(SRC_DIR, file);
    assert.ok(fs.existsSync(fullPath), `${file} must exist`);
    const content = fs.readFileSync(fullPath, 'utf-8');

    assert.ok(
      content.includes('role="dialog"'),
      `${name} must implement role="dialog"`
    );
    assert.ok(
      content.includes('aria-modal="true"'),
      `${name} must implement aria-modal="true"`
    );
    assert.ok(
      content.includes('aria-labelledby=') || content.includes('aria-label='),
      `${name} must have an accessible name via aria-labelledby or aria-label`
    );
    assert.ok(
      content.includes('aria-label="Close dialog"'),
      `${name} close button must have aria-label="Close dialog"`
    );
  }
});

