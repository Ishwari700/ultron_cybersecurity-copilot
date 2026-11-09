import type {
  AuditRecord,
  ChatMessage,
  EvidenceGap,
  EvidenceItem,
  ExecutionOutcome,
  ExperimentObject,
  ImportTrafficPayload,
  IngestionResult,
  InvestigationDetail,
  InvestigationObservation,
  InvestigationSummary,
  ManualObservationPayload,
  SecurityInvariant,
  SystemStatus,
  UserSession,
  InvestigationAuditResponse,
  KnowledgeSource,
  GraphExtractionResponse,
  SourceGraphStatusResponse,
  KnowledgeGraphStatsResponse,
  GraphAuditResponse,
  IngestionJob,
} from './types';

const BASE_URL = '/api';

// Memory-only fallback token if ever used programmatically; default is HttpOnly session cookies.
let inMemoryBearerToken: string | null = null;
if (typeof window !== 'undefined') {
  try {
    localStorage.removeItem('ultron_auth_token');
  } catch {
    // Ignore restricted storage environments
  }
}

export function setAuthToken(token: string | null) {
  inMemoryBearerToken = token;
}

export function getAuthToken(): string | null {
  return inMemoryBearerToken;
}

function getCsrfCookie(): string | null {
  if (typeof document === 'undefined') return null;
  const match = document.cookie.match(/(?:^|;\s*)csrftoken=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : null;
}

export async function ensureCsrfToken(): Promise<string | null> {
  let token = getCsrfCookie();
  if (!token) {
    try {
      const res = await fetch(`${BASE_URL}/auth/csrf`, { credentials: 'include' });
      if (res.ok) {
        const data = await res.json();
        token = data.csrf_token || getCsrfCookie();
      }
    } catch {
      // Ignore network errors on CSRF probe
    }
  }
  return token;
}

export async function authFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const method = (init?.method || 'GET').toUpperCase();
  const headers = new Headers(init?.headers || {});
  const token = getAuthToken();
  if (token && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${token}`);
  }

  // Double-submit CSRF protection for cookie-authenticated mutating requests
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method) && !headers.has('X-CSRF-Token')) {
    let csrf = getCsrfCookie();
    if (!csrf) {
      csrf = await ensureCsrfToken();
    }
    if (csrf) {
      headers.set('X-CSRF-Token', csrf);
    }
  }

  const modifiedInit: RequestInit = {
    ...init,
    credentials: 'include',
    headers,
  };

  try {
    const res = await fetch(input, modifiedInit);
    if (res.status === 401) {
      if (typeof window !== 'undefined') {
        window.dispatchEvent(new CustomEvent('ultron-auth-expired'));
      }
    }
    return res;
  } catch (err: any) {
    if (err.message && err.message.includes('Failed to fetch')) {
      throw new Error('Ultron server is unreachable. Please verify server status.');
    }
    throw err;
  }
}

// ---------------------------------------------------------------------------
// Authentication & Session Endpoints
// ---------------------------------------------------------------------------

export async function login(username: string, password?: string, _deprecated_role?: string): Promise<UserSession> {
  await ensureCsrfToken();
  const res = await authFetch(`${BASE_URL}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password: password || '' }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Login failed: ${res.statusText}`);
  }
  const data = await res.json();
  if (data.token) {
    setAuthToken(data.token);
  }
  return data;
}

export async function fetchCurrentUser(): Promise<UserSession> {
  const res = await authFetch(`${BASE_URL}/auth/me`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch session: ${res.statusText}`);
  }
  return res.json();
}

export async function logout(): Promise<{ status: string; logged_out: boolean }> {
  const res = await authFetch(`${BASE_URL}/auth/logout`, {
    method: 'POST',
  });
  setAuthToken(null);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Logout failed: ${res.statusText}`);
  }
  return res.json();
}

// ---------------------------------------------------------------------------
// System & Investigations
// ---------------------------------------------------------------------------

export async function fetchStatus(): Promise<SystemStatus> {
  const res = await authFetch(`${BASE_URL}/status`);
  if (!res.ok) throw new Error(`Failed to fetch system status: ${res.statusText}`);
  return res.json();
}

export async function fetchInvestigations(searchQuery?: string): Promise<InvestigationSummary[]> {
  const url = searchQuery
    ? `${BASE_URL}/investigations?q=${encodeURIComponent(searchQuery)}`
    : `${BASE_URL}/investigations`;
  const res = await authFetch(url);
  if (!res.ok) throw new Error(`Failed to fetch investigations: ${res.statusText}`);
  return res.json();
}

export async function fetchInvestigation(id: string): Promise<InvestigationDetail> {
  const res = await authFetch(`${BASE_URL}/investigations/${id}`);
  if (!res.ok) throw new Error(`Failed to fetch investigation ${id}: ${res.statusText}`);
  return res.json();
}

export async function renameInvestigation(id: string, name: string): Promise<InvestigationSummary> {
  const res = await authFetch(`${BASE_URL}/investigations/${id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: jsonStringify({ name }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to rename investigation: ${res.statusText}`);
  }
  return res.json();
}

export async function deleteInvestigation(id: string): Promise<{ success: boolean; id: string }> {
  const res = await authFetch(`${BASE_URL}/investigations/${id}`, {
    method: 'DELETE',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to delete investigation: ${res.statusText}`);
  }
  return res.json();
}

export async function createInvestigation(name: string, target_host: string): Promise<InvestigationSummary> {
  const res = await authFetch(`${BASE_URL}/investigations`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: jsonStringify({ name, target_host }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to create investigation: ${res.statusText}`);
  }
  return res.json();
}

export async function sendMessage(inv_id: string, content: string, clientMsgId?: string): Promise<ChatMessage[]> {
  const res = await authFetch(`${BASE_URL}/investigations/${inv_id}/messages`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: jsonStringify({ content, client_msg_id: clientMsgId }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to send message: ${res.statusText}`);
  }
  return res.json();
}

export async function stopInvestigationGeneration(invId: string, reason?: string): Promise<{ stopped: boolean; investigation_id: string }> {
  const res = await authFetch(`${BASE_URL}/investigations/${encodeURIComponent(invId)}/stop`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: jsonStringify({ reason: reason || 'User requested stop' }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to stop generation: ${res.statusText}`);
  }
  return res.json();
}

export async function editAndRegeneratePrompt(invId: string, messageId: string, content: string): Promise<ChatMessage[]> {
  const res = await authFetch(`${BASE_URL}/investigations/${encodeURIComponent(invId)}/messages/${encodeURIComponent(messageId)}/edit`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: jsonStringify({ content }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to edit prompt: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchEvidence(inv_id: string): Promise<EvidenceItem[]> {
  const res = await authFetch(`${BASE_URL}/investigations/${inv_id}/evidence`);
  if (!res.ok) throw new Error(`Failed to fetch evidence: ${res.statusText}`);
  return res.json();
}

export async function fetchApplicationModel(inv_id: string): Promise<any> {
  const res = await authFetch(`${BASE_URL}/investigations/${inv_id}/model`);
  if (!res.ok) throw new Error(`Failed to fetch application model: ${res.statusText}`);
  return res.json();
}

export async function fetchInvariants(inv_id: string): Promise<SecurityInvariant[]> {
  const res = await authFetch(`${BASE_URL}/investigations/${inv_id}/invariants`);
  if (!res.ok) throw new Error(`Failed to fetch invariants: ${res.statusText}`);
  return res.json();
}

export async function fetchGaps(inv_id: string): Promise<EvidenceGap[]> {
  const res = await authFetch(`${BASE_URL}/investigations/${inv_id}/gaps`);
  if (!res.ok) throw new Error(`Failed to fetch evidence gaps: ${res.statusText}`);
  return res.json();
}

export async function fetchExperiments(inv_id: string): Promise<ExperimentObject[]> {
  const res = await authFetch(`${BASE_URL}/investigations/${inv_id}/experiments`);
  if (!res.ok) throw new Error(`Failed to fetch experiments: ${res.statusText}`);
  return res.json();
}

export async function validateExperiment(exp_id: string): Promise<any> {
  const res = await authFetch(`${BASE_URL}/experiments/${exp_id}/validate`, {
    method: 'POST',
  });
  if (!res.ok) throw new Error(`Failed to validate experiment: ${res.statusText}`);
  return res.json();
}

export async function approveExperiment(
  exp_id: string,
  actor: string,
  safety_acknowledged: boolean,
  notes?: string
): Promise<any> {
  const res = await authFetch(`${BASE_URL}/experiments/${exp_id}/approve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: jsonStringify({ actor, safety_acknowledged, notes }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Approval failed: ${res.statusText}`);
  }
  return res.json();
}

export async function rejectExperiment(exp_id: string, actor: string, reason: string): Promise<any> {
  const res = await authFetch(`${BASE_URL}/experiments/${exp_id}/reject?actor=${encodeURIComponent(actor)}&reason=${encodeURIComponent(reason)}`, {
    method: 'POST',
  });
  if (!res.ok) throw new Error(`Rejection failed: ${res.statusText}`);
  return res.json();
}

export async function executeExperiment(exp_id: string): Promise<ExecutionOutcome> {
  const res = await authFetch(`${BASE_URL}/experiments/${exp_id}/execute`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: jsonStringify({ safe_simulation: true }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Execution failed: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchAuditLog(limit = 50): Promise<AuditRecord[]> {
  const res = await authFetch(`${BASE_URL}/audit?limit=${limit}`);
  if (!res.ok) throw new Error(`Failed to fetch audit log: ${res.statusText}`);
  return res.json();
}

export async function fetchInvestigationAudit(invId: string, limit = 100): Promise<InvestigationAuditResponse> {
  const res = await authFetch(`${BASE_URL}/audit/${encodeURIComponent(invId)}?limit=${limit}`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch investigation audit: ${res.statusText}`);
  }
  return res.json();
}

export async function loadDemoFixture(): Promise<InvestigationSummary> {
  const res = await authFetch(`${BASE_URL}/demo/load`, {
    method: 'POST',
  });
  if (!res.ok) throw new Error(`Failed to load demo fixture: ${res.statusText}`);
  return res.json();
}

export async function fetchCascadeTraces(limit = 10): Promise<any[]> {
  const res = await authFetch(`${BASE_URL}/system/cascade-trace?limit=${limit}`);
  if (!res.ok) throw new Error(`Failed to fetch cascade traces: ${res.statusText}`);
  return res.json();
}

export async function fetchCascadeTrace(traceId: string): Promise<any> {
  const res = await authFetch(`${BASE_URL}/cascade-traces/${encodeURIComponent(traceId)}`);
  if (!res.ok) throw new Error(`Failed to fetch trace ${traceId}: ${res.statusText}`);
  return res.json();
}

export async function fetchMessageTrace(invId: string, messageId: string): Promise<any> {
  const res = await authFetch(`${BASE_URL}/investigations/${encodeURIComponent(invId)}/messages/${encodeURIComponent(messageId)}/trace`);
  if (!res.ok) throw new Error(`Failed to fetch message trace: ${res.statusText}`);
  return res.json();
}

export async function importTraffic(invId: string, payload: ImportTrafficPayload): Promise<IngestionResult> {
  const res = await authFetch(`${BASE_URL}/investigations/${encodeURIComponent(invId)}/import`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: jsonStringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Import failed: ${res.statusText}`);
  }
  return res.json();
}

export async function addObservation(invId: string, payload: ManualObservationPayload): Promise<IngestionResult> {
  const res = await authFetch(`${BASE_URL}/investigations/${encodeURIComponent(invId)}/observations`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: jsonStringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to add observation: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchObservationDetail(invId: string, obsId: string): Promise<InvestigationObservation> {
  const res = await authFetch(`${BASE_URL}/investigations/${encodeURIComponent(invId)}/evidence/${encodeURIComponent(obsId)}`);
  if (!res.ok) throw new Error(`Failed to fetch observation: ${res.statusText}`);
  return res.json();
}

// ---------------------------------------------------------------------------
// M11.5 Long Response API Methods
// ---------------------------------------------------------------------------

export async function fetchResponseSession(responseId: string): Promise<any> {
  const res = await authFetch(`${BASE_URL}/responses/${encodeURIComponent(responseId)}`);
  if (!res.ok) throw new Error(`Failed to fetch response: ${res.statusText}`);
  return res.json();
}

export async function fetchResponseChunks(responseId: string): Promise<any[]> {
  const res = await authFetch(`${BASE_URL}/responses/${encodeURIComponent(responseId)}/chunks`);
  if (!res.ok) throw new Error(`Failed to fetch response chunks: ${res.statusText}`);
  return res.json();
}

export async function fetchResponseVersions(responseId: string): Promise<any[]> {
  const res = await authFetch(`${BASE_URL}/responses/${encodeURIComponent(responseId)}/versions`);
  if (!res.ok) throw new Error(`Failed to fetch response versions: ${res.statusText}`);
  return res.json();
}

export async function stopResponseGeneration(responseId: string, reason?: string): Promise<{ stopped: boolean; response_id: string }> {
  const res = await authFetch(`${BASE_URL}/responses/${encodeURIComponent(responseId)}/stop`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reason: reason || 'User requested stop' }),
  });
  if (!res.ok) throw new Error(`Failed to stop response: ${res.statusText}`);
  return res.json();
}

export async function continueResponse(responseId: string, directive?: string): Promise<any> {
  const res = await authFetch(`${BASE_URL}/responses/${encodeURIComponent(responseId)}/continue`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ custom_directive: directive }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to continue response: ${res.statusText}`);
  }
  return res.json();
}

export async function regenerateResponse(responseId: string, temperature: number = 0.7): Promise<any> {
  const res = await authFetch(`${BASE_URL}/responses/${encodeURIComponent(responseId)}/regenerate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ temperature }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to regenerate response: ${res.statusText}`);
  }
  return res.json();
}

export async function performResponseAction(responseId: string, action: string, detail?: string): Promise<any> {
  const res = await authFetch(`${BASE_URL}/responses/${encodeURIComponent(responseId)}/actions`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action, detail }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to perform response action: ${res.statusText}`);
  }
  return res.json();
}

export async function exportResponse(responseId: string, format: 'markdown' | 'txt' = 'markdown'): Promise<{ response_id: string; format: string; content: string }> {
  const res = await authFetch(`${BASE_URL}/responses/${encodeURIComponent(responseId)}/export?format=${format}`);
  if (!res.ok) throw new Error(`Failed to export response: ${res.statusText}`);
  return res.json();
}

export async function fetchResponseMetrics(): Promise<any> {
  const res = await authFetch(`${BASE_URL}/responses/metrics`);
  if (!res.ok) throw new Error(`Failed to fetch response metrics: ${res.statusText}`);
  return res.json();
}

// ---------------------------------------------------------------------------
// M13 Full Security Assessment Workspace API Calls
// ---------------------------------------------------------------------------

export async function fetchAssessments(): Promise<any[]> {
  const res = await authFetch(`${BASE_URL}/assessments`);
  if (!res.ok) throw new Error(`Failed to fetch assessments: ${res.statusText}`);
  const data = await res.json();
  return data.assessments || [];
}

export async function createAssessment(organization: string, assessment_name: string, created_by?: string): Promise<any> {
  const payload: Record<string, any> = { organization, assessment_name };
  if (created_by) {
    payload.created_by = created_by;
  }
  const res = await authFetch(`${BASE_URL}/assessments`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to create assessment: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchAssessmentWorkspace(assessmentId: string): Promise<any> {
  const res = await authFetch(`${BASE_URL}/assessments/${encodeURIComponent(assessmentId)}/workspace`);
  if (!res.ok) throw new Error(`Failed to fetch workspace for ${assessmentId}: ${res.statusText}`);
  const data = await res.json();
  return data.workspace;
}

export async function fetchAssessmentOverview(assessmentId: string): Promise<any> {
  const res = await authFetch(`${BASE_URL}/assessments/${encodeURIComponent(assessmentId)}/overview`);
  if (!res.ok) throw new Error(`Failed to fetch overview for ${assessmentId}: ${res.statusText}`);
  const data = await res.json();
  return data.overview;
}

export async function fetchAssessmentActivity(assessmentId: string, limit: number = 50): Promise<any[]> {
  const res = await authFetch(`${BASE_URL}/assessments/${encodeURIComponent(assessmentId)}/activity?limit=${limit}`);
  if (!res.ok) throw new Error(`Failed to fetch activity for ${assessmentId}: ${res.statusText}`);
  const data = await res.json();
  return data.activity || [];
}

export async function fetchAssessmentAssets(assessmentId: string): Promise<any[]> {
  const res = await authFetch(`${BASE_URL}/assessments/${encodeURIComponent(assessmentId)}/assets`);
  if (!res.ok) throw new Error(`Failed to fetch assets for ${assessmentId}: ${res.statusText}`);
  const data = await res.json();
  return data.assets || [];
}

export async function createAssessmentAsset(assessmentId: string, asset: { canonical_identifier: string; asset_type: string; scope_status?: string; tags?: string[] }): Promise<any> {
  const res = await authFetch(`${BASE_URL}/assessments/${encodeURIComponent(assessmentId)}/assets`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(asset),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to create asset: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchAssessmentObservations(assessmentId: string): Promise<any[]> {
  const res = await authFetch(`${BASE_URL}/assessments/${encodeURIComponent(assessmentId)}/observations`);
  if (!res.ok) throw new Error(`Failed to fetch observations: ${res.statusText}`);
  const data = await res.json();
  return data.observations || [];
}

export async function fetchAssessmentHypotheses(assessmentId: string): Promise<any[]> {
  const res = await authFetch(`${BASE_URL}/assessments/${encodeURIComponent(assessmentId)}/hypotheses`);
  if (!res.ok) throw new Error(`Failed to fetch hypotheses: ${res.statusText}`);
  const data = await res.json();
  return data.hypotheses || [];
}

export async function generateAssessmentHypotheses(assessmentId: string): Promise<any> {
  const res = await authFetch(`${BASE_URL}/assessments/${encodeURIComponent(assessmentId)}/hypotheses`, {
    method: 'POST',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to generate hypotheses: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchAssessmentExperiments(assessmentId: string): Promise<any[]> {
  const res = await authFetch(`${BASE_URL}/assessments/${encodeURIComponent(assessmentId)}/experiments`);
  if (!res.ok) throw new Error(`Failed to fetch experiments: ${res.statusText}`);
  const data = await res.json();
  return data.experiments || [];
}

export async function proposeAssessmentExperiment(assessmentId: string, experiment: any): Promise<any> {
  const res = await authFetch(`${BASE_URL}/assessments/${encodeURIComponent(assessmentId)}/experiments`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(experiment),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to propose experiment: ${res.statusText}`);
  }
  return res.json();
}

export async function approveAssessmentExperiment(assessmentId: string, expId: string): Promise<any> {
  const res = await authFetch(`${BASE_URL}/assessments/${encodeURIComponent(assessmentId)}/experiments/${encodeURIComponent(expId)}/approve`, {
    method: 'POST',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Approval failed: ${res.statusText}`);
  }
  return res.json();
}

export async function importAssessmentExperimentResult(experimentId: string, resultPayload: any): Promise<any> {
  const res = await authFetch(`${BASE_URL}/experiments/${encodeURIComponent(experimentId)}/result`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ result_payload: resultPayload }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Importing experiment result failed: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchAssessmentFindings(assessmentId: string): Promise<any[]> {
  const res = await authFetch(`${BASE_URL}/assessments/${encodeURIComponent(assessmentId)}/findings`);
  if (!res.ok) throw new Error(`Failed to fetch findings: ${res.statusText}`);
  const data = await res.json();
  return data.findings || [];
}

export async function createAssessmentFinding(assessmentId: string, finding: any): Promise<any> {
  const res = await authFetch(`${BASE_URL}/assessments/${encodeURIComponent(assessmentId)}/findings`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(finding),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to create finding: ${res.statusText}`);
  }
  return res.json();
}

export async function verifyFindingAuthoritative(findingId: string, justification: string, human_reviewer?: string): Promise<any> {
  const payload: Record<string, any> = { justification };
  if (human_reviewer) {
    payload.human_reviewer = human_reviewer;
  }
  const res = await authFetch(`${BASE_URL}/findings/${encodeURIComponent(findingId)}/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to verify finding: ${res.statusText}`);
  }
  return res.json();
}

export interface ExportReportResult {
  status: string;
  format: string;
  content: string;
  mime_type: string;
  filename: string;
}

export async function generateAssessmentReport(assessmentId: string, format: string = 'markdown'): Promise<any> {
  const res = await authFetch(`${BASE_URL}/assessments/${encodeURIComponent(assessmentId)}/report?format_type=${encodeURIComponent(format)}`, {
    method: 'POST',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to generate report: ${res.statusText}`);
  }
  return res.json();
}

export async function exportAssessmentReport(assessmentId: string, format: string = 'markdown'): Promise<ExportReportResult> {
  const res = await authFetch(`${BASE_URL}/assessments/${encodeURIComponent(assessmentId)}/reports/export?format_type=${encodeURIComponent(format)}`, {
    method: 'POST',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to export report: ${res.statusText}`);
  }
  return res.json();
}

export async function updateAssessment(assessmentId: string, payload: { state?: string; notes?: string }): Promise<any> {
  const res = await authFetch(`${BASE_URL}/assessments/${encodeURIComponent(assessmentId)}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to update assessment: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchAssessmentMemory(assessmentId: string): Promise<any[]> {
  const res = await authFetch(`${BASE_URL}/assessments/${encodeURIComponent(assessmentId)}/memory`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch memory: ${res.statusText}`);
  }
  return res.json();
}

export async function searchAssessmentMemory(
  assessmentId: string,
  query: string,
  allowedNamespaces?: string[]
): Promise<any> {
  const payload: Record<string, any> = { query, top_k: 10 };
  if (allowedNamespaces && allowedNamespaces.length > 0 && !allowedNamespaces.includes('ALL')) {
    payload.allowed_namespaces = allowedNamespaces;
  }
  const res = await authFetch(`${BASE_URL}/assessments/${encodeURIComponent(assessmentId)}/memory/search`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to search memory: ${res.statusText}`);
  }
  return res.json();
}

export async function validateAssessmentScope(assessmentId: string, target: string): Promise<any> {
  const res = await authFetch(`${BASE_URL}/assessments/${encodeURIComponent(assessmentId)}/scope/validate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to validate scope: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchAssessmentArtifacts(assessmentId: string): Promise<any[]> {
  const res = await authFetch(`${BASE_URL}/assessments/${encodeURIComponent(assessmentId)}/artifacts`);
  if (!res.ok) throw new Error(`Failed to fetch artifacts: ${res.statusText}`);
  const data = await res.json();
  return data.artifacts || [];
}

export async function uploadAssessmentArtifact(
  assessmentId: string,
  file: File,
  artifactType: string = 'OTHER'
): Promise<any> {
  const url = `${BASE_URL}/assessments/${encodeURIComponent(assessmentId)}/artifacts/upload?filename=${encodeURIComponent(file.name)}&artifact_type=${encodeURIComponent(artifactType)}`;
  const res = await authFetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/octet-stream',
      'X-Filename': file.name,
      'X-Artifact-Type': artifactType,
    },
    body: file,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to upload artifact: ${res.statusText}`);
  }
  return res.json();
}

export function getArtifactDownloadUrl(assessmentId: string, artifactId: string): string {
  return `${BASE_URL}/assessments/${encodeURIComponent(assessmentId)}/artifacts/${encodeURIComponent(artifactId)}/download`;
}

export async function registerAssessmentArtifact(assessmentId: string, artifact: any): Promise<any> {
  const res = await authFetch(`${BASE_URL}/assessments/${encodeURIComponent(assessmentId)}/artifacts`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(artifact),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to register artifact: ${res.statusText}`);
  }
  return res.json();
}

export async function searchWorkspaceGlobal(query: string, assessmentId?: string): Promise<any[]> {
  const url = assessmentId
    ? `${BASE_URL}/workspace/search?query=${encodeURIComponent(query)}&assessment_id=${encodeURIComponent(assessmentId)}`
    : `${BASE_URL}/workspace/search?query=${encodeURIComponent(query)}`;
  const res = await authFetch(url);
  if (!res.ok) throw new Error(`Search failed: ${res.statusText}`);
  const data = await res.json();
  return data.results || [];
}

export async function setAssessmentAuthorization(assessmentId: string, payload: any): Promise<any> {
  const res = await authFetch(`${BASE_URL}/assessments/${encodeURIComponent(assessmentId)}/authorization`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to set authorization: ${res.statusText}`);
  }
  return res.json();
}

export async function setAssessmentScope(assessmentId: string, payload: any): Promise<any> {
  const res = await authFetch(`${BASE_URL}/assessments/${encodeURIComponent(assessmentId)}/scope`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to set scope: ${res.statusText}`);
  }
  return res.json();
}

// ---------------------------------------------------------------------------
// Knowledge Source Intake & Ingestion API
// ---------------------------------------------------------------------------

export async function listKnowledgeSources(status?: string): Promise<KnowledgeSource[]> {
  const url = status
    ? `${BASE_URL}/knowledge/sources?status=${encodeURIComponent(status)}`
    : `${BASE_URL}/knowledge/sources`;
  const res = await authFetch(url);
  if (!res.ok) throw new Error(`Failed to list knowledge sources: ${res.statusText}`);
  return res.json();
}

export async function getKnowledgeSource(sourceId: string): Promise<KnowledgeSource> {
  const res = await authFetch(`${BASE_URL}/knowledge/sources/${encodeURIComponent(sourceId)}`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch knowledge source: ${res.statusText}`);
  }
  return res.json();
}

export async function importLocalKnowledgeSource(payload: {
  relative_path: string;
  title?: string;
  authority_level?: string;
  tags?: string[];
}): Promise<KnowledgeSource> {
  await ensureCsrfToken();
  const res = await authFetch(`${BASE_URL}/knowledge/sources/import`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to import local source: ${res.statusText}`);
  }
  return res.json();
}

export async function uploadKnowledgeSource(formData: FormData): Promise<KnowledgeSource> {
  await ensureCsrfToken();
  const res = await authFetch(`${BASE_URL}/knowledge/sources/upload`, {
    method: 'POST',
    body: formData,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to upload knowledge source: ${res.statusText}`);
  }
  return res.json();
}

export async function ingestKnowledgeText(payload: {
  content: string;
  filename: string;
  title?: string;
  authority_level?: string;
  tags?: string[];
}): Promise<KnowledgeSource> {
  await ensureCsrfToken();
  const res = await authFetch(`${BASE_URL}/knowledge/sources/ingest-text`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to ingest text knowledge: ${res.statusText}`);
  }
  return res.json();
}

export async function deactivateKnowledgeSource(sourceId: string): Promise<{ status: string; source_id: string }> {
  await ensureCsrfToken();
  const res = await authFetch(`${BASE_URL}/knowledge/sources/${encodeURIComponent(sourceId)}/deactivate`, {
    method: 'POST',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to deactivate source: ${res.statusText}`);
  }
  return res.json();
}

export async function retryKnowledgeSource(sourceId: string): Promise<KnowledgeSource> {
  await ensureCsrfToken();
  const res = await authFetch(`${BASE_URL}/knowledge/sources/${encodeURIComponent(sourceId)}/retry`, {
    method: 'POST',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to retry source: ${res.statusText}`);
  }
  return res.json();
}

export async function extractKnowledgeGraph(
  sourceId: string,
  maxChunks?: number,
  force?: boolean,
  modelName?: string,
  background?: boolean
): Promise<GraphExtractionResponse> {
  await ensureCsrfToken();
  const params = new URLSearchParams();
  if (maxChunks !== undefined) params.append('max_chunks', String(maxChunks));
  if (force) params.append('force', 'true');
  if (modelName) params.append('model_name', modelName);
  if (background) params.append('background', 'true');
  const q = params.toString() ? `?${params.toString()}` : '';
  const res = await authFetch(`${BASE_URL}/knowledge/sources/${encodeURIComponent(sourceId)}/extract-graph${q}`, {
    method: 'POST',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to extract knowledge graph: ${res.statusText}`);
  }
  return res.json();
}

export async function retryFailedKnowledgeGraph(
  sourceId: string,
  modelName?: string
): Promise<GraphExtractionResponse> {
  await ensureCsrfToken();
  const params = new URLSearchParams();
  if (modelName) params.append('model_name', modelName);
  const q = params.toString() ? `?${params.toString()}` : '';
  const res = await authFetch(`${BASE_URL}/knowledge/sources/${encodeURIComponent(sourceId)}/retry-failed-graph${q}`, {
    method: 'POST',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to retry failed knowledge graph chunks: ${res.statusText}`);
  }
  return res.json();
}

export async function cancelKnowledgeGraph(
  sourceId: string
): Promise<{ status: string; source_id: string; message: string }> {
  await ensureCsrfToken();
  const res = await authFetch(`${BASE_URL}/knowledge/sources/${encodeURIComponent(sourceId)}/cancel-graph`, {
    method: 'POST',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to cancel knowledge graph extraction: ${res.statusText}`);
  }
  return res.json();
}

// ---------------------------------------------------------------------------
// Ingestion Jobs API
// ---------------------------------------------------------------------------

export async function listIngestionJobs(status?: string): Promise<IngestionJob[]> {
  const url = status
    ? `${BASE_URL}/knowledge/jobs?status=${encodeURIComponent(status)}`
    : `${BASE_URL}/knowledge/jobs`;
  const res = await authFetch(url);
  if (!res.ok) throw new Error(`Failed to list ingestion jobs: ${res.statusText}`);
  return res.json();
}

export async function getIngestionJob(jobId: string): Promise<IngestionJob> {
  const res = await authFetch(`${BASE_URL}/knowledge/jobs/${encodeURIComponent(jobId)}`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch ingestion job: ${res.statusText}`);
  }
  return res.json();
}

export async function cancelIngestionJob(jobId: string): Promise<IngestionJob> {
  await ensureCsrfToken();
  const res = await authFetch(`${BASE_URL}/knowledge/jobs/${encodeURIComponent(jobId)}/cancel`, {
    method: 'POST',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to cancel ingestion job: ${res.statusText}`);
  }
  return res.json();
}

export async function retryIngestionJob(jobId: string): Promise<IngestionJob> {
  await ensureCsrfToken();
  const res = await authFetch(`${BASE_URL}/knowledge/jobs/${encodeURIComponent(jobId)}/retry`, {
    method: 'POST',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to retry ingestion job: ${res.statusText}`);
  }
  return res.json();
}

export async function getKnowledgeGraphStatus(sourceId: string): Promise<SourceGraphStatusResponse> {
  const res = await authFetch(`${BASE_URL}/knowledge/sources/${encodeURIComponent(sourceId)}/graph-status`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch graph status: ${res.statusText}`);
  }
  return res.json();
}

export async function getKnowledgeGraphStats(): Promise<KnowledgeGraphStatsResponse> {
  const res = await authFetch(`${BASE_URL}/knowledge/graph/stats`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to fetch graph stats: ${res.statusText}`);
  }
  return res.json();
}

export async function auditKnowledgeGraph(
  categories?: string[],
  maxRecords?: number
): Promise<GraphAuditResponse> {
  const params = new URLSearchParams();
  if (categories && categories.length > 0) params.append('categories', categories.join(','));
  if (maxRecords !== undefined) params.append('max_records', String(maxRecords));
  const q = params.toString() ? `?${params.toString()}` : '';
  const res = await authFetch(`${BASE_URL}/knowledge/graph/audit${q}`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to audit knowledge graph: ${res.statusText}`);
  }
  return res.json();
}

function jsonStringify(obj: any): string {
  return JSON.stringify(obj);
}

