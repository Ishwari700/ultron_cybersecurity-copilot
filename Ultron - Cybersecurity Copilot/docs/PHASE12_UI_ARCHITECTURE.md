# Phase 12: Local AI Investigation Workspace Architecture
**Document Version:** 1.0.0  
**Status:** Approved Architecture Specification  
**Baseline Milestone:** M5 Phase 11.6 Pass  
**Target URL:** `http://127.0.0.1:8000` (Single Same-Origin Application)

---

## 1. Executive Summary & Objective

The primary objective of Milestone Phase 12 is to build the first production-quality user interface for the **Local AI-Assisted Bug Bounty Research Platform**. The resulting workspace delivers a calm, conversational, research-first environment inspired by the interaction philosophy and visual restraint of the current Claude product experience—specifically tailored for scientific security investigation.

### Core Tenets
1. **Single Application / Single Origin**: The entire platform operates at a single URL (`http://127.0.0.1:8000`). The user executes a single command (`run_local_ui.bat` on Windows or `./run_local_ui.sh` on Linux/Kali), which launches FastAPI, serves the compiled React application, exposes same-origin REST APIs (`/api/*`), and automatically opens the browser. No separate frontend dev server (`5173`) or manual multi-process orchestration is ever exposed.
2. **Authoritative Server-Side Security**: The frontend is strictly a presentation and interaction surface. It possesses zero execution or authorization authority. All security invariants—including `ScopeGate`, `ApprovalGate`, `GroundingValidator`, `ExperimentPolarityValidator`, `DeterministicExecutionEngine`, `RedactionVault`, and `AuditLogger`—are strictly enforced server-side. Browser-controlled data can never override server-side safety checks.
3. **Conversation-First Security Research**: Rather than presenting a generic cybersecurity dashboard filled with high-contrast cards, neon styling, or noisy charts, the interface centers on a calm, document-like AI conversation. Structured reasoning objects (Application Models, Security Invariants, Evidence Gaps, Hypotheses, Experiment Proposals, Human Approvals, Execution Timelines, and Observations) are rendered as clean, expandable inline cards with details on demand via a right-side contextual drawer.
4. **Epistemic Segregation & Strict Provenance**: The UI strictly and visually distinguishes between:
   - `OBSERVED EVIDENCE` (Empirical HTTP interactions from target traffic)
   - `FACT` (Ground-truth verified application observations)
   - `SECURITY INVARIANT` (Documented or derived security policies)
   - `EVIDENCE GAP` (Identified missing facts required to confirm/disprove a hypothesis)
   - `MODEL INFERENCE` (Tentative deductions produced by local LLMs)
   - `VAPT KNOWLEDGE` (General vulnerability methodology retrieved via RAG)
   - `HUMAN VERIFIED FINDING` (Empirically verified vulnerabilities signed off by an authorized human reviewer)
5. **Local-First & Zero External Network Calls**: The UI relies solely on local system fonts (`Inter, ui-sans-serif, -system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif`) and pre-bundled local assets. No CDNs, no Google Fonts, no remote analytics, and no external bug bounty targets are ever contacted.

---

## 2. Current Repository Inspection & Interface Inventory

A comprehensive inspection of the existing codebase confirms the presence of robust, verified production infrastructure:

### 2.1 Existing Entry Points
- **`src/dashboard/app.py`**: Factory function `create_dashboard_app(db_manager, audit_logger, auth_manager, require_auth)` providing a FastAPI instance. Includes session management (`DashboardAuthManager`), RBAC (`DashboardRole.OBSERVER`, `REVIEWER`, `ADMIN`), bind validation (`validate_dashboard_bind`), and initial endpoints for `/api/hypotheses`, `/api/invariants`, and `/api/audit`.
- **`src/engine/llm_health.py`**: Local LLM and GPU health check diagnostic CLI (`run_health_check()`) verifying NVIDIA GPU state via `nvidia-smi` and Ollama connectivity at `/api/tags`.
- **`src/eval/phase11_6_production/runner.py` & `pipeline.py`**: Complete 17-stage production pipeline validator orchestrating safe local simulation across all security gates.

### 2.2 Domain Models & Schemas
- **`src/database/schema.sql` & `manager.py`**: SQLite database (`data/evidence.db`) containing tables:
  - `assets`: Target endpoints, HTTP methods, mutability (`READ_ONLY`, `STATE_CHANGING`, `DESTRUCTIVE`), liveness.
  - `parameters`: HTTP parameters with locations and `is_server_volatile` flags.
  - `identities`: Multi-tenant security identities and roles.
  - `evidence_items`: Canonical facts with `certainty` (`OBSERVED`, `DOCUMENTED`, `DETERMINISTIC_DERIVATION`) and full tool provenance.
  - `derivations`: Parent-child lineage for deterministic business logic derivations.
  - `security_invariants`: Epistemic origin tracking (`DOCUMENTED`, `OBSERVED`, `DETERMINISTIC_DERIVATION`, `MODEL_PROPOSED`).
  - `hypotheses`: Security hypotheses with lifecycle states (`New`, `Under Review`, `Confirmed`, `Rejected`, `Reported`).
  - `verifications`: Human verification audit records binding decisions to human actors.
  - `scope_decisions`: Persistent audit log of all URL/tool scope evaluations.
- **`src/graph/models.py` & `workflow_engine.py`**: `ApplicationModel`, `WorkflowNode`, `WorkflowTransition`, `DerivationRecord`.
- **`src/hypothesis/experiment.py` & `src/execution/models.py`**: `ExperimentProposal`, `MutationClass`, `SafetyLevel`, `ExpectedObservations`, `ExecutionDescriptor`, `HumanApproval`, `ExecutionResult`, `ExecutionStatus`.
- **`src/scope/models.py`**: `ScopePolicy`, `ToolPolicy`, `ScopeDecisionObject`, `ScopeDecision` (`ALLOW` / `DENY`).

### 2.3 Authoritative Security Boundaries
- **Scope**: `ScopeGate.evaluate(...)` validates target URLs against `scope.yaml` and strict IP pinning / private network blocking rules.
- **Human Approval**: `ApprovalGate.verify_approval(...)` cryptographically verifies that a state-changing proposal was explicitly authorized by an authorized human actor, with an exact match of the `compute_digest()` descriptor hash and valid unexpired TTL.
- **Deterministic Execution**: `DeterministicExecutionEngine.execute_proposal(...)` coordinates the 14-step boundary pipeline (`BLOCKED_SCOPE`, `BLOCKED_SAFETY`, `BLOCKED_APPROVAL`, `BLOCKED_TTL`, `BLOCKED_AUTH_STATE`, `BLOCKED_CSRF`, `BLOCKED_RATE_LIMIT`, `BLOCKED_EXECUTION_MODE`, `BLOCKED_TOCTOU`, `EXECUTED`).
- **Secret Redaction**: `RedactionVault` replaces raw credentials with typed placeholders (`<SECRET:AUTH_TOKEN:1>`). Reversal requires authorized `VaultAccessContext`.
- **Grounding Validation**: `Phase11GroundingValidator` prevents fact-ID hallucinations and cross-namespace epistemic pollution (`CHK-` vs `FACT-`).
- **Hypothesis State Machine**: `HypothesisStateMachine` enforces atomic state transitions and SQLite database triggers preventing unverified promotions.
- **Audit Logging**: `AuditLogger` writes append-only JSONL event records with cryptographic SHA256/HMAC hash chaining and cross-process file locking.

---

## 3. Single-Origin Architecture

The application is served strictly from `http://127.0.0.1:8000`:

```
┌────────────────────────────────────────────────────────┐
│                        Browser                         │
│             http://127.0.0.1:8000                      │
│                                                        │
│  React + TypeScript UI (Compiled Production Bundle)   │
└───────────────────────────┬────────────────────────────┘
                            │ Same-Origin Requests
                            ▼
┌────────────────────────────────────────────────────────┐
│                   FastAPI Server                       │
│                                                        │
│  GET /                   →  frontend/dist/index.html   │
│  GET /assets/*           →  frontend/dist/assets/*     │
│  GET /api/*              →  REST API Controllers       │
│  GET /{full_path:path}   →  SPA Catch-all Fallback     │
└───────────────────────────┬────────────────────────────┘
                            │ Direct Python Calls
                            ▼
┌────────────────────────────────────────────────────────┐
│             Authoritative Security Engine              │
│  ScopeGate · ApprovalGate · ExecutionEngine · Vault   │
│  GroundingValidator · StateMachine · AuditLogger       │
│  DatabaseManager (data/evidence.db)                    │
└────────────────────────────────────────────────────────┘
```

### Static Asset Serving Rules
1. All compiled React assets reside in `frontend/dist/`.
2. Static assets are mounted via Starlette's `StaticFiles(directory="frontend/dist/assets", html=False)` at `/assets`.
3. The root path `GET /` serves `frontend/dist/index.html`.
4. Any unrecognized non-API route `GET /{full_path:path}` serves `frontend/dist/index.html` to support client-side routing seamlessly upon page refresh.
5. All REST endpoints reside exclusively under `/api/`.

---

## 4. REST API Specification

All endpoints return JSON and enforce server-side validation and role-based access control.

### 4.1 System & Health Endpoints
- `GET /api/health`
  - Returns overall platform health, local AI runtime status, GPU detection info, Ollama status, database connectivity, and audit chain verification status.
- `GET /api/status`
  - Returns lightweight subsystem readiness states:
    `{ "local_ai": "READY", "ollama": "READY", "evidence": "READY", "vapt_rag": "READY", "audit": "VERIFIED", "gpu": { "detected": false, "name": "None" } }`.

### 4.2 Investigation Management Endpoints
- `GET /api/investigations`
  - Returns list of recent investigations with short name, target host, scope status, evidence count, hypothesis count, and last activity timestamp.
- `POST /api/investigations`
  - Creates a new investigation session with target host, scope configuration, and seed description.
- `GET /api/investigations/{id}`
  - Returns detailed investigation state, including target metadata, scope policy, evidence count, active hypotheses, and research conversation history.
- `POST /api/investigations/{id}/messages`
  - Posts a new user query to the local research AI. Executes the server-side reasoning pipeline (retrieval, context building, invariant mapping, hypothesis synthesis, experiment proposal) and returns structured response chunks with progressive disclosure.
- `GET /api/investigations/{id}/evidence`
  - Returns canonical evidence items associated with the investigation, with epistemic certainty flags (`OBSERVED`, `DOCUMENTED`, `DETERMINISTIC_DERIVATION`), source tool, timestamp, and redacted parameter values.
- `GET /api/investigations/{id}/model`
  - Returns the derived `ApplicationModel`: discovered assets/endpoints, parameters, identities, roles, and derived business logic workflows (`WorkflowNode`).
- `GET /api/investigations/{id}/invariants`
  - Returns security invariants with epistemic origins (`OBSERVED`, `DOCUMENTED`, `DETERMINISTIC_DERIVATION`, `MODEL_PROPOSED`).
- `GET /api/investigations/{id}/gaps`
  - Returns active evidence gaps (missing empirical facts required to falsify or substantiate candidate hypotheses).
- `GET /api/investigations/{id}/hypotheses`
  - Returns hypotheses with categories, decisions, evidence states, grounding status, and lifecycle states.

### 4.3 Experiment & Execution Endpoints
- `GET /api/investigations/{id}/experiments`
  - Returns proposed and executed experiments for the investigation.
- `POST /api/experiments/{id}/validate`
  - Runs deterministic validation (`Phase11GroundingValidator`, `ExperimentPolarityValidator`, `ScopeGate`) on an experiment proposal.
- `POST /api/experiments/{id}/approve`
  - Registers a cryptographically bound `HumanApproval` with `ApprovalGate`. Accepts `actor`, `safety_acknowledged`, `notes`. Computes and binds the descriptor digest.
- `POST /api/experiments/{id}/reject`
  - Rejects an experiment proposal, transitioning the corresponding hypothesis to `Rejected` and logging the audit event.
- `POST /api/experiments/{id}/execute`
  - Dispatches execution to `DeterministicExecutionEngine.execute_proposal(...)`. Enforces the full 14-step boundary checks. Returns real execution status (`EXECUTED`, `BLOCKED_APPROVAL`, `BLOCKED_SCOPE`, etc.), observation, and updated hypothesis state.
- `GET /api/audit`
  - Reads recent immutable audit log records from `data/audit.log` and evaluates the cryptographic hash chain integrity (`AuditLogger.verify_audit_log(...)`).

---

## 5. UI Architecture & Claude-Inspired Visual Language

### 5.1 Design Philosophy
The visual presentation embodies calm restraint, clarity, and readability. It avoids excessive cybersecurity clichés:
- **No Neon Colors**: No radioactive greens, hot pinks, or harsh cyan glowing outlines.
- **No Dense Cyber Grids**: No background gridlines, hex patterns, or fake matrix animations.
- **No Excessive Glassmorphism**: Clean opaque surfaces with subtle, crisp borders.
- **No Cluttered KPI Dashboards**: No giant metric cards consuming visual focus.

### 5.2 Visual Specification Tokens
- **Background**: Warm off-white / ivory (`#FBFBF9` / `#F8F7F4`) for page surfaces; clean white (`#FFFFFF`) for elevated cards.
- **Primary Text**: Deep charcoal (`#1F1E1D` / `#2D2C2A`), providing exceptional contrast and legibility.
- **Secondary Text**: Muted neutral gray (`#6E6D6A` / `#8C8B87`).
- **Borders**: Subdued warm neutrals (`#E6E4DF` / `#DFDCD6`).
- **Card Surfaces**: Soft warm elevated surfaces (`#FFFFFF` with `#F4F2ED` accents).
- **Primary Button**: Deep dark charcoal (`#1F1E1D`) with crisp white text and restrained rounding (`border-radius: 8px`).
- **Semantic Muted Accents**:
  - *Success / Verified*: Subdued forest green (`#2D6A4F` text on `#EAF4EE` background).
  - *Warning / Action Required*: Subdued warm amber (`#9A6B1F` text on `#FDF6E8` background).
  - *Blocked / Denied*: Subdued terracotta crimson (`#9E2A2B` text on `#FAECEB` background).
  - *Model Inference / AI*: Subdued slate indigo (`#3D4A6B` text on `#EEF1F7` background).
- **Typography**: Local font stack only:
  ```css
  font-family: Inter, ui-sans-serif, -system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  ```
- **Spacing & Layout**: Generous whitespace, comfortable line-heights (`1.6`), balanced max-width reading containers (`760px` for conversation flow).

### 5.3 Component Architecture
The React application (`frontend/src/`) is organized into focused, modular components:
- `App.tsx`: Main application container managing layout, active investigation selection, and system drawer state.
- `components/Sidebar.tsx`: Minimal left sidebar with New Investigation, Search, Recent Investigations list, and System Status indicator at the bottom.
- `components/InvestigationHeader.tsx`: Minimal header showing target host, scope status (`ALLOWED` / `DENY`), evidence count, and hypothesis count.
- `components/ConversationView.tsx`: Central document-style conversation container rendering user prompts, AI assistant messages, and inline structured cards.
- `components/Composer.tsx`: Bottom multiline chat composer with suggested research prompts, keyboard shortcuts (`Enter` to submit, `Shift+Enter` for newline), and active processing indicators.
- `components/cards/InvariantCard.tsx`: Expandable inline card displaying security invariants, epistemic origins, and supporting facts.
- `components/cards/HypothesisCard.tsx`: Expandable inline card displaying hypothesis category, target asset, decision, grounding status, and experiment links.
- `components/cards/ExperimentCard.tsx`: Interactive action card displaying objective, action predicate, safety level, human approval requirements, and execution buttons.
- `components/cards/ApprovalModal.tsx`: Explicit confirmation modal for human approval requiring safety acknowledgment before registering with `ApprovalGate`.
- `components/cards/ExecutionTimeline.tsx`: Quiet step-by-step progress indicator showing the 14-step boundary checks (`Scope check`, `Approval`, `Preflight`, `Rate limit`, `TOCTOU`, `Execution`, `Audit`).
- `components/cards/ObservationCard.tsx`: Displays observed execution output clearly segregated from AI interpretation.
- `components/ContextDrawer.tsx`: Collapsible right-hand drawer providing on-demand deep inspection of Evidence, Application Model, Invariants, Gaps, and Audit Trail.
- `components/SystemStatusModal.tsx`: Lightweight modal displaying local AI, Ollama, GPU, Evidence, and Audit cryptographic chain status.

---

## 6. Investigation State Model & Epistemic Hierarchy

The UI strictly preserves the platform's epistemic hierarchy:

```
┌────────────────────────────────────────────────────────┐
│                   Target Evidence                      │
│      Observed HTTP interactions, parameters, facts     │
│             (Source: Target Traffic / Tools)           │
└───────────────────────────┬────────────────────────────┘
                            │ Grounding Validator
                            ▼
┌────────────────────────────────────────────────────────┐
│                  Application Model                     │
│         Assets, Endpoints, Invariants, Gaps            │
│         (Documented / Derived Epistemic State)         │
└───────────────────────────┬────────────────────────────┘
                            │ 3B/7B Reasoning Engine
                            ▼
┌────────────────────────────────────────────────────────┐
│                  Security Hypothesis                   │
│          Candidate explanation of security risk        │
│          (Epistemic status: UNVERIFIED / MODEL)        │
└───────────────────────────┬────────────────────────────┘
                            │ Polarity & Skeleton Policy
                            ▼
┌────────────────────────────────────────────────────────┐
│                  Experiment Proposal                   │
│     Discriminative test distinguishing hypotheses      │
└───────────────────────────┬────────────────────────────┘
                            │ State-Changing Policy
                            ▼
┌────────────────────────────────────────────────────────┐
│                Human Approval Boundary                 │
│         ApprovalGate verifies descriptor digest        │
└───────────────────────────┬────────────────────────────┘
                            │ Safe Local Execution
                            ▼
┌────────────────────────────────────────────────────────┐
│                   Observed Result                      │
│        Supporting / Contradicting Observation          │
└───────────────────────────┬────────────────────────────┘
                            │ Human Review
                            ▼
┌────────────────────────────────────────────────────────┐
│                Human-Verified Finding                  │
│       Authoritatively signed & recorded in audit       │
└────────────────────────────────────────────────────────┘
```

---

## 7. Startup & Orchestration Workflow

### 7.1 Single-Command Launchers
- **Windows**: `run_local_ui.bat`
- **Linux/Kali**: `run_local_ui.sh`

### 7.2 Execution Steps
1. Verify Python virtual environment (`.venv/Scripts/python.exe` or `.venv/bin/python`).
2. Verify Python dependencies (`fastapi`, `uvicorn`, `pydantic`).
3. Check if frontend production bundle exists (`frontend/dist/index.html`). If missing, trigger automated build (`npm run build` inside `frontend/`).
4. Launch FastAPI server via Uvicorn bound strictly to `127.0.0.1:8000`.
5. Automatically open the default browser to `http://127.0.0.1:8000` via Python's standard `webbrowser` module.
6. Display clear terminal banner:
   ```
   ========================================
   LOCAL BUG BOUNTY AI WORKSPACE
   ========================================
   Application ready:
   http://127.0.0.1:8000

   Press Ctrl+C to stop.
   ========================================
   ```

---

## 8. Deterministic Local Demo Investigation

A dedicated demo investigation fixture (`demo_investigation`) is pre-seeded using safe local data:
- **Target**: `api.target.local` (Scope: `ALLOWED`).
- **Endpoint**: `POST /api/v1/billing/invoices/export` (Mutability: `STATE_CHANGING_REQUIRES_APPROVAL`).
- **Invariant**: `INV-001`: "Users may only export billing statements for organizations in their authenticated tenancy."
- **Evidence Gap**: `GAP-001`: "Cross-tenant export authorization check not verified."
- **Hypothesis**: `HYP-001`: "BOLA vulnerability permits unauthorized cross-tenant export via resource ID substitution."
- **Experiment**: `EXP-001`: Action `SUBSTITUTE_RESOURCE_IDENTIFIER` targeting tenant ID with discriminative expected observations.
- **Human Approval**: Experiment requires explicit safety acknowledgment and human approval before execution.
- **Execution**: Demonstrates safe local execution via mock transport, resulting in observed output, evidence generation, and audit logging.

---

## 9. Testing & Verification Strategy

### 9.1 Unit Tests (`tests/unit/test_phase12_ui.py`)
- API endpoints: `/api/health`, `/api/status`, `/api/investigations`, `/api/hypotheses`, `/api/experiments/*`, `/api/audit`.
- Single-origin static file serving: `GET /` serves HTML, `GET /assets/*` serves static files, SPA fallback works for `/investigations/INV-001`.
- Human approval boundary: Unapproved state-changing experiment execution fails closed (`BLOCKED_APPROVAL`).
- Scope boundary: Out-of-scope target execution is blocked (`BLOCKED_SCOPE`).
- Secret isolation: Secret tokens are redacted in all API responses.

### 9.2 Integration Tests (`tests/integration/test_phase12_e2e_ui.py`)
- Complete end-to-end flow: Creating an investigation, generating a hypothesis, reviewing experiment proposal, requesting and registering human approval, executing via the engine, recording observed evidence, and verifying the audit log hash chain.

### 9.3 Historical Immutability Assurance
- Re-verify SHA256 hashes of all 7 historical M5 benchmark datasets before and after Phase 12 changes.
- Ensure `git diff -- data/eval/` remains completely empty.

---

## 10. Conclusion & Acceptance Criteria

Phase 12 succeeds when the researcher can start the platform with `run_local_ui.bat`, open `http://127.0.0.1:8000`, interact with the AI assistant in a calm Claude-inspired workspace, review grounded security invariants and hypotheses, approve experiments via strict human verification boundaries, and see deterministic execution outcomes without exposing raw secrets or contacting external networks.
