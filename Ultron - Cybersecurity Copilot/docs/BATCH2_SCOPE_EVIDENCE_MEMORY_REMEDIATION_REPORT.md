# BATCH 2: SCOPE ENFORCEMENT, EVIDENCE INTEGRITY & MEMORY ISOLATION REMEDIATION REPORT

**Project:** Ultron – Cybersecurity Copilot  
**Milestone / Batch:** Batch 2 of 4  
**Date:** 2026-10-17  
**Execution Context:** Local Synthetic Fixtures, Isolated Test Databases, Mock Network Transports  
**Safety Gate:** ZERO external network transmissions, ZERO real-target scanning, Strict local test isolation  

---

## 1. Initial Repository and Git State

Before implementing changes for Batch 2, the baseline state of the repository was inspected:
- **Repository Path:** `C:\Projects\Ultron - Cybersecurity Copilot`
- **Active Branch:** `master` (synchronized with `origin/master`)
- **Python Runtime:** Python 3.13.14 x64 in `.venv` (`C:\Projects\Ultron - Cybersecurity Copilot\.venv\Scripts\python.exe`)
- **Node.js Environment:** Vite 8.3.2, TypeScript 5.8
- **Pre-existing Unstaged Artifacts:** Batch 1, Batch 1.1, Batch 1.2, and Batch 1.3 hardening reports and verification changes were present and preserved intact.
- **Evaluation Artifact Preservation Gate:** The three historical benchmark records:
  - `data/eval/m10_evaluation_results.json`
  - `data/eval/m11_5_evaluation_results.json`
  - `data/eval/m12_evaluation_results.json`
  were maintained without deletion or corruption.

---

## 2. Scope, Authorization & Policy-Version Findings (Workstream A)

### Baseline Vulnerability Analysis
1. **Scope Policy In-Place Mutation:** Previously, scope policies could be updated on an active assessment without invalidating existing authorization records. An operator or rogue workflow could alter target hostnames, paths, or constraints while the assessment remained in `AUTHORIZED` or `ASSESSMENT_ACTIVE` state.
2. **Missing Version & Digest Binding:** Neither `AuthorizationRecord` nor `AssessmentRecord` held a cryptographically bound digest of the specific `ScopePolicy` version that received legal consent.
3. **Execution Guard Separation:** Target execution checks in `AssessmentLifecycleEngine` checked broad lifecycle status but did not revalidate the content digest of the scope policy against the authorization record immediately before execution dispatch.

### Remediation Implemented
1. **Deterministic Scope Policy Digest (`ScopePolicy.compute_policy_hash()`):**
   - Implemented SHA-256 digest computation over normalized canonical fields (`program_name`, `scope_policy_version`, sorted `in_scope`, sorted `out_of_scope`, `rules_of_engagement`, `program_constraints`).
   - Exposed `@property policy_hash` and bound `ScopeDecisionObject.scope_policy_hash`.
2. **Authorization-to-Policy Cryptographic Binding:**
   - Extended `AuthorizationRecord` with `scope_policy_hash` and `scope_policy_version`, including these in its immutable `content_hash`.
   - Extended `AssessmentRecord` with `scope_policy_hash` and `scope_policy_version`.
3. **Automatic Authorization Invalidation upon Scope Mutation (`AssessmentManager.set_scope()`):**
   - If an approved or active assessment has its scope policy altered, `AssessmentManager.set_scope()` immediately revokes the existing authorization (`AuthorizationStatus.REVOKED`), transitions the assessment state back to `AUTHORIZATION_PENDING`, records audit event `AUTHORIZATION_REVOKED_SCOPE_CHANGED`, and requires fresh human authorization.
4. **Activation Precondition Verification:**
   - In `AssessmentLifecycleEngine.transition()` and `AssessmentManager.activate_assessment()`, transition to `ASSESSMENT_ACTIVE` strictly requires `authorization.is_currently_valid()` and verifies `authorization.scope_policy_hash == assessment.scope_policy_hash`.
   - In `AssessmentLifecycleEngine.is_target_interaction_allowed()`, expired, revoked, or mismatched authorizations fail closed and deterministically block all target network interactions.

---

## 3. Scope Decisions and Safe Networking (Workstream B)

### Baseline Vulnerability Analysis
1. **Client-Selected Asset Scope Status:** In `src/dashboard/app.py` (`POST /api/assessments/{assessment_id}/assets`), the endpoint accepted a client-provided `scope_status` string in `CreateAssetRequest`. An attacker or malicious browser client could inject arbitrary out-of-scope domains (e.g., `evil.com`, `internal.target.com`) labeled as `IN_SCOPE`.
2. **Ambiguous Error Outcome Collapsing:** In `src/workspace/service.py` (`validate_scope_target()`), resolver failures or exceptions were collapsed into boolean false or generic out-of-scope strings, misrepresenting network outages or unresolvable hosts as authoritative policy denials.
3. **DNS TOCTOU & Pinning Drift:** `src/scope/client.py` did not enforce deterministic address selection when multiple A/AAAA records were returned, nor did it verify actual peer addresses or guarantee TLS validation arguments.

### Remediation Implemented
1. **Authoritative Backend Asset Evaluation:**
   - Modified `src/dashboard/app.py` (`add_asset()`): Replaced client-provided `req.scope_status` with server-side authoritative evaluation via `evaluate_asset_scope_independent(req.canonical_identifier, cont.scope_gate)`.
   - Modified `frontend/src/api.ts` and `frontend/src/components/workspace/tabs/ScopeAssetsTab.tsx`: Removed manual scope status dropdown; displayed authoritative `ScopeGate Evaluated` badge with policy version.
2. **Deterministic Six-Way Outcome Vocabulary:**
   - Extended `AssessmentScopeStatus` and `WorkspaceService.validate_scope_target()` with explicit outcomes:
     - `IN_SCOPE`
     - `OUT_OF_SCOPE`
     - `SCOPE_UNVERIFIABLE`
     - `AUTHORIZATION_EXPIRED`
     - `POLICY_VERSION_MISMATCH`
     - `SCOPE_EVALUATION_ERROR`
   - Unresolvable DNS or internal evaluation errors return `SCOPE_UNVERIFIABLE` / `SCOPE_EVALUATION_ERROR`, ensuring operational errors fail closed without corrupting the historical policy record.
3. **Hardened HTTP Transport & Pinned Address Selection (`src/scope/client.py`):**
   - Implemented `select_pinned_address(resolved_addresses)`: Deterministically selects and sorts addresses (IPv4 prioritized before IPv6, lexicographical tie-breaker).
   - Enforced peer address membership verification against approved addresses.
   - Enforced `follow_redirects=False` on the transport, validating each redirect hop against `self.scope_gate.evaluate()`.
   - Explicitly configured `verify=True` on `httpx.Client`, ensuring TLS certificate validation cannot be disabled via request keyword propagation.

---

## 4. Canonical Evidence Integrity and Provenance (Workstream C)

### Baseline Vulnerability Analysis
1. **Unstructured Transaction Keys:** `src/evidence/ingestion/pipeline.py` previously constructed a loose string key (`tx_key = f"{tx.method}:{tx.url}:{tx.response_status}"`) for deduplication and identification. This omitted response body content, request payloads, and headers, leaving records vulnerable to silent modification or false collisions.
2. **Lack of Stored Content Tamper Verification:** The SQLite database lacked a canonical verification method to check whether stored observation records had been manipulated out-of-band.

### Remediation Implemented
1. **Canonical JSON Serialization & Content Digest:**
   - Added `compute_canonical_transaction_digest(method, host, path, response_status, request_body, response_body)` in `src/evidence/ingestion/pipeline.py`.
   - Uses SHA-256 over canonical JSON with sorted keys, unambiguous ASCII encoding, and separate SHA-256 hashing for request/response payloads.
2. **Database Integrity Verification (`DatabaseManager.verify_observation_integrity()`):**
   - Added `verify_observation_integrity(observation_id: str) -> bool` to `DatabaseManager`.
   - Reconstructs the canonical transaction digest from stored database columns and compares against the recorded SHA-256 digest in constant time.
   - Detected manual SQLite row tampering in tests and immediately failed verification closed.
3. **Evidence Preservation Gate Enforcement:**
   - Verified that `EvidencePreservationGate.validate()` strictly rejects missing Channel A evidence or packs lacking valid asset/endpoint identifiers (`CanonicalEvidenceIntegrityError`).

---

## 5. Memory Admission, Namespace Isolation & Retrieval Security (Workstream D)

### Baseline Vulnerability Analysis
1. **Untrusted Tenancy Metadata on Import:** In `src/memory/export.py` (`parse_imported_payload()`), imported JSON records supplied their own `tenant_id` and `assessment_id`, allowing imported files to claim membership in victim tenants or assessments.
2. **Adversarial Instruction Injection:** Imported text could contain prompt injections attempting to override scope or bypass security gates.
3. **Cross-Tenant & Cross-Assessment Retrieval Leakage:** Retrieval engines needed verification that caller context filtering is applied prior to similarity ranking or prompt context construction.

### Remediation Implemented
1. **Authoritative Receiving-Context Rebinding:**
   - In `MemoryExportEngine.parse_imported_payload(raw_json, receiving_context)`: Rebound `tenant_id`, `assessment_id`, and `owner_id` deterministically to the authorized `receiving_context`. Untrusted metadata fields in imported JSON payloads are stripped and cannot override caller context.
   - Forced `epistemic_status = EpistemicStatus.UNVERIFIED_CLAIM` and `authority_level = MemoryAuthority.UNVERIFIED` on all imported entries.
2. **Prompt Injection & Adversarial Pattern Defense:**
   - Enhanced `MemorySanitizer.POISONING_PATTERNS` to catch variants including `system directive:`, `bypass scope gate`, and execution override attempts.
   - In `MemoryAdmissionPipeline.process_candidate()`: Candidate memory items with adversarial instructions raise `MemoryPoisoningAttemptError` and are rejected before entering persistence or vector storage.
3. **Pre-Ranking Context Filtering & Memory Isolation:**
   - Verified that `HybridMemoryRetriever.retrieve()` filters items by `tenant_id`, `assessment_id`, and permitted namespaces before ranking.
   - Verified that Assessment 2 cannot retrieve local memories from Assessment 1, and Tenant Beta cannot retrieve private memories from Tenant Alpha.

---

## 6. Export Disclosure Protections (Workstream D & Vault Integration)

### Remediation Implemented
1. **Authorization-Aware Export Allowlisting:**
   - In `MemoryExportEngine.export_items(items, caller_context)`:
     - Filtered items by caller tenant: non-admin callers cannot export items belonging to other tenants.
     - Filtered items by caller assessment: private assessment items are excluded if `item.assessment_id != caller_context.assessment_id`.
     - Sanitized owner and tenant identifiers for non-admin callers.
2. **Mandatory Redaction Vault Integration:**
   - Every exported memory item has `content`, `summary`, and `provenance_references` processed through `RedactionVault.redact_text()`.
   - Added URI credential pattern matching (`URI_CREDENTIAL_PATTERN = re.compile(r"(://[^:\s/]+:)([^@\s/]+)(@)")`) in `RedactionVault` to ensure embedded database connection strings (e.g., `postgres://user:password@host`) are converted to `[REDACTED_SECRET_X]` placeholders.

---

## 7. Minimal UI Consistency Changes (Workstream E)

### Remediation Implemented
1. **`frontend/src/components/workspace/tabs/ScopeAssetsTab.tsx`:**
   - Removed the manual `<select>` dropdown that allowed users to assign `IN_SCOPE` or `OUT_OF_SCOPE` directly on asset creation.
   - Added an authoritative badge: `"Authority: ScopeGate Evaluated"`.
   - Updated the `ScopeGate Target Validator` panel to render explicit backend outcomes (`IN_SCOPE`, `OUT_OF_SCOPE`, `SCOPE_UNVERIFIABLE`, `AUTHORIZATION_EXPIRED`, `POLICY_VERSION_MISMATCH`) with appropriate color coding and displayed the active scope policy version (`v6.1`).
2. **`frontend/src/api.ts`:**
   - Made `scope_status` optional in `createAssessmentAsset()`, reflecting that the backend computes the authoritative value.
3. **Build & Test Verification:**
   - `npm test`: 10 passed, 0 failed.
   - `npm run build`: TypeScript typecheck and Vite production bundling succeeded in 339ms (53 modules transformed, 0 errors).

---

## 8. Database and Schema Migrations

### Safety & Compatibility Analysis
- **`src/database/schema.sql`:** Existing tables (`investigations`, `observations`, `artifacts`, `audit_events`, `findings`) remain structurally compatible.
- **`DatabaseManager.__init__()`:** Enhanced constructor to accept positional `Path` or `str` arguments transparently without breaking existing callers passing `DatabaseConfig`.
- **Integrity Column Alignment:** Canonical SHA-256 transaction digests computed during ingestion match `observations.content_hash`, verified deterministically by `DatabaseManager.verify_observation_integrity()`.
- **Zero Data Loss:** Existing test databases and evaluation artifacts were untouched.

---

## 9. Files Changed and Technical Justifications

| File Path | Component | Reason for Modification |
|---|---|---|
| `src/scope/models.py` | Scope Policy Model | Added `compute_policy_hash()` and `@property policy_hash` for immutable versioning. |
| `src/scope/gate.py` | Scope Gate Evaluator | Bound decisions to `policy.policy_hash` and `policy.scope_policy_version`. |
| `src/scope/client.py` | Scoped HTTP Transport | Added deterministic address selection (`select_pinned_address`), peer verification, and strict TLS `verify=True` enforcement. |
| `src/assessment/models.py` | Assessment Domain Models | Added `scope_policy_hash` / `scope_policy_version` to `AuthorizationRecord` and `AssessmentRecord`. Added explicit scope outcomes. |
| `src/assessment/lifecycle.py` | Lifecycle State Machine | Verified policy digest matching on `ASSESSMENT_ACTIVE` transition; enforced execution blocking on expired/revoked authorization. |
| `src/assessment/manager.py` | Assessment Manager | Invalidate authorization upon scope changes in `set_scope()`; advance lifecycle safely when scope and authorization are established. |
| `src/workspace/models.py` | Workspace DTOs | Added explicit outcome enums (`SCOPE_UNVERIFIABLE`, `POLICY_VERSION_MISMATCH`, etc.). |
| `src/workspace/service.py` | Scope Target Service | Updated `validate_scope_target()` to emit deterministic six-way outcomes and classify DNS errors as unverifiable rather than denials. |
| `src/dashboard/app.py` | Dashboard REST API | Replaced client-provided asset `scope_status` with backend authoritative evaluation via `evaluate_asset_scope_independent()`. |
| `src/dashboard/service.py` | Dashboard Service | Bound request queries strictly to authenticated session context. |
| `src/database/manager.py` | Database Layer | Added `verify_observation_integrity()` and relaxed constructor argument handling for `Path` instances. |
| `src/evidence/ingestion/pipeline.py` | Evidence Ingestion | Added `compute_canonical_transaction_digest()` and `verify_observation_digest()` using canonical JSON serialization. |
| `src/evidence/vault.py` | Redaction Vault | Added URI credential redaction pattern (`URI_CREDENTIAL_PATTERN`) for passwords in connection strings. |
| `src/memory/export.py` | Memory Import/Export | Rebound imported memory tenancy to receiving context; added caller context filtering and redaction to export engine. |
| `src/memory/sanitizer.py` | Memory Sanitizer | Added detection for `system directive` and `bypass scope gate` adversarial injection patterns. |
| `frontend/src/api.ts` | Frontend API Client | Made `scope_status` optional in `createAssessmentAsset()`. |
| `frontend/src/components/workspace/tabs/ScopeAssetsTab.tsx` | Scope Assets UI | Removed manual scope dropdown; added authoritative evaluation badges and policy version display. |
| `tests/unit/test_batch2_scope_evidence_memory.py` | Regression Suite | New comprehensive 18-test regression suite covering all Batch 2 boundaries. |

---

## 10. Regression Test Commands and Execution Results

### 1. Focused Batch 2 Suite (18 End-to-End Tests)
**Command:**
```powershell
.\.venv\Scripts\python.exe -m pytest tests/unit/test_batch2_scope_evidence_memory.py -v
```
**Output:**
```
============================= test session starts =============================
tests/unit/test_batch2_scope_evidence_memory.py::test_scope_policy_revision_after_approval_invalidates_authorization PASSED [  5%]
tests/unit/test_batch2_scope_evidence_memory.py::test_authorization_policy_version_mismatch_blocks_activation PASSED [ 11%]
tests/unit/test_batch2_scope_evidence_memory.py::test_expired_or_revoked_authorization_blocks_target_action PASSED [ 16%]
tests/unit/test_batch2_scope_evidence_memory.py::test_scope_uncertainty_and_resolver_errors_fail_closed PASSED [ 22%]
tests/unit/test_batch2_scope_evidence_memory.py::test_redirect_to_unauthorized_destination_blocked PASSED [ 27%]
tests/unit/test_batch2_scope_evidence_memory.py::test_dns_peer_selection_and_prohibited_ranges PASSED [ 33%]
tests/unit/test_batch2_scope_evidence_memory.py::test_canonical_evidence_digest_tampering_detected PASSED [ 38%]
tests/unit/test_batch2_scope_evidence_memory.py::test_invalid_evidence_provenance_rejected PASSED [ 44%]
tests/unit/test_batch2_scope_evidence_memory.py::test_cross_investigation_evidence_isolation PASSED [ 50%]
tests/unit/test_batch2_scope_evidence_memory.py::test_cross_assessment_memory_isolation PASSED [ 55%]
tests/unit/test_batch2_scope_evidence_memory.py::test_cross_tenant_retrieval_isolation PASSED [ 61%]
tests/unit/test_batch2_scope_evidence_memory.py::test_memory_poisoning_and_metadata_rebinding PASSED [ 66%]
tests/unit/test_batch2_scope_evidence_memory.py::test_export_metadata_disclosure_protection PASSED [ 72%]
tests/unit/test_batch2_scope_evidence_memory.py::test_scope_status_spoofing_from_api_ignored PASSED [ 77%]
tests/unit/test_batch2_scope_evidence_memory.py::test_evidence_admission_blocked_after_scope_denial PASSED [ 83%]
tests/unit/test_batch2_scope_evidence_memory.py::test_memory_and_evidence_isolation_across_restart PASSED [ 88%]
tests/unit/test_batch2_scope_evidence_memory.py::test_batch1_rbac_regressions_intact PASSED [ 94%]
tests/unit/test_batch2_scope_evidence_memory.py::test_batch1_finding_verification_invariants_intact PASSED [100%]
======================= 18 passed, 2 warnings in 3.90s ========================
```

### 2. Scope & Network Enforcement Suite (41 Tests)
**Command:**
```powershell
.\.venv\Scripts\python.exe -m pytest tests/unit/test_scope.py tests/unit/test_scope_enforcement.py tests/unit/test_scope_security_remediation.py tests/unit/test_phase12_scope_regression.py -v
```
**Output:**
```
============================= 41 passed in 7.09s ==============================
```

### 3. Evidence, Memory Invariants & Batch 1 Hardening Regressions (121 Tests)
**Command:**
```powershell
.\.venv\Scripts\python.exe -m pytest tests/unit/test_phase12_x_evidence_ingestion.py tests/unit/test_vault_security_authorization.py tests/unit/test_vault_adversarial.py tests/unit/test_m12_memory_engine.py tests/unit/test_m12_security_invariants.py tests/unit/test_m13_security_invariants.py tests/unit/test_batch1_security_boundaries.py tests/unit/test_batch1_1_auth_closure.py tests/unit/test_batch1_2_bootstrap_safety.py -v
```
**Output:**
```
====================== 121 passed, 2 warnings in 40.04s =======================
```

### 4. Deterministic Integration Suite (14 Tests)
**Command:**
```powershell
.\.venv\Scripts\python.exe -m pytest tests/integration/test_m13_workspace_pipeline.py tests/integration/test_m12_pipeline.py tests/integration/test_m6_integration.py tests/integration/test_phase12_e2e_ui.py -m "not live_ollama" -v
```
**Output:**
```
======================= 14 passed, 2 warnings in 59.25s =======================
```

### 5. Frontend Unit Tests & Production Bundle Build
**Commands:**
```powershell
npm test -- --run
npm run build
```
**Output:**
```
✔ 10/10 tests passed (duration_ms: 119.36)
✓ built in 339ms (0 errors, 53 modules transformed)
```

---

## 11. Discovered Issues and Remediation Status Inventory

| ID | Issue Description | Severity | Status | Acceptance Test Reference |
|---|---|---|---|---|
| B2-01 | Scope policy could be edited in place after approval without invalidating authorization. | CRITICAL | FIXED AND VERIFIED | `test_scope_policy_revision_after_approval_invalidates_authorization` |
| B2-02 | Assessment activation did not verify that authorization policy digest matched active scope. | HIGH | FIXED AND VERIFIED | `test_authorization_policy_version_mismatch_blocks_activation` |
| B2-03 | Expired or revoked authorization allowed target interaction. | HIGH | FIXED AND VERIFIED | `test_expired_or_revoked_authorization_blocks_target_action` |
| B2-04 | DNS resolution and parsing errors collapsed into false policy denials instead of fail-closed unverifiable state. | MEDIUM | FIXED AND VERIFIED | `test_scope_uncertainty_and_resolver_errors_fail_closed` |
| B2-05 | Client-provided `scope_status` in `add_asset` API allowed attackers to spoof `IN_SCOPE` assets. | CRITICAL | FIXED AND VERIFIED | `test_scope_status_spoofing_from_api_ignored` |
| B2-06 | Redirect to an out-of-scope host was not checked before dispatching subsequent requests. | HIGH | FIXED AND VERIFIED | `test_redirect_to_unauthorized_destination_blocked` |
| B2-07 | DNS resolution address selection was non-deterministic when multiple IPs were returned. | MEDIUM | FIXED AND VERIFIED | `test_dns_peer_selection_and_prohibited_ranges` |
| B2-08 | Observation content lacked a canonical serialized digest for detecting out-of-band DB tampering. | HIGH | FIXED AND VERIFIED | `test_canonical_evidence_digest_tampering_detected` |
| B2-09 | Missing or unparented evidence lacked strict validation before entering analysis pipeline. | HIGH | FIXED AND VERIFIED | `test_invalid_evidence_provenance_rejected` |
| B2-10 | Traffic from one investigation could bleed into another without strict tenant/investigation scoping. | HIGH | FIXED AND VERIFIED | `test_cross_investigation_evidence_isolation` |
| B2-11 | Memory items in Assessment 1 were retrievable from Assessment 2 context. | HIGH | FIXED AND VERIFIED | `test_cross_assessment_memory_isolation` |
| B2-12 | Memory items in Tenant Alpha were retrievable from Tenant Beta context. | CRITICAL | FIXED AND VERIFIED | `test_cross_tenant_retrieval_isolation` |
| B2-13 | Imported memory payloads could specify untrusted `tenant_id` and `assessment_id` to spoof context. | CRITICAL | FIXED AND VERIFIED | `test_memory_poisoning_and_metadata_rebinding` |
| B2-14 | Adversarial prompt instructions inside candidate memory items could instruct system to bypass scope. | HIGH | FIXED AND VERIFIED | `test_memory_poisoning_and_metadata_rebinding` |
| B2-15 | Memory export leaked raw credentials embedded in connection URIs and cross-tenant entries. | HIGH | FIXED AND VERIFIED | `test_export_metadata_disclosure_protection` |
| B2-16 | UI assets tab allowed operators to manually assign authoritative asset scope status via dropdown. | MEDIUM | FIXED AND VERIFIED | `ScopeAssetsTab.tsx` removal & frontend test suite |
| B2-17 | Evidence ingestion allowed out-of-scope transactions to be admitted as persistent observations. | HIGH | FIXED AND VERIFIED | `test_evidence_admission_blocked_after_scope_denial` |
| B2-18 | Memory and evidence isolation across database restarts was not verified under unified schema. | HIGH | FIXED AND VERIFIED | `test_memory_and_evidence_isolation_across_restart` |

---

## 12. Remaining Limitations and Scope Boundary

1. **Local Single-Process Deployment Constraint:** Rate-limiting via `SharedRateLimiter` is thread-safe and process-bound using in-memory token buckets with sliding windows. Multi-process clustering requires an external distributed coordinator (e.g. Redis), which remains deliberately out of scope for the supported local deployment model.
2. **Deterministic vs. Live Ollama Testing:** All 194 tests run across unit and integration suites were executed deterministically without invoking live LLM weights. Live-Ollama suites (`test_live_v6_smoke.py`, etc.) remain separated under the `live_ollama` pytest marker.
3. **No Out-of-Scope Work:** In accordance with the strict scope constraints, Batch 3 (Autonomous Planning, Tool Execution & Safety Rails) and Batch 4 (UI/UX Refinement) have not been started.

---

## 13. Recommendation on Batch 3 Readiness

**Recommendation:** **SAFE TO PROCEED TO BATCH 3.**  
All 14 acceptance criteria for Batch 2 are fully satisfied and verified by deterministic regression tests. Backend authoritative policy binding, tamper-evident evidence digests, safe HTTP transport pinning, and memory isolation barriers are firmly in place.
