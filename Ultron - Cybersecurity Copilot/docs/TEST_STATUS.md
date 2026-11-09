# Test Status & Reproducibility Baseline

**Last Updated:** 2026-09-22 (Post-Remediation Baseline)  
**Scope:** Complete repository test inventory, offline hermetic test validation, and live-model test boundary.

---

## 1. Executive Summary

| Suite Category | Files | Collected Items | Passing (Offline) | Failing (Offline) | Errors (Offline) | Skipped (Offline) | Hermetic Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Unit Test Suite** (`tests/unit/`) | 86 | 772 | **769** | **0** | **0** | **3** | **100% Hermetic Passing** |
| **Integration Suite** (`tests/integration/`) | 10 | 51 | **37** | 2* | 4* | 8 | *Requires Live Ollama Daemon |
| **Total Test Suite** | **96** | **823** | **806** | **2\*** | **4\*** | **11** | **Hermetic Core Validated** |

*\*Note on Offline vs. Live Model Execution:*  
Running the full repository root without an active local Ollama daemon produces 2 failures and 4 errors exclusively in `tests/integration/test_live_cascade_phase8.py` and `tests/integration/test_live_v6_complete_pipeline.py`. These tests execute direct HTTP calls against `http://127.0.0.1:11434` to validate live model residency, prompt injection defense with live 7B weights, and full batch cascades. All 772 unit tests and 37 offline integration tests execute 100% deterministically and hermetically without external dependencies.

---

## 2. Test Count Discrepancy & Evolution Reconciliation

Historical documentation originally referenced 126 tests from the Milestone M1 era. The repository has since evolved across Milestones M2, M3, M4, M5, and the comprehensive critical security remediation pass:

1. **Initial v6 Post-Build Baseline**: **77 tests** across 20 initial suites.
2. **Milestone M0 (Phase 0 Hardening)**: **+17 tests** (94 total) for scope CIDR/RFC1918 enforcement and typed vault placeholders.
3. **Milestone M1 & EXP-0006 Baseline**: **+32 tests** (**126 total** across 28 suites) establishing the initial published `TEST_STATUS.md`.
4. **Milestones M2, M3, M4, M5 Research & Evaluation Expansion**: **+631 tests** (**757 total** across 90 files) adding:
   - Lossless structural diffing and observation ingestion.
   - P4 capacity oracle and canonical serialization parity.
   - 3B/7B batch-sequential cascade routing and gate fail-safes.
   - Phase 7, 8, and 9 empirical evaluation harnesses and metric integrity controls.
5. **Critical Security Remediation Pass (Post-Audit)**: **+66 tests** (**823 total** across 96 files) providing dedicated adversarial and regression testing for all findings:
   - `tests/unit/test_simulator_security_remediation.py` (+6 tests): Authenticated simulator boundary, 401 fail-closed verification, and identity protection (Finding 1).
   - `tests/unit/test_execution_credential_fail_closed.py` (+7 tests): Strict credential resolution fail-closed behavior (Finding 2).
   - `tests/unit/test_dashboard_security.py` (+7 tests): Dashboard loopback binding validation, RBAC, session revocation, and UI XSS escaping (Finding 3).
   - `tests/unit/test_artifact_seal_and_provenance.py` (+9 tests): Cryptographic artifact seal verification, code invariant checks, and provenance chains (Findings 4 & 5).
   - `tests/unit/test_vault_security_authorization.py` (+7 tests): Authorized vault reversal, context binding, memory tamper detection, and fail-closed audit requirements (Finding 6).
   - `tests/unit/test_scope_security_remediation.py` (+7 tests): Injected client redirect re-evaluation, redirect loop rejection, and cross-instance rate limiting (Findings 7 & 8).
   - `tests/unit/test_audit_and_poisoning_defense.py` (+6 tests): Cryptographic audit log chaining, tamper detection, ANSI/log-injection telemetry sanitization, and quarantine isolation (Findings 9 & 10).
   - `tests/unit/test_state_machine_atomic_remediation.py` (+9 tests): Atomic human verification transactions, rollback on failure, and complete database state machine triggers (Findings 11 & 12).
   - `tests/unit/test_token_budget_remediation.py` (+6 tests): Tokenizer-aware budgeting, JSON/code density adjustments, Unicode overhead, and Ollama tokenizer fallback (Finding 14).
   - Dashboard API additions (+2 tests): Safe HTML template rendering and safety confirmation gates.

---

## 3. Key Remediation Test Suites

| Remediation Suite | Finding Addressed | Tests | Focus Area & Invariants Enforced |
| :--- | :--- | :--- | :--- |
| `test_simulator_security_remediation.py` | Finding 1 (CRITICAL) | 6 | Replaces redacted authorization headers with canonical bearer tokens; verifies 401 on unauthenticated requests; ensures simulator cannot forge arbitrary roles. |
| `test_execution_credential_fail_closed.py` | Finding 2 (CRITICAL) | 7 | Fails closed on missing or unresolvable credential references; guarantees proposals without valid credentials never reach dispatch. |
| `test_dashboard_security.py` | Finding 3 (HIGH) | 7 | Blocks non-loopback dashboard binding without authentication; enforces Role-Based Access Control (Observer vs Reviewer); verifies HTML entity escaping against stored XSS. |
| `test_artifact_seal_and_provenance.py` | Findings 4 & 5 (HIGH) | 9 | Replaces self-authored booleans with verifiable programmatic code checks; attaches cryptographic HMAC/ECDSA signatures; enforces causal track provenance separation. |
| `test_vault_security_authorization.py` | Finding 6 (HIGH) | 7 | Restricts vault reversal to authorized human reviewers with purpose audit logging; detects memory tampering and fails closed on audit failures. |
| `test_scope_security_remediation.py` | Findings 7 & 8 (HIGH/MED) | 7 | Enforces `follow_redirects=False` on external clients; re-evaluates each redirect hop through `ScopeGate`; shares rate limiter across all client instances. |
| `test_audit_and_poisoning_defense.py` | Findings 9 & 10 (MEDIUM) | 6 | Validates sequential record cryptographic hash chaining; detects log line tampering, deletion, or reordering; sanitizes ANSI/newlines in telemetry; quarantines hostile chunks. |
| `test_state_machine_atomic_remediation.py` | Findings 11 & 12 (MEDIUM) | 9 | Atomically commits verification and hypothesis state transitions in a single transaction; enforces DB triggers preventing state-machine bypass (New -> Confirmed, terminal states). |
| `test_token_budget_remediation.py` | Finding 14 (LOW) | 6 | Tokenizer protocol with remote Ollama tokenizer, FastTokenizer adapter, and calibrated heuristic accounting for code/JSON punctuation density and Unicode overhead. |

---

## 4. Execution Commands

### Hermetic Offline Execution (Recommended for CI & Local Development)
Runs all 772 unit tests hermetically without requiring external daemons or network access:
```powershell
.venv\Scripts\python.exe -m pytest tests/unit/ -v
```

### Dedicated Remediation Suites
Runs all 66 newly added security remediation regression tests:
```powershell
.venv\Scripts\python.exe -m pytest tests/unit/test_*remediation*.py tests/unit/test_artifact_seal_and_provenance.py tests/unit/test_vault_security_authorization.py tests/unit/test_audit_and_poisoning_defense.py -v
```

### Integration Suite (Requires Live Ollama Daemon)
Requires local Ollama daemon running on `127.0.0.1:11434` with `qwen2.5-coder:3b` and `qwen2.5-coder:7b` models loaded:
```powershell
.venv\Scripts\python.exe -m pytest tests/integration/ -v
```

### Complete Test Suite
```powershell
.venv\Scripts\python.exe -m pytest tests/ -v
```
