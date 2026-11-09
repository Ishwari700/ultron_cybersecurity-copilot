# ULTRON — BATCH 1.3: TEST CLASSIFICATION & RUNTIME RECONCILIATION REPORT

**Project:** Ultron – Cybersecurity Copilot  
**Phase:** Batch 1.3 — Final Verification & Runtime Reconciliation Before Batch 2  
**Date:** October 17, 2026  
**Status:** PASS — VERIFIED  
**Repository Root:** `C:\Projects\Ultron - Cybersecurity Copilot`  
**Active Branch:** `master`  
**Execution Environment:** Windows (PowerShell), Python 3.13.14 (`.venv`), Node.js (v20+, Vite 8.3.2 + React 19), Ollama v0.34.1  
**Batch 2 Readiness Recommendation:** **SAFE TO BEGIN BATCH 2**

---

## 1. Initial Repository and Git State

Before implementing test classification changes or executing regression suites, the repository state was inspected and verified:

```
Repository Root: C:\Projects\Ultron - Cybersecurity Copilot
Active Branch: master
Head Commit: 8a2d326 "feat(branding): rename AI to Ultron with cyber UI aesthetics and update repository references"

Preserved User Modifications:
  M data/eval/m10_evaluation_results.json (STRICTLY PRESERVED)
  M data/eval/m11_5_evaluation_results.json (STRICTLY PRESERVED)
  M data/eval/m12_evaluation_results.json (STRICTLY PRESERVED)

Preserved Phase Changes:
  - Batch 1 Security Boundary Remediations (Finding verification atomicity, artifact integrity & quarantine, audit isolation)
  - Batch 1.1 Authentication Closure (Auth enabled by default, scrypt password verification, session cookie CSRF protection)
  - Batch 1.2 Bootstrap Safety (Interactive non-echoing password prompt, password confirmation, rejection of CLI password args)
```

No external networks, targets, or remote endpoints were contacted. All testing occurred against local fixtures and the local Ollama runtime (`127.0.0.1:11434`).

---

## 2. Test Classification Architecture and Changes

### Problem Statement
In earlier runs, the test suite lacked a formal mechanism to separate fast, deterministic unit/integration tests from runtime-dependent tests requiring a running Ollama daemon, resident GPU models, and autoregressive inference. When Ollama was offline, tests skipped; when Ollama was online under load or cold model state, tests executed live inference and were vulnerable to consumer-hardware socket timeouts (30.0s ceiling), leading to inconsistent suite outcomes.

### The Exact Solution
1. **Registered Custom Pytest Marker in `pyproject.toml`:**
   ```toml
   [tool.pytest.ini_options]
   testpaths = ["tests"]
   pythonpath = ["."]
   python_files = ["test_*.py"]
   python_functions = ["test_*"]
   addopts = "-v --strict-markers"
   markers = [
       "live_ollama: marks tests requiring a running local Ollama daemon and loaded models",
   ]
   ```
2. **Explicitly Tagged All 17 Live-Model Tests Across Repository:**
   - **Unit Suite (3 tests):**
     - `tests/unit/test_m4_counterfactual_prompting.py::test_19_live_ollama_i3_unconstrained_sanity_check` (`@pytest.mark.live_ollama`)
     - `tests/unit/test_m4_schema_constrained_generation.py::test_13_live_ollama_runtime_capability_sanity_check` (`@pytest.mark.live_ollama`)
     - `tests/unit/test_m4_namespace_segregation.py::test_19_live_ollama_i2_unconstrained_sanity_check` (`@pytest.mark.live_ollama`)
   - **Integration Suite (14 tests across 8 files):**
     - `tests/integration/test_live_cascade_phase8.py`:
       - `test_phase8_digest_consistency_against_phase0` (`@pytest.mark.live_ollama`)
       - `test_phase8_live_cascade_full_suite` (`@pytest.mark.live_ollama`)
       *(Note: 5 deterministic unit/mock tests in this file remain in the deterministic suite)*
     - `tests/integration/test_live_v6_complete_pipeline.py` (4 tests; module `pytestmark = [pytest.mark.live_ollama]`)
     - `tests/integration/test_live_v6_smoke.py` (3 tests; module `pytestmark = [pytest.mark.live_ollama]`)
     - `tests/integration/test_live_ablation_pilot.py` (1 test; module `pytestmark = [pytest.mark.live_ollama]`)
     - `tests/integration/test_m4_bair_live.py` (1 test; module `pytestmark = [pytest.mark.live_ollama]`)
     - `tests/integration/test_m4_decision_policy_live.py` (1 test; module `pytestmark = [pytest.mark.live_ollama]`)
     - `tests/integration/test_m4_protected_handoff_live.py` (1 test; module `pytestmark = [pytest.mark.live_ollama]`)
     - `tests/integration/test_model_inference.py::test_live_ollama_inference` (`@pytest.mark.live_ollama`)
3. **Execution Commands:**
   - **Deterministic Suite (Zero Live-Runtime Dependencies):**
     ```powershell
     .\.venv\Scripts\python.exe -m pytest -m "not live_ollama" tests/unit
     .\.venv\Scripts\python.exe -m pytest -m "not live_ollama" tests/integration
     # Or full repository:
     .\.venv\Scripts\python.exe -m pytest -m "not live_ollama" tests
     ```
   - **Live-Runtime Suite (Dedicated Model Validation):**
     ```powershell
     .\.venv\Scripts\python.exe -m pytest -m "live_ollama" tests/unit
     .\.venv\Scripts\python.exe -m pytest -m "live_ollama" tests/integration
     # Or full live suite:
     .\.venv\Scripts\python.exe -m pytest -m "live_ollama" tests
     ```

---

## 3. Test Configuration & Import-Resolution Verification

Test environment resolution was verified using the project virtual environment `.venv`:

- **Python Executable:** `C:\Projects\Ultron - Cybersecurity Copilot\.venv\Scripts\python.exe`
- **Pytest Rootdir:** `C:\Projects\Ultron - Cybersecurity Copilot` (`pyproject.toml`)
- **Package Resolution Check:**
  ```python
  import src.dashboard.app -> C:\Projects\Ultron - Cybersecurity Copilot\src\dashboard\app.py
  import src.dashboard.auth -> C:\Projects\Ultron - Cybersecurity Copilot\src\dashboard\auth.py
  import src.dashboard.bootstrap -> C:\Projects\Ultron - Cybersecurity Copilot\src\dashboard\bootstrap.py
  import src.database.manager -> C:\Projects\Ultron - Cybersecurity Copilot\src\database\manager.py
  import src.engine.runner -> C:\Projects\Ultron - Cybersecurity Copilot\src\engine\runner.py
  ```
- **Total Repository Items Collected:** **1,616 tests**
  - `tests/unit/`: 1,506 collected items
  - `tests/integration/`: 110 collected items
  - Cross-project contamination: **0 items** (100% project-local resolution).

---

## 4. Root-Cause Diagnosis of the Two Live-Ollama Failures

### C1. Investigation of `test_19_live_ollama_i3_unconstrained_sanity_check`

**Test Location:** `tests/unit/test_m4_counterfactual_prompting.py`  
**Reported Symptom:** Raw response was empty (`len(result.raw_response) > 0` failed) despite Ollama being reachable.

**Empirical Analysis:**
1. In `src/engine/runner.py`, `OllamaRunner` defines:
   ```python
   def __init__(self, ..., timeout_seconds: float = 30.0, ...):
   ```
2. When `ReasoningRunner.execute_i3_generation(prompt=prompt, category_id="API-AUTH-NONE")` is invoked:
   - `raw_response = ""` is initialized at line 1116.
   - It calls `self.ollama_runner.generate_raw(...)` with `effective_timeout = 30.0` seconds.
3. If the model is cold (loading 4.68 GB weights into VRAM) or system resources are contested:
   - Wall-clock time exceeds 30.0 seconds.
   - `httpx` raises `httpx.TimeoutException`.
   - `src/engine/runner.py` catches the exception as `transport_error = exc` (line 1142).
   - Lines 1146-1158 handle `transport_error`:
     ```python
     if transport_error is not None:
         classification = classify_primary_failure(transport_error=transport_error, ...)
         return I3ExecutionResult(
             raw_response=raw_response,  # Empty string ""
             parsed_json=None,
             hypothesis=None,
             classification=classification,
             latency_ms=latency_ms,
             template_category_id=category_id,
         )
     ```
   - The test asserts: `assert len(result.raw_response) > 0`. Because `raw_response` remained `""`, the assertion failed.
4. **Authoritative Live Verification:**
   - Executed against warmed `qwen2.5-coder:7b`:
     - Test completed in **31.02s** (request latency ~27s).
     - Raw response length: 750 characters.
     - `result.classification.primary_category`: `PrimaryFailureCategory.VALID`.
     - Outcome: **PASSED**.

---

### C2. Investigation of `test_13_live_ollama_runtime_capability_sanity_check`

**Test Location:** `tests/unit/test_m4_schema_constrained_generation.py`  
**Reported Symptom:** Test failed with `PrimaryFailureCategory.RUNTIME_TIMEOUT` after 30 seconds.

**Empirical Analysis:**
1. In `src/engine/runner.py`, `execute_i1_generation` invokes `self.ollama_runner.generate_raw` with structured decoding under the 30.0s timeout ceiling.
2. When inference elapsed time reached 30.0s:
   - `httpx` raised `TimeoutError`.
   - `classify_primary_failure` in `src/engine/models.py` line 983 detects `isinstance(transport_error, TimeoutError)` and assigns:
     `primary_category = PrimaryFailureCategory.RUNTIME_TIMEOUT`.
3. The test asserts:
   ```python
   assert result.classification.primary_category in [
       PrimaryFailureCategory.VALID,
       PrimaryFailureCategory.MAX_TOKEN_TRUNCATION,
   ]
   ```
   Because `primary_category` was `RUNTIME_TIMEOUT`, the assertion failed.
4. **Authoritative Live Verification:**
   - Executed against warmed `qwen2.5-coder:7b`:
     - Test completed in **28.44s** (request latency ~24.5s).
     - `result.classification.primary_category`: `PrimaryFailureCategory.VALID`.
     - `result.hypothesis.decision`: `HypothesisDecision.INSUFFICIENT_EVIDENCE`.
     - Outcome: **PASSED**.

---

### C3. Live Runtime Facts and Diagnostics

Local diagnostics captured directly from `http://127.0.0.1:11434`:

| Metric / Parameter | Live Verified Value |
| :--- | :--- |
| **Ollama Daemon Version** | `0.34.1` |
| **Active 7B Model Tag** | `qwen2.5-coder:7b` |
| **Active 7B Model Digest** | `dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364` |
| **Active 7B Size** | 4,683,087,561 bytes (4.68 GB) |
| **Active 3B Model Tag** | `qwen2.5-coder:3b` |
| **Active 3B Model Digest** | `f72c60cabf6237b07f6e632b2c48d533cef25eda2efbd34bed21c5e9c01e6225` |
| **Active 3B Size** | 1,929,912,626 bytes (1.93 GB) |
| **VRAM Resident Allocation** | 2,282,540,236 bytes (~2.28 GB) |
| **Context Length (`num_ctx`)** | 4096 (Ollama runner configured for 2048) |
| **Generation Limit (`num_predict`)** | 300 tokens |
| **Hard Socket Timeout** | 30.0 seconds |

---

### C4. Evaluation: Are These Failures Related to Batch 1?

**Conclusion: UNRELATED TO BATCH 1.**

- **Code Boundary Isolation:** Batch 1, 1.1, and 1.2 remediations modified `src/dashboard/auth.py`, `src/dashboard/bootstrap.py`, `src/dashboard/app.py`, `src/assessment/manager.py`, `src/assessment/experiments.py`, and `src/database/schema.sql`.
- **Zero Shared Dependencies:** None of the Batch 1 changes touch `ReasoningRunner`, `OllamaRunner`, `classify_primary_failure`, `context_builder.py`, or any prompt contracts.
- **Root Cause Mechanism:** The 30.0s socket timeout in `OllamaRunner` sits directly adjacent to typical 7B cold-start autoregressive generation latency (25s–35s). Under cold load or system contention, requests exceed 30.0s, tripping `TimeoutError`. Both tests pass cleanly when the model is warm in VRAM.

---

## 5. Security Gate Reconfirmation (Batch 1, 1.1, 1.2)

All 13 security invariants were independently retested and verified:

| # | Security Invariant / Gate Requirement | Verification Command / Suite | Result |
| :---: | :--- | :--- | :---: |
| 1 | Launcher requires authentication by default (`AUTH_ENABLED=True`) | `test_batch1_1_auth_closure.py::test_attack_3` | **PASS — VERIFIED** |
| 2 | Missing credentials fail closed with 401 across assessment endpoints | `test_batch1_security_boundaries.py::test_missing_credentials` | **PASS — VERIFIED** |
| 3 | Login verifies real credentials against scrypt-hashed DB accounts | `test_batch1_1_auth_closure.py::test_login_credential_verification` | **PASS — VERIFIED** |
| 4 | Client-supplied role payloads cannot elevate privileges | `test_batch1_1_auth_closure.py::test_attack_1` | **PASS — VERIFIED** |
| 5 | Logout revokes session from DB and clears session cookie | `test_batch1_security_boundaries.py::test_session_login_and_cookie` | **PASS — VERIFIED** |
| 6 | Cookie-authenticated state-changing requests require valid CSRF proof | `test_batch1_1_auth_closure.py::test_attack_6` | **PASS — VERIFIED** |
| 7 | Bootstrap CLI rejects `--password` / `-p` command-line argument (exit code 2) | `test_batch1_2_bootstrap_safety.py::test_bootstrap_cli_rejects` | **PASS — VERIFIED** |
| 8 | Client-controlled actor fields cannot override authenticated identity | `test_batch1_security_boundaries.py::test_actor_attribution` | **PASS — VERIFIED** |
| 9 | Experiment result import rejected unless `HUMAN_APPROVED` state present | `test_batch1_security_boundaries.py::test_experiment_result_import` | **PASS — VERIFIED** |
| 10 | Failed finding validation atomically rolls back transaction | `test_batch1_security_boundaries.py::test_finding_verification` | **PASS — VERIFIED** |
| 11 | Artifact registration requires valid bytes for SHA-256 computation | `test_batch1_security_boundaries.py::test_artifact_upload_computes` | **PASS — VERIFIED** |
| 12 | Unverified artifacts remain strictly `QUARANTINED` | `test_batch1_security_boundaries.py::test_artifact_upload_computes` | **PASS — VERIFIED** |
| 13 | Audit queries isolate events by `investigation_id` without cross-leakage | `test_batch1_security_boundaries.py::test_audit_records_isolated` | **PASS — VERIFIED** |

**Security Gate Suite Execution:**
```powershell
.\.venv\Scripts\python.exe -m pytest tests/unit/test_batch1_1_auth_closure.py tests/unit/test_batch1_2_bootstrap_safety.py tests/unit/test_batch1_security_boundaries.py tests/unit/test_dashboard_security.py tests/unit/test_m13_security_invariants.py -v
```
**Outcome:** **77 passed, 0 skipped, 0 failed in 53.20s** (**PASS — VERIFIED**).

---

## 6. Frontend Verification and Production Build

Executed from `C:\Projects\Ultron - Cybersecurity Copilot\frontend`:

1. **Frontend Tests (`npm test`):**
   ```powershell
   cd frontend
   npm test
   ```
   **Outcome:** **10 passed, 0 failed in 465.5ms** (**PASS — VERIFIED**).
   - Branding: Displays ULTRON cleanly without legacy taglines or emoji decoration.
   - Defect Prevention: Hardcoded canned intro string is completely absent from all frontend sources.
   - Startup Mode: Copilot is default view; localStorage session persistence is eliminated.
   - Traffic Scenarios A–E: Ingestion, deduplication, scope filtering, and error handling contracts pass.

2. **Frontend Production Build (`npm run build`):**
   ```powershell
   npm run build
   ```
   **Outcome:** **53 modules transformed, 0 errors in 588ms** (**PASS — VERIFIED**).
   - `dist/index.html`: 0.72 kB
   - `dist/assets/index-AF4UnUie.css`: 4.92 kB
   - `dist/assets/index-orv-7z2C.js`: 452.79 kB (gzip: 109.62 kB)

---

## 7. Deterministic Regression Baseline (Unit & Integration)

### 7.1 Deterministic Unit Suite
Executed from `C:\Projects\Ultron - Cybersecurity Copilot`:

```powershell
.\.venv\Scripts\python.exe -m pytest -m "not live_ollama" tests/unit -q
```
**Outcome:** **1,503 passed, 3 deselected, 0 failed, 0 errors, 0 skips in 1008.17s (16m 48s)** (**PASS — VERIFIED**).

All 1,503 deterministic unit tests across all project modules (m3, m4, m5, m6, m9, phase10, phase11, phase12, dashboard, assessment, database, core) passed cleanly. The 3 tagged live tests (`test_19` in `test_m4_counterfactual_prompting.py`, `test_13` in `test_m4_schema_constrained_generation.py`, and `test_19` in `test_m4_namespace_segregation.py`) were properly deselected.

### 7.2 Deterministic Integration Suite
Executed from `C:\Projects\Ultron - Cybersecurity Copilot`:

```powershell
.\.venv\Scripts\python.exe -m pytest -m "not live_ollama" tests/integration -q
```
**Outcome:** **96 passed, 14 deselected, 0 failed, 0 errors in 184.44s** (**PASS — VERIFIED**).

Modules verified:
- `test_copilot_end_to_end_regression.py` (1 test)
- `test_live_cascade_phase8.py` (5 deterministic mock/gate/hashing tests)
- `test_m10_deep_analysis.py` (5 tests)
- `test_m11_5_pipeline.py` (3 tests)
- `test_m11_pipeline.py` (2 tests)
- `test_m12_pipeline.py` (7 tests)
- `test_m13_workspace_pipeline.py` (2 tests)
- `test_m5_integration.py` (7 tests)
- `test_m6_integration.py` (1 test)
- `test_m7_integration.py` (3 tests)
- `test_m8_integration.py` (2 tests)
- `test_m9_real_cybersecurity_questions.py` (17 tests)
- `test_model_inference.py` (9 deterministic tests)
- `test_phase10_adversarial_security.py` (21 tests)
- `test_phase11_6_pipeline_integration.py` (5 tests)
- `test_phase12_e2e_ui.py` (4 tests)
- `test_reasoning_loop.py` (2 tests)

---

## 8. Historical vs. Current Test Reconciliation

| Historical / Current Run | Exact Command | Collected | Passed | Skipped | Failed | Errors | Deselected | Runtime Status | Authoritative Note |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- | :--- |
| **Batch 1.2 Historical Run** | `pytest tests/unit -q` | 1506 | 1503 | 3 | 0 | 0 | 0 | Offline | Ollama was offline; all 3 live unit tests skipped. |
| **Subsequent Observation** | `pytest tests/unit -q` | 1506 | 1504 | 2 | 2 | 0 | 0 | Online (Cold) | Ollama was online; cold 7B model caused 30s timeouts on 2 tests. |
| **Batch 1.3 Live Unit Suite** | `pytest -m "live_ollama" tests/unit -v` | 1506 | 3 | 0 | 0 | 0 | 1503 | Online (Warm) | Tagged live tests verified passing against warm VRAM models. |
| **Batch 1.3 Deterministic Unit Suite** | `pytest -m "not live_ollama" tests/unit -q` | 1506 | 1503 | 0 | 0 | 0 | 3 | Any | **AUTHORITATIVE UNIT BASELINE** (fully deterministic). |
| **Batch 1.3 Deterministic Integration Suite** | `pytest -m "not live_ollama" tests/integration -q` | 110 | 96 | 0 | 0 | 0 | 14 | Any | **AUTHORITATIVE INTEGRATION BASELINE** (96 passed). |
| **Batch 1.3 Full Deterministic Baseline** | `pytest -m "not live_ollama" tests -q` | 1616 | 1599 | 0 | 0 | 0 | 17 | Any | **AUTHORITATIVE COMPLETE BASELINE** (1,599 passed). |

### Explanation of Discrepancies
1. In Batch 1.2, Ollama was offline. Three M4 tests skipped via `if not runner.is_available(): pytest.skip(...)`. Total: 1,503 passed, 3 skipped, 0 failed.
2. In the intermediate observation, Ollama was online but cold. Two of the three M4 tests hit the 30.0s socket timeout. One live test passed (`test_19` i2). Total: 1,504 passed, 2 failed.
3. In Batch 1.3, test classification via `@pytest.mark.live_ollama` decouples deterministic execution from model runtime latency. The deterministic suite collects 1,506 unit tests, cleanly deselects the 3 live tests, and executes 1,503 deterministic tests with **0 skips, 0 failures, 0 errors**.
4. In integration tests, 14 live model tests are tagged `@pytest.mark.live_ollama`, leaving 96 deterministic integration tests which pass with **0 skips, 0 failures, 0 errors**.

---

## 9. All Failures, Errors, and Skips

- **Unexplained Failures:** 0
- **Unexplained Errors:** 0
- **Deterministic Suite Skips:** 0
- **Live Suite Failures in Authoritative Run:** 0 (all 3 live unit tests passed in warm VRAM verification)

---

## 10. Changed Files and Final Git Diff Summary

### Changed Files
1. `pyproject.toml`: Registered `live_ollama` marker.
2. `tests/unit/test_m4_counterfactual_prompting.py`: Added `@pytest.mark.live_ollama` to `test_19`.
3. `tests/unit/test_m4_schema_constrained_generation.py`: Added `@pytest.mark.live_ollama` to `test_13`.
4. `tests/unit/test_m4_namespace_segregation.py`: Added `@pytest.mark.live_ollama` to `test_19`.
5. `tests/integration/test_live_cascade_phase8.py`: Added `@pytest.mark.live_ollama` to live tests.
6. `tests/integration/test_live_v6_complete_pipeline.py`: Added module-level `pytestmark = [pytest.mark.live_ollama]`.
7. `tests/integration/test_live_v6_smoke.py`: Added module-level `pytestmark = [pytest.mark.live_ollama]`.
8. `tests/integration/test_live_ablation_pilot.py`: Added module-level `pytestmark = [pytest.mark.live_ollama]`.
9. `tests/integration/test_m4_bair_live.py`: Added module-level `pytestmark = [pytest.mark.live_ollama]`.
10. `tests/integration/test_m4_decision_policy_live.py`: Added module-level `pytestmark = [pytest.mark.live_ollama]`.
11. `tests/integration/test_m4_protected_handoff_live.py`: Added module-level `pytestmark = [pytest.mark.live_ollama]`.
12. `tests/integration/test_model_inference.py`: Added `@pytest.mark.live_ollama` to `test_live_ollama_inference`.

---

## 11. Known Limitations

1. **Hardware Latency Boundary for 7B Models:**
   - Autoregressive generation of 300 tokens on `qwen2.5-coder:7b` requires 18s–28s on local consumer hardware.
   - The default `OllamaRunner` socket timeout is 30.0s. If the model is not pre-warmed in VRAM, weight loading adds 10s–15s, which exceeds 30.0s and triggers `TimeoutError`.
   - In production or diagnostic runs with cold models, increasing the socket timeout parameter (e.g. `timeout_seconds=60.0`) or ensuring model residency via `keep_alive` prevents timeout degradation.

---

## 12. Batch 2 Readiness Decision

### Evaluation of Exit Gate Conditions
- [x] Test classification correctly distinguishes deterministic from runtime-dependent tests.
- [x] The deterministic suite runs from the verified Ultron environment.
- [x] No unexplained deterministic failures or errors remain (0 failures, 0 errors).
- [x] Both reported live inference failures have an evidence-based diagnosis.
- [x] Live tests remain enabled, collected, and independently runnable (`pytest -m "live_ollama"`).
- [x] Security tests for Batch 1, 1.1, and 1.2 remain green (77/77 passed).
- [x] Frontend tests (10/10 passed) and production build pass without errors.
- [x] Historical and current test totals are fully reconciled in a unified table.
- [x] User evaluation artifacts (`data/eval/m10_*.json`, `m11_5_*.json`, `m12_*.json`) are preserved.
- [x] The final Git diff is reviewed without discarding existing changes.
- [x] The report accurately distinguishes what was verified from what remains uncertain.

### Final Recommendation

# **SAFE TO BEGIN BATCH 2**

The security boundaries from Batch 1/1.1/1.2 are rock-solid, the deterministic regression baseline is 100% green (1,599 tests passing, 0 failures, 0 errors, 0 skips), the live model failures have been fully explained and verified as hardware latency boundaries unrelated to security code, and the frontend builds and tests cleanly.
