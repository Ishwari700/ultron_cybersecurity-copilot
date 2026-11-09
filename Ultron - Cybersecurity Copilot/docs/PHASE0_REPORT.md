# PHASE 0 AUDIT & HARDENING REPORT
**Local AI-Assisted Bug Bounty Research Platform — V6 Final**  
**Date**: September 17, 2026  
**Status**: COMPLETE — AWAITING USER APPROVAL TO PROCEED TO PHASE 1  

---

## 1. Confirmed Audit Findings

The Phase 0 security and research-integrity audit confirmed several critical operational, security, and architectural gaps in the original implementation:

1. **Unenforced Scope Rules & Rate Limits**:  
   `scope.yaml` specified `rate_limit_rps`, `disallowed_techniques`, `no_automated_scanning_on`, and `tool_policy`. However, `ScopeGate.evaluate()` only verified destination domain names, IP address resolution, and private/loopback SSRF blocking. Rate limiting was completely unimplemented, disallowed techniques (e.g. `sql_injection`, `fuzzer`) were ignored, protected URL paths (`no_automated_scanning_on`) were uninspected, and passive tool policies were bypassed.
2. **DNS TOCTOU / Rebinding Vulnerability**:  
   `ScopeGate.evaluate()` validated target hostnames by resolving them via DNS and testing the resulting IP addresses against RFC 1918 / loopback ranges. However, `ScopedHttpClient` subsequently passed the original hostname URL to `httpx.Client`. `httpx` re-resolved DNS independently upon socket connection. This created an exploitable DNS Time-of-Check to Time-of-Use (TOCTOU) window where a malicious domain could pass validation and then resolve to an internal loopback or metadata IP (e.g., `169.254.169.254` or `127.0.0.1`) during the actual HTTP request.
3. **Fail-Open Risk on Audit or Database Logging Failures**:  
   If an internal database error or audit log write failure occurred during `ScopeGate.evaluate()`, the gate did not reliably fail closed on `ALLOW` decisions, potentially permitting unrecorded network traffic.
4. **Silent Exception Swallowing in Core Reasoning Engines**:  
   `WorkflowEngine._derive_transitions()` and `InvariantEngine.load_invariants()` caught general `Exception` with bare `pass`, concealing database anomalies, syntax errors, and missing invariants from researchers and developers.
5. **Broad Exception Handling in Adapters & Compressor**:  
   `OpenAPIAdapter`, `BurpAdapter`, and `EvidenceCompressor` caught broad `Exception` instead of specific parsing and decoding exceptions (`JSONDecodeError`, `binascii.Error`, `ValueError`), masking subtle data transformation bugs.
6. **Insecure Dashboard Binding Default**:  
   `src/dashboard/app.py` allowed arbitrary bind hosts (including `0.0.0.0`) without validation or safety warnings, potentially exposing the local human-in-the-loop review interface and approval mechanisms to unauthorized local network actors.
7. **Dynamic SQL String Formatting**:  
   `DatabaseManager` used dynamic f-string formatting in several query methods instead of strictly parameterized or static queries.
8. **Missing Runtime Dependencies & Typings**:  
   `pyproject.toml` lacked required dependencies `fastapi` and `uvicorn`, while `src/retrieval/vector_store.py` used `Tuple` annotations without importing `Tuple` from `typing`.
9. **Prompt Serialization Redundancy**:  
   `src/engine/runner.py` transmitted `SYSTEM_POLICY_PROMPT` redundantly in both the user prompt body and the system prompt argument to Ollama, causing unnecessary token consumption and context window pressure.

---

## 2. Rejected Audit Findings

The following audit findings and proposals were evaluated and explicitly rejected:

1. **Rejected: Immediate Disk-Based Encryption for Redaction Vault**  
   *Proposal*: Require `RedactionVault` to encrypt and store secret-to-placeholder mappings immediately on disk via symmetric AES-GCM.  
   *Rejection Rationale*: The V6 platform runs locally as a single-user research assistant on an OS already protected by full-disk encryption (BitLocker). Writing secret mappings to disk creates a key management dilemma (where the master key must be derived or stored) and expands the forensic disk attack surface. An in-memory, ephemeral vault with strict scoped lifetimes is safer and cleaner for Phase 0. A complete architectural design for optional encrypted persistence was produced in `docs/VAULT_PERSISTENCE_DESIGN.md` for future consideration.
2. **Rejected: Overbroad Redaction of Random / Opaque Identifiers (User Modification 2)**  
   *Proposal*: Redact all high-entropy strings, UUIDs, hex tokens, and alphanumeric identifiers across all evidence items.  
   *Rejection Rationale*: Broad redaction destroys the semantic utility of security evidence. Legitimate security analysis requires cross-identity and object-level correlation (e.g. testing IDOR between `user_a` and `user_b`, observing invoice ID `INV-4011`, or tracking canonical IDs `EVID-001`, `FACT-002`, `ASSET-001`). Indiscriminate redaction turns evidence into illegible noise. Per User Modification 2, redaction was hardened into typed, explicit detectors targeting actual secrets (AWS keys, session tokens, refresh tokens, cookie headers, sensitive credentials) while strictly preserving legitimate identifiers.
3. **Rejected: Modifying Tracks A–E or Providing Ground Truth to Reasoning**  
   *Proposal*: Modify ablation tracks or inject ground truth (`scen.vulnerable_variant` / `scen.ground_truth_vulnerable`) into reasoning paths to improve synthetic score pass rates.  
   *Rejection Rationale*: Violates scientific research integrity. Ground truth is strictly reserved for the offline evaluator and deterministic scorer. The reasoning engine must operate solely on observable, canonical evidence.

---

## 3. Files Changed

### Modified Files (15 files)
| File Path | Nature of Modifications |
|:---|:---|
| `src/scope/gate.py` | Enforced `disallowed_techniques`, `no_automated_scanning_on`, `tool_policy`, and fail-closed behavior on logging/DB errors. |
| `src/scope/client.py` | Implemented `RateLimiter` (token bucket), DNS IP pinning to validated socket IP, TLS SNI preservation (`extensions={"sni_hostname": host}`), `Host` header preservation, IPv4/IPv6 support, and hop-by-hop redirect re-evaluation and re-pinning. |
| `src/graph/workflow_engine.py` | Replaced bare `except Exception: pass` with structured error logging. |
| `src/invariants/engine.py` | Replaced bare `except Exception: pass` with structured error logging. |
| `src/evidence/compressor.py` | Replaced bare `except Exception:` with specific `(json.JSONDecodeError, ValueError, TypeError)`. |
| `src/evidence/adapters/openapi.py` | Replaced bare `except Exception:` with specific `(json.JSONDecodeError, ValueError, TypeError)`. |
| `src/evidence/adapters/burp.py` | Replaced bare `except Exception:` with specific `(binascii.Error, ValueError, UnicodeDecodeError)`. |
| `src/evidence/vault.py` | Implemented typed secret redaction (`AWS_SECRET`, `SESSION_TOKEN`, `REFRESH_TOKEN`, `COOKIE`, sensitive keys); preserved non-secret domain identifiers; ensured deterministic placeholder correlation. |
| `src/dashboard/app.py` | Enforced default loopback binding (`127.0.0.1`); rejected external binds without explicit `allow_external=True`; documented session trust boundary. |
| `src/core/config.py` | Added `DashboardConfig`; unified model naming scheme (`model_7b`/`primary_model`, `model_3b`/`lightweight_model`). |
| `src/retrieval/vector_store.py` | Added missing `Tuple` import from `typing`. |
| `src/database/manager.py` | Replaced dynamic f-string SQL field interpolation with static queries. |
| `src/engine/runner.py` | Deduplicated `SYSTEM_POLICY_PROMPT` in network calls to Ollama while maintaining backward compatibility for unit tests. |
| `pyproject.toml` | Added `fastapi>=0.110.0` and `uvicorn>=0.29.0`. |
| `tests/unit/test_dashboard.py` | Added 3 tests validating localhost binding and external bind restrictions. |

### Created Files (5 files)
| File Path | Description |
|:---|:---|
| `tests/unit/test_scope_enforcement.py` | 10 unit tests covering rate limits, disallowed techniques, no-scan paths, tool policies, malformed scope, DNS IP pinning, IPv4/IPv6, SNI preservation, and redirect handling. |
| `tests/unit/test_error_handling.py` | 4 unit tests validating fail-closed gate behavior and structured error logging. |
| `tests/unit/test_vault_adversarial.py` | 6 unit tests verifying typed redaction, correlation preservation, and zero secret leakage. |
| `docs/VAULT_PERSISTENCE_DESIGN.md` | Comprehensive design note on vault threat modeling, key management, and in-memory vs disk persistence. |
| `docs/REAL_LLM_ABLATION_DESIGN.md` | Formal experimental protocol for running Tracks A–E under identical evidence budgets with zero ground truth leakage. |

---

## 4. Security Changes

1. **Strict DNS TOCTOU Mitigation & IP Pinning (Modification 1)**:
   - Evaluated the execution path: `ScopeGate.evaluate()` resolves the target hostname and checks IP safety. Previously, `ScopedHttpClient` discarded this IP and let `httpx` re-resolve.
   - Proof of TOCTOU: In multi-homed or fast-flux environments, `httpx` could connect to a different IP than the one inspected.
   - Implementation: `ScopedHttpClient` now rewrites the request target to the exact, validated IP address while preserving the original hostname in the `Host` HTTP header and TLS SNI extension (`extensions={"sni_hostname": original_host}`).
   - Handles IPv4 (`http://93.184.216.34:80/path`) and IPv6 (`http://[2606:2800:220:1:248:1893:25c8:1946]:80/path`).
   - Handles HTTP redirects hop-by-hop: redirects are intercepted, the new target URL is re-evaluated by `ScopeGate.evaluate()`, and the new socket IP is pinned for subsequent hops.
2. **Comprehensive Scope Rule Enforcement**:
   - `ScopeGate.evaluate()` inspects `disallowed_techniques` against requested methods/actions and denies forbidden techniques.
   - `ScopeGate.evaluate()` matches request paths against `no_automated_scanning_on` prefixes and rejects matching paths.
   - `ScopeGate.evaluate()` blocks active requests from tools marked with a `passive` policy.
   - Fail-Closed: If database logging or audit log writes fail during an `ALLOW` evaluation, the gate immediately revokes permission and returns `DENY` with an explicit safety rationale.
3. **Token Bucket Rate Limiting**:
   - Implemented thread-safe `RateLimiter` inside `ScopedHttpClient` governed by `rate_limit_rps` from `scope.yaml`. Enforces smooth request pacing and prevents denial-of-service against target systems.
4. **Dashboard Trust Boundary Hardening**:
   - `validate_dashboard_bind()` restricts the server to `127.0.0.1` by default. Binding to `0.0.0.0` or external interfaces is blocked unless explicitly overridden via `allow_external=True` (or `--allow-external`), with an explicit terminal warning.
5. **SQL Parameterization**:
   - Eliminated dynamic SQL string interpolation across `DatabaseManager` to prevent internal SQL injection vulnerabilities.

---

## 5. Research-Integrity Changes

1. **Typed Redaction Preserving Evidence Grounding (Modification 2)**:
   - Designed typed redaction tokens: `[REDACTED_AWS_SECRET_#]`, `[REDACTED_SESSION_TOKEN_#]`, `[REDACTED_REFRESH_TOKEN_#]`, `[REDACTED_COOKIE_#]`, and `[REDACTED_SECRET_#]`.
   - Explicitly preserved domain identifiers required for authorization differential testing (`user_a`, `user_b`, `admin`, `tenant_id`, `role`, `account_id`, `ACC-*`, `INV-*`, `ORDER-*`) and canonical platform identifiers (`EVID-*`, `FACT-*`, `ASSET-*`, `INVAR-*`, `HYP-*`).
   - Maintained deterministic cross-evidence correlation: identical secrets map to identical typed placeholders across multiple evidence items, enabling the LLM to recognize shared session or credential usage without exposing actual raw secrets.
2. **Ground Truth Isolation**:
   - Formally verified that `scen.vulnerable_variant` and `scen.ground_truth_vulnerable` are strictly excluded from reasoning prompts, vector stores, graph state, invariant engines, and hypothesis generators.
   - Verified that `tests/unit/test_evaluation_isolation.py` enforces zero ground truth leakage into runtime dataflows.
3. **Ablation Protocol Formalization (`docs/REAL_LLM_ABLATION_DESIGN.md`)**:
   - Documented the exact execution protocol for Tracks A through E under an identical observable evidence budget.
   - Specified evaluation metrics, sample sizes (50 scenarios across 5 application families), deterministic scoring criteria, and statistical confidence intervals (Wilson score intervals and McNemar's paired tests).
4. **Prompt Optimization**:
   - Removed redundant inline `SYSTEM_POLICY_PROMPT` duplication in network payloads to Ollama, reducing token overhead by ~300 tokens per inference while preserving full prompt inspection contracts for unit testing.

---

## 6. Tests Added

A total of **23 new tests** were added across 4 test files:

### `tests/unit/test_scope_enforcement.py` (10 tests)
1. `test_scope_enforcement_allow_in_scope`: Confirms valid in-scope requests are permitted.
2. `test_scope_enforcement_deny_disallowed_technique`: Confirms `disallowed_techniques` trigger denial.
3. `test_scope_enforcement_deny_no_automated_scanning_paths`: Confirms protected path prefixes trigger denial.
4. `test_scope_enforcement_passive_tool_policy_blocked`: Confirms passive tool policies block active evaluations.
5. `test_scope_enforcement_malformed_configuration`: Confirms corrupted scope configurations fail closed.
6. `test_scoped_http_client_rate_limiting`: Verifies rate limiter paces requests according to `rate_limit_rps`.
7. `test_dns_ip_pinning_ipv4_and_sni_preservation`: Proves IPv4 IP pinning, TLS SNI extension, and `Host` header preservation.
8. `test_dns_ip_pinning_ipv6_formatting`: Proves IPv6 bracketed formatting and pinning.
9. `test_scoped_http_client_redirect_re_evaluates_and_pins`: Proves redirect locations are re-evaluated and pinned hop-by-hop.
10. `test_scoped_http_client_redirect_to_disallowed_path_blocked`: Proves redirects to forbidden paths are intercepted and blocked.

### `tests/unit/test_error_handling.py` (4 tests)
11. `test_scope_gate_fails_closed_when_database_fails`: Proves gate fails closed on DB error.
12. `test_scope_gate_fails_closed_when_audit_logger_fails`: Proves gate fails closed on audit logger failure.
13. `test_workflow_engine_handles_db_failure`: Proves workflow engine logs structured errors rather than silently swallowing exceptions.
14. `test_invariant_engine_handles_db_failure`: Proves invariant engine logs structured errors rather than silently swallowing exceptions.

### `tests/unit/test_vault_adversarial.py` (6 tests)
15. `test_typed_redaction_aws_secret_key`: Verifies AWS secret access key redaction with typed placeholder.
16. `test_typed_redaction_session_and_refresh_tokens`: Verifies session and refresh token typed redaction.
17. `test_typed_redaction_cookie_headers`: Verifies cookie value redaction inside HTTP header strings.
18. `test_preservation_of_ordinary_security_identifiers`: Proves canonical evidence IDs and cross-identity identifiers are preserved intact.
19. `test_correlation_identical_secrets_map_to_identical_placeholders`: Proves identical secrets receive identical placeholders across multiple inputs.
20. `test_adversarial_pipeline_zero_raw_secret_leakage`: Verifies zero raw secret leakage in synthetic multi-step evidence pipeline.

### `tests/unit/test_dashboard.py` (3 new tests added)
21. `test_dashboard_bind_defaults_to_localhost`: Validates default bind is `127.0.0.1`.
22. `test_dashboard_bind_rejects_external_by_default`: Validates bind to `0.0.0.0` raises ValueError by default.
23. `test_dashboard_bind_allows_external_with_explicit_flag`: Validates bind to `0.0.0.0` succeeds when `allow_external=True`.

---

## 7. Before / After Test Counts & Regression Results

### Test Suite Comparison
| Metric | Baseline (Pre-Phase 0) | Post-Hardening (Phase 0 Complete) | Delta |
|:---|:---:|:---:|:---:|
| **Total Test Count** | **94** | **117** | **+23 (+24.5%)** |
| **Passed Tests** | **94** | **117** | **+23** |
| **Failed Tests** | **0** | **0** | **0** |
| **Test Execution Time** | 82.08s | 76.73s | -5.35s |
| **Test Warnings** | 2 (Starlette deprecation) | 2 (Starlette deprecation) | 0 |

### Live Ollama Regression Status
```text
============================================================
 V6 Final — Local LLM Health & Diagnostic Check
============================================================
GPU detected:           YES (NVIDIA GeForce RTX 3050 Laptop GPU, VRAM: 4096 MiB)
Ollama reachable:       YES (http://127.0.0.1:11434)
3B available (qwen2.5-coder:3b): YES
7B available (qwen2.5-coder:7b): YES
3B inference:           PASS (3.89s latency)
7B inference:           PASS (13.43s latency)
schema validation:      PASS
============================================================
```
- **Live Integration Tests**: All 4 live integration tests (`test_live_v6_complete_pipeline.py`, `test_live_v6_smoke.py`, `test_model_inference.py`, and `test_reasoning_loop.py`) passed cleanly against the real Ollama daemon.
- **Zero Weakened Tests**: No existing test assertions were softened, commented out, or deleted.

---

## 8. Remaining Risks

1. **In-Memory Vault Volatility**:  
   Because `RedactionVault` operates in process memory, restarting the application clears the reversible placeholder mapping. While this eliminates disk exposure risks, long-running research sessions spanning process restarts will require re-ingesting raw evidence to rebuild the mapping. (Addressed in `docs/VAULT_PERSISTENCE_DESIGN.md`).
2. **Upstream Corporate HTTP Proxies**:  
   If an analyst configures an explicit upstream HTTP proxy (`HTTP_PROXY`/`HTTPS_PROXY`), the socket connection is made to the proxy server rather than directly to the destination IP. In this configuration, DNS resolution occurs on the proxy server, partially bypassing local IP pinning.
3. **Local VRAM Constraints (4 GB VRAM)**:  
   The `qwen2.5-coder:7b` model requires partial offloading across GPU and CPU on a 4 GB RTX 3050. While functionally sound and fully validated, 7B inference latency averages 13–15 seconds per call. For large ablation batches, tests must be batched sequentially to avoid system thrashing.
4. **Scope Subnet Precision**:  
   Scope targets specified as CIDR blocks require reverse IP checking. While RFC 1918 and loopback addresses are strictly blocked, complex split-horizon intranet environments require explicit CIDR configuration in `scope.yaml`.

---

## 9. REAL_LLM_ABLATION_DESIGN Summary

The ablation design document (`docs/REAL_LLM_ABLATION_DESIGN.md`) formalizes the empirical benchmark to evaluate whether the V6 architecture provides measurable benefits over conventional LLM approaches under identical constraints:

- **Research Hypothesis**: Given an identical budget of observable evidence, the explicit V6 architecture (*Application Model → Security Invariant → Evidence Gap → Hypothesis → Discriminative Experiment*) improves hypothesis precision, abstention quality, and investigation yield compared to standard direct LLM and RAG baselines.
- **Strict Evidence Budget**: Exactly identical evidence sets are supplied to all 5 tracks. No track receives external ground truth, crawler feeds, or privileged metadata.
- **The 5 Ablation Tracks**:
  - **Track A (Direct LLM)**: Raw Evidence + Direct LLM inference (no RAG, no graph, no invariants).
  - **Track B (RAG Baseline)**: BM25/Vector retrieved evidence chunks + Direct LLM inference.
  - **Track C (Application Model Only)**: Observable Evidence + State Machine / Graph Model + LLM inference (no invariant rules).
  - **Track D (Invariant Verification Only)**: Observable Evidence + Invariant Engine + LLM inference (no state machine / graph).
  - **Track E (Full V6 Architecture)**: Complete pipeline (Model + Invariants + Evidence Gaps + Hypotheses + Discriminative Experiments).
- **Ground Truth Isolation**: All 5 tracks output structured hypothesis proposals. The reasoning engine has zero access to `scen.ground_truth_vulnerable` or `scen.vulnerable_variant`. Scenarios are scored post-hoc by a deterministic evaluator using Wilson score confidence intervals and McNemar's paired contingency tests.

---

## 10. What Must NOT Be Changed in Phase 1

To maintain research rigor and system integrity, the following components are frozen and **MUST NOT** be modified during Phase 1:
1. **Tracks A through E Definitions**: Do not alter track prompts, evidence inputs, or pipeline stages.
2. **Authoritative Invariants**: The 9 core security invariants (`src/invariants/`) must not be rewritten, relaxed, or augmented without prior design review.
3. **Scoring Formulas**: Deterministic precision, recall, useful hypothesis yield, and Wilson interval denominators must remain unchanged.
4. **Ground Truth Isolation Boundary**: `scen.ground_truth_vulnerable` and `scen.vulnerable_variant` must never enter the reasoning path.
5. **Scope & Safety Gates**: `ScopeGate` and `ScopedHttpClient` fail-closed guarantees, rate limits, and DNS IP pinning must not be bypassed or disabled.
6. **No Autonomous Testing**: The platform must remain strictly human-in-the-loop; no autonomous vulnerability execution or unapproved active probing.

---

## 11. Exact Recommended Phase 1

### Objective: Execute the Real-LLM Ablation Benchmark (EXP-0006)
With Phase 0 security and research hardening complete, the platform is ready for its primary scientific experiment.

### Step-by-Step Phase 1 Plan:
1. **Dataset Preparation**:
   - Load the 50 standardized synthetic benchmark scenarios across 5 distinct application families (`e-commerce`, `b2b-saas`, `fintech`, `healthcare`, `developer-tools`).
   - Validate that each scenario exposes only canonical, unprivileged evidence items.
2. **Benchmark Execution (Track A through Track E)**:
   - Run Track A (Direct LLM) across all 50 scenarios using `qwen2.5-coder:7b`.
   - Run Track B (RAG Baseline) across all 50 scenarios using `qwen2.5-coder:7b`.
   - Run Track C (Application Model Only) across all 50 scenarios using `qwen2.5-coder:7b`.
   - Run Track D (Invariant Verification Only) across all 50 scenarios using `qwen2.5-coder:7b`.
   - Run Track E (Full V6 Final Pipeline) across all 50 scenarios using `qwen2.5-coder:7b`.
3. **Deterministic Evaluation & Metric Computation**:
   - Pass all generated hypotheses through the offline deterministic scorer.
   - Compute:
     - Hypothesis Precision (with 95% Wilson confidence intervals).
     - Useful Hypothesis Yield.
     - Investigation Yield.
     - Appropriate Abstention Rate.
     - McNemar's paired test p-values comparing Track E to Tracks A, B, C, and D.
4. **Publication of EXP-0006 Results**:
   - Produce `docs/EXP-0006_RESULTS.md` with complete case-level breakdowns, statistical significance tables, and empirical conclusions regarding the research question.

---

**PHASE 0 STATUS: COMPLETE.**  
*Antigravity has stopped per instructions and is awaiting user approval before beginning Phase 1.*
