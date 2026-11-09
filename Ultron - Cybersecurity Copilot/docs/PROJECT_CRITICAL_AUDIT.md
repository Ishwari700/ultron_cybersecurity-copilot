# Project Critical Audit

**Audit date:** 2026-09-22  
**Scope:** Full tracked repository, source, tests, configuration, documentation, benchmark/evaluation artifacts, and data manifests.  
**Method:** Static inspection plus the test suite executed from the repository root with `pytest -q -p no:cacheprovider tests`. No project files other than this report were intentionally modified.

## Executive assessment

The project has substantial defensive structure and unusually explicit provenance/evaluation goals, but several claimed invariants are not enforced at the actual execution boundary. The most serious issue is that the headless simulator sends a redacted authorization marker while the synthetic application only authenticates real token values. This makes protected simulator experiments return unauthenticated responses and invalidates any benchmark conclusions derived from those outcomes. The execution engine also treats missing credential references as non-blocking, and the dashboard can expose untrusted hypothesis content as executable browser HTML.

The documentation and artifact metadata frequently describe stronger guarantees than the implementation proves. Cryptographic hashes provide tamper evidence for selected bytes, but the artifact seal contains self-authored boolean attestations and is not itself signed. The test status document is stale: the repository currently collects 757 tests, not 126, and the full root run produced 740 passes, 2 failures, 4 errors, and 11 skips when Ollama was unavailable.

## Findings

### 1. Simulator authentication is incompatible with the synthetic application

**Severity:** CRITICAL  
**Confidence:** 10/10  
**References:** `src/eval/simulator.py:39-80`; `src/eval/synthetic_app.py:75-91`; `tests/unit/test_simulator.py:14-28`

`HeadlessSimulator` deliberately places `"Authorization": "******"` in requests. `SyntheticApp` authenticates only when a real `token_a`, `token_b`, or `token_admin` substring is present. Therefore protected requests do not identify a caller and return HTTP 401 before the vulnerable/patched authorization branches execute. The unit test claims the same redacted header produces 200/403, but a direct invocation of the implementation returned `(401, {"error": "Authentication required"})`. Any closed-loop result classified from these simulator responses is not evidence about BOLA, BFLA, state skipping, or tenant authorization.

### 2. Missing credential references are explicitly allowed to continue

**Severity:** CRITICAL  
**Confidence:** 10/10  
**References:** `src/execution/engine.py:249-267`; `src/execution/engine.py:437-461`

Credential ownership validation rejects cross-identity, cross-target, and cross-environment substitutions, but the engine ignores `TOKEN_REFERENCE_NOT_FOUND` and proceeds. The same condition is repeated immediately before dispatch. A proposal can therefore reach the outbound execution path without a resolvable credential reference. The fallback inserts the literal `"******"` as an Authorization header rather than failing closed. This violates the stated “no execution without validated authorization state” boundary.

### 3. External dashboard binding has no authentication, and the UI has stored-XSS exposure

**Severity:** HIGH  
**Confidence:** 9/10  
**References:** `src/dashboard/app.py:20-42`; `src/dashboard/app.py:200-201`; `src/dashboard/app.py:249-250`

The application intentionally permits `allow_external=True` while providing no authentication or authorization. The warning is only a log message; it does not prevent exposure of hypotheses, evidence references, audit records, or state-changing review endpoints. Separately, database-controlled fields such as `category`, `state`, `asset_id`, and `reasoning_summary` are interpolated into a JavaScript template and assigned to `innerHTML` without escaping. Untrusted evidence or model output stored in a hypothesis can execute script in any browser opening the dashboard. Loopback-by-default reduces remote exposure but does not remove the XSS or the risk from an explicit external bind.

### 4. The “artifact seal” records unverified attestations and has no signature

**Severity:** HIGH  
**Confidence:** 10/10  
**References:** `src/eval/artifact_seal.py:116-145`; `data/eval/m3_artifact_manifest.json:1-20`

`build_m3_artifact_seal` writes claims such as `causal_parity_enforced`, `zero_execution_authority`, and `offline_local_boundary` as hard-coded `True`/string values. It does not recompute those properties or verify them against code. The manifest digest is only a SHA-256 over the manifest payload and is written into that same file; it is not signed and there is no verifier shown that authenticates the producer. Anyone who can rewrite the manifest can rewrite both the attestation and digest. This is integrity checking of a self-authored statement, not independent proof of the architectural invariant.

### 5. Published evaluation artifacts mix “live LLM” claims with deterministic simulator data

**Severity:** HIGH  
**Confidence:** 9/10  
**References:** `EXPERIMENT_LOG.md:256-305`; `data/eval/m3_benchmark_rerun_20260920.json:1-12`; `src/eval/ablation.py:329-330`; `src/eval/ablation.py:503-509`

The experiment log labels EXP-0006 as a real local-LLM full ablation, while the repository contains deterministic hermetic benchmark artifacts and the ablation code always constructs `SyntheticApp(..., vulnerable_variant=scen.vulnerable_variant)` for Track E. Results are subsequently attached to records containing `ground_truth_vulnerable`. The project does document some earlier offline runs, but the naming and final-artifact boundary do not make it possible to distinguish model-generated decisions from simulator-generated outcomes without manually tracing each run. This creates a material risk of overstating live-model evidence and causal conclusions.

### 6. The reversible secret vault is process-local and has unrestricted reversal

**Severity:** HIGH  
**Confidence:** 9/10  
**References:** `src/evidence/vault.py:46-60`; `src/evidence/vault.py:184-194`; `config/default_config.yaml:43-45`

The configured `data/vault.enc` path is not used by `RedactionVault`; raw secrets remain in ordinary in-memory dictionaries. Any code holding the vault object can call `reverse_placeholder` or `reverse_text` without an authorization check, actor binding, audit event, or purpose limitation. Process restart loses mappings, while a memory disclosure exposes the complete raw-to-placeholder map. This contradicts the documented persistent “secret vault” and “authorized human verification” boundary and makes recovery/reproducibility of redacted evidence unreliable.

### 7. Redirect validation can be bypassed when an external HTTPX client is supplied

**Severity:** HIGH  
**Confidence:** 8/10  
**References:** `src/scope/client.py:48-99`; `src/scope/client.py:159-166`

The internally created client is configured with `follow_redirects=False`, but an injected external client is used unchanged. If that client was created with `follow_redirects=True`, HTTPX can follow redirects internally before `ScopedHttpClient` sees the response, bypassing the per-hop `ScopeGate.evaluate` loop. The class API accepts such a client without validating its redirect policy, so the documented “every redirect hop is independently re-evaluated” invariant depends on an unverified caller configuration.

### 8. Rate limiting is only per client instance, not per target/policy

**Severity:** MEDIUM  
**Confidence:** 8/10  
**References:** `src/scope/client.py:61-75`

The lock and last-request timestamp live on one `ScopedHttpClient`. Multiple client instances, workers, or processes can each send at the configured `rate_limit_rps`, multiplying traffic against the target. The scope policy is a program-level rule, but enforcement is object-local and has no shared limiter or database-backed lease. This is especially risky because the project describes the rate limit as rules-of-engagement enforcement.

### 9. Audit logs are hash-marked records, not an immutable or tamper-evident chain

**Severity:** MEDIUM  
**Confidence:** 8/10  
**References:** `src/core/logging.py:28-75`

Each record hashes only its own `details` payload. There is no previous-record hash, trusted append-only storage, file permissions hardening, signature, rotation integrity, or verification routine. An attacker who can edit, delete, reorder, or replace lines can produce a syntactically valid log; changing top-level fields such as actor, event type, timestamp, or subject does not invalidate `payload_hash`. The “immutable audit logging” description is therefore stronger than the implemented property.

### 10. Poisoning telemetry logs hostile content and does not quarantine it

**Severity:** MEDIUM  
**Confidence:** 8/10  
**References:** `src/knowledge/poisoning_defense.py:79-101`; `src/knowledge/poisoning_defense.py:105-127`

Injection matches, including `matched_text`, are written to logs verbatim. If the advisory contains secrets, personal data, or a long malicious payload, the telemetry log becomes another disclosure and log-injection surface. `sanitize_pack_for_serialization` escapes markup but preserves the content and only logs detections; it does not enforce the module/document quarantine described by the ingestion documentation. Detection is not isolation.

### 11. Human verification is not an atomic transaction and actor identity is unauthenticated

**Severity:** MEDIUM  
**Confidence:** 8/10  
**References:** `src/hypothesis/state_machine.py:118-141`; `src/dashboard/app.py:45-59`; `src/database/manager.py:331-359`

Confirmation records a verification using one database connection and then updates the hypothesis using another. A crash between those operations leaves a durable “confirmed” verification without the corresponding state transition, or permits repeated/conflicting records. The dashboard accepts arbitrary client-supplied `actor` and `dashboard_session_id` values; the latter is explicitly not a credential. The database trigger proves that a row exists, not that the actor was authenticated or that the verification and transition were committed atomically.

### 12. State transition enforcement is incomplete outside the state machine

**Severity:** MEDIUM  
**Confidence:** 8/10  
**References:** `src/database/manager.py:300-329`; `src/database/schema.sql:111-145`

`update_hypothesis_state` accepts any state string and the database triggers constrain only evidence/verification for `Confirmed` and the previous state for `Reported`. There are no database rules for `New -> Under Review`, review ownership, rejection/revision consistency, or prevention of direct transitions to `Confirmed` through a pre-created verification row. Any caller with database access can bypass the Python state machine while still satisfying the narrow triggers.

### 13. Test-status and current test behavior are materially out of date

**Severity:** MEDIUM  
**Confidence:** 10/10  
**References:** `TEST_STATUS.md:3-15`; `tests/` (90 Python test files); `pyproject.toml:19-25`

The status document reports 126 collected tests, but the current repository collects 757. Running from the project root with cache writes disabled produced **740 passed, 2 failed, 4 errors, 11 skipped, and 2 warnings**. The failures/errors include live cascade tests and live pipeline tests because Ollama was unavailable. This does not mean every failure is a product defect—some tests intentionally require the daemon—but the published “zero failures / 126 tests” status is not a current reproducible baseline and can mislead reviewers about validation coverage.

### 14. Token budgeting uses a fixed character heuristic rather than the active model tokenizer

**Severity:** LOW  
**Confidence:** 8/10  
**References:** `src/retrieval/budget.py:12-20`; `src/engine/runner.py:224-233`

Evidence fit is estimated with `len(text) / 3.5`, while the actual Qwen/Ollama tokenizer is never consulted. JSON escaping, Unicode, code, and structured schema overhead can change token counts substantially. The resulting “strict token budget” is only an approximation and can overflow the configured context or crop required evidence unexpectedly, undermining reproducibility across models and languages.

## Positive controls observed

The repository does contain useful controls: parameterized SQLite queries, YAML safe loading, explicit scope decisions, IP-range checks, redirect-loop handling for internally created clients, schema-constrained model output, explicit epistemic enums, ground-truth scrubbing from `ObservableScenarioContext`, and extensive negative-control tests. These controls reduce risk but do not address the findings above where the actual boundary is bypassed or the test oracle is inconsistent with runtime behavior.

## Validation record

- **Tracked files inventoried:** 496
- **Python source files inspected:** 128
- **Python test files inspected:** 90
- **Data/evaluation artifacts:** 211 files present under `data/`
- **Test command:** `.\.venv\Scripts\pytest.exe -q -p no:cacheprovider tests` from repository root
- **Observed result:** 740 passed, 2 failed, 4 errors, 11 skipped, 2 warnings
- **Project modifications:** No source, test, configuration, benchmark, data, or Git-history files modified. This report is the only created project file.

AUDIT COMPLETE

**Report path:** `PROJECT_CRITICAL_AUDIT.md`  
**Total findings:** 14  
**CRITICAL:** 2  
**HIGH:** 5  
**MEDIUM:** 6  
**LOW:** 1  
**INFO:** 0  
**Files inspected:** 496 tracked files inventoried; 128 Python source files and 90 Python test files inspected directly or through targeted searches; documentation, configuration, and evaluation artifacts cross-referenced.  
**Tests inspected:** 757 collected; full repository run recorded above.  
**Project files modified:** No, except creation of `PROJECT_CRITICAL_AUDIT.md`.
