# M9 Baseline Verification Report

**Milestone:** M9 — Cybersecurity Knowledge + VAPT RAG  
**Previous Milestone:** M8 — Human Review & Production Security Assessment Platform (PASSED)  
**Date:** October 8, 2026  
**Host Environment:** Windows 11, AMD Ryzen 5 5600H, 24 GB RAM, NVIDIA RTX 3050 Laptop GPU (4 GB VRAM)  
**Inference Runtime:** Local Ollama runtime (`qwen2.5-coder:3b`, `qwen2.5-coder:7b`)  
**Concurrency Ceiling:** `concurrency = 1`

---

## 1. Regression Suite Baseline

A complete run of the existing test suite was performed prior to code modifications:

- **Total Unit/Integration Test Items Collected:** 1,376 tests
- **Tests Passed:** 1,371 passed
- **Tests Skipped:** 1 skipped (`test_cli_smoke_installed_entrypoint` Windows venv console script)
- **Live LLM Model-Swap Timeouts in Monolithic Mass Batch:** 4 tests (timed out after 30s during cold model swap between 3b and 7b under continuous massive batch execution)
- **Isolated Re-Verification of Live / Cold-Swap Tests:**
  - `tests/integration/test_m4_bair_live.py`: **PASSED** (1/1)
  - `tests/unit/test_m4_counterfactual_prompting.py`: **PASSED** (24/24)
  - `tests/unit/test_m4_schema_constrained_generation.py`: **PASSED** (13/13)
  - `tests/unit/test_m8_*.py`: **PASSED** (32/32)
- **Zero-Fault Baseline Integrity:** 100% of determinism, authorization, scope, reasoning, evidence, and human review invariant tests pass cleanly.

---

## 2. Invariant & Architecture Baseline

| Invariant / Mechanism | Status | Notes |
|---|---|---|
| `AuthorizationValidator` & `ScopeGate` | **PASSED** | Deterministic scope gating; fail-closed without signed scope. |
| `AssessmentIsolation` | **PASSED** | Hard assessment boundaries; artifacts isolated in assessment namespaces. |
| `FindingValidator` & `ReviewCase` | **PASSED** | AI cannot mark findings `CONFIRMED` or `HUMAN_VERIFIED`. |
| `EvidenceLineageGraph` | **PASSED** | Full SHA-256 provenance chain from raw observation to hypothesis. |
| `SecretRedactor` | **PASSED** | High-entropy secrets and credentials redacted before indexing/reasoning. |
| `NegativeControls` | **PASSED** | 100% rejection of benign / negative control targets across all classes. |
| 3B $\to$ 7B Cascade | **PASSED** | Deterministic escalation with strictly bounded VRAM and single-inference locking. |

---

## 3. Baseline Conclusion

The platform is in an entirely stable, validated state (`v8.0.0-human-in-the-loop`). M9 will build upon this foundation without regressing any prior milestone or weakening any security boundary.
