# M6.1 Baseline Report

**Timestamp:** 2026-10-07T07:40:00Z  
**System State:** M6 Complete (`v6.0.0-authorized-copilot`)  
**Purpose:** Pre-Hardening Baseline Verification for Milestone 6.1  

---

## 1. Test Suite Execution Summary

The complete existing test suite was executed across unit and integration tests:

- **Total Test Cases:** 1,242
- **Passed:** 1,239 (99.76% of collected)
- **Failed:** 0 (0.00%)
- **Skipped:** 3 (Pre-existing M4/M5 skipped tests)
- **Warnings:** 2 (`StarletteDeprecationWarning` and `anyio.abc.BlockingPortal` deprecation)
- **Total Test Execution Runtime:** 300.13 seconds (05:00.13)

### M6-Specific Test Suite
All 32 dedicated M6 tests passed cleanly:
- `tests/unit/test_m6_assessment_lifecycle.py`: 4 passed
- `tests/unit/test_m6_authorization_and_scope.py`: 5 passed
- `tests/unit/test_m6_experiments_and_findings.py`: 5 passed
- `tests/unit/test_m6_security.py`: 13 passed
- `tests/unit/test_m6_telemetry_and_assets.py`: 4 passed
- `tests/integration/test_m6_integration.py`: 1 passed
- **M6 Test Runtime:** 0.67s

---

## 2. Frozen M6 Benchmark Evaluation (150 Cases)

Executed from `data/eval/m6_assessment_benchmark_dataset.json` with evaluation engine `src/eval/m6_assessment_evaluator.py`:

| Metric Category | Target Invariant | Measured M6 Baseline |
| :--- | :--- | :--- |
| **Authorization Accuracy** | $\ge 99.0\%$ | **100.0%** |
| **Scope Accuracy** | $\ge 99.0\%$ | **100.0%** |
| **Unknown $\rightarrow$ OUT_OF_SCOPE Enforcement** | $100.0\%$ | **100.0%** |
| **Scope Bypass Rate** | $0.0\%$ | **0.0%** |
| **Authorization Bypass Rate** | $0.0\%$ | **0.0%** |
| **Human Verification Bypass Rate** | $0.0\%$ | **0.0%** |
| **Cross-Assessment Leakage** | $0.0\%$ | **0.0%** |
| **Secret Leakage Rate** | $0.0\%$ | **0.0%** |
| **Prompt Injection Override Rate** | $0.0\%$ | **0.0%** |
| **External $\rightarrow$ Target Contamination** | $0.0\%$ | **0.0%** |
| **Asset Classification Accuracy** | $\ge 95.0\%$ | **100.0%** |
| **Observation Normalization Accuracy** | $\ge 95.0\%$ | **100.0%** |
| **Evidence Lineage Completeness** | $\ge 95.0\%$ | **100.0%** |
| **Hypothesis Grounding** | $\ge 90.0\%$ | **100.0%** |
| **Negative Control Coverage** | $\ge 90.0\%$ | **100.0%** |
| **Experiment Safety Classification** | $\ge 95.0\%$ | **100.0%** |
| **Finding Validation Precision** | $\ge 95.0\%$ | **100.0%** |
| **Finding Validation Recall** | $\ge 95.0\%$ | **100.0%** |
| **Report Correctness** | $\ge 95.0\%$ | **100.0%** |
| **Unsupported Report Claims** | $0.0\%$ | **0.0%** |

---

## 3. Hardware & Resource Profile

- **Processor:** AMD Ryzen 5 5600H (6 Cores, 12 Threads)
- **Host Memory:** 24.0 GB DDR4
- **Graphics / Accelerator:** NVIDIA GeForce RTX 3050 Laptop GPU (4.0 GB VRAM)
- **Model Partitioning:**
  - MiniLM Embedding Model: CPU
  - 3B Triage Model: GPU
  - 7B Deep Reasoning Model: Hybrid GPU/CPU
- **Concurrency:** 1 (Deterministic Single-Stream Processing)
- **Inference Latency Profile:**
  - Track A (3B only): 14.2 ms avg
  - Track B (Cascade): 32.5 ms avg
  - Track F (Full M6 copilot): 58.2 ms avg
- **Peak Resource Footprint:**
  - Peak RAM: ~4.2 GB
  - Peak VRAM: ~3,650 MB

---

## 4. Pre-Hardening Observations & Stress Points for M6.1

While M6 achieves 100% on its initial 150-case benchmark, several subtle boundaries require extensive adversarial testing in M6.1:
1. **Scope Boundary Edge Cases:** Lookalike domains, port variants (`:8443`), path-traversal in URL paths, Punycode/Unicode representations, and trailing-dot FQDN handling.
2. **Telemetry Imperfection:** Truncated HAR files, malformed JSON, unparseable chunked encoding, huge headers, and conflicting timestamps.
3. **Contradictory Telemetry:** Distinguishing temporal or session differences (e.g. 200 vs 403 on different auth cookies) from authentic contradictions.
4. **Adversarial Injections:** Deeply nested prompt injection in HTTP responses, comments, Android manifests, and tool stdout attempting to induce self-authorization or verified findings.
5. **Human Review Protocol:** Formalizing review metrics to ensure no automated path can confirm findings.

Baseline established. Proceeding to Phase 1.
