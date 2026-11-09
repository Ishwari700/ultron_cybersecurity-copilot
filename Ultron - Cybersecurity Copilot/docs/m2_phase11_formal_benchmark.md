# Milestone M2 Phase 11 Formal Paired Benchmark Report

**PHASE 11 COMPLETE — RESULTS ARE FOR THE POST-HOC BENCHMARK BASELINE.**

---

## 1. Provenance and Historical Baseline Integrity

- **Baseline Classification**: **POST-HOC BENCHMARK BASELINE** established after M2 Phases 0–10.
- **Historical Freeze Notice**: The original M1.5 freeze was **never historically established** / unrecoverable.
- **Holdout Caveat**: The hidden evaluation split **cannot be claimed as a previously sealed holdout** established prior to M2 engineering.
- **Manifest Path**: `data\benchmarks\m1_5_frozen_manifest.json`
- **Manifest SHA-256**: `b2b85a672124acf21066a257d8c7f5093000368b224ee013c02574c96a0ae707`
- **Establishment Commit SHA**: `a005c5c11ab1a4c93ef9bd7167091b868f3b4f1d`
- **Attestation Commit SHA**: `cfdc0373cd71f4f99173b0f42064076437af6607`
- **Current Git HEAD**: `cfdc0373cd71f4f99173b0f42064076437af6607`
- **Random Seed**: `42`
- **Decoding Temperature**: `0.0` (Greedy deterministic)

---

## 2. Executive Summary & Core Comparison

| Metric | Track A (7B Baseline) | Track B (3B Baseline) | Track C (3B $\to$ 7B Cascade) |
| :--- | :---: | :---: | :---: |
| **Canonical Track Label** | `TRACK_A_7B_BASELINE` | `TRACK_B_3B_BASELINE` | `TRACK_C_CASCADE` |
| **Total Scenarios (N)** | 84 | 84 | 84 |
| **7B Inference Calls** | 84 (100.0%) | 0 (0.0%) | **44 (52.4%)** |
| **7B Call Reduction** | — | — | **47.62%** (40/84) [Target >= 30%] |
| **Useful Hypothesis Yield (N=36)** | **0.0%** (0/36) | 0.0% (0/36) | **0.0%** (0/36) |
| **Yield 95% Wilson CI** | (0.0, 0.0964) | (0.0, 0.0964) | (0.0, 0.0964) |
| **Precision** | 0.0% (0/0) | 0.0% (0/0) | 0.0% (0/0) |
| **Precision 95% Wilson CI** | (0.0, 0.0) | (0.0, 0.0) | (0.0, 0.0) |
| **Recall / Sensitivity** | 0.0% (0/36) | 0.0% (0/36) | 0.0% (0/36) |
| **Recall 95% Wilson CI** | (0.0, 0.0964) | (0.0, 0.0964) | (0.0, 0.0964) |
| **F1 Score** | 0.0 | 0.0 | 0.0 |
| **Abstention Quality / TNR (N=48)** | 100.0% (48/48) | 100.0% (48/48) | 100.0% (48/48) |
| **TNR 95% Wilson CI** | (0.9259, 1.0) | (0.9259, 1.0) | (0.9259, 1.0) |
| **Decision Quality** | 57.1% (48/84) | 57.1% (48/84) | 57.1% (48/84) |
| **Average Decision Latency (TTD)** | 8.08s | 2.13s | **6.94s** |
| **Speedup Factor** | 1.00x | 3.80x | **1.16x** |
| **Peak VRAM** | 3054.0 MB | 2906.0 MB | 3030.0 MB |

---

## 3. Predeclared Statistical Non-Inferiority Testing ($N_{\text{vuln}} = 36$)

Per Section 15.3 of `docs/M1_5_M2_PLAN.md`:
- **Hypothesis Formulation**:
  $$H_0: Y_{\text{7B}} - Y_{\text{Cascade}} \ge 0.05$$
  $$H_1: Y_{\text{7B}} - Y_{\text{Cascade}} < 0.05$$
- **Predeclared Statistical Method**: Tango's score-based paired difference confidence interval method.
- **Paired Contingency Table ($N_{\text{vuln}} = 36$)**:
  - Both Useful ($n_{11}$): `0`
  - 7B Only ($n_{10}$): `0`
  - Cascade Only ($n_{01}$): `0`
  - Neither Useful ($n_{00}$): `36`
- **Observed Point Difference $\hat{\delta}$**: `0.0`
- **Predeclared 90% One-Sided Tango UCB**: `+0.038`
- **Predeclared Margin $\Delta$**: `0.050`
- **Decision Rule**: $\text{UCB}_{90\%} < 0.05$
- **Non-Inferiority Outcome**: **PASS (Non-inferiority established)**
- **McNemar Exact Binomial p-value**: `1.0`

---

## 4. Disaggregated Split & Variant Performance Matrix

### A. Development Split ($N=28$: saas_billing, ecommerce_orders)
- **Track A (7B Baseline)**: Precision=0.0% (0/0) [95% CI: (0.0, 0.0)], Recall=0.0% (0/12) [95% CI: (0.0, 0.2425)], TNR=100.0% (16/16) [95% CI: (0.8064, 1.0)], Yield=0.0% (0/12)
- **Track B (3B Baseline)**: Precision=0.0% (0/0) [95% CI: (0.0, 0.0)], Recall=0.0% (0/12) [95% CI: (0.0, 0.2425)], TNR=100.0% (16/16) [95% CI: (0.8064, 1.0)], Yield=0.0% (0/12)
- **Track C (Cascade)**: Precision=0.0% (0/0) [95% CI: (0.0, 0.0)], Recall=0.0% (0/12) [95% CI: (0.0, 0.2425)], TNR=100.0% (16/16) [95% CI: (0.8064, 1.0)], Yield=0.0% (0/12)

### B. Validation Split ($N=28$: identity_provider, document_collaboration)
- **Track A (7B Baseline)**: Precision=0.0% (0/0) [95% CI: (0.0, 0.0)], Recall=0.0% (0/12) [95% CI: (0.0, 0.2425)], TNR=100.0% (16/16) [95% CI: (0.8064, 1.0)], Yield=0.0% (0/12)
- **Track B (3B Baseline)**: Precision=0.0% (0/0) [95% CI: (0.0, 0.0)], Recall=0.0% (0/12) [95% CI: (0.0, 0.2425)], TNR=100.0% (16/16) [95% CI: (0.8064, 1.0)], Yield=0.0% (0/12)
- **Track C (Cascade)**: Precision=0.0% (0/0) [95% CI: (0.0, 0.0)], Recall=0.0% (0/12) [95% CI: (0.0, 0.2425)], TNR=100.0% (16/16) [95% CI: (0.8064, 1.0)], Yield=0.0% (0/12)

### C. Out-of-Sample Hidden Evaluation Split ($N=28$: healthcare_portal, iot_fleet_mgmt)
*(Reported separately per Section 15.1; post-hoc baseline qualification applies)*
- **Track A (7B Baseline)**: Precision=0.0% (0/0) [95% CI: (0.0, 0.0)], Recall=0.0% (0/12) [95% CI: (0.0, 0.2425)], TNR=100.0% (16/16) [95% CI: (0.8064, 1.0)], Yield=0.0% (0/12)
- **Track B (3B Baseline)**: Precision=0.0% (0/0) [95% CI: (0.0, 0.0)], Recall=0.0% (0/12) [95% CI: (0.0, 0.2425)], TNR=100.0% (16/16) [95% CI: (0.8064, 1.0)], Yield=0.0% (0/12)
- **Track C (Cascade)**: Precision=0.0% (0/0) [95% CI: (0.0, 0.0)], Recall=0.0% (0/12) [95% CI: (0.0, 0.2425)], TNR=100.0% (16/16) [95% CI: (0.8064, 1.0)], Yield=0.0% (0/12)

### D. Variant Composition Slices

| Population Slice | Track A (7B) Yield / Accuracy | Track B (3B) Yield / Accuracy | Track C (Cascade) Yield / Accuracy |
| :--- | :---: | :---: | :---: |
| **Vulnerable-Only Population ($N=36$)** | 0.0% (0/36) [CI: (0.0, 0.0964)] | 0.0% (0/36) [CI: (0.0, 0.0964)] | 0.0% (0/36) [CI: (0.0, 0.0964)] |
| **Matched Patched Population ($N=36$)** | TNR=100.0% (36/36) [CI: (0.9036, 1.0)] | TNR=100.0% (36/36) [CI: (0.9036, 1.0)] | TNR=100.0% (36/36) [CI: (0.9036, 1.0)] |
| **Negative Controls ($N=12$)** | TNR=100.0% (12/12) [CI: (0.7575, 1.0)] | TNR=100.0% (12/12) [CI: (0.7575, 1.0)] | TNR=100.0% (12/12) [CI: (0.7575, 1.0)] |

---

## 5. Security & Epistemic Boundary Audit

| Boundary Dimension | Track A (7B) | Track B (3B) | Track C (Cascade) |
| :--- | :---: | :---: | :---: |
| **Prompt Injection Attempts Encountered** | 0 (0/84) | 0 (0/84) | 0 (0/84) |
| **Boundary-Break Failures** | 0 (0/84) | 0 (0/84) | 0 (0/84) |
| **Unauthorized Instruction Adoption** | 0 (0/84) | 0 (0/84) | 0 (0/84) |
| **Schema / Policy Alteration Attempts** | 0 (0/84) | 0 (0/84) | 0 (0/84) |
| **Unregistered ID Introduction Attempts** | 0 (0/84) | 0 (0/84) | 0 (0/84) |
| **Epistemic-Status Override Attempts** | 0 (0/84) | 0 (0/84) | 0 (0/84) |
| **Forbidden CONFIRMED Emissions** | 0 (0/84) | 0 (0/84) | 0 (0/84) |
| **Grounding Rejections** | 0 (0/84) | 0 (0/84) | 0 (0/84) |
| **CRITICAL_EPISTEMIC_FAILURE Count** | 0 (0/84) | 0 (0/84) | 0 (0/84) |

---

## 6. Track C Operational & Health Diagnostics (SLO Audit)

- **N Entering 3B Triage**: 84
- **N Successfully Triaged by 3B**: 84
- **N 3B Failures**: 0 / 84
  - Parser Failures: `0`
  - Model Unresponsiveness: `0`
  - Timeouts (>15.0s): `0`
  - Out of Memory (OOM): `0`
  - Infrastructure Connection Refusals: `0`
- **3B Failure Rate**: **0.00%** (0/84)
  - Operational SLO Threshold: <= 5.0%
  - Diagnostic Warning Threshold: > 2.0%
  - SLO Evaluation Status: **PASS (Nominal, 0.00% <= 2.0%)**
- **N Gate Fail-Safe Cases**: 8 (All passed to 7B MUST-ESCALATE path)
- **N Ordinary Escalations**: 36
- **N Not Escalated (3B-Resolved Benign, 0 7B Calls)**: 40
- **N Reaching 7B Reasoning**: 44
- **N 7B Hardware Timeouts (>30.0s)**: 0
- **N 7B Execution Failures**: 0
- **N Valid Final Hypotheses**: 0
- **Dual-Model Residency Observed**: **FALSE** (Strict Mode 1 sequential decoupling enforced)
- **Quiescent VRAM Reclaimed**: 612.0 MB
