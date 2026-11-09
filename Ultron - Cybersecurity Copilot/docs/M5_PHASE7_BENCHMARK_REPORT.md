# M5 Phase 7 — Confirmatory Benchmark Report

**Status**: `M5_PHASE7_COMPLETE`  
**Date**: 2026-09-21  
**Execution Runtime**: Ollama v0.34.1  
**Model**: `qwen2.5-coder:7b` (`Q4_K_M`)  
**Model Digest**: `dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364`  
**Primary Artifact**: [`data/eval/m5_phase7_benchmark_final.json`](data/eval/m5_phase7_benchmark_final.json)  
**Artifact SHA-256**: `1e0ed90c4aa672f135d2d2f2240a14d22fa0037c03efda33634f4bf10ff0b125`  
**Companion SHA File**: [`data/eval/m5_phase7_benchmark_final.json.sha256`](data/eval/m5_phase7_benchmark_final.json.sha256)  
**Git Base Commit**: `dda396dfa7df220494d221768dcd4ada074bfc91`  

---

## 1. Executive Summary

Milestone M5 Phase 7 executed the first formally authorized confirmatory benchmark of the corrected M5 reasoning architecture across all 84 frozen benchmark scenarios and 4 experimental tracks ($84 \times 4 = 336$ scheduled and completed live LLM calls).

This benchmark directly tests the central project research question:
> *“Under a fixed evidence budget, does an explicit Application Model → Security Invariant → Evidence Gap → Hypothesis → Experiment architecture improve security-hypothesis precision, abstention quality, and human investigation efficiency compared to conventional LLM + RAG?”*

Under the frozen Policy 3 governance design ([`docs/M5_PHASE6_8_HYPOTHESIS_GOVERNANCE_DECISION.md`](docs/M5_PHASE6_8_HYPOTHESIS_GOVERNANCE_DECISION.md)), the primary research estimand is strictly preserved as:
$$\text{Useful Hypothesis Yield @ } N \text{ reviewer minutes} = \frac{\text{Useful Vulnerability Hypotheses}}{\text{Total Vulnerable Scenarios}}$$

### Key Empirical Findings:

1. **Complete Elimination of the M4.9 Composition Defect ($0 / 336$ Parser Failures)**:
   - In M4.9, an uncoordinated composition failure caused $336 / 336$ (100.00%) syntactic parser failures due to an instruction/schema divergence.
   - In M5 Phase 7, the 6-layer protocol agreement (`Prompt Instructions == Runtime Schema == Extractor == Parser == Validator == Adapter`) achieved **$0 / 336$ (0.00%) parser failures**.
   - Exactly **$224 / 336$ (66.67%)** of all executions completed as fully **`VALID`** across parsing, schema validation, semantic polarity validation, and deterministic decision policy.

2. **Primary Frozen Research Estimand: 0.0000**:
   - $\text{Useful Hypothesis Yield @ } N \text{ reviewer minutes} = 0.0000$ ($0 / 144$ vulnerable instances across the 4 tracks, $0 / 36$ per track).
   - Zero vulnerability hypotheses were yielded because none of the candidate hypotheses satisfied the strict, closed semantic polarity compatibility rules.

3. **Deterministic Interception of Semantic Inversions ($94 / 104$ Candidate Hypotheses)**:
   - In 104 calls, the model attempted to propose a `HYPOTHESIS`.
   - In **94 of these 104 attempts (90.38%)**, the candidate was deterministically intercepted and failed closed by [`ExperimentPolarityValidator`](src/engine/decision_policy.py) as `SEMANTIC_EXPERIMENT_POLARITY_FAILURE`.
   - The model frequently paired incompatible actions with categories (e.g. `TAMPER_REQUEST_PARAMETER` for state machine logic) or inverted breach outcomes (e.g. claiming `HTTP_403_FORBIDDEN` confirms BOLA or `HTTP_409_CONFLICT` confirms state transitions).
   - The remaining 10 candidate hypotheses were rejected by root Pydantic schema validation (`SCHEMA_VALIDITY_FAILURE`) due to identical supporting and disproving outcomes.
   - Result: **Zero inverted or non-discriminative pseudo-hypotheses leaked into reviewer triage.**

4. **Vulnerable vs. Patched Candidate Parity ($51.0\%$ vs $49.0\%$)**:
   - Among the 104 candidate hypothesis attempts, 53 occurred on vulnerable variants and 51 occurred on patched controls.
   - Under neutral OpenAPI documentation without observed runtime anomaly flags, the local 7B parameter model attempts hypotheses at a rate statistically indistinguishable from a random 50/50 coin flip ($p > 0.85$).
   - The deterministic policy and polarity validator successfully intercepted all 51 would-be false positives and all 53 ungrounded/inverted claims.

5. **Causal Impact of VAPT Knowledge RAG on Calibrated Abstention**:
   - In Track A (No RAG) and Track B (Target RAG only), the model attempted candidate hypotheses in 41 and 42 scenarios respectively, with a validity rate of only $51.19\%$ (43/84).
   - In Track C (VAPT RAG) and Track D (Target + VAPT RAG), when security testing methodology was injected, candidate hypothesis attempts dropped by ~74% (to 11 attempts each), while valid calibrated abstentions (`INSUFFICIENT_EVIDENCE`) surged from 31 to 58 (Track C) and 56 (Track D).
   - Validity rate rose from **$51.19\%$ (Tracks A/B) to $83.33\%$ (Track C) and $80.95\%$ (Track D)**.

6. **Reviewer Triage Safety**:
   - Under Policy 3 presentation mapping, $224 / 336$ ($66.67\%$) executions were classified as `ABSTENTION_CONFIRMED` and $112 / 336$ ($33.33\%$) as `INVALID_PROPOSAL`.
   - **Zero invalid or ungrounded findings were presented to the simulated reviewer** as actionable vulnerability findings.

---

## 2. Frozen Compute Envelope & Preflight Verification

The benchmark ran strictly within the authorized execution configuration:

| Parameter | Pinned Specification | Actual Execution Verification | Status |
| :--- | :--- | :--- | :--- |
| **Model** | `qwen2.5-coder:7b` (`Q4_K_M`) | `qwen2.5-coder:7b` | **VERIFIED** |
| **Model Digest** | `dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364` | `dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364` | **MATCH (EXACT)** |
| **Runtime Version** | Ollama v0.34.1 | Ollama v0.34.1 | **MATCH (EXACT)** |
| **Context Length (`num_ctx`)** | 2048 | 2048 | **VERIFIED** |
| **Prediction Budget (`num_predict`)** | 300 | 300 | **VERIFIED** |
| **Temperature** | 0.0 | 0.0 | **VERIFIED** |
| **Seed** | 42 | 42 | **VERIFIED** |
| **Keep-Alive** | 60m | 60m | **VERIFIED** |
| **Network Egress** | Local-only (`http://127.0.0.1:11434`) | Verified 0 external HTTP egress | **VERIFIED** |
| **Single-Call Policy** | Exactly 1 call per scenario/track | 336 total calls, 0 retries, 0 repairs | **VERIFIED** |
| **Preflight Gates** | All 15 Gates passed prior to call #1 | All 15 Gates verified by `verify_m5_phase7_preflight.py` | **PASSED** |

---

## 3. Confirmatory Benchmark Execution Matrix

### Call Allocation:
$$\text{Total Calls} = 84 \text{ scenarios} \times 4 \text{ tracks} = 336 \text{ live LLM calls}$$
- **Track A** (No Target RAG, No VAPT RAG): 84 calls
- **Track B** (Target RAG enabled, No VAPT RAG): 84 calls
- **Track C** (No Target RAG, VAPT RAG enabled): 84 calls
- **Track D** (Target RAG enabled, VAPT RAG enabled): 84 calls

### Scenario Distribution:
- **Total Scenarios**: 84
- **Vulnerable Variants**: 36
- **Non-Vulnerable Controls**: 48 (12 negative controls + 36 patched variants)
- **Application Domains**: 6 (SaaS Billing, E-Commerce Orders, Identity Provider, Document Collaboration, Healthcare Portal, IoT Fleet Management) $\times$ 14 scenarios each.

---

## 4. Mutually Exclusive Primary Failure Taxonomy ($N=336$)

Every execution terminates in exactly one mutually exclusive taxonomic category:

| Primary Failure Category | Count | Percentage | Description |
| :--- | :---: | :---: | :--- |
| **`VALID`** | **224** | **66.67%** | Execution successfully parsed, validated schema, passed polarity checks, and applied decision policy. |
| **`SEMANTIC_EXPERIMENT_POLARITY_FAILURE`** | **94** | **27.98%** | Candidate `HYPOTHESIS` rejected by `ExperimentPolarityValidator` due to inverted outcomes or incompatible actions. |
| **`SCHEMA_VALIDITY_FAILURE`** | **10** | **2.98%** | Pydantic schema rejection (identical supporting and disproving outcomes). |
| **`MAX_TOKEN_TRUNCATION`** | **8** | **2.38%** | Output reached the 300 token ceiling mid-generation (`eval_count == 300`). |
| **`PARSER_FAILURE`** | **0** | **0.00%** | Zero raw output parsing or JSON syntax errors. |
| **`SEMANTIC_GROUNDING_FAILURE`** | **0** | **0.00%** | Zero cross-namespace citation violations (`FACT` vs `CHK`). |
| **`RUNTIME_TRANSPORT_FAILURE`** | **0** | **0.00%** | Zero HTTP or Ollama transport errors. |
| **Total** | **336** | **100.00%** | |

---

## 5. Cross-Track Comparison (Tracks A, B, C, D)

| Metric | Track A (Baseline) | Track B (Target RAG) | Track C (VAPT RAG) | Track D (Combined) | Overall ($N=336$) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Total Scheduled Calls** | 84 | 84 | 84 | 84 | 336 |
| **Completed Calls** | 84 | 84 | 84 | 84 | 336 |
| **Valid Executions** | 43 (51.19%) | 43 (51.19%) | 70 (83.33%) | 68 (80.95%) | 224 (66.67%) |
| **Polarity Failures** | 41 (48.81%) | 31 (36.90%) | 11 (13.10%) | 11 (13.10%) | 94 (27.98%) |
| **Schema Failures** | 0 (0.00%) | 10 (11.90%) | 0 (0.00%) | 0 (0.00%) | 10 (2.98%) |
| **Truncation Failures** | 0 (0.00%) | 0 (0.00%) | 3 (3.57%) | 5 (5.95%) | 8 (2.38%) |
| **Parser Failures** | 0 (0.00%) | 0 (0.00%) | 0 (0.00%) | 0 (0.00%) | 0 (0.00%) |
| **Final Decision: `INSUFFICIENT_EVIDENCE`** | 31 (36.90%) | 31 (36.90%) | 58 (69.05%) | 56 (66.67%) | 176 (52.38%) |
| **Final Decision: `NO_RELEVANT_FUNCTIONALITY`** | 12 (14.29%) | 12 (14.29%) | 12 (14.29%) | 12 (14.29%) | 48 (14.29%) |
| **Final Decision: `HYPOTHESIS`** | 0 (0.00%) | 0 (0.00%) | 0 (0.00%) | 0 (0.00%) | 0 (0.00%) |
| **Final Decision: `None` (Failed Validation)** | 41 (48.81%) | 41 (48.81%) | 14 (16.67%) | 16 (19.05%) | 112 (33.33%) |
| **Causal Parity Matches (Target B == D)** | — | 84 / 84 (100%) | — | 84 / 84 (100%) | 84 / 84 (100%) |
| **Mean Latency (ms)** | 21,696.8 | 23,321.4 | 27,572.9 | 28,766.5 | 25,339.4 |
| **Median Latency (ms)** | 22,614.3 | 24,340.2 | 28,094.2 | 28,197.1 | 25,723.6 |

---

## 6. Policy 3 Evaluation Governance Metrics

### 6.1 Primary Frozen Estimand
$$\mathbf{\text{Useful Hypothesis Yield @ } N \text{ reviewer minutes} = 0.0000} \quad \left(0 / 144 \text{ vulnerable instances}\right)$$

### 6.2 Secondary Decomposed Metrics
- **Vulnerability-Hypothesis Yield**: Undefined / N/A (0 scenarios presented canonical observed anomaly flags in baseline evidence).
- **Exploratory Verification Validity Rate**: $0.0000$ ($0 / 200$ exploratory-applicable scenarios produced a fully valid, discriminative exploratory proposal).
- **Polarity Compatibility Rate**: $0.0000$ ($0 / 104$ candidate hypotheses conformed to the closed polarity taxonomy without inversion or incompatibility).
- **Grounding Rate**: $0.0000$ ($0$ hypotheses passed downstream to grounding evaluation).

### 6.3 Diagnostic Metrics
- **Parser Failure Rate**: $0.0000$ ($0 / 336$)
- **Schema Failure Rate**: $0.0298$ ($10 / 336$)
- **Semantic Polarity Failure Rate**: $0.2798$ ($94 / 336$)
- **Truncation Rate**: $0.0238$ ($8 / 336$)
- **Runtime Transport Failure Rate**: $0.0000$ ($0 / 336$)
- **Abstention Rate (among valid executions)**: $100.00\%$ ($224 / 224$)
  - `INSUFFICIENT_EVIDENCE`: $176 / 224$ ($78.57\%$)
  - `NO_RELEVANT_FUNCTIONALITY`: $48 / 224$ ($21.43\%$)

### 6.4 Applicability-State Distribution ($N=336$)
- `EXPLORATORY_EVALUATION_APPLICABLE`: 200 (59.52%)
- `INVALID_OUTPUT`: 112 (33.33%)
- `NON_RELEVANT_EVALUATION`: 24 (7.14%)
- `VULNERABILITY_EVALUATION_APPLICABLE`: 0 (0.00%)

### 6.5 Reviewer Presentation Mapping ($N=336$)
- `ABSTENTION_CONFIRMED`: 224 (66.67%)
- `INVALID_PROPOSAL`: 112 (33.33%)
- `VULNERABILITY_FINDING`: 0 (0.00%)
- `EXPLORATORY_VERIFICATION_PROPOSAL`: 0 (0.00%)

---

## 7. Forensic Analysis of Candidate Hypotheses

### 7.1 Why Did Candidate Hypotheses Fail Closed?

In 104 calls, the model generated `decision: "HYPOTHESIS"`. Under legacy protocols (M3/M4), these outputs would have passed loose regex or substring filters and been scored as false positives or ungrounded hypotheses.

Under M5, every candidate was subjected to [`ExperimentPolarityValidator`](src/engine/decision_policy.py):

| Rejection Mechanism | Count | Root Cause Analysis |
| :--- | :---: | :--- |
| **Category-Action Incompatibility** | 50 | Model selected an action that cannot probe the category invariant (e.g. `TAMPER_REQUEST_PARAMETER` for `API-STATE-001` or `INVOKE_WITHOUT_CREDENTIALS` for `API-BOLA-001`). |
| **Semantic Outcome Inversion** | 30 | Model assigned an observation proving invariant enforcement as the `supporting_outcome` (e.g. claiming `HTTP_403_FORBIDDEN` supports BOLA, or `HTTP_409_CONFLICT` supports a state violation). |
| **Identical Outcomes** | 10 | Model emitted identical values for `supporting_outcome` and `disproving_outcome` (`CROSS_IDENTITY_OBJECT_ACCESSIBLE` for both), producing zero discriminative power. |
| **Cross-Tenant Action Incompatibility** | 14 | Model selected parameter tampering or credential dropping for multi-tenant isolation boundaries. |
| **Total Intercepted** | **104** | **100.0% of candidate hypotheses intercepted and rejected.** |

### 7.2 Vulnerable vs. Patched Symmetry
- Among the 104 candidate hypothesis attempts:
  - 53 ($51.0\%$) occurred on vulnerable variants.
  - 51 ($49.0\%$) occurred on patched variants.
- This demonstrates that without observable empirical anomaly signals in target evidence, the 7B model's propensity to propose a hypothesis is driven by category priors and endpoint route semantics, not by an underlying perception of vulnerability.
- The deterministic decision policy and polarity validator prevented this coin-flip behavior from becoming benchmark noise.

---

## 8. Latency & Compute Profile

- **Total Execution Time**: 8,517.17 seconds (141.95 minutes / ~2.37 hours).
- **Overall Mean Latency**: 25,339.4 ms (~25.3s per call).
- **Track Latency Progression**:
  - Track A (No RAG): 21,696.8 ms
  - Track B (Target RAG): 23,321.4 ms (+1.6s for target evidence)
  - Track C (VAPT RAG): 27,572.9 ms (+5.9s for VAPT methodology chunks)
  - Track D (Combined): 28,766.5 ms (+7.1s for combined context)
- **Token Truncation Safety**:
  - Truncation was confined entirely to Track C ($3/84$) and Track D ($5/84$).
  - In all 8 cases, generation terminated cleanly at 300 tokens and was classified as `MAX_TOKEN_TRUNCATION` without causing parser crashes.

---

## 9. Protected Historical Artifact Integrity Verification

Before and after the 336-call execution, all 10 protected historical artifacts were verified byte-identical:

| File Path | Pinned SHA-256 Digest | Status |
| :--- | :--- | :--- |
| `data/eval/m4_live_llm_benchmark_final.json` | `459b9ec63c3a2dc760abde12ec196760f7e505fbab5317f0da0c46b32c5eaac7` | **MATCH (IMMUTABLE)** |
| `data/eval/m5_live_smoke.json` | `7ee8b6b2ec33eca0fcb8a3f0948d1f36b7e41877354ae4a64190f8e19c679b5e` | **MATCH (IMMUTABLE)** |
| `data/eval/m5_live_smoke_v2.json` | `830c225b22f6767ee13b4ce3b443a14aede3ea767ee25ae7343c1a153c4a0818` | **MATCH (IMMUTABLE)** |
| `docs/M5_PHASE6_3_FALSE_POSITIVE_AUDIT.md` | `5cc7ac193aefb6fb5d0d5a845c54b7c6279b713609ce62ea44c00fa98a718bf7` | **MATCH (IMMUTABLE)** |
| `docs/M5_PHASE6_4_BENCHMARK_SEMANTICS_DECISION.md` | `6657ec2ccdc5ff1344e307a6d2e2dab6eff7fc47ece8c3b2d014742eeb91b53e` | **MATCH (IMMUTABLE)** |
| `docs/M5_PHASE6_5_EXPERIMENT_SEMANTICS_PROTOCOL_DESIGN.md` | `ec15f42ba52bd54363f236bff1a71683ab3b1c1a10fa28ddac5c8a97a40b255c` | **MATCH (IMMUTABLE)** |
| `src/eval/scenarios.py` | `102789655bfb04041de9259d1bf6db7f088979e5bce9bac9eb050564ef0110a8` | **MATCH (IMMUTABLE)** |
| `data/eval/m5_typed_protocol_live_smoke.json` | `d33d2a05e3cd2c00f684aa0bf987692c7d3d22b5e727aba941a447014bbfdcd6` | **MATCH (IMMUTABLE)** |
| `docs/M5_PHASE6_8_HYPOTHESIS_GOVERNANCE_DECISION.md` | `3331ddbdd4519c89b23a6e552f979d502ee1e479dcfac87399734b20d43681b5` | **MATCH (IMMUTABLE)** |
| `docs/M5_PHASE6_9_POLICY3_SCORING_IMPLEMENTATION.md` | `2acea4899fac9ae22543c02b23bcc21001f136e14849dd2e196828c79a45389c` | **MATCH (IMMUTABLE)** |

---

## 10. Research Interpretation & Methodological Boundaries

In compliance with the project's scientific constraints:

1. **Observed Benchmark Result vs. Mechanistic Interpretation**:
   - *Observed Result*: Useful Hypothesis Yield is 0.0000. Parser Failure Rate is 0.0000. Valid Abstention Rate is 66.67%.
   - *Mechanistic Interpretation*: Constrained decoding (`I1=1`) successfully eliminated syntactic format defects. However, the local 7B coder model lacks the parametric capability to reliably formulate valid, non-inverted falsification experiments under zero-shot prompting. The deterministic validator strictly prevented these defective formulations from reaching downstream triage.
2. **No Claim of Human Efficiency**:
   - The automated benchmark metrics measure algorithmic contract compliance and abstention behavior. They do not constitute empirical evidence of human investigator time savings.
3. **Causal Attribution of RAG**:
   - VAPT Knowledge RAG dramatically reduced spurious hypothesis attempts (from 41 to 11) and increased calibrated abstentions. This provides causal evidence that providing security methodology helps the model recognize evidence gaps, rather than hallucinating attacks.
4. **Validity for Confirmatory Interpretation**:
   - **This benchmark is valid for confirmatory interpretation.** All frozen preflight gates, scenario definitions, model parameters, and scoring rules were preserved without tuning, post-hoc repair, or retries.

---

## 11. Final Authorization & State Classification

```
================================================================================
FINAL AUTHORIZATION STATE:
M5_PHASE7_COMPLETE
================================================================================
```

- **Runtime**: Ollama v0.34.1
- **Model Digest**: `dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364`
- **Total Calls**: Exactly 336 ($84 \times 4$)
- **Track Counts**: A=84, B=84, C=84, D=84
- **Primary Estimand (Useful Hypothesis Yield @ N reviewer minutes)**: **`0.0000`**
- **Valid Execution Rate**: **`66.67%`** ($224 / 336$)
- **Parser Failure Rate**: **`0.00%`** ($0 / 336$)
- **Semantic Polarity Interceptions**: **`27.98%`** ($94 / 336$)
- **Artifact SHA-256**: `1e0ed90c4aa672f135d2d2f2240a14d22fa0037c03efda33634f4bf10ff0b125`
- **Protected Artifacts**: 10/10 verified byte-identical
- **Deviations**: NONE
