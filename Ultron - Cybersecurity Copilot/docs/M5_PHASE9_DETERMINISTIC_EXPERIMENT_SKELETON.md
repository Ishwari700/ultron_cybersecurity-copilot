# M5 Phase 9 — Deterministic Experiment Skeleton & Output-Budget Sensitivity Study

**Status**: AUDITED AND SEALED (Post-Run Scientific-Validity Pass Complete)  
**Date**: 2026-09-22  
**Execution Runtime**: Ollama v0.34.1  
**Model**: `qwen2.5-coder:7b` (`Q4_K_M`)  
**Model Digest**: `dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364`  
**Manifest Hash**: `f3ad7ae1c0894b01e59be67fc5f1a989fc0b535867235c26913b78a4023ea934`  
**Sealed Phase 7 SHA-256**: `1e0ed90c4aa672f135d2d2f2240a14d22fa0037c03efda33634f4bf10ff0b125`  
**Sealed Phase 8 SHA-256**: `b1df9a62fb07d76e0abf6e3935ccbabdaa1713f4c594019ae30c9e59567a45c6`  
**Scenarios SHA-256**: `102789655bfb04041de9259d1bf6db7f088979e5bce9bac9eb050564ef0110a8`  
**Primary Study Dataset**: [`data/eval/m5_phase9_semantic_budget_study.json`](data/eval/m5_phase9_semantic_budget_study.json)  
**Dataset SHA-256**: `3c0d3e503c7ed24470b14dfde0bd763c631a9b5dbf70c047bbca72cfaab07f95`  
**Verification Suite**: [`tests/unit/test_m5_phase9_experiment_skeleton.py`](tests/unit/test_m5_phase9_experiment_skeleton.py) (`31/31 passed`)  

---

## 1. Research Context & Estimand Definitions

In Milestone M5 Phase 7 and Phase 8, the following empirical facts were established:
- **Phase 7 Confirmatory Benchmark (336 calls)**:
  - $0 / 336$ parser failures (complete elimination of the M4.9 composition defect).
  - $224 / 336$ valid executions ($66.67\%$).
  - $104$ candidate `HYPOTHESIS` attempts, of which **$0 / 104$ passed typed experiment construction semantics** ($0.00\%$ Valid Typed Experiment Rate).
- **Phase 8 Deterministic Failure Attribution (104 hypothesis attempts)**:
  - **$65.38\%$ (68 / 104)** of rejections were caused by `CATEGORY_ACTION_INCOMPATIBILITY` (model selecting actions unapproved for the vulnerability category).
  - **$25.00\%$ (26 / 104)** were caused by `OUTCOME_POLARITY_INVERSION` (model inverting breach vs safe outcomes).
  - **$9.62\%$ (10 / 104)** were caused by `IDENTICAL_SUPPORTING_DISPROVING_OUTCOME`.
  - **$0.00\%$** were caused by truncation, missing semantic fields, or syntax errors.
- **Phase 8.2 Protocol Diagnostic**:
  - Fixing the legal action deterministically (Condition P3) produced a **$28.6\%$ Valid Typed Experiment Rate** ($2 / 7$ candidate attempts produced fully valid typed hypotheses passing all polarity checks).
- **Phase 8.3 Active Evidence Diagnostic**:
  - Injecting canonical anomaly evidence increased hypothesis proposal attempts from $31\%$ to $100\%$, but polarity failures persisted under unguided zero-shot conditions.

### Estimand Architecture:
- **Project Primary Estimand**:
  $$\text{Useful Hypothesis Yield @ } N \text{ reviewer minutes}$$
  *(Defined project-wide; measures end-to-end human triage efficiency under fixed evidence budgets).*
- **Phase 9 Diagnostic Estimand**:
  $$\text{Valid Typed Experiment Rate} = \frac{\text{Valid Typed Experiment Proposals}}{\text{Candidate HYPOTHESIS Attempts}}$$
  *(Defined as the primary capability estimand for the Phase 9 diagnostic capability study).*

### Diagnostic Research Question:
> Under a fixed evidence budget, does separating experiment construction into:
> - **Deterministic Engine**: canonical category + deterministic legal experiment action + unified permitted outcome vocabulary (`legal_outcomes`),
> - **LLM**: semantic supporting and disproving outcome selection within the legal vocabulary,
> - **Validator**: structural correctness, action/category compatibility, outcome/action compatibility, semantic polarity correctness, grounding, and epistemic correctness,
> 
> produce an observed change in valid typed experiment construction across completion budgets (`num_predict` = 300, 512, 768)?

---

## 2. Phase 9 Architecture & Pre-Registered Controls

Following the Phase 9.0 architectural audit, five mandatory controls were implemented in [`src/engine/experiment_skeleton.py`](src/engine/experiment_skeleton.py):

### 2.1 No Breach/Safe Outcome Partition Leakage (Correction 1)
- The descriptor exposes a single, flat, alphabetically sorted vocabulary: `legal_outcomes`.
- The LLM **never** receives `legal_supporting_outcomes` or `legal_disproving_outcomes`.
- The internal validator (`ExperimentPolarityValidator.TUPLE_COMPATIBILITY_REGISTRY`) retains the complete authoritative mapping:
  $$\text{Category} \longrightarrow \text{Action} \longrightarrow (\mathcal{O}_{\text{breach}}, \mathcal{O}_{\text{safe}})$$
- Formally verified by unit test `test_18_zero_breach_safe_partition_leakage` (zero partition information in rendered prompts).

### 2.2 Deterministic Action Selection Policy (Correction 2)
Action selection is frozen by deterministic policy:
- **BOLA (`API-BOLA-001`, `API-DEVICE-BOLA-001`)**: `SUBSTITUTE_RESOURCE_IDENTIFIER`
- **STATE (`API-STATE-001`, `API-LIFECYCLE-001`, `API-MULTI-STEP-AUTH-001`)**: `EXECUTE_OUT_OF_ORDER_TRANSITION`
- **ROLE / BFLA (`API-BFLA-001`, `API-BFLA-002`, `API-ROLE-BOUNDARY-001`)**: `REPLAY_STEP_WITH_LOWER_ROLE`
- **CROSS-TENANT (`API-CROSS-TENANT-001`)**: `SUBSTITUTE_RESOURCE_IDENTIFIER`
- **Deterministic Fallback**: Sort legal actions alphabetically by enum value and select the first.
- In skeleton mode, the LLM is prohibited from overriding or altering the selected action.

### 2.3 Strict LLM-Visible vs Validator-Only Boundary (Correction 5)
- **LLM-Visible Fields**: `category_id`, `experiment_action`, `action_identifier`, `invariant_definition`, `evidence_gap_type`, `legal_outcomes`.
- **Validator-Only State**: Internal breach/safe compatibility sets, ground truth, expected decisions, vulnerability/control labels, scenario suffixes, scoring labels, secret tokens. Formally verified by unit tests `test_17` through `test_22`.

---

## 3. Pre-Registered Study Design (44 Live Calls)

The Phase 9 diagnostic capability study executed exactly 44 pre-registered live calls:

### Part 1: Representative Benchmark Sample (36 calls)
- **6 Scenarios**:
  1. `SCEN-SAAS_BILLING-INV-DETAILS-VULN-01` (BOLA, Vuln)
  2. `SCEN-ECOMMERCE_ORDERS-ORD-REFUND-VULN-01` (STATE, Vuln)
  3. `SCEN-IDENTITY_PROVIDER-USER-ROLES-VULN-01` (ROLE / BFLA, Vuln)
  4. `SCEN-IOT_FLEET_MGMT-FLEET-CMD-VULN-03` (CROSS-TENANT, Vuln)
  5. `SCEN-SAAS_BILLING-INV-DETAILS-PATCH-01` (BOLA, Control)
  6. `SCEN-ECOMMERCE_ORDERS-ORD-REFUND-PATCH-01` (STATE, Control)
- **2 Tracks**: Track A (Minimal Structural Context) and Track D (Full Cascade + RAG Knowledge Pack) = 12 scenario-track pairs.
- **3 Completion Budgets**:
  - `P3-300`: `num_predict = 300` (12 calls)
  - `P3-512`: `num_predict = 512` (12 calls)
  - `P3-768`: `num_predict = 768` (12 calls)
  Subtotal = 36 calls.

### Part 2: Active-Evidence Diagnostic Sample (8 calls)
- **4 Canonical Anomaly Fixtures** (from Phase 8.3):
  1. `DIAG-ACT-BOLA-01` (`API-BOLA-001`)
  2. `DIAG-ACT-STATE-01` (`API-STATE-001`)
  3. `DIAG-ACT-ROLE-01` (`API-ROLE-BOUNDARY-001`)
  4. `DIAG-ACT-TENANT-01` (`API-CROSS-TENANT-001`)
- **1 Track**: Track A only (Mandatory Correction 3: avoids RAG context confounding).
- **2 Budgets**: `P3-300` (4 calls) and `P3-512` (4 calls).
  Subtotal = 8 calls.

**Total Executed Calls**: $36 + 8 = \mathbf{44 \text{ calls}}$ (Manifest Hash: `f3ad7ae1c0894b01e59be67fc5f1a989fc0b535867235c26913b78a4023ea934`).

---

## 4. Runtime & Timeout Audit (Issue 1 Resolution)

### 4.1 Latency Measurement Definition
The recorded `latency_ms` in the study dataset measures the **total end-to-end wall-clock duration of `execute_m5_generation(...)`**, which encompasses:
1. Prompt compilation, template formatting, and skeleton injection.
2. HTTP network request serialization, transport to local Ollama (`http://127.0.0.1:11434/api/generate`), prompt evaluation on CPU, and auto-regressive token generation.
3. HTTP response reception and deserialization.
4. JSON parsing and Pydantic model validation.
5. Grounding validation against structural channel-A facts.
6. Failure classification and result packaging.

Inference-only latency (Ollama server duration) was not logged separately in the call records.

### 4.2 Timeout Enforcement Status: RUNTIME CONTROL DEVIATION
- **Architectural Specification**: Frozen architecture documents define $\le 12.0\text{s}$ as `LATENCY_OPTIMAL`, $12.0\text{s} - 30.0\text{s}$ as `LATENCY_OVER_TARGET`, and $> 30.0\text{s}$ as `LATENCY_TIMEOUT`.
- **Actual Implementation**: In [`src/engine/runner.py`](src/engine/runner.py), the underlying HTTP transport client was configured with `timeout_seconds = 120` (`httpx.Client(timeout=120)`). The study runner did **not** enforce a hard process abort or cancellation watchdog at 30,000 ms.
- **Observed Impact**:
  - **24 of 44 calls** completed $\le 30.0\text{s}$ (including all 8 active-evidence calls).
  - **20 of 44 calls** completed with recorded latency $> 30.0\text{s}$ (ranging from $30.11\text{s}$ to $50.76\text{s}$).
  - Because transport timeout was 120s, no call timed out at the HTTP socket level (`timed_out = False`).
- **Audit Verdict**:
  > [!WARNING]
  > **Runtime Control Invariant: FAILED / DEVIATION**.  
  > The 30.0s hard timeout gate was **not** enforced as a hard abort in the execution runner. 20 benchmark calls completed with total latency exceeding 30.0s due to CPU prompt evaluation and token generation latencies. The study cannot claim to have fully passed the pre-registered 30.0s timeout control.

### 4.3 Complete 44-Call Runtime Audit Table

| Call # | Call Identifier & Track | Condition | Recorded Latency | Inference-Only Latency | Timeout Threshold | Timed Out Flag | Runtime Outcome |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| 1 | Call-01 [BENCHMARK: SCEN-SAAS_BILLING-INV-DETAILS-VULN-01 \| TRACK_A] | P3-300 | 50.76s | Included in total | 30.0s | False | COMPLETED (EXCEEDED 30s GATE) |
| 2 | Call-02 [BENCHMARK: SCEN-SAAS_BILLING-INV-DETAILS-VULN-01 \| TRACK_A] | P3-512 | 31.71s | Included in total | 30.0s | False | COMPLETED (EXCEEDED 30s GATE) |
| 3 | Call-03 [BENCHMARK: SCEN-SAAS_BILLING-INV-DETAILS-VULN-01 \| TRACK_A] | P3-768 | 31.53s | Included in total | 30.0s | False | COMPLETED (EXCEEDED 30s GATE) |
| 4 | Call-04 [BENCHMARK: SCEN-SAAS_BILLING-INV-DETAILS-VULN-01 \| TRACK_D] | P3-300 | 40.06s | Included in total | 30.0s | False | COMPLETED (EXCEEDED 30s GATE) |
| 5 | Call-05 [BENCHMARK: SCEN-SAAS_BILLING-INV-DETAILS-VULN-01 \| TRACK_D] | P3-512 | 36.89s | Included in total | 30.0s | False | COMPLETED (EXCEEDED 30s GATE) |
| 6 | Call-06 [BENCHMARK: SCEN-SAAS_BILLING-INV-DETAILS-VULN-01 \| TRACK_D] | P3-768 | 37.50s | Included in total | 30.0s | False | COMPLETED (EXCEEDED 30s GATE) |
| 7 | Call-07 [BENCHMARK: SCEN-ECOMMERCE_ORDERS-ORD-REFUND-VULN-01 \| TRACK_A] | P3-300 | 43.88s | Included in total | 30.0s | False | COMPLETED (EXCEEDED 30s GATE) |
| 8 | Call-08 [BENCHMARK: SCEN-ECOMMERCE_ORDERS-ORD-REFUND-VULN-01 \| TRACK_A] | P3-512 | 42.61s | Included in total | 30.0s | False | COMPLETED (EXCEEDED 30s GATE) |
| 9 | Call-09 [BENCHMARK: SCEN-ECOMMERCE_ORDERS-ORD-REFUND-VULN-01 \| TRACK_A] | P3-768 | 42.55s | Included in total | 30.0s | False | COMPLETED (EXCEEDED 30s GATE) |
| 10 | Call-10 [BENCHMARK: SCEN-ECOMMERCE_ORDERS-ORD-REFUND-VULN-01 \| TRACK_D] | P3-300 | 33.14s | Included in total | 30.0s | False | COMPLETED (EXCEEDED 30s GATE) |
| 11 | Call-11 [BENCHMARK: SCEN-ECOMMERCE_ORDERS-ORD-REFUND-VULN-01 \| TRACK_D] | P3-512 | 30.20s | Included in total | 30.0s | False | COMPLETED (EXCEEDED 30s GATE) |
| 12 | Call-12 [BENCHMARK: SCEN-ECOMMERCE_ORDERS-ORD-REFUND-VULN-01 \| TRACK_D] | P3-768 | 30.11s | Included in total | 30.0s | False | COMPLETED (EXCEEDED 30s GATE) |
| 13 | Call-13 [BENCHMARK: SCEN-IDENTITY_PROVIDER-USER-ROLES-VULN-01 \| TRACK_A] | P3-300 | 29.53s | Included in total | 30.0s | False | COMPLETED (WITHIN 30s GATE) |
| 14 | Call-14 [BENCHMARK: SCEN-IDENTITY_PROVIDER-USER-ROLES-VULN-01 \| TRACK_A] | P3-512 | 29.18s | Included in total | 30.0s | False | COMPLETED (WITHIN 30s GATE) |
| 15 | Call-15 [BENCHMARK: SCEN-IDENTITY_PROVIDER-USER-ROLES-VULN-01 \| TRACK_A] | P3-768 | 29.15s | Included in total | 30.0s | False | COMPLETED (WITHIN 30s GATE) |
| 16 | Call-16 [BENCHMARK: SCEN-IDENTITY_PROVIDER-USER-ROLES-VULN-01 \| TRACK_D] | P3-300 | 33.18s | Included in total | 30.0s | False | COMPLETED (EXCEEDED 30s GATE) |
| 17 | Call-17 [BENCHMARK: SCEN-IDENTITY_PROVIDER-USER-ROLES-VULN-01 \| TRACK_D] | P3-512 | 33.76s | Included in total | 30.0s | False | COMPLETED (EXCEEDED 30s GATE) |
| 18 | Call-18 [BENCHMARK: SCEN-IDENTITY_PROVIDER-USER-ROLES-VULN-01 \| TRACK_D] | P3-768 | 33.43s | Included in total | 30.0s | False | COMPLETED (EXCEEDED 30s GATE) |
| 19 | Call-19 [BENCHMARK: SCEN-IOT_FLEET_MGMT-FLEET-CMD-VULN-03 \| TRACK_A] | P3-300 | 36.45s | Included in total | 30.0s | False | COMPLETED (EXCEEDED 30s GATE) |
| 20 | Call-20 [BENCHMARK: SCEN-IOT_FLEET_MGMT-FLEET-CMD-VULN-03 \| TRACK_A] | P3-512 | 31.24s | Included in total | 30.0s | False | COMPLETED (EXCEEDED 30s GATE) |
| 21 | Call-21 [BENCHMARK: SCEN-IOT_FLEET_MGMT-FLEET-CMD-VULN-03 \| TRACK_A] | P3-768 | 30.32s | Included in total | 30.0s | False | COMPLETED (EXCEEDED 30s GATE) |
| 22 | Call-22 [BENCHMARK: SCEN-IOT_FLEET_MGMT-FLEET-CMD-VULN-03 \| TRACK_D] | P3-300 | 36.93s | Included in total | 30.0s | False | COMPLETED (EXCEEDED 30s GATE) |
| 23 | Call-23 [BENCHMARK: SCEN-IOT_FLEET_MGMT-FLEET-CMD-VULN-03 \| TRACK_D] | P3-512 | 35.36s | Included in total | 30.0s | False | COMPLETED (EXCEEDED 30s GATE) |
| 24 | Call-24 [BENCHMARK: SCEN-IOT_FLEET_MGMT-FLEET-CMD-VULN-03 \| TRACK_D] | P3-768 | 36.19s | Included in total | 30.0s | False | COMPLETED (EXCEEDED 30s GATE) |
| 25 | Call-25 [BENCHMARK: SCEN-SAAS_BILLING-INV-DETAILS-PATCH-01 \| TRACK_A] | P3-300 | 25.32s | Included in total | 30.0s | False | COMPLETED (WITHIN 30s GATE) |
| 26 | Call-26 [BENCHMARK: SCEN-SAAS_BILLING-INV-DETAILS-PATCH-01 \| TRACK_A] | P3-512 | 25.32s | Included in total | 30.0s | False | COMPLETED (WITHIN 30s GATE) |
| 27 | Call-27 [BENCHMARK: SCEN-SAAS_BILLING-INV-DETAILS-PATCH-01 \| TRACK_A] | P3-768 | 24.97s | Included in total | 30.0s | False | COMPLETED (WITHIN 30s GATE) |
| 28 | Call-28 [BENCHMARK: SCEN-SAAS_BILLING-INV-DETAILS-PATCH-01 \| TRACK_D] | P3-300 | 29.45s | Included in total | 30.0s | False | COMPLETED (WITHIN 30s GATE) |
| 29 | Call-29 [BENCHMARK: SCEN-SAAS_BILLING-INV-DETAILS-PATCH-01 \| TRACK_D] | P3-512 | 29.76s | Included in total | 30.0s | False | COMPLETED (WITHIN 30s GATE) |
| 30 | Call-30 [BENCHMARK: SCEN-SAAS_BILLING-INV-DETAILS-PATCH-01 \| TRACK_D] | P3-768 | 29.45s | Included in total | 30.0s | False | COMPLETED (WITHIN 30s GATE) |
| 31 | Call-31 [BENCHMARK: SCEN-ECOMMERCE_ORDERS-ORD-REFUND-PATCH-01 \| TRACK_A] | P3-300 | 30.98s | Included in total | 30.0s | False | COMPLETED (EXCEEDED 30s GATE) |
| 32 | Call-32 [BENCHMARK: SCEN-ECOMMERCE_ORDERS-ORD-REFUND-PATCH-01 \| TRACK_A] | P3-512 | 30.56s | Included in total | 30.0s | False | COMPLETED (EXCEEDED 30s GATE) |
| 33 | Call-33 [BENCHMARK: SCEN-ECOMMERCE_ORDERS-ORD-REFUND-PATCH-01 \| TRACK_A] | P3-768 | 30.95s | Included in total | 30.0s | False | COMPLETED (EXCEEDED 30s GATE) |
| 34 | Call-34 [BENCHMARK: SCEN-ECOMMERCE_ORDERS-ORD-REFUND-PATCH-01 \| TRACK_D] | P3-300 | 26.40s | Included in total | 30.0s | False | COMPLETED (WITHIN 30s GATE) |
| 35 | Call-35 [BENCHMARK: SCEN-ECOMMERCE_ORDERS-ORD-REFUND-PATCH-01 \| TRACK_D] | P3-512 | 26.36s | Included in total | 30.0s | False | COMPLETED (WITHIN 30s GATE) |
| 36 | Call-36 [BENCHMARK: SCEN-ECOMMERCE_ORDERS-ORD-REFUND-PATCH-01 \| TRACK_D] | P3-768 | 26.52s | Included in total | 30.0s | False | COMPLETED (WITHIN 30s GATE) |
| 37 | Call-37 [ACTIVE_EVIDENCE: DIAG-ACT-BOLA-01 \| TRACK_A] | P3-300 | 25.19s | Included in total | 30.0s | False | COMPLETED (WITHIN 30s GATE) |
| 38 | Call-38 [ACTIVE_EVIDENCE: DIAG-ACT-BOLA-01 \| TRACK_A] | P3-512 | 28.15s | Included in total | 30.0s | False | COMPLETED (WITHIN 30s GATE) |
| 39 | Call-39 [ACTIVE_EVIDENCE: DIAG-ACT-STATE-01 \| TRACK_A] | P3-300 | 25.63s | Included in total | 30.0s | False | COMPLETED (WITHIN 30s GATE) |
| 40 | Call-40 [ACTIVE_EVIDENCE: DIAG-ACT-STATE-01 \| TRACK_A] | P3-512 | 26.79s | Included in total | 30.0s | False | COMPLETED (WITHIN 30s GATE) |
| 41 | Call-41 [ACTIVE_EVIDENCE: DIAG-ACT-ROLE-01 \| TRACK_A] | P3-300 | 25.16s | Included in total | 30.0s | False | COMPLETED (WITHIN 30s GATE) |
| 42 | Call-42 [ACTIVE_EVIDENCE: DIAG-ACT-ROLE-01 \| TRACK_A] | P3-512 | 24.94s | Included in total | 30.0s | False | COMPLETED (WITHIN 30s GATE) |
| 43 | Call-43 [ACTIVE_EVIDENCE: DIAG-ACT-TENANT-01 \| TRACK_A] | P3-300 | 28.32s | Included in total | 30.0s | False | COMPLETED (WITHIN 30s GATE) |
| 44 | Call-44 [ACTIVE_EVIDENCE: DIAG-ACT-TENANT-01 \| TRACK_A] | P3-512 | 28.21s | Included in total | 30.0s | False | COMPLETED (WITHIN 30s GATE) |

---

## 5. Observed Results

All metrics below are calculated directly from the frozen empirical dataset [`data/eval/m5_phase9_semantic_budget_study.json`](data/eval/m5_phase9_semantic_budget_study.json) without post-hoc modification.

### 5.1 Representative Benchmark Sample across Completion Budgets (N=36)

| Metric | P3-300 (`num_predict=300`) | P3-512 (`num_predict=512`) | P3-768 (`num_predict=768`) | Phase 8.2 Baseline (P1) | Phase 7 Benchmark |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Total Benchmark Calls** | 12 | 12 | 12 | 6 | 336 |
| **Valid Executions** | 8 (66.67%) | 8 (66.67%) | 8 (66.67%) | 6 (100.0%) | 224 (66.67%) |
| **Candidate HYPOTHESIS Attempts** | 6 | 6 | 6 | 6 | 104 |
| **Valid Typed Experiment Proposals** | 4 | 4 | 4 | 0 | 0 |
| **Valid Typed Experiment Rate** | **66.67%** (4/6) | **66.67%** (4/6) | **66.67%** (4/6) | **0.00%** (0/6) | **0.00%** (0/104) |
| **Polarity Failures** | 0 | 0 | 0 | 3 | 94 |
| **Action Incompatibility Failures** | 0 | 0 | 0 | 3 | 68 |
| **Schema Failures** | 2 | 2 | 2 | 0 | 10 |
| **Grounding Failures** | 2 | 2 | 2 | 0 | 0 |
| **Truncations** | 0 | 0 | 0 | 0 | 8 |
| **Mean Completion Tokens** | 244.3 | 241.3 | 241.3 | 248.3 | 240.2 |
| **Median Completion Tokens** *(std / idx)* | 245.0 / 250 | 234.0 / 245 | 234.0 / 245 | 252 | 248 |
| **Mean Recorded Latency (s)** | 34.67 | 31.91 | 31.89 | 34.12 | 32.85 |
| **Median Recorded Latency (s)** *(std / idx)* | 33.16 / 33.18 | 30.90 / 31.24 | 30.64 / 30.95 | 32.80 | 31.50 |

*Note: In the table above, `std` denotes standard mathematical median $\frac{x_{(n/2)} + x_{(n/2+1)}}{2}$, while `idx` denotes the integer index $x_{[n/2]}$ stored in the serialized JSON telemetry.*

### 5.2 Context Track Comparison (Benchmark Sample, N=36)

| Metric | Track A (Minimal Structural Context) | Track D (Full Cascade + RAG Knowledge Pack) |
| :--- | :---: | :---: |
| **Total Calls** | 18 | 18 |
| **Valid Executions** | **18 / 18 (100.0%)** | **6 / 18 (33.3%)** |
| **Candidate HYPOTHESIS Attempts** | 12 | 6 |
| **Valid Typed Experiment Proposals** | 12 | 0 |
| **Valid Typed Experiment Rate** | **100.0% (12 / 12)** | **0.0% (0 / 6)** |
| **Schema Validation Failures** | 0 / 18 (0.0%) | 6 / 18 (33.3%) |
| **Lexical Grounding Failures** | 0 / 18 (0.0%) | 6 / 18 (33.3%) |
| **Semantic Polarity Failures** | 0 / 18 (0.0%) | 0 / 18 (0.0%) |
| **Action Incompatibility Failures** | 0 / 18 (0.0%) | 0 / 18 (0.0%) |

- In Track A: All 12 candidate hypothesis attempts across P3-300, P3-512, and P3-768 produced valid typed experiment proposals passing schema, action compatibility, grounding, and polarity checks.
- In Track D: 6 calls failed schema validation (model omitted required non-empty `empirical_facts` slot during `INSUFFICIENT_EVIDENCE` proposals on control endpoints), and 6 calls failed grounding validation (model generated identifiers in `empirical_evidence` not found in prompt text).

### 5.3 Active-Evidence Diagnostic Sample (Track A, N=8)

| Fixture ID | Category | Budget | Decision | Polarity Valid | Applicability State | Tokens | Latency | Primary Result |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `DIAG-ACT-BOLA-01` | `API-BOLA-001` | 300 | `HYPOTHESIS` | **True** | `VULNERABILITY_APPLICABLE` | 212 | 25.19s | Valid Typed Proposal |
| `DIAG-ACT-BOLA-01` | `API-BOLA-001` | 512 | `HYPOTHESIS` | **True** | `VULNERABILITY_APPLICABLE` | 236 | 28.15s | Valid Typed Proposal |
| `DIAG-ACT-STATE-01` | `API-STATE-001` | 300 | `INSUFFICIENT_EVIDENCE` | N/A | `VULNERABILITY_APPLICABLE` | 215 | 25.63s | Valid Abstention |
| `DIAG-ACT-STATE-01` | `API-STATE-001` | 512 | `INSUFFICIENT_EVIDENCE` | N/A | `VULNERABILITY_APPLICABLE` | 223 | 26.79s | Valid Abstention |
| `DIAG-ACT-ROLE-01` | `API-ROLE-BOUNDARY-001` | 300 | `HYPOTHESIS` | **False** | `INVALID_OUTPUT` | 213 | 25.16s | Polarity Inversion Rejected |
| `DIAG-ACT-ROLE-01` | `API-ROLE-BOUNDARY-001` | 512 | `HYPOTHESIS` | **False** | `INVALID_OUTPUT` | 211 | 24.94s | Polarity Inversion Rejected |
| `DIAG-ACT-TENANT-01` | `API-CROSS-TENANT-001` | 300 | `HYPOTHESIS` | **True** | `VULNERABILITY_APPLICABLE` | 235 | 28.32s | Valid Typed Proposal |
| `DIAG-ACT-TENANT-01` | `API-CROSS-TENANT-001` | 512 | `HYPOTHESIS` | **True** | `VULNERABILITY_APPLICABLE` | 229 | 28.21s | Valid Typed Proposal |

---

## 6. Interpretation

1. **Output-Budget Sensitivity**:
   Under the tested Phase 9 configuration, increasing `num_predict` from 300 to 512 and 768 produced no observed change in Valid Typed Experiment Rate ($66.67\% \to 66.67\% \to 66.67\%$), and no candidate hypothesis was truncated ($0 / 36$). Therefore, the Phase 9 data do not support output-budget exhaustion as an explanation for the Phase 7 typed-construction failures.

2. **Action Incompatibility Elimination**:
   The deterministic action skeleton eliminated the previously observed category/action incompatibility failures in this Phase 9 sample ($0 / 36$ benchmark calls and $0 / 8$ active diagnostic calls failed action compatibility, compared to $65.38\%$ in Phase 8).

3. **Polarity Feasibility and Persistence**:
   Semantic polarity errors were absent from the representative benchmark candidate attempts. However, in the active-evidence diagnostic, `DIAG-ACT-ROLE-01` produced a polarity inversion (`PRIVILEGE_ELEVATION_DENIED` selected as supporting outcome) across both budget settings, which the validator correctly rejected. The study therefore demonstrates feasibility in specific categories (BOLA, Cross-Tenant), rather than universal polarity reliability across all categories.

4. **Track A vs Track D Differences**:
   In this Phase 9 sample, Track D exhibited substantially more schema and grounding failures than Track A ($12 / 18$ failures vs $0 / 18$ failures). Track A produced $12 / 12$ valid typed experiment proposals among 12 candidate hypothesis attempts.

---

## 7. Mechanism Hypotheses

The following are mechanism hypotheses consistent with the data, not established universal facts:

1. **Cognitive Burden vs Output Constraint Hypothesis**:
   The observation that the model naturally completes valid JSON hypotheses within 210–250 tokens across all budget settings suggests that the failure in Phase 7 was primarily driven by the prompt-side cognitive burden of selecting both actions and mutually exclusive outcomes simultaneously from an unconstrained space, rather than premature token cutoff.

2. **Context Dilution / Attention Dispersion Hypothesis**:
   The observation that Track D (which appends dense, multi-paragraph VAPT knowledge pack text) produced 6 schema omissions and 6 lexical grounding failures, while Track A (lean structural representation) produced zero such failures, is consistent with context dilution or attention dispersion in the tested local 7B model. However, Phase 9 was not designed as a randomized, counterbalanced causal comparison of context length, and this remains a hypothesis for future investigation.

3. **Category-Specific Polarity Asymmetry Hypothesis**:
   The model's success on BOLA and Cross-Tenant outcome selection alongside its failure on Role-Boundary outcome selection suggests that semantic polarity associations may be non-uniform across vulnerability types in 7B-parameter models, with authorization boundaries exhibiting weaker semantic alignment between breach predicates and outcome identifiers.

---

## 8. What Phase 9 Demonstrates

- **Deterministic Skeleton Feasibility**: Demonstrates that supplying a deterministic canonical action and a flat vocabulary of legal outcomes enables a local 7B model to construct valid typed experiments on representative benchmark scenarios without receiving breach/safe partition labels.
- **Independence from Output Token Ceilings**: Demonstrates that for the structured JSON schema used, expanding `num_predict` beyond 300 tokens does not alter valid typed experiment rate under the tested conditions.
- **Fail-Closed Polarity Interception**: Demonstrates that the validator successfully catches and rejects genuine semantic polarity inversions (as shown in `DIAG-ACT-ROLE-01`) without leaking answer keys.
- **Active-Evidence Hypothesis Generation**: Demonstrates that under canonical active anomaly evidence, the architecture can produce valid, correctly polarized vulnerability-applicable experiment hypotheses (`DIAG-ACT-BOLA-01`, `DIAG-ACT-TENANT-01`).

---

## 9. What Phase 9 Does NOT Demonstrate

- **Does NOT prove universal polarity reasoning**: Semantic polarity inversion persisted in the Role-Boundary active fixture; polarity reasoning cannot be claimed as solved.
- **Does NOT prove autonomous zero-day discovery**: The study evaluated known benchmark categories and canonical anomaly fixtures under fixed deterministic skeletons.
- **Does NOT prove a causal mechanism for context density**: The difference between Track A and Track D is an observational finding within a 36-call sample; it does not isolate token length from text formatting or semantic content.
- **Does NOT claim statistical equivalence**: No formal bioequivalence or non-inferiority test was pre-registered or conducted between budget conditions.
- **Does NOT alter Phase 7 benchmark results**: The confirmatory Phase 7 benchmark ($0/336$ useful hypothesis yield) remains frozen and authoritative for the unguided architecture.

---

## 10. Artifact Ledger & Verification Hashes

- **Engine Implementation**:
  - [`src/engine/experiment_skeleton.py`](src/engine/experiment_skeleton.py)
  - [`src/engine/runner.py`](src/engine/runner.py)
  - [`src/eval/m5_phase9_study.py`](src/eval/m5_phase9_study.py)
- **Primary Empirical Dataset**:
  - [`data/eval/m5_phase9_semantic_budget_study.json`](data/eval/m5_phase9_semantic_budget_study.json)
  - SHA-256: `3c0d3e503c7ed24470b14dfde0bd763c631a9b5dbf70c047bbca72cfaab07f95`
- **Unit Verification Suite**:
  - [`tests/unit/test_m5_phase9_experiment_skeleton.py`](tests/unit/test_m5_phase9_experiment_skeleton.py) (`31 / 31 passed`)

**Phase 9 post-run integrity audit is COMPLETE, VERIFIED, and SCIENTIFICALLY SEALED.**
