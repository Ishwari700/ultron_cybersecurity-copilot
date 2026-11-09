# M5 Phase 10 — Full-Population Validation Preregistration

**Date**: 2026-09-22  
**Milestone**: M5 (Autonomous Reasoning & Hypothesis Verification)  
**Phase**: Phase 10 (Full-Population Validation)  
**Status**: PRE-REGISTERED  
**Repository State**: Branch `master`, Commit audited as `READY_FOR_PHASE_10`.  

---

## 1. Study Rationale & Research Questions

The Milestone M5 Phase 9 diagnostic capability study demonstrated that introducing a Deterministic Experiment Skeleton (separating canonical vulnerability category mapping and deterministic legal action selection from LLM outcome assignment) produced a **66.67% Valid Typed Experiment Rate** across completion budgets in a 6-scenario sample, compared to 0.00% under the unguided Phase 7 architecture.

Phase 10 evaluates whether this architectural intervention remains effective when generalized across the **entire benchmark population (84 scenarios)** under strict runtime controls and dual wall-clock timeout ceilings.

### 1.1 Confirmatory Research Questions
1. **RQ1 (Architecture Main Effect)**: Does the `DETERMINISTIC_EXPERIMENT_SKELETON` produce a statistically significant increase in the **Valid Typed Experiment Rate** compared to the concurrent `BASELINE_EXISTING_ARCHITECTURE` across the full 84-scenario benchmark?
2. **RQ2 (Vulnerability Detection)**: Does the deterministic skeleton increase the **Automated Useful Vulnerable Hypothesis Rate** on ground-truth vulnerable scenarios without inflating false positives on control scenarios?
3. **RQ3 (Context Density Interaction)**: Does the context dilution / attention dispersion effect observed in Phase 9 Track D (Full Cascade + RAG Knowledge Pack) persist across the full population, and does the deterministic skeleton mitigate or exacerbate this effect compared to baseline?

---

## 2. Experimental Design: 2×2 Factorial Matrix

The benchmark evaluates a balanced $2 \times 2$ factorial design:
- **Factor 1 (Architecture)**: `BASELINE_EXISTING_ARCHITECTURE` vs. `DETERMINISTIC_EXPERIMENT_SKELETON`
- **Factor 2 (Context Track)**: `Track A` (Minimal Structural Context) vs. `Track D` (Full Cascade Context + RAG Knowledge Pack)

| Condition ID | Architecture | Context Track | Population | Calls | Nature of Comparison |
| :--- | :--- | :--- | :---: | :---: | :--- |
| **C1** | `DETERMINISTIC_EXPERIMENT_SKELETON` | `Track A` | 84 Scenarios | 84 | **Causal Intervention (Core)** |
| **C2** | `DETERMINISTIC_EXPERIMENT_SKELETON` | `Track D` | 84 Scenarios | 84 | **Causal Intervention (Context Factor)** |
| **C3** | `BASELINE_EXISTING_ARCHITECTURE` | `Track A` | 84 Scenarios | 84 | **Concurrent Causal Control** |
| **C4** | `BASELINE_EXISTING_ARCHITECTURE` | `Track D` | 84 Scenarios | 84 | **Concurrent Causal Control** |

- **Total Scheduled Calls**: Exactly **336 calls** (84 scenarios $\times$ 4 conditions).
- **Scenario Ordering**: Fixed deterministic order based on alphabetical sort of `scenario_id`.
- **Call Execution**: Strictly sequential, local-only execution. Exactly one attempt per call; zero retries; zero semantic repairs.

### 2.1 Deterministic Pseudo-Randomized Condition Ordering

To prevent systematic execution-order, warm-up, Ollama daemon state, or cache-confounding biases across the four conditions, per-scenario condition execution order is pseudo-randomized deterministically prior to inference:

1. **Frozen Randomization Seed**:
   $$\text{FROZEN\_ORDER\_RANDOMIZATION\_SEED} = \texttt{"M5\_PHASE10\_FACTORIAL\_ORDER\_SEED\_42"}$$

2. **Deterministic Shuffle Algorithm**:
   For each scenario $s$ in the 84-scenario benchmark population:
   $$\text{payload} = \text{UTF-8}\left(\text{FROZEN\_ORDER\_RANDOMIZATION\_SEED} \mathbin{\Vert} \texttt{":"} \mathbin{\Vert} s.\text{scenario\_id}\right)$$
   $$\text{order\_seed} = \text{int}\left(\text{SHA256}(\text{payload})[0:16], 16\right)$$
   $$\text{order}_s = \text{Shuffle}\left([C1, C2, C3, C4], \text{PRNG}(\text{order\_seed})\right)$$

3. **Methodological Invariants & Guarantees**:
   - **Pre-Scheduled Determinism**: The condition order for every scenario is fully determined before inference begins; it is 100% reproducible across machines and runs.
   - **Zero Adaptive Bias**: Execution order is strictly independent of model outputs, completion status, errors, timeouts, or prior scenario outcomes.
   - **Complete & Exact Scheduling**: Each scenario executes all four conditions ($C1, C2, C3, C4$) exactly once. Zero conditions are omitted, zero duplicates are introduced, and total scheduled calls remain invariant at exactly 336 calls ($84 \times 4$).
   - **Telemetry Tracking**: Every checkpoint and raw result artifact explicitly records `scenario_condition_order`, `condition_order_index` (1 through 4), and `order_randomization_seed`.

---

## 3. Causal vs. Diagnostic vs. Historical Comparisons

### 3.1 Causal Comparisons (Internal to Phase 10)
All 4 conditions execute under identical runtime, model, prompt engine, and timeout parameters within Phase 10:
- **Architecture Effect**: $(C1 + C2)$ vs. $(C3 + C4)$ tests the causal effect of the deterministic skeleton.
- **Context Effect**: $(C1 + C3)$ vs. $(C2 + C4)$ tests the causal effect of context volume and RAG knowledge retrieval.
- **Architecture $\times$ Context Interaction**: $[(C1 - C3) - (C2 - C4)]$ tests whether the skeleton moderates context sensitivity.

### 3.2 Historical Reference Comparisons (Non-Causal / Observational)
- Comparing Phase 10 Baseline (C3/C4) with historical Phase 7 benchmark results ($0/336$ useful yield) is strictly an **observational historical reference comparison**.
- Key difference: Phase 7 operated with an unenforced 120-second client timeout; Phase 10 operates with an enforced 30-second dual wall-clock timeout.
- Historical data will be cited as prior context, never pooled into Phase 10 causal tests.

---

## 4. Frozen Runtime Configuration & Parameter Parity

All 336 calls in Phase 10 execute under identical, frozen runtime specifications:

- **Serving Framework**: Local Ollama daemon v0.34.1
- **Model**: `qwen2.5-coder:7b` (`Q4_K_M`)
- **Frozen Model Digest**: `dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364`
- **Context Window (`num_ctx`)**: **2048 tokens** (frozen to match Phase 7, 8, and 9; avoids context-window confounding).
- **Output Token Ceiling (`num_predict`)**: **300 tokens** (validated in Phase 9 sensitivity study).
- **Sampling Temperature**: `0.0` (greedy, deterministic).
- **Random Seed**: `42`.
- **Model Keep-Alive**: `"60m"`.
- **Network Bound**: Loopback only (`http://127.0.0.1:11434`), zero external API calls.

---

## 5. Hard Timeout Semantics & Cancellation Controls

Phase 10 enforces a strict dual-layer hard timeout ceiling:

1. **HTTP Request Timeout**: `httpx.Timeout(timeout=30.0, connect=5.0, read=30.0, write=5.0)`.
2. **Wall-Clock Deadline**: Recorded via `time.perf_counter()`. If wall-clock elapsed time reaches 30,000 ms, the request is aborted.
3. **Socket Teardown & In-Flight Abort**:
   - On timeout, the `httpx.Client` connection is explicitly closed (`client.close()`), tearing down the TCP socket.
   - Socket termination signals Ollama's Go HTTP handler (`r.Context().Done()`), triggering cancellation of the underlying model runner slot.
4. **Cancellation Tolerance Bound**:
   - Hard deadline: 30,000 ms.
   - Grace period for teardown/cleanup: $\le 500\text{ ms}$ (maximum permissible recorded duration: 30,500 ms).
5. **Classification**:
   - Timed-out calls are classified strictly as `PrimaryFailureCategory.RUNTIME_TIMEOUT`.
   - Timeouts are never recorded as syntax, parser, schema, or grounding failures.
6. **Telemetry**:
   - `timed_out: bool = True`
   - `total_latency_ms: float`
   - `inference_latency_ms: Union[float, str]` (derived from Ollama `eval_duration` in ns; recorded as `"unavailable"` if missing or timed out; never fabricated).
   - `prompt_build_latency_ms: float`
   - `response_parse_latency_ms: float`
   - `validation_latency_ms: float`

---

## 6. Estimands & Metric Definitions

### 6.1 Estimand Hierarchy
- **Project Primary Estimand**:
  $$\text{Useful Hypothesis Yield @ } N \text{ reviewer minutes}$$
  *(Reserved exclusively for evaluations with directly measured human review time).*
- **Phase 10 Automated Capability Proxy (Primary Capability Estimand)**:
  $$\text{Valid Typed Experiment Rate} = \frac{\text{Valid Typed Experiment Proposals}}{\text{Candidate HYPOTHESIS Attempts}}$$
- **Automated Useful Vulnerable Hypothesis Rate**:
  $$\text{Automated Useful Hypothesis Rate} = \frac{\text{Useful Vulnerable Hypotheses}}{36}$$
  *(Evaluated across the 36 ground-truth vulnerable scenarios in the benchmark).*

---

### 6.2 Decomposed Metrics: Semantic Detection vs. Protocol Failures

To prevent confounding security reasoning with parser/schema/infrastructure errors, metrics are decoupled:

#### A. Semantic Detection Outcomes (Evaluated on Structurally Valid Outputs)
- **Semantic TP**: Vulnerable scenario where model outputs `HYPOTHESIS` with valid polarity and actionable experiment confirming breach.
- **Semantic FP**: Control scenario where model outputs `HYPOTHESIS` alleging breach.
- **Semantic TN**: Control scenario where model outputs valid `INSUFFICIENT_EVIDENCE` or `NO_RELEVANT_FUNCTIONALITY`.
- **Semantic FN**: Vulnerable scenario where model outputs valid `INSUFFICIENT_EVIDENCE` or `NO_RELEVANT_FUNCTIONALITY` (abstention on vulnerable target).
- **$\text{Semantic TPR} = \frac{\text{Semantic TP}}{\text{Semantic TP} + \text{Semantic FN}}$**
- **$\text{Semantic TNR} = \frac{\text{Semantic TN}}{\text{Semantic TN} + \text{Semantic FP}}$**
- **$\text{Semantic Precision} = \frac{\text{Semantic TP}}{\text{Semantic TP} + \text{Semantic FP}}$** (with Wilson score 95% CIs).

#### B. Protocol & Runtime Failures (Orthogonal Failure Modes)
- `SCHEMA_VALIDITY_FAILURE`: Fails JSON schema validation.
- `PARSER_FAILURE`: Malformed / unparseable JSON.
- `SEMANTIC_GROUNDING_FAILURE`: Unbound identifiers or facts.
- `SEMANTIC_EXPERIMENT_POLARITY_FAILURE`: Inverted breach/safe predicates.
- `CATEGORY_ACTION_INCOMPATIBILITY`: Action unapproved for category.
- `RUNTIME_TIMEOUT`: Exceeded 30,000 ms wall-clock ceiling.
- `RUNTIME_TRANSPORT_FAILURE`: Non-timeout socket error.

#### C. Operational Compound Metrics (Combined End-to-End Delivery)
- $\text{Operational TP} = \text{Semantic TP}$
- $\text{Operational FP} = \text{Semantic FP}$
- $\text{Operational TN} = \text{Semantic TN}$
- $\text{Operational FN} = \text{Semantic FN} + \text{Protocol Failures on Vulnerable} + \text{Timeouts on Vulnerable}$
- $\text{Operational Yield} = \frac{\text{Operational TP}}{36}$

---

## 7. Statistical Hypotheses & Testing Plan

### 7.1 Primary Hypothesis Test
- **$H_0$**: $\text{Valid Typed Experiment Rate}_{\text{Skeleton}} = \text{Valid Typed Experiment Rate}_{\text{Baseline}}$
- **$H_1$**: $\text{Valid Typed Experiment Rate}_{\text{Skeleton}} > \text{Valid Typed Experiment Rate}_{\text{Baseline}}$
- **Test**: McNemar's exact test for paired binary outcomes across the 84 matched scenarios in Track A (and Track D). Significance threshold: $\alpha = 0.05$.
- **Confidence Intervals**: 95% Wilson score intervals for all binomial proportions.

---

## 8. Checkpointing, Preflight, & Stopping Rules

### 8.1 Atomic Checkpointing
- Checkpoints saved to `data/eval/m5_phase10_checkpoint.json` after every individual call.
- Checkpoint fields: `scenario_id`, `condition_id`, `track_id`, `call_index`, `model_digest`, `config_hash`, `prompt_hash`, `evidence_hash`, `start_time`, `end_time`, `timed_out`, `raw_response`, `parsed_intermediate`, `classification`, `policy_decision`.
- Zero duplicate calls. Zero in-flight re-runs.

### 8.2 Preflight Gates (Must Pass Before Call #1)
1. Clean Git working tree (`git status --porcelain` empty).
2. Git HEAD matches expected post-audit commit.
3. 4 frozen artifact SHA-256 hashes match bit-for-bit:
   - Phase 7: `1e0ed90c4aa672f135d2d2f2240a14d22fa0037c03efda33634f4bf10ff0b125`
   - Phase 8: `b1df9a62fb07d76e0abf6e3935ccbabdaa1713f4c594019ae30c9e59567a45c6`
   - Phase 9: `3c0d3e503c7ed24470b14dfde0bd763c631a9b5dbf70c047bbca72cfaab07f95`
   - Scenarios: `102789655bfb04041de9259d1bf6db7f088979e5bce9bac9eb050564ef0110a8`
4. Ollama daemon online, version 0.34.1.
5. Model `qwen2.5-coder:7b` present with exact digest `dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364`.
6. Verified parameters: `num_ctx=2048`, `num_predict=300`, `temperature=0.0`, `seed=42`, `timeout=30.0s`, `max_retries=0`.

### 8.3 Stopping Rules
- If any frozen historical file hash changes: **HALT IMMEDIATELY**.
- If any live call exceeds 30,500 ms wall clock: **HALT IMMEDIATELY**.
- If checkpoint integrity validation fails: **HALT AND FAIL CLOSED**.
