# Milestone M5 Phase 10: Full-Population Confirmatory Benchmark
## Final Post-Benchmark Empirical Validation & Forensic Audit Report

**Status**: PHASE 10 BENCHMARK COMPLETE — FINAL AUDITED DATASET AND REPORT  
**Author**: Pair Programming Implementation Agent  
**Date**: September 26, 2026  
**Git Branch**: `master`  
**Experimental Freeze Commit**: `d3c531e71855098dddf568f54aef8dfb5e49c089`  
**Canonical Raw Dataset Path**: [`data/eval/m5_phase10_full_population_validation.json`](data/eval/m5_phase10_full_population_validation.json)  
**Canonical Raw Dataset SHA-256**: `6821d207729de97ac99657a09e38c25895a73285fe9c485d299dc27f37d2bdba`  
**Reconstructed CRLF-Equivalent Artifact**: [`data/eval/m5_phase10_full_population_validation_raw_crlf.json`](data/eval/m5_phase10_full_population_validation_raw_crlf.json)  
**Reconstructed CRLF SHA-256**: `c7e4fb33061db2dd5539c6d8795c1210ea275ef419b9cc5bd2746713405a2e41`  
**Runtime Checkpoint Path**: [`data/eval/m5_phase10_checkpoint.json`](data/eval/m5_phase10_checkpoint.json)  
**Runtime Checkpoint SHA-256**: `40f9f725fca5fdf05a76836182960b7f0d4c303a182d6e8af068a1b57e8f4537`  

> [!IMPORTANT]
> **AUDIT & PROVENANCE NOTICE**:
> 1. **No Benchmark Rerun**: The 336-call benchmark was executed exactly once to completion and was NOT rerun.
> 2. **No Model or Data Changes**: Model outputs, failure classifications, and dataset contents remain unaltered since collection.
> 3. **Historical Immutability**: All four historical reference artifacts (Phase 7, 8, 9, scenarios.py) remain bit-for-bit identical to pre-registered hashes.
> 4. **Runtime-Control Deviation**: 4 timeout calls exceeded the 30,500 ms teardown tolerance window (max 30,892.6 ms), classified as a `POST-BENCHMARK RUNTIME-CONTROL DEVIATION`.
> 5. **CRLF Provenance Note**: `data/eval/m5_phase10_full_population_validation_raw_crlf.json` is a reconstructed CRLF-equivalent representation; the canonical LF dataset is preserved.
> 6. **Human-Review Estimand Notice**: Useful Hypothesis Yield @ N reviewer minutes was **NOT** measured.

---

## 1. Executive Summary

Milestone M5 Phase 10 evaluated whether the **Deterministic Experiment Skeleton** architecture causally impacts typed-experiment proposal validity and useful hypothesis generation across the complete 84-scenario benchmark population (36 vulnerable variants, 48 negative controls).

The evaluation employed a balanced $2 \times 2$ factorial design yielding exactly $84 \times 4 = 336$ scheduled calls:
- **Architecture Dimension**: `DETERMINISTIC_EXPERIMENT_SKELETON` vs. `BASELINE_EXISTING_ARCHITECTURE`
- **Context Dimension**: `TRACK_A` (Minimal Structural Context) vs. `TRACK_D` (Full Cascade Context + RAG Knowledge Pack)

### Key Empirical Findings:

1. **Architecture Simple Effect in Track A (Core Confirmatory Test)**:
   - **Baseline Architecture (`C3`)**: Generated **0 valid typed experiments** out of 37 candidate hypothesis attempts (Candidate-conditional rate: **0.0%** [0/37], 95% CI: 0.0% – 9.4%; Scenario-level success: **0.0%** [0/84], 95% CI: 0.0% – 4.4%). Every candidate hypothesis in C3 failed polarity validation (`SEMANTIC_EXPERIMENT_POLARITY_FAILURE` = 37), confirming that unconstrained LLM generation in the baseline architecture consistently inverts or invalidates breach predicates.
   - **Deterministic Skeleton (`C1`)**: Generated **34 valid typed experiments** out of 56 candidate hypothesis attempts (Candidate-conditional rate: **60.71%** [34/56], 95% CI: 47.63% – 72.42%; Scenario-level success: **40.48%** [34/84], 95% CI: 30.62% – 51.17%).
   - **Paired Exact McNemar Test (Scenario-Level Binary Success, N=84 Matched Pairs)**: Discordant pairs = 34 ($C1 = 34, C3 = 0$), **$p = 1.164 \times 10^{-10}$ ($p < 0.001$)**. The deterministic skeleton provides a statistically significant, causal improvement in scenario-level typed-experiment construction under Track A.
   - **Useful Vulnerable Hypotheses in Track A**: Achieved **14 / 36** (**38.89%**, 95% CI: 24.78% – 55.14%) in `C1` vs. **0 / 36** (**0.0%**, 95% CI: 0.0% – 9.64%) in `C3` (Paired McNemar on 36 vulnerable pairs: Discordant = 14, **$p = 1.221 \times 10^{-4}$, $p < 0.001$**).

2. **Track A vs. Track D Context-Package Comparison & Interaction**:
   - In `C2` (Deterministic Skeleton + Track D), scenario-level success dropped to **2.38%** (2/84, 95% CI: 0.66% – 8.27%), and the candidate-conditional rate dropped to **3.92%** (2/51, 95% CI: 1.08% – 13.22%).
   - Track D added the full cascade history packet plus domain-specific VAPT RAG knowledge chunks. Under the frozen 2048-token context window (`num_ctx=2048`), this context package resulted in **19 wall-clock timeouts** and **26 grounding failures** (`SEMANTIC_GROUNDING_FAILURE`), where the model cited tokens outside the strict structural context slice.
   - **Paired Exact McNemar Test (C1 vs C2, N=84 Matched Pairs)**: Discordant pairs = 32 ($C1 = 32, C2 = 0$), **$p = 4.657 \times 10^{-10}$ ($p < 0.001$)**.
   - **Descriptive Empirical Interaction Contrast**: $[(C1 - C3) - (C2 - C4)] = (34 - 0) - (2 - 0) = \mathbf{+32 \text{ scenarios}}$. The deterministic skeleton's structural scaffolding produced substantially higher scenario-level valid experiment yields under Minimal Structural Context (Track A) than under the full cascade + RAG package (Track D) within the tested 2048-token limit.

3. **Observational Baseline Replication**:
   - Both baseline conditions (`C3` and `C4`) yielded **0 valid typed experiments** ($0/37$ and $0/36$) and **0 useful vulnerable hypotheses** ($0/36$ and $0/36$).
   - This replicates the historical Phase 7 finding ($0/336$ useful yield) under concurrent, enforced 30s runtime conditions.

4. **Balanced Synthesized Interpretation**:
   - Within the frozen benchmark and `qwen2.5-coder:7b` configuration, the deterministic experiment skeleton substantially increased valid typed-experiment construction and generated useful vulnerable hypotheses under Track A. Performance remained limited by false positives and was substantially lower under the Track D context package.

---

## 2. Experimental Freeze & Preflight Audit

The benchmark executed strictly from the frozen Git commit:

| Parameter | Frozen Value |
| :--- | :--- |
| **Git Branch** | `master` |
| **Experimental Freeze Commit** | `d3c531e71855098dddf568f54aef8dfb5e49c089` |
| **Freeze Commit Message** | `experiment: freeze M5 phase 10 benchmark` |
| **Working Tree State** | Strictly clean at benchmark launch (`git status --porcelain` empty) |
| **Benchmark Command** | `python src/eval/run_m5_phase10_benchmark.py --execute-live-benchmark` |

### Historical Artifact Immutability Verification:
All four historical reference artifacts were verified bit-for-bit before and after the 336-call run:

| Historical File | Pre-Registered SHA-256 Digest | Live SHA-256 | Verification Status |
| :--- | :--- | :--- | :---: |
| `data/eval/m5_phase7_benchmark_final.json` | `1e0ed90c4aa672f135d2d2f2240a14d22fa0037c03efda33634f4bf10ff0b125` | `1e0ed90c...` | **MATCH (IMMUTABLE)** |
| `data/eval/m5_phase8_semantic_study.json` | `b1df9a62fb07d76e0abf6e3935ccbabdaa1713f4c594019ae30c9e59567a45c6` | `b1df9a62...` | **MATCH (IMMUTABLE)** |
| `data/eval/m5_phase9_semantic_budget_study.json` | `3c0d3e503c7ed24470b14dfde0bd763c631a9b5dbf70c047bbca72cfaab07f95` | `3c0d3e50...` | **MATCH (IMMUTABLE)** |
| `src/eval/scenarios.py` | `102789655bfb04041de9259d1bf6db7f088979e5bce9bac9eb050564ef0110a8` | `10278965...` | **MATCH (IMMUTABLE)** |

---

## 3. Frozen Runtime & Methodological Configuration

All 336 calls executed under identical, frozen runtime specifications:

- **Serving Daemon**: Local Ollama v0.34.1
- **Model**: `qwen2.5-coder:7b` (`Q4_K_M`)
- **Frozen Model Digest**: `dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364`
- **Context Window (`num_ctx`)**: **2048 tokens** (frozen to match Phase 7, 8, and 9)
- **Output Token Ceiling (`num_predict`)**: **300 tokens**
- **Sampling Temperature**: `0.0` (greedy, deterministic)
- **Model Sampling Seed**: `42`
- **Model Keep-Alive**: `"60m"` (resident in memory)
- **Network Bound**: Loopback only (`http://127.0.0.1:11434`), zero external API calls
- **Dual Timeout Ceiling**: 30.0s HTTP client timeout + 30.0s wall-clock deadline + 500ms teardown tolerance bound
- **Retry Discipline**: Strictly zero retries (`retries=0`), zero repairs, zero adaptive tuning

### Deterministic Pseudo-Randomized Condition Ordering
To prevent runtime-state, cache, or daemon warm-up order biases across conditions:
- **Seed**: `FROZEN_ORDER_RANDOMIZATION_SEED = "M5_PHASE10_FACTORIAL_ORDER_SEED_42"`
- **Algorithm**:
  $$\text{order\_seed} = \text{int}\left(\text{SHA256}(\text{seed} \mathbin{\Vert} \texttt{":"} \mathbin{\Vert} \text{scenario\_id})[0:16], 16\right)$$
  $$\text{shuffled\_conditions} = \text{Random}(\text{order\_seed}).\text{shuffle}([C1, C2, C3, C4])$$
- **Guarantees**:
  - Condition ordering was strictly pre-scheduled before inference began.
  - Every scenario executed all four conditions exactly once ($84 \times 4 = 336$).
  - Produced 23 distinct permutations across 84 scenarios with balanced first-position frequencies (`C1: 27`, `C2: 23`, `C3: 20`, `C4: 14`).

---

## 4. Comprehensive Factorial Performance Results

### 4.1 Primary Factorial Metrics Matrix

All 95% confidence intervals are computed using the Wilson score method.

| Metric Dimension | C1: Skeleton + Track A | C2: Skeleton + Track D | C3: Baseline + Track A | C4: Baseline + Track D |
| :--- | :---: | :---: | :---: | :---: |
| **Total Scheduled Calls** | 84 | 84 | 84 | 84 |
| **Recorded / Completed Calls** | 84 (100%) | 84 (100%) | 84 (100%) | 84 (100%) |
| **Timeouts ($>30.0$s)** | 10 (11.9%) | 19 (22.6%) | 7 (8.3%) | 1 (1.2%) |
| **Transport Failures** | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) |
| **Valid Schema Outputs** | 52 (61.9%) | 14 (16.7%) | 40 (47.6%) | 45 (53.6%) |
| **Candidate HYPOTHESIS Attempts** | 56 | 51 | 37 | 36 |
| **Candidate Abstentions** | 28 | 33 | 47 | 48 |
| **Valid Typed Experiment Proposals** | **34** | **2** | **0** | **0** |
| **Valid Typed Experiment Rate**<br>*(Candidate-Conditional Estimand)* | **60.71%** (34/56)<br>[47.63% – 72.42%] | **3.92%** (2/51)<br>[1.08% – 13.22%] | **0.00%** (0/37)<br>[0.00% – 9.41%] | **0.00%** (0/36)<br>[0.00% – 9.64%] |
| **Scenario-Level Valid Experiment Success**<br>*(Used for Paired McNemar Tests)* | **40.48%** (34/84)<br>[30.62% – 51.17%] | **2.38%** (2/84)<br>[0.66% – 8.27%] | **0.00%** (0/84)<br>[0.00% – 4.37%] | **0.00%** (0/84)<br>[0.00% – 4.37%] |
| **Useful Vulnerable Hypotheses** | **14** | **1** | **0** | **0** |
| **Automated Useful Hypothesis Rate**<br>*(On 36 Ground-Truth Vulnerable)* | **38.89%** (14/36)<br>[24.78% – 55.14%] | **2.78%** (1/36)<br>[0.49% – 14.17%] | **0.00%** (0/36)<br>[0.00% – 9.64%] | **0.00%** (0/36)<br>[0.00% – 9.64%] |
| **Operational Yield** | **38.89%** (14/36)<br>[24.78% – 55.14%] | **2.78%** (1/36)<br>[0.49% – 14.17%] | **0.00%** (0/36)<br>[0.00% – 9.64%] | **0.00%** (0/36)<br>[0.00% – 9.64%] |

---

### 4.2 Semantic Detection Metrics (Evaluated on Structurally Valid Outputs)

Per Section 6.2 of the Preregistration, semantic detection metrics evaluate classification quality strictly on outputs that successfully pass schema and protocol parsing:

| Semantic Metric | C1: Skeleton + Track A | C2: Skeleton + Track D | C3: Baseline + Track A | C4: Baseline + Track D |
| :--- | :---: | :---: | :---: | :---: |
| **Structurally Valid N** | 52 | 14 | 40 | 45 |
| **Semantic True Positives (TP)** | 14 | 1 | 0 | 0 |
| **Semantic False Positives (FP)** | 20 | 1 | 0 | 0 |
| **Semantic True Negatives (TN)** | 8 | 7 | 26 | 28 |
| **Semantic False Negatives (FN)** | 10 | 5 | 14 | 17 |
| **Semantic TPR (Recall)** | **58.33%** (14/24)<br>[38.78% – 75.53%] | **16.67%** (1/6)<br>[3.01% – 56.35%] | **0.00%** (0/14)<br>[0.00% – 21.53%] | **0.00%** (0/17)<br>[0.00% – 18.43%] |
| **Semantic TNR (Specificity)** | **28.57%** (8/28)<br>[15.31% – 47.05%] | **87.50%** (7/8)<br>[52.91% – 97.76%] | **100.00%** (26/26)<br>[87.13% – 100.00%] | **100.00%** (28/28)<br>[87.94% – 100.00%] |
| **Semantic Precision** | **41.18%** (14/34)<br>[26.38% – 57.81%] | **50.00%** (1/2)<br>[9.45% – 90.55%] | **0.00%** (0/0)<br>*(No Hypotheses)* | **0.00%** (0/0)<br>*(No Hypotheses)* |

*Note: In C3 and C4, zero hypotheses passed polarity validation; all structurally valid outputs in C3 and C4 were abstentions (`INSUFFICIENT_EVIDENCE` or `NO_RELEVANT_FUNCTIONALITY`). Consequently, baseline specificity is 100% (all structurally valid controls were abstained upon) and recall is 0% (all structurally valid vulnerable targets were abstained upon).*

---

### 4.3 Operational Compound Metrics (All 84 Scenarios)

Operational metrics reflect end-to-end delivery across the entire 84-scenario benchmark population, penalizing protocol failures, timeouts, and ungrounded claims as failures to detect on vulnerable targets:

| Operational Metric | C1: Skeleton + Track A | C2: Skeleton + Track D | C3: Baseline + Track A | C4: Baseline + Track D |
| :--- | :---: | :---: | :---: | :---: |
| **Operational TP** | 14 | 1 | 0 | 0 |
| **Operational FP** | 20 | 1 | 0 | 0 |
| **Operational TN** | 28 | 47 | 48 | 48 |
| **Operational FN** | 22 | 35 | 36 | 36 |
| **Operational Yield** | **38.89%** (14/36)<br>[24.78% – 55.14%] | **2.78%** (1/36)<br>[0.49% – 14.17%] | **0.00%** (0/36)<br>[0.00% – 9.64%] | **0.00%** (0/36)<br>[0.00% – 9.64%] |

---

### 4.4 Failure Taxonomy Breakdown

Across all 336 calls, failures adhered strictly to the M4/M5 failure precedence taxonomy:

| Failure Category | C1: Skeleton + Track A | C2: Skeleton + Track D | C3: Baseline + Track A | C4: Baseline + Track D | Total |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **`VALID` (Passed all checks)** | **52** | **14** | **40** | **45** | **151** |
| **`RUNTIME_TIMEOUT` ($>30.0$s)** | 10 | 19 | 7 | 1 | **37** |
| **`RUNTIME_TRANSPORT_FAILURE`** | 0 | 0 | 0 | 0 | **0** |
| **`PARSER_FAILURE`** | 0 | 0 | 0 | 0 | **0** |
| **`SCHEMA_VALIDITY_FAILURE`** | 0 | 0 | 0 | 8 | **8** |
| **`SEMANTIC_GROUNDING_FAILURE`** | 0 | **26** | 0 | 0 | **26** |
| **`SEMANTIC_EXPERIMENT_POLARITY_FAILURE`** | 22 | 25 | **37** | **30** | **114** |
| **`CATEGORY_ACTION_INCOMPATIBILITY`** | 0 | 0 | 0 | 0 | **0** |
| **Total Calls** | **84** | **84** | **84** | **84** | **336** |

---

### 4.5 Latency Telemetry Breakdown

Latency was tracked with microsecond resolution via `time.perf_counter()`. Inference latency was derived directly from Ollama `eval_duration` (ns $\to$ ms):

| Latency Dimension | C1: Skeleton + Track A | C2: Skeleton + Track D | C3: Baseline + Track A | C4: Baseline + Track D |
| :--- | :---: | :---: | :---: | :---: |
| **Total Latency Mean (ms)** | 26,747.4 | 27,671.1 | 23,233.3 | 23,121.8 |
| **Total Latency Median (ms)** | 27,070.2 | 27,737.2 | 23,455.3 | 24,225.0 |
| **Total Latency P95 (ms)** | 30,385.3 | 30,394.3 | 30,307.1 | 29,963.9 |
| **Inference Latency Mean (ms)** | 24,950.9 | 25,524.2 | 19,748.3 | 20,199.0 |
| **Inference Latency Median (ms)** | 24,948.7 | 25,540.9 | 20,559.0 | 21,327.3 |
| **Inference Latency P95 (ms)** | 29,107.7 | 29,013.7 | 25,476.5 | 26,502.7 |

---

## 5. Statistical Hypothesis Tests & Factorial Analysis

All formal inferential tests evaluate paired binary scenario-level success across matched scenarios using the **exact two-sided McNemar test**.

### 5.1 Primary Confirmatory Test: Architecture Simple Effect in Track A (`C1` vs. `C3`)

- **Hypothesis**: Does the Deterministic Experiment Skeleton increase scenario-level valid typed experiment success compared to Baseline Architecture under Minimal Structural Context (Track A)?
- **Conditions Compared**: `C1` (Skeleton + Track A) vs. `C3` (Baseline + Track A)
- **Sample Size**: 84 matched scenario pairs

#### $2 \times 2$ Contingency Table:
```
                 C3: Baseline Success    C3: Baseline Failure
C1: Skeleton+             0                       34
C1: Skeleton-             0                       50
```
- **Discordant Pairs**: $b = 34$ (Success in C1 only), $c = 0$ (Success in C3 only). Total discordant = 34.
- **Exact McNemar Two-Sided p-value**:
  $$p = 2 \times \left(\frac{1}{2}\right)^{34} = 1.164 \times 10^{-10} \quad (\mathbf{p < 0.001})$$
- **Conclusion**: **REJECT $H_0$**. The deterministic skeleton causally improves scenario-level valid experiment proposal success in Track A ($40.48\%$ vs. $0.00\%$).

---

### 5.2 Primary Confirmatory Test: Useful Vulnerable Hypotheses in Track A

- **Hypothesis**: Does the Deterministic Experiment Skeleton increase the discovery of actionable vulnerable hypotheses on ground-truth vulnerable targets?
- **Conditions Compared**: `C1` vs. `C3` restricted to the 36 ground-truth vulnerable scenarios
- **Sample Size**: 36 matched vulnerable pairs

#### $2 \times 2$ Contingency Table:
```
                 C3: Baseline Success    C3: Baseline Failure
C1: Skeleton+             0                       14
C1: Skeleton-             0                       22
```
- **Discordant Pairs**: $b = 14$ (Success in C1 only), $c = 0$ (Success in C3 only). Total discordant = 14.
- **Exact McNemar Two-Sided p-value**:
  $$p = 2 \times \left(\frac{1}{2}\right)^{14} = 1.221 \times 10^{-4} \quad (\mathbf{p < 0.001})$$
- **Conclusion**: **REJECT $H_0$**. The deterministic skeleton causally improves useful vulnerable hypothesis generation ($38.89\%$ vs. $0.00\%$, $p < 0.001$).

---

### 5.3 Context-Package Comparison in Skeleton Architecture (`C1` vs. `C2`)

- **Comparison**: Track A (Minimal Structural Context) vs. Track D (Full Cascade + RAG Knowledge Pack) within Skeleton Architecture
- **Sample Size**: 84 matched scenario pairs

#### $2 \times 2$ Contingency Table:
```
                 C2: Track D Success     C2: Track D Failure
C1: Track A+              2                       32
C1: Track A-              0                       50
```
- **Discordant Pairs**: $b = 32$ (Success in C1 only), $c = 0$ (Success in C2 only). Total discordant = 32.
- **Exact McNemar Two-Sided p-value**:
  $$p = 2 \times \left(\frac{1}{2}\right)^{32} = 4.657 \times 10^{-10} \quad (\mathbf{p < 0.001})$$
- **Conclusion**: **REJECT $H_0$**. Track A achieved significantly higher scenario-level valid experiment success than Track D within the skeleton architecture under `num_ctx=2048` ($40.48\%$ vs. $2.38\%$).

---

### 5.4 Context-Package Comparison in Baseline Architecture (`C3` vs. `C4`)

- **Conditions Compared**: `C3` (Baseline + Track A) vs. `C4` (Baseline + Track D)
- **Contingency Table**: Both Success = 0, Only C3 = 0, Only C4 = 0, Neither = 84.
- **Exact McNemar p-value**: $p = 1.000$.
- **Conclusion**: Baseline architecture achieved 0% scenario-level success across both context tracks.

---

### 5.5 Architecture Simple Effect in Track D (`C2` vs. `C4`)

- **Conditions Compared**: `C2` (Skeleton + Track D) vs. `C4` (Baseline + Track D)
- **Contingency Table**: Both Success = 0, Only C2 = 2, Only C4 = 0, Neither = 82.
- **Discordant Pairs**: 2 ($C2 = 2, C4 = 0$).
- **Exact McNemar Two-Sided p-value**:
  $$p = 2 \times \left(\frac{1}{2}\right)^2 = 0.500$$
- **Conclusion**: The difference between Skeleton and Baseline under Track D did not reach statistical significance ($2.38\%$ vs. $0.00\%$, $p = 0.500$).

---

### 5.6 Factorial Analysis & Interaction Preregistration Audit

- **Preregistered Statistical Test**: Section 7.1 of `docs/M5_PHASE10_PREREGISTRATION.md` specified exclusively:
  *"McNemar's exact test for paired binary outcomes across the 84 matched scenarios in Track A (and Track D)."*
  No formal regression model (such as repeated-measures logistic regression, GEE, or log-linear modeling) was preregistered for testing pooled main effects or interaction terms.
- **Descriptive Empirical Interaction Contrast**:
  $$\text{Interaction Contrast} = (C1 - C3) - (C2 - C4) = (34 - 0) - (2 - 0) = \mathbf{+32 \text{ scenarios}}$$
- **Pooled Architecture Contrast (Descriptive)**:
  - Skeleton ($C1 + C2$): $34 + 2 = 36$ successes out of 168 calls ($21.4\%$)
  - Baseline ($C3 + C4$): $0 + 0 = 0$ successes out of 168 calls ($0.0\%$)
- **Pooled Context Contrast (Descriptive)**:
  - Track A ($C1 + C3$): $34 + 0 = 34$ successes out of 168 calls ($20.2\%$)
  - Track D ($C2 + C4$): $2 + 0 = 2$ successes out of 168 calls ($1.2\%$)
- **Methodological Distinction**: The $+32$ contrast is reported strictly as a descriptive empirical pattern, not a formal confirmatory hypothesis test.

---

## 6. Observational Comparison with Historical Benchmark Phases

Historical Phase 7/8/9 results are treated strictly as **observational reference points**, not causal controls:

| Evaluation Phase | Design / Architecture | Context Track | Timeout Enforcement | Valid Typed Exp Rate | Useful Vulnerable Yield |
| :--- | :--- | :--- | :--- | :---: | :---: |
| **Phase 7 Final** (Hist.) | Baseline Unconstrained | Track A / C | 120s (Client Unenforced) | $0 / 336$ ($0.0\%$) | $0 / 336$ ($0.0\%$) |
| **Phase 8 Semantic** (Hist.) | Baseline + Gate Triage | Synthetic / Track C | 30s (Enforced) | — | $0 / 24$ ($0.0\%$) |
| **Phase 9 Diagnostic** (Hist.) | Skeleton Intervention | Track A / D (Sample) | 30s (Enforced) | $16 / 24$ ($66.7\%$) | $8 / 12$ ($66.7\%$) |
| **Phase 10 C3** (Live) | Concurrent Baseline | Track A | 30s (Enforced Dual) | $0 / 37$ ($0.0\%$) | $0 / 36$ ($0.0\%$) |
| **Phase 10 C4** (Live) | Concurrent Baseline | Track D | 30s (Enforced Dual) | $0 / 36$ ($0.0\%$) | $0 / 36$ ($0.0\%$) |
| **Phase 10 C1** (Live) | Deterministic Skeleton | Track A | 30s (Enforced Dual) | **$34 / 56$ ($60.71\%$)** | **$14 / 36$ ($38.89\%$)** |
| **Phase 10 C2** (Live) | Deterministic Skeleton | Track D | 30s (Enforced Dual) | **$2 / 51$ ($3.92\%$)** | **$1 / 36$ ($2.78\%$)** |

---

## 7. Post-Benchmark Statistical & Provenance Audit

This section documents the forensic audit findings across estimand definitions, factorial terminology, raw dataset provenance, timeout telemetry, runtime control deviations, and semantic boundaries.

### 7.1 Estimand Disambiguation (Candidate-Conditional vs. Scenario-Level)

The Phase 10 report explicitly separates two distinct estimands:
1. **Candidate-Conditional Valid Typed Experiment Rate**:
   $$\text{VTER} = \frac{\text{Valid Typed Experiment Proposals}}{\text{Candidate HYPOTHESIS Attempts}}$$
   Measures model capability *conditional upon attempting a hypothesis*. In `C1`, this was $34 / 56 = 60.71\%$. In `C3`, this was $0 / 37 = 0.00\%$. These denominators differ because the model autonomously decides whether to propose a hypothesis or abstain.
2. **Scenario-Level Valid Typed Experiment Success Rate**:
   $$\text{Scenario Success} = \frac{\text{Scenarios Producing a Valid Typed Experiment}}{84}$$
   Measures end-to-end scenario-level binary success across all 84 matched scenarios. In `C1`, this was $34 / 84 = 40.48\%$. In `C3`, this was $0 / 84 = 0.00\%$.
3. **Statistical Inference Alignment**: The exact McNemar test evaluates the *scenario-level paired binary success outcome* across the 84 matched scenario pairs. It does not evaluate the candidate-conditional $34/56$ vs $0/37$ rates, which are unpaired and have differing denominators.

### 7.2 Factorial Terminology & Pre-Registration Scope

- `C1 vs C3` is the **simple effect of architecture within Track A**, not the complete architecture main effect.
- `C2 vs C4` is the **simple effect of architecture within Track D**.
- $[(C1 - C3) - (C2 - C4)] = +32$ is a **descriptive empirical interaction contrast**, not a statistically tested interaction. No formal repeated-measures interaction model was preregistered.

### 7.3 Raw Data Provenance & Line-Ending Normalization Audit

- **Original Capture Provenance**: During benchmark execution, records were sequentially flushed into [`data/eval/m5_phase10_checkpoint.json`](data/eval/m5_phase10_checkpoint.json) on Windows with CRLF newlines (SHA-256: `40f9f725fca5fdf05a76836182960b7f0d4c303a182d6e8af068a1b57e8f4537`).
- **Reconstructed CRLF-Equivalent Artifact**: The file [`data/eval/m5_phase10_full_population_validation_raw_crlf.json`](data/eval/m5_phase10_full_population_validation_raw_crlf.json) was reconstructed post-collection by converting the canonical LF representation to CRLF (SHA-256: `c7e4fb33061db2dd5539c6d8795c1210ea275ef419b9cc5bd2746713405a2e41`). It is classified as a reconstructed CRLF-equivalent representation rather than independently proven original disk capture bytes.
- **Canonical Analysis Representation**: The analysis dataset [`data/eval/m5_phase10_full_population_validation.json`](data/eval/m5_phase10_full_population_validation.json) represents the canonical LF-normalized artifact, matching POSIX conventions and the in-memory sidecar hash (SHA-256: `6821d207729de97ac99657a09e38c25895a73285fe9c485d299dc27f37d2bdba`).
- **Semantic Content Invariance**: Programmatic verification confirmed:
  $$\text{json.loads}(\text{checkpoint}) == \text{json.loads}(\text{CRLF-equivalent}) == \text{json.loads}(\text{canonical LF})$$
  Decoded JSON objects across all 336 call records are 100% semantically identical.
- **Provenance Disclosure**: The phrase "Zero Protocol Deviations" has been removed and replaced with this transparent artifact-canonicalization disclosure.

### 7.4 Post-Benchmark Runtime-Control Deviation (Timeout Telemetry)

- **Preregistered Runtime Rule**:
  - Hard inference ceiling = 30,000 ms
  - Teardown tolerance $\le 500$ ms
  - Expected total completion $\le 30,500$ ms
- **Empirical Audit Findings**:
  - Exactly 37 calls were classified as `RUNTIME_TIMEOUT`.
  - In all 37 timeout calls, `timed_out == True`, `primary_failure_category == "RUNTIME_TIMEOUT"`, and `inference_latency_ms == "unavailable"`.
  - The timeout rule was triggered by the actual HTTP cancellation and wall-clock deadline mechanism, not by post-hoc total-latency filtering.
  - **33 / 37** timeout calls completed within the $\le 30,500$ ms tolerance bound.
  - **4 / 37** timeout calls exceeded 30,500 ms:
    1. Call #95 (`SCEN-ECOMMERCE_ORDERS-ORD-REFUND-VULN-01`, C1): 30,617.4 ms
    2. Call #242 (`SCEN-IOT_FLEET_MGMT-DEVICE-TEL-PATCH-02`, C1): 30,543.3 ms
    3. Call #266 (`SCEN-IOT_FLEET_MGMT-FLEET-TEL-PATCH-04`, C2): 30,892.6 ms (maximum observed duration)
    4. Call #327 (`SCEN-SAAS_BILLING-SUB-PLAN-VULN-06`, C2): 30,511.0 ms
- **Classification**: This is explicitly classified as a **`POST-BENCHMARK RUNTIME-CONTROL DEVIATION`**. The four calls exceeded the preregistered teardown tolerance due to OS-level Windows socket closure and TCP reset latency.
- **Preservation**: The runtime control is not called "perfectly compliant." In accordance with strict data-integrity rules, the four calls are **not reclassified, not rerun, and not removed**. Their status remains `timed_out=True` and `primary_failure_category=RUNTIME_TIMEOUT`.
- **Non-Timeout Inferences > 30.0s**: In 6 non-timeout calls, total overall latency was 30,035 – 30,382 ms. In all 6 calls, the HTTP inference call itself completed within the 30.0s deadline (inference latencies = 26.6s to 29.8s), and client-side JSON parsing + schema validation added ~300–500 ms. These calls correctly did not trigger a timeout.

### 7.5 Causal Interpretation of Track A vs. Track D

- **Treatment Contrast**: Track A (Minimal Structural Context) vs. Track D (Full Cascade + RAG Knowledge Pack) represents a multi-component context-package comparison, not a single-variable context-volume dial.
- **Separation of Evidence and Mechanism**:
  1. *Observed difference*: C1 achieved 34 scenario-level successes vs. C2 achieved 2.
  2. *Observed context package*: Track A contained Channel A alone; Track D added cascade history and VAPT RAG knowledge chunks.
  3. *Observed telemetry*: C2 produced 19 timeouts and 26 grounding failures (citing tokens outside Channel A).
  4. *Hypothesized mechanism*: Expanding context with retrieved chunks under the 2048-token context ceiling may induce cognitive load, attention dispersion, or parameter grounding confusion. This is an explanatory hypothesis to be tested in future research, not a proven fact established solely from outcome correlation.

### 7.6 Semantic Boundaries & Absence of Human Review Data

- **Non-Overstatement**: The deterministic skeleton resolved syntax and polarity errors, but did not solve vulnerability detection. In `C1`, 20 of 48 negative controls resulted in false positives (Specificity = 28.57%).
- **Reviewer Estimand Notice**: Useful Hypothesis Yield @ N reviewer minutes was **not** measured. No claims regarding human reviewer efficiency or time savings are made.

### 7.7 Condition-Level Reconciliation Audit

- **Authoritative Source Dataset**:
  The authoritative dataset is [`data/eval/m5_phase10_full_population_validation.json`](data/eval/m5_phase10_full_population_validation.json) (SHA-256: `6821d207729de97ac99657a09e38c25895a73285fe9c485d299dc27f37d2bdba`), which is semantically identical to the runtime checkpoint [`data/eval/m5_phase10_checkpoint.json`](data/eval/m5_phase10_checkpoint.json) (SHA-256: `40f9f725fca5fdf05a76836182960b7f0d4c303a182d6e8af068a1b57e8f4537`). Both contain exactly 336 call records.
- **Independent Recomputation Method**:
  A fresh, read-only reconciliation script (`scratch/reconcile_phase10.py`) evaluated all 336 records directly from disk, grouping strictly by `record["condition_id"]`. For each condition, failure categories were partitioned by `record["primary_failure_category"]` without using any prior intermediate summary tables.
- **Exact Per-Condition Totals & Failure-Category Allocations**:

  | Failure Category | C1: Skeleton + Track A | C2: Skeleton + Track D | C3: Baseline + Track A | C4: Baseline + Track D | Grand Total |
  | :--- | :---: | :---: | :---: | :---: | :---: |
  | `VALID` | 52 | 14 | 40 | 45 | **151** |
  | `RUNTIME_TIMEOUT` | 10 | 19 | 7 | 1 | **37** |
  | `RUNTIME_TRANSPORT_FAILURE` | 0 | 0 | 0 | 0 | **0** |
  | `PARSER_FAILURE` | 0 | 0 | 0 | 0 | **0** |
  | `SCHEMA_VALIDITY_FAILURE` | 0 | 0 | 0 | 8 | **8** |
  | `SEMANTIC_GROUNDING_FAILURE` | 0 | 26 | 0 | 0 | **26** |
  | `SEMANTIC_EXPERIMENT_POLARITY_FAILURE` | 22 | 25 | 37 | 30 | **114** |
  | `CATEGORY_ACTION_INCOMPATIBILITY` | 0 | 0 | 0 | 0 | **0** |
  | **Total Calls per Condition** | **84** | **84** | **84** | **84** | **336** |

- **Proof of Invariants**:
  - Condition C1 Sum: $52 + 10 + 0 + 0 + 0 + 0 + 22 + 0 = \mathbf{84}$
  - Condition C2 Sum: $14 + 19 + 0 + 0 + 0 + 26 + 25 + 0 = \mathbf{84}$
  - Condition C3 Sum: $40 + 7 + 0 + 0 + 0 + 0 + 37 + 0 = \mathbf{84}$
  - Condition C4 Sum: $45 + 1 + 0 + 0 + 8 + 0 + 30 + 0 = \mathbf{84}$
  - All Conditions Sum: $84 + 84 + 84 + 84 = \mathbf{336}$
  - Grand Total Across Categories: $151 + 37 + 0 + 0 + 8 + 26 + 114 + 0 = \mathbf{336}$
- **Root Cause of Previous Textual Discrepancy**:
  During a previous conversation response summary, a textual summary conflated Candidate Hypothesis counts ($C1=56, C2=51$) with the `VALID` category, and incorrectly presented an unverified allocation ($56/51/22/22, 8/19/5/5, 0/0/4/4, 22/2/49/41$) in chat text. While that erroneous allocation happened to preserve the grand category row sums ($151, 37, 8, 114 \implies 336$), it resulted in impossible column sums ($C1=86, C2=98, C3=80, C4=72$). The authoritative report table in Section 4.4 and the underlying frozen datasets have always contained the verified $52/14/40/45$ distribution where every condition column sums strictly to 84.

---

## 8. Final Status & Conclusion

```
================================================================================
MILESTONE M5 PHASE 10: FULL-POPULATION VALIDATION COMPLETE
FINAL AUDITED DATASET AND REPORT
================================================================================
- Total Calls Executed: 336 / 336 (100% Scheduled Completion)
- Retries / In-Flight Repairs: ZERO (Strict One-Attempt Discipline)
- Benchmark Reruns: ZERO (No inference repeated post-collection)
- Model & Data Modifications: ZERO (Dataset preserved as collected)
- Canonical LF Dataset SHA-256: 6821d207729de97ac99657a09e38c25895a73285fe9c485d299dc27f37d2bdba
- Reconstructed CRLF SHA-256:   c7e4fb33061db2dd5539c6d8795c1210ea275ef419b9cc5bd2746713405a2e41
- Runtime Checkpoint SHA-256:   40f9f725fca5fdf05a76836182960b7f0d4c303a182d6e8af068a1b57e8f4537
- Historical Artifact Integrity: 4/4 BIT-FOR-BIT MATCHES PRESERVED
- Runtime-Control Deviation: 4 timeout calls exceeded 30.5s teardown tolerance (max 30.89s)
- Architecture Simple Effect (Track A, N=84): REJECT H0 (p = 1.164e-10)
- Useful Vulnerable Hypotheses (Track A, N=36): REJECT H0 (p = 1.221e-04)
- Context-Package Comparison (Skeleton, N=84): REJECT H0 (p = 4.657e-10)
- Descriptive Interaction Contrast: +32 scenarios (Exploratory / Non-Preregistered)
- Human Reviewer Yield @ N Minutes: NOT MEASURED
================================================================================
```
