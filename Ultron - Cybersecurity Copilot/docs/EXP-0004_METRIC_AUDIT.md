# EXP-0004: Metric Integrity Audit, Statistical Recomputation & Methodological Correction

**Experiment Reference:** EXP-0004  
**Date:** 2026-09-17  
**System Under Audit:** Local AI-Assisted Bug Bounty Research Platform — V6 Final  
**Scope of Audit:** EXP-0003 Metric Definitions, Statistical Calculations, Denominator Correctness, and Internal Consistency  
**Dataset Digest:** `sha256:e0c3568f2cdc582e0ecbeced3822db3213856ced824708a46b405806cb392864` (`v6_frozen_gold_v2`, $N=84$)  
**Test Suite Status:** 83 collected — 82 passed, 1 skipped, 0 failed  

---

## 1. Historical Artifact Preservation

In accordance with scientific audit protocols, historical records are preserved without retroactive overwriting:
* **EXP-0001:** Preserved in [EXPERIMENT_LOG.md](EXPERIMENT_LOG.md) as the pre-evaluation harness sanity dry run.
* **EXP-0002:** Preserved in [EXPERIMENT_LOG.md](EXPERIMENT_LOG.md) and [EXPERIMENTAL_VALIDATION_REPORT.md](docs/EXPERIMENTAL_VALIDATION_REPORT.md) as the preliminary 7-scenario evaluation.
* **EXP-0003:** Preserved in [EXPERIMENT_LOG.md](EXPERIMENT_LOG.md), [EXP-0003_PROTOCOL.md](docs/EXP-0003_PROTOCOL.md), and [EXP-0003_RESULTS.md](docs/EXP-0003_RESULTS.md) as the 84-scenario benchmark.
* **EXP-0004 (This Document):** Documents the metric integrity audit, resolves mathematical denominator collisions, and recomputes all benchmark statistics from raw scenario outputs.

---

## 2. Critical Audit: Useful Hypothesis Yield Definition vs Implementation

### 2.1 The Mathematical Collision
The audit identified an inconsistency in EXP-0003 between the textual protocol definition and the code implementation:

* **Protocol Definition (Target-Level):**
  $$\text{Useful Hypothesis Yield} = \frac{\text{Number of vulnerable scenarios receiving a verified useful hypothesis}}{\text{Total vulnerable scenarios}} = \frac{\text{Useful\_TP}}{\text{Total\_Vulnerable}}$$
* **Scoring Implementation in EXP-0003 (`src/eval/scorer.py:97`):**
  $$\text{useful\_yield} = \frac{\text{useful\_count}}{\text{hyp\_count}} = \frac{\text{Useful\_TP}}{\text{TP} + \text{FP}}$$

### 2.2 Mathematical Consequence
In Track E, because every True Positive hypothesis was verified by simulator feedback ($\text{Useful\_TP} = \text{TP}$), the implementation formula reduced to:
$$\text{useful\_yield} = \frac{\text{TP}}{\text{TP} + \text{FP}} \equiv \text{Precision}$$
This caused `useful_hypothesis_yield` in EXP-0003 to report **`0.8780`** (Medium/High) and **`0.8684`** (Low), which were mathematically identical to `Precision` ($36/41$ and $33/38$).

Under the protocol's target-level definition, the true Target-Level Useful Yield is:
* Full Benchmark MEDIUM/HIGH: $\frac{36}{36} = \mathbf{1.0000}$ (100% of vulnerable targets discovered and verified).
* Full Benchmark LOW: $\frac{33}{36} = \mathbf{0.9167}$ (91.7% discovered; 3 multi-step dependencies abstained due to 1-experiment budget).

### 2.3 Resolution & Separation of Concepts
In EXP-0004, the metrics have been formally decoupled in [src/eval/scorer.py](src/eval/scorer.py):
1. **Target-Level Metric (`useful_hypothesis_yield`):** $\frac{\text{Useful\_TP}}{\text{Total\_Vulnerable}}$ — Measures target vulnerability discovery under budget.
2. **Hypothesis-Level Metric (`hypothesis_utility_rate`):** $\frac{\text{Useful\_Hypotheses}}{\text{Total\_Hypotheses\_Emitted}}$ — Measures actionable utility of researcher notifications.
3. **Hypothesis Precision (`precision`):** $\frac{\text{TP}}{\text{TP} + \text{FP}}$ — Measures resistance to false positive alerts.

---

## 3. Unit Tests for Metric Independence

To prevent regression and guarantee mathematical independence, unit tests were implemented in [tests/unit/test_metric_integrity.py](tests/unit/test_metric_integrity.py):

* **Case 1 (10 Vuln, 10 Patched; TP=10, FN=0, FP=5, TN=5):**
  * $\text{Precision} = \frac{10}{15} = 0.6667$
  * $\text{Recall} = \frac{10}{10} = 1.0000$
  * $\text{Useful Yield} = \frac{10}{10} = 1.0000$
  * *Verification:* Proved $\text{Precision} \ne \text{Useful Yield}$ ($0.6667 \ne 1.0000$).
* **Case 2 (10 Vuln, 10 Patched; TP=8, FN=2, FP=0, TN=10):**
  * $\text{Precision} = \frac{8}{8} = 1.0000$
  * $\text{Recall} = \frac{8}{10} = 0.8000$
  * $\text{Useful Yield} = \frac{8}{10} = 0.8000$
  * *Verification:* Proved $\text{Precision} \ne \text{Useful Yield}$ ($1.0000 \ne 0.8000$).

---

## 4. Programmatic McNemar & Contingency Table Audit

Rather than assuming aggregate outputs, `compute_paired_contingency_table()` was implemented in [src/eval/scorer.py](src/eval/scorer.py) to derive the paired 2x2 contingency matrix directly from per-scenario execution records:

### 4.1 Paired Variable Definition
* **Binary Variable Evaluated:** *"Did this vulnerable scenario produce an actionable, simulator-supported hypothesis within budget?"*
* **Sample Space:** All $N=36$ vulnerable benchmark scenarios across the 6 application families.

### 4.2 Programmatically Derived Contingency Matrix (Track D vs Track E)

| | Track E Useful (True) | Track E Useful (False) | Total |
| :--- | :---: | :---: | :---: |
| **Track D Useful (True)** | $n_{11} = 0$ | $n_{01} = 0$ | **0** |
| **Track D Useful (False)** | $n_{10} = 36$ | $n_{00} = 0$ | **36** |
| **Total** | **36** | **0** | **36** |

### 4.3 Discordant Pairs & Exact Binomial Test
* Discordant pairs: $b = n_{01} = 0$, $c = n_{10} = 36$.
* Two-sided exact binomial test against null hypothesis $H_0: p = 0.5$:
  $$p = 2 \times \sum_{i=0}^{0} \binom{36}{i} (0.5)^{36} = 2 \times (0.5)^{36} \approx \mathbf{2.910 \times 10^{-11}}$$
* *Methodological Interpretation:* The paired difference in verified vulnerability discovery is statistically significant ($p < 0.001$). However, this significance confirms internal state machine behavior under the synthetic simulator; it does **not** prove generalization to live production applications or human reviewers.

---

## 5. Audit of Budget Implementation & LOW-Budget Abstention

### 5.1 Per-Scenario Audit of LOW-Budget Abstentions
In EXP-0003, Track E reported Recall of 0.9167 (33/36) under LOW budget and 1.0000 (36/36) under MEDIUM/HIGH budgets. The per-scenario execution logs were audited to verify the exact cause:

| Scenario ID | App Family | Ground Truth | Budget Tier | Max Exps | Experiments Executed | Termination Reason | Result |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- | :--- |
| `SCEN-SAAS_BILLING-MULTI-INV-VULN-05` | `saas_billing` | Vulnerable | LOW | 1 | 1 | `BUDGET_EXHAUSTION_MULTISTEP_ABSTAIN` | `INSUFFICIENT_EVIDENCE` |
| `SCEN-DOCUMENT_COLLABORATION-CLASS-BYPASS-VULN-05` | `document_collaboration` | Vulnerable | LOW | 1 | 1 | `BUDGET_EXHAUSTION_MULTISTEP_ABSTAIN` | `INSUFFICIENT_EVIDENCE` |
| `SCEN-DOCUMENT_COLLABORATION-WS-DOWNGRADE-VULN-06` | `document_collaboration` | Vulnerable | LOW | 1 | 1 | `BUDGET_EXHAUSTION_MULTISTEP_ABSTAIN` | `INSUFFICIENT_EVIDENCE` |

*Finding:* Under LOW budget (`max_experiments = 1`), multi-step authorization dependencies require two rounds (Step 1: observe baseline identity permission; Step 2: attempt privilege boundary crossing). With `max_experiments = 1`, the second experiment cannot be executed. The system detects an unresolved evidence gap and transitions to `INSUFFICIENT_EVIDENCE`. When budget expands to MEDIUM (`max_experiments = 3`), all three complete Step 2 and transition to `HYPOTHESIS` with `Useful = True`.

---

## 6. Oracle Boundary Audit & Runtime Assertion

In [src/eval/ablation.py](src/eval/ablation.py), an audit was conducted on Track E's decision block:
1. **Purged Ground Truth References:** Previous draft lines referencing `and scen.ground_truth_vulnerable` were removed. Track E's decision is now driven 100% by `exec_result.observation_type`:
   * `SUPPORTING` (HTTP 200) $\to$ `HYPOTHESIS` (`useful = True`)
   * `CONTRADICTING` (HTTP 403/400) $\to$ `INSUFFICIENT_EVIDENCE` (`useful = False`)
   * `UNRESOLVED` (HTTP 500) $\to$ `INSUFFICIENT_EVIDENCE` (`useful = False`)
2. **Runtime Assertion Added:** Before executing experiments in Track E, [ablation.py](src/eval/ablation.py) now inspects the serialized `exp` payload and raises `RuntimeError` if any forbidden tokens (`ground_truth_vulnerable`, `is_vulnerable`, `is_patched`, `oracle_label`, `expected_class`) are present.

---

## 7. Confidence Interval Audit: Denominator Validation

The confidence interval calculation was audited to ensure appropriate sample sizes ($n$) are used for each metric:

| Metric | Formula | Denominator ($n$) in EXP-0003 | Correct Denominator ($n$) | Audit Finding |
| :--- | :---: | :---: | :---: | :--- |
| **Precision** | $\frac{TP}{TP + FP}$ | $TP + FP = 41$ | $TP + FP = 41$ | **VALID** |
| **Recall** | $\frac{TP}{TP + FN}$ | $TP + FP = 41$ (Reused) | $TP + FN = 36$ | **INCORRECT in script**; corrected in EXP-0004 |
| **Useful Yield** | $\frac{Useful\_TP}{\text{Total\_Vuln}}$ | $TP + FP = 41$ (Reused) | $\text{Total\_Vuln} = 36$ | **INCORRECT in script**; corrected in EXP-0004 |

---

## 8. Complete Discrepancy Catalog: EXP-0003 vs EXP-0004

| Metric / Analysis Area | Original EXP-0003 Value | Corrected EXP-0004 Value | Cause of Discrepancy |
| :--- | :---: | :---: | :--- |
| **Track E Full Benchmark Useful Yield (MED/HIGH)** | 0.8780 | **1.0000** | Original calculation computed `Useful_TP / (TP + FP)` instead of `Useful_TP / Total_Vuln`. |
| **Track E Full Benchmark Useful Yield (LOW)** | 0.8684 | **0.9167** | Original calculation computed `33 / 38` instead of `33 / 36`. |
| **Track E Evaluation Split Useful Yield** | 0.8571 | **1.0000** | Original calculation computed `12 / 14` instead of `12 / 12`. |
| **Useful Yield 95% Confidence Interval (MED/HIGH)** | (0.7446, 0.9468) | **(0.9036, 1.0000)** | Denominator changed from $n=41$ (hypotheses) to $n=36$ (vulnerable scenarios). |
| **Useful Yield 95% Confidence Interval (LOW)** | (0.7267, 0.9425) | **(0.7817, 0.9713)** | Denominator changed from $n=38$ (hypotheses) to $n=36$ (vulnerable scenarios). |
| **Hypothesis Utility Rate** | Not explicitly separated | **0.8780** (MED), **0.8684** (LOW) | Added as independent hypothesis-level metric. |

---

## 9. Recomputed Benchmark Metrics (EXP-0004 Master Table)

### 9.1 Evaluation Split ($N=28$: `healthcare_portal`, `iot_fleet_mgmt`, Total Vuln=12)

| Track | Budget | Precision (95% CI, $n$) | Recall (95% CI, $n$) | Useful Yield (95% CI, $n$) | Hyp. Utility | TP | FP | TN | FN |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Track A** | All | 0.5000 (0.2993, 0.7007, $n=20$) | 0.8333 (0.5520, 0.9530, $n=12$) | 0.0000 (0.0000, 0.2425, $n=12$) | 0.0000 | 10 | 10 | 6 | 2 |
| **Track B** | All | 0.5000 (0.3143, 0.6857, $n=24$) | 1.0000 (0.7575, 1.0000, $n=12$) | 0.0000 (0.0000, 0.2425, $n=12$) | 0.0000 | 12 | 12 | 4 | 0 |
| **Track C** | All | 0.5000 (0.3143, 0.6857, $n=24$) | 1.0000 (0.7575, 1.0000, $n=12$) | 0.0000 (0.0000, 0.2425, $n=12$) | 0.0000 | 12 | 12 | 4 | 0 |
| **Track D** | All | 0.5000 (0.3143, 0.6857, $n=24$) | 1.0000 (0.7575, 1.0000, $n=12$) | 0.0000 (0.0000, 0.2425, $n=12$) | 0.0000 | 12 | 12 | 4 | 0 |
| **Track E** | All | **0.8571** (0.6006, 0.9599, $n=14$) | **1.0000** (0.7575, 1.0000, $n=12$) | **1.0000** (0.7575, 1.0000, $n=12$) | **1.0000** | 12 | 2 | 14 | 0 |

### 9.2 Full Benchmark ($N=84$, Total Vuln=36)

| Track | Budget | Precision (95% CI, $n$) | Recall (95% CI, $n$) | Useful Yield (95% CI, $n$) | Hyp. Utility | TP | FP | TN | FN |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Track A** | All | 0.5000 (0.3689, 0.6311, $n=52$) | 0.7222 (0.5601, 0.8415, $n=36$) | 0.0000 (0.0000, 0.0964, $n=36$) | 0.0000 | 26 | 26 | 22 | 10 |
| **Track B** | LOW | 0.5000 (0.3827, 0.6173, $n=66$) | 0.9167 (0.7817, 0.9713, $n=36$) | 0.0000 (0.0000, 0.0964, $n=36$) | 0.0000 | 33 | 33 | 15 | 3 |
| **Track B** | MED/HIGH | 0.5000 (0.3875, 0.6125, $n=72$) | 1.0000 (0.9036, 1.0000, $n=36$) | 0.0000 (0.0000, 0.0964, $n=36$) | 0.0000 | 36 | 36 | 12 | 0 |
| **Track C** | All | 0.5000 (0.3875, 0.6125, $n=72$) | 1.0000 (0.9036, 1.0000, $n=36$) | 0.0000 (0.0000, 0.0964, $n=36$) | 0.0000 | 36 | 36 | 12 | 0 |
| **Track D** | All | 0.5000 (0.3875, 0.6125, $n=72$) | 1.0000 (0.9036, 1.0000, $n=36$) | 0.0000 (0.0000, 0.0964, $n=36$) | 0.0000 | 36 | 36 | 12 | 0 |
| **Track E** | LOW | **0.8684** (0.7267, 0.9425, $n=38$) | 0.9167 (0.7817, 0.9713, $n=36$) | **0.9167** (0.7817, 0.9713, $n=36$) | **0.8684** | 33 | 5 | 43 | 3 |
| **Track E** | MED/HIGH | **0.8780** (0.7446, 0.9468, $n=41$) | **1.0000** (0.9036, 1.0000, $n=36$) | **1.0000** (0.9036, 1.0000, $n=36$) | **0.8780** | 36 | 5 | 43 | 0 |

---

## 10. Human Audit Contextualization

The blind audit of $N=16$ scenarios was conducted as a sanity check on simulator agreement:
* **Concordance:** 16 / 16 (100.0%).
* **Methodological Restriction:** This result confirms that the human auditor agrees with the simulator's interpretation of HTTP 403 / 400 responses. It must **not** be presented as proof of real-world human researcher efficiency or general clinical/commercial superiority.

---

## 11. Threats to Validity & Unresolved Boundaries

1. **Deterministic Behavioral Simulation:** Live Ollama execution was offline. Benchmark mechanics reflect deterministic behavioral state machines rather than live continuous LLM sampling distributions.
2. **Simulator Status Code Oracle:** Assumes target applications use standard status codes (200 for access, 400/403 for denial). Non-standard APIs returning 200 with error JSON require custom body-parsing adapters.
3. **Statistical Boundaries:** The small p-value ($p = 2.91 \times 10^{-11}$) establishes that the state machines behave differently under paired testing; it does not establish ecological validity for unconstrained production applications.

---

## 12. Final Conclusion

In strict adherence to epistemic audit guidelines:

> **SUPPORTED WITHIN CONTROLLED SYNTHETIC BENCHMARK**

The corrected metrics and independent statistical recomputations confirm that within the controlled synthetic benchmark ($N=84$ scenarios across 6 application families), the closed-loop **Application Model $\to$ Security Invariant $\to$ Evidence Gap $\to$ Experiment Proposal $\to$ Feedback** architecture:
* Achieves **1.0000 Target-Level Useful Yield** under Medium/High budgets (and **0.9167** under Low budget due to disciplined abstention on multi-step flows), compared to **0.0000** for Tracks A through D.
* Achieves **0.8780 Precision** and **0.8780 Hypothesis Utility Rate**, significantly reducing false positives compared to RAG baselines ($0.5000$).
* The paired difference between Track D and Track E is statistically significant ($p = 2.91 \times 10^{-11}$).
* Generalization to live continuous LLMs and real-world targets remains unproven and requires live-model integration on host hardware.
