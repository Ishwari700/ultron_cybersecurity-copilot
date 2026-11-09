# EXP-0003: Pre-Registered Evaluation Protocol & Benchmark Specification

**Experiment ID:** EXP-0003  
**Date:** 2026-09-17  
**Status:** Pre-Registered & Frozen  
**Dataset Specification:** `v6_frozen_gold_v2`  
**Dataset Digest:** `sha256:e0c3568f2cdc582e0ecbeced3822db3213856ced824708a46b405806cb392864`  

---

## 1. Research Question

Under fixed, pre-registered evidence and reviewer budgets, does the explicit reasoning architecture:
$$\text{Application Model} \longrightarrow \text{Security Invariant} \longrightarrow \text{Evidence Gap} \longrightarrow \text{Hypothesis} \longrightarrow \text{Experiment Proposal} \longrightarrow \text{Simulation Feedback}$$
improve useful hypothesis yield, hypothesis precision, abstention quality, and investigation efficiency compared with static rules, RAG baselines, and non-feedback invariant generators?

---

## 2. Research Hypotheses

* **H1 (Precision via Invariant Refutation):** Closed-loop execution of discriminative experiment proposals eliminates false-positive hypothesis generation on patched application endpoints compared with static syntax rules and unverified RAG baselines.
* **H2 (Abstention Quality):** The architecture correctly abstains (`INSUFFICIENT_EVIDENCE` or `NO_RELEVANT_FUNCTIONALITY`) when required evidence is absent, when multi-step preconditions cannot be resolved within budget, or when inspecting public discovery endpoints.
* **H3 (Synthetic Useful Hypothesis Yield @ Constrained Budget):** Closed-loop simulation feedback produces actionable, simulator-verified hypotheses within constrained budget windows ($N \le 10$ simulated reviewer minutes) where non-feedback baselines remain unverified.
* **H4 (Ground-Truth & Scope Isolation):** Runtime evidence construction and model prompts are strictly isolated from hidden evaluation labels (`is_vulnerable`, `ground_truth_label`, `oracle_label`).

---

## 3. Primary & Secondary Metrics

### 3.1 Primary Metric
* **Synthetic Useful Hypothesis Yield @ $N$ Reviewer Minutes:**
  $$\text{Synthetic Useful Yield} = \frac{\text{Simulator-Verified Vulnerabilities Confirmed}}{\text{Total Emitted Hypotheses}}$$
  *Note:* Explicitly distinguished from human productivity; measures simulator-mediated verification under a simulated reviewer budget ($N=5, 15, 30$ minutes).
* **Human Investigation Yield:** Fraction of hypotheses manually audited and validated by human reviewers under blind evaluation conditions.

### 3.2 Secondary Metrics
* **Hypothesis Precision ($P$):** $\frac{TP}{TP + FP}$
* **Hypothesis Recall ($R$):** $\frac{TP}{TP + FN}$
* **F1 Score:** $2 \cdot \frac{P \cdot R}{P + R}$
* **Abstention Precision:** $\frac{TN}{TN + FN}$ (accuracy of negative/abstention decisions)
* **Abstention Rate:** $\frac{\text{Abstentions}}{\text{Total Scenarios}}$
* **Discriminative Experiment Rate:** $\frac{\text{Discriminative Proposals}}{\text{Total Emitted Hypotheses}}$ (proposals with asymmetric expected observations)
* **Evidence Efficiency:** Number of experiment cycles required before reaching definitive confirmation or abstention.

---

## 4. Benchmark Dataset & Generation Rules

* **Total Scenarios:** $N = 84$ scenarios.
* **Application Families ($N=6$):**
  1. `saas_billing` ($N=14$)
  2. `ecommerce_orders` ($N=14$)
  3. `identity_provider` ($N=14$)
  4. `document_collaboration` ($N=14$)
  5. `healthcare_portal` ($N=14$)
  6. `iot_fleet_mgmt` ($N=14$)
* **Composition per Family:**
  * 6 Vulnerable Variants (BOLA, State Machine Step-Skipping, BFLA, Cross-Tenant Access, Lifecycle Inconsistency, Multi-Step Auth Dependency).
  * 6 Paired Patched Variants (Identical endpoints with server-side authorization or state validation enforced).
  * 2 Negative Controls (Public, unauthenticated, non-sensitive endpoints conforming to RFCs / specs).
* **Partitioning:**
  * **Development Split:** `saas_billing`, `ecommerce_orders` ($N = 28$).
  * **Validation Split:** `identity_provider`, `document_collaboration` ($N = 28$).
  * **Evaluation Split:** `healthcare_portal`, `iot_fleet_mgmt` ($N = 28$).
  * *Constraint:* Zero application family overlap across splits to prevent domain contamination.

---

## 5. Budget Levels

| Tier | Available Evidence Chunks | Retrieval $k$ | Max Token Budget | Max Experiments Allowed | Reviewer Time Budget |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **LOW** | 3 items | 3 | 1,024 tokens | 1 experiment | 5 minutes |
| **MEDIUM** | 5 items | 5 | 2,048 tokens | 3 experiments | 15 minutes |
| **HIGH** | 10 items | 10 | 4,096 tokens | 5 experiments | 30 minutes |

---

## 6. Experimental Tracks

1. **Track A — Rules Baseline (`TRACK_A_RULES`):** Deterministic syntactic regex and URI keyword matching rules.
2. **Track B — RAG + 3B (`TRACK_B_RAG_3B`):** Semantic retrieval baseline using 3B parameter model behavioral simulation (subject to token budget constraints on multi-step flows).
3. **Track C — RAG + 7B (`TRACK_C_RAG_7B`):** Semantic retrieval baseline using 7B parameter model behavioral simulation with complete syntactic grounding.
4. **Track D — Application Model + Invariants (`TRACK_D_APP_MODEL_INVARIANTS`):** Structured entity modeling and discriminative proposal generation without closed-loop execution.
5. **Track E — Full V6 Architecture (`TRACK_E_FULL_V6`):** Closed-loop pipeline combining Application Model, Invariants, Evidence Gap detection, Discriminative Experiment Proposal, Headless Simulation Feedback, and Hypothesis Lifecycle Updates.

*Execution Classification:* Tracks B, C, D, and E are classified as **synthetic/deterministic benchmark evaluations** because local Ollama daemon is offline on the evaluation host.

---

## 7. Statistical Analysis & Hypothesis Testing

* **Uncertainty Estimation:** 95% Wilson score confidence intervals computed for all binomial proportions (Precision, Recall, Abstention Precision).
* **Paired Hypothesis Comparison:** Two-sided exact binomial test (McNemar's discordant pair analysis) comparing Track E against Track D on useful hypothesis yield across paired scenarios.
* **Significance Level:** $\alpha = 0.01$.

---

## 8. Failure Taxonomy & Handling

All benchmark discrepancies must be categorized under:
1. `SCOPE_ERROR`
2. `RETRIEVAL_ERROR`
3. `APP_MODEL_ERROR`
4. `INVARIANT_ERROR`
5. `GROUNDING_ERROR`
6. `HYPOTHESIS_ERROR`
7. `ABSTENTION_ERROR`
8. `EXPERIMENT_DESIGN_ERROR`
9. `MODEL_OUTPUT_ERROR`
10. `SIMULATOR_ERROR`
11. `EVALUATION_ERROR`

---

## 9. Oracle Boundary & Safety Constraints

* Hidden ground truth (`is_vulnerable`, `vulnerable_variant`, `expected_decision`) is strictly prohibited from entering `src.engine`, `src.retrieval`, prompt templates, or simulator observation payloads.
* The simulator emits strictly observable HTTP results (`status_code`, `response_data`, `evidence_item`).
* Strictly synthetic and controlled: No real-world targets, credentials, or network traffic are ingested.
