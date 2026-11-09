# EXP-0003: Experimental Results & Methodology Validation Report

**Experiment ID:** EXP-0003  
**Date:** 2026-09-17  
**Benchmark Suite:** `v6_frozen_gold_v2` ($N=84$ scenarios across 6 application families)  
**Dataset Digest:** `sha256:e0c3568f2cdc582e0ecbeced3822db3213856ced824708a46b405806cb392864`  
**Execution Type:** Synthetic / Deterministic Benchmark Evaluation (Offline Host Ollama Fallback)  
**Historical Continuity:** Supersedes EXP-0002 interpretation; preserves EXP-0001 and EXP-0002 raw records.  

---

## 1. Pre-Registered Protocol Reference

This evaluation was conducted strictly in accordance with [docs/EXP-0003_PROTOCOL.md](docs/EXP-0003_PROTOCOL.md). All scenario distributions, family splits, budget definitions, metric formulations, and statistical hypothesis tests were frozen prior to benchmark execution.

---

## 2. Benchmark Dataset Architecture

The benchmark contains $N=84$ controlled scenarios spanning 6 distinct application families, partitioned across three non-overlapping family splits:

| Partition | Application Families | Scenarios ($N$) | Vulnerable Variants | Patched Variants | Negative Controls |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Development** | `saas_billing`, `ecommerce_orders` | 28 | 12 | 12 | 4 |
| **Validation** | `identity_provider`, `document_collaboration` | 28 | 12 | 12 | 4 |
| **Evaluation** | `healthcare_portal`, `iot_fleet_mgmt` | 28 | 12 | 12 | 4 |
| **Total** | **6 Families** | **84** | **36** | **36** | **12** |

### Coverage of Security Properties
1. Object Ownership / Tenant Isolation BOLA (`API-BOLA-001`)
2. Workflow State Machine Bypass / Step-Skipping (`API-STATE-001`)
3. Function-Level Role Escalation / Privilege Mutation (`API-BFLA-001`)
4. Cross-Tenant Resource Access (`API-CROSS-TENANT-001`)
5. Role Boundary Violation / Horizontal Escalation (`API-ROLE-BOUNDARY-001`)
6. Resource Lifecycle Inconsistency / Archived Resource Access (`API-LIFECYCLE-001`)
7. IoT Device Command & Telemetry Ownership (`API-DEVICE-BOLA-001`)
8. Multi-Step Authorization Dependency Bypass (`API-MULTI-STEP-AUTH-001`)
9. Privilege Boundary Mutation (`API-MUTATION-001`)
10. Public Discovery & Documentation Controls (`API-AUTH-NONE`)

---

## 3. Model Execution Status & Methodological Audit

### 3.1 Host Inference Audit
* **Ollama Daemon Status:** Host port `127.0.0.1:11434` connection was refused (daemon process offline on evaluation host).
* **Pytest Result:** `tests/integration/test_model_inference.py::test_live_ollama_inference SKIPPED`.
* **Methodological Finding:** In accordance with section 2 instructions, live LLM inference was **NOT replaced with a silent mock**.
* **Benchmark Nature:** All benchmark results for Tracks B, C, D, and E were executed using **deterministic behavioral simulation models** and the deterministic headless HTTP simulator.
* **Epistemic Classification:** Results represent **synthetic / deterministic benchmark performance**, NOT live continuous LLM comparisons.

---

## 4. Evaluation Tracks

* **Track A (Rules Only):** Static regex and URI keyword matching rules.
* **Track B (RAG 3B):** Semantic retrieval baseline using 3B parameter behavioral model.
* **Track C (RAG 7B):** Semantic retrieval baseline using 7B parameter behavioral model.
* **Track D (App Model + Invariants):** Entity modeling + security invariants generating discriminative proposals without execution.
* **Track E (Full V6 Architecture):** Closed-loop invariant reasoning + experiment proposal + headless HTTP simulator feedback.

---

## 5. Budget Levels

Evaluation was executed across all three pre-registered budget tiers:
* **LOW:** 3 evidence items, retrieval $k=3$, 1,024 tokens, max 1 experiment, 5 min reviewer budget.
* **MEDIUM:** 5 evidence items, retrieval $k=5$, 2,048 tokens, max 3 experiments, 15 min reviewer budget.
* **HIGH:** 10 evidence items, retrieval $k=10$, 4,096 tokens, max 5 experiments, 30 min reviewer budget.

---

## 6. Primary Metric: Synthetic Useful Hypothesis Yield @ $N$ Reviewer Minutes

* **Synthetic Useful Yield Definition:** Proportion of emitted hypotheses that are verified by simulator execution within the simulated reviewer time window.
* **Human Investigation Yield Definition:** Proportion of emitted hypotheses verified by human review.

### Results Across Budget Tiers (Full Benchmark $N=84$)

| Track | LOW Budget (5m / 1 exp) | MEDIUM Budget (15m / 3 exps) | HIGH Budget (30m / 5 exps) |
| :--- | :---: | :---: | :---: |
| **Track A (Rules)** | 0.000 | 0.000 | 0.000 |
| **Track B (RAG 3B)** | 0.000 | 0.000 | 0.000 |
| **Track C (RAG 7B)** | 0.000 | 0.000 | 0.000 |
| **Track D (App Model + Inv)** | 0.000 | 0.000 | 0.000 |
| **Track E (Full V6)** | **0.868** | **0.878** | **0.878** |

*Note:* Tracks A, B, C, and D achieve 0.000 synthetic useful yield because they either generate non-discriminative proposals or fail to execute experiments, leaving all hypotheses unverified. Track E achieves 0.868 under LOW budget (abstaining on multi-step authorization dependencies) and 0.878 under MEDIUM/HIGH budgets.

---

## 7. Secondary Metrics & Split Performance

### 7.1 Evaluation Split ($N=28$: `healthcare_portal`, `iot_fleet_mgmt`)

| Track | Budget Tier | Precision (95% CI) | Recall | F1 | Abst. Prec. | Disc. Rate | TP | FP | TN | FN |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Track A** | All | 0.500 (0.300, 0.700) | 0.833 | 0.625 | 0.750 | 0.000 | 10 | 10 | 6 | 2 |
| **Track B** | All | 0.500 (0.314, 0.686) | 1.000 | 0.667 | 1.000 | 0.000 | 12 | 12 | 4 | 0 |
| **Track C** | All | 0.500 (0.314, 0.686) | 1.000 | 0.667 | 1.000 | 0.000 | 12 | 12 | 4 | 0 |
| **Track D** | All | 0.500 (0.314, 0.686) | 1.000 | 0.667 | 1.000 | 1.000 | 12 | 12 | 4 | 0 |
| **Track E** | LOW / MED / HIGH | **0.857** (0.601, 0.960) | **1.000** | **0.923** | **1.000** | **1.000** | 12 | 2 | 14 | 0 |

### 7.2 Full Benchmark ($N=84$: Development + Validation + Evaluation)

| Track | Budget Tier | Precision (95% CI) | Recall | F1 | Abst. Prec. | Disc. Rate | TP | FP | TN | FN |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Track A** | All | 0.500 (0.369, 0.631) | 0.722 | 0.591 | 0.688 | 0.000 | 26 | 26 | 22 | 10 |
| **Track B** | LOW | 0.500 (0.383, 0.617) | 0.917 | 0.647 | 0.833 | 0.000 | 33 | 33 | 15 | 3 |
| **Track B** | MED / HIGH | 0.500 (0.387, 0.613) | 1.000 | 0.667 | 1.000 | 0.000 | 36 | 36 | 12 | 0 |
| **Track C** | All | 0.500 (0.387, 0.613) | 1.000 | 0.667 | 1.000 | 0.000 | 36 | 36 | 12 | 0 |
| **Track D** | All | 0.500 (0.387, 0.613) | 1.000 | 0.667 | 1.000 | 1.000 | 36 | 36 | 12 | 0 |
| **Track E** | LOW | **0.868** (0.727, 0.942) | 0.917 | 0.892 | 0.935 | 1.000 | 33 | 5 | 43 | 3 |
| **Track E** | MED / HIGH | **0.878** (0.744, 0.947) | **1.000** | **0.935** | **1.000** | **1.000** | 36 | 5 | 43 | 0 |

---

## 8. Ablation Analysis

1. **Syntax Rules $\to$ Semantic Retrieval (Track A $\to$ Track B):**
   * Recall increased from 0.722 to 1.000 (MED/HIGH); false negatives dropped from 10 to 0.
   * Semantic retrieval successfully modeled state machine transitions that static regex missed. However, false positives rose from 26 to 36 due to inability to verify authorization checks.
2. **Model Parameter Scaling 3B $\to$ 7B (Track B $\to$ Track C):**
   * Precision, Recall, and F1 remained identical under MEDIUM/HIGH budgets (0.500, 1.000, 0.667).
   * Under LOW budget, 7B eliminated 3 grounding failures on multi-step flows. However, scaling parameters without closed-loop testing produced zero improvement in precision on patched endpoints.
3. **Application Model + Invariants (Track C $\to$ Track D):**
   * Discriminative experiment proposal rate increased from 0.000 to 1.000.
   * Invariants enabled formulating falsifiable tests. However, without executing them, precision remained fixed at 0.500.
4. **Closed-Loop Simulator Feedback (Track D $\to$ Track E):**
   * Precision increased from 0.500 to 0.878 (+0.378); false positives dropped from 36 to 5 (-86.1%).
   * Synthetic Useful Hypothesis Yield increased from 0.000 to 0.878.

---

## 9. Statistical Analysis & Significance Testing

### 9.1 Paired Hypothesis Comparison: Track E vs Track D
* **Research Question:** Does the closed-loop feedback loop in Track E produce a statistically significant increase in verified useful hypotheses compared to Track D across paired vulnerable scenarios ($N=36$)?
* **Contingency Matrix (Discordant Pairs):**
  * $n_{10}$ (Track E useful, Track D not useful) = 36
  * $n_{01}$ (Track D useful, Track E not useful) = 0
* **Exact Two-Sided Binomial Test:**
  $$p = 2 \times (0.5)^{36} \approx 2.91 \times 10^{-11}$$
* **Finding:** The difference in useful hypothesis yield between Track E and Track D is statistically significant ($p < 0.001$).
* **Caveat:** Statistical significance in this synthetic environment confirms internal validity of the state machine; it does not constitute proof of real-world generalization.

---

## 10. Failure Analysis

| Failure ID | Count | Category | Observed Failure Mode | Root Cause Analysis |
| :--- | :---: | :--- | :--- | :--- |
| `FAIL-001` | 10 | `RULE_SYNTAX_LIMITATION` | False Negatives on orders, approvals, and shipping transitions in Track A. | Static regex rules cannot represent multi-step state transitions or preconditions. |
| `FAIL-002` | 36 | `STATIC_CONTEXT_OVERCONFIDENCE` | False Positives across all patched endpoints in Tracks B, C, and D. | Language models infer vulnerability from presence of sensitive endpoints without active testing. |
| `FAIL-003` | 3 | `RETRIEVAL_BUDGET_TRUNCATION` | False Negatives in Track B under LOW budget ($k=3$). | 1,024-token budget caused truncation of multi-parameter dependency documentation. |
| `FAIL-004` | 5 | `MUTATION_EDGE_CASE` | False Positives in Track E on complex authority boundary mutations. | Synthetic state machine returned HTTP 200 on specific edge-case role updates due to overlapping role mappings. |
| `FAIL-005` | 1 | `ENVIRONMENT_DAEMON_OFFLINE` | Live Ollama inference skipped during integration testing. | Host daemon was offline; mock substitution prohibited. |

---

## 11. Human Audit

A stratified sample of $N=16$ scenarios was audited under blind review conditions (human evaluator blinded to ground truth labels during assessment):

| Scenario ID | App Family | Variant | Track E Automated Judgment | Human Auditor Judgment | Agreement |
| :--- | :--- | :--- | :--- | :--- | :---: |
| `SCEN-SAAS-BOLA-VULN-01` | `saas_billing` | Vulnerable | VULNERABLE | VULNERABLE | **AGREE** |
| `SCEN-SAAS-BOLA-PATCH-01` | `saas_billing` | Patched | NOT VULNERABLE | NOT VULNERABLE | **AGREE** |
| `SCEN-SAAS-PRICE-NEG-01` | `saas_billing` | Negative Control | NOT VULNERABLE | NOT VULNERABLE | **AGREE** |
| `SCEN-ECOM-REFUND-VULN-01` | `ecommerce_orders` | Vulnerable | VULNERABLE | VULNERABLE | **AGREE** |
| `SCEN-ECOM-REFUND-PATCH-01` | `ecommerce_orders` | Patched | NOT VULNERABLE | NOT VULNERABLE | **AGREE** |
| `SCEN-ECOM-PROD-NEG-01` | `ecommerce_orders` | Negative Control | NOT VULNERABLE | NOT VULNERABLE | **AGREE** |
| `SCEN-IDP-ROLE-VULN-01` | `identity_provider` | Vulnerable | VULNERABLE | VULNERABLE | **AGREE** |
| `SCEN-IDP-ROLE-PATCH-01` | `identity_provider` | Patched | NOT VULNERABLE | NOT VULNERABLE | **AGREE** |
| `SCEN-IDP-OIDC-NEG-01` | `identity_provider` | Negative Control | NOT VULNERABLE | NOT VULNERABLE | **AGREE** |
| `SCEN-DOC-EXPORT-VULN-01` | `document_collaboration`| Vulnerable | VULNERABLE | VULNERABLE | **AGREE** |
| `SCEN-DOC-EXPORT-PATCH-01` | `document_collaboration`| Patched | NOT VULNERABLE | NOT VULNERABLE | **AGREE** |
| `SCEN-HEALTH-REC-VULN-01` | `healthcare_portal` | Vulnerable | VULNERABLE | VULNERABLE | **AGREE** |
| `SCEN-HEALTH-REC-PATCH-01` | `healthcare_portal` | Patched | NOT VULNERABLE | NOT VULNERABLE | **AGREE** |
| `SCEN-HEALTH-HOURS-NEG-01` | `healthcare_portal` | Negative Control | NOT VULNERABLE | NOT VULNERABLE | **AGREE** |
| `SCEN-IOT-CMD-VULN-01` | `iot_fleet_mgmt` | Vulnerable | VULNERABLE | VULNERABLE | **AGREE** |
| `SCEN-IOT-CMD-PATCH-01` | `iot_fleet_mgmt` | Patched | NOT VULNERABLE | NOT VULNERABLE | **AGREE** |

*Human Audit Agreement Rate:* **16 / 16 (100.0%)**.  
*Finding:* Human auditor concurred that simulator-observed HTTP 403 / 400 responses definitively refuted hypothesized vulnerabilities on patched variants, confirming that abstention is the correct security posture.

---

## 12. Threats to Validity

1. **Synthetic Environment Threat:** All targets are modeled via `SyntheticApp` Python state machines rather than live production services. Real-world API idiosyncrasies (e.g. 200 OK with custom error JSON, multi-tier CDN caching) are not captured.
2. **Offline LLM Inference Threat:** The local Ollama daemon was offline during benchmark execution. While behavioral simulations rigorously isolate architectural mechanics, live continuous generation dynamics (GPU VRAM saturation, prompt drift) require host daemon activation.
3. **Oracle Simplification Threat:** The headless simulator assumes HTTP 200 indicates success and HTTP 400/403 indicates rejection. Real-world services may exhibit divergent status codes.
4. **Dataset Scope Threat:** While scaled to $N=84$ scenarios across 6 families, the dataset focuses on authorization and state machine vulnerabilities. Memory safety, cryptographic protocol flaws, and timing attacks were not evaluated.

---

## 13. Reproducibility Record

* **Experiment ID:** `EXP-0003`
* **Timestamp:** `2026-09-17T11:35:00Z`
* **Dataset Version:** `v6_frozen_gold_v2`
* **Dataset Hash:** `sha256:e0c3568f2cdc582e0ecbeced3822db3213856ced824708a46b405806cb392864`
* **Hardware:** AMD Ryzen 5 5600H, 24GB DDR4, NVIDIA GeForce RTX 3050 Laptop GPU (4GB VRAM).
* **Virtual Environment:** Python 3.13.14 (`.venv`).
* **Test Status:** 82 collected — 81 passed, 1 skipped (`test_live_ollama_inference`), 0 failed.

---

## 14. Final Interpretation & Conclusion

In strict accordance with section 22 evaluation rules, the final interpretation is:

> **SUPPORTED** (within the boundary of the controlled synthetic benchmark).

### Formal Epistemic Statement
Preliminary evidence supports the research hypothesis within the controlled synthetic benchmark evaluated in EXP-0003 ($N=84$ scenarios across 6 application families). The explicit **Application Model $\to$ Security Invariant $\to$ Evidence Gap $\to$ Experiment Proposal $\to$ Feedback** architecture demonstrated a statistically significant improvement in precision ($0.878$ vs $0.500$, $p < 0.001$) and synthetic useful hypothesis yield ($0.878$ vs $0.000$) compared with static rules and non-feedback baselines under fixed budgets.

However, because these evaluations were conducted using deterministic behavioral models while the host Ollama daemon was offline, this result **does not yet establish generalization to live continuous LLM inference, unconstrained application architectures, or real-world security engagements**. Real-world target traffic must remain strictly out of scope until live model validation is completed under explicit authorization.

---

## 15. Historical Appendix: Original EXP-0003 Reported Metrics

The following metrics were originally reported in EXP-0003 prior to the EXP-0004 Metric Integrity Audit. They are preserved here verbatim for provenance and reproducibility auditing:

### Original Primary Metric Table (Synthetic Useful Yield)
| Track | LOW Budget (5m / 1 exp) | MEDIUM Budget (15m / 3 exps) | HIGH Budget (30m / 5 exps) |
| :--- | :---: | :---: | :---: |
| **Track A (Rules)** | 0.000 | 0.000 | 0.000 |
| **Track B (RAG 3B)** | 0.000 | 0.000 | 0.000 |
| **Track C (RAG 7B)** | 0.000 | 0.000 | 0.000 |
| **Track D (App Model + Inv)** | 0.000 | 0.000 | 0.000 |
| **Track E (Full V6)** | **0.868** | **0.878** | **0.878** |

*Original Formula in Code (`src/eval/scorer.py:97`):* `useful_count / hyp_count` (which calculated Hypothesis-Level Utility, equivalent to Precision for Track E where all TP hypotheses were useful).

### Original Evaluation Split ($N=28$)
* Track E (All Budgets): Precision = 0.857 (95% CI: 0.601, 0.960), Recall = 1.000, F1 = 0.923, Abst. Prec = 1.000, Disc. Rate = 1.000, Useful Yield = 0.857.

### Original Full Benchmark ($N=84$)
* Track E (LOW): Precision = 0.868 (95% CI: 0.727, 0.942), Recall = 0.917, F1 = 0.892, Abst. Prec = 0.935, Disc. Rate = 1.000, Useful Yield = 0.868.
* Track E (MED/HIGH): Precision = 0.878 (95% CI: 0.744, 0.947), Recall = 1.000, F1 = 0.935, Abst. Prec = 1.000, Disc. Rate = 1.000, Useful Yield = 0.878.

---

## 16. Corrected Metrics (EXP-0004 Recomputation)

Following the EXP-0004 audit, metrics were recomputed directly from raw per-scenario outputs, resolving the mathematical collision between Target-Level Useful Yield ($\text{Useful\_TP} / \text{Total\_Vuln}$) and Hypothesis Utility Rate ($\text{Useful\_TP} / \text{Total\_Hypotheses}$):

### Corrected Useful Hypothesis Yield @ Reviewer Budget (Target-Level: $\text{Useful\_TP} / \text{Total\_Vuln}$)
| Track | LOW Budget (5m / 1 exp) | MEDIUM Budget (15m / 3 exps) | HIGH Budget (30m / 5 exps) |
| :--- | :---: | :---: | :---: |
| **Track A (Rules)** | 0.0000 (0/36) | 0.0000 (0/36) | 0.0000 (0/36) |
| **Track B (RAG 3B)** | 0.0000 (0/36) | 0.0000 (0/36) | 0.0000 (0/36) |
| **Track C (RAG 7B)** | 0.0000 (0/36) | 0.0000 (0/36) | 0.0000 (0/36) |
| **Track D (App Model + Inv)** | 0.0000 (0/36) | 0.0000 (0/36) | 0.0000 (0/36) |
| **Track E (Full V6)** | **0.9167** (33/36) | **1.0000** (36/36) | **1.0000** (36/36) |

### Corrected Evaluation Split ($N=28$, Total Vulnerable = 12)
| Track | Budget Tier | Precision (95% CI, $n$) | Recall (95% CI, $n$) | Useful Yield (95% CI, $n$) | Hyp. Utility Rate | TP | FP | TN | FN |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Track A** | All | 0.5000 (0.2993, 0.7007, $n=20$) | 0.8333 (0.5520, 0.9530, $n=12$) | 0.0000 (0.0000, 0.2425, $n=12$) | 0.0000 | 10 | 10 | 6 | 2 |
| **Track B** | All | 0.5000 (0.3143, 0.6857, $n=24$) | 1.0000 (0.7575, 1.0000, $n=12$) | 0.0000 (0.0000, 0.2425, $n=12$) | 0.0000 | 12 | 12 | 4 | 0 |
| **Track C** | All | 0.5000 (0.3143, 0.6857, $n=24$) | 1.0000 (0.7575, 1.0000, $n=12$) | 0.0000 (0.0000, 0.2425, $n=12$) | 0.0000 | 12 | 12 | 4 | 0 |
| **Track D** | All | 0.5000 (0.3143, 0.6857, $n=24$) | 1.0000 (0.7575, 1.0000, $n=12$) | 0.0000 (0.0000, 0.2425, $n=12$) | 0.0000 | 12 | 12 | 4 | 0 |
| **Track E** | All | **0.8571** (0.6006, 0.9599, $n=14$) | **1.0000** (0.7575, 1.0000, $n=12$) | **1.0000** (0.7575, 1.0000, $n=12$) | **1.0000** | 12 | 2 | 14 | 0 |

### Corrected Full Benchmark ($N=84$, Total Vulnerable = 36)
| Track | Budget Tier | Precision (95% CI, $n$) | Recall (95% CI, $n$) | Useful Yield (95% CI, $n$) | Hyp. Utility Rate | TP | FP | TN | FN |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Track A** | All | 0.5000 (0.3689, 0.6311, $n=52$) | 0.7222 (0.5601, 0.8415, $n=36$) | 0.0000 (0.0000, 0.0964, $n=36$) | 0.0000 | 26 | 26 | 22 | 10 |
| **Track B** | LOW | 0.5000 (0.3827, 0.6173, $n=66$) | 0.9167 (0.7817, 0.9713, $n=36$) | 0.0000 (0.0000, 0.0964, $n=36$) | 0.0000 | 33 | 33 | 15 | 3 |
| **Track B** | MED/HIGH | 0.5000 (0.3875, 0.6125, $n=72$) | 1.0000 (0.9036, 1.0000, $n=36$) | 0.0000 (0.0000, 0.0964, $n=36$) | 0.0000 | 36 | 36 | 12 | 0 |
| **Track C** | All | 0.5000 (0.3875, 0.6125, $n=72$) | 1.0000 (0.9036, 1.0000, $n=36$) | 0.0000 (0.0000, 0.0964, $n=36$) | 0.0000 | 36 | 36 | 12 | 0 |
| **Track D** | All | 0.5000 (0.3875, 0.6125, $n=72$) | 1.0000 (0.9036, 1.0000, $n=36$) | 0.0000 (0.0000, 0.0964, $n=36$) | 0.0000 | 36 | 36 | 12 | 0 |
| **Track E** | LOW | **0.8684** (0.7267, 0.9425, $n=38$) | 0.9167 (0.7817, 0.9713, $n=36$) | **0.9167** (0.7817, 0.9713, $n=36$) | **0.8684** | 33 | 5 | 43 | 3 |
| **Track E** | MED/HIGH | **0.8780** (0.7446, 0.9468, $n=41$) | **1.0000** (0.9036, 1.0000, $n=36$) | **1.0000** (0.9036, 1.0000, $n=36$) | **0.8780** | 36 | 5 | 43 | 0 |

### Key Audit Highlights
1. **Target-Level Useful Yield vs Hypothesis Utility Rate:** Target-Level Useful Yield is $1.0000$ ($36/36$) for MED/HIGH and $0.9167$ ($33/36$) for LOW. Hypothesis Utility Rate is $0.8780$ ($36/41$) for MED/HIGH and $0.8684$ ($33/38$) for LOW.
2. **Wilson 95% Confidence Interval Denominators:** Precision intervals now correctly use $n = TP + FP$; Recall and Useful Yield intervals now correctly use $n = \text{Total Vulnerable} = 36$ (or $12$ in the evaluation split).
3. **Paired Contingency Table:** Derived programmatically from raw outputs: $n_{11}=0, n_{10}=36, n_{01}=0, n_{00}=0$. Two-sided exact binomial test: $p = 2.91 \times 10^{-11}$.
4. **Epistemic Classification:** The verdict is refined to **SUPPORTED WITHIN CONTROLLED SYNTHETIC BENCHMARK**.
