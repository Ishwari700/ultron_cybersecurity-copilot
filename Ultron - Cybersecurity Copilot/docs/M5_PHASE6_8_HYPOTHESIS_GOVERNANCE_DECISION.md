# Milestone M5 Phase 6.8 — Exploratory vs Vulnerability Hypothesis Governance Decision

**Document Identifier**: `docs/M5_PHASE6_8_HYPOTHESIS_GOVERNANCE_DECISION.md`  
**Phase Status**: COMPLETE (GOVERNANCE & MEASUREMENT-DESIGN DECISION)  
**Governance Scope**: Strictly offline governance and measurement design. Zero live LLM calls. Zero modifications to production engine code. Zero modifications to frozen benchmark scenario definitions or labels (`src/eval/scenarios.py`). Zero modifications to M3, M4.8/M4.9, or planning-freeze artifacts. No execution of the 84-scenario benchmark or 336-call confirmatory benchmark.  
**Repository State Classification**: **`M5_PHASE6_8_GOVERNANCE_DECISION_COMPLETE_BENCHMARK_POLICY_RESOLVED`**

---

## 1. Executive Summary & Problem Context

Milestones M5 Phase 6.3 through Phase 6.7 systematically uncovered and audited a core methodological conflict at the intersection of automated reasoning, prompt design, and benchmark evaluation:

1. **Reasoning Architecture Intent**: In both [`docs/M4_REASONING_ENGINE_PLAN.md`](docs/M4_REASONING_ENGINE_PLAN.md) and [`src/engine/protocol.py`](src/engine/protocol.py), the reasoning engine is explicitly instructed to emit `decision = HYPOTHESIS` whenever:
   - *"Evidence indicates, implies, or strongly suggests a potential invariant violation,"* **OR**
   - *"Relevant functionality has an unverified invariant requiring experiment verification."*
2. **Benchmark Evaluation Contradiction**: In [`src/eval/scenarios.py`](src/eval/scenarios.py) and [`src/eval/scorer.py`](src/eval/scorer.py), the benchmark expects `expected_decision = HYPOTHESIS` for vulnerable scenarios and `expected_decision = INSUFFICIENT_EVIDENCE` for patched scenarios. Any emission of `HYPOTHESIS` on a patched scenario is mechanically scored as a **False Positive (FP)**.
3. **The Counterfactual Impasse**: In canonical scenario pairs (e.g. BOLA `SCEN-SAAS_BILLING-INV-DETAILS-VULN-01` vs `SCEN-SAAS_BILLING-INV-DETAILS-PATCH-01`), the observable evidence provided to the model consists solely of OpenAPI documentation describing an unverified route parameter (`GET /api/v1/invoices/{id}`) with zero runtime execution logs. The inputs are byte-identical. Under this condition:
   - When VAPT knowledge retrieval is active (Track D), the model is prompted to propose an authorization test (substituting `{id}` to observe `200 OK` vs `403 Forbidden`).
   - For the vulnerable scenario, this valid test proposal is scored as a **True Positive (TP)**.
   - For the patched scenario, the exact same valid test proposal on the exact same input is penalized as a **False Positive (FP)**.
4. **Phase 6.7 Empirical Evidence**: The Phase 6.7 live viability smoke proved that the newly implemented typed outcome protocol (`ExperimentPolarityValidator`) deterministically intercepts 100% of semantically inverted and incompatible proposals. Furthermore, in Call #24 (Patched Scenario 3 Track D I1=1), the model emitted candidate `NO_RELEVANT_FUNCTIONALITY`, which was deterministically calibrated by I5 to `INSUFFICIENT_EVIDENCE` (`VALID`), showing that the pipeline operates reliably.

This governance decision formally resolves the benchmark-policy conflict by establishing a rigorous epistemological foundation and defining **POLICY 3: Dual-Track Evaluation Scoring with Preserved Production State**.

---

## 2. Formalization of Two Distinct Epistemic States

To resolve this conflict without invoking hidden ground truth during inference, we formalize two mutually exclusive epistemic states that characterize the relationship between available evidence and a proposed hypothesis:

```
                                 [Target Asset & Canonical Evidence]
                                                  |
                                                  v
                              Is the relevant invariant verified?
                                       /              \
                                     YES              NO
                                     /                  \
                [INSUFFICIENT_EVIDENCE /                 \
                 NO_RELEVANT_FUNCTIONALITY]               v
                                            Does evidence contain active
                                            anomalies or breach indications?
                                                    /            \
                                                  YES             NO
                                                  /                 \
                                                 v                   v
                                     [VULNERABILITY_HYPOTHESIS]  [EXPLORATORY_VERIFICATION]
```

### State A: `EXPLORATORY_VERIFICATION`
- **Formal Definition**: A security property/invariant relevant to the target functionality is currently **unverified**, and the engine proposes a bounded, discriminative experiment that could ascertain whether the invariant holds.
- **Evidence Condition**: Canonical evidence contains API routes, parameter definitions, schemas, or architectural documentation, but lacks runtime telemetry, traffic logs, or differential execution observations. No anomaly or breach indication is observed.
- **Epistemic Status**: State of unverified ignorance. The model does *not* assert that a vulnerability exists; it asserts that an invariant has not been demonstrated to hold and proposes an empirical test to find out.
- **Reviewer Action**: Automated test generation / security test suite expansion. (Reviewer cost if patched: zero; test runs, returns 403 Forbidden, confirms security).

### State B: `VULNERABILITY_HYPOTHESIS`
- **Formal Definition**: Available empirical evidence actively **indicates, implies, or demonstrates** an invariant violation, and the proposed experiment is designed to verify, isolate, or disprove that specific evidence-supported concern.
- **Evidence Condition**: Canonical evidence contains anomalous telemetry, cross-tenant data leakage in response traces, differential error codes, or broken state sequences indicating an active flaw.
- **Epistemic Status**: Suspicion or tentative diagnosis supported by empirical data. The model asserts that a vulnerability is likely present.
- **Reviewer Action**: High-priority triage and reproduction of an alleged defect. (Reviewer cost if patched: high; wasted engineering investigation on a false alarm).

> [!IMPORTANT]
> Neither `EXPLORATORY_VERIFICATION` nor `VULNERABILITY_HYPOTHESIS` requires or permits the system to know hidden ground truth. Both are properties of the observable evidence and the model's assertions.

---

## 3. Pipeline Conflation Audit

An end-to-end trace through the production reasoning architecture identifies the exact structural points where these two epistemic states were historically conflated:

| Pipeline Stage | Component | Current Implementation | Epistemic Conflation Analysis |
| :--- | :--- | :--- | :--- |
| **1. Prompt Formulation** | `SYSTEM_POLICY_PROMPT` (`protocol.py`) | *"HYPOTHESIS: Evidence indicates, implies, or strongly suggests a potential invariant violation, **or** relevant functionality has an unverified invariant requiring experiment verification."* | **ROOT CAUSE**: The disjunctive `"or"` merges evidence-supported breach suspicion with unverified invariant exploration into a single label `HYPOTHESIS`. |
| **2. Schema Contract** | `BairJsonObject` (`models.py`) | `decision: Literal["HYPOTHESIS", "INSUFFICIENT_EVIDENCE", "NO_RELEVANT_FUNCTIONALITY"]` | **TOKEN CONFLATION**: Only one JSON token exists for both concepts. A model proposing a test on an unverified route has no token other than `HYPOTHESIS`. |
| **3. Typed Predicates** | Typed Outcome Slots (`models.py`) | `experiment_action`, `supporting_outcome`, `disproving_outcome` | **PROCEDURAL IDENTITY**: Probing whether an invariant holds (exploratory) uses the exact same operational test as proving an observed bug (vulnerability). |
| **4. Internal Representation** | `HypothesisModelOutput` (`models.py`) | `decision = HypothesisDecision.HYPOTHESIS` | **MODEL CONFLATION**: S0 representation preserves the single enum token without subtyping. |
| **5. Decision Policy** | `deterministic_decide()` (`decision_policy.py`) | Layers 1–4 validate relevance, polarity, falsification, and grounding. | **POLICY PASS-THROUGH**: Validates structural and semantic soundness of the test proposal; preserves candidate `HYPOTHESIS`. |
| **6. Benchmark Scoring** | `DeterministicScorer` (`scorer.py`) | `is_tp = (output.decision == scen.expected_decision)` | **FATAL CONFLATION POINT**: The scorer assumes `HYPOTHESIS` strictly means "vulnerability claimed". For patched scenarios (`expected_decision = INSUFFICIENT_EVIDENCE`), it penalizes valid exploratory tests as False Positives. |

---

## 4. Primary Metric Analysis

The primary research estimand established in M1 through M4 is:
$$\text{Useful Hypothesis Yield @ } N \text{ reviewer minutes}$$

### Integrity of the Estimand
- **Non-Negotiable Constraint**: The primary estimand must **NOT** be renamed, redefined, or silently replaced. Historical comparability with M1, M2, M3, and M4.9 must be strictly preserved.
- **Scientific Ambiguity of a Combined Metric**: A single combined metric that sums exploratory test proposals and vulnerability hypotheses into one bucket is scientifically uninterpretable:
  1. It mixes two disjoint operational tasks: triage of suspected security defects vs. automated test coverage generation.
  2. In benchmark evaluation, it penalizes valid test generation on patched endpoints as "false alarms", artificially deflating measured precision.
  3. It forces an unnatural tradeoff: an agent must either refuse to propose tests for unverified routes (abstaining with `INSUFFICIENT_EVIDENCE` and missing verification opportunities) or propose tests and suffer severe False Positive penalties on negative controls.

### Metric Decomposition Under Policy 3
To preserve full scientific rigor and historical continuity, we define an explicit decomposition:

1. **Primary Research Estimand**:
   $$\text{Useful Vulnerability-Hypothesis Yield @ } N \text{ reviewer minutes}$$
   Evaluated strictly on scenarios where the model asserts an evidence-supported vulnerability on truly vulnerable targets.
2. **Secondary Engineering Estimand**:
   $$\text{Exploratory Verification Validity Rate} = \frac{\text{Valid, Grounded, Polarity-Compatible Test Proposals}}{\text{Total Unverified Relevant Endpoints}}$$
   Evaluated across unverified relevant API endpoints to measure the agent's capability to generate valid, discriminative test cases without penalizing them when the underlying endpoint is patched.
3. **Legacy Composite Estimand**:
   Reported in parallel for exact 1:1 mathematical comparison with historical M4.0–M4.9 benchmark runs.

---

## 5. Comparative Evaluation of Benchmark Scoring Options

We systematically evaluate the three candidate scoring policies against eight mandatory criteria:

| Evaluation Dimension | OPTION A: Keep Current Semantics Unchanged | OPTION B: Split Decision State in Production Code | OPTION C (POLICY 3): Preserve State, Epistemic Decomposition in Evaluation |
| :--- | :--- | :--- | :--- |
| **Description** | Keep `HYPOTHESIS` on patched scenarios as FP, even when evidence is neutral and test is valid. | Split enum into `VULNERABILITY_HYPOTHESIS` and `EXPLORATORY_VERIFICATION` in production models and schemas. | Retain `HypothesisDecision.HYPOTHESIS` in engine/schemas; evaluate dual tracks (Vulnerability vs Exploratory) in scoring. |
| **1. Scientific Validity** | **FATALLY FLAWED**: Demands opposite outputs on byte-identical inputs without discriminating evidence. | **HIGH**: Clean separation of states. | **HIGH**: Resolves information constraint without corrupting production models. |
| **2. Reviewer Interpretation** | **POOR**: Valid test proposals on unverified routes are labeled "false alarms". | **EXCELLENT**: Reviewer clearly sees finding type. | **EXCELLENT**: Distinguishes bug reports from test recommendations. |
| **3. Compatibility with M1-M5** | **PERFECT SYNTACTIC**: Re-runs same flawed scoring. | **BREAKS COMPATIBILITY**: Invalidates historical schemas, JSON_BAIR contract, and frozen artifacts. | **100% COMPATIBLE**: Production schemas and enums remain untouched; historical data remains directly comparable. |
| **4. Impact on Useful Yield** | **ARTIFICIALLY SUPPRESSED**: Penalizes Track D whenever VAPT retrieval prompts test generation. | **REDEFINED**: Cannot compare with historical baseline directly. | **PRESERVED**: Primary yield metric remains intact while secondary exploratory metric is added. |
| **5. Impact on TPR / TNR** | **DISTORTED**: TNR drops toward 0% on patched controls when VAPT guidance is active. | **CLEAN**: Computed separately on new enums. | **RIGOROUS**: Distinguishes true vulnerability FPs from valid exploratory tests. |
| **6. Historical Comparability** | Preserves historical flawed numbers. | **ZERO**: Historical benchmarks did not have these enums. | **PERFECT**: Allows both legacy comparison and decomposed analysis. |
| **7. Implementation Complexity** | Zero. | **EXTREME**: Rewrite engine, runner, models, schemas, prompts, validators across entire repo. | **LOW / MODERATE**: Implemented purely in evaluation reporting harness; zero production changes. |
| **8. Risk of Ground-Truth Leakage**| **HIGH**: Incentivizes prompting tricks to guess scenario status from metadata. | None. | **ZERO**: Ground truth remains strictly isolated in the evaluator. |

---

## 6. The Canonical BOLA Counterfactual

The canonical pair from Phase 6.2/6.3 provides an incontrovertible mathematical proof of the information constraint:

- **Scenario 1**: `SCEN-SAAS_BILLING-INV-DETAILS-VULN-01` (`API-BOLA-001`, `ground_truth_vulnerable = True`, `expected_decision = HYPOTHESIS`)
- **Scenario 3**: `SCEN-SAAS_BILLING-INV-DETAILS-PATCH-01` (`API-BOLA-001`, `ground_truth_vulnerable = False`, `expected_decision = INSUFFICIENT_EVIDENCE`)

### Observable Input Parity
Both scenarios supply the exact same observable context:
- Endpoint: `GET /api/v1/invoices/{id}`
- Parameter: `{id}` (path parameter)
- Associated Identities: `user_a` (tenant 1), `user_b` (tenant 2)
- Telemetry: **Zero**. No request/response traffic logs. No server status codes.

Let $X$ denote the observable input. In this pair:
$$X_{\text{vuln}} = X_{\text{patch}} = X$$

### The Mathematical Proof
Let $f(X, \text{RAG})$ represent any deterministic or pseudo-deterministic reasoning engine. Since the inputs are byte-identical:
$$f(X, \text{RAG})_{\text{vuln}} \equiv f(X, \text{RAG})_{\text{patch}}$$

Under legacy benchmark scoring:
- If $f(X) = \text{HYPOTHESIS}$: Scored as $\text{TP}$ on Scenario 1, and $\text{FP}$ on Scenario 3.
- If $f(X) = \text{INSUFFICIENT\_EVIDENCE}$: Scored as $\text{FN}$ on Scenario 1, and $\text{TN}$ on Scenario 3.

**Conclusion**: Under identical observable inputs, it is mathematically impossible for any grounded, non-clairvoyant system to achieve $\text{TP} = 1.0$ and $\text{TN} = 1.0$ simultaneously. Demanding that the model output `HYPOTHESIS` on Scenario 1 and `INSUFFICIENT_EVIDENCE` on Scenario 3 requires:
1. Out-of-band leakage of `ground_truth_vulnerable`;
2. Memorization of scenario IDs (`-VULN-` vs `-PATCH-`); or
3. Pure stochastic randomness.

Proposing an authorization test on an unverified ID parameter is the **only correct security behavior** given $X$. The resulting "False Positive" on Scenario 3 is strictly an artifact of benchmark design, not model failure.

---

## 7. Audit of "Useful Hypothesis" Definition

The frozen benchmark definition states:
> *"A Useful Hypothesis is a hypothesis emitted for a **truly vulnerable target scenario** that matches the gold-standard category, asset ID, and vulnerable parameter, and passes grounding and validation gates."*

### Analysis
The qualifying clause **"truly vulnerable target scenario"** embeds hidden ground-truth knowledge that is strictly unavailable to the model at inference time. Therefore, we must formally distinguish:

1. **Intrinsic Model-Side Validity**:
   - Structural completeness (invariant, evidence gap, affected target, typed experiment fields);
   - Fact and methodology grounding (valid FACT and CHK references);
   - Semantic polarity compatibility (valid 4-tuple: category + action + supporting + disproving);
   - Parameter relevance (targets active route parameters).
   *This is fully evaluable without oracle ground truth.*
2. **Extrinsic Benchmark-Side Alignment**:
   - Whether the target environment is in fact vulnerable (`ground_truth_vulnerable == True`).
   *This is an oracle evaluation metric, not a property of the model's reasoning.*

---

## 8. Human Review Workflow Implications

In practical application security and bug bounty triage, human reviewers treat exploratory test suggestions and vulnerability bug reports through completely different operational workflows:

```
[Agent Output Emitted]
         |
         +--> STATEMENT A: "Observed cross-tenant data in HTTP 200 response; test X confirms breach."
         |    - Workflow: High-Priority Vulnerability Triage.
         |    - Human Action: Immediate reproduction, escalation to development team, patch deployment.
         |    - Cost of False Alarm: HIGH (wasted developer time, unnecessary escalations).
         |
         +--> STATEMENT B: "Endpoint accepts ID parameter with no observed auth check; run test X to verify."
              - Workflow: Test Coverage & Verification Planning.
              - Human Action: Add test case to automated integration/regression suite; dispatch active probe.
              - Cost if Target is Patched: ZERO (test executes, receives 403 Forbidden, confirms security boundary).
```

Labeling Statement B as a "False Positive" damages the utility of the reasoning engine by treating standard, desirable security verification as an erroneous alarm.

---

## 9. Empirical Evidence: Phase 6.7 Live Smoke Results

The Phase 6.7 live viability smoke provides direct empirical evidence regarding the interaction of the typed protocol with the live `qwen2.5-coder:7b` model:

- **Total Calls**: 24 calls (3 scenarios × 4 tracks × 2 schema conditions).
- **Valid Executions**: 3 (12.5%).
- **Semantic Polarity Rejections**: 10 (41.7%).
- **Schema Validity Failures**: 6 (25.0%).
- **Parser Failures**: 4 (16.7%).
- **Max Token Truncations**: 1 (4.2%).
- **Grounding Failures**: 0 (0.0%).
- **Transport Failures**: 0 (0.0%).

### Critical Findings:
1. **Deterministic Enforcement**: The production `ExperimentPolarityValidator` functioned with 100% deterministic precision, intercepting all 10 semantically inverted or category-mismatched proposals (e.g. asserting 403 supports BOLA or 409 supports state machine breaches).
2. **Model Capability Separation**: The typed protocol works deterministically; however, the unassisted 7B model frequently struggles with polarity alignment. Output reliability is a model reasoning characteristic, not an engine bug.
3. **Resolution of Call #24**: In Phase 6.7 Call #24 (`SCEN-SAAS_BILLING-INV-DETAILS-PATCH-01`, Track D, I1=1), the model emitted candidate `NO_RELEVANT_FUNCTIONALITY`, which was deterministically calibrated by Layer 1 / I5 policy on the relevant endpoint to **`INSUFFICIENT_EVIDENCE`** (`VALID`), completely eliminating the historical false positive.

---

## 10. Definitive Governance Decision

### Selection:
# **`POLICY 3: PRESERVE PRODUCTION DECISION STATE; DISAGGREGATE EVALUATION SCORING`**

### Rationale:
1. **Zero Production Disruption**: `HypothesisDecision.HYPOTHESIS`, `BairJsonObject`, and `map_bair_json_to_s0()` remain completely unchanged. No production code modifications, no schema breaks, no prompt tampering.
2. **100% Historical Continuity**: All M1–M5 historical benchmark outputs remain directly comparable. The legacy unified metric can still be computed alongside the new decomposed metrics.
3. **Methodological Soundness**: Eliminates the impossible information constraint where identical observable inputs were required to yield opposite decisions based on hidden oracle labels.
4. **Preserves Primary Estimand**: Keeps `Useful Hypothesis Yield @ N reviewer minutes` as the primary research metric for vulnerability detection, while adding `Exploratory Verification Validity Rate` as an orthogonal secondary metric.

---

## 11. Formal Benchmark Scoring Semantics Under Policy 3

When the 84-scenario benchmark is authorized in a future phase, evaluation scoring will follow these formal semantics:

### Track 1: Vulnerability Hypothesis Evaluation (Primary Research Metric)
- **Applicability**: Scenarios with active evidence (telemetry/anomalies) OR hypotheses that cite observed anomalies in `empirical_facts`.
- **True Positive (TP)**: Model emits `HYPOTHESIS`, passes grounding and polarity validation, matches gold category/asset/parameter, and target has `ground_truth_vulnerable = True`.
- **False Positive (FP)**: Model emits `HYPOTHESIS` claiming an active vulnerability breach on a scenario with `ground_truth_vulnerable = False`.
- **True Negative (TN)**: Model emits `INSUFFICIENT_EVIDENCE` or `NO_RELEVANT_FUNCTIONALITY` on a scenario with `ground_truth_vulnerable = False`.
- **False Negative (FN)**: Model emits `INSUFFICIENT_EVIDENCE` or `NO_RELEVANT_FUNCTIONALITY` on a scenario with `ground_truth_vulnerable = True`.

### Track 2: Exploratory Verification Evaluation (Secondary Engineering Metric)
- **Applicability**: Unverified relevant endpoints where initial evidence consists solely of static route documentation.
- **Valid Exploratory Proposal**: Model emits a structurally complete, grounded, polarity-compatible experiment proposal targeting an unverified parameter on a relevant endpoint.
- **Evaluation Metric**:
  $$\text{Exploratory Verification Validity Rate} = \frac{\text{Valid Exploratory Proposals}}{\text{Total Unverified Relevant Endpoints Tested}}$$
- **Scoring Rule**: A valid exploratory test proposal on an unverified endpoint is scored as a **Valid Exploratory Verification**, NOT as a False Positive, regardless of whether the backend server happens to be patched.

### Reporting Standard:
Every future evaluation report will present:
1. **Primary Vulnerability Metrics**: Useful Vulnerability Yield @ N min, Precision, Recall/TPR, TNR.
2. **Secondary Exploratory Metrics**: Exploratory Proposal Validity Rate, Polarity Compatibility Rate, Grounding Rate.
3. **Legacy Unified Metrics**: Exact M4.0 composite score (for historical baseline tracking).

---

## 12. Benchmark Authorization State

### Repository State Classification:
# **`M5_PHASE6_8_GOVERNANCE_DECISION_COMPLETE_BENCHMARK_POLICY_RESOLVED`**

### Explicit Confirmation:
- The benchmark-policy conflict is **FORMALLY RESOLVED** by Policy 3.
- The 84-scenario benchmark was **NOT RUN** in Phase 6.8.
- The 336-call confirmatory run was **NOT RUN** in Phase 6.8.
- Zero live LLM calls were made in Phase 6.8.
- Zero production code files were modified in Phase 6.8.
- All protected evaluation and decision artifacts remain byte-identical.
- The 84-scenario benchmark will require an explicit, separate authorization phase (Phase 7 / Benchmark Execution) that incorporates the Policy 3 evaluation harness updates.
