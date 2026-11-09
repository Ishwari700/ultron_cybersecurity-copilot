# Milestone M5 Phase 6.9 — Policy 3 Evaluation-Scoring Harness Implementation Record

**Document Identifier**: `docs/M5_PHASE6_9_POLICY3_SCORING_IMPLEMENTATION.md`  
**Phase Status**: COMPLETE (EVALUATION-HARNESS IMPLEMENTATION ONLY)  
**Governance & Constraints**: Strictly offline implementation of evaluation scoring components. Zero live LLM calls. Zero modifications to production reasoning semantics (`HypothesisDecision`, `BairJsonObject`, `ReasoningRunner`, `deterministic_decide` remain untouched). Zero modifications to frozen benchmark scenarios or expected decisions (`src/eval/scenarios.py`). Zero modifications to historical benchmark artifacts. No execution of the 84-scenario benchmark or 336-call confirmatory benchmark.  
**Repository State Classification**: **`M5_PHASE6_9_POLICY3_SCORING_IMPLEMENTED_BENCHMARK_BLOCKED`**

---

## 1. Executive Summary

Milestone M5 Phase 6.8 formally resolved the benchmark-policy conflict by selecting **POLICY 3: PRESERVE PRODUCTION DECISION STATE; DISAGGREGATE EVALUATION SCORING**.

Phase 6.9 implements this governance decision exclusively within the evaluation and scoring layer (`src/eval/scorer.py` and `src/eval/__init__.py`), providing:
1. **Deterministic Canonical Evidence Applicability**: Evaluator-side classification of scenarios based strictly on approved Class-1 structural anomaly predicates, with zero access to hidden ground truth, expected decisions, scenario ID suffixes, or model-generated prose.
2. **Dual-Track Evaluation Scoring**:
   - **Track 1 (Vulnerability Hypothesis Evaluation)**: Evaluated when canonical evidence presents active breach indications.
   - **Track 2 (Exploratory Verification Evaluation)**: Evaluated when relevant endpoints present unverified invariants under neutral documentation.
3. **Preservation of the Frozen Primary Research Estimand**:
   - The primary research estimand remains exactly **`Useful Hypothesis Yield @ N reviewer minutes`** under its frozen mathematical definition ($TP_{\text{useful}} / N_{\text{total vulnerable}}$).
   - Decomposed views (Vulnerability Yield, Exploratory Verification Validity Rate, Polarity Compatibility Rate, Grounding Rate) are computed in parallel.
4. **Zero Production Contamination**: No production engine code was modified. Historical scorer methods (`DeterministicScorer.score()`) remain 100% backward compatible and reproducible.

---

## 2. Canonical Evidence Applicability Predicate

### The Rule
Applicability MUST NOT be determined from model-generated prose, `evidence_gap` text, claims that a FACT is anomalous, `expected_decision`, `ground_truth_vulnerable`, scenario ID suffixes (`-VULN-`, `-PATCH-`), model confidence, model decisions, or methodology references.

### Implementation: `canonical_vulnerability_evidence_present`
In [`src/eval/scorer.py`](src/eval/scorer.py):
```python
CANONICAL_ANOMALY_KEYS: Set[str] = {
    # Class-1 structural predicate booleans from LosslessStructuralPack
    "has_cross_identity_object_access_success",
    "has_privilege_level_delta",
    "status_code_changed_under_different_role",
    "has_unauthenticated_success",
    "has_cross_role_response_shape_delta",
    "has_observed_contradictions",
    "has_evidence_parse_asymmetry",
    # Structured anomaly flags in observation records
    "observed_cross_identity_access",
    "observed_privilege_delta",
    "status_code_differential",
    "response_shape_differential",
    "observed_invariant_contradiction",
    "observed_unauthorized_success",
    "observed_state_transition_violation",
}
```

The function `canonical_vulnerability_evidence_present(evidence, structural_pack)` inspects only:
- Approved Class-1 predicate booleans on `LosslessStructuralPack`;
- Explicit structured anomaly booleans in canonical evidence items;
- Explicit `anomaly_detected` / `is_anomaly` flags.

If the evidence consists solely of OpenAPI documentation (e.g. `source_tool == "openapi"` and `certainty == "DOCUMENTED"` without active anomaly flags), the predicate evaluates strictly to `False`.

---

## 3. Evaluator State Machine

The evaluator classifies each execution record into one of four mutually exclusive, deterministic evaluator-side states via `determine_applicability_state()`:

```
                                      [Execution Record]
                                              |
                                              v
                                     Is output valid?
                             (parser, schema, polarity, grounding)
                                           /      \
                                         NO        YES
                                         /          \
                       [INVALID_OUTPUT]              v
                                           Is target functionality
                                                  relevant?
                                                   /      \
                                                 NO        YES
                                                 /          \
                             [NON_RELEVANT_EVALUATION]       v
                                                   Does canonical evidence
                                                   contain approved anomaly?
                                                           /      \
                                                         YES       NO
                                                         /          \
                                                        v            v
                                             [VULNERABILITY]    [EXPLORATORY]
```

### Evaluator State Definitions:
1. **`VULNERABILITY_EVALUATION_APPLICABLE`**: Canonical evidence contains an approved empirical anomaly or invariant breach indication.
2. **`EXPLORATORY_EVALUATION_APPLICABLE`**: Relevant functionality exists, invariant is unverified, and no approved canonical anomaly predicate is present (e.g. neutral OpenAPI route documentation).
3. **`NON_RELEVANT_EVALUATION`**: Functionality is outside the examined security property (e.g. static public endpoints `/catalog`, `/.well-known/openid-configuration`).
4. **`INVALID_OUTPUT`**: Parsing, schema, polarity, grounding, or transport failure.

---

## 4. Formal TP / FP / TN / FN Semantics

Under Policy 3, truth labels (`ground_truth_vulnerable`) are inspected **only after** the output has been assigned to its applicability track:

### Track 1: Vulnerability Hypothesis Scoring (`VULNERABILITY_EVALUATION_APPLICABLE`)
| Metric | Condition |
| :--- | :--- |
| **True Positive (TP)** | Model emits `HYPOTHESIS`, passes validation (parsing, schema, polarity, grounding), and `ground_truth_vulnerable == True`. |
| **False Positive (FP)** | Model emits `HYPOTHESIS`, passes validation, but `ground_truth_vulnerable == False`. |
| **True Negative (TN)** | Model emits `INSUFFICIENT_EVIDENCE` or `NO_RELEVANT_FUNCTIONALITY`, and `ground_truth_vulnerable == False`. |
| **False Negative (FN)** | Model emits `INSUFFICIENT_EVIDENCE` or `NO_RELEVANT_FUNCTIONALITY`, and `ground_truth_vulnerable == True`. |

### Track 2: Exploratory Verification Scoring (`EXPLORATORY_EVALUATION_APPLICABLE`)
| Metric | Condition |
| :--- | :--- |
| **Valid Exploratory Proposal** | Model emits `HYPOTHESIS`, valid typed action, valid supporting outcome, valid disproving outcome, passes `ExperimentPolarityValidator`, passes grounding, targets relevant parameter. |
| **Abstention** | Model emits `INSUFFICIENT_EVIDENCE` or `NO_RELEVANT_FUNCTIONALITY`. |
| **Invalid Proposal** | Model emits proposal with invalid polarity, malformed schema, ungrounded IDs, or syntax errors. |

> [!IMPORTANT]
> A valid exploratory proposal on an unverified endpoint is scored as a **Valid Exploratory Proposal**, NOT as a False Positive, regardless of whether the backend server happens to be patched. Ground truth is not inspected when evaluating the validity of an exploratory proposal.

---

## 5. Reviewer Presentation Mapping

To reflect real-world security triage workflows without modifying production enums, the evaluator maps outputs to four descriptive `ReviewerPresentationLabel` categories:

1. **`VULNERABILITY_FINDING`**: Model emitted a valid hypothesis on an endpoint with observed anomaly evidence (*"Observed evidence indicates a potential security violation; reproduction experiment proposed."*)
2. **`EXPLORATORY_VERIFICATION_PROPOSAL`**: Model emitted a valid discriminative test proposal on an unverified endpoint (*"Relevant endpoint has an unverified security property; discriminative test proposed."*)
3. **`ABSTENTION_CONFIRMED`**: Model cleanly abstained on incomplete evidence or non-relevant functionality (*"Evidence is insufficient or functionality is not relevant; abstained cleanly."*)
4. **`INVALID_PROPOSAL`**: Model emitted an output that failed schema, polarity, or grounding gates (*"Output failed validation, polarity, or grounding gates; rejected."*)

---

## 6. Primary Research Estimand Preservation & Decomposition Table

The primary research estimand is strictly preserved and remains the authoritative top-line metric.

| Metric Name | Frozen Estimand? | Evaluator Role | Requires Ground Truth? | Historical M4 Baseline Comparability |
| :--- | :--- | :--- | :--- | :--- |
| **Useful Hypothesis Yield @ N reviewer minutes** | **YES** | **Primary Research Estimand** | YES (checks gold vulnerability) | **100% Identical Formula** ($TP_{\text{useful}} / N_{\text{total vuln}}$) |
| **Vulnerability-Hypothesis Yield** | NO | Decomposed Secondary Metric | YES (checks gold vulnerability) | Decomposed view for active evidence cases |
| **Exploratory Verification Validity Rate** | NO | Decomposed Secondary Metric | NO (intrinsic experiment validity) | New measurement for test generation |
| **Polarity Compatibility Rate** | NO | Decomposed Secondary Metric | NO (4-tuple compatibility) | New measurement for semantic alignment |
| **Grounding Rate** | YES | Secondary Metric | NO (factual reference validity) | Directly comparable to M4 |
| **Precision** | YES | Diagnostic Metric | YES | Directly comparable to M4 |
| **TPR (Recall)** | YES | Diagnostic Metric | YES | Directly comparable to M4 |
| **TNR (Specificity)** | YES | Diagnostic Metric | YES | Directly comparable to M4 |
| **Legacy M4 Composite** | YES | Legacy Baseline Metric | YES | Embedded in `legacy_metrics` for exact parity |

---

## 7. Canonical BOLA Negative-Control Handling

In the canonical BOLA pair:
- **Scenario 1**: `SCEN-SAAS_BILLING-INV-DETAILS-VULN-01` (`ground_truth_vulnerable = True`)
- **Scenario 3**: `SCEN-SAAS_BILLING-INV-DETAILS-PATCH-01` (`ground_truth_vulnerable = False`)

Both scenarios present neutral OpenAPI documentation (`GET /api/v1/invoices/{id}`) with zero runtime logs. Under Policy 3:
1. Both evaluate to `canonical_vulnerability_evidence_present == False`.
2. Both receive `applicability_state = EXPLORATORY_EVALUATION_APPLICABLE`.
3. If both generate the valid authorization test (`SUBSTITUTE_RESOURCE_IDENTIFIER` -> `CROSS_IDENTITY_OBJECT_ACCESSIBLE` vs `CROSS_IDENTITY_OBJECT_DENIED`):
   - Both count toward `valid_exploratory_proposals += 1`.
   - **Neither is penalized as an exploratory False Positive**.
   - **Neither enters the vulnerability False Positive count**, preventing artificial suppression of the agent's specificity on unobserved routes.

---

## 8. Historical Comparability and Immutability

1. **Frozen Historical Artifacts**: All past benchmark files (`data/eval/m4_live_llm_benchmark_final.json`, `data/eval/m5_live_smoke.json`, `data/eval/m5_live_smoke_v2.json`, `data/eval/m5_typed_protocol_live_smoke.json`) are immutable and will never be regenerated or re-scored.
2. **Reproducibility of Legacy Scorer**: `DeterministicScorer.score()` was preserved with zero functional modifications. Calling `score()` on any past run yields byte-identical numbers.
3. **New Policy 3 Interface**: Policy 3 scoring is invoked via `score_policy3()` on `DeterministicScorer` (or `Policy3DeterministicScorer`), returning `Policy3EvaluationMetrics` which contains both the legacy `EvaluationMetrics` and the decomposed metrics.

---

## 9. Deterministic Unit Tests

The test suite [`tests/unit/test_m5_policy3_evaluation.py`](tests/unit/test_m5_policy3_evaluation.py) implements 15 exhaustive deterministic tests:

| Test Identifier | Invariant Verified | Result |
| :--- | :--- | :--- |
| `test_01_identical_observable_bola_pair_gets_identical_applicability_state` | Vulnerable and patched BOLA pair receive identical `EXPLORATORY_EVALUATION_APPLICABLE` | **PASSED** |
| `test_02_neutral_documentation_yields_exploratory_applicability` | Neutral OpenAPI documentation yields `EXPLORATORY_EVALUATION_APPLICABLE` | **PASSED** |
| `test_03_canonical_observed_anomaly_yields_vulnerability_applicability` | Class-1 structural booleans yield `VULNERABILITY_EVALUATION_APPLICABLE` | **PASSED** |
| `test_04_model_prose_cannot_change_applicability_state` | Model prose in `evidence_gap` or `reasoning_summary` cannot alter applicability | **PASSED** |
| `test_05_ground_truth_cannot_change_model_side_applicability_state` | Flipping `ground_truth_vulnerable` leaves applicability state identical | **PASSED** |
| `test_06_valid_exploratory_proposal_on_patched_neutral_endpoint_is_not_exploratory_fp` | Valid test proposal on patched endpoint counts as valid exploratory, not FP | **PASSED** |
| `test_07_vulnerability_fp_remains_fp_when_vulnerability_evidence_active` | Active anomaly scenario on patched target strictly scores as vulnerability FP | **PASSED** |
| `test_08_malformed_output_yields_invalid_output_state` | Schema/parser/polarity failure yields `INVALID_OUTPUT` | **PASSED** |
| `test_09_valid_typed_tuple_yields_exploratory_valid_when_appropriate` | Valid 4-tuple on exploratory endpoint yields `is_valid_exploratory_proposal = True` | **PASSED** |
| `test_10_frozen_useful_hypothesis_yield_definition_remains_unchanged` | Useful Hypothesis Yield strictly matches historical formula ($TP_{\text{useful}} / N_{\text{total vuln}}$) | **PASSED** |
| `test_11_legacy_scorer_remains_reproducible` | `DeterministicScorer.score()` produces exact historical point metrics | **PASSED** |
| `test_12_no_benchmark_artifact_modification` | Protected evaluation artifacts match pinned SHA-256 digests | **PASSED** |
| `test_13_no_ground_truth_leakage_into_runtime_applicability` | Signature inspection proves ground truth is not accessed during applicability checks | **PASSED** |
| `test_14_evaluator_never_promotes_exploratory_evidence_into_vulnerability_evidence` | Neutral docs without Class-1 flags are never promoted to vulnerability state | **PASSED** |
| `test_15_evaluator_never_downgrades_observed_vulnerability_evidence` | Class-1 anomaly is never downgraded to exploratory state | **PASSED** |

---

## 10. Regression & Integrity Verification

- **New Policy 3 Unit Tests**: 15 passed in 0.45s.
- **Full M5 & Integrity Regression Suite**: **180 passed in 0.88s** across 11 modules:
  - `tests/unit/test_m5_policy3_evaluation.py`: 15 passed
  - `tests/unit/test_m5_hypothesis_governance_design.py`: 8 passed
  - `tests/unit/test_m5_typed_experiment_protocol.py`: 19 passed
  - `tests/unit/test_m5_composition.py`: 33 passed
  - `tests/unit/test_m5_decision_boundary_audit.py`: 9 passed
  - `tests/unit/test_m5_end_to_end.py`: 30 passed
  - `tests/unit/test_m5_experiment_semantics_design.py`: 7 passed
  - `tests/unit/test_m5_falsification_semantics_audit.py`: 7 passed
  - `tests/unit/test_m5_smoke_fidelity.py`: 14 passed
  - `tests/unit/test_real_ablation_integrity.py`: 8 passed
  - `tests/unit/test_m4_deterministic_decision_policy.py`: 30 passed

### Protected File SHA-256 Hashes:
All protected artifacts were verified byte-identical before and after implementation:

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

---

## 11. Modified and New Files

- **Modified Files**:
  - [`src/eval/scorer.py`](src/eval/scorer.py): Added Policy 3 evaluation types, predicates, and `DeterministicScorer.score_policy3()`.
  - [`src/eval/__init__.py`](src/eval/__init__.py): Exported Policy 3 evaluation symbols.
- **New Files**:
  - [`tests/unit/test_m5_policy3_evaluation.py`](tests/unit/test_m5_policy3_evaluation.py): 15 deterministic unit tests.
  - [`docs/M5_PHASE6_9_POLICY3_SCORING_IMPLEMENTATION.md`](docs/M5_PHASE6_9_POLICY3_SCORING_IMPLEMENTATION.md): This report.

---

## 12. Final State & Benchmark Status

### Repository State Classification:
# **`M5_PHASE6_9_POLICY3_SCORING_IMPLEMENTED_BENCHMARK_BLOCKED`**

### Explicit Confirmation:
- The 84-scenario benchmark was **NOT RUN** in Phase 6.9.
- The 336-call confirmatory run was **NOT RUN** in Phase 6.9.
- Zero live LLM calls were executed in Phase 6.9.
- Evaluation harness implementation is complete, verified, and gated.
- Execution of the full benchmark remains strictly blocked until formal authorization of Phase 7 (or subsequent benchmark phase).
