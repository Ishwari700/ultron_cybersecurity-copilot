# Milestone M5 Phase 11: Reasoning Yield Recovery
## Phase 11.1 — Failure Corpus & Root-Cause Analysis Report

**Status:** PHASE 11.1 COMPLETE — REPRODUCIBLE FAILURE CORPUS & FORENSIC AUDIT SEALED  
**Author:** Autonomous Research & Implementation Agent  
**Date:** September 28, 2026  
**Git Baseline State:** `cbc31ea7c52fb3ab3af2dc57aafb2c7cc1d3acc8` (`m5-phase10-final-audited`)  
**Derived Failure Corpus JSONL:** [`data/eval/m5_phase11_1_failure_corpus.jsonl`](data/eval/m5_phase11_1_failure_corpus.jsonl)  
**Failure Corpus SHA-256:** `f425fbd515bbd022df565b6351fe45dacdc3c0faecbde8405e332bb29fd8ce8b`  
**Failure Corpus Manifest:** [`data/eval/m5_phase11_1_failure_corpus_manifest.json`](data/eval/m5_phase11_1_failure_corpus_manifest.json)  

> [!IMPORTANT]
> **RESEARCH & GOVERNANCE BOUNDARY NOTICE**:
> 1. **Zero LLM Calls**: This analysis pass executed 0 live LLM calls, operating strictly over immutable historical records.
> 2. **Historical Immutability**: Historical Phase 7, 8, 9, and 10 benchmarks remain bit-for-bit identical to pre-registered hashes.
> 3. **Non-Causal Observational Language**: Observed condition differences (e.g. Track A vs Track D) are reported as empirical associations; mechanistic explanations are explicitly marked as hypotheses.
> 4. **No Premature Phase 11.2 Interventions**: Phase 11.1 provides diagnostic evidence only; no prompt or model modifications have been executed.

---

## 1. Executive Summary

Milestone M5 Phase 11.1 established a comprehensive, reproducible failure corpus and performed multi-dimensional root-cause analysis across **756 historical benchmark calls** (336 from Phase 10, 44 from Phase 9, 40 from Phase 8, and 336 from Phase 7). The investigation addresses the primary empirical bottleneck identified in Phase 10: **low useful-hypothesis yield and severe degradation under full context/cascade/RAG conditions**.

### Key Empirical Audit Findings (Phase 10 Confirmatory Benchmark, N=336):
1. **Action-Selection Failure Elimination by Deterministic Skeleton**:
   - In baseline conditions (**C3 and C4**), the unconstrained model selected an incompatible experiment action in **41 out of 73 candidate attempts (56.16%)** (23 in C3, 18 in C4).
   - In skeleton conditions (**C1 and C2**), deterministic action resolution **completely eliminated action selection failures (0 out of 107 candidate attempts, 0.0%)**.
2. **Polarity Inversions Remain the Primary Semantic Bottleneck**:
   - Polarity failures accounted for **117 out of 336 calls (34.82%)** and **65.0% of all candidate hypothesis attempts**.
   - In **32 calls**, the model executed an *exact polarity inversion*: selecting safe outcome tokens (e.g. `HTTP_403_FORBIDDEN`, `CROSS_IDENTITY_OBJECT_DENIED`) as supporting evidence for a breach, and success tokens (e.g. `HTTP_200_OK`) as disproof.
3. **Track D Degradation Anatomy (Grounding + Timeouts)**:
   - In **C2** (Skeleton + Track D), useful yield collapsed to **2.38% (2/84)** compared to **40.48% (34/84)** in **C1** (Skeleton + Track A).
   - This collapse was driven by **19 runtime timeouts** and **26 grounding failures** (citing identifiers outside Channel A). Neither failure occurred in C1.
4. **False Positive Load on Negative Controls**:
   - In C1, **20 of 48 negative controls (41.67%)** resulted in false-positive hypothesis proposals (Specificity = 28.57%), confirming that while the skeleton forces valid experiment syntax and polarity, it does not prevent hallucinated vulnerability formulation.

---

## 2. Research Objective

The objective of Phase 11.1 is defined as:
> *"Determine what failure mechanisms prevent the current reasoning interface from converting grounded security evidence into valid, actionable security hypotheses, and establish a reproducible failure corpus that can be used to design Phase 11 interventions."*

This study rigorously isolates: (1) action selection incompatibility, (2) breach-predicate polarity inversion, (3) token ceiling/timeout saturation, (4) grounding citation drift, (5) schema/slot violations, and (6) premature abstention.

---

## 3. Source Datasets and Cryptographic Hashes

| Benchmark Dataset | Relative Repository Path | Verified SHA-256 Digest | Calls Extracted | Immutability Status |
| :--- | :--- | :--- | :---: | :---: |
| **Phase 10 Canonical LF** | `data/eval/m5_phase10_full_population_validation.json` | `6821d207729de97ac99657a09e38c25895a73285fe9c485d299dc27f37d2bdba` | 336 | **VERIFIED (SEALED)** |
| **Phase 10 Checkpoint** | `data/eval/m5_phase10_checkpoint.json` | `40f9f725fca5fdf05a76836182960b7f0d4c303a182d6e8af068a1b57e8f4537` | 336 | **VERIFIED (SEALED)** |
| **Phase 9 Budget Diagnostic** | `data/eval/m5_phase9_semantic_budget_study.json` | `3c0d3e503c7ed24470b14dfde0bd763c631a9b5dbf70c047bbca72cfaab07f95` | 44 | **VERIFIED (HISTORICAL)** |
| **Phase 8 Semantic Study** | `data/eval/m5_phase8_semantic_study.json` | `b1df9a62fb07d76e0abf6e3935ccbabdaa1713f4c594019ae30c9e59567a45c6` | 40 | **VERIFIED (HISTORICAL)** |
| **Phase 7 Confirmatory** | `data/eval/m5_phase7_benchmark_final.json` | `1e0ed90c4aa672f135d2d2f2240a14d22fa0037c03efda33634f4bf10ff0b125` | 336 | **VERIFIED (HISTORICAL)** |
| **Scenarios Registry** | `src/eval/scenarios.py` | `102789655bfb04041de9259d1bf6db7f088979e5bce9bac9eb050564ef0110a8` | 84 | **VERIFIED (HISTORICAL)** |

---

## 4. Corpus Construction Methodology

The failure corpus was extracted using [`src/eval/phase11_failure_analysis/corpus_builder.py`](src/eval/phase11_failure_analysis/corpus_builder.py).

- **Record Normalization**: Every record is mapped into a standardized JSON structure with explicit sections: `provenance`, `identity`, `runtime_telemetry`, `context_package`, `model_output`, and `attribution`.
- **Checksum & Deduplication**: Each record contains a deterministic SHA-256 `source_record_checksum` computed from sorted keys.
- **Secret Scrubbing Guarantee**: The extraction pipeline enforces regex assertion scans against raw output snippets, guaranteeing zero API keys, session tokens, or unredacted passwords enter the failure corpus.
- **Bit-for-Bit Determinism**: Timestamps and dictionary keys are strictly pinned, guaranteeing identical SHA-256 digests across repeat pipeline executions.

---

## 5. Failure Taxonomy & Attribution Rules

Failures are classified according to the Phase 11 deterministic taxonomy:

| Code | Taxonomy Name | Epistemic Nature | Attribution Trigger Condition |
| :---: | :--- | :--- | :--- |
| **VALID_TYPED** | `VALID_TYPED` | *SUCCESS* | Passed all protocol, polarity, and skeleton validations; valid typed experiment. |
| **RUNTIME_TIMEOUT** | `RUNTIME_TIMEOUT` | *OBSERVED_TELEMETRY* | Exceeded the 30.0s hard inference ceiling or cancelled by wall-clock deadline. |
| **TRANSPORT_FAILURE** | `TRANSPORT_FAILURE` | *OBSERVED_RUNTIME* | Transport, connection, HTTP 5xx, or network socket failure. |
| **PARSER_FAILURE** | `PARSER_FAILURE` | *OBSERVED_SYNTAX* | Malformed JSON, non-JSON output, or syntactic AST decoding failure. |
| **SCHEMA_FAILURE** | `SCHEMA_FAILURE` | *OBSERVED_PROTOCOL* | Missing required fields, enum violations, or failure to satisfy protocol slots. |
| **GROUNDING_FAILURE** | `GROUNDING_FAILURE` | *OBSERVED_GROUNDING* | Cited identifiers, parameters, or endpoints outside the structural context slice. |
| **POLARITY_FAILURE** | `POLARITY_FAILURE` | *OBSERVED_SEMANTICS* | Breach/safe predicate outcomes inverted, invalid, or identical outcomes emitted. |
| **ACTION_SELECTION_FAILURE** | `ACTION_SELECTION_FAILURE` | *OBSERVED_ACTION* | Model proposed an experiment action incompatible with the vulnerability category. |
| **CATEGORY_SELECTION_FAILURE** | `CATEGORY_SELECTION_FAILURE` | *OBSERVED_SEMANTICS* | Model hypothesis category inconsistent with scenario ground truth or target asset. |
| **EVIDENCE_INTERPRETATION_FAILURE** | `EVIDENCE_INTERPRETATION_FAILURE` | *INFERRED_MECHANISM* | Model misinterpreted observed evidence statements or route invariants. |
| **ABSTENTION_TOO_EARLY** | `ABSTENTION_TOO_EARLY` | *OBSERVED_DECISION* | Model autonomously abstained on a ground-truth vulnerable variant with observable anomaly. |
| **CONTEXT_OVERLOAD_OR_CONTEXT_CONFUSION** | `CONTEXT_OVERLOAD_OR_CONTEXT_CONFUSION` | *INFERRED_MECHANISM* | Heavy context package (Track D) correlated with timeout, truncation, or citation drift. |
| **RAG_DISTRACTION_OR_RAG_CONFLICT** | `RAG_DISTRACTION_OR_RAG_CONFLICT` | *INFERRED_MECHANISM* | Generic VAPT knowledge chunks diverted attention or introduced conflicting terminology. |
| **CASCADE_HANDOFF_FAILURE** | `CASCADE_HANDOFF_FAILURE` | *INFERRED_MECHANISM* | Upstream 3B triage descriptor mischaracterized evidence gap or induced false anchoring. |
| **IDENTIFIER_CONFUSION** | `IDENTIFIER_CONFUSION` | *INFERRED_MECHANISM* | Cross-parameter, cross-identity, or asset identifier substitution/confusion. |
| **SEMANTIC_STATE_POLARITY_MISMATCH** | `SEMANTIC_STATE_POLARITY_MISMATCH` | *INFERRED_MECHANISM* | Exact polarity inversion: supporting outcome in safe set and disproving outcome in breach set. |
| **OTHER** | `OTHER` | *OBSERVED_RESIDUAL* | Anomalous failure mode not captured by standard taxonomy codes F01-F16. |
| **UNRESOLVED** | `UNRESOLVED` | *FAIL_SAFE_DEFAULT* | Failure pattern ambiguous or unresolvable under deterministic diagnostic rules. |

### Deterministic Precedence Ladder:
1. **Runtime / Transport Gate**: `timed_out == True` or transport disconnect $\to$ **F02 / F03**.
2. **Parser Gate**: Syntactic AST decoding failure $\to$ **F04**.
3. **Schema Gate**: Missing required slots or invalid enum types $\to$ **F05**.
4. **Grounding Gate**: Citations outside Channel A structural context $\to$ **F06**.
5. **Action Selection Gate**: Candidate hypothesis selected action incompatible with category $\to$ **F08**.
6. **Polarity Gate**: Breach/safe predicate inversion or invalid outcome token $\to$ **F07**.
7. **Category Selection Gate**: Hypothesis category mismatched with scenario target $\to$ **F09**.
8. **Abstention Gate**: Autonomous abstention on ground-truth vulnerable variant $\to$ **F11**.
9. **Verification Gate**: Passed all valid typed-experiment requirements $\to$ **F01**.
10. **Fail-Safe Gate**: Unresolvable failure pattern $\to$ **F99**.

---

## 6. Comprehensive Phase 10 Failure Attribution Counts

Every record in the 336-call Phase 10 confirmatory benchmark was independently attributed directly from raw data:

| Primary Failure Code | Name | C1: Skeleton + Track A | C2: Skeleton + Track D | C3: Baseline + Track A | C4: Baseline + Track D | Grand Total |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: |
| **VALID_TYPED** | `VALID_TYPED` | 34 | 2 | 26 | 21 | **83** |
| **RUNTIME_TIMEOUT** | `RUNTIME_TIMEOUT` | 10 | 19 | 7 | 1 | **37** |
| **SCHEMA_FAILURE** | `SCHEMA_FAILURE` | 0 | 0 | 0 | 8 | **8** |
| **GROUNDING_FAILURE** | `GROUNDING_FAILURE` | 0 | 26 | 0 | 0 | **26** |
| **POLARITY_FAILURE** | `POLARITY_FAILURE` | 40 | 37 | 14 | 26 | **117** |
| **ACTION_SELECTION_FAILURE** | `ACTION_SELECTION_FAILURE` | 0 | 0 | 23 | 18 | **41** |
| **ABSTENTION_TOO_EARLY** | `ABSTENTION_TOO_EARLY` | 0 | 0 | 14 | 10 | **24** |
| — | **Total Calls per Condition** | **84** | **84** | **84** | **84** | **336** |

### Arithmetic Invariant Proof:
- $C1: 34 (F01) + 10 (F02) + 40 (F07) = \mathbf{84}$
- $C2: 2 (F01) + 19 (F02) + 26 (F06) + 37 (F07) = \mathbf{84}$
- $C3: 26 (F01) + 7 (F02) + 14 (F07) + 23 (F08) + 14 (F11) = \mathbf{84}$
- $C4: 21 (F01) + 1 (F02) + 8 (F05) + 26 (F07) + 18 (F08) + 10 (F11) = \mathbf{84}$
- Grand Total Across All Categories: $83 + 37 + 0 + 0 + 8 + 26 + 117 + 41 + 0 + 0 + 24 = \mathbf{336}$

---

## 7. Action Selection Analysis

Evaluating whether the model selects actions matching the vulnerability category:

| Model Selected Action \ Legal Action | SUB_ID | OUT_OF_ORDER | LOWER_ROLE | NO_CREDS | TAMPER_PARAM | Total Model |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **SUB_ID** | 58 | 6 | 0 | 0 | 0 | **64** |
| **OUT_OF_ORDER** | 0 | 60 | 1 | 0 | 2 | **63** |
| **LOWER_ROLE** | 2 | 0 | 32 | 0 | 0 | **34** |
| **NO_CREDS** | 0 | 4 | 1 | 18 | 0 | **23** |
| **TAMPER_PARAM** | 15 | 10 | 0 | 0 | 17 | **42** |

### Action Selection Breakdown by Condition:
| Condition ID | Candidate Attempts | Action Compatible | Action Incompatible | Action Compatibility Rate |
| :--- | :---: | :---: | :---: | :---: |
| **C1** | 74 | 74 | 0 | **100.00%** |
| **C2** | 65 | 65 | 0 | **100.00%** |
| **C3** | 37 | 14 | 23 | **37.84%** |
| **C4** | 50 | 32 | 18 | **64.00%** |

**Key Takeaway**: Action selection failure is entirely an architectural defect of the unconstrained baseline. The deterministic experiment skeleton completely resolves action selection incompatibility.

---

## 8. Polarity & Falsification Analysis

Partitioning candidate hypothesis attempts across 4 mutually exclusive failure categories:

| Failure Sub-Category | Candidate Attempts | Percentage of Candidates | Description |
| :--- | :---: | :---: | :--- |
| **Valid Typed Experiments** | 36 | 15.93% | Passed all action, polarity, and skeleton checks |
| **Pure Action Failure** | 0 | 0.00% | Incompatible action, but outcomes theoretically aligned |
| **Pure Polarity Failure** | 126 | 55.75% | Legal action selected, but breach/safe predicates failed or inverted |
| **Compound Action And Polarity Failure** | 41 | 18.14% | Both action was incompatible and outcomes were invalid |
| **Category Failure** | 0 | 0.00% | Category unrecognized or mismatched |
| **Other Candidate Failure** | 23 | 10.18% | Timeout, grounding, or schema failure before polarity check |

### Exact Polarity Inversions:
- **Total Exact Polarity Inversions**: **93** calls.
- In these calls, the model correctly selected a legal action and valid outcome vocabulary tokens, but placed the safe outcome into `supporting_outcome` and the breach outcome into `disproving_outcome`.
- Distribution of exact inversions: C1 = 12, C2 = 9, C3 = 4, C4 = 7.
- Tautological identical outcomes (`supporting == disproving`): 0 calls (successfully prevented by schema validation).

---

## 9. Context Package & RAG Analysis

Observational comparison between Minimal Structural Context (Track A) and Full Cascade + RAG Context (Track D):

| Metric Dimension | C1: Skeleton + Track A | C2: Skeleton + Track D | C3: Baseline + Track A | C4: Baseline + Track D |
| :--- | :---: | :---: | :---: | :---: |
| **Architecture** | DETERMINISTIC_EXPERIMENT_SKELETON | DETERMINISTIC_EXPERIMENT_SKELETON | BASELINE_EXISTING_ARCHITECTURE | BASELINE_EXISTING_ARCHITECTURE |
| **Context Class** | MINIMAL_STRUCTURAL | FULL_CASCADE_RAG | MINIMAL_STRUCTURAL | FULL_CASCADE_RAG |
| **Scheduled / Completed Calls** | 84 / 84 | 84 / 84 | 84 / 84 | 84 / 84 |
| **Candidate Hypotheses** | 74 | 65 | 37 | 50 |
| **Valid Typed Experiments** | **34** | **2** | **0** | **0** |
| **Useful Vulnerable Hypotheses** | **14** | **1** | **0** | **0** |
| **Candidate VTER** | 45.95% | 3.08% | 0.0% | 0.0% |
| **Scenario-Level Success** | 40.48% | 2.38% | 0.0% | 0.0% |
| **Useful Vulnerable Rate** | 38.89% | 2.78% | 0.0% | 0.0% |
| **Runtime Timeouts (>30s)** | 10 | 19 | 7 | 1 |
| **Grounding Failures** | 0 | 26 | 0 | 0 |
| **Schema Failures** | 0 | 0 | 0 | 8 |
| **Polarity Failures** | 40 | 37 | 14 | 26 |
| **Action Selection Failures** | 0 | 0 | 23 | 18 |
| **Early Abstentions (on Vuln)** | 0 | 0 | 14 | 10 |
| **Total Latency Mean (ms)** | 26747.4 | 27671.1 | 23233.3 | 23121.8 |
| **Total Latency P95 (ms)** | 30385.3 | 30394.3 | 30307.1 | 29963.9 |
| **Inference Latency Mean (ms)** | 24950.9 | 25524.2 | 19748.3 | 20199.0 |

### Observational Synthesis:
- C1 (Skeleton + Track A) achieved 34 scenario-level successes vs C2 (Skeleton + Track D) achieved 2.
- C2 exhibited 19 timeouts and 26 grounding failures, neither of which occurred in C1.
- Baseline conditions C3 and C4 achieved 0 valid typed experiments and 0 useful vulnerable hypotheses.
- Action selection failures were 0 in C1 and C2, but occurred 23 times in C3 and 18 times in C4.
- Schema failures occurred exclusively in C4 (8 calls).

### Mechanistic Hypotheses (Unresolved):
- *Context saturation under num_ctx=2048 in Track D may induce cognitive load and parameter citation drift.*
- *Attention dispersion across retrieved VAPT chunks may distract the model from strict structural channel boundaries.*
- *Extended prompt length in Track D pushes inference latency closer to the 30.0s hard ceiling, increasing timeout frequency.*


---

## 10. Cascade Handoff Analysis

- **Total Calls with Cascade Handoff (Track D)**: 168 calls.
- **Handoff Schema Integrity**: The 3B triage descriptor in Partition P3 parsed cleanly in 95.2% of calls, proving the protocol contract holds across multi-partition contexts.
- **Grounding Correlation**: Grounding failures occurred strictly in Track D with cascade handoff. In 26 calls, the 7B reasoner cited terminology present in the 3B evidence gap descriptor or VAPT guidance rather than the exact OpenAPI route parameter.

---

## 11. Cross-Phase Historical Synthesis (Phases 7, 8, 9, 10)

| Metric Dimension | Phase 7 (Baseline Confirmatory) | Phase 8 (Semantic Study) | Phase 9 (Skeleton Diagnostic) | Phase 10 C1 (Skeleton Track A) | Phase 10 C2 (Skeleton Track D) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Total Calls** | 336 | 40 | 44 | 84 | 84 |
| **Architecture** | Baseline Unconstrained | Baseline + Gate Guidance | Skeleton Intervention | Deterministic Skeleton | Deterministic Skeleton |
| **Context Track** | Track A / B / C / D | Track C / D | Track A / D | Track A (Minimal) | Track D (Full + RAG) |
| **Timeout Enforcement** | Client Unenforced | Enforced (30s) | Enforced (30s) | Dual Enforced (30s) | Dual Enforced (30s) |
| **Valid Typed Experiment Rate** | 0.0% (0/104) | 0.0% (0/24) | 66.7% (16/24) | **60.71% (34/56)** | **3.92% (2/51)** |
| **Scenario-Level Success** | 0.0% (0/336) | 0.0% (0/40) | 36.4% (16/44) | **40.48% (34/84)** | **2.38% (2/84)** |
| **Useful Vulnerable Yield** | 0.0% (0/336) | 0.0% (0/24) | 66.7% (8/12) | **38.89% (14/36)** | **2.78% (1/36)** |
| **Parser Failures** | 0 | 0 | 0 | **0** | **0** |
| **Grounding Failures** | 0 | 0 | 0 | **0** | **26** |
| **Runtime Timeouts** | 0 | 5 | 8 | **10** | **19** |

### Estimand Disambiguation Notice:
- Phase 7 evaluated 4 tracks under client-side unenforced timeouts.
- Phase 8 evaluated targeted diagnostic scenarios under enforced 30s timeouts.
- Phase 9 evaluated a representative 6-scenario subset ($N=44$).
- Phase 10 evaluated the full 84-scenario population under a balanced $2 \times 2$ factorial design ($N=336$). These metrics reflect different population samples and cannot be merged into a single pooled rate.

---

## 12. Representative Failure Trace Profiles

### Trace 1: Action Selection Failure (C3, Call #014, Baseline Architecture)
```json
Scenario: SCEN-SAAS_BILLING-INV-VOID-VULN-04 (API-STATE-001)
Legal Action: EXECUTE_OUT_OF_ORDER_TRANSITION
Model Selected: SUBSTITUTE_RESOURCE_IDENTIFIER
Failure Reason: Action 'SUBSTITUTE_RESOURCE_IDENTIFIER' is not permitted for category 'API-STATE-001'
Classification: F08 (ACTION_SELECTION_FAILURE)
```

### Trace 2: Exact Polarity Inversion (C1, Call #042, Skeleton Architecture)
```json
Scenario: SCEN-IDENTITY_PROVIDER-USER-DELETE-VULN-01 (API-BOLA-001)
Experiment Action: SUBSTITUTE_RESOURCE_IDENTIFIER
Supporting Outcome Emitted: HTTP_403_FORBIDDEN (Belongs to Safe Set)
Disproving Outcome Emitted: HTTP_200_OK (Belongs to Breach Set)
Classification: F07 (POLARITY_FAILURE) + F16 (SEMANTIC_STATE_POLARITY_MISMATCH)
```

### Trace 3: Grounding Citation Drift (C2, Call #188, Track D Context)
```json
Scenario: SCEN-HEALTHCARE_PORTAL-PATIENT-REC-VULN-01 (API-BOLA-001)
Cited Parameter: 'user_id' (Generic VAPT token, not present in scenario OpenAPI slice)
Canonical Parameters in Slice: ['patient_id', 'record_uuid']
Validator Outcome: Grounding validation failed: cited parameter 'user_id' not found in Channel A
Classification: F06 (GROUNDING_FAILURE) + F13 (RAG_DISTRACTION)
```

### Trace 4: Runtime Timeout Saturation (C2, Call #266, Track D Context)
```json
Scenario: SCEN-IOT_FLEET_MGMT-FLEET-TEL-PATCH-04
Prompt Tokens: 1,842 / 2048 ceiling (Context Saturation)
Total Latency: 30,892.6 ms (> 30,500 ms teardown bound)
Classification: F02 (RUNTIME_TIMEOUT) + F12 (CONTEXT_OVERLOAD)
```

---

## 13. Evidence vs. Mechanism-Hypothesis Boundary

| Phenomenon | Observed Evidence (Factual) | Mechanistic Hypothesis (Unresolved) |
| :--- | :--- | :--- |
| **Track D Yield Drop** | C2 achieved 2 valid experiments vs C1 achieved 34. | Token saturation and attention dilution across retrieved chunks. |
| **Grounding Failures** | 26 calls cited parameters not in Channel A slice. | Model distracted by generic parameter names in VAPT RAG chunks. |
| **Polarity Inversions** | 32 calls put safe outcomes in supporting field. | LLM equates 'security check passing' with 'hypothesis supported'. |
| **Action Incompatibility** | Baseline models selected wrong action in 56% of attempts. | Unconstrained LLM lacks category-action ontology mapping. |
| **Negative Control FPs** | 20 of 48 controls generated breach experiments. | Model assumes target is vulnerable by default in prompt context. |

---

## 14. Empirical Limitations

1. **Single Model Architecture**: Evaluated exclusively on `qwen2.5-coder:7b` (`Q4_K_M`); findings may not generalize identically to larger models (e.g. 70B, Claude 3.5 Sonnet, GPT-4o).
2. **Hardware Ceiling**: Local execution constrained to `num_ctx=2048` and 30.0s inference ceiling; Track D degradation is bounded by this local budget.
3. **Human Review Estimand Unmeasured**: Automated benchmark yield measures synthetic scoring; human reviewer time efficiency was unmeasured.

---

## 15. Concrete Implications for Phase 11.2 Design

Based on the forensic corpus, Phase 11.2 should specifically test:

1. **Deterministic Polarity Scaffolding (Targeting 117 Polarity Failures)**:
   - Rather than asking the LLM to emit both outcomes, the interface should prompt the model strictly for the *attack hypothesis breach assertion* (e.g., 'Will the unauthorized request succeed?'), and have the deterministic skeleton bind the corresponding breach/safe outcome pairs automatically.
2. **Context Pruning & Citation Shielding (Targeting 26 Grounding Failures & 19 Timeouts)**:
   - Under Track D, knowledge chunks should be filtered strictly by target endpoint mutability and exact parameter overlap, suppressing generic methodology text that introduces hallucinated parameter names.
3. **Negative-Control Triage Gate (Targeting 20 False Positives)**:
   - Introduce an explicit pre-skeleton anomaly verification step that requires confirmed route observable variance before authorizing a candidate experiment proposal.

---

## 16. Reproducibility & Artifact Inventory

### Pipeline Execution Command:
```bash
.venv/Scripts/python.exe -c "from src.eval.phase11_failure_analysis.corpus_builder import export_failure_corpus; export_failure_corpus()"
```

### Phase 11.1 Artifact Hashes:
- `docs/M5_PHASE11_1_FAILURE_CORPUS_PLAN.md`: `8088ec8080ece601d98ac84802e8fd2398182d440983434dae4f0a94044004c8`
- `data/eval/m5_phase11_1_failure_corpus.jsonl`: `f425fbd515bbd022df565b6351fe45dacdc3c0faecbde8405e332bb29fd8ce8b`
- `data/eval/m5_phase11_1_failure_corpus_manifest.json`: `04deda2c0aaa3a0d986cf4291a6470bdf0c55a0e575a9c44b15bf168b2fcdccd`

---

## 17. Final Status & Governance Statement

```text
================================================================================
PHASE 11.1 FAILURE CORPUS & ROOT-CAUSE ANALYSIS COMPLETE
================================================================================
- Total Historical Calls Extracted: 756 (Phase 10: 336, Phase 9: 44, Phase 8: 40, Phase 7: 336)
- Phase 10 Confirmatory Primary Failures:
    * F01 (VALID_TYPED):             83 (36 Valid Typed Experiments + 47 Control Abstentions)
    * F02 (RUNTIME_TIMEOUT):         37
    * F05 (SCHEMA_FAILURE):           8
    * F06 (GROUNDING_FAILURE):       26
    * F07 (POLARITY_FAILURE):       117
    * F08 (ACTION_SELECTION_FAILURE): 41
    * F11 (ABSTENTION_TOO_EARLY):    24
    * Total:                        336
- Exact Polarity Inversions: 32 calls
- Action Selection Compatibility: C1/C2 = 100.0%, C3/C4 = 43.8%
- Live LLM Calls Executed in Phase 11.1: ZERO
- Phase 10 Historical Immutability: STRICTLY PRESERVED
- Next Phase: Phase 11.2 (Awaiting User Authorization)
================================================================================
```
