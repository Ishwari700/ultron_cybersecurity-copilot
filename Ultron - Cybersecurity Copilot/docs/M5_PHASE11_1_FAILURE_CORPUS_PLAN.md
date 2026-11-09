# Milestone M5 Phase 11: Reasoning Yield Recovery
## Phase 11.1 — Failure Corpus & Root-Cause Analysis Architectural Plan

**Milestone Identifier:** M5 Phase 11 (Reasoning Yield Recovery)  
**Sub-Phase:** Phase 11.1 (Failure Corpus & Root-Cause Analysis)  
**Document Version:** `1.0.0 — FROZEN ARCHITECTURAL SPECIFICATION`  
**Status:** DRAFT / ANALYSIS SPECIFICATION (READ-ONLY ANALYSIS & INFRASTRUCTURE — ZERO LLM CALLS)  
**Parent Milestone State:** Milestone M5 Phase 10 SEALED & IMMUTABLE (`m5-phase10-final-audited`, commit `cbc31ea7c52fb3ab3af2dc57aafb2c7cc1d3acc8`)  

---

## 1. Executive Summary & Research Objective

### 1.1 Context
Milestone M5 Phase 10 executed the preregistered 336-call, 84-scenario $2 \times 2$ factorial confirmatory benchmark, confirming that the Deterministic Experiment Skeleton significantly improved valid typed-experiment construction under Track A (Minimal Structural Context) compared to the unconstrained baseline ($C1=34/84 \text{ vs } C3=0/84, p = 1.164 \times 10^{-10}$).

However, Phase 10 also revealed a stark empirical bottleneck:
- Under Track D (Full Cascade History + VAPT RAG Knowledge Pack), performance dropped severely ($C2=2/84 \text{ vs } C1=34/84, p = 4.657 \times 10^{-10}$).
- Overall useful-hypothesis yield remained constrained ($14/36 = 38.89\%$ in C1, $1/36 = 2.78\%$ in C2), accompanied by 37 timeouts, 26 grounding failures (clustered entirely in C2), 114 polarity failures, and substantial false positives on negative controls ($20/48$ in C1).

### 1.2 Core Research Objective of Phase 11.1
> "Determine what failure mechanisms prevent the current reasoning interface from converting grounded security evidence into valid, actionable security hypotheses, and establish a reproducible failure corpus that can be used to design Phase 11 interventions."

This phase must strictly distinguish:
1. **Model reasoning failure** (inability to synthesize a coherent breach attack chain given grounded facts).
2. **Experiment-action selection failure** (selecting an action incompatible with the vulnerability category).
3. **Polarity failure** (inverting breach vs. safe predicate outcomes, or using safe indicators as breach proof).
4. **Context/interface failure** (token ceiling pressure, prompt construction artifacts, schema constraints).
5. **RAG contamination/distraction** (retrieved generic knowledge diluting attention or introducing incompatible terminology).
6. **Cascade/handoff failure** (3B triage descriptors misleading the 7B reasoner or misrepresenting evidence gaps).
7. **Protocol/schema failure** (JSON syntax, missing required fields, enum violations).
8. **Grounding failure** (referencing identifiers or parameters not present in the structural target slice).
9. **Runtime failure** (wall-clock timeout or socket teardown latency).
10. **Semantic mismatch** (divergence between expected state transitions and model assumptions).
11. **Other / Unresolved** (unclassified failure patterns).

### 1.3 Strict Research Boundary Invariants
1. **Zero LLM Calls**: Phase 11.1 is strictly an offline, deterministic analysis pass over already collected historical artifacts.
2. **Immutability of Sealed Artifacts**: Phase 7, 8, 9, and 10 raw datasets, checkpoints, reports, and code must never be overwritten, modified in-place, or recomputed.
3. **No Premature Causal Assertions**: We distinguish *observed telemetry/validator state* from *inferred mechanistic hypotheses*. Where data shows correlation without causal proof, it is explicitly labeled as an observational association.
4. **No Premature Phase 11.2 Fixes**: No prompt edits, action-selection patches, or RAG changes will be executed during Phase 11.1.

---

## 2. Repository Forensic Inventory

The table below catalogs all existing repository artifacts, reports, schemas, engines, and utilities relevant to Phase 11.1 root-cause analysis:

| # | Artifact Category | Repository Path | File Size (Bytes) | SHA-256 Digest | Role in Phase 11.1 Analysis |
| :-: | :--- | :--- | :-: | :--- | :--- |
| **1** | M5 Phase 10 Final Report | [`docs/M5_PHASE10_FULL_POPULATION_VALIDATION.md`](docs/M5_PHASE10_FULL_POPULATION_VALIDATION.md) | 33,288 | `ee98e15c36b1a3ca2d0becd28b17875b64849c0b6fae68075ec2742dce8c94a9` | Baseline source for audited statistical estimands, contingency tables, and telemetry findings. |
| **2** | M5 Phase 10 Canonical Dataset | [`data/eval/m5_phase10_full_population_validation.json`](data/eval/m5_phase10_full_population_validation.json) | 1,036,984 | `6821d207729de97ac99657a09e38c25895a73285fe9c485d299dc27f37d2bdba` | Authoritative 336-call evaluation dataset (POSIX LF format). Primary source for failure corpus extraction. |
| **3** | M5 Phase 10 Runtime Checkpoint | [`data/eval/m5_phase10_checkpoint.json`](data/eval/m5_phase10_checkpoint.json) | 1,057,481 | `40f9f725fca5fdf05a76836182960b7f0d4c303a182d6e8af068a1b57e8f4537` | Sequential Windows execution checkpoint. Verified semantically invariant with canonical dataset. |
| **4** | M5 Phase 10 Final Seal Manifest | [`data/eval/m5_phase10_final_seal.json`](data/eval/m5_phase10_final_seal.json) | 5,954 | `3134ca638e1f921f200e74e6e29acc4abb5a3927f77abe9aac8cacbe24083e33` | Cryptographic seal manifest confirming 336 calls, condition allocations, and telemetry deviations. |
| **5** | Phase 8 Semantic Study Report & Data | [`docs/M5_PHASE8_SEMANTIC_CAPABILITY_STUDY.md`](docs/M5_PHASE8_SEMANTIC_CAPABILITY_STUDY.md)<br>[`data/eval/m5_phase8_semantic_study.json`](data/eval/m5_phase8_semantic_study.json) | 20,952<br>95,612 | `7f5f80e0d3ff35d80717807fd1e8c8bb4fb25531e7266ccf96936400d8c1140c`<br>`b1df9a62fb07d76e0abf6e3935ccbabdaa1713f4c594019ae30c9e59567a45c6` | Historical attribution study on 104 candidate attempts with prompt polarity guidance. Cross-phase comparator. |
| **6** | Phase 9 Skeleton Study Report & Data | [`docs/M5_PHASE9_DETERMINISTIC_EXPERIMENT_SKELETON.md`](docs/M5_PHASE9_DETERMINISTIC_EXPERIMENT_SKELETON.md)<br>[`data/eval/m5_phase9_semantic_budget_study.json`](data/eval/m5_phase9_semantic_budget_study.json) | 27,205<br>64,136 | `f8e74782fd6f3ec496aa663a25938179687df163575c6a63de2cc02ac54359b0`<br>`3c0d3e503c7ed24470b14dfde0bd763c631a9b5dbf70c047bbca72cfaab07f95` | Historical diagnostic study on 44 calls establishing deterministic skeleton intervention. Cross-phase comparator. |
| **7** | Phase 7 Benchmark Report & Data | [`docs/M5_PHASE7_BENCHMARK_REPORT.md`](docs/M5_PHASE7_BENCHMARK_REPORT.md)<br>[`data/eval/m5_phase7_benchmark_final.json`](data/eval/m5_phase7_benchmark_final.json) | 18,369<br>2,492,176 | `2c5eb26432314ed59d38e402d8640ef7d28d4b3318d17aaf22172f5248b46acf`<br>`1e0ed90c4aa672f135d2d2f2240a14d22fa0037c03efda33634f4bf10ff0b125` | Historical baseline confirmatory benchmark (336 calls). Demonstrates 0% useful yield without skeleton. |
| **8** | Benchmark Scenarios Registry | [`src/eval/scenarios.py`](src/eval/scenarios.py) | 34,490 | `102789655bfb04041de9259d1bf6db7f088979e5bce9bac9eb050564ef0110a8` | Authoritative definition of 84 benchmark scenarios (36 vulnerable variants, 48 negative controls). |
| **9** | Hypothesis & Protocol Models | [`src/engine/models.py`](src/engine/models.py)<br>[`src/engine/protocol.py`](src/engine/protocol.py) | 47,714<br>17,837 | `5951a9759c594c2565c7aba1082c82c3491e41ea991fca465855e7e0bb1134f9`<br>`df781a0e07e50cbfb49c00d842c69c6988e32a9a0e0fe23d75200053451888e2` | Core Pydantic contracts: `BairJsonObject`, `HypothesisModelOutput`, `OutputProtocolContract`. |
| **10** | Experiment Skeleton Engine | [`src/engine/experiment_skeleton.py`](src/engine/experiment_skeleton.py) | 10,493 | `418af3ff740b4c1aa85fc799c96968d1164f8f953ae3f82ede00b0df2571cd49` | Deterministic skeleton builder, legal action mapping, and compliance validator. |
| **11** | Decision Policy & Polarity Validator | [`src/engine/decision_policy.py`](src/engine/decision_policy.py) | 39,488 | `d436641571080f1f4703f0c7d9b1252ee5bd3ef2b1902398f27e0548f3057d9e` | `ExperimentPolarityValidator` and `TUPLE_COMPATIBILITY_REGISTRY` (legal action/outcome tuples). |
| **12** | Context Builder & Token Budgeting | [`src/engine/context_builder.py`](src/engine/context_builder.py)<br>[`src/retrieval/budget.py`](src/retrieval/budget.py) | 26,181<br>7,294 | `5843f60185213f01f58dcccb7c360cc8cb5a4a66a5e278279d329946c7d773d0`<br>— | Modular context compiler for Track A vs Track D, partitioning P0–P4, token budget ceiling enforcement. |
| **13** | Cascade Handoff Models | [`src/engine/handoff_serializer.py`](src/engine/handoff_serializer.py)<br>[`src/evidence/cascade_models.py`](src/evidence/cascade_models.py) | 15,118<br>7,090 | `b8d48be75af54ba5c9ed6a7055cb2585b5a1701394df4f284df6aff37cd291e1`<br>`e79547d1bcbdb312b55b3f748d408dc41961b7b5e65dda3f7f106e676b5c9db2` | `CascadeHandoffPacket`, `DeterministicRoutingDecision`, and Partition P3 descriptor serialization. |
| **14** | Grounding & Forensic Attribution | [`src/validation/grounding.py`](src/validation/grounding.py)<br>[`src/eval/forensic_attribution.py`](src/eval/forensic_attribution.py) | 8,470<br>14,752 | `7e0ff4df01c4b3b0914278c57b26997340a12d1281c3dec0f8e27cc23c116654`<br>— | ID existence checks, parameter-asset grounding validation, and legacy forensic triage rules. |
| **15** | Domain Models (Graph, Invariants, Evidence) | [`src/graph/models.py`](src/graph/models.py)<br>[`src/invariants/models.py`](src/invariants/models.py)<br>[`src/evidence/models.py`](src/evidence/models.py) | 2,812<br>1,839<br>3,573 | `b9320a4316e65bf04d99312f30940dc4dd531343f011d483a555342d93daec58`<br>`f8cca7fee889e9ad0a24b18ebf4ef6855aabdeea038c15575c0659c9323042ec`<br>`b97f9f46760dbbf93853eefcbeddd9405b99abd1570077130f8ec330398379dd` | Core semantic structures: `ApplicationModel`, `SecurityInvariant`, `Observation`, `CanonicalEvidenceItem`. |

---

## 3. Failure Taxonomy (F01 – F17, F99)

The Phase 11.1 taxonomy formalizes failure categorization with explicit separation between **observed telemetry/validator state** and **inferred mechanistic hypothesis**:

```text
+-------------------------------------------------------------------------------------------------------+
|                                    PHASE 11.1 FAILURE TAXONOMY                                        |
+------+--------------------------------------+--------------------+------------------------------------+
| Code | Category Name                        | Nature             | Deterministic Diagnostic Condition |
+------+--------------------------------------+--------------------+------------------------------------+
| F01  | VALID_TYPED                          | Success            | Passed all protocol, polarity,     |
|      |                                      |                    | and skeleton validations.          |
| F02  | RUNTIME_TIMEOUT                      | Observed Telemetry | timed_out == True or > 30.0s HTTP. |
| F03  | TRANSPORT_FAILURE                    | Observed Runtime   | Network/socket disconnect, 5xx.    |
| F04  | PARSER_FAILURE                       | Observed Syntax    | Malformed JSON, unparseable AST.   |
| F05  | SCHEMA_FAILURE                       | Observed Protocol  | Missing mandatory field, bad enum. |
| F06  | GROUNDING_FAILURE                    | Observed Grounding | Cited token not in Channel A slice.|
| F07  | POLARITY_FAILURE                     | Observed Semantics | Breach/safe predicates inverted    |
|      |                                      |                    | or invalid outcome token.          |
| F08  | ACTION_SELECTION_FAILURE             | Observed Action    | Action incompatible with category. |
| F09  | CATEGORY_SELECTION_FAILURE           | Observed Semantics | Category does not match scenario.  |
| F10  | EVIDENCE_INTERPRETATION_FAILURE      | Inferred Reasoning | Misinterpreted observed evidence.  |
| F11  | ABSTENTION_TOO_EARLY                 | Observed Decision  | Abstained on clear vulnerability.  |
| F12  | CONTEXT_OVERLOAD_OR_CONFUSION        | Inferred Mechanism | Large context correlating with     |
|      |                                      |                    | timeout/grounding breakdown.       |
| F13  | RAG_DISTRACTION_OR_CONFLICT          | Inferred Mechanism | RAG chunks diverting attention     |
|      |                                      |                    | or introducing incompatible vocab. |
| F14  | CASCADE_HANDOFF_FAILURE              | Inferred Mechanism | Upstream 3B descriptor divergence. |
| F15  | IDENTIFIER_CONFUSION                 | Inferred Mechanism | Swapped parameters / asset IDs.    |
| F16  | SEMANTIC_STATE_MISMATCH              | Inferred Mechanism | Misunderstood application workflow |
|      |                                      |                    | state or mutability constraints.   |
| F17  | OTHER                                | Observed Residual  | Anomaly not fitting F01-F16.       |
| F99  | UNRESOLVED                           | Fail-Safe Default  | Insufficient evidence to classify. |
+------+--------------------------------------+--------------------+------------------------------------+
```

### Invariant: Single Primary Failure with Multi-Contributing Flags
Every record is assigned:
- Exactly **one** `primary_failure_code` (e.g. `F07`).
- A non-empty list of `contributing_failure_codes` (e.g. `["F07", "F08", "F12"]`), capturing all observed and contextual failure conditions without losing granular telemetry.

---

## 4. Deterministic Attribution Precedence Rules

To prevent subjective model prose from determining failure classifications, failure attribution follows a strict, deterministic evaluation ladder:

```text
[1. Runtime & Transport Gate]
   Is timed_out == True or transport error?
   ├── YES ──> PRIMARY = F02 (RUNTIME_TIMEOUT) or F03 (TRANSPORT_FAILURE)
   └── NO
        │
[2. Syntactic & Protocol Gate]
   Did raw response fail JSON parsing?
   ├── YES ──> PRIMARY = F04 (PARSER_FAILURE)
   └── NO
        │
   Did parsed object fail schema validation / required slots?
   ├── YES ──> PRIMARY = F05 (SCHEMA_FAILURE)
   └── NO
        │
[3. Grounding Gate]
   Did hypothesis reference ungrounded identifiers or fail structural grounding?
   ├── YES ──> PRIMARY = F06 (GROUNDING_FAILURE)
   └── NO
        │
[4. Action Compatibility Gate]
   Was an experiment action proposed that is incompatible with the vulnerability category?
   ├── YES ──> PRIMARY = F08 (ACTION_SELECTION_FAILURE)
   └── NO
        │
[5. Semantic Polarity Gate]
   Did the hypothesis propose a candidate experiment, but fail breach/safe polarity validation?
   ├── YES ──> PRIMARY = F07 (POLARITY_FAILURE)
   └── NO
        │
[6. Category Selection Gate]
   Did the hypothesis select a category inconsistent with the scenario target?
   ├── YES ──> PRIMARY = F09 (CATEGORY_SELECTION_FAILURE)
   └── NO
        │
[7. Decision & Abstention Gate]
   Did the model abstain on a ground-truth vulnerable variant with obvious canonical anomaly?
   ├── YES ──> PRIMARY = F11 (ABSTENTION_TOO_EARLY)
   └── NO
        │
[8. Verification & Success Gate]
   Did the record satisfy all valid typed-experiment invariants?
   ├── YES ──> PRIMARY = F01 (VALID_TYPED)
   └── NO  ──> PRIMARY = F99 (UNRESOLVED)
```

Secondary and mechanism-level flags (e.g. `F12` Context Overload, `F13` RAG Distraction, `F15` Identifier Confusion) are recorded as **contributing failure flags** when their trigger conditions are met.

---

## 5. Failure Corpus Schema Specification

Each record in `data/eval/m5_phase11_1_failure_corpus.jsonl` follows a strict JSON structure:

```json
{
  "corpus_record_id": "CORPUS-M5P10-C1-SCEN-ECOMMERCE_ORDERS-ORD-REFUND-VULN-01-CALL-000",
  "provenance": {
    "source_phase": "PHASE_10",
    "source_artifact": "data/eval/m5_phase10_full_population_validation.json",
    "source_artifact_sha256": "6821d207729de97ac99657a09e38c25895a73285fe9c485d299dc27f37d2bdba",
    "source_call_index": 0,
    "source_record_checksum": "a1b2c3d4...",
    "corpus_pipeline_version": "1.0.0",
    "extracted_at_utc": "2026-09-28T18:30:00Z"
  },
  "identity": {
    "scenario_id": "SCEN-ECOMMERCE_ORDERS-ORD-REFUND-VULN-01",
    "condition_id": "C1",
    "track_id": "TRACK_A",
    "architecture": "DETERMINISTIC_EXPERIMENT_SKELETON",
    "app_family": "ecommerce_orders",
    "target_category_id": "API-STATE-001",
    "vulnerable_variant": true
  },
  "runtime_telemetry": {
    "model_name": "qwen2.5-coder:7b",
    "model_digest": "dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364",
    "num_ctx": 2048,
    "num_predict": 300,
    "temperature": 0.0,
    "seed": 42,
    "timed_out": false,
    "total_latency_ms": 27070.2,
    "inference_latency_ms": 24948.7,
    "eval_count": 210,
    "prompt_eval_count": 850
  },
  "context_package": {
    "context_class": "MINIMAL_STRUCTURAL",
    "rag_present": false,
    "cascade_present": false,
    "handoff_present": true,
    "evidence_gap_type": "STATE_MACHINE_TRANSITION_UNVERIFIED",
    "target_asset_id": "ASSET-ECOMMERCE_ORDERS-ORD-REFUND-01"
  },
  "model_output": {
    "raw_response_snippet": "{\"decision\": \"HYPOTHESIS\", ...}",
    "candidate_decision": "HYPOTHESIS",
    "final_decision": "HypothesisDecision.HYPOTHESIS",
    "experiment_action": "EXECUTE_OUT_OF_ORDER_TRANSITION",
    "supporting_outcome": "HTTP_200_OK",
    "disproving_outcome": "HTTP_400_BAD_REQUEST"
  },
  "attribution": {
    "primary_failure_code": "F01",
    "primary_failure_name": "VALID_TYPED",
    "contributing_failure_codes": ["F01"],
    "observed_validator_failure": "VALID",
    "skeleton_compliant": true,
    "polarity_valid": true,
    "grounding_valid": true,
    "is_valid_typed_experiment": true,
    "is_useful_vulnerable_hypothesis": true
  }
}
```

---

## 6. Detailed Special Analysis Modules

### 6.1 Action Selection Analysis (`action_analysis.py`)
- **Objective**: Determine whether models propose illegal or off-target experiment actions given a vulnerability category.
- **Confusion Matrix**: Maps model-selected actions against legal category actions.
- **Category Clustering**: Identifies whether action selection errors concentrate in complex lifecycle/state-machine categories (e.g. `API-STATE-001`, `API-LIFECYCLE-001`) vs parameter tampering (`API-MUTATION-001`).
- **Context Track Contrasts**: Compares action-selection fidelity between Track A and Track D.

### 6.2 Polarity Analysis (`polarity_analysis.py`)
- **Objective**: Quantify the frequency and patterns of breach-predicate inversions.
- **Decomposition**:
  1. *Pure Action Failure*: Model selected wrong action, regardless of polarity.
  2. *Pure Polarity Failure*: Action was legal, but breach/safe outcomes were inverted or invalid.
  3. *Compound Failure*: Incompatible action and invalid polarity.
  4. *Tautological / Identical Outcomes*: Model proposed `supporting_outcome == disproving_outcome`.

### 6.3 Context & RAG Distraction Analysis (`context_analysis.py` & `rag_analysis.py`)
- **Objective**: Characterize the exact empirical degradation observed in Track D without assuming unproven causal mechanisms.
- **Metrics**: Token density, prompt build time, time-to-first-token, timeout distribution, grounding citation drift (tokens cited outside Channel A).
- **RAG Content Alignment**: Analysis of retrieved chunk relevance to the target asset vs tangential methodology chunks.

### 6.4 Cascade Handoff Analysis (`cascade_analysis.py`)
- **Objective**: Evaluate how 3B handoff descriptors and routing decisions impact downstream 7B reasoning.
- **Patterns**: Evidence gap alignment, invariant statement anchoring, and descriptor length vs reasoning quality.

### 6.5 Cross-Phase Historical Synthesis
- Synthesize findings across **Phase 7** (Baseline, 0% useful yield), **Phase 8** (Polarity Prompting, 0% useful yield), **Phase 9** (Skeleton Diagnostic, 66.7% sample yield), and **Phase 10** (Factorial Full-Population Confirmatory).
- Maintain rigorous separation between disparate estimands (candidate-conditional capability vs scenario-level paired success vs active evidence diagnostic fixtures).

---

## 7. Implementation & Verification Plan

```text
src/eval/phase11_failure_analysis/
├── __init__.py
├── taxonomy.py            # F01-F17, F99 definitions and data models
├── attribution.py         # Deterministic evaluation ladder and rule engine
├── corpus_builder.py      # Extract, normalize, and emit failure corpus JSONL + manifest
├── action_analysis.py     # Action selection confusion matrix & category cross-tabs
├── polarity_analysis.py   # Polarity inversion & compound failure quantification
├── context_analysis.py    # Track A vs Track D observational comparison
├── cascade_analysis.py    # 3B -> 7B handoff and descriptor correlation
├── rag_analysis.py        # RAG chunk alignment and grounding citation drift
└── report_generation.py   # Automated synthesis into Phase 11.1 final report
```

### Deterministic Test Suite (`tests/unit/test_phase11_failure_analysis.py`)
1. **Hash Immutability Test**: Assert all Phase 7, 8, 9, 10 artifact digests match their pre-registered constants.
2. **Corpus Extraction Test**: Verify all 336 Phase 10 records (and historical sets) are processed without data loss.
3. **Precedence Ladder Test**: Assert attribution rules resolve in strict precedence order (Runtime $\to$ Syntax $\to$ Schema $\to$ Grounding $\to$ Action $\to$ Polarity $\to$ Category $\to$ Abstention $\to$ Unresolved).
4. **Action Confusion Test**: Assert legal action resolution matches `ExperimentPolarityValidator.TUPLE_COMPATIBILITY_REGISTRY`.
5. **Polarity Disambiguation Test**: Assert pure polarity failures vs action failures are partitioned cleanly.
6. **Secret Exclusion Test**: Assert zero passwords, keys, or bearer tokens appear in emitted corpus fields.
7. **Reproducibility Test**: Assert running the corpus builder twice yields identical SHA-256 hashes.
8. **Unresolved Fail-Safe Test**: Assert arbitrary unrecognized records resolve to `F99` rather than being misclassified.

---

## 8. Success Criteria & Phase 11.2 Hand-off

Phase 11.1 will be considered complete when:
- [x] Forensic repository inventory established.
- [ ] Failure corpus JSONL and manifest generated with complete provenance.
- [ ] Deterministic failure taxonomy and precedence attribution implemented and tested.
- [ ] Special analyses (action selection, polarity, context/RAG, cascade) computed and documented.
- [ ] Comprehensive Phase 11.1 Failure Analysis Report generated.
- [ ] All unit and integration tests passing (100%).
- [ ] Working tree clean, zero modifications to historical sealed artifacts.
- [ ] Formal hand-off recommendations drafted for Phase 11.2 intervention design.
