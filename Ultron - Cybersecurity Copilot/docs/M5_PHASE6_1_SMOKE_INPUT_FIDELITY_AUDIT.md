# Milestone M5 — Phase 6.1 Smoke Input & Evidence Fidelity Audit

**Date**: 2026-09-21  
**Status**: AUDIT COMPLETE  
**Milestone**: Milestone M5 (Reasoning Interface & Protocol Reconciliation)  
**Phase**: Phase 6.1 — M5 Smoke Input / Evidence Fidelity Audit  
**Scope**: Forensic audit of input evidence construction, decision policy interaction, and methodology hallucination in Phase 6 live smoke evaluation.

---

## 1. Executive Summary & Verdict

Phase 6 successfully established **interface viability** (0/24 parser failures vs 336/336 in M4.9, 100% JSON decoding, 0 transport errors, 0 truncations). However, forensic analysis of the semantic outcomes reveals a critical **upstream test-harness evidence-fidelity defect**:

1. **Root Cause of Universal `NO_RELEVANT_FUNCTIONALITY`**:
   The live smoke runner (`src/eval/run_m5_smoke.py`, inheriting directly from `src/eval/m4_live_benchmark.py` and `src/eval/m4_screening_harness.py`) instantiated `LosslessStructuralPack` by copying only basic route metadata, **completely dropping `parameters` and `identities` from the frozen benchmark scenario**.
   Because `parameter_lineage` and `identity_matrix` were omitted (defaulting to `[]`), and all Class-1 booleans were hard-coded to `False`, the authoritative decision policy (`is_relevant_functionality`) evaluated the target as an unparameterized, static, read-only endpoint with zero users. Consequently, the policy triggered `DecisionPredicate.NO_RELEVANT_FUNCTIONALITY_IRRELEVANT_TARGET`, **overriding the model's actual emission (`INSUFFICIENT_EVIDENCE`) to `NO_RELEVANT_FUNCTIONALITY`**.
2. **Root Cause of `CHK-001` Methodology Hallucination in Tracks A/B**:
   The `JSON_BAIR` prompt instruction and schema demand `"methodology_references": ["CHK-xxx"]` as a required field matching regex `^CHK-[A-Z0-9_-]+$`. In Tracks A and B (and Scenario 2 where VAPT retrieval yielded 0 chunks), no methodology guidance was provided in the prompt, but the prompt never instructed the model that `methodology_references` should be empty (`[]`) when no methodology block is present. Faced with a required field matching `^CHK-...$`, the model fabricated placeholder `["CHK-001"]`, which was strictly caught and rejected downstream by `KnowledgeGroundingValidator`.
3. **Audit Classification**:
   - **Interface Viability**: CONFIRMED AND REPRODUCIBLE.
   - **Semantic Smoke Results**: **NON-INTERPRETABLE** due to test-harness evidence omission.
   - **Action**: No large benchmark may be run. A targeted harness fix and a clean smoke rerun are required before any confirmatory experiment.

---

## 2. Smoke Harness Dataflow & Evidence Construction Trace (Phase 6.1A)

The dataflow from benchmark scenario to model-visible prompt and decision policy proceeds as follows:

```text
Frozen Benchmark Scenario (EvaluationScenario)
  ├── scenario_id, category_id, expected_decision
  ├── target_asset (method, host, raw_path, normalized_path, application_mutability)
  ├── parameters (param_id, name, location, schema_type)  <── DROPPED BY HARNESS
  ├── identities (identity_id, role)                      <── DROPPED BY HARNESS
  └── initial_evidence (fact_id, statement, certainty)
          │
          ▼
Smoke Harness get_canonical_input()
  ├── pack = LosslessStructuralPack(
  │       asset_id = gold_scen.target_asset["asset_id"]
  │       route_template = gold_scen.target_asset["normalized_path"]
  │       http_method = gold_scen.target_asset["method"]
  │       application_mutability = gold_scen.target_asset["application_mutability"]
  │       parameter_lineage = []                           <── EMPTY (DEFAULTED)
  │       identity_matrix = []                             <── EMPTY (DEFAULTED)
  │       has_privilege_level_delta = False                <── HARD-CODED
  │       has_cross_identity_object_access_success = False <── HARD-CODED
  │       has_numeric_path_identifier = False              <── EMPTY (DEFAULTED)
  │       observed_facts = gold_scen.initial_evidence
  │   )
  ├── target_asset = gold_scen.target_asset                <── DOES NOT CONTAIN PARAMETERS/IDENTITIES
  │
  ├── ReasoningContextBuilder.build_context(handoff, vapt_pack, ...)
  │       Prompt compiled: parameters missing from structural header
  │
  ├── Ollama Live Inference (qwen2.5-coder:7b)
  │       Model emits JSON_BAIR (e.g. decision="INSUFFICIENT_EVIDENCE")
  │
  └── deterministic_decide(candidate, EvidenceState(channel_a=pack, target_asset=target_asset))
          │
          ├── is_relevant_functionality(evidence_state)
          │     ├── mutability == "READ_ONLY" (not STATE_CHANGING)
          │     ├── class1_predicates == all False
          │     ├── parameter_lineage == [] (empty!)
          │     ├── identity_matrix == [] (empty!)
          │     └── RETURNS: False (static read-only endpoint with zero signals)
          │
          └── Layer 1 Override:
                OVERWRITES candidate decision to NO_RELEVANT_FUNCTIONALITY
                Predicate: NO_RELEVANT_FUNCTIONALITY_IRRELEVANT_TARGET
```

---

## 3. Field-Level Comparison: Frozen Scenario vs Harness Construction (Phase 6.1B)

A field-level comparison between the frozen scenario definition in `data/benchmarks/m1_5_frozen_manifest.json` and what `run_m5_smoke.py` constructed:

| Frozen Scenario Field | Target Model / Harness Field | Smoke Harness Value Used | Classification | Impact |
|---|---|---|---|---|
| `scenario_id` | `LosslessStructuralPack.endpoint_id` / metadata | `gold_scen.scenario_id` | **Correct** | Accurate scenario identity maintained. |
| `category_id` | Prompt context & contract category | `gold_scen.category_id` | **Correct** | Category counterfactual template loaded correctly. |
| `target_asset.normalized_path` | `LosslessStructuralPack.route_template` | `gold_scen.target_asset["normalized_path"]` | **Correct** | Route template preserved accurately. |
| `target_asset.method` | `LosslessStructuralPack.http_method` | `gold_scen.target_asset["method"]` | **Correct** | HTTP method preserved. |
| `target_asset.application_mutability`| `LosslessStructuralPack.application_mutability` | `gold_scen.target_asset["application_mutability"]` | **Correct** | Mutability preserved (`READ_ONLY` or `STATE_CHANGING`). |
| `initial_evidence` | `LosslessStructuralPack.observed_facts` | `gold_scen.initial_evidence` | **Correct** | Initial OpenAPI facts supplied to model. |
| `parameters` | `LosslessStructuralPack.parameter_lineage` | `[]` (Defaulted / Omitted) | **MISSING / DROPPED** | Endpoint appears unparameterized to `is_relevant_functionality`. |
| `identities` | `LosslessStructuralPack.identity_matrix` | `[]` (Defaulted / Omitted) | **MISSING / DROPPED** | Endpoint appears single-user / non-multi-tenant. |
| `parameters` (in path) | `LosslessStructuralPack.has_numeric_path_identifier` | `False` (Defaulted / Omitted) | **MISSING / DROPPED** | BOLA object-ID predicate evaluated as absent. |
| `has_privilege_level_delta` | `LosslessStructuralPack.has_privilege_level_delta` | `False` | **HARD-CODED** | Correct for initial triage (no role delta observed yet). |
| `has_cross_identity_object_access_success` | `LosslessStructuralPack.has_cross_identity_object_access_success` | `False` | **HARD-CODED** | Correct for initial triage (no attack traffic observed yet). |
| `target_asset` argument | `execute_m5_generation(..., target_asset=...)` | `gold_scen.target_asset` | **TRANSFORMED / INCOMPLETE** | Passed dict lacks `parameters` and `identities` (which are sibling keys on `EvaluationScenario`). |

---

## 4. Causal Analysis: Why `NO_RELEVANT_FUNCTIONALITY` Occurred (Phase 6.1C)

### Trace in `deterministic_decide()`
In `src/engine/decision_policy.py`:
```python
def is_relevant_functionality(evidence_state: EvidenceState) -> bool:
    ch_a = evidence_state.channel_a
    asset = evidence_state.target_asset or {}

    # 1. Application mutability check
    mutability = getattr(ch_a, "application_mutability", "")
    if mutability in ("STATE_CHANGING", "DESTRUCTIVE"):
        return True

    # 2. Class-1 structural predicate booleans
    for pred in class1_predicates:
        if bool(getattr(ch_a, pred, None)):
            return True

    # 3. Parameter lineage check
    params = getattr(ch_a, "parameter_lineage", None) or asset.get("parameters")
    if params and len(params) > 0:
        return True

    # 4. Identity matrix check
    identities = getattr(ch_a, "identity_matrix", None) or asset.get("identities")
    if identities and len(identities) > 1:
        return True

    # Default to False for static read-only endpoints with zero structural signals
    return False
```

### The Causal Chain for `SCEN-SAAS_BILLING-INV-DETAILS-VULN-01`:
1. Scenario 1 is an invoice detail endpoint (`/api/v1/invoices/{id}`). Its mutability is `READ_ONLY`.
2. All Class-1 booleans were set to `False`.
3. In `pack`, `parameter_lineage` was omitted $\to$ `[]`. In `target_asset`, `parameters` was missing (because it was on `gold_scen.parameters`, not `gold_scen.target_asset`).
4. In `pack`, `identity_matrix` was omitted $\to$ `[]`. In `target_asset`, `identities` was missing.
5. `is_relevant_functionality()` returned `False`.
6. `deterministic_decide()` executed:
   ```python
   if not relevant:
       final_dec = HypothesisDecision.NO_RELEVANT_FUNCTIONALITY
       pred_id = DecisionPredicate.NO_RELEVANT_FUNCTIONALITY_IRRELEVANT_TARGET
       canonical_out = candidate.model_copy(update={"decision": final_dec})
   ```
7. **Empirical Verification**:
   In Calls #05, #06, and #08, the model actually emitted:
   `decision: "INSUFFICIENT_EVIDENCE"`
   with substantive reasoning that object ownership verification was absent.
   **The decision policy forcefully rewrote the model's `INSUFFICIENT_EVIDENCE` into `NO_RELEVANT_FUNCTIONALITY` because the harness failed to supply the parameter and identity metadata.**

### Verification of Faithful Pack Construction:
When tested with `parameter_lineage=scen.parameters` and `identity_matrix=scen.identities`:
- `is_relevant_functionality()` returns: **`True`**
- `deterministic_decide()` produces: **`HypothesisDecision.INSUFFICIENT_EVIDENCE`** with predicate **`DecisionPredicate.INSUFFICIENT_EVIDENCE_CONFIRMED`**.

---

## 5. Methodology-Citation Fidelity & Hallucination Analysis (Phase 6.1D)

### Observed Phenomenon
In all failed calls across Tracks A, B, and Scenario 2, the model emitted:
`"methodology_references": ["CHK-001"]`

### Forensic Investigation:
1. **Prompt Instructions**:
   In `src/engine/protocol.py`, `JSON_BAIR_PROMPT_INSTRUCTION` explicitly specifies:
   ```json
   "methodology_references": ["CHK-xxx"]
   ```
   The prompt does **not** inform the model what to emit if no methodology guidance is provided in the prompt.
2. **Context Assembly**:
   In Track A and Track B (and Scenario 2 where VAPT retriever returned 0 chunks), the `<security_testing_methodology>` block was completely omitted from the prompt. There was no explicit negative assertion (e.g. *"No methodology guidance is provided. Emit an empty list `[]`"*).
3. **JSON Schema Constraint**:
   In `BairJsonObject.get_inference_schema()`, `methodology_references` is a required field with array items matching `^CHK-[A-Z0-9_-]+$`.
4. **Model Behavior**:
   Given a mandatory field illustrated as `["CHK-xxx"]` and constrained by pattern `^CHK-...$`, the model inferred that an empty list was forbidden or non-standard, fabricating the minimal placeholder `["CHK-001"]`.
5. **Downstream Safety Gate**:
   `KnowledgeGroundingValidator` observed `CHK-001`, checked against `vapt_pack` (which was `None` or empty), and failed closed as designed:
   `SEMANTIC_GROUNDING_FAILURE: Grounding failure: Cited methodology chunks not found in pack: ['CHK-001']`.

### Recommended Deterministic Contract Clarification:
The grounding validator performed exactly as intended (blocking ungrounded methodology citations). The issue is prompt ambiguity.
- In `JSON_BAIR_PROMPT_INSTRUCTION`, add explicit instruction:
  `- 'methodology_references': cite ONLY valid CHK-xxx IDs from available methodology guidance. If no methodology guidance is provided in the prompt, emit an empty list: []`.
- In `ReasoningContextBuilder.build_context()`, when `include_vapt == False` or `vapt_pack` is empty, emit an explicit empty notice in the context:
  `=== SECURITY TESTING METHODOLOGY ===\n[No methodology guidance provided. Set methodology_references to []]`.

---

## 6. Track Input Parity Audit (Phase 6.1E)

Per-scenario SHA-256 fingerprints across all 3 smoke scenarios and 4 tracks:

```text
SCENARIO: SCEN-SAAS_BILLING-INV-DETAILS-VULN-01
  canonical_input_hash:    b3d7d8eb62ed023c
  canonical_pack_hash:     e1d95a35d64781f5
  evidence_gap_hash:       6d309d9bd0ed534e
  vapt_pack_wire_hash:     fcde76e7a023316f
  TRACK_A: has_target=False target_hash=NONE             has_vapt=False
  TRACK_B: has_target=True  target_hash=56e159483adb462c has_vapt=False
  TRACK_C: has_target=False target_hash=NONE             has_vapt=True
  TRACK_D: has_target=True  target_hash=56e159483adb462c has_vapt=True

SCENARIO: SCEN-ECOMMERCE_ORDERS-ORD-REFUND-VULN-01
  canonical_input_hash:    c6f146385b020a8d
  canonical_pack_hash:     adaa71479d59a17e
  evidence_gap_hash:       120cd979a6096e2d
  vapt_pack_wire_hash:     e3b0c44298fc1c14 (empty wire, 0 items)
  TRACK_A: has_target=False target_hash=NONE             has_vapt=False
  TRACK_B: has_target=True  target_hash=6bcff23ce6814585 has_vapt=False
  TRACK_C: has_target=False target_hash=NONE             has_vapt=False
  TRACK_D: has_target=True  target_hash=6bcff23ce6814585 has_vapt=False

SCENARIO: SCEN-SAAS_BILLING-INV-DETAILS-PATCH-01
  canonical_input_hash:    b3d7d8eb62ed023c
  canonical_pack_hash:     4d5bee2c44bc8469
  evidence_gap_hash:       6d309d9bd0ed534e
  vapt_pack_wire_hash:     fcde76e7a023316f
  TRACK_A: has_target=False target_hash=NONE             has_vapt=False
  TRACK_B: has_target=True  target_hash=56e159483adb462c has_vapt=False
  TRACK_C: has_target=False target_hash=NONE             has_vapt=True
  TRACK_D: has_target=True  target_hash=56e159483adb462c has_vapt=True
```

### Invariants Confirmed:
1. **Target-Evidence Causal Parity**: For both Scenarios 1 and 3, Track B and Track D have byte-for-byte identical target evidence hashes (`56e15948...`). For Scenario 2, Track B and Track D have byte-for-byte identical target evidence hashes (`6bcff23c...`).
2. **Paired Input Parity**: Scenario 1 (vuln) and Scenario 3 (patch) share identical canonical input hashes (`b3d7d8eb62ed023c`), confirming zero ground-truth divergence.
3. **Track Component Isolation**: Tracks A and B strictly exclude VAPT knowledge; Tracks A and C strictly exclude target snippets.

---

## 7. Classification of Findings (Phase 6.1F)

| Finding | Classification | Rationale |
|---|---|---|
| Omission of `parameters` and `identities` in `LosslessStructuralPack` | **HARNESSED TEST-DATA FIDELITY ISSUE** | Code in `run_m5_smoke.py` (inherited from `m4_live_benchmark.py`) did not map scenario parameters/identities into the structural pack. Masked in M4.9 by parser failures; exposed in M5 when pipeline reached semantic layers. |
| Overriding model's `INSUFFICIENT_EVIDENCE` to `NO_RELEVANT_FUNCTIONALITY` | **DECISION POLICY INTERACTION (INDUCED)** | `deterministic_decide()` operated strictly according to specification. It correctly marked a target with no parameters or identities as irrelevant. The defect was upstream in the evidence provided to it. |
| Hallucination of `["CHK-001"]` in Tracks A/B | **PROMPT SPECIFICATION AMBIGUITY** | Prompt illustrated `"methodology_references": ["CHK-xxx"]` without explicitly directing the model to emit `[]` when no methodology section exists. |
| Retrieval of 0 VAPT chunks for `API-STATE-001` | **KNOWLEDGE BASE / QUERY COVERAGE GAP** | The query `Missing Mutation State Boundary` on `POST /api/v1/orders/{id}/refund` did not hit any chunks in `vapt_knowledge.db` above threshold. |

---

## 8. Required Fixes Before Future Live Validation (Phase 6.1G)

The following changes are documented and required for a future clean smoke rerun (Phase 6.2):

1. **Harness Pack Construction (`run_m5_smoke.py`)**:
   Map all scenario attributes into `LosslessStructuralPack`:
   ```python
   pack = LosslessStructuralPack(
       schema_version="2.0.0",
       asset_id=gold_scen.target_asset.get("asset_id", f"ASSET-{gold_scen.scenario_id}"),
       endpoint_id=f"EP-{gold_scen.scenario_id}",
       route_template=gold_scen.target_asset.get("normalized_path", gold_scen.target_asset.get("raw_path", "/api/v1/resource")),
       http_method=gold_scen.target_asset.get("method", "GET"),
       application_mutability=gold_scen.target_asset.get("application_mutability", "READ_ONLY"),
       parameter_lineage=gold_scen.parameters,
       identity_matrix=gold_scen.identities,
       has_privilege_level_delta=False,
       has_cross_identity_object_access_success=False,
       observed_facts=observed_facts,
       raw_body_sample=raw_sample,
   )
   ```
2. **Target Asset Enrichment**:
   Ensure `target_asset` passed to `execute_m5_generation()` includes `parameters` and `identities`:
   ```python
   target_asset_enriched = dict(gold_scen.target_asset)
   target_asset_enriched["parameters"] = gold_scen.parameters
   target_asset_enriched["identities"] = gold_scen.identities
   ```
3. **Prompt Methodology Empty-List Directive**:
   Update `JSON_BAIR_PROMPT_INSTRUCTION` to clarify:
   `- 'methodology_references': cite ONLY valid CHK-xxx IDs from available methodology guidance. If no methodology guidance is provided in the prompt, emit an empty list: []`.
4. **Context Builder Methodology Negative Notice**:
   In `ReasoningContextBuilder.build_context()`, when `include_vapt == False` or `vapt_pack.serialized_p4_wire` is empty, insert:
   `=== SECURITY TESTING METHODOLOGY ===\n[No methodology guidance provided. Set methodology_references to []]`.

---

## 9. Conclusion on Semantic Interpretability

- **Phase 6 Interface Viability**: **VALID AND CONFIRMED.** The pipeline demonstrated 100% parse rate, zero crashes, zero transport failures, and strict execution gating.
- **Phase 6 Semantic Yield**: **NON-INTERPRETABLE.** The observed `NO_RELEVANT_FUNCTIONALITY` outcomes and `SEMANTIC_GROUNDING_FAILURE` outcomes were driven by test harness evidence omissions and prompt ambiguity, not by genuine model reasoning limitations.
- **Next Step**: Apply the targeted harness and prompt fixes under an authorized Phase 6.2 before running any further evaluations.
- **Large Benchmark Execution**: **STRICTLY PROHIBITED.** No 84-scenario benchmark or 336-call run is authorized.
