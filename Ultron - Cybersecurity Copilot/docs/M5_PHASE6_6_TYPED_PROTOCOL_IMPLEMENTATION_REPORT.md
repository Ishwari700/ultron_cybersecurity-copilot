# M5 Phase 6.6 — Typed Experiment-Outcome Protocol Implementation Report

**Status**: `M5_PHASE6_6_IMPLEMENTED_DETERMINISTICALLY_BENCHMARK_BLOCKED`  
**Date**: 2026-09-21  
**Execution Environment**: Local Deterministic Sandbox (`python 3.13.14`, `pytest 9.1.1`)  
**Scope**: Production Protocol Implementation Only (Zero Live Benchmark Calls Executed)

---

## 1. Executive Summary & Gate Decision

In Phase 6.6, the production inference protocol for Milestone M5 was migrated from free-text falsification plans to **Option B: Typed Outcome Predicates**.

The implementation tightens the Phase 6.5 design draft by establishing a deterministic 4-tuple compatibility validator:
$$\text{Compatibility Tuple} = (\text{category}, \text{experiment\_action}, \text{supporting\_outcome}, \text{disproving\_outcome})$$

Free-text substring presence checks (`is_falsification_complete()`) have been eliminated from the production semantic authorization path. A candidate `HYPOTHESIS` can now be authorized **only** if its action and outcome predicates form an authorized compatibility tuple in the closed taxonomy registry.

Under strict governance rules:
- **No benchmark runs were executed** (neither the 84-scenario benchmark nor the 336-call confirmatory benchmark).
- **Zero live LLM calls were made**; deterministic verification was completely sufficient.
- **Protected artifacts from M3, M4, M4.8, M4.9, and Phase 6.2/6.3/6.4/6.5 remain byte-identical**.
- **Benchmark status remains BLOCKED** pending resolution of the exploratory vs. vulnerability benchmark-policy conflict documented in Phase 6.4.

---

## 2. Exact Production Files Changed

Four core production files were modified:

1. [`src/engine/models.py`](src/engine/models.py):
   - Defined closed enums: `ExperimentActionPredicate`, `SemanticOutcomePredicate`, `HttpOutcomePredicate`.
   - Defined validation sets: `VALID_ACTION_PREDICATES`, `VALID_OUTCOME_PREDICATES`.
   - Added typed fields to `HypothesisModelOutput`: `experiment_action`, `supporting_outcome`, `disproving_outcome`, `falsification_description`.
   - Updated `BairJsonObject`:
     - Added typed fields and individual Pydantic validators (`validate_experiment_action`, `validate_outcomes`).
     - Added root validator `validate_decision_dependent_slots`: enforces mandatory typed fields for `HYPOTHESIS`, rejects identical outcomes (`supporting_outcome == disproving_outcome`), and fails closed if legacy free-text `falsification_plan` is supplied without typed fields.
     - Updated `get_inference_schema()` to generate runtime JSON schema with closed enum constraints for `experiment_action`, `supporting_outcome`, `disproving_outcome`, and string for `falsification_description`.

2. [`src/engine/protocol.py`](src/engine/protocol.py):
   - Updated `JSON_BAIR_PROMPT_INSTRUCTION` to explicitly specify the typed fields, closed enums, and mandatory constraints for `HYPOTHESIS`.
   - Maintained strict 6-layer protocol agreement.

3. [`src/engine/bair_extractor.py`](src/engine/bair_extractor.py):
   - Added `experiment_action`, `supporting_outcome`, `disproving_outcome`, and `falsification_description` to `allowed_keys` in `parse_bair_json`.
   - Updated `map_bair_json_to_s0` to map typed fields onto `HypothesisModelOutput` and synthesize canonical `experiment_proposal` string:
     `"Action: {act}; Breach: {supp}; Safe: {disp} ({desc})"`

4. [`src/engine/decision_policy.py`](src/engine/decision_policy.py):
   - Implemented `ExperimentPolarityValidator` with closed `TUPLE_COMPATIBILITY_REGISTRY` mapping `category_id -> action -> (VALID_BREACH_OUTCOMES, VALID_INVARIANT_HOLDS_OUTCOMES)`.
   - Updated `is_discriminating_evidence_absent` to support both `API-BFLA-001` and `API-BFLA-002`.
   - Updated `deterministic_decide()` Layer 2:
     1. Verifies empirical FACT grounding.
     2. Calls `ExperimentPolarityValidator.validate_tuple(category_id, action, supporting, disproving)`.
     3. Rejects invalid tuples, unknown categories, unknown actions, unknown outcomes, mismatched actions, mismatched outcomes, and identical outcomes with `FAIL_CLOSED_INCOMPLETE_HYPOTHESIS`.
   - Retained `is_falsification_complete()` strictly as a legacy helper; it is no longer used for authorizing new hypotheses under JSON_BAIR.

---

## 3. Exact Protocol Fields

### JSON_BAIR Schema Contract
| Field Name | Type | Status (HYPOTHESIS) | Status (INSUFFICIENT_EVIDENCE) | Description / Closed Values |
| :--- | :--- | :--- | :--- | :--- |
| `invariant` | `str` | Mandatory | Mandatory | Natural language security invariant |
| `evidence_gap` | `Optional[str]` | Mandatory | Optional | Natural language evidence gap description |
| `affected_target` | `str` | Mandatory | Mandatory | Endpoint route, asset ID, or parameter |
| `decision` | `HypothesisDecision` | Mandatory | Mandatory | `"HYPOTHESIS"` or `"INSUFFICIENT_EVIDENCE"` |
| `empirical_facts` | `List[str]` | Mandatory (>=1) | Mandatory | Cites verified `FACT-xxx` identifiers only |
| `methodology_references` | `List[str]` | Mandatory (>=0) | Mandatory (>=0) | Cites verified `CHK-xxx` identifiers or `[]` |
| `experiment_action` | `str` | **Mandatory** | Optional / `None` | Closed enum: `VALID_ACTION_PREDICATES` |
| `supporting_outcome` | `str` | **Mandatory** | Optional / `None` | Closed enum: `VALID_OUTCOME_PREDICATES` (breach set) |
| `disproving_outcome` | `str` | **Mandatory** | Optional / `None` | Closed enum: `VALID_OUTCOME_PREDICATES` (safe set) |
| `falsification_description` | `Optional[str]` | Optional | Optional | Natural language experiment narrative (informational only) |
| `falsification_plan` | `Optional[str]` | Deprecated | Deprecated | Legacy field; fails closed if used without typed fields |

### Closed Action Predicate Taxonomy (`ExperimentActionPredicate`)
- `SUBSTITUTE_RESOURCE_IDENTIFIER`
- `EXECUTE_OUT_OF_ORDER_TRANSITION`
- `REPLAY_STEP_WITH_LOWER_ROLE`
- `INVOKE_WITHOUT_CREDENTIALS`
- `TAMPER_REQUEST_PARAMETER`

### Closed Outcome Predicate Taxonomy (`SemanticOutcomePredicate` + `HttpOutcomePredicate`)
- **Semantic Predicates**:
  - `CROSS_IDENTITY_OBJECT_ACCESSIBLE` (breach) / `CROSS_IDENTITY_OBJECT_DENIED` (safe)
  - `OWNERSHIP_NOT_ENFORCED` (breach) / `OWNERSHIP_ENFORCED` (safe)
  - `STATE_TRANSITION_ACCEPTED` (breach) / `STATE_TRANSITION_REJECTED` (safe)
  - `PRIVILEGE_ELEVATION_SUCCEEDS` (breach) / `PRIVILEGE_ELEVATION_DENIED` (safe)
  - `UNAUTHENTICATED_ACCESS_ALLOWED` (breach) / `UNAUTHENTICATED_ACCESS_DENIED` (safe)
  - `STATUS_SUCCESS_2XX` (generic breach) / `STATUS_CLIENT_ERROR_4XX` (generic safe)
- **HTTP Code Predicates**:
  - `HTTP_200_OK`, `HTTP_201_CREATED`, `HTTP_204_NO_CONTENT` (breach)
  - `HTTP_400_BAD_REQUEST`, `HTTP_401_UNAUTHORIZED`, `HTTP_403_FORBIDDEN`, `HTTP_404_NOT_FOUND`, `HTTP_409_CONFLICT` (safe)

---

## 4. Deterministic Category / Action / Outcome Compatibility Matrix

The compatibility registry `ExperimentPolarityValidator.TUPLE_COMPATIBILITY_REGISTRY` defines the closed matrix derived from the repository's 10 benchmark categories:

| Category ID | Allowed Actions | Valid Breach Outcomes (`supporting_outcome`) | Valid Invariant-Holds Outcomes (`disproving_outcome`) |
| :--- | :--- | :--- | :--- |
| **`API-BOLA-001`**<br>**`API-DEVICE-BOLA-001`**<br>**`API-CROSS-TENANT-001`** | `SUBSTITUTE_RESOURCE_IDENTIFIER` | `HTTP_200_OK`<br>`HTTP_201_CREATED`<br>`HTTP_204_NO_CONTENT`<br>`STATUS_SUCCESS_2XX`<br>`CROSS_IDENTITY_OBJECT_ACCESSIBLE`<br>`OWNERSHIP_NOT_ENFORCED` | `HTTP_403_FORBIDDEN`<br>`HTTP_404_NOT_FOUND`<br>`STATUS_CLIENT_ERROR_4XX`<br>`CROSS_IDENTITY_OBJECT_DENIED`<br>`OWNERSHIP_ENFORCED` |
| **`API-BFLA-001`**<br>**`API-BFLA-002`**<br>**`API-ROLE-BOUNDARY-001`** | `REPLAY_STEP_WITH_LOWER_ROLE` | `HTTP_200_OK`<br>`HTTP_201_CREATED`<br>`HTTP_204_NO_CONTENT`<br>`STATUS_SUCCESS_2XX`<br>`PRIVILEGE_ELEVATION_SUCCEEDS` | `HTTP_401_UNAUTHORIZED`<br>`HTTP_403_FORBIDDEN`<br>`STATUS_CLIENT_ERROR_4XX`<br>`PRIVILEGE_ELEVATION_DENIED` |
| **`API-STATE-001`**<br>**`API-LIFECYCLE-001`** | `EXECUTE_OUT_OF_ORDER_TRANSITION` | `HTTP_200_OK`<br>`HTTP_201_CREATED`<br>`HTTP_204_NO_CONTENT`<br>`STATUS_SUCCESS_2XX`<br>`STATE_TRANSITION_ACCEPTED` | `HTTP_400_BAD_REQUEST`<br>`HTTP_409_CONFLICT`<br>`STATUS_CLIENT_ERROR_4XX`<br>`STATE_TRANSITION_REJECTED` |
| **`API-MUTATION-001`** | `TAMPER_REQUEST_PARAMETER`<br>`EXECUTE_OUT_OF_ORDER_TRANSITION` | `HTTP_200_OK`<br>`HTTP_201_CREATED`<br>`HTTP_204_NO_CONTENT`<br>`STATUS_SUCCESS_2XX`<br>`STATE_TRANSITION_ACCEPTED` | `HTTP_400_BAD_REQUEST`<br>`HTTP_409_CONFLICT`<br>`STATUS_CLIENT_ERROR_4XX`<br>`STATE_TRANSITION_REJECTED` |
| **`API-MULTI-STEP-AUTH-001`** | `EXECUTE_OUT_OF_ORDER_TRANSITION`<br>`INVOKE_WITHOUT_CREDENTIALS` | `HTTP_200_OK`<br>`STATUS_SUCCESS_2XX`<br>`UNAUTHENTICATED_ACCESS_ALLOWED`<br>`STATE_TRANSITION_ACCEPTED` | `HTTP_401_UNAUTHORIZED`<br>`HTTP_403_FORBIDDEN`<br>`STATUS_CLIENT_ERROR_4XX`<br>`UNAUTHENTICATED_ACCESS_DENIED`<br>`STATE_TRANSITION_REJECTED` |
| **`API-AUTH-NONE`** | `INVOKE_WITHOUT_CREDENTIALS` | `HTTP_200_OK`<br>`STATUS_SUCCESS_2XX`<br>`UNAUTHENTICATED_ACCESS_ALLOWED` | `HTTP_401_UNAUTHORIZED`<br>`HTTP_403_FORBIDDEN`<br>`STATUS_CLIENT_ERROR_4XX`<br>`UNAUTHENTICATED_ACCESS_DENIED` |

---

## 5. Deterministic Fail-Closed Rules

Every verification step enforces strict fail-closed semantics:

1. **Unknown Category**: If `category_id` is null, unlisted, or unrecognized $\rightarrow$ **REJECT** (`FAIL_CLOSED_INCOMPLETE_HYPOTHESIS`).
2. **Unknown Action**: If `experiment_action` is not in `VALID_ACTION_PREDICATES` $\rightarrow$ **REJECT** at Schema (`ValidationError`) and Policy (`FAIL_CLOSED_INCOMPLETE_HYPOTHESIS`).
3. **Category / Action Mismatch**: If `experiment_action` is not registered for `category_id` (e.g. BOLA with `EXECUTE_OUT_OF_ORDER_TRANSITION`) $\rightarrow$ **REJECT** (`FAIL_CLOSED_INCOMPLETE_HYPOTHESIS`).
4. **Unknown Outcome**: If `supporting_outcome` or `disproving_outcome` is not in `VALID_OUTCOME_PREDICATES` $\rightarrow$ **REJECT** at Schema and Policy.
5. **Action / Outcome Mismatch**: If an outcome predicate does not belong to the allowed outcomes for the (category, action) pair $\rightarrow$ **REJECT** (`FAIL_CLOSED_INCOMPLETE_HYPOTHESIS`).
6. **Polarity Inversion**:
   - `supporting_outcome` in safe/invariant-holds set (e.g. `HTTP_403_FORBIDDEN` or `STATE_TRANSITION_REJECTED`) $\rightarrow$ **REJECT**.
   - `disproving_outcome` in breach set (e.g. `HTTP_200_OK` or `STATE_TRANSITION_ACCEPTED`) $\rightarrow$ **REJECT**.
7. **Identical Outcomes**: If `supporting_outcome == disproving_outcome` $\rightarrow$ **REJECT** at Schema and Policy (zero discriminative power).
8. **Missing Typed Fields on HYPOTHESIS**: If candidate decision is `HYPOTHESIS` and any typed field is missing/null $\rightarrow$ **REJECT** at Schema and Policy.
9. **Natural Language Governance**: `falsification_description` is purely informational. A valid narrative **cannot** authorize an invalid or inverted typed tuple; an invalid narrative **cannot** invalidate a valid typed tuple.

---

## 6. Migration and Backward-Compatibility Behavior

- **Legacy Input Fail-Closed**: Any input containing legacy free-text `falsification_plan` without the typed experiment fields fails closed immediately with:
  `"Legacy free-text falsification_plan cannot authorize a HYPOTHESIS under JSON_BAIR protocol; typed experiment fields (experiment_action, supporting_outcome, disproving_outcome) are mandatory"`.
- **No Semantic Heuristic Extraction**: No regex, NLP, or heuristic parsing is attempted on legacy strings.
- **Canonical Adapter Compatibility**: `map_bair_json_to_s0` populates the legacy `experiment_proposal` string on `HypothesisModelOutput` from the structured typed fields, guaranteeing seamless downstream compatibility with logging and reporting utilities.

---

## 7. Schema / Prompt / Parser / Adapter Agreement (Six-Layer Proof)

All six architectural layers agree unconditionally:
1. **PromptInstructions** (`JSON_BAIR_PROMPT_INSTRUCTION`): Specifies the exact field names, constraints, and closed enum values.
2. **RuntimeSchema** (`BairJsonObject.get_inference_schema()`): Emits JSON Schema with identical field names and closed enums.
3. **Extractor** (`parse_bair_json`): Extracts the typed keys from JSON payloads.
4. **Parser** (`BairJsonObject`): Validates enum membership and decision dependencies.
5. **Validator** (`ExperimentPolarityValidator.validate_tuple`): Validates deterministic 4-tuple compatibility.
6. **Adapter** (`map_bair_json_to_s0`): Maps typed slots into canonical internal representations.

### Dual-Track Contract Agreement
- **Track I1=0**: LLM receives unconstrained JSON emission instructions (`schema=None`).
- **Track I1=1**: LLM receives constrained decoding via `schema=BairJsonObject.get_inference_schema()`.
- Both tracks route through the exact same parser, validator, and adapter functions.

---

## 8. Token Budget Verification

The frozen compute envelope is:
- Model: `qwen2.5-coder:7b`
- `num_ctx = 2048`
- `num_predict = 300`
- `temperature = 0.0`, `seed = 42`
- Single inference call

Deterministic token budget verification fixture (`test_typed_fields_token_budget_envelope`):
- A maximal JSON emission with all mandatory and optional typed fields (`invariant`, `evidence_gap`, `affected_target`, `decision`, 2 FACT citations, 2 CHK citations, `experiment_action`, `supporting_outcome`, `disproving_outcome`, `falsification_description`) measures **684 characters**.
- Estimated tokens: **~195 tokens**.
- Headroom: **>100 tokens** below the `num_predict=300` generation ceiling.

---

## 9. Test Suite Verification Results

A comprehensive suite of 19 new deterministic tests was created in [`tests/unit/test_m5_typed_experiment_protocol.py`](tests/unit/test_m5_typed_experiment_protocol.py), implementing all 16 required cases (A through P) plus architectural agreement and token budget fixtures:

| Test Identifier | Description | Result |
| :--- | :--- | :--- |
| `test_a_valid_bola_semantic_predicates` | Valid BOLA (SUBSTITUTE_RESOURCE_IDENTIFIER, CROSS_IDENTITY_OBJECT_ACCESSIBLE, CROSS_IDENTITY_OBJECT_DENIED) | **PASSED** |
| `test_b_valid_bola_http_predicates` | Valid BOLA (SUBSTITUTE_RESOURCE_IDENTIFIER, HTTP_200_OK, HTTP_403_FORBIDDEN) | **PASSED** |
| `test_c_inverted_bola_fails_closed` | Inverted BOLA (HTTP_403_FORBIDDEN, HTTP_200_OK) fails closed | **PASSED** |
| `test_d_valid_state_machine_semantic_predicates` | Valid State Machine (EXECUTE_OUT_OF_ORDER_TRANSITION, STATE_TRANSITION_ACCEPTED, STATE_TRANSITION_REJECTED) | **PASSED** |
| `test_e_valid_state_machine_http_predicates` | Valid State Machine (EXECUTE_OUT_OF_ORDER_TRANSITION, HTTP_200_OK, HTTP_409_CONFLICT) | **PASSED** |
| `test_f_inverted_state_machine_fails_closed` | Inverted State Machine (HTTP_409_CONFLICT, STATE_TRANSITION_ACCEPTED) fails closed | **PASSED** |
| `test_g_category_action_mismatch_fails_closed` | Category/Action mismatch (BOLA + EXECUTE_OUT_OF_ORDER_TRANSITION) fails closed | **PASSED** |
| `test_h_action_outcome_mismatch_fails_closed` | Action/Outcome mismatch (BOLA + SUBSTITUTE_RESOURCE_IDENTIFIER + STATE_TRANSITION_ACCEPTED) fails closed | **PASSED** |
| `test_i_unknown_category_fails_closed` | Unknown category ID fails closed | **PASSED** |
| `test_j_unknown_action_fails_closed` | Unknown action enum fails closed | **PASSED** |
| `test_k_unknown_outcome_fails_closed` | Unknown outcome enum fails closed | **PASSED** |
| `test_l_identical_outcomes_fail_closed` | Identical outcomes (HTTP_200_OK, HTTP_200_OK) fail closed | **PASSED** |
| `test_m_missing_typed_fields_on_hypothesis_fails_closed` | Missing typed fields on HYPOTHESIS candidate fails closed | **PASSED** |
| `test_n_insufficient_evidence_without_experiment_accepted` | INSUFFICIENT_EVIDENCE candidate without experiment fields accepted | **PASSED** |
| `test_o_description_contradiction_governed_by_typed_fields` | Contradictory text description ignored; typed fields govern | **PASSED** |
| `test_p_legacy_free_text_falsification_plan_fails_closed` | Legacy free-text falsification_plan fails closed | **PASSED** |
| `test_six_layer_architectural_agreement` | Six-layer agreement (Prompt == Schema == Extractor == Parser == Validator == Adapter) | **PASSED** |
| `test_dual_track_decoding_contract_agreement` | I1=0 vs I1=1 contract parity | **PASSED** |
| `test_typed_fields_token_budget_envelope` | Token budget verification within 300 token limit | **PASSED** |

### Regression Suite Execution
Ran full test suite:
- `tests/unit/test_m5_composition.py`: **33 passed**
- `tests/unit/test_m5_decision_boundary_audit.py`: **9 passed**
- `tests/unit/test_m5_end_to_end.py`: **30 passed**
- `tests/unit/test_m5_experiment_semantics_design.py`: **19 passed**
- `tests/unit/test_m5_falsification_semantics_audit.py`: **7 passed**
- `tests/unit/test_m5_smoke_fidelity.py`: **15 passed**
- `tests/unit/test_m5_typed_experiment_protocol.py`: **19 passed**
- `tests/unit/test_real_ablation_integrity.py`: **8 passed**
- `tests/unit/test_m4_deterministic_decision_policy.py`: **30 passed**

**Total M5 & Policy Regression Suite**: **157 passed in 2.03 seconds** (0 failures, 0 warnings, 0 skips).

---

## 10. Protected File Integrity Verification

SHA256 digests of all protected and frozen files were verified before and after implementation:

| File Path | SHA256 Digest | Status |
| :--- | :--- | :--- |
| `data/eval/m4_live_llm_benchmark_final.json` | `459b9ec63c3a2dc760abde12ec196760f7e505fbab5317f0da0c46b32c5eaac7` | **MATCH / UNCHANGED** |
| `data/eval/m5_live_smoke.json` | `7ee8b6b2ec33eca0fcb8a3f0948d1f36b7e41877354ae4a64190f8e19c679b5e` | **MATCH / UNCHANGED** |
| `data/eval/m5_live_smoke_v2.json` | `830c225b22f6767ee13b4ce3b443a14aede3ea767ee25ae7343c1a153c4a0818` | **MATCH / UNCHANGED** |
| `docs/M5_PHASE6_3_FALSE_POSITIVE_AUDIT.md` | `5cc7ac193aefb6fb5d0d5a845c54b7c6279b713609ce62ea44c00fa98a718bf7` | **MATCH / UNCHANGED** |
| `docs/M5_PHASE6_4_BENCHMARK_SEMANTICS_DECISION.md` | `6657ec2ccdc5ff1344e307a6d2e2dab6eff7fc47ece8c3b2d014742eeb91b53e` | **MATCH / UNCHANGED** |
| `docs/M5_PHASE6_5_EXPERIMENT_SEMANTICS_PROTOCOL_DESIGN.md` | `ec15f42ba52bd54363f236bff1a71683ab3b1c1a10fa28ddac5c8a97a40b255c` | **MATCH / UNCHANGED** |
| `src/eval/scenarios.py` | `102789655bfb04041de9259d1bf6db7f0ad1222416806ea947bb309ee2d6be90` | **MATCH / UNCHANGED** |

---

## 11. Comparability Statement

The typed protocol introduced in Phase 6.6 alters the raw wire representation of the JSON_BAIR intermediate reasoning object. Consequently:
1. Direct byte-level comparison of raw response strings against Phase 6.2/6.3 artifacts is **invalid**.
2. Prior evaluation artifacts (`m5_live_smoke.json`, `m5_live_smoke_v2.json`, `m4_live_llm_benchmark_final.json`) represent immutable historical evidence under their respective legacy protocols and remain preserved without modification.
3. The semantic meaning of hypothesis outputs is significantly stronger under Phase 6.6 because polarity and category compatibility are strictly verified prior to hypothesis authorization.

---

## 12. Benchmark-Policy Conflict Status & Blockade Statement

**The benchmark remains explicitly BLOCKED.**

As established in Phase 6.4 and reiterated in Phase 6.5, the benchmark cannot be executed because of an unresolved epistemic metric conflict:
- In negative-control / patched scenarios (such as `SCEN-SAAS_BILLING-INV-DETAILS-PATCH-01`), the observable evidence presented to the model contains only documentation and route specifications identical to the vulnerable scenario.
- Under an exploratory security testing paradigm, a model proposing a valid, discriminating experiment proposal is conducting legitimate hypothesis formation.
- Under a strict vulnerability labeling paradigm, the scenario expects `INSUFFICIENT_EVIDENCE` or `NO_RELEVANT_FUNCTIONALITY`.
- This metric conflict is a benchmark policy decision that cannot be resolved by engine code changes.

Therefore:
- **NO BENCHMARK WAS RUN.**
- The benchmark scenarios in `src/eval/scenarios.py` have not been altered.
- Execution remains gated until an explicit benchmark-policy decision is formalized.

---

## 13. Summary Gate Determination

```
================================================================================
FINAL GATE DECISION:
M5_PHASE6_6_IMPLEMENTED_DETERMINISTICALLY_BENCHMARK_BLOCKED
================================================================================
```
