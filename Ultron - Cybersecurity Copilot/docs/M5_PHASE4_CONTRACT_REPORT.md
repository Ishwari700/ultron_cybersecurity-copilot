# M5 Phase 4 Contract Infrastructure & Composition Report

**Milestone**: M5 — Reasoning Interface & Protocol Reconciliation  
**Phase**: Phase 4 — Contract Infrastructure + Composition Invariants Implementation  
**Status**: COMPLETE  
**Execution Date**: 2026-09-21  
**Authoritative Specification**: `docs/M5_REASONING_INTERFACE_PLAN.md`  
**Prior Audits & Errata**: `docs/M4_9_TECHNICAL_ERRATUM.md`, `docs/M4_COMPOSITION_AUDIT.md`  

---

## Executive Summary & Boundary Notice

Phase 4 of Milestone M5 implements the core interface abstractions, deterministic output contract, additive prompt compiler, canonical field adapter, pre-flight contract validator, and budget pre-allocation mechanics defined in `docs/M5_REASONING_INTERFACE_PLAN.md`.

> [!IMPORTANT]
> **SCIENTIFIC & EMPIRICAL BOUNDARY**  
> This milestone and report demonstrate **engineering correctness and interface viability only**.  
> We make **no empirical claims** that M5 or JSON_BAIR improves reasoning quality, increases vulnerability detection rate, or improves Useful Hypothesis Yield. Those questions are strictly reserved for future controlled empirical benchmarks (Phase 5 smoke test and subsequent confirmatory evaluations).

---

## 1. Implementation Changes

The following repository modules were created or modified during Phase 4:

1. **`src/engine/models.py`** [MODIFIED]:
   - Added `ContractCompilationError(ValueError)` for deterministic pre-flight gating failure.
   - Added `OutputProtocolIdentifier` enum (`JSON_BAIR`, `BAIR_XML`, `S0_JSON`).
   - Added `BairJsonObject` Pydantic model implementing the 7 canonical BAIR conceptual slots with regex validators, decision-dependent constraints (strict rejection of `CONFIRMED`), and `get_inference_schema()`.
   - Added `M5ExecutionResult` tracking full provenance, contract validation status, intermediate structures, and grounding results.

2. **`src/engine/protocol.py`** [NEW]:
   - Defined `OutputProtocolContract` frozen dataclass binding protocol identifier to serialization instructions, runtime schema factory, parser, validator, and S0 adapter.
   - Implemented `get_protocol_contract(protocol: OutputProtocolIdentifier)` registry returning authoritative contracts for `JSON_BAIR` (primary) and `BAIR_XML` (legacy).
   - Defined `ReasoningExecutionContract` capturing the full execution intent.
   - Implemented `validate_reasoning_contract(contract: ReasoningExecutionContract)` enforcing all 16 deterministic pre-flight invariants with zero LLM calls on error.

3. **`src/engine/bair_extractor.py`** [MODIFIED]:
   - Implemented `parse_bair_json(raw_text)`: handles optional markdown envelope stripping (` ```json ... ``` `), decodes JSON, checks for all 7 required slot keys without semantic alteration.
   - Implemented `validate_bair_json(parsed_dict, empirical_evidence_present)`: validates against `BairJsonObject`, enforces decision-dependent slot rules, and respects empirical evidence boundaries.
   - Implemented `map_bair_json_to_s0(obj, target_asset, category_id)`: 1:1 deterministic field projection into canonical `HypothesisModelOutput`.
   - Integrated `extract_bair_json()` method into `BairExtractor`.

4. **`src/engine/context_builder.py`** [MODIFIED]:
   - Created `PromptContractCompiler`: additive mixin architecture eliminating the legacy mutually-exclusive `if/elif` prompt branch cascade.
   - Enforced strict separation of concerns: protocol owns serialization instructions (`JSON_BAIR`), while interventions (I2, I3, I5) contribute domain semantics only.
   - Repaired token floor budgeting: included I3 counterfactual block (`p1_cf_tokens`) and I6 protected handoff (`p3_tokens`) in mandatory pre-allocation floor (`floor_tokens`).
   - Replaced silent omission of I6 with fail-closed `ContextBudgetOverflowError`.

5. **`src/engine/runner.py`** [MODIFIED]:
   - Added `execute_m5_generation(contract, empirical_evidence_present, ...)`: enforces pre-flight validation gating, dynamically selects Ollama runtime schema based on I1 status, executes protocol-bound parser/validator/adapter pipeline, and integrates grounding validation.

6. **`tests/unit/test_m5_composition.py`** [NEW]:
   - Implemented 28 comprehensive unit tests covering schema validation, pairwise intervention combinations, full composition invariants, prompt/protocol contradiction detection, I6 and I3 budget protection, pre-flight gating, and offline mock execution.

7. **`tests/unit/test_m4_bair.py`** [MODIFIED]:
   - Updated `test_context_builder_enable_i4_bair` to verify both M5 default `JSON_BAIR` protocol emission and explicit legacy `BAIR_XML` protocol emission.

---

## 2. Protocol Contract Structure

The reasoning interface decouples serialization syntax from core reasoning semantics via the `OutputProtocolContract`:

```
OutputProtocolIdentifier (JSON_BAIR)
       │
       ├── Prompt Serialization Instructions (PromptProtocolInstruction.JSON_BAIR)
       ├── Runtime Schema Factory (BairJsonObject.get_inference_schema() if I1 else None)
       ├── Deterministic Parser (parse_bair_json)
       ├── Semantic Validator (validate_bair_json)
       └── Canonical Adapter (map_bair_json_to_s0)
```

No implicit protocol fallback is permitted. An explicit protocol must be declared before final prompt compilation.

---

## 3. JSON_BAIR Schema Summary

`BairJsonObject` represents the 7 BAIR conceptual slots with deterministic validation:

| Slot Name | Type | Description / Constraints |
| :--- | :--- | :--- |
| `invariant` | `str` | Stated security invariant evaluated against the target. Cannot be empty or placeholder. |
| `evidence_gap` | `Optional[str]` | Unmitigated evidence gap or missing observation (null if none). |
| `affected_target` | `str` | Target endpoint, asset ID, or parameter under evaluation. |
| `decision` | `HypothesisDecision` | Closed enum: `HYPOTHESIS`, `INSUFFICIENT_EVIDENCE`, `NO_RELEVANT_FUNCTIONALITY`. (`CONFIRMED` strictly rejected). |
| `empirical_facts` | `List[str]` | Target observations cited. Must strictly match regex `^FACT-[A-Za-z0-9_-]+$`. No CHK citations. |
| `methodology_references` | `List[str]` | VAPT guidance cited. Must strictly match regex `^CHK-[A-Za-z0-9_-]+$`. No FACT citations. |
| `falsification_plan` | `str` | Testable criteria stating what observation supports and what observation falsifies/disproves the hypothesis. |

---

## 4. Intervention Composition Mechanism

In M4, system prompt assembly was governed by a mutually-exclusive branch selection:
```python
# M4 Legacy Defect (Disallowed in M5):
if enable_i4_bair: ...
elif enable_i3_counterfactual_prompting: ...
elif enable_i2_namespace_partitioning: ...
elif enable_i5_decision_policy: ...
```

In M5, `PromptContractCompiler` executes an additive mixin pipeline:
```
BASE POLICY
  +
SELECTED OUTPUT PROTOCOL (JSON_BAIR)
  +
I2 (EPISTEMIC BOUNDARY & NAMESPACES) [if enabled]
  +
I3 (COUNTERFACTUAL REASONING FRAMEWORK) [if enabled]
  +
I5 (CALIBRATED ABSTENTION CONTRACT) [if enabled]
  +
USER PROMPT (Partitions P1, P3 [I6], P4)
  =
COHERENT REASONING CONTRACT
```

Crucially:
- I2, I3, and I5 do **not** emit conflicting format instructions (such as "Output valid JSON" or "Emit XML").
- The output protocol contract exclusively governs serialization instructions.

---

## 5. Canonical Field Mapping

The adapter `map_bair_json_to_s0` projects `BairJsonObject` into canonical S0 `HypothesisModelOutput`:

| M5 `BairJsonObject` Slot | Canonical S0 `HypothesisModelOutput` Field | Adaptation Behavior |
| :--- | :--- | :--- |
| `invariant` | `invariant` | Direct assignment |
| `evidence_gap` | `evidence_gap` | Direct assignment |
| `affected_target` | `affected_target` | Direct assignment |
| `decision` | `decision` | Direct assignment (`HypothesisDecision`) |
| `empirical_facts` | `supporting_evidence_ids` | Deterministic list copy; preserved order |
| `methodology_references` | `methodology_references` | Deterministic list copy; preserved order |
| `falsification_plan` | `experiment_proposal` | Direct assignment |

The mapping is strictly deterministic, performs zero semantic inference or citation substitution, and fails closed on invalid types.

---

## 6. Parser / Validator / Adapter Flow

The M5 decoding and extraction pipeline enforces the frozen state machine:

```
Raw Model Output
       │
       ▼
Markdown Envelope Stripping (extract innermost JSON block if wrapped in ```json ... ```)
       │
       ▼
JSON Decoding (json.loads; fails closed with BairParseError on syntax error)
       │
       ▼
BairJsonObject Pydantic Validation (validates slot presence, types, regex formats)
       │
       ▼
Decision-Dependent Slot Validation (validate_bair_json: verifies slot consistency with decision)
       │
       ▼
Deterministic Canonical S0 Adaptation (map_bair_json_to_s0)
       │
       ▼
Grounding Validation (KnowledgeGroundingValidator: verifies fact/chunk IDs against target context)
       │
       ▼
Final Classified Result (M5ExecutionResult)
```

---

## 7. Budget Enforcement & Repair

In M4, the budget allocator computed remaining tokens before evaluating I6 or I3, causing:
1. I6 to be silently dropped (`triage_block = ""`) when budget was constrained.
2. I3 counterfactual block to be appended after budget calculation, risking silent overflow.

In M5, budget calculation adheres to a mandatory floor pre-allocation model:
1. **Mandatory Floor (`floor_tokens`)**:
   $$\text{floor\_tokens} = \text{tokens}(P_0\text{ [System Policy]}) + \text{tokens}(P_1\text{ [Target Envelope, Diffs, Canonical Facts]}) + \text{tokens}(P_1\text{ [I3 CF Block]}) + \text{tokens}(P_3\text{ [I6 Handoff]})$$
2. **Deterministic Overflow**:
   If $\text{floor\_tokens} > \text{budget\_tier}$, compilation immediately raises `ContextBudgetOverflowError`. Zero LLM calls occur.
3. **Advisory Pruning**:
   Advisory content ($P_4$ snippets, $P_4$ VAPT methodology) is deterministically pruned only from remaining space after the mandatory floor is reserved.
4. **I6 Protection**:
   I6 is never silently omitted. If enabled, it must either fit in the allocated budget or compilation aborts.

---

## 8. Contract Pre-Flight Validation

Before any LLM invocation, `validate_reasoning_contract` verifies 16 deterministic invariants:

1. **Protocol Exclusivity**: Exactly one `OutputProtocolIdentifier` is selected.
2. **Parser Presence**: Protocol contract specifies a callable parser.
3. **Validator Presence**: Protocol contract specifies a callable validator.
4. **Adapter Presence**: Protocol contract specifies a callable S0 adapter.
5. **Prompt/Protocol Alignment**: System prompt contains protocol formatting instructions; no contradictory tags (`<bair>` forbidden under `JSON_BAIR`).
6. **Runtime Schema Agreement**: If I1 is enabled, runtime schema matches `BairJsonObject.get_inference_schema()`; if I1 is disabled, runtime schema is `None`.
7. **Parser Agreement**: Parser matches selected protocol (`parse_bair_json` for `JSON_BAIR`).
8. **Validator Agreement**: Validator matches selected protocol (`validate_bair_json` for `JSON_BAIR`).
9. **Adapter Agreement**: Adapter matches selected protocol (`map_bair_json_to_s0` for `JSON_BAIR`).
10. **Intervention Composability**: All enabled interventions are valid members of $\{I_1, I_2, I_3, I_4, I_5, I_6\}$.
11. **Intervention Non-Shadowing**: Enabled intervention semantics (I2 epistemic boundaries, I3 counterfactual templates, I5 abstention) are verified in prompt text.
12. **Formatting Non-Contradiction**: Prompt does not contain conflicting serialization commands.
13. **Budget Compliance**: Mandatory floor tokens and total prompt tokens do not exceed the declared budget tier.
14. **I6 Handoff Integrity**: If I6 is enabled, handoff block is present in user prompt with verified delimiters.
15. **Ground-Truth Isolation**: Prompt is verified free of ground-truth leakage tokens (`is_vulnerable: true`, `ground_truth`, etc.).
16. **Secret Isolation**: Target payloads and prompt text are verified free of secret credentials.

On any violation, `ContractCompilationError` is raised and **zero LLM inference calls occur**.

---

## 9. I1=0 vs I1=1 Runtime Behavior

The contract explicitly handles structured decoding enablement:

| Dimension | Configuration: I1=0 (Unconstrained Sampling) | Configuration: I1=1 (Constrained Decoding) |
| :--- | :--- | :--- |
| **Prompt Format** | `JSON_BAIR` instructions | `JSON_BAIR` instructions |
| **Ollama Request Schema** | `schema=None` | `schema=BairJsonObject.get_inference_schema()` |
| **Output Parser** | `parse_bair_json` | `parse_bair_json` |
| **Output Validator** | `validate_bair_json` | `validate_bair_json` |
| **Contract Status** | Validated pre-flight | Validated pre-flight |

Crucially, under both I1=0 and I1=1, the prompt instructions, parser, validator, and adapter are identical. The runtime schema and parser never disagree.

---

## 10. Test Coverage & Validation Results

Deterministic test suites were executed with live LLM calls disabled (`$env:SKIP_LIVE_OLLAMA="1"`):

- **New M5 Composition Suite** (`tests/unit/test_m5_composition.py`):
  - 33 test cases executed.
  - 33 passed, 0 failed.
  - Covers all 15 pairwise combinations across the entire supported intervention set:
    - 10 prompt/context pairwise combinations ($I_2+I_3$, $I_2+I_4$, $I_2+I_5$, $I_2+I_6$, $I_3+I_4$, $I_3+I_5$, $I_3+I_6$, $I_4+I_5$, $I_4+I_6$, $I_5+I_6$).
    - 5 schema-decoding pairwise combinations ($I_1+I_2$, $I_1+I_3$, $I_1+I_4$, $I_1+I_5$, $I_1+I_6$), verifying protocol exclusivity, runtime schema binding, parser/validator/adapter consistency, and fail-closed mismatch gating.
  - Covers full composition $\{I_1: 0, I_2: 1, I_3: 1, I_4: 1, I_5: 1, I_6: 1\}$ and $\{I_1: 1, I_2: 1, I_3: 1, I_4: 1, I_5: 1, I_6: 1\}$.
  - Covers contradiction detection, budget repair, I6 protection, pre-flight gating, and offline mock execution.
- **Full Unit Test Suite Regression** (`tests/unit/`):
  - 558 passed, 3 skipped (live Ollama tests skipped offline), 0 failed.
  - 100% pass rate across all existing unit test modules.

---

## 11. Remaining Risks & Phase 5 Prerequisites

While the interface contract and composition invariants are deterministically verified, the following engineering risks remain for subsequent phases:

1. **Model Adherence under I1=0**:
   - `qwen2.5-coder:7b` under unconstrained sampling (`format=None`) may emit markdown wrappers or subtle JSON syntax anomalies. The parser is equipped with markdown envelope stripping, but live empirical formatting adherence must be evaluated in Phase 5 smoke testing.
2. **Context Window Sizing**:
   - In Track D scenarios with extensive target parameters or complex observed facts, mandatory floor tokens must be monitored against the 4096 budget tier.
3. **No-LLM Mock Path vs Live Smoke Testing**:
   - Phase 4 verified the contract using mock models. Phase 5 must proceed cautiously: first validating the deterministic contract and no-LLM end-to-end mock path, before authorizing any small (3–5 scenario) live smoke test.

---

## 12. Confirmation of Zero Live LLM Inference

**Official Attestation**:  
During the entire execution of Phase 4, **zero live LLM inference calls** were executed against `qwen2.5-coder:7b` or any other model. All tests and verifications were executed hermetically using deterministic inputs, compiled prompts, generated schemas, and mock callers.
