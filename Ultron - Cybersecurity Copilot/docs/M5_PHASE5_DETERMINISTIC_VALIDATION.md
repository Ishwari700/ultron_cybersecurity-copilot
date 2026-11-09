# Milestone M5 — Phase 5 Deterministic Validation Report

**Date**: 2026-09-21  
**Status**: COMPLETE  
**Milestone**: Milestone M5 (Reasoning Interface & Protocol Reconciliation)  
**Phase**: Phase 5 — Deterministic End-to-End M5 Contract Validation  
**Isolation Constraint**: Offline / Mock Only. Zero live LLM calls, zero network access.

---

## 1. Pre-Flight Integrity

Prior to executing deterministic validation, the test environment and repository state were verified against strict governance requirements:

- **Git Status**: Working directory confirmed clean with no untracked or dangling files from prior runs.
- **M4 Planning Freeze**: `docs/M4_REASONING_ENGINE_PLAN.md` confirmed frozen and untouched.
- **M4.9 Result Integrity**:
  - `data/eval/m4_live_llm_benchmark_final.json` SHA-256 confirmed byte-for-byte:
    `459b9ec63c3a2dc760abde12ec196760f7e505fbab5317f0da0c46b32c5eaac7`
  - `data/eval/m4_live_llm_benchmark_final.json.sha256` confirmed untouched.
- **Protected Files Integrity**:
  - `docs/M4_REASONING_ENGINE_PLAN.md`: Unchanged
  - `src/retrieval/hybrid.py`: Unchanged
  - `data/eval/m3_live_llm_benchmark_20260920.json`: Unchanged
- **Phase 4 Commits**:
  - Phase 4 commit (`b62e0ba`): Present
  - Phase 4.1 commit (`3e66918`): Present
- **Live Inference / Network Policy**: Zero requests directed to `http://127.0.0.1:11434` or any external network endpoint. Hard network blocking fixture actively verified.

---

## 2. End-to-End Valid Hypothesis Path (Phase 5C)

The deterministic pipeline was exercised under full composite intervention activation:
$$\text{I1}=0, \quad \text{I2}=1, \quad \text{I3}=1, \quad \text{I4}=1, \quad \text{I5}=1, \quad \text{I6}=1$$
using protocol `OutputProtocolIdentifier.JSON_BAIR`.

A synthetic scenario was constructed containing:
- Canonical target evidence (`LosslessStructuralPack` with endpoint `/api/v1/orders/{id}`, parameter lineage `P-ID`, and observed facts `FACT-SYNTH-01`, `FACT-SYNTH-02`);
- VAPT methodology pack (`VaptKnowledgePack` with `CHK-DOC-WSTG-ATHZ-04-001-01`);
- Security invariant: `"Resource access must be restricted to resource owner"`;
- Evidence gap: `EvidenceGapType.MISSING_CROSS_IDENTITY_OBJECT_VERIFICATION`;
- Protected 3B $\to$ 7B handoff (`HandoffSerializer.serialize(...)`);
- Counterfactual category: `API-BOLA-001`.

### Path Verification Results:
1. **Contract Compilation**: Succeeded; single protocol `JSON_BAIR` selected.
2. **Prompt Compilation**: Succeeded with token count within budget; no protocol contradiction detected.
3. **Deterministic Mock Execution**: Syntactically valid JSON_BAIR response emitted matching synthetic facts (`FACT-SYNTH-01`) and methodology (`CHK-DOC-WSTG-ATHZ-04-001-01`). Exactly 1 mock call executed.
4. **Protocol Parser**: Successfully parsed raw string into intermediate dictionary.
5. **Protocol Validator**: Successfully validated `BairJsonObject` Pydantic model with strict field, type, and slot constraints.
6. **Namespace Validation**: All `empirical_facts` validated against `^FACT-[A-Z0-9_-]+$`; all `methodology_references` validated against `^CHK-[A-Z0-9_-]+$`. Zero cross-namespace bleeding.
7. **Deterministic S0 Adapter**: Mapped `BairJsonObject` into canonical `HypothesisModelOutput` with byte-identical slot preservation.
8. **I5 Decision Policy**: `deterministic_decide()` evaluated canonical hypothesis and evidence state; correctly produced `HypothesisDecision.HYPOTHESIS` (`HYPOTHESIS_GROUNDED`).
9. **Authoritative Grounding Validation**: Grounding validator verified cited `FACT-SYNTH-01` against structural pack facts and `CHK-DOC-WSTG-ATHZ-04-001-01` against VAPT items. Grounding succeeded.
10. **Final Evaluation Object**: `M5ExecutionResult` reached evaluation boundary with `contract_valid=True` and `classification.is_valid=True`.
11. **Network Invariance**: Zero live network requests occurred.

---

## 3. Valid INSUFFICIENT_EVIDENCE Path (Phase 5D)

The deterministic pipeline was tested with a synthetic response declaring:
$$\text{decision} = \text{"INSUFFICIENT\_EVIDENCE"}$$
- `evidence_gap` populated with required clarification string;
- `empirical_facts` empty or citing observed partial facts;
- `falsification_plan` populated with discriminating experiment.

### Verification Results:
- Parsing, schema validation, and S0 mapping succeeded.
- `deterministic_decide()` received the exact evidence state.
- Decision remained `INSUFFICIENT_EVIDENCE` (`INSUFFICIENT_EVIDENCE_CONFIRMED`).
- Result was **not** promoted to `HYPOTHESIS`.
- `canonical_hypothesis.decision == HypothesisDecision.INSUFFICIENT_EVIDENCE`.

---

## 4. Valid NO_RELEVANT_FUNCTIONALITY Path (Phase 5E)

The deterministic pipeline was tested with a synthetic scenario on an unparameterized static read-only health endpoint (`/api/v1/health`), declaring:
$$\text{decision} = \text{"NO\_RELEVANT\_FUNCTIONALITY"}$$
- `evidence_gap` set to `None` (optional for non-hypothesis decisions);
- `empirical_facts` empty;
- `methodology_references` empty;
- `falsification_plan` indicating no target isolation functionality.

### Verification Results:
- Parsing, validation, and adapter succeeded.
- `deterministic_decide()` confirmed target functionality was outside examined property (`is_relevant_functionality == False`).
- Classification preserved as `NO_RELEVANT_FUNCTIONALITY` (`NO_RELEVANT_FUNCTIONALITY_CONFIRMED`).
- Zero vulnerability hypothesis was fabricated.

---

## 5. Parser / Schema Negative Tests (Phase 5F)

12 fail-closed negative test cases were evaluated. Every case was verified to fail closed with `classification.is_valid is False`, `canonical_hypothesis is None`, and never score as a valid hypothesis:

| Case ID | Failure Description | Primary Failure Category | Expected Error Substring Match | Status |
|---|---|---|---|---|
| `malformed_json` | Syntax error (missing closing brace) | `PARSER_FAILURE` | `Invalid JSON` | PASSED |
| `wrong_top_level_type` | Root is JSON list `[...]` instead of object `{...}` | `PARSER_FAILURE` | `not a dictionary` | PASSED |
| `missing_required_field` | Missing required slot `invariant` | `SCHEMA_VALIDITY_FAILURE` | `Field required` | PASSED |
| `invalid_decision` | Unrecognized decision string (`PROBABLY_VULNERABLE`) | `SCHEMA_VALIDITY_FAILURE` | `Input should be` | PASSED |
| `confirmed_decision` | Forbidden `CONFIRMED` decision | `SCHEMA_VALIDITY_FAILURE` | `Input should be` | PASSED |
| `invalid_fact_identifier` | Malformed fact ID syntax (`INVALID_FACT_SYNTAX!`) | `SCHEMA_VALIDITY_FAILURE` | `does not match ^FACT` | PASSED |
| `invalid_chk_identifier` | Malformed methodology ID syntax (`INVALID_CHK_FORMAT`) | `SCHEMA_VALIDITY_FAILURE` | `does not match ^CHK` | PASSED |
| `cross_namespace_confusion` | `CHK-*` identifier placed in `empirical_facts` slot | `SCHEMA_VALIDITY_FAILURE` | `does not match ^FACT` | PASSED |
| `malformed_falsification_plan`| Whitespace-only string in `falsification_plan` | `SCHEMA_VALIDITY_FAILURE` | `Mandatory falsification_plan slot missing or empty` | PASSED |
| `placeholder_invariant` | Placeholder string (`"N/A"`) in `invariant` slot | `SCHEMA_VALIDITY_FAILURE` | `cannot be a placeholder value` | PASSED |
| `truncated_output` | Incomplete/truncated stream | `PARSER_FAILURE` | `Invalid JSON` | PASSED |
| `hypothesis_missing_facts` | `HYPOTHESIS` decision with empty `empirical_facts` list | `SCHEMA_VALIDITY_FAILURE` | `mandatory empirical_facts slot missing or empty` | PASSED |

---

## 6. Fail-Closed Zero-Call Tests (Phase 5G)

A deterministic mock-call counter was attached to `ReasoningRunner`. For every pre-flight contract violation, execution gating was asserted:

$$\text{call\_count} == 0$$

Tested contract violation gates:
1. **Protocol Mismatch**: Contract protocol identifier mismatched with parser binding $\to$ `call_count == 0`
2. **Parser Mismatch**: Missing or incompatible parser function $\to$ `call_count == 0`
3. **Validator Mismatch**: Missing or incompatible validator function $\to$ `call_count == 0`
4. **Adapter Mismatch**: Missing or incompatible adapter function $\to$ `call_count == 0`
5. **Mandatory Budget Overflow**: Total tokens exceeding budget tier $\to$ `call_count == 0`
6. **Missing I6 Protected Handoff**: `enable_i6=True` without `protected_handoff_present` $\to$ `call_count == 0`
7. **Invalid Runtime Schema**: `enable_i1=True` with `runtime_schema=None` $\to$ `call_count == 0`
8. **Forbidden Ground-Truth Leakage**: Ground-truth tokens detected in prompts $\to$ `call_count == 0`

All 8 pre-flight failure modes rejected execution **before** invoking the inference caller.

---

## 7. Budget End-to-End Tests (Phase 5H)

Token pre-allocation and budget compliance were tested end-to-end:

1. **Exact-Fit Mandatory Context**: Prompt constructed with `budget_tier` set exactly equal to mandatory floor tokens compiled successfully without error (`token_count == exact_floor`).
2. **One-Token Overflow**: Compiling with `budget_tier == exact_floor - 1` raised `ContextBudgetOverflowError` deterministically, failing closed.
3. **I3 Counterfactual Floor Contribution**: Pre-allocation verified that I3 counterfactual block is accounted for in the pre-flight floor calculation and never appended after budget approval.
4. **I6 Protected Handoff Floor Contribution**: Pre-allocation verified that I6 protected invariant block is accounted for in the pre-flight floor calculation and never dropped.
5. **Advisory Content Pruning**: Under tight budget conditions (`floor_tokens + 10`), advisory snippets (P4 target snippets, P4 VAPT chunks) were pruned first while mandatory structural context and protected handoff were fully preserved.

---

## 8. I1=0 / I1=1 Contract Parity (Phase 5I)

The identical synthetic scenario was compiled and evaluated under both grammar-constrained configurations:

- **Case A (I1=0)**: `schema=None` (unconstrained prompt execution)
- **Case B (I1=1)**: `schema=BairJsonObject.get_inference_schema()` (Ollama structured schema constraint)

### Parity Invariants Verified:
- Protocol selected: `OutputProtocolIdentifier.JSON_BAIR` in both cases.
- System and user prompts: Byte-identical.
- Parser function: Identical `parse_bair_json`.
- Validator function: Identical `validate_bair_json`.
- Adapter function: Identical `adapt_bair_json_to_s0`.
- Output parsing and validation behavior: Identical semantic contract across both cases.
- Zero protocol drift between schema-constrained and schema-free execution modes.

---

## 9. Ground-Truth Isolation (Phase 5J)

The synthetic scenario compilation was audited against the evaluation isolation boundary:
- Synthetic prompts and execution contracts inspected for forbidden tokens:
  `"GROUND_TRUTH"`, `"IS_VULNERABLE"`, `"BENCHMARK_LABEL"`, `"GOLD_LABEL"`.
- All tokens evaluated to 0 occurrences.
- Target asset metadata confirmed decoupled from evaluation labels.
- Synthetic IDs (`FACT-SYNTH-01`, `CHK-DOC-WSTG-ATHZ-04-001-01`) used exclusively.

---

## 10. Repeatability (Phase 5K)

The entire deterministic end-to-end pipeline was executed in two consecutive, independent runs on identical input:
- Run 1 and Run 2 contract objects: Byte-identical.
- Compiled prompt hashes: Byte-identical (`hash_run_1 == hash_run_2`).
- Mock caller outputs: Byte-identical.
- Parsed intermediate dictionaries: Byte-identical.
- Adapted `HypothesisModelOutput` instances: Byte-identical.
- Decision policy outputs: Byte-identical.
- Authoritative grounding results: Byte-identical.
- **Nondeterminism observed**: Zero.

---

## 11. Full Regression Results (Phase 5N)

The complete unit test suite was executed offline with `$env:SKIP_LIVE_OLLAMA="1"`:

```
tests/unit/test_m5_end_to_end.py                       30 passed
tests/unit/test_m5_composition.py                      22 passed
tests/unit/test_context_builder.py                      5 passed
tests/unit/test_m4_bair.py                             33 passed
tests/unit/test_m4_schema_constrained_generation.py    12 passed (1 skipped live test)
tests/unit/test_evaluation_isolation.py                5 passed
Other unit test suites (retrieval, diff, scope, etc.) 481 passed
----------------------------------------------------------------------
Total Passed:                                         588 passed
Total Skipped:                                          3 skipped (live Ollama capability checks)
Total Failed:                                           0 failed
Total Live LLM Requests:                                0
```

---

## 12. Remaining Defects

- **Active Defects**: None remaining in the deterministic pipeline.
- All 15 intervention pairwise combinations compile without protocol conflicts.
- Parser and schema validators enforce exact slot contracts and reject placeholders, cross-namespace citations, and unsupported decisions.
- Pre-flight contract gating guarantees zero LLM calls on contract or budget violations.

---

## 13. Explicit Scientific Boundary

> [!IMPORTANT]
> **SCIENTIFIC INTEGRITY NOTICE**  
> Phase 5 was conducted entirely offline using deterministic mocks and synthetic fixtures.  
> **This report makes ZERO claims regarding:**
> - Improved vulnerability detection or True Positive Rate (TPR);
> - Improved Useful Hypothesis Yield;
> - Superior LLM reasoning capability;
> - Superiority of Retrieval-Augmented Generation (RAG) over baseline prompting;
> - Human-efficiency improvements or operational time savings.
>
> Phase 5 demonstrates software engineering correctness, interface coherence, and execution gating only. Validation against live local LLM inference requires a distinct, authorized confirmatory milestone (Phase 6).

---

## Summary Confirmation

- Deterministic end-to-end pipeline: **COHERENT AND VERIFIED**
- Zero live LLM calls occurred: **CONFIRMED**
- Historical M4.9 benchmark artifacts untouched: **CONFIRMED**
- Phase 5: **COMPLETE**
