# M4.9 Technical Erratum: Post-Execution Intervention Composition and Protocol Analysis

**Document Status:** Sealed Technical Erratum  
**Milestone:** M4 (Reasoning Engine Optimization & Epistemic Calibration)  
**Target Milestone Phase:** Phase M4.9 Confirmatory Evaluation  
**Date of Erratum:** 2026-09-21  
**Authoritative M4 Planning Freeze Commit:** `1e1a87070a018542a0a2e79f8a78654f34df5aba` (`m4-v1.1.0-planning-freeze`)  
**M4.9 Result Artifact SHA-256:** `459b9ec63c3a2dc760abde12ec196760f7e505fbab5317f0da0c46b32c5eaac7`  

---

## 1. Purpose and Status

This document is a formal **Technical Erratum** recording an implementation-level architectural defect discovered during post-execution source inspection of Milestone M4.9. 

> [!IMPORTANT]
> **Historical Artifact Immutability**:
> This erratum does **NOT** modify, overwrite, recalculate, or retroactively invalidate the empirical M4.9 confirmatory benchmark results. The official M4.9 artifact ([`data/eval/m4_live_llm_benchmark_final.json`](data/eval/m4_live_llm_benchmark_final.json)) and its companion checksum file remain permanently sealed and byte-identical to their initial generation state. Phase M4.9 remains **CLOSED**. No rerun of M4.9 is authorized.

The purpose of this erratum is to document the exact software engineering failure mechanism that led to 336/336 parser failures, establish the boundary of what the confirmatory benchmark did and did not measure, and define the architectural requirements for future milestones.

---

## 2. M4.9 Confirmatory Execution Facts

The official M4.9 confirmatory benchmark was executed under the frozen protocol specified in [`docs/M4_REASONING_ENGINE_PLAN.md`](docs/M4_REASONING_ENGINE_PLAN.md):

- **Dataset**: Authoritative 84-scenario benchmark ([`data/benchmarks/m1_5_frozen_manifest.json`](data/benchmarks/m1_5_frozen_manifest.json), SHA-256: `b2b85a672124acf21066a257d8c7f5093000368b224ee013c02574c96a0ae707`).
  - 36 benchmark vulnerable scenarios.
  - 48 negative-control scenarios.
- **Tracks Evaluated**:
  - `TRACK_A`: Track A (No RAG: No Target Evidence, No VAPT Knowledge)
  - `TRACK_B`: Track B (Target-Evidence RAG: `evidence.db`, No VAPT Knowledge)
  - `TRACK_C`: Track C (VAPT Knowledge RAG: `vapt_knowledge.db`, No Target Evidence)
  - `TRACK_D`: Track D (Dual RAG: Target Evidence + VAPT Knowledge)
- **Active Configuration**: Frozen M4.8 configuration `M4-COMBINED-I5-I2-I6-I3-I4`:
  - $I_1 = 0$ (Native runtime schema constrained decoding: OFF)
  - $I_2 = 1$ (Epistemic namespace segregation: ON)
  - $I_3 = 1$ (Counterfactual invariant prompting: ON)
  - $I_4 = 1$ (Bounded Analytical Intermediate Representation / BAIR: ON)
  - $I_5 = 1$ (Calibrated abstention decision policy: ON)
  - $I_6 = 1$ (Pure invariant 3B handoff serializer: ON)
- **Execution Budget**: Exactly 336 scheduled LLM calls ($84 \times 4$).
- **Inference Discipline**:
  - Exactly 1 LLM inference call per scheduled attempt.
  - Exactly 0 automatic retries.
  - Exactly 0 semantic repairs.
  - Exactly 0 transport failures.
- **Compute Envelope**:
  - Model: `qwen2.5-coder:7b` (pinned digest: `dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364`)
  - Runtime: Local Ollama v0.34.1 at `http://127.0.0.1:11434`
  - Parameters: `num_ctx=2048`, `num_predict=300`, `temperature=0.0`, `seed=42`, `keep_alive=60m`
  - Schema: `None` (unconstrained sampling).
- **Causal Parity & Ground-Truth Isolation**:
  - Strict B/D target evidence causal parity: 84/84 byte-identical matches (0 discrepancies).
  - Ground-truth isolation: 18/18 unit tests passed; 0 forbidden ground-truth tokens in prompts.
- **Empirical Results Recorded**:
  - Useful Hypothesis Count: $0 / 84$ across all four tracks (0.00% Useful Hypothesis Rate).
  - True Positive Rate (TPR): $0 / 36$ (0.00%) across all four tracks.
  - True Negative Rate (TNR): $48 / 48$ (100.00%) across all four tracks (due to fail-closed abstention).
  - AC1 Primary Failure Breakdown:
    - `RUNTIME_TRANSPORT_FAILURE`: $0 / 336$ (0.00%)
    - `MAX_TOKEN_TRUNCATION`: $0 / 336$ (0.00%)
    - `PARSER_FAILURE`: $336 / 336$ (**100.00%**)
    - `SCHEMA_VALIDITY_FAILURE`: $0 / 336$ (0.00%)
    - `SEMANTIC_GROUNDING_FAILURE`: $0 / 336$ (0.00%)
    - `VALID`: $0 / 336$ (0.00%)

---

## 3. Source-Level Root Cause: Mutually Exclusive Prompt Branching

A thorough inspection of [`src/engine/context_builder.py`](src/engine/context_builder.py) reveals the primary engineering defect responsible for the uniform parser failure.

### 3.1 The Flawed Branching Structure

In [`ReasoningContextBuilder.build_context()`](src/engine/context_builder.py#L100-L250), system prompt construction was implemented using an `if / elif` cascade:

```python
# src/engine/context_builder.py (Lines 141-249)

if enable_i2_namespace_partitioning:
    system_policy = (
        "You are an authoritative Application Security Reasoning Engine.\n"
        "...\n"
        "- Output valid JSON with segregated epistemic namespace fields:\n"
        "  * 'empirical_fact_ids': ONLY empirical target evidence IDs matching ^FACT-[A-Z0-9_-]+$\n"
        "  * 'methodology_chunk_ids': ONLY VAPT methodology guidance IDs matching ^CHK-[A-Z0-9_-]+$\n"
        "...\n"
    )
elif enable_i3_counterfactual_prompting:
    ...
elif enable_i4_bair:
    system_policy = (
        "You are an authoritative Application Security Reasoning Engine.\n"
        "...\n"
        "OUTPUT FORMAT (BOUNDED ANALYTICAL INFERENCE REPRESENTATION - BAIR):\n"
        "Emit your evaluation strictly as XML enclosed in a single <bair>...</bair> block with exactly these seven slots:\n"
        "<bair>\n"
        "  <invariant>...</invariant>\n"
        "  <evidence_gap>...</evidence_gap>\n"
        "  <affected_target>...</affected_target>\n"
        "  <decision>...</decision>\n"
        "  <facts>...</facts>\n"
        "  <methodology>...</methodology>\n"
        "  <falsification>...</falsification>\n"
        "</bair>\n"
        "...\n"
    )
elif enable_i5_decision_policy:
    ...
else:
    ...
```

### 3.2 The Shadowing Effect Under COMBINED Activation

In Phase M4.8 single-factor screening ($E_1$ through $E_6$), exactly one intervention was active at a time (e.g. for $E_2$: $I_2=1$ and $I_4=0$; for $E_4$: $I_4=1$ and $I_2=0$). Under single-factor evaluation, each intervention's dedicated branch was reached without interference.

However, the final frozen M4.8 configuration activated:
$$\{I_1: 0, I_2: 1, I_3: 1, I_4: 1, I_5: 1, I_6: 1\}$$

When `enable_i2_namespace_partitioning=True` and `enable_i4_bair=True` were passed simultaneously:
1. `if enable_i2_namespace_partitioning:` evaluated to `True`.
2. The entire `elif enable_i4_bair:` branch was **silently skipped and never executed**.
3. The prompt emitted to the model contained **zero instructions regarding `<bair>` XML**, zero slot definitions, and explicitly commanded:  
   `"Output valid JSON with segregated epistemic namespace fields: ..."`
4. In addition, lines 469–478 appended counterfactual instructions referencing JSON fields (`'invariant'`, `'evidence_gap'`, `'experiment_proposal'`), reinforcing the JSON requirement.

---

## 4. Output-Protocol Conflict Across Pipeline Layers

The implementation contained multiple competing and mutually contradictory output-protocol assumptions across its modules:

```text
+----------------------+-----------------------+-----------------------------------------------------------+
| Pipeline Component   | Assumed Protocol      | Concrete Requirement / Implementation                     |
+----------------------+-----------------------+-----------------------------------------------------------+
| I2 Prompt Section    | JSON                  | "Output valid JSON with segregated epistemic namespace"   |
| I3 Prompt Section    | JSON                  | Cites JSON fields: 'invariant', 'experiment_proposal'     |
| I4 Prompt Section    | BAIR XML              | "<bair>...</bair>" with 7 bounded slots                   |
| I5 Decision Policy   | S0 Python Model       | Operates on HypothesisModelOutput (JSON-derived)          |
| Ollama Runtime       | Unconstrained Text    | schema=None (since I1 was disabled)                       |
| Evaluator Harness    | BAIR XML              | Calls parse_bair(raw_response)                            |
+----------------------+-----------------------+-----------------------------------------------------------+
```

### 4.1 The Resulting Failure Chain

1. **Prompt Construction**: `context_builder.py` assembled a prompt instructing the model to output **valid JSON** (due to $I_2$ shadowing $I_4$).
2. **Model Inference**: The local 7B model received the prompt and generated valid JSON markdown:
   ```json
   ```json
   {
     "invariant": "...",
     "evidence_gap": "...",
     ...
   }
   ```
   ```
3. **Evaluation Parser**: The confirmatory harness ([`src/eval/m4_live_benchmark.py`](src/eval/m4_live_benchmark.py#L393)), knowing that $I_4$ was nominally active in the configuration, invoked [`parse_bair(raw_response)`](src/engine/bair_extractor.py#L74).
4. **AST Failure**: `parse_bair()` expects `<bair>...</bair>` XML tags. Finding only JSON text, it raised `BairParseError("No <bair> root tag found in model response")`.
5. **AC1 Classification**: Under the mutually exclusive failure taxonomy, the failure was classified as `PARSER_FAILURE`.
6. **Fail-Closed Gate**: All downstream layers (I5 decision policy, grounding validator, and hypothesis scoring) were skipped. All 336 evaluations failed closed to abstention/rejection.

---

## 5. Causal Interpretation Boundary

To maintain scientific integrity, a strict boundary must be drawn between what M4.9 demonstrated and what it did not:

### A. What M4.9 Empirically Proved
- **Pipeline Integrity**: M4.9 proved that the platform's fail-closed evaluation gates operate with 100% reliability. Malformed or mismatched model outputs never bypass the parser, never fabricate ungrounded hypotheses, and never generate False Positives on negative controls ($\text{TNR} = 100.0\%$).
- **Causal Parity**: B/D causal parity was preserved with zero discrepancies across all 84 scenarios ($84/84$).
- **Deterministic Replication**: The confirmatory run faithfully replicated the exploratory M4.8 COMBINED screening result (where 20/20 scenarios also produced `PARSER_FAILURE` under the same configuration).

### B. What the Source Inspection Discovered
- The zero-yield result was not caused by model reasoning failure, token budget exhaustion, or RAG degradation.
- It was caused by a software engineering composition defect: the prompt compiler instructed JSON, while the evaluation harness expected XML BAIR.

### C. What Cannot Be Inferred About RAG Conditions
- **No Causal Claim on RAG**: The confirmatory run **cannot** be used to draw conclusions regarding the relative effectiveness of Track A (No RAG), Track B (Target Ev), Track C (VAPT), or Track D (Dual).
- Because 100% of calls in all four tracks failed at the syntactic parsing boundary, no track's retrieved evidence or methodology chunks ever reached the reasoning evaluation or grounding layers.

---

## 6. Historical-Artifact Integrity

The official M4.9 confirmatory benchmark artifacts remain sealed and unaltered in their original locations:

- **Primary Result Artifact**:
  - Path: [`data/eval/m4_live_llm_benchmark_final.json`](data/eval/m4_live_llm_benchmark_final.json)
  - Verified SHA-256: `459b9ec63c3a2dc760abde12ec196760f7e505fbab5317f0da0c46b32c5eaac7`
- **Companion Checksum File**:
  - Path: [`data/eval/m4_live_llm_benchmark_final.json.sha256`](data/eval/m4_live_llm_benchmark_final.json.sha256)
  - Content: `459b9ec63c3a2dc760abde12ec196760f7e505fbab5317f0da0c46b32c5eaac7`
- **Planning Freeze State**:
  - Tag: `m4-v1.1.0-planning-freeze`
  - Commit: `1e1a87070a018542a0a2e79f8a78654f34df5aba`

---

## 7. Affected Components and Files

The following components and files in the repository are directly involved in the composition conflict:

1. [`src/engine/context_builder.py`](src/engine/context_builder.py):
   - `ReasoningContextBuilder.build_context()`: Contains the mutually exclusive `if/elif` cascade (lines 141–249) that causes $I_2$ to shadow $I_3$, $I_4$, and $I_5$.
   - Counterfactual block addition (lines 463–478): References JSON field names rather than the active protocol, and bypasses P0/P1 budget checking.
2. [`src/engine/bair_extractor.py`](src/engine/bair_extractor.py):
   - `parse_bair()`: Bounded XML AST parser expecting `<bair>...</bair>`.
   - `validate_bair()`, `map_bair_to_s0()`: Extraction and schema adaptation pipeline.
3. [`src/eval/m4_live_benchmark.py`](src/eval/m4_live_benchmark.py):
   - `M4ConfirmatoryHarness.build_prompt_for_track()`: Passes all combined flags to `build_context()`.
   - `M4ConfirmatoryHarness.execute_scenario_track()`: Invocates `parse_bair()` unconditionally under combined configuration.
4. [`src/eval/m4_screening_harness.py`](src/eval/m4_screening_harness.py):
   - `M4ScreeningHarness.execute_scenario_track()`: Contains the parallel COMBINED branch that produced the original 20/20 parser failures in M4.8.
5. [`src/engine/models.py`](src/engine/models.py):
   - `classify_primary_failure()`: Correctly flagged the parser error under AC1 precedence.
6. [`src/engine/decision_policy.py`](src/engine/decision_policy.py):
   - `deterministic_decide()`: Operates on `HypothesisModelOutput`, which was starved of valid input due to upstream parser rejection.

---

## 8. Research Consequences and Next Milestone Mandate

The discovery of this protocol conflict establishes clear methodological requirements for future work:

1. **Milestone M4 Closure**: Milestone M4 is formally complete and closed. Its empirical records stand as historical evidence of the behavior of the system under the specified engineering state.
2. **New Dedicated Milestone**: The resolution of intervention composition and protocol reconciliation must be undertaken in a new milestone (Milestone M5).
3. **Core Composition Invariant**: In Milestone M5, interventions must be composable. No intervention may unilaterally replace another intervention's system prompt or output protocol.
4. **Explicit Protocol Compiler**: The system prompt instructions, runtime schema constraint (if any), extraction parser, validator, and adapter must be compiled from an explicit, single protocol contract (e.g. `OUTPUT_PROTOCOL_CONTRACT`).
5. **Deterministic Pre-Benchmark Invariants**: Before any live multi-call LLM benchmark is executed, deterministic offline tests must verify that the rendered prompt and downstream parser agree on the exact same output protocol.

---

## 9. Non-Negotiable Governance Declarations

1. **Milestone M4.9 is CLOSED**.
2. **No retrospective rerun of M4.9 is authorized**.
3. **No post-result parameter or prompt tuning is permitted within M4**.
4. **The M4.9 artifact SHA-256 (`459b9ec6...`) remains the permanent reference checksum**.
