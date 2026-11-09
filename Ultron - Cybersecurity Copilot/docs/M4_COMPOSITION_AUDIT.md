# Milestone M4 Composition Audit: Intervention Interaction & Output-Protocol Consistency

**Document Status:** Sealed Technical Audit Report  
**Authoritative Planning Freeze Commit:** `1e1a87070a018542a0a2e79f8a78654f34df5aba` (`m4-v1.1.0-planning-freeze`)  
**Historical M4.9 Result Checksum:** `459b9ec63c3a2dc760abde12ec196760f7e505fbab5317f0da0c46b32c5eaac7`  
**Target Milestone for Resolution:** Milestone M5 (Reasoning Interface & Protocol Reconciliation)  
**Date of Audit:** 2026-09-21  

---

## 1. Executive Summary

During Milestone M4, six controlled interventions ($I_1$ through $I_6$) were designed, implemented, and individually screened ($E_1$ through $E_6$). Following Phase M4.8 deterministic selection rules, five interventions were combined into the final configuration:
$$\text{M4-COMBINED-I5-I2-I6-I3-I4} \quad \Longleftrightarrow \quad \{I_1: 0, I_2: 1, I_3: 1, I_4: 1, I_5: 1, I_6: 1\}$$

When this configuration was evaluated in Phase M4.9 across 84 scenarios and 4 tracks (336 live local LLM calls), the automated pipeline recorded **336 / 336 `PARSER_FAILURE` events**, resulting in a $0.00\%$ Useful Hypothesis Rate and $100.00\%$ negative-control True Negative Rate via fail-closed abstention.

This comprehensive source-level audit investigated the entire execution path from scenario loading to evaluation scoring. The audit confirms:
1. **System Policy Shadowing**: In [`src/engine/context_builder.py`](src/engine/context_builder.py#L141-L249), the system policy is constructed using an `if / elif / elif / elif / else` cascade. When $I_2$ and $I_4$ are simultaneously enabled, $I_2$ evaluates first and **completely suppresses the $I_4$ BAIR XML formatting instructions**.
2. **Output-Protocol Schism**: The rendered prompt commanded the model to emit **valid JSON** with segregated fields (`empirical_fact_ids`, `methodology_chunk_ids`), and user-prompt instructions reinforced JSON field names (`'invariant'`, `'evidence_gap'`, `'experiment_proposal'`). However, the evaluation harness in [`src/eval/m4_live_benchmark.py`](src/eval/m4_live_benchmark.py#L393) invoked [`parse_bair()`](src/engine/bair_extractor.py#L74), which expects XML `<bair>...</bair>` tags.
3. **Token Budget Leakage**: In [`src/engine/context_builder.py`](src/engine/context_builder.py#L461-L478), $I_3$ counterfactual reasoning instructions are appended to the user prompt **after** protected floor token budgeting has been evaluated, bypassing the fail-closed budget check. Conversely, $I_6$ protected handoff metadata is silently dropped (`triage_block = ""`) if it exceeds remaining budget headroom rather than failing closed.
4. **Single-Factor Test Isolation Gap**: Prior unit tests rigorously validated each intervention in isolation ($I_k$ alone with all $I_{j \ne k} = 0$), but zero unit tests validated multi-intervention composition, prompt-parser agreement, or protocol coherence under the combined configuration.

---

## 2. End-to-End Architecture & Data-Flow Failure Trace

The following diagram illustrates the execution flow and the exact juncture where the composition conflict occurs:

```text
               ┌────────────────────────────────────────────────────────┐
               │          84 Frozen Scenarios Manifest (M1.5)           │
               └───────────────────────────┬────────────────────────────┘
                                           │
                                           ▼
               ┌────────────────────────────────────────────────────────┐
               │    Canonical Structural Pack (LosslessStructuralPack)   │
               └───────────────────────────┬────────────────────────────┘
                                           │
                                           ▼
               ┌────────────────────────────────────────────────────────┐
               │  ReasoningContextBuilder.build_context(I2,I3,I4,I5,I6) │
               │                                                        │
               │   if enable_i2:                                        │
               │     system_policy = "Output valid JSON..." ◄───[MATCH] │
               │   elif enable_i3: ... [SKIPPED]                        │
               │   elif enable_i4: "<bair>...</bair>" [SHADOWED/SKIPPED]│
               │   elif enable_i5: ... [SKIPPED]                        │
               │                                                        │
               │   + User Prompt: counterfactual JSON fields (I3)       │
               │   + P3 Triage: Protected Invariant Handoff (I6)        │
               └───────────────────────────┬────────────────────────────┘
                                           │
                                           ▼
               ┌────────────────────────────────────────────────────────┐
               │   Rendered Prompt Explicitly Demands JSON Output       │
               └───────────────────────────┬────────────────────────────┘
                                           │ (Ollama Request: schema=None)
                                           ▼
               ┌────────────────────────────────────────────────────────┐
               │   Local LLM Inference (qwen2.5-coder:7b, 1 call)       │
               │   Output: ```json { "invariant": "...", ... } ```      │
               └───────────────────────────┬────────────────────────────┘
                                           │
                                           ▼
               ┌────────────────────────────────────────────────────────┐
               │ Evaluator Execution (src/eval/m4_live_benchmark.py)    │
               │ Harness calls: parse_bair(raw_response)                │
               └───────────────────────────┬────────────────────────────┘
                                           │
                                           ▼
                       ┌───────────────────────────────────────┐
                       │  parse_bair() expects XML <bair> root │
                       │  Finds JSON -> Raises BairParseError  │
                       └───────────────────┬───────────────────┘
                                           │
                                           ▼
                       ┌───────────────────────────────────────┐
                       │ classify_primary_failure()            │
                       │ Precedence: PARSER_FAILURE (100%)     │
                       └───────────────────┬───────────────────┘
                                           │
                                           ▼
                       ┌───────────────────────────────────────┐
                       │ Fail-Closed Abstention:               │
                       │ - Downstream I5 Policy SKIPPED        │
                       │ - Grounding Validation SKIPPED        │
                       │ - TPR = 0/36 (0%), TNR = 48/48 (100%) │
                       └───────────────────────────────────────┘
```

---

## 3. Intervention Inventory (Phase 2A)

The table below catalogs all six interventions ($I_1$ through $I_6$), their software boundaries, prompt contributions, format assumptions, and composition properties:

| Intervention | Activation Flag | Owning Module / Class | Prompt Sections Contributed | Output Format Assumption | Runtime Schema Assumption | Parser / Extractor | Downstream Consumers | Composable with Others? |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **$I_1$** (Schema-Constrained Generation) | `enable_i1_schema` / `i1` | [`src/engine/models.py`](src/engine/models.py#L64)<br>[`src/engine/runner.py`](src/engine/runner.py#L574) | None (operates at decoding level) | Strict JSON conforming to S0 schema | Native Ollama JSON schema (`format={...}`) | Standard `json.loads` + Pydantic validation | `HypothesisModelOutput` $\to$ `KnowledgeGroundingValidator` | **No**: Incompatible with XML BAIR; requires native JSON. |
| **$I_2$** (Namespace Segregation) | `enable_i2_namespace_partitioning` / `i2` | [`src/engine/context_builder.py`](src/engine/context_builder.py#L141)<br>[`src/engine/models.py`](src/engine/models.py#L267) | System policy (P0); `<empirical_target_evidence>` (P1); `<security_testing_methodology>` (P4) | JSON with segregated arrays: `empirical_fact_ids`, `methodology_chunk_ids` | Unconstrained text (`schema=None`) | Standard `json.loads` + `I2RawHypothesisOutput` $\to$ `adapt_i2_to_s0()` | `KnowledgeGroundingValidator` (checks FACT/CHK namespaces) | **Partial**: Shadowed $I_4$ system prompt; can be composed if namespace tags apply to BAIR slots. |
| **$I_3$** (Counterfactual Prompting) | `enable_i3_counterfactual_prompting` / `i3` | [`src/engine/prompts.py`](src/engine/prompts.py#L21)<br>[`src/engine/context_builder.py`](src/engine/context_builder.py#L158) | System policy (P0, shadowed by $I_2$); `=== COUNTERFACTUAL REASONING INSTRUCTIONS ===` (User Prompt) | JSON S0 fields: `'invariant'`, `'evidence_gap'`, `'experiment_proposal'` | Unconstrained text (`schema=None`) | Standard `json.loads` + `HypothesisModelOutput` | S0 Evaluator $\to$ Grounding Validator | **Partial**: System policy shadowed by $I_2$; user prompt instructions contradict BAIR `<falsification>` slot naming. |
| **$I_4$** (BAIR Analytical Intermediate) | `enable_i4_bair` / `i4` | [`src/engine/bair_extractor.py`](src/engine/bair_extractor.py#L74)<br>[`src/engine/context_builder.py`](src/engine/context_builder.py#L184) | System policy (P0): BAIR format instructions and slot definitions | XML: `<bair>...</bair>` with 7 bounded slots | Unconstrained text (`schema=None`) | `parse_bair()` (XML AST) $\to$ `validate_bair()` $\to$ `map_bair_to_s0()` | `map_bair_to_s0()` produces `HypothesisModelOutput` $\to$ $I_5$ / Grounding | **No**: System policy was completely shadowed by $I_2$; parser cannot parse JSON emitted under $I_2$. |
| **$I_5$** (Calibrated Decision Policy) | `enable_i5_decision_policy` / `i5` | [`src/engine/decision_policy.py`](src/engine/decision_policy.py#L370)<br>[`src/engine/context_builder.py`](src/engine/context_builder.py#L220) | System policy (P0, shadowed by $I_2$): definitions for `HYPOTHESIS`, `INSUFFICIENT_EVIDENCE`, `NO_RELEVANT_FUNCTIONALITY` | Operates in Python on canonical `HypothesisModelOutput` | Indifferent to transport format | Python policy function (`deterministic_decide`) | `ConfirmatoryScenarioRecord.decision` | **Yes**: Downstream Python logic is composable with any valid S0 object; prompt definitions were shadowed by $I_2$. |
| **$I_6$** (Pure Invariant Handoff) | `enable_i6_handoff` / `i6` | [`src/engine/handoff_serializer.py`](src/engine/handoff_serializer.py#L112)<br>[`src/engine/context_builder.py`](src/engine/context_builder.py#L367) | Replaces Channel B natural-language triage in Partition P3 with verified Class-1 booleans and gap type | Upstream prompt injection only (no output format assumption) | Indifferent | None (input serializer) | Model context (P3) | **Yes**: Fully composable with all output formats; risk is silent budget truncation if headroom is exhausted. |

---

## 4. Prompt-Construction Graph & Shadowing Analysis (Phase 2B)

### 4.1 Execution Sequence in `ReasoningContextBuilder.build_context()`

The context builder constructs prompts in the following linear order:

```text
Step 1: System Policy (P0 Floor)
        ├─ if enable_i2_namespace_partitioning:  [BRANCH 1 - Matches if I2=1]
        ├─ elif enable_i3_counterfactual_prompting: [BRANCH 2 - Shadowed if I2=1]
        ├─ elif enable_i4_bair:                  [BRANCH 3 - Shadowed if I2=1 or I3=1]
        ├─ elif enable_i5_decision_policy:       [BRANCH 4 - Shadowed if I2=1, I3=1, or I4=1]
        └─ else:                                 [BRANCH 5 - Baseline]

Step 2: Target Envelope (P1 Floor)
        └─ Always added (Asset ID, Endpoint ID, Route, Method, Mutability)

Step 3: Structural Diffs & Contradictions (P1 Floor)
        └─ Extracted from Channel A LosslessStructuralPack

Step 4: Canonical Evidence Statements (P1 Floor)
        ├─ if enable_i2_namespace_partitioning: wraps in <empirical_target_evidence>
        └─ else: standard evidence lines

Step 5: Budget Floor Check
        └─ floor_tokens = p0_tokens + p1_tokens
        └─ if floor_tokens > budget_tier: raise ContextBudgetOverflowError
        └─ remaining_budget = budget_tier - floor_tokens

Step 6: Channel B Triage / Protected Handoff (P3 Advisory)
        ├─ if enable_i6_handoff and protected_handoff is not None:
        │    if p3_tokens > remaining_budget:
        │       triage_block = ""  <-- [SILENT DROP]
        │    else:
        │       remaining_budget -= p3_tokens
        └─ elif include_triage and optional_advisory_content_mode: ...

Step 7: Encapsulated Raw Snippets (P4 Untrusted Target Data)
        └─ Deducted from remaining_budget

Step 8: VAPT Advisory Knowledge Pack (P4 Advisory)
        ├─ if enable_i2_namespace_partitioning: wraps in <security_testing_methodology>
        └─ Deducted from remaining_budget (fail-soft drop if headroom exhausted)

Step 9: Counterfactual Instructions Block (I3 Addition)
        └─ if enable_i3_counterfactual_prompting:
             appends === COUNTERFACTUAL REASONING INSTRUCTIONS ===
             <-- [CRITICAL: Added after Step 5 floor check and after remaining_budget calculation!]
```

### 4.2 Pairwise Interaction Matrix

```text
+---------+----------------------------------------------------------------------------------------------------+
| Pair    | Interaction & Architectural Behavior                                                               |
+---------+----------------------------------------------------------------------------------------------------+
| I2 + I3 | CONFLICT in P0: I2 system prompt shadows I3 counterfactual system prompt.                          |
|         | PARTIAL LEAKAGE: I3 appends user-prompt instructions that cite JSON field names.                  |
+---------+----------------------------------------------------------------------------------------------------+
| I2 + I4 | FATAL CONFLICT: I2 system prompt ("Output valid JSON...") completely shadows I4 BAIR XML           |
|         | instructions ("<bair>...</bair>"). Model receives JSON instructions; evaluator calls parse_bair(). |
+---------+----------------------------------------------------------------------------------------------------+
| I2 + I5 | CONFLICT in P0: I2 system prompt shadows I5 decision policy definitions.                           |
|         | COMPATIBLE DOWNSTREAM: I5 Python decision logic operates on S0 output produced by I2 adapter.     |
+---------+----------------------------------------------------------------------------------------------------+
| I2 + I6 | COMPATIBLE: I2 governs system policy / namespace tagging; I6 serializes into P3 triage block.      |
+---------+----------------------------------------------------------------------------------------------------+
| I3 + I4 | CONFLICT: I3 user-prompt block commands model to emit JSON fields ('invariant', 'evidence_gap',   |
|         | 'experiment_proposal'). I4 expects XML slots (<invariant>, <evidence_gap>, <falsification>).      |
+---------+----------------------------------------------------------------------------------------------------+
| I3 + I5 | COMPATIBLE: I3 guides evidence-gap evaluation; I5 enforces calibrated decision thresholds on S0.   |
+---------+----------------------------------------------------------------------------------------------------+
| I3 + I6 | COMPATIBLE: I6 supplies invariant definition and gap type; I3 formats counterfactual evaluation.   |
+---------+----------------------------------------------------------------------------------------------------+
| I4 + I5 | COMPATIBLE (IF I4 PARSES): map_bair_to_s0() produces HypothesisModelOutput which I5 consumes.      |
|         | CONFLICT in P0: I4 system policy shadows I5 prompt definitions if both are in if/elif.            |
+---------+----------------------------------------------------------------------------------------------------+
| I4 + I6 | COMPATIBLE: I6 serializes structural deltas; I4 structures model analytical emission.              |
+---------+----------------------------------------------------------------------------------------------------+
| I5 + I6 | FULLY COMPATIBLE: I6 provides verified Class-1 booleans; I5 checks these booleans in predicates.   |
+---------+----------------------------------------------------------------------------------------------------+
```

### 4.3 The Frozen Selected Combination: $\{I_1: 0, I_2: 1, I_3: 1, I_4: 1, I_5: 1, I_6: 1\}$

Under the full combined configuration:
1. $I_2$ activates first in the `if/elif` cascade, asserting absolute ownership over the system policy.
2. The model prompt receives:
   - System Policy: I2 JSON specification (`empirical_fact_ids`, `methodology_chunk_ids`).
   - P1 Evidence: Wrapped in `<empirical_target_evidence>`.
   - P3 Handoff: I6 serialized Class-1 booleans and gap type.
   - P4 Methodology: Wrapped in `<security_testing_methodology>`.
   - User Prompt: I3 counterfactual block citing JSON fields `'invariant'`, `'evidence_gap'`, `'experiment_proposal'`.
3. **Zero traces of $I_4$ BAIR XML instructions exist anywhere in the prompt**.
4. The model generates JSON markdown.
5. The evaluator executes `parse_bair()`, crashing on the first character that is not `<bair>`.

---

## 5. Output-Protocol Audit (Phase 2C)

Every component that makes structural assumptions regarding model generation is audited below:

```text
+-----------------------+-----------------------------+-----------------------------+---------------------+-------------------------------+
| Pipeline Layer        | Expected Input / Protocol   | Emitted Output / Protocol   | Owning Module       | Failure Behavior on Mismatch  |
+-----------------------+-----------------------------+-----------------------------+---------------------+-------------------------------+
| LLM Prompt (Rendered) | Natural Language Prompt     | Natural Language Text       | context_builder.py  | N/A (generates prompt text)   |
| Ollama Runtime API    | Unconstrained (schema=None) | Raw Text String             | runner.py           | TRANSPORT_FAILURE on timeout  |
| Model Emission        | Instruction-following text  | Markdown JSON block         | qwen2.5-coder:7b    | Unconstrained text generation |
| Extractor Layer       | XML with <bair> root tag    | Dict of parsed slot strings | bair_extractor.py   | Raises BairParseError         |
| BAIR Validator        | Dict of slot strings        | Dict of validated slots     | bair_extractor.py   | Raises BairSchemaError        |
| Schema Adapter        | Dict of validated slots     | HypothesisModelOutput (S0)  | bair_extractor.py   | Raises ValidationError        |
| Decision Policy (I5)  | HypothesisModelOutput       | HypothesisModelOutput       | decision_policy.py  | Fails closed to None decision |
| Grounding Validator   | HypothesisModelOutput       | KnowledgeGroundingResult    | grounding_validator | Marks status INVALID          |
| Evaluation Classifier | Raw text + exceptions       | ConfirmatoryScenarioRecord  | models.py / harness | Precedence -> PARSER_FAILURE  |
+-----------------------+-----------------------------+-----------------------------+---------------------+-------------------------------+
```

### Identified Protocol Inconsistencies
1. **Prompt vs Parser**: Prompt commands JSON; parser strictly enforces XML.
2. **Field Names vs Slot Names**:
   - I2 prompt specifies: `empirical_fact_ids` and `methodology_chunk_ids`.
   - I3 prompt specifies: `invariant`, `evidence_gap`, `experiment_proposal`.
   - I4 parser requires: `<facts>`, `<methodology>`, `<falsification>`.
   - S0 schema requires: `supporting_evidence_ids`, `methodology_references`, `experiment_proposal`.
3. **Schema Enforcement vs Sampling**: I1 native schema decoding was disabled ($I_1=0$), meaning the model received no token-level grammar constraint to enforce either JSON or XML syntax.

---

## 6. Parser and Validator Contract Audit (Phase 2D)

### 6.1 Producer-Consumer Contract Tracing

```text
Producer: LLM (qwen2.5-coder:7b under schema=None)
   │  Emits: ```json { "invariant": "...", "evidence_gap": "..." } ```
   ▼
Consumer: parse_bair(raw_text)
   │  Implementation: Looks for root element matching <bair> via xml.etree.ElementTree
   │  Mismatch: json.loads is never attempted in this branch.
   ▼
Result: BairParseError("Expected root element <bair>, got ...")
```

### 6.2 Validator Bypass Analysis

Could an invalid intermediate state bypass validation if the prompt were partially corrected?
- **AST Parsing (`parse_bair`)**: Strictly rejects attributes, unknown slots, duplicate slots, and non-text children. Fail-closed: **Verified Secure**.
- **Slot Validation (`validate_bair`)**: Strictly enforces decision-dependent presence:
  - `HYPOTHESIS`: Requires `<invariant>`, `<evidence_gap>`, `<affected_target>`, `<decision>`, `<facts>`, `<falsification>`.
  - Rejects `CONFIRMED` unconditionally.
  - Rejects placeholder tokens (`"none"`, `"n/a"`, `"{}"`). Fail-closed: **Verified Secure**.
- **Adapter (`map_bair_to_s0`)**: Deterministically maps validated strings into typed Pydantic fields. Zero semantic rewriting: **Verified Secure**.
- **Grounding Validation (`KnowledgeGroundingValidator`)**: Operates downstream of `map_bair_to_s0`. Even if a malformed model output bypassed parsing, the grounding validator independently checks fact existence and rejects ungrounded IDs: **Verified Secure**.

**Conclusion on Validator Bypass**: The failure in M4.9 was an over-rejection at the parser layer, not an under-rejection. System safety boundaries remained entirely intact (0 False Positives on negative controls).

---

## 7. Pairwise Intervention Compatibility Matrix (Phase 2E)

Compatibility categories:
- **`COM`**: Fully composable without code changes.
- **`CONFLICT`**: Direct structural or semantic contradiction in prompt or parsing.
- **`REQUIRES_ADAPTER`**: Output representations differ; requires deterministic transformation.
- **`REQUIRES_PROTOCOL_SELECTION`**: Requires an explicit, unified output protocol choice.

```text
         I1          I2          I3          I4          I5          I6
I1        -       REQUIRES_   REQUIRES_   CONFLICT    REQUIRES_      COM
                  ADAPTER     ADAPTER                 ADAPTER
I2    REQUIRES_       -       CONFLICT    CONFLICT    REQUIRES_      COM
      ADAPTER                             (PROTOCOL)  ADAPTER
I3    REQUIRES_   CONFLICT        -       CONFLICT       COM         COM
      ADAPTER                             (FIELDS)
I4    CONFLICT    CONFLICT    CONFLICT        -       REQUIRES_      COM
                  (PROTOCOL)  (FIELDS)                ADAPTER
I5    REQUIRES_   REQUIRES_      COM      REQUIRES_      -           COM
      ADAPTER     ADAPTER                 ADAPTER
I6       COM         COM         COM         COM         COM          -
```

### Detailed Rationale for Non-`COM` Cells

1. **$I_1$ with $I_4$ (`CONFLICT`)**: $I_1$ enforces native Ollama JSON schema decoding. $I_4$ relies on XML `<bair>` tags. Ollama's `format={...}` parameter accepts JSON schema only; passing a JSON schema forces the model to emit JSON tokens, making `<bair>` XML impossible to sample.
2. **$I_2$ with $I_4$ (`CONFLICT - PROTOCOL`)**: $I_2$ prompt commands JSON with specific array keys. $I_4$ prompt commands XML with specific tags. If both are active, they contradict unless an explicit unified protocol is compiled.
3. **$I_3$ with $I_4$ (`CONFLICT - FIELDS`)**: $I_3$ prompt tells the model to write `'experiment_proposal'`. $I_4$ BAIR requires `<falsification>`.
4. **$I_2$ with $I_3$ (`CONFLICT - SYSTEM PROMPT`)**: In the current implementation, $I_2$ and $I_3$ contend for the system policy block in `context_builder.py`. $I_2$ completely overwrites the counterfactual evaluation framework in P0.
5. **Full Combination $\{I_2, I_3, I_4, I_5, I_6\}$**: Classified as **`FATAL CONFLICT`** in current code due to the `if/elif` prompt shadowing and evaluator parser mismatch.

---

## 8. Token / Context Budget Audit (Phase 2F)

A detailed trace of token budgeting logic in [`ReasoningContextBuilder.build_context()`](src/engine/context_builder.py#L316-L485) reveals two critical budget accounting vulnerabilities:

### 8.1 Late Insertion of $I_3$ (Budget Floor Leakage)
- **Line 317–321**: `floor_tokens` is calculated as `p0_tokens + p1_tokens` where P1 includes Target Envelope, Structural Diffs, Contradictions, and Canonical Evidence Statements.
- **Line 324**: `if floor_tokens > budget_tier: raise ContextBudgetOverflowError` performs the fail-closed budget check.
- **Line 329**: `remaining_budget = budget_tier - floor_tokens` is established.
- **Lines 463–478**: `counterfactual_block` (contributed by $I_3$) is generated and appended to `user_prompt_sections` **after** Step 5 floor check and **after** Step 8 advisory budgeting.
- **Flaw**: `p1_cf_tokens` is never subtracted from `remaining_budget`, never validated against `budget_tier`, and never included in `floor_tokens`. A long counterfactual template can silently cause the total prompt to exceed `budget_tier` without triggering `ContextBudgetOverflowError`.

### 8.2 Silent Discard of $I_6$ Protected Handoff
- **Lines 373–375**:
  ```python
  if p3_tokens > remaining_budget:
      triage_block = ""
      p3_tokens = 0
  else:
      remaining_budget -= p3_tokens
  ```
- **Flaw**: If advisory tokens or canonical evidence consume the budget headroom, the protected $I_6$ handoff block is **silently discarded** (`triage_block = ""`). The prompt compiles without the verified Class-1 invariant deltas, silently reverting to unassisted reasoning without any warning or contract error.

---

## 9. Test-Coverage Gap Analysis (Phase 2G)

Why did the comprehensive test suite (524 passed unit tests) fail to catch this defect before the 336-call confirmatory run?

### Root Cause of Test Blindness
1. **The Single-Factor Isolation Paradigm**: The Phase M4 development plan prioritized strict single-factor isolation ($E_1$ through $E_6$). Unit tests were explicitly designed to verify that when intervention $I_k$ was tested, all other interventions were turned OFF (e.g. `test_i4_single_factor_isolation_no_i2_namespace_partitioning`).
2. **Missing Multi-Intervention Composition Tests**: Zero unit tests were written that activated two or more interventions simultaneously in `build_context()`.
3. **Missing Prompt-Parser Agreement Tests**: Evaluator tests mocked Ollama responses directly with valid BAIR XML (`make_bair_xml()`), completely bypassing the prompt that Ollama actually saw. The tests verified that *if* Ollama emitted BAIR, the parser worked; they never tested whether the prompt *asked* Ollama for BAIR.

### Test Coverage Gap Table

```text
+--------------------------------------+-------------------------------------+------------------+-----------------------------------------------+------------------------------------------------------+
| Architectural Risk                   | Existing Test Coverage              | Evaluated State  | Missing Assertion                             | Proposed Future Invariant                            |
+--------------------------------------+-------------------------------------+------------------+-----------------------------------------------+------------------------------------------------------+
| System policy shadowing              | test_context_builder_enable_i4_bair | I4 alone (I2=0)  | Assert <bair> present when I2=1 and I4=1      | Every active intervention's semantics must be in P0  |
| Prompt-parser protocol mismatch      | test_execute_i4_generation          | Mocked XML input | Assert prompt instruction matches parser type | Prompt protocol contract must equal harness parser   |
| Late budget addition (I3)            | test_counterfactual_budget_tier     | Standalone I3    | Assert total full_prompt tokens <= budget     | All prompt blocks must be accounted in floor tokens  |
| Silent handoff drop (I6)             | test_i6_handoff_serialization       | Unit serialization| Assert error raised if handoff does not fit  | Protected handoff must fail closed if dropped        |
| Combined configuration compatibility | test_activation_matrices_isolation  | Matrices as dict | End-to-end dry run of combined configuration  | Combined config must parse mock output matching spec |
+--------------------------------------+-------------------------------------+------------------+-----------------------------------------------+------------------------------------------------------+
```

---

## 10. Research-Integrity Boundary (Phase 2H)

To prevent ungrounded claims or flawed retrospective revisions, this audit establishes strict epistemic boundaries:

1. **Implementation Facts**:
   - `src/engine/context_builder.py` contains mutually exclusive `if/elif` branching that causes $I_2$ to shadow $I_4$.
   - The confirmatory runner invoked `parse_bair()` on outputs prompted as JSON.
   - The resulting failure rate was 100.0% (336/336).
2. **Empirical Facts**:
   - The official M4.9 artifact ([`data/eval/m4_live_llm_benchmark_final.json`](data/eval/m4_live_llm_benchmark_final.json)) recorded $0 / 84$ Useful Hypotheses and $48 / 48$ True Negatives.
   - This result is an accurate, sealed historical record of how the code operated on 2026-09-21.
3. **Deductions from Source Inspection**:
   - The 336 parser failures were caused by the prompt-parser protocol mismatch, not by model reasoning capacity, context window overflow, or Ollama daemon instability.
4. **Unresolved Uncertainty & Forbidden Claims**:
   - **Do NOT claim that RAG conditions (A vs B vs C vs D) are ineffective**: Because 0 evaluations passed parsing, the causal effect of RAG knowledge on 7B reasoning was never tested in M4.9.
   - **Do NOT claim that `qwen2.5-coder:7b` cannot solve the benchmark**: The model was never evaluated with matching prompt instructions and parser expectations under the combined configuration.
   - **Do NOT alter M4.9 artifacts**: M4.9 is closed. All engineering repairs belong strictly to Milestone M5.

---

## 11. Concrete Requirements for Milestone M5 Architecture

Future repair of the reasoning interface in Milestone M5 must satisfy the following non-negotiable requirements:

1. **Single Explicit Output Protocol (`OUTPUT_PROTOCOL_CONTRACT`)**:
   - The platform must declare an explicit output protocol for any execution configuration (e.g. `JSON_SCHEMA` vs `BAIR_XML` vs `STRUCTURED_JSON_BAIR`).
   - The Prompt Compiler, the Runtime Schema parameter, and the Evaluator Parser must all be derived from this single contract.
2. **Decoupled Prompt Assembly (Modular Mixins)**:
   - System prompt construction must be additive, not mutually exclusive.
   - $I_2$ (Namespace rules), $I_3$ (Counterfactual rules), and $I_5$ (Decision rules) must contribute semantic guidance without altering the chosen serialization protocol.
3. **Rigid Pre-Flight Protocol Agreement Assertion**:
   - The runner must execute a deterministic static assertion before inference:
     $$\text{PromptProtocol}(\text{prompt}) \equiv \text{RuntimeSchema}(\text{ollama}) \equiv \text{ParserProtocol}(\text{evaluator})$$
4. **Strict Token Budget Accounting**:
   - All prompt blocks, including counterfactual instructions and protected handoffs, must be included in the initial budget allocation before inference.
   - If a safety-critical block cannot fit within the configured `budget_tier`, the system must raise `ContextBudgetOverflowError` (fail closed) rather than silently dropping the block.
5. **Hermetic Composition Invariant Tests**:
   - Unit tests must render the combined prompt under all active flags and assert that all required semantic blocks are present and mutually consistent.

---

## 12. Open Questions Requiring Human / Architectural Decision

The following design decisions must be resolved in the Milestone M5 planning specification:

1. **Native JSON vs XML BAIR**:
   - Should BAIR be implemented as native JSON (supported by Ollama's constrained JSON schema decoding), or should it remain XML tags parsed by ElementTree?
   - *Tradeoff*: Native JSON guarantees 0% parser syntax errors via constrained decoding, but risk truncation under 300 tokens; XML BAIR allows bounded slot extraction under unconstrained text, but small 7B models frequently emit markdown JSON unless heavily constrained.
2. **Namespace Representation in XML vs JSON**:
   - If XML BAIR is retained, how should $I_2$ namespace segregation be represented? (e.g. `<facts>` accepting only `FACT-xxx` and `<methodology>` accepting only `CHK-xxx` vs separate child elements).
3. **Counterfactual Slot Alignment**:
   - How should $I_3$ counterfactual definitions be integrated into BAIR slots? (e.g. `<invariant>` maps to $I_3$ invariant, `<falsification>` maps to $I_3$ falsification condition).
