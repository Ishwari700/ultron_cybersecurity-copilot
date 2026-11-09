# Milestone M5: Reasoning Interface & Protocol Reconciliation — Architectural Specification & Implementation Plan

**Milestone Identifier:** M5 (Reasoning Interface & Protocol Reconciliation)  
**Document Version:** `1.0.0 — FROZEN ARCHITECTURAL SPECIFICATION`  
**Status:** DRAFT / DESIGN SPECIFICATION (STRICT DESIGN ONLY — NO CODE CHANGES)  
**Parent Milestones:** 
- Milestone M4 (Reasoning Engine Optimization & Epistemic Calibration — CLOSED)
- Milestone M4.9 Confirmatory Evaluation ([`data/eval/m4_live_llm_benchmark_final.json`](data/eval/m4_live_llm_benchmark_final.json), SHA-256: `459b9ec63c3a2dc760abde12ec196760f7e505fbab5317f0da0c46b32c5eaac7` — CLOSED & IMMUTABLE)
**Foundational Audit Documents:**
- [`docs/M4_9_TECHNICAL_ERRATUM.md`](docs/M4_9_TECHNICAL_ERRATUM.md)
- [`docs/M4_COMPOSITION_AUDIT.md`](docs/M4_COMPOSITION_AUDIT.md)
**Authoritative Planning Freeze Anchor:** `1e1a87070a018542a0a2e79f8a78654f34df5aba` (`m4-v1.1.0-planning-freeze`)  
**Target Specification File:** `docs/M5_REASONING_INTERFACE_PLAN.md`  

---

## 1. Problem Statement

Milestone M4 established six controlled interventions ($I_1$ through $I_6$) to address the empirical bottlenecks observed in Milestone M3 (conservative abstention, token truncation, and epistemic namespace confusion). While each intervention demonstrated clear single-factor properties during isolated screening ($E_1$ through $E_6$), combining them into the final selected configuration:
$$\text{M4-COMBINED-I5-I2-I6-I3-I4} \quad \Longleftrightarrow \quad \{I_1: 0, I_2: 1, I_3: 1, I_4: 1, I_5: 1, I_6: 1\}$$
resulted in a catastrophic software composition failure during the Phase M4.9 confirmatory benchmark. 

Specifically, **336 out of 336 scheduled evaluations terminated in `PARSER_FAILURE`**, yielding $0.00\%$ Useful Hypotheses and $100.00\%$ True Negative Rate on negative controls via fail-closed rejection.

As established by the comprehensive post-execution audits in [`docs/M4_9_TECHNICAL_ERRATUM.md`](docs/M4_9_TECHNICAL_ERRATUM.md) and [`docs/M4_COMPOSITION_AUDIT.md`](docs/M4_COMPOSITION_AUDIT.md), this outcome was caused not by model incapacity, context window exhaustion, or retrieval failure, but by an **unreconciled output-protocol conflict and system-prompt shadowing**:
1. **Mutually Exclusive System Policy Branching**: [`ReasoningContextBuilder.build_context()`](src/engine/context_builder.py#L141-L249) selected system prompt policies using an `if/elif` cascade. When $I_2$ and $I_4$ were simultaneously enabled, $I_2$ evaluated first, commanding JSON output and **completely suppressing the $I_4$ BAIR XML instructions**.
2. **Protocol Schism**: The prompt commanded JSON, while the evaluation harness in [`src/eval/m4_live_benchmark.py`](src/eval/m4_live_benchmark.py#L393) called [`parse_bair()`](src/engine/bair_extractor.py#L74), which requires XML `<bair>...</bair>` tags.
3. **Budget Accounting Gaps**: $I_3$ counterfactual instructions were appended after the token floor check, permitting silent context expansion; conversely, $I_6$ protected handoff was silently dropped if budget headroom was exhausted.
4. **Single-Factor Test Blindness**: Existing unit tests strictly validated single-factor isolation, leaving multi-intervention composition and prompt-parser agreement untested.

Milestone M5 is chartered to **re-architect the Reasoning Interface** to make interventions truly composable, establish a single authoritative output protocol contract, guarantee prompt-parser-runtime coherence, and enforce rigid pre-flight validation invariants.

---

## 2. M4.9 Empirical & Implementation Lessons

Milestone M5 is grounded in four non-negotiable architectural lessons from M4.9:

1. **Interventions Cannot Own Global Serialization**: An intervention that introduces semantic constraints (e.g. $I_2$ namespace segregation or $I_3$ counterfactual invariants) must never unilaterally dictate or overwrite the transport serialization format (JSON vs XML).
2. **Prompts and Parsers Must Be Compiled from a Shared Contract**: It is intolerable for prompt assembly and response parsing to be decoupled. If the prompt asks for JSON, the parser must parse JSON; if the parser expects XML, the prompt must specify XML. Any discrepancy must fail closed before inference.
3. **Decoupled Architecture Over Monolithic `if/elif` Cascades**: Branching cascades inevitably lead to shadowing under combinatorial activation. System prompt construction must be modular and additive.
4. **Composition Invariants Must Be Formally Tested**: Passing single-factor unit tests does not imply system viability. Multi-factor integration tests must assert end-to-end prompt-protocol-parser coherence under all supported activation vectors.

---

## 3. Core Architectural Requirements & Non-Negotiable Invariants

Milestone M5 establishes five foundational architectural invariants:

### 3.1 The Composition Invariant
Every active intervention contributes its designated semantic instructions independently. No active intervention may:
- replace or suppress the system prompt of another active intervention;
- silently omit its required constraints;
- overwrite the global output serialization format unless designated as the explicit protocol owner.

### 3.2 The Single-Protocol Invariant
For any evaluation or inference request, there must exist **exactly ONE explicit output protocol** ($P \in \mathcal{P}$).
The following six pipeline stages must strictly agree on protocol $P$:
$$\text{PromptInstructions}(P) \equiv \text{RuntimeSchema}(P) \equiv \text{Extractor}(P) \equiv \text{Parser}(P) \equiv \text{Validator}(P) \equiv \text{Adapter}(P)$$
Any disagreement detected during pre-flight contract compilation constitutes a fatal engineering defect that blocks execution.

### 3.3 The Fail-Closed Contract Invariant
If a consistent prompt-runtime-parser contract cannot be assembled, or if the mandatory context exceeds the active `budget_tier`:
$$\text{DO NOT CALL THE LLM.}$$
The system must immediately return a deterministic `ContractCompilationError` or `ContextBudgetOverflowError`. Silent section dropping, silent protocol fallback, automatic retries, and post-hoc semantic repairs are strictly prohibited.

### 3.4 The Intervention Ownership Invariant
Each intervention is strictly bounded to its designated architectural layer:
- **$I_1$ (Schema-Constrained Generation)**: Owns the token decoding constraint (`OllamaRunner(schema=...)`).
- **$I_2$ (Epistemic Namespace Segregation)**: Owns namespace partitioning rules (`FACT` vs `CHK`) and post-generation namespace validation.
- **$I_3$ (Counterfactual Invariant Prompting)**: Owns category-aware invariant definitions, evidence-gap focus, and falsification conditions.
- **$I_4$ (Bounded Analytical Intermediate Representation)**: Owns the bounded analytical slot structure and intermediate AST validation.
- **$I_5$ (Calibrated Decision Policy)**: Owns downstream deterministic decision classification rules over canonical S0 hypotheses.
- **$I_6$ (Pure Invariant Handoff)**: Owns upstream 3B $\to$ 7B triage packet serialization (Partition P3) and Class-1 predicate booleans.

### 3.5 The Research Boundary Invariant
Milestone M5 is an **engineering interface reconciliation**. It does not alter the fundamental research question, benchmark scenarios, or baseline datasets. Protocol compliance must never be reported as evidence of superior vulnerability detection or human efficiency gains.

---

## 4. Output-Protocol Option Analysis

To resolve the JSON vs BAIR XML schism, four candidate protocol architectures were rigorously analyzed:

```text
+---------------------------------------------------------------------------------------------------+
|                                M5 PROTOCOL OPTION EVALUATION MATRIX                               |
+--------------------------+-----------------------+-----------------------+------------------------+
| Evaluation Criterion     | OPTION A: XML BAIR    | OPTION B: JSON BAIR   | OPTION C: JSON Wrapper |
+--------------------------+-----------------------+-----------------------+------------------------+
| 1. Composability         | POOR (Clashes with I1)| EXCELLENT (Clean JSON)| FAIR (High complexity) |
| 2. Native Schema Support | IMPOSSIBLE (No XML)   | NATIVE (Ollama JSON)  | NATIVE (Ollama JSON)   |
| 3. Deterministic Parsing | ELEMENTTREE (Fragile) | PYDANTIC / JSON.LOADS | DOUBLE PARSING REQUIRED|
| 4. Namespace Isolation   | TEXT REGEX IN SLOTS   | JSON SCHEMA PATTERNS  | JSON SCHEMA PATTERNS   |
| 5. Grounding Compactness | HIGH (~200 tokens)    | HIGH (~220 tokens)    | MEDIUM (~280 tokens)   |
| 6. I5 Downstream Mapping | DIRECT VIA ADAPTER    | 1:1 DIRECT MAPPING    | REQUIRES ENVELOPE UNPACK|
| 7. I6 Handoff Separation | CLEAN (Input only)    | CLEAN (Input only)    | CLEAN (Input only)     |
| 8. Token Budget Ceiling  | COMPACT (< 300 tok)   | COMPACT (< 300 tok)   | RISK OF TRUNCATION     |
| 9. Latency Gate (<=25s)  | PASS (~13s)           | PASS (~14s)           | PASS (~16s)            |
| 10. Fail-Closed Behavior | STRICT                | STRICT                | STRICT                 |
| 11. Implementation Cost  | MEDIUM                | LOW (Existing models) | HIGH                   |
| 12. Testability          | FAIR                  | EXCELLENT             | FAIR                   |
| 13. Single-Call Contract | YES                   | YES                   | YES                    |
| 14. Research Compatibility| YES                  | YES                   | YES                    |
| 15. 3B -> 7B Cascade     | COMPATIBLE            | FULLY COMPATIBLE      | COMPATIBLE             |
| 16. VAPT RAG Integration | COMPATIBLE            | FULLY COMPATIBLE      | COMPATIBLE             |
+--------------------------+-----------------------+-----------------------+------------------------+
```

### Deep Forensic Analysis of Options:

- **Option A (Preserve XML BAIR)**:
  - *Mechanism*: LLM emits `<bair>...</bair>` XML. Parsed by `parse_bair()`.
  - *Fatal Flaw*: Ollama's native constrained decoding API (`format={...}`) accepts JSON schemas only; it cannot enforce XML context-free grammars. Consequently, Option A forces the model to run under unconstrained sampling (`schema=None`). Small local models (`qwen2.5-coder:7b`) routinely emit markdown JSON blocks or natural language explanations under unconstrained sampling, leading to persistent parser failures unless repaired post-hoc (which is strictly forbidden). Furthermore, Option A makes $I_1$ (schema-constrained decoding) permanently incompatible with $I_4$.
- **Option B (JSON-Native BAIR: `JSON_BAIR`)**:
  - *Mechanism*: Represents the seven conceptual BAIR analytical slots as a deterministic, typed Pydantic JSON schema (`BairJsonObject`).
  - *Advantages*: 
    1. Fully compatible with Ollama native schema constrained decoding ($I_1$), guaranteeing 0% JSON syntax failures and eliminating `PARSER_FAILURE` entirely.
    2. Allows $I_2$ regex namespace constraints (`^FACT-[A-Z0-9_-]+$`, `^CHK-[A-Z0-9_-]+$`) to be embedded directly into JSON schema property definitions.
    3. Seamlessly unifies $I_3$ counterfactual field terminology with intermediate analytical reasoning.
    4. Can operate either constrained (`format=BairJsonObject.model_json_schema()`) or unconstrained (`schema=None`).
- **Option C (JSON Wrapper with XML/Text Payload)**:
  - *Mechanism*: JSON envelope containing a single raw string property `bair_xml`.
  - *Flaw*: Introduces double serialization, increases token overhead by 25–30%, exacerbates truncation risks under the 300-token ceiling, and adds needless parser indirection.
- **Option D (Legacy S0 JSON)**:
  - *Mechanism*: Abandon intermediate analytical slots and revert to single-pass S0 `HypothesisModelOutput`.
  - *Flaw*: Violates the core research hypothesis $H_4$ by eliminating intermediate analytical slot factorization.

---

## 5. Architectural Selection: The M5 Unified Output Protocol

Milestone M5 officially selects **Option B: JSON-Native BAIR (`JSON_BAIR`)** as the primary reasoning interface, supported by an explicit **Output Protocol Contract abstraction** that permits deterministic ablation.

### Formal Selection Rationale:
1. **Mathematical Syntactic Guarantee**: By representing BAIR analytical slots in JSON, the reasoning engine can optionally engage Ollama native schema decoding ($I_1$), proving or disproving whether constrained decoding resolves parser failures without token truncation under fixed compute.
2. **Epistemic Namespace Harmony**: In `JSON_BAIR`, $I_2$ namespace segregation is enforced natively at the schema property level:
   - `empirical_facts`: List of strings matching `^FACT-[A-Z0-9_-]+$`.
   - `methodology_references`: List of strings matching `^CHK-[A-Z0-9_-]+$`.
3. **Falsification Alignment**: The BAIR slot `<falsification>` is represented as `falsification_specification`, aligning 1:1 with $I_3$ counterfactual falsification criteria.
4. **Deterministic S0 Mapping**: Mapping `BairJsonObject` $\to$ `HypothesisModelOutput` is a pure 1:1 field assignment requiring zero heuristic transformation.

---

## 6. Unified Contract Pipeline Architecture

In Milestone M5, every reasoning attempt follows a formal 9-stage lifecycle governed by an immutable `ReasoningExecutionContract`:

```text
[Stage 1: Input Contract]
  - LosslessStructuralPack (Target evidence + metadata)
  - VaptKnowledgePack (Methodology chunks, if Track C/D)
  - ProtectedHandoffDescriptor (I6 Class-1 predicates, if active)
           │
           ▼
[Stage 2: Protocol Selection Contract]
  - Explicit OutputProtocolIdentifier selected: JSON_BAIR (Primary) | BAIR_XML | S0_JSON
           │
           ▼
[Stage 3: Prompt Contract Compilation]
  - BasePolicyMixin + NamespaceMixin(I2) + CounterfactualMixin(I3) + ProtocolMixin(I4)
  - Canonical Evidence (P1) + Protected Handoff (P3) + Advisory VAPT (P4)
           │
           ▼
[Stage 4: Token Budget & Contract Pre-Flight Validation]
  - Total tokens <= budget_tier (Accounted BEFORE inference)
  - Pre-flight Static Assertions: Prompt == Runtime == Parser == Validator
           │
           ▼
[Stage 5: Runtime Execution Contract]
  - OllamaRunner(schema=Protocol.runtime_schema, num_predict=300, 1 call)
           │
           ▼
[Stage 6: Parsing & Extraction Contract]
  - Protocol.parser(raw_response) -> Protocol.intermediate_model
           │
           ▼
[Stage 7: Validation & Adaptation Contract]
  - Protocol.validator(intermediate_model) -> Protocol.adapter() -> Canonical S0
           │
           ▼
[Stage 8: Decision Policy Contract (I5)]
  - deterministic_decide(canonical_s0, evidence_state) -> Final Decision
           │
           ▼
[Stage 9: Grounding & Evaluation Contract]
  - KnowledgeGroundingValidator(canonical_s0) -> AC1 Classification -> EvaluationRecord
```

---

## 7. Modular Prompt Compiler & Mixin Architecture

To eliminate the `if/elif` shadowing defect, [`ReasoningContextBuilder`](src/engine/context_builder.py) is refactored into a **Prompt Contract Compiler** using modular policy mixins:

```python
# M5 Architectural Pattern: Modular Policy Compilation

class PromptContractCompiler:
    """
    Compiles system policy and user prompt sections additively.
    Guarantees that every enabled intervention contributes its full semantics.
    """
    def compile_system_policy(
        self,
        protocol: OutputProtocolContract,
        enable_i2_namespace: bool,
        enable_i3_counterfactual: bool,
        enable_i5_decision_policy: bool,
        category_id: Optional[str] = None,
    ) -> str:
        sections = [
            BASE_SYSTEM_POLICY_SECTION,
        ]
        
        # 1. Output Protocol Specification (Dictated exclusively by protocol contract)
        sections.append(protocol.prompt_formatting_instruction)
        
        # 2. Epistemic Namespace Constraints (I2 Mixin)
        if enable_i2_namespace:
            sections.append(I2_NAMESPACE_POLICY_SECTION)
            
        # 3. Counterfactual Invariant Framework (I3 Mixin)
        if enable_i3_counterfactual:
            tmpl = get_counterfactual_template(category_id)
            sections.append(tmpl.compile_counterfactual_framework())
            
        # 4. Calibrated Decision Policy Rules (I5 Mixin)
        if enable_i5_decision_policy:
            sections.append(I5_DECISION_POLICY_SECTION)
            
        sections.append(BASE_SECURITY_CONSTRAINTS_SECTION)
        return "\n\n".join(sections)
```

### Key Architectural Invariant:
The output format instructions are supplied **exclusively** by the selected `OutputProtocolContract`. Interventions $I_2$, $I_3$, and $I_5$ contribute domain constraints, invariant definitions, and decision thresholds, but are **strictly forbidden** from emitting formatting commands (e.g. `"Output valid JSON"` or `"Emit XML"`).

---

## 8. Canonical Semantic Field Model

To resolve historical naming divergences across modules, M5 defines a formal **Field Normalization Table**:

```text
+-------------------------+----------------------+--------------------------+----------------------------+
| Semantic Concept        | I2 Historical Name   | I4 BAIR Historical Slot  | M5 Canonical JSON_BAIR Key |
+-------------------------+----------------------+--------------------------+----------------------------+
| Evaluated Invariant     | invariant            | <invariant>              | invariant                  |
| Identified Evidence Gap | evidence_gap         | <evidence_gap>           | evidence_gap               |
| Target Asset / Endpoint | affected_target      | <affected_target>        | affected_target            |
| Evaluation Decision     | decision             | <decision>               | decision                   |
| Empirical Target Facts  | empirical_fact_ids   | <facts>                  | empirical_facts            |
| VAPT Guidance Chunks    | methodology_chunk_ids| <methodology>            | methodology_references     |
| Falsification Plan      | experiment_proposal  | <falsification>          | falsification_plan         |
+-------------------------+----------------------+--------------------------+----------------------------+
```

### Deterministic S0 Adapter Mapping:
When `BairJsonObject` is parsed and validated, its fields map 1:1 into canonical `HypothesisModelOutput` (S0):
- `invariant` $\longrightarrow$ `HypothesisModelOutput.invariant`
- `evidence_gap` $\longrightarrow$ `HypothesisModelOutput.evidence_gap`
- `affected_target` $\longrightarrow$ `HypothesisModelOutput.affected_target`
- `decision` $\longrightarrow$ `HypothesisModelOutput.decision`
- `empirical_facts` $\longrightarrow$ `HypothesisModelOutput.supporting_evidence_ids`
- `methodology_references` $\longrightarrow$ `HypothesisModelOutput.methodology_references`
- `falsification_plan` $\longrightarrow$ `HypothesisModelOutput.experiment_proposal`

---

## 9. Token & Context Budget Architecture

M5 establishes a **Two-Tier Pre-Allocation Token Budgeting Algorithm** to eliminate the budget leakage and silent truncation defects identified in Phase 2F:

```text
                     ┌──────────────────────────────────────────┐
                     │          Active Budget Tier             │
                     │          (e.g. 4096 tokens)              │
                     └────────────────────┬─────────────────────┘
                                          │
                                          ▼
     ┌────────────────────────────────────────────────────────────────────────┐
     │ 1. Mandatory Protected Floor (P0 System Policy + P1 Target Envelope)   │
     │    - Base policy + Mixins (I2, I3, I5) + Protocol instructions (I4)    │
     │    - Target envelope, structural diffs, contradictions, canonical facts│
     │    - Counterfactual reasoning category instructions (I3)               │
     │    - Protected 3B Handoff Class-1 booleans (I6)                        │
     └────────────────────────────────────┬───────────────────────────────────┘
                                          │
                        ┌─────────────────┴─────────────────┐
                        │ floor_tokens > budget_tier?       │
                        └─────────────────┬─────────────────┘
                                          │
                       YES ───────────────┴─────────────── NO
                        │                                  │
                        ▼                                  ▼
     ┌────────────────────────────────────┐ ┌─────────────────────────────────┐
     │ FAIL CLOSED:                       │ │ Compute Remaining Headroom:     │
     │ ContextBudgetOverflowError         │ │ remaining = budget - floor      │
     │ (Zero LLM calls, zero silent drops)│ └──────────────┬──────────────────┘
     └────────────────────────────────────┘                │
                                                           ▼
                                            ┌─────────────────────────────────┐
                                            │ 2. Dynamic Advisory Partitions  │
                                            │    - Target Raw Snippets (P4)   │
                                            │    - VAPT Methodology Pack (P4) │
                                            │    (Subject to causal parity    │
                                            │     and fail-soft pruning)      │
                                            └─────────────────────────────────┘
```

### Budget Invariants:
1. **$I_3$ Included in Floor**: The counterfactual reasoning block is classified as mandatory P1 content and is budgeted in `floor_tokens` **before** inference.
2. **$I_6$ Fail-Closed Protection**: If the serialized $I_6$ handoff cannot fit within `budget_tier`, the compiler raises `ContextBudgetOverflowError`. It is strictly forbidden to set `triage_block = ""` and drop verified invariants silently.
3. **Target Snippet Causal Parity**: Raw target evidence snippet truncation remains byte-identical between Track B and Track D.

---

## 10. Parser, Validator & Adapter Architecture

The M5 parser and validator pipeline is implemented as an explicit state machine:

```text
Raw Model Output
       │
       ▼
[Stage 1: Markdown Envelope Stripping]
  - Strips leading/trailing ```json ... ``` or ```xml ... ``` fences cleanly.
       │
       ▼
[Stage 2: Syntactic AST Decoding]
  - Protocol == JSON_BAIR: Standard json.loads() with line/col tracking.
  - Protocol == BAIR_XML: xml.etree.ElementTree with strict root tag validation.
  - On decode failure: Raises ProtocolParseError -> Classified as PARSER_FAILURE.
       │
       ▼
[Stage 3: Decision-Dependent Slot Validation]
  - Validates mandatory fields based on candidate decision (HYPOTHESIS vs INSUFFICIENT_EVIDENCE vs NO_RELEVANT_FUNCTIONALITY).
  - Enforces falsification completeness (supporting observation + disproving observation).
  - Enforces epistemic regex validation on facts and methodology IDs.
  - Rejects CONFIRMED unconditionally.
  - On slot failure: Raises ProtocolSchemaError -> Classified as SCHEMA_VALIDITY_FAILURE.
       │
       ▼
[Stage 4: Deterministic S0 Adaptation]
  - Instantiates canonical HypothesisModelOutput without semantic interpretation.
       │
       ▼
[Stage 5: Downstream Calibration & Grounding]
  - I5 Decision Policy (deterministic_decide)
  - KnowledgeGroundingValidator (epistemic boundary verification)
```

---

## 11. M5 Verification & Test Strategy

Milestone M5 mandates a deterministic test suite that must pass completely before any live LLM execution is authorized:

### 11.1 Composition Integration Suite (`tests/unit/test_m5_composition.py`)
- **Pairwise Invariants**: Test all 15 pairwise intervention combinations ($I_2+I_3$, $I_2+I_4$, $I_2+I_5$, $I_2+I_6$, $I_3+I_4$, $I_3+I_5$, $I_3+I_6$, $I_4+I_5$, $I_4+I_6$, $I_5+I_6$) and assert zero system-policy shadowing.
- **Full Combination Invariant**: Render the complete $\{I_1: 0, I_2: 1, I_3: 1, I_4: 1, I_5: 1, I_6: 1\}$ configuration and verify that:
  - System policy contains protocol formatting instructions, $I_2$ namespace rules, $I_3$ counterfactual framework, and $I_5$ decision thresholds.
  - User prompt contains $I_6$ protected handoff and $I_3$ category falsification requirements.
  - Rendered prompt contains zero contradictory formatting directives.

### 11.2 Static Contract Agreement Assertions
- Assert that for every supported configuration:
  $$\text{RenderedPromptProtocol} \equiv \text{SelectedOutputProtocol} \equiv \text{EvaluatorParser}$$
- Assert that when $I_1=1$, runtime schema matches `BairJsonObject.model_json_schema()`; when $I_1=0$, runtime schema is `None`.

### 11.3 Budget Accounting & Overflow Tests
- **Exact-Fit Budget Test**: Ensure prompts that fit within `budget_tier` compile without truncation.
- **Overflow Fail-Closed Test**: Ensure that an oversized mandatory floor (P0 + P1 + I6) raises `ContextBudgetOverflowError`.
- **I6 Non-Dropping Test**: Ensure $I_6$ handoff is never silently discarded.

### 11.4 Ground-Truth Isolation Test
- Re-execute the 18 evaluation isolation tests (`tests/unit/test_evaluation_isolation.py`) and assert that serialized M5 prompts contain zero forbidden ground-truth tokens.

---

## 12. Live-Execution Authorization Gates

To maintain rigid experimental discipline and prevent wasteful or premature benchmark runs, Milestone M5 enforces a **Four-Stage Authorization Gate**:

```text
[Gate 1: Static Code & Design Freeze]
  - M5 planning document approved and frozen.
  - Zero git diffs on protected M1-M4 files.
  - Working tree clean.
       │
       ▼
[Gate 2: Hermetic Deterministic Test Suite (0 LLM Calls)]
  - All composition integration tests pass (100%).
  - All budget accounting tests pass (100%).
  - All schema/parser unit tests pass (100%).
  - Offline mock runner verifies end-to-end dataflow.
       │
       ▼
[Gate 3: Small-Sample Live Smoke Test (3-5 Scenarios, 12-20 Calls)]
  - Evaluates 3-5 representative benchmark scenarios across 4 tracks.
  - Purpose: Empirically prove that raw model responses are parsed, validated, adapted,
    and reach the scoring layer without syntactic crashing.
  - Verification: At least one scenario completes with valid parsing.
       │
       ▼
[Gate 4: Formal Confirmatory Benchmark Authorization]
  - Dedicated human review of Smoke Test results.
  - Explicit user authorization required before scheduling any large confirmatory run.
```

---

## 13. Research Methodology Boundary

Milestone M5 establishes clear methodological distinctions to preserve scientific rigor:

1. **Engineering Correction vs Scientific Discovery**: Resolving the prompt-parser composition defect is an engineering correction of an implementation flaw, not a novel cognitive or security-reasoning intervention.
2. **Primary Estimand Stability**: The primary automated estimand remains the **Scenario-Level Useful Hypothesis Rate** evaluated under the fixed compute envelope (local `qwen2.5-coder:7b`, `num_predict=300`, 1 call per scenario).
3. **No Retroactive Claims**: Achieving non-zero parse rates in M5 will not be described as "improving" model reasoning over M4.9; it will be accurately documented as enabling the evaluation layer to measure model reasoning for the first time under the combined configuration.
4. **Human Efficiency Separation**: Automated benchmark metrics do not measure human researcher productivity. Any claims regarding human investigation efficiency require an independent condition-masked human review study.

---

## 14. Upstream 3B $\to$ 7B Cascade Compatibility

The M5 interface preserves clean architectural boundaries for future multi-model cascade development:

1. **Triage Decoupling**: The 3B triage model emits upstream classification signals (`Class-1` predicates and `EvidenceGapType`), which $I_6$ serializes into Partition P3 as immutable descriptors.
2. **Zero Semantic Pollution**: Subjective natural-language 3B commentary remains excluded from the 7B reasoning context.
3. **Interface Transparency**: The 7B model reasons over structural target diffs and immutable handoff descriptors; it is agnostic to whether the handoff was generated by automated heuristics or a 3B triage pass.

---

## 15. Open Architectural Design Questions

Before finalizing implementation in Phase 4+, the following design choices must be ratified:

1. **Runtime Schema Deployment ($I_1$)**:
   - *Question*: Under `JSON_BAIR`, should $I_1$ native Ollama schema constrained decoding be activated by default in the combined configuration, or should it remain an independent ablation condition ($I_1=0$ vs $I_1=1$)?
   - *Recommendation*: Preserve $I_1$ as a distinct controlled condition. Evaluate the smoke test under both $I_1=0$ (unconstrained JSON) and $I_1=1$ (constrained JSON) to isolate the causal effect of runtime constrained decoding on token truncation.
2. **Legacy BAIR XML Parser Retention**:
   - *Question*: Should the XML `parse_bair()` parser be retained in the codebase or deprecated?
   - *Recommendation*: Retain `parse_bair()` in `bair_extractor.py` under the explicit protocol flag `OutputProtocolIdentifier.BAIR_XML` for regression testing and historical traceability, while setting `OutputProtocolIdentifier.JSON_BAIR` as the active default for M5.

---

## 16. Explicit Implementation Checklist for Phase 4+

The following sequential tasks are specified for execution in Phase 4 and subsequent phases:

- [ ] **Task 1: Contract Infrastructure**:
  - Implement `OutputProtocolContract` enum and descriptors in [`src/engine/models.py`](src/engine/models.py).
  - Define `BairJsonObject` Pydantic model with strict field definitions and regex patterns.
- [ ] **Task 2: Modular Prompt Compiler**:
  - Refactor [`ReasoningContextBuilder`](src/engine/context_builder.py) to assemble system policy and user prompt using modular mixins.
  - Eliminate the `if/elif` cascade in system policy construction.
  - Relocate $I_3$ counterfactual block into mandatory P1 budgeting.
  - Implement fail-closed `ContextBudgetOverflowError` if $I_6$ handoff cannot fit.
- [ ] **Task 3: Parser and Adapter Reconciliation**:
  - Implement `parse_bair_json()`, `validate_bair_json()`, and `map_bair_json_to_s0()`.
  - Wire protocol-aware parsing into evaluation harnesses.
- [ ] **Task 4: Static Pre-Flight Assertions**:
  - Add static agreement validation in `ReasoningRunner` and benchmark harnesses.
- [ ] **Task 5: Composition Unit Tests**:
  - Implement all 15 pairwise and full-combination tests in `tests/unit/test_m5_composition.py`.
- [ ] **Task 6: Deterministic Smoke Test**:
  - Implement and run the 3–5 scenario live smoke harness under Gate 3.

---

### Non-Negotiable Governance Statement
- **Milestone M4 is CLOSED and FROZEN.**
- **Implementation of the above checklist is STRICTLY PROHIBITED during Phase 3.**
- **Execution of code modifications requires formal completion of Phase 3 and user authorization.**
