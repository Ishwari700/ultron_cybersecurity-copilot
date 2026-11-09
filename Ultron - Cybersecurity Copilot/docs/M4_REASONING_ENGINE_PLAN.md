# Milestone M4: Reasoning Engine Optimization & Epistemic Calibration — Architectural Specification & Implementation Plan

**Document Version:** `1.2.4 — DRAFT / FINAL PRE-FREEZE MICRO-REVISION`  
**Status:** DRAFT / FINAL PRE-FREEZE MICRO-REVISION (STRICT PLANNING ONLY — NO CODE CHANGES)  
**Parent Milestone Planning Freeze:** `m3-v2.3.8-planning-freeze` (`819b83399e24080bf2942c3941cc96728885df49`)  
**Parent Milestone Verified Live Baseline:** Commit `049ffa0` (`docs(m3): validate live ollama rag benchmark`)  
**Target Specification File:** `docs/M4_REASONING_ENGINE_PLAN.md`  
**Eventual Milestone Freeze Tag:** `m4-v1.1.0-planning-freeze` *(Not created yet; pending human review)*  

---

## 1. Executive Summary & Current Project State

Milestone M4 specifies the **Reasoning Engine Optimization and Epistemic Calibration** subsystem for the Local AI-Assisted Bug Bounty Research Platform.

### 1.1 Project Lineage & Verified Milestone History

The platform has established a deterministic, security-bounded foundation across prior milestones:

1. **Milestones M1 / M1.5 (`docs/ROADMAP.md`)**: Froze the authoritative 84-scenario benchmark dataset (`data/benchmarks/m1_5_frozen_manifest.json`, SHA-256: `b2b85a67...`), containing 36 benchmark vulnerable scenarios and 48 negative-control scenarios across OWASP API Security Top 10 categories.
2. **Milestone M2 (Phase 11.6, Commit `f335b98`)**: Established the two-tier reasoning cascade (`qwen2.5-coder:3b` triage $\to$ `qwen2.5-coder:7b` reasoning) with lossless structural diffs (`LosslessStructuralPack`), deterministic routing (`DeterministicRouter`), rigid token budgeting (`ReasoningContextBuilder`), and the core research abstractions:
   $$\text{Application Model} \longrightarrow \text{Security Invariant} \longrightarrow \text{Evidence Gap} \longrightarrow \text{Security Hypothesis} \longrightarrow \text{Experiment Proposal}$$
3. **Milestone M2.75 (Commit `a753ebf`)**: Implemented the deterministic state and live execution boundary (`src/execution/`), enforcing pre-execution TTL validation, session lifecycle tracking, CSRF/nonce freshness, AWS SigV4 request signing, CIDR network scope enforcement, and strict human-in-the-loop approval.
4. **Milestone M3 (Frozen Tag: `m3-v2.3.8-planning-freeze`, Commit `819b8339`, Completed at `049ffa0`)**: Designed, implemented, and validated the **VAPT Knowledge RAG** subsystem:
   - Built dual-store isolation between target empirical evidence (`evidence.db`) and external VAPT methodology (`vapt_knowledge.db`).
   - Selected and deployed production retrieval Candidate 1 (Local ONNX `all-MiniLM-L6-v2` + SQLite FTS5 via Reciprocal Rank Fusion $k=60$ and exact parameter gating).
   - Preserved Target-Evidence retriever `src/retrieval/hybrid.py` with **0 diff lines**.
   - Enforced strict B/D causal parity ($\text{TargetEvidence}(B) \equiv \text{TargetEvidence}(D)$ byte-identical across 84/84 scenarios).
   - Integrated `KnowledgeGroundingValidator` to enforce epistemic boundary segregation.
   - Preserved historical blinded human study ($n=20$ scenarios, 3 raters, 120 evaluations, $\Delta\text{MeanYield} = +0.4888$, $p=0.02119$).
   - Executed full 84-scenario deterministic hermetic rerun (`data/eval/m3_benchmark_rerun_20260920.json`).
   - Executed the full **336-evaluation live local LLM benchmark** (`data/eval/m3_live_llm_benchmark_20260920.json`) against local Ollama `qwen2.5-coder:7b` (`Q4_K_M`, 7.6B parameters).

M3 is fully implemented, verified, and frozen. **Milestone M4 enters planning only; no code or artifacts from M1 through M3 will be modified.**

---

## 2. Empirical M3 Findings That Motivate M4

Milestone M4 is directly grounded in the empirical findings of the completed M3 live LLM validation benchmark (`data/eval/m3_live_llm_benchmark_20260920.json`, wall-clock time 6,913.96s / ~115.2 minutes, local `qwen2.5-coder:7b`, local Ollama v0.34.1 at `http://127.0.0.1:11434`):

```text
+---------------------------------------------------------------------------------------------------+
|                        M3 LIVE 4-TRACK BENCHMARK SUMMARY (n=84, 336 CALLS)                        |
+--------------------------+-------------------+--------------------+---------------+---------------+
| Metric                   | Track A (No RAG)  | Track B (Target Ev)| Track C (VAPT)| Track D (Dual)|
+--------------------------+-------------------+--------------------+---------------+---------------+
| Hypotheses Emitted       | 0                 | 0                  | 0             | 0             |
| Abstentions Emitted      | 79 (94.05%)       | 82 (97.62%)        | 74 (88.10%)   | 75 (89.29%)   |
| Useful Hypothesis Yield  | 0.0000            | 0.0000             | 0.0000        | 0.0000        |
| True Positive Rate (Vuln)| 0.0000 (0/36)     | 0.0000 (0/36)      | 0.0000 (0/36) | 0.0000 (0/36) |
| True Negative Rate (Ctrl)| 0.9167 (44/48)    | 0.9583 (46/48)     | 0.9167 (44/48)| 0.9583 (46/48)|
| False Positives (Ctrl)   | 0                 | 0                  | 0             | 0             |
| False Negatives (Vuln)   | 36                | 36                 | 36            | 36            |
| Grounding Validity Rate  | 1.0000 (84/84)    | 1.0000 (84/84)     | 0.8690 (73/84)| 0.8571 (72/84)|
| Epistemic Violations     | 0                 | 0                  | 11 / 84       | 12 / 84       |
| Causal Parity (B vs D)   | N/A               | 84/84 byte-match   | N/A           | 0 discrepancies|
+--------------------------+-------------------+--------------------+---------------+---------------+
```

### 2.1 The Five Core Empirical Bottlenecks Identified in M3

1. **Extreme Conservative Abstention Prior (Zero Useful Yield)**:
   In zero-shot structured reasoning, `qwen2.5-coder:7b` defaulted to `NO_RELEVANT_FUNCTIONALITY` in ~90%–97% of scenarios. The base model treats passive OpenAPI/HTTP traces as normal platform operations unless explicitly guided to evaluate counterfactual security invariant violations. Consequently, Useful Hypothesis Yield was $0.0000$ in Track B and $0.0000$ in Track D ($\Delta_{B \to D} = 0.0000$).
2. **Epistemic Namespace Confusion (`CHK` vs `FACT`)**:
   In Tracks C and D (where VAPT methodology chunks were supplied in Partition P4), the model cited `CHK-DOC-...` IDs inside `supporting_evidence_ids` in 11 scenarios in Track C and 12 scenarios in Track D:
   - **Dual-RAG Track D Namespace Violation Rate**: $12 / 84 = 14.29\%$ (or ~14.3%).
   - **Combined VAPT-Enabled Namespace Violation Rate**: $(11 + 12) / 168 = 13.69\%$.
   The model conflated generic methodology guidance with empirical traffic evidence. Although `KnowledgeGroundingValidator` successfully caught 100% of these attempts and marked them `INVALID`, the model's unguided prompt structure lacked epistemic field segregation.
3. **Structured-Output Truncation Under Token Ceilings**:
   When the model attempted to generate extensive, verbose natural-language justification in `reasoning_summary`, it hit the configured 300-token `num_predict` ceiling mid-generation. This truncated the closing JSON braces, resulting in schema validation failures (`None` decision) in 11 scenario track evaluations.
4. **Conflation of Internal Analysis and Structured Formatting**:
   The current single-pass inference prompt forces the model to perform security analysis, invariant checking, counterfactual evaluation, and strict JSON serialization simultaneously. Without a scratchpad or intermediate separation, analytical depth directly compromises JSON syntactic integrity.
5. **Passive 3B $\to$ 7B Handoff Noise**:
   The 3B triage model often emits generic categorical assertions (e.g. `API-MULTI-STEP-AUTH-001`) that lack concrete invariant predicate bindings, anchoring 7B reasoning to superficial labels rather than verifiable structural diffs.

---

## 3. Core M4 Research Purpose & Compute Envelopes

### 3.1 Overarching Platform Research Question
Milestone M4 remains strictly tethered to the foundational research question of the project:

> *"Under a fixed evidence and compute budget, does an explicit Application Model $\to$ Security Invariant $\to$ Evidence Gap $\to$ Hypothesis $\to$ Experiment architecture improve security-hypothesis precision, abstention quality, and human investigation efficiency compared to conventional LLM + RAG?"*

### 3.2 Specific M4 Sub-Question
Milestone M4 focuses exclusively on the **Reasoning Engine Layer** (`src/engine/`):

> *"How can the local 7B reasoning engine convert verified target structural evidence and retrieved VAPT knowledge into useful, grounded, correctly structured security hypotheses and experiment proposals under fixed compute and context budgets, without increasing false positives on negative controls?"*

### 3.3 Formal Compute Envelopes (Fixed Budget vs Secondary Diagnostic)

To preserve scientific rigor and prevent silent budget inflation, M4 formally separates evaluation into two compute envelopes:

```text
+---------------------------------------------------------------------------------------------------+
|                                  M4 COMPUTE ENVELOPE SPECIFICATION                                |
+------------------------------+----------------------------------+---------------------------------+
| Parameter                    | PRIMARY FIXED-BUDGET ENVELOPE    | SECONDARY COMPUTE DIAGNOSTIC    |
+------------------------------+----------------------------------+---------------------------------+
| Evaluation Purpose           | Primary M4 execution envelope    | Feasibility / latency bounds    |
| Local Model Identity         | qwen2.5-coder:7b (Q4_K_M, 7.6B)  | qwen2.5-coder:7b (Q4_K_M, 7.6B) |
| Local Server Endpoint        | 127.0.0.1:11434 (Ollama v0.34.1) | 127.0.0.1:11434 (Ollama v0.34.1)|
| Context Budget (num_ctx)     | 2048 tokens                      | 2048 tokens                     |
| Output Budget (num_predict)  | 300 tokens (Frozen M3 baseline)  | 512 tokens (Expanded buffer)    |
| Allowed Calls per Scenario   | Exactly 1 LLM inference call     | Up to 2 calls (Two-Stage)       |
| Mean Latency Budget          | <= 25,000 ms per scenario-track  | <= 45,000 ms per scenario-track |
| Sampling Hyperparameters     | temperature = 0.0, seed = 42     | temperature = 0.0, seed = 42    |
| Network Policy               | Offline execution; explicit      | Offline execution; explicit     |
|                              | egress verification required     | egress verification required    |
+------------------------------+----------------------------------+---------------------------------+
```

> [!IMPORTANT]
> **Strict Fixed-Budget Clarification**: The primary comparison holds the maximum allowed context (`num_ctx = 2048`), maximum output budget (`num_predict = 300`), call count (exactly 1 call), and model/runtime identity fixed. Actual token consumption and latency remain diagnostic quantities and are not silently treated as equal computational effort. Any intervention that requires `num_predict > 300` or more than 1 inference call per scenario belongs exclusively to the **Secondary Compute Diagnostic** and must **NOT** be claimed as an equivalent fixed-budget improvement over the M3 baseline.

### 3.4 Planning-Time Runtime Capability Requirement (Phase M4.0 Gate)
The reasoning runner relies on runtime-level schema-constrained decoding. During pre-flight Phase M4.0:
- The implementation must verify that the pinned local Ollama runtime (`v0.34.1`) supports structured JSON schema decoding (`format: {...}`) natively without requiring external proxies or altering the pinned model digest.
- If the local runtime cannot enforce declared schema constraints, M4 implementation must **STOP and trigger a human review decision point** rather than silently substituting an unpinned runtime or model.

---

## 4. Scope, Boundaries & Non-Goals

### 4.1 In Scope (Reasoning Engine Only)
- Schema-constrained structured generation and fail-closed syntactic parsing.
- Strict prompt-level and schema-level epistemic namespace isolation (`FACT-xxx` vs `CHK-xxx`).
- Evidence-gap-specific reasoning contexts and counterfactual prompt framing.
- Decoupled analytical reasoning via a **Bounded Analytical Intermediate Representation (BAIR)** followed by deterministic extraction.
- Calibrated abstention policies that distinguish between absence of functionality (`NO_RELEVANT_FUNCTIONALITY`), missing data (`INSUFFICIENT_EVIDENCE`), and valid invariant violations (`HYPOTHESIS`).
- Refined, deterministic 3B $\to$ 7B handoff contracts via `HandoffSerializer`.
- Hardware profiling and latency envelope validation.

### 4.2 Strict Non-Goals (Out of Scope)
Milestone M4 must **NOT** become:
- Autonomous vulnerability scanning or crawling.
- Automated exploit generation or payload firing.
- Target discovery, subdomain enumeration, or credential stuffing.
- Secret management or session signing redesign.
- Modification of M2.75 deterministic execution controls (`src/execution/`).
- Redesign of the M3 VAPT corpus, embeddings, or retrieval algorithms (`src/retrieval/`).
- Changing the Target-Evidence retriever `src/retrieval/hybrid.py` (which must remain **0 diff lines**).
- Cloud inference, external API reliance, or cluster deployment.

---

## 5. Formal Hypothesis Semantics & Decision States

To ensure crisp epistemic boundaries and prevent conflating hypothesis generation with vulnerability confirmation, M4 establishes strict semantic definitions:

```text
+---------------------------------------------------------------------------------------------------+
|                                  M4 DECISION STATE SEMANTICS                                      |
+---------------------------+-----------------------------------------------------------------------+
| Decision State            | Formal Grounded Meaning                                               |
+---------------------------+-----------------------------------------------------------------------+
| HYPOTHESIS                | An evidence-supported security-invariant concern with a defined       |
|                           | affected behavior/object/action and a falsifiable experiment proposal.|
+---------------------------+-----------------------------------------------------------------------+
| INSUFFICIENT_EVIDENCE     | A plausible security concern where one or more critical observations  |
|                           | needed to discriminate the hypothesis are missing.                    |
+---------------------------+-----------------------------------------------------------------------+
| NO_RELEVANT_FUNCTIONALITY | Evidence indicates the tested functionality is not relevant to the   |
|                           | security property under examination (e.g. public static metadata).    |
+---------------------------+-----------------------------------------------------------------------+
| CONFIRMED                 | STRICTLY FORBIDDEN in the reasoning engine. Only deterministic live   |
|                           | execution (M2.75) and human approval can confirm a vulnerability.     |
+---------------------------+-----------------------------------------------------------------------+
```

> [!CAUTION]
> **Separation of Formation vs Confirmation**: Reproducible confirmation is strictly outside the reasoning engine and remains exclusively governed by M2.75 deterministic execution and human review. The reasoning engine only emits `HYPOTHESIS` or abstentions.

---

## 6. Frozen Baseline Quarantine

The following artifacts and codebases are **cryptographically and historically frozen**:

```text
+---------------------------------------------------------------------------------------------------+
|                                  FROZEN HISTORICAL ARTIFACT SEAL                                  |
+--------------------------------------------+------------------------------------------------------+
| Artifact Path                              | Role / Status                                        |
+--------------------------------------------+------------------------------------------------------+
| docs/M3_VAPT_KNOWLEDGE_RAG_PLAN.md        | Frozen M3 Plan v2.3.8 (Commit 819b8339)              |
| data/benchmarks/m1_5_frozen_manifest.json  | Frozen 84-scenario benchmark definition              |
| data/eval/m3_benchmark_results.json        | Historical pilot benchmark results                   |
| data/eval/m3_benchmark_rerun_20260920.json  | Fresh hermetic deterministic rerun                   |
| data/eval/retrieval_final_eval_results.json| Frozen 5-candidate retrieval qualification results   |
| data/eval/human_study_summary.json         | Historical blinded human study (20 scenarios)        |
| data/eval/m3_live_llm_benchmark_20260920.json| Authoritative M3 336-evaluation live LLM baseline    |
| docs/M3_LIVE_LLM_VALIDATION_REPORT.md      | M3 live LLM validation milestone report              |
| src/retrieval/hybrid.py                    | Target-Evidence retriever (0 diff lines required)    |
+--------------------------------------------+------------------------------------------------------+
```

M4 experiments will read these artifacts as historical comparison points, but will **never overwrite or mutate them**. All M4 evaluation outputs will reside in dedicated `data/eval/m4_...` files.

---

## 7. M4 Research Hypotheses & Unified Metric Thresholds

Milestone M4 establishes a 1:1 mapping between its six formal research hypotheses (H1–H6) and its six controlled intervention families (I1–I6). To eliminate threshold ambiguity, all target metrics adhere strictly to standardized threshold tiers:
- **Minimum Acceptance Floor**: Strict pass/fail gate for milestone viability.
- **Target Standard**: Expected engineering outcome.
- **Stretch Target**: Optimal upper-bound performance.

```text
+---------------------------------------------------------------------------------------------------+
|                                  UNIFIED METRIC THRESHOLD TIERS                                   |
+-----------------------------------+--------------------+--------------------+---------------------+
| Metric                            | Minimum Acceptance | Target Standard    | Stretch Target      |
+-----------------------------------+--------------------+--------------------+---------------------+
| Track D Useful Hypothesis Rate    | > 0.0000 (Live)    | >= 0.1500 (13/84)  | >= 0.2500 (21/84)   |
| True Negative Rate (Controls)     | >= 0.9000 (44/48)  | >= 0.9583 (46/48)  | 1.0000 (48/48, 0 FP)|
| False Positive Count on Controls  | <= 4 / 48          | <= 2 / 48          | 0 / 48              |
| Track D Raw Namespace Emission    | < 2.0% (<= 1/84)   | < 1.0% (0/84)      | 0.0% (0/84)         |
| Combined VAPT Raw Emission Rate   | < 2.0% (<= 3/168)  | < 1.0% (<= 1/168)  | 0.0% (0/168)        |
| Validator Bypass Rate (Safety)    | 0.0% (0/84)        | 0.0% (0/84)        | 0.0% (0/84)         |
| Track D Grounding Validity Rate   | >= 98.0% (82/84)   | >= 98.8% (83/84)   | 100.0% (84/84)      |
| Structured-Output Truncation Rate | < 1.0% (<= 3/336)  | < 0.5% (<= 1/336)  | 0.0% (0/336)        |
| Target-Evidence Causal Parity     | 100.0% (84/84)     | 100.0% (84/84)     | 100.0% (84/84)      |
+-----------------------------------+--------------------+--------------------+---------------------+
```

### 7.1 Formal 1:1 Hypothesis Mapping (H1–H6 $\longleftrightarrow$ I1–I6)

- **H1 $\longleftrightarrow$ I1 (Schema-Constrained Structured Generation)**:  
  Enforcing runtime JSON schema-constrained decoding directly during token sampling will reduce structured-output schema validity and truncation-related failures from the M3-observed 11/336 truncation-associated structured-output failures ($3.27\%$) to below the Minimum Acceptance Floor ($< 1.0\%$) under the unchanged Primary Fixed-Budget Envelope (`num_predict = 300`, 1 call), without relying on post-hoc semantic repair. Constrained decoding specifically targets syntactic and structural formatting; it does NOT guarantee semantic correctness, epistemic correctness, grounding correctness, useful hypothesis generation, or vulnerability confirmation. Syntactic validity is a necessary engineering precondition for automated evaluation, but does not imply correct security reasoning.
- **H2 $\longleftrightarrow$ I2 (Epistemic Namespace Segregation & Schema Validation)**:  
  Explicit prompt-level namespace partitioning will reduce the model's **Raw Namespace Emission Rate** (invalid `FACT`/`CHK` cross-namespace emissions divided by all generated outputs before validation) from the M3 baseline of $14.29\%$ (12/84) to below the Target Standard ($< 1.0\%$), establishing the primary causal effect of prompt-level namespace segregation on raw model generation behavior. Downstream, post-generation schema validation and `KnowledgeGroundingValidator` rules enforce strict acceptance discipline under baseline unconstrained sampling, ensuring a **Validator Bypass Rate** of $0.0\%$ ($0 / 84$ invalid namespace outputs accepted by the downstream validation/scoring path) and achieving $\ge 98.0\%$ Track D grounding validity, without relying on runtime token-level constrained decoding. Post-generation validation fails closed to protect system safety but does not alter the model's raw generation behavior; validator rejection is not described as evidence of reduced model emission. Raw Namespace Emission Rate, Validator Bypass Rate, and Grounding Failure Rate are defined, tracked, and reported independently.
- **H3 $\longleftrightarrow$ I3 (Evidence-Gap Counterfactual Prompting)**:  
  Providing the 7B reasoning engine with structured counterfactual evaluation instructions (asking *"What specific invariant does this evidence gap allow to be breached?"* rather than *"Is this vulnerable?"*) will activate non-zero useful hypothesis generation on benchmark vulnerable scenarios ($\text{TPR} \ge 35.0\%$, vs $0.0\%$ in M3) while maintaining negative-control safety ($\text{TNR} \ge 90.0\%$).
- **H4 $\longleftrightarrow$ I4 (Bounded Analytical Intermediate Representation)**:  
  Emitting a Bounded Analytical Intermediate Representation (BAIR) with compact pre-allocated analytical slots followed by deterministic extraction within a single 7B call will improve proposal completeness and structurally valid hypothesis formation relative to single-pass structured generation under the Primary Fixed-Budget Envelope (`num_predict = 300`, 1 call), without requiring unrestricted chain-of-thought.
- **H5 $\longleftrightarrow$ I5 (Calibrated Abstention & Decision Policy)**:  
  Explicitly distinguishing `NO_RELEVANT_FUNCTIONALITY` from `INSUFFICIENT_EVIDENCE`, while reserving `HYPOTHESIS` for evidence-supported security-invariant concerns with falsifiable experiments, will reduce incorrect conservative abstention on benchmark vulnerable scenarios without reducing negative-control TNR below the predefined safety floor ($\text{TNR} \ge 90.0\%$).
- **H6 $\longleftrightarrow$ I6 (Deterministic 3B Invariant Handoff)**:  
  Restricting 3B handoff to verified structural invariant deltas (`Class-1` predicates) via a dedicated handoff serializer while suppressing subjective 3B category guesses will reduce 7B anchoring bias and prevent false-positive propagation on negative-control scenarios.

---

## 8. Controlled Intervention Definitions

M4 evaluates six discrete intervention families. To ensure strict causal attribution, each intervention is implemented with clean boundaries and evaluated independently before combination.

```text
+---------------------------------------------------------------------------------------------------+
|                                 M4 INTERVENTION SPECIFICATION                                     |
+----+-----------------------------+------------------------------------+---------------------------+
| ID | Intervention Family         | Implementation Boundary            | Target Failure Mode       |
+----+-----------------------------+------------------------------------+---------------------------+
| I1 | Schema-Constrained Output   | src/engine/models.py               | Truncated JSON / parse    |
|    | Generation & Validation     | src/engine/runner.py               | failure at 300 tokens     |
+----+-----------------------------+------------------------------------+---------------------------+
| I2 | Epistemic Namespace Dual-   | src/engine/context_builder.py      | Model putting CHK IDs into|
|    | Field Schema Constraints    | src/engine/models.py               | supporting_evidence_ids   |
+----+-----------------------------+------------------------------------+---------------------------+
| I3 | Counterfactual Evidence-Gap | src/engine/context_builder.py      | Base model conservative   |
|    | Reasoning Templates         | src/engine/prompts.py              | bias defaulting to NO_REV |
+----+-----------------------------+------------------------------------+---------------------------+
| I4 | Bounded Analytical Inter-   | src/engine/bair_extractor.py       | Analytical shallowing vs  |
|    | mediate Representation(BAIR)| src/engine/runner.py               | syntax breakdown conflict |
+----+-----------------------------+------------------------------------+---------------------------+
| I5 | Calibrated Abstention &     | src/engine/context_builder.py      | Inability to distinguish  |
|    | Decision Thresholding       | src/engine/models.py               | missing data from safe app|
+----+-----------------------------+------------------------------------+---------------------------+
| I6 | Pure Invariant 3B Handoff   | src/engine/handoff_serializer.py   | Subjective 3B text priming|
|    | (Class-1 Predicates Only)   | src/engine/context_builder.py      | 7B false conclusions      |
+----+-----------------------------+------------------------------------+---------------------------+
```

### Detailed Specifications for Each Intervention:

#### Intervention I1: Schema-Constrained Output Generation & Fail-Closed Validation
- **Motivation**: In M3, unconstrained generation caused verbose output cutoffs at 300 tokens, truncating JSON syntax and producing unparseable output in 11 evaluations.
- **Canonical Base Schema ($S_0$)**: Shared infrastructure defining the canonical typed schema for `HypothesisModelOutput` (`invariant`, `evidence_gap`, `affected_target`, `decision`, `supporting_evidence_ids`, `methodology_references`, `reasoning_summary`, `experiment_proposal`) with standard type constraints, but without constrained decoding enforcement, without field-length compaction, and without namespace regex restrictions.
- **Experimental Condition Setup**:
  - **Baseline**: Employs $S_0$ under standard unconstrained sampling; no constrained decoding intervention; no namespace-specific schema regexes.
  - **E1 / I1**: Employs $S_0$ under runtime generic schema-constrained generation; no `FACT` / `CHK` namespace regex constraints; fail-closed parser/validator; zero field-length compaction.
- **Causal Isolation (Option A Clean Boundary)**: $S_0$ is shared infrastructure, while runtime constrained decoding is the I1 intervention mechanism. I1 does **NOT** apply any I1-specific field-length bounds, word-count limits, or schema compaction; it enforces identical $S_0$ type constraints at sampling time.
- **Primary Mechanism**:
  1. Use canonical base schema $S_0$ directly via `HypothesisModelOutput.get_inference_schema()`, preserving identical structural and type constraints shared across all conditions without any I1-specific field-length compaction.
  2. Pass schema $S_0$ to the local inference runtime via native constrained decoding (`format: {...}`).
  3. Parse raw response via strict JSON decoder and fail closed if syntax/schema validation fails.
  4. Flow: $\text{Schema } S_0 \longrightarrow \text{Constrained Generation} \longrightarrow \text{Strict Parser} \longrightarrow \text{Semantic / Grounding Validation}$.
- **Diagnostic/Fallback Boundary**: Post-hoc repair is retained **strictly as a non-authoritative diagnostic logger** (`DIAGNOSTIC_ONLY`). It must **never** fabricate semantic content or upgrade an incomplete output to a valid hypothesis.
- **Structured-Output Failure Taxonomy**:
  To prevent confounding syntactic formatting with epistemic or semantic reasoning, M4 explicitly distinguishes five structured-output failure modes:
  1. **Schema Validity Failure**: Output is syntactically valid JSON, but violates typed schema definitions (e.g. missing required properties, invalid field types, or unlisted enum values).
  2. **Parser Failure**: Output contains invalid or malformed JSON syntax (e.g. unbalanced braces, illegal escapes, unquoted keys) that cannot be parsed by standard JSON parsers.
  3. **Runtime / Transport Failure**: Inference execution or networking interruption (e.g. HTTP disconnect, daemon timeout, process crash, OOM).
  4. **Max-Token Termination / Truncation Event**: Generation is halted prematurely upon reaching the `num_predict = 300` token ceiling, truncating strings or delimiters before completion.
  5. **Semantic Grounding Failure**: Output is syntactically valid and schema-conformant, but cites non-existent/fabricated entity IDs, violates namespace boundaries, or asserts unsupported security claims rejected by `KnowledgeGroundingValidator`.
- **Syntactic vs Semantic Scope**: Constrained decoding is an engineering intervention intended to reduce parser failures, schema validity failures, and max-token truncation events caused by unconstrained verbosity. It does **NOT** guarantee:
  - semantic correctness
  - epistemic correctness
  - grounding correctness
  - useful hypothesis generation
  - vulnerability confirmation  
  Syntactic validity is a necessary engineering precondition for automated evaluation, but does not imply correct security reasoning.
- **Expected Effect**: Truncation and schema/syntax errors drop below $< 1.0\%$ (measured empirically; no 100% guarantee claimed).
- **Failure Mode**: Runtime constrained-decoding overhead or rejection if schema is too complex.
- **Metrics**: Truncation rate, schema validity failure rate, parser failure rate, transport failure rate, decoding latency delta.

#### Intervention I2: Epistemic Namespace Dual-Field Protocol with Schema Validation
- **Motivation**: In M3, the model placed `CHK` IDs in `supporting_evidence_ids` in 14.29% of Track D runs due to conflating methodology chunks with empirical traffic.
- **Experimental Condition Setup (E2 / I2)**:
  - Employs canonical base schema $S_0$ augmented with namespace-specific field definitions and post-generation schema validation constraints.
  - Baseline structured output (unconstrained sampling; does **NOT** inherit I1-specific schema compaction, does **NOT** use runtime token-level constrained decoding, and does **NOT** inherit any other I1-specific mechanisms).
  - Evaluates namespace validator rules (`KnowledgeGroundingValidator`) and post-generation schema validation.
- **Causal Isolation**: $S_0$ is shared infrastructure, while prompt-level namespace-field segregation, namespace-specific schema validation constraints, and validator checks constitute the I2 intervention mechanism. E2/I2 does not use runtime token-level constrained decoding; I2 does not prevent wrong namespace emissions during token sampling, but detects and enforces namespace compliance post-generation. Pure single-factor ablation is preserved; I1 and I2 are never silently combined.
- **Explicit Separation of Metric Quantities**:
  To ensure rigorous causal accounting, I2 explicitly separates:
  1. **Raw Namespace Emission Rate**: Number of generated outputs containing a cross-namespace citation before validation / all generated outputs. This represents the primary causal behavior metric for I2.
  2. **Validator Bypass Rate**: Number of invalid namespace outputs accepted by the downstream validation/scoring path / all generated outputs. This is a hard safety and integrity metric (must be 0 for accepted outputs to be considered safe).
  3. **Grounding Failure Rate**: Number of outputs rejected by `KnowledgeGroundingValidator` for namespace or grounding reasons / all generated outputs. Separately reported.
  *Causal distinction*: Prompt namespace segregation directly influences raw model generation behavior; post-generation validation enforces acceptance discipline by failing closed. Post-generation validation does not change raw generation behavior; validator rejection is not described as evidence of reduced model emission. Both raw emission rates and post-validation acceptance/bypass metrics must be reported.
- **Deterministic I2 Output-Schema Adapter Contract**:
  Raw I2 emissions employ segregated fields (`empirical_fact_ids` and `methodology_chunk_ids`). To preserve identical evaluation interfaces across conditions, I2 specifies a deterministic adapter mapping raw fields into canonical `HypothesisModelOutput`:
  $$\text{empirical\_fact\_ids} \longrightarrow \text{supporting\_evidence\_ids}$$
  $$\text{methodology\_chunk\_ids} \longrightarrow \text{methodology\_references}$$
  The adapter strictly:
  - Performs **zero semantic inference** or field interpretation.
  - Performs **zero citation substitution** or hallucinated expansion.
  - Preserves exact entity IDs as emitted by the model.
  - Rejects invalid namespaces (fails closed if `empirical_fact_ids` contains `CHK-` or `methodology_chunk_ids` contains `FACT-`).
  - Emits the canonical `HypothesisModelOutput` representation, maintaining a strictly uniform downstream scoring contract across all experimental arms.
- **Primary Mechanism**:
  1. Partition context prompt clearly into discrete partitions: `<empirical_target_evidence>` (P1) vs `<security_testing_methodology>` (P4).
  2. Embed namespace-specific regex constraints into model schema validation rules:
     - `empirical_fact_ids`: Array of strings matching `^FACT-[A-Z0-9_-]+$`
     - `methodology_chunk_ids`: Array of strings matching `^CHK-[A-Z0-9_-]+$`
  3. Validate emitted output post-generation under baseline unconstrained sampling: verify that cross-namespace citations are caught and rejected by schema validation and epistemic checks.
  4. Authoritative check remains `KnowledgeGroundingValidator`: Any namespace mismatch is an immediate hard grounding failure (`INVALID_NAMESPACE_BREACH`).
- **Expected Effect**: Measurable reduction in Raw Namespace Emission Rate to $< 1.0\%$; Validator Bypass Rate remains $0.0\%$.
- **Metrics**: Raw Namespace Emission Rate, Validator Bypass Rate, Grounding Failure Rate, Combined VAPT Raw Emission Rate.

#### Intervention I3: Counterfactual Evidence-Gap Reasoning Templates
- **Motivation**: Base model exhibited 97.6% abstention because it lacked a framework to evaluate whether missing controls constitute a vulnerability.
- **Mechanism**:
  - Replace passive instruction (*"Analyze this endpoint"*) with active counterfactual framing:
    1. *Invariant Check*: What invariant does the target enforce?
    2. *Gap Check*: What observed fact indicates a gap in this invariant?
    3. *Falsification Condition*: What concrete observation would disprove this hypothesis?
- **Expected Effect**: Meaningful hypothesis generation on benchmark vulnerable scenarios ($\text{TPR} \ge 35\%$).
- **Failure Mode**: Risk of inducing false positives on negative controls if prompt is overly aggressive.
- **Metrics**: TPR on vulnerable scenarios, TNR on controls, False Positive count.

#### Intervention I4: Bounded Analytical Intermediate Representation (BAIR) + Deterministic Extraction
- **Motivation**: Forcing analytical reasoning and JSON formatting simultaneously within 300 tokens causes token budget conflicts. Unrestricted chain-of-thought is impossible within 300 tokens.
- **Primary Mechanism (BAIR — Primary Fixed-Budget Envelope)**:
  - Single 7B inference call with `num_predict = 300` and `num_ctx = 2048`.
  - The model emits a **Bounded Analytical Intermediate Representation (BAIR)** with exactly seven compact, pre-allocated slots (zero eighth slot permitted):
    ```xml
    <bair>
      <invariant>ID or brief statement</invariant>
      <evidence_gap>GAP-xxx or brief gap</evidence_gap>
      <affected_target>behavior/object/action</affected_target>
      <decision>HYPOTHESIS | INSUFFICIENT_EVIDENCE | NO_RELEVANT_FUNCTIONALITY</decision>
      <facts>FACT-xxx, FACT-yyy</facts>
      <methodology>CHK-xxx</methodology>
      <falsification>observation supporting hypothesis AND observation disproving/falsifying hypothesis</falsification>
    </bair>
    ```
  - **Slot Definition for `<falsification>`**:
    Defined strictly as a bounded complete experiment specification containing:
    1. The concrete observation supporting the hypothesis.
    2. The concrete observation disproving/falsifying the hypothesis.
  - **Deterministic BAIR $\longrightarrow$ HypothesisModelOutput Field Mapping Rules**:
    The deterministic Python Stage 2 extractor maps BAIR XML slots directly into typed `HypothesisModelOutput` fields:
    - `<invariant>` $\longrightarrow$ `HypothesisModelOutput.invariant`
    - `<evidence_gap>` $\longrightarrow$ `HypothesisModelOutput.evidence_gap`
    - `<affected_target>` $\longrightarrow$ `HypothesisModelOutput.affected_target`
    - `<decision>` $\longrightarrow$ `HypothesisModelOutput.decision`
    - `<facts>` $\longrightarrow$ `HypothesisModelOutput.supporting_evidence_ids` (split by comma/whitespace into array)
    - `<methodology>` $\longrightarrow$ `HypothesisModelOutput.methodology_references` (split by comma/whitespace into array)
    - `<falsification>` $\longrightarrow$ `HypothesisModelOutput.experiment_proposal`: The extractor must copy the raw string content of `<falsification>` directly into `HypothesisModelOutput.experiment_proposal`. No semantic inference, reconstruction, expansion, or fabricated content is allowed. For `decision == HYPOTHESIS`, this mapping is mandatory and the extractor **MUST fail closed** if `<falsification>` is absent, empty, or incomplete.
  - **Decision-Dependent BAIR Slot Validation Contract**:
    The BAIR slot set is strictly validated according to the emitted `decision` state:
    - **When `decision == HYPOTHESIS`**:
      - `invariant`: **REQUIRED** (non-empty string specifying the violated security invariant).
      - `evidence_gap`: **REQUIRED** (non-empty string specifying the observed gap).
      - `affected_target`: **REQUIRED** (non-empty string specifying the affected behavior/object/action).
      - `decision`: **REQUIRED** (`HYPOTHESIS`).
      - `facts`: **REQUIRED** (non-empty list of valid `FACT-` IDs cited from empirical target evidence).
      - `falsification`: **REQUIRED** (bounded complete experiment specification detailing supporting observation and falsifying observation; mapped directly to `experiment_proposal`).
      - `methodology`: **OPTIONAL** unless required by the existing grounding contract (e.g. Tracks C and D where VAPT methodology was retrieved).
    - **When `decision == INSUFFICIENT_EVIDENCE`**:
      - `invariant`: **REQUIRED** (non-empty string specifying the invariant under examination).
      - `evidence_gap`: **REQUIRED** (non-empty string identifying the missing observation or gap).
      - `affected_target`: **REQUIRED** (non-empty string specifying the examined target component).
      - `decision`: **REQUIRED** (`INSUFFICIENT_EVIDENCE`).
      - `falsification`: **REQUIRED** (non-empty string specifying what observation would resolve/falsify the question).
      - `facts`: **REQUIRED** where empirical evidence exists (empty list allowed only if zero target traffic exists for the endpoint).
      - `methodology`: **OPTIONAL** unless required by grounding.
    - **When `decision == NO_RELEVANT_FUNCTIONALITY`**:
      - `invariant`: **REQUIRED** where applicable (statement of baseline invariant evaluated).
      - `affected_target`: **REQUIRED** (non-empty string specifying the benign or unimpacted functionality).
      - `decision`: **REQUIRED** (`NO_RELEVANT_FUNCTIONALITY`).
      - `evidence_gap`: **OPTIONAL** (may be empty or omitted as no relevant security gap exists).
      - `falsification`: **OPTIONAL** (may be empty or omitted).
      - `facts` / `methodology`: **No fabricated facts or methodology allowed** (zero phantom or placeholder citations permitted).
  - **Strict Fail-Closed Extraction Rules**:
    1. Section 5 semantic definitions remain unchanged.
    2. The extractor must **NEVER** infer or impute missing slots.
    3. Optional slots must **NEVER** become fabricated placeholders (e.g. `"N/A"`, `"None"`, or synthetic tokens).
    4. If `<bair>...</bair>` tags are missing, malformed, duplicated ambiguously, or if any mandatory slot for the declared decision state is missing or semantically incomplete, the extractor **MUST fail closed** emitting `INVALID_TRUNCATED_OUTPUT`. Zero semantic reconstruction or hallucinated facts permitted.
- **Secondary Diagnostic (Sub-Option B — Dual-LLM Pipeline)**:
  - Stage 1 = Unconstrained reasoning pass; Stage 2 = Second local LLM extraction call. Strictly classified under Secondary Compute Diagnostic due to doubling LLM inference cost.
- **Expected Effect**: Analytical depth within fixed 300-token envelope without JSON syntax breakdowns.
- **Metrics**: Mean latency, proposal completeness, parse validity rate, slot validation pass rate.

#### Intervention I5: Calibrated Abstention & Deterministic Decision Policy
- **Motivation**: In M3, the model defaulted to extreme conservative abstention without distinguishing between safe functionality and untested security gaps.
- **Frozen Deterministic Decision-Policy Contract**:
  Decision states in prompt policy (P0) and validation engines adhere strictly to the following deterministic predicate conditions:
  - **`HYPOTHESIS`**:
    - All mandatory invariant, evidence gap, affected target, and falsification conditions are fully satisfied.
    - The experiment proposal is directly grounded in observed empirical evidence.
  - **`INSUFFICIENT_EVIDENCE`**:
    - The examined functionality is relevant to the security property under inspection.
    - One or more pre-declared discriminating observations needed to confirm or falsify the invariant violation are absent from the evidence.
  - **`NO_RELEVANT_FUNCTIONALITY`**:
    - Empirical evidence indicates the tested functionality is entirely outside the examined security property (e.g. public static assets, unauthenticated informational endpoints with no state mutation).
- **Deterministic Governance Invariants**:
  - **No Hidden Thresholds**: Zero hidden probability, logit, or confidence thresholds.
  - **No Post-Hoc Tuning**: Zero post-hoc threshold shifting or heuristic re-weighting.
  - **Immutable Decision Boundary**: Zero decision adjustments based on post-screening or confirmatory benchmark outcomes.
  - **No Semantic Extrapolation**: Zero semantic inference outside the declared decision contract.
  - **No Learned Classifier**: No learned secondary classifier or probabilistic calibration module is introduced.
  - **Strict Confirmation Boundary**: Reproducible confirmation remains strictly outside the reasoning engine and is governed exclusively by M2.75 deterministic execution and human review.
- **Expected Effect**: High abstention on controls, appropriate triage on ambiguous scenarios ($\text{TNR} \ge 90.0\%$).
- **Metrics**: Decision-state distribution, True Positive Rate (TPR) on vulnerable scenarios, True Negative Rate (TNR) on negative controls, false-positive count, false-negative count, Scenario-Level Useful Hypothesis Rate.
- **Human Study Boundary**: Reviewer time savings is NOT measured in M4 and requires a separate condition-masked human study.

#### Intervention I6: Pure Invariant 3B Handoff (Protected Routing Architecture)
- **Motivation**: 3B free-text triage occasionally misled 7B reasoning.
- **Architectural Protection**:
  - `StructuralDiffEngine` predicate authority remains untouched.
  - `EvidencePreservationGate` semantics remain untouched.
  - `DeterministicRouter` semantics remain untouched.
  - Scope and execution controls remain untouched.
- **Mechanism**:
  $$\text{Structural Diff} \longrightarrow \text{Gate} \longrightarrow \text{Deterministic Router} \longrightarrow \text{verified decision} \longrightarrow \mathbf{HandoffSerializer} \longrightarrow \text{7B Context Builder}$$
  - The new `HandoffSerializer` suppresses natural-language 3B notes and serializes strictly verified Class-1 predicate booleans and the exact `EvidenceGapType` into Partition P3.
- **Expected Effect**: Cleaner 7B context, lower token consumption, zero label priming.
- **Metrics**: Scenario-Level Useful Hypothesis Rate, True Positive Rate (TPR) on vulnerable scenarios, True Negative Rate (TNR) on negative controls, False-positive count, P3 prompt-token consumption.
- **Measurement Boundary**: No separate undefined "accuracy" score is introduced; performance is quantified strictly through the defined metrics above.

---

## 9. Reasoning Engine Architecture (Dual Execution Paths)

```text
PATH A: I1 SCHEMA-CONSTRAINED PATH (Single-Pass Direct JSON)
       ┌──────────────────────────────────────────────────────────┐
       │            M4 ReasoningContextBuilder (Partitioned)      │
       └─────────────────────────────┬────────────────────────────┘
                                     │
                                     ▼
       ┌──────────────────────────────────────────────────────────┐
       │               Local Ollama qwen2.5-coder:7b              │
       │        (Runtime-enforced JSON schema constrained decoding)│
       └─────────────────────────────┬────────────────────────────┘
                                     │
                                     ▼
       ┌──────────────────────────────────────────────────────────┐
       │              Typed HypothesisModelOutput                 │
       │              (Fail-closed parser validation)             │
       └─────────────────────────────┬────────────────────────────┘
                                     │
                                     ▼
       ┌──────────────────────────────────────────────────────────┐
       │            KnowledgeGroundingValidator                   │
       │       (Authoritative semantic / provenance check)        │
       └─────────────────────────────┬────────────────────────────┘
                                     │
                                     ▼
       ┌──────────────────────────────────────────────────────────┐
       │          M2.75 Scorer & Deterministic State Engine       │
       └──────────────────────────────────────────────────────────┘

PATH B: I4 BAIR PATH (Bounded Intermediate Analytical Representation)
       ┌──────────────────────────────────────────────────────────┐
       │            M4 ReasoningContextBuilder (Partitioned)      │
       └─────────────────────────────┬────────────────────────────┘
                                     │
                                     ▼
       ┌──────────────────────────────────────────────────────────┐
       │               Local Ollama qwen2.5-coder:7b              │
       │             (Bounded analytical generation)              │
       └─────────────────────────────┬────────────────────────────┘
                                     │
                                     ▼
       ┌──────────────────────────────────────────────────────────┐
       │      Bounded Analytical Intermediate Representation      │
       │     (<bair> invariant, gap, affected, falsification </bair>)
       └─────────────────────────────┬────────────────────────────┘
                                     │
                                     ▼
       ┌──────────────────────────────────────────────────────────┐
       │             Deterministic BAIR Extractor                 │
       │        (Python AST / regex parser; fail-closed)          │
       └─────────────────────────────┬────────────────────────────┘
                                     │
                                     ▼
       ┌──────────────────────────────────────────────────────────┐
       │              Typed HypothesisModelOutput                 │
       └─────────────────────────────┬────────────────────────────┘
                                     │
                                     ▼
       ┌──────────────────────────────────────────────────────────┐
       │            KnowledgeGroundingValidator                   │
       └─────────────────────────────┬────────────────────────────┘
                                     │
                                     ▼
       ┌──────────────────────────────────────────────────────────┐
       │          M2.75 Scorer & Deterministic State Engine       │
       └──────────────────────────────────────────────────────────┘
```

---

## 10. Causal Experiment Design & Pure Single-Factor Ablation Matrix

To guarantee strict scientific attribution, M4 evaluates each intervention **strictly in isolation** against the frozen M3 live baseline before evaluating a synthesized composite configuration:

```text
+---------------------------------------------------------------------------------------------------+
|                              M4 PURE SINGLE-FACTOR ABLATION MATRIX                                |
+-----------+--------------+--------------+--------------+--------------+--------------+------------+
| Condition | I1: Schema-  | I2: Dual-    | I3: Counter- | I4: BAIR     | I5: Calibr.  | I6: Pure   |
|           | Constrained  | Field Regex  | factual Prom.| Decomposition| Abstention   | Invariant  |
+-----------+--------------+--------------+--------------+--------------+--------------+------------+
| Baseline  | — (OFF)      | — (OFF)      | — (OFF)      | — (OFF)      | — (OFF)      | — (OFF)    |
| EXP-M4-1  | ✓ (ONLY)     | — (OFF)      | — (OFF)      | — (OFF)      | — (OFF)      | — (OFF)    |
| EXP-M4-2  | — (OFF)      | ✓ (ONLY)     | — (OFF)      | — (OFF)      | — (OFF)      | — (OFF)    |
| EXP-M4-3  | — (OFF)      | — (OFF)      | ✓ (ONLY)     | — (OFF)      | — (OFF)      | — (OFF)    |
| EXP-M4-4  | — (OFF)      | — (OFF)      | — (OFF)      | ✓ (ONLY)     | — (OFF)      | — (OFF)    |
| EXP-M4-5  | — (OFF)      | — (OFF)      | — (OFF)      | — (OFF)      | ✓ (ONLY)     | — (OFF)    |
| EXP-M4-6  | — (OFF)      | — (OFF)      | — (OFF)      | — (OFF)      | — (OFF)      | ✓ (ONLY)   |
+-----------+--------------+--------------+--------------+--------------+--------------+------------+
| COMBINED  | Evaluated ONLY after screening via Phase M4.8b Configuration Freeze Protocol.         |
| (Composite| [Selected based strictly on pre-declared gates; NOT a single-factor condition].      |
+-----------+---------------------------------------------------------------------------------------+
```

### 10.1 Canonical Base Schema ($S_0$) & Shared Infrastructure vs Intervention-Specific Mechanisms

To prevent confounding across experimental conditions and maintain strict causal isolation:

- **Canonical Base Schema ($S_0$)**: Shared infrastructure defining the canonical typed JSON schema for `HypothesisModelOutput` (`invariant`, `evidence_gap`, `affected_target`, `decision`, `supporting_evidence_ids`, `methodology_references`, `reasoning_summary`, `experiment_proposal`) with standard type constraints, but without constrained decoding enforcement, without field-length compaction, and without namespace regex restrictions.
- **Shared Infrastructure**: The underlying Pydantic model definitions, canonical base schema $S_0$, context builder partition framework (P0–P4), deterministic router, and benchmark runner scaffolding constitute shared infrastructure across all conditions.

**Experimental Conditions & Causal Isolation Definition**:
- **Baseline**:
  - Employs canonical base schema $S_0$.
  - No constrained decoding intervention (standard unconstrained token sampling).
  - No namespace-specific schema regexes.
- **E1 / I1 (`EXP-M4-1`)**:
  - Employs canonical base schema $S_0$.
  - Generic schema-constrained generation enforced natively at token sampling time.
  - No `FACT` / `CHK` namespace regex constraints.
  - Fail-closed parser/validator.
  - Zero I1-specific field-length compaction (Option A clean single-factor isolation).
- **E2 / I2 (`EXP-M4-2`)**:
  - Employs canonical base schema $S_0$.
  - Namespace-specific `FACT` / `CHK` schema validation constraints (`^FACT-[A-Z0-9_-]+$`, `^CHK-[A-Z0-9_-]+$`).
  - Evaluates deterministic adapter (`empirical_fact_ids` $\to$ `supporting_evidence_ids`, `methodology_chunk_ids` $\to$ `methodology_references`) to output canonical $S_0$.
  - Namespace validator rules (`KnowledgeGroundingValidator`) and post-generation validation.
  - Baseline structured output (unconstrained sampling); does **NOT** inherit I1-specific schema compaction, does **NOT** use runtime token-level constrained decoding, and does **NOT** inherit any other I1-specific mechanisms.
- **E3 / I3 (`EXP-M4-3`)**:
  - Employs $S_0$ under baseline decoding with counterfactual evidence-gap reasoning prompt templates.
- **E4 / I4 (`EXP-M4-4`)**:
  - Employs BAIR compact slot generation and deterministic Stage 2 Python extraction without runtime JSON schema decoding during inference.
- **E5 / I5 (`EXP-M4-5`)**:
  - Employs $S_0$ under baseline decoding with calibrated abstention policy prompts and thresholds.
- **E6 / I6 (`EXP-M4-6`)**:
  - Employs pure structural invariant 3B handoff serializer (`HandoffSerializer`) formatting Partition P3; downstream-only.

> [!IMPORTANT]
> **Strict Causal Attribution**: Canonical base schema $S_0$ is shared infrastructure, while:
> - **Constrained decoding** is the I1 intervention mechanism.
> - **FACT/CHK namespace segregation & validation constraints** are the I2 intervention mechanism.
>
> The pure single-factor ablation matrix is strictly preserved; I1 and I2 are evaluated independently and are never silently combined in single-factor conditions.

### 10.2 Pre-Declared Intervention Compatibility Matrix

```text
+---------------------------------------------------------------------------------------------------+
|                            PRE-DECLARED INTERVENTION COMPATIBILITY MATRIX                         |
+----+-----------------------------+-----+-----+-----+-----+-----+-----+----------------------------+
| ID | Intervention                | I1  | I2  | I3  | I4  | I5  | I6  | Architectural Notes        |
+----+-----------------------------+-----+-----+-----+-----+-----+-----+----------------------------+
| I1 | Schema-Constrained Output   |  —  | COM | COM | ADT | COM | COM | ADT: If I4 active, I4 AST  |
| I2 | Dual-Field Namespace Regex  | COM |  —  | COM | COM | COM | COM | Fully orthogonal fields    |
| I3 | Counterfactual Templates    | COM | COM |  —  | COM | COM | COM | Modifies P0/P1 templates   |
| I4 | BAIR Intermediate Extract.  | ADT | COM | COM |  —  | COM | COM | ADT: Extractor maps to I1  |
| I5 | Calibrated Abstention       | COM | COM | COM | COM |  —  | COM | Modifies decision policy   |
| I6 | Pure Invariant Handoff      | COM | COM | COM | COM | COM |  —  | Modifies P3 serializer only|
+----+-----------------------------+-----+-----+-----+-----+-----+-----+----------------------------+
| Legend: COM = Fully Compatible.                                                                   |
|         ADT = Compatible with Pre-Declared Adaptation (Stage 2 extractor targets I1 schema).      |
|         INC = Strictly Incompatible (mutually exclusive; cannot enter COMBINED together).         |
+---------------------------------------------------------------------------------------------------+
```

---

## 11. Final Configuration Freeze & Selection Protocol (Phase M4.8b)

Between exploratory screening (Phase M4.8) and confirmatory validation (Phase M4.9), M4 executes a formal, deterministic **Configuration Freeze**:

```text
                        Phase M4.8: Screening (E1 through E6)
                                         │
                                         ▼
            ┌─────────────────────────────────────────────────────────┐
            │        Phase M4.8b: Final Configuration Freeze          │
            │  1. Gate 1: Safety Floor (TNR >= 90.0%, FP <= 4)        │
            │  2. Gate 2: Compute Envelope (num_predict=300, <=25s)   │
            │  3. Gate 3: Syntax Validity (Truncation < 1.0%)         │
            │  4. Gate 4: Namespace Validity (Violation < 2.0%)       │
            │  5. Rank surviving interventions by Delta Useful Yield  │
            │  6. Execute deterministic greedy combination algorithm  │
            │  7. Serialize data/eval/m4_frozen_config_manifest.json  │
            │  8. HARD LOCK: Zero tuning allowed after freeze         │
            └────────────────────────────┬────────────────────────────┘
                                         │
                                         ▼
                 Phase M4.9: Confirmatory 84-Scenario Benchmark
```

### 11.1 Methodological Interpretation of Greedy Selection
> [!IMPORTANT]
> The greedy combination algorithm is an **engineering screening and configuration-assembly rule**, NOT a statistical proof of interaction superiority or global optimality. It assembles the best-performing compatible interventions identified on the exploratory development partition. Confirmatory evidence is estimated strictly downstream in Phase M4.9 on the untouched 84-scenario benchmark.

### 11.2 Deterministic Selection & Tie-Breaking Rules
A candidate intervention is eligible for inclusion in `COMBINED` if and only if:
1. It passes all hard safety floors ($\text{TNR} \ge 90.0\%$, $\text{FP} \le 4$).
2. It fits the Primary Fixed-Budget Compute Envelope (`num_predict = 300`, single call, latency $\le 25$s).
3. It exhibits non-negative exploratory $\Delta\text{UsefulHypothesisRate} \ge 0.0000$ relative to baseline on the development partition.
4. Its compatibility with every already-selected intervention is marked `COM` or `ADT` in the pre-declared compatibility matrix.

**Deterministic Ordering for Inclusion**:
Surviving eligible interventions are ordered by:
1. Higher exploratory $\Delta\text{UsefulHypothesisRate}$, then
2. Lower mean latency (ms), then
3. Lower prompt-token consumption, then
4. Smaller code-diff footprint, then
5. Deterministic intervention ID ($I1 < I2 < I3 < I4 < I5 < I6$).

Starting from an empty set, candidates are iteratively evaluated in this exact order. If an intervention is compatible with all currently selected members, it is added. If no intervention is eligible, $\text{COMBINED} \equiv \text{BASELINE}$. The resulting configuration is committed to `data/eval/m4_frozen_config_manifest.json` with a SHA-256 checksum. **Zero tuning or code changes are permitted after freeze.**

---

## 12. Development Partition vs Confirmatory Evaluation

To protect against p-hacking and ungrounded claims of generalizability:

### 12.1 Exploratory Screening Partition Contract (Phase M4.8)
- **Total Scenarios**: Exactly 20 scenarios.
- **Composition**: 10 benchmark vulnerable scenarios and 10 negative-control scenarios.
- **Stratification**: Exactly 2 scenarios (1 vulnerable variant, 1 negative control) per OWASP API category.
- **Deterministic Selection Rule**: Scenarios are selected by lexicographically sorting scenario IDs within each category and selecting the first available vulnerable scenario and first available control scenario.
- **Freezing Contract**: The 20 scenario IDs are serialized into `data/eval/m4_dev_partition_manifest.json` with SHA-256 hash prior to executing E1–E6.
- **Immutable Rule**: Zero replacement, resampling, or scenario substitution after observing screening results.

### 12.2 Confirmatory Validation Partition Contract (Phase M4.9)
- The frozen configuration selected in Phase M4.8b is evaluated across the full **84 frozen benchmark scenarios** (336 evaluations).
- These results represent confirmatory validation **on the frozen benchmark**, and will be explicitly reported as measuring performance on the defined benchmark set rather than unconstrained real-world generalization.

### 12.3 Small-Sample Exploratory Selection Limitation
> [!WARNING]
> The 20-scenario screening partition is a deliberately compact exploratory development set ($n=20$ represents ~23.8% of the frozen benchmark). A single scenario transition represents a $5.0\%$ shift in point estimates, giving individual scenarios high leverage. Screening results are used solely to lock a candidate configuration; confirmatory performance is estimated exclusively after configuration lock on the untouched 84-scenario benchmark. The final report will explicitly document selection uncertainty.

---

## 13. Metric Hierarchy & Acceptance Criteria

```text
+---------------------------------------------------------------------------------------------------+
|                                     M4 METRIC HIERARCHY                                           |
+--------------------------+---------------------------------------------------+--------------------+
| Tier                     | Metric Name                                       | Target Standard    |
+--------------------------+---------------------------------------------------+--------------------+
| Tier 1: Primary Estimand | Scenario-Level Useful Hypothesis Rate             | >= 0.1500 (13/84)  |
|                          | Useful Hypothesis Yield @ 60 min (Broad Context)  | Historical Context |
+--------------------------+---------------------------------------------------+--------------------+
| Tier 2: Classification   | True Positive Rate (TPR) on Vulnerable (n=36)     | >= 0.3500 (13/36)  |
| & Control Quality        | True Negative Rate (TNR) on Controls (n=48)       | >= 0.9583 (46/48)  |
|                          | False Positive Count on Negative Controls         | <= 2 / 48          |
|                          | Abstention Calibration Distribution               | Concordant with GT |
+--------------------------+---------------------------------------------------+--------------------+
| Tier 3: Engineering &    | Track D Raw Namespace Emission Rate               | < 1.0% (0/84)      |
| Syntactic Reliability    | Combined VAPT Raw Namespace Emission Rate         | < 1.0% (<= 1/168)  |
|                          | Validator Bypass Rate (Hard Safety Metric)        | 0.0% (0/84)        |
|                          | Grounding Validity Rate (Track D)                 | >= 98.0%           |
|                          | AC1 Syntactic Failure Rate (Mutually Exclusive    | < 0.5% (<= 1/336)  |
|                          | Primary Truncation, Parser, Schema Failures)      |                    |
|                          | Mean Per-Scenario Latency (Primary Envelope)      | <= 25,000 ms       |
|                          | Mean Per-Scenario Latency (Secondary Diagnostic)  | <= 45,000 ms       |
+--------------------------+---------------------------------------------------+--------------------+
```

> [!NOTE]
> **Primary Automated Estimand vs Human Study Metric**:
> - **Scenario-Level Useful Hypothesis Rate** is the authoritative primary automated live-benchmark activation metric for M4 because Phase M4.9 executes an 84-scenario live LLM benchmark.
> - **Useful Hypothesis Yield @ 60 Reviewer Minutes** represents the broader end-to-end human-efficiency research objective. It is **NOT** newly estimated in Phase M4.9 unless an independent, condition-masked human review study is separately commissioned. M4 will not claim human-efficiency gains from the 84-scenario benchmark alone. Historical M3 human-study results remain historical baseline context.

### 13.1 Decomposed Structured-Output Failure Taxonomy & Reporting Protocol

Milestone M4 formally decomposes structured-output reliability metrics into five distinct failure categories to ensure granular error accounting:

1. **Schema Validity Failure**: The model output is valid JSON syntax, but fails typed schema validation (e.g. missing mandatory fields, wrong field types, or violating enum specifications).
2. **Parser Failure**: The model output contains invalid JSON syntax (e.g. unbalanced braces, unescaped characters, or malformed tokens) unparseable by standard JSON decoders.
3. **Runtime / Transport Failure**: Non-syntactic execution or network interruptions (e.g. HTTP connection reset, inference daemon timeout, process crash, OOM).
4. **Max-Token Termination / Truncation Event**: Token generation is terminated prematurely upon reaching the `num_predict = 300` token ceiling, truncating closing braces or strings.
5. **Semantic Grounding Failure**: The output is syntactically valid and schema-conformant, but cites non-existent/fabricated entity IDs, violates namespace boundaries, or asserts unsupported security claims rejected by `KnowledgeGroundingValidator`.

#### Deterministic Primary Failure Classification Protocol
To eliminate double-counting (for example, when an output truncated at `num_predict = 300` also fails JSON parsing), every scenario-track evaluation attempt is assigned **exactly one mutually exclusive PRIMARY category**:
- `0. VALID`
- `1. RUNTIME_TRANSPORT_FAILURE`
- `2. MAX_TOKEN_TRUNCATION`
- `3. PARSER_FAILURE`
- `4. SCHEMA_VALIDITY_FAILURE`
- `5. SEMANTIC_GROUNDING_FAILURE`

Primary classification follows strict deterministic evaluation precedence:
$$\text{RUNTIME\_TRANSPORT\_FAILURE} > \text{MAX\_TOKEN\_TRUNCATION} > \text{PARSER\_FAILURE} > \text{SCHEMA\_VALIDITY\_FAILURE} > \text{SEMANTIC\_GROUNDING\_FAILURE}$$

**Classification Rules**:
- If an attempt fails because transport/runtime failed (e.g. HTTP reset, daemon timeout, process crash), classify it strictly and exclusively as `RUNTIME_TRANSPORT_FAILURE`.
- If generation reaches `num_predict` and the output is incomplete, classify it strictly as `MAX_TOKEN_TRUNCATION` even when the resulting truncated JSON is also malformed.
- Only classify `PARSER_FAILURE` when malformed JSON exists without a higher-precedence truncation or transport cause.
- Only classify `SCHEMA_VALIDITY_FAILURE` after valid JSON parsing succeeds.
- `SEMANTIC_GROUNDING_FAILURE` is only evaluated after successful parse and schema validation pass.
- `VALID` indicates zero failures across all evaluation layers.

Secondary diagnostic flags MAY record downstream cascade consequences (e.g., `truncation -> downstream_parser_invalid`), but secondary diagnostic flags MUST NOT be included in primary AC1 counts.

**Granular Failure Metric Definitions ($N=336$ scheduled scenario-track evaluation attempts)**:
Benchmark evaluation reports must independently report separate rates and raw counts for all mutually exclusive primary categories across all 336 scheduled scenario-track evaluation attempts:
- $\text{Rate}_{\text{transport}} = N_{\text{transport}} / 336$ (Must be $0 / 336$; transport stability requirement)
- $\text{Rate}_{\text{truncation}} = N_{\text{truncation}} / 336$
- $\text{Rate}_{\text{parser}} = N_{\text{parser}} / 336$
- $\text{Rate}_{\text{schema\_validity}} = N_{\text{schema\_validity}} / 336$
- $\text{Rate}_{\text{grounding\_failure}} = N_{\text{grounding\_failure}} / 336$ (Governed separately by AC5 $\ge 98.0\%$ validity)

The authoritative syntactic reliability gate (AC1) is explicitly defined over the denominator of all 336 scheduled scenario-track evaluation attempts ($N=336$), specifically bounding the sum of mutually exclusive primary truncation, parser, and schema validity failures:
$$\text{AC1 Syntactic Failure Rate} = \frac{N_{\text{truncation}} + N_{\text{parser}} + N_{\text{schema\_validity}}}{336} < 1.0\% \quad (\le 3 / 336)$$

> [!IMPORTANT]
> **Syntactic Validity vs Epistemic Security Reasoning**:
> Schema-constrained decoding is an engineering intervention designed to reduce syntax failures, schema validity failures, and max-token truncation events caused by unconstrained verbosity. It does **NOT** guarantee semantic correctness, epistemic correctness, grounding correctness, useful hypothesis generation, or vulnerability confirmation. Syntactic validity is a necessary engineering precondition for automated evaluation, but does NOT imply correct security reasoning.

### 13.2 Milestone M4 Acceptance Criteria Table
To achieve milestone sign-off, M4 must satisfy all criteria below:

```text
+---------------------------------------------------------------------------------------------------+
|                                  M4 ACCEPTANCE CRITERIA TABLE                                     |
+----+----------------------------------------------+-------------------------+---------------------+
| ID | Requirement                                  | Measurement Threshold   | Verification Method |
+----+----------------------------------------------+-------------------------+---------------------+
| AC1| Mutually Exclusive Syntactic Failure Rate    | Separate reporting for  | 84-scenario 4-track |
|    | (Primary Classification: Truncation,         | all categories;         | live benchmark logs |
|    | Parser, Schema Validity)                     | (N_trunc + N_parse +    | and validation      |
|    |                                              | N_schema)/336 < 1.0%    | report              |
+----+----------------------------------------------+-------------------------+---------------------+
| AC2| Epistemic Namespace Discipline               | Track D Raw Namespace   | 84-scenario 4-track |
|    |                                              | Emission Rate < 1.0%;   | live benchmark logs |
|    |                                              | Validator Bypass Rate=0 | and validator report|
+----+----------------------------------------------+-------------------------+---------------------+
| AC3| Negative Control Preservation                | TNR >= 90.0% (<=4 FP)   | Negative controls   |
|    |                                              | on 48 control scenarios | (n=48) live run     |
+----+----------------------------------------------+-------------------------+---------------------+
| AC4| Activation of Useful Hypothesis Rate         | Useful Hypothesis Rate  | 84-scenario live    |
|    |                                              | > 0.0000 on Track D     | benchmark           |
+----+----------------------------------------------+-------------------------+---------------------+
| AC5| Grounding Validity in Dual RAG               | Grounding Validity Rate | KnowledgeGrounding- |
|    |                                              | >= 98.0% in Track D     | Validator report    |
+----+----------------------------------------------+-------------------------+---------------------+
| AC6| Strict B/D Causal Parity Preservation        | 84/84 byte-identical    | SHA-256 payload     |
|    |                                              | target evidence payloads| hash comparison     |
+----+----------------------------------------------+-------------------------+---------------------+
| AC7| Target-Evidence Retriever Untouched          | 0 diff lines on         | git diff            |
|    |                                              | src/retrieval/hybrid.py |                     |
+----+----------------------------------------------+-------------------------+---------------------+
| AC8| Complete Regression Suite Passing            | 100% unit & non-live    | pytest unit/integ   |
|    |                                              | integration tests pass  | test execution      |
+----+----------------------------------------------+-------------------------+---------------------+
| AC9| Primary Latency Envelope Verified            | Mean latency <= 25,000ms| Profiling & live run|
|    |                                              | per scenario-track call | latency records     |
+----+----------------------------------------------+-------------------------+---------------------+
|AC10| Runtime Capability Check Passed              | Schema-constrained dec. | Phase M4.0 test     |
|    |                                              | verified on local daemon| report artifact     |
+----+----------------------------------------------+-------------------------+---------------------+
```

---

## 14. Negative-Control Integrity & Safety Floors

A primary danger of prompt optimization in security reasoning is **hypersensitivity** (generating confident vulnerabilities on safe endpoints).

### 14.1 Strict Negative-Control Rules
1. **The TNR Safety Floor**: Any intervention that drives True Negative Rate on negative controls below **90.0%** (more than 4 false positives out of 48 controls) is automatically rejected, regardless of its TPR gains.
2. **Ungrounded Hallucination Penalty**: Any hypothesis citing a non-existent fact ID or placing a `CHK` chunk in place of target traffic is scored as a severe grounding failure.
3. **Falsification Proposal Completeness**: Every emitted `HYPOTHESIS` must specify a concrete, non-empty `experiment_proposal` detailing both:
   - What observation proves the hypothesis.
   - What observation disproves the hypothesis.

---

## 15. Statistical Methodology & Paired Evaluation Standards

Because multiple interventions will be screened prior to final configuration freezing:
1. **Methodological Separation**: The plan strictly separates **Exploratory Screening Statistics** (Phase M4.8) from **Pre-Frozen Confirmatory Evaluation Statistics** (Phase M4.9).
2. **Scenario-Level Pairing**: Every comparison between conditions (e.g. M3 Baseline vs M4 Candidate) will be paired scenario-by-scenario.
3. **Confidence Intervals**: 95% confidence intervals for differences in Useful Hypothesis Yield and Abstention Rates will be computed using **bias-corrected and accelerated (BCa) bootstrap** with $R = 10,000$ resamples.
4. **Significance Testing**: Two-sided paired permutation tests ($R = 100,000$) will evaluate whether observed yield differences are statistically distinguishable from chance.
5. **Selection-Aware Reporting**: The final report will explicitly document that the evaluated configuration was selected from an exploratory screening pool, preventing inflated post-selection inference claims.

---

## 16. Local Hardware Plan & Hardware Profiling Specification

All M4 development and validation will execute on the existing local development environment:

- **Hardware Target**: NVIDIA GeForce RTX 3050 Laptop GPU (4 GB GDDR6 VRAM, 60W TGP).
- **Inference Server**: Local Ollama v0.34.1 (`http://127.0.0.1:11434`).
- **Offline Guarantee**: Offline evaluation must be verified by an explicit network-egress control or equivalent runtime/network verification; `$env:OLLAMA_ORIGINS=""` is not itself treated as the sole egress guarantee.
- **Model Residency**:
  - `qwen2.5-coder:7b` (4.7 GB GGUF) resides primarily in RAM with ~3.2 GB offloaded to VRAM.
  - `keep_alive = "60m"` prevents memory thrashing during batch runs.
  - When evaluating 3B handoff, models are swapped sequentially with 15s cool-down.
- **Context Allocation (2048 tokens total)**:
  - System Prompt (P0): ~450 tokens
  - Canonical Evidence (P1): ~800 tokens
  - 3B Predicates (P3): ~150 tokens
  - VAPT Methodology (P4): ~250 tokens
  - Output Headroom (`num_predict`): 300 tokens (Primary Envelope) / 512 tokens (Secondary Diagnostic)

### 16.1 Hardware Profiling Spike Specification (Phase M4.0)
Before any implementation decisions are locked, Phase M4.0 executes an empirical hardware profiling spike recording:
- Model identity and digest (`dae161e2...`)
- Quantization (`Q4_K_M`)
- `num_ctx = 2048`, `num_predict = 300`, `temperature = 0.0`, `seed = 42`
- Prompt / input token count & generated / output token count
- Prefill latency (ms), decode latency (ms), and total latency (ms)
- Effective generation throughput (tokens/sec)
- GPU VRAM consumption & system RAM consumption
- Offload configuration (GPU layers vs CPU layers)

**Primary Latency Gate**:
Mean per-scenario-track latency must be $\le 25,000$ ms. If profiling indicates that the pinned 7B model systematically breaches 25,000 ms on the local hardware, implementation must **pause for a human review decision point**. The agent must **NOT** automatically raise the threshold or substitute a smaller model (e.g. 3B) or different quantization.

---

## 17. Security Boundaries & Invariants

M4 preserves all platform security boundaries without compromise:
1. **Zero Execution Authority**: The LLM reasoning engine emits hypotheses and experiment proposals. It has **zero capability** to execute network requests, touch sockets, or launch scripts.
2. **Zero Vulnerability Confirmation Authority**: The LLM can never transition a hypothesis to `CONFIRMED`. Only the deterministic execution engine and human approval can confirm findings.
3. **Immutable Scope Boundary**: Scope CIDRs and hostname whitelists are enforced by `src/scope/` outside the LLM context.
4. **Secret Redaction**: Raw headers, cookies, and tokens are redacted prior to context building (`src/evidence/redaction.py`).

---

## 18. Hard-Stop Conditions

If any of the following occur during M4 execution, all implementation stops immediately:
- **HS1**: False positive count on negative controls exceeds 4 ($> 4 / 48$, $\text{TNR} < 90.0\%$).
- **HS2**: Target-evidence causal parity is violated on even a single scenario ($\text{discrepancies} > 0$).
- **HS3**: Any modification is made to historical M3 artifacts or `src/retrieval/hybrid.py`.
- **HS4**: Model generates ungrounded fact citations that bypass `KnowledgeGroundingValidator`.
- **HS5**: Runtime structured-decoding capability check fails in Phase M4.0.
- **HS6**: Hardware profiling spike reveals systematic violation of the 25,000 ms latency gate without human approval.

---

## 19. Artifact & Provenance Plan

All M4 artifacts will be uniquely identified, versioned, and sealed:

```text
+---------------------------------------------------------------------------------------------------+
|                                     M4 ARTIFACT DIRECTORY                                         |
+--------------------------------------------+------------------------------------------------------+
| Artifact Path                              | Content / Purpose                                    |
+--------------------------------------------+------------------------------------------------------+
| docs/M4_REASONING_ENGINE_PLAN.md           | Authoritative planning specification (this file)     |
| data/eval/m4_hardware_profile_baseline.json| Phase M4.0 hardware profiling spike results          |
| data/eval/m4_runtime_capability_report.json| Phase M4.0 runtime structured-decoding audit         |
| data/eval/m4_ablation_manifest.json        | Pre-registered configuration of all M4 conditions    |
| data/eval/m4_dev_partition_manifest.json   | Sealed 20-scenario screening manifest & checksum     |
| data/eval/m4_ablation_e1_schema.json       | Screening results for Intervention 1 (Schema)        |
| data/eval/m4_ablation_e2_namespace.json    | Screening results for Intervention 2 (Namespace)     |
| data/eval/m4_ablation_e3_counterfactual.json| Screening results for Intervention 3 (Prompts)      |
| data/eval/m4_ablation_e4_bair.json         | Screening results for Intervention 4 (BAIR)          |
| data/eval/m4_ablation_e5_abstention.json   | Screening results for Intervention 5 (Abstention)    |
| data/eval/m4_ablation_e6_handoff.json      | Screening results for Intervention 6 (3B Handoff)    |
| data/eval/m4_frozen_config_manifest.json   | Sealed final configuration manifest & checksum       |
| data/eval/m4_live_llm_benchmark_final.json | Final confirmatory 84-scenario validation run        |
| docs/M4_FINAL_VALIDATION_REPORT.md         | Comprehensive milestone research report              |
+--------------------------------------------+------------------------------------------------------+
```

---

## 20. Sequential Phase-by-Phase Implementation Plan

Milestone M4 is decomposed into 12 sequential, auditable phases:

```text
+---------------------------------------------------------------------------------------------------+
|                                 M4 SEQUENTIAL PHASE DECOMPOSITION                                 |
+-------+---------------------------------------------+---------------------------------------------+
| Phase | Title                                       | Primary Deliverable / Milestone             |
+-------+---------------------------------------------+---------------------------------------------+
| M4.0  | Pre-Flight Audit, Capability & Profiling    | Runtime check & hardware latency profile    |
| M4.1  | Failure Taxonomy & Trace Profiling          | Formal catalog of M3 live model errors      |
| M4.2  | I1 Schema-Constrained Structured Generation | Runtime schema decoding & fail-closed parser|
| M4.3  | I2 Epistemic Namespace Schema Constraints   | Dual-field schema regexes & validator gating|
| M4.4  | I3 Counterfactual Invariant Prompting       | Evidence-gap counterfactual prompt templates|
| M4.5  | I4 BAIR Intermediate Representation & Extr. | Bounded intermediate representation + AST   |
| M4.6  | I5 Calibrated Abstention & Decision Policy  | Triaged decision calibration rules          |
| M4.7  | I6 Pure Invariant Handoff Serializer        | Protected structural handoff serializer     |
| M4.8  | Independent Intervention Screening (E1-E6)  | Exploratory screening results on dev split  |
| M4.8b | Deterministic Final Configuration Freeze    | Locked configuration manifest & checksum    |
| M4.9  | Confirmatory Frozen 84-Scenario Benchmark   | Full 336-call live validation run           |
| M4.10 | Forensic Analysis, Research Report & Seal   | docs/M4_FINAL_VALIDATION_REPORT.md & tag    |
+-------+---------------------------------------------+---------------------------------------------+
```

### Phase Details:

- **Phase M4.0: Pre-Flight Audit, Capability Check & Hardware Profiling**
  - Verify clean working tree, Git commit ancestry, and zero diffs on `src/retrieval/hybrid.py`.
  - Validate historical artifact checksums.
  - Execute Ollama runtime capability test for JSON schema constrained decoding.
  - Execute hardware latency profiling spike on local RTX 3050; verify Primary Latency Gate ($\le 25$s).
- **Phase M4.1: Failure Taxonomy & Trace Profiling**
  - Deep forensic analysis of the 11 truncated responses and 23 namespace violations from `data/eval/m3_live_llm_benchmark_20260920.json`.
- **Phase M4.2: I1 Schema-Constrained Structured Generation**
  - Configure `HypothesisModelOutput.get_inference_schema()` for native runtime constrained decoding with fail-closed parser.
- **Phase M4.3: I2 Epistemic Namespace Schema Constraints**
  - Add schema regexes (`^FACT-[A-Z0-9_-]+$`, `^CHK-[A-Z0-9_-]+$`) and update `KnowledgeGroundingValidator`.
- **Phase M4.4: I3 Counterfactual Invariant Prompting**
  - Design category-specific counterfactual evaluation templates for the 10 OWASP API categories.
- **Phase M4.5: I4 BAIR Intermediate Representation & Extraction**
  - Implement BAIR XML slot emission and deterministic AST parser; verify fail-closed behavior on malformed tags.
- **Phase M4.6: I5 Calibrated Abstention & Decision Policy**
  - Formalize prompt definitions for `HYPOTHESIS` vs `INSUFFICIENT_EVIDENCE` vs `NO_RELEVANT_FUNCTIONALITY`.
- **Phase M4.7: I6 Pure Invariant Handoff Serializer**
  - Implement `HandoffSerializer` to pass strictly verified Class-1 booleans without touching router authority.
- **Phase M4.8: Independent Intervention Screening (E1 through E6)**
  - Execute pure single-factor evaluations on the 20-scenario exploratory development partition.
- **Phase M4.8b: Deterministic Final Configuration Freeze & Manifest Seal**
  - Apply deterministic selection rules, verify gates, serialize `data/eval/m4_frozen_config_manifest.json`, and lock configuration.
- **Phase M4.9: Confirmatory Frozen 84-Scenario Benchmark**
  - Run full 84 scenarios $\times$ 4 tracks = 336 live calls with the frozen configuration.
  - Verify strict B/D causal parity (0 discrepancies).
- **Phase M4.10: Forensic Analysis, Research Report & Seal**
  - Publish `docs/M4_FINAL_VALIDATION_REPORT.md`.
  - Verify zero regressions across the complete pre-registered unit/integration regression suite.
  - Freeze milestone under `m4-v1.1.0-planning-freeze` tag.

---

## 21. Known Limitations & Open Research Questions

1. **Small Exploratory Development Partition ($n=20$)**:
   The development partition represents ~23.8% of the frozen benchmark. Individual scenarios have high leverage ($5.0\%$ per scenario). It is suitable strictly for engineering screening, not generalized superiority claims.
2. **Post-Screening Selection Uncertainty**:
   The final candidate configuration is assembled post-screening; reported confirmatory results must explicitly document selection-aware interpretation.
3. **Benchmark-Bounded Confirmatory Generalization**:
   The 84-scenario benchmark provides rigorous internal validity and exact reproducibility, but findings cannot be unconditionally generalized to uncurated, wild API traffic without continuous testing.
4. **Hardware-Dependent Local Model Throughput**:
   A 7.6B quantized model (`Q4_K_M`) on consumer hardware has finite throughput. Latency is hardware- and runtime-dependent, including CPU/GPU offload behavior, memory-transfer behavior, prompt length, and inference-runtime characteristics.
5. **Separation of Constrained Decoding, Namespace Validation, and Semantic Grounding**:
   Runtime schema-constrained decoding belongs exclusively to Intervention I1 and constrains token sampling strictly to valid JSON schema syntax and structural types; it does not evaluate namespace semantics. FACT/CHK namespace regex validation belongs to Intervention I2 and operates post-generation under baseline unconstrained sampling. Neither mechanism guarantees semantic security correctness, epistemic validity, or hypothesis truth. `KnowledgeGroundingValidator` remains the authoritative semantic and epistemic check across all conditions.
6. **BAIR Analytical Capacity**:
   BAIR is a compact intermediate analytical interface (bounded slots), not unrestricted chain-of-thought. Complex multi-step authorization paths are bounded by slot structure.
7. **Automated Rate vs Human Efficiency**:
   The primary automated metric measures hypothesis formation rate on the benchmark. Human-investigation efficiency claims require a condition-masked human review study.

---

## 22. Curation, Review & Freeze Procedure

Milestone M4 strictly follows a 4-phase governance procedure:

```text
  Phase 1: Draft Planning Specification (Completed: docs/M4_REASONING_ENGINE_PLAN.md v1.0.0)
     │
     ▼
  Phase 2: Architectural Revision & Curation (Current: v1.2.4 — DRAFT / FINAL PRE-FREEZE MICRO-REVISION)
     │
     ▼
  Phase 3: Formal Milestone Planning Freeze (Git Tag: m4-v1.1.0-planning-freeze)
     │
     ▼
  Phase 4: Implementation Begins (Strict adherence to frozen specification)
```

---

## 23. V1.2.4 Human Review Checklist (HUMAN REVIEW REQUIRED)

Before triggering the formal Phase 3 planning freeze and creating Git tag `m4-v1.1.0-planning-freeze`, the human reviewer must verify every item on this checklist:

```text
+---------------------------------------------------------------------------------------------------+
|                        M4 V1.2.4 HUMAN REVIEW CHECKLIST (ALL MUST BE VERIFIED)                    |
+----+-------------------------------------------------------------------------+--------------------+
| #  | Verification Item                                                       | Status             |
+----+-------------------------------------------------------------------------+--------------------+
| 1  | S0 canonical base schema is shared infrastructure; I1 has no compaction | [ ] REVIEW REQUIRED|
| 2  | I1 schema-constrained structured generation is primary, not repair      | [ ] REVIEW REQUIRED|
| 3  | Structured-output failure taxonomy splits syntax from semantic grounding| [ ] REVIEW REQUIRED|
| 4  | AC1 primary failure categories are mutually exclusive (N=336 attempts)  | [ ] REVIEW REQUIRED|
| 5  | I2 namespace validation operates post-generation under unconstrained run| [ ] REVIEW REQUIRED|
| 6  | H2 evaluates raw namespace emission; validator bypass is safety metric  | [ ] REVIEW REQUIRED|
| 7  | I2 deterministic output-schema adapter preserves canonical S0 output    | [ ] REVIEW REQUIRED|
| 8  | H4 operationalized as proposal completeness and structural validity     | [ ] REVIEW REQUIRED|
| 9  | I4 BAIR analytical slots follow decision-dependent validation contract  | [ ] REVIEW REQUIRED|
| 10 | I4 stays strictly within one 300-token LLM call (Primary Envelope)      | [ ] REVIEW REQUIRED|
| 11 | I4 BAIR analytical slots are bounded and fail-closed                    | [ ] REVIEW REQUIRED|
| 12 | I4 does NOT require or assume unrestricted Chain-of-Thought             | [ ] REVIEW REQUIRED|
| 13 | Runtime structured-decoding capability check is required in Phase M4.0  | [ ] REVIEW REQUIRED|
| 14 | Hardware profiling spike occurs in Phase M4.0 before latency decisions  | [ ] REVIEW REQUIRED|
| 15 | Hardware language reflects runtime-dependent characteristics, not bus   | [ ] REVIEW REQUIRED|
| 16 | Network policy requires explicit egress verification; not OLLAMA_ORIGINS| [ ] REVIEW REQUIRED|
| 17 | No automatic model, quantization, or runtime substitution permitted     | [ ] REVIEW REQUIRED|
| 18 | 20-scenario screening partition is explicitly marked exploratory        | [ ] REVIEW REQUIRED|
| 19 | 84-scenario confirmatory benchmark remains locked from selection/tuning | [ ] REVIEW REQUIRED|
| 20 | COMBINED configuration is selection-aware, not proof of optimality     | [ ] REVIEW REQUIRED|
| 21 | Platform security boundaries and zero LLM execution authority preserved | [ ] REVIEW REQUIRED|
| 22 | Target-Evidence retriever (src/retrieval/hybrid.py) has 0 diff lines    | [ ] REVIEW REQUIRED|
| 23 | Historical M1–M3 artifacts and benchmarks are quarantined and untouched | [ ] REVIEW REQUIRED|
| 24 | Milestone M4 remains strictly planning-only (no code, tests, or tag)    | [ ] REVIEW REQUIRED|
+----+-------------------------------------------------------------------------+--------------------+
```

---

## 24. Statement of Planning-Only Status

- **No project implementation code, test suite, benchmark, or live LLM inference was executed.**
- **No source-code changes were made.**
- **No test changes were made.**
- **No evaluation data changes were made.**
- **No benchmark execution occurred.**
- **No live LLM inference occurred.**
- **Milestone M4 is NOT frozen.**
- **Implementation remains strictly blocked pending formal human review and completion of Phase 3 planning freeze.**
