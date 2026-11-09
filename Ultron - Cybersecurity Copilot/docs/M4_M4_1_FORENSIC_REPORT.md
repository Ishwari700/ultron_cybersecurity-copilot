# Milestone M4 — Phase M4.1 Forensic Trace & Baseline Reconciliation Report

**Milestone:** M4 — Reasoning Engine Optimization & Epistemic Calibration  
**Subsystem:** Phase M4.1 — Failure Taxonomy & Trace Profiling  
**Authoritative Input Source:** [data/eval/m3_live_llm_benchmark_20260920.json](data/eval/m3_live_llm_benchmark_20260920.json) (SHA-256: `c516fdc112418e00955ffc7231482ea52dd4b1c96da71a83a5e92ebfcbe31dac`, strictly read-only)  
**Target Catalog Artifact:** [data/eval/m4_failure_trace_profile.json](data/eval/m4_failure_trace_profile.json)  
**Parent M4 Planning Freeze:** `m4-v1.1.0-planning-freeze` (`1e1a87070a018542a0a2e79f8a78654f34df5aba`)  
**Parent M3 Freeze:** `m3-v2.3.8-planning-freeze` (`819b83399e24080bf2942c3941cc96728885df49`)  
**Status:** COMPLETE / FORENSIC REPORT ONLY (NO CODE IMPLEMENTATION)  

---

## 1. Executive Summary & Milestone Progress

Milestone M4 addresses the empirical bottlenecks identified during the live local LLM execution of Milestone M3. Phase M4.1 performs an exhaustive, deterministic forensic analysis of the frozen 336-evaluation live benchmark dataset (`data/eval/m3_live_llm_benchmark_20260920.json`, local `qwen2.5-coder:7b`, `Q4_K_M`, Ollama v0.34.1).

### Core Forensic Findings:
1. **Truncation Failures**: Under the strict, mutually exclusive M4 failure taxonomy, exactly **26 / 336 evaluations (7.74%)** across 21 unique scenarios terminated at the `num_predict = 300` ceiling, truncating closing JSON syntax.
2. **Namespace Violations**: Exactly **23 / 336 evaluations (6.85%)** emitted cross-namespace citations (`CHK-DOC-...` inside `supporting_evidence_ids`), confined entirely to Track C (11 / 84) and Track D (12 / 84).
3. **Safety Gate Integrity**: `KnowledgeGroundingValidator` rejected 100% of namespace violations (23/23). **Validator Bypass Rate was strictly 0.0% (0 / 84)**.
4. **Zero Useful Yield on Vulnerable Scenarios**: 100% of parseable outputs (310 / 310) defaulted to `decision = "NO_RELEVANT_FUNCTIONALITY"`, yielding **TPR = 0.0% (0 / 36)** on vulnerable scenarios while maintaining **TNR = 91.67% to 95.83%** on negative controls with **0 False Positives**.

---

## 2. Deterministic Baseline Reconciliation & Provenance Note

### 11/336 vs 26/336 Baseline Reconciliation

1. **Prior Planning Specification Reference**: The frozen M4 planning specification ([docs/M4_REASONING_ENGINE_PLAN.md](docs/M4_REASONING_ENGINE_PLAN.md), v1.2.4) referenced `11/336 truncation-associated structured-output failures` as the prior historical characterization derived during M3 validation.
2. **Application of Strict M4.1 Taxonomy**: Phase M4.1 applied the now-explicit, mutually exclusive primary failure taxonomy and deterministic precedence rules:
   $$\text{RUNTIME\_TRANSPORT\_FAILURE} > \text{MAX\_TOKEN\_TRUNCATION} > \text{PARSER\_FAILURE} > \text{SCHEMA\_VALIDITY\_FAILURE} > \text{SEMANTIC\_GROUNDING\_FAILURE}$$
3. **Forensic Reclassification Result**: Under this exhaustive and deterministic classification, exactly **26 / 336 evaluation attempts** are classified as `MAX_TOKEN_TRUNCATION`. Every single one of these 26 runs reached the 300-token ceiling mid-generation with character lengths between 1,381 and 1,567 chars (average 1,474.5 chars), causing trailing closing braces and delimiters to be cut off.
4. **Supersedence Policy**: The **26 / 336** figure supersedes the earlier **11 / 336** figure for all subsequent M4.1 forensic analysis and M4 engineering motivation.
5. **Provenance Clarification**: This is a reclassification and provenance clarification resulting from a stricter, mutually exclusive primary taxonomy; it is **NOT** a mutation, rerun, or modification of the frozen M3 live benchmark data.
6. **Integrity of Historical Context**: The earlier 11/336 characterization reflected a narrower pre-taxonomic filter (such as specific track groupings or post-hoc heuristics), whereas the M4.1 figure represents an exhaustive, primary categorization across all 336 attempts. The underlying frozen benchmark remains byte-identical.

---

## 3. Mutually Exclusive Primary Failure Taxonomy ($N=336$)

Every scheduled evaluation attempt across the 84 scenarios and 4 tracks is assigned **exactly one mutually exclusive primary category**:

```text
+---------------------------------------------------------------------------------------------------+
|                        M4.1 DETERMINISTIC PRIMARY FAILURE DISTRIBUTION                            |
+----+------------------------------------+-------+------------+------------------------------------+
| ID | Primary Failure Category           | Count | Proportion | Primary Deterministic Attribution  |
+----+------------------------------------+-------+------------+------------------------------------+
| 0  | VALID                              | 287   | 85.42%     | Syntactically valid & grounded     |
| 1  | RUNTIME_TRANSPORT_FAILURE          | 0     | 0.00%      | All 336 HTTP 200 responses received|
| 2  | MAX_TOKEN_TRUNCATION               | 26    | 7.74%      | Terminated at num_predict=300 ceil |
| 3  | PARSER_FAILURE                     | 0     | 0.00%      | Subsumed by higher-precedence trunc|
| 4  | SCHEMA_VALIDITY_FAILURE            | 0     | 0.00%      | All parseable outputs schema-valid |
| 5  | SEMANTIC_GROUNDING_FAILURE         | 23    | 6.85%      | FACT/CHK cross-namespace breach    |
+----+------------------------------------+-------+------------+------------------------------------+
|    | TOTAL SCHEDULED EVALUATIONS        | 336   | 100.00%    | 84 scenarios x 4 tracks            |
+----+------------------------------------+-------+------------+------------------------------------+
```

### Track-Level Breakdown

| Track | Scheduled Calls | Primary VALID | Primary MAX_TOKEN_TRUNCATION | Primary SEMANTIC_GROUNDING |
|---|---|---|---|---|
| **TRACK_A** (Baseline Structural) | 84 | 79 (94.05%) | 5 (5.95%) | 0 (0.00%) |
| **TRACK_B** (Target Evidence) | 84 | 82 (97.62%) | 2 (2.38%) | 0 (0.00%) |
| **TRACK_C** (Dual-Store Methodology) | 84 | 63 (75.00%) | 10 (11.90%) | 11 (13.10%) |
| **TRACK_D** (Full Dual-RAG Parity) | 84 | 63 (75.00%) | 9 (10.71%) | 12 (14.29%) |
| **Total** | **336** | **287** | **26** | **23** |

---

## 4. Deep Trace Forensic Analysis

### 4.1 Structured-Output Truncation Traces ($n=26$)
- **Mechanism**: The base model generated discursive, unconstrained natural language in `reasoning_summary` and `experiment_proposal`. Upon emitting token 300, the generation process ceased abruptly.
- **Syntactic Impact**: Closing brackets and braces (`" ... }`) were cut off mid-string. Downstream parsers encountered `JSONDecodeError: Unterminated string starting at...`.
- **Character Length Distribution**:
  - Minimum raw characters: 1,381
  - Maximum raw characters: 1,567
  - Mean raw characters: 1,474.5 (concordant with 300 sub-word tokens)
- **Causal Motivation**: Motivates **Intervention I1** (runtime schema-constrained decoding to reduce incomplete or syntactically invalid structured outputs) and **Intervention I4** (Bounded Analytical Intermediate Representation to enforce compact slot budgets).

### 4.2 Epistemic Namespace Violation Traces ($n=23$)
- **Mechanism**: When Partition P4 provided security testing methodology chunks, the model cited `CHK-DOC-PLATFORM-INV-...` IDs inside `supporting_evidence_ids`.
- **Observed Rates**:
  - Track C Namespace Violations: 11 / 84 ($13.10\%$)
  - Track D Raw Namespace Emission Rate: 12 / 84 ($14.29\%$)
  - Combined VAPT Raw Namespace Emission Rate: 23 / 168 ($13.69\%$)
- **Validator Discipline**: `KnowledgeGroundingValidator` failed-closed on all 23 occurrences (`grounding_status: INVALID`). **Validator Bypass Rate was strictly 0.0%**.
- **Causal Motivation**: Motivates **Intervention I2** (prompt-level namespace segregation and dual-field schema validation) to reduce raw cross-namespace emission tendencies.

### 4.3 Conservative Abstention Traces ($n=310$ parseable)
- **Zero Useful Yield**: All 310 parseable outputs emitted `decision = "NO_RELEVANT_FUNCTIONALITY"`.
- **Vulnerable Scenarios ($n=36$)**:
  - True Positive Rate: **0.0% (0 / 36)**
  - False Negatives: **36 / 36** across all tracks (130 evaluated as `NO_REL`, 14 truncated)
- **Negative Controls ($n=48$)**:
  - False Positives: **0 / 48** across all tracks
  - True Negative Rate: Track A = 91.67% (44/48), Track B = 95.83% (46/48), Track C = 91.67% (44/48), Track D = 95.83% (46/48)
- **Causal Motivation**: Motivates **Intervention I3** (counterfactual invariant prompting) and **Intervention I5** (calibrated decision policy) to activate hypothesis formation without degrading negative-control safety.

### 4.4 3B $\to$ 7B Handoff Implementation-Path Evidence
- **Implementation-Path Evidence**: Inspection of the M3 context-building path ([src/engine/context_builder.py](src/engine/context_builder.py#L240-L255)) shows that Channel B advisory content can pass natural-language triage rationale and subjective suspected category assertions (e.g. `Suspected Category: BOLA`, `Triage Rationale: Endpoint lacks authentication check`) into Partition P3.
- **Architectural Motivation**: This implementation-path evidence directly motivates **Intervention I6** (`HandoffSerializer`) to restrict P3 strictly to verified Class-1 predicate booleans, eliminating unconstrained natural language overhead and potential label priming.
- **Measurement Boundary**: Anchoring bias remains an architectural hypothesis rather than an empirically measured metric on the benchmark.

---

## 5. Cross-Track Descriptive Comparison

- **Track A (Baseline Structural Context)**: 5 truncations, 0 namespace violations, 79 valid abstentions.
- **Track B (Target Evidence Enabled)**: 2 truncations, 0 namespace violations, 82 valid abstentions. Track B produced fewer truncation events in this benchmark configuration than Track A.
- **Track C (Methodology Context Added)**: 10 truncations, 11 namespace violations, 63 valid abstentions. Track C exhibited cross-namespace citations and a higher truncation count in this methodology-enabled condition, motivating the controlled I2 experiment.
- **Track D (Full Dual-RAG with Causal Parity)**: 9 truncations, 12 namespace violations, 63 valid abstentions. Track D exhibited namespace violations in this methodology-enabled condition, motivating the controlled I2 experiment.

---

## 6. Audit & Governance Verification

- **Planning Freeze Integrity**: Tag `m4-v1.1.0-planning-freeze` remains anchored to commit `1e1a87070a018542a0a2e79f8a78654f34df5aba`.
- **Retriever Boundary**: `src/retrieval/hybrid.py` has **0 diff lines**.
- **Historical Integrity**: All 8 frozen M1–M3 artifacts match their recorded SHA-256 digests.
- **Read-Only Source Verification**: `data/eval/m3_live_llm_benchmark_20260920.json` is byte-identical to its baseline commit (`049ffa0`).

---

## 7. Next Steps

- **Phase M4.1 is COMPLETE.**
- Execution is **STOPPED** for human review of this reconciliation before any Phase M4.2 implementation begins.
