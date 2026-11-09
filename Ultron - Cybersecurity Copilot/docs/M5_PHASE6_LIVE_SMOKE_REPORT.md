# Milestone M5 — Phase 6 Limited Live Smoke Validation Report

**Date**: 2026-09-21  
**Status**: COMPLETE  
**Milestone**: Milestone M5 (Reasoning Interface & Protocol Reconciliation)  
**Phase**: Phase 6 — Limited Live M5 Smoke Validation  
**Execution Target**: Local Ollama runtime (`ollama version is 0.34.1`), `qwen2.5-coder:7b` (`dae161e27b0e...`)  
**Evaluation Scope**: 3 pre-registered scenarios $\times$ 4 tracks $\times$ 2 $I_1$ conditions = 24 live calls total.

---

## 1. Executive Summary & Core Finding

Phase 6 executed a pre-registered, strictly bounded live smoke validation of the repaired M5 reasoning interface against local Ollama `qwen2.5-coder:7b`.

### Primary Empirical Finding: Interface Viability Established
- **M4.9 Historical Baseline**: 336/336 (100%) `PARSER_FAILURE`. Under M4.9, the XML/JSON protocol collision caused the model output to be completely unparseable across all tracks.
- **M5 Live Smoke Evaluation**: **0/24 (0%) `PARSER_FAILURE`**.
- **100% of live model outputs (24/24) were successfully decoded by the production parser.**
- **8/24 calls reached the final decision and grounding layers**, yielding valid evaluation results with preserved canonical decision objects.
- **Zero retries, zero alternate prompts, and zero semantic repairs occurred.** Exactly 1 LLM call was executed per condition.
- **Target-Evidence Causal Parity**: Verified 100% byte-identical between Track B and Track D across all 3 scenarios and both $I_1$ conditions.

> [!IMPORTANT]
> **SCIENTIFIC BOUNDARY & NON-SUPERIORITY NOTICE**  
> This smoke test establishes **interface viability and engineering coherence only** (i.e. real model output can flow through parsing, schema validation, canonical adaptation, and decision policy).  
> **This report makes NO claims regarding:**
> - Improved vulnerability detection or True Positive Rate (TPR);
> - Improved Useful Hypothesis Yield;
> - Superior model reasoning or RAG efficacy;
> - Human-efficiency improvements.  
> Confirmatory benchmarking remains strictly deferred until authorized under separate milestone planning.

---

## 2. Pre-Smoke Freeze Verification (Phase 6A)

All 10 pre-flight freeze checks passed with 100% compliance prior to the first live invocation:

| # | Item | Required Value / State | Observed Value | Status |
|---|---|---|---|---|
| 1 | Git Working Tree | Clean (no unstaged changes to tracked files) | Clean | PASS |
| 2 | M4 Planning Freeze | Commit `1e1a87070a018542a0a2e79f8a78654f34df5aba` (`m4-v1.1.0-planning-freeze`) | `1e1a8707...` (0 diff) | PASS |
| 3 | M4.9 Benchmark SHA | `459b9ec63c3a2dc760abde12ec196760f7e505fbab5317f0da0c46b32c5eaac7` | `459b9ec6...` | PASS |
| 4 | Source Benchmark SHA | `b2b85a672124acf21066a257d8c7f5093000368b224ee013c02574c96a0ae707` | `b2b85a67...` | PASS |
| 5 | Protected Files Diff | 0 diff lines (`docs/M4_REASONING_ENGINE_PLAN.md`, `src/retrieval/hybrid.py`, M3 result) | Clean | PASS |
| 6 | Output Smoke File | `data/eval/m5_live_smoke.json` absent before run | Absent | PASS |
| 7 | Ollama Model | `qwen2.5-coder:7b` | `qwen2.5-coder:7b` | PASS |
| 8 | Model Digest | `dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364` | `dae161e2...` | PASS |
| 9 | Ollama Runtime Version | `0.34.1` | `ollama version is 0.34.1` | PASS |
| 10 | Primary Parameters | `num_ctx=2048, num_predict=300, temp=0.0, seed=42, keep_alive=60m` | Configured | PASS |

---

## 3. Pre-Registered Smoke Scenario Roster (Phase 6B)

In compliance with Phase 6B requirements, 3 representative scenarios were pre-registered before inference:

1. **Vulnerable Access-Control Scenario**:
   - `SCEN-SAAS_BILLING-INV-DETAILS-VULN-01`
   - Category: `API-BOLA-001` (Broken Object Level Authorization)
   - Application: `saas_billing`
   - Vulnerable Variant: `True`
2. **Vulnerable State / Business-Logic Scenario (Different Application & Category)**:
   - `SCEN-ECOMMERCE_ORDERS-ORD-REFUND-VULN-01`
   - Category: `API-STATE-001` (Order Workflow / State Transition Bypass)
   - Application: `ecommerce_orders`
   - Vulnerable Variant: `True`
3. **Negative-Control Scenario (Patched Access Control)**:
   - `SCEN-SAAS_BILLING-INV-DETAILS-PATCH-01`
   - Category: `API-BOLA-001`
   - Application: `saas_billing`
   - Vulnerable Variant: `False` (Patched negative control)

---

## 4. Track & Condition Matrix (Phase 6C)

Each of the 3 scenarios was evaluated across 4 frozen tracks and 2 runtime schema conditions:

- **Tracks**:
  - `TRACK_A`: Baseline (No RAG: zero target evidence, zero VAPT knowledge)
  - `TRACK_B`: Target-Evidence RAG (structural evidence pack only)
  - `TRACK_C`: VAPT Knowledge RAG (OWASP methodology pack only)
  - `TRACK_D`: Dual RAG (Target Evidence + VAPT Knowledge)
- **$I_1$ Conditions**:
  - `CONDITION 0` ($I_1=0$): Unconstrained prompt execution (`schema=None`)
  - `CONDITION 1` ($I_1=1$): Ollama native JSON schema constrained decoding (`schema=BairJsonObject.get_inference_schema()`)

**Total Live Invocations**: $3 \times 4 \times 2 = 24$ calls.

---

## 5. Complete 24-Call Execution Ledger

| Call # | Scenario ID | Track | $I_1$ | Status | Failure Category | Decision Reached | Latency | Causal Parity |
|---|---|---|---|---|---|---|---|---|
| 01 | `SAAS_BILLING-INV-DETAILS-VULN-01` | `TRACK_A` | 0 | FAIL | `SEMANTIC_GROUNDING_FAILURE` | None | 22,205 ms | N/A |
| 02 | `SAAS_BILLING-INV-DETAILS-VULN-01` | `TRACK_A` | 1 | FAIL | `SCHEMA_VALIDITY_FAILURE` | None | 23,703 ms | N/A |
| 03 | `SAAS_BILLING-INV-DETAILS-VULN-01` | `TRACK_B` | 0 | FAIL | `SEMANTIC_GROUNDING_FAILURE` | None | 21,212 ms | Matched |
| 04 | `SAAS_BILLING-INV-DETAILS-VULN-01` | `TRACK_B` | 1 | FAIL | `SEMANTIC_GROUNDING_FAILURE` | None | 22,124 ms | Matched |
| 05 | `SAAS_BILLING-INV-DETAILS-VULN-01` | `TRACK_C` | 0 | **VALID** | `VALID` | `NO_RELEVANT_FUNCTIONALITY` | 18,488 ms | N/A |
| 06 | `SAAS_BILLING-INV-DETAILS-VULN-01` | `TRACK_C` | 1 | **VALID** | `VALID` | `NO_RELEVANT_FUNCTIONALITY` | 19,101 ms | N/A |
| 07 | `SAAS_BILLING-INV-DETAILS-VULN-01` | `TRACK_D` | 0 | **VALID** | `VALID` | `NO_RELEVANT_FUNCTIONALITY` | 17,352 ms | **Byte-Identical to B** |
| 08 | `SAAS_BILLING-INV-DETAILS-VULN-01` | `TRACK_D` | 1 | **VALID** | `VALID` | `NO_RELEVANT_FUNCTIONALITY` | 19,166 ms | **Byte-Identical to B** |
| 09 | `ECOMMERCE_ORDERS-ORD-REFUND-VULN-01` | `TRACK_A` | 0 | FAIL | `SCHEMA_VALIDITY_FAILURE` | None | 19,258 ms | N/A |
| 10 | `ECOMMERCE_ORDERS-ORD-REFUND-VULN-01` | `TRACK_A` | 1 | FAIL | `SEMANTIC_GROUNDING_FAILURE` | None | 21,317 ms | N/A |
| 11 | `ECOMMERCE_ORDERS-ORD-REFUND-VULN-01` | `TRACK_B` | 0 | FAIL | `SEMANTIC_GROUNDING_FAILURE` | None | 20,333 ms | Matched |
| 12 | `ECOMMERCE_ORDERS-ORD-REFUND-VULN-01` | `TRACK_B` | 1 | FAIL | `SEMANTIC_GROUNDING_FAILURE` | None | 21,346 ms | Matched |
| 13 | `ECOMMERCE_ORDERS-ORD-REFUND-VULN-01` | `TRACK_C` | 0 | FAIL | `SCHEMA_VALIDITY_FAILURE` | None | 18,361 ms | N/A |
| 14 | `ECOMMERCE_ORDERS-ORD-REFUND-VULN-01` | `TRACK_C` | 1 | FAIL | `SEMANTIC_GROUNDING_FAILURE` | None | 21,313 ms | N/A |
| 15 | `ECOMMERCE_ORDERS-ORD-REFUND-VULN-01` | `TRACK_D` | 0 | FAIL | `SEMANTIC_GROUNDING_FAILURE` | None | 20,366 ms | **Byte-Identical to B** |
| 16 | `ECOMMERCE_ORDERS-ORD-REFUND-VULN-01` | `TRACK_D` | 1 | FAIL | `SEMANTIC_GROUNDING_FAILURE` | None | 21,330 ms | **Byte-Identical to B** |
| 17 | `SAAS_BILLING-INV-DETAILS-PATCH-01` | `TRACK_A` | 0 | FAIL | `SEMANTIC_GROUNDING_FAILURE` | None | 21,819 ms | N/A |
| 18 | `SAAS_BILLING-INV-DETAILS-PATCH-01` | `TRACK_A` | 1 | FAIL | `SEMANTIC_GROUNDING_FAILURE` | None | 21,612 ms | N/A |
| 19 | `SAAS_BILLING-INV-DETAILS-PATCH-01` | `TRACK_B` | 0 | FAIL | `SEMANTIC_GROUNDING_FAILURE` | None | 21,052 ms | Matched |
| 20 | `SAAS_BILLING-INV-DETAILS-PATCH-01` | `TRACK_B` | 1 | FAIL | `SEMANTIC_GROUNDING_FAILURE` | None | 22,057 ms | Matched |
| 21 | `SAAS_BILLING-INV-DETAILS-PATCH-01` | `TRACK_C` | 0 | **VALID** | `VALID` | `NO_RELEVANT_FUNCTIONALITY` | 18,997 ms | N/A |
| 22 | `SAAS_BILLING-INV-DETAILS-PATCH-01` | `TRACK_C` | 1 | **VALID** | `VALID` | `NO_RELEVANT_FUNCTIONALITY` | 19,232 ms | N/A |
| 23 | `SAAS_BILLING-INV-DETAILS-PATCH-01` | `TRACK_D` | 0 | **VALID** | `VALID` | `NO_RELEVANT_FUNCTIONALITY` | 16,415 ms | **Byte-Identical to B** |
| 24 | `SAAS_BILLING-INV-DETAILS-PATCH-01` | `TRACK_D` | 1 | **VALID** | `VALID` | `NO_RELEVANT_FUNCTIONALITY` | 19,462 ms | **Byte-Identical to B** |

---

## 6. Failure Breakdown & Diagnosis

The mutually exclusive failure categories across all 24 calls:

| Category | Count | Percentage | Diagnosis |
|---|---|---|---|
| `VALID` | 8 | 33.3% | Model emitted valid JSON conforming to BAIR schema; cited facts grounded in pack; reached decision layer. |
| `PARSER_FAILURE` | **0** | **0.0%** | **Completely eliminated.** Raw JSON decoded cleanly on every single call. |
| `MAX_TOKEN_TRUNCATION` | 0 | 0.0% | Zero token truncation observed (`num_predict=300` sufficient for JSON_BAIR format). |
| `RUNTIME_TRANSPORT_FAILURE` | 0 | 0.0% | Zero connection drops, timeouts, or HTTP failures. |
| `SCHEMA_VALIDITY_FAILURE` | 3 | 12.5% | Occurred in Calls #02, #09, #13. In each case, JSON syntax was valid, but the model's `falsification_plan` slot specified only disproving/refuting observations without specifying an affirmative observation that would support the hypothesis. Failed closed at Pydantic slot validation. |
| `SEMANTIC_GROUNDING_FAILURE` | 13 | 54.2% | Model emitted valid JSON conforming to BAIR schema, but cited non-existent or fabricated methodology IDs (e.g. `CHK-API-BOLA-001` or `CHK-001` in Tracks A/B where no VAPT pack is provided). Authoritative `KnowledgeGroundingValidator` failed closed as designed. |

---

## 7. Comparison: $I_1=0$ vs $I_1=1$ (Smoke Observation Only)

| Metric | Condition 0 ($I_1=0$, Unconstrained) | Condition 1 ($I_1=1$, Schema Constrained) |
|---|---|---|
| Total Invocations | 12 | 12 |
| Successful Parses | 12 / 12 (100%) | 12 / 12 (100%) |
| Valid Pipeline Executions | 4 / 12 (33.3%) | 4 / 12 (33.3%) |
| `SCHEMA_VALIDITY_FAILURE` | 2 / 12 (16.7%) | 1 / 12 (8.3%) |
| `SEMANTIC_GROUNDING_FAILURE` | 6 / 12 (50.0%) | 7 / 12 (58.3%) |
| Mean Latency | 19,655 ms | 20,980 ms |

> [!NOTE]
> $I_1=1$ schema-constrained decoding guarantees JSON structural adherence at the token sampler level, reducing schema syntax errors. However, neither $I_1=0$ nor $I_1=1$ alters semantic hallucination (citing absent methodology IDs in Tracks A and B), which is appropriately caught and blocked downstream by the authoritative grounding validator.

---

## 8. Safety & Integrity Invariants Verified

1. **Zero Retries**: Verified $\text{retry\_count} == 0$.
2. **Zero Semantic Repairs**: Verified $\text{repair\_count} == 0$.
3. **Strict Single-Call Rule**: Exactly 24 LLM calls executed across the 24 cells.
4. **Target-Evidence Causal Parity**:
   For every scenario, target evidence bytes extracted between `<untrusted_target_data>` tags in Track B and Track D were asserted byte-identical:
   - Scenario 1 (SAAS_BILLING vuln): Byte-Identical (`49a4...`)
   - Scenario 2 (ECOMMERCE_ORDERS vuln): Byte-Identical (`8cb1...`)
   - Scenario 3 (SAAS_BILLING patch): Byte-Identical (`49a4...`)
5. **Ground-Truth Isolation**: Zero ground-truth labels leaked into model prompts.
6. **M4.9 Historical Artifact**:
   `data/eval/m4_live_llm_benchmark_final.json` verified byte-for-byte unchanged:
   `459b9ec63c3a2dc760abde12ec196760f7e505fbab5317f0da0c46b32c5eaac7`.

---

## 9. Artifact Coordinates & Checksums

- **Live Smoke Result File**: `data/eval/m5_live_smoke.json`
- **Result File SHA-256**: `7ee8b6b2ec33eca0fcb8a3f0948d1f36b7e41877354ae4a64190f8e19c679b5e`
- **Checksum File**: `data/eval/m5_live_smoke.json.sha256`
- **Post-Run Git Status**: Clean working tree on master.

---

## 10. Phase 6 Completion Status

Phase 6 Limited Live Smoke Validation is **COMPLETE**.  
The repaired M5 contract and reasoning interface has demonstrated real model viability without protocol collision, without parser failure, and without modifying historical benchmark results.

Large-scale confirmatory benchmarking (84 scenarios, 336 calls) remains **STRICTLY STOPPED** pending formal authorization.
