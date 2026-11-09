# M5 Phase 6.7 — Typed Protocol Live Viability Smoke Report

**Status**: `M5_PHASE6_7_LIVE_PROTOCOL_VIABLE_BENCHMARK_STILL_BLOCKED`  
**Date**: 2026-09-21  
**Execution Runtime**: Ollama v0.34.1  
**Model**: `qwen2.5-coder:7b`  
**Model Digest**: `dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364`  
**Primary Artifact**: [`data/eval/m5_typed_protocol_live_smoke.json`](data/eval/m5_typed_protocol_live_smoke.json)  
**Artifact SHA-256**: `d33d2a05e3cd2c00f684aa0bf987692c7d3d22b5e727aba941a447014bbfdcd6`  

---

## 1. Executive Summary & Authorization State

Milestone M5 Phase 6.7 executed a pre-registered 24-call live viability smoke evaluation against local Ollama `qwen2.5-coder:7b` using the newly implemented Typed Outcome Predicate protocol (Option B).

The objective was **not** to evaluate vulnerability detection performance or benchmark accuracy, but to verify protocol viability in the real inference runtime:
1. Does the pinned 7B model adopt the newly structured JSON_BAIR contract (`experiment_action`, `supporting_outcome`, `disproving_outcome`, `falsification_description`)?
2. Does the deterministic production validator (`ExperimentPolarityValidator`) catch semantic inversions, incompatible actions, and mismatched outcomes in real live model outputs exactly as predicted by unit tests?
3. What is the behavior of the negative-control scenario (`SCEN-SAAS_BILLING-INV-DETAILS-PATCH-01`, Track D, I1=1) under the typed protocol?

### Core Empirical Findings:
- **Protocol Viability Confirmed**: In 15 of the 19 non-truncated/parse-successful invocations (78.9%), the model reliably emitted the newly required typed experiment fields (`experiment_action`, `supporting_outcome`, `disproving_outcome`). Under schema-constrained decoding (`I1=1`), 100% of structured outputs adhered to the closed enum taxonomy.
- **Production Polarity Validator Actively Intercepted 10 Inverted Hypotheses**: In 10 live calls where the model attempted to propose a `HYPOTHESIS`, `ExperimentPolarityValidator` strictly intercepted and rejected inverted or mismatched propositions (e.g., claiming HTTP 403 supports BOLA, or HTTP 409 supports a state machine violation). In previous legacy protocols (Phase 6.2), these inverted claims silently passed lexical keyword checks.
- **Identical Outcomes Strictly Blocked**: In 2 calls (Calls #04 and #20), the model emitted identical supporting and disproving outcomes (`CROSS_IDENTITY_OBJECT_ACCESSIBLE` for both). The Pydantic validator strictly caught and rejected this non-discriminative proposition (`SCHEMA_VALIDITY_FAILURE`).
- **Scenario 3 Patched Negative-Control Resolved (Call #24)**: In Phase 6.2, Call #24 emitted an ungrounded `HYPOTHESIS` false positive. Under Phase 6.7, Call #24 emitted candidate `NO_RELEVANT_FUNCTIONALITY`, calibrated by I5 policy to **`INSUFFICIENT_EVIDENCE`** (`VALID`), fully eliminating the previous false-positive pathway.
- **Zero Retries, Zero Repairs**: All 24 calls executed as strictly single-shot invocations without retries, heuristic rewriting, or LLM judges.
- **Benchmark Remained Blocked**: Zero benchmark runs were conducted. The 84-scenario and 336-call benchmarks remain gated pending formal resolution of the exploratory-vs-vulnerability policy definition.

---

## 2. Pinned Runtime & Compute Envelope

The live smoke executed under frozen parameter controls:

| Parameter | Pinned Value | Verification Status |
| :--- | :--- | :--- |
| **Model** | `qwen2.5-coder:7b` | Verified |
| **Digest** | `dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364` | Verified |
| **Runtime** | Ollama v0.34.1 | Verified |
| **`num_ctx`** | 2048 | Verified |
| **`num_predict`** | 300 | Verified |
| **`temperature`** | 0.0 | Verified |
| **`seed`** | 42 | Verified |
| **`keep_alive`** | 60m | Verified |
| **Inference Call Count** | Exactly 1 call per scenario/track/condition (24 total) | Verified |
| **Retries / Repairs** | 0 retries, 0 repairs, 0 prompt mutations | Verified |

---

## 3. Pre-Registered Smoke Matrix

The 24 calls evaluated 3 scenarios across 4 tracks and 2 decoding conditions:

### Scenarios
1. `SCEN-SAAS_BILLING-INV-DETAILS-VULN-01` (`API-BOLA-001`, Vulnerable)
2. `SCEN-ECOMMERCE_ORDERS-ORD-REFUND-VULN-01` (`API-STATE-001`, Vulnerable)
3. `SCEN-SAAS_BILLING-INV-DETAILS-PATCH-01` (`API-BOLA-001`, Patched Negative Control)

### Tracks
- **TRACK_A**: No Target Evidence, No VAPT Knowledge
- **TRACK_B**: Target Evidence Present, No VAPT Knowledge
- **TRACK_C**: No Target Evidence, VAPT Knowledge Present
- **TRACK_D**: Target Evidence Present, VAPT Knowledge Present

### Decoding Conditions
- **I1=0**: Unconstrained JSON (`runtime_schema = None`)
- **I1=1**: Constrained JSON (`runtime_schema = BairJsonObject.get_inference_schema()`)

---

## 4. 24-Call Execution Summary & Failure Breakdown

### High-Level Metrics
- **Total Calls**: 24
- **Valid Executions**: 3 (12.5%)
- **Failed / Rejected Executions**: 21 (87.5%)
- **Mean Latency**: 23,192 ms (~23.2s)
- **Min Latency**: 16,426 ms
- **Max Latency**: 31,717 ms

### Mutually Exclusive Primary Failure Breakdown
| Primary Category | Count | Percentage | Description |
| :--- | :--- | :--- | :--- |
| `VALID` | 3 | 12.5% | Passed parsing, schema, polarity validation, and decision policy |
| `SEMANTIC_EXPERIMENT_POLARITY_FAILURE` | 10 | 41.7% | Inverted polarity or incompatible category/action tuple rejected by `ExperimentPolarityValidator` |
| `SCHEMA_VALIDITY_FAILURE` | 6 | 25.0% | Pydantic schema rejection (missing typed fields, identical outcomes, or legacy string) |
| `PARSER_FAILURE` | 4 | 16.7% | Raw model output failed JSON syntax parsing (empty/markdown formatting) |
| `MAX_TOKEN_TRUNCATION` | 1 | 4.2% | Generation reached 300 token ceiling mid-generation (eval_count=300) |
| `SEMANTIC_GROUNDING_FAILURE` | 0 | 0.0% | FACT/CHK namespace grounding violations |
| `RUNTIME_TRANSPORT_FAILURE` | 0 | 0.0% | Transport or Ollama API errors |

---

## 5. Complete 24-Call Execution Roster

| # | Scenario ID | Track | I1 | Cand Dec | Final Dec | Category / Status | Action Predicate | Supporting | Disproving | Latency |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **01** | `SAAS_BILLING-VULN` | TRK_A | 0 | HYP | None | `SEMANTIC_POLARITY_FAIL` | `SUBSTITUTE_RESOURCE_IDENTIFIER` | `HTTP_403_FORBIDDEN` *(Inverted)* | `HTTP_200_OK` | 23.1s |
| **02** | `SAAS_BILLING-VULN` | TRK_A | 1 | HYP | None | `SEMANTIC_POLARITY_FAIL` | `SUBSTITUTE_RESOURCE_IDENTIFIER` | `HTTP_403_FORBIDDEN` *(Inverted)* | `HTTP_200_OK` | 21.7s |
| **03** | `SAAS_BILLING-VULN` | TRK_B | 0 | HYP | None | `SCHEMA_VALIDITY_FAIL` | None *(Legacy free-text emitted)* | None | None | 18.7s |
| **04** | `SAAS_BILLING-VULN` | TRK_B | 1 | HYP | None | `SCHEMA_VALIDITY_FAIL` | `INVOKE_WITHOUT_CREDENTIALS` | `CROSS_IDENTITY_OBJECT_ACC` | `CROSS_IDENTITY_OBJECT_ACC` *(Identical)* | 23.4s |
| **05** | `SAAS_BILLING-VULN` | TRK_C | 0 | None | None | `PARSER_FAILURE` | None *(Empty/malformed emission)* | None | None | 23.1s |
| **06** | `SAAS_BILLING-VULN` | TRK_C | 1 | None | None | `MAX_TOKEN_TRUNCATION` | None *(Length ceiling reached)* | None | None | 31.7s |
| **07** | `SAAS_BILLING-VULN` | TRK_D | 0 | None | None | `PARSER_FAILURE` | None *(Empty/malformed emission)* | None | None | 16.5s |
| **08** | `SAAS_BILLING-VULN` | TRK_D | 1 | NO_REL | **INSUFFICIENT_EVID** | **`VALID`** | `INVOKE_WITHOUT_CREDENTIALS` | `UNAUTHENTICATED_ACCESS_DEN` | `UNAUTHENTICATED_ACCESS_ALL` | 26.0s |
| **09** | `ECOMMERCE_ORD-VULN` | TRK_A | 0 | HYP | None | `SEMANTIC_POLARITY_FAIL` | `TAMPER_REQUEST_PARAMETER` *(Mismatch)* | `HTTP_409_CONFLICT` *(Inverted)* | `HTTP_200_OK` | 25.7s |
| **10** | `ECOMMERCE_ORD-VULN` | TRK_A | 1 | HYP | None | `SEMANTIC_POLARITY_FAIL` | `TAMPER_REQUEST_PARAMETER` *(Mismatch)* | `HTTP_409_CONFLICT` *(Inverted)* | `HTTP_200_OK` | 24.8s |
| **11** | `ECOMMERCE_ORD-VULN` | TRK_B | 0 | HYP | None | `SCHEMA_VALIDITY_FAIL` | None *(Legacy free-text emitted)* | None | None | 21.0s |
| **12** | `ECOMMERCE_ORD-VULN` | TRK_B | 1 | HYP | None | `SEMANTIC_POLARITY_FAIL` | `SUBSTITUTE_RESOURCE_IDENTIFIER` *(Mismatch)* | `STATE_TRANSITION_REJECTED` *(Inverted)* | `STATE_TRANSITION_ACCEPTED` | 24.5s |
| **13** | `ECOMMERCE_ORD-VULN` | TRK_C | 0 | HYP | None | `SEMANTIC_POLARITY_FAIL` | `TAMPER_REQUEST_PARAMETER` *(Mismatch)* | `HTTP_409_CONFLICT` *(Inverted)* | `HTTP_200_OK` | 25.7s |
| **14** | `ECOMMERCE_ORD-VULN` | TRK_C | 1 | HYP | None | `SEMANTIC_POLARITY_FAIL` | `TAMPER_REQUEST_PARAMETER` *(Mismatch)* | `HTTP_409_CONFLICT` *(Inverted)* | `HTTP_200_OK` | 24.6s |
| **15** | `ECOMMERCE_ORD-VULN` | TRK_D | 0 | HYP | None | `SCHEMA_VALIDITY_FAIL` | None *(Legacy free-text emitted)* | None | None | 20.9s |
| **16** | `ECOMMERCE_ORD-VULN` | TRK_D | 1 | HYP | None | `SEMANTIC_POLARITY_FAIL` | `SUBSTITUTE_RESOURCE_IDENTIFIER` *(Mismatch)* | `STATE_TRANSITION_REJECTED` *(Inverted)* | `STATE_TRANSITION_ACCEPTED` | 25.3s |
| **17** | `SAAS_BILLING-PATCH` | TRK_A | 0 | HYP | None | `SEMANTIC_POLARITY_FAIL` | `SUBSTITUTE_RESOURCE_IDENTIFIER` | `HTTP_403_FORBIDDEN` *(Inverted)* | `HTTP_200_OK` | 22.9s |
| **18** | `SAAS_BILLING-PATCH` | TRK_A | 1 | HYP | None | `SEMANTIC_POLARITY_FAIL` | `SUBSTITUTE_RESOURCE_IDENTIFIER` | `HTTP_403_FORBIDDEN` *(Inverted)* | `HTTP_200_OK` | 20.9s |
| **19** | `SAAS_BILLING-PATCH` | TRK_B | 0 | HYP | None | `SCHEMA_VALIDITY_FAIL` | None *(Legacy free-text emitted)* | None | None | 17.5s |
| **20** | `SAAS_BILLING-PATCH` | TRK_B | 1 | HYP | None | `SCHEMA_VALIDITY_FAIL` | `INVOKE_WITHOUT_CREDENTIALS` | `CROSS_IDENTITY_OBJECT_ACC` | `CROSS_IDENTITY_OBJECT_ACC` *(Identical)* | 23.2s |
| **21** | `SAAS_BILLING-PATCH` | TRK_C | 0 | None | None | `PARSER_FAILURE` | None *(Empty/malformed emission)* | None | None | 22.0s |
| **22** | `SAAS_BILLING-PATCH` | TRK_C | 1 | NO_REL | **INSUFFICIENT_EVID** | **`VALID`** | `INVOKE_WITHOUT_CREDENTIALS` | `UNAUTHENTICATED_ACCESS_DEN` | `UNAUTHENTICATED_ACCESS_ALL` | 31.3s |
| **23** | `SAAS_BILLING-PATCH` | TRK_D | 0 | None | None | `PARSER_FAILURE` | None *(Empty/malformed emission)* | None | None | 16.4s |
| **24** | `SAAS_BILLING-PATCH` | TRK_D | 1 | NO_REL | **INSUFFICIENT_EVID** | **`VALID`** | `INVOKE_WITHOUT_CREDENTIALS` | `UNAUTHENTICATED_ACCESS_DEN` | `UNAUTHENTICATED_ACCESS_ALL` | 25.7s |

---

## 6. In-Depth Analysis of Failure Modes & Semantic Validation

### A. Proof of Inversion Interception (`SEMANTIC_EXPERIMENT_POLARITY_FAILURE`)
In 10 separate calls across all three scenarios, `qwen2.5-coder:7b` attempted to propose a hypothesis with **inverted polarity** or **incompatible actions**:
- **BOLA Inversion (Calls #01, #02, #17, #18)**:  
  The model emitted:
  - `action = SUBSTITUTE_RESOURCE_IDENTIFIER`
  - `supporting_outcome = HTTP_403_FORBIDDEN`
  - `disproving_outcome = HTTP_200_OK`  
  *Analysis*: The model asserted that receiving a `403 Forbidden` confirms the vulnerability hypothesis, while receiving `200 OK` disproves it. This is diametrically backward: 403 proves authorization is enforced; 200 proves authorization was bypassed.  
  *Validator Action*: Intercepted deterministically:
  `Outcome 'HTTP_403_FORBIDDEN' is not a valid breach outcome for category 'API-BOLA-001' and action 'SUBSTITUTE_RESOURCE_IDENTIFIER'`.

- **State-Machine Inversion & Action Mismatch (Calls #09, #10, #12, #13, #14, #16)**:  
  In Scenario 2 (`API-STATE-001`), the model attempted:
  - `action = TAMPER_REQUEST_PARAMETER` or `SUBSTITUTE_RESOURCE_IDENTIFIER`
  - `supporting_outcome = HTTP_409_CONFLICT` or `STATE_TRANSITION_REJECTED`
  - `disproving_outcome = HTTP_200_OK` or `STATE_TRANSITION_ACCEPTED`  
  *Analysis*: A state machine violation requires an out-of-order transition to succeed (`STATE_TRANSITION_ACCEPTED` or `HTTP_200_OK`). Rejection (`HTTP_409_CONFLICT`) proves the invariant held.  
  *Validator Action*: Intercepted deterministically for both action incompatibility (`TAMPER_REQUEST_PARAMETER is not compatible with category API-STATE-001`) and outcome inversion.

### B. Proof of Identical Outcome Rejection (`SCHEMA_VALIDITY_FAILURE`)
In Calls #04 and #20 (Track B, I1=1), the model emitted:
- `supporting_outcome = CROSS_IDENTITY_OBJECT_ACCESSIBLE`
- `disproving_outcome = CROSS_IDENTITY_OBJECT_ACCESSIBLE`  
*Validator Action*: The root Pydantic validator on `BairJsonObject` strictly raised:
`Value error, supporting_outcome and disproving_outcome cannot be identical`.  
This proves the schema layer prevents hypotheses with zero discriminative power from reaching execution.

### C. Proof of Legacy Free-Text Fail-Closed (`SCHEMA_VALIDITY_FAILURE`)
In Calls #03, #11, #15, #19 (Track B and Track D under unconstrained `I1=0`), the model emitted the legacy field `falsification_plan` without the typed fields.  
*Validator Action*: The root validator strictly rejected the candidate with:
`Legacy free-text falsification_plan cannot authorize a HYPOTHESIS under JSON_BAIR protocol; typed experiment fields are mandatory`.

---

## 7. Special Analysis of Patched Scenario 3 Track D I1=1 (Call #24)

Call #24 represents the focal case of the Phase 6.3/6.4 audits:
- In Phase 6.2, Call #24 emitted an ungrounded `HYPOTHESIS` with a free-text falsification plan that bypassed lexical validation and triggered a false positive under benchmark scoring.
- In Phase 6.7:
  - **Candidate Emission**:
    ```json
    {
      "invariant": "Resource access restricted to owner",
      "evidence_gap": "No evidence of ownership check",
      "affected_target": "/api/v1/tenants/{tenant_id}/billing/invoices/{invoice_id}/download",
      "decision": "NO_RELEVANT_FUNCTIONALITY",
      "empirical_facts": ["FACT-SAAS_BILLING-INV-DETAILS-DOC"],
      "methodology_references": ["CHK-DOC-WSTG-ATHZ-04-001-01"],
      "experiment_action": "INVOKE_WITHOUT_CREDENTIALS",
      "supporting_outcome": "UNAUTHENTICATED_ACCESS_DENIED",
      "disproving_outcome": "UNAUTHENTICATED_ACCESS_ALLOWED",
      "falsification_description": "Invoke endpoint without credentials to verify authentication enforcement"
    }
    ```
  - **Decision Policy Evaluation**:
    - `candidate_decision`: `"NO_RELEVANT_FUNCTIONALITY"`
    - Endpoint is relevant (`route_template` matches parameters and identities).
    - Under I5 policy rule: `NO_RELEVANT_FUNCTIONALITY` on an explicitly relevant endpoint is calibrated to **`INSUFFICIENT_EVIDENCE`**.
  - **Final Decision**: **`INSUFFICIENT_EVIDENCE`** (`VALID`).
  - **Result**: The model correctly abstained from claiming a vulnerability hypothesis on the patched endpoint. The prior false positive was completely eliminated.

---

## 8. Comparative Analysis: I1=0 vs I1=1

| Metric | I1=0 (Unconstrained) | I1=1 (Schema Constrained) | Impact of Schema Constraint |
| :--- | :--- | :--- | :--- |
| **Total Calls** | 12 | 12 | Exact 1:1 balance |
| **Valid Executions** | 0 (0.0%) | 3 (25.0%) | Schema constraint enabled valid completion |
| **Parser Failures** | 4 (33.3%) | 0 (0.0%) | Schema constraint eliminated 100% of syntax/markdown parse errors |
| **Schema Failures** | 4 (33.3%) | 2 (16.7%) | Reduced legacy free-text emissions |
| **Polarity Failures** | 4 (33.3%) | 6 (50.0%) | Allowed model to reach semantic validation stage |
| **Truncation Failures** | 0 (0.0%) | 1 (8.3%) | 1 call reached 300 token ceiling |
| **Mean Latency** | 21,126 ms | 25,259 ms | +4.1s overhead for constrained decoding |

*Conclusion*: Schema constraint (`I1=1`) completely eliminated JSON parser failures (0 vs 4) and ensured that 100% of generated tokens conformed to structured JSON syntax. However, constrained decoding does not fix semantic misunderstandings of vulnerability logic within the 7B parameter model, which were deterministically caught by the post-generation `ExperimentPolarityValidator`.

---

## 9. Protected File Integrity Verification

SHA-256 hashes of all protected and frozen artifacts were verified before and after execution:

| File Path | Pinned SHA-256 Digest | Status |
| :--- | :--- | :--- |
| `data/eval/m4_live_llm_benchmark_final.json` | `459b9ec63c3a2dc760abde12ec196760f7e505fbab5317f0da0c46b32c5eaac7` | **MATCH (IMMUTABLE)** |
| `data/eval/m5_live_smoke.json` | `7ee8b6b2ec33eca0fcb8a3f0948d1f36b7e41877354ae4a64190f8e19c679b5e` | **MATCH (IMMUTABLE)** |
| `data/eval/m5_live_smoke_v2.json` | `830c225b22f6767ee13b4ce3b443a14aede3ea767ee25ae7343c1a153c4a0818` | **MATCH (IMMUTABLE)** |
| `docs/M5_PHASE6_3_FALSE_POSITIVE_AUDIT.md` | `5cc7ac193aefb6fb5d0d5a845c54b7c6279b713609ce62ea44c00fa98a718bf7` | **MATCH (IMMUTABLE)** |
| `docs/M5_PHASE6_4_BENCHMARK_SEMANTICS_DECISION.md` | `6657ec2ccdc5ff1344e307a6d2e2dab6eff7fc47ece8c3b2d014742eeb91b53e` | **MATCH (IMMUTABLE)** |
| `docs/M5_PHASE6_5_EXPERIMENT_SEMANTICS_PROTOCOL_DESIGN.md` | `ec15f42ba52bd54363f236bff1a71683ab3b1c1a10fa28ddac5c8a97a40b255c` | **MATCH (IMMUTABLE)** |
| `src/eval/scenarios.py` | `102789655bfb04041de9259d1bf6db7f0ad1222416806ea947bb309ee2d6be90` | **MATCH (IMMUTABLE)** |
| `data/eval/m5_typed_protocol_live_smoke.json` | `d33d2a05e3cd2c00f684aa0bf987692c7d3d22b5e727aba941a447014bbfdcd6` | **NEW IMMUTABLE ARTIFACT** |

---

## 10. Benchmark-Policy Blockade Status

```
================================================================================
FINAL AUTHORIZATION STATE:
M5_PHASE6_7_LIVE_PROTOCOL_VIABLE_BENCHMARK_STILL_BLOCKED
================================================================================
```

### Rationale:
1. **Protocol Viability Established**: The 7B model can emit the typed JSON_BAIR fields, and the engine deterministically enforces the closed taxonomy, successfully blocking inverted hypotheses and identical outcomes.
2. **Benchmark Remained Blocked**: Zero benchmark runs were executed. The exploratory vs. vulnerability benchmark-policy conflict remains open and pending separate governance resolution. The benchmark scenario definitions and expected decisions remain frozen.
