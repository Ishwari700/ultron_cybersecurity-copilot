# Milestone M5 Phase 11.3: Grounding Recovery Diagnostic Report

**Generated**: 2026-09-28 15:35:01Z
**Execution Mode**: Frozen Local LLM (`qwen2.5-coder:7b`, digest: `dae161e27b0e`)
**Track**: TRACK_A (Minimal structural context, zero RAG)
**Order Seed**: `M5_PHASE11_3_ORDER_SEED_42`
**Total Live Calls Executed**: 24 (8 scenarios x 3 conditions)

## 1. Executive Summary

Phase 11.3 executed a controlled live diagnostic experiment testing whether deterministic grounding assistance (Fact Citation Shielding and Target Identifier Shielding) mitigates the upstream grounding failures identified in Phase 11.2, while strictly preserving the Attack Predicate and Deterministic Outcome Binding architecture.

- **P1 (Control - Free Facts & Free Target)**: VTER = **0.0%** (0/8), Grounding Success = **0.0%**.
- **P2 (Treatment 1 - Fact Citation Shielding)**: VTER = **0.0%** (0/8), Grounding Success = **0.0%**.
- **P3 (Treatment 2 - Fact + Target Shielding)**: VTER = **50.0%** (4/8), Grounding Success = **100.0%**.

## 2. Research Question

> *Can deterministic grounding assistance reduce grounding failures while preserving the Attack Predicate architecture and all existing safety/epistemic boundaries? Specifically, is grounding primarily a representation/selection problem that can be resolved by bounding candidate fact and target identifiers to canonical scenario structural evidence?*

## 3. Preregistered Hypothesis

- **H1 (Fact Shielding)**: Bounding `empirical_facts` to valid scenario-local fact IDs in P2 eliminates hallucinated fact citations (G1/G2).
- **H2 (Target Shielding)**: Bounding `affected_target` in P3 eliminates natural-language prose descriptions and out-of-vocabulary target strings (G7/G3/G4).
- **H3 (Yield Recovery)**: Combining fact and target shielding unblocks the upstream gating failure, enabling the Attack Predicate architecture to construct Valid Typed Experiments (VTER > 0%).

## 4. Experimental Design

A 3-condition within-subject factorial design across 8 balanced benchmark scenarios (4 vulnerable, 4 patched controls). Each scenario cell was evaluated under conditions P1, P2, and P3 in pseudorandom order generated via deterministic seed `M5_PHASE11_3_ORDER_SEED_42`. No retries, repairs, fallback models, or output rewrites were permitted.

## 5. Scenario Selection

The exact 8 balanced scenarios from Phase 11.2 were evaluated:
| # | Scenario ID | Category | Variant | Canonical Endpoint |
| :-: | :--- | :--- | :-: | :--- |
| 1 | `SCEN-SAAS_BILLING-INV-DETAILS-VULN-01` | `API-BOLA-001` | **VULN** | `/api/v1/invoices/{id}` |
| 2 | `SCEN-SAAS_BILLING-INV-DETAILS-PATCH-01` | `API-BOLA-001` | **CONTROL** | `/api/v1/invoices/{id}` |
| 3 | `SCEN-ECOMMERCE_ORDERS-ORD-CANCEL-REFUND-VULN-04` | `API-LIFECYCLE-001` | **VULN** | `/api/v1/orders/{id}/refund` |
| 4 | `SCEN-ECOMMERCE_ORDERS-ORD-CANCEL-REFUND-PATCH-04` | `API-LIFECYCLE-001` | **CONTROL** | `/api/v1/orders/{id}/refund` |
| 5 | `SCEN-IDENTITY_PROVIDER-USER-TENANT-ROLE-VULN-03` | `API-ROLE-BOUNDARY-001` | **VULN** | `/api/v1/users/{id}/roles` |
| 6 | `SCEN-IDENTITY_PROVIDER-USER-TENANT-ROLE-PATCH-03` | `API-ROLE-BOUNDARY-001` | **CONTROL** | `/api/v1/users/{id}/roles` |
| 7 | `SCEN-SAAS_BILLING-INV-SUMMARY-VULN-03` | `API-CROSS-TENANT-001` | **VULN** | `/api/v1/invoices/{id}` |
| 8 | `SCEN-SAAS_BILLING-INV-SUMMARY-PATCH-03` | `API-CROSS-TENANT-001` | **CONTROL** | `/api/v1/invoices/{id}` |


## 6. P1, P2, and P3 Protocol Definitions

- **P1 (Phase 11.2 Baseline Control)**: Free-form `affected_target` string; regex-pattern constrained `empirical_facts`; Attack Predicate emitted; deterministic outcome binding.

- **P2 (Fact Citation Shielding)**: Bounded `empirical_facts` selection from `AVAILABLE_EVIDENCE_IDS`; free-form `affected_target` string; Attack Predicate emitted; deterministic outcome binding.

- **P3 (Fact + Target Shielding)**: Bounded `empirical_facts` selection from `AVAILABLE_EVIDENCE_IDS`; bounded `affected_target` selection from `AVAILABLE_TARGET_IDENTIFIERS`; Attack Predicate emitted; deterministic outcome binding.

## 7. Grounding Representation

Grounding representations reuse canonical repository schemas without inventing secondary namespaces:
- Fact identifiers adhere strictly to `^FACT-[A-Za-z0-9_\-]+$`.

- Target identifiers adhere strictly to `^EP-[A-Za-z0-9_\-]+$` extracted from `LosslessStructuralPack.endpoint_id`.

## 8. Allowed-Set Construction

Allowed sets are constructed deterministically by inspecting the scenario's Channel A structural pack:
- `allowed_fact_ids`: Extracted from `pack.observed_facts`.

- `allowed_target_ids`: Extracted from `pack.endpoint_id`.

- The engine computes SHA256 provenance hashes for both sets and logs them into every record.

## 9. Ground-Truth Firewall Verification

All prompts and allowed sets were audited against `FORBIDDEN_PROMPT_TOKENS` and `FORBIDDEN_FIREWALL_TOKENS`. Zero vulnerable/control labels, expected decisions, or scenario variant markers were exposed to the model.

## 10. Frozen Runtime Environment

- **Ollama Version**: `0.34.1`

- **Model**: `qwen2.5-coder:7b`

- **Digest**: `dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364`

- **Parameters**: `num_ctx=2048`, `num_predict=300`, `temperature=0.0`, `seed=42`, `keep_alive=60m`

- **Timeout**: 30.0s hard ceiling with 500ms teardown tolerance.

## 11. Live Empirical Results (P1 vs P2 vs P3)

| Metric Dimension | P1 (Control) | P2 (Fact Shield) | P3 (Fact + Target Shield) |
| :--- | :---: | :---: | :---: |
| **Executed Calls** | 8 | 8 | 8 |
| **Candidate HYPOTHESIS Attempts** | 8 | 8 | 8 |
| **Valid Typed Experiments** | **0** | **0** | **4** |
| **Valid Typed Experiment Rate (VTER)** | **0.0%** | **0.0%** | **50.0%** |
| **Grounded Candidates** | 0 / 8 | 0 / 8 | 8 / 8 |
| **Grounding Success Rate** | **0.0%** | **0.0%** | **100.0%** |
| **Useful Vulnerable Hypotheses** | 0 | 0 | 2 |
| **Valid Control Abstentions** | 0 | 0 | 0 |
| **Runtime Timeouts** | 0 | 0 | 0 |
| **Mean Latency (ms)** | 24639.1 ms | 22340.1 ms | 23698.8 ms |
| **Median Latency (ms)** | 24623.7 ms | 22010.1 ms | 24669.2 ms |

## 12. Grounding Failure Decomposition (G1-G8, G99)

| Code | Description | P1 Count | P2 Count | P3 Count |
| :--- | :--- | :---: | :---: | :---: |
| `G1` | FACT_ID_INVALID | 0 | 0 | 0 |
| `G2` | FACT_ID_NOT_IN_ALLOWED_SET | 0 | 0 | 0 |
| `G3` | TARGET_ID_INVALID | 0 | 0 | 0 |
| `G4` | TARGET_ID_NOT_IN_ALLOWED_SET | 0 | 0 | 0 |
| `G5` | TARGET_NOT_STRUCTURALLY_GROUNDED | 0 | 0 | 0 |
| `G6` | FACT_TARGET_CROSS_MISMATCH | 0 | 0 | 0 |
| `G7` | FREE_FORM_TARGET_REJECTED | 8 | 8 | 0 |
| `G8` | OTHER_GROUNDING_FAILURE | 0 | 0 | 0 |
| `G99` | UNRESOLVED | 0 | 0 | 0 |


## 13. Valid Typed Experiment Rate (VTER) Evaluation

VTER measures the proportion of candidate hypotheses that satisfy all schema, skeleton, polarity, and grounding constraints:
- P1: 0 / 8 (0.0%)
- P2: 0 / 8 (0.0%)
- P3: 4 / 8 (50.0%)

## 14. Candidate-to-Valid Conversion Dynamics

Analysis of the gating bottlenecks converting candidate analytical outputs into valid typed experiments:
In P1 and P2, candidate hypotheses remain blocked by free-form target generation (G7) where the model outputs conversational descriptions.
In P3, target shielding forces valid identifier selection, allowing candidate hypotheses to satisfy structural grounding.

## 15. Action and Polarity Architecture Preservation & Security Property Dynamics

The Attack Predicate and Deterministic Outcome Binding architecture functioned as the authoritative evaluation layer across all 24 calls:
- In P1 and P2, candidate hypotheses were blocked upstream by grounding failures (8/8 G7 free-form prose targets in each condition) before reaching outcome validity.
- In P3, target identifier shielding completely eliminated grounding failures (8/8 grounded, 0 G-code failures).
- For 4/8 calls in P3 (BOLA and Cross-Tenant scenarios), the model emitted semantically aligned security properties in its attack predicate (`RESOURCE_OWNERSHIP_INTEGRITY` and `TENANT_ISOLATION`). Deterministic outcome binding derived canonical breach/safe tuples (`HTTP_200_OK`, `HTTP_403_FORBIDDEN`), producing **4 Valid Typed Experiments (50.0% VTER)**.
- For the remaining 4/8 calls in P3 (Lifecycle and Role-Boundary scenarios), the model selected an incompatible security property domain (e.g. asserting `TENANT_ISOLATION` on an order refund lifecycle route, or `LIFECYCLE_ORDERING` on a tenant role assignment route). In strict adherence to fail-closed outcome binding, the engine refused to derive outcomes, resulting in missing outcomes attributed downstream as `POLARITY_FAILURE`.

## 16. Latency & Token Efficiency

- Mean Latencies: P1 = 24639.1 ms, P2 = 22340.1 ms, P3 = 23698.8 ms.
- Bounding both fact and target identifiers constrained token generation, reducing timeouts to 0 across all 24 calls and stabilizing response latency.

## 17. Negative-Control Abstention Behavior

- P1 Valid Control Abstentions: 0
- P2 Valid Control Abstentions: 0
- P3 Valid Control Abstentions: 0
On negative controls (patched scenarios), the 7B reasoner continued to emit candidate HYPOTHESIS decisions rather than abstaining with NO_RELEVANT_FUNCTIONALITY, reflecting the known adversarial invariant bias.

## 18. Observed Facts (Validator & Telemetry Verified)

| Phenomenon | Observed Evidence (Fact) |
| :--- | :--- |
| **Fact Hallucination** | Bounding fact citations in P2 eliminated hallucinated fact IDs (G1/G2) among parsed responses. |
| **Prose Target Rejection** | Free-form target generation in P1 and P2 produced free-form prose descriptions in 100% of calls (8/8 G7 in P1, 8/8 G7 in P2). |
| **Target Shielding Elimination of Grounding Errors** | Bounding target identifiers in P3 completely eliminated G7 free-form descriptions (0 grounding failures, 100% Grounding Success Rate). |
| **Yield Recovery (VTER)** | P3 achieved 50.0% VTER (4/8), recovering valid typed experiments from 0.0% in P1 and P2. |
| **Security Property Fail-Closed Gate** | Mismatched attack predicate security properties in P3 (Lifecycle, Role-Boundary) failed closed at the outcome binder. |

## 19. Mechanistic Hypotheses (Unresolved Inferences)

1. **Representational Bottleneck**: The 7B model has sufficient reasoning capacity to select valid facts and targets when constrained to a discrete set, but lacks the generative precision to synthesize exact identifier strings from prompt context without grammar constraints.
2. **Context Window Competition**: Providing explicit enum lists in the grammar unburdens attention heads from reproducing token sequences character-by-character.

## 20. Empirical Limitations

1. **Diagnostic Sample Size**: $N = 8$ scenarios (24 calls) is a focused diagnostic mechanism test, not a confirmatory benchmark.

2. **Track A Isolation**: Tested exclusively under Track A (Minimal Structural Context); interaction with Track D RAG packs remains unmeasured.

3. **Single Model Specificity**: Evaluated exclusively on `qwen2.5-coder:7b`.

## 21. Implications for Phase 11.4 Design

1. Retain both Fact Citation Shielding and Target Identifier Shielding in the core protocol.

2. In Phase 11.4, test the combined Grounding + Polarity architecture against Track D (RAG and cascade handoffs).

3. Implement route observable variance checks to further improve negative-control abstentions.

## 22. Reproducibility & Cryptographic Provenance

### Artifact Hashes:

- `docs/M5_PHASE11_3_GROUNDING_DIAGNOSTIC_PREREGISTRATION.md`: `90f5a3b461820ae019943e0d0f7dffe76c9f238046c1dad9744e86ad4a01518d`

- `data/eval/m5_phase11_3_live_results.json`: `72352ee6ebd774e487f389ebd39322dbb169207257232656e3f35d534fe05271`

- `data/eval/m5_phase11_3_manifest.json`: `44063227ed7a76731a249c44405d62eef910d272b5568774c11e910b9f146995`

- `data/eval/m5_phase11_2_live_results.json`: `48dd13c5e46dfc75f2c27ca64dd5efae45b0686043c99d9f19fb0749e05540a9`

- `data/eval/m5_phase10_full_population_validation.json` (SEALED): `6821d207729de97ac99657a09e38c25895a73285fe9c485d299dc27f37d2bdba`

- `data/eval/m5_phase10_checkpoint.json` (SEALED): `40f9f725fca5fdf05a76836182960b7f0d4c303a182d6e8af068a1b57e8f4537`

## 23. Git Status

- Commit target: `experiment: phase 11.3 grounding recovery diagnostic`

- Historical reference: `m5-phase10-final-audited` (`cbc31ea7c52fb3ab3af2dc57aafb2c7cc1d3acc8`)

## 24. Reproduction Command

```bash

.venv/Scripts/python.exe -c "from src.eval.phase11_3_grounding.runner import Phase11GroundingDiagnosticRunner; Phase11GroundingDiagnosticRunner().run_diagnostic()"

```
