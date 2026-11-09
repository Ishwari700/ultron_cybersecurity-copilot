# Milestone M5 Phase 11.3: Grounding Recovery Diagnostic Preregistration

**Protocol Identifier**: `M5_PHASE11_3_GROUNDING_RECOVERY_PREREGISTRATION_V1`  
**Registration Date (UTC)**: 2026-09-28  
**Governance State**: PREREGISTERED PRIOR TO LIVE INFERENCE  
**Status**: ACTIVE & BINDING  

---

## 1. Context & Research Question

Phase 11.2 demonstrated that deterministic outcome binding derived from model-generated `attack_predicate` objects eliminated outcome polarity generation failures from the failure path (0 polarity failures in P1). However, live Valid Typed Experiment Rate (VTER) remained 0.0% due to an upstream gating failure: **Semantic Grounding Failure** (11/16 calls in Phase 11.2).

The 7B reasoner repeatedly failed grounding by:
1. Hallucinating fact IDs (`FACT-001`, `FACT-002` instead of canonical `FACT-...`).
2. Emitting verbose, conversational prose or invalid strings into `affected_target` (e.g. `"The target resource identifier is the billing invoice record."`, `"PARTITION P3"`, `"NO_RELEVANT_FUNCTIONALITY"`).

### Core Research Question:
> *Can deterministic grounding assistance (Fact Citation Shielding and Target Identifier Shielding) reduce grounding failures while preserving the Attack Predicate architecture and all existing safety/epistemic boundaries? Specifically, is grounding primarily a representation and selection problem that can be resolved by bounding candidate identifiers to canonical scenario structural evidence?*

---

## 2. Preregistered Hypotheses

- **Hypothesis H1 (Fact Citation Shielding - P2)**: Bounding `empirical_facts` selection to scenario-local `allowed_fact_ids` will eliminate hallucinated and out-of-vocabulary fact IDs (G1 and G2 failure codes).
- **Hypothesis H2 (Target Identifier Shielding - P3)**: Bounding `affected_target` selection to scenario-local `allowed_target_ids` will eliminate free-form prose and conversational target strings (G7 and G3 failure codes).
- **Hypothesis H3 (Yield Recovery - P3)**: Combining fact citation shielding and target identifier shielding will resolve the upstream grounding blocker, allowing candidate hypotheses to satisfy structural validation and recover non-zero Valid Typed Experiment Rate (VTER > 0%).

---

## 3. Experimental Conditions

The diagnostic evaluates three conditions in a within-subject factorial design:

### Condition P1 — Phase 11.2 Baseline (Control)
- **Model Emits**: `decision`, `invariant`, `evidence_gap`, `affected_target`, `empirical_facts`, `attack_predicate`, `falsification_description`, `methodology_references`.
- **Target Representation**: Free-form string (unconstrained).
- **Fact Representation**: Array of strings matching regex `^FACT-[A-Z0-9_-]+$`.
- **Deterministic Layer**: `experiment_action`, `supporting_outcome`, and `disproving_outcome` bound deterministically from `attack_predicate`.
- **Allowed Sets**: Not supplied in prompt or schema.

### Condition P2 — Fact Citation Shielding (Treatment 1)
- Identical to P1 except:
- **Allowed Evidence**: Prompt supplies `AVAILABLE_EVIDENCE_IDS: ["FACT-..."]`.
- **Fact Representation**: JSON schema constrains `empirical_facts.items.enum` strictly to `allowed_fact_ids`.
- **Target Representation**: Free-form string (identical to P1).
- **Model Choice**: The model selects zero or more IDs from the supplied list, or emits `[]` if abstaining.

### Condition P3 — Fact + Target Shielding (Treatment 2)
- Identical to P2 except:
- **Allowed Targets**: Prompt supplies `AVAILABLE_TARGET_IDENTIFIERS: ["EP-..."]`.
- **Target Representation**: JSON schema constrains `affected_target.enum` strictly to `allowed_target_ids`.
- **Fact Representation**: Bounded to `allowed_fact_ids` (identical to P2).
- **Model Choice**: The model selects one exact canonical endpoint identifier from `allowed_target_ids`. Free-form natural language prose is strictly rejected.

---

## 4. Balanced Diagnostic Dataset (8 Scenarios)

The diagnostic evaluates the identical 8 balanced benchmark scenarios from Phase 11.2 (4 vulnerable, 4 patched controls):

| # | Scenario ID | Category ID | Variant | Canonical Route |
| :-: | :--- | :--- | :-: | :--- |
| 1 | `SCEN-SAAS_BILLING-INV-DETAILS-VULN-01` | `API-BOLA-001` | **VULN** | `/api/v1/invoices/{id}` |
| 2 | `SCEN-SAAS_BILLING-INV-DETAILS-PATCH-01` | `API-BOLA-001` | **CONTROL** | `/api/v1/invoices/{id}` |
| 3 | `SCEN-ECOMMERCE_ORDERS-ORD-CANCEL-REFUND-VULN-04` | `API-LIFECYCLE-001` | **VULN** | `/api/v1/orders/{id}/refund` |
| 4 | `SCEN-ECOMMERCE_ORDERS-ORD-CANCEL-REFUND-PATCH-04` | `API-LIFECYCLE-001` | **CONTROL** | `/api/v1/orders/{id}/refund` |
| 5 | `SCEN-IDENTITY_PROVIDER-USER-TENANT-ROLE-VULN-03` | `API-ROLE-BOUNDARY-001` | **VULN** | `/api/v1/users/{id}/roles` |
| 6 | `SCEN-IDENTITY_PROVIDER-USER-TENANT-ROLE-PATCH-03` | `API-ROLE-BOUNDARY-001` | **CONTROL** | `/api/v1/users/{id}/roles` |
| 7 | `SCEN-SAAS_BILLING-INV-SUMMARY-VULN-03` | `API-CROSS-TENANT-001` | **VULN** | `/api/v1/invoices/{id}` |
| 8 | `SCEN-SAAS_BILLING-INV-SUMMARY-PATCH-03` | `API-CROSS-TENANT-001` | **CONTROL** | `/api/v1/invoices/{id}` |

Total call count: 8 scenarios $\times$ 3 conditions = **24 live inference calls**.

---

## 5. Frozen Runtime Configuration

- **Ollama Version**: `v0.34.1`
- **Model**: `qwen2.5-coder:7b`
- **Model Digest**: `dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364`
- **Context Window (`num_ctx`)**: `2048`
- **Max Generation (`num_predict`)**: `300`
- **Sampling Temperature**: `0.0`
- **Deterministic Seed**: `42`
- **Keep-Alive**: `60m`
- **Timeout Ceiling**: 30.0s hard cutoff with 500ms teardown tolerance.
- **Execution Protocol**: Single attempt per cell. Zero retries, zero repairs, zero fallbacks.

---

## 6. Deterministic Execution Ordering

Calls are scheduled per scenario and pseudorandomly shuffled using deterministic order seed `M5_PHASE11_3_ORDER_SEED_42`:
```
seed_payload = f"M5_PHASE11_3_ORDER_SEED_42:{scenario_id}"
rng = Random(int(sha256(seed_payload)[:16], 16))
conds = ["P1", "P2", "P3"]
rng.shuffle(conds)
```
The exact 24-call sequence is preregistered and executed sequentially without post-hoc reordering.

---

## 7. Metrics & Deterministic Failure Taxonomy

### Primary Diagnostic Metric:
$$\text{VTER} = \frac{\text{Valid Typed Experiment Proposals}}{\text{Candidate HYPOTHESIS Attempts}}$$

### Grounding Success Metric:
$$\text{Grounding Success Rate} = \frac{\text{Grounded Candidate Outputs}}{\text{Candidate Outputs Reaching Grounding Validation}}$$

### Grounding Failure Taxonomy (G1-G8, G99):
- `G1 = FACT_ID_INVALID`: Cited fact does not match regex `^FACT-[A-Za-z0-9_\-]+$`.
- `G2 = FACT_ID_NOT_IN_ALLOWED_SET`: Cited fact matches syntax but does not exist in `allowed_fact_ids`.
- `G3 = TARGET_ID_INVALID`: Target does not match valid identifier syntax.
- `G4 = TARGET_ID_NOT_IN_ALLOWED_SET`: Target is a valid identifier syntax but not in `allowed_target_ids`.
- `G5 = TARGET_NOT_STRUCTURALLY_GROUNDED`: Target identifier not found anywhere in Channel A structural pack.
- `G6 = FACT_TARGET_CROSS_MISMATCH`: Cited facts do not belong to the target endpoint envelope.
- `G7 = FREE_FORM_TARGET_REJECTED`: `affected_target` contains conversational prose, sentence punctuation, or non-target phrases.
- `G8 = OTHER_GROUNDING_FAILURE`: Missing target facts on HYPOTHESIS decision or epistemic tier confusion.
- `G99 = UNRESOLVED`: Fail-safe unclassified grounding failure.

---

## 8. Ground-Truth Firewall

- The model receives zero ground-truth labels, expected decisions, scoring markers, or variant suffixes.
- `allowed_fact_ids` and `allowed_target_ids` are constructed strictly from neutral structural evidence (`LosslessStructuralPack`).
- Both vulnerable and patched variants receive identical neutral OpenAPI specifications and neutral allowed sets.

---

## 9. Preregistered Stopping Rules

Live execution will immediately STOP if:
1. P1 protocol diverges from Phase 11.2 specifications.
2. An allowed set contains ground-truth tokens or reveals variant status.
3. Model digest differs from `dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364`.
4. Any external HTTP egress is detected.
5. Historical benchmark artifact digests differ from sealed references.

---

## 10. Cryptographic Provenance Baseline

- `data/eval/m5_phase10_full_population_validation.json` (SEALED): `6821d207729de97ac99657a09e38c25895a73285fe9c485d299dc27f37d2bdba`
- `data/eval/m5_phase10_checkpoint.json` (SEALED): `40f9f725fca5fdf05a76836182960b7f0d4c303a182d6e8af068a1b57e8f4537`
- `data/eval/m5_phase11_2_live_results.json`: `48dd13c5e46dfc75f2c27ca64dd5efae45b0686043c99d9f19fb0749e05540a9`
- `data/eval/m5_phase11_2_manifest.json`: `b72e0dfbafb23b7edf561fe5df0d44ff65e45d5b52caf251cd039fbedd304cab`
- `docs/M5_PHASE11_2_POLARITY_DIAGNOSTIC_REPORT.md`: `ec46f5eff4780af67c725e5d9e93370f54a2d122ed94297f5b78b7a2f29f8369`

---

## 11. Execution Command

```bash
.venv/Scripts/python.exe -c "from src.eval.phase11_3_grounding.runner import Phase11GroundingDiagnosticRunner; Phase11GroundingDiagnosticRunner().run_diagnostic()"
```
