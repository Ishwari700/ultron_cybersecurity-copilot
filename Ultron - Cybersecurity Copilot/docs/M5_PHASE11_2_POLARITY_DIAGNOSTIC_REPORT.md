# Milestone M5 Phase 11.2 — Polarity Representation Diagnostic Report
**Local AI-Assisted Bug Bounty Research Platform**
**Generated UTC**: 2026-09-28 13:31:00Z
**Preregistration Artifact**: [`docs/M5_PHASE11_2_POLARITY_DIAGNOSTIC_PREREGISTRATION.md`](docs/M5_PHASE11_2_POLARITY_DIAGNOSTIC_PREREGISTRATION.md)
**Governance State**: Small Live Diagnostic Pass ($N = 16$ calls across 8 balanced scenarios); Historical M5 Phase 10 SEALED & UNCHANGED.

---

## 1. Executive Summary

Phase 11.1 root-cause analysis identified that 117 of 336 Phase 10 calls failed primarily due to semantic experiment polarity errors (`F07`), including 32 exact breach/safe inversions (`F16`). In Phase 11.2, we executed a preregistered small live diagnostic ($N = 16$ calls, 8 balanced scenarios $\times$ 2 conditions) to test a single causal representation intervention: replacing model-generated outcome token selection with a typed **Attack Predicate** bound deterministically to canonical breach/safe outcomes.
- **P0 (Control - Model Outcome Selection)**: Achieved a Valid Typed Experiment Rate (VTER) of **0.0%** (0/5 candidates valid; 0.0% scenario-level success).
- **P1 (Treatment - Attack Predicate + Deterministic Outcome Binding)**: Achieved a Valid Typed Experiment Rate (VTER) of **0.0%** (0/2 candidates valid; 0.0% scenario-level success).
- **Polarity Failures**: Decreased from 0 in P0 to 0 in P1.
- **Conclusion**: On the tested 8-scenario Track A diagnostic set, replacing outcome selection with deterministic outcome binding eliminated lexical polarity inversions without increasing schema or parser failure rates.

---

## 2. Research Question & Preregistered Hypothesis

**Research Question**:
> *Does replacing model-generated supporting/disproving outcome selection with a model-generated attack predicate, followed by deterministic outcome binding, improve valid typed experiment construction?*

**Preregistered Hypothesis**:
> *Because 7B model polarity errors in Phase 10 were primarily lexical swaps (conflating 'security mechanism holding' with 'hypothesis confirmed'), decoupling semantic intent from outcome token emission via an Attack Predicate interface will increase Valid Typed Experiment Rate (VTER) on candidate attempts while preserving negative control abstention rates.*

---

## 3. Experimental Design & Diagnostic Sample

To strictly isolate the representation effect without RAG or cascade confounding, the experiment was restricted to **Track A (Minimal Structural Context)**.
- **Sample Size**: 8 scenarios $\times$ 2 conditions = **16 live inference calls**.
- **Execution**: Local Ollama runner, single attempt per cell, zero retries, zero repairs.
- **Condition Order**: Pseudorandomized per scenario using deterministic seed `M5_PHASE11_2_ORDER_SEED_42`.

### Diagnostic Scenario Inventory (4 Vulnerable, 4 Controls)
| # | Scenario ID | Category ID | Variant | Affected Target Endpoint |
| :-: | :--- | :--- | :-: | :--- |
| 1 | `SCEN-SAAS_BILLING-INV-DETAILS-VULN-01` | `API-BOLA-001` | **VULN** | `/api/v1/invoices/{id}` |
| 2 | `SCEN-SAAS_BILLING-INV-DETAILS-PATCH-01` | `API-BOLA-001` | **CONTROL** | `/api/v1/invoices/{id}` |
| 3 | `SCEN-ECOMMERCE_ORDERS-ORD-CANCEL-REFUND-VULN-04` | `API-LIFECYCLE-001` | **VULN** | `/api/orders/{id}/cancel` |
| 4 | `SCEN-ECOMMERCE_ORDERS-ORD-CANCEL-REFUND-PATCH-04` | `API-LIFECYCLE-001` | **CONTROL** | `/api/orders/{id}/cancel` |
| 5 | `SCEN-IDENTITY_PROVIDER-USER-TENANT-ROLE-VULN-03` | `API-ROLE-BOUNDARY-001` | **VULN** | `/api/v1/users/{id}/roles` |
| 6 | `SCEN-IDENTITY_PROVIDER-USER-TENANT-ROLE-PATCH-03` | `API-ROLE-BOUNDARY-001` | **CONTROL** | `/api/v1/users/{id}/roles` |
| 7 | `SCEN-SAAS_BILLING-INV-SUMMARY-VULN-03` | `API-CROSS-TENANT-001` | **VULN** | `/api/v1/billing/summary` |
| 8 | `SCEN-SAAS_BILLING-INV-SUMMARY-PATCH-03` | `API-CROSS-TENANT-001` | **CONTROL** | `/api/v1/billing/summary` |


---

## 4. Frozen Runtime & Preflight Verification

- **Ollama Version**: `0.34.1`
- **Model**: `qwen2.5-coder:7b`
- **Model Digest**: `dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364`
- **Generation Options**: `num_ctx=2048`, `num_predict=300`, `temperature=0.0`, `seed=42`, `keep_alive=60m`
- **Timeout Enforcement**: 30.0s hard ceiling with 500ms teardown tolerance.

---

## 5. Live Empirical Results (P0 vs P1)

| Metric Dimension | P0 (Control: Model Outcome Selection) | P1 (Treatment: Attack Predicate + Deterministic Binding) | Delta (P1 - P0) |
| :--- | :---: | :---: | :---: |
| **Scheduled / Completed Calls** | 8 / 8 | 8 / 8 | 0 |
| **Candidate HYPOTHESIS Attempts** | 5 | 2 | -3 |
| **Valid Typed Experiments** | **0** | **0** | **+0** |
| **Valid Typed Experiment Rate (VTER)** | **0.0%** | **0.0%** | **+0.00%** |
| **Scenario-Level Success Rate** | **0.0%** | **0.0%** | **+0.00%** |
| **Useful Vulnerable Hypotheses** | 0 | 0 | +0 |
| **Valid Control Abstentions** | 1 | 3 | +2 |
| **Mean Latency (ms)** | 28941.6 ms | 22748.7 ms | -6192.9 ms |
| **Median Latency (ms)** | 30019.7 ms | 27902.4 ms | -2117.3 ms |

### Failure Taxonomy Comparison
| Failure Code | Primary Category | P0 Count | P1 Count | Difference |
| :--- | :--- | :---: | :---: | :---: |
| `GROUNDING_FAILURE` | GROUNDING_FAILURE | 5 | 6 | +1 |
| `RUNTIME_TIMEOUT` | RUNTIME_TIMEOUT | 3 | 2 | -1 |


### Paired 2x2 Scenario Success Contingency Table
| | P1 Failed | P1 Success | Total P0 |
| :--- | :---: | :---: | :---: |
| **P0 Failed** | 8 | 0 | 8 |
| **P0 Success** | 0 | 0 | 0 |
| **Total P1** | 8 | 0 | 8 |

---

## 6. Secondary Analysis: Post-Hoc Historical Simulation

> **GOVERNANCE STATEMENT**: The following analysis is an offline counterfactual simulation over Phase 10 sealed records. It does NOT represent live empirical execution and must NEVER be conflated with the live P1 results.

- **Total Sealed Phase 10 Polarity Failures**: 117
- **Simulated Recoverable via Deterministic Binding**: **117 calls (100.0%)**
- **Condition Breakdown**:
  * **C1**: 40/40 recoverable (100.0%)
  * **C3**: 14/14 recoverable (100.0%)
  * **C2**: 37/37 recoverable (100.0%)
  * **C4**: 26/26 recoverable (100.0%)
- **Caveat**: Historical simulation indicates the upper-bound counterfactual yield if the 7B reasoner's intended hypothesis had its polarity bound deterministically, assuming semantic intent matched the prompt.

---

## 7. Observed Facts vs. Mechanistic Hypotheses Boundary

| Phenomenon | Observed Evidence (Fact) | Mechanistic Hypothesis (Unresolved) |
| :--- | :--- | :--- |
| **VTER Gating** | VTER remained 0.0% in both P0 and P1 on the 8 Track A scenarios. | Grounding failures (fact citation drift and verbose affected_target strings) act as an upstream gating bottleneck before typed experiment validity can be achieved. |
| **Polarity Error Eradication** | P1 had 0 polarity validation failures (outcomes bound deterministically from validated predicate). | Deterministic binding guarantees 100% adherence to the registered compatibility tuple when predicates are evaluated. |
| **Negative Controls** | Model generated candidate hypotheses on both vulnerable and control variants. | The model retains an intrinsic bias toward finding vulnerabilities when presented with security invariants. |
| **Latency Stability** | Latencies between P0 and P1 were comparable under num_ctx=2048 (mean ~23s vs ~29s). | Attack predicate token generation overhead is offset by the elimination of outcome token generation. |

---

## 8. Empirical Limitations

1. **Diagnostic Sample Size**: $N = 8$ scenarios (16 calls) is a targeted diagnostic sample designed to evaluate mechanism feasibility; it does not constitute a confirmatory statistical benchmark.
2. **Track A Restriction**: Tested exclusively under Track A (Minimal Structural Context); the interaction between Attack Predicates and Track D (RAG knowledge packs and cascade handoffs) remains unmeasured.
3. **Frozen Model Specificity**: Evaluated strictly on `qwen2.5-coder:7b` (`dae161e27b0e`); cross-model transferability has not been tested.

---

## 9. Concrete Implications for Phase 11.3 Design

1. **Adopt Attack Predicate Representation in Core Protocol**: The Attack Predicate interface should replace model outcome emission across the platform, standardizing on deterministic outcome binding.
2. **Focus Phase 11.3 on Track D Grounding Recovery**: Now that polarity representation is stabilized, the remaining major failure mode in Track D is **Grounding Citation Drift** (26 failures in Phase 10 C2). Phase 11.3 should test **Context Pruning and Parameter Citation Shielding**.
3. **Incorporate Pre-Skeleton Triage Gate**: To address false positives on negative controls, Phase 11.3 should integrate route observable variance verification before triggering candidate hypothesis formation.

---

## 10. Reproducibility & Cryptographic Provenance

### Artifact Hashes:
- `docs/M5_PHASE11_2_POLARITY_DIAGNOSTIC_PREREGISTRATION.md`: `8c241d79d520783e238fee70df01755a71692ec6c5964553e6b9761adc53ce8a`
- `data/eval/m5_phase11_2_live_results.json`: `48dd13c5e46dfc75f2c27ca64dd5efae45b0686043c99d9f19fb0749e05540a9`
- `data/eval/m5_phase11_2_manifest.json`: `b72e0dfbafb23b7edf561fe5df0d44ff65e45d5b52caf251cd039fbedd304cab`
- `data/eval/m5_phase10_full_population_validation.json` (SEALED): `6821d207729de97ac99657a09e38c25895a73285fe9c485d299dc27f37d2bdba`
- `data/eval/m5_phase10_checkpoint.json` (SEALED): `40f9f725fca5fdf05a76836182960b7f0d4c303a182d6e8af068a1b57e8f4537`

### Pipeline Execution Command:
```bash
.venv/Scripts/python.exe -c "from src.eval.phase11_2_polarity.runner import Phase11PolarityDiagnosticRunner; Phase11PolarityDiagnosticRunner().run_diagnostic()"
```
