# Phase 11.5: Full-Population Evidence-Representation Validation Report
**Experiment Version**: 11.5.0  
**Git Commit**: `518b868e35e1f6f599390aaf5a5ba417e9eb99d8`  
**Execution Timestamp**: 2026-09-18 19:04:17 UTC  
**Official Manifest SHA-256**: `b2b85a672124acf21066a257d8c7f5093000368b224ee013c02574c96a0ae707`  
**Frozen Trace Set SHA-256**: `e4658d7dcfc1a6138337bbb2369dbe93d3d7d39da001c1078c67f92411869e19`  
**Final Classification**: **`SUPPORTED_FOR_ARCHITECTURAL_REVIEW`**  

## Section A: Executive Summary
Phase 11.5 evaluated whether adding typed, observable interaction-level evidence to canonical evidence improves grounded useful security-hypothesis generation across the ENTIRE official 84-scenario benchmark population (`data/benchmarks/m1_5_frozen_manifest.json`) under strictly frozen 7B inference conditions (`qwen2.5-coder:7b`, seed=42, temp=0.0, num_ctx=4096).

Across all 36 vulnerable scenarios, useful hypothesis yield increased from **1/36 (2.8%)** in Condition A (Baseline Canonical) to **36/36 (100.0%)** in Condition B (Enriched Observable), representing an absolute gain of **+97.2%** (95% CI: [91.8%, 102.6%], exact McNemar p = 5.82e-11).

Across the 48 controls:
- **Primary Raw-Population View**: True Negative Rate was **97.9%** (47/48) in Condition A and **95.8%** (46/48) in Condition B, with 2 false positives: 1 caused by a verified benchmark-oracle contradiction (`SCEN-ECOMMERCE_ORDERS-ORD-PAY-PATCH-03`) and 1 on a public negative control (`SCEN-IOT_FLEET_MGMT-NEG-01`).
- **Oracle-Clean Sensitivity View**: True Negative Rate was **97.9%** (46/47) in Condition B with **1 false positive** on `SCEN-IOT_FLEET_MGMT-NEG-01` (where anonymous access to a SYSTEM-owned public catalog was tagged as cross-identity relational evidence).
- Grounding acceptance remained strictly 100% (`UNGROUNDED_ACCEPTED = 0`).
- Scored decision reproducibility across 12 declared scenarios repeated twice was **100.0%**.

## Section B: Frozen Assets and Trace Integrity
All benchmark inputs and architecture components remained 100% frozen throughout execution:

- `data/benchmarks/m1_5_frozen_manifest.json` SHA-256: `b2b85a672124acf21066a257d8c7f5093000368b224ee013c02574c96a0ae707` (VERIFIED)
- Model: `qwen2.5-coder:7b` pinned digest: `dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364` (VERIFIED)
- Production modules (`LosslessStructuralPack v2.0.0`, `StructuralDiffEngine`, `ContextBuilder`, `Gate`, `Router`): UNTOUCHED
- Number of frozen raw interaction traces: **84**
- Trace Set SHA-256: `e4658d7dcfc1a6138337bbb2369dbe93d3d7d39da001c1078c67f92411869e19`
- Trace Hash Equality: `TRACE_HASH_A == TRACE_HASH_B` verified for all 84 scenario pairs (0 mismatches)

## Section C: Population Specification
Total scenarios evaluated: **84** (processed in exact official manifest order)

| Dimension | Vulnerable | Control (Matched) | Control (Negative) | Total |
| :--- | :--- | :--- | :--- | :--- |
| `saas_billing` | 6 | 6 | 2 | 14 |
| `ecommerce_orders` | 6 | 6 | 2 | 14 |
| `identity_provider` | 6 | 6 | 2 | 14 |
| `document_collaboration` | 6 | 6 | 2 | 14 |
| `healthcare_portal` | 6 | 6 | 2 | 14 |
| `iot_fleet_mgmt` | 6 | 6 | 2 | 14 |
| **Total** | **36** | **36** | **12** | **84** |

## Section D: Trace Freezing and Verification
Exactly one raw interaction trace per scenario was pre-captured and frozen before model inference. Both Condition A and Condition B consumed the exact same trace.

## Section E: Ground-Truth Leakage Audit
Static and runtime assertions audited all traces, canonical evidence, enriched evidence, context builder packets, and prompts for forbidden keys:
`['category', 'category_id', 'designation', 'expected_decision', 'gold_category', 'gold_parameter', 'ground_truth', 'ground_truth_vulnerable', 'hidden_label', 'is_vulnerable', 'scorer_label', 'vulnerability_category', 'vulnerable_variant']`

- `NO_GROUND_TRUTH_LEAKAGE = TRUE`
- Leaked keys detected: **0**

## Section F: Secret Audit
All credential fields (`Authorization`, `Bearer`, `Cookie`, tokens, API keys) were scanned across all 84 traces and evidence representations.

- `SECRET_LEAK_COUNT = 0` (All bearer tokens typed-quarantined and redacted as `Bearer [REDACTED]`)

## Section G: Evidence Transformation and Fact Preservation
The enrichment interface strictly obeyed: `enrich(canonical_evidence, raw_interaction_trace, provenance)`.

- Added fact count per scenario: **2** (`FACT-OBSERVED-INTERACTION-01`, `FACT-DERIVED-RELATION-01`)
- Fact preservation: `BASE_FACTS ⊆ ENRICHED_FACTS`
- `REMOVED_FACTS = 0`
- `MODIFIED_EXISTING_FACTS = 0`

## Section H: Control Oracle Audit
All 48 control scenarios were audited against `SyntheticApp` runtime behavior:

- **Consistent Controls**: 47/48 (35 matched controls rejected with 403/400 + 12 public negative controls)
- **Oracle Contradictions**: 1/48 (`SCEN-ECOMMERCE_ORDERS-ORD-PAY-PATCH-03`)
  - Route: `POST /api/v1/orders/ORD-001/pay`
  - Observed Behavior: `SyntheticApp` returned HTTP 200 with payment processed for caller `user_b` targeting order owned by `user_a` without authorization validation.
  - Outcome: The model in Condition B faithfully detected this cross-identity payment vulnerability exposed by the simulator, causing a raw-population false positive against the official non-vulnerable gold label.

## Section I & J: Primary Benchmark Results

### Primary Raw-Population View (All 48 Controls Included)

| Metric | Condition A (Baseline) | Condition B (Enriched) | Delta |
| :--- | :--- | :--- | :--- |
| Useful Hypotheses (Vuln) | 1/36 (2.8%) | 36/36 (100.0%) | +35 (+97.2%) |
| Vulnerable Recall | 2.8% | 100.0% | +97.2% |
| False Positives (Controls) | 1/48 | 2/48 | +1 |
| True Negative Rate (TNR) | 97.9% | 95.8% | -2.1% |
| Precision | 50.0% | 94.7% | N/A |
| F1 Score | 5.3% | 97.3% | N/A |
| Median Latency | 7.52s | 8.67s | +1.15s |
| Mean Prompt Tokens | 304.2 | 472.0 | +167.8 |

### Oracle-Clean Sensitivity View (Oracle-Consistent Controls Only, N=47)

| Metric | Condition A (Baseline) | Condition B (Enriched) | Delta |
| :--- | :--- | :--- | :--- |
| Useful Hypotheses (Vuln) | 1/36 (2.8%) | 36/36 (100.0%) | +35 (+97.2%) |
| False Positives (Clean Controls) | 1/47 | 1/47 | 0 |
| Clean True Negative Rate (TNR) | 97.9% | 97.9% | 0.0% |
| Clean Precision | 50.0% | 97.3% | N/A |
| Clean F1 Score | 5.3% | 98.6% | N/A |

## Section K: Paired Statistical Comparison

### Paired Vulnerable 2x2 Contingency Table (N = 36)

| Condition A \ Condition B | Useful (+) | Not Useful (-) |
| :--- | :---: | :---: |
| **Useful (+)** | 1 | 0 |
| **Not Useful (-)** | 35 | 0 |

- Discordant pairs: b (A only) = 0, c (B only) = 35
- Paired yield difference: **+97.2%**
- 95% Confidence Interval: **[91.8%, 102.6%]**
- Exact McNemar two-tailed test: **p = 5.82e-11** (statistically significant)

### Vulnerable Scenario Transition Breakdown

- `INCORRECT_BENIGN_TO_USEFUL`: **35** scenarios
- `UNCHANGED_USEFUL`: **1** scenarios

## Section L: Grounding Results
- Grounding Validator: `CascadeGroundingValidator` (active throughout)
- `UNGROUNDED_ACCEPTED = 0` (Strictly zero ungrounded hypotheses accepted)
- Condition A grounding accepted: 2, rejected: 0
- Condition B grounding accepted: 38, rejected: 0

## Section M: Failure-Layer Analysis

| Failure Layer | Condition A (Baseline) | Condition B (Enriched) |
| :--- | :---: | :---: |
| `REASONING_INCORRECT_LOGIC` | 36 | 2 |
| `SUCCESS` | 48 | 82 |

## Section N: Application Family Analysis

| Application Family | Vuln N | Ctrl N | Cond A Useful | Cond B Useful | Delta | Clean Ctrl FP (Cond B) | Oracle Contradictions |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `saas_billing` | 6 | 8 | 0/6 (0.0%) | 6/6 (100.0%) | +6 | 0 | 0 |
| `ecommerce_orders` | 6 | 8 | 0/6 (0.0%) | 6/6 (100.0%) | +6 | 0 | 1 |
| `identity_provider` | 6 | 8 | 0/6 (0.0%) | 6/6 (100.0%) | +6 | 0 | 0 |
| `document_collaboration` | 6 | 8 | 1/6 (16.7%) | 6/6 (100.0%) | +5 | 0 | 0 |
| `healthcare_portal` | 6 | 8 | 0/6 (0.0%) | 6/6 (100.0%) | +6 | 0 | 0 |
| `iot_fleet_mgmt` | 6 | 8 | 0/6 (0.0%) | 6/6 (100.0%) | +6 | 1 | 0 |

## Section O: Vulnerability Taxonomy Category Analysis

| Category ID | Description / Type | Vuln N | Cond A Useful | Cond B Useful | Delta |
| :--- | :--- | :---: | :---: | :---: | :---: |
| `API-AUTH-NONE` | Authorization / State | 0 | 0/0 | 0/0 | +0 |
| `API-BFLA-001` | Authorization / State | 3 | 0/3 | 3/3 | +3 |
| `API-BOLA-001` | Authorization / State | 5 | 0/5 | 5/5 | +5 |
| `API-CROSS-TENANT-001` | Authorization / State | 6 | 0/6 | 6/6 | +6 |
| `API-DEVICE-BOLA-001` | Authorization / State | 2 | 0/2 | 2/2 | +2 |
| `API-LIFECYCLE-001` | Authorization / State | 4 | 0/4 | 4/4 | +4 |
| `API-MULTI-STEP-AUTH-001` | Authorization / State | 3 | 1/3 | 3/3 | +2 |
| `API-MUTATION-001` | Authorization / State | 4 | 0/4 | 4/4 | +4 |
| `API-ROLE-BOUNDARY-001` | Authorization / State | 3 | 0/3 | 3/3 | +3 |
| `API-STATE-001` | Authorization / State | 6 | 0/6 | 6/6 | +6 |

## Section P: Reproducibility and Dependency-Aware Ablation

### Reproducibility Verification (N = 12 Scenarios Repeated)
- Scored Decision Match Rate: **100.0%**
- Scored outcome determinism across repeated executions: **VERIFIED**

### Secondary Dependency-Aware Ablation Study (N = 6 Scenarios Across 7 Conditions)

| Condition | Useful Hypotheses | Useful Rate | Impact Description |
| :--- | :---: | :---: | :--- |
| `COND_1_FULL_ENRICHED` | 6/6 | 100.0% | Dependent derived facts recomputed |
| `COND_2_MASK_IDENTITY` | 0/6 | 0.0% | Dependent derived facts recomputed |
| `COND_3_MASK_TENANT` | 6/6 | 100.0% | Dependent derived facts recomputed |
| `COND_4_MASK_RESPONSE` | 6/6 | 100.0% | Dependent derived facts recomputed |
| `COND_5_MASK_ROLE_AUTH` | 6/6 | 100.0% | Dependent derived facts recomputed |
| `COND_6_MASK_STATE` | 6/6 | 100.0% | Dependent derived facts recomputed |
| `COND_7_FULL_BASELINE` | 0/6 | 0.0% | Dependent derived facts recomputed |

## Section Q: Final Interpretation and Validity Classification

**Final Status**: **`SUPPORTED_FOR_ARCHITECTURAL_REVIEW`**

### Empirical Findings
1. Under the controlled synthetic benchmark conditions, enriched observable interaction evidence increased grounded useful-hypothesis yield from **2.8%** to **100.0%** across the entire 84-scenario benchmark population.
2. The effect persisted across all 6 application families without exception.
3. True negative rate on oracle-consistent controls was **97.9%** (46/47) with exactly 1 false positive on `SCEN-IOT_FLEET_MGMT-NEG-01` where anonymous access to a SYSTEM-owned public catalog was represented as a cross-identity relation.
4. Exactly 1 additional false positive in the raw population was observed on `SCEN-ECOMMERCE_ORDERS-ORD-PAY-PATCH-03`, which was verified as a benchmark-oracle contradiction in the underlying `SyntheticApp` implementation.
5. All validity conditions (zero leakage, trace hash parity, zero secrets, fact preservation, grounding validity, decision reproducibility) were satisfied.

### Limitations and Constraints
- **Synthetic Application Limitation**: All observations reflect behavior within `SyntheticApp` state machine simulations and must not be conflated with arbitrary real-world HTTP traffic.
- **Freeze Boundary**: Production architecture (`LosslessStructuralPack`, `StructuralDiffEngine`, `Gate`, `Router`) and the official benchmark manifest remain strictly unchanged.
- **Integration Boundary**: This result supports scheduling an architectural review for milestone M2 integration; it does not constitute automatic deployment.
