# Phase 11.6: Production Interaction-Enrichment Validation Report
**Experiment Version**: 11.6.0  
**Git Commit**: `2b47c5d8a8d15e9740341667958918c581124522`  
**Validation Timestamp**: 2026-09-19  
**Official Manifest SHA-256**: `b2b85a672124acf21066a257d8c7f5093000368b224ee013c02574c96a0ae707`  
**Frozen Trace Set SHA-256**: `e4658d7dcfc1a6138337bbb2369dbe93d3d7d39da001c1078c67f92411869e19`  
**Final Status**: **`FULLY_VALIDATED`**  

## Section 1: Executive Summary
Phase 11.6 evaluated the promotion of the interaction-evidence enrichment pipeline from prototype evaluation (`src/eval/`) into the production engine (`src/evidence/structural_diff.py` and `src/evidence/interaction_enrichment.py`).
The entire official 84-scenario benchmark population (`data/benchmarks/m1_5_frozen_manifest.json`) was executed through the new production pipeline under frozen 7B inference conditions (`qwen2.5-coder:7b`, seed=42, temp=0.0, num_ctx=4096).

Key empirical outcomes:
- **Useful Hypothesis Yield (Vulnerable)**: **100.0%** (36/36), maintaining the 100% detection rate from Phase 11.5.
- **Raw True Negative Rate (All 48 Controls)**: **97.9%** (47/48), improving by +2.1% over Phase 11.5 (46/48).
- **Oracle-Clean True Negative Rate (47 Consistent Controls)**: **100.0%** (47/47), reaching perfect specificity.
- **Grounding Acceptance**: **100.0%** (`UNGROUNDED_ACCEPTED = 0`).
- **Secret Leakage Count**: **0** (All credentials and auth tokens properly redacted).
- **Regression Rate**: **0.0%** (Zero regressions across all 84 scenarios).

## Section 2: Core Metric Summary & Paired Comparison

| Metric | Phase 11.5 Baseline (Prototype) | Phase 11.6 Production | Delta | Interpretation |
| :--- | :---: | :---: | :---: | :--- |
| **Useful Yield (Vulnerable)** | 36/36 (100.0%) | 36/36 (100.0%) | 0.0% | Maintained 100% recall |
| **Raw True Negative Rate** | 46/48 (95.8%) | 47/48 (97.9%) | +2.1% | False positive eliminated |
| **Oracle-Clean TNR** | 46/47 (97.9%) | 47/47 (100.0%) | +2.1% | Perfect clean specificity (100.0%) |
| **Ungrounded Hypotheses Accepted** | 0 | 0 | 0 | Strict grounding preserved |
| **Secret Leaks** | 0 | 0 | 0 | Redaction vault validated |
| **Deterministic Routing Escalations** | 84/84 (100.0%) | 84/84 (100.0%) | 0 | Proper signal escalation |
| **Benchmark Latency (Total)** | 728.3s | 812.78s | +84.5s | ~9.67s per scenario avg |

## Section 3: Vulnerable Scenario Detection Results
All 36 vulnerable scenarios were correctly identified and formulated as valid security hypotheses (`useful = True`, `grounding_valid = True`).
Detection recall is **100.0%** (36/36).

## Section 4: Control Scenarios & False Positive Audit
Out of 48 control scenarios (36 matched controls + 12 negative controls), exactly **1** false positive was observed in the raw population:
- **`SCEN-ECOMMERCE_ORDERS-ORD-PAY-PATCH-03`**: Known and documented simulator contradiction. In the synthetic simulator, `POST /api/v1/orders/ORD-001/pay` permits cross-identity payment (HTTP 200) despite being labeled as a patched control in the benchmark manifest. The model's identification of this vulnerability is an accurate reading of the provided interaction telemetry.
- Under the **Oracle-Clean Sensitivity View** (excluding this simulator bug), the control false positive count is **0**, and TNR is **100.0%** (47/47).

## Section 5: Grounding Failures and Secret Leakage Audit
- `UNGROUNDED_ACCEPTED`: **0**
- `GROUNDING_FAILURES`: **0**
- `SECRET_LEAK_COUNT`: **0**
All structural facts emitted into `LosslessStructuralPack` adhere to Section 20 fact preservation: `BASE_FACTS ⊆ ENRICHED_FACTS`. Grounding was strictly verified for every scenario by `CascadeGroundingValidator`.

## Section 6: Routing Analysis
- Escalated scenarios: **84/84** (100.0%)
- High-risk interaction signals detected across scenarios: `has_cross_identity_object_access_success`, `has_unauthenticated_success`, `has_privilege_level_delta`, and `status_code_changed_under_different_role`.
- The `DeterministicRouter` correctly forwarded all packets containing high-risk interaction telemetry to LLM reasoning evaluation without dropping or misrouting any signals.

## Section 7: Per-Scenario Regressions
- Total regressions: **0**
- All 36 vulnerable scenarios detected in Phase 11.5 remained detected in Phase 11.6.
- All 46 benign controls correctly rejected in Phase 11.5 remained correctly rejected in Phase 11.6.

## Section 8: Explicit Scenario Decision Changes Relative to Phase 11.5
Exactly **1** scenario changed decision between Phase 11.5 and Phase 11.6:

| Scenario ID | Family | Category | Phase 11.5 Decision | Phase 11.6 Decision | Impact |
| :--- | :--- | :--- | :---: | :---: | :--- |
| `SCEN-IOT_FLEET_MGMT-NEG-01` | `iot_fleet_mgmt` | `API-AUTH-NONE` | `HYPOTHESIS` (FP) | `NO_RELEVANT_FUNCTIONALITY` (TN) | **False positive eliminated. TNR increased from 95.8% to 97.9%.** |

### Detailed Root Cause & Verification for SCEN-IOT_FLEET_MGMT-NEG-01
In Phase 11.5, `SCEN-IOT_FLEET_MGMT-NEG-01` was evaluated as a false positive because the prototype enricher treated anonymous access to a SYSTEM-owned public catalog (`GET /api/v1/devices/catalog`) as a cross-identity access event (`caller='anonymous'`, `resource_owner='system'`).
In the Phase 11.6 production `InteractionEvidenceEnricher`:
1. Genuine cross-identity access is defined strictly as an authenticated tenant user accessing another tenant user's resource (`caller_is_auth and owner_is_tenant and caller != owner`).
2. Anonymous access to a resource owned by `SYSTEM` or `PUBLIC` is recognized as standard public access (`cross_identity_access = False`, `has_unauthenticated_success = False`).
3. As a result, the structural pack accurately reflects that no authorization boundary was crossed.
4. The pinned 7B model evaluated the endpoint as `NO_RELEVANT_FUNCTIONALITY`, confirming the true negative.

## Section 9: Verification of SYSTEM/PUBLIC Semantic Rules Against Legitimate Authorization Findings
To ensure that the generic SYSTEM/PUBLIC semantic rule does not inadvertently suppress legitimate authorization vulnerabilities:
1. **Vulnerable Population Audit**: We audited all 36 vulnerable scenarios in `data/benchmarks/m1_5_frozen_manifest.json` and their corresponding frozen interaction traces.
   - Scenarios with caller in `('anonymous', 'unauthenticated', 'system', 'public')`: **0 / 36**
   - Scenarios with resource owner in `('system', 'public')`: **0 / 36**
   - Result: All 36 vulnerable scenarios involve authentic tenant users (`USER_A`, `USER_B`, `TENANT_X`, `TENANT_Y`, `ORG_ADMIN`, `SUPPORT_AGENT`) accessing tenant-owned assets.
2. **Unauthorized Access Protection**: For endpoints where an unauthenticated caller accesses a protected tenant resource (i.e. `owner` is NOT public/system), `has_unauthenticated_success` evaluates to `True`, preserving unauthenticated vulnerability detection.
3. **Empirical Validation**: Vulnerable detection yield is **100.0%** (36/36). Zero legitimate authorization findings were suppressed.

## Section 10: Application Family Breakdown

| Application Family | Vuln Total | Vuln Detected | Useful Yield | Ctrl Total | Ctrl TNs | Raw Ctrl FPs | Clean Ctrl FPs |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `document_collaboration` | 6 | 6 | 100.0% | 8 | 8 | 0 | 0 |
| `ecommerce_orders` | 6 | 6 | 100.0% | 8 | 7 | 1 | 0 |
| `healthcare_portal` | 6 | 6 | 100.0% | 8 | 8 | 0 | 0 |
| `identity_provider` | 6 | 6 | 100.0% | 8 | 8 | 0 | 0 |
| `iot_fleet_mgmt` | 6 | 6 | 100.0% | 8 | 8 | 0 | 0 |
| `saas_billing` | 6 | 6 | 100.0% | 8 | 8 | 0 | 0 |
| **Total** | **36** | **36** | **100.0%** | **48** | **47** | **1** | **0** |

## Section 11: Taxonomy Category Breakdown

| Category ID | Description / Focus | Vuln N | Useful Yield | Ctrl N |
| :--- | :--- | :---: | :---: | :---: |
| `API-AUTH-NONE` | Authorization / State / BOLA | 0 | N/A (Controls only) | 12 |
| `API-BFLA-001` | Authorization / State / BOLA | 3 | 3/3 (100%) | 3 |
| `API-BOLA-001` | Authorization / State / BOLA | 5 | 5/5 (100%) | 5 |
| `API-CROSS-TENANT-001` | Authorization / State / BOLA | 6 | 6/6 (100%) | 6 |
| `API-DEVICE-BOLA-001` | Authorization / State / BOLA | 2 | 2/2 (100%) | 2 |
| `API-LIFECYCLE-001` | Authorization / State / BOLA | 4 | 4/4 (100%) | 4 |
| `API-MULTI-STEP-AUTH-001` | Authorization / State / BOLA | 3 | 3/3 (100%) | 3 |
| `API-MUTATION-001` | Authorization / State / BOLA | 4 | 4/4 (100%) | 4 |
| `API-ROLE-BOUNDARY-001` | Authorization / State / BOLA | 3 | 3/3 (100%) | 3 |
| `API-STATE-001` | Authorization / State / BOLA | 6 | 6/6 (100%) | 6 |

## Section 12: Paired Scenario Comparison Matrix (Phase 11.5 vs Phase 11.6)

| Scenario ID | Designation | Phase 11.5 Decision | Phase 11.6 Decision | Grounding | Latency (s) | Status |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| `SCEN-SAAS_BILLING-INV-DETAILS-VULN-01` | `vulnerable` | `HYPOTHESIS` | `HYPOTHESIS` | True | 8.83s | MATCH |
| `SCEN-SAAS_BILLING-INV-DETAILS-PATCH-01` | `control` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | True | 8.88s | MATCH |
| `SCEN-SAAS_BILLING-SUB-DETAILS-VULN-02` | `vulnerable` | `HYPOTHESIS` | `HYPOTHESIS` | True | 7.47s | MATCH |
| `SCEN-SAAS_BILLING-SUB-DETAILS-PATCH-02` | `control` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | True | 9.43s | MATCH |
| `SCEN-SAAS_BILLING-INV-SUMMARY-VULN-03` | `vulnerable` | `HYPOTHESIS` | `HYPOTHESIS` | True | 6.50s | MATCH |
| `SCEN-SAAS_BILLING-INV-SUMMARY-PATCH-03` | `control` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | True | 11.22s | MATCH |
| `SCEN-SAAS_BILLING-SUB-SUMMARY-VULN-04` | `vulnerable` | `HYPOTHESIS` | `HYPOTHESIS` | True | 6.62s | MATCH |
| `SCEN-SAAS_BILLING-SUB-SUMMARY-PATCH-04` | `control` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | True | 10.66s | MATCH |
| `SCEN-SAAS_BILLING-INV-WORKFLOW-VULN-05` | `vulnerable` | `HYPOTHESIS` | `HYPOTHESIS` | True | 8.81s | MATCH |
| `SCEN-SAAS_BILLING-INV-WORKFLOW-PATCH-05` | `control` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | True | 9.79s | MATCH |
| `SCEN-SAAS_BILLING-SUB-PLAN-VULN-06` | `vulnerable` | `HYPOTHESIS` | `HYPOTHESIS` | True | 8.69s | MATCH |
| `SCEN-SAAS_BILLING-SUB-PLAN-PATCH-06` | `control` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | True | 10.69s | MATCH |
| `SCEN-SAAS_BILLING-NEG-01` | `control` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | True | 10.58s | MATCH |
| `SCEN-SAAS_BILLING-NEG-02` | `control` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | True | 14.09s | MATCH |
| `SCEN-ECOMMERCE_ORDERS-ORD-REFUND-VULN-01` | `vulnerable` | `HYPOTHESIS` | `HYPOTHESIS` | True | 9.22s | MATCH |
| `SCEN-ECOMMERCE_ORDERS-ORD-REFUND-PATCH-01` | `control` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | True | 8.10s | MATCH |
| `SCEN-ECOMMERCE_ORDERS-ORD-SHIP-VULN-02` | `vulnerable` | `HYPOTHESIS` | `HYPOTHESIS` | True | 8.29s | MATCH |
| `SCEN-ECOMMERCE_ORDERS-ORD-SHIP-PATCH-02` | `control` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | True | 13.76s | MATCH |
| `SCEN-ECOMMERCE_ORDERS-ORD-PAY-VULN-03` | `vulnerable` | `HYPOTHESIS` | `HYPOTHESIS` | True | 9.07s | MATCH |
| `SCEN-ECOMMERCE_ORDERS-ORD-PAY-PATCH-03` | `control` | `HYPOTHESIS` | `HYPOTHESIS` | True | 9.99s | MATCH |
| `SCEN-ECOMMERCE_ORDERS-ORD-CANCEL-REFUND-VULN-04` | `vulnerable` | `HYPOTHESIS` | `HYPOTHESIS` | True | 8.77s | MATCH |
| `SCEN-ECOMMERCE_ORDERS-ORD-CANCEL-REFUND-PATCH-04` | `control` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | True | 9.95s | MATCH |
| `SCEN-ECOMMERCE_ORDERS-ORD-DISPATCH-VULN-05` | `vulnerable` | `HYPOTHESIS` | `HYPOTHESIS` | True | 9.55s | MATCH |
| `SCEN-ECOMMERCE_ORDERS-ORD-DISPATCH-PATCH-05` | `control` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | True | 9.86s | MATCH |
| `SCEN-ECOMMERCE_ORDERS-ORD-RETURN-VULN-06` | `vulnerable` | `HYPOTHESIS` | `HYPOTHESIS` | True | 9.29s | MATCH |
| `SCEN-ECOMMERCE_ORDERS-ORD-RETURN-PATCH-06` | `control` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | True | 14.07s | MATCH |
| `SCEN-ECOMMERCE_ORDERS-NEG-01` | `control` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | True | 13.87s | MATCH |
| `SCEN-ECOMMERCE_ORDERS-NEG-02` | `control` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | True | 9.52s | MATCH |
| `SCEN-IDENTITY_PROVIDER-USER-ROLES-VULN-01` | `vulnerable` | `HYPOTHESIS` | `HYPOTHESIS` | True | 10.25s | MATCH |
| `SCEN-IDENTITY_PROVIDER-USER-ROLES-PATCH-01` | `control` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | True | 8.75s | MATCH |
| `SCEN-IDENTITY_PROVIDER-USER-MFA-VULN-02` | `vulnerable` | `HYPOTHESIS` | `HYPOTHESIS` | True | 9.20s | MATCH |
| `SCEN-IDENTITY_PROVIDER-USER-MFA-PATCH-02` | `control` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | True | 11.10s | MATCH |
| `SCEN-IDENTITY_PROVIDER-USER-TENANT-ROLE-VULN-03` | `vulnerable` | `HYPOTHESIS` | `HYPOTHESIS` | True | 11.40s | MATCH |
| `SCEN-IDENTITY_PROVIDER-USER-TENANT-ROLE-PATCH-03` | `control` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | True | 10.94s | MATCH |
| `SCEN-IDENTITY_PROVIDER-USER-TENANT-MFA-VULN-04` | `vulnerable` | `HYPOTHESIS` | `HYPOTHESIS` | True | 10.60s | MATCH |
| `SCEN-IDENTITY_PROVIDER-USER-TENANT-MFA-PATCH-04` | `control` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | True | 11.51s | MATCH |
| `SCEN-IDENTITY_PROVIDER-USER-ADMIN-ROLE-VULN-05` | `vulnerable` | `HYPOTHESIS` | `HYPOTHESIS` | True | 11.77s | MATCH |
| `SCEN-IDENTITY_PROVIDER-USER-ADMIN-ROLE-PATCH-05` | `control` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | True | 8.61s | MATCH |
| `SCEN-IDENTITY_PROVIDER-USER-AUTH-MUTATE-VULN-06` | `vulnerable` | `HYPOTHESIS` | `HYPOTHESIS` | True | 9.20s | MATCH |
| `SCEN-IDENTITY_PROVIDER-USER-AUTH-MUTATE-PATCH-06` | `control` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | True | 9.35s | MATCH |
| `SCEN-IDENTITY_PROVIDER-NEG-01` | `control` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | True | 11.57s | MATCH |
| `SCEN-IDENTITY_PROVIDER-NEG-02` | `control` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | True | 13.08s | MATCH |
| `SCEN-DOCUMENT_COLLABORATION-DOC-EXPORT-VULN-01` | `vulnerable` | `HYPOTHESIS` | `HYPOTHESIS` | True | 7.89s | MATCH |
| `SCEN-DOCUMENT_COLLABORATION-DOC-EXPORT-PATCH-01` | `control` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | True | 9.12s | MATCH |
| `SCEN-DOCUMENT_COLLABORATION-DOC-ORG-EXPORT-VULN-02` | `vulnerable` | `HYPOTHESIS` | `HYPOTHESIS` | True | 8.24s | MATCH |
| `SCEN-DOCUMENT_COLLABORATION-DOC-ORG-EXPORT-PATCH-02` | `control` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | True | 11.38s | MATCH |
| `SCEN-DOCUMENT_COLLABORATION-DOC-PUBLISH-VULN-03` | `vulnerable` | `HYPOTHESIS` | `HYPOTHESIS` | True | 6.18s | MATCH |
| `SCEN-DOCUMENT_COLLABORATION-DOC-PUBLISH-PATCH-03` | `control` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | True | 10.12s | MATCH |
| `SCEN-DOCUMENT_COLLABORATION-DOC-RELEASE-VULN-04` | `vulnerable` | `HYPOTHESIS` | `HYPOTHESIS` | True | 6.18s | MATCH |
| `SCEN-DOCUMENT_COLLABORATION-DOC-RELEASE-PATCH-04` | `control` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | True | 13.52s | MATCH |
| `SCEN-DOCUMENT_COLLABORATION-DOC-CLASSIFY-VULN-05` | `vulnerable` | `HYPOTHESIS` | `HYPOTHESIS` | True | 6.60s | MATCH |
| `SCEN-DOCUMENT_COLLABORATION-DOC-CLASSIFY-PATCH-05` | `control` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | True | 10.52s | MATCH |
| `SCEN-DOCUMENT_COLLABORATION-DOC-WORKSPACE-VULN-06` | `vulnerable` | `HYPOTHESIS` | `HYPOTHESIS` | True | 6.45s | MATCH |
| `SCEN-DOCUMENT_COLLABORATION-DOC-WORKSPACE-PATCH-06` | `control` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | True | 8.89s | MATCH |
| `SCEN-DOCUMENT_COLLABORATION-NEG-01` | `control` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | True | 14.52s | MATCH |
| `SCEN-DOCUMENT_COLLABORATION-NEG-02` | `control` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | True | 10.30s | MATCH |
| `SCEN-HEALTHCARE_PORTAL-PATIENT-REC-VULN-01` | `vulnerable` | `HYPOTHESIS` | `HYPOTHESIS` | True | 8.55s | MATCH |
| `SCEN-HEALTHCARE_PORTAL-PATIENT-REC-PATCH-01` | `control` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | True | 8.45s | MATCH |
| `SCEN-HEALTHCARE_PORTAL-PATIENT-RX-VULN-02` | `vulnerable` | `HYPOTHESIS` | `HYPOTHESIS` | True | 6.62s | MATCH |
| `SCEN-HEALTHCARE_PORTAL-PATIENT-RX-PATCH-02` | `control` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | True | 10.65s | MATCH |
| `SCEN-HEALTHCARE_PORTAL-RECORD-ARCHIVE-VULN-03` | `vulnerable` | `HYPOTHESIS` | `HYPOTHESIS` | True | 8.52s | MATCH |
| `SCEN-HEALTHCARE_PORTAL-RECORD-ARCHIVE-PATCH-03` | `control` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | True | 10.96s | MATCH |
| `SCEN-HEALTHCARE_PORTAL-CLINIC-REC-VULN-04` | `vulnerable` | `HYPOTHESIS` | `HYPOTHESIS` | True | 6.62s | MATCH |
| `SCEN-HEALTHCARE_PORTAL-CLINIC-REC-PATCH-04` | `control` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | True | 11.11s | MATCH |
| `SCEN-HEALTHCARE_PORTAL-STAFF-RX-VULN-05` | `vulnerable` | `HYPOTHESIS` | `HYPOTHESIS` | True | 9.67s | MATCH |
| `SCEN-HEALTHCARE_PORTAL-STAFF-RX-PATCH-05` | `control` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | True | 9.84s | MATCH |
| `SCEN-HEALTHCARE_PORTAL-RECORD-PURGE-VULN-06` | `vulnerable` | `HYPOTHESIS` | `HYPOTHESIS` | True | 6.72s | MATCH |
| `SCEN-HEALTHCARE_PORTAL-RECORD-PURGE-PATCH-06` | `control` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | True | 7.89s | MATCH |
| `SCEN-HEALTHCARE_PORTAL-NEG-01` | `control` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | True | 9.17s | MATCH |
| `SCEN-HEALTHCARE_PORTAL-NEG-02` | `control` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | True | 8.94s | MATCH |
| `SCEN-IOT_FLEET_MGMT-DEVICE-CMD-VULN-01` | `vulnerable` | `HYPOTHESIS` | `HYPOTHESIS` | True | 8.56s | MATCH |
| `SCEN-IOT_FLEET_MGMT-DEVICE-CMD-PATCH-01` | `control` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | True | 10.46s | MATCH |
| `SCEN-IOT_FLEET_MGMT-DEVICE-TEL-VULN-02` | `vulnerable` | `HYPOTHESIS` | `HYPOTHESIS` | True | 5.16s | MATCH |
| `SCEN-IOT_FLEET_MGMT-DEVICE-TEL-PATCH-02` | `control` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | True | 11.24s | MATCH |
| `SCEN-IOT_FLEET_MGMT-FLEET-CMD-VULN-03` | `vulnerable` | `HYPOTHESIS` | `HYPOTHESIS` | True | 6.83s | MATCH |
| `SCEN-IOT_FLEET_MGMT-FLEET-CMD-PATCH-03` | `control` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | True | 9.33s | MATCH |
| `SCEN-IOT_FLEET_MGMT-FLEET-TEL-VULN-04` | `vulnerable` | `HYPOTHESIS` | `HYPOTHESIS` | True | 5.26s | MATCH |
| `SCEN-IOT_FLEET_MGMT-FLEET-TEL-PATCH-04` | `control` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | True | 10.98s | MATCH |
| `SCEN-IOT_FLEET_MGMT-DEVICE-FW-VULN-05` | `vulnerable` | `HYPOTHESIS` | `HYPOTHESIS` | True | 10.57s | MATCH |
| `SCEN-IOT_FLEET_MGMT-DEVICE-FW-PATCH-05` | `control` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | True | 10.66s | MATCH |
| `SCEN-IOT_FLEET_MGMT-FLEET-CONFIG-VULN-06` | `vulnerable` | `HYPOTHESIS` | `HYPOTHESIS` | True | 9.45s | MATCH |
| `SCEN-IOT_FLEET_MGMT-FLEET-CONFIG-PATCH-06` | `control` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | True | 14.85s | MATCH |
| `SCEN-IOT_FLEET_MGMT-NEG-01` | `control` | `HYPOTHESIS` | `NO_RELEVANT_FUNCTIONALITY` | True | 9.94s | TRANSITION(HYPOTHESIS->NO_RELEVANT_FUNCTIONALITY) |
| `SCEN-IOT_FLEET_MGMT-NEG-02` | `control` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | True | 12.36s | MATCH |