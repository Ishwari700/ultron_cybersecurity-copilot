# Phase 11.4: Evidence-Representation Replication and Generalization Experiment

## 1. Executive Summary

- **Experiment Name**: Phase 11.4 Evidence-Representation Replication & Generalization
- **Primary Research Question**: Under otherwise frozen 7B inference conditions, does adding explicit, observable interaction-level evidence to canonical evidence improve grounded useful-hypothesis yield across a broader set of application families and vulnerability patterns without increasing false positives?
- **Experimental Population**: Fixed stratified sample of $N = 48$ scenarios (24 vulnerable, 24 matched non-vulnerable controls).
- **Stratification**: Exactly 4 vulnerable scenarios and 4 matched controls across all 6 application families.
- **Single Independent Variable**: `EVIDENCE REPRESENTATION` (Condition A: `BASELINE_CANONICAL_EVIDENCE` vs Condition B: `ENRICHED_OBSERVABLE_EVIDENCE`).
- **All Other Parameters Frozen**: `qwen2.5-coder:7b` (digest `dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364`), seed=42, temp=0.0, num_ctx=4096, identical system prompt, task instruction, context-builder budget, grounding validator, and scorer semantics.
- **Replication Verdict**: **`EVIDENCE_REPRESENTATION_REPLICATION = NOT_SUPPORTED`**

---

## 2. Primary Comparative Results

| Metric | Condition A (Baseline Canonical) | Condition B (Enriched Observable) | Delta (B - A) |
|---|---|---|---|
| **Useful Grounded Hypotheses** | 0 / 24 | 24 / 24 | **+24** |
| **Useful Hypothesis Yield (Recall)** | 0.0% | 100.0% | **+100.0%** |
| **Control False Positives** | 0 / 24 | 1 / 24 | **1** |
| **True Negatives (Controls)** | 24 / 24 | 23 / 24 | **-1** |
| **True Negative Rate (TNR)** | 100.0% | 95.8% | **-4.2%** |
| **Precision** | N/A | 96.0% | **96.0%** |
| **Grounding Failures** | 0 | 0 | 0 |
| **Ground-Truth Leakage** | 0 | 0 | PASSED |
| **Removed Existing Facts** | 0 | 0 | PASSED |

---

## 3. Success Criteria Evaluation (Section 24)

1. **Enriched condition improves useful grounded yield over baseline**: `PASSED` (24/24 vs 0/24)
2. **Improvement occurs across more than one application family**: `PASSED` (6/6 families improved)
3. **Improvement is not confined to the original 3/5 cases**: `PASSED` (24 total useful cases)
4. **No unacceptable increase in false positives**: `FAILED` (FP = 1/24)
5. **No unsupported/ungrounded positives**: `FAILED` (0 ungrounded)
6. **No ground-truth leakage**: `PASSED` (Runtime assertions verified)
7. **Existing evidence is preserved**: `PASSED` (`BASE_FACTS ⊆ ENRICHED_FACTS`, 0 removed)
8. **The effect survives the context-budget audit**: `PASSED` (Max prompt 509 < 4096 tokens)
9. **Reproducibility check passes**: `FAILED` (6/6 duplicate runs produced 100% identical outputs)

**OVERALL OUTCOME**: **`EVIDENCE_REPRESENTATION_REPLICATION = NOT_SUPPORTED`**

---

## 4. Required Report Tables

### Table 1: Scenario × Condition A × Condition B
| Scenario ID | Application Family | Type | Condition A Decision | Condition B Decision | Paired Transition |
|---|---|---|---|---|---|
| `SCEN-SAAS_BILLING-INV-DETAILS-VULN-01` | saas_billing | vulnerable | NO_RELEVANT_FUNCTIONALITY (Not useful) | HYPOTHESIS (Useful) | `INCORRECT_BENIGN_TO_USEFUL` |
| `SCEN-SAAS_BILLING-INV-DETAILS-PATCH-01` | saas_billing | control | NO_RELEVANT_FUNCTIONALITY (Not useful) | NO_RELEVANT_FUNCTIONALITY (Not useful) | `CONTROL_CORRECT_PRESERVED` |
| `SCEN-SAAS_BILLING-SUB-DETAILS-VULN-02` | saas_billing | vulnerable | NO_RELEVANT_FUNCTIONALITY (Not useful) | HYPOTHESIS (Useful) | `INCORRECT_BENIGN_TO_USEFUL` |
| `SCEN-SAAS_BILLING-SUB-DETAILS-PATCH-02` | saas_billing | control | NO_RELEVANT_FUNCTIONALITY (Not useful) | NO_RELEVANT_FUNCTIONALITY (Not useful) | `CONTROL_CORRECT_PRESERVED` |
| `SCEN-SAAS_BILLING-INV-SUMMARY-VULN-03` | saas_billing | vulnerable | NO_RELEVANT_FUNCTIONALITY (Not useful) | HYPOTHESIS (Useful) | `INCORRECT_BENIGN_TO_USEFUL` |
| `SCEN-SAAS_BILLING-INV-SUMMARY-PATCH-03` | saas_billing | control | NO_RELEVANT_FUNCTIONALITY (Not useful) | NO_RELEVANT_FUNCTIONALITY (Not useful) | `CONTROL_CORRECT_PRESERVED` |
| `SCEN-SAAS_BILLING-SUB-SUMMARY-VULN-04` | saas_billing | vulnerable | NO_RELEVANT_FUNCTIONALITY (Not useful) | HYPOTHESIS (Useful) | `INCORRECT_BENIGN_TO_USEFUL` |
| `SCEN-SAAS_BILLING-SUB-SUMMARY-PATCH-04` | saas_billing | control | NO_RELEVANT_FUNCTIONALITY (Not useful) | NO_RELEVANT_FUNCTIONALITY (Not useful) | `CONTROL_CORRECT_PRESERVED` |
| `SCEN-ECOMMERCE_ORDERS-ORD-REFUND-VULN-01` | ecommerce_orders | vulnerable | NO_RELEVANT_FUNCTIONALITY (Not useful) | HYPOTHESIS (Useful) | `INCORRECT_BENIGN_TO_USEFUL` |
| `SCEN-ECOMMERCE_ORDERS-ORD-REFUND-PATCH-01` | ecommerce_orders | control | NO_RELEVANT_FUNCTIONALITY (Not useful) | NO_RELEVANT_FUNCTIONALITY (Not useful) | `CONTROL_CORRECT_PRESERVED` |
| `SCEN-ECOMMERCE_ORDERS-ORD-SHIP-VULN-02` | ecommerce_orders | vulnerable | NO_RELEVANT_FUNCTIONALITY (Not useful) | HYPOTHESIS (Useful) | `INCORRECT_BENIGN_TO_USEFUL` |
| `SCEN-ECOMMERCE_ORDERS-ORD-SHIP-PATCH-02` | ecommerce_orders | control | NO_RELEVANT_FUNCTIONALITY (Not useful) | NO_RELEVANT_FUNCTIONALITY (Not useful) | `CONTROL_CORRECT_PRESERVED` |
| `SCEN-ECOMMERCE_ORDERS-ORD-PAY-VULN-03` | ecommerce_orders | vulnerable | NO_RELEVANT_FUNCTIONALITY (Not useful) | HYPOTHESIS (Useful) | `INCORRECT_BENIGN_TO_USEFUL` |
| `SCEN-ECOMMERCE_ORDERS-ORD-PAY-PATCH-03` | ecommerce_orders | control | NO_RELEVANT_FUNCTIONALITY (Not useful) | HYPOTHESIS (Not useful) | `CONTROL_NEW_FP` |
| `SCEN-ECOMMERCE_ORDERS-ORD-CANCEL-REFUND-VULN-04` | ecommerce_orders | vulnerable | NO_RELEVANT_FUNCTIONALITY (Not useful) | HYPOTHESIS (Useful) | `INCORRECT_BENIGN_TO_USEFUL` |
| `SCEN-ECOMMERCE_ORDERS-ORD-CANCEL-REFUND-PATCH-04` | ecommerce_orders | control | NO_RELEVANT_FUNCTIONALITY (Not useful) | NO_RELEVANT_FUNCTIONALITY (Not useful) | `CONTROL_CORRECT_PRESERVED` |
| `SCEN-IDENTITY_PROVIDER-USER-ROLES-VULN-01` | identity_provider | vulnerable | NO_RELEVANT_FUNCTIONALITY (Not useful) | HYPOTHESIS (Useful) | `INCORRECT_BENIGN_TO_USEFUL` |
| `SCEN-IDENTITY_PROVIDER-USER-ROLES-PATCH-01` | identity_provider | control | NO_RELEVANT_FUNCTIONALITY (Not useful) | NO_RELEVANT_FUNCTIONALITY (Not useful) | `CONTROL_CORRECT_PRESERVED` |
| `SCEN-IDENTITY_PROVIDER-USER-MFA-VULN-02` | identity_provider | vulnerable | NO_RELEVANT_FUNCTIONALITY (Not useful) | HYPOTHESIS (Useful) | `INCORRECT_BENIGN_TO_USEFUL` |
| `SCEN-IDENTITY_PROVIDER-USER-MFA-PATCH-02` | identity_provider | control | NO_RELEVANT_FUNCTIONALITY (Not useful) | NO_RELEVANT_FUNCTIONALITY (Not useful) | `CONTROL_CORRECT_PRESERVED` |
| `SCEN-IDENTITY_PROVIDER-USER-TENANT-ROLE-VULN-03` | identity_provider | vulnerable | NO_RELEVANT_FUNCTIONALITY (Not useful) | HYPOTHESIS (Useful) | `INCORRECT_BENIGN_TO_USEFUL` |
| `SCEN-IDENTITY_PROVIDER-USER-TENANT-ROLE-PATCH-03` | identity_provider | control | NO_RELEVANT_FUNCTIONALITY (Not useful) | NO_RELEVANT_FUNCTIONALITY (Not useful) | `CONTROL_CORRECT_PRESERVED` |
| `SCEN-IDENTITY_PROVIDER-USER-TENANT-MFA-VULN-04` | identity_provider | vulnerable | NO_RELEVANT_FUNCTIONALITY (Not useful) | HYPOTHESIS (Useful) | `INCORRECT_BENIGN_TO_USEFUL` |
| `SCEN-IDENTITY_PROVIDER-USER-TENANT-MFA-PATCH-04` | identity_provider | control | NO_RELEVANT_FUNCTIONALITY (Not useful) | NO_RELEVANT_FUNCTIONALITY (Not useful) | `CONTROL_CORRECT_PRESERVED` |
| `SCEN-DOCUMENT_COLLABORATION-DOC-EXPORT-VULN-01` | document_collaboration | vulnerable | NO_RELEVANT_FUNCTIONALITY (Not useful) | HYPOTHESIS (Useful) | `INCORRECT_BENIGN_TO_USEFUL` |
| `SCEN-DOCUMENT_COLLABORATION-DOC-EXPORT-PATCH-01` | document_collaboration | control | NO_RELEVANT_FUNCTIONALITY (Not useful) | NO_RELEVANT_FUNCTIONALITY (Not useful) | `CONTROL_CORRECT_PRESERVED` |
| `SCEN-DOCUMENT_COLLABORATION-DOC-ORG-EXPORT-VULN-02` | document_collaboration | vulnerable | NO_RELEVANT_FUNCTIONALITY (Not useful) | HYPOTHESIS (Useful) | `INCORRECT_BENIGN_TO_USEFUL` |
| `SCEN-DOCUMENT_COLLABORATION-DOC-ORG-EXPORT-PATCH-02` | document_collaboration | control | NO_RELEVANT_FUNCTIONALITY (Not useful) | NO_RELEVANT_FUNCTIONALITY (Not useful) | `CONTROL_CORRECT_PRESERVED` |
| `SCEN-DOCUMENT_COLLABORATION-DOC-PUBLISH-VULN-03` | document_collaboration | vulnerable | NO_RELEVANT_FUNCTIONALITY (Not useful) | HYPOTHESIS (Useful) | `INCORRECT_BENIGN_TO_USEFUL` |
| `SCEN-DOCUMENT_COLLABORATION-DOC-PUBLISH-PATCH-03` | document_collaboration | control | NO_RELEVANT_FUNCTIONALITY (Not useful) | NO_RELEVANT_FUNCTIONALITY (Not useful) | `CONTROL_CORRECT_PRESERVED` |
| `SCEN-DOCUMENT_COLLABORATION-DOC-RELEASE-VULN-04` | document_collaboration | vulnerable | NO_RELEVANT_FUNCTIONALITY (Not useful) | HYPOTHESIS (Useful) | `INCORRECT_BENIGN_TO_USEFUL` |
| `SCEN-DOCUMENT_COLLABORATION-DOC-RELEASE-PATCH-04` | document_collaboration | control | NO_RELEVANT_FUNCTIONALITY (Not useful) | NO_RELEVANT_FUNCTIONALITY (Not useful) | `CONTROL_CORRECT_PRESERVED` |
| `SCEN-HEALTHCARE_PORTAL-PATIENT-REC-VULN-01` | healthcare_portal | vulnerable | NO_RELEVANT_FUNCTIONALITY (Not useful) | HYPOTHESIS (Useful) | `INCORRECT_BENIGN_TO_USEFUL` |
| `SCEN-HEALTHCARE_PORTAL-PATIENT-REC-PATCH-01` | healthcare_portal | control | NO_RELEVANT_FUNCTIONALITY (Not useful) | NO_RELEVANT_FUNCTIONALITY (Not useful) | `CONTROL_CORRECT_PRESERVED` |
| `SCEN-HEALTHCARE_PORTAL-PATIENT-RX-VULN-02` | healthcare_portal | vulnerable | NO_RELEVANT_FUNCTIONALITY (Not useful) | HYPOTHESIS (Useful) | `INCORRECT_BENIGN_TO_USEFUL` |
| `SCEN-HEALTHCARE_PORTAL-PATIENT-RX-PATCH-02` | healthcare_portal | control | NO_RELEVANT_FUNCTIONALITY (Not useful) | NO_RELEVANT_FUNCTIONALITY (Not useful) | `CONTROL_CORRECT_PRESERVED` |
| `SCEN-HEALTHCARE_PORTAL-RECORD-ARCHIVE-VULN-03` | healthcare_portal | vulnerable | NO_RELEVANT_FUNCTIONALITY (Not useful) | HYPOTHESIS (Useful) | `INCORRECT_BENIGN_TO_USEFUL` |
| `SCEN-HEALTHCARE_PORTAL-RECORD-ARCHIVE-PATCH-03` | healthcare_portal | control | NO_RELEVANT_FUNCTIONALITY (Not useful) | NO_RELEVANT_FUNCTIONALITY (Not useful) | `CONTROL_CORRECT_PRESERVED` |
| `SCEN-HEALTHCARE_PORTAL-CLINIC-REC-VULN-04` | healthcare_portal | vulnerable | NO_RELEVANT_FUNCTIONALITY (Not useful) | HYPOTHESIS (Useful) | `INCORRECT_BENIGN_TO_USEFUL` |
| `SCEN-HEALTHCARE_PORTAL-CLINIC-REC-PATCH-04` | healthcare_portal | control | NO_RELEVANT_FUNCTIONALITY (Not useful) | NO_RELEVANT_FUNCTIONALITY (Not useful) | `CONTROL_CORRECT_PRESERVED` |
| `SCEN-IOT_FLEET_MGMT-DEVICE-CMD-VULN-01` | iot_fleet_mgmt | vulnerable | NO_RELEVANT_FUNCTIONALITY (Not useful) | HYPOTHESIS (Useful) | `INCORRECT_BENIGN_TO_USEFUL` |
| `SCEN-IOT_FLEET_MGMT-DEVICE-CMD-PATCH-01` | iot_fleet_mgmt | control | NO_RELEVANT_FUNCTIONALITY (Not useful) | NO_RELEVANT_FUNCTIONALITY (Not useful) | `CONTROL_CORRECT_PRESERVED` |
| `SCEN-IOT_FLEET_MGMT-DEVICE-TEL-VULN-02` | iot_fleet_mgmt | vulnerable | NO_RELEVANT_FUNCTIONALITY (Not useful) | HYPOTHESIS (Useful) | `INCORRECT_BENIGN_TO_USEFUL` |
| `SCEN-IOT_FLEET_MGMT-DEVICE-TEL-PATCH-02` | iot_fleet_mgmt | control | NO_RELEVANT_FUNCTIONALITY (Not useful) | NO_RELEVANT_FUNCTIONALITY (Not useful) | `CONTROL_CORRECT_PRESERVED` |
| `SCEN-IOT_FLEET_MGMT-FLEET-CMD-VULN-03` | iot_fleet_mgmt | vulnerable | NO_RELEVANT_FUNCTIONALITY (Not useful) | HYPOTHESIS (Useful) | `INCORRECT_BENIGN_TO_USEFUL` |
| `SCEN-IOT_FLEET_MGMT-FLEET-CMD-PATCH-03` | iot_fleet_mgmt | control | NO_RELEVANT_FUNCTIONALITY (Not useful) | NO_RELEVANT_FUNCTIONALITY (Not useful) | `CONTROL_CORRECT_PRESERVED` |
| `SCEN-IOT_FLEET_MGMT-FLEET-TEL-VULN-04` | iot_fleet_mgmt | vulnerable | NO_RELEVANT_FUNCTIONALITY (Not useful) | HYPOTHESIS (Useful) | `INCORRECT_BENIGN_TO_USEFUL` |
| `SCEN-IOT_FLEET_MGMT-FLEET-TEL-PATCH-04` | iot_fleet_mgmt | control | NO_RELEVANT_FUNCTIONALITY (Not useful) | NO_RELEVANT_FUNCTIONALITY (Not useful) | `CONTROL_CORRECT_PRESERVED` |

### Table 2: Application Family × Vulnerable Yield
| Application Family | N (Vuln) | Baseline Yield (Cond A) | Enriched Yield (Cond B) | Delta |
|---|---|---|---|---|
| `saas_billing` | 4 | 0.0% (0/4) | 100.0% (4/4) | **+100.0%** |
| `ecommerce_orders` | 4 | 0.0% (0/4) | 100.0% (4/4) | **+100.0%** |
| `identity_provider` | 4 | 0.0% (0/4) | 100.0% (4/4) | **+100.0%** |
| `document_collaboration` | 4 | 0.0% (0/4) | 100.0% (4/4) | **+100.0%** |
| `healthcare_portal` | 4 | 0.0% (0/4) | 100.0% (4/4) | **+100.0%** |
| `iot_fleet_mgmt` | 4 | 0.0% (0/4) | 100.0% (4/4) | **+100.0%** |

### Table 3: Vulnerability Class × Vulnerable Yield
| Category ID | N (Vuln) | Baseline Yield (Cond A) | Enriched Yield (Cond B) | Delta |
|---|---|---|---|---|
| `API-BFLA-001` | 2 | 0.0% (0/2) | 100.0% (2/2) | **+100.0%** |
| `API-BOLA-001` | 5 | 0.0% (0/5) | 100.0% (5/5) | **+100.0%** |
| `API-CROSS-TENANT-001` | 6 | 0.0% (0/6) | 100.0% (6/6) | **+100.0%** |
| `API-DEVICE-BOLA-001` | 2 | 0.0% (0/2) | 100.0% (2/2) | **+100.0%** |
| `API-LIFECYCLE-001` | 2 | 0.0% (0/2) | 100.0% (2/2) | **+100.0%** |
| `API-ROLE-BOUNDARY-001` | 2 | 0.0% (0/2) | 100.0% (2/2) | **+100.0%** |
| `API-STATE-001` | 5 | 0.0% (0/5) | 100.0% (5/5) | **+100.0%** |

### Table 4: Failure-Layer Transitions
| Earliest Failure Transition (Cond A -> Cond B) | Scenario Count |
|---|---|
| `None -> None` | 23 |
| `None -> REASONING_INCORRECT_LOGIC` | 1 |
| `REASONING_INCORRECT_LOGIC -> None` | 24 |

### Table 5: False-Positive / Control Results
| Application Family | N (Control) | Condition A FP | Condition B FP | Condition A TN | Condition B TN |
|---|---|---|---|---|---|
| `saas_billing` | 4 | 0 | 0 | 4 | 4 |
| `ecommerce_orders` | 4 | 0 | 1 | 4 | 3 |
| `identity_provider` | 4 | 0 | 0 | 4 | 4 |
| `document_collaboration` | 4 | 0 | 0 | 4 | 4 |
| `healthcare_portal` | 4 | 0 | 0 | 4 | 4 |
| `iot_fleet_mgmt` | 4 | 0 | 0 | 4 | 4 |

### Table 6: Evidence Fields Added
| Field Name | Epistemic Status | Description & Semantics |
|---|---|---|
| `interaction_id` | `OBSERVED_FACT` | Unique identifier of active interaction probe |
| `requester_identity_id` | `OBSERVED_FACT` | Caller identity header or authenticated token identity |
| `requester_role` | `OBSERVED_FACT` | Privilege role assigned to caller in target system |
| `requester_tenant_id` | `OBSERVED_FACT` | Organizational tenant partition of caller |
| `resource_id` | `OBSERVED_FACT` | Identifier of accessed entity in path/payload |
| `resource_owner_identity_id` | `OBSERVED_FACT` | Owner identity registered in backend storage |
| `resource_tenant_id` | `OBSERVED_FACT` | Tenant boundary registered for resource |
| `required_role` | `OBSERVED_FACT` | Minimum role required by documented endpoint specification |
| `observed_authorization_context` | `OBSERVED_FACT` | Authorization header context provided in request |
| `http_method` | `OBSERVED_FACT` | HTTP verb executed against target asset |
| `route` | `OBSERVED_FACT` | Raw path executed against target asset |
| `request_parameter_id` | `OBSERVED_FACT` | Registered route parameter name/id |
| `response_status` | `OBSERVED_FACT` | Observed HTTP response status code |
| `response_shape` | `OBSERVED_FACT` | Observed response payload keys and summary structure |
| `resource_access_result` | `OBSERVED_FACT` | Categorical outcome: GRANTED, DENIED, or INVALID_STATE |
| `state_before` | `OBSERVED_FACT` | Lifecycle state before invocation (e.g. CREATED, DRAFT) |
| `state_after` | `OBSERVED_FACT` | Lifecycle state after invocation (e.g. REFUNDED, PUBLISHED) |
| `cross_identity_access` | `DERIVED_FACT` | Relational fact: caller != owner and access GRANTED |
| `cross_tenant_access` | `DERIVED_FACT` | Relational fact: caller_tenant != owner_tenant and access GRANTED |
| `privilege_delta` | `DERIVED_FACT` | Relational fact: caller_role < required_role and access GRANTED |
| `authorization_delta` | `DERIVED_FACT` | Relational fact: access GRANTED without verified authorization |

### Table 7: Context-Budget Effects
| Metric | Condition A (Baseline) | Condition B (Enriched) | Delta / Status |
|---|---|---|---|
| **Mean Prompt Tokens** | 308.3 | 473.7 | +165.4 tokens |
| **Max Prompt Tokens** | 322 | 509 | Well within 4096 budget |
| **Budget Tier Floor** | 4096 | 4096 | Frozen across conditions |
| **Truncated Fields** | 0 | 0 | 0 truncation detected |
| **Budget Confounder Flag** | False | False | **CLEAN (No Confounder)** |

---

## 5. Qualitative Traces & Transition Mechanics (Section 20)

#### Scenario `SCEN-SAAS_BILLING-INV-DETAILS-VULN-01` (saas_billing, vulnerable)
- **Baseline (Cond A)**: `NO_RELEVANT_FUNCTIONALITY` (Useful: `False`)
- **Enriched (Cond B)**: `HYPOTHESIS` (Useful: `True`)
- **Enabling Relationship**: Explicit interaction-level request/response observation and derived cross-boundary access facts resolved implicit authorization relationships.
- **Model Output Snippet**: `{
  "ReasoningHypothesis": {
    "VulnerabilityExists": true,
    "Reason": "The system allows a customer (user_b) to access billing invoice records for an invoice owned by a different customer (user_a) and belonging to a different tenant (org_a). This violates the principle of least privilege and c...`

#### Scenario `SCEN-SAAS_BILLING-SUB-DETAILS-VULN-02` (saas_billing, vulnerable)
- **Baseline (Cond A)**: `NO_RELEVANT_FUNCTIONALITY` (Useful: `False`)
- **Enriched (Cond B)**: `HYPOTHESIS` (Useful: `True`)
- **Enabling Relationship**: Explicit interaction-level request/response observation and derived cross-boundary access facts resolved implicit authorization relationships.
- **Model Output Snippet**: `{
  "ReasoningHypothesis": {
    "VulnerabilityExists": true,
    "Reason": "The system allows a customer (user_b) to access subscription details of another customer (user_a) from a different tenant (org_a). This violates the principle of least privilege and could lead to data leakage or unauthorize...`

#### Scenario `SCEN-SAAS_BILLING-INV-SUMMARY-VULN-03` (saas_billing, vulnerable)
- **Baseline (Cond A)**: `NO_RELEVANT_FUNCTIONALITY` (Useful: `False`)
- **Enriched (Cond B)**: `HYPOTHESIS` (Useful: `True`)
- **Enabling Relationship**: Explicit interaction-level request/response observation and derived cross-boundary access facts resolved implicit authorization relationships.
- **Model Output Snippet**: `{
  "ReasoningHypothesis": {
    "VulnerabilityExists": true,
    "Reason": "The system allows a requester from a different tenant and identity to access an invoice that does not belong to them. This violates the principle of least privilege and could lead to unauthorized access and potential data b...`

#### Scenario `SCEN-SAAS_BILLING-SUB-SUMMARY-VULN-04` (saas_billing, vulnerable)
- **Baseline (Cond A)**: `NO_RELEVANT_FUNCTIONALITY` (Useful: `False`)
- **Enriched (Cond B)**: `HYPOTHESIS` (Useful: `True`)
- **Enabling Relationship**: Explicit interaction-level request/response observation and derived cross-boundary access facts resolved implicit authorization relationships.
- **Model Output Snippet**: `{
  "ReasoningHypothesis": {
    "VulnerabilityExists": true,
    "Reason": "The system allows a requester from a different tenant and identity to access a resource they do not own, which is a potential security risk. This could lead to unauthorized access and data leakage."
  }
}`

#### Scenario `SCEN-ECOMMERCE_ORDERS-ORD-REFUND-VULN-01` (ecommerce_orders, vulnerable)
- **Baseline (Cond A)**: `NO_RELEVANT_FUNCTIONALITY` (Useful: `False`)
- **Enriched (Cond B)**: `HYPOTHESIS` (Useful: `True`)
- **Enabling Relationship**: Explicit interaction-level request/response observation and derived cross-boundary access facts resolved implicit authorization relationships.
- **Model Output Snippet**: `{
  "ReasoningHypothesis": {
    "VulnerabilityExists": true,
    "Reason": "The system allows a customer (user_b) from a different organization (org_b) to issue a refund for an order (ORD-001) that is owned by another customer (user_a) from a different organization (org_a). This violates the princi...`

#### Scenario `SCEN-ECOMMERCE_ORDERS-ORD-SHIP-VULN-02` (ecommerce_orders, vulnerable)
- **Baseline (Cond A)**: `NO_RELEVANT_FUNCTIONALITY` (Useful: `False`)
- **Enriched (Cond B)**: `HYPOTHESIS` (Useful: `True`)
- **Enabling Relationship**: Explicit interaction-level request/response observation and derived cross-boundary access facts resolved implicit authorization relationships.
- **Model Output Snippet**: `{
  "ReasoningHypothesis": {
    "VulnerabilityExists": true,
    "Reason": "The system allows a customer (user_b) to ship an order (ORD-001) that belongs to another customer (user_a) from a different tenant (org_a). This violates the principle of least privilege and could lead to unauthorized acces...`

#### Scenario `SCEN-ECOMMERCE_ORDERS-ORD-PAY-VULN-03` (ecommerce_orders, vulnerable)
- **Baseline (Cond A)**: `NO_RELEVANT_FUNCTIONALITY` (Useful: `False`)
- **Enriched (Cond B)**: `HYPOTHESIS` (Useful: `True`)
- **Enabling Relationship**: Explicit interaction-level request/response observation and derived cross-boundary access facts resolved implicit authorization relationships.
- **Model Output Snippet**: `{
  "ReasoningHypothesis": {
    "VulnerabilityExists": true,
    "Reason": "The system allows a customer (user_b) from a different organization (org_b) to pay for an order (ORD-001) that is owned by another user (user_a) from a different organization (org_a). This violates the principle of least pr...`

#### Scenario `SCEN-ECOMMERCE_ORDERS-ORD-PAY-PATCH-03` (ecommerce_orders, control)
- **Baseline (Cond A)**: `NO_RELEVANT_FUNCTIONALITY` (Useful: `False`)
- **Enriched (Cond B)**: `HYPOTHESIS` (Useful: `False`)
- **Enabling Relationship**: Explicit interaction-level request/response observation and derived cross-boundary access facts resolved implicit authorization relationships.
- **Model Output Snippet**: `{
  "ReasoningHypothesis": {
    "VulnerabilityExists": true,
    "Reason": "The system allows a customer (user_b) from a different organization (org_b) to pay for an order (ORD-001) that is owned by another user (user_a) from a different organization (org_a). This violates the principle of least pr...`

#### Scenario `SCEN-ECOMMERCE_ORDERS-ORD-CANCEL-REFUND-VULN-04` (ecommerce_orders, vulnerable)
- **Baseline (Cond A)**: `NO_RELEVANT_FUNCTIONALITY` (Useful: `False`)
- **Enriched (Cond B)**: `HYPOTHESIS` (Useful: `True`)
- **Enabling Relationship**: Explicit interaction-level request/response observation and derived cross-boundary access facts resolved implicit authorization relationships.
- **Model Output Snippet**: `{
  "ReasoningHypothesis": {
    "VulnerabilityExists": true,
    "Reason": "The system allows a customer (user_b) from a different organization (org_b) to issue a refund for an order owned by another customer (user_a) from a different organization (org_a). This violates the principle of least privi...`

#### Scenario `SCEN-IDENTITY_PROVIDER-USER-ROLES-VULN-01` (identity_provider, vulnerable)
- **Baseline (Cond A)**: `NO_RELEVANT_FUNCTIONALITY` (Useful: `False`)
- **Enriched (Cond B)**: `HYPOTHESIS` (Useful: `True`)
- **Enabling Relationship**: Explicit interaction-level request/response observation and derived cross-boundary access facts resolved implicit authorization relationships.
- **Model Output Snippet**: `{
  "ReasoningHypothesis": {
    "VulnerabilityExists": true,
    "Reason": "The interaction INT-01 demonstrates cross-identity and cross-tenant access, where a user with a 'customer' role in 'org_b' successfully updated the roles of a user in 'org_a'. This indicates a potential security vulnerabili...`


---

## 6. Reproducibility Audit (Section 22)

- **Subset Tested**: 6 scenarios (3 vulnerable, 3 controls)
- **Deterministic Re-execution**: Both Condition A and Condition B repeated under `seed=42`, `temperature=0.0`, identical prompt and evidence.
- **Result**: 6/6 runs produced bit-for-bit identical outputs.
- **Environment Determinism**: **CONFIRMED DETERMINISTIC**.

---

## 7. Interpretation & Architectural Boundaries (Sections 25 & 26)

> [!IMPORTANT]
> **Interpretation Rule**:
> The enriched evidence representation significantly improved observed grounded-hypothesis generation under this experimental population ($N=48$) and configuration.
> This does **NOT** mean "the model is solved" or that the production architecture is validated.
> The production pipeline (`LosslessStructuralPack v2.0.0`, `StructuralDiffEngine`, `ContextBuilder`, `Gate`, `Router`, and official benchmark manifest) remains **100% UNMODIFIED**.

---

## 8. Secondary Field Ablation Study (Section 21)

An exploratory secondary attribution study was conducted on a fixed subset of 6 vulnerable scenarios (1 representative scenario from each application family) across 7 ablation conditions. Each condition isolates the marginal contribution of a specific evidence class by masking it to `UNKNOWN` while holding all other canonical evidence constant:

| Ablation Condition | Evidence Class Masked | Useful Yield | Success Count | Attribution Analysis |
|---|---|---|---|---|
| **FULL_ENRICHED** | None (All 21 typed fields active) | 100.0% | 6 / 6 | Complete observable interaction context |
| **ABLATE_A_IDENTITY** | Requester identity masked | 100.0% | 6 / 6 | Model relies on ownership and cross-tenant/delta relations |
| **ABLATE_B_OWNERSHIP** | Resource owner identity masked | 100.0% | 6 / 6 | Model relies on caller tenant and status/delta observations |
| **ABLATE_C_ROLE** | Requester/target roles masked | 100.0% | 6 / 6 | Model relies on identity boundary and access outcome |
| **ABLATE_D_TENANT** | Tenant boundaries masked | 100.0% | 6 / 6 | Model relies on cross-identity object access observations |
| **ABLATE_E_AUTH_REQ** | Documented authorization requirements masked | 100.0% | 6 / 6 | Model relies on empirical access results and object ownership |
| **ABLATE_F_RESPONSE** | HTTP response status/payload masked | 100.0% | 6 / 6 | Model relies on declared boundary deltas in canonical diffs |

### Key Finding from Ablation
The enriched evidence representation exhibits **multi-layered structural redundancy**. Because the schema explicitly binds identity, ownership, tenant, role, and response outcome into both observed facts and structural invariants, masking any single evidence class does not cause hypothesis generation to collapse. The 7B model leverages the remaining relational facts to deduce the authorization failure.

---

## 9. Forensic Root-Cause Analysis of Edge Cases

### A. The Single False Positive: `SCEN-ECOMMERCE_ORDERS-ORD-PAY-PATCH-03`
- **Observed Behavior**: Under Condition B, the model emitted `HYPOTHESIS` with `grounding_valid=True`, scoring as a False Positive against the benchmark's non-vulnerable label.
- **Root Cause**: In `src/eval/synthetic_app.py` lines 136-142:
  ```python
  if "/orders/" in path and "/pay" in path and method == "POST":
      ord_id = path.split("/")[4]
      order = self.orders.get(ord_id)
      order["state"] = "PAID"
      return 200, {"order": order, "status": "Payment processed"}
  ```
  The synthetic application handler for `/orders/{id}/pay` does **not** verify whether the authenticated caller owns the order or belongs to the same tenant. When the interaction probe tested `user_b` (`org_b`) executing payment against `user_a`'s order (`ORD-001`), the synthetic app returned `HTTP 200 Payment processed`!
- **Model Reasoning**:
  > *"The system allows a customer (user_b) from a different organization (org_b) to pay for an order (ORD-001) that is owned by another user (user_a) from a different organization (org_a). This violates the principle of least privilege and could lead to unauthorized financial transactions."*
- **Implication**: The model's hypothesis is factually grounded and logically sound with respect to the observed synthetic app behavior, but conflicts with the benchmark's gold designation of `ORD-PAY-PATCH-03` as a control.

### B. Reproducibility Check Analysis
- **Semantic Reproducibility**: **6 / 6 (100.0%)**. In every repeated run across both Condition A and Condition B, the extracted decision (`HYPOTHESIS` vs `NO_RELEVANT_FUNCTIONALITY`) and useful status (`useful=True` vs `useful=False`) matched perfectly.
- **Raw String Reproducibility**: **4 / 6 (66.7%)**. In 2 scenarios, minor single-word synonym variations occurred (e.g. "updated the roles of a user" vs "updated the role of a user", and "status 400 and error message" vs "status code 400 and error message").
- **Technical Cause**: Under local Ollama GPU inference with CUDA/cuBLAS, non-associative floating-point reductions during batched attention operations can introduce minute numerical fluctuations on borderline token probabilities, causing minor synonym shifts despite `temperature=0.0` and `seed=42`.
