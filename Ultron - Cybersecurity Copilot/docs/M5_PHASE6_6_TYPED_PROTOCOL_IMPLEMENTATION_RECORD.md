# M5 Phase 6.6 — Typed Protocol Implementation Record: Pre-Implementation Reconciliation

**Date**: 2026-09-21  
**Milestone**: M5 Phase 6.6  
**Author**: Antigravity Autonomous Agent (Pair Programming with User)  
**Status**: Authoritative Pre-Implementation Freeze  

---

## 1. Executive Summary

In accordance with M5 Phase 6.6 requirements, this record documents the pre-implementation audit and identifier reconciliation across the entire repository prior to modifying production code for the Typed Experiment-Outcome Protocol.

No production code modifications or live inferences were performed prior to freezing these identifiers.

---

## 2. Vulnerability Category Reconciliation

### 2.1 Benchmark Category Inventory (`src/eval/scenarios.py`)
All 84 frozen scenarios in `src/eval/scenarios.py` utilize exactly 10 distinct `category_id` values across 3 high-level categories (`authorization`, `business_logic`, `public_endpoint`):

| Category ID | Count | App Families | Benchmark Category | Scenario Description Summary |
| :--- | :--- | :--- | :--- | :--- |
| `API-BOLA-001` | 10 | `document_collaboration`, `healthcare_portal`, `saas_billing` | `authorization` | Broken Object Level Authorization (invoice/record details) |
| `API-DEVICE-BOLA-001` | 4 | `iot_fleet_mgmt` | `authorization` | Device-level command dispatch object authorization |
| `API-CROSS-TENANT-001` | 12 | `document_collaboration`, `healthcare_portal`, `iot_fleet_mgmt`, `saas_billing` | `authorization` | Tenant boundary / isolation breakdown on resource access |
| `API-STATE-001` | 12 | `document_collaboration`, `ecommerce_orders` | `business_logic` | State-machine lifecycle sequence violation (e.g. refunding unapproved order) |
| `API-LIFECYCLE-001` | 8 | `ecommerce_orders`, `healthcare_portal` | `business_logic` | Invalid state transition on terminal/inactive objects (cancelled order, discharged patient) |
| `API-MULTI-STEP-AUTH-001` | 6 | `document_collaboration`, `saas_billing` | `authorization` | Multi-party workflow step bypassing / out-of-order execution |
| `API-BFLA-001` | 6 | `identity_provider`, `iot_fleet_mgmt` | `authorization` | Broken Function Level Authorization (privileged role assignment, firmware updates) |
| `API-ROLE-BOUNDARY-001` | 6 | `healthcare_portal`, `identity_provider` | `authorization` | Cross-tenant role assignment / boundary enforcement failure |
| `API-MUTATION-001` | 8 | `identity_provider`, `iot_fleet_mgmt`, `saas_billing` | `authorization` | Parameter tampering / mutation on security configurations and plan tiers |
| `API-AUTH-NONE` | 12 | All 6 families | `public_endpoint` | Unauthenticated public endpoints (Negative Controls) |
| **Total** | **84** | **6 Families** | — | — |

### 2.2 BFLA Reconciliation: `API-BFLA-001` vs `API-BFLA-002`
An audit of all references across the repository reveals:
1. `src/eval/scenarios.py`: Exclusively uses `API-BFLA-001` across 6 scenarios (`SCEN-IDENTITY_PROVIDER-USER-ROLES-VULN-01`, `SCEN-IDENTITY_PROVIDER-USER-ROLES-PATCH-01`, `SCEN-IOT_FLEET_MGMT-DEVICE-FW-VULN-05`, `SCEN-IOT_FLEET_MGMT-DEVICE-FW-PATCH-05`, etc.).
2. `taxonomy/categories.yaml`: Defines `- id: API-BFLA-002` (name: Broken Function Level Authorization).
3. `src/engine/prompts.py`: Defines an explicit normalization alias: `"API-BFLA-002": "API-BFLA-001"`.
4. `src/engine/decision_policy.py`: Line 240 checks `elif cat_id == "API-BFLA-002":`.
5. `src/engine/triage_runner.py`: Specifies `"API-BOLA-001" | "API-BFLA-002" | ...`.
6. `src/evidence/gate.py`: Sets `cats = {"API-BOLA-001", "API-BFLA-002", ...}`.
7. `tests/unit/test_context_builder.py`: Uses `suspected_category="API-BFLA-002"`.

**Reconciliation Decision**:
Both identifiers designate Broken Function Level Authorization. The typed experiment protocol compatibility registry must recognize **both** `API-BFLA-001` and `API-BFLA-002` identically, mapping both to the `REPLAY_STEP_WITH_LOWER_ROLE` action and role-elevation outcomes. In addition, `src/engine/decision_policy.py` line 240 must be updated to accept both `API-BFLA-001` and `API-BFLA-002`.

---

## 3. Application Families Reconciliation

The repository contains exactly 6 application families in `src/eval/scenarios.py`:
1. `saas_billing` (development split: 14 scenarios)
2. `ecommerce_orders` (development split: 14 scenarios)
3. `identity_provider` (validation split: 14 scenarios)
4. `document_collaboration` (validation split: 14 scenarios)
5. `healthcare_portal` (evaluation split: 14 scenarios)
6. `iot_fleet_mgmt` (evaluation split: 14 scenarios)

All 6 families are fully accounted for in the category mapping.

---

## 4. EvidenceGapType Reconciliation (`src/knowledge/models.py`)

The enum `EvidenceGapType` defines exactly 6 values:
1. `MISSING_CROSS_IDENTITY_OBJECT_VERIFICATION` (corresponds to `API-BOLA-001`, `API-DEVICE-BOLA-001`)
2. `MISSING_TENANT_ISOLATION_CHECK` (corresponds to `API-CROSS-TENANT-001`)
3. `MISSING_ROLE_HIERARCHY_ENFORCEMENT` (corresponds to `API-BFLA-001`, `API-BFLA-002`, `API-ROLE-BOUNDARY-001`)
4. `MISSING_MUTATION_STATE_BOUNDARY` (corresponds to `API-STATE-001`, `API-LIFECYCLE-001`, `API-MULTI-STEP-AUTH-001`)
5. `MISSING_INPUT_TYPE_TAMPER_CONTROL` (corresponds to `API-MUTATION-001`)
6. `MISSING_UNAUTHENTICATED_ACCESS_CHECK` (corresponds to `API-AUTH-NONE`)

---

## 5. Closed Taxonomy for Typed Experiment Protocol

### 5.1 Experiment Actions (`ExperimentActionPredicate`)
- `SUBSTITUTE_RESOURCE_IDENTIFIER`
- `EXECUTE_OUT_OF_ORDER_TRANSITION`
- `REPLAY_STEP_WITH_LOWER_ROLE`
- `INVOKE_WITHOUT_CREDENTIALS`
- `TAMPER_REQUEST_PARAMETER`

### 5.2 HTTP Status Outcomes (`HttpOutcomePredicate`)
- `HTTP_200_OK`
- `HTTP_201_CREATED`
- `HTTP_204_NO_CONTENT`
- `HTTP_400_BAD_REQUEST`
- `HTTP_401_UNAUTHORIZED`
- `HTTP_403_FORBIDDEN`
- `HTTP_404_NOT_FOUND`
- `HTTP_409_CONFLICT`

### 5.3 Semantic Invariant Outcomes (`SemanticOutcomePredicate`)
- `STATUS_SUCCESS_2XX`
- `STATUS_CLIENT_ERROR_4XX`
- `CROSS_IDENTITY_OBJECT_ACCESSIBLE`
- `CROSS_IDENTITY_OBJECT_DENIED`
- `OWNERSHIP_NOT_ENFORCED`
- `OWNERSHIP_ENFORCED`
- `STATE_TRANSITION_ACCEPTED`
- `STATE_TRANSITION_REJECTED`
- `PRIVILEGE_ELEVATION_SUCCEEDS`
- `PRIVILEGE_ELEVATION_DENIED`
- `UNAUTHENTICATED_ACCESS_ALLOWED`
- `UNAUTHENTICATED_ACCESS_DENIED`

---

## 6. Deterministic 4-Tuple Compatibility Registry

The compatibility validator verifies:
`(category, experiment_action, supporting_outcome, disproving_outcome)`

```
CATEGORY -> allowed experiment actions
CATEGORY + ACTION -> allowed breach outcomes
CATEGORY + ACTION -> allowed safe outcomes
```

### Complete Tuple Specification Table:

1. **Object Authorization / BOLA** (`API-BOLA-001`, `API-DEVICE-BOLA-001`, `API-CROSS-TENANT-001`):
   - Action: `SUBSTITUTE_RESOURCE_IDENTIFIER`
   - Allowed Breach (supporting):
     - `HTTP_200_OK`, `HTTP_201_CREATED`, `HTTP_204_NO_CONTENT`, `STATUS_SUCCESS_2XX`, `CROSS_IDENTITY_OBJECT_ACCESSIBLE`, `OWNERSHIP_NOT_ENFORCED`
   - Allowed Safe (disproving):
     - `HTTP_403_FORBIDDEN`, `HTTP_404_NOT_FOUND`, `STATUS_CLIENT_ERROR_4XX`, `CROSS_IDENTITY_OBJECT_DENIED`, `OWNERSHIP_ENFORCED`

2. **State Machine / Business Logic** (`API-STATE-001`, `API-LIFECYCLE-001`, `API-MULTI-STEP-AUTH-001`):
   - Action: `EXECUTE_OUT_OF_ORDER_TRANSITION`
   - Allowed Breach (supporting):
     - `HTTP_200_OK`, `HTTP_201_CREATED`, `HTTP_204_NO_CONTENT`, `STATUS_SUCCESS_2XX`, `STATE_TRANSITION_ACCEPTED`
   - Allowed Safe (disproving):
     - `HTTP_400_BAD_REQUEST`, `HTTP_409_CONFLICT`, `STATUS_CLIENT_ERROR_4XX`, `STATE_TRANSITION_REJECTED`

3. **Function Level Authorization (BFLA) & Role Boundaries** (`API-BFLA-001`, `API-BFLA-002`, `API-ROLE-BOUNDARY-001`):
   - Action: `REPLAY_STEP_WITH_LOWER_ROLE`
   - Allowed Breach (supporting):
     - `HTTP_200_OK`, `HTTP_201_CREATED`, `HTTP_204_NO_CONTENT`, `STATUS_SUCCESS_2XX`, `PRIVILEGE_ELEVATION_SUCCEEDS`
   - Allowed Safe (disproving):
     - `HTTP_401_UNAUTHORIZED`, `HTTP_403_FORBIDDEN`, `STATUS_CLIENT_ERROR_4XX`, `PRIVILEGE_ELEVATION_DENIED`

4. **Parameter Tampering / Mutation** (`API-MUTATION-001`):
   - Action: `TAMPER_REQUEST_PARAMETER`
     - Allowed Breach: `HTTP_200_OK`, `HTTP_201_CREATED`, `STATUS_SUCCESS_2XX`, `PRIVILEGE_ELEVATION_SUCCEEDS`
     - Allowed Safe: `HTTP_400_BAD_REQUEST`, `HTTP_403_FORBIDDEN`, `STATUS_CLIENT_ERROR_4XX`, `PRIVILEGE_ELEVATION_DENIED`
   - Action: `REPLAY_STEP_WITH_LOWER_ROLE`
     - Allowed Breach: `HTTP_200_OK`, `STATUS_SUCCESS_2XX`, `PRIVILEGE_ELEVATION_SUCCEEDS`
     - Allowed Safe: `HTTP_401_UNAUTHORIZED`, `HTTP_403_FORBIDDEN`, `STATUS_CLIENT_ERROR_4XX`, `PRIVILEGE_ELEVATION_DENIED`

5. **Authentication / Public Endpoints** (`API-AUTH-NONE`):
   - Action: `INVOKE_WITHOUT_CREDENTIALS`
   - Allowed Breach:
     - `HTTP_200_OK`, `STATUS_SUCCESS_2XX`, `UNAUTHENTICATED_ACCESS_ALLOWED`
   - Allowed Safe:
     - `HTTP_401_UNAUTHORIZED`, `HTTP_403_FORBIDDEN`, `STATUS_CLIENT_ERROR_4XX`, `UNAUTHENTICATED_ACCESS_DENIED`

### Fail-Closed Invariants:
1. `category` not in registry: FAIL CLOSED (`is_valid=False`).
2. `experiment_action` not allowed for `category`: FAIL CLOSED.
3. `supporting_outcome` not in `allowed_breach_outcomes(category, action)`: FAIL CLOSED.
4. `disproving_outcome` not in `allowed_safe_outcomes(category, action)`: FAIL CLOSED.
5. `supporting_outcome == disproving_outcome`: FAIL CLOSED.
6. Any free-text or unparsed string: FAIL CLOSED.
