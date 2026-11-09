# Milestone M5 Phase 11.4: Security Property Alignment & Track D Interaction Preregistration

**Protocol Identifier**: `M5_PHASE11_4_PROPERTY_ALIGNMENT_AND_TRACK_D_PREREGISTRATION_V1`  
**Registration Date (UTC)**: 2026-09-29  
**Governance State**: PREREGISTERED PRIOR TO LIVE INFERENCE  
**Status**: ACTIVE & BINDING  

---

## 1. Context & Research Questions

Phase 11.3 demonstrated that bounding candidate fact citations and target endpoint identifiers to scenario-local evidence eliminated semantic grounding failures (100% Grounding Success) and recovered non-zero yield (**50.0% VTER** under P3).
Crucially, the remaining 4 failure calls in Phase 11.3 were all caused by **security property mismatches** in the `attack_predicate` (e.g., asserting `TENANT_ISOLATION` on an order refund lifecycle route, or `LIFECYCLE_ORDERING` on a tenant role assignment route). In strict adherence to fail-closed design, the deterministic outcome binder refused to bind outcomes on mismatched security properties, resulting in downstream polarity failure attributions.

Phase 11.4 addresses two distinct research questions:

### Question A — Security Property Alignment
> *Does constraining the attack_predicate security_property to a deterministic category-compatible vocabulary improve valid typed experiment construction and useful hypothesis yield?*

### Question B — Track D Context Interaction
> *After applying the validated polarity + grounding + property-alignment architecture, does the full Track D context package (cascade + RAG) still degrade reasoning performance?*

---

## 2. Experimental Structure & Hypotheses

Phase 11.4 uses a sequential two-step experimental design:

### Step 1: P3 (Control) vs. P4 (Treatment) on Track A (16 live calls)
- **P3 Control**: Grounding-shielded baseline from Phase 11.3 (bounded facts + bounded targets, unconstrained global 10-property enum for `security_property`, deterministic outcome binding, minimal Track A context).
- **P4 Treatment**: P3 + **Security Property Shielding**. The `attack_predicate.security_property` is strictly constrained in prompt and schema to the category's deterministic allowed property set.
- **Hypothesis H1 (Property Alignment)**: Bounding `security_property` to category-compatible domains will eliminate SP3 category mismatches, allowing candidate hypotheses in Lifecycle and Role-Boundary categories to successfully bind canonical breach/safe outcomes, increasing VTER from 50.0% to >75%.

### Step 2: P4 (Track A) vs. P5 (Track D) (16 live calls)
- Executed only after Step 1 has completed and verified.
- **P4 Track A**: P4 architecture evaluated under minimal Track A structural context.
- **P5 Track D**: Identical P4 architecture evaluated under the repository's authoritative Track D context (cascade handoff + dual RAG knowledge retrieval).
- **Hypothesis H2 (Track D Context Interaction)**: With structured output slots bounded (facts, targets, properties), the model will maintain structural grounding under Track D without schema degradation, testing whether earlier Track D failures in Phase 10 were driven by context distraction or token budget pressure.

---

## 3. Authoritative Category-to-Security-Property Registry

The deterministic registry is versioned (`1.0.0`) in `src/eval/phase11_4_property_alignment/property_registry.py` and strictly independent of ground truth:

| Vulnerability Category ID | Allowed Security Property Domains |
| :--- | :--- |
| `API-BOLA-001` | `OBJECT_LEVEL_AUTHORIZATION`, `RESOURCE_OWNERSHIP_INTEGRITY` |
| `API-DEVICE-BOLA-001` | `OBJECT_LEVEL_AUTHORIZATION`, `RESOURCE_OWNERSHIP_INTEGRITY` |
| `API-CROSS-TENANT-001` | `CROSS_TENANT_AUTHORIZATION`, `TENANT_ISOLATION` |
| `API-LIFECYCLE-001` | `LIFECYCLE_ORDERING`, `STATE_TRANSITION_INTEGRITY` |
| `API-STATE-001` | `LIFECYCLE_ORDERING`, `STATE_TRANSITION_INTEGRITY` |
| `API-ROLE-BOUNDARY-001` | `FUNCTION_LEVEL_AUTHORIZATION`, `ROLE_BOUNDARY_ENFORCEMENT` |
| `API-BFLA-001` | `FUNCTION_LEVEL_AUTHORIZATION`, `ROLE_BOUNDARY_ENFORCEMENT` |
| `API-BFLA-002` | `FUNCTION_LEVEL_AUTHORIZATION`, `ROLE_BOUNDARY_ENFORCEMENT` |
| `API-MULTI-STEP-AUTH-001` | `AUTHENTICATION_REQUIREMENT`, `LIFECYCLE_ORDERING`, `STATE_TRANSITION_INTEGRITY` |
| `API-MUTATION-001` | `MUTATION_INTEGRITY` |
| `API-AUTH-NONE` | `AUTHENTICATION_REQUIREMENT` |

---

## 4. Balanced Diagnostic Dataset (8 Scenarios)

The diagnostic evaluates the identical 8 balanced benchmark scenarios from Phase 11.2 and Phase 11.3 (4 vulnerable, 4 control):

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

Total call count:
- Step 1: 8 scenarios $\times$ 2 conditions (P3, P4) = 16 calls.
- Step 2: 8 scenarios $\times$ 2 conditions (P4 Track A, P5 Track D) = 16 calls.
- Combined total = **32 live inference calls**.

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

## 6. Deterministic Ordering

Calls are scheduled per scenario and pseudorandomly shuffled using deterministic order seed `M5_PHASE11_4_ORDER_SEED_42`:
- Step 1: `seed:step1:{scenario_id}` shuffles `["P3", "P4"]`.
- Step 2: `seed:step2:{scenario_id}` shuffles `["P4_TRACK_A", "P5_TRACK_D"]`.
The exact 32-call sequence is preregistered and executed sequentially.

---

## 7. Metrics & Deterministic Failure Taxonomy

### Primary Diagnostic Metric:
$$\text{VTER} = \frac{\text{Valid Typed Experiment Proposals}}{\text{Candidate HYPOTHESIS Attempts}}$$

### Property Validation Metrics:
- **Property Selection Success**: Model selected property $\in$ deterministic allowed set.
- **Property Semantic Compatibility**: Model selected property compatible with category + invariant + gap.

### Security Property Failure Taxonomy:
- `SP1 = PROPERTY_MISSING`: `security_property` is missing or empty.
- `SP2 = PROPERTY_OUT_OF_SET`: Not a member of `SecurityPropertyDomain`.
- `SP3 = PROPERTY_CATEGORY_MISMATCH`: Valid domain, but not allowed for scenario category.
- `SP4 = PROPERTY_INVARIANT_MISMATCH`: Property contradicts evaluated invariant.
- `SP5 = PROPERTY_EVIDENCE_GAP_MISMATCH`: Property incompatible with evidence gap.
- `SP99 = PROPERTY_UNRESOLVED`: Fail-safe unclassified property error.

---

## 8. Ground-Truth Firewall

- The model receives zero ground-truth labels, expected decisions, scoring markers, or variant suffixes.
- `allowed_security_properties` are derived solely from `category_id` and the invariant ontology.
- Vulnerable and patched variants of the same category receive identical allowed security properties.

---

## 9. Preregistered Stopping Rules

Live execution will immediately STOP if:
1. P3 control condition diverges from Phase 11.3 implementation.
2. Canonical property mapping cannot be established for a scenario category.
3. Post-Step 1 audit shows P4 unexpectedly breaks grounding, action, or polarity architecture.
4. Model digest differs from `dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364`.
5. Any external network egress is detected.
6. Historical benchmark artifact digests differ from sealed references.

---

## 10. Execution Command

```bash
.venv/Scripts/python.exe -c "from src.eval.phase11_4_property_alignment.runner import Phase11_4DiagnosticRunner; Phase11_4DiagnosticRunner().run_all()"
```
