# Milestone M5 Phase 11.2 — Polarity Representation Diagnostic Preregistration
**Local AI-Assisted Bug Bounty Research Platform**
**Authoritative Version**: 1.0.0
**Preregistered Date (UTC)**: 2026-09-28
**Governance State**: Small Live Diagnostic Pass ($N = 16$ calls across 8 balanced scenarios); Historical M5 Phase 10 SEALED & IMMUTABLE (`m5-phase10-final-audited`, commit `cbc31ea7c52fb3ab3af2dc57aafb2c7cc1d3acc8`).

---

## 1. Research Question

Phase 11.1 root-cause analysis identified 117 semantic experiment polarity failures (`F07`), including 32 exact breach/safe inversions (`F16`), across the sealed Phase 10 benchmark. This failure mode was concentrated in candidate hypothesis attempts where the 7B reasoner successfully parsed the OpenAPI structural context, identified the relevant vulnerability category, and adhered to the deterministic experiment action, but selected inverted outcome tokens (e.g., emitting `HTTP_403_FORBIDDEN` as "supporting" and `HTTP_200_OK` as "disproving").

The research question for Phase 11.2 is:
> **"Does replacing model-generated supporting/disproving outcome selection with a model-generated attack predicate, followed by deterministic outcome binding, improve valid typed experiment construction?"**

---

## 2. Preregistered Hypothesis & Prediction Direction

### Core Causal Factor Under Test:
**Polarity Representation Interface** (Decoupling vulnerability intent from lexical outcome token decoding).

### Prediction Direction:
1. **Primary Prediction**: Under Condition P1 (Attack Predicate + Deterministic Outcome Binding), the **Valid Typed Experiment Rate (VTER)** on candidate hypothesis attempts will be substantially higher than under Condition P0 (Control: model outcome token selection).
2. **Polarity Failure Elimination**: Lexical polarity inversions (`F16`) will drop to 0 under P1 because the deterministic outcome engine binds outcomes strictly from the trusted compatibility registry (`TUPLE_COMPATIBILITY_REGISTRY`).
3. **Control Integrity**: Negative control scenarios will maintain their valid abstention behavior without artificial inflation of false positive experiment proposals.

---

## 3. Experimental Conditions

The diagnostic evaluates two paired conditions across Track A (Minimal Structural Context):

### Condition P0 — Current Typed Polarity Interface (Control)
- **Protocol**: Standard Phase 10 JSON_BAIR output format.
- **Model Output Fields**: `decision`, `invariant`, `evidence_gap`, `affected_target`, `empirical_facts`, `methodology_references`, `experiment_action`, `supporting_outcome`, `disproving_outcome`, `falsification_description`.
- **Validation**: Strict deterministic verification of action legality, outcome legality, polarity orientation, grounding, and schema via `ExperimentPolarityValidator.validate_tuple(...)`.

### Condition P1 — Attack-Predicate Interface (Treatment)
- **Protocol**: P1 Attack-Predicate output format (`P1BairJsonObject`).
- **Supplied Engine Context**: Category identifier, deterministic experiment action, structural OpenAPI slice, security invariant definition.
- **Model Output Fields**: `decision`, `invariant`, `evidence_gap`, `affected_target`, `empirical_facts`, `methodology_references`, `attack_predicate`, `falsification_description`.
  * The model **MUST NOT** emit `supporting_outcome` or `disproving_outcome`.
  * `attack_predicate` is a typed, bounded object:
    ```json
    {
      "subject": "UNAUTHORIZED_ACTOR | TENANT_B_USER | LOWER_ROLE_ACTOR | ...",
      "operation": "SUBSTITUTE_RESOURCE_IDENTIFIER | EXECUTE_OUT_OF_ORDER_TRANSITION | ...",
      "target": "string (endpoint / parameter / resource ID)",
      "security_property": "RESOURCE_OWNERSHIP_INTEGRITY | TENANT_ISOLATION | ...",
      "expected_violation": "string"
    }
    ```
- **Deterministic Engine Outcome Binding**:
  The engine maps:
  $$(\text{category\_id}, \text{experiment\_action}) + \text{validated AttackPredicate} \longrightarrow (\text{canonical supporting\_outcome}, \text{canonical disproving\_outcome})$$
  using the authoritative `TUPLE_COMPATIBILITY_REGISTRY`. Emitted outcomes are explicitly tagged `outcome_origin: "DETERMINISTICALLY_DERIVED"`.

---

## 4. Diagnostic Scenario Selection & Balance

To isolate polarity representation from Track D RAG confounding, the study is restricted to **Track A (Minimal Structural Context)**.
The sample size is fixed at **8 scenarios (4 vulnerable, 4 controls)** across 4 representative categories:

| # | Scenario ID | Category ID | Variant | Family | Description |
| :-: | :--- | :--- | :-: | :--- | :--- |
| 1 | `SCEN-SAAS_BILLING-INV-DETAILS-VULN-01` | `API-BOLA-001` | **VULN** | SaaS Billing | Invoice details cross-account access |
| 2 | `SCEN-SAAS_BILLING-INV-DETAILS-PATCH-01` | `API-BOLA-001` | **CONTROL** | SaaS Billing | Invoice details tenant-isolated |
| 3 | `SCEN-ECOMMERCE_ORDERS-ORD-CANCEL-REFUND-VULN-04` | `API-LIFECYCLE-001` | **VULN** | E-Commerce | Out-of-order refund after cancel |
| 4 | `SCEN-ECOMMERCE_ORDERS-ORD-CANCEL-REFUND-PATCH-04` | `API-LIFECYCLE-001` | **CONTROL** | E-Commerce | Enforced order state transitions |
| 5 | `SCEN-IDENTITY_PROVIDER-USER-TENANT-ROLE-VULN-03` | `API-ROLE-BOUNDARY-001` | **VULN** | Identity Provider | Role boundary elevation bypass |
| 6 | `SCEN-IDENTITY_PROVIDER-USER-TENANT-ROLE-PATCH-03` | `API-ROLE-BOUNDARY-001` | **CONTROL** | Identity Provider | Role boundary strictly enforced |
| 7 | `SCEN-SAAS_BILLING-INV-SUMMARY-VULN-03` | `API-CROSS-TENANT-001` | **VULN** | SaaS Billing | Cross-tenant invoice summary access |
| 8 | `SCEN-SAAS_BILLING-INV-SUMMARY-PATCH-03` | `API-CROSS-TENANT-001` | **CONTROL** | SaaS Billing | Cross-tenant invoice summary isolated |

### Selection Procedure Guarantees:
- Selected before live execution.
- Exactly 1 vulnerable and 1 control scenario per category family.
- All 8 scenarios exhibited candidate hypothesis generation in Phase 10 C1.
- Zero selection bias based on P0/P1 live execution results.

---

## 5. Frozen Runtime Configuration

- **Local Ollama Daemon**: `v0.34.1` (`http://127.0.0.1:11434`)
- **Model**: `qwen2.5-coder:7b`
- **Model Digest**: `dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364`
- **Context Window (`num_ctx`)**: `2048`
- **Max Generation Tokens (`num_predict`)**: `300`
- **Temperature**: `0.0` (greedy deterministic decoding)
- **Seed**: `42`
- **Keep-Alive**: `60m`
- **Timeout Policy**: 30.0s hard inference ceiling (+500ms teardown tolerance).
- **Execution Limits**: Exactly 1 attempt per cell (8 scenarios $\times$ 2 conditions = 16 calls). Zero retries, zero repairs, zero fallbacks.

---

## 6. Execution Order & Randomization

Condition ordering is pseudorandomized per scenario using deterministic seed `M5_PHASE11_2_ORDER_SEED_42`:
$$\text{seed\_int} = \text{int}\Big(\text{SHA256}\big(\texttt{"M5\_PHASE11\_2\_ORDER\_SEED\_42:"} + \text{scenario\_id}\big)[:16], 16\Big)$$

Pre-computed execution order:
- `SCEN-SAAS_BILLING-INV-DETAILS-VULN-01`: Deterministic Order [P0, P1] or [P1, P0]
- `SCEN-SAAS_BILLING-INV-DETAILS-PATCH-01`: Deterministic Order
- `SCEN-ECOMMERCE_ORDERS-ORD-CANCEL-REFUND-VULN-04`: Deterministic Order
- `SCEN-ECOMMERCE_ORDERS-ORD-CANCEL-REFUND-PATCH-04`: Deterministic Order
- `SCEN-IDENTITY_PROVIDER-USER-TENANT-ROLE-VULN-03`: Deterministic Order
- `SCEN-IDENTITY_PROVIDER-USER-TENANT-ROLE-PATCH-03`: Deterministic Order
- `SCEN-SAAS_BILLING-INV-SUMMARY-VULN-03`: Deterministic Order
- `SCEN-SAAS_BILLING-INV-SUMMARY-PATCH-03`: Deterministic Order

---

## 7. Metrics & Statistical Estimands

### Primary Diagnostic Estimand:
**Valid Typed Experiment Rate (VTER)**:
$$\text{VTER} = \frac{\text{Valid Typed Experiment Proposals}}{\text{Candidate HYPOTHESIS Attempts}}$$

### Secondary Diagnostic Estimands:
1. **Scenario-Level Success Rate**: Valid Typed Experiments / Total Scenarios ($N = 8$).
2. **Polarity Failure Rate**: Polarity Failures (`F07`) / Candidate HYPOTHESIS Attempts.
3. **Useful Vulnerable Hypothesis Yield**: Valid Typed Experiments on Vulnerable Variants ($N = 4$).
4. **Valid Control Abstention Rate**: Clean non-hypothesis decisions on Control Variants ($N = 4$).
5. **Inference Latency**: Mean, median, and P95 latency (ms).

### Paired Comparison:
- 2x2 Contingency Table for Scenario-Level Success (McNemar paired comparison structure).

---

## 8. Failure Taxonomy & Attribution Rules

Uses the authoritative Phase 11.1 deterministic precedence ladder:
1. `F02` — RUNTIME_TIMEOUT (>30.0s)
2. `F04` — PARSER_FAILURE (Invalid JSON syntax)
3. `F05` — SCHEMA_FAILURE (Schema violation, missing mandatory slots)
4. `F06` — GROUNDING_FAILURE (Target or cited parameters not in Channel A slice)
5. `F08` — ACTION_SELECTION_FAILURE (Action incompatible with category)
6. `F07` — POLARITY_FAILURE (Outcome mismatch, invalid breach/safe orientation)
7. `F09` — CATEGORY_SELECTION_FAILURE
8. `F11` — ABSTENTION_TOO_EARLY (Abstention on confirmed vulnerable variant)
9. `F01` — VALID_TYPED (Passed all validations)
10. `F99` — UNRESOLVED (Fail-safe default)

---

## 9. Ground Truth Firewall & Immutability Rules

1. **Firewall**: Neither the prompt builder, LLM runner, nor outcome binding engine has access to `vulnerable_variant` or expected decisions.
2. **Phase 10 Immutability**:
   - `data/eval/m5_phase10_full_population_validation.json` MUST remain untouched (`6821d207729de97ac99657a09e38c25895a73285fe9c485d299dc27f37d2bdba`).
   - `data/eval/m5_phase10_checkpoint.json` MUST remain untouched (`40f9f725fca5fdf05a76836182960b7f0d4c303a182d6e8af068a1b57e8f4537`).
3. **Secret Exclusion**: Assert zero passwords, bearer tokens, or sensitive API keys in recorded outputs.
4. **Stopping Rule**: Stop immediately if runtime fails preflight or unhandled schema corruption occurs.
