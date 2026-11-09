# Milestone M5 Phase 6.4 — Benchmark Semantics Decision & Falsification Polarity Audit Record

**Document Identifier**: `docs/M5_PHASE6_4_BENCHMARK_SEMANTICS_DECISION.md`  
**Phase Status**: COMPLETE (AUDIT & DECISION RECORD)  
**Governance & Constraints**: Strictly offline audit. Zero live LLM calls. Zero modifications to frozen planning documents, M4.9 artifacts, M3 artifacts, or benchmark scenario definitions.  
**Repository State Classification**: **STATE 4: BENCHMARK-BLOCKED — BOTH (Semantic Protocol Defect & Benchmark Policy Conflict)**

---

## Executive Summary

Milestone M5 Phase 6.3 determined that Call #24 (`SCEN-SAAS_BILLING-INV-DETAILS-PATCH-01`, Track D, `I1=1`, `FINAL DECISION=HYPOTHESIS`) was not an engine implementation breakdown, but rather the consequence of:
1. Vulnerable and patched scenarios receiving byte-identical neutral initial OpenAPI evidence;
2. VAPT methodology retrieval prompting the generation of a valid, discriminative verification experiment; and
3. `deterministic_decide()` preserving structurally complete hypotheses on relevant targets.

Phase 6.3 also discovered a critical semantic vulnerability: the falsification validator enforces keyword presence rather than semantic polarity. In Scenario 2 (Ecommerce Refund), the model inverted the falsification logic (asserting that HTTP 409/400 rejection *supported* the vulnerability hypothesis and that successful out-of-order execution *disproved* it), yet passed structural validation.

This Phase 6.4 audit formally documents:
- **Part I**: The architectural definitions, benchmark policy, and the fundamental semantic conflict between exploratory hypotheses and static ground-truth labeling.
- **Part II**: The mathematical and source-level proof of the falsification polarity blind spot, and evaluation of protocol alternatives (Options A, B, and C).
- **Part III**: The definitive repository classification blocking the 84-scenario benchmark.

---

## Part I: Benchmark-Policy Semantics Audit

### 1. Frozen Architectural Definitions

From [`docs/M4_REASONING_ENGINE_PLAN.md`](file:///c:/Projects/Bug%20Bounty%20AI/docs/M4_REASONING_ENGINE_PLAN.md) (Section 5, lines 152–170), [`docs/M1_5_M2_PLAN.md`](file:///c:/Projects/Bug%20Bounty%20AI/docs/M1_5_M2_PLAN.md) (Section 11.4), and [`src/engine/runner.py`](file:///c:/Projects/Bug%20Bounty%20AI/src/engine/runner.py) (lines 65–81):

- **Security Invariant**: A formal operational statement defining the security policy boundary of the target asset (e.g. *"Object access must verify that the requesting identity owns or is explicitly authorized to access the specific target resource identifier"*).
- **Evidence Gap**: A concrete observation or analytical absence in canonical evidence indicating either that an invariant check is not demonstrated or that an unverified pathway exists.
- **Security Hypothesis**: An evidence-supported security-invariant concern with a defined affected behavior/object/action and a falsifiable experiment proposal. Never implies vulnerability confirmation.
- **Experiment Proposal**: A bounded, reproducible operational procedure specifying both:
  1. A concrete observation that would support the hypothesis (confirming invariant breach); and
  2. A concrete observation that would disprove/falsify the hypothesis (upholding the invariant).
- **Useful Hypothesis**: A hypothesis emitted for a truly vulnerable target scenario that matches the gold-standard category, asset ID, and vulnerable parameter, and passes grounding and validation gates.
- **Decision States**:
  - `HYPOTHESIS`:
    - *Prompt Specification (`SYSTEM_POLICY_PROMPT`)*: *"Evidence indicates, implies, or strongly suggests a potential invariant violation, or relevant functionality has an unverified invariant requiring experiment verification."*
    - *Plan Specification (`M4_REASONING_ENGINE_PLAN.md` Section 8)*: All mandatory invariant, evidence gap, affected target, and falsification conditions are satisfied, and the proposal is grounded in empirical facts.
  - `INSUFFICIENT_EVIDENCE`:
    - *Prompt Specification*: *"Asset functionality is relevant to the category, but available evidence is incomplete or lacks comparison observations."*
    - *Plan Specification*: The examined functionality is relevant to the security property under inspection, but one or more pre-declared discriminating observations needed to confirm or falsify the invariant violation are absent.
  - `NO_RELEVANT_FUNCTIONALITY`:
    - Empirical evidence indicates the tested functionality is entirely outside the examined security property (e.g. public static metadata, unauthenticated informational endpoints with no state mutation).
  - `CONFIRMED`: Strictly forbidden in the reasoning engine layer (fails closed).

### 2. Frozen Benchmark Definition of `expected_decision` and Controls

From [`src/eval/scenarios.py`](file:///c:/Projects/Bug%20Bounty%20AI/src/eval/scenarios.py) (lines 24–170) and [`docs/M1_5_M2_PLAN.md`](file:///c:/Projects/Bug%20Bounty%20AI/docs/M1_5_M2_PLAN.md) (lines 1420–1445):

- **True Positive (TP)**: Model emits `HYPOTHESIS` on a vulnerable scenario (`ground_truth_vulnerable = True`, `expected_decision = HYPOTHESIS`), passes grounding, and matches gold asset/parameter.
- **False Positive (FP)**: Model emits `HYPOTHESIS` on a patched scenario (`ground_truth_vulnerable = False`, `expected_decision = INSUFFICIENT_EVIDENCE`) or negative control (`expected_decision = NO_RELEVANT_FUNCTIONALITY`).
- **True Negative (TN)**: Model emits `INSUFFICIENT_EVIDENCE` or `NO_RELEVANT_FUNCTIONALITY` on a patched scenario or negative control.
- **False Negative (FN)**: Model emits `INSUFFICIENT_EVIDENCE` or `NO_RELEVANT_FUNCTIONALITY` on a truly vulnerable scenario.

### 3. Formal Semantic Case Analysis

| Case | Evidence & Target State | Architectural Intent | Current Benchmark `expected_decision` | Current Engine Output (Track D) | Alignment / Conflict |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **CASE 1: Observed Invariant Violation** | Active traffic logs demonstrate successful cross-identity object access (`200 OK`) or privilege escalation. | `HYPOTHESIS` (Observed violation requires confirmation experiment). | `HYPOTHESIS` | `HYPOTHESIS` | **ALIGNED** |
| **CASE 2: Unverified Relevant Endpoint (Initial Docs Only)** | Route accepts parameters and processes tenant data, but evidence consists solely of OpenAPI documentation without execution logs. Bounded experiment can discriminate invariant. | **AMBIGUOUS**: Prompt defines this as `HYPOTHESIS` (*"relevant functionality has an unverified invariant requiring experiment verification"*). Plan defines missing comparison observations as `INSUFFICIENT_EVIDENCE`. | `HYPOTHESIS` (if labeled `VULN`)<br>`INSUFFICIENT_EVIDENCE` (if labeled `PATCH`) | `HYPOTHESIS` (for both `VULN` and `PATCH`) | **CONFLICT**: The benchmark expects different decisions for identical evidence based on hidden ground truth. |
| **CASE 3: Irrelevant / Static Target** | Endpoint is static, unauthenticated, read-only metadata (`/catalog`, `/pricing`, `/.well-known/...`). | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` | `NO_RELEVANT_FUNCTIONALITY` (enforced by Layer 1) | **ALIGNED** |
| **CASE 4: Direct Invariant Support (Benign Traffic)** | Traffic logs demonstrate explicit server-side enforcement (e.g., cross-tenant query returns `403 Forbidden`). | `INSUFFICIENT_EVIDENCE` or abstention (invariant upheld; no vulnerability). | `INSUFFICIENT_EVIDENCE` | N/A (No benchmark scenario currently supplies 403 traffic logs). | **POTENTIAL FUTURE ALIGNMENT** |

### 4. Deep Analysis of Patched BOLA Call #24

In Call #24 (`SCEN-SAAS_BILLING-INV-DETAILS-PATCH-01`):
1. **Identical Observable Evidence**: The target evidence is byte-identical to vulnerable Scenario 1: `GET /api/v1/invoices/{id}` with identities `user_a` and `user_b`.
2. **Zero Telemetry**: Neither scenario contains HTTP response logs showing whether foreign access yields 200 or 403.
3. **VAPT Guidance**: In Track D, injecting horizontal isolation testing methodology explicitly instructs how to test `{id}`.
4. **Discriminative Output**: The model generated an experiment proposal to substitute `{id}` and observe 200 vs 403.
5. **The Semantic Dilemma**:
   - In an operational setting, the model’s action is **correct and desirable**: when given an API spec with an unverified ID parameter, proposing an authorization test is standard security testing.
   - However, in the benchmark scoring harness, because Scenario 3 has `ground_truth_vulnerable = False`, any emission of `HYPOTHESIS` is mechanically scored as a **False Positive (FP)**, destroying the True Negative Rate (TNR).

### 5. Benchmark-Policy Conflict Resolution

The frozen architecture contains a direct contradiction between:
- **The Prompt/Engine Contract**: Encourages generating a `HYPOTHESIS` when relevant functionality has an unverified invariant requiring test verification.
- **The Evaluation Scoring Contract**: Penalizes generating a `HYPOTHESIS` on any non-vulnerable scenario, expecting `INSUFFICIENT_EVIDENCE` as a True Negative, despite providing zero evidence that the endpoint is patched.

**Conclusion**: This conflict cannot be resolved by model prompting or decision policy tuning. It is a benchmark-level policy conflict regarding whether Case 2 (untested parameterized endpoints) represents an exploratory `HYPOTHESIS` or an abstention (`INSUFFICIENT_EVIDENCE`).

---

## Part II: Falsification-Plan Semantic Polarity Audit

### 6. Current Validation Mechanism

In `src/engine/models.py` (`BairJsonObject.validate_slots`, lines 532–538) and `src/engine/decision_policy.py` (`is_falsification_complete`, lines 257–279):

```python
lower = plan.lower()
has_supporting = any(term in lower for term in ["support", "confirm", "positive", "observed", "expected", "200"])
has_disproving = any(term in lower for term in ["disprov", "falsif", "reject", "refut", "negative", "403", "404", "400", "block"])
```

Both validators perform purely unanchored substring matching across the entire string. They do not parse grammatical structure, subject-predicate relationships, or logical polarity.

### 7. Deterministic Demonstration of Semantic Inversion

In Phase 6.2 Call #09 (Ecommerce Refund), the model emitted:
> *"An observation supporting the hypothesis would be a state machine validation that rejects an out-of-order transition with HTTP 409 Conflict or 400 Bad Request. An observation disproving the hypothesis would be a successful out-of-order transition without such a rejection."*

**Logical Error**:
- The model asserted that **server rejection (409/400) supports** the hypothesis of an out-of-order transition vulnerability. In reality, rejection enforces the state machine invariant.
- The model asserted that **successful transition without rejection disproves** the hypothesis. In reality, successful out-of-order execution breaches the invariant and confirms the vulnerability.

**Validation Breakdown**:
- `has_supporting`: matches `"supporting"` $\to$ `True`
- `has_disproving`: matches `"disproving"`, `"reject"`, `"409"`, `"400"` $\to$ `True`
- Both `is_falsification_complete()` and `BairJsonObject` Pydantic validation evaluate to `True`.
- The engine accepted a proposal with 100% reversed logic as a valid `HYPOTHESIS_GROUNDED`.

Deterministic proof is established in [`tests/unit/test_m5_falsification_semantics_audit.py`](file:///c:/Projects/Bug%20Bounty%20AI/tests/unit/test_m5_falsification_semantics_audit.py).

### 8. Theoretical Limit of Free-Text Representation

A free-text string `falsification_plan: str` **cannot guarantee semantic polarity deterministically** without:
1. An LLM semantic judge (violating single-call, local offline constraints);
2. Fragile natural-language heuristics (regex matching clause order, which breaks on passive voice or complex syntax); or
3. Uncalibrated confidence thresholds.

Natural language is inherently unconstrained: a sentence can negate terms (`"not 403"`), invert order (`"disproving if 200, confirming if 403"`), or state nonsensical assertions while containing all required keywords.

### 9. Comparative Protocol Alternatives

| Evaluation Dimension | OPTION A: Free-Text + Prompt Hardening | OPTION B: Typed Structural Slots | OPTION C: Closed Predicate Schema |
| :--- | :--- | :--- | :--- |
| **Description** | Retain `falsification_plan: str`; adjust prompt instructions to emphasize correct polarity. | Split into dedicated string slots:<br>`supporting_observation: str`<br>`disproving_observation: str` | Use machine-readable outcome descriptors:<br>`expected_breach_status: int`<br>`expected_invariant_status: int` |
| **Semantic Guarantee** | **Very Weak**: Model can still invert clauses; validator remains blind to polarity. | **Moderate**: Enforces slot separation; allows slot-specific vocabulary checking. | **Absolute**: Deterministically verified; zero natural-language ambiguity. |
| **Token Budget (300 Tok)** | **High Compatibility**: Zero JSON overhead. | **High Compatibility**: Adds ~15–25 tokens of JSON keys; fits comfortably. | **Optimal**: Highly compact (numeric/enum tokens require less space than prose). |
| **Fail-Closed Behavior** | **Poor**: Reversed plans pass validation. | **Good**: Empty or mismatched slots fail closed individually. | **Absolute**: Schema strictly validates enums/integers. |
| **Implementation Impact** | **None** (Prompt only). | **Moderate**: Update schema, extractor, and adapter. | **High**: Requires mapping taxonomy to concrete action predicates. |
| **Comparability with Phase 6.2**| **100% Comparable**: Byte-level schema identical. | **Breaks Byte Parity**: New JSON keys invalidate raw output equivalence. | **Breaks Byte Parity**: Entirely new output representation. |
| **Preserves Research Boundary**| **Yes**: Evaluates LLM reasoning in prose. | **Yes**: Preserves natural-language hypothesis formation while structuring slots. | **Partially Shifts Boundary**: Moves from open reasoning to closed slot-filling. |

### 10. Technical Recommendation

**Technical Recommendation (Not an Empirical Claim)**:
**OPTION B (Typed Structural Slots)** represents the most balanced path forward:
```json
{
  "invariant": "...",
  "evidence_gap": "...",
  "affected_target": "...",
  "decision": "HYPOTHESIS",
  "empirical_facts": ["FACT-..."],
  "methodology_references": ["CHK-..."],
  "supporting_observation": "HTTP 200 OK returning foreign object contents",
  "disproving_observation": "HTTP 403 Forbidden or 404 Not Found"
}
```
Option B isolates the model's assertions into distinct, dedicated schema slots. This allows slot-specific validation (e.g. ensuring `disproving_observation` contains rejection terms like 403/404, while `supporting_observation` contains success terms like 200) without resorting to complex NLP heuristics, while preserving natural language reasoning within the 300-token budget.

---

## Part III: Final Authorization State

### Repository State Classification:
# `STATE 4: BENCHMARK-BLOCKED — BOTH`

### Justification:
1. **Semantic Protocol Defect**: The current `JSON_BAIR` interface accepts semantically inverted falsification proposals where the model misidentifies invariant enforcement as vulnerability confirmation. Proceeding to an 84-scenario benchmark with an unanchored free-text validator will score logically defective hypotheses as valid.
2. **Benchmark Policy Conflict**: The current benchmark evaluates initial OpenAPI documentation without execution logs. Under Track D, the model emits exploratory hypotheses on unverified parameters, which are penalized as False Positives on patched variants. Proceeding to the benchmark will produce high false-positive rates on negative controls due to benchmark design rather than model failure.

**Authorization Verdict**:
The 84-scenario benchmark and 336-call confirmatory run remain **STRICTLY BLOCKED**.
