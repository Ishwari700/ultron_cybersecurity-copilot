# Milestone M5 Phase 6.5 — Deterministic Experiment-Semantics Protocol Design

**Document Identifier**: `docs/M5_PHASE6_5_EXPERIMENT_SEMANTICS_PROTOCOL_DESIGN.md`  
**Phase Status**: DESIGN ONLY (IMPLEMENTATION BLOCKED)  
**Classification**: `PHASE_6_5_DESIGN_COMPLETE_IMPLEMENTATION_BLOCKED`  
**Governance & Constraints**: Strictly offline design analysis. Zero live LLM calls. Zero modifications to frozen planning documents, M4.9 artifacts, M3 artifacts, or benchmark scenario definitions. Zero production engine modifications in this phase.

---

## 1. Current Defect in Phase 6.2 Architecture

In Milestone M5 Phase 6.2, the `JSON_BAIR` protocol represented experiment proposals as a single free-text string:
```json
{
  "falsification_plan": "observation supporting hypothesis AND observation disproving/falsifying hypothesis"
}
```

Validation of this field in both `BairJsonObject.validate_slots` (`src/engine/models.py`) and `is_falsification_complete` (`src/engine/decision_policy.py`) was implemented via unanchored substring matching:
```python
has_supporting = any(term in lower for term in ["support", "confirm", "positive", "observed", "expected", "200"])
has_disproving = any(term in lower for term in ["disprov", "falsif", "reject", "refut", "negative", "403", "404", "400", "block"])
```

### The Exact Failure Mode
This validator confirms that keywords from both lists co-occur in the string, but **cannot evaluate grammatical syntax or logical polarity**:
- In Phase 6.2 Call #09 (Ecommerce Orders Refund), the model generated:
  > *"An observation supporting the hypothesis would be a state machine validation that rejects an out-of-order transition with HTTP 409 Conflict or 400 Bad Request. An observation disproving the hypothesis would be a successful out-of-order transition without such a rejection."*
- **The Logical Inversion**: The model asserted that server rejection (`409/400`) *supports* the existence of a vulnerability, and that successful out-of-order transition without error *disproves* it. In reality, rejection enforces the invariant, while successful out-of-order execution breaches it.
- **The Validation Failure**: Because the string contains `"supporting"`, `"disproving"`, `"reject"`, and `"409"`, the check evaluated to `True`. The engine accepted a proposal with **100% reversed logic** as a valid `HYPOTHESIS_GROUNDED`.

---

## 2. Formal Requirements for Deterministic Experiment Semantics

To preserve the scientific integrity of the platform without compromising local execution constraints, any replacement representation must satisfy the following formal requirements:

1. **Deterministic Polarity Verification**: The engine must mathematically prove that the observation asserted to "support" a hypothesis actually corresponds to an invariant violation, and that the observation asserted to "disprove" it corresponds to invariant enforcement.
2. **Zero Semantic NLP / LLM Judges**: Polarity validation must execute via pure deterministic logic (set membership, enum lookup, integer comparison), requiring zero secondary LLM calls, zero semantic classifiers, zero regex grammars, and zero post-hoc heuristic repair.
3. **Strict Single-Call & Token Budget Preservation**: The representation must comfortably fit within the pinned local `qwen2.5-coder:7b` Primary Fixed-Budget Envelope (`num_predict = 300`, 1 call per scenario).
4. **Preservation of the Core Research Boundary**:
   - **LLM**: Autoregressively analyzes the evidence gap and proposes an experiment structure.
   - **Deterministic Engine**: Verifies that the experiment's machine-readable predicates are internally consistent with the declared security invariant and target mutability.
5. **Discriminative Falsification Requirement**: The experiment must specify two distinct, mutually exclusive outcomes such that observation of one outcome confirms the invariant breach, while observation of the other outcome upholds the invariant.
6. **Strict Fail-Closed Behavior**: Any malformed, ambiguous, unknown, or inverted predicate must immediately fail closed to `INVALID_SCHEMA` or `FAIL_CLOSED_INCOMPLETE_HYPOTHESIS`.

---

## 3. Comparative Evaluation of Protocol Alternatives

| Evaluation Dimension | OPTION A: Typed Structural Slots | OPTION B: Typed Outcome Predicates | OPTION C: Closed Semantic Schema |
| :--- | :--- | :--- | :--- |
| **Schema Representation** | Split into two free-text strings:<br>`"supporting_observation": str`<br>`"disproving_observation": str` | Action + Status Predicates:<br>`"action": str`<br>`"supporting_outcome": str`<br>`"disproving_outcome": str` | Fully Formalized Schema:<br>`"invariant_id": str`<br>`"action_predicate": Enum`<br>`"breach_predicate": Enum`<br>`"holds_predicate": Enum` |
| **Deterministic Semantic Guarantee** | **FAIL**: Cannot guarantee polarity. Free text inside slots can still state reversed logic (e.g. `supporting: "rejected with 409"`). | **STRONG**: Mathematical verification via closed set membership against taxonomy rules. | **ABSOLUTE**: Mathematical verification across action, target, and outcome enums. |
| **Token Cost (`num_predict = 300`)** | ~20–30 tokens JSON overhead. | ~25–35 tokens JSON overhead. Highly compact. | ~35–45 tokens JSON overhead. Compact. |
| **JSON_BAIR Compatibility** | Directly maps to BAIR slots. | Fully compatible with BAIR JSON schema. | Fully compatible with BAIR JSON schema. |
| **One-Call Inference Compatibility** | 100% compatible. | 100% compatible. | 100% compatible. |
| **Parser / Adapter Impact** | Low: minor field split. | Moderate: maps predicates to canonical S0. | Moderate-High: requires full taxonomy mapper. |
| **Detects State-Machine Inversion?** | **NO**. Free text inside slots still passes lexical checks. | **YES**. Deterministically rejects `HTTP_409_CONFLICT` as a supporting breach outcome. | **YES**. Deterministically rejects `STATE_TRANSITION_REJECTED` as a breach outcome. |
| **Prevents `403`/`404` as Breach?** | **NO**. Lexical presence in free-text slots cannot detect inverted intent. | **YES**. `HTTP_403_FORBIDDEN` is strictly prohibited in `supporting_outcome` for BOLA. | **YES**. Authorization failure predicates are strictly prohibited as breach outcomes. |
| **Multiple Valid Outcomes?** | Yes, but ambiguous. | **YES**. Can accept sets (e.g. `403` OR `404` in holds). | **YES**. Categorical outcome classes (e.g. `STATUS_CLIENT_ERROR_4XX`). |
| **Fail-Closed Behavior** | Weak: lexical matching fails open on reversed prose. | **Strict**: Unknown predicates fail schema validation immediately. | **Strict**: Schema strictly rejects any unknown enum. |
| **Impact on Phase 6.2 Parity** | Breaks raw byte output parity. | Breaks raw byte output parity. | Breaks raw byte output parity. |

---

## 4. Formal Limitation Analysis: Can Free-Text Ever Guarantee Polarity?

> [!CAUTION]
> **FORMAL THEORETICAL LIMITATION**:  
> **NO**. A deterministic computing system can **NEVER guarantee semantic polarity if experiment observations remain arbitrary free-form natural language strings**, unless it employs an external semantic judge (e.g. secondary LLM) or complex NLP heuristics.

### Mathematical Proof
Let $S$ be the universe of natural language sentences. Let $V$ be the target security invariant (e.g. *"Only authorized owners may access resource $R$"*).
1. A valid falsification proposal requires asserting a proposition $P_{\text{breach}}$ that implies $\neg V$ (invariant breach), and a proposition $P_{\text{holds}}$ that implies $V$ (invariant holds).
2. Natural language allows arbitrary syntactic composition:
   - Negation: *"Rejection with 403 does not prove the invariant is broken."*
   - Clause reordering: *"The hypothesis is confirmed if 200 OK is returned, whereas 403 Forbidden disproves it."* vs *"The hypothesis is disproved if 403 Forbidden is returned, whereas 200 OK confirms it."*
   - Inverted attribution: *"An observation supporting the vulnerability is that the server rejects with 400."*
3. Any deterministic string validator operating without NLP syntax parsing can only evaluate lexical projections:
   $$f(s) = \mathbb{I}(\text{keywords} \subseteq s)$$
4. For any set of keyword dictionaries $K_{\text{support}}$ and $K_{\text{disprove}}$, there exist sentences $s_1, s_2 \in S$ such that:
   - $s_1$ asserts correct polarity;
   - $s_2$ asserts inverted polarity;
   - Yet $\text{Tokens}(s_1) \cap K = \text{Tokens}(s_2) \cap K$.
5. Therefore, $f(s_1) = f(s_2) = \text{True}$. The validator is provably incapable of separating $s_1$ from $s_2$.

**Direct Corollary**: Simply splitting a single string into two strings (`supporting_observation: str` and `disproving_observation: str`) **does not solve the problem**. A model can still output:
```json
{
  "supporting_observation": "The server rejects out-of-order transition with HTTP 409 Conflict",
  "disproving_observation": "The server accepts the transition with 200 OK"
}
```
If the validator only checks for keywords like `409` or `rejection` inside `supporting_observation`, it must either:
- Hardcode brittle natural-language regexes (which break on phrasing variations); OR
- Fail open, allowing the inverted proposal to pass.

**Conclusion**: Semantic polarity can only be verified deterministically if the observations are constrained to a **closed vocabulary of machine-readable predicates**.

---

## 5. Minimal Closed Predicate Taxonomy for M5 Scenarios

To avoid creating an over-engineered universal ontology, the taxonomy is strictly minimal and justified exclusively by the 6 application families and 10 OWASP categories in the frozen M5 benchmark:

### 5.1 HTTP Outcome Predicates
- `HTTP_200_OK`
- `HTTP_201_CREATED`
- `HTTP_204_NO_CONTENT`
- `HTTP_400_BAD_REQUEST`
- `HTTP_401_UNAUTHORIZED`
- `HTTP_403_FORBIDDEN`
- `HTTP_404_NOT_FOUND`
- `HTTP_409_CONFLICT`

### 5.2 Semantic State Predicates
- **Response Classes**: `STATUS_SUCCESS_2XX`, `STATUS_CLIENT_ERROR_4XX`
- **Object Access & Isolation (BOLA / IDOR)**:
  - `CROSS_IDENTITY_OBJECT_ACCESSIBLE` (Breach)
  - `CROSS_IDENTITY_OBJECT_DENIED` (Invariant Holds)
  - `OWNERSHIP_ENFORCED` (Invariant Holds)
  - `OWNERSHIP_NOT_ENFORCED` (Breach)
- **State Machine Transitions (Step-Skipping / Business Logic)**:
  - `STATE_TRANSITION_ACCEPTED` (Breach when out-of-order)
  - `STATE_TRANSITION_REJECTED` (Invariant Holds when out-of-order)
- **Privilege & Roles (BFLA)**:
  - `PRIVILEGE_ELEVATION_SUCCEEDS` (Breach)
  - `PRIVILEGE_ELEVATION_DENIED` (Invariant Holds)

### 5.3 Experiment Action Predicates
- `SUBSTITUTE_RESOURCE_IDENTIFIER` (BOLA / IDOR)
- `EXECUTE_OUT_OF_ORDER_TRANSITION` (Business Logic / State Machine)
- `REPLAY_STEP_WITH_LOWER_ROLE` (BFLA)
- `INVOKE_WITHOUT_CREDENTIALS` (Authentication Bypass)

---

## 6. Exact JSON Schema Specification (Design Option B Prototype)

```json
{
  "type": "object",
  "properties": {
    "invariant": {
      "type": "string",
      "description": "Evaluated security invariant statement"
    },
    "evidence_gap": {
      "type": "string",
      "description": "Concrete missing observation or unverified state"
    },
    "affected_target": {
      "type": "string",
      "description": "Target endpoint or route parameter"
    },
    "decision": {
      "type": "string",
      "enum": ["HYPOTHESIS", "INSUFFICIENT_EVIDENCE", "NO_RELEVANT_FUNCTIONALITY"]
    },
    "empirical_facts": {
      "type": "array",
      "items": { "type": "string", "pattern": "^FACT-[A-Z0-9_-]+$" }
    },
    "methodology_references": {
      "type": "array",
      "items": { "type": "string", "pattern": "^CHK-[A-Z0-9_-]+$" }
    },
    "experiment_action": {
      "type": "string",
      "enum": [
        "SUBSTITUTE_RESOURCE_IDENTIFIER",
        "EXECUTE_OUT_OF_ORDER_TRANSITION",
        "REPLAY_STEP_WITH_LOWER_ROLE",
        "INVOKE_WITHOUT_CREDENTIALS"
      ]
    },
    "supporting_outcome": {
      "type": "string",
      "description": "Machine-readable predicate indicating invariant violation (confirming hypothesis)",
      "enum": [
        "HTTP_200_OK",
        "HTTP_201_CREATED",
        "STATUS_SUCCESS_2XX",
        "CROSS_IDENTITY_OBJECT_ACCESSIBLE",
        "OWNERSHIP_NOT_ENFORCED",
        "STATE_TRANSITION_ACCEPTED",
        "PRIVILEGE_ELEVATION_SUCCEEDS"
      ]
    },
    "disproving_outcome": {
      "type": "string",
      "description": "Machine-readable predicate indicating invariant enforcement (falsifying hypothesis)",
      "enum": [
        "HTTP_400_BAD_REQUEST",
        "HTTP_401_UNAUTHORIZED",
        "HTTP_403_FORBIDDEN",
        "HTTP_404_NOT_FOUND",
        "HTTP_409_CONFLICT",
        "STATUS_CLIENT_ERROR_4XX",
        "CROSS_IDENTITY_OBJECT_DENIED",
        "OWNERSHIP_ENFORCED",
        "STATE_TRANSITION_REJECTED",
        "PRIVILEGE_ELEVATION_DENIED"
      ]
    },
    "falsification_description": {
      "type": "string",
      "description": "Brief human-readable summary of the test procedure"
    }
  },
  "required": [
    "invariant",
    "evidence_gap",
    "affected_target",
    "decision",
    "empirical_facts",
    "methodology_references"
  ],
  "additionalProperties": false
}
```

---

## 7. Deterministic Validation Rules

When `decision == "HYPOTHESIS"`, the deterministic engine validates the experiment using the following strict rules:

1. **Mandatory Presence**: `experiment_action`, `supporting_outcome`, and `disproving_outcome` must be present and valid enum values.
2. **Category Polarity Matrix**:
   - For `API-BOLA-001`:
     - `supporting_outcome` $\in \{\text{HTTP\_200\_OK}, \text{STATUS\_SUCCESS\_2XX}, \text{CROSS\_IDENTITY\_OBJECT\_ACCESSIBLE}, \text{OWNERSHIP\_NOT\_ENFORCED}\}$
     - `disproving_outcome` $\in \{\text{HTTP\_403\_FORBIDDEN}, \text{HTTP\_404\_NOT\_FOUND}, \text{STATUS\_CLIENT\_ERROR\_4XX}, \text{CROSS\_IDENTITY\_OBJECT\_DENIED}, \text{OWNERSHIP\_ENFORCED}\}$
   - For `API-STATE-001`:
     - `supporting_outcome` $\in \{\text{HTTP\_200\_OK}, \text{STATUS\_SUCCESS\_2XX}, \text{STATE\_TRANSITION\_ACCEPTED}\}$
     - `disproving_outcome` $\in \{\text{HTTP\_400\_BAD\_REQUEST}, \text{HTTP\_409\_CONFLICT}, \text{STATUS\_CLIENT\_ERROR\_4XX}, \text{STATE\_TRANSITION\_REJECTED}\}$
   - For `API-BFLA-002`:
     - `supporting_outcome` $\in \{\text{HTTP\_200\_OK}, \text{STATUS\_SUCCESS\_2XX}, \text{PRIVILEGE\_ELEVATION\_SUCCEEDS}\}$
     - `disproving_outcome` $\in \{\text{HTTP\_401\_UNAUTHORIZED}, \text{HTTP\_403\_FORBIDDEN}, \text{STATUS\_CLIENT\_ERROR\_4XX}, \text{PRIVILEGE\_ELEVATION\_DENIED}\}$
3. **Mutual Exclusivity**: `supporting_outcome` and `disproving_outcome` must not be identical (zero vacuous experiments).
4. **Fail-Closed Gate**: If any predicate fails its category mapping, the candidate fails closed immediately (`FAIL_CLOSED_INCOMPLETE_HYPOTHESIS`).

---

## 8. Proof Test Results Across the Five Key Cases

The protocol design was implemented and verified deterministically in [`tests/unit/test_m5_experiment_semantics_design.py`](file:///c:/Projects/Bug%20Bounty%20AI/tests/unit/test_m5_experiment_semantics_design.py):

| Test Case | Scenario / Condition | Engine Behavior | Verification Result |
| :--- | :--- | :--- | :--- |
| **Case 1: Valid BOLA** | Breach = `HTTP_200_OK`<br>Safe = `HTTP_403_FORBIDDEN` | Accepted as valid discriminative experiment | **PASSED** |
| **Case 2: Valid State Machine** | Breach = `STATE_TRANSITION_ACCEPTED`<br>Safe = `HTTP_409_CONFLICT` | Accepted as valid discriminative experiment | **PASSED** |
| **Case 3: Inverted State Machine** | Breach = `HTTP_409_CONFLICT`<br>Safe = `STATE_TRANSITION_ACCEPTED` | **Deterministically rejected** (409 is not in valid breach outcomes) | **PASSED (FIX CONFIRMED)** |
| **Case 4: Ambiguous Prose** | `supporting_outcome = "Maybe server accepts or errors"` | **Fails closed** (not in closed taxonomy enum) | **PASSED** |
| **Case 5: Unsupported / Unknown** | `action = "UNKNOWN_ACTION_999"` | **Fails closed** (schema validation rejects unknown value) | **PASSED** |

---

## 9. Benchmark-Policy Separation: Exploratory vs Vulnerability Hypotheses

To permanently resolve the benchmark-policy conflict exposed in Phase 6.3/6.4, the platform must formally separate two distinct epistemic concepts:

### Concept A: Exploratory Verification Hypothesis
- **Definition**: Relevant functionality contains an unverified security invariant (e.g. parameter `{id}` in an OpenAPI spec with no execution telemetry), and a bounded, discriminative experiment is proposed to test it.
- **Appropriate Context**: Passive documentation analysis; early target reconnaissance.
- **Benchmark Evaluation**: When an exploratory experiment is proposed for a patched endpoint where no telemetry was provided, it is **not a false positive** of vulnerability detection, but a **valid exploratory test proposal**.

### Concept B: Confirmed / Evidenced Vulnerability Hypothesis
- **Definition**: Active empirical evidence (traffic logs, response shape deltas, error messages) indicates or implies that an invariant violation is currently occurring.
- **Appropriate Context**: Runtime traffic analysis; active vulnerability scanning.
- **Benchmark Evaluation**: Strictly scored as True Positive on vulnerable scenarios and False Positive on patched scenarios.

### Architectural Decision on Metric Separation
The primary research estimand **Useful Hypothesis Yield** is currently overloaded because it aggregates both Concept A and Concept B under the single token `HYPOTHESIS`.
- **Recommendation**: For future benchmarks, report:
  1. **Primary Metric**: Confirmed Vulnerability Hypothesis Yield (evaluated strictly when comparative traffic evidence is present).
  2. **Secondary Metric**: Exploratory Hypothesis Validity Rate (evaluating whether proposed experiments on untelemetred endpoints are valid and discriminative).

---

## 10. Comparability Analysis

| Milestone Artifact | Status Under Current Frozen Record | Impact of Protocol Change |
| :--- | :--- | :--- |
| **M4 Baseline (`m4_live_llm_benchmark_final.json`)** | **Cryptographically Frozen** (SHA: `459b9ec6...`) | **Preserved**. M4 baseline is immutable historical record. |
| **M5 Phase 6.0 Smoke (`m5_live_smoke.json`)** | **Cryptographically Frozen** (SHA: `7ee8b6b2...`) | **Preserved**. Serves as historical interface benchmark. |
| **M5 Phase 6.2 Smoke (`m5_live_smoke_v2.json`)** | **Cryptographically Frozen** (SHA: `830c225b...`) | **Preserved**. Demonstrates 87.5% valid interface rate under free-text schema. Direct byte-level comparison with future runs will be decoupled due to new schema fields. |
| **84-Scenario Large Benchmark** | **UNEXECUTED / BLOCKED** | Will run exclusively under the repaired typed-predicate protocol, ensuring clean, interpretable results. |

---

## 11. Technical Design Recommendation

**TECHNICAL DESIGN RECOMMENDATION (NOT AN EMPIRICAL CLAIM)**:

Adopt **OPTION B (Typed Outcome Predicates)** as the authoritative interface for Milestone M5 Phase 6.6:
1. Retains natural language for `invariant`, `evidence_gap`, `affected_target`, and `falsification_description`.
2. Replaces free-text `falsification_plan` with typed enum fields: `experiment_action`, `supporting_outcome`, and `disproving_outcome`.
3. Validates outcomes using category-specific polarity matrices in `deterministic_decide()`.
4. Fully preserves the Primary Fixed-Budget Envelope (`num_predict = 300`, 1 inference call) with negligible token overhead (~25 tokens).

---

## 12. Explicit List of Implementation Changes Required in Phase 6.6

When Phase 6.6 is authorized, the following source files will be modified:

1. [`src/engine/models.py`](file:///c:/Projects/Bug%20Bounty%20AI/src/engine/models.py):
   - Add `ExperimentActionPredicate`, `HttpOutcomePredicate`, and `SemanticOutcomePredicate` enums.
   - Update `BairJsonObject` schema to include `experiment_action`, `supporting_outcome`, `disproving_outcome`, and `falsification_description`.
   - Update `BairJsonObject.get_inference_schema()` for Ollama runtime constrained decoding.
2. [`src/engine/protocol.py`](file:///c:/Projects/Bug%20Bounty%20AI/src/engine/protocol.py):
   - Update `JSON_BAIR` template to prompt for the typed outcome fields.
3. [`src/engine/bair_extractor.py`](file:///c:/Projects/Bug%20Bounty%20AI/src/engine/bair_extractor.py):
   - Update `map_bair_json_to_s0` to map typed outcomes into canonical `HypothesisModelOutput`.
4. [`src/engine/decision_policy.py`](file:///c:/Projects/Bug%20Bounty%20AI/src/engine/decision_policy.py):
   - Replace keyword-based `is_falsification_complete()` with `ExperimentPolarityValidator.validate_experiment_polarity()`.
5. [`tests/unit/`](file:///c:/Projects/Bug%20Bounty%20AI/tests/unit/):
   - Update existing unit test mocks to supply the new typed outcome fields.

---

## 13. Final State Classification

# `PHASE_6_5_DESIGN_COMPLETE_IMPLEMENTATION_BLOCKED`

The protocol design is complete, mathematically verified, and proven via deterministic unit fixtures. Implementation in production source code remains **BLOCKED** pending project authorization. The 84-scenario benchmark remains **STRICTLY BLOCKED**.
