"""Counterfactual Evidence-Gap Reasoning Templates (Intervention I3).

Milestone M4 Phase M4.4:
Transforms reasoning from passive vulnerability estimation ("Is this vulnerable?")
into structured counterfactual evaluation:
1. Application Model & Relevant Security Invariant
2. Evidence Gap Analysis (what observations are missing or ambiguous)
3. Counterfactual Violation Condition (what specific behavior constitutes a breach)
4. Falsification Observation (concrete observation that disproves the hypothesis)

Preserves strict single-factor isolation:
- Operates under baseline unconstrained token sampling (NO I1 schema constraint).
- Uses canonical S0 output schema (NO I2 segregated fields).
- Preserves negative-control safety floors (never leads the model to assume vulnerabilities).
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class CounterfactualTemplate(BaseModel):
    """Category-aware counterfactual reasoning template."""
    category_id: str
    category_name: str
    invariant_definition: str
    evidence_gap_focus: str
    counterfactual_violation_condition: str
    falsification_condition: str
    negative_control_indicator: str


# ---------------------------------------------------------------------------
# Authoritative Category-Specific Counterfactual Templates (10 OWASP API)
# ---------------------------------------------------------------------------

OWASP_API_COUNTERFACTUAL_TEMPLATES: Dict[str, CounterfactualTemplate] = {
    "API-AUTH-NONE": CounterfactualTemplate(
        category_id="API-AUTH-NONE",
        category_name="Missing Authentication / Public Endpoint Boundary",
        invariant_definition=(
            "Protected operations and state-altering endpoints must require authentication. "
            "Unauthenticated access is valid strictly for public non-sensitive discovery/catalog assets."
        ),
        evidence_gap_focus=(
            "Evaluate whether observed traffic lacks authentication tokens on endpoints handling private data "
            "or state changes, or whether the endpoint is strictly a public non-sensitive discovery interface."
        ),
        counterfactual_violation_condition=(
            "The invariant is violated if an unauthenticated request successfully accesses confidential resources "
            "or executes state modifications that should require identity verification."
        ),
        falsification_condition=(
            "The hypothesis is disproved if unauthenticated requests consistently return HTTP 401/403, "
            "or if the asset is confirmed to be public catalog/documentation functionality with zero private data."
        ),
        negative_control_indicator=(
            "If the endpoint exposes only public discovery information (e.g. catalog, healthcheck, docs) "
            "and performs no authenticated operations, emit NO_RELEVANT_FUNCTIONALITY."
        ),
    ),
    "API-BFLA-001": CounterfactualTemplate(
        category_id="API-BFLA-001",
        category_name="Broken Function Level Authorization (BFLA)",
        invariant_definition=(
            "Administrative and privileged functions must enforce role hierarchy checks; "
            "lower-privileged or standard roles must be rejected."
        ),
        evidence_gap_focus=(
            "Examine whether observed facts confirm that requests to administrative functions "
            "are gated by role validation, or if a lower-privileged role can invoke the privileged endpoint."
        ),
        counterfactual_violation_condition=(
            "The invariant is violated if an identity possessing a standard user role can invoke administrative "
            "or privileged functions with HTTP 200/success."
        ),
        falsification_condition=(
            "The hypothesis is disproved if non-admin requests consistently return HTTP 403 Forbidden, "
            "or if the function is verified to be intentionally available to all authenticated roles."
        ),
        negative_control_indicator=(
            "If role-based access control enforces HTTP 403 against lower roles, or if the function has no "
            "privileged requirement, do NOT hypothesize BFLA; emit NO_RELEVANT_FUNCTIONALITY."
        ),
    ),
    "API-BOLA-001": CounterfactualTemplate(
        category_id="API-BOLA-001",
        category_name="Broken Object Level Authorization (BOLA/IDOR)",
        invariant_definition=(
            "Object access must verify that the requesting identity owns or is explicitly authorized "
            "to access the specific target resource identifier."
        ),
        evidence_gap_focus=(
            "Examine whether available evidence establishes explicit server-side object ownership verification, "
            "or whether observed facts demonstrate cross-identity access without authorization comparison."
        ),
        counterfactual_violation_condition=(
            "The invariant is violated if actor A can access or mutate an object belonging to distinct actor B "
            "simply by substituting the object identifier in the request."
        ),
        falsification_condition=(
            "The hypothesis is disproved if substituting foreign object identifiers returns HTTP 403 Forbidden / "
            "404 Not Found, or if the object identifier refers to a shared/public non-tenant entity."
        ),
        negative_control_indicator=(
            "If the endpoint implements strict ownership gating or operates on public objects where any user "
            "is authorized to read the resource, emit NO_RELEVANT_FUNCTIONALITY."
        ),
    ),
    "API-CROSS-TENANT-001": CounterfactualTemplate(
        category_id="API-CROSS-TENANT-001",
        category_name="Cross-Tenant Multi-Tenancy Boundary Breach",
        invariant_definition=(
            "Database queries and resource mutations must strictly enforce tenant boundary isolation; "
            "queries must be scoped to the authenticated tenant context."
        ),
        evidence_gap_focus=(
            "Examine whether tenant scoping parameters are strictly enforced by the backend, "
            "or whether observed evidence shows cross-tenant data retrieval across distinct tenant boundaries."
        ),
        counterfactual_violation_condition=(
            "The invariant is violated if an authenticated session under Tenant A receives data or mutates records "
            "belonging to Tenant B."
        ),
        falsification_condition=(
            "The hypothesis is disproved if tenant-scoped database filters enforce cross-tenant separation "
            "returning HTTP 403 Forbidden or an empty response."
        ),
        negative_control_indicator=(
            "If tenant isolation filters are verified or the resource is globally shared across all tenants, "
            "emit NO_RELEVANT_FUNCTIONALITY."
        ),
    ),
    "API-DEVICE-BOLA-001": CounterfactualTemplate(
        category_id="API-DEVICE-BOLA-001",
        category_name="Device / Fleet Object Level Authorization",
        invariant_definition=(
            "IoT device commands and telemetry endpoints must verify that the requesting operator account "
            "owns or manages the specific device identifier."
        ),
        evidence_gap_focus=(
            "Examine whether device management endpoints accept arbitrary device identifiers without verifying "
            "device-to-account ownership linkage in observed facts."
        ),
        counterfactual_violation_condition=(
            "The invariant is violated if an operator can issue commands or retrieve telemetry from devices "
            "registered to a distinct customer account."
        ),
        falsification_condition=(
            "The hypothesis is disproved if device gateway authorization rejects commands targeted at unlinked devices "
            "with HTTP 403 or device unauthenticated error."
        ),
        negative_control_indicator=(
            "If device ownership verification is enforced at gateway ingress, emit NO_RELEVANT_FUNCTIONALITY."
        ),
    ),
    "API-LIFECYCLE-001": CounterfactualTemplate(
        category_id="API-LIFECYCLE-001",
        category_name="Asset Lifecycle & State Mutation Integrity",
        invariant_definition=(
            "Terminal, archived, or cancelled entities must reject subsequent mutation requests "
            "(e.g. refunds against cancelled orders, updates to deleted assets)."
        ),
        evidence_gap_focus=(
            "Examine whether the backend validates the current lifecycle status before processing mutations, "
            "or whether observed evidence indicates that terminal state transitions can be overridden."
        ),
        counterfactual_violation_condition=(
            "The invariant is violated if an operation modifies or refunds an asset that is already in a "
            "cancelled, expired, or terminal state."
        ),
        falsification_condition=(
            "The hypothesis is disproved if backend state checks reject mutations on terminal entities "
            "with HTTP 400 Bad Request or HTTP 409 Conflict."
        ),
        negative_control_indicator=(
            "If lifecycle state machines enforce terminal immutability, emit NO_RELEVANT_FUNCTIONALITY."
        ),
    ),
    "API-MULTI-STEP-AUTH-001": CounterfactualTemplate(
        category_id="API-MULTI-STEP-AUTH-001",
        category_name="Multi-Step Workflow / Step Skipping Bypass",
        invariant_definition=(
            "Multi-step verification workflows must enforce prerequisite state progression; "
            "intermediate verification or approval steps cannot be bypassed."
        ),
        evidence_gap_focus=(
            "Examine whether the final workflow action endpoint enforces server-side verification of prior steps, "
            "or whether observed evidence shows direct step-skipping access."
        ),
        counterfactual_violation_condition=(
            "The invariant is violated if a client can directly submit Step N without completing Steps 1 through N-1 "
            "and receive HTTP 200/success."
        ),
        falsification_condition=(
            "The hypothesis is disproved if direct calls to subsequent workflow steps fail with HTTP 400/403 "
            "due to missing session prerequisite tokens."
        ),
        negative_control_indicator=(
            "If sequential step progression is strictly validated by backend state nonces, emit NO_RELEVANT_FUNCTIONALITY."
        ),
    ),
    "API-MUTATION-001": CounterfactualTemplate(
        category_id="API-MUTATION-001",
        category_name="Parameter Tampering & State Mutation Control",
        invariant_definition=(
            "Authoritative server-controlled attributes (e.g. price, subscription tier, role) must not "
            "be mutable through client-supplied request body or query parameters."
        ),
        evidence_gap_focus=(
            "Examine whether parameter lineage shows client-controlled overrides for billing or privilege properties, "
            "or whether the server enforces authoritative server-side pricing and tier assignment."
        ),
        counterfactual_violation_condition=(
            "The invariant is violated if injecting modified parameters forces the backend to assign "
            "a higher subscription tier or lower price than authorized."
        ),
        falsification_condition=(
            "The hypothesis is disproved if server-side data stores overwrite client input with authoritative values "
            "or reject modified fields with HTTP 400."
        ),
        negative_control_indicator=(
            "If the server strictly ignores or rejects unauthorized client parameter overrides, emit NO_RELEVANT_FUNCTIONALITY."
        ),
    ),
    "API-ROLE-BOUNDARY-001": CounterfactualTemplate(
        category_id="API-ROLE-BOUNDARY-001",
        category_name="Role Boundary & Hierarchy Enforcement",
        invariant_definition=(
            "Role boundaries must strictly isolate horizontal and vertical privilege sets; "
            "cross-role capabilities cannot be exercised without explicit assignment."
        ),
        evidence_gap_focus=(
            "Examine whether observed structural diffs show privilege level deltas or response shape divergence "
            "indicating that role boundary enforcement is absent or inconsistent."
        ),
        counterfactual_violation_condition=(
            "The invariant is violated if an identity assigned Role X exercises operations or retrieves data "
            "reserved strictly for Role Y."
        ),
        falsification_condition=(
            "The hypothesis is disproved if role authorization middleware consistently intercepts and denies "
            "cross-role requests with HTTP 403 Forbidden."
        ),
        negative_control_indicator=(
            "If role-based authorization filters successfully restrict access to assigned roles, emit NO_RELEVANT_FUNCTIONALITY."
        ),
    ),
    "API-STATE-001": CounterfactualTemplate(
        category_id="API-STATE-001",
        category_name="State Machine & Workflow Transition Integrity",
        invariant_definition=(
            "Business logic state transitions must follow a valid, strictly ordered finite state machine; "
            "transitions from invalid current states must be rejected."
        ),
        evidence_gap_focus=(
            "Examine whether the endpoint validates that the target entity is currently in an eligible state "
            "for the requested transition, or whether observed facts show unvalidated state changes."
        ),
        counterfactual_violation_condition=(
            "The invariant is violated if an entity in state A can trigger a transition permitted only from state B."
        ),
        falsification_condition=(
            "The hypothesis is disproved if state machine validation rejects out-of-order transitions "
            "with HTTP 409 Conflict or 400 Bad Request."
        ),
        negative_control_indicator=(
            "If the application validates state preconditions before executing transitions, emit NO_RELEVANT_FUNCTIONALITY."
        ),
    ),
}

# Deterministic alias mapping for robust category resolution
_CATEGORY_ALIAS_MAP: Dict[str, str] = {
    "API-BFLA-002": "API-BFLA-001",
    "STATE-MACHINE-001": "API-STATE-001",
    "INFO-EXPOSURE-001": "API-MUTATION-001",
    "BOLA": "API-BOLA-001",
    "IDOR": "API-BOLA-001",
    "BFLA": "API-BFLA-001",
    "CROSS-TENANT": "API-CROSS-TENANT-001",
    "DEVICE-BOLA": "API-DEVICE-BOLA-001",
    "LIFECYCLE": "API-LIFECYCLE-001",
    "MULTI-STEP": "API-MULTI-STEP-AUTH-001",
    "MUTATION": "API-MUTATION-001",
    "ROLE-BOUNDARY": "API-ROLE-BOUNDARY-001",
    "STATE": "API-STATE-001",
    "AUTH-NONE": "API-AUTH-NONE",
}


class UnknownCounterfactualCategoryError(ValueError):
    """Raised when an unknown, malformed, empty, or unsupported category is supplied to the I3 template resolver."""
    pass


def get_counterfactual_template(
    category_id: Optional[str],
    evidence_gap_type: Optional[str] = None,
) -> CounterfactualTemplate:
    """
    Deterministically retrieve the counterfactual template for a category identifier.
    Fails closed by raising UnknownCounterfactualCategoryError for unknown, malformed, empty,
    or unsupported categories.

    Deterministic resolution precedence:
    1. Exact canonical category match (e.g. 'API-BOLA-001')
    2. Exact predefined alias match (e.g. 'BOLA' -> 'API-BOLA-001')
    3. Fail closed (raises UnknownCounterfactualCategoryError)
    """
    if not category_id or not isinstance(category_id, str) or not category_id.strip():
        raise UnknownCounterfactualCategoryError(
            f"Category ID cannot be empty or malformed: {category_id!r}"
        )

    normalized = category_id.strip().upper()

    # 1. Exact canonical category match
    if normalized in OWASP_API_COUNTERFACTUAL_TEMPLATES:
        return OWASP_API_COUNTERFACTUAL_TEMPLATES[normalized]

    # 2. Exact predefined alias match
    if normalized in _CATEGORY_ALIAS_MAP:
        target = _CATEGORY_ALIAS_MAP[normalized]
        return OWASP_API_COUNTERFACTUAL_TEMPLATES[target]

    # 3. Unknown, malformed, decorated, or unsupported category -> FAIL CLOSED
    raise UnknownCounterfactualCategoryError(
        f"Unsupported or unknown counterfactual category: {category_id!r}"
    )


def format_counterfactual_reasoning_prompt(
    target_asset: Dict[str, Any],
    category_id: str,
    retrieved_evidence: List[Dict[str, Any]],
    template: Optional[CounterfactualTemplate] = None,
    parameters: Optional[List[Dict[str, Any]]] = None,
    invariants: Optional[List[Dict[str, Any]]] = None,
) -> str:
    """
    Construct the authoritative Intervention I3 Counterfactual Prompt.
    Directs the model to evaluate the four counterfactual questions:
    1. What security invariant is relevant?
    2. What observed evidence indicates a potential gap in that invariant?
    3. What specific behavior would have to occur for that invariant to be violated?
    4. What concrete observation would disprove/falsify the hypothesis?

    Does NOT lead the model to assume a vulnerability.
    Uses canonical S0 output schema fields.
    """
    tmpl = template or get_counterfactual_template(category_id)

    evidence_lines = []
    for ev in retrieved_evidence:
        fid = ev.get("fact_id", "FACT-UNKNOWN")
        tool = ev.get("source_tool", "generic")
        trust = ev.get("trust", "UNTRUSTED")
        stmt = ev.get("statement", "")
        evidence_lines.append(f"EVIDENCE [{fid}] (source: {tool}, trust: {trust})\n{stmt}")
    evidence_section = "\n\n".join(evidence_lines) if evidence_lines else "No direct traffic facts retrieved."

    param_lines = []
    for p in (parameters or []):
        param_lines.append(f"- {p.get('param_id')} (name: '{p.get('name')}', location: {p.get('location')})")
    param_section = "\n".join(param_lines) if param_lines else "None registered."

    prompt = f"""SYSTEM SECURITY POLICY (COUNTERFACTUAL REASONING PROTOCOL):
You are an authoritative Application Security Reasoning Engine.
Evaluate the provided canonical structural observations using evidence-gap counterfactual analysis.

EVALUATION FRAMEWORK (DO NOT ASSUME A VULNERABILITY EXISTS):
1. RELEVANT INVARIANT:
   {tmpl.invariant_definition}

2. EVIDENCE-GAP ANALYSIS:
   {tmpl.evidence_gap_focus}

3. COUNTERFACTUAL VIOLATION CONDITION:
   {tmpl.counterfactual_violation_condition}

4. FALSIFICATION REQUIREMENT:
   {tmpl.falsification_condition}

NEGATIVE-CONTROL SAFETY RULE:
{tmpl.negative_control_indicator}

DECISION POLICY:
- HYPOTHESIS: Observed evidence demonstrates an unverified gap where the counterfactual violation condition is plausible and requires experiment verification. You MUST provide an 'experiment_proposal' detailing what concrete observation would confirm or falsify the hypothesis.
- INSUFFICIENT_EVIDENCE: Relevant functionality exists, but available evidence is incomplete to confirm or rule out the violation.
- NO_RELEVANT_FUNCTIONALITY: The asset has no functionality relevant to this category (e.g. public static assets, or endpoints where controls are verified).
- NEVER emit CONFIRMED.

CONSTRAINTS:
- Rely strictly on canonical facts and verified structural diffs.
- Never invent IDs or paths.
- Output valid JSON conforming to the canonical schema:
  {{
    "decision": "NO_RELEVANT_FUNCTIONALITY" | "INSUFFICIENT_EVIDENCE" | "HYPOTHESIS",
    "invariant": "Statement of relevant security invariant evaluated",
    "evidence_gap": "Identified gap or missing observation",
    "affected_target": "{target_asset.get('asset_id')}",
    "supporting_evidence_ids": ["FACT-..."],
    "methodology_references": [],
    "reasoning_summary": "Concise human-readable rationale",
    "experiment_proposal": "Concrete verification experiment with supporting observation and falsifying observation"
  }}
- Output raw JSON directly without markdown code fences.

SECURITY REASONING TASK:
Target Asset ID: {target_asset.get('asset_id')}
Method: {target_asset.get('method')}
Path Template: {target_asset.get('normalized_path')}
Application Mutability: {target_asset.get('application_mutability', 'UNKNOWN')}
Taxonomy Category: [{tmpl.category_id}] - {tmpl.category_name}

AVAILABLE PARAMETERS:
---------------------------------------------
{param_section}
---------------------------------------------

AVAILABLE EVIDENCE:
---------------------------------------------
{evidence_section}
---------------------------------------------

DERIVED INVARIANTS:
{invariants or '[]'}

COUNTERFACTUAL INSTRUCTIONS:
1. State the evaluated invariant in 'invariant'.
2. If evidence demonstrates an unmitigated gap, state it in 'evidence_gap'.
3. Formulate the falsification observation in 'experiment_proposal'.
4. If the endpoint is safe, public, or lacks relevant functionality, emit NO_RELEVANT_FUNCTIONALITY.
"""
    return prompt
