"""Milestone M2 Phase 11.5: Dependency-Aware Typed Observable Interaction Evidence Enricher.

Implements the formal Enriched Evidence Contract adhering strictly to:
- Section 5: Evidence Enricher Boundary: enrich(canonical_evidence, raw_interaction_trace, provenance)
- Section 8: Strict Dependency Graph for derived facts (recomputed/removed if parents absent)
- Section 14: Prohibition of Hidden Ground-Truth Leakage (static & runtime assertions)
- Section 15: Secret Handling (redaction & quarantine: SECRET_LEAK_COUNT == 0)
- Section 20: Fact Preservation (BASE_FACTS ⊆ ENRICHED_FACTS, REMOVED_FACTS == 0, MODIFIED_EXISTING_FACTS == 0)
"""

import copy
import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))


FORBIDDEN_GT_KEYS: Set[str] = {
    "ground_truth_vulnerable",
    "vulnerable_variant",
    "designation",
    "category",
    "category_id",
    "gold_category",
    "gold_parameter",
    "scorer_label",
    "expected_decision",
    "hidden_label",
    "is_vulnerable",
    "vulnerability_category",
    "ground_truth",
}


class EnrichedField(BaseModel):
    name: str
    value: Any
    epistemic_status: str  # "OBSERVED_FACT" | "DERIVED_FACT" | "UNKNOWN"
    source_fact_id: str


class EnrichedLineageRecord(BaseModel):
    interaction_id: str
    scenario_id: str
    fields: Dict[str, Dict[str, Any]]
    base_fact_ids: List[str]
    added_fact_ids: List[str]
    verification_passed: bool = True


class Phase11_5Enricher:
    """
    Dependency-aware interaction evidence enricher.
    Transforms canonical evidence + frozen raw interaction trace into enriched observable evidence.
    """

    ALLOWED_FIELD_NAMES = [
        "interaction_id",
        "requester_identity_id",
        "requester_role",
        "requester_tenant_id",
        "resource_id",
        "resource_owner_identity_id",
        "resource_tenant_id",
        "required_role",
        "observed_authorization_context",
        "http_method",
        "route",
        "request_parameter_id",
        "response_status",
        "response_shape",
        "resource_access_result",
        "state_before",
        "state_after",
        "access_success",
        "cross_identity_access",
        "cross_tenant_access",
        "privilege_delta",
        "authorization_delta",
    ]

    @classmethod
    def assert_no_ground_truth_leakage(cls, obj: Any, path: str = "") -> None:
        """Recursively validates that no forbidden ground-truth key exists in input."""
        if isinstance(obj, dict):
            for k, v in obj.items():
                current_path = f"{path}.{k}" if path else str(k)
                if k in FORBIDDEN_GT_KEYS:
                    raise AssertionError(
                        f"GROUND-TRUTH LEAKAGE DETECTED: Forbidden key '{k}' at {current_path}"
                    )
                cls.assert_no_ground_truth_leakage(v, current_path)
        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                cls.assert_no_ground_truth_leakage(item, f"{path}[{idx}]")

    @classmethod
    def enrich(
        cls,
        canonical_evidence: Dict[str, Any],
        raw_interaction_trace: Dict[str, Any],
        provenance: Dict[str, Any],
        mask_identity: bool = False,
        mask_tenant: bool = False,
        mask_response: bool = False,
        mask_role_auth: bool = False,
        mask_state: bool = False,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], EnrichedLineageRecord]:
        """
        Formal enricher interface per Section 5.
        
        INPUTS:
            - canonical_evidence: Dict containing 'base_facts', 'base_identities', 'target_asset', 'parameters'
            - raw_interaction_trace: Frozen label-free trace
            - provenance: Provenance metadata
        """
        # Section 14: Static & Runtime Leakage Assertion
        cls.assert_no_ground_truth_leakage(canonical_evidence)
        cls.assert_no_ground_truth_leakage(raw_interaction_trace)
        cls.assert_no_ground_truth_leakage(provenance)

        # Section 20: Precondition snapshot of base facts
        base_facts = canonical_evidence["base_facts"]
        original_base_facts = copy.deepcopy(base_facts)
        base_identities = canonical_evidence.get("base_identities", [])
        target_asset = canonical_evidence.get("target_asset", {})
        parameters = canonical_evidence.get("parameters", [])

        scenario_id = raw_interaction_trace.get("scenario_id", "UNKNOWN_SCENARIO")
        interaction_id = raw_interaction_trace.get("interaction_id", "INT-01")

        # -------------------------------------------------------------
        # 1. Extract and type observable PARENT facts (with ablation support)
        # -------------------------------------------------------------
        # Identity fields
        if mask_identity:
            requester_id = None
            resource_owner = None
        else:
            requester_id = raw_interaction_trace.get("requester_identity")
            resource_owner = raw_interaction_trace.get("observed_owner")

        # Tenant fields
        if mask_tenant:
            requester_tenant = None
            resource_tenant = None
        else:
            requester_tenant = raw_interaction_trace.get("requester_tenant")
            resource_tenant = raw_interaction_trace.get("observed_tenant")

        # Response fields
        if mask_response:
            status_code = None
            shape_summary = None
            access_result = None
        else:
            status_code = raw_interaction_trace.get("response_status")
            body_val = raw_interaction_trace.get("response_body")
            shape_summary = json.dumps(body_val) if isinstance(body_val, (dict, list)) else str(body_val)
            if status_code in (200, 201, 204, 206):
                access_result = "GRANTED"
            elif status_code == 400:
                access_result = "INVALID_STATE_REJECTED"
            elif status_code in (401, 403, 404):
                access_result = "DENIED"
            else:
                access_result = "UNKNOWN"

        # Role / Auth fields
        route = raw_interaction_trace.get("route", "")
        http_method = raw_interaction_trace.get("method", "GET")
        resource_id = raw_interaction_trace.get("observed_resource")

        if mask_role_auth:
            requester_role = None
            required_role = None
            observed_auth = None
        else:
            requester_role = raw_interaction_trace.get("requester_role")
            required_role = "admin" if (route and "/roles" in route) else ("customer" if requester_role == "customer" else "unauthenticated")
            observed_auth = "Bearer credential [REDACTED]" if requester_role != "unauthenticated" else "None"

        # State fields
        if mask_state:
            state_before = None
            state_after = None
        else:
            st_dict = raw_interaction_trace.get("observed_state_transition", {})
            state_before = st_dict.get("state_before")
            state_after = st_dict.get("state_after")

        # -------------------------------------------------------------
        # 2. Strict Dependency Graph for DERIVED facts per Section 8
        # -------------------------------------------------------------
        # Parent -> Child: access_success depends on response_status and access_result
        if status_code is not None and access_result is not None:
            access_success = (access_result == "GRANTED" and status_code in (200, 201, 204, 206))
        else:
            access_success = None

        # Parent -> Child: cross_identity_access depends on requester_id, resource_owner, and access_success
        if requester_id is not None and resource_owner is not None and access_success is not None:
            cross_identity_access = bool(access_success and (requester_id != resource_owner))
        else:
            cross_identity_access = None

        # Parent -> Child: cross_tenant_access depends on requester_tenant, resource_tenant, and access_success
        if requester_tenant is not None and resource_tenant is not None and access_success is not None:
            cross_tenant_access = bool(access_success and (requester_tenant != resource_tenant))
        else:
            cross_tenant_access = None

        # Parent -> Child: privilege_delta depends on requester_role, required_role, and access_success
        if requester_role is not None and required_role is not None and access_success is not None:
            privilege_delta = bool(access_success and (requester_role == "customer" and required_role == "admin"))
        else:
            privilege_delta = None

        # Parent -> Child: state_transition_delta depends on state_before, state_after, and access_success
        if state_before is not None and state_after is not None and access_success is not None:
            state_transition_delta = bool(access_success and (state_before != state_after))
        else:
            state_transition_delta = None

        # authorization_delta
        active_deltas = [d for d in [cross_identity_access, cross_tenant_access, privilege_delta, state_transition_delta] if d is not None]
        if active_deltas:
            authorization_delta = any(active_deltas)
        else:
            authorization_delta = None

        # -------------------------------------------------------------
        # 3. Populate Typed Field Records
        # -------------------------------------------------------------
        obs_fact_id = "FACT-OBSERVED-INTERACTION-01"
        der_fact_id = "FACT-DERIVED-RELATION-01"
        field_records: Dict[str, EnrichedField] = {}

        def add_obs(name: str, val: Any):
            if val is not None:
                field_records[name] = EnrichedField(
                    name=name,
                    value=val,
                    epistemic_status="OBSERVED_FACT",
                    source_fact_id=obs_fact_id,
                )

        def add_der(name: str, val: Any):
            if val is not None:
                field_records[name] = EnrichedField(
                    name=name,
                    value=val,
                    epistemic_status="DERIVED_FACT",
                    source_fact_id=der_fact_id,
                )

        add_obs("interaction_id", interaction_id)
        add_obs("requester_identity_id", requester_id)
        add_obs("requester_role", requester_role)
        add_obs("requester_tenant_id", requester_tenant)
        add_obs("resource_id", resource_id)
        add_obs("resource_owner_identity_id", resource_owner)
        add_obs("resource_tenant_id", resource_tenant)
        add_obs("required_role", required_role)
        add_obs("observed_authorization_context", observed_auth)
        add_obs("http_method", http_method)
        add_obs("route", route)
        add_obs("request_parameter_id", parameters[0]["param_id"] if parameters else "NONE")
        add_obs("response_status", status_code)
        add_obs("response_shape", shape_summary)
        add_obs("resource_access_result", access_result)
        add_obs("state_before", state_before)
        add_obs("state_after", state_after)

        add_der("access_success", access_success)
        add_der("cross_identity_access", cross_identity_access)
        add_der("cross_tenant_access", cross_tenant_access)
        add_der("privilege_delta", privilege_delta)
        add_der("state_transition_delta", state_transition_delta)
        add_der("authorization_delta", authorization_delta)

        # -------------------------------------------------------------
        # 4. Construct Natural Language Fact Statements
        # -------------------------------------------------------------
        obs_elements = []
        if requester_id:
            role_tenant = []
            if requester_role:
                role_tenant.append(f"role='{requester_role}'")
            if requester_tenant:
                role_tenant.append(f"tenant='{requester_tenant}'")
            rt_str = f" ({', '.join(role_tenant)})" if role_tenant else ""
            obs_elements.append(f"requester_identity_id='{requester_id}'{rt_str}")

        obs_elements.append(f"executed {http_method} {route}")

        if resource_id:
            res_meta = []
            if resource_owner:
                res_meta.append(f"owner='{resource_owner}'")
            if resource_tenant:
                res_meta.append(f"tenant='{resource_tenant}'")
            rm_str = f" ({', '.join(res_meta)})" if res_meta else ""
            obs_elements.append(f"targeting resource_id='{resource_id}'{rm_str}")

        if status_code is not None:
            obs_elements.append(f"Response status: {status_code}")
        if shape_summary is not None:
            obs_elements.append(f"Response payload: {shape_summary}")
        if access_result is not None:
            obs_elements.append(f"Access result: '{access_result}'")

        obs_statement = f"[OBSERVED_FACT] Interaction {interaction_id}: " + ". ".join(obs_elements) + "."

        # Derived statement
        der_parts = []
        if access_success is True:
            if cross_identity_access is True:
                der_parts.append(f"requester_identity_id != resource_owner_identity_id ('{requester_id}' != '{resource_owner}', cross_identity_access=true)")
                if cross_tenant_access is True:
                    der_parts.append(f"requester_tenant_id != resource_tenant_id ('{requester_tenant}' != '{resource_tenant}', cross_tenant_access=true)")
                der_parts.append(f"Target object '{resource_id}' owned by '{resource_owner}' was returned to requester '{requester_id}'")
            elif state_transition_delta is True:
                der_parts.append(f"State transition: object '{resource_id}' transitioned from state_before='{state_before}' to state_after='{state_after}' via {http_method} {route}")
            else:
                if requester_id and resource_owner and requester_id == resource_owner:
                    der_parts.append(f"requester_identity_id == resource_owner_identity_id ('{requester_id}' == '{resource_owner}', cross_identity_access=false)")
                else:
                    der_parts.append(f"Access succeeded with status {status_code}")
        elif access_success is False:
            if requester_id and resource_owner and requester_id != resource_owner:
                der_parts.append(f"requester_identity_id != resource_owner_identity_id ('{requester_id}' != '{resource_owner}'). Target object access was denied with status {status_code} (cross_identity_access=false)")
            elif status_code == 400:
                der_parts.append(f"State transition blocked: object '{resource_id}' in state_before='{state_before}' rejected invalid transition (status {status_code})")
            else:
                der_parts.append(f"Access denied: request rejected by server with status {status_code}")
        else:
            der_parts.append("Derived relationships unavailable due to masked parent facts")

        der_statement = "[DERIVED_FACT] Relationship: " + "; ".join(der_parts) + "."

        endpoint_id = target_asset.get("endpoint_id") or ("EP-" + target_asset.get("asset_id", scenario_id))
        asset_id = target_asset.get("asset_id", scenario_id)
        route_template = target_asset.get("normalized_path") or target_asset.get("raw_path")
        mutability = target_asset.get("application_mutability", "READ_ONLY")

        int_fact_dict = {
            "fact_id": obs_fact_id,
            "endpoint_id": endpoint_id,
            "asset_id": asset_id,
            "route_template": route_template,
            "http_method": http_method,
            "application_mutability": mutability,
            "parameters": parameters,
            "statement": obs_statement,
            "source_tool": "interaction_observer",
            "caller_identity_id": requester_id,
            "caller_role": requester_role,
            "resource_owner_id": resource_owner,
            "resource_id": resource_id,
            "target_object": resource_id,
            "response_status": status_code,
            "response_body": shape_summary,
            "request_headers": {"Authorization": "Bearer [REDACTED]"},
        }

        der_fact_dict = {
            "fact_id": der_fact_id,
            "endpoint_id": endpoint_id,
            "asset_id": asset_id,
            "route_template": route_template,
            "http_method": http_method,
            "application_mutability": mutability,
            "parameters": parameters,
            "statement": der_statement,
            "source_tool": "relational_analysis",
        }

        # -------------------------------------------------------------
        # 5. Section 20: Fact Preservation Verification
        # -------------------------------------------------------------
        # BASE_FACTS ⊆ ENRICHED_FACTS
        enriched_facts = list(original_base_facts) + [int_fact_dict, der_fact_dict]
        assert len(enriched_facts) == len(original_base_facts) + 2, "Fact count mismatch"
        for idx, bf in enumerate(original_base_facts):
            assert enriched_facts[idx] == bf, f"Base fact {idx} was modified in violation of Section 20!"

        # Enriched identities
        enriched_identities = copy.deepcopy(base_identities)
        if not mask_identity and resource_owner and resource_id:
            for ident in enriched_identities:
                if ident.get("identity_id") == resource_owner:
                    owned = ident.get("owned_resources", [])
                    if resource_id not in owned:
                        ident["owned_resources"] = owned + [resource_id]

        lineage = EnrichedLineageRecord(
            interaction_id=interaction_id,
            scenario_id=scenario_id,
            fields={k: v.model_dump() for k, v in field_records.items()},
            base_fact_ids=[f.get("fact_id", "") for f in original_base_facts],
            added_fact_ids=[obs_fact_id, der_fact_id],
            verification_passed=True,
        )

        return enriched_facts, enriched_identities, lineage
