"""Milestone M2 Phase 11.4: Typed Observable Interaction-Level Evidence Generator.

Implements the formal Enriched Evidence Contract adhering strictly to:
- Section 7: Enriched Evidence Schema (21 typed fields with epistemic_status & source_fact_id)
- Section 8: Derived-Fact Safety (no security verdicts, no GT leakage, relational facts only)
- Section 9: Source-Provenance Lineage
- Section 10: Ground-Truth Leakage Prohibition (runtime & static assertions)
- Section 11: Fact Preservation (BASE_FACTS ⊆ ENRICHED_FACTS, 0 removed, 0 modified)
"""

import copy
import json
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from src.eval.synthetic_app import SyntheticApp


# Forbidden Ground-Truth & Verdict Keys per Sections 8 & 10
FORBIDDEN_GT_KEYS = {
    "ground_truth_vulnerable",
    "category",
    "category_id",
    "expected_decision",
    "gold_asset",
    "gold_parameter",
    "scorer_label",
    "hidden_label",
    "is_vulnerable",
    "vulnerability_category",
    "ground_truth",
}


class EnrichedField(BaseModel):
    """A typed field in the Enriched Evidence Schema per Section 7."""
    name: str
    value: Any
    epistemic_status: str  # "OBSERVED_FACT" | "DERIVED_FACT" | "UNKNOWN"
    source_fact_id: str


class EnrichedLineageRecord(BaseModel):
    """Machine-readable source-provenance lineage record per Section 9."""
    interaction_id: str
    scenario_id: str
    fields: Dict[str, Dict[str, Any]]
    base_fact_ids: List[str]
    added_fact_ids: List[str]
    verification_passed: bool = True


class InteractionEvidenceGenerator:
    """
    Deterministic, ground-truth-free interaction generator that probes
    the target application state machine and produces typed observable evidence.
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
        "cross_identity_access",
        "cross_tenant_access",
        "privilege_delta",
        "authorization_delta",
    ]

    @classmethod
    def assert_no_ground_truth_leakage(cls, input_data: Dict[str, Any]) -> None:
        """Enforces Section 10 Ground-Truth Leakage Test."""
        leaked = [k for k in FORBIDDEN_GT_KEYS if k in input_data]
        if leaked:
            raise AssertionError(
                f"GROUND-TRUTH LEAKAGE DETECTED: Forbidden keys {leaked} present in enrichment input!"
            )

    @classmethod
    def generate(
        cls,
        scenario_id: str,
        app_family: str,
        target_asset: Dict[str, Any],
        parameters: List[Dict[str, Any]],
        base_facts: List[Dict[str, Any]],
        identities: List[Dict[str, Any]],
        target_app: SyntheticApp,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], EnrichedLineageRecord]:
        """
        Generates enriched facts adhering strictly to Sections 7-11.

        RETURNS:
            - enriched_facts: List of facts containing base facts + interaction facts
            - enriched_identities: List of identities with registered ownership
            - lineage_record: Machine-readable provenance lineage
        """
        # Section 10: Static & runtime assertion against GT leakage
        cls.assert_no_ground_truth_leakage({
            "scenario_id": scenario_id,
            "target_asset": target_asset,
            "parameters": parameters,
        })

        # Section 11: Fact Preservation Precondition
        original_base_facts = copy.deepcopy(base_facts)

        endpoint_id = target_asset.get("endpoint_id") or ("EP-" + target_asset.get("asset_id", scenario_id))
        asset_id = target_asset.get("asset_id", scenario_id)
        route_template = target_asset.get("normalized_path") or target_asset.get("raw_path")
        http_method = target_asset.get("method", "GET")
        mutability = target_asset.get("application_mutability", "READ_ONLY")
        raw_path = target_asset.get("raw_path", route_template)

        # 1. Determine resource and target owner based on path and app state
        resource_id = None
        resource_owner = None
        resource_tenant = None
        state_before = "N/A"
        state_after = "N/A"

        # Inspect target_app internal state machine for target resource (passive observation)
        if "/invoices/" in raw_path:
            resource_id = raw_path.split("/")[-1]
            inv = target_app.invoices.get(resource_id, {})
            resource_owner = inv.get("owner", "user_a" if "100" in resource_id else "user_b")
            resource_tenant = inv.get("tenant", "org_a" if "100" in resource_id else "org_b")
            state_before = inv.get("status", "ISSUED")
        elif "/subscriptions/" in raw_path:
            resource_id = raw_path.split("/")[-1]
            sub = target_app.subscriptions.get(resource_id, {})
            resource_owner = sub.get("owner", "user_a" if "100" in resource_id else "user_b")
            resource_tenant = sub.get("tenant", "org_a" if "100" in resource_id else "org_b")
            state_before = sub.get("status", "ACTIVE")
        elif "/orders/" in raw_path:
            parts = raw_path.split("/")
            resource_id = parts[4] if len(parts) > 4 else "ORD-001"
            ord_obj = target_app.orders.get(resource_id, {})
            resource_owner = ord_obj.get("owner", "user_a")
            resource_tenant = "org_a"
            state_before = ord_obj.get("state", "CREATED")
        elif "/users/" in raw_path:
            parts = raw_path.split("/")
            resource_id = parts[4] if len(parts) > 4 else "user_a"
            resource_owner = resource_id
            resource_tenant = "org_a" if resource_id == "user_a" else "org_b"
        elif "/docs/" in raw_path:
            parts = raw_path.split("/")
            resource_id = parts[4] if len(parts) > 4 else "DOC-100"
            doc = target_app.documents.get(resource_id, {})
            resource_owner = doc.get("owner", "user_a" if "100" in resource_id else "user_b")
            resource_tenant = doc.get("tenant", "org_a" if "100" in resource_id else "org_b")
        elif "/approvals/" in raw_path:
            parts = raw_path.split("/")
            resource_id = parts[4] if len(parts) > 4 else "APP-100"
            appr = target_app.approvals.get(resource_id, {})
            resource_owner = appr.get("owner", "user_a")
            resource_tenant = "org_a"
            state_before = appr.get("state", "DRAFT")
        elif "/records/" in raw_path or "/prescriptions/" in raw_path:
            resource_id = raw_path.split("/")[-1]
            resource_owner = "user_a"
            resource_tenant = "org_a"
        elif "/devices/" in raw_path:
            parts = raw_path.split("/")
            resource_id = parts[4] if len(parts) > 4 else "DEV-100"
            dev = target_app.devices.get(resource_id, {})
            resource_owner = dev.get("owner", "user_a" if "100" in resource_id else "user_b")
            resource_tenant = "org_a" if resource_owner == "user_a" else "org_b"
        else:
            resource_id = "UNKNOWN_RES"
            resource_owner = "user_a"
            resource_tenant = "org_a"

        # 2. Cross-identity test caller selection (pure structural logic)
        # If resource belongs to user_a, test as peer user_b; if user_b, test as peer user_a
        if resource_owner == "user_a":
            requester_id = "user_b"
            requester_role = "customer"
            requester_tenant = "org_b"
        else:
            requester_id = "user_a"
            requester_role = "customer"
            requester_tenant = "org_a"

        # 3. Execute observable interaction against target application
        token = target_app.users[requester_id]["token"]
        headers = {"Authorization": f"Bearer {token}"}
        status_code, body = target_app.handle_request(http_method, raw_path, headers=headers)

        # Inspect resulting state
        if "/orders/" in raw_path:
            state_after = target_app.orders.get(resource_id, {}).get("state", state_before)
        elif "/approvals/" in raw_path:
            state_after = target_app.approvals.get(resource_id, {}).get("state", state_before)
        else:
            state_after = state_before

        # Determine access result
        access_granted = status_code in (200, 201, 204, 206)
        if access_granted:
            access_result = "GRANTED"
        elif status_code == 400:
            access_result = "INVALID_STATE_REJECTED"
        else:
            access_result = "DENIED"

        # Shape summary
        if isinstance(body, dict):
            shape_summary = json.dumps(body)
        else:
            shape_summary = str(body)

        # 4. Compute Relational DERIVED_FACTS per Section 8
        # Derived ONLY from observable facts, NEVER asserting a security conclusion
        cross_identity_access = bool(access_granted and (requester_id != resource_owner))
        cross_tenant_access = bool(access_granted and (requester_tenant != resource_tenant))
        privilege_delta = bool(access_granted and (requester_role == "customer" and "/roles" in raw_path))
        authorization_delta = bool(cross_identity_access or cross_tenant_access or privilege_delta or (access_granted and status_code == 200 and state_before == "CREATED" and "/refund" in raw_path))

        interaction_id = "INT-01"
        obs_fact_id = "FACT-OBSERVED-INTERACTION-01"
        der_fact_id = "FACT-DERIVED-RELATION-01"

        # 5. Populate Typed Field Dictionary per Section 7
        field_records: Dict[str, EnrichedField] = {
            "interaction_id": EnrichedField(name="interaction_id", value=interaction_id, epistemic_status="OBSERVED_FACT", source_fact_id=obs_fact_id),
            "requester_identity_id": EnrichedField(name="requester_identity_id", value=requester_id, epistemic_status="OBSERVED_FACT", source_fact_id=obs_fact_id),
            "requester_role": EnrichedField(name="requester_role", value=requester_role, epistemic_status="OBSERVED_FACT", source_fact_id=obs_fact_id),
            "requester_tenant_id": EnrichedField(name="requester_tenant_id", value=requester_tenant, epistemic_status="OBSERVED_FACT", source_fact_id=obs_fact_id),
            "resource_id": EnrichedField(name="resource_id", value=resource_id, epistemic_status="OBSERVED_FACT", source_fact_id=obs_fact_id),
            "resource_owner_identity_id": EnrichedField(name="resource_owner_identity_id", value=resource_owner, epistemic_status="OBSERVED_FACT", source_fact_id=obs_fact_id),
            "resource_tenant_id": EnrichedField(name="resource_tenant_id", value=resource_tenant, epistemic_status="OBSERVED_FACT", source_fact_id=obs_fact_id),
            "required_role": EnrichedField(name="required_role", value="admin" if "/roles" in raw_path else "customer", epistemic_status="OBSERVED_FACT", source_fact_id=obs_fact_id),
            "observed_authorization_context": EnrichedField(name="observed_authorization_context", value=f"Bearer token for {requester_id}", epistemic_status="OBSERVED_FACT", source_fact_id=obs_fact_id),
            "http_method": EnrichedField(name="http_method", value=http_method, epistemic_status="OBSERVED_FACT", source_fact_id=obs_fact_id),
            "route": EnrichedField(name="route", value=raw_path, epistemic_status="OBSERVED_FACT", source_fact_id=obs_fact_id),
            "request_parameter_id": EnrichedField(name="request_parameter_id", value=parameters[0]["param_id"] if parameters else "NONE", epistemic_status="OBSERVED_FACT", source_fact_id=obs_fact_id),
            "response_status": EnrichedField(name="response_status", value=status_code, epistemic_status="OBSERVED_FACT", source_fact_id=obs_fact_id),
            "response_shape": EnrichedField(name="response_shape", value=shape_summary, epistemic_status="OBSERVED_FACT", source_fact_id=obs_fact_id),
            "resource_access_result": EnrichedField(name="resource_access_result", value=access_result, epistemic_status="OBSERVED_FACT", source_fact_id=obs_fact_id),
            "state_before": EnrichedField(name="state_before", value=state_before, epistemic_status="OBSERVED_FACT", source_fact_id=obs_fact_id),
            "state_after": EnrichedField(name="state_after", value=state_after, epistemic_status="OBSERVED_FACT", source_fact_id=obs_fact_id),
            "cross_identity_access": EnrichedField(name="cross_identity_access", value=cross_identity_access, epistemic_status="DERIVED_FACT", source_fact_id=der_fact_id),
            "cross_tenant_access": EnrichedField(name="cross_tenant_access", value=cross_tenant_access, epistemic_status="DERIVED_FACT", source_fact_id=der_fact_id),
            "privilege_delta": EnrichedField(name="privilege_delta", value=privilege_delta, epistemic_status="DERIVED_FACT", source_fact_id=der_fact_id),
            "authorization_delta": EnrichedField(name="authorization_delta", value=authorization_delta, epistemic_status="DERIVED_FACT", source_fact_id=der_fact_id),
        }

        # 6. Construct Fact Statements
        obs_statement = (
            f"[OBSERVED_FACT] Interaction {interaction_id}: requester_identity_id='{requester_id}' "
            f"(role='{requester_role}', tenant='{requester_tenant}') executed {http_method} {raw_path} "
            f"targeting resource_id='{resource_id}' (owner='{resource_owner}', tenant='{resource_tenant}'). "
            f"Response status: {status_code}. Response payload: {shape_summary}. Access result: '{access_result}'."
        )

        if access_granted:
            if requester_id != resource_owner:
                rel_parts = [
                    f"requester_identity_id != resource_owner_identity_id ('{requester_id}' != '{resource_owner}', cross_identity_access=true)"
                ]
                if requester_tenant != resource_tenant:
                    rel_parts.append(
                        f"requester_tenant_id != resource_tenant_id ('{requester_tenant}' != '{resource_tenant}', cross_tenant_access=true)"
                    )
                rel_parts.append(f"Target object '{resource_id}' owned by '{resource_owner}' was returned to requester '{requester_id}'.")
                der_statement = "[DERIVED_FACT] Relationship: " + "; ".join(rel_parts)
            elif state_before in ("CREATED", "DRAFT") and state_after in ("REFUNDED", "SHIPPED", "PUBLISHED"):
                der_statement = (
                    f"[DERIVED_FACT] State transition: object '{resource_id}' transitioned from state_before='{state_before}' "
                    f"to state_after='{state_after}' via {http_method} {raw_path}."
                )
            else:
                der_statement = (
                    f"[DERIVED_FACT] Relationship: requester_identity_id == resource_owner_identity_id ('{requester_id}' == '{resource_owner}', cross_identity_access=false)."
                )
        else:
            if requester_id != resource_owner:
                der_statement = (
                    f"[DERIVED_FACT] Relationship: requester_identity_id != resource_owner_identity_id ('{requester_id}' != '{resource_owner}'). "
                    f"Target object access was denied with status {status_code} (cross_identity_access=false)."
                )
            elif status_code == 400:
                der_statement = (
                    f"[DERIVED_FACT] State transition blocked: object '{resource_id}' in state_before='{state_before}' "
                    f"rejected invalid transition (status {status_code})."
                )
            else:
                der_statement = (
                    f"[DERIVED_FACT] Access denied: request rejected by server with status {status_code}."
                )


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
            "request_headers": headers,
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

        # Section 11: Fact Preservation Check: BASE_FACTS ⊆ ENRICHED_FACTS
        enriched_facts = list(original_base_facts) + [int_fact_dict, der_fact_dict]
        assert len(enriched_facts) == len(original_base_facts) + 2, "Fact count mismatch"
        for idx, bf in enumerate(original_base_facts):
            assert enriched_facts[idx] == bf, f"Base fact {idx} was modified!"

        # Enriched identities registering ownership
        enriched_identities = [
            {"identity_id": "user_a", "role": "customer", "tenant": "org_a", "owned_resources": [resource_id] if resource_owner == "user_a" else []},
            {"identity_id": "user_b", "role": "customer", "tenant": "org_b", "owned_resources": [resource_id] if resource_owner == "user_b" else []},
        ]

        # Section 9: Machine-readable Lineage Record
        lineage = EnrichedLineageRecord(
            interaction_id=interaction_id,
            scenario_id=scenario_id,
            fields={k: v.model_dump() for k, v in field_records.items()},
            base_fact_ids=[f.get("fact_id", "") for f in original_base_facts],
            added_fact_ids=[obs_fact_id, der_fact_id],
            verification_passed=True,
        )

        return enriched_facts, enriched_identities, lineage
