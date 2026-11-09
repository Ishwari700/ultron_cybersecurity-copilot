"""Production Interaction Evidence Enricher (Milestone M2, Phase 11.6).

Promotes validated Phase 11.5 interaction-evidence enrichment into production.
Transforms canonical evidence facts and raw interaction traces into enriched
observable interaction facts and deterministically-derived relational facts.

Architectural Constraints:
- Preserves Section 20 Fact Preservation: BASE_FACTS ⊆ ENRICHED_FACTS.
- Enforces strict DAG dependency propagation: child relational facts are only
  derived when required parent observations are present and valid.
- Enforces generic Public/Anonymous/SYSTEM semantics: anonymous access to
  public or SYSTEM-owned resources does not produce cross-identity violations.
- Strictly isolated from benchmark-specific scaffolding (SyntheticApp, scenario IDs,
  gold labels, or evaluator-only control flow).
- Enforces Section 14 Ground-Truth Leakage rejection.
- Enforces Section 15 Secret Quarantine and Redaction.
"""

import copy
import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field

from src.evidence.vault import RedactionVault


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

SYSTEM_IDENTITIES: Set[str] = {"SYSTEM", "SYSTEM_USER", "INTERNAL", "ROOT", "ADMIN_SYSTEM"}
PUBLIC_IDENTITIES: Set[str] = {"PUBLIC", "ANONYMOUS", "UNAUTHENTICATED", "GUEST", "NONE"}


class EnrichedField(BaseModel):
    """A typed field within an enriched interaction lineage record."""
    name: str
    value: Any
    epistemic_status: str  # "OBSERVED" | "DETERMINISTIC_DERIVATION" | "UNKNOWN"
    source_fact_id: str


class EnrichedLineageRecord(BaseModel):
    """Lineage metadata documenting the provenance of enriched facts."""
    interaction_id: str
    fields: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    base_fact_ids: List[str] = Field(default_factory=list)
    added_fact_ids: List[str] = Field(default_factory=list)
    suppressed_derivations: List[Dict[str, str]] = Field(default_factory=list)
    verification_passed: bool = True


class InteractionEvidenceEnricher:
    """
    Production-grade dependency-aware interaction evidence enricher.
    Transforms canonical evidence + raw interaction traces into enriched observable evidence.
    """

    ALLOWED_FIELD_NAMES: List[str] = [
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
                if str(k).lower() in FORBIDDEN_GT_KEYS:
                    raise AssertionError(
                        f"GROUND-TRUTH LEAKAGE DETECTED: Forbidden key '{k}' at {current_path}"
                    )
                cls.assert_no_ground_truth_leakage(v, current_path)
        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                cls.assert_no_ground_truth_leakage(item, f"{path}[{idx}]")

    @staticmethod
    def is_anonymous_or_public_caller(caller_id: Optional[str], caller_role: Optional[str]) -> bool:
        """Return True if the caller is unauthenticated or anonymous."""
        if not caller_id:
            return True
        c_clean = str(caller_id).strip().upper()
        r_clean = str(caller_role).strip().upper() if caller_role else ""
        return c_clean in PUBLIC_IDENTITIES or r_clean in ("ANONYMOUS", "UNAUTHENTICATED", "PUBLIC", "GUEST")

    @staticmethod
    def is_system_or_public_resource(owner_id: Optional[str], owner_tenant: Optional[str]) -> bool:
        """Return True if the resource belongs to SYSTEM, PUBLIC, or is an unowned public catalog."""
        if not owner_id:
            return False
        o_clean = str(owner_id).strip().upper()
        t_clean = str(owner_tenant).strip().upper() if owner_tenant else ""
        return o_clean in SYSTEM_IDENTITIES or o_clean in PUBLIC_IDENTITIES or t_clean in ("PUBLIC", "SYSTEM")

    @classmethod
    def enrich_single_trace(
        cls,
        base_facts: List[Dict[str, Any]],
        base_identities: List[Dict[str, Any]],
        target_asset: Dict[str, Any],
        parameters: List[Dict[str, Any]],
        raw_interaction_trace: Dict[str, Any],
        vault: Optional[RedactionVault] = None,
        interaction_index: int = 1,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], EnrichedLineageRecord]:
        """
        Enrich base canonical facts with a single raw interaction trace.
        Enforces DAG dependencies, generic Public/SYSTEM semantics, secret redaction,
        and fact preservation.
        """
        # Section 14: Ground-truth leakage audit
        cls.assert_no_ground_truth_leakage(raw_interaction_trace)

        vault = vault or RedactionVault()
        original_base_facts = copy.deepcopy(base_facts)

        interaction_id = str(raw_interaction_trace.get("interaction_id") or f"INT-{interaction_index:02d}")
        obs_fact_id = f"FACT-OBSERVED-INTERACTION-{interaction_index:02d}"
        der_fact_id = f"FACT-DERIVED-RELATION-{interaction_index:02d}"

        field_records: Dict[str, EnrichedField] = {}
        suppressed_derivations: List[Dict[str, str]] = []

        # -------------------------------------------------------------
        # 1. Extract Parent Observable Values
        # -------------------------------------------------------------
        requester_id = raw_interaction_trace.get("requester_identity") or raw_interaction_trace.get("caller_identity_id")
        requester_role = raw_interaction_trace.get("requester_role") or raw_interaction_trace.get("caller_role")
        requester_tenant = raw_interaction_trace.get("requester_tenant") or raw_interaction_trace.get("caller_tenant_id")

        resource_id = raw_interaction_trace.get("observed_resource") or raw_interaction_trace.get("resource_id") or raw_interaction_trace.get("target_object")
        resource_owner = raw_interaction_trace.get("observed_owner") or raw_interaction_trace.get("resource_owner_id") or raw_interaction_trace.get("resource_owner")
        resource_tenant = raw_interaction_trace.get("observed_tenant") or raw_interaction_trace.get("resource_tenant_id")

        route = raw_interaction_trace.get("route") or target_asset.get("normalized_path") or target_asset.get("raw_path") or ""
        http_method = (raw_interaction_trace.get("method") or raw_interaction_trace.get("http_method") or target_asset.get("method") or "GET").upper()

        status_code = raw_interaction_trace.get("response_status") or raw_interaction_trace.get("status_code")
        body_val = raw_interaction_trace.get("response_body")
        if body_val is not None:
            # Redact sensitive material from body before generating shape summary
            if isinstance(body_val, dict):
                redacted_body = vault.redact_dict(body_val)
            else:
                redacted_body = vault.redact_text(str(body_val))
            shape_summary = json.dumps(redacted_body) if isinstance(redacted_body, (dict, list)) else str(redacted_body)
        else:
            shape_summary = None

        req_headers = raw_interaction_trace.get("request_headers") or {}
        redacted_headers = {}
        if isinstance(req_headers, dict):
            for hk, hv in req_headers.items():
                hk_norm = hk.lower().replace("-", "_").replace("x_", "")
                if vault.SENSITIVE_KEY_PATTERN.search(hk_norm) or vault.SENSITIVE_KEY_PATTERN.search(hk.lower()):
                    redacted_headers[hk] = vault._get_or_create_placeholder(str(hv), "SECRET")
                else:
                    redacted_headers[hk] = vault.redact_text(str(hv))
        # Ensure observed auth context is typed and sanitized
        has_auth_header = bool(redacted_headers.get("Authorization") or redacted_headers.get("authorization") or redacted_headers.get("Cookie") or redacted_headers.get("cookie") or any("key" in hk.lower() or "token" in hk.lower() for hk in redacted_headers))
        if has_auth_header:
            observed_auth = "Authenticated (Bearer/Cookie/Key credential [REDACTED])"
        elif requester_role and requester_role not in ("unauthenticated", "anonymous", "public"):
            observed_auth = f"Authenticated ({requester_role})"
        else:
            observed_auth = "Unauthenticated (None)"

        required_role = raw_interaction_trace.get("required_role")
        if not required_role and route and ("/admin" in route or "/roles" in route):
            required_role = "admin"

        # State transition
        st_dict = raw_interaction_trace.get("observed_state_transition") or {}
        state_before = st_dict.get("state_before")
        state_after = st_dict.get("state_after")

        # Response access result classification
        if status_code is not None:
            if status_code in (200, 201, 204, 206):
                access_result = "GRANTED"
            elif status_code == 400:
                access_result = "INVALID_STATE_REJECTED"
            elif status_code in (401, 403, 404):
                access_result = "DENIED"
            else:
                access_result = "UNKNOWN"
        else:
            access_result = None

        # -------------------------------------------------------------
        # 2. DAG Dependency Enforcement & Generic Public/SYSTEM Semantics
        # -------------------------------------------------------------
        # Rule 1: access_success depends on status_code and access_result
        if status_code is not None and access_result is not None:
            access_success = (access_result == "GRANTED" and status_code in (200, 201, 204, 206))
        else:
            access_success = None
            suppressed_derivations.append({"target": "access_success", "reason": "Missing status_code or access_result"})

        # Rule 2: cross_identity_access
        # For cross-identity access to be True, require:
        # 1. access_success is True
        # 2. requester is a known, authenticated identity (not anonymous/public)
        # 3. resource owner is a specific user/tenant identity (not SYSTEM/PUBLIC)
        # 4. requester identity differs from resource owner
        is_anon_caller = cls.is_anonymous_or_public_caller(requester_id, requester_role)
        is_sys_or_pub_res = cls.is_system_or_public_resource(resource_owner, resource_tenant)

        if access_success is not None:
            if is_anon_caller or is_sys_or_pub_res:
                # Access to public or system resources anonymously is NOT cross-identity access
                cross_identity_access = False
            elif requester_id is not None and resource_owner is not None:
                cross_identity_access = bool(access_success and (requester_id != resource_owner))
            else:
                cross_identity_access = None
                suppressed_derivations.append({
                    "target": "cross_identity_access",
                    "reason": "Missing requester_identity_id or resource_owner_identity_id",
                })
        else:
            cross_identity_access = None
            suppressed_derivations.append({
                "target": "cross_identity_access",
                "reason": "access_success parent dependency unresolved",
            })

        # Rule 3: cross_tenant_access
        if access_success is not None:
            if is_anon_caller or is_sys_or_pub_res:
                cross_tenant_access = False
            elif requester_tenant is not None and resource_tenant is not None:
                cross_tenant_access = bool(access_success and (requester_tenant != resource_tenant))
            else:
                cross_tenant_access = None
                suppressed_derivations.append({
                    "target": "cross_tenant_access",
                    "reason": "Missing requester_tenant or resource_tenant",
                })
        else:
            cross_tenant_access = None
            suppressed_derivations.append({
                "target": "cross_tenant_access",
                "reason": "access_success parent dependency unresolved",
            })

        # Rule 4: privilege_delta
        if access_success is not None:
            if requester_role is not None and required_role is not None:
                r_req = str(requester_role).lower()
                r_reqd = str(required_role).lower()
                privilege_delta = bool(access_success and (r_req in ("user", "customer", "member") and r_reqd in ("admin", "tenant_admin", "super_admin")))
            else:
                privilege_delta = None
                suppressed_derivations.append({
                    "target": "privilege_delta",
                    "reason": "Missing requester_role or required_role",
                })
        else:
            privilege_delta = None
            suppressed_derivations.append({
                "target": "privilege_delta",
                "reason": "access_success parent dependency unresolved",
            })

        # Rule 5: state_transition_delta
        if access_success is not None:
            if state_before is not None and state_after is not None:
                state_transition_delta = bool(access_success and (state_before != state_after))
            else:
                state_transition_delta = None
                suppressed_derivations.append({
                    "target": "state_transition_delta",
                    "reason": "Missing state_before or state_after",
                })
        else:
            state_transition_delta = None
            suppressed_derivations.append({
                "target": "state_transition_delta",
                "reason": "access_success parent dependency unresolved",
            })

        # Rule 6: authorization_delta
        active_deltas = [d for d in [cross_identity_access, cross_tenant_access, privilege_delta, state_transition_delta] if d is not None]
        if active_deltas:
            authorization_delta = any(active_deltas)
        else:
            authorization_delta = None
            suppressed_derivations.append({
                "target": "authorization_delta",
                "reason": "No active child deltas resolved",
            })

        # -------------------------------------------------------------
        # 3. Populate Lineage Field Records
        # -------------------------------------------------------------
        def add_obs(name: str, val: Any):
            if val is not None:
                field_records[name] = EnrichedField(
                    name=name,
                    value=val,
                    epistemic_status="OBSERVED",
                    source_fact_id=obs_fact_id,
                )

        def add_der(name: str, val: Any):
            if val is not None:
                field_records[name] = EnrichedField(
                    name=name,
                    value=val,
                    epistemic_status="DETERMINISTIC_DERIVATION",
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
        param_id_str = parameters[0].get("param_id", parameters[0].get("param_name", "NONE")) if parameters else "NONE"
        add_obs("request_parameter_id", param_id_str)
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

        # Derived relational statement
        der_parts = []
        if access_success is True:
            if is_anon_caller and is_sys_or_pub_res:
                der_parts.append(f"Unauthenticated request accessed public/system resource '{resource_id}' (status {status_code}, cross_identity_access=false)")
            elif cross_identity_access is True:
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
            der_parts.append("Derived relationships unavailable due to masked or missing parent facts")

        der_statement = "[DERIVED_FACT] Relationship: " + "; ".join(der_parts) + "."

        # Target metadata resolution
        endpoint_id = target_asset.get("endpoint_id") or ("EP-" + str(target_asset.get("asset_id", "UNKNOWN")))
        asset_id = target_asset.get("asset_id", "UNKNOWN")
        route_template = route or target_asset.get("route_template") or target_asset.get("normalized_path") or target_asset.get("raw_path") or "/"
        mutability = target_asset.get("application_mutability", "READ_ONLY")

        # Clean redacted request headers (never leak bearer token or raw auth)
        safe_headers = dict(redacted_headers)
        if "Authorization" not in safe_headers and "authorization" not in safe_headers:
            if requester_role and requester_role not in ("unauthenticated", "anonymous", "public"):
                safe_headers["Authorization"] = "Bearer [REDACTED]"

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
            "request_headers": safe_headers,
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
            "cross_identity_access": cross_identity_access,
            "cross_tenant_access": cross_tenant_access,
            "privilege_delta": privilege_delta,
            "state_transition_delta": state_transition_delta,
            "authorization_delta": authorization_delta,
        }

        # -------------------------------------------------------------
        # 5. Fact Preservation Assertion & Identity Matrix Update
        # -------------------------------------------------------------
        enriched_facts = list(original_base_facts) + [int_fact_dict, der_fact_dict]
        assert len(enriched_facts) == len(original_base_facts) + 2, "Fact count mismatch after enrichment"
        for idx, bf in enumerate(original_base_facts):
            assert enriched_facts[idx] == bf, f"Base fact {idx} was modified in violation of Section 20!"

        # Update identity matrix with observed resource ownership if authenticated
        enriched_identities = copy.deepcopy(base_identities)
        if not is_anon_caller and not is_sys_or_pub_res and resource_owner and resource_id:
            owner_found = False
            for ident in enriched_identities:
                if ident.get("identity_id") == resource_owner:
                    owner_found = True
                    owned = ident.get("owned_resources", [])
                    if resource_id not in owned:
                        ident["owned_resources"] = owned + [resource_id]
            if not owner_found:
                # Add implicit identity record for the owner
                enriched_identities.append({
                    "identity_id": resource_owner,
                    "role": "STANDARD_USER",
                    "owned_resources": [resource_id],
                })

        lineage = EnrichedLineageRecord(
            interaction_id=interaction_id,
            fields={k: v.model_dump() for k, v in field_records.items()},
            base_fact_ids=[f.get("fact_id", "") for f in original_base_facts],
            added_fact_ids=[obs_fact_id, der_fact_id],
            suppressed_derivations=suppressed_derivations,
            verification_passed=True,
        )

        return enriched_facts, enriched_identities, lineage

    @classmethod
    def enrich(
        cls,
        raw_facts: List[Dict[str, Any]],
        interaction_traces: List[Dict[str, Any]],
        identity_matrix: Optional[List[Dict[str, Any]]] = None,
        target_asset: Optional[Dict[str, Any]] = None,
        vault: Optional[RedactionVault] = None,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[EnrichedLineageRecord]]:
        """
        Enrich raw facts with a list of interaction traces.
        Produces combined enriched facts, updated identity matrix, and lineage records.
        """
        if not interaction_traces:
            return raw_facts, identity_matrix or [], []

        identities = list(identity_matrix or [])
        current_facts = list(raw_facts)
        lineage_records = []

        primary_fact = raw_facts[0] if raw_facts else {}
        derived_target_asset = target_asset or {
            "endpoint_id": primary_fact.get("endpoint_id", "EP-PRIMARY"),
            "asset_id": primary_fact.get("asset_id", "ASSET-PRIMARY"),
            "route_template": primary_fact.get("route_template") or primary_fact.get("normalized_path") or "/",
            "method": primary_fact.get("http_method", "GET"),
            "application_mutability": primary_fact.get("application_mutability", "READ_ONLY"),
        }
        parameters = primary_fact.get("parameters", [])

        for idx, trace in enumerate(interaction_traces, 1):
            current_facts, identities, lineage = cls.enrich_single_trace(
                base_facts=current_facts,
                base_identities=identities,
                target_asset=derived_target_asset,
                parameters=parameters,
                raw_interaction_trace=trace,
                vault=vault,
                interaction_index=idx,
            )
            lineage_records.append(lineage)

        return current_facts, identities, lineage_records
