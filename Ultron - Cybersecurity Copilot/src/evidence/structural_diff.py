"""StructuralDiffEngine: Canonical Evidence Synthesis & Predicate Authority.

Sole component permitted to compute Class-1 canonical-evidence predicate booleans.
Pure, deterministic computational engine operating over canonical evidence snapshots.
"""

import json
from typing import Any, Dict, List, Optional, Set, Tuple

from src.evidence.cascade_models import (
    CanonicalEvidenceIntegrityError,
    LosslessStructuralPack,
)


# Canonical privilege role lattice order:
# ANONYMOUS (0) < STANDARD_USER (1) < TENANT_ADMIN (2)
ROLE_LATTICE: Dict[str, int] = {
    "ANONYMOUS": 0,
    "USER": 1,
    "STANDARD_USER": 1,
    "MEMBER": 1,
    "ADMIN": 2,
    "TENANT_ADMIN": 2,
    "SUPER_ADMIN": 3,
}


class StructuralDiffEngine:
    """
    Deterministic, pure structural diff computation over canonical evidence.db snapshots.
    Sole component permitted to compute Class-1 canonical-evidence predicate booleans.
    """

    @staticmethod
    def get_role_level(role: Optional[str]) -> Optional[int]:
        """Return integer privilege level for a role in the canonical lattice."""
        if not role:
            return None
        return ROLE_LATTICE.get(role.upper(), None)

    @classmethod
    def compute(
        cls,
        raw_facts: List[Dict[str, Any]],
        identity_matrix: Optional[List[Dict[str, Any]]] = None,
        interaction_traces: Optional[List[Dict[str, Any]]] = None,
    ) -> LosslessStructuralPack:
        """
        Pure deterministic computation of LosslessStructuralPack and Class-1 predicates.

        FAILURE MODES:
            - Missing or Corrupt Evidence: If raw_facts is empty, or missing endpoint_id/asset_id,
              raises CanonicalEvidenceIntegrityError -> Pipeline enters immediate HOLD/BLOCK.
            - All Unparseable Responses: If all response bodies for an endpoint are unparseable,
              raises CanonicalEvidenceIntegrityError.
        """
        if not raw_facts:
            raise CanonicalEvidenceIntegrityError("raw_facts cannot be empty; canonical evidence required.")

        interaction_lineage_dicts: Optional[List[Dict[str, Any]]] = None
        if interaction_traces:
            from src.evidence.interaction_enrichment import InteractionEvidenceEnricher
            raw_facts, identity_matrix, lineage_records = InteractionEvidenceEnricher.enrich(
                raw_facts=raw_facts,
                interaction_traces=interaction_traces,
                identity_matrix=identity_matrix,
            )
            interaction_lineage_dicts = [r.model_dump() for r in lineage_records]

        # Ensure required identifiers exist on all facts
        primary_fact = raw_facts[0]
        endpoint_id = primary_fact.get("endpoint_id")
        asset_id = primary_fact.get("asset_id")
        route_template = primary_fact.get("route_template") or primary_fact.get("normalized_path") or primary_fact.get("raw_path")
        http_method = (primary_fact.get("http_method") or "GET").upper()
        application_mutability = primary_fact.get("application_mutability") or "READ_ONLY"

        if not endpoint_id or not asset_id or not route_template:
            raise CanonicalEvidenceIntegrityError(
                f"Missing required canonical identifiers (endpoint_id={endpoint_id}, "
                f"asset_id={asset_id}, route_template={route_template})"
            )

        identity_matrix = identity_matrix or []
        identity_lookup: Dict[str, Dict[str, Any]] = {
            ident.get("identity_id", ""): ident for ident in identity_matrix if ident.get("identity_id")
        }

        # Collect observations across facts
        observed_roles: Set[str] = set()
        status_by_role: Dict[str, Set[int]] = {}
        json_keys_by_role: Dict[str, Set[str]] = {}
        body_parse_success_by_role: Dict[str, bool] = {}

        has_privilege_level_delta = False
        has_unauthenticated_success = False
        has_cross_identity_object_access_success = False
        has_evidence_parse_asymmetry = False
        has_numeric_path_id = False
        has_unseen_param = False
        auth_header_present = False
        auth_header_absent = False

        total_response_bodies = 0
        failed_response_bodies = 0

        # Check path parameters for numeric or UUID patterns
        import re
        numeric_or_uuid_pattern = re.compile(
            r"(\b\d+\b|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"
        )
        if numeric_or_uuid_pattern.search(route_template):
            has_numeric_path_id = True

        for fact in raw_facts:
            # Check fact endpoint/asset consistency
            if fact.get("endpoint_id") and fact.get("endpoint_id") != endpoint_id:
                raise CanonicalEvidenceIntegrityError("Inconsistent endpoint_id across raw_facts snapshot.")

            headers = fact.get("request_headers") or fact.get("headers") or {}
            has_auth = bool(headers.get("Authorization") or headers.get("authorization") or headers.get("Cookie") or headers.get("cookie"))
            if has_auth:
                auth_header_present = True
            else:
                auth_header_absent = True

            # Parameter inspection
            params = fact.get("parameters") or []
            for p in params:
                if isinstance(p, dict):
                    if p.get("location") == "path" and numeric_or_uuid_pattern.search(str(p.get("param_name", ""))):
                        has_numeric_path_id = True
                    if p.get("is_unseen") or p.get("unseen_in_baseline"):
                        has_unseen_param = True

            # Identity Context Semantics: Three Distinct States
            # State 1: Known Authenticated Identity
            # State 2: Explicitly Observed Unauthenticated Identity (identity_context == "UNAUTHENTICATED")
            # State 3: Missing / Unknown Identity Metadata (identity_context == "UNKNOWN" or None)
            ident_ctx = fact.get("identity_context")
            caller_id = fact.get("caller_identity_id") or fact.get("identity_id")
            caller_role = fact.get("caller_role") or fact.get("role")

            if caller_id and not caller_role and caller_id in identity_lookup:
                caller_role = identity_lookup[caller_id].get("role")

            is_known_authenticated = (ident_ctx not in ("UNAUTHENTICATED", "UNKNOWN") and bool(caller_role and caller_role != "UNKNOWN"))
            is_unauthenticated = (ident_ctx == "UNAUTHENTICATED" or (not has_auth and ident_ctx != "UNKNOWN"))
            is_unknown = (ident_ctx == "UNKNOWN" or (not is_known_authenticated and not is_unauthenticated))

            # Status code & body parsing
            status_code = fact.get("response_status") or fact.get("status_code")
            raw_body = fact.get("response_body") or fact.get("response_body_summary")

            if raw_body is not None:
                total_response_bodies += 1
                try:
                    parsed_body = json.loads(raw_body) if isinstance(raw_body, str) else raw_body
                    if isinstance(parsed_body, dict):
                        extracted_keys = set(parsed_body.keys())
                    elif isinstance(parsed_body, list) and len(parsed_body) > 0 and isinstance(parsed_body[0], dict):
                        extracted_keys = set(parsed_body[0].keys())
                    else:
                        extracted_keys = set()
                    parsed_ok = True
                except Exception:
                    extracted_keys = set()
                    parsed_ok = False
                    failed_response_bodies += 1
            else:
                parsed_body = None
                extracted_keys = set()
                parsed_ok = True

            # 1. Check Unauthenticated Access Success (Predicate 3)
            # Must have is_unauthenticated == True (State 2), NOT is_unknown (State 3)
            if is_unauthenticated and not is_unknown and status_code is not None:
                auth_required = fact.get("auth_required", True)
                if auth_required and status_code in (200, 201, 204, 206):
                    has_unauthenticated_success = True

            # Record for role-based comparisons if role is known (State 1)
            if is_known_authenticated and caller_role:
                observed_roles.add(caller_role)
                if status_code is not None:
                    status_by_role.setdefault(caller_role, set()).add(status_code)
                if raw_body is not None:
                    body_parse_success_by_role[caller_role] = parsed_ok
                    if parsed_ok:
                        json_keys_by_role.setdefault(caller_role, set()).update(extracted_keys)

                # 2. Check Privilege Level Delta (Predicate 1)
                owner_role = fact.get("resource_owner_role")
                owner_id = fact.get("resource_owner_id")
                if owner_id and not owner_role and owner_id in identity_lookup:
                    owner_role = identity_lookup[owner_id].get("role")

                caller_lvl = cls.get_role_level(caller_role)
                owner_lvl = cls.get_role_level(owner_role)
                if caller_lvl is not None and owner_lvl is not None:
                    if caller_lvl < owner_lvl and status_code in (200, 201, 204, 206):
                        has_privilege_level_delta = True

                # 3. Check Cross Identity Object Access Success (Predicate 5)
                # Anomaly condition: caller_id != owner_id, caller accesses owner's resource, returns 200/201/204/206
                if owner_id and caller_id and caller_id != owner_id:
                    # Verify ownership
                    owned_resources = fact.get("owner_resources")
                    if owned_resources is None and owner_id in identity_lookup:
                        owned_resources = identity_lookup[owner_id].get("owned_resources", [])
                    owned_resources = owned_resources or []

                    accessed_object = fact.get("target_object") or fact.get("object_id")
                    # If target_object is in owner's resources, or explicit cross-owner access flag
                    if accessed_object and accessed_object in owned_resources:
                        if status_code in (200, 201, 204, 206):
                            has_cross_identity_object_access_success = True

        # Check total response body integrity
        if total_response_bodies > 0 and failed_response_bodies == total_response_bodies:
            # All required response bodies are unparseable/corrupt
            raise CanonicalEvidenceIntegrityError("All required response bodies for endpoint are corrupt/unparseable.")

        # Check Asymmetric Response Corruption across observed roles
        # If one role's body parsed successfully and another role's body failed
        if any(body_parse_success_by_role.values()) and not all(body_parse_success_by_role.values()):
            has_evidence_parse_asymmetry = True

        # Multi-Role Existential Quantification over all observed role pairs
        # Evaluates existentially over all distinct pairs (R_i, R_j)
        roles_list = sorted(observed_roles)
        status_code_changed = False
        shape_delta_detected = False

        num_roles = len(roles_list)
        for i in range(num_roles):
            for j in range(i + 1, num_roles):
                r_i, r_j = roles_list[i], roles_list[j]

                # Status code delta
                s_i = status_by_role.get(r_i, set())
                s_j = status_by_role.get(r_j, set())
                if s_i and s_j and s_i != s_j:
                    status_code_changed = True

                # Shape delta (key symmetric difference on 200 responses)
                if r_i in json_keys_by_role and r_j in json_keys_by_role:
                    keys_i = json_keys_by_role[r_i]
                    keys_j = json_keys_by_role[r_j]
                    if keys_i.symmetric_difference(keys_j):
                        shape_delta_detected = True

        auth_header_delta = bool(auth_header_present and auth_header_absent)
        has_observed_contradictions = bool(primary_fact.get("contradiction_pairs") or primary_fact.get("has_contradictions"))

        # Collect parameter lineage
        parameter_lineage = primary_fact.get("parameters") or []

        return LosslessStructuralPack(
            schema_version="2.0.0",
            asset_id=asset_id,
            endpoint_id=endpoint_id,
            route_template=route_template,
            http_method=http_method,
            application_mutability=application_mutability,
            parameter_lineage=parameter_lineage,
            identity_matrix=identity_matrix,
            auth_header_delta=auth_header_delta,
            status_code_changed_under_different_role=status_code_changed,
            has_privilege_level_delta=has_privilege_level_delta,
            has_unauthenticated_success=has_unauthenticated_success,
            has_cross_role_response_shape_delta=shape_delta_detected,
            has_cross_identity_object_access_success=has_cross_identity_object_access_success,
            has_evidence_parse_asymmetry=has_evidence_parse_asymmetry,
            has_unseen_endpoint_parameter=has_unseen_param,
            has_numeric_path_identifier=has_numeric_path_id,
            has_observed_contradictions=has_observed_contradictions,
            observed_facts=raw_facts,
            raw_body_sample=primary_fact.get("raw_body_sample"),
            contradiction_pairs=primary_fact.get("contradiction_pairs"),
            interaction_lineage=interaction_lineage_dicts,
        )
