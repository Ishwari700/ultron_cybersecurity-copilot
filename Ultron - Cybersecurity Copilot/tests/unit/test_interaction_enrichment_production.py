"""Production Unit Tests for Interaction Evidence Enrichment (Milestone M2, Phase 11.6).

Tests coverage across:
1. Basic enrichment
2. Fact preservation (BASE_FACTS ⊆ ENRICHED_FACTS)
3. DAG parent dependency enforcement
4. Suppression when required parent evidence is missing
5. Authenticated cross-identity access derivation
6. Cross-tenant derivation
7. Privilege delta derivation
8. Authorization delta derivation
9. Anonymous caller semantics
10. SYSTEM resource semantics
11. PUBLIC resource semantics
12. Secret-redaction compatibility
13. No benchmark-ground-truth leakage
14. StructuralDiffEngine integration with interaction_traces
15. StructuralDiffEngine behavior unchanged when interaction_traces=None

Explicit regression:
anonymous caller + public SYSTEM/PUBLIC resource MUST NOT generate cross_identity_access=True.
"""

import json
import pytest
from typing import Any, Dict, List

from src.evidence.cascade_models import LosslessStructuralPack
from src.evidence.interaction_enrichment import (
    FORBIDDEN_GT_KEYS,
    InteractionEvidenceEnricher,
)
from src.evidence.structural_diff import StructuralDiffEngine
from src.evidence.vault import RedactionVault


@pytest.fixture
def sample_canonical_facts() -> List[Dict[str, Any]]:
    return [
        {
            "fact_id": "FACT-OPENAPI-01",
            "endpoint_id": "EP-INVOICES-01",
            "asset_id": "ASSET-BILLING",
            "route_template": "/api/v1/invoices/{id}",
            "http_method": "GET",
            "application_mutability": "READ_ONLY",
            "parameters": [
                {"param_name": "id", "param_id": "PARAM-ID-01", "location": "path"}
            ],
            "statement": "OpenAPI endpoint specification for invoice retrieval",
        }
    ]


@pytest.fixture
def sample_identity_matrix() -> List[Dict[str, Any]]:
    return [
        {
            "identity_id": "user_alice",
            "role": "STANDARD_USER",
            "owned_resources": ["inv_alice_01"],
        },
        {
            "identity_id": "user_bob",
            "role": "STANDARD_USER",
            "owned_resources": ["inv_bob_02"],
        },
    ]


# ---------------------------------------------------------------------------
# Test 1: Basic Enrichment
# ---------------------------------------------------------------------------
def test_basic_enrichment(sample_canonical_facts, sample_identity_matrix):
    trace = {
        "interaction_id": "INT-01",
        "method": "GET",
        "route": "/api/v1/invoices/inv_alice_01",
        "requester_identity": "user_alice",
        "requester_role": "STANDARD_USER",
        "requester_tenant": "tenant_1",
        "observed_resource": "inv_alice_01",
        "observed_owner": "user_alice",
        "observed_tenant": "tenant_1",
        "response_status": 200,
        "response_body": {"invoice_id": "inv_alice_01", "amount": 100},
    }

    enriched_facts, enriched_identities, lineages = InteractionEvidenceEnricher.enrich(
        raw_facts=sample_canonical_facts,
        interaction_traces=[trace],
        identity_matrix=sample_identity_matrix,
    )

    assert len(enriched_facts) == len(sample_canonical_facts) + 2
    assert len(lineages) == 1
    lin = lineages[0]
    assert lin.interaction_id == "INT-01"
    assert "FACT-OBSERVED-INTERACTION-01" in lin.added_fact_ids
    assert "FACT-DERIVED-RELATION-01" in lin.added_fact_ids
    assert lin.fields["access_success"]["value"] is True
    assert lin.fields["cross_identity_access"]["value"] is False


# ---------------------------------------------------------------------------
# Test 2: Fact Preservation (BASE_FACTS ⊆ ENRICHED_FACTS)
# ---------------------------------------------------------------------------
def test_fact_preservation(sample_canonical_facts, sample_identity_matrix):
    trace = {
        "interaction_id": "INT-01",
        "method": "GET",
        "route": "/api/v1/invoices/inv_bob_02",
        "requester_identity": "user_alice",
        "observed_resource": "inv_bob_02",
        "observed_owner": "user_bob",
        "response_status": 200,
    }

    enriched_facts, _, _ = InteractionEvidenceEnricher.enrich(
        raw_facts=sample_canonical_facts,
        interaction_traces=[trace],
        identity_matrix=sample_identity_matrix,
    )

    # Base facts preserved in exact prefix sequence and content
    for idx, base_f in enumerate(sample_canonical_facts):
        assert enriched_facts[idx] == base_f
    assert len(enriched_facts) == len(sample_canonical_facts) + 2


# ---------------------------------------------------------------------------
# Test 3 & 4: DAG Parent Dependency Enforcement & Missing Parent Suppression
# ---------------------------------------------------------------------------
def test_dag_dependency_enforcement_and_suppression(sample_canonical_facts):
    # Trace with missing status_code -> access_success cannot be computed
    trace_no_status = {
        "interaction_id": "INT-01",
        "method": "GET",
        "route": "/api/v1/invoices/inv_01",
        "requester_identity": "user_alice",
        "observed_resource": "inv_01",
        "observed_owner": "user_bob",
        "response_status": None,  # Missing parent
    }

    _, _, lineages = InteractionEvidenceEnricher.enrich(
        raw_facts=sample_canonical_facts,
        interaction_traces=[trace_no_status],
    )

    lin = lineages[0]
    assert lin.fields.get("access_success") is None
    assert lin.fields.get("cross_identity_access") is None
    suppressed_targets = [s["target"] for s in lin.suppressed_derivations]
    assert "access_success" in suppressed_targets
    assert "cross_identity_access" in suppressed_targets


# ---------------------------------------------------------------------------
# Test 5: Authenticated Cross-Identity Access Derivation
# ---------------------------------------------------------------------------
def test_authenticated_cross_identity_access_derivation(sample_canonical_facts, sample_identity_matrix):
    trace = {
        "interaction_id": "INT-01",
        "method": "GET",
        "route": "/api/v1/invoices/inv_bob_02",
        "requester_identity": "user_alice",
        "requester_role": "STANDARD_USER",
        "requester_tenant": "tenant_1",
        "observed_resource": "inv_bob_02",
        "observed_owner": "user_bob",
        "observed_tenant": "tenant_1",
        "response_status": 200,
        "response_body": {"secret_data": "bob_confidential"},
    }

    enriched_facts, _, lineages = InteractionEvidenceEnricher.enrich(
        raw_facts=sample_canonical_facts,
        interaction_traces=[trace],
        identity_matrix=sample_identity_matrix,
    )

    lin = lineages[0]
    assert lin.fields["access_success"]["value"] is True
    assert lin.fields["cross_identity_access"]["value"] is True
    assert lin.fields["cross_tenant_access"]["value"] is False

    # Check derived statement in fact
    der_fact = next(f for f in enriched_facts if f["fact_id"] == "FACT-DERIVED-RELATION-01")
    assert "cross_identity_access=true" in der_fact["statement"]
    assert "user_alice" in der_fact["statement"]
    assert "user_bob" in der_fact["statement"]


# ---------------------------------------------------------------------------
# Test 6: Cross-Tenant Derivation
# ---------------------------------------------------------------------------
def test_cross_tenant_derivation(sample_canonical_facts, sample_identity_matrix):
    trace = {
        "interaction_id": "INT-01",
        "method": "GET",
        "route": "/api/v1/invoices/inv_bob_02",
        "requester_identity": "user_alice",
        "requester_role": "STANDARD_USER",
        "requester_tenant": "tenant_alpha",
        "observed_resource": "inv_bob_02",
        "observed_owner": "user_bob",
        "observed_tenant": "tenant_beta",
        "response_status": 200,
    }

    _, _, lineages = InteractionEvidenceEnricher.enrich(
        raw_facts=sample_canonical_facts,
        interaction_traces=[trace],
        identity_matrix=sample_identity_matrix,
    )

    lin = lineages[0]
    assert lin.fields["access_success"]["value"] is True
    assert lin.fields["cross_identity_access"]["value"] is True
    assert lin.fields["cross_tenant_access"]["value"] is True


# ---------------------------------------------------------------------------
# Test 7: Privilege Delta Derivation
# ---------------------------------------------------------------------------
def test_privilege_delta_derivation(sample_canonical_facts):
    trace = {
        "interaction_id": "INT-01",
        "method": "POST",
        "route": "/api/v1/admin/users/roles",
        "requester_identity": "user_alice",
        "requester_role": "customer",
        "required_role": "admin",
        "response_status": 200,
    }

    _, _, lineages = InteractionEvidenceEnricher.enrich(
        raw_facts=sample_canonical_facts,
        interaction_traces=[trace],
    )

    lin = lineages[0]
    assert lin.fields["privilege_delta"]["value"] is True


# ---------------------------------------------------------------------------
# Test 8: Authorization Delta Derivation
# ---------------------------------------------------------------------------
def test_authorization_delta_derivation(sample_canonical_facts, sample_identity_matrix):
    trace_with_delta = {
        "interaction_id": "INT-01",
        "method": "GET",
        "route": "/api/v1/invoices/inv_bob_02",
        "requester_identity": "user_alice",
        "requester_role": "STANDARD_USER",
        "observed_resource": "inv_bob_02",
        "observed_owner": "user_bob",
        "response_status": 200,
    }

    _, _, lineages = InteractionEvidenceEnricher.enrich(
        raw_facts=sample_canonical_facts,
        interaction_traces=[trace_with_delta],
        identity_matrix=sample_identity_matrix,
    )

    assert lineages[0].fields["authorization_delta"]["value"] is True


# ---------------------------------------------------------------------------
# Test 9, 10, 11: Anonymous Caller & SYSTEM / PUBLIC Resource Semantics
# EXPLICIT REGRESSION TEST: SCEN-IOT_FLEET_MGMT-NEG-01
# ---------------------------------------------------------------------------
def test_anonymous_caller_and_system_public_resource_semantics(sample_canonical_facts):
    """
    CRITICAL REGRESSION TEST:
    Anonymous caller accessing a public SYSTEM or PUBLIC resource must NEVER
    generate cross_identity_access=True.
    """
    trace_iot_neg_01 = {
        "interaction_id": "INT-01",
        "method": "GET",
        "route": "/catalog",
        "requester_identity": "anonymous",
        "requester_role": "unauthenticated",
        "requester_tenant": "public",
        "observed_resource": "PUBLIC_CATALOG",
        "observed_owner": "SYSTEM",
        "observed_tenant": "PUBLIC",
        "response_status": 200,
        "response_body": {"public_catalog": [{"accessible": True, "item": "standard"}]},
    }

    enriched_facts, _, lineages = InteractionEvidenceEnricher.enrich(
        raw_facts=sample_canonical_facts,
        interaction_traces=[trace_iot_neg_01],
    )

    lin = lineages[0]
    assert lin.fields["access_success"]["value"] is True
    # MUST BE FALSE - NOT A BOUNDARY VIOLATION
    assert lin.fields["cross_identity_access"]["value"] is False
    assert lin.fields["cross_tenant_access"]["value"] is False

    der_fact = next(f for f in enriched_facts if f["fact_id"] == "FACT-DERIVED-RELATION-01")
    assert "cross_identity_access=false" in der_fact["statement"]
    assert "cross_identity_access=true" not in der_fact["statement"]


def test_public_identity_semantics(sample_canonical_facts):
    for pub_ident in ["PUBLIC", "ANONYMOUS", "UNAUTHENTICATED", "GUEST", "NONE"]:
        trace = {
            "interaction_id": "INT-01",
            "method": "GET",
            "route": "/public/data",
            "requester_identity": pub_ident,
            "requester_role": "unauthenticated",
            "observed_resource": "DOC-PUB-01",
            "observed_owner": "SYSTEM",
            "response_status": 200,
        }
        _, _, lineages = InteractionEvidenceEnricher.enrich(
            raw_facts=sample_canonical_facts,
            interaction_traces=[trace],
        )
        assert lineages[0].fields["cross_identity_access"]["value"] is False


# ---------------------------------------------------------------------------
# Test 12: Secret-Redaction Compatibility
# ---------------------------------------------------------------------------
def test_secret_redaction_compatibility(sample_canonical_facts):
    raw_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    raw_secret_key = "SECRET_API_KEY_SUPER_CONFIDENTIAL_123456"

    trace = {
        "interaction_id": "INT-01",
        "method": "GET",
        "route": "/api/v1/invoices",
        "requester_identity": "user_alice",
        "requester_role": "STANDARD_USER",
        "request_headers": {
            "Authorization": f"Bearer {raw_jwt}",
            "X-Api-Key": raw_secret_key,
        },
        "response_status": 200,
        "response_body": {
            "token": raw_jwt,
            "secret": raw_secret_key,
        },
    }

    vault = RedactionVault()
    enriched_facts, _, lineages = InteractionEvidenceEnricher.enrich(
        raw_facts=sample_canonical_facts,
        interaction_traces=[trace],
        vault=vault,
    )

    # Convert entire fact and lineage payloads to string and ensure raw secrets never leak
    serialized_facts = json.dumps(enriched_facts)
    serialized_lineage = json.dumps([l.model_dump() for l in lineages])

    assert raw_jwt not in serialized_facts
    assert raw_secret_key not in serialized_facts
    assert raw_jwt not in serialized_lineage
    assert raw_secret_key not in serialized_lineage


# ---------------------------------------------------------------------------
# Test 13: No Benchmark Ground-Truth Leakage Rejection
# ---------------------------------------------------------------------------
def test_no_ground_truth_leakage_rejection(sample_canonical_facts):
    for forbidden_key in FORBIDDEN_GT_KEYS:
        leaky_trace = {
            "interaction_id": "INT-01",
            "method": "GET",
            "route": "/api/v1/invoices",
            forbidden_key: "leaked_evaluator_value",
        }
        with pytest.raises(AssertionError, match="GROUND-TRUTH LEAKAGE DETECTED"):
            InteractionEvidenceEnricher.enrich(
                raw_facts=sample_canonical_facts,
                interaction_traces=[leaky_trace],
            )


# ---------------------------------------------------------------------------
# Test 14: StructuralDiffEngine Integration with interaction_traces
# ---------------------------------------------------------------------------
def test_structural_diff_engine_integration_with_traces(sample_canonical_facts, sample_identity_matrix):
    vuln_trace = {
        "interaction_id": "INT-01",
        "method": "GET",
        "route": "/api/v1/invoices/inv_bob_02",
        "requester_identity": "user_alice",
        "requester_role": "STANDARD_USER",
        "observed_resource": "inv_bob_02",
        "observed_owner": "user_bob",
        "response_status": 200,
        "response_body": {"invoice_id": "inv_bob_02", "amount": 500},
    }

    pack: LosslessStructuralPack = StructuralDiffEngine.compute(
        raw_facts=sample_canonical_facts,
        identity_matrix=sample_identity_matrix,
        interaction_traces=[vuln_trace],
    )

    # Pack must have schema_version 2.0.0
    assert pack.schema_version == "2.0.0"
    # StructuralDiffEngine must have detected cross-identity object access
    assert pack.has_cross_identity_object_access_success is True
    # Interaction lineage must be populated
    assert pack.interaction_lineage is not None
    assert len(pack.interaction_lineage) == 1
    assert pack.interaction_lineage[0]["interaction_id"] == "INT-01"
    # Enriched facts are present in pack.observed_facts
    assert len(pack.observed_facts) == len(sample_canonical_facts) + 2


# ---------------------------------------------------------------------------
# Test 15: StructuralDiffEngine Behavior Unchanged When interaction_traces=None
# ---------------------------------------------------------------------------
def test_structural_diff_engine_unchanged_when_traces_none(sample_canonical_facts, sample_identity_matrix):
    pack: LosslessStructuralPack = StructuralDiffEngine.compute(
        raw_facts=sample_canonical_facts,
        identity_matrix=sample_identity_matrix,
        interaction_traces=None,
    )

    assert pack.schema_version == "2.0.0"
    assert pack.has_cross_identity_object_access_success is False
    assert pack.interaction_lineage is None
    assert len(pack.observed_facts) == len(sample_canonical_facts)
    assert pack.observed_facts == sample_canonical_facts
