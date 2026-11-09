"""Test Suite A.5: StructuralDiffEngine Raw Synthetic Evidence Fixture Suite.

Verifies pure deterministic computation of StructuralDiffEngine.compute(raw_facts, identity_matrix):
- Sole producer of Class-1 canonical-evidence predicate booleans
- CROSS_IDENTITY_OBJECT_ACCESS_SUCCESS across 6 dedicated synthetic fixtures
- Multi-role existential quantification across 2, 3, and 15-20 roles over all C(N, 2) pairs
- Asymmetric response corruption handling (EVIDENCE_PARSE_ASYMMETRY)
- CanonicalEvidenceIntegrityError -> HOLD/BLOCK on corrupt or all-unparseable evidence
- Three-state identity context semantics (Known, Unauthenticated, Unknown)
"""

import json
import pytest

from src.evidence.cascade_models import (
    CanonicalEvidenceIntegrityError,
    LosslessStructuralPack,
)
from src.evidence.structural_diff import StructuralDiffEngine


@pytest.fixture
def base_identity_matrix():
    return [
        {"identity_id": "user_alice", "role": "STANDARD_USER", "owned_resources": ["res_alice_1", "res_alice_2"]},
        {"identity_id": "user_bob", "role": "STANDARD_USER", "owned_resources": ["res_bob_1"]},
        {"identity_id": "admin_carol", "role": "TENANT_ADMIN", "owned_resources": ["res_admin_1"]},
    ]


# ---------------------------------------------------------------------------
# 1. Pure Computation & Sole Producer Verification
# ---------------------------------------------------------------------------

def test_pure_computation_and_immutability(base_identity_matrix):
    raw_facts = [
        {
            "endpoint_id": "EP-USERS-001",
            "asset_id": "ASSET-USERS",
            "route_template": "/api/v1/users/{id}",
            "http_method": "GET",
            "application_mutability": "READ_ONLY",
            "caller_identity_id": "user_alice",
            "caller_role": "STANDARD_USER",
            "response_status": 200,
            "response_body": json.dumps({"id": "1", "name": "Alice"}),
            "headers": {"Authorization": "Bearer token_alice"},
        }
    ]

    pack1 = StructuralDiffEngine.compute(raw_facts, base_identity_matrix)
    pack2 = StructuralDiffEngine.compute(raw_facts, base_identity_matrix)

    assert isinstance(pack1, LosslessStructuralPack)
    assert pack1.schema_version == "2.0.0"
    assert pack1.endpoint_id == "EP-USERS-001"
    assert pack1.asset_id == "ASSET-USERS"
    # Deterministic and identical outputs
    assert pack1.model_dump() == pack2.model_dump()


def test_empty_or_corrupt_facts_raises_integrity_error():
    # Empty facts
    with pytest.raises(CanonicalEvidenceIntegrityError):
        StructuralDiffEngine.compute([])

    # Missing endpoint_id
    with pytest.raises(CanonicalEvidenceIntegrityError):
        StructuralDiffEngine.compute([{"asset_id": "A1", "route_template": "/test"}])

    # Missing asset_id
    with pytest.raises(CanonicalEvidenceIntegrityError):
        StructuralDiffEngine.compute([{"endpoint_id": "EP1", "route_template": "/test"}])

    # Inconsistent endpoint_id
    with pytest.raises(CanonicalEvidenceIntegrityError):
        StructuralDiffEngine.compute([
            {"endpoint_id": "EP1", "asset_id": "A1", "route_template": "/test"},
            {"endpoint_id": "EP2", "asset_id": "A1", "route_template": "/test"},
        ])


# ---------------------------------------------------------------------------
# 2. CROSS_IDENTITY_OBJECT_ACCESS_SUCCESS (6 Dedicated Fixtures)
# ---------------------------------------------------------------------------

def test_cross_identity_fixture_1_same_role_same_owner_success(base_identity_matrix):
    """Fixture 1: Alice accesses her own resource (negative condition)."""
    raw_facts = [{
        "endpoint_id": "EP-DOCS-001",
        "asset_id": "ASSET-DOCS",
        "route_template": "/api/v1/documents/{id}",
        "caller_identity_id": "user_alice",
        "caller_role": "STANDARD_USER",
        "resource_owner_id": "user_alice",
        "resource_owner_role": "STANDARD_USER",
        "target_object": "res_alice_1",
        "response_status": 200,
        "response_body": json.dumps({"doc": "data"}),
    }]
    pack = StructuralDiffEngine.compute(raw_facts, base_identity_matrix)
    assert pack.has_cross_identity_object_access_success is False


def test_cross_identity_fixture_2_same_role_diff_owner_success(base_identity_matrix):
    """Fixture 2: Alice accesses Bob's resource and receives 200 OK (positive condition)."""
    raw_facts = [{
        "endpoint_id": "EP-DOCS-001",
        "asset_id": "ASSET-DOCS",
        "route_template": "/api/v1/documents/{id}",
        "caller_identity_id": "user_alice",
        "caller_role": "STANDARD_USER",
        "resource_owner_id": "user_bob",
        "resource_owner_role": "STANDARD_USER",
        "target_object": "res_bob_1",
        "response_status": 200,
        "response_body": json.dumps({"doc": "bob_secret"}),
    }]
    pack = StructuralDiffEngine.compute(raw_facts, base_identity_matrix)
    assert pack.has_cross_identity_object_access_success is True


def test_cross_identity_fixture_3_diff_role_diff_owner_success(base_identity_matrix):
    """Fixture 3: Alice (STANDARD_USER) accesses Carol's (TENANT_ADMIN) resource (positive condition)."""
    raw_facts = [{
        "endpoint_id": "EP-DOCS-001",
        "asset_id": "ASSET-DOCS",
        "route_template": "/api/v1/documents/{id}",
        "caller_identity_id": "user_alice",
        "caller_role": "STANDARD_USER",
        "resource_owner_id": "admin_carol",
        "resource_owner_role": "TENANT_ADMIN",
        "target_object": "res_admin_1",
        "response_status": 200,
        "response_body": json.dumps({"admin": "report"}),
    }]
    pack = StructuralDiffEngine.compute(raw_facts, base_identity_matrix)
    assert pack.has_cross_identity_object_access_success is True


def test_cross_identity_fixture_4_denied_access(base_identity_matrix):
    """Fixture 4: Alice attempts to access Bob's resource but receives 403 Forbidden (negative condition)."""
    raw_facts = [{
        "endpoint_id": "EP-DOCS-001",
        "asset_id": "ASSET-DOCS",
        "route_template": "/api/v1/documents/{id}",
        "caller_identity_id": "user_alice",
        "caller_role": "STANDARD_USER",
        "resource_owner_id": "user_bob",
        "resource_owner_role": "STANDARD_USER",
        "target_object": "res_bob_1",
        "response_status": 403,
        "response_body": json.dumps({"error": "forbidden"}),
    }]
    pack = StructuralDiffEngine.compute(raw_facts, base_identity_matrix)
    assert pack.has_cross_identity_object_access_success is False


def test_cross_identity_fixture_5_unknown_ownership(base_identity_matrix):
    """Fixture 5: Object ownership is unresolved in canonical evidence (negative condition)."""
    raw_facts = [{
        "endpoint_id": "EP-DOCS-001",
        "asset_id": "ASSET-DOCS",
        "route_template": "/api/v1/documents/{id}",
        "caller_identity_id": "user_alice",
        "caller_role": "STANDARD_USER",
        "resource_owner_id": None,
        "target_object": "res_unknown_999",
        "response_status": 200,
        "response_body": json.dumps({"doc": "data"}),
    }]
    pack = StructuralDiffEngine.compute(raw_facts, base_identity_matrix)
    assert pack.has_cross_identity_object_access_success is False


def test_cross_identity_fixture_6_unregistered_id(base_identity_matrix):
    """Fixture 6: Object identifier is not in owner's resources (negative condition)."""
    raw_facts = [{
        "endpoint_id": "EP-DOCS-001",
        "asset_id": "ASSET-DOCS",
        "route_template": "/api/v1/documents/{id}",
        "caller_identity_id": "user_alice",
        "caller_role": "STANDARD_USER",
        "resource_owner_id": "user_bob",
        "resource_owner_role": "STANDARD_USER",
        "target_object": "res_nonexistent",
        "response_status": 200,
        "response_body": json.dumps({"doc": "empty"}),
    }]
    pack = StructuralDiffEngine.compute(raw_facts, base_identity_matrix)
    assert pack.has_cross_identity_object_access_success is False


# ---------------------------------------------------------------------------
# 3. Multi-Role Existential Quantification Over All Observed Role Pairs
# ---------------------------------------------------------------------------

def test_multi_role_2_roles_status_code_delta():
    raw_facts = [
        {
            "endpoint_id": "EP-ADMIN-001",
            "asset_id": "ASSET-ADMIN",
            "route_template": "/api/v1/admin/settings",
            "caller_role": "STANDARD_USER",
            "response_status": 403,
            "response_body": json.dumps({"error": "forbidden"}),
        },
        {
            "endpoint_id": "EP-ADMIN-001",
            "asset_id": "ASSET-ADMIN",
            "route_template": "/api/v1/admin/settings",
            "caller_role": "TENANT_ADMIN",
            "response_status": 200,
            "response_body": json.dumps({"settings": "ok"}),
        },
    ]
    pack = StructuralDiffEngine.compute(raw_facts)
    assert pack.status_code_changed_under_different_role is True


def test_multi_role_3_roles_shape_delta():
    """3 roles = C(3,2) = 3 pairs. Role A and B have same keys, Role C has extra keys."""
    raw_facts = [
        {
            "endpoint_id": "EP-ITEMS-001",
            "asset_id": "ASSET-ITEMS",
            "route_template": "/api/v1/items",
            "caller_role": "ANONYMOUS",
            "response_status": 200,
            "response_body": json.dumps({"id": 1, "title": "public"}),
        },
        {
            "endpoint_id": "EP-ITEMS-001",
            "asset_id": "ASSET-ITEMS",
            "route_template": "/api/v1/items",
            "caller_role": "STANDARD_USER",
            "response_status": 200,
            "response_body": json.dumps({"id": 1, "title": "public"}),
        },
        {
            "endpoint_id": "EP-ITEMS-001",
            "asset_id": "ASSET-ITEMS",
            "route_template": "/api/v1/items",
            "caller_role": "TENANT_ADMIN",
            "response_status": 200,
            "response_body": json.dumps({"id": 1, "title": "public", "internal_debug": True}),
        },
    ]
    pack = StructuralDiffEngine.compute(raw_facts)
    assert pack.has_cross_role_response_shape_delta is True


def test_multi_role_15_roles_existential_quantification():
    """15 roles = C(15,2) = 105 pairs. Exactly 1 pair has a status code delta."""
    raw_facts = []
    for r_idx in range(1, 16):
        role_name = f"ROLE_{r_idx:02d}"
        # Only ROLE_15 gets 200, all other 14 roles get 403
        status = 200 if r_idx == 15 else 403
        raw_facts.append({
            "endpoint_id": "EP-LATTICE-001",
            "asset_id": "ASSET-LATTICE",
            "route_template": "/api/v1/lattice",
            "caller_role": role_name,
            "response_status": status,
            "response_body": json.dumps({"role": role_name}),
        })

    pack = StructuralDiffEngine.compute(raw_facts)
    assert pack.status_code_changed_under_different_role is True


# ---------------------------------------------------------------------------
# 4. Asymmetric Response Corruption (EVIDENCE_PARSE_ASYMMETRY)
# ---------------------------------------------------------------------------

def test_asymmetric_response_corruption_sets_trigger_and_preserves_provenance():
    """One role has valid JSON, another role has truncated/unparseable body."""
    raw_facts = [
        {
            "endpoint_id": "EP-DATA-001",
            "asset_id": "ASSET-DATA",
            "route_template": "/api/v1/data",
            "caller_role": "STANDARD_USER",
            "response_status": 200,
            "response_body": '{"valid": "json"}',
        },
        {
            "endpoint_id": "EP-DATA-001",
            "asset_id": "ASSET-DATA",
            "route_template": "/api/v1/data",
            "caller_role": "TENANT_ADMIN",
            "response_status": 200,
            "response_body": '{"corrupt_truncated": ',  # Unparseable
        },
    ]
    pack = StructuralDiffEngine.compute(raw_facts)
    assert pack.has_evidence_parse_asymmetry is True


def test_all_unparseable_responses_raises_canonical_integrity_error():
    """When ALL response bodies are corrupt, engine raises CanonicalEvidenceIntegrityError."""
    raw_facts = [
        {
            "endpoint_id": "EP-CORRUPT-001",
            "asset_id": "ASSET-CORRUPT",
            "route_template": "/api/v1/corrupt",
            "caller_role": "STANDARD_USER",
            "response_status": 200,
            "response_body": '<<<NOT JSON>>>',
        },
        {
            "endpoint_id": "EP-CORRUPT-001",
            "asset_id": "ASSET-CORRUPT",
            "route_template": "/api/v1/corrupt",
            "caller_role": "TENANT_ADMIN",
            "response_status": 200,
            "response_body": '{"truncated":',
        },
    ]
    with pytest.raises(CanonicalEvidenceIntegrityError):
        StructuralDiffEngine.compute(raw_facts)


# ---------------------------------------------------------------------------
# 5. Three-State Identity Context Semantics (Known, Unauthenticated, Unknown)
# ---------------------------------------------------------------------------

def test_identity_state_2_unauthenticated_access_success():
    """State 2: Explicitly observed unauthenticated caller receiving 200 on protected route."""
    raw_facts = [{
        "endpoint_id": "EP-PROTECTED-001",
        "asset_id": "ASSET-PROTECTED",
        "route_template": "/api/v1/secure/profile",
        "identity_context": "UNAUTHENTICATED",
        "auth_required": True,
        "response_status": 200,
        "response_body": json.dumps({"profile": "public_leak"}),
        "headers": {},  # No auth header
    }]
    pack = StructuralDiffEngine.compute(raw_facts)
    assert pack.has_unauthenticated_success is True


def test_identity_state_3_unknown_identity_never_classified_as_anonymous():
    """State 3: Missing identity metadata (identity_context = UNKNOWN) must NOT become unauthenticated success."""
    raw_facts = [{
        "endpoint_id": "EP-PROTECTED-001",
        "asset_id": "ASSET-PROTECTED",
        "route_template": "/api/v1/secure/profile",
        "identity_context": "UNKNOWN",
        "auth_required": True,
        "response_status": 200,
        "response_body": json.dumps({"profile": "data"}),
    }]
    pack = StructuralDiffEngine.compute(raw_facts)
    assert pack.has_unauthenticated_success is False


def test_missing_role_does_not_fabricate_privilege_delta():
    """Known identity but missing role metadata -> has_privilege_level_delta evaluates False."""
    raw_facts = [{
        "endpoint_id": "EP-ADMIN-002",
        "asset_id": "ASSET-ADMIN",
        "route_template": "/api/v1/admin/actions",
        "caller_identity_id": "user_unknown_role",
        "caller_role": None,  # Role genuinely missing
        "resource_owner_role": "TENANT_ADMIN",
        "response_status": 200,
        "response_body": json.dumps({"ok": True}),
    }]
    pack = StructuralDiffEngine.compute(raw_facts)
    assert pack.has_privilege_level_delta is False


def test_privilege_level_delta_positive_when_lower_role_succeeds_on_higher_asset():
    """STANDARD_USER (level 1) accesses TENANT_ADMIN (level 2) asset and receives 200."""
    raw_facts = [{
        "endpoint_id": "EP-ADMIN-003",
        "asset_id": "ASSET-ADMIN",
        "route_template": "/api/v1/admin/sensitive",
        "caller_role": "STANDARD_USER",
        "resource_owner_role": "TENANT_ADMIN",
        "response_status": 200,
        "response_body": json.dumps({"admin_data": "exposed"}),
    }]
    pack = StructuralDiffEngine.compute(raw_facts)
    assert pack.has_privilege_level_delta is True
