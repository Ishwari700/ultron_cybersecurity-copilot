"""Unit tests for Multi-Target Assessment Graph and Cross-Asset Scope Preservation.

Verifies:
- INV-SEC-02 / INV-M8-02: Relationships between assets do NOT expand authorization scope.
- Cross-asset relationships (Android App -> API -> Backend) retain provenance.
- Independent scope evaluation for each related asset.
"""

import pytest

from src.assessment.assets import (
    AssetGraph,
    AssetRelationshipType,
    AssessmentAssetGraph,
)
from src.assessment.models import AssetType, AssessmentScopeStatus
from src.scope.gate import ScopeGate
from src.scope.models import ScopePolicy


def test_cross_asset_relationships_do_not_expand_scope():
    """
    INV-M8-02: If Asset A is IN_SCOPE and Asset A CALLS Asset B,
    Asset B must still evaluate strictly against ScopeGate and cannot inherit scope.
    """
    graph = AssessmentAssetGraph("ASM-MULTI-01")

    # Scope policy only authorizes targetcorp.com domains
    gate = ScopeGate(
        policy=ScopePolicy(
            program_name="TargetCorp Multi-Asset",
            platform="HackerOne",
            in_scope=["api.targetcorp.com", "com.targetcorp.app"],
            out_of_scope=["thirdparty-analytics.com", "partner-api.com"],
        ),
        allow_private_ranges=True,
    )

    # 1. Add Asset A (Android App - In Scope)
    app_asset = graph.add_asset(
        asset_type=AssetType.ANDROID_APP,
        canonical_identifier="com.targetcorp.app",
        scope_status=AssessmentScopeStatus.IN_SCOPE,
    )

    # 2. Add Asset B (Internal API - In Scope)
    api_asset = graph.add_asset(
        asset_type=AssetType.API,
        canonical_identifier="api.targetcorp.com",
        scope_status=AssessmentScopeStatus.IN_SCOPE,
    )

    # 3. Add Asset C (Third Party Analytics API - Out of Scope)
    thirdparty_asset = graph.add_asset(
        asset_type=AssetType.THIRD_PARTY_DEPENDENCY,
        canonical_identifier="thirdparty-analytics.com",
        scope_status=AssessmentScopeStatus.OUT_OF_SCOPE,
    )

    # 4. Link relationships: App CALLS API, and App EMBEDS third party
    rel1 = graph.add_relationship(
        source_asset_id=app_asset.asset_id,
        target_asset_id=api_asset.asset_id,
        relationship_type=AssetRelationshipType.COMMUNICATES_WITH,
    )
    rel2 = graph.add_relationship(
        source_asset_id=app_asset.asset_id,
        target_asset_id=thirdparty_asset.asset_id,
        relationship_type=AssetRelationshipType.EMBEDS,
    )

    assert len(graph.get_relationships()) == 2

    # 5. Verify independent scope evaluation:
    # app_asset is IN_SCOPE
    assert graph.evaluate_asset_scope_independent(app_asset.asset_id, gate) == AssessmentScopeStatus.IN_SCOPE
    # api_asset is IN_SCOPE
    assert graph.evaluate_asset_scope_independent(api_asset.asset_id, gate) == AssessmentScopeStatus.IN_SCOPE
    # thirdparty_asset is OUT_OF_SCOPE despite being embedded in in-scope app!
    assert graph.evaluate_asset_scope_independent(thirdparty_asset.asset_id, gate) == AssessmentScopeStatus.OUT_OF_SCOPE


def test_asset_graph_export_includes_relationships():
    graph = AssetGraph("ASM-EXPORT-01")

    a1 = graph.add_asset(AssetType.DOMAIN, "targetcorp.com")
    a2 = graph.add_asset(AssetType.SUBDOMAIN, "auth.targetcorp.com", parent_asset_id=a1.asset_id)
    a3 = graph.add_asset(AssetType.SERVICE, "auth.targetcorp.com:443")

    graph.add_relationship(a2.asset_id, a3.asset_id, AssetRelationshipType.SERVES)

    exported = graph.export_graph()
    assert exported["assessment_id"] == "ASM-EXPORT-01"
    assert exported["total_assets"] == 3
    assert len(exported["edges"]) >= 2  # CONTAINS + SERVES
