"""Unit tests for M6 Asset Graph and Telemetry Normalization Pipeline."""

import json
from src.assessment.models import (
    AssetType,
    AssessmentScopeStatus,
    AttackSurfaceState,
    ObservationType,
)
from src.assessment.assets import AssetGraph
from src.scope.gate import ScopeGate
from src.scope.models import ScopePolicy
from src.telemetry.normalizer import TelemetryIngestionPipeline
from src.telemetry.parsers import (
    HARParser,
    BurpCaidoParser,
    RawHTTPParser,
    DNSTLSParser,
    SecurityToolParser,
    MobileArtifactParser,
)


def test_asset_graph_hierarchy_and_lineage():
    """Verify multi-tier asset hierarchy and lineage DAG traversal."""
    graph = AssetGraph("ASM-TEST-01")

    root = graph.add_asset(AssetType.DOMAIN, "target.corp", scope_status=AssessmentScopeStatus.IN_SCOPE)
    sub = graph.add_asset(AssetType.SUBDOMAIN, "api.target.corp", parent_asset_id=root.asset_id, scope_status=AssessmentScopeStatus.IN_SCOPE)
    ip = graph.add_asset(AssetType.IP, "93.184.216.34", parent_asset_id=sub.asset_id, scope_status=AssessmentScopeStatus.IN_SCOPE)
    svc = graph.add_asset(AssetType.SERVICE, "93.184.216.34:443", parent_asset_id=ip.asset_id, scope_status=AssessmentScopeStatus.IN_SCOPE)
    ep = graph.add_asset(AssetType.ENDPOINT, "/api/v1/auth/token", parent_asset_id=svc.asset_id, scope_status=AssessmentScopeStatus.IN_SCOPE)

    # Lineage from endpoint up to domain root
    lineage = graph.get_lineage(ep.asset_id)
    lineage_types = [a.asset_type for a in lineage]
    assert AssetType.ENDPOINT in lineage_types
    assert AssetType.DOMAIN in lineage_types

    # Hierarchy navigation
    children = graph.get_children(root.asset_id)
    assert len(children) == 1
    assert children[0].canonical_identifier == "api.target.corp"

    # Invariant: discovery != vulnerability
    for a in graph.get_all_assets():
        assert a.attack_surface_state in (AttackSurfaceState.OBSERVED, AttackSurfaceState.UNKNOWN)


def test_har_and_burp_telemetry_normalization():
    """Verify HAR and Burp exports pass through normalizer and receive scope tags."""
    gate = ScopeGate(
        policy=ScopePolicy(
            program_name="Test",
            platform="LOCAL",
            in_scope=["api.target.com"],
            out_of_scope=["forbidden.target.com"],
        ),
        allow_private_ranges=True,
    )
    graph = AssetGraph("ASM-TEL-01")
    pipeline = TelemetryIngestionPipeline(scope_gate=gate, asset_graph=graph)

    # Ingest HAR
    har_sample = {
        "log": {"entries": [
            {
                "request": {
                    "url": "https://api.target.com/users/list",
                    "method": "GET",
                    "headers": [{"name": "Authorization", "value": "Bearer testtoken"}],
                },
                "response": {"status": 200, "headers": []},
            },
            {
                "request": {
                    "url": "https://forbidden.target.com/admin",
                    "method": "GET",
                    "headers": [],
                },
                "response": {"status": 403, "headers": []},
            },
        ]}
    }
    report = pipeline.ingest("ASM-TEL-01", "har", har_sample)
    assert report["valid_observations"] == 2
    assert report["in_scope_count"] == 1
    assert report["out_of_scope_count"] == 1

    # Verify observations in evidence store
    obs = pipeline.get_observations()
    assert len(obs) == 2
    in_scope_obs = [o for o in obs if o.scope_decision == AssessmentScopeStatus.IN_SCOPE]
    assert len(in_scope_obs) == 1
    assert in_scope_obs[0].observation_type == ObservationType.HTTP_RESPONSE


def test_tool_parsers_nmap_and_httpx():
    """Verify nmap and httpx output formats parse accurately."""
    httpx_sample = [
        {"host": "api.target.com", "url": "https://api.target.com", "status_code": 200, "title": "API Gateway", "tech": ["Nginx", "Python"]}
    ]
    recs = SecurityToolParser.parse("httpx", httpx_sample)
    assert len(recs) == 1
    assert recs[0]["target_identifier"] == "api.target.com"
    assert "Nginx" in recs[0]["technologies"]

    nmap_sample = [
        {"host": "192.168.1.1", "ports": [22, 80, 443]}
    ]
    n_recs = SecurityToolParser.parse("nmap", nmap_sample)
    assert len(n_recs) == 1
    assert n_recs[0]["ports"] == [22, 80, 443]


def test_mobile_artifact_parser():
    """Verify Android APK manifest metadata parsing."""
    manifest = {
        "package_name": "com.target.customerapp",
        "exported_components": [".MainActivity", ".SyncService"],
        "permissions": ["android.permission.INTERNET"],
    }
    rec = MobileArtifactParser.parse_manifest(manifest)
    assert rec is not None
    assert rec["target_identifier"] == "com.target.customerapp"
    assert len(rec["exported_components"]) == 2
