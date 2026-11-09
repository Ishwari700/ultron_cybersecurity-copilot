"""Integration tests for M12 Security Research Memory and Knowledge Management Pipeline.
Verifies REST API endpoints, service layer, admission pipeline,
multi-tenant / assessment isolation, episodic adapters, and memory governance.
"""

from pathlib import Path
import pytest
from starlette.testclient import TestClient

from src.dashboard.app import create_dashboard_app
from src.database.manager import DatabaseManager
from src.memory.adapters import EpisodicMemoryAdapters
from src.memory.enums import EpistemicStatus, MemoryAuthority, MemoryNamespace, PromotionStatus


@pytest.fixture
def app_client(tmp_path: Path):
    db_file = tmp_path / "test_m12_pipeline.db"
    db = DatabaseManager(db_path=db_file)
    db.initialize_schema()

    with db.get_connection() as conn:
        conn.execute(
            """
            INSERT INTO investigations (investigation_id, name, target_host, scope_status, status)
            VALUES 
                ('INV-ALPHA', 'Assessment Alpha', 'alpha.corp.local', 'ALLOWED', 'ACTIVE'),
                ('INV-BETA', 'Assessment Beta', 'beta.corp.local', 'ALLOWED', 'ACTIVE')
            """
        )
        conn.commit()

    from src.dashboard.auth import DashboardAuthManager, DashboardRole
    auth_mgr = DashboardAuthManager(db_manager=db)
    sess = auth_mgr.create_session("memory_tester", DashboardRole.ADMIN)
    app = create_dashboard_app(db_manager=db, auth_manager=auth_mgr)
    client = TestClient(app, headers={"Authorization": f"Bearer {sess.token}"})
    return client, db


def test_api_admit_and_search_memory_item(app_client):
    """Verify admitting a valid memory item and searching via REST API."""
    client, _ = app_client

    payload = {
        "namespace": "USER_RESEARCH",
        "content": "Graphql query complexity limits prevent denial of service through nested queries.",
        "title": "GraphQL Query Depth Defense",
        "summary": "Tested depth-limit validation on enterprise GraphQL API.",
        "epistemic_status": "FACT",
        "authority_level": "USER_PROVIDED",
        "source_type": "RESEARCH_PROCEDURE",
        "assessment_id": None,
        "provenance_references": ["researcher_notes:graphql_v1"],
    }

    res = client.post("/api/memory/items", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "memory_id" in data
    memory_id = data["memory_id"]
    assert memory_id.startswith("MEM-")

    # Search for it
    search_payload = {
        "query": "GraphQL query complexity limits",
        "top_k": 5,
    }
    sres = client.post("/api/memory/search", json=search_payload)
    assert sres.status_code == 200
    sdata = sres.json()
    assert sdata["total_found"] >= 1
    found = [item for item in sdata["items"] if item["memory"]["memory_id"] == memory_id]
    assert len(found) == 1
    assert found[0]["memory"]["namespace"] == "USER_RESEARCH"
    assert found[0]["memory"]["epistemic_status"] == "FACT"


def test_api_reject_unredactable_secret_persistence(app_client):
    """Verify that unredactable secrets are rejected with 400 Bad Request."""
    client, _ = app_client

    payload = {
        "namespace": "USER_RESEARCH",
        "content": "CRITICAL CREDENTIAL: AKIAIOSFODNN7EXAMPLE SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "title": "AWS Leaked Credential",
        "epistemic_status": "OBSERVATION",
        "authority_level": "USER_PROVIDED",
        "source_type": "RESEARCH_PROCEDURE",
    }

    res = client.post("/api/memory/items", json=payload)
    assert res.status_code == 400
    detail = res.json()["detail"].lower()
    assert "credential" in detail or "secret" in detail or "unredactable" in detail or "forbidden" in detail


def test_api_assessment_strict_isolation_leakage_prevented(app_client):
    """
    Verify invariant M12-01: Assessment A cannot retrieve private memory from Assessment B.
    Pre-ranking isolation test via REST API.
    """
    client, _ = app_client

    # Item in Assessment Alpha
    item_alpha = {
        "namespace": "ASSESSMENT_LOCAL",
        "assessment_id": "INV-ALPHA",
        "content": "Internal staging host found at staging.alpha.corp.local on port 8443.",
        "title": "Alpha Staging Host",
        "epistemic_status": "OBSERVATION",
        "authority_level": "CANONICAL_OBSERVATION",
        "source_type": "ANALYST_NOTE",
        "provenance_references": ["nmap:alpha_port_scan"],
        "evidence_references": ["artifact:scan_alpha"],
    }
    res_a = client.post("/api/memory/items", json=item_alpha)
    assert res_a.status_code == 200, res_a.text
    alpha_mem_id = res_a.json()["memory_id"]

    # Item in Assessment Beta
    item_beta = {
        "namespace": "ASSESSMENT_LOCAL",
        "assessment_id": "INV-BETA",
        "content": "Staging host configuration found at internal.beta.corp.local on port 9443.",
        "title": "Beta Staging Host",
        "epistemic_status": "OBSERVATION",
        "authority_level": "CANONICAL_OBSERVATION",
        "source_type": "ANALYST_NOTE",
        "provenance_references": ["nmap:beta_port_scan"],
        "evidence_references": ["artifact:scan_beta"],
    }
    res_b = client.post("/api/memory/items", json=item_beta)
    assert res_b.status_code == 200
    beta_mem_id = res_b.json()["memory_id"]

    # Query Assessment Alpha endpoint
    search_a = client.post(
        "/api/assessments/INV-ALPHA/memory/search",
        json={"query": "staging host internal", "top_k": 5},
    )
    assert search_a.status_code == 200
    hits_a = search_a.json()["items"]
    mem_ids_in_a = [h["memory"]["memory_id"] for h in hits_a]
    assert alpha_mem_id in mem_ids_in_a
    assert beta_mem_id not in mem_ids_in_a, "LEAKAGE: Beta assessment memory retrieved in Alpha context!"

    # Query Assessment Beta endpoint
    search_b = client.post(
        "/api/assessments/INV-BETA/memory/search",
        json={"query": "staging host internal", "top_k": 5},
    )
    assert search_b.status_code == 200
    hits_b = search_b.json()["items"]
    mem_ids_in_b = [h["memory"]["memory_id"] for h in hits_b]
    assert beta_mem_id in mem_ids_in_b
    assert alpha_mem_id not in mem_ids_in_b, "LEAKAGE: Alpha assessment memory retrieved in Beta context!"


def test_api_memory_promotion_governance(app_client):
    """Verify promotion of candidate memory to shared research or verified pattern."""
    client, _ = app_client

    # Create candidate item
    payload = {
        "namespace": "USER_RESEARCH",
        "content": "IDOR detection rule: Check sequential ID variance in JSON PUT requests to /api/users/{id}.",
        "title": "IDOR Sequential Pattern",
        "epistemic_status": "FACT",
        "authority_level": "USER_PROVIDED",
        "source_type": "RESEARCH_PROCEDURE",
        "provenance_references": ["assessment_notes:idor_01"],
    }
    res = client.post("/api/memory/items", json=payload)
    assert res.status_code == 200
    mem_id = res.json()["memory_id"]

    # Promote to SHARED_RESEARCH
    promo_payload = {
        "memory_id": mem_id,
        "target_namespace": "SHARED_RESEARCH",
        "requester_id": "researcher",
        "reviewer_id": "lead_security_architect",
        "justification": "High value general IDOR detection pattern abstracted for team reuse.",
        "approve_immediately": True,
    }
    pres = client.post("/api/memory/promote", json=promo_payload)
    assert pres.status_code == 200
    pdata = pres.json()
    assert pdata["promotion_status"] == "PROMOTED"
    assert pdata["namespace"] == "SHARED_RESEARCH"

    # Verify provenance endpoint
    prov_res = client.get(f"/api/memory/{mem_id}/provenance")
    assert prov_res.status_code == 200
    prov_data = prov_res.json()
    assert prov_data["memory_id"] == mem_id


def test_api_memory_supersession_and_history(app_client):
    """Verify version supersession chain V1 -> V2, ensuring V1 is superseded and not returned as current."""
    client, _ = app_client

    # Admit V1
    v1_payload = {
        "namespace": "USER_RESEARCH",
        "content": "CORS misconfiguration hypothesis: wildcard Origin with credentials allowed.",
        "title": "CORS Wildcard Hypothesis",
        "epistemic_status": "MODEL_HYPOTHESIS",
        "authority_level": "MODEL_DERIVED",
        "source_type": "RESEARCH_PROCEDURE",
    }
    v1_res = client.post("/api/memory/items", json=v1_payload)
    assert v1_res.status_code == 200
    v1_id = v1_res.json()["memory_id"]

    # Supersede with V2
    super_payload = {
        "memory_id": v1_id,
        "new_content": "CORS configuration verified: Server strictly validates Origin header against internal regex.",
        "change_rationale": "Live negative control confirmed server rejects wildcard Origin with credentials.",
        "new_epistemic_status": "OBSERVATION",
    }
    sres = client.post("/api/memory/supersede", json=super_payload)
    assert sres.status_code == 200
    sdata = sres.json()
    v2_id = sdata["memory_id"]
    assert v2_id != v1_id

    # Active search should return V2, not V1
    search_res = client.post("/api/memory/search", json={"query": "CORS configuration", "top_k": 5})
    assert search_res.status_code == 200
    hits = search_res.json()["items"]
    hit_ids = [h["memory"]["memory_id"] for h in hits]
    assert v2_id in hit_ids
    assert v1_id not in hit_ids, "SUPERSEDED memory V1 was returned in active search!"

    # History endpoint
    hist_res = client.get(f"/api/memory/{v2_id}/history")
    assert hist_res.status_code == 200
    hist_data = hist_res.json()
    assert isinstance(hist_data, list)


def test_api_forget_and_tombstone(app_client):
    """Verify complete forgetting and tombstoning of memory."""
    client, _ = app_client

    payload = {
        "namespace": "USER_RESEARCH",
        "content": "Temporary test debug note regarding Redis unauthenticated ping.",
        "title": "Redis Debug Note",
        "epistemic_status": "FACT",
        "authority_level": "USER_PROVIDED",
        "source_type": "RESEARCH_PROCEDURE",
    }
    res = client.post("/api/memory/items", json=payload)
    assert res.status_code == 200
    mem_id = res.json()["memory_id"]

    # Forget memory
    fres = client.post("/api/memory/forget", json={"memory_id": mem_id, "reason": "User requested forget action"})
    assert fres.status_code == 200
    fdata = fres.json()
    assert fdata["forgotten"] is True

    # Search should no longer return forgotten memory
    sres = client.post("/api/memory/search", json={"query": "Redis unauthenticated ping", "top_k": 5})
    hits = sres.json()["items"]
    assert mem_id not in [h["memory"]["memory_id"] for h in hits]

    # Direct GET should return 404
    gres = client.get(f"/api/memory/items/{mem_id}")
    assert gres.status_code == 404


def test_episodic_adapters_e2e(app_client):
    """Verify episodic adapters for controlled experiment, negative control, and verified finding."""
    client, db = app_client

    # 1. Controlled Experiment
    exp_item = EpisodicMemoryAdapters.from_controlled_experiment(
        experiment_id="EXP-101",
        assessment_id="INV-ALPHA",
        hypothesis="Timing delay indicates SQL injection vulnerability in search parameter",
        experiment_type="differential_timing",
        outcome="No differential delay observed between sleep(0) and sleep(5)",
        falsified=True,
        evidence_digest="sha256:d8a2bf6...",
        limitations="Network jitter +-12ms",
    )
    assert exp_item.namespace == MemoryNamespace.ASSESSMENT_LOCAL
    assert exp_item.epistemic_status == EpistemicStatus.OBSERVATION
    assert len(exp_item.evidence_pointers) == 1
    assert exp_item.evidence_pointers[0].target_evidence_id == "EXP-101"

    # 2. Negative Control
    neg_item = EpisodicMemoryAdapters.from_negative_control(
        assessment_id="INV-ALPHA",
        tested_hypothesis="403 response on /admin indicates hidden authorization gateway",
        benign_explanation="Cloudflare edge returns generic 403 for non-existent virtual hosts",
        control_artifact_digest="sha256:b1a7c3...",
    )
    assert neg_item.namespace == MemoryNamespace.USER_RESEARCH
    assert "Negative Control Lesson" in neg_item.content
    assert neg_item.evidence_pointers[0].evidence_type == "negative_control"

    # 3. Verified Finding
    pat_item = EpisodicMemoryAdapters.from_verified_finding_reference(
        finding_id="FINDING-CORP-404",
        assessment_id="INV-ALPHA",
        vulnerability_type="BOLA / IDOR",
        abstracted_reproduction_pattern="Modifying client_id in PUT /api/v1/profile without session re-verification",
        finding_digest="sha256:c9e8f4...",
    )
    assert pat_item.namespace == MemoryNamespace.VERIFIED_PATTERN
    assert pat_item.epistemic_status == EpistemicStatus.HUMAN_VERIFIED_FINDING
    assert pat_item.authority_level == MemoryAuthority.HUMAN_VERIFIED
    assert pat_item.promotion_status == PromotionStatus.PROMOTED
