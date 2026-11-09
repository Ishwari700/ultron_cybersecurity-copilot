"""Phase 12 Scope Enforcement and Traffic Ingestion Regression Suite.

Verifies:
TEST 1:  scope = api.target.local, Host = api.target.local -> IN SCOPE
TEST 2:  scope = api.target.local, Host = API.TARGET.LOCAL -> IN SCOPE (case-insensitive normalization)
TEST 3:  scope = api.target.local, Host = api.target.local:443 -> IN SCOPE (port stripping)
TEST 4:  scope = api.target.local, Host = evil.api.target.local -> OUT OF SCOPE (exact host matching when no wildcard)
TEST 5:  scope = api.target.local, Host = api.target.local.evil.com -> OUT OF SCOPE (domain boundary preservation)
TEST 6:  scope = example.com, Host = evil-example.com -> OUT OF SCOPE (no substring prefix match)
TEST 7:  valid in-scope raw HTTP transaction -> observation created
TEST 8:  valid out-of-scope raw HTTP transaction -> observation NOT created
TEST 9:  mixed import (some in-scope + some out-of-scope) -> only in-scope observations created
TEST 10: malformed HTTP transaction -> no Internal Server Error / no corrupted observation, parse error reported
TEST 11: lab.target.local fixture that produced Internal Server Error -> import succeeds with all in-scope transactions
TEST 12: duplicate transaction -> duplicate handling remains correct (duplicate_count incremented, no duplicate persisted)
TEST 13: no scope configured -> preserves fail-closed behavior without inventing new semantics
TEST 14: ambiguous/invalid scope -> fail closed
"""

import json
from pathlib import Path
import pytest

from src.database.manager import DatabaseManager
from src.dashboard.service import WorkspaceService
from src.dashboard.models import ImportTrafficRequest
from src.evidence.ingestion.importers import RawHttpImporter
from src.evidence.ingestion.models import RawTransactionRecord
from src.evidence.ingestion.pipeline import EvidenceIngestionPipeline
from src.scope.gate import ScopeGate, canonicalize_host
from src.scope.models import ScopePolicy, ScopeDecision


@pytest.fixture
def temp_db(tmp_path: Path) -> DatabaseManager:
    db_file = tmp_path / "test_scope_regression.db"
    db = DatabaseManager(db_path=db_file)
    db.initialize_schema()
    return db


@pytest.fixture
def workspace_service(temp_db: DatabaseManager) -> WorkspaceService:
    return WorkspaceService(db_manager=temp_db)


# =============================================================================
# TESTS 1 - 6: Deterministic Scope & Host Matching Semantics
# =============================================================================

def test_1_exact_host_in_scope():
    """TEST 1: scope = api.target.local, Host = api.target.local -> IN SCOPE"""
    scope = "api.target.local"
    host = "api.target.local"
    assert ScopeGate.matches_pattern(host, scope) is True

    gate = ScopeGate(policy=ScopePolicy(program_name="Test", platform="LOCAL", in_scope=[scope]))
    decision = gate.evaluate(f"https://{host}/api/v1/users", allow_passive=True, target_scope=scope)
    assert decision.decision == ScopeDecision.ALLOW


def test_2_uppercase_host_normalization():
    """TEST 2: scope = api.target.local, Host = API.TARGET.LOCAL -> IN SCOPE after normalization"""
    scope = "api.target.local"
    host = "API.TARGET.LOCAL"
    assert ScopeGate.matches_pattern(host, scope) is True

    gate = ScopeGate(policy=ScopePolicy(program_name="Test", platform="LOCAL", in_scope=[scope]))
    decision = gate.evaluate(f"https://{host}/api/v1/users", allow_passive=True, target_scope=scope)
    assert decision.decision == ScopeDecision.ALLOW


def test_3_host_with_port_normalization():
    """TEST 3: scope = api.target.local, Host = api.target.local:443 -> IN SCOPE after port normalization"""
    scope = "api.target.local"
    host = "api.target.local:443"
    assert ScopeGate.matches_pattern(host, scope) is True

    gate = ScopeGate(policy=ScopePolicy(program_name="Test", platform="LOCAL", in_scope=[scope]))
    decision = gate.evaluate(f"https://{host}/api/v1/users", allow_passive=True, target_scope=scope)
    assert decision.decision == ScopeDecision.ALLOW


def test_4_subdomain_on_exact_scope_out_of_scope():
    """TEST 4: scope = api.target.local, Host = evil.api.target.local -> OUT OF SCOPE (exact host policy)"""
    scope = "api.target.local"
    host = "evil.api.target.local"
    # When scope does not specify wildcard (*.), subdomains are not authorized
    assert ScopeGate.matches_pattern(host, scope) is False

    gate = ScopeGate(policy=ScopePolicy(program_name="Test", platform="LOCAL", in_scope=[scope]))
    decision = gate.evaluate(f"https://{host}/api/v1/users", allow_passive=True, target_scope=scope)
    assert decision.decision == ScopeDecision.DENY
    assert "does not match authorized target scope" in decision.reason


def test_5_suffix_spoofing_out_of_scope():
    """TEST 5: scope = api.target.local, Host = api.target.local.evil.com -> OUT OF SCOPE"""
    scope = "api.target.local"
    host = "api.target.local.evil.com"
    assert ScopeGate.matches_pattern(host, scope) is False

    gate = ScopeGate(policy=ScopePolicy(program_name="Test", platform="LOCAL", in_scope=[scope]))
    decision = gate.evaluate(f"https://{host}/api/v1/users", allow_passive=True, target_scope=scope)
    assert decision.decision == ScopeDecision.DENY


def test_6_prefix_spoofing_out_of_scope():
    """TEST 6: scope = example.com, Host = evil-example.com -> OUT OF SCOPE (no substring match)"""
    scope = "example.com"
    host = "evil-example.com"
    assert ScopeGate.matches_pattern(host, scope) is False

    gate = ScopeGate(policy=ScopePolicy(program_name="Test", platform="LOCAL", in_scope=[scope]))
    decision = gate.evaluate(f"https://{host}/api/v1/users", allow_passive=True, target_scope=scope)
    assert decision.decision == ScopeDecision.DENY


# =============================================================================
# TESTS 7 - 12: Ingestion Pipeline Behavior & Database Persistence
# =============================================================================

def test_7_valid_in_scope_raw_http_transaction(temp_db: DatabaseManager):
    """TEST 7: valid in-scope raw HTTP transaction -> observation created"""
    inv_id = "INV-TEST-007"
    temp_db.insert_investigation({
        "id": inv_id,
        "name": "Test In Scope",
        "target_host": "api.target.local",
        "scope_status": "ALLOWED",
        "status": "ACTIVE",
    })

    pipeline = EvidenceIngestionPipeline(db_manager=temp_db)
    raw_tx = (
        "GET /api/v1/users/1002 HTTP/1.1\r\n"
        "Host: api.target.local\r\n"
        "X-Authenticated-User: 1001\r\n"
        "Accept: application/json\r\n\r\n"
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n\r\n"
        '{"id": 1002, "name": "Alice"}'
    )

    result = pipeline.ingest_raw(
        investigation_id=inv_id,
        target_host="api.target.local",
        raw_content=raw_tx,
        format_type="raw_http",
    )

    assert result.accepted_count == 1
    assert result.observations_added == 1
    assert result.out_of_scope_count == 0
    assert len(result.out_of_scope) == 0

    obs = temp_db.get_investigation_observations(inv_id)
    assert len(obs) == 1
    assert obs[0]["host"] == "api.target.local"
    assert obs[0]["raw_path"] == "/api/v1/users/1002"


def test_8_valid_out_of_scope_raw_http_transaction(temp_db: DatabaseManager):
    """TEST 8: valid out-of-scope raw HTTP transaction -> observation NOT created"""
    inv_id = "INV-TEST-008"
    temp_db.insert_investigation({
        "id": inv_id,
        "name": "Test Out Of Scope",
        "target_host": "api.target.local",
        "scope_status": "ALLOWED",
        "status": "ACTIVE",
    })

    pipeline = EvidenceIngestionPipeline(db_manager=temp_db)
    raw_tx = (
        "GET /api/v1/admin/secrets HTTP/1.1\r\n"
        "Host: evil.unauthorized.local\r\n\r\n"
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n\r\n"
        '{"stolen": true}'
    )

    result = pipeline.ingest_raw(
        investigation_id=inv_id,
        target_host="api.target.local",
        raw_content=raw_tx,
        format_type="raw_http",
    )

    assert result.accepted_count == 0
    assert result.observations_added == 0
    assert result.out_of_scope_count == 1
    assert len(result.out_of_scope) == 1
    assert result.out_of_scope[0]["host"] == "evil.unauthorized.local"

    # Invariant: out-of-scope traffic must NEVER become an observation
    obs = temp_db.get_investigation_observations(inv_id)
    assert len(obs) == 0


def test_9_mixed_import_in_scope_and_out_of_scope(temp_db: DatabaseManager):
    """TEST 9: mixed import: some in-scope + some out-of-scope -> only in-scope observations created"""
    inv_id = "INV-TEST-009"
    temp_db.insert_investigation({
        "id": inv_id,
        "name": "Mixed Import",
        "target_host": "api.target.local",
        "scope_status": "ALLOWED",
        "status": "ACTIVE",
    })

    pipeline = EvidenceIngestionPipeline(db_manager=temp_db)
    raw_content = (
        "GET /api/v1/in-scope HTTP/1.1\r\n"
        "Host: api.target.local\r\n\r\n"
        "HTTP/1.1 200 OK\r\n\r\n"
        "OK\r\n"
        "---\r\n"
        "GET /evil/out-of-scope HTTP/1.1\r\n"
        "Host: evil.target.local\r\n\r\n"
        "HTTP/1.1 200 OK\r\n\r\n"
        "EVIL\r\n"
        "---\r\n"
        "GET /api/v1/in-scope-2 HTTP/1.1\r\n"
        "Host: API.TARGET.LOCAL:443\r\n\r\n"
        "HTTP/1.1 200 OK\r\n\r\n"
        "OK2\r\n"
    )

    result = pipeline.ingest_raw(
        investigation_id=inv_id,
        target_host="api.target.local",
        raw_content=raw_content,
        format_type="raw_http",
    )

    assert result.imported_count == 3
    assert result.accepted_count == 2
    assert result.observations_added == 2
    assert result.out_of_scope_count == 1
    assert len(result.out_of_scope) == 1
    assert result.out_of_scope[0]["host"] == "evil.target.local"

    obs = temp_db.get_investigation_observations(inv_id)
    assert len(obs) == 2
    paths = {o["raw_path"] for o in obs}
    assert paths == {"/api/v1/in-scope", "/api/v1/in-scope-2"}


def test_10_malformed_http_transaction_isolation(temp_db: DatabaseManager):
    """TEST 10: malformed HTTP transaction -> no Internal Server Error / no corrupted observation"""
    inv_id = "INV-TEST-010"
    temp_db.insert_investigation({
        "id": inv_id,
        "name": "Malformed Isolation",
        "target_host": "api.target.local",
        "scope_status": "ALLOWED",
        "status": "ACTIVE",
    })

    pipeline = EvidenceIngestionPipeline(db_manager=temp_db)
    # Block 1 is valid, Block 2 is malformed garbage, Block 3 is valid
    raw_content = (
        "GET /valid/1 HTTP/1.1\r\n"
        "Host: api.target.local\r\n\r\n"
        "HTTP/1.1 200 OK\r\n\r\n"
        "OK1\r\n"
        "---\r\n"
        "THIS_IS_CORRUPT_NOT_HTTP\r\n"
        "---\r\n"
        "GET /valid/2 HTTP/1.1\r\n"
        "Host: api.target.local\r\n\r\n"
        "HTTP/1.1 200 OK\r\n\r\n"
        "OK2\r\n"
    )

    result = pipeline.ingest_raw(
        investigation_id=inv_id,
        target_host="api.target.local",
        raw_content=raw_content,
        format_type="raw_http",
    )

    assert result.accepted_count == 2
    assert result.observations_added == 2
    assert result.parsing_failures >= 1
    assert len(result.parse_errors) >= 1

    obs = temp_db.get_investigation_observations(inv_id)
    assert len(obs) == 2


def test_11_lab_target_local_fixture_ingestion_succeeds(workspace_service: WorkspaceService, temp_db: DatabaseManager):
    """TEST 11: lab.target.local fixture that produced Internal Server Error -> import succeeds without error"""
    # Create investigation with target: lab.target.local
    inv_id = "INV-LAB-001"
    temp_db.insert_investigation({
        "id": inv_id,
        "name": "Lab Target Investigation",
        "target_host": "lab.target.local",
        "scope_status": "ALLOWED",
        "status": "ACTIVE",
    })

    # Read the actual synthetic fixture containing 16 transactions
    fixture_path = Path("tests/fixtures/security_test_fixture_10_vulnerabilities.txt")
    assert fixture_path.exists(), f"Fixture file not found at {fixture_path}"

    with open(fixture_path, "r", encoding="utf-8") as f:
        fixture_content = f.read()

    req = ImportTrafficRequest(
        content=fixture_content,
        format="raw_http",
        filename="security_test_fixture_10_vulnerabilities.txt",
    )

    # Ingest through workspace_service (which was failing with 500 sqlite3.OperationalError)
    result_dict = workspace_service.ingest_traffic(inv_id, req)

    # 16 total transactions: Previously 15 distinct observations + 1 duplicate (Finding 8B had identical body/URL but distinct headers).
    # With canonical header integrity included in the evidence digest, all 16 transactions are recognized as distinct observations.
    assert result_dict["imported_count"] == 16
    assert result_dict["accepted_count"] == 16
    assert result_dict["observations_added"] == 16
    assert result_dict["duplicate_count"] == 0
    assert result_dict["duplicates"] == 0
    assert result_dict["out_of_scope_count"] == 0
    assert len(result_dict["out_of_scope"]) == 0
    assert result_dict["parsing_failures"] == 0

    # Verify observations in database
    obs = temp_db.get_investigation_observations(inv_id)
    assert len(obs) == 16
    assert all(o["host"] == "lab.target.local" for o in obs)


def test_12_duplicate_transaction_handling(temp_db: DatabaseManager):
    """TEST 12: duplicate transaction -> duplicate handling remains correct"""
    inv_id = "INV-TEST-012"
    temp_db.insert_investigation({
        "id": inv_id,
        "name": "Duplicate Test",
        "target_host": "api.target.local",
        "scope_status": "ALLOWED",
        "status": "ACTIVE",
    })

    pipeline = EvidenceIngestionPipeline(db_manager=temp_db)
    raw_tx = (
        "GET /api/v1/profile HTTP/1.1\r\n"
        "Host: api.target.local\r\n\r\n"
        "HTTP/1.1 200 OK\r\n\r\n"
        '{"user": "alice"}'
    )

    # First import
    res1 = pipeline.ingest_raw(
        investigation_id=inv_id,
        target_host="api.target.local",
        raw_content=raw_tx,
        format_type="raw_http",
    )
    assert res1.accepted_count == 1
    assert res1.observations_added == 1
    assert res1.duplicate_count == 0

    # Second import (duplicate)
    res2 = pipeline.ingest_raw(
        investigation_id=inv_id,
        target_host="api.target.local",
        raw_content=raw_tx,
        format_type="raw_http",
    )
    assert res2.accepted_count == 0
    assert res2.observations_added == 0
    assert res2.duplicate_count == 1
    assert res2.duplicates == 1

    # Database still has only 1 observation
    obs = temp_db.get_investigation_observations(inv_id)
    assert len(obs) == 1


# =============================================================================
# TESTS 13 - 14: Security Invariants & Fail-Closed Semantics
# =============================================================================

def test_13_no_scope_configured_fails_closed(temp_db: DatabaseManager):
    """TEST 13: no scope configured -> preserve application's intended fail-closed behavior"""
    inv_id = "INV-TEST-013"
    temp_db.insert_investigation({
        "id": inv_id,
        "name": "No Scope Investigation",
        "target_host": "",
        "scope_status": "UNKNOWN",
        "status": "ACTIVE",
    })

    pipeline = EvidenceIngestionPipeline(db_manager=temp_db)
    raw_tx = (
        "GET /api/v1/users HTTP/1.1\r\n"
        "Host: api.target.local\r\n\r\n"
        "HTTP/1.1 200 OK\r\n\r\n"
        "OK"
    )

    result = pipeline.ingest_raw(
        investigation_id=inv_id,
        target_host="",
        raw_content=raw_tx,
        format_type="raw_http",
    )

    # Invariant: Traffic cannot be approved without configured authorized scope
    assert result.accepted_count == 0
    assert result.observations_added == 0
    assert result.out_of_scope_count == 1

    obs = temp_db.get_investigation_observations(inv_id)
    assert len(obs) == 0


def test_14_ambiguous_invalid_scope_fails_closed(temp_db: DatabaseManager):
    """TEST 14: ambiguous/invalid scope -> fail closed"""
    inv_id = "INV-TEST-014"
    temp_db.insert_investigation({
        "id": inv_id,
        "name": "Invalid Scope Investigation",
        "target_host": "http://invalid@@target::scope",
        "scope_status": "UNKNOWN",
        "status": "ACTIVE",
    })

    pipeline = EvidenceIngestionPipeline(db_manager=temp_db)
    raw_tx = (
        "GET /api/v1/users HTTP/1.1\r\n"
        "Host: api.target.local\r\n\r\n"
        "HTTP/1.1 200 OK\r\n\r\n"
        "OK"
    )

    result = pipeline.ingest_raw(
        investigation_id=inv_id,
        target_host="http://invalid@@target::scope",
        raw_content=raw_tx,
        format_type="raw_http",
    )

    assert result.accepted_count == 0
    assert result.observations_added == 0
    assert result.out_of_scope_count == 1
    assert len(result.out_of_scope) == 1
    assert "invalid" in result.out_of_scope[0]["reason"].lower() or "ambiguous" in result.out_of_scope[0]["reason"].lower()

    obs = temp_db.get_investigation_observations(inv_id)
    assert len(obs) == 0
