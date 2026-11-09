"""Phase 12.X Real Security Evidence Ingestion Test Suite.

Verifies:
- HAR (.har) parsing
- Raw HTTP parsing (single & multi-block)
- Burp importer adapter architecture
- Malformed import rejection (safe failure)
- Scope rejection (out-of-scope traffic excluded)
- Secret detection and redaction via RedactionVault
- Deterministic duplicate detection (distinct observations preserved)
- Canonical evidence and asset creation
- Provenance preservation (digest, source_type, timestamps, transforms, audit log)
- Investigation isolation (cross-tenant evidence separation)
- Manual observation creation (validation, redaction, persistence)
- Persistence across restart (database reload)
- Evidence visibility to the security analysis pipeline
- No secret leakage into persisted messages
- Empty investigation remains genuinely empty
- Imported evidence does not fabricate findings
- Local cascade receives canonical evidence rather than raw import blobs
"""

import json
from pathlib import Path
from typing import Dict, Any
from unittest.mock import MagicMock
import pytest

from src.database.manager import DatabaseManager
from src.dashboard.service import WorkspaceService
from src.dashboard.models import (
    CreateInvestigationRequest,
    ImportTrafficRequest,
    ManualObservationRequest,
)
from src.core.logging import AuditLogger
from src.evidence.ingestion.importers import HarImporter, RawHttpImporter, BurpImporter
from src.evidence.ingestion.models import IngestionSourceType, RawTransactionRecord
from src.evidence.ingestion.pipeline import EvidenceIngestionPipeline
from src.evidence.cascade_models import LosslessStructuralPack, RawTriageOutput
from src.engine.cascade_orchestrator import CascadeExecutionTrace
from src.evidence.vault import RedactionVault


# =====================================================================
# Fixtures & Helpers
# =====================================================================

@pytest.fixture
def temp_db(tmp_path: Path) -> DatabaseManager:
    db_file = tmp_path / "test_phase12_x.db"
    db = DatabaseManager(db_path=db_file)
    db.initialize_schema()
    return db


@pytest.fixture
def workspace_service(temp_db: DatabaseManager) -> WorkspaceService:
    return WorkspaceService(db_manager=temp_db)


def create_test_investigation(db: DatabaseManager, inv_id: str, host: str = "api.target.local") -> None:
    """Helper to insert an authorized investigation parent record."""
    db.insert_investigation({
        "investigation_id": inv_id,
        "name": f"Test Investigation {inv_id}",
        "target_host": host,
        "scope_status": "ALLOWED",
        "status": "ACTIVE",
        "is_demo": 0,
    })


@pytest.fixture
def sample_har_json() -> str:
    """Realistic standard HAR 1.2 fixture."""
    har_data = {
        "log": {
            "version": "1.2",
            "creator": {"name": "TestHarGenerator", "version": "1.0"},
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "https://api.target.local/api/v1/invoices/4821",
                        "headers": [
                            {"name": "Host", "value": "api.target.local"},
                            {"name": "Authorization", "value": "Bearer secret_jwt_token_alpha_12345"},
                            {"name": "Accept", "value": "application/json"},
                        ],
                        "queryString": [],
                        "postData": None,
                    },
                    "response": {
                        "status": 200,
                        "statusText": "OK",
                        "headers": [
                            {"name": "Content-Type", "value": "application/json"},
                            {"name": "X-Request-Id", "value": "req-9871"},
                        ],
                        "content": {
                            "text": '{"invoice_id": 4821, "amount": 1250.00, "org_id": 42}',
                            "mimeType": "application/json",
                        },
                    },
                },
                {
                    "request": {
                        "method": "GET",
                        "url": "https://api.target.local/api/v1/invoices/4822",
                        "headers": [
                            {"name": "Host", "value": "api.target.local"},
                            {"name": "Authorization", "value": "Bearer secret_jwt_token_alpha_12345"},
                        ],
                        "queryString": [],
                        "postData": None,
                    },
                    "response": {
                        "status": 200,
                        "statusText": "OK",
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                        "content": {
                            "text": '{"invoice_id": 4822, "amount": 3400.00, "org_id": 42}',
                            "mimeType": "application/json",
                        },
                    },
                },
            ],
        }
    }
    return json.dumps(har_data)


@pytest.fixture
def sample_raw_http() -> str:
    """Standard raw HTTP request and response pair."""
    return """POST /api/v1/invoices/export HTTP/1.1
Host: api.target.local
Authorization: Bearer secret_export_token_beta_99999
Content-Type: application/json
Cookie: session=secret_session_cookie_1234567890

{"export_format": "pdf", "invoice_ids": [4821, 4822]}

HTTP/1.1 200 OK
Content-Type: application/pdf
Content-Disposition: attachment; filename="invoices.pdf"

%PDF-1.4 mock binary stream"""


# =====================================================================
# Unit Tests: Importer Architecture
# =====================================================================

def test_har_importer_parsing(sample_har_json: str):
    """Verify HarImporter extracts uniform RawTransactionRecords from standard HAR."""
    importer = HarImporter()
    records, errors = importer.parse(sample_har_json, source_artifact="captured_session.har")

    assert len(errors) == 0
    assert len(records) == 2
    rec1 = records[0]
    assert rec1.method == "GET"
    assert rec1.host == "api.target.local"
    assert rec1.path == "/api/v1/invoices/4821"
    assert rec1.response_status == 200
    assert rec1.request_headers.get("Host") == "api.target.local"
    assert rec1.request_headers.get("Authorization") == "Bearer secret_jwt_token_alpha_12345"
    assert "invoice_id" in rec1.response_body
    assert rec1.source_tool == "har_importer"
    assert rec1.source_artifact == "captured_session.har"

    rec2 = records[1]
    assert rec2.path == "/api/v1/invoices/4822"


def test_raw_http_importer_parsing(sample_raw_http: str):
    """Verify RawHttpImporter parses standard raw HTTP request & response blocks."""
    importer = RawHttpImporter()
    records, errors = importer.parse(sample_raw_http, source_artifact="raw_export.txt")

    assert len(errors) == 0
    assert len(records) == 1
    rec = records[0]
    assert rec.method == "POST"
    assert rec.host == "api.target.local"
    assert rec.path == "/api/v1/invoices/export"
    assert rec.response_status == 200
    assert rec.request_headers.get("Content-Type") == "application/json"
    assert rec.request_headers.get("Authorization") == "Bearer secret_export_token_beta_99999"
    assert "export_format" in rec.request_body
    assert "PDF" in rec.response_body
    assert rec.source_tool == "raw_http_importer"


def test_raw_http_importer_multi_transaction():
    """Verify RawHttpImporter supports multiple transactions separated by delimiters."""
    multi_text = """GET /api/v1/users/me HTTP/1.1
Host: api.target.local
Accept: application/json

HTTP/1.1 200 OK
Content-Type: application/json

{"user_id": "usr_1"}

---

GET /api/v1/orgs/42 HTTP/1.1
Host: api.target.local
Accept: application/json

HTTP/1.1 200 OK
Content-Type: application/json

{"org_id": 42}"""

    importer = RawHttpImporter()
    records, errors = importer.parse(multi_text)
    assert len(errors) == 0
    assert len(records) == 2
    assert records[0].path == "/api/v1/users/me"
    assert records[1].path == "/api/v1/orgs/42"


def test_burp_importer_architecture():
    """Verify BurpImporter adapter produces uniform RawTransactionRecord instances."""
    import base64

    req_raw = "GET /api/v1/burp_test HTTP/1.1\r\nHost: api.target.local\r\n\r\n"
    resp_raw = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nBurpOK"

    burp_data = {
        "items": [
            {
                "host": "api.target.local",
                "port": 443,
                "protocol": "https",
                "request": base64.b64encode(req_raw.encode("utf-8")).decode("utf-8"),
                "response": base64.b64encode(resp_raw.encode("utf-8")).decode("utf-8"),
                "status": 200,
                "path": "/api/v1/burp_test",
            }
        ]
    }

    importer = BurpImporter()
    records, errors = importer.parse(json.dumps(burp_data), source_artifact="burp_traffic.json")
    assert len(errors) == 0
    assert len(records) == 1
    rec = records[0]
    assert rec.method == "GET"
    assert rec.host == "api.target.local"
    assert rec.path == "/api/v1/burp_test"
    assert rec.response_status == 200
    assert rec.source_tool == "burp_importer"


def test_malformed_import_rejection(temp_db: DatabaseManager):
    """Verify pipeline rejects malformed imports without unhandled crashes."""
    create_test_investigation(temp_db, "INV-TEST")
    pipeline = EvidenceIngestionPipeline(db_manager=temp_db)

    # 1. Invalid HAR JSON
    res_har = pipeline.ingest_raw(
        raw_content="{ invalid: json syntax missing braces",
        format_type="har",
        investigation_id="INV-TEST",
        target_host="api.target.local",
    )
    assert res_har.parsing_failures >= 1
    assert res_har.accepted_count == 0
    assert len(res_har.errors) > 0

    # 2. Garbage text for raw HTTP
    res_raw = pipeline.ingest_raw(
        raw_content="totally not an HTTP request or response at all",
        format_type="raw_http",
        investigation_id="INV-TEST",
        target_host="api.target.local",
    )
    assert res_raw.parsing_failures >= 1
    assert res_raw.accepted_count == 0


# =====================================================================
# Pipeline Integration Tests: Scope, Redaction, Deduplication
# =====================================================================

def test_scope_rejection(temp_db: DatabaseManager):
    """Verify transactions outside authorized target_host are excluded deterministically."""
    create_test_investigation(temp_db, "INV-SCOPE-01", "api.target.local")
    pipeline = EvidenceIngestionPipeline(db_manager=temp_db)

    out_of_scope_har = {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "https://evil-unauthorized.com/admin/secrets",
                        "headers": [{"name": "Host", "value": "evil-unauthorized.com"}],
                    },
                    "response": {"status": 200, "headers": [], "content": {"text": "stolen"}},
                },
                {
                    "request": {
                        "method": "GET",
                        "url": "https://api.target.local/api/v1/profile",
                        "headers": [{"name": "Host", "value": "api.target.local"}],
                    },
                    "response": {"status": 200, "headers": [], "content": {"text": "ok"}},
                },
            ]
        }
    }

    res = pipeline.ingest_raw(
        raw_content=json.dumps(out_of_scope_har),
        format_type="har",
        investigation_id="INV-SCOPE-01",
        target_host="api.target.local",
    )

    assert res.imported_count == 2
    assert res.accepted_count == 1
    assert res.out_of_scope_count == 1

    # Verify evil domain was NOT saved
    obs = temp_db.get_investigation_observations("INV-SCOPE-01")
    assert len(obs) == 1
    assert obs[0]["host"] == "api.target.local"
    assert obs[0]["raw_path"] == "/api/v1/profile"


def test_secret_redaction(temp_db: DatabaseManager):
    """Verify raw secrets are detected, stripped, and vaulted; never stored plaintext."""
    create_test_investigation(temp_db, "INV-SECRET-01", "api.target.local")
    vault = RedactionVault()
    pipeline = EvidenceIngestionPipeline(db_manager=temp_db, vault=vault)

    har_data = {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "POST",
                        "url": "https://api.target.local/api/v1/auth/exchange",
                        "headers": [
                            {"name": "Host", "value": "api.target.local"},
                            {"name": "Authorization", "value": "Bearer my_super_secret_jwt_token_9999"},
                            {"name": "Cookie", "value": "session=secret_cookie_val_abc; token=sec_xyz"},
                            {"name": "X-API-Key", "value": "api_key_secret_12345"},
                        ],
                        "postData": {"text": '{"password": "plain_secret_password_here"}'},
                    },
                    "response": {
                        "status": 200,
                        "headers": [
                            {"name": "Set-Cookie", "value": "session=secret_new_session_987; HttpOnly"}
                        ],
                        "content": {"text": '{"access_token": "returned_secret_jwt_token_678"}'},
                    },
                }
            ]
        }
    }

    res = pipeline.ingest_raw(
        raw_content=json.dumps(har_data),
        format_type="har",
        investigation_id="INV-SECRET-01",
        target_host="api.target.local",
    )

    assert res.accepted_count == 1
    assert res.redacted_secret_count > 0

    obs = temp_db.get_investigation_observations("INV-SECRET-01")[0]

    # Verify no raw secrets in persisted headers or bodies
    headers_str = json.dumps(obs["request_headers"])
    assert "my_super_secret_jwt_token_9999" not in headers_str
    assert "secret_cookie_val_abc" not in headers_str
    assert "api_key_secret_12345" not in headers_str
    assert "plain_secret_password_here" not in obs["request_body"]
    assert "returned_secret_jwt_token_678" not in obs["response_body"]

    # Redaction placeholders should exist
    assert "REDACTED" in headers_str


def test_duplicate_detection(temp_db: DatabaseManager, sample_har_json: str):
    """Verify deterministic deduplication skips identical HTTP transactions."""
    create_test_investigation(temp_db, "INV-DEDUP-01", "api.target.local")
    pipeline = EvidenceIngestionPipeline(db_manager=temp_db)

    # 1. First import
    res1 = pipeline.ingest_raw(
        raw_content=sample_har_json,
        format_type="har",
        investigation_id="INV-DEDUP-01",
        target_host="api.target.local",
    )
    assert res1.accepted_count == 2
    assert res1.duplicate_count == 0

    # 2. Second import of the identical traffic
    res2 = pipeline.ingest_raw(
        raw_content=sample_har_json,
        format_type="har",
        investigation_id="INV-DEDUP-01",
        target_host="api.target.local",
    )
    assert res2.accepted_count == 0
    assert res2.duplicate_count == 2

    # Database still only contains 2 records
    obs = temp_db.get_investigation_observations("INV-DEDUP-01")
    assert len(obs) == 2


def test_distinct_endpoints_not_falsely_deduplicated(temp_db: DatabaseManager):
    """Verify distinct observations to the same path or method are preserved."""
    create_test_investigation(temp_db, "INV-DISTINCT-01", "api.target.local")
    pipeline = EvidenceIngestionPipeline(db_manager=temp_db)

    raw_transactions = """GET /api/invoices/1 HTTP/1.1
Host: api.target.local

HTTP/1.1 200 OK

{"id": 1}

---

GET /api/invoices/2 HTTP/1.1
Host: api.target.local

HTTP/1.1 200 OK

{"id": 2}"""

    res = pipeline.ingest_raw(
        raw_content=raw_transactions,
        format_type="raw_http",
        investigation_id="INV-DISTINCT-01",
        target_host="api.target.local",
    )

    assert res.accepted_count == 2
    assert res.duplicate_count == 0


# =====================================================================
# Provenance & Isolation Tests
# =====================================================================

def test_provenance_preservation(temp_db: DatabaseManager, tmp_path: Path, sample_raw_http: str):
    """Verify evidence provenance: ID, source_type, digest, normalized path, timestamp, and audit trail."""
    create_test_investigation(temp_db, "INV-PROV-01", "api.target.local")
    audit_file = tmp_path / "provenance_audit.log"
    logger = AuditLogger(audit_file_path=audit_file)
    pipeline = EvidenceIngestionPipeline(db_manager=temp_db, audit_logger=logger)

    res = pipeline.ingest_raw(
        raw_content=sample_raw_http,
        format_type="raw_http",
        investigation_id="INV-PROV-01",
        target_host="api.target.local",
        source_artifact="session_export.txt",
    )

    assert res.accepted_count == 1
    obs_id = res.accepted_observations[0].id
    obs = temp_db.get_investigation_observation(obs_id)

    assert obs is not None
    assert obs["investigation_id"] == "INV-PROV-01"
    assert obs["source_type"] == IngestionSourceType.RAW_HTTP
    assert obs["source_artifact"] == "session_export.txt"
    assert obs["transaction_digest"].startswith("sha256:")
    assert obs["normalized_path"] == "/api/v1/invoices/export"
    assert obs["created_at"] is not None

    # Verify audit log was written
    assert audit_file.exists()
    audit_content = audit_file.read_text(encoding="utf-8")
    assert "EVIDENCE_INGESTED" in audit_content
    assert "INV-PROV-01" in audit_content


def test_investigation_isolation(temp_db: DatabaseManager, sample_har_json: str, sample_raw_http: str):
    """Verify complete evidence isolation between two separate investigations."""
    create_test_investigation(temp_db, "INV-TENANT-A", "api.target.local")
    create_test_investigation(temp_db, "INV-TENANT-B", "api.target.local")
    pipeline = EvidenceIngestionPipeline(db_manager=temp_db)

    pipeline.ingest_raw(
        raw_content=sample_har_json,
        format_type="har",
        investigation_id="INV-TENANT-A",
        target_host="api.target.local",
    )

    pipeline.ingest_raw(
        raw_content=sample_raw_http,
        format_type="raw_http",
        investigation_id="INV-TENANT-B",
        target_host="api.target.local",
    )

    obs_a = temp_db.get_investigation_observations("INV-TENANT-A")
    obs_b = temp_db.get_investigation_observations("INV-TENANT-B")

    assert len(obs_a) == 2
    assert len(obs_b) == 1

    ids_a = {o["id"] for o in obs_a}
    ids_b = {o["id"] for o in obs_b}
    assert ids_a.isdisjoint(ids_b)


# =====================================================================
# Manual Observation Creation Tests
# =====================================================================

def test_manual_observation_creation(workspace_service: WorkspaceService, temp_db: DatabaseManager):
    """Verify researcher can manually record an observation via the service."""
    # 1. Create target investigation
    inv = workspace_service.create_investigation(
        CreateInvestigationRequest(name="Payment Gateway Test", target_host="payments.target.local")
    )

    # 2. Add manual observation
    manual_req = ManualObservationRequest(
        method="POST",
        host="payments.target.local",
        path="/api/v1/charges",
        status_code=201,
        request_headers={
            "Authorization": "Bearer secret_charge_key_1111",
            "Content-Type": "application/json",
        },
        request_body='{"amount": 5000, "currency": "usd"}',
        response_headers={"Content-Type": "application/json"},
        response_body='{"charge_id": "ch_987", "status": "succeeded"}',
        researcher_note="Successful charge using tenant token",
    )

    result = workspace_service.add_manual_observation(inv.id, manual_req)
    assert result["accepted_count"] == 1
    assert result["redacted_secret_count"] > 0

    # 3. Verify in DB
    obs = temp_db.get_investigation_observations(inv.id)
    assert len(obs) == 1
    record = obs[0]
    assert record["method"] == "POST"
    assert record["raw_path"] == "/api/v1/charges"
    assert record["status_code"] == 201
    assert record["researcher_note"] == "Successful charge using tenant token"
    assert "secret_charge_key_1111" not in json.dumps(record["request_headers"])


def test_manual_observation_scope_enforcement(workspace_service: WorkspaceService):
    """Verify manual observations reject out-of-scope targets."""
    inv = workspace_service.create_investigation(
        CreateInvestigationRequest(name="Scoped App", target_host="app.target.local")
    )

    manual_req = ManualObservationRequest(
        method="GET",
        host="forbidden-external-host.com",
        path="/secret",
        status_code=200,
    )

    result = workspace_service.add_manual_observation(inv.id, manual_req)
    assert result["accepted_count"] == 0
    assert result["out_of_scope_count"] == 1


# =====================================================================
# Persistence & Empty State Integrity Tests
# =====================================================================

def test_persistence_across_restart(tmp_path: Path, sample_har_json: str):
    """Verify observations and derived evidence persist across database reopen."""
    db_file = tmp_path / "persistence_restart_test.db"

    # 1. Initialize and ingest
    db1 = DatabaseManager(db_path=db_file)
    db1.initialize_schema()
    service1 = WorkspaceService(db_manager=db1)

    inv = service1.create_investigation(
        CreateInvestigationRequest(name="Restart Check", target_host="api.target.local")
    )
    service1.ingest_traffic(
        inv.id,
        ImportTrafficRequest(format="har", content=sample_har_json, filename="traffic.har"),
    )

    count1 = db1.get_observation_count(inv.id)
    assert count1 == 2

    # 2. Simulate complete restart by instantiating new manager
    db2 = DatabaseManager(db_path=db_file)
    db2.initialize_schema()
    service2 = WorkspaceService(db_manager=db2)

    count2 = db2.get_observation_count(inv.id)
    assert count2 == 2

    evidence2 = service2.get_evidence(inv.id)
    assert len(evidence2) == 2
    assert evidence2[0]["statement"].startswith("GET /api/v1/invoices/")


def test_empty_investigation_remains_genuinely_empty(workspace_service: WorkspaceService):
    """Verify non-demo investigations have zero observations and zero fake findings."""
    inv = workspace_service.create_investigation(
        CreateInvestigationRequest(name="Clean Investigation", target_host="api.target.local")
    )

    detail = workspace_service.get_investigation(inv.id)
    assert detail.evidence_count == 0
    assert detail.hypothesis_count == 0
    # Clean investigation starts with exactly 1 system initialization notification
    assert len(detail.messages) == 1
    assert detail.messages[0].sender == "system"
    assert "No target evidence loaded" in detail.messages[0].content

    evidence = workspace_service.get_evidence(inv.id)
    assert len(evidence) == 0

    model = workspace_service.get_application_model(inv.id)
    assert len(model["assets"]) == 0
    assert len(model["workflows"]) == 0


# =====================================================================
# Cascade Security Integration: Canonical Evidence Visibility
# =====================================================================

def test_evidence_visible_to_security_analysis_pipeline(
    workspace_service: WorkspaceService,
    sample_har_json: str,
):
    """Verify real ingested observations feed dynamically into the security analysis cascade."""
    inv = workspace_service.create_investigation(
        CreateInvestigationRequest(name="Real Target", target_host="api.target.local")
    )

    # Ingest real traffic
    res = workspace_service.ingest_traffic(
        inv.id,
        ImportTrafficRequest(format="har", content=sample_har_json, filename="real.har"),
    )
    assert res["accepted_count"] == 2

    # Application model now derives assets from ingested observations
    app_model = workspace_service.get_application_model(inv.id)
    assert len(app_model["assets"]) > 0
    assert app_model["assets"][0]["normalized_path"] == "/api/v1/invoices/{id}"

    # Mock cascade orchestrator to inspect passed LosslessStructuralPack
    mock_orchestrator = MagicMock()
    mock_triage = RawTriageOutput(
        decision="BENIGN_CONTROL_CONFIRMED",
        suspected_category="BENIGN",
        triage_rationale="Invoices returned properly for authorized tenant",
    )
    mock_trace = CascadeExecutionTrace(
        run_id="RUN-0001",
        investigation_id=inv.id,
        task_type="SECURITY_RESEARCH",
        target_endpoint="/api/v1/invoices/{id}",
        overall_status="CASCADE_VERIFIED",
        routing_decision="BENIGN_CONTROL",
        total_latency_seconds=0.05,
        stages=[],
    )
    mock_orchestrator.execute_cascade.return_value = (mock_trace, None)
    workspace_service.cascade_orchestrator = mock_orchestrator

    # Run query
    workspace_service.send_message(inv.id, "Analyze target traffic for security invariants.")

    # Verify cascade orchestrator was called
    assert mock_orchestrator.execute_cascade.called
    call_args = mock_orchestrator.execute_cascade.call_args[0]
    pack: LosslessStructuralPack = call_args[0]

    # Verify cascade received canonical structural pack derived from observations
    assert pack.route_template == "/api/v1/invoices/{id}"
    assert len(pack.observed_facts) >= 2
    assert "4821" in pack.observed_facts[0]["statement"]


def test_no_secret_leakage_into_persisted_messages(
    workspace_service: WorkspaceService,
    sample_har_json: str,
):
    """Verify unredacted secrets do not leak into conversation messages."""
    inv = workspace_service.create_investigation(
        CreateInvestigationRequest(name="Leak Test", target_host="api.target.local")
    )

    workspace_service.ingest_traffic(
        inv.id,
        ImportTrafficRequest(format="har", content=sample_har_json),
    )

    messages = workspace_service.get_messages(inv.id)
    for m in messages:
        assert "secret_jwt_token_alpha_12345" not in m.content
