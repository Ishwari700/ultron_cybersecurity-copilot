"""Integration tests for knowledge source intake and ingestion APIs (Milestone M9 Stage B).

Tests the real FastAPI application endpoints:
- GET /api/knowledge/sources
- GET /api/knowledge/sources/{source_id}
- POST /api/knowledge/sources/upload (multipart form data)
- POST /api/knowledge/sources/import (local filesystem containment)
- POST /api/knowledge/sources/ingest-text (direct text intake)
- POST /api/knowledge/sources/{source_id}/deactivate (purges FTS5 index)
- POST /api/knowledge/sources/{source_id}/retry (re-indexes from imports)
"""

import io
from pathlib import Path
import pytest
import pypdf
from fastapi.testclient import TestClient

from src.core.logging import AuditLogger
from src.dashboard.app import create_dashboard_app
from src.dashboard.auth import DashboardAuthManager, DashboardRole
from src.dashboard.service import WorkspaceService
from src.database.manager import DatabaseManager
from src.knowledge.ingestion_engine import KnowledgeIngestionEngine
from src.knowledge.store import VaptKnowledgeStore


def _build_test_pdf(pages_text: list[str]) -> bytes:
    """Helper generating a standards-compliant multi-page PDF with pypdf."""
    writer = pypdf.PdfWriter()
    for text in pages_text:
        if text:
            raw = f"""%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> >> >> /Contents 4 0 R >> endobj
4 0 obj << /Length {len(text) + 40} >> stream
BT /F1 12 Tf 72 712 Td ({text}) Tj ET
endstream endobj
xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000057 00000 n 
0000000114 00000 n 
0000000267 00000 n 
trailer << /Size 5 /Root 1 0 R >>
startxref
{350 + len(text)}
%%EOF"""
        else:
            raw = """%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> /Contents 4 0 R >> endobj
4 0 obj << /Length 0 >> stream
endstream endobj
xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000057 00000 n 
0000000114 00000 n 
0000000220 00000 n 
trailer << /Size 5 /Root 1 0 R >>
startxref
270
%%EOF"""
        reader = pypdf.PdfReader(io.BytesIO(raw.encode("latin1")))
        writer.add_page(reader.pages[0])

    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


@pytest.fixture
def test_env(tmp_path: Path):
    """Sets up an isolated database, knowledge store, and authenticated test client."""
    db_file = tmp_path / "app.db"
    k_db_file = tmp_path / "knowledge.db"
    audit_file = tmp_path / "audit.log"
    k_audit_file = tmp_path / "k_audit.jsonl"
    quarantine_dir = tmp_path / "quarantine"
    imports_dir = tmp_path / "data" / "knowledge" / "imports"
    imports_dir.mkdir(parents=True, exist_ok=True)

    db_mgr = DatabaseManager(db_file)
    auditor = AuditLogger(audit_file)
    k_store = VaptKnowledgeStore(k_db_file)
    k_engine = KnowledgeIngestionEngine(
        knowledge_store=k_store,
        audit_log_path=k_audit_file,
        quarantine_dir=quarantine_dir,
        import_root=imports_dir,
    )

    ws_service = WorkspaceService(db_manager=db_mgr, audit_logger=auditor)
    ws_service.knowledge_ingestion_engine = k_engine

    auth_mgr = DashboardAuthManager(db_manager=db_mgr)
    op_session = auth_mgr.create_session(username="operator_user", role=DashboardRole.OPERATOR)
    obs_session = auth_mgr.create_session(username="observer_user", role=DashboardRole.OBSERVER)

    app = create_dashboard_app(
        db_manager=db_mgr,
        audit_logger=auditor,
        auth_manager=auth_mgr,
        workspace_service=ws_service,
        require_auth=True,
    )
    client = TestClient(app)

    yield {
        "client": client,
        "k_store": k_store,
        "k_engine": k_engine,
        "imports_dir": imports_dir,
        "op_token": op_session.token,
        "obs_token": obs_session.token,
    }

    k_store.close()


# ---------------------------------------------------------------------------
# Authentication & Role Authorization
# ---------------------------------------------------------------------------

def test_unauthenticated_request_fails_closed(test_env):
    """Verify unauthenticated requests return 401."""
    client = test_env["client"]
    res = client.get("/api/knowledge/sources")
    assert res.status_code == 401


def test_insufficient_role_mutation_rejected(test_env):
    """Verify Observer role cannot perform state-changing intake."""
    client = test_env["client"]
    obs_headers = {"Authorization": f"Bearer {test_env['obs_token']}"}

    # Upload attempt
    pdf_bytes = _build_test_pdf(["Page 1 content"])
    res = client.post(
        "/api/knowledge/sources/upload",
        headers=obs_headers,
        files={"file": ("test.pdf", pdf_bytes, "application/pdf")},
    )
    assert res.status_code == 403

    # Local import attempt
    res = client.post(
        "/api/knowledge/sources/import",
        headers=obs_headers,
        json={"relative_path": "any.txt"},
    )
    assert res.status_code == 403


# ---------------------------------------------------------------------------
# In-App File Upload Endpoint
# ---------------------------------------------------------------------------

def test_upload_pdf_successful_ingestion(test_env):
    """Verify multipart PDF upload extracts pages, chunks, and indexes source."""
    client = test_env["client"]
    op_headers = {"Authorization": f"Bearer {test_env['op_token']}"}

    pdf_bytes = _build_test_pdf([
        "Chapter 1: Insecure Direct Object References (IDOR) mechanics.",
        "Chapter 2: Remediation through indirect object reference maps.",
    ])

    res = client.post(
        "/api/knowledge/sources/upload",
        headers=op_headers,
        files={"file": ("idor_guide.pdf", pdf_bytes, "application/pdf")},
        data={"title": "IDOR Guide 2026", "authority_level": "USER_OWNED", "tags": "idor, access-control"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "INDEXED"
    assert data["format"] == "PDF"
    assert data["page_count"] == 2
    assert data["pages_with_text"] == 2
    assert data["chunk_count"] == 2
    assert len(data["chunks"]) == 2
    assert "CHK-" in data["chunks"][0]

    # Verify searchability in knowledge store
    store = test_env["k_store"]
    hits = store.query_lexical("IDOR mechanics")
    assert len(hits) >= 1
    assert "Chapter 1" in hits[0][0].content


def test_upload_markdown_and_text(test_env):
    """Verify upload endpoint handles Markdown and plain text files."""
    client = test_env["client"]
    op_headers = {"Authorization": f"Bearer {test_env['op_token']}"}

    # Markdown
    md_bytes = b"# SSRF Defenses\nValidate all incoming destination URLs against a strict allowlist."
    res_md = client.post(
        "/api/knowledge/sources/upload",
        headers=op_headers,
        files={"file": ("ssrf.md", md_bytes, "text/markdown")},
        data={"title": "SSRF Defenses"},
    )
    assert res_md.status_code == 200
    assert res_md.json()["format"] == "MARKDOWN"
    assert res_md.json()["status"] == "INDEXED"

    # Plain Text
    txt_bytes = b"Hardcoded credentials in source control must be revoked immediately."
    res_txt = client.post(
        "/api/knowledge/sources/upload",
        headers=op_headers,
        files={"file": ("creds.txt", txt_bytes, "text/plain")},
        data={"title": "Credential Policy"},
    )
    assert res_txt.status_code == 200
    assert res_txt.json()["format"] == "PLAIN_TEXT"
    assert res_txt.json()["status"] == "INDEXED"


def test_upload_unsupported_format_rejected(test_env):
    """Verify unsupported file extensions are rejected with 400 Bad Request."""
    client = test_env["client"]
    op_headers = {"Authorization": f"Bearer {test_env['op_token']}"}

    res = client.post(
        "/api/knowledge/sources/upload",
        headers=op_headers,
        files={"file": ("exploit.bin", b"\x7fELF...", "application/octet-stream")},
    )
    assert res.status_code == 400
    assert "Unsupported file format" in res.json().get("detail", "")


# ---------------------------------------------------------------------------
# Direct Text Ingestion Endpoint
# ---------------------------------------------------------------------------

def test_ingest_text_endpoint(test_env):
    """Verify POST /api/knowledge/sources/ingest-text directly indexes markdown."""
    client = test_env["client"]
    op_headers = {"Authorization": f"Bearer {test_env['op_token']}"}

    payload = {
        "filename": "csrf_notes.md",
        "title": "CSRF Mitigation Notes",
        "content": "# CSRF Mitigation\nUse SameSite=Strict cookies and synchronizer tokens.",
        "authority_level": "USER_OWNED",
        "tags": ["csrf", "session"],
    }
    res = client.post("/api/knowledge/sources/ingest-text", headers=op_headers, json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "INDEXED"
    assert data["title"] == "CSRF Mitigation Notes"


# ---------------------------------------------------------------------------
# Deduplication Semantics
# ---------------------------------------------------------------------------

def test_duplicate_ingestion_rejection(test_env):
    """Verify identical content returns DUPLICATE status and reuses existing source ID."""
    client = test_env["client"]
    op_headers = {"Authorization": f"Bearer {test_env['op_token']}"}

    pdf_bytes = _build_test_pdf(["Deterministic content for duplicate testing"])
    res1 = client.post(
        "/api/knowledge/sources/upload",
        headers=op_headers,
        files={"file": ("dup_test.pdf", pdf_bytes, "application/pdf")},
    )
    assert res1.status_code == 200
    source_id1 = res1.json()["source_id"]

    res2 = client.post(
        "/api/knowledge/sources/upload",
        headers=op_headers,
        files={"file": ("dup_test.pdf", pdf_bytes, "application/pdf")},
    )
    assert res2.status_code == 200
    data2 = res2.json()
    assert data2["status"] == "DUPLICATE"
    assert data2["source_id"] == source_id1


# ---------------------------------------------------------------------------
# Local-Path Import & Path Containment
# ---------------------------------------------------------------------------

def test_import_local_path_security_containment(test_env):
    """Verify path traversal is rejected and containment inside imports dir is enforced."""
    client = test_env["client"]
    op_headers = {"Authorization": f"Bearer {test_env['op_token']}"}
    imports_dir = test_env["imports_dir"]

    # 1. Path traversal attempt (absolute parent escape)
    res_trav1 = client.post(
        "/api/knowledge/sources/import",
        headers=op_headers,
        json={"relative_path": "../../../etc/passwd"},
    )
    assert res_trav1.status_code == 400
    assert "Path traversal rejected" in res_trav1.json().get("detail", "")

    # 2. Path traversal attempt (relative parent escape)
    res_trav2 = client.post(
        "/api/knowledge/sources/import",
        headers=op_headers,
        json={"relative_path": "../sibling_secret.txt"},
    )
    assert res_trav2.status_code == 400

    # 3. Non-existent file inside imports dir
    res_missing = client.post(
        "/api/knowledge/sources/import",
        headers=op_headers,
        json={"relative_path": "nonexistent_file.md"},
    )
    assert res_missing.status_code == 404

    # 4. Valid file inside approved imports dir
    valid_file = imports_dir / "authorized_manual.md"
    valid_file.write_text("# Authorized Manual\nInternal testing procedures.")
    res_valid = client.post(
        "/api/knowledge/sources/import",
        headers=op_headers,
        json={"relative_path": "authorized_manual.md", "title": "Manual"},
    )
    assert res_valid.status_code == 200
    assert res_valid.json()["status"] == "INDEXED"


# ---------------------------------------------------------------------------
# Source Retrieval & Deactivation (FTS5 Invalidation)
# ---------------------------------------------------------------------------

def test_source_listing_and_deactivation_lifecycle(test_env):
    """Verify listing, detail retrieval, deactivation, and lexical index invalidation."""
    client = test_env["client"]
    op_headers = {"Authorization": f"Bearer {test_env['op_token']}"}
    obs_headers = {"Authorization": f"Bearer {test_env['obs_token']}"}

    # Ingest a source
    txt_bytes = b"Deactivation test: Zero-day vulnerability remediation procedures."
    res = client.post(
        "/api/knowledge/sources/upload",
        headers=op_headers,
        files={"file": ("deact.txt", txt_bytes, "text/plain")},
        data={"title": "Remediation Document"},
    )
    source_id = res.json()["source_id"]

    # Verify listing includes the source
    list_res = client.get("/api/knowledge/sources", headers=obs_headers)
    assert list_res.status_code == 200
    sources = list_res.json()
    assert any(s["source_id"] == source_id for s in sources)

    # Verify detail retrieval
    get_res = client.get(f"/api/knowledge/sources/{source_id}", headers=obs_headers)
    assert get_res.status_code == 200
    assert get_res.json()["title"] == "Remediation Document"

    # Search returns hit before deactivation
    store = test_env["k_store"]
    hits_before = store.query_lexical("zero-day vulnerability")
    assert len(hits_before) >= 1

    # Deactivate source
    deact_res = client.post(f"/api/knowledge/sources/{source_id}/deactivate", headers=op_headers)
    assert deact_res.status_code == 200
    assert deact_res.json()["status"] == "DEACTIVATED"

    # Verify chunks purged from FTS5 index
    hits_after = store.query_lexical("zero-day vulnerability")
    assert len(hits_after) == 0


def test_partial_extraction_status_truthfulness(test_env):
    """Verify PDF with empty pages returns truthful PARTIAL status via API."""
    client = test_env["client"]
    op_headers = {"Authorization": f"Bearer {test_env['op_token']}"}

    pdf_bytes = _build_test_pdf([
        "Page 1: Valid content",
        "",  # Empty Page 2
    ])

    res = client.post(
        "/api/knowledge/sources/upload",
        headers=op_headers,
        files={"file": ("partial.pdf", pdf_bytes, "application/pdf")},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "PARTIAL"
    assert data["page_count"] == 2
    assert data["pages_with_text"] == 1
    assert data["empty_pages"] == [2]
    assert data["chunk_count"] == 1


def test_retry_behavior(test_env):
    """Verify POST /api/knowledge/sources/{source_id}/retry re-indexes updated source."""
    client = test_env["client"]
    op_headers = {"Authorization": f"Bearer {test_env['op_token']}"}
    imports_dir = test_env["imports_dir"]

    # 1. Place initial file and import it
    test_file = imports_dir / "retry_guide.md"
    test_file.write_text("# Initial Version\nInitial content for testing retry.")
    res_import = client.post(
        "/api/knowledge/sources/import",
        headers=op_headers,
        json={"relative_path": "retry_guide.md", "title": "Retry Guide"},
    )
    assert res_import.status_code == 200
    source_id = res_import.json()["source_id"]

    # 2. Modify source file content
    test_file.write_text("# Updated Version\nUpdated and expanded content for testing retry.")

    # 3. Trigger retry
    res_retry = client.post(
        f"/api/knowledge/sources/{source_id}/retry",
        headers=op_headers,
    )
    assert res_retry.status_code == 200
    retry_data = res_retry.json()
    assert retry_data["status"] == "INDEXED"

    # Verify updated content is searchable
    store = test_env["k_store"]
    hits = store.query_lexical("expanded content")
    assert len(hits) >= 1

    # 4. Retry on non-existent source returns 404
    res_bad = client.post(
        "/api/knowledge/sources/NON_EXISTENT/retry",
        headers=op_headers,
    )
    assert res_bad.status_code == 404
