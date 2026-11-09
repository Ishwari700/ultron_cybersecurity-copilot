"""Unit tests for Observation Adapters (Burp, Reqable, PCAPdroid, OpenAPI, GenericHttp)."""

from src.evidence.adapters.burp import BurpAdapter
from src.evidence.adapters.generic_http import GenericHttpAdapter
from src.evidence.adapters.openapi import OpenApiAdapter
from src.evidence.adapters.pcapdroid import PCAPdroidAdapter
from src.evidence.adapters.reqable import ReqableAdapter
from src.evidence.models import EpistemicCertainty


def test_generic_http_adapter():
    """Verify GenericHttpAdapter produces normalized CanonicalEvidence."""
    adapter = GenericHttpAdapter()
    raw = {
        "method": "POST",
        "url": "https://api.target.com/v1/invoices/1024?action=pay",
        "request_headers": {"Authorization": "Bearer sensitive_token_123"},
        "request_body": '{"amount": 100}',
        "response_status": 200,
        "response_headers": {"Content-Type": "application/json"},
        "response_body": '{"status": "paid"}',
        "source_tool": "httpx",
    }
    evidence_list = adapter.ingest(raw, scope_decision_id="SCOPE-123")

    assert len(evidence_list) == 1
    ev = evidence_list[0]
    assert ev.http_method == "POST"
    assert ev.raw_path == "/v1/invoices/1024"
    assert ev.normalized_path == "/v1/invoices/{id}"
    assert ev.application_mutability == "STATE_CHANGING"
    assert ev.certainty == EpistemicCertainty.OBSERVED
    assert ev.scope_decision_id == "SCOPE-123"

    # Verify query and path parameter extraction
    param_names = {p.param_name for p in ev.parameters}
    assert "action" in param_names
    assert "id" in param_names


def test_burp_adapter():
    """Verify BurpAdapter ingests Burp Suite proxy item exports."""
    adapter = BurpAdapter()
    raw = [
        {
            "host": "api.target.com",
            "method": "GET",
            "path": "/api/v1/profile",
            "status": 200,
            "request": "GET /api/v1/profile HTTP/1.1\nHost: api.target.com",
            "response": '{"user": "alice", "email": "alice@target.com"}',
        }
    ]
    evidence_list = adapter.ingest(raw)

    assert len(evidence_list) == 1
    ev = evidence_list[0]
    assert ev.source_tool == "burp"
    assert ev.application_mutability == "READ_ONLY"
    assert ev.asset_id.startswith("ASSET-")


def test_reqable_adapter():
    """Verify ReqableAdapter ingests HAR logs."""
    adapter = ReqableAdapter()
    har_log = {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "https://api.target.com/v2/orders",
                        "headers": [{"name": "Accept", "value": "application/json"}],
                    },
                    "response": {
                        "status": 200,
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                        "content": {"text": '{"orders": []}'},
                    },
                }
            ]
        }
    }
    evidence_list = adapter.ingest(har_log)

    assert len(evidence_list) == 1
    ev = evidence_list[0]
    assert ev.source_tool == "reqable"
    assert ev.normalized_path == "/v2/orders"
    assert ev.request_headers.get("Accept") == "application/json"


def test_pcapdroid_adapter():
    """Verify PCAPdroidAdapter ingests mobile flow logs."""
    adapter = PCAPdroidAdapter()
    flows = [
        {
            "host": "mobile.target.com",
            "path": "/api/mobile/config",
            "method": "GET",
            "status_code": 200,
            "response_payload": '{"version": "1.2.0"}',
        }
    ]
    evidence_list = adapter.ingest({"flows": flows})

    assert len(evidence_list) == 1
    ev = evidence_list[0]
    assert ev.source_tool == "pcapdroid"
    assert ev.host == "mobile.target.com"


def test_openapi_adapter():
    """Verify OpenApiAdapter generates DOCUMENTED facts with parameters and security."""
    adapter = OpenApiAdapter()
    openapi_spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "https://api.target.com/v1"}],
        "paths": {
            "/users/{userId}": {
                "get": {
                    "summary": "Retrieve user profile",
                    "parameters": [
                        {"name": "userId", "in": "path", "required": True, "schema": {"type": "string"}},
                        {"name": "fields", "in": "query", "schema": {"type": "string"}},
                    ],
                    "security": [{"bearerAuth": []}],
                    "responses": {"200": {"description": "OK"}, "403": {"description": "Forbidden"}},
                }
            }
        },
    }
    evidence_list = adapter.ingest(openapi_spec)

    assert len(evidence_list) == 1
    ev = evidence_list[0]
    assert ev.certainty == EpistemicCertainty.DOCUMENTED # Must be DOCUMENTED
    assert ev.liveness == "LIVE_DOCUMENTED"
    assert ev.http_method == "GET"
    assert ev.raw_path == "/users/{userId}"
    assert "userId" in [p.param_name for p in ev.parameters]
    assert "fields" in [p.param_name for p in ev.parameters]
    assert "auth_required" in ev.statement
