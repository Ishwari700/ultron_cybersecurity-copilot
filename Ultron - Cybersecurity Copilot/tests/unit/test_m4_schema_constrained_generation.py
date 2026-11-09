"""Unit and integration tests for Milestone M4 Phase M4.2:
Intervention I1 — Schema-Constrained Structured Generation & Fail-Closed Validation.

Tests all 12 core requirements:
1. Schema object generation from S0.
2. Native Ollama format:{...} request formation.
3. Strict JSON parsing.
4. Typed schema validation.
5. Fail-closed behavior.
6. Truncation classification.
7. Parser classification.
8. Schema validity classification.
9. Runtime transport classification.
10. Semantic grounding classification separation.
11. DIAGNOSTIC_ONLY repair isolation.
12. Confirmation authority remaining outside reasoning engine.
"""

import json
import os
from typing import Any, Dict, List
import httpx
import pytest
from pydantic import ValidationError

from src.engine.models import (
    FailureClassificationResult,
    HypothesisDecision,
    HypothesisModelOutput,
    I1ExecutionResult,
    PrimaryFailureCategory,
    classify_primary_failure,
    perform_diagnostic_repair,
)
from src.engine.runner import (
    PRIMARY_KEEP_ALIVE,
    PRIMARY_NUM_CTX,
    PRIMARY_NUM_PREDICT,
    PRIMARY_SEED,
    PRIMARY_TEMPERATURE,
    OllamaRunner,
    ReasoningRunner,
)
from src.knowledge.grounding_validator import KnowledgeGroundingValidator


# ---------------------------------------------------------------------------
# Requirement 1: Schema object generation from S0
# ---------------------------------------------------------------------------

def test_01_schema_object_generation_from_s0():
    """Verify S0 canonical schema object generation matches M4 specification."""
    schema = HypothesisModelOutput.get_inference_schema()

    assert isinstance(schema, dict)
    assert schema.get("type") == "object"
    assert "properties" in schema
    assert "required" in schema

    expected_canonical_fields = [
        "invariant",
        "evidence_gap",
        "affected_target",
        "decision",
        "supporting_evidence_ids",
        "methodology_references",
        "reasoning_summary",
        "experiment_proposal",
    ]

    # All 8 canonical fields must be present and required
    for field in expected_canonical_fields:
        assert field in schema["properties"], f"Field '{field}' missing from S0 properties"
        assert field in schema["required"], f"Field '{field}' missing from S0 required list"

    # Verify decision enum values
    decision_prop = schema["properties"]["decision"]
    assert decision_prop["type"] == "string"
    assert set(decision_prop["enum"]) == {
        "NO_RELEVANT_FUNCTIONALITY",
        "INSUFFICIENT_EVIDENCE",
        "HYPOTHESIS",
    }
    assert "CONFIRMED" not in decision_prop["enum"]

    # Verify array types for citations
    assert schema["properties"]["supporting_evidence_ids"]["type"] == "array"
    assert schema["properties"]["supporting_evidence_ids"]["items"]["type"] == "string"
    assert schema["properties"]["methodology_references"]["type"] == "array"
    assert schema["properties"]["methodology_references"]["items"]["type"] == "string"

    # Verify NO I2 regex constraints are present in S0 (pure I1 single-factor isolation)
    assert "pattern" not in schema["properties"]["supporting_evidence_ids"].get("items", {})
    assert "pattern" not in schema["properties"]["methodology_references"].get("items", {})

    # Verify NO field-length compaction or word limits exist (Option A clean boundary)
    assert "maxLength" not in schema["properties"]["reasoning_summary"]
    assert "maxLength" not in schema["properties"]["experiment_proposal"]
    assert "maxItems" not in schema["properties"]["supporting_evidence_ids"]


# ---------------------------------------------------------------------------
# Requirement 2: Native Ollama format:{...} request formation
# ---------------------------------------------------------------------------

def test_02_native_ollama_format_request_formation(monkeypatch):
    """Verify native Ollama format parameter and primary compute envelope options."""
    captured_payloads: List[Dict[str, Any]] = []

    def mock_post(self, url, *args, **kwargs):
        captured_payloads.append(kwargs.get("json"))
        return httpx.Response(
            status_code=200,
            json={
                "response": json_dumps_valid_s0(),
                "eval_count": 120,
                "prompt_eval_count": 80,
                "done_reason": "stop",
            },
        )

    monkeypatch.setattr(httpx.Client, "post", mock_post)

    runner = ReasoningRunner()
    result = runner.execute_i1_generation(prompt="Evaluate target security invariant.")

    assert len(captured_payloads) == 1
    payload = captured_payloads[0]

    # Native format:{...} structured schema passing
    assert "format" in payload
    assert isinstance(payload["format"], dict)
    assert "properties" in payload["format"]
    assert "decision" in payload["format"]["properties"]

    # Fixed Primary Compute Envelope parameters
    opts = payload.get("options", {})
    assert opts.get("num_ctx") == PRIMARY_NUM_CTX  # 2048
    assert opts.get("num_predict") == PRIMARY_NUM_PREDICT  # 300
    assert opts.get("temperature") == PRIMARY_TEMPERATURE  # 0.0
    assert opts.get("seed") == PRIMARY_SEED  # 42
    assert payload.get("keep_alive") == PRIMARY_KEEP_ALIVE  # 60m
    assert payload.get("stream") is False


# ---------------------------------------------------------------------------
# Requirement 3: Strict JSON parsing
# ---------------------------------------------------------------------------

def test_03_strict_json_parsing():
    """Verify strict JSON decoding succeeds on valid JSON and fails on malformed/truncated syntax."""
    valid_raw = json_dumps_valid_s0()
    parsed = json.loads(valid_raw)
    assert isinstance(parsed, dict)
    assert parsed["decision"] == "HYPOTHESIS"

    # Unterminated string (classic 300-token truncation syntax breakdown)
    truncated_raw = '{"decision": "HYPOTHESIS", "reasoning_summary": "Truncated mid-senten'
    with pytest.raises(json.JSONDecodeError):
        json.loads(truncated_raw)

    # Malformed non-JSON syntax
    malformed_raw = "I am an AI assistant and I believe this endpoint is secure."
    with pytest.raises(json.JSONDecodeError):
        json.loads(malformed_raw)


# ---------------------------------------------------------------------------
# Requirement 4: Typed schema validation
# ---------------------------------------------------------------------------

def test_04_typed_schema_validation():
    """Verify Pydantic validation over S0 canonical model and fail-closed rejection on invalid schema."""
    valid_dict = {
        "decision": "HYPOTHESIS",
        "invariant": "Account balance must only be readable by authorized owner",
        "evidence_gap": "Missing cross-tenant read attempt with unauthorized credentials",
        "affected_target": "/api/v1/accounts/{id}/balance",
        "supporting_evidence_ids": ["FACT-01", "FACT-02"],
        "methodology_references": ["CHK-DOC-API-AUTH-01"],
        "reasoning_summary": "Endpoint lacks ownership checks in handler logic.",
        "experiment_proposal": "Replay GET request with user B token targeting user A account.",
    }
    model = HypothesisModelOutput.model_validate(valid_dict)
    assert model.decision == HypothesisDecision.HYPOTHESIS
    assert model.invariant.startswith("Account balance")
    assert model.supporting_evidence_ids == ["FACT-01", "FACT-02"]

    # Missing mandatory decision field
    invalid_no_decision = dict(valid_dict)
    del invalid_no_decision["decision"]
    with pytest.raises(ValidationError):
        HypothesisModelOutput.model_validate(invalid_no_decision)

    # Invalid decision enum value
    invalid_enum_decision = dict(valid_dict, decision="UNKNOWN_STATE")
    with pytest.raises(ValidationError):
        HypothesisModelOutput.model_validate(invalid_enum_decision)

    # Invalid type for supporting_evidence_ids (dict instead of list)
    invalid_type = dict(valid_dict, supporting_evidence_ids={"fact": "FACT-01"})
    with pytest.raises(ValidationError):
        HypothesisModelOutput.model_validate(invalid_type)


# ---------------------------------------------------------------------------
# Requirement 5: Fail-closed behavior
# ---------------------------------------------------------------------------

def test_05_fail_closed_behavior(monkeypatch):
    """Verify fail-closed behavior: invalid outputs yield None hypothesis with zero synthetic injection."""
    def mock_post(self, url, *args, **kwargs):
        return httpx.Response(
            status_code=200,
            json={
                "response": '{"broken_json": true, "reasoning": "unterminated',
                "eval_count": 300,
                "done_reason": "length",
            },
        )

    monkeypatch.setattr(httpx.Client, "post", mock_post)

    runner = ReasoningRunner()
    result = runner.execute_i1_generation(prompt="Evaluate target security invariant.")

    # Must fail closed: hypothesis is strictly None
    assert result.hypothesis is None
    assert result.classification.is_valid is False
    assert result.classification.primary_category == PrimaryFailureCategory.MAX_TOKEN_TRUNCATION
    # Must NOT manufacture missing fields or convert to HYPOTHESIS
    assert result.parsed_json is None


# ---------------------------------------------------------------------------
# Requirement 6: Truncation classification
# ---------------------------------------------------------------------------

def test_06_truncation_classification():
    """Verify MAX_TOKEN_TRUNCATION deterministic classification and parser failure cascade."""
    res = classify_primary_failure(
        raw_response='{"decision": "HYPOTHESIS", "reasoning_summary": "Cut off mid-',
        eval_count=300,
        done_reason="length",
        num_predict=300,
        parsed_json=None,
        parse_error=json.JSONDecodeError("Unterminated string", "doc", 45),
    )

    assert res.primary_category == PrimaryFailureCategory.MAX_TOKEN_TRUNCATION
    assert res.is_valid is False
    # Precedence: Truncation subsumes downstream parser failure into cascade
    assert PrimaryFailureCategory.PARSER_FAILURE.value in res.downstream_cascade


# ---------------------------------------------------------------------------
# Requirement 7: Parser classification
# ---------------------------------------------------------------------------

def test_07_parser_classification():
    """Verify PARSER_FAILURE classification when syntax is broken without truncation."""
    res = classify_primary_failure(
        raw_response="Unparseable natural language text emitted by unconstrained model",
        eval_count=120,  # Well below 300 token ceiling
        done_reason="stop",
        num_predict=300,
        parsed_json=None,
        parse_error=json.JSONDecodeError("Expecting value", "doc", 0),
    )

    assert res.primary_category == PrimaryFailureCategory.PARSER_FAILURE
    assert res.is_valid is False
    assert res.downstream_cascade == []


# ---------------------------------------------------------------------------
# Requirement 8: Schema validity classification
# ---------------------------------------------------------------------------

def test_08_schema_validity_classification():
    """Verify SCHEMA_VALIDITY_FAILURE classification when JSON is syntactically valid but schema-invalid."""
    res = classify_primary_failure(
        raw_response='{"invalid_field": 123}',
        eval_count=50,
        done_reason="stop",
        num_predict=300,
        parsed_json={"invalid_field": 123},
        parse_error=None,
        schema_error=ValidationError.from_exception_data(
            "HypothesisModelOutput",
            [{"type": "missing", "loc": ("decision",), "msg": "Field required", "input": {}}],
        ),
    )

    assert res.primary_category == PrimaryFailureCategory.SCHEMA_VALIDITY_FAILURE
    assert res.is_valid is False
    assert res.downstream_cascade == []


# ---------------------------------------------------------------------------
# Requirement 9: Runtime transport classification
# ---------------------------------------------------------------------------

def test_09_runtime_transport_classification():
    """Verify RUNTIME_TRANSPORT_FAILURE classification trumps all other categories."""
    transport_exc = httpx.ConnectError("Connection refused at 127.0.0.1:11434")

    res = classify_primary_failure(
        transport_error=transport_exc,
        eval_count=300,
        num_predict=300,
    )

    # Precedence rule: Transport failure trumps truncation, parser, and schema
    assert res.primary_category == PrimaryFailureCategory.RUNTIME_TRANSPORT_FAILURE
    assert res.is_valid is False


# ---------------------------------------------------------------------------
# Requirement 10: Semantic grounding classification separation
# ---------------------------------------------------------------------------

def test_10_semantic_grounding_classification_separation(monkeypatch):
    """Verify SEMANTIC_GROUNDING_FAILURE is classified separately from syntactic parser/schema failures."""
    # Output is 100% valid JSON and conforms to S0 schema, but breaches epistemic namespace
    namespace_breach_dict = {
        "decision": "HYPOTHESIS",
        "invariant": "Object ID isolation invariant",
        "evidence_gap": "Missing auth verification",
        "affected_target": "/api/v1/invoices/{id}",
        "supporting_evidence_ids": ["CHK-DOC-VAPT-001"],  # ILLEGAL CHK in supporting evidence
        "methodology_references": ["CHK-DOC-VAPT-001"],
        "reasoning_summary": "Cited VAPT guidance inside evidence field.",
        "experiment_proposal": "Replay request with alternate token.",
    }

    def mock_post(self, url, *args, **kwargs):
        return httpx.Response(
            status_code=200,
            json={
                "response": json.dumps(namespace_breach_dict),
                "eval_count": 85,
                "done_reason": "stop",
            },
        )

    monkeypatch.setattr(httpx.Client, "post", mock_post)

    validator = KnowledgeGroundingValidator()
    runner = ReasoningRunner()
    result = runner.execute_i1_generation(
        prompt="Evaluate invariant.",
        grounding_validator=validator,
    )

    # Must be classified strictly as SEMANTIC_GROUNDING_FAILURE
    assert result.classification.primary_category == PrimaryFailureCategory.SEMANTIC_GROUNDING_FAILURE
    assert result.classification.is_valid is False
    assert result.hypothesis is None  # Fails closed on semantic grounding breach


# ---------------------------------------------------------------------------
# Requirement 11: DIAGNOSTIC_ONLY repair isolation
# ---------------------------------------------------------------------------

def test_11_diagnostic_repair_isolation():
    """Verify diagnostic repair is isolated, non-authoritative, and cannot upgrade invalid outputs."""
    raw_invalid = {
        "supporting_evidence_ids": ["EVIDENCE [FACT-01]", "[FACT-02]", "EVIDENCE-FACT-03"],
        "reasoning_summary": "Some rationale without decision or target",
    }

    diag = perform_diagnostic_repair(
        raw_dict=raw_invalid,
        target_asset={"asset_id": "ASSET-101"},
        category_id="API-BOLA-001",
    )

    assert diag["diagnostic_only"] is True
    assert "injected_affected_target_from_context" in diag["repairs_applied"]
    assert "defaulted_missing_decision_to_abstention" in diag["repairs_applied"]
    assert diag["repaired_dict"]["supporting_evidence_ids"] == ["FACT-01", "FACT-02", "FACT-03"]

    # Verify that diagnostic repair does NOT mutate or upgrade raw classification
    classification = classify_primary_failure(
        parsed_json=raw_invalid,
        schema_error=ValidationError.from_exception_data(
            "HypothesisModelOutput",
            [{"type": "missing", "loc": ("decision",), "msg": "Field required", "input": {}}],
        ),
    )
    assert classification.is_valid is False
    assert classification.primary_category == PrimaryFailureCategory.SCHEMA_VALIDITY_FAILURE


# ---------------------------------------------------------------------------
# Requirement 12: Confirmation authority remaining outside reasoning engine
# ---------------------------------------------------------------------------

def test_12_confirmation_authority_remaining_outside_reasoning_engine():
    """Verify CONFIRMED is rejected across Pydantic, Grounding Validator, and Reasoning Runner."""
    # 1. HypothesisDecision enum does not contain CONFIRMED
    with pytest.raises(ValueError):
        HypothesisDecision("CONFIRMED")

    # 2. Pydantic validation fails closed on CONFIRMED emission
    with pytest.raises(ValidationError):
        HypothesisModelOutput(
            decision="CONFIRMED",  # type: ignore[arg-type]
            reasoning_summary="Attempted forbidden confirmation emission",
        )

    # 3. Grounding validator detects and rejects CONFIRMED status
    validator = KnowledgeGroundingValidator()
    hypo_dict = {
        "decision": "CONFIRMED",
        "supporting_evidence_ids": ["FACT-01"],
        "reasoning_summary": "Claiming vulnerability confirmed",
    }
    g_res = validator.validate_grounding(hypo_dict)
    assert g_res.valid is False
    assert g_res.status == "DISCARD"
    assert g_res.error_code == "ZERO_CONFIRMATION_AUTHORITY_VIOLATION"


# ---------------------------------------------------------------------------
# Requirement 13: Lightweight Live Ollama Sanity Check
# ---------------------------------------------------------------------------

@pytest.mark.live_ollama
@pytest.mark.skipif(
    os.environ.get("SKIP_LIVE_OLLAMA") == "1",
    reason="Live Ollama execution skipped by environment flag",
)
def test_13_live_ollama_runtime_capability_sanity_check():
    """Lightweight live sanity check verifying pinned native Ollama structured decoding on S0."""
    runner = ReasoningRunner()
    if not runner.ollama_runner.is_available():
        pytest.skip("Local Ollama daemon not currently reachable at 127.0.0.1:11434")

    prompt = (
        "SYSTEM SECURITY POLICY:\n"
        "You are an evidence-grounded security reasoning engine.\n"
        "Analyze the provided canonical evidence to evaluate potential security invariant violations.\n\n"
        "<empirical_target_evidence>\n"
        "FACT-01: Endpoint GET /api/v1/users/{id}/profile returns user profile data.\n"
        "FACT-02: User A token accessing User A profile returns HTTP 200 with User A data.\n"
        "</empirical_target_evidence>\n\n"
        "Evaluate whether an invariant violation exists."
    )

    result = runner.execute_i1_generation(prompt=prompt)

    # Verify that live Ollama executes native format decoding
    assert result.latency_ms > 0.0
    assert result.classification.primary_category in [
        PrimaryFailureCategory.VALID,
        PrimaryFailureCategory.MAX_TOKEN_TRUNCATION,
    ]
    if result.classification.is_valid:
        assert result.hypothesis is not None
        assert result.hypothesis.decision in [
            HypothesisDecision.NO_RELEVANT_FUNCTIONALITY,
            HypothesisDecision.INSUFFICIENT_EVIDENCE,
            HypothesisDecision.HYPOTHESIS,
        ]


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def json_dumps_valid_s0() -> str:
    """Return serialized valid S0 JSON string."""
    return json.dumps({
        "decision": "HYPOTHESIS",
        "invariant": "Only account owner may access account invoice data",
        "evidence_gap": "Missing cross-tenant verification request",
        "affected_target": "/api/v1/invoices/{id}",
        "supporting_evidence_ids": ["FACT-SAAS_BILLING-01"],
        "methodology_references": ["CHK-DOC-METHODOLOGY-01"],
        "reasoning_summary": "Invoice route does not verify requesting identity against invoice owner.",
        "experiment_proposal": "Send GET request with user B credentials to invoice owned by user A.",
    })
