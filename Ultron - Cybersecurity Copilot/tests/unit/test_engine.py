"""Unit tests for reasoning engine, taxonomy filtering, and prompt budgeting."""

import json
from src.engine.models import HypothesisDecision, HypothesisModelOutput
from src.engine.runner import ReasoningRunner
from src.engine.taxonomy import ApplicabilityFilter


def test_applicability_filter():
    """Verify applicability filter skips endpoints without required structural properties."""
    filter_engine = ApplicabilityFilter()

    # Asset with object identifier
    asset_with_id = {
        "asset_id": "ASSET-1",
        "method": "GET",
        "raw_path": "/api/users/123",
        "normalized_path": "/api/users/{id}",
    }
    params_with_id = [{"param_name": "id", "location": "path", "param_type": "identifier"}]

    assert filter_engine.is_applicable("API-BOLA-001", asset_with_id, params_with_id) is True

    # Asset without object identifier
    asset_static = {
        "asset_id": "ASSET-2",
        "method": "GET",
        "raw_path": "/api/health",
        "normalized_path": "/api/health",
    }
    params_empty = []
    assert filter_engine.is_applicable("API-BOLA-001", asset_static, params_empty) is False


def test_reasoning_runner_prompt_and_mock_inference():
    """Verify prompt formatting and structured JSON schema output."""
    mock_output = {
        "app_model_delta": {
            "observation": "Endpoint allows invoice fetching. Identity A accesses it. Missing test: Identity B access.",
            "epistemic_status": "MODEL_PROPOSED",
        },
        "violation_assessment": {
            "relation": "SUPPORTED",
            "evidence_ids": ["FACT-01"],
        },
        "decision": "HYPOTHESIS",
        "category": "API-BOLA-001",
        "asset_id": "ASSET-101",
        "parameter_ids": ["PARAM-01"],
        "actor_identity_id": "user_a",
        "target_identity_id": "user_b_victim",
        "missing_evidence": ["Cross-tenant test"],
        "supporting_evidence_ids": ["FACT-01"],
        "contradicting_evidence_ids": [],
        "evidence_sufficiency": 0.6,
    }

    def mock_llm_call(prompt: str, schema: dict) -> str:
        assert "CRITICAL INVARIANTS" in prompt
        assert "EVIDENCE [FACT-01]" in prompt
        return json.dumps(mock_output)

    runner = ReasoningRunner(llm_caller=mock_llm_call)
    target_asset = {
        "asset_id": "ASSET-101",
        "method": "GET",
        "normalized_path": "/invoices/{id}",
        "application_mutability": "READ_ONLY",
    }
    retrieved = [
        {"fact_id": "FACT-01", "source_tool": "burp", "trust": "UNTRUSTED", "statement": "GET /invoices/100 returned 200"}
    ]

    result = runner.run(target_asset, "API-BOLA-001", retrieved)
    assert result.decision == HypothesisDecision.HYPOTHESIS
    assert result.app_model_delta.observation.startswith("Endpoint allows")
    assert result.actor_identity_id == "user_a"
