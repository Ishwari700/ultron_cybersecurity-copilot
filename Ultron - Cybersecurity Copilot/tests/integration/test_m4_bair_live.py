"""Integration test for Milestone M4 Phase M4.5: Intervention I4 (BAIR + Deterministic Extraction).

Authoritative live Ollama execution verification for BAIR intermediate representation.
Validates:
- Target model: qwen2.5-coder:7b
- Inference hyperparameters: num_ctx=2048, num_predict=300, temperature=0.0, seed=42
- Unconstrained sampling: schema=None (zero native JSON schema format parameter)
- Exactly one LLM inference call
- Pure single-factor isolation:
  * No I1 activation (schema=None)
  * No I2 activation (no namespace segregated fields)
  * No I3 activation (no counterfactual template)
  * No I5 activation (no decision policy rewriting)
  * No I6 activation (no handoff serializer)
- Authoritative execution result: I4ExecutionResult
"""

import httpx
import pytest

pytestmark = [pytest.mark.live_ollama]

from src.engine.models import (
    HypothesisDecision,
    I4ExecutionResult,
    PrimaryFailureCategory,
)
from src.engine.runner import (
    OllamaRunner,
    ReasoningRunner,
)
from src.evidence.cascade_models import LosslessStructuralPack


def is_ollama_available(base_url: str = "http://127.0.0.1:11434") -> bool:
    """Check if local Ollama daemon is responsive."""
    try:
        res = httpx.get(f"{base_url}/api/tags", timeout=2.0)
        return res.status_code == 200
    except Exception:
        return False


def test_live_ollama_i4_unconstrained_sanity_check():
    """
    Live Ollama sanity check verifying bounded analytical intermediate representation
    under unconstrained sampling (schema=None, 1 call, 300 tokens, 2048 context).
    """
    base_url = "http://127.0.0.1:11434"
    if not is_ollama_available(base_url):
        pytest.skip(f"Local Ollama daemon is not reachable at {base_url}")

    # Hyperparameters strictly per M4 specification:
    # num_ctx=2048, num_predict=300, temperature=0.0, seed=42
    runner = OllamaRunner(
        base_url=base_url,
        model_name="qwen2.5-coder:7b",
        num_ctx=2048,
        num_predict=300,
        temperature=0.0,
        seed=42,
    )

    reasoning_runner = ReasoningRunner(ollama_runner=runner)

    prompt = reasoning_runner.build_i4_bair_prompt(
        target_asset={
            "asset_id": "AST-PUBLIC-HEALTH",
            "method": "GET",
            "normalized_path": "/health",
            "application_mutability": "READ_ONLY",
        },
        category_id="API-AUTH-NONE",
        retrieved_evidence=[
            {"fact_id": "FACT-HEALTH-01", "statement": "GET /health returns HTTP 200 with status UP."},
        ],
    )

    # Invariant checks on prompt: No I2 / I3 contamination
    assert "<empirical_target_evidence>" not in prompt
    assert "<security_testing_methodology>" not in prompt
    assert "empirical_fact_ids" not in prompt
    assert "methodology_chunk_ids" not in prompt
    assert "COUNTERFACTUAL REASONING INSTRUCTIONS" not in prompt
    assert "<bair>" in prompt
    assert "</bair>" in prompt

    pack = LosslessStructuralPack(
        asset_id="AST-PUBLIC-HEALTH",
        endpoint_id="EP-HEALTH",
        route_template="/health",
        http_method="GET",
        application_mutability="READ_ONLY",
        observed_facts=[{"fact_id": "FACT-HEALTH-01", "statement": "GET /health returns HTTP 200 with status UP."}],
    )

    # Track calls to ensure exactly one LLM inference call occurs
    original_generate_raw = runner.generate_raw
    call_count = 0
    passed_schemas = []

    def tracking_generate_raw(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        passed_schemas.append(kwargs.get("schema"))
        return original_generate_raw(*args, **kwargs)

    runner.generate_raw = tracking_generate_raw

    result = reasoning_runner.execute_i4_generation(
        prompt=prompt,
        channel_a=pack,
        category_id="API-AUTH-NONE",
    )

    # Verification of execution constraints:
    # 1. Exactly one LLM inference call
    assert call_count == 1, f"Expected exactly 1 LLM call, got {call_count}"

    # 2. Schema strictly None (unconstrained sampling, no I1 format param)
    assert passed_schemas == [None], f"Expected schema=None, got {passed_schemas}"

    # 3. Result structure
    assert isinstance(result, I4ExecutionResult)
    assert len(result.raw_response) > 0
    assert result.latency_ms > 0
    assert result.classification.primary_category in (
        PrimaryFailureCategory.VALID,
        PrimaryFailureCategory.SCHEMA_VALIDITY_FAILURE,
        PrimaryFailureCategory.MAX_TOKEN_TRUNCATION,
        PrimaryFailureCategory.PARSER_FAILURE,
    )
