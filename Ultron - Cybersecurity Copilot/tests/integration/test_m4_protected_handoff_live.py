"""Integration test for Milestone M4 Phase M4.7: Intervention I6 (Protected 3B -> 7B Invariant Handoff).

Authoritative live Ollama execution verification for protected invariant handoff.
Validates:
- Target model: qwen2.5-coder:7b
- Local Ollama v0.34.1
- Inference hyperparameters: num_ctx=2048, num_predict=300, temperature=0.0, seed=42
- Unconstrained sampling: schema=None (zero native JSON schema format parameter)
- Exactly ONE LLM inference call (no second LLM arbitration)
- Pure single-factor isolation:
  * No I1 activation (schema=None)
  * No I2 activation (no namespace segregated fields)
  * No I3 activation (no counterfactual template)
  * No I4 activation (no BAIR prompt / extractor)
  * No I5 activation (no deterministic decision policy)
  * I6 ON: protected invariant handoff serialized in Partition P3
- Captures:
  * serialized handoff
  * handoff hash
  * invariant
  * EvidenceGapType
  * latency, call count
- Authoritative execution result: I6ExecutionResult
"""

import httpx
import pytest

pytestmark = [pytest.mark.live_ollama]

from src.engine.models import (
    I6ExecutionResult,
    PrimaryFailureCategory,
)
from src.engine.handoff_serializer import (
    HandoffSerializer,
    ProtectedHandoffDescriptor,
)
from src.knowledge.models import EvidenceGapType
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


def test_live_ollama_i6_unconstrained_sanity_check():
    """
    Live Ollama sanity check verifying protected 3B -> 7B invariant handoff
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

    target_asset = {
        "asset_id": "AST-PUBLIC-HEALTH",
        "method": "GET",
        "normalized_path": "/health",
        "application_mutability": "READ_ONLY",
    }
    retrieved_evidence = [
        {"fact_id": "FACT-HEALTH-01", "statement": "GET /health returns HTTP 200 with status UP."},
    ]

    pack = LosslessStructuralPack(
        asset_id="AST-PUBLIC-HEALTH",
        endpoint_id="EP-HEALTH",
        route_template="/health",
        http_method="GET",
        application_mutability="READ_ONLY",
        observed_facts=[{"fact_id": "FACT-HEALTH-01", "statement": "Health check ok"}],
    )

    # Construct protected handoff descriptor
    protected_handoff = HandoffSerializer.serialize(
        invariant="Unauthenticated health endpoints must not leak internal system topology",
        evidence_gap_type=EvidenceGapType.MISSING_UNAUTHENTICATED_ACCESS_CHECK,
        class1_predicates=pack,
    )

    prompt = reasoning_runner.build_i6_handoff_prompt(
        target_asset=target_asset,
        protected_handoff=protected_handoff,
        category_id="API-AUTH-NONE",
        retrieved_evidence=retrieved_evidence,
    )

    # Invariant checks on prompt: Strict single-factor isolation
    assert "<empirical_target_evidence>" not in prompt
    assert "<security_testing_methodology>" not in prompt
    assert "empirical_fact_ids" not in prompt
    assert "methodology_chunk_ids" not in prompt
    assert "COUNTERFACTUAL REASONING INSTRUCTIONS" not in prompt
    assert "<bair>" not in prompt
    assert "</bair>" not in prompt
    assert "CALIBRATED ABSTENTION CONTRACT" not in prompt
    # I6 protected handoff presence
    assert "=== PROTECTED 3B -> 7B INVARIANT HANDOFF (PARTITION P3) ===" in prompt
    assert protected_handoff.handoff_hash in prompt
    assert "EVIDENCE_GAP_TYPE: MISSING_UNAUTHENTICATED_ACCESS_CHECK" in prompt

    # Live execution: Exactly ONE 7B inference call with schema=None
    result = reasoning_runner.execute_i6_generation(
        prompt=prompt,
        protected_handoff=protected_handoff,
        retrieved_evidence=retrieved_evidence,
        channel_a=pack,
        target_asset=target_asset,
        category_id="API-AUTH-NONE",
    )

    # Assertions on result
    assert isinstance(result, I6ExecutionResult)
    assert result.latency_ms > 0
    assert result.serialized_handoff == protected_handoff.serialized_handoff
    assert result.handoff_hash == protected_handoff.handoff_hash
    assert result.invariant == protected_handoff.invariant
    assert result.evidence_gap_type == "MISSING_UNAUTHENTICATED_ACCESS_CHECK"
    assert result.classification is not None
    assert result.raw_response != ""

    # Verify no secret or ground-truth leakage into handoff or prompt
    assert "cookie" not in result.serialized_handoff.lower()
    assert "is_vulnerable" not in result.serialized_handoff.lower()
    assert "ground_truth" not in result.serialized_handoff.lower()
