"""Unit tests for Milestone M4 Phase M4.3: Intervention I2 (Epistemic Namespace Segregation & Validation).

Verifies all 18 pre-registered requirements for Intervention I2:
1. Raw I2 schema uses empirical_fact_ids.
2. Raw I2 schema uses methodology_chunk_ids.
3. FACT regex accepted.
4. CHK regex accepted.
5. CHK in empirical_fact_ids rejected.
6. FACT in methodology_chunk_ids rejected.
7. Validator catches cross-namespace output.
8. Validator Bypass Rate cannot occur (0.0%).
9. Adapter maps empirical_fact_ids exactly to supporting_evidence_ids.
10. Adapter maps methodology_chunk_ids exactly to methodology_references.
11. Adapter performs zero semantic inference.
12. Adapter performs zero citation substitution.
13. Adapter fails closed on invalid namespace.
14. S0 downstream representation remains canonical.
15. I2 does not invoke I1 constrained decoding (unconstrained sampling).
16. Prompt partitions FACT and CHK epistemically (<empirical_target_evidence> and <security_testing_methodology>).
17. Existing KnowledgeGroundingValidator remains authoritative.
18. No fabricated IDs are introduced.
19. Lightweight live Ollama sanity check under unconstrained sampling.
"""

import json
import os
import re
from typing import Any, Dict
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from src.engine.context_builder import ReasoningContextBuilder, TRACK_D
from src.engine.models import (
    CHK_NAMESPACE_PATTERN,
    CHK_NAMESPACE_REGEX,
    FACT_NAMESPACE_PATTERN,
    FACT_NAMESPACE_REGEX,
    HypothesisDecision,
    HypothesisModelOutput,
    I2ExecutionResult,
    I2RawHypothesisOutput,
    PrimaryFailureCategory,
    adapt_i2_to_s0,
    check_raw_namespace_breach,
)
from src.engine.runner import OllamaRunner, ReasoningRunner
from src.evidence.cascade_models import (
    CascadeHandoffPacket,
    DeterministicRoutingDecision,
    LosslessStructuralPack,
)
from src.knowledge.grounding_validator import (
    KnowledgeGroundingResult,
    KnowledgeGroundingValidator,
)
from src.knowledge.models import (
    KnowledgeChunk,
    KnowledgeRetrievalItem,
    KnowledgeSourceType,
    KnowledgeType,
    VaptKnowledgePack,
)


def test_1_raw_i2_schema_uses_empirical_fact_ids():
    """Requirement 1: Raw I2 schema defines empirical_fact_ids with FACT regex."""
    schema = I2RawHypothesisOutput.get_raw_schema()
    props = schema["properties"]
    assert "empirical_fact_ids" in props
    assert "supporting_evidence_ids" not in props
    assert props["empirical_fact_ids"]["type"] == "array"
    assert props["empirical_fact_ids"]["items"]["pattern"] == FACT_NAMESPACE_PATTERN
    assert "empirical_fact_ids" in schema["required"]


def test_2_raw_i2_schema_uses_methodology_chunk_ids():
    """Requirement 2: Raw I2 schema defines methodology_chunk_ids with CHK regex."""
    schema = I2RawHypothesisOutput.get_raw_schema()
    props = schema["properties"]
    assert "methodology_chunk_ids" in props
    assert "methodology_references" not in props
    assert props["methodology_chunk_ids"]["type"] == "array"
    assert props["methodology_chunk_ids"]["items"]["pattern"] == CHK_NAMESPACE_PATTERN
    assert "methodology_chunk_ids" in schema["required"]


def test_3_fact_regex_accepted():
    """Requirement 3: FACT regex accepts valid empirical observation identifiers."""
    valid_facts = [
        "FACT-01",
        "FACT-AUTH-002",
        "FACT-PARAM-LINEAGE-03",
        "FACT-SIM-EXEC-01",
        "FACT-HTTP_DIFF_123",
    ]
    for fid in valid_facts:
        assert FACT_NAMESPACE_REGEX.match(fid) is not None, f"Expected {fid} to match FACT pattern"

    raw = I2RawHypothesisOutput(
        decision=HypothesisDecision.INSUFFICIENT_EVIDENCE,
        empirical_fact_ids=valid_facts,
        methodology_chunk_ids=[],
    )
    assert raw.empirical_fact_ids == valid_facts


def test_4_chk_regex_accepted():
    """Requirement 4: CHK regex accepts valid VAPT methodology identifiers."""
    valid_chunks = [
        "CHK-01",
        "CHK-DOC-ASVS-V4-01-001-01",
        "CHK-DOC-WSTG-ATHZ-04-002-01",
        "CHK-WSTG-INP-01",
        "CHK-CWE-285-001-01",
    ]
    for cid in valid_chunks:
        assert CHK_NAMESPACE_REGEX.match(cid) is not None, f"Expected {cid} to match CHK pattern"

    raw = I2RawHypothesisOutput(
        decision=HypothesisDecision.INSUFFICIENT_EVIDENCE,
        empirical_fact_ids=[],
        methodology_chunk_ids=valid_chunks,
    )
    assert raw.methodology_chunk_ids == valid_chunks


def test_5_chk_in_empirical_fact_ids_rejected():
    """Requirement 5: Placing a CHK ID in empirical_fact_ids is strictly rejected by schema."""
    with pytest.raises(ValidationError) as exc_info:
        I2RawHypothesisOutput(
            decision=HypothesisDecision.HYPOTHESIS,
            empirical_fact_ids=["CHK-DOC-WSTG-ATHZ-04-002-01"],
            methodology_chunk_ids=[],
        )
    err_str = str(exc_info.value)
    assert "INVALID_NAMESPACE_BREACH" in err_str


def test_6_fact_in_methodology_chunk_ids_rejected():
    """Requirement 6: Placing a FACT ID in methodology_chunk_ids is strictly rejected by schema."""
    with pytest.raises(ValidationError) as exc_info:
        I2RawHypothesisOutput(
            decision=HypothesisDecision.HYPOTHESIS,
            empirical_fact_ids=[],
            methodology_chunk_ids=["FACT-AUTH-001"],
        )
    err_str = str(exc_info.value)
    assert "INVALID_NAMESPACE_BREACH" in err_str


def test_7_validator_catches_cross_namespace_output():
    """Requirement 7: KnowledgeGroundingValidator catches cross-namespace emissions fail-closed."""
    validator = KnowledgeGroundingValidator()

    # CHK in supporting evidence
    hypo_bad_chk = HypothesisModelOutput(
        decision=HypothesisDecision.HYPOTHESIS,
        affected_target="AST-ORDERS-01",
        supporting_evidence_ids=["FACT-01", "CHK-DOC-WSTG-01"],
        methodology_references=[],
    )
    res_chk = validator.validate_grounding(hypo_bad_chk)
    assert res_chk.valid is False
    assert res_chk.status == "DISCARD"
    assert res_chk.error_code == "EPISTEMIC_CONFUSION_ERROR"
    assert res_chk.is_namespace_breach is True
    assert "INVALID_NAMESPACE_BREACH" in res_chk.reason

    # FACT in methodology
    hypo_bad_fact = HypothesisModelOutput(
        decision=HypothesisDecision.HYPOTHESIS,
        affected_target="AST-ORDERS-01",
        supporting_evidence_ids=["FACT-01"],
        methodology_references=["FACT-HTTP-002"],
    )
    res_fact = validator.validate_grounding(hypo_bad_fact)
    assert res_fact.valid is False
    assert res_fact.status == "DISCARD"
    assert res_fact.error_code == "EPISTEMIC_CONFUSION_ERROR"
    assert res_fact.is_namespace_breach is True
    assert "INVALID_NAMESPACE_BREACH" in res_fact.reason


def test_8_validator_bypass_rate_cannot_occur():
    """Requirement 8: Validator Bypass Rate cannot occur (0.0%). Breaches are never marked valid."""
    runner = ReasoningRunner()

    # Case A: Model emits a raw breach in empirical_fact_ids
    breach_payload = json.dumps({
        "decision": "HYPOTHESIS",
        "invariant": "Cross-role boundary must hold",
        "evidence_gap": "Missing token verify",
        "affected_target": "/api/orders/1",
        "empirical_fact_ids": ["CHK-DOC-WSTG-ATHZ-04-002-01"],  # Breach!
        "methodology_chunk_ids": [],
        "reasoning_summary": "Summary",
        "experiment_proposal": "Probe /api/orders/1",
    })
    runner.llm_caller = lambda prompt, schema: breach_payload

    result = runner.execute_i2_generation(prompt="test prompt")
    assert result.has_raw_namespace_breach is True
    assert result.validator_bypassed is False
    assert result.classification.is_valid is False
    assert result.canonical_hypothesis is None
    assert result.classification.primary_category == PrimaryFailureCategory.SCHEMA_VALIDITY_FAILURE

    # Case B: Raw text breach caught in unparseable or semi-parseable stream
    raw_text_breach = '{"empirical_fact_ids": ["CHK-DOC-ASVS-01"], "decision": "HYPOTHESIS"'
    runner.llm_caller = lambda prompt, schema: raw_text_breach
    result2 = runner.execute_i2_generation(prompt="test prompt")
    assert result2.has_raw_namespace_breach is True
    assert result2.validator_bypassed is False
    assert result2.classification.is_valid is False


def test_9_adapter_maps_empirical_fact_ids_to_supporting_evidence_ids():
    """Requirement 9: Adapter maps empirical_fact_ids exactly to supporting_evidence_ids."""
    raw = I2RawHypothesisOutput(
        decision=HypothesisDecision.HYPOTHESIS,
        invariant="Tenant isolation invariant",
        evidence_gap="Missing tenant check",
        affected_target="/api/v1/tenants/42",
        empirical_fact_ids=["FACT-AUTH-001", "FACT-HTTP-002"],
        methodology_chunk_ids=["CHK-DOC-WSTG-ATHZ-04-001-01"],
        reasoning_summary="Observed cross-tenant response with status 200.",
        experiment_proposal="Send cross-tenant GET request.",
    )
    canonical = adapt_i2_to_s0(raw)
    assert canonical.supporting_evidence_ids == ["FACT-AUTH-001", "FACT-HTTP-002"]


def test_10_adapter_maps_methodology_chunk_ids_to_methodology_references():
    """Requirement 10: Adapter maps methodology_chunk_ids exactly to methodology_references."""
    raw = I2RawHypothesisOutput(
        decision=HypothesisDecision.HYPOTHESIS,
        invariant="Tenant isolation invariant",
        evidence_gap="Missing tenant check",
        affected_target="/api/v1/tenants/42",
        empirical_fact_ids=["FACT-AUTH-001"],
        methodology_chunk_ids=["CHK-DOC-ASVS-V4-01-001-01", "CHK-DOC-WSTG-ATHZ-04-002-01"],
        reasoning_summary="Observed cross-tenant response.",
        experiment_proposal="Send cross-tenant GET request.",
    )
    canonical = adapt_i2_to_s0(raw)
    assert canonical.methodology_references == ["CHK-DOC-ASVS-V4-01-001-01", "CHK-DOC-WSTG-ATHZ-04-002-01"]
    assert canonical.cited_methodology_chunk_ids == canonical.methodology_references


def test_11_adapter_performs_zero_semantic_inference():
    """Requirement 11: Adapter performs zero semantic inference or expansion."""
    raw = I2RawHypothesisOutput(
        decision=HypothesisDecision.INSUFFICIENT_EVIDENCE,
        invariant="Verifiable invariant string",
        evidence_gap="Verifiable gap string",
        affected_target="AST-TARGET-09",
        empirical_fact_ids=["FACT-01"],
        methodology_chunk_ids=[],
        reasoning_summary="Strict summary without modification.",
        experiment_proposal="Strict experiment without modification.",
    )
    canonical = adapt_i2_to_s0(raw)
    assert canonical.invariant == "Verifiable invariant string"
    assert canonical.evidence_gap == "Verifiable gap string"
    assert canonical.affected_target == "AST-TARGET-09"
    assert canonical.reasoning_summary == "Strict summary without modification."
    assert canonical.experiment_proposal == "Strict experiment without modification."


def test_12_adapter_performs_zero_citation_substitution():
    """Requirement 12: Adapter performs zero citation substitution or hallucinated expansion."""
    raw_dict = {
        "decision": "HYPOTHESIS",
        "invariant": "Inv",
        "evidence_gap": "Gap",
        "affected_target": "AST-1",
        "empirical_fact_ids": ["CHK-INVALID-01"],  # Cannot be silently substituted into FACT-01!
        "methodology_chunk_ids": [],
        "reasoning_summary": "Summary",
        "experiment_proposal": "Proposal",
    }
    with pytest.raises((ValueError, ValidationError)):
        adapt_i2_to_s0(raw_dict)


def test_13_adapter_fails_closed_on_invalid_namespace():
    """Requirement 13: Adapter fails closed on invalid namespace or cross-namespace emissions."""
    # CHK in empirical
    with pytest.raises(ValueError):
        adapt_i2_to_s0({
            "decision": "HYPOTHESIS",
            "empirical_fact_ids": ["CHK-DOC-01"],
            "methodology_chunk_ids": [],
        })

    # FACT in methodology
    with pytest.raises(ValueError):
        adapt_i2_to_s0({
            "decision": "HYPOTHESIS",
            "empirical_fact_ids": [],
            "methodology_chunk_ids": ["FACT-AUTH-01"],
        })


def test_14_s0_downstream_representation_remains_canonical():
    """Requirement 14: Downstream representation after adapter is canonical S0 HypothesisModelOutput."""
    raw = I2RawHypothesisOutput(
        decision=HypothesisDecision.NO_RELEVANT_FUNCTIONALITY,
        invariant="Public endpoint invariant",
        evidence_gap="None",
        affected_target="AST-HEALTH",
        empirical_fact_ids=[],
        methodology_chunk_ids=[],
        reasoning_summary="Healthcheck endpoint contains no sensitive functionality.",
        experiment_proposal="None required.",
    )
    canonical = adapt_i2_to_s0(raw)
    assert isinstance(canonical, HypothesisModelOutput)
    # Check all canonical S0 attributes are present
    assert hasattr(canonical, "invariant")
    assert hasattr(canonical, "evidence_gap")
    assert hasattr(canonical, "affected_target")
    assert hasattr(canonical, "decision")
    assert hasattr(canonical, "supporting_evidence_ids")
    assert hasattr(canonical, "methodology_references")
    assert hasattr(canonical, "reasoning_summary")
    assert hasattr(canonical, "experiment_proposal")


def test_15_i2_does_not_invoke_i1_constrained_decoding():
    """Requirement 15: I2 executes under UNCONSTRAINED sampling; never passes format: {...}."""
    mock_runner = MagicMock(spec=OllamaRunner)
    mock_runner.generate_raw.return_value = {
        "response": json.dumps({
            "decision": "NO_RELEVANT_FUNCTIONALITY",
            "invariant": "Inv",
            "evidence_gap": "Gap",
            "affected_target": "AST-1",
            "empirical_fact_ids": [],
            "methodology_chunk_ids": [],
            "reasoning_summary": "Summary",
            "experiment_proposal": "Proposal",
        }),
        "eval_count": 50,
        "prompt_eval_count": 200,
        "done_reason": "stop",
    }

    runner = ReasoningRunner(ollama_runner=mock_runner)
    result = runner.execute_i2_generation(prompt="Test unconstrained prompt")

    # Verify generate_raw was called with schema=None (UNCONSTRAINED)
    mock_runner.generate_raw.assert_called_once()
    call_kwargs = mock_runner.generate_raw.call_args[1]
    assert call_kwargs.get("schema") is None, "Intervention I2 must run under unconstrained token sampling (schema=None)"
    assert result.classification.is_valid is True


def test_16_prompt_partitions_fact_and_chk_epistemically():
    """Requirement 16: Prompt partitions FACT and CHK into discrete epistemic XML blocks."""
    # Test A: ReasoningContextBuilder with enable_i2_namespace_partitioning=True
    ch_a = LosslessStructuralPack(
        asset_id="AST-ORDERS-01",
        endpoint_id="EP-01",
        route_template="/api/orders/{id}",
        http_method="GET",
        application_mutability="READ_ONLY",
        has_privilege_level_delta=True,
        observed_facts=[
            {"fact_id": "FACT-01", "statement": "User B accessed order owned by User A"},
        ],
    )
    chunk = KnowledgeChunk(
        chunk_id="CHK-DOC-WSTG-ATHZ-04-002-01",
        document_id="DOC-WSTG-ATHZ-04",
        source_type=KnowledgeSourceType.OWASP_WSTG,
        knowledge_type=KnowledgeType.TESTING_METHODOLOGY,
        title="OWASP WSTG",
        section_heading="Testing for BOLA",
        content="Verify that user cannot access resources owned by other users.",
        token_estimate=15,
        content_hash="abc123hash",
    )
    vapt_pack = VaptKnowledgePack(
        pack_id="PACK-01",
        items=[
            KnowledgeRetrievalItem(
                chunk=chunk,
                dense_score=0.9,
                sparse_score=0.9,
                fused_score=0.9,
                retrieval_rank=1,
                query_id="Q-01",
            ),
        ],
        total_tokens=15,
        rendered_query_text="query",
        retrieval_timestamp="2026-09-20T00:00:00Z",
        corpus_manifest_hash="manifesthash",
        provenance_hash="provhash123",
        serialized_p4_wire=f"=== VAPT METHODOLOGY ===\n[CHK-DOC-WSTG-ATHZ-04-002-01] Testing for BOLA",
    )
    routing = DeterministicRoutingDecision(
        schema_version="2.0.0",
        escalate=True,
        has_high_risk_signal=True,
        high_risk_signals=["PRIVILEGE_LEVEL_DELTA_DETECTED"],
        fail_safe_triggered=False,
    )
    handoff = CascadeHandoffPacket(
        schema_version="2.0.0",
        channel_a_structural=ch_a,
        validated_triage=None,
        routing_decision=routing,
        provenance_hash="hash123",
    )

    ctx = ReasoningContextBuilder.build_context(
        handoff_packet=handoff,
        model_identifier="qwen2.5-coder:7b",
        cascade_mode=TRACK_D,
        vapt_pack=vapt_pack,
        enable_i2_namespace_partitioning=True,
    )

    prompt = ctx.prompt
    assert "<empirical_target_evidence>" in prompt
    assert "</empirical_target_evidence>" in prompt
    assert "<security_testing_methodology>" in prompt
    assert "</security_testing_methodology>" in prompt
    assert "empirical_fact_ids" in prompt
    assert "methodology_chunk_ids" in prompt
    assert "A CHK citation MUST NEVER be treated as empirical target evidence" in prompt
    assert "A FACT citation MUST NEVER be treated as methodology" in prompt

    # Test B: ReasoningRunner.build_i2_prompt
    runner = ReasoningRunner()
    prompt_runner = runner.build_i2_prompt(
        target_asset={"asset_id": "AST-01", "method": "GET", "normalized_path": "/api/users"},
        category_id="API-BOLA-001",
        retrieved_evidence=[{"fact_id": "FACT-01", "statement": "Observation"}],
        vapt_chunks=[{"chunk_id": "CHK-01", "source_name": "WSTG", "content": "Guidance"}],
    )
    assert "<empirical_target_evidence>" in prompt_runner
    assert "</empirical_target_evidence>" in prompt_runner
    assert "<security_testing_methodology>" in prompt_runner
    assert "</security_testing_methodology>" in prompt_runner


def test_17_existing_knowledge_grounding_validator_remains_authoritative():
    """Requirement 17: Existing KnowledgeGroundingValidator remains the authoritative gating check."""
    validator = KnowledgeGroundingValidator()
    raw = I2RawHypothesisOutput(
        decision=HypothesisDecision.HYPOTHESIS,
        invariant="Invariant",
        evidence_gap="Gap",
        affected_target="AST-1",
        empirical_fact_ids=["FACT-SIM-EXEC-01"],
        methodology_chunk_ids=["CHK-DOC-WSTG-ATHZ-04-002-01"],
        reasoning_summary="Summary",
        experiment_proposal="Proposal",
    )
    canonical = adapt_i2_to_s0(raw)

    # Valid grounding check
    res = validator.validate_grounding(canonical)
    assert res.valid is True
    assert res.status == "VALID"


def test_18_no_fabricated_ids_introduced():
    """Requirement 18: Adapter introduces zero fabricated IDs; output is exact copy of input IDs."""
    fact_ids = ["FACT-01", "FACT-02", "FACT-AUTH-03"]
    chunk_ids = ["CHK-DOC-ASVS-V4-01-001-01"]
    raw = I2RawHypothesisOutput(
        decision=HypothesisDecision.INSUFFICIENT_EVIDENCE,
        empirical_fact_ids=fact_ids,
        methodology_chunk_ids=chunk_ids,
    )
    canonical = adapt_i2_to_s0(raw)

    assert set(canonical.supporting_evidence_ids) == set(fact_ids)
    assert len(canonical.supporting_evidence_ids) == len(fact_ids)
    assert set(canonical.methodology_references) == set(chunk_ids)
    assert len(canonical.methodology_references) == len(chunk_ids)


@pytest.mark.live_ollama
@pytest.mark.skipif(
    os.environ.get("SKIP_LIVE_OLLAMA") == "1",
    reason="Live Ollama execution skipped by environment flag",
)
def test_19_live_ollama_i2_unconstrained_sanity_check():
    """Requirement 19: Lightweight live Ollama sanity check under unconstrained sampling."""
    runner = OllamaRunner(num_predict=300, temperature=0.0)
    if not runner.is_available():
        pytest.skip("Local Ollama daemon is not reachable at 127.0.0.1:11434")

    reasoning_runner = ReasoningRunner(ollama_runner=runner)
    prompt = reasoning_runner.build_i2_prompt(
        target_asset={
            "asset_id": "AST-PUBLIC-HEALTH",
            "method": "GET",
            "normalized_path": "/health",
            "application_mutability": "READ_ONLY",
        },
        category_id="API-BOLA-001",
        retrieved_evidence=[
            {"fact_id": "FACT-HEALTH-01", "statement": "GET /health returns HTTP 200 with status UP."},
        ],
        vapt_chunks=[
            {"chunk_id": "CHK-DOC-WSTG-ATHZ-04-001-01", "source_name": "OWASP WSTG", "content": "Test authorization boundaries."},
        ],
    )

    # Execute I2 generation under UNCONSTRAINED sampling
    result = reasoning_runner.execute_i2_generation(prompt=prompt)
    assert isinstance(result, I2ExecutionResult)
    assert len(result.raw_response) > 0
    assert result.latency_ms > 0
    assert result.classification.primary_category in (
        PrimaryFailureCategory.VALID,
        PrimaryFailureCategory.SCHEMA_VALIDITY_FAILURE,
        PrimaryFailureCategory.MAX_TOKEN_TRUNCATION,
        PrimaryFailureCategory.PARSER_FAILURE,
    )
    # Most critical invariant: validator bypass MUST be False!
    assert result.validator_bypassed is False
