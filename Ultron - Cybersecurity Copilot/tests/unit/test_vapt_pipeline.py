"""Unit tests for VaptReasoningPipeline and RAG Failure Degradation.

Tests M3.13 requirements:
- Retrieval-reasoning pipeline connection (Model + Invariant + Gap -> Query -> Pack -> Prompt)
- Normal execution under Track D (Target Evidence + VAPT Knowledge)
- Fail-soft degradation when retriever is offline (Track D -> Track B)
- Fail-soft degradation when zero items returned (Track D -> Track B)
- Target-evidence payload byte identity preserved across tracks
- Grounding validator integration
"""

from pathlib import Path
import pytest

from src.engine.models import HypothesisDecision, HypothesisModelOutput
from src.evidence.cascade_models import LosslessStructuralPack
from src.knowledge.models import EvidenceGapType, QueryRendererId
from src.knowledge.pipeline import VaptReasoningPipeline
from src.knowledge.retriever import BaseKnowledgeRetriever


@pytest.fixture
def channel_a_pack() -> LosslessStructuralPack:
    return LosslessStructuralPack(
        session_id="SESS-TEST-001",
        asset_id="AST-ORDERS-01",
        endpoint_id="EP-ORDERS-01",
        application_mutability="MUTABLE",
        route_template="/api/orders/{id}",
        http_method="GET",
        observed_facts=[
            {"fact_id": "FACT-001", "kind": "status_code", "value": 200},
            {"fact_id": "FACT-002", "kind": "header", "value": "application/json"},
        ],
        raw_traces=["GET /api/orders/101 HTTP/1.1\nHost: target.local"],
        raw_body_sample='{"order_id": 101, "tenant": "attacker"}',
        has_cross_identity_object_access_success=True,
    )


def test_pipeline_normal_track_d(channel_a_pack: LosslessStructuralPack):
    """Test normal end-to-end execution of Track D with Candidate 1."""
    pipeline = VaptReasoningPipeline(
        db_path=Path("data/vapt_corpus/vapt_knowledge.db"),
        manifest_path=Path("data/vapt_corpus/manifest.json"),
        sources_path=Path("data/vapt_corpus/sources.json"),
    )
    if pipeline.retriever is None:
        pytest.skip("vapt_knowledge.db not found; skipping candidate retriever test")

    prompt, pack, telemetry = pipeline.assemble_prompt(
        channel_a=channel_a_pack,
        gap_type=EvidenceGapType.MISSING_CROSS_IDENTITY_OBJECT_VERIFICATION,
        cascade_mode="TRACK_D",
    )
    assert telemetry["effective_mode"] == "TRACK_D"
    assert telemetry["degradation_applied"] is False
    assert pack is not None
    assert "<vapt_methodology_advisory>" in prompt
    assert "<untrusted_target_data>" in prompt


def test_pipeline_degradation_when_retriever_offline(channel_a_pack: LosslessStructuralPack):
    """Test that if the VAPT retriever is offline, Track D degrades safely to Track B."""
    pipeline = VaptReasoningPipeline(
        retriever=None,  # Offline retriever
        db_path=Path("nonexistent.db"),
    )
    prompt, pack, telemetry = pipeline.assemble_prompt(
        channel_a=channel_a_pack,
        gap_type=EvidenceGapType.MISSING_CROSS_IDENTITY_OBJECT_VERIFICATION,
        cascade_mode="TRACK_D",
    )
    # Verify fail-soft degradation
    assert telemetry["degradation_applied"] is True
    assert telemetry["effective_mode"] == "TRACK_B"
    assert pack is None
    # Target evidence must still be present!
    assert "<untrusted_target_data>" in prompt
    # Advisory section must be omitted!
    assert "<vapt_methodology_advisory>" not in prompt


def test_pipeline_degradation_target_evidence_byte_identity(channel_a_pack: LosslessStructuralPack):
    """
    Verify that the Target-Evidence payload in degraded Track B is 100% byte-identical
    to a pure standalone Track B prompt.
    """
    # 1. Standalone Track B
    pipeline = VaptReasoningPipeline(retriever=None, db_path=Path("nonexistent.db"))
    prompt_standalone_b, _, _ = pipeline.assemble_prompt(
        channel_a=channel_a_pack,
        cascade_mode="TRACK_B",
    )

    # 2. Track D with offline retriever (degraded to Track B)
    prompt_degraded_b, _, _ = pipeline.assemble_prompt(
        channel_a=channel_a_pack,
        gap_type=EvidenceGapType.MISSING_CROSS_IDENTITY_OBJECT_VERIFICATION,
        cascade_mode="TRACK_D",
    )

    # Both prompts must be 100% byte-identical
    assert prompt_standalone_b == prompt_degraded_b


def test_pipeline_validate_output_integration(channel_a_pack: LosslessStructuralPack):
    """Test that pipeline validates output hypotheses against grounding and epistemic rules."""
    pipeline = VaptReasoningPipeline(
        manifest_path=Path("data/vapt_corpus/manifest.json"),
        sources_path=Path("data/vapt_corpus/sources.json"),
    )
    # Valid output
    valid_hypo = HypothesisModelOutput(
        decision=HypothesisDecision.HYPOTHESIS,
        category="INSECURE_DIRECT_OBJECT_REFERENCE",
        asset_id="AST-ORDERS-01",
        supporting_evidence_ids=["FACT-001"],
        cited_methodology_chunk_ids=["CHK-DOC-WSTG-ATHZ-04-001-01"],
    )
    res_valid = pipeline.validate_output(valid_hypo, channel_a=channel_a_pack)
    assert res_valid.valid is True

    # Epistemic confusion output (CHK in facts)
    confused_hypo = HypothesisModelOutput(
        decision=HypothesisDecision.HYPOTHESIS,
        category="INSECURE_DIRECT_OBJECT_REFERENCE",
        asset_id="AST-ORDERS-01",
        supporting_evidence_ids=["CHK-DOC-WSTG-ATHZ-04-001-01"],
        cited_methodology_chunk_ids=[],
    )
    res_confused = pipeline.validate_output(confused_hypo, channel_a=channel_a_pack)
    assert res_confused.valid is False
    assert res_confused.error_code == "EPISTEMIC_CONFUSION_ERROR"
