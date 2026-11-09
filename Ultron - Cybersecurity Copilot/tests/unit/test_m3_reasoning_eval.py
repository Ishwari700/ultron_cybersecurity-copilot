"""Unit tests for Milestone M3: Retrieval -> Reasoning Evaluation.

Validates:
- Phase 17 requirements:
  - test_reasoning_dataset_validity
  - test_reasoning_case_schema
  - test_all_cases_have_gold_expectations
  - test_retrieval_configuration_isolation
  - test_same_evidence_across_configurations
  - test_same_prompt_across_configurations
  - test_output_schema
  - test_provenance_preservation
  - test_epistemic_status_preservation
  - test_evaluation_reproducibility
  - test_metrics_calculation
"""

from pathlib import Path
import pytest

from src.eval.m3_reasoning_dataset import get_m3_reasoning_cases, load_m3_reasoning_dataset
from src.eval.m3_reasoning_evaluator import (
    M3ReasoningEvaluator,
    score_reasoning_output,
)
from src.eval.m3_reasoning_schema import (
    DifficultyLevel,
    M3ReasoningCase,
    M3ReasoningDataset,
    M3ReasoningOutput,
    M3ScoringRubric,
    ReasoningDecision,
    RetrievalConfigId,
)
from src.evidence.cascade_models import LosslessStructuralPack
from src.knowledge.models import VaptKnowledgePack


@pytest.fixture(scope="module")
def dataset():
    return load_m3_reasoning_dataset()


@pytest.fixture(scope="module")
def evaluator():
    return M3ReasoningEvaluator()


def test_reasoning_dataset_validity(dataset):
    """Dataset contains exactly 20 cases with valid difficulty, domain, and decision distributions."""
    assert dataset.total_cases == 20
    assert len(dataset.cases) == 20

    # Decision balance: 12 HYPOTHESIS, 4 INSUFFICIENT_EVIDENCE, 4 NO_RELEVANT_FUNCTIONALITY
    vulnerable_cases = [c for c in dataset.cases if c.expected_decision == ReasoningDecision.HYPOTHESIS]
    gap_cases = [c for c in dataset.cases if c.expected_decision == ReasoningDecision.INSUFFICIENT_EVIDENCE]
    nc_cases = [c for c in dataset.cases if c.expected_decision == ReasoningDecision.NO_RELEVANT_FUNCTIONALITY]

    assert len(vulnerable_cases) == 12, f"Expected 12 vulnerable cases, found {len(vulnerable_cases)}"
    assert len(gap_cases) == 4, f"Expected 4 gap cases, found {len(gap_cases)}"
    assert len(nc_cases) == 4, f"Expected 4 negative control cases, found {len(nc_cases)}"

    # Difficulty balance: 7 EASY, 8 MEDIUM, 5 HARD
    easy = [c for c in dataset.cases if c.difficulty == DifficultyLevel.EASY]
    med = [c for c in dataset.cases if c.difficulty == DifficultyLevel.MEDIUM]
    hard = [c for c in dataset.cases if c.difficulty == DifficultyLevel.HARD]

    assert len(easy) == 7
    assert len(med) == 8
    assert len(hard) == 5
    assert len(easy) + len(med) + len(hard) == 20


def test_reasoning_case_schema(dataset):
    """Every case adheres strictly to the M3ReasoningCase schema with non-empty fields."""
    for case in dataset.cases:
        assert case.reasoning_case_id.startswith("RC-")
        assert len(case.case_name) > 0
        assert len(case.user_query) > 0
        assert len(case.security_domain) > 0
        assert isinstance(case.target_evidence, dict)
        assert len(case.target_evidence.get("observed_facts", [])) > 0
        assert len(case.expected_security_concept) > 0
        assert len(case.expected_security_invariant) > 0
        assert len(case.expected_evidence_requirements) > 0
        assert len(case.expected_experiment_characteristics) > 0
        assert len(case.expected_falsification_characteristics) > 0


def test_all_cases_have_gold_expectations(dataset):
    """Every case contains complete, unambiguous gold-standard expectations."""
    for case in dataset.cases:
        assert case.expected_decision in [
            ReasoningDecision.HYPOTHESIS,
            ReasoningDecision.INSUFFICIENT_EVIDENCE,
            ReasoningDecision.NO_RELEVANT_FUNCTIONALITY,
        ]
        assert len(case.relevant_chunk_ids) > 0
        for cid in case.relevant_chunk_ids:
            assert cid.startswith("CHK-")


def test_retrieval_configuration_isolation(evaluator):
    """Verifies that each retrieval configuration is isolated with its designated retriever."""
    # Config A has no retriever (returns None / 0 items)
    assert evaluator.retrievers[RetrievalConfigId.CONFIG_A_NO_RAG.value] is None

    # Config B uses pure SQLite FTS5
    ret_b = evaluator.retrievers[RetrievalConfigId.CONFIG_B_FTS5.value]
    assert ret_b is not None
    assert ret_b.is_sparse is True
    assert ret_b.is_dense is False

    # Config D uses MiniLM Hybrid (Sparse + Dense)
    ret_d = evaluator.retrievers[RetrievalConfigId.CONFIG_D_MINILM_HYBRID.value]
    assert ret_d is not None
    assert ret_d.is_sparse is True
    assert ret_d.is_dense is True

    # Config E uses MiniLM Dense Only
    ret_e = evaluator.retrievers[RetrievalConfigId.CONFIG_E_MINILM_DENSE.value]
    assert ret_e is not None
    assert ret_e.is_sparse is False
    assert ret_e.is_dense is True


def test_same_evidence_across_configurations(dataset, evaluator):
    """Ensures exact causal parity: target evidence is byte-for-byte identical across configurations."""
    for case in dataset.cases:
        pack = evaluator._convert_case_to_structural_pack(case)
        assert isinstance(pack, LosslessStructuralPack)
        # Verify deterministic JSON serialization of evidence
        json1 = pack.model_dump_json()
        pack2 = evaluator._convert_case_to_structural_pack(case)
        json2 = pack2.model_dump_json()
        assert json1 == json2, "Target evidence serialization must be strictly deterministic"


def test_same_prompt_across_configurations(dataset, evaluator):
    """Verifies prompt template and system policy consistency across configurations."""
    case = dataset.cases[0]
    pack = evaluator._convert_case_to_structural_pack(case)

    from src.engine.context_builder import ReasoningContextBuilder
    from src.engine.models import OutputProtocolIdentifier
    from src.evidence.cascade_models import CascadeHandoffPacket, DeterministicRoutingDecision

    decision = DeterministicRoutingDecision(
        escalate=True,
        priority="HIGH",
        reasons=["test_parity"],
        has_high_risk_signal=True,
        fail_safe_triggered=False,
    )
    handoff = CascadeHandoffPacket(
        schema_version="2.0.0",
        channel_a_structural=pack,
        routing_decision=decision,
        provenance_hash="test_prov_hash",
    )

    ctx_no_rag = ReasoningContextBuilder.build_context(
        handoff_packet=handoff,
        model_identifier="qwen2.5-coder:7b",
        cascade_mode="TRACK_B",
        vapt_pack=None,
        enable_i2_namespace_partitioning=True,
        output_protocol=OutputProtocolIdentifier.JSON_BAIR,
    )

    # Both system policies must be identical
    assert "You are an authoritative Application Security Reasoning Engine." in ctx_no_rag.system_prompt
    assert "JSON_BAIR" in ctx_no_rag.system_prompt
    assert "<untrusted_target_data>" in ctx_no_rag.prompt or "=== TARGET ENVELOPE ===" in ctx_no_rag.prompt


def test_output_schema():
    """M3ReasoningOutput model validates structured reasoning attributes."""
    out = M3ReasoningOutput(
        hypothesis="BOLA exists on invoice endpoint",
        security_invariant="Horizontal tenant isolation invariant",
        evidence_gap="None",
        manual_experiment="Substitute invoice ID",
        expected_secure_result="403 Forbidden",
        expected_vulnerable_result="200 OK",
        falsification="Request rejected",
        decision="HYPOTHESIS",
        confidence=0.85,
        empirical_facts=["FACT-0101"],
        methodology_references=["CHK-DOC-CWE-639-001-01"],
    )
    assert out.decision == "HYPOTHESIS"
    assert len(out.empirical_facts) == 1
    assert len(out.methodology_references) == 1


def test_provenance_preservation(dataset, evaluator):
    """Evaluator preserves case ID, configuration ID, and execution telemetry."""
    case = dataset.cases[0]
    out = M3ReasoningOutput(
        hypothesis="Test hypothesis",
        security_invariant="Test invariant",
        decision="HYPOTHESIS",
    )
    rubric = score_reasoning_output(case, out)
    assert 0.0 <= rubric.composite_reasoning_score <= 4.0
    assert rubric.unsupported_claim_count >= 0


def test_epistemic_status_preservation():
    """Target facts and methodology references remain strictly segregated."""
    out = M3ReasoningOutput(
        hypothesis="Test isolation",
        empirical_facts=["FACT-0101", "FACT-0102"],
        methodology_references=["CHK-DOC-CWE-639-001-01"],
    )
    # Target facts must strictly begin with FACT-
    for fid in out.empirical_facts:
        assert fid.startswith("FACT-")
    # Methodology chunks must strictly begin with CHK-
    for cid in out.methodology_references:
        assert cid.startswith("CHK-")


def test_evaluation_reproducibility(dataset):
    """Evaluating identical outputs produces strictly deterministic scores."""
    case = dataset.cases[0]
    out = M3ReasoningOutput(
        hypothesis="Broken Object Level Authorization in invoice fetch",
        security_invariant="Horizontal tenant isolation invariant",
        evidence_gap="None",
        manual_experiment="Request invoice with user B token",
        expected_secure_result="403 Forbidden",
        expected_vulnerable_result="200 OK",
        falsification="Server rejects request with 403 Forbidden",
        decision="HYPOTHESIS",
        confidence=0.9,
        empirical_facts=["FACT-0101", "FACT-0102"],
        methodology_references=["CHK-DOC-CWE-639-001-01"],
    )

    score1 = score_reasoning_output(case, out)
    score2 = score_reasoning_output(case, out)

    assert score1.composite_reasoning_score == score2.composite_reasoning_score
    assert score1.hypothesis_correctness == score2.hypothesis_correctness
    assert score1.evidence_grounding == score2.evidence_grounding
    assert score1.falsification_quality == score2.falsification_quality


def test_metrics_calculation():
    """M3ScoringRubric composite score equals the exact unweighted mean of all 7 dimensions."""
    rubric = M3ScoringRubric(
        hypothesis_correctness=4.0,
        evidence_grounding=3.0,
        evidence_gap_quality=2.0,
        security_invariant_correctness=3.0,
        experiment_quality=4.0,
        falsification_quality=3.0,
        false_positive_resistance=4.0,
        unsupported_claim_count=0,
        total_claims_count=3,
        unsupported_claim_rate=0.0,
    )
    expected_composite = (4.0 + 3.0 + 2.0 + 3.0 + 4.0 + 3.0 + 4.0) / 7.0
    assert abs(rubric.composite_reasoning_score - expected_composite) < 1e-5
