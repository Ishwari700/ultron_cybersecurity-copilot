"""Unit tests for KnowledgeGroundingValidator and Epistemic Separation.

Tests M3.11 requirements:
- Epistemic tier discipline (zero CHK in facts, zero FACT in methodology)
- Citation validity against signed corpus manifest
- Zero confirmation authority enforcement
- Target evidence requirement for HYPOTHESIS decision
- RFC 9162 Merkle audit path verification
- Sourcing & licensing allowlist enforcement
"""

from pathlib import Path
import pytest

from src.engine.models import HypothesisDecision, HypothesisModelOutput
from src.evidence.cascade_models import LosslessStructuralPack
from src.knowledge.grounding_validator import (
    KnowledgeGroundingValidator,
    KnowledgeGroundingResult,
)
from src.knowledge.provenance import (
    compute_canonical_leaf_bytes,
    compute_corpus_merkle_root,
    compute_rfc9162_audit_path,
    compute_rfc9162_mth,
    verify_rfc9162_audit_path,
)


@pytest.fixture
def validator() -> KnowledgeGroundingValidator:
    manifest_path = Path("data/vapt_corpus/manifest.json")
    sources_path = Path("data/vapt_corpus/sources.json")
    return KnowledgeGroundingValidator(
        manifest_path=manifest_path,
        sources_path=sources_path,
    )


def test_valid_hypothesis_with_vapt_citations(validator: KnowledgeGroundingValidator):
    """Test that a well-formed hypothesis with FACT and CHK citations passes."""
    hypo = HypothesisModelOutput(
        decision=HypothesisDecision.HYPOTHESIS,
        category="INSECURE_DIRECT_OBJECT_REFERENCE",
        asset_id="AST-ORDERS-01",
        parameter_ids=["PARAM-ORDER-ID"],
        reasoning_summary="Observed horizontal object access across distinct tenant IDs.",
        supporting_evidence_ids=["FACT-AUTH-001", "FACT-HTTP-002"],
        cited_methodology_chunk_ids=["CHK-DOC-WSTG-ATHZ-04-001-01"],
    )
    result = validator.validate_grounding(hypo)
    assert result.valid is True
    assert result.status == "VALID"
    assert result.error_code is None


def test_epistemic_confusion_chk_in_supporting_evidence(validator: KnowledgeGroundingValidator):
    """Test that placing a CHK ID in supporting_evidence_ids is rejected immediately."""
    hypo = HypothesisModelOutput(
        decision=HypothesisDecision.HYPOTHESIS,
        category="INSECURE_DIRECT_OBJECT_REFERENCE",
        asset_id="AST-ORDERS-01",
        supporting_evidence_ids=["FACT-AUTH-001", "CHK-DOC-WSTG-ATHZ-04-001-01"],
        cited_methodology_chunk_ids=[],
    )
    result = validator.validate_grounding(hypo)
    assert result.valid is False
    assert result.status == "DISCARD"
    assert result.error_code == "EPISTEMIC_CONFUSION_ERROR"
    assert "CHK-DOC-WSTG-ATHZ-04-001-01" in result.invalid_chunk_ids


def test_epistemic_confusion_fact_in_methodology_citations(validator: KnowledgeGroundingValidator):
    """Test that placing a FACT ID in cited_methodology_chunk_ids is rejected immediately."""
    hypo = HypothesisModelOutput(
        decision=HypothesisDecision.HYPOTHESIS,
        category="INSECURE_DIRECT_OBJECT_REFERENCE",
        asset_id="AST-ORDERS-01",
        supporting_evidence_ids=["FACT-AUTH-001"],
        cited_methodology_chunk_ids=["FACT-HTTP-002"],
    )
    result = validator.validate_grounding(hypo)
    assert result.valid is False
    assert result.status == "DISCARD"
    assert result.error_code == "EPISTEMIC_CONFUSION_ERROR"
    assert "FACT-HTTP-002" in result.invalid_fact_ids


def test_zero_confirmation_authority_enforced(validator: KnowledgeGroundingValidator):
    """Test that emitting CONFIRMED decision is blocked with zero confirmation authority error."""
    raw_hypo = {
        "decision": "CONFIRMED",
        "category": "INSECURE_DIRECT_OBJECT_REFERENCE",
        "asset_id": "AST-ORDERS-01",
        "supporting_evidence_ids": ["FACT-001"],
        "cited_methodology_chunk_ids": ["CHK-DOC-WSTG-ATHZ-04-001-01"],
    }
    result = validator.validate_grounding(raw_hypo)
    assert result.valid is False
    assert result.status == "DISCARD"
    assert result.error_code == "ZERO_CONFIRMATION_AUTHORITY_VIOLATION"


def test_ungrounded_hypothesis_vapt_without_target_facts(validator: KnowledgeGroundingValidator):
    """Test that VAPT methodology cannot substantiate a hypothesis without target facts."""
    hypo = HypothesisModelOutput(
        decision=HypothesisDecision.HYPOTHESIS,
        category="INSECURE_DIRECT_OBJECT_REFERENCE",
        asset_id="AST-ORDERS-01",
        supporting_evidence_ids=[],
        cited_methodology_chunk_ids=["CHK-DOC-WSTG-ATHZ-04-001-01"],
    )
    result = validator.validate_grounding(hypo)
    assert result.valid is False
    assert result.status == "DISCARD"
    assert result.error_code == "UNGROUNDED_HYPOTHESIS"


def test_invalid_chunk_citation_rejected(validator: KnowledgeGroundingValidator):
    """Test that citing a nonexistent chunk ID is rejected with CITATION_VALIDITY_ERROR."""
    hypo = HypothesisModelOutput(
        decision=HypothesisDecision.HYPOTHESIS,
        category="INSECURE_DIRECT_OBJECT_REFERENCE",
        asset_id="AST-ORDERS-01",
        supporting_evidence_ids=["FACT-AUTH-001"],
        cited_methodology_chunk_ids=["CHK-NONEXISTENT-CHUNK-999"],
    )
    result = validator.validate_grounding(hypo)
    assert result.valid is False
    assert result.status == "DISCARD"
    assert result.error_code == "CITATION_VALIDITY_ERROR"
    assert "CHK-NONEXISTENT-CHUNK-999" in result.invalid_chunk_ids


def test_channel_a_evidence_grounding_integration(validator: KnowledgeGroundingValidator):
    """Test validation against Channel A LosslessStructuralPack."""
    pack = LosslessStructuralPack(
        session_id="SESS-01",
        asset_id="AST-ORDERS-01",
        endpoint_id="EP-01",
        application_mutability="MUTABLE",
        route_template="/api/orders/{id}",
        http_method="GET",
        observed_facts=[
            {"fact_id": "FACT-001", "kind": "status_code", "value": 200},
            {"fact_id": "FACT-002", "kind": "header", "value": "json"},
        ],
    )
    # Valid cited fact
    valid_hypo = HypothesisModelOutput(
        decision=HypothesisDecision.HYPOTHESIS,
        category="API-BOLA-001",
        asset_id="AST-ORDERS-01",
        supporting_evidence_ids=["FACT-001"],
        cited_methodology_chunk_ids=["CHK-DOC-WSTG-ATHZ-04-001-01"],
    )
    assert validator.validate_grounding(valid_hypo, channel_a=pack).valid is True

    # Hallucinated fact not in pack
    invalid_hypo = HypothesisModelOutput(
        decision=HypothesisDecision.HYPOTHESIS,
        category="API-BOLA-001",
        asset_id="AST-ORDERS-01",
        supporting_evidence_ids=["FACT-999-HALLUCINATED"],
        cited_methodology_chunk_ids=["CHK-DOC-WSTG-ATHZ-04-001-01"],
    )
    res = validator.validate_grounding(invalid_hypo, channel_a=pack)
    assert res.valid is False
    assert res.error_code == "TARGET_EVIDENCE_GROUNDING_FAILURE"


def test_rfc9162_merkle_audit_path_cryptographic_verification():
    """Test cryptographic generation and verification of RFC 9162 Merkle audit paths."""
    leaves = [f"leaf_data_payload_{i}".encode("utf-8") for i in range(23)]
    root = compute_rfc9162_mth(leaves)

    for i in range(len(leaves)):
        path = compute_rfc9162_audit_path(leaves, i)
        assert verify_rfc9162_audit_path(leaves[i], i, len(leaves), path, root) is True

    # Tampered leaf fails
    tampered_leaf = b"tampered_data"
    path_0 = compute_rfc9162_audit_path(leaves, 0)
    assert verify_rfc9162_audit_path(tampered_leaf, 0, len(leaves), path_0, root) is False

    # Tampered root fails
    fake_root = b"\x00" * 32
    assert verify_rfc9162_audit_path(leaves[0], 0, len(leaves), path_0, fake_root) is False
