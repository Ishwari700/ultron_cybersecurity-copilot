"""Unit tests for retrieval qualification harness, split disjointness, and backend selection."""

import hashlib
import json
from pathlib import Path
import pytest

from src.eval.p4_capacity_oracle import CanonicalP4CapacityOracle
from src.eval.retrieval_qualification import (
    QualificationResult,
    RetrievalQualificationHarness,
)
from src.evidence.cascade_models import LosslessStructuralPack
from src.knowledge.models import EvidenceGapType, QueryRendererId
from src.knowledge.query_builder import VaptQueryBuilder
from src.knowledge.retriever import (
    ChromaFts5Retriever,
    OnnxVectorFts5Retriever,
    SqliteFts5KnowledgeRetriever,
)


def test_split_pairwise_disjointness():
    """
    Verify strict pairwise disjointness between DEV, VAL, QUALIFICATION_SELECTION_SET,
    and RETRIEVAL_FINAL_EVAL on query_id and payload hash per Section 27.1.
    """
    gold_file = Path("data/eval/retrieval_gold.json")
    final_file = Path("data/eval/retrieval_final_eval.json")
    assert gold_file.exists()
    assert final_file.exists()

    with open(gold_file, "r", encoding="utf-8") as f:
        gold_recs = json.load(f)
    with open(final_file, "r", encoding="utf-8") as f:
        final_recs = json.load(f)

    all_recs = gold_recs + final_recs
    assert len(all_recs) == 65

    seen_qids = set()
    seen_payload_hashes = set()

    for r in all_recs:
        qid = r["query_id"]
        assert qid not in seen_qids, f"Duplicate query_id {qid}"
        seen_qids.add(qid)

        # Recompute canonical payload hash
        raw_payload = f"{r['http_method'].upper()}:{r['route_template'].strip()}:{r['evidence_gap_type']}:{r['has_cross_identity_object_access_success']}:{r['has_privilege_level_delta']}"
        phash = hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()
        assert phash not in seen_payload_hashes, f"Payload hash collision for {qid}"
        seen_payload_hashes.add(phash)


def test_retrieval_gold_query_builder_parity():
    """
    Verify Section 13.5 automated parity gate:
    Asserts that VaptQueryBuilder.build_query matches expected_rendered_query byte-for-byte.
    """
    gold_file = Path("data/eval/retrieval_gold.json")
    with open(gold_file, "r", encoding="utf-8") as f:
        gold_recs = json.load(f)

    for rec in gold_recs:
        pack = LosslessStructuralPack(
            asset_id=f"ASSET-{rec['query_id']}",
            endpoint_id=f"EP-{rec['query_id']}",
            route_template=rec["route_template"],
            http_method=rec["http_method"],
            application_mutability="READ_ONLY" if rec["http_method"] == "GET" else "STATE_CHANGING",
            has_cross_identity_object_access_success=rec["has_cross_identity_object_access_success"],
            has_privilege_level_delta=rec["has_privilege_level_delta"],
        )
        gap = EvidenceGapType(rec["evidence_gap_type"])

        # Test Renderer S byte parity
        built_s = VaptQueryBuilder.build_query(pack, gap, QueryRendererId.RENDERER_S)
        assert built_s == rec["expected_rendered_query"]["RENDERER_S"]

        # Test Renderer N byte parity
        built_n = VaptQueryBuilder.build_query(pack, gap, QueryRendererId.RENDERER_N)
        assert built_n == rec["expected_rendered_query"]["RENDERER_N"]


def test_harness_evaluation_on_candidate2():
    """Verify Candidate 2 evaluation on QUALIFICATION_SELECTION_SET using harness."""
    gold_file = Path("data/eval/retrieval_gold.json")
    db_file = Path("data/vapt_corpus/vapt_knowledge.db")

    harness = RetrievalQualificationHarness(gold_file)
    retriever = SqliteFts5KnowledgeRetriever(db_file)

    res = harness.evaluate_split(
        retriever=retriever,
        split_name="QUALIFICATION_SELECTION_SET",
        renderer_id=QueryRendererId.RENDERER_S,
    )

    assert res.query_count == 15
    assert res.candidate_id == "Candidate 2"
    assert res.mean_recall_at_5 > 0.0
    assert res.mean_mrr_at_5 > 0.0
    assert res.mean_injection_hit > 0.0
    assert res.mean_latency_ms >= 0.0
    retriever.close()


def test_harness_reproducibility_100_runs():
    """
    Verify Gate 1: 100 repeated runs under fixed configuration.
    Zero ranking instability, score drift <= 1e-6.
    """
    gold_file = Path("data/eval/retrieval_gold.json")
    db_file = Path("data/vapt_corpus/vapt_knowledge.db")

    harness = RetrievalQualificationHarness(gold_file)
    retriever = SqliteFts5KnowledgeRetriever(db_file)

    passed, max_drift = harness.verify_reproducibility(
        retriever=retriever,
        split_name="QUALIFICATION_SELECTION_SET",
        repetitions=100,
    )

    assert passed is True
    assert max_drift <= 1e-6
    retriever.close()


def test_macro_averaged_renderer_selection_rule():
    """Verify Section 13.4 macro-averaged global renderer selection logic."""
    r_s = QualificationResult(
        candidate_id="Candidate 2",
        candidate_name="Pure FTS5",
        split_name="VAL",
        renderer_id=QueryRendererId.RENDERER_S,
        query_count=15,
        mean_recall_at_5=0.85,
        mean_mrr_at_5=0.70,
        mean_injection_hit=0.80,
        mean_latency_ms=5.0,
        reproducibility_passed=True,
        max_score_drift=0.0,
        hard_gates_passed=True,
        gate_details={},
    )
    r_n = QualificationResult(
        candidate_id="Candidate 2",
        candidate_name="Pure FTS5",
        split_name="VAL",
        renderer_id=QueryRendererId.RENDERER_N,
        query_count=15,
        mean_recall_at_5=0.80,
        mean_mrr_at_5=0.65,
        mean_injection_hit=0.75,
        mean_latency_ms=5.0,
        reproducibility_passed=True,
        max_score_drift=0.0,
        hard_gates_passed=True,
        gate_details={},
    )

    matrix = {
        QueryRendererId.RENDERER_S: {"Candidate 2": r_s},
        QueryRendererId.RENDERER_N: {"Candidate 2": r_n},
    }

    selected, scores = RetrievalQualificationHarness.select_global_production_renderer(matrix)
    assert selected == QueryRendererId.RENDERER_S
    assert scores[QueryRendererId.RENDERER_S] == 0.80


def test_canonical_backend_selection_rule():
    """Verify Section 11.5 candidate ranking and deterministic tie-breaking."""
    # Candidate 2: Recall 0.85, MRR 0.70, Latency 2ms, Footprint stdlib
    c2 = QualificationResult(
        candidate_id="Candidate 2",
        candidate_name="Pure FTS5",
        split_name="QUAL",
        renderer_id=QueryRendererId.RENDERER_S,
        query_count=15,
        mean_recall_at_5=0.85,
        mean_mrr_at_5=0.70,
        mean_injection_hit=0.80,
        mean_latency_ms=2.0,
        reproducibility_passed=True,
        max_score_drift=0.0,
        hard_gates_passed=True,
        gate_details={},
    )

    # Candidate 1: Recall 0.85, MRR 0.70, Latency 15ms, Footprint ONNX
    c1 = QualificationResult(
        candidate_id="Candidate 1",
        candidate_name="ONNX FTS5",
        split_name="QUAL",
        renderer_id=QueryRendererId.RENDERER_S,
        query_count=15,
        mean_recall_at_5=0.85,
        mean_mrr_at_5=0.70,
        mean_injection_hit=0.80,
        mean_latency_ms=15.0,
        reproducibility_passed=True,
        max_score_drift=0.0,
        hard_gates_passed=True,
        gate_details={},
    )

    # Candidate 3: Failed hard gate
    c3 = QualificationResult(
        candidate_id="Candidate 3",
        candidate_name="Chroma FTS5",
        split_name="QUAL",
        renderer_id=QueryRendererId.RENDERER_S,
        query_count=15,
        mean_recall_at_5=0.50,
        mean_mrr_at_5=0.40,
        mean_injection_hit=0.50,
        mean_latency_ms=20.0,
        reproducibility_passed=True,
        max_score_drift=0.0,
        hard_gates_passed=False,
        gate_details={},
    )

    best = RetrievalQualificationHarness.rank_and_select_backend([c1, c2, c3])
    assert best is not None
    # Candidate 2 has lower latency and smaller footprint than Candidate 1
    assert best.candidate_id == "Candidate 2"
