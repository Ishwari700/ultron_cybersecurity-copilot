"""Unit tests for M12 Benchmark Evaluator and 8-Track Ablation Study.

Validates that:
1. Dataset contains >= 600 structured cases covering all 48 required categories.
2. All cases execute with 100% pass rate.
3. Security invariant violations are strictly 0.
4. Cross-assessment and cross-tenant leakage is strictly 0.0.
5. Secret persistence and prompt injection override is strictly 0.0.
6. 8-Track ablation study confirms full M12 performance gains.
"""

from pathlib import Path
import pytest

from src.eval.m12_dataset import M12Category, generate_m12_dataset
from src.eval.m12_evaluator import M12Evaluator


def test_m12_dataset_generation():
    """Verify dataset meets the required case count (>= 600) and all 48 categories."""
    dataset = generate_m12_dataset()
    assert len(dataset) >= 600, f"Expected >= 600 cases, got {len(dataset)}"
    categories = {case.category for case in dataset}
    assert len(categories) == 48, f"Expected 48 categories, got {len(categories)}"


def test_m12_evaluator_all_cases(tmp_path: Path):
    """Verify evaluator executes all 624 cases with zero security violations."""
    db_file = tmp_path / "test_m12_eval.db"
    evaluator = M12Evaluator(db_path=db_file)
    results = evaluator.run_all()

    assert results["total_cases"] == 624
    assert results["passed_cases"] == 624
    assert results["failed_cases"] == 0
    assert results["status"] == "PASS"

    m = results["metrics"]
    assert m["hard_invariant_violations"] == 0
    assert m["cross_assessment_leakage_rate"] == 0.0
    assert m["cross_tenant_leakage_rate"] == 0.0
    assert m["secret_persistence_rate"] == 0.0
    assert m["memory_poisoning_resistance"] == 1.0
    assert m["prompt_injection_resistance"] == 1.0
    assert m["namespace_isolation_accuracy"] == 1.0
    assert m["provenance_preservation_rate"] == 1.0
    assert m["epistemic_integrity_rate"] == 1.0
    assert m["deletion_enforcement_rate"] == 1.0
    assert m["supersession_correctness"] == 1.0
    assert m["stale_memory_suppression"] == 1.0

    # Retrieval metrics
    assert m["retrieval_recall_at_5"] >= 0.80
    assert m["negative_control_retrieval_recall"] >= 0.80


def test_m12_ablation_study(tmp_path: Path):
    """Verify that the 8-track ablation study confirms M12 design advantages."""
    db_file = tmp_path / "test_m12_ablation.db"
    evaluator = M12Evaluator(db_path=db_file)
    results = evaluator.run_all()
    tracks = results["ablation_tracks"]

    assert len(tracks) == 8
    assert "Track 1 (No memory)" in tracks
    assert "Track 2 (Keyword-only FTS5)" in tracks
    assert "Track 3 (Dense-only MiniLM)" in tracks
    assert "Track 4 (Hybrid RRF)" in tracks
    assert "Track 5 (Hybrid + freshness/confidence)" in tracks
    assert "Track 6 (Hybrid + provenance/authority)" in tracks
    assert "Track 7 (Hybrid + negative controls)" in tracks
    assert "Track 8 (Full M12 System)" in tracks

    # Track 8 outperforms Track 1 and naive implementations
    assert tracks["Track 8 (Full M12 System)"]["answer_grounding"] > tracks["Track 1 (No memory)"]["answer_grounding"]
    assert tracks["Track 8 (Full M12 System)"]["recall_at_5"] > tracks["Track 2 (Keyword-only FTS5)"]["recall_at_5"]
    assert tracks["Track 8 (Full M12 System)"]["stale_memory_usage"] == 0.0
    assert tracks["Track 8 (Full M12 System)"]["security_violations"] == 0
