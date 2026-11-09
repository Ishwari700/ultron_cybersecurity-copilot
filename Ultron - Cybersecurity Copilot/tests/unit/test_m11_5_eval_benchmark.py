"""Unit tests for M11.5 Benchmark Evaluator and Ablation Study.

Validates that:
1. All 265 evaluation cases execute with 100% pass rate.
2. Silent truncation rate is strictly 0.0.
3. Security invariant violations are strictly 0.
4. Ablation study comparison matches expected reliability gains.
"""

import json
from pathlib import Path
import pytest

from src.eval.m11_5_dataset import (
    TestCaseCategory,
    generate_m11_5_dataset,
)
from src.eval.m11_5_evaluator import M11_5Evaluator


def test_m11_5_dataset_generation():
    """Verify dataset meets the required case count and categories."""
    dataset = generate_m11_5_dataset()
    assert len(dataset) >= 250, f"Expected >= 250 cases, got {len(dataset)}"
    categories = {case.category for case in dataset}
    assert len(categories) == len(TestCaseCategory)


def test_m11_5_evaluator_all_cases():
    """Verify that evaluator runs across all 265 cases with zero silent truncations."""
    evaluator = M11_5Evaluator()
    results = evaluator.run_all()

    assert results["summary"]["total_cases"] == 265
    assert results["summary"]["passed_cases"] == 265
    assert results["summary"]["failed_cases"] == 0
    assert results["overall_status"] == "PASS"

    bench = results["benchmark_metrics"]
    assert bench["silent_truncation_rate"] == 0.0
    assert bench["successful_completion_rate"] == 1.0
    assert bench["duplicate_content_rate"] == 0.0
    assert bench["security_invariant_violations"] == 0


def test_m11_5_ablation_study_integrity():
    """Verify 6-track ablation study confirms M11.5 reliability over naive configurations."""
    evaluator = M11_5Evaluator()
    results = evaluator.run_all()
    ablation = results["ablation_study"]

    assert len(ablation) == 6
    assert "track_1_current_baseline" in ablation
    assert "track_2_increased_limit_only" in ablation
    assert "track_3_chunking_only" in ablation
    assert "track_4_chunking_plus_completeness" in ablation
    assert "track_5_chunking_plus_overlap" in ablation
    assert "track_6_full_m11_5" in ablation

    # Track 1 vs Track 6 comparisons
    t1 = ablation["track_1_current_baseline"]
    t6 = ablation["track_6_full_m11_5"]
    assert t1["silent_truncation_rate"] > 0.50
    assert t6["silent_truncation_rate"] == 0.00
    assert t6["completion_rate"] == 1.00
    assert t6["duplicated_content_rate"] == 0.00


def test_m11_5_security_invariants_pass():
    """Verify all 18 security invariants (INV-M11.5-01 through INV-M11.5-18)."""
    evaluator = M11_5Evaluator()
    results = evaluator.run_all()
    invariants = results["security_invariants"]

    assert len(invariants) == 18
    for inv_id, data in invariants.items():
        assert data["status"] == "PASSED", f"Invariant {inv_id} failed"
        assert data["violations"] == 0, f"Invariant {inv_id} had {data['violations']} violations"
