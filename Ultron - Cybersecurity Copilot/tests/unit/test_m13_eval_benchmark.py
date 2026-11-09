"""Unit tests for M13 Benchmark Dataset and Evaluator.

Validates that:
1. Dataset contains >= 350 structured cases covering all 24 required categories.
2. All 360 cases execute with 100% pass rate.
3. Hard invariant violations are strictly 0.
4. All 24 categories achieve 100% pass rate.
5. Benchmark results are persisted to data/eval/m13_evaluation_results.json.
"""

from pathlib import Path
import pytest

from src.eval.m13_dataset import M13Category, generate_m13_dataset
from src.eval.m13_evaluator import M13Evaluator


def test_m13_dataset_generation():
    """Verify dataset meets the required case count (>= 350) and all 24 categories."""
    dataset = generate_m13_dataset()
    assert len(dataset) >= 350, f"Expected >= 350 cases, got {len(dataset)}"
    assert len(dataset) == 360, f"Expected 360 cases, got {len(dataset)}"
    categories = {case.category for case in dataset}
    assert len(categories) == 24, f"Expected 24 categories, got {len(categories)}"

    # Ensure every category has at least 15 test cases
    for cat in M13Category:
        cat_cases = [c for c in dataset if c.category == cat]
        assert len(cat_cases) >= 15, f"Category {cat.value} has only {len(cat_cases)} cases"


def test_m13_evaluator_execution(tmp_path: Path):
    """Verify evaluator executes all 360 cases with 100% pass rate and zero violations."""
    out_file = tmp_path / "m13_eval_test.json"
    evaluator = M13Evaluator(output_path=str(out_file))
    results = evaluator.run_benchmark()

    assert results["total_cases"] == 360
    assert results["passed_cases"] == 360
    assert results["failed_cases"] == 0
    assert results["pass_rate"] == 1.0
    assert results["hard_invariant_violations"] == 0
    assert results["categories_evaluated"] == 24
    assert out_file.exists()


def test_m13_category_coverage(tmp_path: Path):
    """Verify that every single category achieves 100% pass rate."""
    out_file = tmp_path / "m13_eval_breakdown.json"
    evaluator = M13Evaluator(output_path=str(out_file))
    results = evaluator.run_benchmark()

    breakdown = results["category_breakdown"]
    for cat_name, stats in breakdown.items():
        assert stats["total"] >= 15, f"Category {cat_name} evaluated fewer than 15 cases"
        assert stats["failed"] == 0, f"Category {cat_name} had {stats['failed']} failures"
        assert stats["passed"] == stats["total"], f"Category {cat_name} did not achieve 100% pass rate"
