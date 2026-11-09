"""Unit tests for M3.16 RETRIEVAL_FINAL_EVAL Generalization Evaluation."""

import json
from pathlib import Path
import pytest

from src.eval.retrieval_final_eval import (
    deterministic_query_bootstrap_ci,
    run_retrieval_final_evaluation,
)


def test_deterministic_query_bootstrap_ci():
    values = [1.0, 1.0, 0.5, 0.0, 1.0, 1.0, 0.0, 0.5, 1.0, 1.0]
    pt, lo, hi = deterministic_query_bootstrap_ci(values, b_resamples=500, seed=42)
    assert pt == sum(values) / len(values)
    assert lo <= pt <= hi

    # Exact repeatability
    pt2, lo2, hi2 = deterministic_query_bootstrap_ci(values, b_resamples=500, seed=42)
    assert pt == pt2
    assert lo == lo2
    assert hi == hi2


def test_retrieval_final_eval_results_file_exists():
    results_path = Path("data/eval/retrieval_final_eval_results.json")
    assert results_path.exists(), "Results file data/eval/retrieval_final_eval_results.json should exist"

    with open(results_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data["evaluation_name"] == "RETRIEVAL_FINAL_EVAL_GENERALIZATION"
    assert data["query_count"] == 15
    assert "recall_at_5" in data["metrics"]
    assert "mrr_at_5" in data["metrics"]
    assert "injection_hit_at_p4_256" in data["metrics"]
    assert data["metrics"]["recall_at_5"]["point_estimate"] >= 0.80
    assert data["metrics"]["mrr_at_5"]["point_estimate"] >= 0.60
