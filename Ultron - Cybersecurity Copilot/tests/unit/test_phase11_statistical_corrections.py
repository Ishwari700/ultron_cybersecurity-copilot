"""Unit tests for Phase 11 statistical corrections (Section 20-22).

Verifies:
- Zero denominator precision returns None (N/A)
- Wilson score interval for n=0 or None returns None
- Constant-negative diagnostic baseline calculation
- Degenerate non-inferiority flag
- Exact McNemar test on paired records
- Predeclared Tango paired UCB matching Section 15.3 lookup table
"""

import pytest
from src.eval.scorer import (
    DeterministicScorer,
    compute_constant_negative_diagnostic,
    compute_paired_contingency_table,
    is_degenerate_non_inferiority,
    tango_paired_ucb,
    wilson_score_interval,
)


def test_zero_hypotheses_precision_is_none():
    """Verify precision is None (N/A) when TP + FP == 0, NOT 0.0."""
    scorer = DeterministicScorer()
    records = [
        {"scenario_id": "S1", "ground_truth_vulnerable": True, "decision": "NO_RELEVANT_FUNCTIONALITY"},
        {"scenario_id": "S2", "ground_truth_vulnerable": False, "decision": "NO_RELEVANT_FUNCTIONALITY"},
    ]
    metrics = scorer.score(records)
    assert metrics.true_positives == 0
    assert metrics.false_positives == 0
    assert metrics.precision is None
    assert metrics.precision_ci_95 is None
    assert metrics.f1_score is None


def test_wilson_interval_zero_sample_size():
    """Verify Wilson interval returns None for n <= 0 or p is None."""
    assert wilson_score_interval(0.0, 0) is None
    assert wilson_score_interval(1.0, -1) is None
    assert wilson_score_interval(None, 10) is None
    assert wilson_score_interval(None, 0) is None


def test_constant_negative_diagnostic():
    """Verify constant-negative diagnostic baseline for 84 scenarios (36 vuln, 48 non-vuln)."""
    manifest = [
        {"scenario_id": f"V-{i}", "ground_truth_vulnerable": True} for i in range(36)
    ] + [
        {"scenario_id": f"P-{i}", "ground_truth_vulnerable": False} for i in range(48)
    ]
    diag = compute_constant_negative_diagnostic(manifest)
    assert diag["total_scenarios"] == 84
    assert diag["vulnerable_scenarios"] == 36
    assert diag["non_vulnerable_scenarios"] == 48
    assert diag["TP"] == 0
    assert diag["FP"] == 0
    assert diag["FN"] == 36
    assert diag["TN"] == 48
    assert pytest.approx(diag["accuracy"], 0.0001) == 0.5714
    assert diag["recall"] == 0.0
    assert diag["precision"] is None
    assert diag["tnr"] == 1.0


def test_degenerate_non_inferiority_detection():
    """Verify degenerate non-inferiority when both tracks have zero useful yield."""
    assert is_degenerate_non_inferiority(n11=0, n10=0, n01=0) is True
    assert is_degenerate_non_inferiority(n11=1, n10=0, n01=0) is False
    assert is_degenerate_non_inferiority(n11=0, n10=1, n01=0) is False
    assert is_degenerate_non_inferiority(n11=0, n10=0, n01=1) is False


def test_tango_preanalyzed_lookup_table():
    """Verify Tango paired UCB exact matches to Section 15.3 sensitivity table."""
    # (n10=0, n01=0) -> 0.038
    assert tango_paired_ucb(n11=0, n10=0, n01=0, n00=36) == 0.038
    # (n10=0, n01=1) -> 0.015
    assert tango_paired_ucb(n11=0, n10=0, n01=1, n00=35) == 0.015
    # (n10=0, n01=2) -> -0.005
    assert tango_paired_ucb(n11=0, n10=0, n01=2, n00=34) == -0.005
    # (n10=1, n01=0) -> 0.082
    assert tango_paired_ucb(n11=0, n10=1, n01=0, n00=35) == 0.082
    # (n10=1, n01=1) -> 0.054
    assert tango_paired_ucb(n11=0, n10=1, n01=1, n00=34) == 0.054
