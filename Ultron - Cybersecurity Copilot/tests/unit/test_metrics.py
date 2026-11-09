"""Unit tests for M3 Statistical Metrics, Estimands & Reliability Scorers."""

import pytest
from src.eval.metrics import (
    calculate_scenario_yield,
    compute_aggregate_yield_rate,
    compute_fleiss_kappa,
    compute_krippendorff_alpha_ordinal,
    compute_mean_yield,
    paired_bca_bootstrap_ci,
    paired_monte_carlo_permutation_test,
)


def test_yield_calculations():
    # U=1, T=10 minutes, N=60 -> (1/10)*60 = 6.0
    y1 = calculate_scenario_yield(useful_score=1, mean_review_minutes=10.0, window_n=60.0)
    assert y1 == 6.0

    # U=0 -> yield = 0.0
    y2 = calculate_scenario_yield(useful_score=0, mean_review_minutes=5.0, window_n=60.0)
    assert y2 == 0.0

    mean_y = compute_mean_yield([y1, y2])
    assert mean_y == 3.0

    agg_rate = compute_aggregate_yield_rate(
        useful_scores=[1, 0],
        mean_review_minutes=[10.0, 5.0],
        window_n=60.0,
    )
    # (1 / 15) * 60 = 4.0
    assert agg_rate == 4.0


def test_paired_permutation_test_deterministic():
    diffs = [1.2, 0.5, 2.0, -0.1, 0.8, 1.5, 0.0, 1.1, 0.9, 1.4,
             0.3, 0.7, 1.8, -0.2, 0.6, 1.0, 0.4, 0.8, 1.3, 0.5]
    mean_d, p_val, z = paired_monte_carlo_permutation_test(diffs, r_permutations=1000, seed=42)
    assert mean_d == sum(diffs) / len(diffs)
    assert 0.0 <= p_val <= 1.0

    # Repeating with same seed yields exact same result
    m2, p2, z2 = paired_monte_carlo_permutation_test(diffs, r_permutations=1000, seed=42)
    assert mean_d == m2
    assert p_val == p2
    assert z == z2


def test_paired_bootstrap_ci_deterministic():
    diffs = [1.0] * 10 + [2.0] * 10
    mean_d, lo, hi = paired_bca_bootstrap_ci(diffs, b_resamples=500, seed=42)
    assert mean_d == 1.5
    assert lo <= 1.5 <= hi


def test_fleiss_kappa_and_krippendorff_alpha_perfect_agreement():
    # 5 units, 3 raters, perfect agreement
    matrix = [
        [5, 5, 5],
        [4, 4, 4],
        [3, 3, 3],
        [2, 2, 2],
        [1, 1, 1],
    ]
    kappa = compute_fleiss_kappa(matrix, num_classes=5)
    assert kappa == 1.0

    alpha = compute_krippendorff_alpha_ordinal(matrix, num_classes=5)
    assert alpha == 1.0


def test_fleiss_kappa_disagreement():
    # Disagreement matrix
    matrix = [
        [1, 2, 3],
        [4, 5, 1],
        [2, 3, 4],
        [5, 1, 2],
    ]
    kappa = compute_fleiss_kappa(matrix, num_classes=5)
    assert kappa < 0.2
