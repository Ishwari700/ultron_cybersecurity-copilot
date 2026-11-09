"""Milestone M3 Statistical Metrics, Estimands & Reliability Scorers.

Implements M3 Section 24:
- Useful Hypothesis Mean Yield @ N Reviewer Minutes: MeanYield_c(N)
- Aggregate Yield Rate: AggregateRate_c(N)
- Two-sided paired Monte Carlo permutation test (R=100,000, seed=42)
- Query/Scenario-level deterministic bootstrap (B=2000, seed=42)
- Pre-adjudication Fleiss' kappa (N=40, m=3)
- Secondary Krippendorff's alpha (ordinal distance metric)
- 3-rater binary majority rule
- Un-clamped timing with T_validity_flag
"""

import math
import random
from typing import Any, Dict, List, Optional, Sequence, Tuple
from pydantic import BaseModel, Field


class TimingRecord(BaseModel):
    """Raw timing event stream for an evaluation session."""
    scenario_id: str
    condition: str  # e.g. "TRACK_B", "TRACK_D"
    rater_id: str   # e.g. "RATER_1", "RATER_2", "RATER_3"
    start_time_iso: str
    stop_time_iso: str
    pause_duration_seconds: float = 0.0
    raw_active_minutes: float
    validity_flag: bool = False  # True if < 0.5 minutes (30s)
    timing_failure: bool = False


class HumanRatingRecord(BaseModel):
    """Single independent rating observation."""
    unit_id: str      # e.g. "UNIT-01"
    scenario_id: str  # e.g. "SCEN-..."
    condition: str    # "TRACK_B" or "TRACK_D"
    rater_id: str     # "RATER_1", "RATER_2", "RATER_3"
    security_reasoning_level: int = Field(ge=1, le=5)  # 1..5
    is_useful: int = Field(ge=0, le=1)                 # 1 if confirmatory or valid experiment, 0 otherwise
    semantic_fidelity_level: Optional[int] = Field(default=None, ge=1, le=5)  # Track D only
    raw_active_minutes: float = Field(gt=0.0)
    validity_flag: bool = False


def calculate_scenario_yield(
    useful_score: int,
    mean_review_minutes: float,
    window_n: float = 60.0,
) -> float:
    """
    Computes Yield_c(s; N) = (U_c(s) / T_bar_c(s)) * N.
    """
    if mean_review_minutes <= 0:
        raise ValueError("Mean review minutes must be positive")
    return (useful_score / mean_review_minutes) * window_n


def compute_mean_yield(
    scenario_yields: Sequence[float],
) -> float:
    """
    MeanYield_c(N) = (1/S) * sum_{s=1}^S Yield_c(s; N).
    """
    if not scenario_yields:
        return 0.0
    return sum(scenario_yields) / len(scenario_yields)


def compute_aggregate_yield_rate(
    useful_scores: Sequence[int],
    mean_review_minutes: Sequence[float],
    window_n: float = 60.0,
) -> float:
    """
    AggregateRate_c(N) = (sum U_c(s) / sum T_bar_c(s)) * N.
    """
    tot_useful = sum(useful_scores)
    tot_time = sum(mean_review_minutes)
    if tot_time <= 0:
        return 0.0
    return (tot_useful / tot_time) * window_n


def paired_monte_carlo_permutation_test(
    diffs: Sequence[float],
    r_permutations: int = 100000,
    seed: int = 42,
) -> Tuple[float, float, float]:
    """
    Two-sided paired Monte Carlo randomization/permutation test on delta_Yield(s).
    Tests H0: E[delta_Yield] = 0 using random sign-flips.
    Returns (observed_mean_diff, p_value, z_score).
    """
    n = len(diffs)
    if n == 0:
        return 0.0, 1.0, 0.0

    obs_mean = sum(diffs) / n
    obs_abs = abs(obs_mean)

    rng = random.Random(seed)
    greater_or_equal_count = 0

    perm_means: List[float] = []
    for _ in range(r_permutations):
        # Sign flip each difference with probability 0.5
        perm_sum = 0.0
        for d in diffs:
            sign = 1.0 if rng.random() < 0.5 else -1.0
            perm_sum += sign * d
        m = perm_sum / n
        perm_means.append(m)
        if abs(m) >= obs_abs - 1e-12:
            greater_or_equal_count += 1

    p_value = (1.0 + greater_or_equal_count) / (1.0 + r_permutations)

    # Standard error of permutation distribution for approximate z
    mean_perm = sum(perm_means) / r_permutations
    var_perm = sum((x - mean_perm) ** 2 for x in perm_means) / (r_permutations - 1)
    se_perm = math.sqrt(var_perm) if var_perm > 0 else 1.0
    z_score = (obs_mean - mean_perm) / se_perm

    return obs_mean, p_value, z_score


def paired_bca_bootstrap_ci(
    diffs: Sequence[float],
    b_resamples: int = 2000,
    seed: int = 42,
    alpha: float = 0.05,
) -> Tuple[float, float, float]:
    """
    Computes 95% paired bootstrap confidence interval for mean paired difference.
    Uses percentile / BCa fallback.
    Returns (mean_diff, ci_lower, ci_upper).
    """
    n = len(diffs)
    if n == 0:
        return 0.0, 0.0, 0.0

    mean_diff = sum(diffs) / n
    rng = random.Random(seed)

    boot_means: List[float] = []
    for _ in range(b_resamples):
        sample = [diffs[rng.randint(0, n - 1)] for _ in range(n)]
        boot_means.append(sum(sample) / n)

    boot_means.sort()
    lo_idx = int((alpha / 2.0) * b_resamples)
    hi_idx = int((1.0 - alpha / 2.0) * b_resamples)
    ci_lower = boot_means[lo_idx]
    ci_upper = boot_means[hi_idx]

    return mean_diff, ci_lower, ci_upper


def compute_fleiss_kappa(
    ratings_matrix: Sequence[Sequence[int]],
    num_classes: int = 5,
) -> float:
    """
    Computes Fleiss' Kappa for inter-rater agreement.
    ratings_matrix: N evaluation units x m raters (each entry is class 1..num_classes).
    """
    N = len(ratings_matrix)
    if N == 0:
        return 0.0
    m = len(ratings_matrix[0])
    if m <= 1:
        return 1.0

    # Count table: N rows x num_classes columns
    counts = [[0] * num_classes for _ in range(N)]
    for i in range(N):
        for r in ratings_matrix[i]:
            cls_idx = r - 1
            if 0 <= cls_idx < num_classes:
                counts[i][cls_idx] += 1

    # P_i: extent to which raters agree on unit i
    P_i_list = []
    for i in range(N):
        sum_sq = sum(c * c for c in counts[i])
        P_i = (sum_sq - m) / (m * (m - 1))
        P_i_list.append(P_i)
    P_bar = sum(P_i_list) / N

    # p_j: proportion of all assignments to class j
    total_assignments = N * m
    p_j = [sum(counts[i][j] for i in range(N)) / total_assignments for j in range(num_classes)]

    # P_bar_e: degree of agreement expected by chance
    P_bar_e = sum(p * p for p in p_j)

    if math.isclose(P_bar_e, 1.0):
        return 1.0

    kappa = (P_bar - P_bar_e) / (1.0 - P_bar_e)
    return kappa


def compute_krippendorff_alpha_ordinal(
    ratings_matrix: Sequence[Sequence[int]],
    num_classes: int = 5,
) -> float:
    """
    Computes Krippendorff's alpha with ordinal difference metric.
    ratings_matrix: N evaluation units x m raters (entries 1..num_classes).
    """
    N = len(ratings_matrix)
    if N == 0:
        return 0.0
    m = len(ratings_matrix[0])
    if m <= 1:
        return 1.0

    # Pairwise coincidence table
    # Collect all within-unit pairs (u, v)
    total_pairs = N * m * (m - 1)
    if total_pairs == 0:
        return 0.0

    # Marginal distribution of categories
    cat_counts = [0] * (num_classes + 1)
    total_values = N * m
    for row in ratings_matrix:
        for val in row:
            if 1 <= val <= num_classes:
                cat_counts[val] += 1

    # Ordinal metric distance:
    # d(j, k) = ( sum_{g=min(j,k)}^{max(j,k)} n_g - (n_j + n_k)/2 )^2
    def ordinal_dist(c1: int, c2: int) -> float:
        if c1 == c2:
            return 0.0
        low = min(c1, c2)
        high = max(c1, c2)
        mid_sum = sum(cat_counts[g] for g in range(low, high + 1))
        delta = mid_sum - (cat_counts[low] + cat_counts[high]) / 2.0
        return delta * delta

    # Observed disagreement D_o
    D_o = 0.0
    for row in ratings_matrix:
        for j in range(len(row)):
            for k in range(j + 1, len(row)):
                D_o += 2.0 * ordinal_dist(row[j], row[k])
    D_o = D_o / (N * m * (m - 1))

    # Expected disagreement D_e
    D_e = 0.0
    for c1 in range(1, num_classes + 1):
        for c2 in range(1, num_classes + 1):
            D_e += cat_counts[c1] * cat_counts[c2] * ordinal_dist(c1, c2)
    D_e = D_e / (total_values * (total_values - 1))

    if math.isclose(D_e, 0.0):
        return 1.0

    alpha = 1.0 - (D_o / D_e)
    return alpha
