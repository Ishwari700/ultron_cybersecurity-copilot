"""
Milestone M5 Phase 11.5: Confirmatory Benchmark Package.
"""

from src.eval.phase11_5_confirmatory.runner import (
    EXPECTED_PHASE10_POPULATION_DIGEST,
    FROZEN_ORDER_SEED,
    get_scenario_condition_order,
    Phase11_5ConfirmatoryRunner,
)
from src.eval.phase11_5_confirmatory.analysis import (
    analyze_phase11_5_confirmatory,
    compute_condition_metrics,
    compute_paired_comparison,
    exact_mcnemar_test,
    ConfirmatoryConditionMetrics,
    PairedComparisonResult,
    Phase11_5AnalysisReport,
)
from src.eval.phase11_5_confirmatory.report_generation import generate_phase11_5_report

__all__ = [
    "EXPECTED_PHASE10_POPULATION_DIGEST",
    "FROZEN_ORDER_SEED",
    "get_scenario_condition_order",
    "Phase11_5ConfirmatoryRunner",
    "analyze_phase11_5_confirmatory",
    "compute_condition_metrics",
    "compute_paired_comparison",
    "exact_mcnemar_test",
    "ConfirmatoryConditionMetrics",
    "PairedComparisonResult",
    "Phase11_5AnalysisReport",
    "generate_phase11_5_report",
]
