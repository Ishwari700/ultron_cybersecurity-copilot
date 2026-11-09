"""Evaluation harness, headless simulator, and ablation runners."""

from src.eval.synthetic_app import SyntheticApp
from src.eval.simulator import HeadlessSimulator, ExperimentExecutionResult
from src.eval.scenarios import EvaluationScenario, get_gold_set_scenarios
from src.eval.scorer import (
    EvaluationMetrics,
    DeterministicScorer,
    EvaluationApplicabilityState,
    ReviewerPresentationLabel,
    Policy3ScenarioEvaluation,
    Policy3EvaluationMetrics,
    Policy3DeterministicScorer,
    canonical_vulnerability_evidence_present,
    determine_applicability_state,
)
from src.eval.ablation import AblationFramework

__all__ = [
    "SyntheticApp",
    "HeadlessSimulator",
    "ExperimentExecutionResult",
    "EvaluationScenario",
    "get_gold_set_scenarios",
    "EvaluationMetrics",
    "DeterministicScorer",
    "EvaluationApplicabilityState",
    "ReviewerPresentationLabel",
    "Policy3ScenarioEvaluation",
    "Policy3EvaluationMetrics",
    "Policy3DeterministicScorer",
    "canonical_vulnerability_evidence_present",
    "determine_applicability_state",
    "AblationFramework",
]
