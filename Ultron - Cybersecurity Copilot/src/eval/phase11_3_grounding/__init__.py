"""
Milestone M5 Phase 11.3: Grounding Recovery Diagnostic Package.
"""

from src.eval.phase11_3_grounding.allowed_sets import (
    build_scenario_allowed_sets,
    extract_allowed_fact_ids,
    extract_allowed_target_ids,
    ScenarioAllowedSets,
)
from src.eval.phase11_3_grounding.grounding_protocol import (
    get_inference_schema_for_condition,
    render_p2_prompt_instruction,
    render_p3_prompt_instruction,
)
from src.eval.phase11_3_grounding.validator import (
    GroundingFailureCode,
    GroundingValidationResult,
    Phase11GroundingValidator,
)
from src.eval.phase11_3_grounding.runner import (
    DIAGNOSTIC_SCENARIO_IDS,
    FROZEN_ORDER_SEED,
    get_diagnostic_condition_order,
    Phase11GroundingDiagnosticRunner,
)
from src.eval.phase11_3_grounding.analysis import (
    analyze_phase11_3_results,
    ConditionMetrics,
    DiagnosticAnalysisResult,
)
from src.eval.phase11_3_grounding.report_generation import generate_phase11_3_report

__all__ = [
    "build_scenario_allowed_sets",
    "extract_allowed_fact_ids",
    "extract_allowed_target_ids",
    "ScenarioAllowedSets",
    "get_inference_schema_for_condition",
    "render_p2_prompt_instruction",
    "render_p3_prompt_instruction",
    "GroundingFailureCode",
    "GroundingValidationResult",
    "Phase11GroundingValidator",
    "DIAGNOSTIC_SCENARIO_IDS",
    "FROZEN_ORDER_SEED",
    "get_diagnostic_condition_order",
    "Phase11GroundingDiagnosticRunner",
    "analyze_phase11_3_results",
    "ConditionMetrics",
    "DiagnosticAnalysisResult",
    "generate_phase11_3_report",
]
