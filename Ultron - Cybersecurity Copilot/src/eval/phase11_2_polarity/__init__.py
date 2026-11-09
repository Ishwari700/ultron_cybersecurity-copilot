"""
Milestone M5 Phase 11.2: Polarity Representation Diagnostic Package.

Exports:
- AttackPredicate, SecurityPropertyDomain
- derive_outcomes_from_attack_predicate, OutcomeBindingResult
- P1BairJsonObject, parse_p1_response
- Phase11PolarityDiagnosticRunner, DIAGNOSTIC_SCENARIO_IDS
- analyze_diagnostic_results, run_historical_replay_simulation
- generate_phase11_2_report
"""

from src.eval.phase11_2_polarity.attack_predicate import (
    AttackPredicate,
    SecurityPropertyDomain,
    CATEGORY_SECURITY_PROPERTY_MAP,
)
from src.eval.phase11_2_polarity.outcome_binding import (
    derive_outcomes_from_attack_predicate,
    OutcomeBindingResult,
    CANONICAL_PRIMARY_OUTCOME_PAIRS,
)
from src.eval.phase11_2_polarity.protocol import (
    P1_PROMPT_INSTRUCTION,
    P1BairJsonObject,
    parse_p1_response,
)
from src.eval.phase11_2_polarity.runner import (
    Phase11PolarityDiagnosticRunner,
    DIAGNOSTIC_SCENARIO_IDS,
    get_diagnostic_condition_order,
)
from src.eval.phase11_2_polarity.analysis import (
    analyze_diagnostic_results,
    run_historical_replay_simulation,
)
from src.eval.phase11_2_polarity.report_generation import (
    generate_phase11_2_report,
)

__all__ = [
    "AttackPredicate",
    "SecurityPropertyDomain",
    "CATEGORY_SECURITY_PROPERTY_MAP",
    "derive_outcomes_from_attack_predicate",
    "OutcomeBindingResult",
    "CANONICAL_PRIMARY_OUTCOME_PAIRS",
    "P1_PROMPT_INSTRUCTION",
    "P1BairJsonObject",
    "parse_p1_response",
    "Phase11PolarityDiagnosticRunner",
    "DIAGNOSTIC_SCENARIO_IDS",
    "get_diagnostic_condition_order",
    "analyze_diagnostic_results",
    "run_historical_replay_simulation",
    "generate_phase11_2_report",
]
