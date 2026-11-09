"""Milestone M5 Phase 11.6: Production Pipeline Validation Package.

Contains deterministic local fixtures, end-to-end pipeline validation harness,
failure injection tests, and report generation using exclusively verified
production repository interfaces.
"""

from src.eval.phase11_6_production.fixtures import get_validation_fixtures, ProductionFixture
from src.eval.phase11_6_production.pipeline import ProductionPipelineHarness, PipelineExecutionResult
from src.eval.phase11_6_production.failure_injection import run_failure_injections, FailureInjectionResult

__all__ = [
    "get_validation_fixtures",
    "ProductionFixture",
    "ProductionPipelineHarness",
    "PipelineExecutionResult",
    "run_failure_injections",
    "FailureInjectionResult",
]
