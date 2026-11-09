"""
Milestone M5 Phase 11.1: Failure Corpus & Root-Cause Analysis Package.
"""

from src.eval.phase11_failure_analysis.taxonomy import (
    FailureCode,
    FailureNature,
    FailureAttributionResult,
    TAXONOMY_METADATA,
)
from src.eval.phase11_failure_analysis.attribution import attribute_failure
from src.eval.phase11_failure_analysis.corpus_builder import (
    build_corpus_records,
    export_failure_corpus,
)
from src.eval.phase11_failure_analysis.action_analysis import run_action_selection_analysis
from src.eval.phase11_failure_analysis.polarity_analysis import run_polarity_analysis
from src.eval.phase11_failure_analysis.context_analysis import run_context_package_analysis
from src.eval.phase11_failure_analysis.cascade_analysis import run_cascade_handoff_analysis
from src.eval.phase11_failure_analysis.rag_analysis import run_rag_knowledge_analysis

__all__ = [
    "FailureCode",
    "FailureNature",
    "FailureAttributionResult",
    "TAXONOMY_METADATA",
    "attribute_failure",
    "build_corpus_records",
    "export_failure_corpus",
    "run_action_selection_analysis",
    "run_polarity_analysis",
    "run_context_package_analysis",
    "run_cascade_handoff_analysis",
    "run_rag_knowledge_analysis",
]
