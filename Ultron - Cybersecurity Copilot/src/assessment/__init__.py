"""M6 Authorized Security Assessment & Pentest Copilot Package.

Provides deterministic authorization, scope enforcement, asset modeling,
passive telemetry ingestion, attack surface mapping, safe experiment protocols,
human review workspace, and finding validation.
"""

from src.assessment.models import (
    AssessmentLifecycleState,
    AuthorizationStatus,
    AuthorizationType,
    AuthorizationRecord,
    AssessmentRecord,
    AssessmentScopeStatus,
    AssetType,
    AssetRecord,
    ObservationType,
    CanonicalObservation,
    AttackSurfaceState,
    SecurityInvariantType,
    SecurityInvariant,
    AssessmentHypothesisStatus,
    AssessmentHypothesis,
    EpistemicStatus,
    ExperimentRiskLevel,
    ExperimentStatus,
    AssessmentExperiment,
    FindingSeverity,
    FindingVerificationStatus,
    AssessmentFinding,
    AssessmentAuditRecord,
)
from src.assessment.authorization import AuthorizationValidator
from src.assessment.lifecycle import AssessmentLifecycleEngine

__all__ = [
    "AssessmentLifecycleState",
    "AuthorizationStatus",
    "AuthorizationType",
    "AuthorizationRecord",
    "AssessmentRecord",
    "AssessmentScopeStatus",
    "AssetType",
    "AssetRecord",
    "ObservationType",
    "CanonicalObservation",
    "AttackSurfaceState",
    "SecurityInvariantType",
    "SecurityInvariant",
    "AssessmentHypothesisStatus",
    "AssessmentHypothesis",
    "EpistemicStatus",
    "ExperimentRiskLevel",
    "ExperimentStatus",
    "AssessmentExperiment",
    "FindingSeverity",
    "FindingVerificationStatus",
    "AssessmentFinding",
    "AssessmentAuditRecord",
    "AuthorizationValidator",
    "AssessmentLifecycleEngine",
]
