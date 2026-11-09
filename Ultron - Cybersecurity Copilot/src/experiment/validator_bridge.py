"""Milestone M11.8: Finding Validation Integration Bridge.

Enforces:
1. Strict Epistemic Pipeline:
   PoC → Execution Result → Observation → Evidence → Falsification → ReviewCase → Human Verification → FindingValidator → Verified Finding.
2. Invariant INV-M11-12: Observation cannot automatically become HUMAN_VERIFIED_FINDING.
3. Invariant INV-M11-13: FindingValidator remains authoritative (no second finding gate).
4. FindingCandidate generation: Remains unverified until explicit human review and validation.
"""

from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from src.experiment.models import ControlledExperiment
from src.experiment.observation import ControlledObservation
from src.experiment.falsification import FalsificationReport
from src.experiment.poc import SafePoC
from src.review.review_models import (
    ReviewCase,
    ReviewStatus,
    ReviewTargetType,
    ReviewerDecision,
)
from src.assessment.models import (
    AssessmentFinding,
    FindingVerificationStatus,
)
from src.assessment.validation import (
    AssessmentValidationContext,
    FindingValidator,
)


class FindingCandidate(BaseModel):
    """
    Candidate finding entity produced by an experiment.
    Strictly unverified (epistemic status = FINDING_CANDIDATE).
    """
    candidate_id: str
    assessment_id: str
    hypothesis_id: str
    experiment_id: str
    title: str
    target_asset: str
    observation_ids: List[str] = Field(default_factory=list)
    evidence_ids: List[str] = Field(default_factory=list)
    falsification_outcome: str
    confidence: float
    evidence_gaps: List[str] = Field(default_factory=list)
    epistemic_status: str = "FINDING_CANDIDATE"  # UNVERIFIED
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class FindingValidationBridge:
    """
    Bridges experiment outcomes with the canonical Human Review and FindingValidator pipelines.
    """

    @classmethod
    def create_finding_candidate(
        cls,
        experiment: ControlledExperiment,
        poc: Optional[SafePoC],
        observation: ControlledObservation,
        falsification: FalsificationReport,
    ) -> FindingCandidate:
        """
        Creates an unverified FindingCandidate.
        Under no circumstance is this marked as verified (INV-M11-12).
        """
        title = poc.title if poc else f"Experiment finding for {experiment.hypothesis_id}"
        target = experiment.target_id or experiment.asset_id or "LOCAL_LAB_TARGET"

        seed = f"{experiment.assessment_id}:{experiment.experiment_id}:{observation.observation_id}"
        cand_id = f"FCAND-M11-{hashlib.sha256(seed.encode()).hexdigest()[:10].upper()}"

        return FindingCandidate(
            candidate_id=cand_id,
            assessment_id=experiment.assessment_id,
            hypothesis_id=experiment.hypothesis_id,
            experiment_id=experiment.experiment_id,
            title=title,
            target_asset=target,
            observation_ids=[observation.observation_id],
            evidence_ids=[observation.content_hash],
            falsification_outcome=falsification.outcome.value,
            confidence=falsification.confidence,
            evidence_gaps=falsification.evidence_gaps,
            epistemic_status="FINDING_CANDIDATE",
        )

    @classmethod
    def create_review_case(
        cls,
        candidate: FindingCandidate,
        experiment: ControlledExperiment,
        poc: Optional[SafePoC] = None,
    ) -> ReviewCase:
        """
        Submits candidate to human review queue as a ReviewCase with PENDING status.
        """
        seed = f"{candidate.candidate_id}:{candidate.assessment_id}"
        rev_id = f"REV-M11-{hashlib.sha256(seed.encode()).hexdigest()[:10].upper()}"

        return ReviewCase(
            review_id=rev_id,
            assessment_id=candidate.assessment_id,
            target_id=candidate.candidate_id,
            target_type=ReviewTargetType.TENTATIVE_FINDING,
            title=candidate.title,
            description=poc.objective if poc else "Security hypothesis under experimental review",
            severity="MEDIUM",
            affected_asset=candidate.target_asset,
            status=ReviewStatus.PENDING,
            epistemic_status="HUMAN_REVIEW_PENDING",
            supporting_evidence=candidate.evidence_ids,
            evidence_gaps=candidate.evidence_gaps,
            falsification_result=experiment.falsification_result,
        )

    @classmethod
    def validate_with_authoritative_validator(
        cls,
        finding: AssessmentFinding,
        context: AssessmentValidationContext,
    ) -> Tuple[bool, List[str]]:
        """
        Invokes authoritative FindingValidator (13-point check).
        Enforces INV-M11-13: FindingValidator remains authoritative.
        """
        return FindingValidator.validate_finding(finding, context)
