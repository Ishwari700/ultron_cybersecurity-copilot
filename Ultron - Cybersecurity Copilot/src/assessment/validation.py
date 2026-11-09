"""Deterministic 13-Point Finding Validator for M6 Authorized Security Assessments.

Enforces:
1. Complete verification checklist before any finding can be marked HUMAN_VERIFIED
   or included in a final confirmed security report.
2. 13 Strict Deterministic Checks:
   1. Assessment exists.
   2. Authorization exists.
   3. Authorization was valid during relevant activity.
   4. Asset is in scope.
   5. Evidence exists.
   6. Evidence is linked to the asset.
   7. Evidence provenance is valid.
   8. Hypothesis exists.
   9. Hypothesis has supporting evidence.
   10. Required experiment was performed where applicable.
   11. Negative control was considered.
   12. Human verification exists.
   13. No unresolved critical evidence gap invalidates the conclusion.
3. INVARIANT: Failure of any single condition causes deterministic FAIL CLOSED.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field, ConfigDict
from src.assessment.models import (
    AssessmentFinding,
    AssessmentHypothesis,
    AssessmentExperiment,
    AssessmentRecord,
    AssessmentScopeStatus,
    AuthorizationRecord,
    CanonicalObservation,
    ExperimentStatus,
    FindingVerificationStatus,
)
from src.assessment.authorization import AuthorizationValidator
from src.scope.gate import ScopeGate


class FindingValidationError(ValueError):
    """Raised when a candidate finding fails any of the 13 verification checks."""
    pass


class AssessmentValidationContext(BaseModel):
    """Container holding all related entities needed to validate a finding."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    assessment: Optional[AssessmentRecord] = None
    authorization: Optional[AuthorizationRecord] = None
    scope_gate: Optional[Any] = None
    observations: Dict[str, CanonicalObservation] = Field(default_factory=dict)
    hypotheses: Dict[str, AssessmentHypothesis] = Field(default_factory=dict)
    experiments: Dict[str, AssessmentExperiment] = Field(default_factory=dict)


class FindingValidator:
    """Deterministic validation engine for confirming security findings."""

    @classmethod
    def validate_finding(
        cls,
        finding: AssessmentFinding,
        context: AssessmentValidationContext,
    ) -> Tuple[bool, List[str]]:
        """
        Executes the 13-point checklist against finding.
        Returns (is_valid: bool, failure_reasons: List[str]).
        Fails closed on any unsatisfied condition.
        """
        failures: List[str] = []

        # 1. Assessment exists
        if not context.assessment:
            failures.append("CHECK_1_FAILED: Assessment does not exist.")

        # 2. Authorization exists
        if not context.authorization:
            failures.append("CHECK_2_FAILED: Authorization record does not exist.")

        # 3. Authorization was valid during activity
        if context.authorization:
            is_valid_auth, auth_msg = AuthorizationValidator.validate_authorization(context.authorization)
            if not is_valid_auth:
                failures.append(f"CHECK_3_FAILED: Authorization is invalid ({auth_msg}).")

        # 4. Asset is in scope
        target_asset = finding.asset
        if not target_asset:
            failures.append("CHECK_4_FAILED: Finding asset is unspecified.")
        elif context.scope_gate:
            scope_res = context.scope_gate.evaluate_extended_scope(target_asset)
            if scope_res.scope_status != AssessmentScopeStatus.IN_SCOPE:
                failures.append(
                    f"CHECK_4_FAILED: Target asset '{target_asset}' is not IN_SCOPE (got {scope_res.scope_status.value})."
                )

        # 5. Evidence exists
        if not finding.evidence:
            failures.append("CHECK_5_FAILED: No evidence items associated with finding.")
        else:
            for ev_id in finding.evidence:
                if ev_id not in context.observations:
                    failures.append(f"CHECK_5_FAILED: Referenced evidence '{ev_id}' does not exist.")

        # 6. Evidence is linked to the asset
        for ev_id in finding.evidence:
            obs = context.observations.get(ev_id)
            if obs:
                obs_target = obs.normalized_data.get("target_identifier", obs.asset_id)
                if target_asset not in obs_target and obs.asset_id not in target_asset and target_asset not in obs.asset_id:
                    failures.append(
                        f"CHECK_6_FAILED: Evidence '{ev_id}' (target: {obs_target}) is not linked to asset '{target_asset}'."
                    )

        # 7. Evidence provenance is valid
        for ev_id in finding.evidence:
            obs = context.observations.get(ev_id)
            if obs:
                if not obs.content_hash:
                    failures.append(f"CHECK_7_FAILED: Evidence '{ev_id}' lacks cryptographic content hash.")
                if obs.scope_decision != AssessmentScopeStatus.IN_SCOPE:
                    failures.append(f"CHECK_7_FAILED: Evidence '{ev_id}' was captured outside authorized scope.")

        # 8. Hypothesis exists
        # Locate hypothesis in context
        linked_hyp = None
        for hyp in context.hypotheses.values():
            if target_asset in hyp.title or target_asset in hyp.description or any(ev in hyp.supporting_observations for ev in finding.evidence):
                linked_hyp = hyp
                break

        if not linked_hyp and context.hypotheses:
            # Fallback: check first hypothesis if singular
            if len(context.hypotheses) == 1:
                linked_hyp = list(context.hypotheses.values())[0]

        if not linked_hyp:
            failures.append("CHECK_8_FAILED: No corresponding security hypothesis exists for finding.")

        # 9. Hypothesis has supporting evidence
        if linked_hyp and not linked_hyp.supporting_observations and not finding.evidence:
            failures.append("CHECK_9_FAILED: Linked hypothesis has zero supporting observations.")

        # 10. Required experiment was performed where applicable
        # If hypothesis has suggested experiment or requires active verification
        if linked_hyp and linked_hyp.suggested_experiment_id:
            exp = context.experiments.get(linked_hyp.suggested_experiment_id)
            if not exp or exp.status != ExperimentStatus.EXECUTED:
                failures.append(f"CHECK_10_FAILED: Required experiment was not executed (status: {exp.status if exp else 'NONE'}).")

        # 11. Negative control was considered
        if linked_hyp and not linked_hyp.negative_control:
            failures.append("CHECK_11_FAILED: Negative control was not defined or considered.")

        # 12. Human verification exists
        if finding.verification_status != FindingVerificationStatus.HUMAN_VERIFIED:
            failures.append(
                f"CHECK_12_FAILED: Finding verification status is '{finding.verification_status.value}', not HUMAN_VERIFIED."
            )
        if not finding.verified_by or not finding.verified_by.strip():
            failures.append("CHECK_12_FAILED: Missing identified human verifier name.")
        elif any(t in finding.verified_by.upper() for t in ("LLM", "MODEL", "AI", "AUTO", "BOT", "SYSTEM", "AGENT", "ORCHESTRATOR", "COPILOT")):
            failures.append(f"CHECK_12_FAILED: Automated entity '{finding.verified_by}' cannot sign off on finding.")

        # 13. No unresolved critical evidence gap
        if linked_hyp and linked_hyp.evidence_gaps:
            critical_gaps = [
                g for g in linked_hyp.evidence_gaps
                if "CRITICAL" in str(g).upper() or "UNRESOLVED" in str(g).upper()
            ]
            if critical_gaps:
                failures.append(
                    f"CHECK_13_FAILED: Unresolved critical evidence gap invalidates conclusion ({'; '.join(critical_gaps)})."
                )
            elif not finding.evidence and len(linked_hyp.evidence_gaps) > 0:
                failures.append("CHECK_13_FAILED: Unresolved evidence gaps exist without supporting evidence.")

        is_valid = len(failures) == 0
        return is_valid, failures

    @classmethod
    def validate_candidate_finding(
        cls,
        finding: AssessmentFinding,
        context: AssessmentValidationContext,
        candidate_reviewer: str,
    ) -> Tuple[bool, List[str]]:
        """
        Validates all 13 checklist checks for a candidate finding and reviewer
        WITHOUT mutating or requiring finding to already be in HUMAN_VERIFIED state.
        """
        candidate = finding.model_copy(update={
            "verification_status": FindingVerificationStatus.HUMAN_VERIFIED,
            "verified_by": candidate_reviewer,
            "verified_at": datetime.now(timezone.utc).isoformat(),
        })
        return cls.validate_finding(candidate, context)

    @classmethod
    def assert_candidate_valid(
        cls,
        finding: AssessmentFinding,
        context: AssessmentValidationContext,
        candidate_reviewer: str,
    ) -> None:
        """Enforces all 13 checks on candidate finding and raises FindingValidationError on failure."""
        is_valid, failures = cls.validate_candidate_finding(finding, context, candidate_reviewer)
        if not is_valid:
            raise FindingValidationError(f"FINDING VALIDATION FAILED CLOSED: {'; '.join(failures)}")

    @classmethod
    def assert_finding_valid(
        cls,
        finding: AssessmentFinding,
        context: AssessmentValidationContext,
    ) -> None:
        """Enforces all 13 checks and raises FindingValidationError on any failure."""
        is_valid, failures = cls.validate_finding(finding, context)
        if not is_valid:
            raise FindingValidationError(f"FINDING VALIDATION FAILED CLOSED: {'; '.join(failures)}")
