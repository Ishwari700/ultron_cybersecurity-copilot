"""Human Review Workspace and Verification Gates for M6.

Enforces:
1. Interactive human reviewer workspace presenting:
   Assessment, Authorization, Scope, Assets, Observations, Hypotheses,
   Evidence Gaps, Experiments, Negative Controls, External Research, and Findings.
2. Explicit human actions:
   ACCEPT_HYPOTHESIS, REQUEST_EVIDENCE, MARK_REFUTED,
   APPROVE_EXPERIMENT, REJECT_EXPERIMENT, VERIFY_FINDING, REJECT_FINDING.
3. INVARIANT: AUTO-CONFIRM is strictly forbidden. Finding promotion requires
   an identifiable human reviewer, valid timestamp, and justification.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from src.assessment.models import (
    AssessmentFinding,
    AssessmentHypothesis,
    AssessmentHypothesisStatus,
    AssessmentExperiment,
    ExperimentStatus,
    FindingVerificationStatus,
)


class HumanReviewWorkspace:
    """Manages the human-in-the-loop review actions and gatekeeping."""

    def __init__(self, assessment_id: str) -> None:
        self.assessment_id = assessment_id
        self.hypotheses: Dict[str, AssessmentHypothesis] = {}
        self.experiments: Dict[str, AssessmentExperiment] = {}
        self.findings: Dict[str, AssessmentFinding] = {}
        self.review_audit_log: List[Dict[str, Any]] = []

    def load_hypothesis(self, hyp: AssessmentHypothesis) -> None:
        self.hypotheses[hyp.hypothesis_id] = hyp

    def load_experiment(self, exp: AssessmentExperiment) -> None:
        self.experiments[exp.experiment_id] = exp

    def load_finding(self, finding: AssessmentFinding) -> None:
        self.findings[finding.finding_id] = finding

    # -----------------------------------------------------------------------
    # Explicit Human Actions on Hypotheses
    # -----------------------------------------------------------------------

    def accept_hypothesis(self, hypothesis_id: str, human_reviewer: str, notes: str) -> AssessmentHypothesis:
        self._assert_human_actor(human_reviewer, "accept_hypothesis")
        if hypothesis_id not in self.hypotheses:
            raise KeyError(f"Hypothesis {hypothesis_id} not found.")
        hyp = self.hypotheses[hypothesis_id]
        hyp.status = AssessmentHypothesisStatus.SUPPORTED
        hyp.verification_notes = f"Accepted by {human_reviewer}: {notes}"
        self._log_action("ACCEPT_HYPOTHESIS", hypothesis_id, human_reviewer, notes)
        return hyp

    def request_evidence(self, hypothesis_id: str, human_reviewer: str, gap_description: str) -> AssessmentHypothesis:
        self._assert_human_actor(human_reviewer, "request_evidence")
        if hypothesis_id not in self.hypotheses:
            raise KeyError(f"Hypothesis {hypothesis_id} not found.")
        hyp = self.hypotheses[hypothesis_id]
        hyp.status = AssessmentHypothesisStatus.NEEDS_EVIDENCE
        hyp.evidence_gaps.append(gap_description)
        self._log_action("REQUEST_EVIDENCE", hypothesis_id, human_reviewer, gap_description)
        return hyp

    def mark_hypothesis_refuted(self, hypothesis_id: str, human_reviewer: str, refutation_notes: str) -> AssessmentHypothesis:
        self._assert_human_actor(human_reviewer, "mark_hypothesis_refuted")
        if hypothesis_id not in self.hypotheses:
            raise KeyError(f"Hypothesis {hypothesis_id} not found.")
        hyp = self.hypotheses[hypothesis_id]
        hyp.status = AssessmentHypothesisStatus.REFUTED
        hyp.verification_notes = f"Refuted by {human_reviewer}: {refutation_notes}"
        self._log_action("MARK_REFUTED", hypothesis_id, human_reviewer, refutation_notes)
        return hyp

    # -----------------------------------------------------------------------
    # Explicit Human Actions on Experiments
    # -----------------------------------------------------------------------

    def approve_experiment(self, experiment_id: str, human_reviewer: str) -> AssessmentExperiment:
        self._assert_human_actor(human_reviewer, "approve_experiment")
        if experiment_id not in self.experiments:
            raise KeyError(f"Experiment {experiment_id} not found.")
        exp = self.experiments[experiment_id]
        exp.status = ExperimentStatus.APPROVED
        self._log_action("APPROVE_EXPERIMENT", experiment_id, human_reviewer, "Protocol approved for manual run.")
        return exp

    def reject_experiment(self, experiment_id: str, human_reviewer: str, reason: str) -> AssessmentExperiment:
        self._assert_human_actor(human_reviewer, "reject_experiment")
        if experiment_id not in self.experiments:
            raise KeyError(f"Experiment {experiment_id} not found.")
        exp = self.experiments[experiment_id]
        exp.status = ExperimentStatus.REJECTED
        self._log_action("REJECT_EXPERIMENT", experiment_id, human_reviewer, reason)
        return exp

    # -----------------------------------------------------------------------
    # Explicit Human Actions on Findings
    # -----------------------------------------------------------------------

    def verify_finding(self, finding_id: str, human_reviewer: str, justification: str) -> AssessmentFinding:
        """
        Human gate for confirming a finding.
        Auto-confirm is strictly prohibited.
        """
        self._assert_human_actor(human_reviewer, "verify_finding")
        if not justification or len(justification.strip()) < 10:
            raise ValueError("VERIFICATION_REJECTED: Substantive human justification required.")

        if finding_id not in self.findings:
            raise KeyError(f"Finding {finding_id} not found.")

        finding = self.findings[finding_id]
        finding.verification_status = FindingVerificationStatus.HUMAN_VERIFIED
        finding.verified_by = human_reviewer
        finding.verified_at = datetime.now(timezone.utc).isoformat()
        self._log_action("VERIFY_FINDING", finding_id, human_reviewer, justification)
        return finding

    def reject_finding(self, finding_id: str, human_reviewer: str, reason: str) -> AssessmentFinding:
        self._assert_human_actor(human_reviewer, "reject_finding")
        if finding_id not in self.findings:
            raise KeyError(f"Finding {finding_id} not found.")
        finding = self.findings[finding_id]
        finding.verification_status = FindingVerificationStatus.REJECTED
        self._log_action("REJECT_FINDING", finding_id, human_reviewer, reason)
        return finding

    @staticmethod
    def _assert_human_actor(actor: str, action: str) -> None:
        """Ensures that no LLM or automated subsystem masquerades as a human reviewer."""
        if not actor or not actor.strip():
            raise PermissionError(f"ACTION_DENIED: {action} requires an identified human reviewer.")
        actor_clean = actor.upper().strip()
        if any(token in actor_clean for token in ("LLM", "MODEL", "AI", "AUTO", "COPILOT", "BOT", "SYSTEM")):
            raise PermissionError(
                f"SAFETY_VIOLATION: Automated agent '{actor}' cannot perform human action '{action}'. AUTO-CONFIRM IS BLOCKED."
            )

    def _log_action(self, action: str, entity_id: str, actor: str, notes: str) -> None:
        self.review_audit_log.append({
            "action": action,
            "entity_id": entity_id,
            "actor": actor,
            "notes": notes,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
