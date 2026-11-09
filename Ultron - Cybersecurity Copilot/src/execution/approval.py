"""Human Approval Binding and Verification Gate for Milestone M2.75.

Enforces:
- Pre-execution human approval is MANDATORY for all STATE_CHANGING_REQUIRES_APPROVAL
  and DESTRUCTIVE_ISOLATED_DATA experiments.
- Cryptographic binding: Approval is bound to an authoritative SHA-256 digest of the
  complete ExecutionDescriptor (experiment ID, identity ID, environment context,
  target authority, destination URL, resolved IP, HTTP method, normalized route,
  canonical query, request body digest, safety level, affected resource, expected state transition).
- Recomputed immediately before outbound dispatch to guarantee zero TOCTOU tampering.
- Missing, expired, cross-identity, cross-environment, or mutated approvals fail closed with BLOCKED_APPROVAL.
"""

from typing import Dict, Optional, Tuple
from src.execution.models import ExecutionDescriptor, HumanApproval
from src.hypothesis.experiment import SafetyLevel


class ApprovalGate:
    """Validates human approval bindings prior to irreversible state change or transmission."""

    def __init__(self) -> None:
        # approval_id -> HumanApproval
        self._approvals: Dict[str, HumanApproval] = {}
        # experiment_id -> approval_id
        self._experiment_to_approval: Dict[str, str] = {}

    def register_approval(self, approval: HumanApproval) -> None:
        """Register an explicit human approval record."""
        self._approvals[approval.approval_id] = approval
        self._experiment_to_approval[approval.experiment_id] = approval.approval_id

    def get_approval(self, approval_id: str) -> Optional[HumanApproval]:
        return self._approvals.get(approval_id)

    def get_approval_for_experiment(self, experiment_id: str) -> Optional[HumanApproval]:
        app_id = self._experiment_to_approval.get(experiment_id)
        if app_id:
            return self._approvals.get(app_id)
        return None

    def requires_approval(self, safety_classification: str) -> bool:
        """Check if safety level requires explicit human approval."""
        clean = safety_classification.strip()
        if clean in (
            SafetyLevel.STATE_CHANGING_REQUIRES_APPROVAL.value,
            SafetyLevel.DESTRUCTIVE_ISOLATED_DATA.value,
            "STATE_CHANGING_REQUIRES_APPROVAL",
            "DESTRUCTIVE_ISOLATED_DATA",
            "STATE_CHANGING",
            "DESTRUCTIVE",
        ):
            return True
        return False

    def verify_approval(
        self,
        descriptor: ExecutionDescriptor,
        approval_id: Optional[str] = None,
        current_time: Optional[float] = None,
    ) -> Tuple[bool, Optional[str], Optional[HumanApproval]]:
        """Verify that a valid, unexpired approval exists matching the exact descriptor.

        Returns:
            (is_approved, failure_reason, approval_record)
        """
        # 1. If experiment is read-only safe, approval is not required
        if not self.requires_approval(descriptor.safety_classification):
            return True, None, None

        # 2. Look up approval record
        approval: Optional[HumanApproval] = None
        if approval_id:
            approval = self._approvals.get(approval_id)
        else:
            approval = self.get_approval_for_experiment(descriptor.experiment_id)

        if not approval:
            return False, "APPROVAL_REQUIRED_BUT_NOT_FOUND", None

        # 3. Verify experiment ID match
        if approval.experiment_id != descriptor.experiment_id:
            return False, "APPROVAL_EXPERIMENT_ID_MISMATCH", approval

        # 4. Verify expiration
        if not approval.is_valid(current_time=current_time):
            return False, "APPROVAL_EXPIRED", approval

        # 5. Cryptographic descriptor digest check
        current_digest = descriptor.compute_digest()
        if approval.approved_descriptor_digest != current_digest:
            return False, "APPROVAL_DESCRIPTOR_DIGEST_MISMATCH", approval

        return True, None, approval
