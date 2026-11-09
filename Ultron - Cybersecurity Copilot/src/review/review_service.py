"""Review Service Coordinating Human Review with Deterministic Security Gates.

Enforces:
- Human verification cannot be bypassed (INV-SEC-03, INV-M8-01, INV-M8-07)
- UI/API cannot bypass ScopeGate or AuthorizationValidator (INV-M8-02, INV-M8-03)
- Multi-tenant assessment isolation
- Audit trail immutability and provenance preservation
"""

from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List, Optional, Tuple

from src.assessment.manager import AssessmentManager
from src.assessment.models import (
    AssessmentFinding,
    AssessmentScopeStatus,
    FindingSeverity,
    FindingVerificationStatus,
)
from src.assessment.validation import AssessmentValidationContext, FindingValidator
from src.review.review_actions import (
    ApproveForValidationRequest,
    ContestRequest,
    RejectRequest,
    RequestEvidenceRequest,
    SubmitVerificationRequest,
)
from src.review.review_audit import ReviewAuditLogger
from src.review.review_models import (
    ReviewCase,
    ReviewStatus,
    ReviewTargetType,
    ReviewerDecision,
)
from src.review.review_queue import ReviewQueue


class ReviewService:
    """Coordinates researcher review operations, audit logging, and deterministic finding validation."""

    def __init__(self, assessment_manager: Optional[AssessmentManager] = None):
        self.assessment_manager = assessment_manager or AssessmentManager()
        self._queues: Dict[str, ReviewQueue] = {}
        self._audit_loggers: Dict[str, ReviewAuditLogger] = {}

    def _get_queue(self, assessment_id: str) -> ReviewQueue:
        if assessment_id not in self._queues:
            self._queues[assessment_id] = ReviewQueue(assessment_id)
        return self._queues[assessment_id]

    def _get_audit_logger(self, assessment_id: str) -> ReviewAuditLogger:
        if assessment_id not in self._audit_loggers:
            self._audit_loggers[assessment_id] = ReviewAuditLogger(assessment_id)
        return self._audit_loggers[assessment_id]

    def create_review_case_from_hypothesis(
        self,
        assessment_id: str,
        hypothesis_id: str,
        reviewer_id: Optional[str] = None,
    ) -> ReviewCase:
        """Constructs a ReviewCase from an existing assessment hypothesis."""
        cont = self.assessment_manager.get_container(assessment_id)
        hyp = cont.review_workspace.hypotheses.get(hypothesis_id)
        if not hyp:
            # Also check analysis_engine or global index if needed
            for h in cont.analysis_engine.hypotheses.values():
                if h.hypothesis_id == hypothesis_id:
                    hyp = h
                    break
        if not hyp:
            raise ValueError(f"Hypothesis '{hypothesis_id}' not found in assessment '{assessment_id}'")
        if hyp.assessment_id != assessment_id:
            raise ValueError(f"Assessment mismatch: hypothesis belongs to '{hyp.assessment_id}', not '{assessment_id}'")

        target_asset = hyp.asset_ids[0] if hyp.asset_ids else ""

        # Map proposed experiments if attached
        exp_list = []
        if hyp.suggested_experiment_id:
            exp = cont.review_workspace.experiments.get(hyp.suggested_experiment_id)
            if exp:
                exp_list.append(exp.model_dump())

        case = ReviewCase.create(
            assessment_id=assessment_id,
            target_id=hypothesis_id,
            target_type=ReviewTargetType.HYPOTHESIS,
            title=hyp.title,
            description=hyp.description,
            severity="HIGH" if "HIGH" in hyp.description.upper() else "MEDIUM",
            affected_asset=target_asset,
            epistemic_status=hyp.epistemic_status,
            supporting_evidence=list(hyp.supporting_observations),
            contradicting_evidence=list(hyp.contradicting_observations),
            evidence_gaps=list(hyp.evidence_gaps),
            falsification_result={"falsification_condition": hyp.falsification_condition} if hyp.falsification_condition else None,
            proposed_experiments=exp_list,
            metadata={"domain": hyp.domain, "security_invariants": hyp.security_invariants},
        )
        if reviewer_id:
            case.reviewer_id = reviewer_id
            case.status = ReviewStatus.IN_REVIEW

        queue = self._get_queue(assessment_id)
        queue.add_case(case)

        logger = self._get_audit_logger(assessment_id)
        logger.append_event(
            actor=reviewer_id or "SYSTEM",
            event_type="REVIEW_CASE_CREATED",
            object_id=case.review_id,
            metadata={"hypothesis_id": hypothesis_id, "title": case.title},
        )
        return case

    def get_case(self, assessment_id: str, review_id: str) -> Optional[ReviewCase]:
        return self._get_queue(assessment_id).get_case(review_id)

    def list_cases(
        self,
        assessment_id: str,
        status: Optional[ReviewStatus] = None,
        severity: Optional[str] = None,
    ) -> List[ReviewCase]:
        return self._get_queue(assessment_id).list_cases(status=status, severity=severity)

    def request_evidence(
        self,
        assessment_id: str,
        review_id: str,
        req: RequestEvidenceRequest,
    ) -> ReviewCase:
        """Transitions case to NEEDS_EVIDENCE with specific gap notes."""
        if not req.reviewer_id or not req.reviewer_id.strip():
            raise ValueError("Reviewer ID is required for attributable review actions.")

        case = self.get_case(assessment_id, review_id)
        if not case:
            raise KeyError(f"ReviewCase '{review_id}' not found.")

        case.reviewer_id = req.reviewer_id
        case.status = ReviewStatus.NEEDS_EVIDENCE
        case.reviewer_decision = ReviewerDecision.REQUEST_MORE_EVIDENCE
        case.reviewer_notes = req.notes
        case.decision_timestamp = datetime.now(timezone.utc).isoformat()
        if req.missing_gaps:
            case.evidence_gaps.extend(g for g in req.missing_gaps if g not in case.evidence_gaps)

        logger = self._get_audit_logger(assessment_id)
        evt = logger.append_event(
            actor=req.reviewer_id,
            event_type="EVIDENCE_REQUESTED",
            object_id=case.review_id,
            metadata={"notes": req.notes, "gaps": req.missing_gaps},
        )
        case.audit_reference = evt.event_id
        return case

    def contest(
        self,
        assessment_id: str,
        review_id: str,
        req: ContestRequest,
    ) -> ReviewCase:
        """Marks a case CONTESTED with human objections."""
        if not req.reviewer_id or not req.reviewer_id.strip():
            raise ValueError("Reviewer ID is required for attributable review actions.")

        case = self.get_case(assessment_id, review_id)
        if not case:
            raise KeyError(f"ReviewCase '{review_id}' not found.")

        case.reviewer_id = req.reviewer_id
        case.status = ReviewStatus.CONTESTED
        case.epistemic_status = "CONTESTED"
        case.reviewer_decision = ReviewerDecision.MARK_CONTESTED
        case.reviewer_notes = req.reason
        case.decision_timestamp = datetime.now(timezone.utc).isoformat()

        logger = self._get_audit_logger(assessment_id)
        evt = logger.append_event(
            actor=req.reviewer_id,
            event_type="REVIEW_CONTESTED",
            object_id=case.review_id,
            metadata={"reason": req.reason, "alternative": req.alternative_explanation},
        )
        case.audit_reference = evt.event_id
        return case

    def reject(
        self,
        assessment_id: str,
        review_id: str,
        req: RejectRequest,
    ) -> ReviewCase:
        """Rejects the case completely."""
        if not req.reviewer_id or not req.reviewer_id.strip():
            raise ValueError("Reviewer ID is required for attributable review actions.")

        case = self.get_case(assessment_id, review_id)
        if not case:
            raise KeyError(f"ReviewCase '{review_id}' not found.")

        case.reviewer_id = req.reviewer_id
        case.status = ReviewStatus.REJECTED
        case.reviewer_decision = ReviewerDecision.REJECT
        case.reviewer_notes = req.reason
        case.decision_timestamp = datetime.now(timezone.utc).isoformat()

        logger = self._get_audit_logger(assessment_id)
        evt = logger.append_event(
            actor=req.reviewer_id,
            event_type="FINDING_REJECTED",
            object_id=case.review_id,
            metadata={"reason": req.reason},
        )
        case.audit_reference = evt.event_id
        return case

    def approve_for_validation(
        self,
        assessment_id: str,
        review_id: str,
        req: ApproveForValidationRequest,
    ) -> ReviewCase:
        """Approves a case for validation (does NOT confirm finding yet)."""
        if not req.reviewer_id or not req.reviewer_id.strip():
            raise ValueError("Reviewer ID is required for attributable review actions.")

        case = self.get_case(assessment_id, review_id)
        if not case:
            raise KeyError(f"ReviewCase '{review_id}' not found.")

        case.reviewer_id = req.reviewer_id
        case.status = ReviewStatus.APPROVED_FOR_VALIDATION
        case.reviewer_decision = ReviewerDecision.CONFIRM
        case.reviewer_notes = req.notes or "Approved for deterministic validation."
        case.decision_timestamp = datetime.now(timezone.utc).isoformat()

        logger = self._get_audit_logger(assessment_id)
        evt = logger.append_event(
            actor=req.reviewer_id,
            event_type="APPROVED_FOR_VALIDATION",
            object_id=case.review_id,
            metadata={"notes": case.reviewer_notes},
        )
        case.audit_reference = evt.event_id
        return case

    def submit_human_verification(
        self,
        assessment_id: str,
        review_id: str,
        req: SubmitVerificationRequest,
    ) -> Tuple[bool, Optional[AssessmentFinding], List[str]]:
        """
        Submits explicit human verification through the deterministic FindingValidator.
        Returns: (is_confirmed: bool, finding: Optional[AssessmentFinding], errors: List[str]).
        Fails closed if FindingValidator rejects any condition.
        """
        # 1. Enforce human verifier attribution (reject missing, automated, or AI identities)
        if not req.reviewer_id or not req.reviewer_id.strip():
            return False, None, ["CHECK_12_FAILED: Missing identified human verifier name."]
        if any(t in req.reviewer_id.upper() for t in ("LLM", "MODEL", "AI", "AUTO", "BOT", "SYSTEM", "AGENT", "ORCHESTRATOR", "COPILOT")):
            return False, None, [f"CHECK_12_FAILED: Automated entity '{req.reviewer_id}' cannot sign off on finding."]

        case = self.get_case(assessment_id, review_id)
        if not case:
            return False, None, [f"ReviewCase '{review_id}' not found in assessment '{assessment_id}'."]

        # 2. Build candidate finding payload
        override = req.finding_override or {}
        now_ts = datetime.now(timezone.utc).isoformat()
        raw_seed = f"{assessment_id}:{case.target_id}:{req.reviewer_id}:{now_ts}"
        f_id = override.get("finding_id") or f"FIND-{hashlib.sha256(raw_seed.encode()).hexdigest()[:12].upper()}"

        severity_str = override.get("severity", case.severity).upper()
        try:
            sev = FindingSeverity(severity_str)
        except Exception:
            sev = FindingSeverity.MEDIUM

        evidence_items = list(req.evidence_references or case.supporting_evidence)

        finding = AssessmentFinding(
            finding_id=f_id,
            assessment_id=assessment_id,
            title=override.get("title", case.title),
            severity=sev,
            asset=override.get("asset", case.affected_asset),
            affected_component=override.get("affected_component", case.title),
            description=override.get("description", case.description),
            impact=override.get("impact", "Potential security impact identified."),
            evidence=evidence_items,
            reproduction_reference=override.get("reproduction_reference", "Verified via manual execution."),
            security_invariant=override.get("security_invariant", "SECURITY_INVARIANT_SPECIFIED"),
            root_cause=override.get("root_cause", "Observed security violation."),
            remediation=override.get("remediation", "Apply appropriate defensive controls."),
            references=override.get("references", []),
            confidence=1.0,
            verification_status=FindingVerificationStatus.HUMAN_VERIFIED,
            verified_by=req.reviewer_id,
            verified_at=now_ts,
            provenance={"review_id": review_id, "reviewer_notes": req.reviewer_notes},
        )

        # 3. Construct deterministic validation context
        cont = self.assessment_manager.get_container(assessment_id)
        obs_map = {o.observation_id: o for o in cont.telemetry_pipeline.get_observations()}
        ctx = AssessmentValidationContext(
            assessment=cont.record,
            authorization=cont.authorization,
            scope_gate=cont.scope_gate,
            assets=cont.asset_graph.get_all_assets(),
            observations=obs_map,
            hypotheses=cont.review_workspace.hypotheses,
            experiments=cont.review_workspace.experiments,
        )

        # 4. Execute deterministic FindingValidator
        is_valid, failures = FindingValidator.validate_finding(finding, ctx)
        logger = self._get_audit_logger(assessment_id)

        if not is_valid:
            logger.append_event(
                actor=req.reviewer_id,
                event_type="VALIDATION_FAILED",
                object_id=review_id,
                metadata={"failures": failures},
            )
            return False, None, failures

        # 5. Passed: store verified finding and record in audit log
        self.assessment_manager.register_candidate_finding(assessment_id, finding)
        cont.findings[finding.finding_id] = finding
        case.status = ReviewStatus.APPROVED_FOR_VALIDATION
        case.epistemic_status = "HUMAN_VERIFIED_FINDING"
        case.reviewer_decision = ReviewerDecision.CONFIRM
        case.reviewer_notes = req.reviewer_notes
        case.decision_timestamp = now_ts

        evt = logger.append_event(
            actor=req.reviewer_id,
            event_type="FINDING_VALIDATED",
            object_id=finding.finding_id,
            metadata={"review_id": review_id, "title": finding.title, "severity": finding.severity.value},
        )
        case.audit_reference = evt.event_id

        return True, finding, []

    def get_review_workspace_view(self, assessment_id: str, review_id: str) -> Dict[str, Any]:
        """Assembles rich workspace payload making epistemic statuses visually distinct."""
        case = self.get_case(assessment_id, review_id)
        if not case:
            raise KeyError(f"ReviewCase '{review_id}' not found.")

        cont = self.assessment_manager.get_container(assessment_id)
        hyp = cont.review_workspace.hypotheses.get(case.target_id)
        # Scope details for affected asset
        scope_status = "UNKNOWN"
        if cont.scope_gate and case.affected_asset:
            res = cont.scope_gate.evaluate_extended_scope(case.affected_asset)
            scope_status = res.scope_status.value

        # Retrieve detailed observation records
        obs_map = {o.observation_id: o for o in cont.telemetry_pipeline.get_observations()}
        evidence_details = []
        for ev_id in case.supporting_evidence:
            obs = obs_map.get(ev_id)
            if obs:
                evidence_details.append({
                    "observation_id": obs.observation_id,
                    "epistemic_status": obs.epistemic_status,
                    "type": obs.observation_type.value,
                    "source": obs.source,
                    "timestamp": obs.timestamp,
                    "content_hash": obs.content_hash,
                    "scope_decision": obs.scope_decision.value,
                    "normalized_data": obs.normalized_data,
                })
            else:
                evidence_details.append({"observation_id": ev_id, "status": "NOT_FOUND"})

        audit_logger = self._get_audit_logger(assessment_id)

        return {
            "review_case": case.model_dump(),
            "epistemic_badge": {
                "status": case.epistemic_status,
                "is_verified": case.epistemic_status == "HUMAN_VERIFIED_FINDING",
                "is_contested": case.epistemic_status == "CONTESTED",
                "is_hypothesis": case.epistemic_status == "MODEL_HYPOTHESIS",
            },
            "assessment_context": {
                "assessment_id": assessment_id,
                "organization": cont.record.organization,
                "assessment_name": cont.record.assessment_name,
                "state": cont.record.state.value,
            },
            "target_and_scope": {
                "affected_asset": case.affected_asset,
                "scope_status": scope_status,
                "is_in_scope": scope_status == AssessmentScopeStatus.IN_SCOPE.value,
            },
            "hypothesis": hyp.model_dump() if hyp else None,
            "evidence_items": evidence_details,
            "evidence_gaps": case.evidence_gaps,
            "falsification_result": case.falsification_result,
            "consensus_result": case.consensus_result,
            "proposed_experiments": case.proposed_experiments,
            "audit_trail": [e.model_dump() for e in audit_logger.events if e.object_id in (review_id, case.target_id)],
            "audit_integrity": audit_logger.verify_integrity(),
        }
