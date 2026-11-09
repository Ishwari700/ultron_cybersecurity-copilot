"""Investigation Lifecycle Management and Human Verification Gate (Milestone M5).

Enforces:
1. Deterministic state transitions for Hypotheses and Evidence Gaps
2. Mandatory Human Verification Gate:
   - Hypotheses can transition from PROPOSED -> TESTABLE -> SUPPORTED
   - ONLY explicit human verification can produce HUMAN_VERIFIED or create a FindingEntity
   - Attempts by automated logic to bypass human verification fail closed
3. Report Generation:
   - Always labeled "DRAFT / UNVERIFIED" unless backed by a human-verified finding
"""

from datetime import datetime, timezone
import hashlib
from typing import List, Optional

from src.investigation.models import (
    EvidenceGapEntity,
    EvidenceGapStatus,
    FindingEntity,
    HypothesisEntity,
    HypothesisStatus,
    InvestigationWorkspace,
    ManualExperimentEntity,
    ObservationEntity,
    SecurityReportDraft,
    SeverityLevel,
)


class LifecycleManager:
    """Governs valid state machine transitions within an investigation."""

    @classmethod
    def record_observation(
        cls,
        workspace: InvestigationWorkspace,
        endpoint: str,
        summary: str,
        asset_id: str = "default_asset",
        http_method: str = "GET",
        status_code: int = 200,
    ) -> ObservationEntity:
        """Adds a target observation to the isolated workspace."""
        obs_id = f"FACT-{hashlib.sha256((workspace.investigation_id + endpoint + summary).encode()).hexdigest()[:8]}"
        obs = ObservationEntity(
            observation_id=obs_id,
            investigation_id=workspace.investigation_id,
            asset_id=asset_id,
            endpoint=endpoint,
            http_method=http_method,
            status_code=status_code,
            summary=summary,
        )
        workspace.observations.append(obs)
        workspace.last_updated = datetime.now(timezone.utc).isoformat()
        return obs

    @classmethod
    def propose_hypothesis(
        cls,
        workspace: InvestigationWorkspace,
        statement: str,
        domain: str,
        supporting_fact_ids: List[str],
        falsification_condition: str,
    ) -> HypothesisEntity:
        """Proposes a new hypothesis in the PROPOSED state."""
        # Validate that all supporting fact IDs belong to this investigation
        known_fact_ids = {o.observation_id for o in workspace.observations}
        for fid in supporting_fact_ids:
            if fid not in known_fact_ids:
                raise ValueError(f"Supporting fact {fid} does not exist in workspace {workspace.investigation_id}")

        hyp_id = f"HYP-{hashlib.sha256((workspace.investigation_id + statement).encode()).hexdigest()[:8]}"
        hyp = HypothesisEntity(
            hypothesis_id=hyp_id,
            investigation_id=workspace.investigation_id,
            statement=statement,
            domain=domain,
            status=HypothesisStatus.PROPOSED,
            supporting_fact_ids=supporting_fact_ids,
            falsification_condition=falsification_condition,
        )
        workspace.hypotheses.append(hyp)
        workspace.last_updated = datetime.now(timezone.utc).isoformat()
        return hyp

    @classmethod
    def add_evidence_gap(
        cls,
        workspace: InvestigationWorkspace,
        hypothesis_id: str,
        description: str,
        required_evidence: str,
    ) -> EvidenceGapEntity:
        """Identifies an evidence gap and updates hypothesis status to NEEDS_EVIDENCE."""
        gap_id = f"GAP-{hashlib.sha256((hypothesis_id + description).encode()).hexdigest()[:8]}"
        gap = EvidenceGapEntity(
            gap_id=gap_id,
            investigation_id=workspace.investigation_id,
            hypothesis_id=hypothesis_id,
            description=description,
            reason="Missing observation needed to distinguish competing explanations",
            required_evidence=required_evidence,
            status=EvidenceGapStatus.OPEN,
        )
        workspace.evidence_gaps.append(gap)

        # Update hypothesis state
        for hyp in workspace.hypotheses:
            if hyp.hypothesis_id == hypothesis_id:
                hyp.status = HypothesisStatus.NEEDS_EVIDENCE
                break

        workspace.last_updated = datetime.now(timezone.utc).isoformat()
        return gap

    @classmethod
    def propose_experiment(
        cls,
        workspace: InvestigationWorkspace,
        hypothesis_id: str,
        objective: str,
        steps: List[str],
        expected_secure: str,
        expected_vulnerable: str,
        falsification: str,
        negative_control: str,
    ) -> ManualExperimentEntity:
        """Proposes a manual experiment and marks hypothesis as TESTABLE."""
        exp_id = f"EXP-{hashlib.sha256((hypothesis_id + objective).encode()).hexdigest()[:8]}"
        exp = ManualExperimentEntity(
            experiment_id=exp_id,
            investigation_id=workspace.investigation_id,
            hypothesis_id=hypothesis_id,
            objective=objective,
            steps=steps,
            expected_secure_result=expected_secure,
            expected_vulnerable_result=expected_vulnerable,
            falsification=falsification,
            negative_control=negative_control,
            safety_notes="Manual verification protocol. Do not execute destructive attacks.",
        )
        workspace.experiments.append(exp)

        for hyp in workspace.hypotheses:
            if hyp.hypothesis_id == hypothesis_id:
                hyp.status = HypothesisStatus.TESTABLE
                break

        workspace.last_updated = datetime.now(timezone.utc).isoformat()
        return exp

    @classmethod
    def resolve_evidence_gap(
        cls,
        workspace: InvestigationWorkspace,
        gap_id: str,
        status: EvidenceGapStatus,
        resolution_notes: str,
    ) -> EvidenceGapEntity:
        """Transitions an evidence gap to ADDRESSED, SATISFIED, DISPROVED, or STALE."""
        for gap in workspace.evidence_gaps:
            if gap.gap_id == gap_id:
                gap.status = status
                gap.resolution_notes = resolution_notes
                workspace.last_updated = datetime.now(timezone.utc).isoformat()
                return gap
        raise ValueError(f"Evidence gap {gap_id} not found in workspace {workspace.investigation_id}")

    @classmethod
    def update_hypothesis_status(
        cls,
        workspace: InvestigationWorkspace,
        hypothesis_id: str,
        new_status: HypothesisStatus,
        reason: str = "",
    ) -> HypothesisEntity:
        """
        Updates hypothesis status along its formal lifecycle.
        FORBIDS automated promotion to HUMAN_VERIFIED (must use verify_hypothesis_by_human).
        """
        if new_status == HypothesisStatus.HUMAN_VERIFIED:
            raise PermissionError(
                "Automated logic cannot set status to HUMAN_VERIFIED. Must invoke verify_hypothesis_by_human with authentic human identity."
            )

        for hyp in workspace.hypotheses:
            if hyp.hypothesis_id == hypothesis_id:
                hyp.status = new_status
                workspace.last_updated = datetime.now(timezone.utc).isoformat()
                return hyp
        raise ValueError(f"Hypothesis {hypothesis_id} not found in workspace {workspace.investigation_id}")

    @classmethod
    def verify_hypothesis_by_human(
        cls,
        workspace: InvestigationWorkspace,
        hypothesis_id: str,
        human_verifier: str,
        notes: str,
        severity: SeverityLevel = SeverityLevel.MEDIUM,
    ) -> FindingEntity:
        """
        NON-NEGOTIABLE HUMAN VERIFICATION GATE.
        
        Transitions hypothesis to HUMAN_VERIFIED and mints a FindingEntity.
        Fails closed if human_verifier is missing or empty.
        """
        if not human_verifier or human_verifier.strip() in ("", "system", "llm", "ai", "copilot"):
            raise PermissionError("Human verification gate requires an authentic human researcher identity.")

        target_hyp: Optional[HypothesisEntity] = None
        for hyp in workspace.hypotheses:
            if hyp.hypothesis_id == hypothesis_id:
                target_hyp = hyp
                break

        if not target_hyp:
            raise ValueError(f"Hypothesis {hypothesis_id} not found in workspace {workspace.investigation_id}")

        target_hyp.status = HypothesisStatus.HUMAN_VERIFIED
        target_hyp.human_verified = True
        target_hyp.verified_by = human_verifier
        target_hyp.verification_notes = notes

        # Mint confirmed finding
        find_id = f"FIND-{hashlib.sha256((workspace.investigation_id + hypothesis_id).encode()).hexdigest()[:8]}"
        finding = FindingEntity(
            finding_id=find_id,
            investigation_id=workspace.investigation_id,
            hypothesis_id=hypothesis_id,
            title=f"Verified: {target_hyp.statement[:80]}",
            severity=severity,
            affected_endpoint=workspace.target_host,
            security_invariant_violated=target_hyp.statement,
            verified_facts=target_hyp.supporting_fact_ids,
            human_verifier=human_verifier,
        )
        workspace.findings.append(finding)
        workspace.last_updated = datetime.now(timezone.utc).isoformat()
        return finding

    @classmethod
    def draft_report(
        cls,
        workspace: InvestigationWorkspace,
        hypothesis_id: str,
    ) -> SecurityReportDraft:
        """
        Drafts a structured security report.
        Strictly marks status as 'DRAFT / UNVERIFIED' unless human verification has occurred.
        """
        target_hyp: Optional[HypothesisEntity] = None
        for hyp in workspace.hypotheses:
            if hyp.hypothesis_id == hypothesis_id:
                target_hyp = hyp
                break

        if not target_hyp:
            raise ValueError(f"Hypothesis {hypothesis_id} not found.")

        # Find matching experiment if any
        matching_exp = next((e for e in workspace.experiments if e.hypothesis_id == hypothesis_id), None)
        steps = matching_exp.steps if matching_exp else ["Re-test endpoint with differential test cases."]

        is_verified = target_hyp.human_verified
        status_label = "HUMAN_VERIFIED" if is_verified else "DRAFT / UNVERIFIED"

        rep_id = f"REP-{hashlib.sha256((workspace.investigation_id + hypothesis_id).encode()).hexdigest()[:8]}"
        return SecurityReportDraft(
            report_id=rep_id,
            investigation_id=workspace.investigation_id,
            title=f"Report Draft: {target_hyp.statement[:70]}",
            severity=SeverityLevel.MEDIUM,
            status_label=status_label,
            affected_asset=workspace.target_host,
            affected_endpoint=workspace.target_host,
            description=target_hyp.statement,
            reproduction_steps=steps,
            expected_behavior="Enforce invariant and return HTTP 403 / reject unauthorized actions.",
            actual_behavior="Observed potential invariant invalidation under test conditions.",
            security_impact="Unauthorized data exposure or function execution if verified.",
            remediation="Implement strict server-side authorization check before state change.",
            citations=target_hyp.supporting_fact_ids + target_hyp.knowledge_chunk_ids,
            human_verified=is_verified,
        )
