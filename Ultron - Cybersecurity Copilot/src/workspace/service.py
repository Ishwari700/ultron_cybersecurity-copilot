"""Unified Assessment Workspace Service for M13.

Coordinates across:
- AssessmentManager (Lifecycle, ScopeGate, AssetGraph, AttackSurface, Findings)
- ArtifactRegistry (Multi-tenant isolated artifact management)
- TelemetryPipeline & EvidenceLineageGraph (Observation & evidence tracking)
- SafeExperimentEngine (Plane A controlled experiments & Plane B procedures)
- AssessmentAuditLogger (Immutable audit trail & activity timeline)
- HumanReviewWorkspace & FindingValidator (Epistemic separation & 13-point verification)

STRICT SECURITY INVARIANTS ENFORCED:
- M13-01: Workspace navigation cannot create authorization.
- M13-02: A listed asset is not automatically an authorized asset.
- M13-03: No workspace operation can silently expand scope.
- M13-04: Invalid authorization blocks protected actions.
- M13-05: Cross-assessment data access is strictly denied.
- M13-07: Model hypotheses remain separate from observations.
- M13-16: Only authoritative human-review workflow can establish verification.
"""

from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List, Optional

from src.assessment.manager import AssessmentManager, AssessmentContainer
from src.assessment.models import (
    AssessmentLifecycleState,
    AssessmentScopeStatus,
    AssetRecord,
    AssetType,
    AuthorizationStatus,
    AuthorizationType,
    FindingSeverity,
    FindingVerificationStatus,
)
from src.artifacts.metadata import ArtifactRecord, ArtifactType, QuarantineStatus
from src.artifacts.registry import ArtifactRegistry
from src.workspace.models import (
    AssessmentActivity,
    AssessmentOverview,
    AssessmentSection,
    AssessmentSummary,
    AssessmentWorkflowStatus,
    AssessmentWorkspace,
    GlobalSearchResultItem,
    WorkspaceViewState,
)


class UnifiedWorkspaceService:
    """Service providing aggregated views and navigation over authorized security assessments."""

    def __init__(self, assessment_manager: Optional[AssessmentManager] = None) -> None:
        self.assessment_mgr = assessment_manager or AssessmentManager.get_instance()
        # Per-assessment artifact registries if not already held in container
        self._artifact_registries: Dict[str, ArtifactRegistry] = {}
        # Per-assessment workspace view states
        self._view_states: Dict[str, WorkspaceViewState] = {}

    def get_artifact_registry(self, assessment_id: str) -> ArtifactRegistry:
        """Retrieves or initializes the assessment-scoped artifact registry."""
        # Ensure assessment exists
        _ = self.assessment_mgr.get_container(assessment_id)
        if assessment_id not in self._artifact_registries:
            self._artifact_registries[assessment_id] = ArtifactRegistry(assessment_id=assessment_id)
        return self._artifact_registries[assessment_id]

    def list_assessment_summaries(self) -> List[AssessmentSummary]:
        """Lists high-level summaries for all registered assessments."""
        summaries: List[AssessmentSummary] = []
        for aid, cont in self.assessment_mgr._assessments.items():
            rec = cont.record
            assets = cont.asset_graph.get_all_assets()
            observations = cont.telemetry_pipeline.get_observations(assessment_id=aid)
            hypotheses = list(cont.review_workspace.hypotheses.values())
            findings = list(cont.findings.values())
            verified = [f for f in findings if f.verification_status == FindingVerificationStatus.HUMAN_VERIFIED]

            events = cont.audit_logger.get_events()
            last_activity = events[-1].timestamp if events else rec.created_at

            auth_status = cont.authorization.status if cont.authorization else AuthorizationStatus.PENDING
            auth_type = cont.authorization.authorization_type if cont.authorization else None

            summaries.append(
                AssessmentSummary(
                    assessment_id=rec.assessment_id,
                    organization=rec.organization,
                    assessment_name=rec.assessment_name,
                    state=rec.state,
                    authorization_status=auth_status,
                    authorization_type=auth_type,
                    created_at=rec.created_at,
                    updated_at=rec.updated_at,
                    asset_count=len(assets),
                    observation_count=len(observations),
                    hypothesis_count=len(hypotheses),
                    finding_count=len(findings),
                    verified_finding_count=len(verified),
                    last_activity_at=last_activity,
                )
            )
        return sorted(summaries, key=lambda s: s.updated_at, reverse=True)

    def get_workspace_overview(self, assessment_id: str) -> AssessmentOverview:
        """Returns the consolidated assessment overview and workflow status metrics."""
        cont = self.assessment_mgr.get_container(assessment_id)
        rec = cont.record

        assets = cont.asset_graph.get_all_assets()
        in_scope_assets = [a for a in assets if a.scope_status == AssessmentScopeStatus.IN_SCOPE]
        out_of_scope_assets = [a for a in assets if a.scope_status == AssessmentScopeStatus.OUT_OF_SCOPE]

        observations = cont.telemetry_pipeline.get_observations(assessment_id=assessment_id)
        hypotheses = list(cont.review_workspace.hypotheses.values())
        evidence_gaps = [gap for h in hypotheses for gap in h.evidence_gaps]
        experiments = list(cont.review_workspace.experiments.values())
        findings = list(cont.findings.values())
        verified_findings = [f for f in findings if f.verification_status == FindingVerificationStatus.HUMAN_VERIFIED]
        artifacts = self.get_artifact_registry(assessment_id).list_artifacts(include_quarantined=True)

        auth_valid = bool(cont.authorization and cont.authorization.status == AuthorizationStatus.AUTHORIZED)
        scope_def = bool(cont.scope_gate.policy.in_scope)
        telemetry_ing = len(observations) > 0
        attack_surface_map = len(assets) > 0 or len(cont.attack_surface.export_summary().get("endpoints", [])) > 0
        hyps_eval = len(hypotheses) > 0
        exps_exec = any(getattr(e.status, "value", str(e.status)) != "PROPOSED" for e in experiments)
        findings_rev = any(f.verification_status != FindingVerificationStatus.UNVERIFIED for f in findings)
        report_gen = any(evt.event_type == "REPORT_GENERATED" for evt in cont.audit_logger.get_events())

        # Determine current primary workflow milestone
        if not auth_valid:
            milestone = "ESTABLISH_AUTHORIZATION"
        elif not scope_def:
            milestone = "DEFINE_SCOPE"
        elif not telemetry_ing:
            milestone = "INGEST_TELEMETRY"
        elif not attack_surface_map:
            milestone = "MAP_ATTACK_SURFACE"
        elif not hyps_eval:
            milestone = "ANALYZE_HYPOTHESES"
        elif not exps_exec:
            milestone = "EXECUTE_EXPERIMENTS"
        elif not findings_rev:
            milestone = "REVIEW_FINDINGS"
        elif not report_gen:
            milestone = "GENERATE_REPORT"
        else:
            milestone = "ASSESSMENT_COMPLETE"

        wf_status = AssessmentWorkflowStatus(
            authorization_valid=auth_valid,
            scope_defined=scope_def,
            telemetry_ingested=telemetry_ing,
            attack_surface_mapped=attack_surface_map,
            hypotheses_evaluated=hyps_eval,
            experiments_executed=exps_exec,
            findings_reviewed=findings_rev,
            report_generated=report_gen,
            current_milestone=milestone,
        )

        return AssessmentOverview(
            assessment_id=rec.assessment_id,
            organization=rec.organization,
            assessment_name=rec.assessment_name,
            state=rec.state,
            authorization_id=cont.authorization.authorization_id if cont.authorization else None,
            authorization_status=cont.authorization.status if cont.authorization else AuthorizationStatus.PENDING,
            valid_from=cont.authorization.valid_from if cont.authorization else None,
            valid_until=cont.authorization.valid_until if cont.authorization else None,
            scope_policy_id=cont.record.scope_policy_id,
            scope_policy_version=getattr(cont.scope_gate.policy, "scope_policy_version", "v6"),
            scope_policy_hash=cont.scope_gate.policy.policy_hash if hasattr(cont.scope_gate.policy, "policy_hash") else None,
            in_scope_count=len(in_scope_assets),
            out_of_scope_count=len(out_of_scope_assets),
            asset_count=len(assets),
            observation_count=len(observations),
            hypothesis_count=len(hypotheses),
            evidence_gap_count=len(evidence_gaps),
            experiment_count=len(experiments),
            finding_count=len(findings),
            verified_finding_count=len(verified_findings),
            artifact_count=len(artifacts),
            workflow_status=wf_status,
            created_at=rec.created_at,
            updated_at=rec.updated_at,
            created_by=getattr(rec, "created_by", "HUMAN_OPERATOR"),
        )

    def get_assessment_workspace(
        self,
        assessment_id: str,
        view_state: Optional[WorkspaceViewState] = None,
    ) -> AssessmentWorkspace:
        """Constructs aggregated workspace state with warnings, permissions and current view preferences."""
        overview = self.get_workspace_overview(assessment_id)
        cont = self.assessment_mgr.get_container(assessment_id)

        warnings: List[str] = []
        if not cont.authorization or cont.authorization.status != AuthorizationStatus.AUTHORIZED:
            warnings.append(
                "Execution Blocked: Assessment lacks active, authorized sign-off. "
                "Target interactions and active experiments are restricted."
            )
        if not cont.scope_gate.policy.in_scope:
            warnings.append("Scope Unconfigured: In-scope target definitions must be specified before active testing.")
        if overview.out_of_scope_count > 0:
            warnings.append(
                f"Boundary Warning: {overview.out_of_scope_count} asset(s) are explicitly classified as OUT OF SCOPE. "
                "All testing against these targets remains strictly blocked."
            )
        if overview.state in (AssessmentLifecycleState.COMPLETED, AssessmentLifecycleState.ARCHIVED):
            warnings.append(f"Assessment is currently {overview.state.value}. Workspace is in read-only audit mode.")

        is_read_only = overview.state in (
            AssessmentLifecycleState.COMPLETED,
            AssessmentLifecycleState.ARCHIVED,
            AssessmentLifecycleState.CANCELLED,
            AssessmentLifecycleState.EXPIRED,
            AssessmentLifecycleState.REVOKED,
        )

        persisted_view = self._view_states.get(assessment_id, WorkspaceViewState())
        if view_state:
            persisted_view = view_state
            self._view_states[assessment_id] = persisted_view

        return AssessmentWorkspace(
            overview=overview,
            view_state=persisted_view,
            allowed_sections=list(AssessmentSection),
            is_read_only=is_read_only,
            warning_banners=warnings,
        )

    def update_view_state(self, assessment_id: str, view_state: WorkspaceViewState) -> WorkspaceViewState:
        """Persists researcher UI preferences for the given assessment."""
        # Validate existence
        _ = self.assessment_mgr.get_container(assessment_id)
        self._view_states[assessment_id] = view_state
        return view_state

    def get_activity_timeline(self, assessment_id: str, limit: int = 50) -> List[AssessmentActivity]:
        """Returns chronological activity history read from the authoritative assessment audit logger."""
        cont = self.assessment_mgr.get_container(assessment_id)
        raw_events = cont.audit_logger.get_events()

        activities: List[AssessmentActivity] = []
        for evt in reversed(raw_events):
            summary = f"{evt.event_type} executed by {evt.actor} on {evt.component}"
            if evt.input_reference:
                summary += f" [Ref: {evt.input_reference}]"

            details = {
                "input_reference": evt.input_reference,
                "output_reference": evt.output_reference,
                "provenance": evt.provenance,
            }
            activities.append(
                AssessmentActivity(
                    event_id=evt.event_id,
                    assessment_id=evt.assessment_id,
                    timestamp=evt.timestamp,
                    actor=evt.actor,
                    component=evt.component,
                    event_type=evt.event_type,
                    summary=summary,
                    details=details,
                    authorization_state=evt.authorization_state,
                    scope_state=evt.scope_state,
                    epistemic_state=evt.epistemic_state,
                )
            )
            if len(activities) >= limit:
                break
        return activities

    def validate_scope_target(self, assessment_id: str, target: str) -> Dict[str, Any]:
        """Authoritatively checks whether a given URL, domain, or IP is in-scope.

        INVARIANT M13-03: This validation operation NEVER modifies or expands scope.
        Deterministic backend scope evaluation with explicit error and boundary outcomes:
        - IN_SCOPE
        - OUT_OF_SCOPE
        - SCOPE_UNVERIFIABLE
        - AUTHORIZATION_EXPIRED
        - POLICY_VERSION_MISMATCH
        - SCOPE_EVALUATION_ERROR
        """
        cont = self.assessment_mgr.get_container(assessment_id)
        pol = cont.scope_gate.policy
        pol_hash = pol.policy_hash if hasattr(pol, "policy_hash") else pol.program_name
        pol_ver = getattr(pol, "scope_policy_version", "v6")

        # 1. Authorization & Policy Version Binding Pre-check
        if cont.authorization:
            if not cont.authorization.is_currently_valid():
                return {
                    "assessment_id": assessment_id,
                    "target": target,
                    "is_in_scope": False,
                    "is_allowed": False,
                    "outcome": AssessmentScopeStatus.AUTHORIZATION_EXPIRED.value,
                    "scope_policy_version": pol_ver,
                    "scope_policy_hash": pol_hash,
                    "scope_program": pol.program_name,
                    "reason": "Authorization has expired or is revoked.",
                    "evaluation_reason": "Authorization has expired or is revoked.",
                }
            if cont.authorization.scope_policy_hash and cont.authorization.scope_policy_hash != pol_hash:
                return {
                    "assessment_id": assessment_id,
                    "target": target,
                    "is_in_scope": False,
                    "is_allowed": False,
                    "outcome": AssessmentScopeStatus.POLICY_VERSION_MISMATCH.value,
                    "scope_policy_version": pol_ver,
                    "scope_policy_hash": pol_hash,
                    "scope_program": pol.program_name,
                    "reason": "Active scope policy version/hash does not match approved authorization.",
                    "evaluation_reason": "Active scope policy version/hash does not match approved authorization.",
                }

        # 2. Scope Evaluation
        try:
            decision = cont.scope_gate.evaluate_extended_scope(target)
            is_in_scope = decision.is_permitted
            if is_in_scope:
                outcome = AssessmentScopeStatus.IN_SCOPE.value
                reason = decision.reason or "Target is within authorized boundaries"
            elif decision.scope_status == AssessmentScopeStatus.OUT_OF_SCOPE:
                outcome = AssessmentScopeStatus.OUT_OF_SCOPE.value
                reason = decision.reason or "Target is explicitly out of scope"
            else:
                outcome = AssessmentScopeStatus.OUT_OF_SCOPE.value
                reason = decision.reason or "Target is not within authorized scope rules"
        except (TimeoutError, OSError) as e:
            outcome = AssessmentScopeStatus.SCOPE_UNVERIFIABLE.value
            is_in_scope = False
            reason = f"Network boundary/resolver unverifiable: {e}"
        except Exception as e:
            outcome = AssessmentScopeStatus.SCOPE_EVALUATION_ERROR.value
            is_in_scope = False
            reason = f"Scope evaluation error: {e}"

        return {
            "assessment_id": assessment_id,
            "target": target,
            "is_in_scope": is_in_scope,
            "is_allowed": is_in_scope,
            "outcome": outcome,
            "scope_policy_version": pol_ver,
            "scope_policy_hash": pol_hash,
            "scope_program": pol.program_name,
            "reason": reason,
            "evaluation_reason": reason,
        }

    def register_artifact(
        self,
        assessment_id: str,
        filename: str,
        artifact_type: ArtifactType,
        size_bytes: int,
        sha256_hash: str,
        source: str = "WORKSPACE",
        description: str = "",
        quarantine_status: QuarantineStatus = QuarantineStatus.QUARANTINED,
    ) -> ArtifactRecord:
        """Registers a verified artifact and records the event in the audit trail."""
        registry = self.get_artifact_registry(assessment_id)
        artifact_id = f"ART-{hashlib.sha256(f'{assessment_id}:{filename}:{sha256_hash}'.encode('utf-8')).hexdigest()[:12].upper()}"
        rec = ArtifactRecord(
            artifact_id=artifact_id,
            assessment_id=assessment_id,
            filename=filename,
            sha256=sha256_hash,
            size_bytes=size_bytes,
            artifact_type=artifact_type,
            quarantine_status=quarantine_status,
        )
        registry.register(rec)
        cont = self.assessment_mgr.get_container(assessment_id)
        cont.audit_logger.record_event(
            event_type="ARTIFACT_REGISTERED",
            actor="HUMAN_OPERATOR",
            component="ArtifactRegistry",
            authorization_state=cont.authorization.status.value if cont.authorization else "NONE",
            scope_state="IN_SCOPE",
            input_reference=artifact_id,
        )
        return rec

    def list_artifacts(
        self,
        assessment_id: str,
        artifact_type: Optional[ArtifactType] = None,
        include_quarantined: bool = True,
    ) -> List[ArtifactRecord]:
        """Lists artifacts belonging to this assessment."""
        registry = self.get_artifact_registry(assessment_id)
        return registry.list_artifacts(artifact_type=artifact_type, include_quarantined=include_quarantined)

    def export_report_markdown(self, assessment_id: str) -> str:
        """Exports authoritative assessment report in markdown format."""
        return self.assessment_mgr.generate_report(assessment_id)

    def search_workspace(
        self,
        query: str,
        assessment_id: Optional[str] = None,
    ) -> List[GlobalSearchResultItem]:
        """Cross-entity search with strict namespace isolation.

        INVARIANT M13-05: When assessment_id is supplied, records from other
        assessments are NEVER returned.
        """
        q = query.strip().lower()
        if not q:
            return []

        results: List[GlobalSearchResultItem] = []

        # Determine containers to search
        if assessment_id:
            containers = [self.assessment_mgr.get_container(assessment_id)]
        else:
            containers = list(self.assessment_mgr._assessments.values())

        for cont in containers:
            aid = cont.record.assessment_id
            aname = cont.record.assessment_name

            # 1. Assessment record itself
            if q in cont.record.assessment_name.lower() or q in cont.record.organization.lower() or q in aid.lower():
                results.append(
                    GlobalSearchResultItem(
                        entity_id=aid,
                        entity_type="assessment",
                        title=f"Assessment: {cont.record.assessment_name} ({cont.record.organization})",
                        assessment_id=aid,
                        assessment_name=aname,
                        snippet=f"Status: {cont.record.state.value}. Scope: {cont.record.scope_policy_id or 'None'}",
                        provenance={"created_by": cont.record.created_by},
                        url_target=f"/workspace/{aid}/overview",
                    )
                )

            # 2. Assets
            for asset in cont.asset_graph.get_all_assets():
                if q in asset.canonical_identifier.lower() or any(q in t.lower() for t in asset.tags):
                    results.append(
                        GlobalSearchResultItem(
                            entity_id=asset.asset_id,
                            entity_type="asset",
                            title=f"Asset: {asset.canonical_identifier} ({asset.asset_type.value})",
                            assessment_id=aid,
                            assessment_name=aname,
                            snippet=f"Scope: {asset.scope_status.value}. Tags: {', '.join(asset.tags)}",
                            provenance={"discovery_method": asset.discovery_method},
                            url_target=f"/workspace/{aid}/scope_assets",
                        )
                    )

            # 3. Observations
            for obs in cont.telemetry_pipeline.get_observations(assessment_id=aid):
                text_content = str(obs.normalized_data)
                obs_target = getattr(obs, "canonical_identifier", obs.asset_id)
                if q in obs_target.lower() or q in obs.observation_id.lower() or q in text_content.lower():
                    results.append(
                        GlobalSearchResultItem(
                            entity_id=obs.observation_id,
                            entity_type="evidence",
                            title=f"Observation: {obs.observation_type.value} on {obs_target}",
                            assessment_id=aid,
                            assessment_name=aname,
                            snippet=text_content[:160],
                            provenance=obs.provenance,
                            url_target=f"/workspace/{aid}/evidence",
                        )
                    )

            # 4. Hypotheses
            for hyp in cont.review_workspace.hypotheses.values():
                if q in hyp.title.lower() or q in hyp.description.lower() or q in hyp.hypothesis_id.lower():
                    results.append(
                        GlobalSearchResultItem(
                            entity_id=hyp.hypothesis_id,
                            entity_type="hypothesis",
                            title=f"Hypothesis: {hyp.title}",
                            assessment_id=aid,
                            assessment_name=aname,
                            snippet=hyp.description[:160],
                            provenance={"author": hyp.author, "epistemic_certainty": hyp.epistemic_certainty.value},
                            url_target=f"/workspace/{aid}/hypotheses",
                        )
                    )

            # 5. Experiments
            for exp in cont.review_workspace.experiments.values():
                if q in exp.objective.lower() or q in exp.experiment_id.lower():
                    results.append(
                        GlobalSearchResultItem(
                            entity_id=exp.experiment_id,
                            entity_type="experiment",
                            title=f"Experiment: {exp.objective[:80]}",
                            assessment_id=aid,
                            assessment_name=aname,
                            snippet=f"Risk: {exp.risk_level.value}. Status: {exp.status.value}",
                            provenance={"status": exp.status.value},
                            url_target=f"/workspace/{aid}/experiments",
                        )
                    )

            # 6. Findings
            for finding in cont.findings.values():
                if (
                    q in finding.title.lower()
                    or q in finding.description.lower()
                    or q in finding.finding_id.lower()
                    or q in finding.asset.lower()
                ):
                    results.append(
                        GlobalSearchResultItem(
                            entity_id=finding.finding_id,
                            entity_type="finding",
                            title=f"Finding: {finding.title} [{finding.severity.value}]",
                            assessment_id=aid,
                            assessment_name=aname,
                            snippet=finding.description[:160],
                            provenance={"verification_status": finding.verification_status.value},
                            url_target=f"/workspace/{aid}/findings_review",
                        )
                    )

            # 7. Artifacts
            registry = self.get_artifact_registry(aid)
            for art in registry.list_artifacts(include_quarantined=True):
                if q in art.filename.lower() or q in art.sha256.lower() or q in art.artifact_id.lower():
                    results.append(
                        GlobalSearchResultItem(
                            entity_id=art.artifact_id,
                            entity_type="artifact",
                            title=f"Artifact: {art.filename} ({art.artifact_type.value})",
                            assessment_id=aid,
                            assessment_name=aname,
                            snippet=f"SHA256: {art.sha256[:16]}... Size: {art.size_bytes} bytes",
                            provenance={"quarantine": art.quarantine_status.value},
                            url_target=f"/workspace/{aid}/artifacts",
                        )
                    )

        return results
