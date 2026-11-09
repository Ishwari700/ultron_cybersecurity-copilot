"""Copilot Cascade Orchestrator and Epistemic Reasoning Pipeline (Milestone M5 Section 5, 34, 35).

Coordinates the multi-stage research and copilot pipeline:
1. Intent & Task Classification (IntentRouter)
2. Domain Classification (DomainRouter)
3. Local Knowledge Retrieval & Coverage Check (DomainKnowledgeRegistry)
4. Knowledge Sufficiency Assessment (KnowledgeSufficiencyEngine)
5. Research Budget Allocation (ResearchBudgetManager)
6. Context Budgeting & Epistemic Prioritization (ContextBudgetManager)
7. Domain-Aware Counterfactual Layer (NegativeControlEngine)
8. 3B Fast Triage -> Deterministic Router -> 7B Structured Reasoning Cascade

Preserves:
- Strict Human Verification Gate (HUMAN_VERIFIED can only be set by human)
- Epistemic Isolation (EXTERNAL_KNOWLEDGE != TARGET_EVIDENCE)
- Non-Destructive Operation (Manual experiments proposed, NEVER autonomously executed)
"""

from enum import Enum
import hashlib
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from src.copilot.budget import (
    ResearchBudgetLimits,
    ResearchBudgetManager,
    ResearchBudgetPolicy,
    ResearchBudgetUsage,
)
from src.copilot.context import ContextBudgetManager, PartitionedContextSlots
from src.copilot.domain import DomainClassificationResult, DomainRouter, SecurityDomain
from src.copilot.intent import (
    CopilotMode,
    CopilotTaskType,
    IntentClassificationResult,
    IntentRouter,
)
from src.copilot.registry import CoverageLevel, DomainKnowledgeRegistry
from src.copilot.sufficiency import (
    KnowledgeSufficiencyEngine,
    SufficiencyEvaluationResult,
    SufficiencyStatus,
)
from src.investigation.lifecycle import LifecycleManager
from src.investigation.models import (
    EvidenceGapEntity,
    FindingEntity,
    HypothesisEntity,
    HypothesisStatus,
    InvestigationWorkspace,
    ManualExperimentEntity,
    ObservationEntity,
    SecurityReportDraft,
    SeverityLevel,
)
from src.knowledge.general_corpus import GeneralSecurityKnowledgeCorpus
from src.knowledge.models import KnowledgeChunk
from src.research.conflicts import ConflictDetector
from src.research.models import (
    ExternalClaim,
    ExternalSource,
    NegativeControlGuidance,
    SourceConflict,
)
from src.research.negative_control import NegativeControlEngine


class ComplexityTier(str, Enum):
    """Complexity classification governing 3B vs 7B model execution (Section 35)."""
    LOW_COMPLEXITY = "LOW_COMPLEXITY"        # 3B fast direct response
    MEDIUM_COMPLEXITY = "MEDIUM_COMPLEXITY"  # 7B reasoning escalated
    HIGH_COMPLEXITY = "HIGH_COMPLEXITY"      # 7B deep reasoning with research/conflict fusion


class EscalationDecision(BaseModel):
    """Deterministic routing decision for 3B -> 7B escalation."""
    should_escalate_to_7b: bool
    complexity: ComplexityTier
    escalation_reasons: List[str] = Field(default_factory=list)


class CopilotResponse(BaseModel):
    """Structured, provenance-preserving output emitted by CopilotOrchestrator."""
    mode: CopilotMode
    primary_task: CopilotTaskType
    primary_domain: SecurityDomain
    secondary_domains: List[SecurityDomain] = Field(default_factory=list)
    complexity: ComplexityTier
    escalated_to_7b: bool
    escalation_reasons: List[str] = Field(default_factory=list)
    content: str
    epistemic_status: str = "MODEL_INFERENCE"
    hypotheses: List[HypothesisEntity] = Field(default_factory=list)
    evidence_gaps: List[EvidenceGapEntity] = Field(default_factory=list)
    experiments: List[ManualExperimentEntity] = Field(default_factory=list)
    conflicts: List[SourceConflict] = Field(default_factory=list)
    human_verified_findings_count: int = 0
    report_draft: Optional[SecurityReportDraft] = None
    citations: List[str] = Field(default_factory=list)


class CopilotOrchestrator:
    """Central orchestration engine executing the 3B -> 7B cascade with epistemic guards."""

    @classmethod
    def evaluate_escalation(
        cls,
        task: CopilotTaskType,
        mode: CopilotMode,
        observations_count: int,
        conflicts_count: int,
        evidence_gaps_count: int,
        requires_experiment_design: bool,
        is_multi_domain: bool,
        has_external_fusion: bool,
    ) -> EscalationDecision:
        """
        Deterministic escalation policy evaluating whether 3B can fulfill directly or 7B is required.
        """
        reasons: List[str] = []

        # High complexity triggers
        if observations_count >= 2:
            reasons.append(f"Multiple empirical target observations ({observations_count}) require 7B differential invariant analysis")
        if conflicts_count > 0:
            reasons.append(f"Detected external source contradictions ({conflicts_count}) require 7B dialectical evaluation")
        if requires_experiment_design or task == CopilotTaskType.DESIGN_EXPERIMENT:
            reasons.append("Experiment design requires 7B counterfactual and falsification generation")
        if has_external_fusion:
            reasons.append("External technical research fusion requires 7B grounded synthesis")

        # Medium complexity triggers
        if observations_count == 1:
            reasons.append("Target evidence observation requires 7B invariant check")
        if evidence_gaps_count > 0:
            reasons.append(f"Unresolved evidence gaps ({evidence_gaps_count}) require 7B reasoning")
        if is_multi_domain:
            reasons.append("Multi-domain reasoning boundary requires 7B model")
        if task in (
            CopilotTaskType.CODE_SECURITY_REVIEW,
            CopilotTaskType.TRAFFIC_ANALYSIS,
            CopilotTaskType.CONFIGURATION_ANALYSIS,
            CopilotTaskType.VULNERABILITY_RESEARCH,
            CopilotTaskType.INVESTIGATE,
            CopilotTaskType.REPORTING,
        ):
            reasons.append(f"Task type {task.value} mandates structured 7B analysis")

        if len(reasons) >= 3:
            return EscalationDecision(
                should_escalate_to_7b=True,
                complexity=ComplexityTier.HIGH_COMPLEXITY,
                escalation_reasons=reasons,
            )
        elif len(reasons) >= 1:
            return EscalationDecision(
                should_escalate_to_7b=True,
                complexity=ComplexityTier.MEDIUM_COMPLEXITY,
                escalation_reasons=reasons,
            )
        else:
            return EscalationDecision(
                should_escalate_to_7b=False,
                complexity=ComplexityTier.LOW_COMPLEXITY,
                escalation_reasons=["Direct 3B resolution: conceptual inquiry without empirical evidence gaps"],
            )

    @classmethod
    def process_query(
        cls,
        user_query: str,
        workspace: Optional[InvestigationWorkspace] = None,
        external_claims: Optional[List[ExternalClaim]] = None,
        conflicts: Optional[List[SourceConflict]] = None,
    ) -> CopilotResponse:
        """
        Processes a user request through the full deterministic M5 pipeline.
        """
        has_active_evidence = bool(workspace and len(workspace.observations) > 0)

        # 1. Intent Classification
        intent_res: IntentClassificationResult = IntentRouter.classify_intent(
            user_query, has_active_evidence=has_active_evidence
        )

        # 2. Domain Classification
        domain_res: DomainClassificationResult = DomainRouter.classify_domain(user_query)

        # 3. Local Knowledge Retrieval
        local_chunks = GeneralSecurityKnowledgeCorpus.find_chunks_by_domain(domain_res.primary_domain)

        # 4. Knowledge Sufficiency
        obs_count = len(workspace.observations) if workspace else 0
        gap_count = len(workspace.evidence_gaps) if workspace else 0
        conf_count = len(conflicts) if conflicts else 0

        suff_res: SufficiencyEvaluationResult = KnowledgeSufficiencyEngine.evaluate_sufficiency(
            query=user_query,
            domain=domain_res.primary_domain,
            task=intent_res.primary_task,
            mode=intent_res.mode,
            retrieval_scores=[0.040] if local_chunks else [],
            evidence_gaps=[g.gap_id for g in workspace.evidence_gaps] if workspace else [],
        )

        # 5. Escalation Decision
        is_multi_domain = len(domain_res.secondary_domains) > 0
        has_external_fusion = bool(external_claims and len(external_claims) > 0)
        requires_exp = intent_res.primary_task == CopilotTaskType.DESIGN_EXPERIMENT

        esc_decision = cls.evaluate_escalation(
            task=intent_res.primary_task,
            mode=intent_res.mode,
            observations_count=obs_count,
            conflicts_count=conf_count,
            evidence_gaps_count=gap_count,
            requires_experiment_design=requires_exp,
            is_multi_domain=is_multi_domain,
            has_external_fusion=has_external_fusion,
        )

        # 6. Counterfactual / Negative-Control Guidance
        nc_guidance = NegativeControlEngine.get_guidance(user_query, domain=domain_res.primary_domain)

        # 7. Context Partitioning
        obs_list = workspace.observations if workspace else []
        gaps_list = workspace.evidence_gaps if workspace else []
        slots: PartitionedContextSlots = ContextBudgetManager.assemble_budgeted_context(
            observations=obs_list,
            evidence_gaps=gaps_list,
            local_chunks=local_chunks[:3],
            negative_controls=nc_guidance[:2],
            external_claims=external_claims[:4] if external_claims else [],
            conflicts=conflicts[:2] if conflicts else [],
        )

        # 8. Dispatch Response Mode
        if intent_res.mode == CopilotMode.REPORTING and workspace:
            # Generate reporting draft
            hyp_id = workspace.hypotheses[0].hypothesis_id if workspace.hypotheses else "HYP-NONE"
            if workspace.hypotheses:
                draft = LifecycleManager.draft_report(workspace, hyp_id)
            else:
                draft = SecurityReportDraft(
                    report_id="REP-DRAFT-001",
                    investigation_id=workspace.investigation_id,
                    title="Draft Report - No Active Hypothesis",
                    severity=SeverityLevel.INFO,
                    status_label="DRAFT / UNVERIFIED",
                    affected_asset=workspace.target_host,
                    affected_endpoint=workspace.target_host,
                    description="No hypothesis proposed yet.",
                    expected_behavior="N/A",
                    actual_behavior="N/A",
                    security_impact="N/A",
                    remediation="N/A",
                    human_verified=False,
                )

            return CopilotResponse(
                mode=intent_res.mode,
                primary_task=intent_res.primary_task,
                primary_domain=domain_res.primary_domain,
                secondary_domains=domain_res.secondary_domains,
                complexity=esc_decision.complexity,
                escalated_to_7b=esc_decision.should_escalate_to_7b,
                escalation_reasons=esc_decision.escalation_reasons,
                content=f"Report drafted for {workspace.investigation_id} ({draft.status_label}).",
                epistemic_status="HUMAN_VERIFIED" if draft.human_verified else "DRAFT_UNVERIFIED",
                hypotheses=workspace.hypotheses,
                evidence_gaps=workspace.evidence_gaps,
                experiments=workspace.experiments,
                conflicts=conflicts or [],
                human_verified_findings_count=len(workspace.findings),
                report_draft=draft,
                citations=[c.chunk_id for c in local_chunks],
            )

        # Normal Response Generation (General QA, Tool Explanation, Investigation, Research)
        summary_lines = []
        summary_lines.append(f"**Operating Mode**: {intent_res.mode.value} | **Task**: {intent_res.primary_task.value}")
        summary_lines.append(f"**Domain**: {domain_res.primary_domain.value} ({domain_res.confidence:.0%})")
        summary_lines.append(f"**Cascade Router**: {'7B Escalated' if esc_decision.should_escalate_to_7b else '3B Direct'} ({esc_decision.complexity.value})")

        if esc_decision.should_escalate_to_7b:
            summary_lines.append(f"*Escalation Rationale*: {'; '.join(esc_decision.escalation_reasons)}")

        if local_chunks:
            summary_lines.append(f"\n### Relevant Security Invariants ({len(local_chunks)} local chunks)")
            for chk in local_chunks[:2]:
                summary_lines.append(f"- **{chk.title}**: {chk.content}")

        if nc_guidance:
            summary_lines.append("\n### Counterfactuals & Negative Controls")
            for g in nc_guidance[:1]:
                summary_lines.append(f"- **Legitimate Explanation**: {g.legitimate_explanations[0] if g.legitimate_explanations else 'None'}")
                summary_lines.append(f"- **Falsification Condition**: {g.falsification_conditions[0] if g.falsification_conditions else 'None'}")

        if conflicts:
            summary_lines.append(f"\n### Detected Source Conflicts ({len(conflicts)})")
            for conf in conflicts:
                summary_lines.append(f"- **{conf.category.value}** ({conf.topic}): '{conf.statement_a}' vs '{conf.statement_b}' -> *{conf.preferred_interpretation}*")

        content_rendered = "\n".join(summary_lines)

        return CopilotResponse(
            mode=intent_res.mode,
            primary_task=intent_res.primary_task,
            primary_domain=domain_res.primary_domain,
            secondary_domains=domain_res.secondary_domains,
            complexity=esc_decision.complexity,
            escalated_to_7b=esc_decision.should_escalate_to_7b,
            escalation_reasons=esc_decision.escalation_reasons,
            content=content_rendered,
            epistemic_status="MODEL_INFERENCE",
            hypotheses=workspace.hypotheses if workspace else [],
            evidence_gaps=workspace.evidence_gaps if workspace else [],
            experiments=workspace.experiments if workspace else [],
            conflicts=conflicts or [],
            human_verified_findings_count=len(workspace.findings) if workspace else 0,
            citations=[c.chunk_id for c in local_chunks],
        )
