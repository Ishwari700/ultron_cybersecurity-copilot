"""Unit Tests for 3B -> 7B Escalation Policy and Context Budgeting (Milestone M5 Section 34-36)."""

import pytest
from src.copilot.context import ContextBudgetManager, PartitionedContextSlots
from src.copilot.domain import SecurityDomain
from src.copilot.intent import CopilotMode, CopilotTaskType
from src.copilot.orchestration import (
    ComplexityTier,
    CopilotOrchestrator,
    EscalationDecision,
)
from src.investigation.lifecycle import LifecycleManager
from src.investigation.models import (
    EvidenceGapEntity,
    EvidenceGapStatus,
    InvestigationWorkspace,
    ObservationEntity,
)
from src.knowledge.models import (
    KnowledgeChunk,
    KnowledgeSourceType,
    KnowledgeType,
)
from src.research.models import (
    ClaimEpistemicStatus,
    ClaimType,
    ExternalClaim,
    NegativeControlGuidance,
)


def test_3b_7b_routing_low_complexity_direct_3b():
    """Simple conceptual question resolves at 3B without escalation."""
    decision = CopilotOrchestrator.evaluate_escalation(
        task=CopilotTaskType.EXPLAIN,
        mode=CopilotMode.GENERAL_QA,
        observations_count=0,
        conflicts_count=0,
        evidence_gaps_count=0,
        requires_experiment_design=False,
        is_multi_domain=False,
        has_external_fusion=False,
    )
    assert decision.should_escalate_to_7b is False
    assert decision.complexity == ComplexityTier.LOW_COMPLEXITY


def test_3b_7b_routing_escalate_on_target_evidence():
    """Presence of target evidence observations escalates to 7B."""
    decision = CopilotOrchestrator.evaluate_escalation(
        task=CopilotTaskType.INVESTIGATE,
        mode=CopilotMode.INVESTIGATION,
        observations_count=2,
        conflicts_count=0,
        evidence_gaps_count=0,
        requires_experiment_design=False,
        is_multi_domain=False,
        has_external_fusion=False,
    )
    assert decision.should_escalate_to_7b is True
    assert decision.complexity in (ComplexityTier.MEDIUM_COMPLEXITY, ComplexityTier.HIGH_COMPLEXITY)
    assert any("Multiple empirical target observations" in r for r in decision.escalation_reasons)


def test_3b_7b_routing_escalate_on_conflict_and_experiment():
    """Conflicts and experiment design demand 7B reasoning."""
    decision = CopilotOrchestrator.evaluate_escalation(
        task=CopilotTaskType.DESIGN_EXPERIMENT,
        mode=CopilotMode.INVESTIGATION,
        observations_count=1,
        conflicts_count=1,
        evidence_gaps_count=1,
        requires_experiment_design=True,
        is_multi_domain=True,
        has_external_fusion=True,
    )
    assert decision.should_escalate_to_7b is True
    assert decision.complexity == ComplexityTier.HIGH_COMPLEXITY
    assert len(decision.escalation_reasons) >= 3


def test_context_budget_prioritization_and_isolation():
    """Target evidence is prioritized in Channel A and never evicted by external text."""
    obs = [
        ObservationEntity(
            observation_id=f"FACT-00{i}",
            investigation_id="INV-001",
            asset_id="ASSET-01",
            endpoint="/api/v1/user",
            summary=f"Observation {i}",
        )
        for i in range(3)
    ]
    gaps = [
        EvidenceGapEntity(
            gap_id="GAP-01",
            investigation_id="INV-001",
            hypothesis_id="HYP-01",
            description="Missing differential test",
            reason="Distinguish role",
            required_evidence="Response code",
            status=EvidenceGapStatus.OPEN,
        )
    ]
    clm = [
        ExternalClaim(
            claim_id="EXT-01",
            source_id="SRC-01",
            statement="External claim from RFC",
            claim_type=ClaimType.SECURITY_INVARIANT,
            epistemic_status=ClaimEpistemicStatus.EXTERNAL_REPORTED,
        )
    ]

    slots = ContextBudgetManager.assemble_budgeted_context(
        observations=obs,
        evidence_gaps=gaps,
        external_claims=clm,
        token_ceiling=500,
    )

    assert len(slots.target_evidence_lines) == 3
    assert len(slots.evidence_gap_lines) == 1
    assert slots.target_evidence_preserved is True

    prompt = ContextBudgetManager.format_prompt_block(slots)
    assert "=== CHANNEL A: VERIFIED TARGET EVIDENCE ===" in prompt
    assert "=== EVIDENCE GAPS REQUIRING CONFIRMATION ===" in prompt
    assert "=== CHANNEL B: PASSIVE EXTERNAL CLAIMS ===" in prompt
