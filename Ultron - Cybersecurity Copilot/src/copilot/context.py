"""Context Budgeting and Epistemic Prioritization Layer (Milestone M5 Section 36).

Enforces strict context window allocation priorities to guarantee that external knowledge
never overwhelms or evicts target evidence:
Priority 1: Target Evidence (Verified observations from active target)
Priority 2: Evidence Gaps (Missing properties requiring confirmation)
Priority 3: Directly Relevant Local Knowledge (Invariants, methodology)
Priority 4: Negative Controls & Counterfactual Guidance
Priority 5: Relevant External Claims
Priority 6: Source Conflicts & Discrepancies
Priority 7: Secondary References & Citations

Preserves the fundamental invariant:
    EXTERNAL_KNOWLEDGE != TARGET_EVIDENCE
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from src.investigation.models import (
    EvidenceGapEntity,
    HypothesisEntity,
    ObservationEntity,
)
from src.knowledge.models import KnowledgeChunk
from src.research.models import (
    ExternalClaim,
    NegativeControlGuidance,
    SourceConflict,
)


class PartitionedContextSlots(BaseModel):
    """Structured context slots assembled under budget."""
    target_evidence_lines: List[str] = Field(default_factory=list)
    evidence_gap_lines: List[str] = Field(default_factory=list)
    local_knowledge_lines: List[str] = Field(default_factory=list)
    negative_control_lines: List[str] = Field(default_factory=list)
    external_claim_lines: List[str] = Field(default_factory=list)
    conflict_lines: List[str] = Field(default_factory=list)
    secondary_ref_lines: List[str] = Field(default_factory=list)

    total_tokens_estimate: int = 0
    target_evidence_preserved: bool = True


class ContextBudgetManager:
    """Allocates tokens across prioritized context tiers under hard token ceilings."""

    DEFAULT_CEILING: int = 3072

    @classmethod
    def assemble_budgeted_context(
        cls,
        observations: List[ObservationEntity],
        evidence_gaps: Optional[List[EvidenceGapEntity]] = None,
        local_chunks: Optional[List[KnowledgeChunk]] = None,
        negative_controls: Optional[List[NegativeControlGuidance]] = None,
        external_claims: Optional[List[ExternalClaim]] = None,
        conflicts: Optional[List[SourceConflict]] = None,
        token_ceiling: int = DEFAULT_CEILING,
    ) -> PartitionedContextSlots:
        """
        Assembles context respecting strict priority order.
        Target evidence is allocated FIRST and is never evicted.
        """
        slots = PartitionedContextSlots()
        current_tokens = 0

        def est(text: str) -> int:
            return max(1, len(text.split()))

        # ---------------------------------------------------------------------
        # TIER 1: Target Evidence (Non-negotiable)
        # ---------------------------------------------------------------------
        for obs in observations:
            line = f"[TARGET_EVIDENCE] {obs.observation_id}: {obs.http_method} {obs.endpoint} -> HTTP {obs.status_code} ({obs.summary})"
            slots.target_evidence_lines.append(line)
            current_tokens += est(line)

        # ---------------------------------------------------------------------
        # TIER 2: Evidence Gaps
        # ---------------------------------------------------------------------
        if evidence_gaps:
            for gap in evidence_gaps:
                line = f"[EVIDENCE_GAP] {gap.gap_id} ({gap.status.value}): {gap.description} | Required: {gap.required_evidence}"
                cost = est(line)
                if current_tokens + cost <= token_ceiling:
                    slots.evidence_gap_lines.append(line)
                    current_tokens += cost

        # ---------------------------------------------------------------------
        # TIER 3: Local Knowledge Invariants
        # ---------------------------------------------------------------------
        if local_chunks:
            for chk in local_chunks:
                line = f"[LOCAL_KNOWLEDGE] {chk.chunk_id} [{chk.knowledge_type.value}]: {chk.title} - {chk.content[:200]}"
                cost = est(line)
                if current_tokens + cost <= token_ceiling:
                    slots.local_knowledge_lines.append(line)
                    current_tokens += cost

        # ---------------------------------------------------------------------
        # TIER 4: Negative Controls & Counterfactual Guidance
        # ---------------------------------------------------------------------
        if negative_controls:
            for ncg in negative_controls:
                line = f"[NEGATIVE_CONTROL] {ncg.topic} - Legitimate: {ncg.legitimate_explanations[:1]} | Falsification: {ncg.falsification_conditions[:1]}"
                cost = est(line)
                if current_tokens + cost <= token_ceiling:
                    slots.negative_control_lines.append(line)
                    current_tokens += cost

        # ---------------------------------------------------------------------
        # TIER 5: External Technical Claims
        # ---------------------------------------------------------------------
        if external_claims:
            for clm in external_claims:
                line = f"[EXTERNAL_CLAIM] {clm.claim_id} [{clm.epistemic_status.value}]: {clm.statement}"
                cost = est(line)
                if current_tokens + cost <= token_ceiling:
                    slots.external_claim_lines.append(line)
                    current_tokens += cost

        # ---------------------------------------------------------------------
        # TIER 6: Source Conflicts
        # ---------------------------------------------------------------------
        if conflicts:
            for conf in conflicts:
                line = f"[SOURCE_CONFLICT] {conf.conflict_id} ({conf.category.value}): '{conf.statement_a}' vs '{conf.statement_b}' | Resolution: {conf.preferred_interpretation}"
                cost = est(line)
                if current_tokens + cost <= token_ceiling:
                    slots.conflict_lines.append(line)
                    current_tokens += cost

        slots.total_tokens_estimate = current_tokens
        slots.target_evidence_preserved = True
        return slots

    @classmethod
    def format_prompt_block(cls, slots: PartitionedContextSlots) -> str:
        """Renders the budgeted slots into distinct epistemic sections."""
        sections = []
        if slots.target_evidence_lines:
            sections.append("=== CHANNEL A: VERIFIED TARGET EVIDENCE ===\n" + "\n".join(slots.target_evidence_lines))
        if slots.evidence_gap_lines:
            sections.append("=== EVIDENCE GAPS REQUIRING CONFIRMATION ===\n" + "\n".join(slots.evidence_gap_lines))
        if slots.local_knowledge_lines:
            sections.append("=== LOCAL SECURITY KNOWLEDGE ===\n" + "\n".join(slots.local_knowledge_lines))
        if slots.negative_control_lines:
            sections.append("=== COUNTERFACTUAL & NEGATIVE CONTROLS ===\n" + "\n".join(slots.negative_control_lines))
        if slots.external_claim_lines:
            sections.append("=== CHANNEL B: PASSIVE EXTERNAL CLAIMS ===\n" + "\n".join(slots.external_claim_lines))
        if slots.conflict_lines:
            sections.append("=== UNRESOLVED SOURCE CONFLICTS ===\n" + "\n".join(slots.conflict_lines))
        return "\n\n".join(sections)
