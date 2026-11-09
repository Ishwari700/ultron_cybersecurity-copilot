"""
Milestone M5 Phase 11.4: Authoritative Track D Context Builder.

Preserves the repository's native Track D implementation:
- Full cascade handoff packet
- Dual RAG / VAPT knowledge retrieval via VaptReasoningPipeline
- Existing deterministic routing decision
- Unaltered RAG corpus, retrieval parameters, and RRF rankings
- Strict provenance tracking
"""

import hashlib
from typing import Any, Dict, Optional, Tuple

from src.engine.context_builder import (
    AssembledReasoningContext,
    ReasoningContextBuilder,
    TRACK_D,
)
from src.engine.handoff_serializer import HandoffSerializer
from src.engine.models import OutputProtocolIdentifier
from src.engine.prompts import get_counterfactual_template
from src.eval.m4_live_benchmark import infer_evidence_gap_type
from src.eval.scenarios import EvaluationScenario
from src.evidence.cascade_models import (
    CascadeHandoffPacket,
    DeterministicRoutingDecision,
    LosslessStructuralPack,
)
from src.knowledge.models import EvidenceGapType, VaptKnowledgePack
from src.knowledge.pipeline import VaptReasoningPipeline


class AuthoritativeTrackDBuilder:
    """Encapsulates unchanged, authoritative Track D context assembly."""

    def __init__(self, pipeline: Optional[VaptReasoningPipeline] = None) -> None:
        self.pipeline = pipeline or VaptReasoningPipeline()
        self.context_builder = ReasoningContextBuilder()

    def build_track_d_context(
        self,
        scenario: EvaluationScenario,
        pack: LosslessStructuralPack,
    ) -> Tuple[AssembledReasoningContext, Optional[VaptKnowledgePack], str]:
        """
        Builds authoritative Track D context for a scenario.
        Returns:
        (assembled_context, vapt_pack, context_provenance_hash)
        """
        gap_type: EvidenceGapType = infer_evidence_gap_type(scenario.category_id)
        routing = DeterministicRoutingDecision(
            escalate=True,
            has_high_risk_signal=True,
            high_risk_signals=["M5_PHASE11_4_TRACK_D"],
            fail_safe_triggered=False,
        )
        handoff = CascadeHandoffPacket(
            schema_version="2.0.0",
            channel_a_structural=pack,
            routing_decision=routing,
            provenance_hash=f"prov_track_d_{pack.asset_id}",
        )
        cat_tmpl = get_counterfactual_template(scenario.category_id)
        active_descriptor = HandoffSerializer.from_cascade_packet(
            handoff_packet=handoff,
            evidence_gap_type=gap_type,
            invariant=cat_tmpl.invariant_definition,
        )

        # Execute authoritative VAPT Knowledge retrieval
        vapt_pack, _ = self.pipeline.retrieve_and_pack(channel_a=pack, gap_type=gap_type)

        ctx: AssembledReasoningContext = self.context_builder.build_context(
            handoff_packet=handoff,
            model_identifier="qwen2.5-coder:7b",
            budget_tier=2048,
            cascade_mode=TRACK_D,
            vapt_pack=vapt_pack,
            enable_i2_namespace_partitioning=True,
            enable_i3_counterfactual_prompting=True,
            category_id=scenario.category_id,
            enable_i4_bair=True,
            enable_i5_decision_policy=True,
            enable_i6_handoff=True,
            protected_handoff=active_descriptor,
            output_protocol=OutputProtocolIdentifier.JSON_BAIR,
        )

        full_raw = f"{ctx.system_prompt}\n{ctx.user_prompt}".encode("utf-8")
        prov_hash = hashlib.sha256(full_raw).hexdigest().lower()

        return ctx, vapt_pack, prov_hash
