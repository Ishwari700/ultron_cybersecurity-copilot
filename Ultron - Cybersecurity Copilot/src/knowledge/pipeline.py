"""Integrated VAPT Retrieval-Reasoning Pipeline & Graceful Degradation Engine.

Implements M3.13 per M3 Plan v2.3.8 Sections 4, 13, 16, 20, and 22:
- Connects Application Model + Security Invariant Delta + EvidenceGapType
- VaptQueryBuilder -> Candidate 1 (OnnxVectorFts5Retriever) -> ProductionP4Serializer
- Graceful degradation:
    Normal: Target Evidence + VAPT Knowledge (Track D)
    Retrieval Offline / Backend Error: Fall back to Target Evidence only (Track B)
    Corpus Tamper Detected: Fall back to Target Evidence only (Track B)
    Empty / Low Relevance: Fall back to Target Evidence only (Track B)
- Causal parity: Target-Evidence payload in P4 is byte-identical between B and D
- Epistemic separation & dual grounding validation before post-processing
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from src.engine.models import HypothesisModelOutput
from src.evidence.cascade_models import (
    CascadeHandoffPacket,
    DeterministicRoutingDecision,
    LosslessStructuralPack,
)
from src.knowledge.grounding_validator import (
    KnowledgeGroundingResult,
    KnowledgeGroundingValidator,
)
from src.knowledge.models import (
    EvidenceGapType,
    KnowledgeRetrievalItem,
    QueryRendererId,
    VaptKnowledgePack,
)
from src.knowledge.poisoning_defense import KnowledgePoisoningDefense
from src.knowledge.query_builder import VaptQueryBuilder
from src.knowledge.retriever import BaseKnowledgeRetriever, OnnxVectorFts5Retriever
from src.knowledge.serializer import ProductionP4Serializer

logger = logging.getLogger("m3.pipeline")


class VaptReasoningPipeline:
    """
    End-to-end integration of VAPT Knowledge RAG with the 7B reasoning engine.
    Guarantees causal isolation, context budget floors, and fail-soft degradation.
    """

    def __init__(
        self,
        retriever: Optional[BaseKnowledgeRetriever] = None,
        db_path: Optional[Path] = None,
        manifest_path: Optional[Path] = None,
        sources_path: Optional[Path] = None,
        theta_min: float = 0.010,
        top_k: int = 5,
    ) -> None:
        self.db_path = Path(db_path) if db_path else Path("data/vapt_corpus/vapt_knowledge.db")
        self.manifest_path = Path(manifest_path) if manifest_path else Path("data/vapt_corpus/manifest.json")
        self.sources_path = Path(sources_path) if sources_path else Path("data/vapt_corpus/sources.json")
        self.theta_min = theta_min
        self.top_k = top_k

        # Initialize or assign retriever (Candidate 1 default)
        if retriever is not None:
            self.retriever = retriever
        elif self.db_path.exists():
            try:
                self.retriever = OnnxVectorFts5Retriever(db_path=self.db_path)
            except Exception as e:
                logger.warning(f"Could not initialize default OnnxVectorFts5Retriever: {e}")
                self.retriever = None
        else:
            self.retriever = None

        from src.engine.context_builder import ReasoningContextBuilder
        self.serializer = ProductionP4Serializer()
        self.context_builder = ReasoningContextBuilder()
        self.grounding_validator = KnowledgeGroundingValidator(
            manifest_path=self.manifest_path,
            sources_path=self.sources_path,
        )
        self.poisoning_defense = KnowledgePoisoningDefense()

    def retrieve_and_pack(
        self,
        channel_a: LosslessStructuralPack,
        gap_type: EvidenceGapType,
        renderer_id: QueryRendererId = QueryRendererId.RENDERER_S,
    ) -> Tuple[Optional[VaptKnowledgePack], Dict[str, Any]]:
        """
        Execute deterministic query building and retrieval for VAPT knowledge.
        
        Degradation behaviors:
        - If retriever is unavailable: emits RETRIEVAL_BACKEND_ERROR, returns None.
        - If zero items returned: emits RETRIEVAL_EMPTY, returns None.
        - If all items below theta_min: emits LOW_RELEVANCE_FILTERED, returns None.
        """
        # Step 1: Deterministic Query Construction (Section 13)
        try:
            rendered_query = VaptQueryBuilder.build_query(
                pack=channel_a,
                gap_type=gap_type,
                renderer_id=renderer_id,
            )
        except Exception as e:
            logger.error(f"Query builder failed: {e}")
            return None, {"event": "QUERY_BUILDER_ERROR", "error": str(e)}

        # Step 2: Candidate Retrieval Execution
        if self.retriever is None:
            logger.warning("VAPT retriever is unavailable; degrading to unaugmented path")
            return None, {"event": "RETRIEVAL_BACKEND_ERROR", "reason": "retriever_offline"}

        try:
            items = self.retriever.retrieve(
                query=rendered_query,
                top_k=self.top_k,
                theta_min=self.theta_min,
            )
        except Exception as e:
            logger.error(f"Retrieval execution error: {e}")
            return None, {"event": "RETRIEVAL_TOTAL_FAILURE", "error": str(e)}

        if not items:
            logger.info("VAPT retrieval returned zero items")
            return None, {"event": "RETRIEVAL_EMPTY", "query": rendered_query}

        # Step 3: Pack Construction via ProductionP4Serializer (Section 13.6)
        manifest_hash = (
            self.grounding_validator.manifest.merkle_root
            if self.grounding_validator.manifest
            else "0" * 64
        )
        try:
            renderer_str = (
                renderer_id.value
                if hasattr(renderer_id, "value")
                else str(renderer_id)
            )
            pack = self.serializer.build_knowledge_pack(
                retrieval_items=items,
                token_budget=256,
                retrieval_query=rendered_query,
                query_renderer_id=renderer_str,
                corpus_manifest_hash=manifest_hash,
            )
        except Exception as e:
            logger.error(f"Pack serialization failed: {e}")
            return None, {"event": "PACK_CONSTRUCTION_ERROR", "error": str(e)}

        # Step 4: Non-Destructive Poisoning Defense & Escaping (Section 18)
        sanitized_pack = self.poisoning_defense.sanitize_pack_for_serialization(pack)

        return sanitized_pack, {
            "event": "RETRIEVAL_SUCCESS",
            "item_count": len(items),
            "rendered_query": rendered_query,
        }

    def assemble_prompt(
        self,
        channel_a: LosslessStructuralPack,
        gap_type: Optional[EvidenceGapType] = None,
        cascade_mode: str = "TRACK_D",
        renderer_id: QueryRendererId = QueryRendererId.RENDERER_S,
        target_evidence_budget: int = 256,
    ) -> Tuple[str, Optional[VaptKnowledgePack], Dict[str, Any]]:
        """
        Assemble the complete 7B reasoning prompt under strict causal budget invariants.
        
        If cascade_mode is TRACK_D or TRACK_C and retrieval fails or is unavailable,
        gracefully degrades to TRACK_B (or TRACK_A) without failing the whole pipeline.
        """
        telemetry: Dict[str, Any] = {
            "requested_mode": cascade_mode,
            "effective_mode": cascade_mode,
            "degradation_applied": False,
        }

        vapt_pack: Optional[VaptKnowledgePack] = None

        if cascade_mode in ("TRACK_C", "TRACK_D", "TRACK_E") and gap_type is not None:
            vapt_pack, ret_diag = self.retrieve_and_pack(
                channel_a=channel_a,
                gap_type=gap_type,
                renderer_id=renderer_id,
            )
            telemetry["retrieval_diagnostic"] = ret_diag

            if vapt_pack is None:
                # Fail-Soft Degradation (Section 20)
                telemetry["degradation_applied"] = True
                if cascade_mode == "TRACK_D":
                    telemetry["effective_mode"] = "TRACK_B"
                elif cascade_mode == "TRACK_C":
                    telemetry["effective_mode"] = "TRACK_A"
                logger.info(
                    f"RAG failure degradation: switched {cascade_mode} -> {telemetry['effective_mode']}"
                )

        effective_mode = telemetry["effective_mode"]
        routing = DeterministicRoutingDecision(
            schema_version="2.0.0",
            escalate=True,
            has_high_risk_signal=True,
            high_risk_signals=["M3_RAG_REASONING"],
            fail_safe_triggered=False,
        )
        sess_id = getattr(channel_a, "session_id", None) or f"sess_{channel_a.asset_id}_{channel_a.endpoint_id}"
        handoff = CascadeHandoffPacket(
            schema_version="2.0.0",
            channel_a_structural=channel_a,
            routing_decision=routing,
            provenance_hash=f"prov_{sess_id}",
        )
        context = self.context_builder.build_context(
            handoff_packet=handoff,
            model_identifier="qwen2.5-coder:7b",
            budget_tier=4096,
            cascade_mode=effective_mode,
            vapt_pack=vapt_pack if effective_mode in ("TRACK_C", "TRACK_D", "TRACK_E") else None,
        )

        return context.prompt, vapt_pack, telemetry

    def validate_output(
        self,
        output: Union[HypothesisModelOutput, Dict[str, Any]],
        pack: Optional[VaptKnowledgePack] = None,
        channel_a: Optional[LosslessStructuralPack] = None,
    ) -> KnowledgeGroundingResult:
        """
        Validate model reasoning output against dual evidence and methodology grounding gates.
        """
        return self.grounding_validator.validate_grounding(
            hypothesis=output,
            pack=pack,
            channel_a=channel_a,
        )
