"""Deterministic Retrieval Query Construction (VaptQueryBuilder).

Implements M3.7 per M3 Plan v2.3.8 Section 13:
- Primary causal query construction from (LosslessStructuralPack, EvidenceGapType)
- Zero free-form 3B hints or target-controlled raw body strings in primary path
- Dual canonical query renderers: Renderer S (Structured) & Renderer N (Natural Language)
- Strict closed enum enforcement
"""

import logging
from typing import Optional

from src.evidence.cascade_models import LosslessStructuralPack
from src.knowledge.models import EvidenceGapType, QueryRendererId

logger = logging.getLogger("m3.query_builder")


class VaptQueryBuilder:
    """
    Deterministic Query Builder for VAPT Knowledge Retrieval.
    
    Transforms canonical application model state and security invariant deltas
    into deterministic query representations under Renderer S or Renderer N.
    """

    QUERY_BUILDER_VERSION: str = "3.0.0"
    FIXTURE_SCHEMA_VERSION: str = "1.0.0"

    @staticmethod
    def build_query(
        pack: LosslessStructuralPack,
        gap_type: EvidenceGapType,
        renderer_id: QueryRendererId = QueryRendererId.RENDERER_S,
    ) -> str:
        """
        Build deterministic retrieval query from canonical structural inputs.
        
        CRITICAL SECURITY INVARIANTS:
        1. gap_type must be strictly typed as the closed enum EvidenceGapType.
        2. No target-controlled freeform body text is used.
        3. No 3B model category hints participate in the primary causal path.
        """
        if not isinstance(gap_type, EvidenceGapType):
            raise TypeError(
                f"gap_type must be an instance of EvidenceGapType, got {type(gap_type)}"
            )
        if not isinstance(renderer_id, QueryRendererId):
            raise TypeError(
                f"renderer_id must be an instance of QueryRendererId, got {type(renderer_id)}"
            )

        clean_route = pack.route_template.strip()
        clean_method = pack.http_method.strip().upper()
        gap_desc = gap_type.value.replace("_", " ").title()

        invariants = []
        if getattr(pack, "has_cross_identity_object_access_success", False):
            invariants.append("Horizontal tenant object isolation")
        if getattr(pack, "has_privilege_level_delta", False):
            invariants.append("Vertical role privilege hierarchy")

        inv_str = ", ".join(invariants) if invariants else "General authorization boundary"

        if renderer_id == QueryRendererId.RENDERER_S:
            # Structured Deterministic Rendering (Renderer S)
            parts = [
                f"Method: {clean_method}",
                f"Route: {clean_route}",
                f"Evidence Gap: {gap_desc}",
            ]
            if invariants:
                parts.append(f"Invariant: {inv_str}")
            return " | ".join(parts)

        elif renderer_id == QueryRendererId.RENDERER_N:
            # Natural-Language Deterministic Rendering (Renderer N)
            return (
                f"How should {clean_method} {clean_route} enforce {gap_desc}? "
                f"Relevant invariant: {inv_str}."
            )

        raise ValueError(f"Unsupported QueryRendererId: {renderer_id}")
