"""Contradiction and Conflict Detection Engine for Memory Subsystem.

Detects contradictions, source disagreements, and hypothesis-vs-observation
discrepancies without silently discarding either item.
"""

from datetime import datetime, timezone
import re
from typing import List, Optional
import uuid

from src.memory.enums import ConflictType, EpistemicStatus
from src.memory.models import MemoryConflict, MemoryItem

# Polarity/negation indicators for semantic contradiction detection
VULN_AFFIRMATIVE = [
    re.compile(r"\b(?:is|was|found)\s+vulnerable\b", re.I),
    re.compile(r"\b(?:exploit|bypass|vulnerability)\s+(?:succeeded|confirmed|verified)\b", re.I),
    re.compile(r"\b(?:allows|permitted)\s+unauthorized\s+access\b", re.I),
]

VULN_NEGATIVE = [
    re.compile(r"\b(?:is|was)\s+not\s+vulnerable\b", re.I),
    re.compile(r"\b(?:exploit|bypass|vulnerability)\s+(?:failed|refuted|falsified)\b", re.I),
    re.compile(r"\b(?:does\s+not\s+allow|denied)\s+unauthorized\s+access\b", re.I),
    re.compile(r"\bfalse\s+positive\b", re.I),
]


class ConflictDetector:
    """
    Detects semantic, temporal, and epistemic contradictions between memory items.
    """

    @staticmethod
    def detect_polarity_conflict(text_a: str, text_b: str) -> bool:
        """
        Detects if text_a affirms a condition that text_b negates (or vice-versa).
        """
        a_is_aff = any(p.search(text_a) for p in VULN_AFFIRMATIVE)
        a_is_neg = any(p.search(text_a) for p in VULN_NEGATIVE)
        b_is_aff = any(p.search(text_b) for p in VULN_AFFIRMATIVE)
        b_is_neg = any(p.search(text_b) for p in VULN_NEGATIVE)

        if (a_is_aff and b_is_neg) or (a_is_neg and b_is_aff):
            return True
        return False

    @classmethod
    def check_conflict(
        cls,
        item_a: MemoryItem,
        item_b: MemoryItem,
    ) -> Optional[MemoryConflict]:
        """
        Examines two memory items for potential conflicts.
        Returns a MemoryConflict record if a discrepancy is detected, else None.
        """
        if item_a.memory_id == item_b.memory_id:
            return None

        # 1. Hypothesis vs Observation conflict
        if (
            (item_a.epistemic_status == EpistemicStatus.MODEL_HYPOTHESIS and
             item_b.epistemic_status in (EpistemicStatus.OBSERVATION, EpistemicStatus.FACT)) or
            (item_b.epistemic_status == EpistemicStatus.MODEL_HYPOTHESIS and
             item_a.epistemic_status in (EpistemicStatus.OBSERVATION, EpistemicStatus.FACT))
        ):
            if cls.detect_polarity_conflict(item_a.content, item_b.content):
                return MemoryConflict(
                    conflict_id=f"CONF-{uuid.uuid4().hex[:8]}",
                    conflict_type=ConflictType.HYPOTHESIS_VS_OBSERVATION,
                    memory_id_a=item_a.memory_id,
                    memory_id_b=item_b.memory_id,
                    description=f"Model hypothesis ({item_a.memory_id}) directly contradicts empirical observation ({item_b.memory_id})",
                    resolution_status="OPEN",
                )

        # 2. Direct Contradiction
        if cls.detect_polarity_conflict(item_a.content, item_b.content):
            conflict_type = ConflictType.DIRECT_CONTRADICTION
            # If one is substantially newer, classify as STALE_VS_NEW
            if item_a.created_at != item_b.created_at:
                conflict_type = ConflictType.STALE_VS_NEW

            return MemoryConflict(
                conflict_id=f"CONF-{uuid.uuid4().hex[:8]}",
                conflict_type=conflict_type,
                memory_id_a=item_a.memory_id,
                memory_id_b=item_b.memory_id,
                description=f"Direct polarity contradiction between {item_a.memory_id} and {item_b.memory_id}",
                resolution_status="OPEN",
            )

        # 3. Source Disagreement
        if item_a.source_type != item_b.source_type and cls.detect_polarity_conflict(item_a.summary, item_b.summary):
            return MemoryConflict(
                conflict_id=f"CONF-{uuid.uuid4().hex[:8]}",
                conflict_type=ConflictType.SOURCE_DISAGREEMENT,
                memory_id_a=item_a.memory_id,
                memory_id_b=item_b.memory_id,
                description=f"Opposing summaries between sources {item_a.source_type.value} and {item_b.source_type.value}",
                resolution_status="OPEN",
            )

        return None
