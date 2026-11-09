"""Freshness tracking and recency decay weighting for Memory Subsystem."""

from datetime import datetime, timezone
import math
from typing import Optional
from src.memory.enums import FreshnessState
from src.memory.models import MemoryItem


class FreshnessTracker:
    """
    Evaluates freshness states and computes retrieval decay multipliers.
    """

    def __init__(
        self,
        aging_days: int = 30,
        stale_days: int = 90,
        half_life_days: float = 60.0,
    ) -> None:
        self.aging_days = aging_days
        self.stale_days = stale_days
        self.decay_constant = math.log(2) / half_life_days

    def evaluate_freshness(self, item: MemoryItem, now: Optional[datetime] = None) -> FreshnessState:
        """
        Determines the FreshnessState for a given memory item.
        """
        if item.superseded_by:
            return FreshnessState.SUPERSEDED
        if item.lifecycle_state.value in ("RETIRED", "DELETED"):
            return FreshnessState.RETIRED

        curr_time = now or datetime.now(timezone.utc)
        try:
            created = datetime.fromisoformat(item.created_at.replace("Z", "+00:00"))
        except Exception:
            return FreshnessState.UNKNOWN

        age_days = (curr_time - created).total_seconds() / 86400.0
        if age_days < self.aging_days:
            return FreshnessState.CURRENT
        elif age_days < self.stale_days:
            return FreshnessState.AGING
        else:
            return FreshnessState.STALE

    def compute_decay_multiplier(self, item: MemoryItem, now: Optional[datetime] = None) -> float:
        """
        Computes a multiplicative weight in range [0.05, 1.0] for ranking.
        """
        state = self.evaluate_freshness(item, now)
        if state == FreshnessState.SUPERSEDED:
            return 0.10
        if state == FreshnessState.RETIRED:
            return 0.05

        curr_time = now or datetime.now(timezone.utc)
        try:
            created = datetime.fromisoformat(item.created_at.replace("Z", "+00:00"))
            age_days = max(0.0, (curr_time - created).total_seconds() / 86400.0)
        except Exception:
            age_days = 0.0

        # Exponential decay: exp(-lambda * delta_t)
        base_decay = math.exp(-self.decay_constant * age_days)

        # Floor at 0.40 for active non-superseded memories to ensure relevant history is not silenced
        return max(0.40, min(1.0, base_decay))
