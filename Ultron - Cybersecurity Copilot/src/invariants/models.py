"""Security Invariant models with strict epistemic origin tracking."""

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class InvariantOrigin(str, Enum):
    DOCUMENTED = "DOCUMENTED"
    OBSERVED = "OBSERVED"
    DETERMINISTIC_DERIVATION = "DETERMINISTIC_DERIVATION"
    MODEL_PROPOSED = "MODEL_PROPOSED"


class InvariantConfidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class SecurityInvariant(BaseModel):
    """
    First-class security invariant object.
    Explicitly tracks whether an invariant is documented, observed,
    deterministically derived, or merely proposed by an AI model.
    """
    invariant_id: str
    description: str
    origin: InvariantOrigin
    derived_from: List[str] = Field(default_factory=list) # Cited fact_ids or asset_ids
    confidence: InvariantConfidence = InvariantConfidence.MEDIUM
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @classmethod
    def compute_invariant_id(cls, description: str, origin: InvariantOrigin) -> str:
        raw = f"{origin.value}:{description.strip().lower()}"
        return f"INV-{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:12].upper()}"

    @classmethod
    def create(
        cls,
        description: str,
        origin: InvariantOrigin,
        derived_from: Optional[List[str]] = None,
        confidence: InvariantConfidence = InvariantConfidence.MEDIUM,
    ) -> "SecurityInvariant":
        inv_id = cls.compute_invariant_id(description, origin)
        return cls(
            invariant_id=inv_id,
            description=description,
            origin=origin,
            derived_from=derived_from or [],
            confidence=confidence,
        )
