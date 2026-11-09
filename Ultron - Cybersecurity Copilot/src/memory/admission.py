"""Deterministic Memory Admission Pipeline.

Executes the non-bypassable 12-stage validation sequence:
Candidate Memory
    ↓
1. Structural Validation
    ↓
2. Eligibility & Anti-Chatter Check (No chain-of-thought, no trivial chatter)
    ↓
3. Sensitivity Detection & Secret Redaction (RedactionVault)
    ↓
4. Prompt Poisoning Defense
    ↓
5. Epistemic Validation & Authority Consistency
    ↓
6. Provenance Validation
    ↓
7. Namespace Policy Authorization
    ↓
8. Deduplication Check
    ↓
9. Conflict & Contradiction Detection
    ↓
10. Sanitized Admission Finalization

The LLM may propose candidate memory, but CAN NEVER bypass this admission pipeline.
"""

import re
from typing import Dict, List, Optional, Tuple
import uuid

from src.memory.conflicts import ConflictDetector
from src.memory.deduplication import MemoryDeduplicator
from src.memory.enums import (
    EpistemicStatus,
    MemoryAuthority,
    MemoryNamespace,
    PromotionStatus,
    SensitivityClassification,
)
from src.memory.errors import (
    MemoryAdmissionRejectedError,
    MemoryPoisoningAttemptError,
    SecretPersistenceForbiddenError,
)
from src.memory.models import MemoryConflict, MemoryItem
from src.memory.namespaces import NamespaceValidator
from src.memory.provenance import ProvenanceValidator
from src.memory.sanitizer import MemorySanitizer

# Low-value conversational chatter patterns that should never be admitted
CHATTER_PATTERNS = [
    re.compile(r"^(?:hello|hi|hey|thanks|thank you|ok|okay|sounds good|understood)[.!]?$", re.I),
    re.compile(r"^(?:how can i help you|what would you like to do)[.!]?$", re.I),
    re.compile(r"^(?:let me think about that|thinking step by step|thought:)", re.I),
]


class MemoryAdmissionPipeline:
    """
    Validates and admits candidate memory items. Rejects ineligible, poisonous, or secret-leaking data.
    """

    def __init__(self) -> None:
        self.sanitizer = MemorySanitizer()
        self.deduplicator = MemoryDeduplicator()
        self.conflict_detector = ConflictDetector()

    def check_eligibility(self, content: str) -> bool:
        """
        Rejects trivial conversation, pure conversational fillers, or chain-of-thought traces.
        """
        stripped = content.strip()
        if not stripped or len(stripped) < 10:
            return False

        for pattern in CHATTER_PATTERNS:
            if pattern.search(stripped):
                return False

        return True

    def process_candidate(
        self,
        candidate: MemoryItem,
        existing_items: Optional[List[MemoryItem]] = None,
        existing_hashes: Optional[Dict[str, str]] = None,
    ) -> Tuple[MemoryItem, Optional[MemoryConflict]]:
        """
        Runs candidate through all admission stages.
        Returns (admitted_item, optional_conflict).
        Raises MemoryAdmissionRejectedError if rejected.
        """
        # 1. Structural Validation
        if not candidate.memory_id:
            candidate.memory_id = f"MEM-{uuid.uuid4().hex[:8]}"

        # 2. Eligibility & Anti-Chatter Check
        if not self.check_eligibility(candidate.content):
            raise MemoryAdmissionRejectedError("Candidate rejected: content is trivial conversation or ineligible chatter")

        # 3. Sensitivity Detection & Secret Redaction
        sanitized_text, redaction_count = self.sanitizer.sanitize_content(
            candidate.content,
            reject_on_critical=True,
        )
        candidate.content = sanitized_text
        candidate.sanitization_status = "SANITIZED"
        if redaction_count > 0:
            candidate.metadata["redactions_applied"] = redaction_count

        # 4. Prompt Poisoning Defense
        self.sanitizer.check_poisoning_defense(candidate.content, strict=True)

        # 5. Provenance & Epistemic Validation
        # Recompute hash after sanitization
        candidate.content_hash = ""
        candidate.model_post_init(None)
        ProvenanceValidator.validate_provenance(candidate)

        # 6. Namespace Policy Validation
        NamespaceValidator.validate_admission(candidate)

        # 7. Deduplication Check
        if existing_hashes:
            dup_id = self.deduplicator.check_exact_duplicate(candidate.content_hash, existing_hashes)
            if dup_id:
                raise MemoryAdmissionRejectedError(
                    f"Candidate is an exact duplicate of existing memory item {dup_id}"
                )

        # 8. Conflict & Contradiction Detection
        detected_conflict: Optional[MemoryConflict] = None
        if existing_items:
            for existing in existing_items:
                conflict = self.conflict_detector.check_conflict(candidate, existing)
                if conflict:
                    detected_conflict = conflict
                    candidate.metadata["conflict_detected_with"] = existing.memory_id
                    break

        return candidate, detected_conflict
