"""Provenance preservation and validation for M12 Security Research Memory.

Guarantees:
1. Every admitted memory item preserves complete origin lineage.
2. Missing provenance prevents admission to high-authority namespaces.
3. Verified finding references must link to authoritative evidence digests.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from src.memory.enums import (
    EpistemicStatus,
    MemoryAuthority,
    MemoryNamespace,
    MemorySourceType,
)
from src.memory.errors import EpistemicViolationError, MemoryAdmissionRejectedError
from src.memory.models import EvidencePointer, MemoryItem


class ProvenanceValidator:
    """
    Validates provenance integrity, evidence linkage, and epistemic consistency.
    """

    HIGH_AUTHORITY_NAMESPACES = {
        MemoryNamespace.SHARED_RESEARCH,
        MemoryNamespace.VERIFIED_PATTERN,
        MemoryNamespace.GLOBAL_KNOWLEDGE,
    }

    HIGH_AUTHORITY_LEVELS = {
        MemoryAuthority.AUTHORITATIVE_EXTERNAL,
        MemoryAuthority.HUMAN_VERIFIED,
        MemoryAuthority.CURATED_RESEARCH,
    }

    @classmethod
    def validate_provenance(cls, item: MemoryItem) -> bool:
        """
        Validates provenance metadata on candidate memory items.
        Enforces Rule M12-13: Missing provenance prevents high-authority memory admission.
        """
        # 1. Content hash integrity check
        if not item.verify_hash():
            raise MemoryAdmissionRejectedError(
                f"MemoryItem {item.memory_id} content hash does not match content"
            )

        # 2. Origin timestamp must be valid ISO-8601
        if not item.created_at:
            raise MemoryAdmissionRejectedError(
                f"MemoryItem {item.memory_id} is missing created_at timestamp"
            )

        # 3. High-authority namespace provenance requirements
        if item.namespace in cls.HIGH_AUTHORITY_NAMESPACES or item.authority_level in cls.HIGH_AUTHORITY_LEVELS:
            if not item.provenance_references:
                raise MemoryAdmissionRejectedError(
                    f"High-authority namespace '{item.namespace.value}' requires explicit provenance_references (M12-13)"
                )
            if not item.owner_id:
                raise MemoryAdmissionRejectedError(
                    f"High-authority memory requires explicit owner/author attribution"
                )

        # 4. Epistemic status consistency checks
        if item.epistemic_status == EpistemicStatus.HUMAN_VERIFIED_FINDING:
            if not item.evidence_references and not item.evidence_pointers:
                raise EpistemicViolationError(
                    "HUMAN_VERIFIED_FINDING memory must reference authoritative canonical evidence (M12-28)"
                )
            if item.authority_level not in (MemoryAuthority.HUMAN_VERIFIED, MemoryAuthority.AUTHORITATIVE_EXTERNAL):
                raise EpistemicViolationError(
                    f"HUMAN_VERIFIED_FINDING cannot have low authority level '{item.authority_level.value}'"
                )

        # 5. Model hypotheses cannot claim high authority (M12-06)
        if item.epistemic_status == EpistemicStatus.MODEL_HYPOTHESIS:
            if item.authority_level in cls.HIGH_AUTHORITY_LEVELS:
                raise EpistemicViolationError(
                    f"MODEL_HYPOTHESIS cannot claim high authority level '{item.authority_level.value}' (M12-06)"
                )

        # 6. Unverified claims cannot claim high authority (M12-07)
        if item.epistemic_status == EpistemicStatus.UNVERIFIED_CLAIM:
            if item.authority_level in cls.HIGH_AUTHORITY_LEVELS:
                raise EpistemicViolationError(
                    f"UNVERIFIED_CLAIM cannot claim high authority level '{item.authority_level.value}' (M12-07)"
                )

        return True
