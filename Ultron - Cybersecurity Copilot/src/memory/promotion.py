"""Human-in-the-Loop Memory Promotion Engine.

Governs the promotion of high-value research lessons from isolated assessment memory
into reusable SHARED_RESEARCH or VERIFIED_PATTERN namespaces.

NON-NEGOTIABLE TENETS:
1. Automatic promotion from MODEL_HYPOTHESIS or UNVERIFIED_CLAIM is FORBIDDEN.
2. High-value shared patterns require explicit attributable human approval.
3. Target-specific secrets, customer PII, and internal IPs must be abstracted.
4. Promotion is strictly auditable.
"""

from datetime import datetime, timezone
import uuid
from typing import Optional

from src.memory.enums import (
    EpistemicStatus,
    MemoryAuthority,
    MemoryNamespace,
    PromotionStatus,
    SensitivityClassification,
)
from src.memory.errors import InvalidMemoryPromotionError
from src.memory.models import MemoryItem, MemoryPromotion
from src.memory.sanitizer import MemorySanitizer


class MemoryPromotionEngine:
    """
    Manages promotion lifecycle, abstraction, and human verification gates for memory items.
    """

    def __init__(self) -> None:
        self.sanitizer = MemorySanitizer()

    def request_promotion(
        self,
        item: MemoryItem,
        target_namespace: MemoryNamespace,
        requester_id: str,
        justification: str,
    ) -> MemoryPromotion:
        """
        Creates a promotion candidate request.
        """
        if item.epistemic_status in (EpistemicStatus.MODEL_HYPOTHESIS, EpistemicStatus.UNVERIFIED_CLAIM):
            raise InvalidMemoryPromotionError(
                f"Automatic or unverified promotion of {item.epistemic_status.value} is strictly forbidden"
            )

        if target_namespace not in (MemoryNamespace.SHARED_RESEARCH, MemoryNamespace.VERIFIED_PATTERN):
            raise InvalidMemoryPromotionError(
                f"Target promotion namespace must be SHARED_RESEARCH or VERIFIED_PATTERN, got {target_namespace.value}"
            )

        item.promotion_status = PromotionStatus.HUMAN_REVIEW_REQUIRED

        return MemoryPromotion(
            promotion_id=f"PROM-{uuid.uuid4().hex[:8]}",
            memory_id=item.memory_id,
            requester_id=requester_id,
            source_namespace=item.namespace,
            target_namespace=target_namespace,
            status=PromotionStatus.HUMAN_REVIEW_REQUIRED,
            justification=justification,
            requested_at=datetime.now(timezone.utc).isoformat(),
        )

    def approve_promotion(
        self,
        promotion: MemoryPromotion,
        item: MemoryItem,
        reviewer_id: str,
    ) -> MemoryItem:
        """
        Executes human approval of promotion.
        Scrubs target details, updates namespace, and marks as PROMOTED.
        """
        # Reviewer cannot be an automated AI model
        if reviewer_id.lower() in ("ai", "assistant", "model", "system", "llm"):
            raise InvalidMemoryPromotionError(
                f"Promotion approval requires human attribution; '{reviewer_id}' rejected"
            )

        # 1. Abstract target-specific details
        abstracted_content = self.sanitizer.abstract_pattern(item.content)

        # 2. Update promotion record
        promotion.reviewer_id = reviewer_id
        promotion.status = PromotionStatus.PROMOTED
        promotion.reviewed_at = datetime.now(timezone.utc).isoformat()

        # 3. Create promoted MemoryItem
        promoted_item = MemoryItem(
            memory_id=f"MEM-PROM-{uuid.uuid4().hex[:8]}",
            namespace=promotion.target_namespace,
            owner_id=reviewer_id,
            tenant_id=item.tenant_id,
            assessment_id=None,  # Cleared: now shared across assessments
            source_type=item.source_type,
            epistemic_status=item.epistemic_status,
            authority_level=MemoryAuthority.CURATED_RESEARCH if promotion.target_namespace == MemoryNamespace.SHARED_RESEARCH else MemoryAuthority.HUMAN_VERIFIED,
            content=abstracted_content,
            title=f"[Promoted] {item.title}" if item.title else "[Promoted Pattern]",
            summary=item.summary,
            confidence=item.confidence,
            provenance_references=item.provenance_references + [f"promoted_from:{item.memory_id}", f"approved_by:{reviewer_id}"],
            evidence_references=item.evidence_references,
            sensitivity_classification=SensitivityClassification.INTERNAL,
            sanitization_status="SANITIZED_AND_ABSTRACTED",
            promotion_status=PromotionStatus.PROMOTED,
            metadata={
                **item.metadata,
                "original_memory_id": item.memory_id,
                "promoted_by": reviewer_id,
                "promotion_id": promotion.promotion_id,
            },
        )

        item.promotion_status = PromotionStatus.PROMOTED
        return promoted_item

    def reject_promotion(
        self,
        promotion: MemoryPromotion,
        item: MemoryItem,
        reviewer_id: str,
        reason: str,
    ) -> None:
        """
        Rejects candidate promotion. Marks status as REVOKED.
        """
        promotion.reviewer_id = reviewer_id
        promotion.status = PromotionStatus.REVOKED
        promotion.reviewed_at = datetime.now(timezone.utc).isoformat()
        promotion.justification += f" [REJECTED: {reason}]"
        item.promotion_status = PromotionStatus.REVOKED
