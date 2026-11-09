"""Lifecycle state and supersession versioning engine for Memory Subsystem."""

from datetime import datetime, timezone
import uuid
from typing import Optional, Tuple
from src.memory.enums import EpistemicStatus, LifecycleState, MemoryAuthority
from src.memory.models import MemoryItem, MemoryVersion


class MemoryLifecycleEngine:
    """
    Manages operational lifecycle states, version snapshots, and supersession chains.
    """

    @staticmethod
    def archive_item(item: MemoryItem) -> None:
        """Transitions memory item to ARCHIVED state."""
        item.lifecycle_state = LifecycleState.ARCHIVED
        item.updated_at = datetime.now(timezone.utc).isoformat()

    @staticmethod
    def create_version_snapshot(item: MemoryItem, change_rationale: str = "") -> MemoryVersion:
        """
        Creates an immutable historical version snapshot of the current item state.
        """
        return MemoryVersion(
            version_id=f"VER-{uuid.uuid4().hex[:8]}",
            memory_id=item.memory_id,
            version_number=item.version,
            content=item.content,
            content_hash=item.content_hash,
            epistemic_status=item.epistemic_status,
            authority_level=item.authority_level,
            created_at=item.updated_at or item.created_at,
            superseded_by=item.superseded_by,
            change_rationale=change_rationale,
        )

    @classmethod
    def supersede_item(
        cls,
        old_item: MemoryItem,
        new_content: str,
        new_epistemic_status: Optional[EpistemicStatus] = None,
        new_authority: Optional[MemoryAuthority] = None,
        change_rationale: str = "",
        actor: str = "researcher",
    ) -> Tuple[MemoryItem, MemoryItem, MemoryVersion]:
        """
        Performs explicit supersession:
        1. Snapshots old_item to MemoryVersion.
        2. Creates new_item with incremented version and supersedes pointer.
        3. Sets old_item.superseded_by = new_item.memory_id.
        Returns (updated_old_item, new_item, version_snapshot).
        """
        snapshot = cls.create_version_snapshot(old_item, change_rationale=change_rationale)

        new_item_id = f"MEM-{uuid.uuid4().hex[:8]}"
        old_item.superseded_by = new_item_id
        old_item.updated_at = datetime.now(timezone.utc).isoformat()

        new_item = MemoryItem(
            memory_id=new_item_id,
            namespace=old_item.namespace,
            owner_id=actor,
            tenant_id=old_item.tenant_id,
            assessment_id=old_item.assessment_id,
            source_type=old_item.source_type,
            epistemic_status=new_epistemic_status or old_item.epistemic_status,
            authority_level=new_authority or old_item.authority_level,
            content=new_content,
            title=old_item.title,
            summary=old_item.summary,
            confidence=old_item.confidence,
            provenance_references=old_item.provenance_references + [f"supersedes:{old_item.memory_id}"],
            evidence_references=old_item.evidence_references,
            evidence_pointers=old_item.evidence_pointers,
            version=old_item.version + 1,
            supersedes=old_item.memory_id,
            superseded_by=None,
            sensitivity_classification=old_item.sensitivity_classification,
            sanitization_status=old_item.sanitization_status,
            promotion_status=old_item.promotion_status,
            lifecycle_state=LifecycleState.ACTIVE,
            metadata={
                **old_item.metadata,
                "change_rationale": change_rationale,
                "superseded_from": old_item.memory_id,
            },
        )

        return old_item, new_item, snapshot
