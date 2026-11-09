"""Deletion and Tombstone Engine for Memory Subsystem."""

from datetime import datetime, timezone
from typing import Tuple
from src.memory.enums import LifecycleState
from src.memory.models import MemoryDeletionRecord, MemoryItem
from src.memory.retention import RetentionManager


class MemoryDeletionEngine:
    """
    Executes secure deletion, forgetting, and tombstoning of memory items.
    Enforces Rule M12-14: Deleted memory is not returned as active memory.
    Enforces Rule M12-25: Memory deletion/correction is auditable.
    """

    @staticmethod
    def tombstone_item(
        item: MemoryItem,
        deleted_by: str,
        reason: str,
    ) -> Tuple[MemoryItem, MemoryDeletionRecord]:
        """
        Transitions item to DELETED and creates an audit tombstone.
        Empties content to prevent accidental retention of sensitive data.
        """
        tombstone = RetentionManager.create_tombstone(
            item=item,
            deleted_by=deleted_by,
            reason=reason,
        )

        item.lifecycle_state = LifecycleState.DELETED
        item.is_tombstone = True
        item.content = "[DELETED]"
        item.normalized_content = ""
        item.summary = f"[Deleted on {tombstone.deleted_at} by {deleted_by}]"
        item.updated_at = datetime.now(timezone.utc).isoformat()

        return item, tombstone

    @staticmethod
    def forget_item(
        item: MemoryItem,
        user_id: str,
    ) -> Tuple[MemoryItem, MemoryDeletionRecord]:
        """
        Handles user-initiated 'forget memory' action.
        """
        return MemoryDeletionEngine.tombstone_item(
            item=item,
            deleted_by=user_id,
            reason="User explicitly requested forgetting this memory item",
        )
