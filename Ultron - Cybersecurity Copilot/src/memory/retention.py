"""Memory retention, expiration, and lifecycle management engine."""

from datetime import datetime, timezone
import uuid
from typing import Optional
from src.memory.enums import LifecycleState
from src.memory.models import MemoryDeletionRecord, MemoryItem


class RetentionManager:
    """
    Evaluates memory item expiration and coordinates lifecycle transitions.
    """

    @staticmethod
    def is_expired(item: MemoryItem, now: Optional[datetime] = None) -> bool:
        """
        Checks if item has exceeded its retention_expiry timestamp.
        """
        if not item.retention_expiry:
            return False
        curr_time = now or datetime.now(timezone.utc)
        try:
            expiry = datetime.fromisoformat(item.retention_expiry.replace("Z", "+00:00"))
            return curr_time >= expiry
        except Exception:
            return False

    @staticmethod
    def create_tombstone(
        item: MemoryItem,
        deleted_by: str,
        reason: str,
    ) -> MemoryDeletionRecord:
        """
        Creates an audit tombstone for deleted memory.
        Crucial: Never preserves raw content or secrets in the tombstone.
        """
        return MemoryDeletionRecord(
            tombstone_id=f"TOMB-{uuid.uuid4().hex[:8]}",
            memory_id=item.memory_id,
            namespace=item.namespace,
            assessment_id=item.assessment_id,
            deleted_by=deleted_by,
            deleted_at=datetime.now(timezone.utc).isoformat(),
            reason=reason,
            content_hash=item.content_hash,
        )
