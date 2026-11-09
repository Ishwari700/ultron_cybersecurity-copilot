"""Telemetry and Observability Engine for Memory Subsystem.

Collects structured counters and latencies without ever logging secrets or raw text.
"""

from dataclasses import dataclass, field
import threading
from typing import Any, Dict


@dataclass
class MemoryTelemetry:
    """Thread-safe telemetry metrics for M12 memory subsystem."""
    _lock: threading.Lock = field(default_factory=threading.Lock)

    admission_attempts: int = 0
    admission_success: int = 0
    admission_rejected: int = 0
    rejection_secret: int = 0
    rejection_provenance: int = 0
    rejection_policy: int = 0
    retrieval_count: int = 0
    retrieval_empty: int = 0
    retrieval_cross_namespace_block: int = 0
    retrieval_cross_assessment_block: int = 0
    conflict_count: int = 0
    supersession_count: int = 0
    deletion_count: int = 0
    promotion_count: int = 0
    stale_count: int = 0
    duplicate_count: int = 0
    poisoning_attempts: int = 0
    total_retrieval_latency_ms: float = 0.0
    total_index_latency_ms: float = 0.0

    def record_admission(self, success: bool, rejection_reason: str = "") -> None:
        with self._lock:
            self.admission_attempts += 1
            if success:
                self.admission_success += 1
            else:
                self.admission_rejected += 1
                if "secret" in rejection_reason.lower() or "credential" in rejection_reason.lower():
                    self.rejection_secret += 1
                elif "provenance" in rejection_reason.lower():
                    self.rejection_provenance += 1
                else:
                    self.rejection_policy += 1

    def record_poisoning_attempt(self) -> None:
        with self._lock:
            self.poisoning_attempts += 1

    def record_duplicate(self) -> None:
        with self._lock:
            self.duplicate_count += 1

    def record_conflict(self) -> None:
        with self._lock:
            self.conflict_count += 1

    def record_retrieval(self, count: int, latency_ms: float) -> None:
        with self._lock:
            self.retrieval_count += 1
            if count == 0:
                self.retrieval_empty += 1
            self.total_retrieval_latency_ms += latency_ms

    def record_cross_assessment_block(self) -> None:
        with self._lock:
            self.retrieval_cross_assessment_block += 1

    def record_cross_namespace_block(self) -> None:
        with self._lock:
            self.retrieval_cross_namespace_block += 1

    def record_supersession(self) -> None:
        with self._lock:
            self.supersession_count += 1

    def record_deletion(self) -> None:
        with self._lock:
            self.deletion_count += 1

    def record_promotion(self) -> None:
        with self._lock:
            self.promotion_count += 1

    def get_metrics_snapshot(self) -> Dict[str, Any]:
        with self._lock:
            avg_ret_latency = (
                self.total_retrieval_latency_ms / self.retrieval_count
                if self.retrieval_count > 0 else 0.0
            )
            return {
                "memory_admission_attempts": self.admission_attempts,
                "memory_admission_success": self.admission_success,
                "memory_admission_rejected": self.admission_rejected,
                "memory_rejection_secret": self.rejection_secret,
                "memory_rejection_provenance": self.rejection_provenance,
                "memory_rejection_policy": self.rejection_policy,
                "memory_retrieval_count": self.retrieval_count,
                "memory_retrieval_empty": self.retrieval_empty,
                "memory_retrieval_cross_namespace_block": self.retrieval_cross_namespace_block,
                "memory_retrieval_cross_assessment_block": self.retrieval_cross_assessment_block,
                "memory_conflict_count": self.conflict_count,
                "memory_supersession_count": self.supersession_count,
                "memory_deletion_count": self.deletion_count,
                "memory_promotion_count": self.promotion_count,
                "memory_stale_count": self.stale_count,
                "memory_duplicate_count": self.duplicate_count,
                "memory_poisoning_attempts": self.poisoning_attempts,
                "avg_retrieval_latency_ms": round(avg_ret_latency, 2),
            }


GLOBAL_MEMORY_TELEMETRY = MemoryTelemetry()
