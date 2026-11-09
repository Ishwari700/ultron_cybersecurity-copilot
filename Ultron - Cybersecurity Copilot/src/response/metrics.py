"""Structured metrics and telemetry recorder for M11.5 Long Response Subsystem.
Guarantees: Zero secrets logged. All logs passed through credential redaction.
"""

from dataclasses import dataclass, field
import threading
import time
from typing import Any, Dict, List, Optional
from src.core.logging import get_logger
from src.evidence.vault import RedactionVault

logger = get_logger("ResponseTelemetry")


@dataclass
class ResponseMetricsData:
    """Thread-safe telemetry counters and latency accumulators."""
    response_generation_count: int = 0
    response_completion_count: int = 0
    response_continuation_count: int = 0
    response_token_limit_count: int = 0
    response_context_limit_count: int = 0
    response_timeout_count: int = 0
    response_error_count: int = 0
    response_user_stop_count: int = 0
    response_duplicate_overlap_count: int = 0
    response_total_tokens: int = 0
    response_generation_latency: float = 0.0
    response_continuation_latency: float = 0.0
    response_finalization_latency: float = 0.0
    diagnostics: List[Dict[str, Any]] = field(default_factory=list)


class ResponseTelemetry:
    """Singleton recorder for structured response observability."""

    _instance: Optional["ResponseTelemetry"] = None
    _lock = threading.Lock()

    def __new__(cls) -> "ResponseTelemetry":
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._data = ResponseMetricsData()
                cls._instance._data_lock = threading.Lock()
                cls._instance._vault = RedactionVault()
        return cls._instance

    @classmethod
    def get_instance(cls) -> "ResponseTelemetry":
        if cls._instance is None:
            return cls()
        return cls._instance

    def reset(self) -> None:
        """Reset all metrics (primarily for test isolation)."""
        with self._data_lock:
            self._data = ResponseMetricsData()

    def record_generation_start(self, session_id: str, model: str) -> None:
        with self._data_lock:
            self._data.response_generation_count += 1
        logger.info(f"Response session started: session_id={session_id}, model={model}")

    def record_chunk(
        self,
        session_id: str,
        chunk_index: int,
        tokens: int,
        latency: float,
        stop_reason: str,
        is_continuation: bool = False,
    ) -> None:
        with self._data_lock:
            self._data.response_total_tokens += tokens
            if is_continuation:
                self._data.response_continuation_count += 1
                self._data.response_continuation_latency += latency
            else:
                self._data.response_generation_latency += latency

            if stop_reason == "length":
                self._data.response_token_limit_count += 1

        logger.debug(
            f"Chunk recorded: session={session_id}, idx={chunk_index}, tokens={tokens}, "
            f"latency={latency:.2f}s, reason={stop_reason}, is_cont={is_continuation}"
        )

    def record_overlap_pruned(self, session_id: str, chunk_index: int, overlap_chars: int) -> None:
        with self._data_lock:
            self._data.response_duplicate_overlap_count += 1
        logger.info(
            f"Duplicate continuation overlap pruned: session={session_id}, chunk={chunk_index}, "
            f"overlap_chars={overlap_chars}"
        )

    def record_context_limit(self, session_id: str, detail: str) -> None:
        with self._data_lock:
            self._data.response_context_limit_count += 1
        safe_detail = self._vault.redact_text(detail)
        logger.warning(f"Context limit reached: session={session_id}, detail={safe_detail}")

    def record_timeout(self, session_id: str, elapsed: float) -> None:
        with self._data_lock:
            self._data.response_timeout_count += 1
        logger.warning(f"Response timeout: session={session_id}, elapsed={elapsed:.2f}s")

    def record_user_stop(self, session_id: str, tokens_so_far: int) -> None:
        with self._data_lock:
            self._data.response_user_stop_count += 1
        logger.info(f"User stopped response generation: session={session_id}, tokens={tokens_so_far}")

    def record_error(self, session_id: str, error_message: str) -> None:
        with self._data_lock:
            self._data.response_error_count += 1
        safe_err = self._vault.redact_text(error_message)
        logger.error(f"Response engine error: session={session_id}, error={safe_err}")

    def record_completion(
        self,
        session_id: str,
        total_chunks: int,
        total_tokens: int,
        termination_reason: str,
        finalization_latency: float = 0.0,
        continuation_rationale: Optional[str] = None,
        stop_rationale: Optional[str] = None,
    ) -> None:
        with self._data_lock:
            self._data.response_completion_count += 1
            self._data.response_finalization_latency += finalization_latency
            diagnostic_entry = {
                "session_id": session_id,
                "timestamp": time.time(),
                "total_chunks": total_chunks,
                "total_tokens": total_tokens,
                "termination_reason": termination_reason,
                "continuation_rationale": self._vault.redact_text(continuation_rationale or "N/A"),
                "stop_rationale": self._vault.redact_text(stop_rationale or "N/A"),
            }
            # Keep bounded in-memory diagnostic history (last 50 items)
            self._data.diagnostics.append(diagnostic_entry)
            if len(self._data.diagnostics) > 50:
                self._data.diagnostics.pop(0)

        logger.info(
            f"Response session completed: session={session_id}, chunks={total_chunks}, "
            f"tokens={total_tokens}, reason={termination_reason}"
        )

    def get_metrics_snapshot(self) -> Dict[str, Any]:
        """Return snapshot dictionary matching Milestone 11.5 naming."""
        with self._data_lock:
            return {
                "response_generation_count": self._data.response_generation_count,
                "response_completion_count": self._data.response_completion_count,
                "response_continuation_count": self._data.response_continuation_count,
                "response_token_limit_count": self._data.response_token_limit_count,
                "response_context_limit_count": self._data.response_context_limit_count,
                "response_timeout_count": self._data.response_timeout_count,
                "response_error_count": self._data.response_error_count,
                "response_user_stop_count": self._data.response_user_stop_count,
                "response_duplicate_overlap_count": self._data.response_duplicate_overlap_count,
                "response_total_tokens": self._data.response_total_tokens,
                "response_generation_latency": round(self._data.response_generation_latency, 4),
                "response_continuation_latency": round(self._data.response_continuation_latency, 4),
                "response_finalization_latency": round(self._data.response_finalization_latency, 4),
                "diagnostics_count": len(self._data.diagnostics),
                "recent_diagnostics": list(self._data.diagnostics[-5:]),
            }
