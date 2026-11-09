"""Streaming reliability and progressive delivery protocol for M11.5 Long Response Subsystem.
Supports cancellation tokens, partial progress capture, and SSE formatting.
"""

from dataclasses import dataclass
import json
import threading
import time
from typing import Any, Callable, Dict, Generator, Optional
from src.evidence.vault import RedactionVault
from src.response.models import ResponseStatus


class CancellationToken:
    """Thread-safe cancellation token for user-directed stop requests."""

    def __init__(self) -> None:
        self._cancelled = threading.Event()
        self._reason = ""
        self._callbacks: List[Callable[[], None]] = []
        self._lock = threading.Lock()

    def register_callback(self, cb: Callable[[], None]) -> None:
        """Register a callback to be invoked immediately upon cancellation."""
        with self._lock:
            if self._cancelled.is_set():
                try:
                    cb()
                except Exception:
                    pass
                return
            self._callbacks.append(cb)

    def cancel(self, reason: str = "User stopped generation") -> None:
        with self._lock:
            self._reason = reason
            self._cancelled.set()
            callbacks = list(self._callbacks)
        for cb in callbacks:
            try:
                cb()
            except Exception:
                pass

    @property
    def is_cancelled(self) -> bool:
        return self._cancelled.is_set()

    @property
    def reason(self) -> str:
        return self._reason


@dataclass
class StreamEvent:
    """Strongly typed SSE streaming event."""
    event: str  # 'status', 'token', 'chunk', 'continuation', 'complete', 'stopped', 'error'
    data: Dict[str, Any]

    def to_sse(self) -> str:
        """Format as standard Server-Sent Event."""
        payload = json.dumps(self.data)
        return f"event: {self.event}\ndata: {payload}\n\n"


class ResponseStreamHandler:
    """
    Manages live streaming buffers, partial persistence hooks,
    and event dispatches for real-time progressive response delivery.
    """

    def __init__(self, cancellation_token: Optional[CancellationToken] = None) -> None:
        self.cancellation_token = cancellation_token or CancellationToken()
        self.vault = RedactionVault()
        self._accumulated_content = ""
        self._current_chunk_content = ""
        self._is_active = True

    def emit_token(self, token: str) -> StreamEvent:
        """Process incoming raw token, append to buffer, and yield event."""
        self._current_chunk_content += token
        self._accumulated_content += token
        return StreamEvent(
            event="token",
            data={"token": token, "accumulated_length": len(self._accumulated_content)},
        )

    def emit_status(self, status: ResponseStatus, message: Optional[str] = None) -> StreamEvent:
        """Dispatch explicit lifecycle status event."""
        return StreamEvent(
            event="status",
            data={"status": status.value, "message": message or status.value},
        )

    def emit_chunk_complete(
        self,
        chunk_id: str,
        sequence_number: int,
        tokens: int,
        stop_reason: str,
    ) -> StreamEvent:
        """Dispatch notification that a discrete chunk has finished."""
        self._current_chunk_content = ""
        return StreamEvent(
            event="chunk",
            data={
                "chunk_id": chunk_id,
                "sequence_number": sequence_number,
                "token_count": tokens,
                "stop_reason": stop_reason,
            },
        )

    def emit_complete(self, response_id: str, final_content: str, total_tokens: int) -> StreamEvent:
        """Dispatch terminal completion event."""
        self._is_active = False
        safe_content = self.vault.redact_text(final_content)
        return StreamEvent(
            event="complete",
            data={
                "response_id": response_id,
                "status": ResponseStatus.COMPLETED.value,
                "final_content": safe_content,
                "total_tokens": total_tokens,
            },
        )

    def emit_stopped(self, response_id: str, partial_content: str, tokens: int) -> StreamEvent:
        """Dispatch user-stopped event."""
        self._is_active = False
        safe_content = self.vault.redact_text(partial_content)
        return StreamEvent(
            event="stopped",
            data={
                "response_id": response_id,
                "status": ResponseStatus.USER_STOPPED.value,
                "partial_content": safe_content,
                "total_tokens": tokens,
            },
        )

    def emit_error(self, response_id: str, error_message: str, partial_content: str) -> StreamEvent:
        """Dispatch error event while maintaining access to partial response."""
        self._is_active = False
        safe_err = self.vault.redact_text(error_message)
        safe_content = self.vault.redact_text(partial_content)
        return StreamEvent(
            event="error",
            data={
                "response_id": response_id,
                "status": ResponseStatus.ERROR.value,
                "error": safe_err,
                "partial_content": safe_content,
            },
        )
