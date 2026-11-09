"""Canonical model routing, readiness checking, and inference resource bounding.

Enforces:
1. Canonical task-to-model mapping.
2. Observable, non-synthetic model selection without silent fallback masquerading.
3. Strict local inference concurrency bound (concurrency = 1 for 4GB VRAM laptop GPU).
4. Truthful runtime availability checks distinguishing unavailable daemon from missing model.
"""

from contextlib import contextmanager
from enum import Enum
import threading
import time
from typing import Any, Dict, Iterator, List, Optional, Tuple
from pydantic import BaseModel, Field

from src.core.logging import get_logger

logger = get_logger("ModelRouter")

PINNED_7B_MODEL = "qwen2.5-coder:7b"
PINNED_3B_MODEL = "qwen2.5-coder:3b"


class TaskType(str, Enum):
    """Categorization of AI task for model routing."""
    CONVERSATIONAL_QA = "CONVERSATIONAL_QA"
    CHAT = "CONVERSATIONAL_QA"  # Backward-compatible alias
    SECURITY_TRIAGE = "SECURITY_TRIAGE"
    STRUCTURED_REASONING = "STRUCTURED_REASONING"
    CODE_SECURITY_REVIEW = "CODE_SECURITY_REVIEW"
    VULNERABILITY_RESEARCH = "VULNERABILITY_RESEARCH"
    REPORT_DRAFT = "REPORT_DRAFT"
    EXPLANATION = "EXPLANATION"


class ModelRouteDecision(BaseModel):
    """Deterministic routing decision detailing chosen model and runtime readiness."""
    task_type: TaskType
    configured_model: str
    selected_model: str
    fallback_model: Optional[str] = None
    fallback_used: bool = False
    fallback_reason: Optional[str] = None
    max_tokens: int = 512
    context_window: int = 4096
    temperature: float = 0.7
    timeout_seconds: float = 120.0
    runtime_available: bool = True
    runtime_status: str = "AVAILABLE"  # "AVAILABLE", "DAEMON_UNAVAILABLE", "MODEL_NOT_FOUND", "OFFLINE_FALLBACK"


class InferenceConcurrencyGate:
    """
    Global thread-safe concurrency regulator ensuring local GPU VRAM (4GB)
    is never overloaded by concurrent model invocations.
    Defaults to strictly concurrency 1 for local inference.
    Implements priority scheduling where INTERACTIVE chat takes precedence over BACKGROUND graph extraction.
    """
    _instance: Optional["InferenceConcurrencyGate"] = None
    _lock = threading.Lock()

    def __init__(self, max_concurrent: int = 1) -> None:
        self.max_concurrent = max_concurrent
        self._semaphore = threading.BoundedSemaphore(max_concurrent)
        self._active_count = 0
        self._active_priority: Optional[str] = None
        self._waiting_interactive = 0
        self._counter_lock = threading.Lock()
        self._interactive_condition = threading.Condition(self._counter_lock)

    @classmethod
    def get_instance(cls, max_concurrent: int = 1) -> "InferenceConcurrencyGate":
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls(max_concurrent=max_concurrent)
            return cls._instance

    def acquire(self, timeout: float = 60.0, priority: str = "INTERACTIVE") -> bool:
        """
        Acquire inference slot within timeout.
        INTERACTIVE priority takes precedence over BACKGROUND work.
        """
        if priority == "INTERACTIVE":
            with self._counter_lock:
                self._waiting_interactive += 1
            try:
                acquired = self._semaphore.acquire(timeout=timeout)
                with self._counter_lock:
                    self._waiting_interactive = max(0, self._waiting_interactive - 1)
                    if acquired:
                        self._active_count += 1
                        self._active_priority = "INTERACTIVE"
                return acquired
            except Exception:
                with self._counter_lock:
                    self._waiting_interactive = max(0, self._waiting_interactive - 1)
                raise
        else:
            # BACKGROUND priority: must wait while interactive requests are waiting or running
            t_start = time.monotonic()
            with self._counter_lock:
                while self._waiting_interactive > 0:
                    rem = timeout - (time.monotonic() - t_start)
                    if rem <= 0:
                        return False
                    self._interactive_condition.wait(timeout=min(rem, 0.5))

            rem = timeout - (time.monotonic() - t_start)
            if rem <= 0:
                return False

            acquired = self._semaphore.acquire(timeout=rem)
            with self._counter_lock:
                if acquired:
                    self._active_count += 1
                    self._active_priority = "BACKGROUND"
            return acquired

    def release(self) -> None:
        """Release inference slot and wake any priority-waiting threads."""
        with self._counter_lock:
            if self._active_count > 0:
                self._active_count -= 1
                self._active_priority = None
                try:
                    self._semaphore.release()
                except ValueError:
                    pass
            self._interactive_condition.notify_all()

    def should_yield_to_interactive(self) -> bool:
        """Check if any interactive chat inference requests are waiting for GPU slot."""
        with self._counter_lock:
            return self._waiting_interactive > 0

    def wait_for_interactive_clear(self, timeout: float = 60.0) -> bool:
        """Block until all waiting and running interactive requests have released the GPU slot."""
        t_start = time.monotonic()
        with self._counter_lock:
            while self._waiting_interactive > 0 or self._active_priority == "INTERACTIVE":
                rem = timeout - (time.monotonic() - t_start)
                if rem <= 0:
                    return False
                self._interactive_condition.wait(timeout=min(rem, 0.5))
            return True

    @property
    def active_inferences(self) -> int:
        with self._counter_lock:
            return self._active_count

    @property
    def waiting_interactive(self) -> int:
        with self._counter_lock:
            return self._waiting_interactive

    def __enter__(self) -> "InferenceConcurrencyGate":
        self.acquire(priority="INTERACTIVE")
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.release()

    @contextmanager
    def slot(self, timeout: float = 60.0, priority: str = "INTERACTIVE") -> Iterator[bool]:
        acquired = self.acquire(timeout=timeout, priority=priority)
        try:
            yield acquired
        finally:
            if acquired:
                self.release()


class ModelRouter:
    """
    Deterministic router mapping operational cybersecurity tasks to model configurations
    with explicit pre-flight daemon and tag verification.
    """

    # Canonical model allocations per task type
    TASK_CONFIG: Dict[TaskType, Dict[str, Any]] = {
        TaskType.CONVERSATIONAL_QA: {
            "model": PINNED_7B_MODEL,
            "fallback": PINNED_3B_MODEL,
            "max_tokens": 512,
            "context_window": 4096,
            "temperature": 0.7,
            "timeout": 120.0,
        },
        TaskType.SECURITY_TRIAGE: {
            "model": PINNED_3B_MODEL,
            "fallback": None,
            "max_tokens": 300,
            "context_window": 2048,
            "temperature": 0.0,
            "timeout": 45.0,
        },
        TaskType.STRUCTURED_REASONING: {
            "model": PINNED_7B_MODEL,
            "fallback": PINNED_3B_MODEL,
            "max_tokens": 800,
            "context_window": 4096,
            "temperature": 0.0,
            "timeout": 120.0,
        },
        TaskType.CODE_SECURITY_REVIEW: {
            "model": PINNED_7B_MODEL,
            "fallback": None,
            "max_tokens": 1024,
            "context_window": 4096,
            "temperature": 0.2,
            "timeout": 150.0,
        },
        TaskType.VULNERABILITY_RESEARCH: {
            "model": PINNED_7B_MODEL,
            "fallback": PINNED_3B_MODEL,
            "max_tokens": 768,
            "context_window": 4096,
            "temperature": 0.4,
            "timeout": 120.0,
        },
        TaskType.REPORT_DRAFT: {
            "model": PINNED_7B_MODEL,
            "fallback": PINNED_3B_MODEL,
            "max_tokens": 1024,
            "context_window": 4096,
            "temperature": 0.3,
            "timeout": 180.0,
        },
        TaskType.EXPLANATION: {
            "model": PINNED_7B_MODEL,
            "fallback": PINNED_3B_MODEL,
            "max_tokens": 512,
            "context_window": 4096,
            "temperature": 0.6,
            "timeout": 90.0,
        },
    }

    @classmethod
    def check_model_readiness(
        cls,
        model_name: str,
        ollama_client: Optional[Any] = None,
    ) -> Tuple[bool, str]:
        """
        Verify that Ollama daemon is reachable and target model tag is present.
        Returns (ready: bool, status_reason: str).
        """
        if ollama_client is None:
            return False, "NO_CLIENT"

        # 1. Daemon Reachability Check
        try:
            if not ollama_client.is_available():
                return False, "DAEMON_UNAVAILABLE"
        except Exception:
            return False, "DAEMON_UNAVAILABLE"

        # 2. Installed Model Tag Check
        try:
            installed = ollama_client.list_models()
            model_names = [m.get("name", "") for m in installed if isinstance(m, dict)]
            # Match either exact tag or base tag (e.g. qwen2.5-coder:7b in qwen2.5-coder:7b-instruct-q4_K_M)
            target_base = model_name.split(":")[0] if ":" in model_name else model_name
            found = any(model_name in name or target_base in name for name in model_names)
            if not found:
                return False, f"MODEL_NOT_FOUND: {model_name} not installed in local Ollama daemon"
        except Exception as e:
            return False, f"INVENTORY_ERROR: {e}"

        return True, "AVAILABLE"

    @classmethod
    def route_task(
        cls,
        task_type: TaskType,
        ollama_client: Optional[Any] = None,
        allow_fallback: bool = True,
        override_model: Optional[str] = None,
    ) -> ModelRouteDecision:
        """
        Execute deterministic model selection.
        If requested model is unavailable and fallback is allowed, select fallback
        and truthfully record the fallback reason.
        """
        cfg = cls.TASK_CONFIG.get(task_type, cls.TASK_CONFIG[TaskType.CONVERSATIONAL_QA])
        configured_model = override_model or cfg["model"]
        fallback_model = cfg["fallback"]

        # Check primary model readiness
        is_ready, reason = cls.check_model_readiness(configured_model, ollama_client)

        if is_ready:
            return ModelRouteDecision(
                task_type=task_type,
                configured_model=configured_model,
                selected_model=configured_model,
                fallback_model=fallback_model,
                fallback_used=False,
                fallback_reason=None,
                max_tokens=cfg["max_tokens"],
                context_window=cfg["context_window"],
                temperature=cfg["temperature"],
                timeout_seconds=cfg["timeout"],
                runtime_available=True,
                runtime_status="AVAILABLE",
            )

        # Primary not ready: evaluate fallback if permitted and available
        if allow_fallback and fallback_model and fallback_model != configured_model:
            fb_ready, fb_reason = cls.check_model_readiness(fallback_model, ollama_client)
            if fb_ready:
                logger.info(
                    f"Model routing fallback: {configured_model} unavailable ({reason}) -> using fallback {fallback_model}"
                )
                return ModelRouteDecision(
                    task_type=task_type,
                    configured_model=configured_model,
                    selected_model=fallback_model,
                    fallback_model=fallback_model,
                    fallback_used=True,
                    fallback_reason=f"Primary model {configured_model} unavailable: {reason}",
                    max_tokens=cfg["max_tokens"],
                    context_window=cfg["context_window"],
                    temperature=cfg["temperature"],
                    timeout_seconds=cfg["timeout"],
                    runtime_available=True,
                    runtime_status="AVAILABLE_VIA_FALLBACK",
                )

        # Neither primary nor fallback available
        logger.warning(
            f"Model routing unavailable: {configured_model} ({reason}). No operational local LLM available."
        )
        return ModelRouteDecision(
            task_type=task_type,
            configured_model=configured_model,
            selected_model=configured_model,
            fallback_model=fallback_model,
            fallback_used=False,
            fallback_reason=reason,
            max_tokens=cfg["max_tokens"],
            context_window=cfg["context_window"],
            temperature=cfg["temperature"],
            timeout_seconds=cfg["timeout"],
            runtime_available=False,
            runtime_status=reason,
        )
