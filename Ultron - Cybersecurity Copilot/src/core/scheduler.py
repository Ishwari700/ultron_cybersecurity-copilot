"""Hardware-aware pipeline scheduler enforcing phased synchronous execution."""

import time
import threading
from contextlib import contextmanager
from enum import Enum
from typing import Dict, Generator, Optional
from src.core.config import PipelineConfig


class PipelinePhase(str, Enum):
    """Execution phases corresponding to hardware scheduling allocations."""
    IDLE = "IDLE"
    PHASE_1_RECON_INGESTION = "PHASE_1_RECON_INGESTION"  # 100% CPU to crawlers/adapters
    PHASE_2_EMBEDDING_INDEXING = "PHASE_2_EMBEDDING_INDEXING"  # 100% CPU to ChromaDB/BM25
    PHASE_3_REASONING_SWEEPS = "PHASE_3_REASONING_SWEEPS"  # 100% GPU to Ollama inference


class PhaseConcurrencyError(Exception):
    """Raised when an illegal phase transition or concurrent execution is attempted."""
    pass


class PipelineScheduler:
    """
    Manages pipeline execution state, enforcing strict synchronous phasing
    to eliminate CPU/IO and VRAM contention on AMD Ryzen 5 5600H and RTX 3050.
    """

    def __init__(self, config: Optional[PipelineConfig] = None) -> None:
        self.config = config or PipelineConfig()
        self._current_phase: PipelinePhase = PipelinePhase.IDLE
        self._lock = threading.RLock()
        self._phase_history: list[Dict[str, object]] = []

    @property
    def current_phase(self) -> PipelinePhase:
        with self._lock:
            return self._current_phase

    @property
    def phase_history(self) -> list[Dict[str, object]]:
        with self._lock:
            return list(self._phase_history)

    def can_transition_to(self, target_phase: PipelinePhase) -> bool:
        """Check if a transition from the current phase to target_phase is permissible."""
        with self._lock:
            if target_phase == PipelinePhase.IDLE:
                return True
            if self._current_phase != PipelinePhase.IDLE and not self.config.allow_concurrent_phases:
                return False
            return True

    @contextmanager
    def enter_phase(self, phase: PipelinePhase) -> Generator[PipelinePhase, None, None]:
        """
        Context manager to safely execute work inside an authorized phase.
        Enforces exit back to IDLE upon completion or error.
        """
        with self._lock:
            if not self.can_transition_to(phase):
                raise PhaseConcurrencyError(
                    f"Cannot enter {phase.value} while currently in active phase {self._current_phase.value}. "
                    "Strict phasing requires the previous phase to complete before starting another."
                )
            previous_phase = self._current_phase
            self._current_phase = phase
            start_time = time.time()

        try:
            yield phase
        finally:
            with self._lock:
                end_time = time.time()
                duration = end_time - start_time
                self._phase_history.append({
                    "phase": phase.value,
                    "start_time": start_time,
                    "end_time": end_time,
                    "duration_seconds": round(duration, 4),
                })
                self._current_phase = previous_phase if previous_phase == PipelinePhase.IDLE else PipelinePhase.IDLE

    def reset(self) -> None:
        """Reset the scheduler to IDLE state and clear history."""
        with self._lock:
            self._current_phase = PipelinePhase.IDLE
            self._phase_history.clear()
