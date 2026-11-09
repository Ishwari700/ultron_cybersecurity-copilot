"""Unit tests for the hardware-aware pipeline scheduler."""

import pytest
from src.core.config import PipelineConfig
from src.core.scheduler import PipelinePhase, PipelineScheduler, PhaseConcurrencyError


def test_scheduler_initial_state():
    """Verify scheduler initializes in IDLE state with empty history."""
    scheduler = PipelineScheduler()
    assert scheduler.current_phase == PipelinePhase.IDLE
    assert scheduler.phase_history == []


def test_single_phase_execution():
    """Verify entering and leaving a phase via context manager."""
    scheduler = PipelineScheduler()

    with scheduler.enter_phase(PipelinePhase.PHASE_1_RECON_INGESTION) as phase:
        assert phase == PipelinePhase.PHASE_1_RECON_INGESTION
        assert scheduler.current_phase == PipelinePhase.PHASE_1_RECON_INGESTION

    assert scheduler.current_phase == PipelinePhase.IDLE
    assert len(scheduler.phase_history) == 1
    record = scheduler.phase_history[0]
    assert record["phase"] == PipelinePhase.PHASE_1_RECON_INGESTION.value
    assert record["duration_seconds"] >= 0.0


def test_sequential_phases():
    """Verify running Phase 1, Phase 2, and Phase 3 sequentially."""
    scheduler = PipelineScheduler()

    with scheduler.enter_phase(PipelinePhase.PHASE_1_RECON_INGESTION):
        pass
    with scheduler.enter_phase(PipelinePhase.PHASE_2_EMBEDDING_INDEXING):
        pass
    with scheduler.enter_phase(PipelinePhase.PHASE_3_REASONING_SWEEPS):
        pass

    assert scheduler.current_phase == PipelinePhase.IDLE
    assert len(scheduler.phase_history) == 3
    phases = [r["phase"] for r in scheduler.phase_history]
    assert phases == [
        PipelinePhase.PHASE_1_RECON_INGESTION.value,
        PipelinePhase.PHASE_2_EMBEDDING_INDEXING.value,
        PipelinePhase.PHASE_3_REASONING_SWEEPS.value,
    ]


def test_concurrent_phase_rejection():
    """Verify that attempting to enter a second phase concurrently raises PhaseConcurrencyError."""
    scheduler = PipelineScheduler(config=PipelineConfig(strict_phasing=True))

    with scheduler.enter_phase(PipelinePhase.PHASE_1_RECON_INGESTION):
        with pytest.raises(PhaseConcurrencyError, match="Cannot enter PHASE_2_EMBEDDING_INDEXING"):
            with scheduler.enter_phase(PipelinePhase.PHASE_2_EMBEDDING_INDEXING):
                pass

    # Ensure scheduler cleaned up to IDLE after outer context finishes
    assert scheduler.current_phase == PipelinePhase.IDLE


def test_scheduler_reset():
    """Verify reset returns scheduler to IDLE and clears history."""
    scheduler = PipelineScheduler()
    with scheduler.enter_phase(PipelinePhase.PHASE_1_RECON_INGESTION):
        pass
    assert len(scheduler.phase_history) == 1

    scheduler.reset()
    assert scheduler.current_phase == PipelinePhase.IDLE
    assert scheduler.phase_history == []
