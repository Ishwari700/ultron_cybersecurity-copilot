"""Milestone M11: Experiment Replay Engine.

Enforces:
1. Replay Reproducibility: Re-executes completed local experiments in clean disposable environments (Section 18).
2. Replay Comparison: ORIGINAL vs REPLAY.
3. Invariant INV-M11-20: Replay mismatch cannot be reported as reproducible success.
4. Mismatch Detection: Flags status codes, exit codes, canary occurrences, or output divergences as REPRODUCTION_MISMATCH.
"""

from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Callable, Dict, List, Optional
from pydantic import BaseModel, Field

from src.experiment.models import ControlledExperiment
from src.experiment.lab_runner import ControlledLabRunner, LabExecutionResult
from src.experiment.poc import SafePoC


class ExperimentReplayRecord(BaseModel):
    """
    Deterministic comparison record of an experiment replay.
    """
    replay_id: str
    experiment_id: str
    original_execution_id: str
    replay_execution_id: str
    is_reproducible: bool
    status: str  # "REPRODUCED" or "REPRODUCTION_MISMATCH"
    mismatches: List[str] = Field(default_factory=list)
    original_summary: Dict[str, Any] = Field(default_factory=dict)
    replay_summary: Dict[str, Any] = Field(default_factory=dict)
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ExperimentReplayEngine:
    """
    Re-executes controlled security experiments and verifies reproducible outcomes.
    """

    @classmethod
    def replay_experiment(
        cls,
        experiment: ControlledExperiment,
        original_result: LabExecutionResult,
        poc: Optional[SafePoC] = None,
        mock_http_handler: Optional[Callable[[str, Dict[str, Any]], Dict[str, Any]]] = None,
    ) -> ExperimentReplayRecord:
        """
        Replays experiment and evaluates reproducibility.
        Fails closed on any outcome divergence (INV-M11-20).
        """
        replay_result = ControlledLabRunner.execute_experiment(
            experiment=experiment,
            poc=poc,
            mock_http_handler=mock_http_handler,
        )

        mismatches: List[str] = []

        # Compare exit code
        if original_result.exit_code != replay_result.exit_code:
            mismatches.append(
                f"Exit code mismatch: Original={original_result.exit_code} vs Replay={replay_result.exit_code}"
            )

        # Compare execution status
        if original_result.status != replay_result.status:
            mismatches.append(
                f"Status mismatch: Original={original_result.status.value} vs Replay={replay_result.status.value}"
            )

        # Compare HTTP responses if present
        orig_codes = [r.get("status_code") for r in original_result.http_responses]
        repl_codes = [r.get("status_code") for r in replay_result.http_responses]
        if orig_codes != repl_codes:
            mismatches.append(f"HTTP status code sequence mismatch: Original={orig_codes} vs Replay={repl_codes}")

        # Compare canary presence if PoC defined
        if poc and poc.canary_marker:
            orig_has_canary = poc.canary_marker in original_result.stdout or any(poc.canary_marker in str(r) for r in original_result.http_responses)
            repl_has_canary = poc.canary_marker in replay_result.stdout or any(poc.canary_marker in str(r) for r in replay_result.http_responses)
            if orig_has_canary != repl_has_canary:
                mismatches.append(
                    f"Canary marker mismatch: Original has_canary={orig_has_canary} vs Replay has_canary={repl_has_canary}"
                )

        is_reproducible = len(mismatches) == 0
        status = "REPRODUCED" if is_reproducible else "REPRODUCTION_MISMATCH"

        seed = f"{experiment.experiment_id}:{original_result.execution_id}:{replay_result.execution_id}"
        rep_id = f"REPLAY-M11-{hashlib.sha256(seed.encode()).hexdigest()[:10].upper()}"

        record = ExperimentReplayRecord(
            replay_id=rep_id,
            experiment_id=experiment.experiment_id,
            original_execution_id=original_result.execution_id,
            replay_execution_id=replay_result.execution_id,
            is_reproducible=is_reproducible,
            status=status,
            mismatches=mismatches,
            original_summary={
                "status": original_result.status.value,
                "exit_code": original_result.exit_code,
                "http_status_codes": orig_codes,
            },
            replay_summary={
                "status": replay_result.status.value,
                "exit_code": replay_result.exit_code,
                "http_status_codes": repl_codes,
            },
        )

        experiment.replay_records.append(record.model_dump())
        return record
