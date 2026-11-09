"""Unit & Failure-Injection Tests for Atomic Writing Mechanism.

Covers the 8 required failure-injection scenarios:
1. Interruption during staged JSON writing.
2. JSON serialization or validation failure.
3. Failure during checksum generation or sidecar publication.
4. Replacement failure (os.replace failure).
5. Recovery from a temporary file left by an interrupted run.
6. A JSON/sidecar mismatch.
7. A checkpoint interrupted while being written.
8. Preservation of the previous valid artifact when publication fails.
"""

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from src.core.atomic_write import (
    AtomicWriteError,
    atomic_write_bytes,
    atomic_write_json,
    clean_orphaned_tmp_files,
    verify_artifact_checksum,
)


def test_interruption_during_staged_write(tmp_path: Path):
    """Scenario 1: Simulated IO interruption during staging file write.
    Target must NOT be published, and temporary file must be cleaned up."""
    target = tmp_path / "interrupted.json"

    # Inject failure during write on the file object
    with patch("tempfile.NamedTemporaryFile") as mock_tmp:
        mock_file = MagicMock()
        mock_file.name = str(tmp_path / ".tmp_interrupted_test.tmp")
        mock_file.write.side_effect = IOError("Simulated disk write failure")
        mock_tmp.return_value = mock_file

        with pytest.raises(AtomicWriteError, match="Simulated disk write failure"):
            atomic_write_bytes(target, b'{"test": "data"}')

    # Target must not exist
    assert not target.exists()
    # No temporary files should remain
    tmp_files = list(tmp_path.glob(".tmp_*.tmp"))
    assert len(tmp_files) == 0


def test_json_serialization_or_validation_failure(tmp_path: Path):
    """Scenario 2: Serialization or validation failure on staged JSON.
    Target file is not published and invalid data is rejected."""
    target = tmp_path / "invalid_data.json"

    # Non-serializable object
    class NonSerializable:
        pass

    with pytest.raises(AtomicWriteError, match="JSON serialization failed"):
        atomic_write_json(target, {"unsupported": NonSerializable()})

    assert not target.exists()
    assert len(list(tmp_path.glob(".tmp_*.tmp"))) == 0


def test_failure_during_checksum_generation_or_sidecar_publication(tmp_path: Path):
    """Scenario 3: Failure during sidecar publication is properly raised."""
    target = tmp_path / "target_with_sidecar.json"

    # Mock sidecar write failure by failing second os.replace call
    original_replace = os.replace
    call_count = 0

    def mock_replace(src, dst):
        nonlocal call_count
        call_count += 1
        if call_count == 2:  # Sidecar replacement
            raise OSError("Simulated sidecar replace failure")
        return original_replace(src, dst)

    with patch("os.replace", side_effect=mock_replace):
        with pytest.raises(AtomicWriteError, match="Simulated sidecar replace failure"):
            atomic_write_json(target, {"key": "value"}, write_checksum_sidecar=True)

    # Clean up temp files
    clean_orphaned_tmp_files(tmp_path)


def test_replacement_failure_preserves_original(tmp_path: Path):
    """Scenario 4: Replacement failure (os.replace failure) leaves original target intact."""
    target = tmp_path / "important_artifact.json"
    initial_content = {"version": 1, "status": "stable"}
    atomic_write_json(target, initial_content)

    # Attempt overwrite with failing os.replace
    with patch("os.replace", side_effect=OSError("Access denied during replacement")):
        with pytest.raises(AtomicWriteError, match="Access denied during replacement"):
            atomic_write_json(target, {"version": 2, "status": "corrupted"})

    # Original target must remain byte-for-byte intact
    loaded = json.loads(target.read_text(encoding="utf-8"))
    assert loaded == initial_content
    # Temporary files cleaned up
    assert len(list(tmp_path.glob(".tmp_*.tmp"))) == 0


def test_recovery_from_temporary_file_left_by_interrupted_run(tmp_path: Path):
    """Scenario 5: Recovery from orphaned temporary files left by previous aborted runs."""
    # Simulate crashed process leaving orphaned .tmp files
    orphan1 = tmp_path / ".tmp_crash1.tmp"
    orphan2 = tmp_path / ".tmp_crash2.tmp"
    orphan1.write_text("partial data 1", encoding="utf-8")
    orphan2.write_text("partial data 2", encoding="utf-8")

    # Valid artifact alongside orphans
    valid_file = tmp_path / "valid.json"
    valid_file.write_text('{"status": "ok"}', encoding="utf-8")

    # Clean orphaned temp files
    cleaned = clean_orphaned_tmp_files(tmp_path)
    assert cleaned == 2
    assert not orphan1.exists()
    assert not orphan2.exists()
    assert valid_file.exists()


def test_json_sidecar_mismatch_detection(tmp_path: Path):
    """Scenario 6: Detection of JSON and checksum sidecar mismatch."""
    target = tmp_path / "verified_artifact.json"
    atomic_write_json(target, {"verified": True, "count": 100}, write_checksum_sidecar=True)

    # Should verify successfully
    is_valid, actual_h, sc_h = verify_artifact_checksum(target)
    assert is_valid is True
    assert actual_h == sc_h

    # Tamper with the artifact
    target.write_text('{"verified": false, "count": 100}', encoding="utf-8")

    # Should detect mismatch
    is_valid_tampered, actual_tampered, sc_tampered = verify_artifact_checksum(target)
    assert is_valid_tampered is False
    assert actual_tampered != sc_tampered


def test_checkpoint_interrupted_while_being_written(tmp_path: Path):
    """Scenario 7: A checkpoint interrupted during writing preserves the existing checkpoint."""
    ckpt_path = tmp_path / "checkpoint.json"
    valid_checkpoint = {
        "completed_count": 10,
        "results": {f"CASE-{i}": {"prediction": "VALID"} for i in range(10)},
    }
    atomic_write_json(ckpt_path, valid_checkpoint)

    # Attempt to write corrupted/interrupted update
    with patch("os.replace", side_effect=RuntimeError("Process terminated abruptly")):
        with pytest.raises(AtomicWriteError, match="Process terminated abruptly"):
            atomic_write_json(
                ckpt_path,
                {"completed_count": 11, "results": {"corrupted": True}},
            )

    # Checkpoint must still contain original valid 10 results
    reloaded = json.loads(ckpt_path.read_text(encoding="utf-8"))
    assert reloaded["completed_count"] == 10
    assert len(reloaded["results"]) == 10


def test_preservation_of_previous_valid_artifact_when_publication_fails(tmp_path: Path):
    """Scenario 8: Complete failure-injection demonstrating preservation of last known-good artifact."""
    artifact = tmp_path / "model_results.json"
    known_good = {"cases_evaluated": 20, "metrics": {"f1": 0.85}}
    atomic_write_json(artifact, known_good, write_checksum_sidecar=True)
    is_valid, _, _ = verify_artifact_checksum(artifact)
    assert is_valid is True

    # Injection: serialization error during update
    with pytest.raises(AtomicWriteError):
        atomic_write_json(artifact, {"cases_evaluated": 21, "bad": object()})

    # File and sidecar are preserved intact
    current_data = json.loads(artifact.read_text(encoding="utf-8"))
    assert current_data == known_good
    is_valid_after, _, _ = verify_artifact_checksum(artifact)
    assert is_valid_after is True
