"""Multi-process concurrent audit logging test verifying cross-process locking and hash chain integrity."""

import multiprocessing
from pathlib import Path
from typing import List
from src.core.logging import AuditLogger, verify_audit_log


def _worker_log_events(audit_path: str, proc_id: int, num_events: int) -> None:
    """Worker function executed in an independent OS process."""
    logger = AuditLogger(audit_file_path=Path(audit_path))
    for i in range(num_events):
        logger.log_event(
            event_type="PROCESS_CONCURRENT_EVENT",
            actor=f"worker_proc_{proc_id}",
            subject_id=f"item_{proc_id}_{i}",
            details={"process_id": proc_id, "iteration": i},
        )


def test_audit_logger_multiprocess_chain_integrity(tmp_path: Path):
    """Verify that multiple independent OS processes writing to the same audit log preserve hash chain and sequence monotonicity."""
    audit_file = tmp_path / "concurrent_audit.jsonl"
    num_processes = 4
    events_per_process = 15
    total_expected_records = num_processes * events_per_process

    processes: List[multiprocessing.Process] = []
    # Use spawn context for cross-platform process isolation (required on Windows)
    ctx = multiprocessing.get_context("spawn")

    for proc_id in range(num_processes):
        p = ctx.Process(
            target=_worker_log_events,
            args=(str(audit_file), proc_id, events_per_process),
        )
        processes.append(p)
        p.start()

    for p in processes:
        p.join(timeout=30.0)
        assert p.exitcode == 0, f"Process {p.pid} terminated with exit code {p.exitcode}"

    # Verify audit log independently
    result = verify_audit_log(audit_file)
    assert result.valid is True, f"Audit log verification failed: {result.error_messages}"
    assert result.total_records == total_expected_records
    assert len(result.tampered_records) == 0
    assert len(result.tampering_types) == 0

    # Explicitly verify sequence monotonicity and zero duplicate sequence numbers
    reader = AuditLogger(audit_file_path=audit_file)
    records = reader.read_records()
    assert len(records) == total_expected_records

    seen_seqs = set()
    prev_hash = "0" * 64
    for idx, rec in enumerate(records, start=1):
        seq = rec["sequence_number"]
        assert seq == idx, f"Sequence gap/mismatch at index {idx}: got sequence {seq}"
        assert seq not in seen_seqs, f"Duplicate sequence number detected: {seq}"
        seen_seqs.add(seq)

        assert rec["previous_record_hash"] == prev_hash, f"Hash chain broken at sequence {seq}"
        prev_hash = rec["record_hash"]
