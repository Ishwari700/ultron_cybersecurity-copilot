"""Unit tests for structured logging and immutable audit log."""

import json
from pathlib import Path
from src.core.logging import AuditLogger, get_logger


def test_get_logger():
    """Verify structured logger instantiates with handler."""
    logger = get_logger("test_component", level="DEBUG")
    assert logger.name == "test_component"
    assert len(logger.handlers) >= 1


def test_audit_logger_event_logging(tmp_path: Path):
    """Verify audit logger writes immutable JSONL entries."""
    audit_file = tmp_path / "audit.log"
    auditor = AuditLogger(audit_file)

    record = auditor.log_event(
        event_type="SCOPE_DECISION",
        actor="ScopeGate",
        subject_id="https://api.target.com",
        previous_state=None,
        new_state="ALLOWED",
        details={"matched_rule": "*.target.com", "resolved_ip": "192.0.2.1"},
    )

    assert record["event_type"] == "SCOPE_DECISION"
    assert record["actor"] == "ScopeGate"
    assert record["new_state"] == "ALLOWED"
    assert "timestamp" in record
    assert "payload_hash" in record
    assert record["details"]["resolved_ip"] == "192.0.2.1"

    # Verify written file contents
    assert audit_file.exists()
    lines = audit_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    loaded = json.loads(lines[0])
    assert loaded["subject_id"] == "https://api.target.com"
    assert loaded["payload_hash"] == record["payload_hash"]


def test_audit_logger_read_records(tmp_path: Path):
    """Verify reading records back in order."""
    audit_file = tmp_path / "audit.log"
    auditor = AuditLogger(audit_file)

    auditor.log_event("EVENT_1", actor="user_a", subject_id="SUBJ-1")
    auditor.log_event("EVENT_2", actor="user_b", subject_id="SUBJ-2")
    auditor.log_event("EVENT_3", actor="user_c", subject_id="SUBJ-3")

    records = auditor.read_records()
    assert len(records) == 3
    assert [r["event_type"] for r in records] == ["EVENT_1", "EVENT_2", "EVENT_3"]

    latest_two = auditor.read_records(limit=2)
    assert len(latest_two) == 2
    assert [r["event_type"] for r in latest_two] == ["EVENT_2", "EVENT_3"]
