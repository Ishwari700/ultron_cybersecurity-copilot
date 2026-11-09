"""Unit tests for M8 Audit Trail Integrity and Tamper Detection (Phase 20 & Phase 22).

Verifies:
- Append-only semantics.
- Cryptographic SHA-256 event chaining.
- Detection of modifications (actor, metadata, event_type).
- Detection of deletion / omission.
- Detection of reordering.
- Immutable event hash verification.
"""

import pytest
from src.audit.models import AuditEventType, ImmutableAuditEvent
from src.audit.ledger import AuditLedger


def test_audit_ledger_genesis_and_chaining():
    """Verifies that events are properly chained from GENESIS with SHA-256 hashes."""
    ledger = AuditLedger(assessment_id="ASM-AUDIT-01")
    assert len(ledger.get_events()) == 0
    assert ledger.verify_integrity() is True

    evt1 = ledger.append(
        actor="Alice",
        event_type=AuditEventType.ASSESSMENT_CREATED,
        object_id="ASM-AUDIT-01",
        metadata={"scope": "in_scope"},
    )
    assert evt1.previous_event_hash == "GENESIS"
    assert len(evt1.event_hash) == 64
    assert evt1.event_hash == evt1.compute_event_hash()

    evt2 = ledger.append(
        actor="Bob",
        event_type=AuditEventType.ASSET_ADDED,
        object_id="asset-1",
        metadata={"asset": "api.example.com"},
    )
    assert evt2.previous_event_hash == evt1.event_hash
    assert evt2.event_hash == evt2.compute_event_hash()

    evt3 = ledger.append(
        actor="System",
        event_type=AuditEventType.REPORT_FINALIZED,
        object_id="REP-001",
    )
    assert evt3.previous_event_hash == evt2.event_hash
    assert evt3.event_hash == evt3.compute_event_hash()

    assert len(ledger.get_events()) == 3
    assert ledger.verify_integrity() is True


def test_audit_ledger_detects_actor_modification():
    """Modifying the actor of an event breaks the cryptographic hash check."""
    ledger = AuditLedger(assessment_id="ASM-AUDIT-02")
    ledger.append("Alice", AuditEventType.ASSESSMENT_CREATED, "ASM-AUDIT-02")
    ledger.append("Bob", AuditEventType.REVIEW_STARTED, "REV-01")
    ledger.append("Charlie", AuditEventType.FINDING_VALIDATED, "FIND-01")

    assert ledger.verify_integrity() is True

    # Tamper with actor in event 1
    ledger._events[1].actor = "MaliciousHacker"
    assert ledger.verify_integrity() is False


def test_audit_ledger_detects_metadata_modification():
    """Modifying metadata of a historical event breaks integrity."""
    ledger = AuditLedger(assessment_id="ASM-AUDIT-03")
    ledger.append("Alice", AuditEventType.ASSESSMENT_CREATED, "ASM-AUDIT-03", {"flag": 1})
    ledger.append("Bob", AuditEventType.EVIDENCE_ADDED, "EVID-01", {"target": "ok"})

    assert ledger.verify_integrity() is True

    # Tamper with metadata
    ledger._events[0].metadata["flag"] = 999
    assert ledger.verify_integrity() is False


def test_audit_ledger_detects_event_deletion():
    """Deleting an event breaks the previous_event_hash chain."""
    ledger = AuditLedger(assessment_id="ASM-AUDIT-04")
    ledger.append("Alice", AuditEventType.ASSESSMENT_CREATED, "ASM-AUDIT-04")
    ledger.append("Bob", AuditEventType.ARTIFACT_IMPORTED, "ART-01")
    ledger.append("Charlie", AuditEventType.REPORT_EXPORTED, "REP-01")

    assert ledger.verify_integrity() is True

    # Delete the middle event
    del ledger._events[1]
    assert ledger.verify_integrity() is False


def test_audit_ledger_detects_event_reordering():
    """Reordering events breaks hash chaining."""
    ledger = AuditLedger(assessment_id="ASM-AUDIT-05")
    ledger.append("Alice", AuditEventType.ASSESSMENT_CREATED, "ASM-AUDIT-05")
    ledger.append("Bob", AuditEventType.ARTIFACT_IMPORTED, "ART-01")

    assert ledger.verify_integrity() is True

    # Swap events
    ledger._events[0], ledger._events[1] = ledger._events[1], ledger._events[0]
    assert ledger.verify_integrity() is False


def test_audit_ledger_filter_by_type():
    """Filtering events returns the matching types without modifying the ledger."""
    ledger = AuditLedger(assessment_id="ASM-AUDIT-06")
    ledger.append("Alice", AuditEventType.ASSESSMENT_CREATED, "ASM-06")
    ledger.append("Bob", AuditEventType.ARTIFACT_IMPORTED, "ART-01")
    ledger.append("Bob", AuditEventType.ARTIFACT_IMPORTED, "ART-02")
    ledger.append("Charlie", AuditEventType.REPORT_GENERATED, "REP-01")

    imports = ledger.get_events(AuditEventType.ARTIFACT_IMPORTED)
    assert len(imports) == 2
    assert imports[0].object_id == "ART-01"
    assert imports[1].object_id == "ART-02"

    reports = ledger.get_events(AuditEventType.REPORT_GENERATED)
    assert len(reports) == 1
    assert reports[0].object_id == "REP-01"

    assert ledger.verify_integrity() is True
