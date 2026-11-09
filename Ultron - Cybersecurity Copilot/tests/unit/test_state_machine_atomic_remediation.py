"""Regression tests for atomic verification and state machine lifecycle remediation."""

import sqlite3
import pytest
from src.database.manager import DatabaseManager
from src.hypothesis.state_machine import EvidenceState, HypothesisState, HypothesisStateMachine


@pytest.fixture
def test_db(tmp_path):
    db_file = tmp_path / "test_state_machine.db"
    db = DatabaseManager(db_path=db_file)
    db.initialize_schema()

    # Seed an asset
    db.insert_asset({
        "asset_id": "ASSET-TEST-001",
        "method": "POST",
        "host": "api.test.local",
        "raw_path": "/api/v1/test",
        "normalized_path": "/api/v1/test",
    })
    return db


def create_sample_hypothesis(db: DatabaseManager, state: str = "New") -> int:
    return db.insert_hypothesis({
        "asset_id": "ASSET-TEST-001",
        "category": "API-BOLA-001",
        "decision": "HYPOTHESIS",
        "evidence_state": "PARTIAL",
        "state": state,
    })


def test_atomic_verification_rollback_on_failure(test_db):
    """
    Verify that if verification/transition fails (e.g., short evidence_ref or trigger abort),
    the transaction rolls back completely and leaves NO orphan verification record.
    """
    hyp_id = create_sample_hypothesis(test_db, state="New")
    sm = HypothesisStateMachine(test_db)
    sm.start_review(hyp_id)

    # Attempt confirmation with invalid evidence_ref (< 5 chars)
    with pytest.raises(ValueError, match="evidence_ref must be non-empty and at least 5 characters"):
        sm.confirm_with_human_verification(
            hypothesis_id=hyp_id,
            actor="analyst_alice",
            evidence_ref="log",  # Only 3 chars -> fails validation
            session_id="SESS-001",
        )

    # Verify hypothesis remains Under Review
    hyp = test_db.get_hypothesis(hyp_id)
    assert hyp["state"] == "Under Review"

    # Verify NO verification record was inserted
    with test_db.get_connection() as conn:
        cursor = conn.execute("SELECT COUNT(*) as count FROM verifications WHERE hypothesis_id = ?", (hyp_id,))
        assert cursor.fetchone()["count"] == 0


def test_atomic_confirmation_success(test_db):
    """Verify that valid human verification atomically commits both verification and state transition."""
    hyp_id = create_sample_hypothesis(test_db, state="New")
    sm = HypothesisStateMachine(test_db)
    sm.start_review(hyp_id)

    verif_id = sm.confirm_with_human_verification(
        hypothesis_id=hyp_id,
        actor="lead_researcher",
        evidence_ref="logs/repro_verified_01.txt",
        session_id="SESS-SECURE-999",
        notes="Empirically confirmed vulnerability",
    )

    assert verif_id.startswith("VERIF-")

    # Hypothesis must now be Confirmed
    hyp = test_db.get_hypothesis(hyp_id)
    assert hyp["state"] == "Confirmed"
    assert hyp["evidence_ref"] == "logs/repro_verified_01.txt"

    # Verification row must exist with matching parameters
    with test_db.get_connection() as conn:
        cursor = conn.execute("SELECT * FROM verifications WHERE verification_id = ?", (verif_id,))
        row = cursor.fetchone()
        assert row is not None
        assert row["actor"] == "lead_researcher"
        assert row["decision"] == "confirmed"
        assert row["hypothesis_id"] == hyp_id


def test_direct_transition_from_new_to_confirmed_blocked(test_db):
    """
    A hypothesis in 'New' must NOT be allowed to jump directly to 'Confirmed'
    even if a verification record was manually inserted.
    """
    hyp_id = create_sample_hypothesis(test_db, state="New")

    # Manually insert a verification row
    test_db.record_verification({
        "verification_id": "VERIF-PRECREATED",
        "hypothesis_id": hyp_id,
        "actor": "rogue_actor",
        "decision": "confirmed",
        "evidence_ref": "logs/bypass_attempt.txt",
        "dashboard_session_id": "SESS-ROGUE",
    })

    # Direct transition from New to Confirmed must fail at DB trigger level
    with pytest.raises(sqlite3.DatabaseError, match="Cannot move hypothesis to Confirmed without first being in Under Review state"):
        test_db.update_hypothesis_state(hyp_id, "Confirmed", evidence_ref="logs/bypass_attempt.txt")

    # Hypothesis must remain in New
    assert test_db.get_hypothesis(hyp_id)["state"] == "New"


def test_direct_transition_to_reported_blocked(test_db):
    """A hypothesis in 'New' or 'Under Review' must NOT be allowed to jump to 'Reported'."""
    hyp_new = create_sample_hypothesis(test_db, state="New")
    with pytest.raises(sqlite3.DatabaseError, match="Cannot move hypothesis to Reported without first being in Confirmed state"):
        test_db.update_hypothesis_state(hyp_new, "Reported")

    hyp_review = create_sample_hypothesis(test_db, state="New")
    test_db.update_hypothesis_state(hyp_review, "Under Review")
    with pytest.raises(sqlite3.DatabaseError, match="Cannot move hypothesis to Reported without first being in Confirmed state"):
        test_db.update_hypothesis_state(hyp_review, "Reported")


def test_terminal_reported_state_cannot_be_changed(test_db):
    """Once a hypothesis is Reported, it is in a terminal state and cannot transition to any other state."""
    hyp_id = create_sample_hypothesis(test_db, state="New")
    sm = HypothesisStateMachine(test_db)
    sm.start_review(hyp_id)
    sm.confirm_with_human_verification(
        hypothesis_id=hyp_id,
        actor="lead_analyst",
        evidence_ref="logs/valid_evidence_123.txt",
        session_id="SESS-VAL",
    )
    sm.report_hypothesis(hyp_id)
    assert test_db.get_hypothesis(hyp_id)["state"] == "Reported"

    # Attempting to move away from Reported must be blocked by DB trigger
    for invalid_target in ["New", "Under Review", "Confirmed", "Rejected"]:
        with pytest.raises(sqlite3.DatabaseError, match="Cannot transition away from terminal Reported state"):
            test_db.update_hypothesis_state(hyp_id, invalid_target)


def test_terminal_rejected_state_cannot_be_changed(test_db):
    """Once a hypothesis is Rejected, it is terminal and cannot transition to any other state."""
    hyp_id = create_sample_hypothesis(test_db, state="New")
    test_db.update_hypothesis_state(hyp_id, "Rejected")
    assert test_db.get_hypothesis(hyp_id)["state"] == "Rejected"

    for invalid_target in ["New", "Under Review", "Confirmed", "Reported"]:
        with pytest.raises(sqlite3.DatabaseError, match="Cannot transition away from terminal Rejected state"):
            test_db.update_hypothesis_state(hyp_id, invalid_target)


def test_confirmed_cannot_be_rejected_directly(test_db):
    """A Confirmed hypothesis cannot be directly transitioned to Rejected."""
    hyp_id = create_sample_hypothesis(test_db, state="New")
    sm = HypothesisStateMachine(test_db)
    sm.start_review(hyp_id)
    sm.confirm_with_human_verification(
        hypothesis_id=hyp_id,
        actor="lead_analyst",
        evidence_ref="logs/valid_evidence_123.txt",
        session_id="SESS-VAL",
    )

    with pytest.raises(sqlite3.DatabaseError, match="Cannot reject hypothesis that has already been Confirmed"):
        test_db.update_hypothesis_state(hyp_id, "Rejected")


def test_arbitrary_state_rejected(test_db):
    """update_hypothesis_state must reject arbitrary state strings outside the allowed enum."""
    hyp_id = create_sample_hypothesis(test_db, state="New")
    with pytest.raises(ValueError, match="Invalid hypothesis state"):
        test_db.update_hypothesis_state(hyp_id, "MALICIOUS_INJECTED_STATE")


def test_cannot_move_to_under_review_unless_new(test_db):
    """A hypothesis cannot transition to 'Under Review' from any state other than 'New'."""
    hyp_id = create_sample_hypothesis(test_db, state="New")
    test_db.update_hypothesis_state(hyp_id, "Under Review")
    # Now it is in Under Review. Trying to transition to Under Review again via raw trigger check:
    # From Confirmed:
    test_db.record_verification({
        "verification_id": "VERIF-TEST-UR",
        "hypothesis_id": hyp_id,
        "actor": "tester",
        "decision": "confirmed",
        "evidence_ref": "logs/valid_evidence_123.txt",
        "dashboard_session_id": "SESS-1",
    })
    test_db.update_hypothesis_state(hyp_id, "Confirmed", evidence_ref="logs/valid_evidence_123.txt")

    with pytest.raises(sqlite3.DatabaseError, match="Cannot move hypothesis to Under Review without first being in New state"):
        test_db.update_hypothesis_state(hyp_id, "Under Review")
