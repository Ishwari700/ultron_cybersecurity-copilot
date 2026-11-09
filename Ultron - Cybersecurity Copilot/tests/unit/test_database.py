"""Unit tests for the unified evidence.db schema, triggers, and DatabaseManager."""

import sqlite3
import pytest
from pathlib import Path
from src.database.manager import DatabaseManager


@pytest.fixture
def db(tmp_path: Path) -> DatabaseManager:
    """Provide an initialized DatabaseManager instance on a temporary SQLite database."""
    db_file = tmp_path / "test_evidence.db"
    manager = DatabaseManager(db_path=db_file)
    manager.initialize_schema()
    return manager


def test_schema_initialization(db: DatabaseManager):
    """Verify all authoritative tables and triggers are created."""
    with db.get_connection() as conn:
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"
        )
        tables = {row[0] for row in cursor.fetchall()}
        required = {
            "scope_decisions",
            "assets",
            "asset_state_history",
            "parameters",
            "identities",
            "evidence_items",
            "derivations",
            "security_invariants",
            "hypotheses",
            "verifications",
            "evidence_fts",
        }
        assert required.issubset(tables)


def test_scope_decision_lifecycle(db: DatabaseManager):
    """Verify scope decision insert and retrieval."""
    decision = {
        "scope_decision_id": "SCOPE-001",
        "decision": "ALLOW",
        "requested_url": "https://api.target.com/v1/users",
        "canonical_host": "api.target.com",
        "resolved_addresses": ["192.0.2.1"],
        "matched_rule": "*.target.com",
        "out_of_scope_rule": None,
        "tool_policy": "low_impact_active",
        "reason": "Host matches in-scope rule and resolves to public IP",
        "scope_policy_version": "v6",
    }
    db.insert_scope_decision(decision)
    retrieved = db.get_scope_decision("SCOPE-001")
    assert retrieved is not None
    assert retrieved["decision"] == "ALLOW"
    assert retrieved["resolved_addresses"] == ["192.0.2.1"]


def test_asset_and_state_history(db: DatabaseManager):
    """Verify asset insertion and append-only state history updates."""
    # Insert prerequisite scope decision
    db.insert_scope_decision({
        "scope_decision_id": "SCOPE-001",
        "decision": "ALLOW",
        "requested_url": "https://api.target.com/v1/users",
        "canonical_host": "api.target.com",
        "resolved_addresses": ["192.0.2.1"],
        "tool_policy": "low_impact_active",
        "scope_policy_version": "v6",
    })

    asset = {
        "asset_id": "ASSET-101",
        "method": "GET",
        "host": "api.target.com",
        "raw_path": "/v1/users/123",
        "normalized_path": "/v1/users/{id}",
        "normalization_confidence": 0.95,
        "application_mutability": "READ_ONLY",
        "liveness": "SHADOW_ACTIVE",
        "scope_decision_id": "SCOPE-001",
    }
    db.insert_asset(asset)

    retrieved = db.get_asset("ASSET-101")
    assert retrieved is not None
    assert retrieved["application_mutability"] == "READ_ONLY"

    # Transition liveness
    db.update_asset_state("ASSET-101", "liveness", "LIVE_DOCUMENTED")
    updated = db.get_asset("ASSET-101")
    assert updated["liveness"] == "LIVE_DOCUMENTED"

    # Verify history recorded
    with db.get_connection() as conn:
        cursor = conn.execute("SELECT * FROM asset_state_history WHERE asset_id = 'ASSET-101'")
        history = [dict(r) for r in cursor.fetchall()]
        assert len(history) == 1
        assert history[0]["field"] == "liveness"
        assert history[0]["old_value"] == "SHADOW_ACTIVE"
        assert history[0]["new_value"] == "LIVE_DOCUMENTED"


def test_parameters_and_cascade(db: DatabaseManager):
    """Verify parameter insertion and cascade deletion on asset removal."""
    db.insert_asset({
        "asset_id": "ASSET-201",
        "method": "POST",
        "host": "api.target.com",
        "raw_path": "/v1/orders",
        "normalized_path": "/v1/orders",
    })

    db.insert_parameter({
        "param_id": "PARAM-001",
        "asset_id": "ASSET-201",
        "param_name": "order_id",
        "location": "body",
        "content_type": "application/json",
        "param_type": "uuid",
        "is_server_volatile": 0,
    })

    params = db.get_parameters_for_asset("ASSET-201")
    assert len(params) == 1
    assert params[0]["param_name"] == "order_id"

    # Test cascade delete
    with db.get_connection() as conn:
        conn.execute("DELETE FROM assets WHERE asset_id = 'ASSET-201'")
        conn.commit()

    params_after = db.get_parameters_for_asset("ASSET-201")
    assert len(params_after) == 0


def test_fts5_evidence_search(db: DatabaseManager):
    """Verify FTS5 triggers index evidence items and enable keyword search."""
    item = {
        "fact_id": "FACT-001",
        "certainty": "OBSERVED",
        "statement": "Response contained Authorization token bearer in header",
        "source_tool": "burp",
        "trust": "UNTRUSTED",
    }
    db.insert_evidence_item(item)

    results = db.query_fts("Authorization")
    assert len(results) == 1
    assert results[0]["fact_id"] == "FACT-001"

    # Search non-matching term
    assert len(db.query_fts("NonExistentTermXYZ")) == 0


def test_security_invariants_origin(db: DatabaseManager):
    """Verify security invariants enforce epistemic origin types."""
    db.insert_security_invariant({
        "invariant_id": "INV-01",
        "description": "Only user A can view user A invoices",
        "origin": "MODEL_PROPOSED",
        "derived_from": ["FACT-001"],
        "confidence": "MEDIUM",
    })

    inv = db.get_security_invariant("INV-01")
    assert inv is not None
    assert inv["origin"] == "MODEL_PROPOSED"
    assert inv["derived_from"] == ["FACT-001"]

    # Test illegal origin check constraint
    with pytest.raises(sqlite3.IntegrityError):
        with db.get_connection() as conn:
            conn.execute(
                "INSERT INTO security_invariants (invariant_id, description, origin) VALUES (?, ?, ?)",
                ("INV-INVALID", "test", "UNVALIDATED_GUESS"),
            )


def test_hypothesis_triggers_and_verification_workflow(db: DatabaseManager):
    """Verify the human verification state machine and hard database triggers."""
    db.insert_asset({
        "asset_id": "ASSET-BOLA",
        "method": "GET",
        "host": "api.target.com",
        "raw_path": "/invoices/100",
        "normalized_path": "/invoices/{id}",
    })

    hyp_id = db.insert_hypothesis({
        "asset_id": "ASSET-BOLA",
        "category": "API-BOLA-001",
        "decision": "HYPOTHESIS",
        "evidence_state": "PARTIAL",
        "reasoning_summary": "Cross tenant invoice access observed without auth validation",
        "state": "New",
    })
    assert hyp_id > 0

    # Transition to Under Review
    db.update_hypothesis_state(hyp_id, "Under Review")
    hyp = db.get_hypothesis(hyp_id)
    assert hyp["state"] == "Under Review"

    # TRIGGER 2: Cannot move to Confirmed with evidence_ref but without a matching confirmed verifications record
    with pytest.raises(sqlite3.DatabaseError, match="Cannot move hypothesis to Confirmed without a matching confirmed verifications record"):
        db.update_hypothesis_state(hyp_id, "Confirmed", evidence_ref="logs/repro_01.txt")

    # Now add human verification record
    db.record_verification({
        "verification_id": "VERIF-001",
        "hypothesis_id": hyp_id,
        "actor": "security_researcher_1",
        "decision": "confirmed",
        "evidence_ref": "logs/repro_01.txt",
        "dashboard_session_id": "SESS-XYZ",
        "notes": "Confirmed BOLA via cross-account token replay",
    })

    # TRIGGER 1: Even with verifications record, cannot move to Confirmed without evidence_ref >= 5 chars
    with pytest.raises(sqlite3.DatabaseError, match="Cannot move hypothesis to Confirmed without an attached evidence_ref"):
        db.update_hypothesis_state(hyp_id, "Confirmed", evidence_ref="")

    # Now transition to Confirmed should succeed with valid evidence_ref!
    db.update_hypothesis_state(hyp_id, "Confirmed", evidence_ref="logs/repro_01.txt")
    confirmed_hyp = db.get_hypothesis(hyp_id)
    assert confirmed_hyp["state"] == "Confirmed"

    # TRIGGER 3: Cannot move to Reported unless previously Confirmed
    # Create another hypothesis that is New and try moving to Reported
    hyp_id2 = db.insert_hypothesis({
        "asset_id": "ASSET-BOLA",
        "category": "API-BOLA-001",
        "decision": "HYPOTHESIS",
        "evidence_state": "PARTIAL",
        "state": "New",
    })
    with pytest.raises(sqlite3.DatabaseError, match="Cannot move hypothesis to Reported without first being in Confirmed state"):
        db.update_hypothesis_state(hyp_id2, "Reported")

    # But moving hyp_id (which is Confirmed) to Reported should succeed!
    db.update_hypothesis_state(hyp_id, "Reported")
    reported_hyp = db.get_hypothesis(hyp_id)
    assert reported_hyp["state"] == "Reported"


def test_fts5_update_and_delete_synchronization(db: DatabaseManager):
    """
    Verify FTS5 external content table synchronization on INSERT, UPDATE, and DELETE.
    Enforces trg_evidence_ai, trg_evidence_au, and trg_evidence_ad integrity.
    """
    # 1. Insert evidence with statement 'apple'
    db.insert_evidence_item({
        "fact_id": "FACT-FRUIT-01",
        "certainty": "OBSERVED",
        "statement": "Observed apple pie vulnerability in billing",
        "source_tool": "scanner",
    })

    # 2. Confirm FTS finds 'apple'
    hits_apple = db.query_fts("apple")
    assert len(hits_apple) == 1
    assert hits_apple[0]["fact_id"] == "FACT-FRUIT-01"

    # 3. Update statement to 'banana'
    with db.get_connection() as conn:
        conn.execute(
            "UPDATE evidence_items SET statement = ? WHERE fact_id = ?",
            ("Observed banana split vulnerability in billing", "FACT-FRUIT-01"),
        )
        conn.commit()

    # 4. Confirm FTS finds 'banana'
    hits_banana = db.query_fts("banana")
    assert len(hits_banana) == 1
    assert hits_banana[0]["fact_id"] == "FACT-FRUIT-01"

    # 5. Confirm old 'apple' entry no longer matches
    hits_apple_after = db.query_fts("apple")
    assert len(hits_apple_after) == 0

    # 6. Verify delete still works
    with db.get_connection() as conn:
        conn.execute("DELETE FROM evidence_items WHERE fact_id = ?", ("FACT-FRUIT-01",))
        conn.commit()

    hits_banana_after_delete = db.query_fts("banana")
    assert len(hits_banana_after_delete) == 0
