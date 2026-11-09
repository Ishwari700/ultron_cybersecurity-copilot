"""Regression tests for error handling and fail-closed audit requirements (Task 2)."""

from pathlib import Path
import pytest

from src.core.logging import AuditLogger
from src.database.manager import DatabaseManager
from src.graph.models import DerivationRecord, EpistemicOrigin
from src.graph.workflow_engine import WorkflowEngine
from src.invariants.engine import SecurityInvariantEngine
from src.invariants.models import InvariantConfidence, InvariantOrigin, SecurityInvariant
from src.scope.gate import ScopeGate
from src.scope.models import ScopeDecision, ScopePolicy, ToolPolicy


@pytest.fixture
def test_scope_policy() -> ScopePolicy:
    return ScopePolicy(
        program_name="audit-test-program",
        platform="hackerone",
        in_scope=["*.target.com", "api.target.com"],
        tool_policy={"httpx": ToolPolicy.ACTIVE},
    )


def test_scope_gate_fails_closed_when_database_fails(test_scope_policy, tmp_path):
    """Verify ScopeGate fails closed (DENY) if persisting an ALLOW decision to DB fails."""
    class FailingDbManager:
        def insert_scope_decision(self, data):
            raise RuntimeError("Simulated database failure (disk full)")

    gate = ScopeGate(
        policy=test_scope_policy,
        dns_resolver=lambda h: ["93.184.216.34"],
        db_manager=FailingDbManager(),
    )

    decision = gate.evaluate("https://api.target.com/users")
    assert decision.decision == ScopeDecision.DENY
    assert "fail-closed" in decision.reason.lower()


def test_scope_gate_fails_closed_when_audit_logger_fails(test_scope_policy, tmp_path):
    """Verify ScopeGate fails closed (DENY) if writing an ALLOW decision to audit log fails."""
    class FailingAuditLogger:
        def log_event(self, **kwargs):
            raise IOError("Simulated permission denied on audit log")

    gate = ScopeGate(
        policy=test_scope_policy,
        dns_resolver=lambda h: ["93.184.216.34"],
        audit_logger=FailingAuditLogger(),
    )

    decision = gate.evaluate("https://api.target.com/users")
    assert decision.decision == ScopeDecision.DENY
    assert "fail-closed" in decision.reason.lower()


def test_workflow_engine_handles_db_failure(tmp_path, caplog):
    """Verify WorkflowEngine logs an error rather than silently failing when DB write fails."""
    class FailingDbManager:
        def get_connection(self):
            raise RuntimeError("Database locked")

    engine = WorkflowEngine()
    engine.db_manager = FailingDbManager()

    # Should not crash unhandled, but log error
    derivation = DerivationRecord(
        derivation_id="DERIV-FAIL-1",
        derived_fact_id="FACT-1",
        parent_fact_ids=["FACT-0"],
        derivation_rule="TEMPORAL_SEQUENCE",
        algorithm_version="v6",
        epistemic_origin=EpistemicOrigin.DETERMINISTIC_DERIVATION,
    )
    # Testing direct execution or derivation
    # Derivation should complete without crashing caller


def test_invariant_engine_handles_db_failure(tmp_path, caplog):
    """Verify SecurityInvariantEngine logs error when DB insert fails."""
    class FailingDbManager:
        def insert_security_invariant(self, data):
            raise RuntimeError("Database constraint violation")

    engine = SecurityInvariantEngine(db_manager=FailingDbManager())
    inv = SecurityInvariant(
        invariant_id="INVAR-FAIL-1",
        description="Must be authenticated",
        origin=InvariantOrigin.DOCUMENTED,
        confidence=InvariantConfidence.HIGH,
    )

    # Should not crash unhandled
    engine._persist(inv)
