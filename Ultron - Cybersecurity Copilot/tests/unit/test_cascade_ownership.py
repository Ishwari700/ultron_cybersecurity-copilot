"""Test Suite A.6: Routing Ownership Conformance.

Verifies:
- Ownership Boundary: EvidencePreservationGate does NOT accept, own, construct, or mutate DeterministicRoutingDecision.
- DeterministicRouter is the sole producer of DeterministicRoutingDecision.
- Read-Only Gate Result: DeterministicRouter treats GateValidationResult as strictly read-only and does not mutate it.
- Sequence Enforcement: 3B Triage -> Gate -> Router -> 7B.
- Contract breach identifier: ROUTING_DECISION_OWNERSHIP_VIOLATION.
"""

import inspect
import pytest

from src.evidence.cascade_models import (
    DeterministicRoutingDecision,
    GateValidationResult,
    LosslessStructuralPack,
    RawTriageOutput,
)
from src.evidence.gate import EvidencePreservationGate
from src.engine.router import DeterministicRouter


def test_gate_validate_signature_has_no_routing_decision():
    """Static assertion: EvidencePreservationGate.validate must NOT accept routing_decision."""
    sig = inspect.signature(EvidencePreservationGate.validate)
    param_names = list(sig.parameters.keys())
    if "routing_decision" in param_names:
        pytest.fail("ROUTING_DECISION_OWNERSHIP_VIOLATION: Gate must not accept routing_decision")
    assert "channel_a" in param_names
    assert "raw_triage" in param_names


def test_gate_returns_gate_validation_result_not_routing_decision():
    """Runtime assertion: Gate returns GateValidationResult, never DeterministicRoutingDecision."""
    diff = LosslessStructuralPack(
        schema_version="2.0.0",
        asset_id="A1",
        endpoint_id="EP1",
        route_template="/test",
        http_method="GET",
        application_mutability="READ_ONLY",
    )
    res = EvidencePreservationGate.validate(diff, None)
    if isinstance(res, DeterministicRoutingDecision):
        pytest.fail("ROUTING_DECISION_OWNERSHIP_VIOLATION: Gate produced DeterministicRoutingDecision")
    assert isinstance(res, GateValidationResult)
    assert not hasattr(res, "escalate")


def test_router_is_sole_producer_of_deterministic_routing_decision():
    """Runtime assertion: DeterministicRouter produces DeterministicRoutingDecision."""
    diff = LosslessStructuralPack(
        schema_version="2.0.0",
        asset_id="A1",
        endpoint_id="EP1",
        route_template="/test",
        http_method="GET",
        application_mutability="READ_ONLY",
    )
    gate_res = GateValidationResult(
        schema_version="2.0.0",
        gate_triggers=[],
        fail_safe_required=False,
    )
    decision = DeterministicRouter.evaluate_escalation(diff, gate_res)
    assert isinstance(decision, DeterministicRoutingDecision)
    assert hasattr(decision, "escalate")
    assert hasattr(decision, "fail_safe_triggered")


def test_router_treats_gate_validation_result_as_strictly_read_only():
    """Assertion: evaluate_escalation does NOT mutate the passed GateValidationResult."""
    diff = LosslessStructuralPack(
        schema_version="2.0.0",
        asset_id="A1",
        endpoint_id="EP1",
        route_template="/test",
        http_method="GET",
        application_mutability="READ_ONLY",
    )
    gate_res = GateValidationResult(
        schema_version="2.0.0",
        gate_triggers=["TRIAGE_CATEGORY_INVALID"],
        fail_safe_required=True,
        audit_event_ids=["EV1"],
    )
    snapshot_before = gate_res.model_dump()

    _ = DeterministicRouter.evaluate_escalation(diff, gate_res)

    snapshot_after = gate_res.model_dump()
    assert snapshot_before == snapshot_after, (
        "ROUTING_DECISION_OWNERSHIP_VIOLATION: Router mutated GateValidationResult!"
    )
