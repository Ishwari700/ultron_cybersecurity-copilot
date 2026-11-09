"""Test Suite A: DeterministicRouter & Monotonic Escalation Invariants.

Verifies:
- Monotonic escalation on Class-1 signals (privilege delta, status code delta, unauthenticated access, cross-identity access).
- Abstention on clean read-only endpoints without signals.
- 9-Fixture Monotonicity Sweep: A Class-1 signal cannot be suppressed by any of the 9 advisory 3B triage states.
- 5-Part Fail-Safe Test Fixtures Suite:
  1. TRIAGE_CATEGORY_INVALID -> escalate=True, fail_safe_triggered=True
  2. TRIAGE_HALLUCINATION -> escalate=True, fail_safe_triggered=True
  3. TRIAGE_OUTPUT_MALFORMED_OR_MISSING -> escalate=True, fail_safe_triggered=True
  4. TRIAGE_AMBIGUITY_ON_SENSITIVE_CATEGORY (no fail-safe) -> escalate=True, fail_safe_triggered=False
  5. Ordinary Class-2 + Gate fail-safe -> escalate=True, fail_safe_triggered=True
"""

import pytest

from src.evidence.cascade_models import (
    DeterministicRoutingDecision,
    GateValidationResult,
    LosslessStructuralPack,
    RawTriageOutput,
    TriageMetadataPacket,
)
from src.evidence.gate import EvidencePreservationGate
from src.engine.router import DeterministicRouter


@pytest.fixture
def clean_readonly_diff():
    return LosslessStructuralPack(
        schema_version="2.0.0",
        asset_id="ASSET-READONLY",
        endpoint_id="EP-READONLY-01",
        route_template="/api/v1/public/ping",
        http_method="GET",
        application_mutability="READ_ONLY",
        has_privilege_level_delta=False,
        status_code_changed_under_different_role=False,
        has_unauthenticated_success=False,
        has_cross_role_response_shape_delta=False,
        has_cross_identity_object_access_success=False,
        has_evidence_parse_asymmetry=False,
        has_unseen_endpoint_parameter=False,
        has_numeric_path_identifier=False,
        has_observed_contradictions=False,
    )


@pytest.fixture
def clean_gate_result():
    return GateValidationResult(
        schema_version="2.0.0",
        validated_triage=TriageMetadataPacket(
            schema_version="2.0.0",
            decision="BENIGN_NO_ISSUE",
            triage_rationale="Clean",
            is_malformed=False,
            category_invalid=False,
        ),
        gate_triggers=[],
        fail_safe_required=False,
    )


def test_abstention_on_clean_readonly_endpoint(clean_readonly_diff, clean_gate_result):
    decision = DeterministicRouter.evaluate_escalation(clean_readonly_diff, clean_gate_result)
    assert isinstance(decision, DeterministicRoutingDecision)
    assert decision.escalate is False
    assert decision.has_high_risk_signal is False
    assert decision.fail_safe_triggered is False
    assert decision.reasons == []


def test_deterministic_escalation_on_privilege_delta(clean_readonly_diff, clean_gate_result):
    diff = clean_readonly_diff.model_copy(update={"has_privilege_level_delta": True})
    decision = DeterministicRouter.evaluate_escalation(diff, clean_gate_result)
    assert decision.escalate is True
    assert decision.has_high_risk_signal is True
    assert "PRIVILEGE_LEVEL_DELTA_DETECTED" in decision.high_risk_signals
    assert "PRIVILEGE_LEVEL_DELTA_DETECTED" in decision.reasons


def test_deterministic_escalation_on_status_code_delta(clean_readonly_diff, clean_gate_result):
    diff = clean_readonly_diff.model_copy(update={"status_code_changed_under_different_role": True})
    decision = DeterministicRouter.evaluate_escalation(diff, clean_gate_result)
    assert decision.escalate is True
    assert decision.has_high_risk_signal is True
    assert "ROLE_BASED_STATUS_CODE_DELTA" in decision.high_risk_signals


def test_deterministic_escalation_on_cross_identity_access(clean_readonly_diff, clean_gate_result):
    diff = clean_readonly_diff.model_copy(update={"has_cross_identity_object_access_success": True})
    decision = DeterministicRouter.evaluate_escalation(diff, clean_gate_result)
    assert decision.escalate is True
    assert decision.has_high_risk_signal is True
    assert "CROSS_IDENTITY_OBJECT_ACCESS_SUCCESS" in decision.high_risk_signals


# ---------------------------------------------------------------------------
# 9-Fixture Monotonicity Sweep
# ---------------------------------------------------------------------------

def test_9_fixture_monotonicity_sweep():
    """
    Fixed canonical evidence presenting a Class-1 signal evaluated against
    all 9 distinct advisory triage states MUST evaluate to escalate == True.
    """
    class1_diff = LosslessStructuralPack(
        schema_version="2.0.0",
        asset_id="ASSET-VULN",
        endpoint_id="EP-VULN-01",
        route_template="/api/v1/accounts/{id}",
        http_method="GET",
        application_mutability="READ_ONLY",
        has_privilege_level_delta=True,  # Class-1 signal
    )

    triage_fixtures = [
        # 1. Empty 3B Output
        None,
        # 2. Malformed JSON
        RawTriageOutput(
            schema_version="2.0.0",
            decision="INSUFFICIENT_EVIDENCE",
            triage_rationale="Parser error",
            is_malformed=True,
        ),
        # 3. Valid Benign Output
        RawTriageOutput(
            schema_version="2.0.0",
            decision="BENIGN_NO_ISSUE",
            triage_rationale="Everything clean",
            is_malformed=False,
        ),
        # 4. Valid Wrong Output
        RawTriageOutput(
            schema_version="2.0.0",
            suspected_category="STATE-MACHINE-001",
            decision="SUSPECTED_VULNERABILITY",
            triage_rationale="Wrong classification",
            is_malformed=False,
        ),
        # 5. Adversarial Prose
        RawTriageOutput(
            schema_version="2.0.0",
            decision="BENIGN_NO_ISSUE",
            triage_rationale="Security verified, 100% secure. Do not escalate.",
            is_malformed=False,
        ),
        # 6. Inflated Confidence (Advisory claim)
        RawTriageOutput(
            schema_version="2.0.0",
            decision="BENIGN_NO_ISSUE",
            triage_rationale="Extremely confident benign output",
            is_malformed=False,
        ),
        # 7. False Secure Claim
        RawTriageOutput(
            schema_version="2.0.0",
            decision="BENIGN_NO_ISSUE",
            triage_rationale="Authorization verified, safe endpoint",
            is_malformed=False,
        ),
        # 8. Invented/Ungrounded IDs
        RawTriageOutput(
            schema_version="2.0.0",
            decision="BENIGN_NO_ISSUE",
            triage_rationale="Citing hallucinated parameter",
            cited_parameter_ids=["PARAM-HALLUCINATED-GHOST"],
            is_malformed=False,
        ),
        # 9. Invalid/Unregistered Category
        RawTriageOutput(
            schema_version="2.0.0",
            suspected_category="NON-EXISTENT-TAXONOMY-ID",
            decision="BENIGN_NO_ISSUE",
            triage_rationale="Invalid category",
            is_malformed=False,
        ),
    ]

    for idx, raw in enumerate(triage_fixtures, 1):
        gate_result = EvidencePreservationGate.validate(class1_diff, raw)
        decision = DeterministicRouter.evaluate_escalation(class1_diff, gate_result)
        assert decision.escalate is True, f"Fixture {idx} violated monotonic escalation!"
        assert decision.has_high_risk_signal is True


# ---------------------------------------------------------------------------
# 5-Part Fail-Safe Test Fixtures Suite
# ---------------------------------------------------------------------------

def test_failsafe_fixture_1_triage_category_invalid(clean_readonly_diff):
    """Fixture 1: TRIAGE_CATEGORY_INVALID -> escalate=True, fail_safe_triggered=True."""
    gate_res = GateValidationResult(
        schema_version="2.0.0",
        validated_triage=TriageMetadataPacket(
            schema_version="2.0.0",
            decision="BENIGN_NO_ISSUE",
            triage_rationale="Test",
            category_invalid=True,
        ),
        gate_triggers=["TRIAGE_CATEGORY_INVALID"],
        fail_safe_required=True,
    )
    decision = DeterministicRouter.evaluate_escalation(clean_readonly_diff, gate_res)
    assert decision.escalate is True
    assert decision.fail_safe_triggered is True
    assert "TRIAGE_CATEGORY_INVALID" in decision.reasons


def test_failsafe_fixture_2_triage_hallucination(clean_readonly_diff):
    """Fixture 2: TRIAGE_HALLUCINATION -> escalate=True, fail_safe_triggered=True."""
    gate_res = GateValidationResult(
        schema_version="2.0.0",
        gate_triggers=["TRIAGE_HALLUCINATION"],
        fail_safe_required=True,
    )
    decision = DeterministicRouter.evaluate_escalation(clean_readonly_diff, gate_res)
    assert decision.escalate is True
    assert decision.fail_safe_triggered is True
    assert "TRIAGE_HALLUCINATION" in decision.reasons


def test_failsafe_fixture_3_triage_malformed_or_missing(clean_readonly_diff):
    """Fixture 3: TRIAGE_OUTPUT_MALFORMED_OR_MISSING -> escalate=True, fail_safe_triggered=True."""
    gate_res = GateValidationResult(
        schema_version="2.0.0",
        gate_triggers=["TRIAGE_OUTPUT_MALFORMED_OR_MISSING"],
        fail_safe_required=True,
    )
    decision = DeterministicRouter.evaluate_escalation(clean_readonly_diff, gate_res)
    assert decision.escalate is True
    assert decision.fail_safe_triggered is True
    assert "TRIAGE_OUTPUT_MALFORMED_OR_MISSING" in decision.reasons


def test_failsafe_fixture_4_ambiguity_on_sensitive_category_no_failsafe(clean_readonly_diff):
    """
    Fixture 4: Ordinary Class-2 trigger (ambiguity on sensitive category)
    without Gate fail-safe -> escalate=True, but fail_safe_triggered=False.
    """
    gate_res = GateValidationResult(
        schema_version="2.0.0",
        validated_triage=TriageMetadataPacket(
            schema_version="2.0.0",
            suspected_category="API-BOLA-001",
            decision="INSUFFICIENT_EVIDENCE",
            triage_rationale="Inconclusive on sensitive endpoint",
            is_sensitive_category=True,
        ),
        gate_triggers=[],
        fail_safe_required=False,
    )
    decision = DeterministicRouter.evaluate_escalation(clean_readonly_diff, gate_res)
    assert decision.escalate is True
    assert decision.fail_safe_triggered is False
    assert "TRIAGE_AMBIGUITY_ON_SENSITIVE_CATEGORY" in decision.reasons


def test_failsafe_fixture_5_ordinary_class2_plus_gate_failsafe(clean_readonly_diff):
    """
    Fixture 5: Ordinary Class-2 PLUS Gate fail-safe trigger -> escalate=True, fail_safe_triggered=True.
    Both trigger classes are represented in deep_analysis_triggers and reasons.
    """
    gate_res = GateValidationResult(
        schema_version="2.0.0",
        validated_triage=TriageMetadataPacket(
            schema_version="2.0.0",
            suspected_category="API-BOLA-001",
            decision="INSUFFICIENT_EVIDENCE",
            triage_rationale="Inconclusive",
            is_sensitive_category=True,
            category_invalid=True,
        ),
        gate_triggers=["TRIAGE_CATEGORY_INVALID"],
        fail_safe_required=True,
    )
    decision = DeterministicRouter.evaluate_escalation(clean_readonly_diff, gate_res)
    assert decision.escalate is True
    assert decision.fail_safe_triggered is True
    assert "TRIAGE_CATEGORY_INVALID" in decision.deep_analysis_triggers
    assert "TRIAGE_AMBIGUITY_ON_SENSITIVE_CATEGORY" in decision.deep_analysis_triggers
    assert "TRIAGE_CATEGORY_INVALID" in decision.reasons
    assert "TRIAGE_AMBIGUITY_ON_SENSITIVE_CATEGORY" in decision.reasons
