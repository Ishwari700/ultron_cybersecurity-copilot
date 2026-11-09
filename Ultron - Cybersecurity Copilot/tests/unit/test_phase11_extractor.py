"""Unit tests for Phase 11 Decision Extractor & Failure Taxonomy.

Covers the 15-case extraction test matrix (Section 5) and failure layer taxonomy (Section 7).
"""

import pytest
from src.eval.extractor import (
    ExtractionResult,
    FailureLayer,
    classify_earliest_failure,
    extract_decision,
    extract_decision_from_hypothesis,
    normalize_hypothesis,
)


def test_01_direct_vulnerability_exists_true():
    """1. direct VulnerabilityExists=True -> candidate vulnerable"""
    payload = {"VulnerabilityExists": True}
    res = extract_decision(payload)
    assert res.decision == "HYPOTHESIS"
    assert res.vulnerability_exists is True
    assert res.vulnerability_type is None
    assert res.failure_reason is None
    assert res.is_valid is True


def test_02_nested_reasoning_hypothesis_vulnerability_exists_true():
    """2. nested ReasoningHypothesis + VulnerabilityExists=True"""
    payload = {
        "ReasoningHypothesis": {
            "VulnerabilityExists": True,
            "Justification": "Critical IDOR detected in invoices endpoint",
        }
    }
    res = extract_decision(payload)
    assert res.decision == "HYPOTHESIS"
    assert res.vulnerability_exists is True
    assert res.failure_reason is None
    assert res.is_valid is True


def test_03_nested_type():
    """3. nested Type preserved as evidence, does not override frozen contract"""
    payload = {
        "ReasoningHypothesis": {
            "Type": "Vulnerability",
            "Description": "Potentially missing auth",
        }
    }
    res = extract_decision(payload)
    # Preserved as extracted evidence, but without explicit VulnerabilityExists or decision flag,
    # it is unresolved/abstention (INSUFFICIENT_EVIDENCE), never silently benign
    assert res.decision == "INSUFFICIENT_EVIDENCE"
    assert res.vulnerability_type == "Vulnerability"
    assert "UNRESOLVED_DECISION" in (res.failure_reason or "")
    assert res.is_valid is False


def test_04_nested_vulnerability_type():
    """4. nested VulnerabilityType preserved as evidence, not blindly classified as VULNERABLE"""
    payload = {
        "ReasoningHypothesis": {
            "VulnerabilityType": "Authentication Bypass",
            "Impact": "Account takeover",
        }
    }
    res = extract_decision(payload)
    assert res.decision == "INSUFFICIENT_EVIDENCE"
    assert res.vulnerability_type == "Authentication Bypass"
    assert "UNRESOLVED_DECISION" in (res.failure_reason or "")
    assert res.is_valid is False


def test_05_explicit_false():
    """5. explicit false -> NO_RELEVANT_FUNCTIONALITY"""
    payload = {"VulnerabilityExists": False}
    res = extract_decision(payload)
    assert res.decision == "NO_RELEVANT_FUNCTIONALITY"
    assert res.vulnerability_exists is False
    assert res.failure_reason is None
    assert res.is_valid is True


def test_06_direct_finding_object():
    """6. direct finding object if supported"""
    payload = {
        "finding": {
            "decision": "HYPOTHESIS",
            "VulnerabilityExists": True,
        }
    }
    res = extract_decision(payload)
    assert res.decision == "HYPOTHESIS"
    assert res.vulnerability_exists is True
    assert res.is_valid is True


def test_07_malformed_object():
    """7. malformed object -> normalization failure, never silently benign"""
    payload = ["not", "a", "dict"]
    res = extract_decision(payload)
    assert res.decision == "INSUFFICIENT_EVIDENCE"
    assert res.is_valid is False
    assert "MALFORMED_STRUCTURE" in (res.failure_reason or "")


def test_08_empty_object():
    """8. empty object -> unresolved/invalid, never silently benign"""
    payload = {}
    res = extract_decision(payload)
    assert res.decision == "INSUFFICIENT_EVIDENCE"
    assert res.is_valid is False
    assert "EMPTY_PAYLOAD" in (res.failure_reason or "")


def test_09_none():
    """9. None -> unresolved/invalid, never silently benign"""
    res = extract_decision(None)
    assert res.decision == "INSUFFICIENT_EVIDENCE"
    assert res.is_valid is False
    assert "NULL_PAYLOAD" in (res.failure_reason or "")


def test_10_unexpected_additional_fields():
    """10. unexpected additional fields handled gracefully without failure"""
    payload = {
        "ReasoningHypothesis": {
            "VulnerabilityExists": True,
            "extra_field_foo": 12345,
            "unexpected_nested": {"a": [1, 2, 3]},
            "Justification": "Valid reasoning with extra metadata",
        }
    }
    res = extract_decision(payload)
    assert res.decision == "HYPOTHESIS"
    assert res.vulnerability_exists is True
    assert res.is_valid is True
    assert res.failure_reason is None


def test_11_conflicting_true_plus_benign_decision():
    """11. conflicting true + benign decision -> fail-safe uncertain"""
    payload = {
        "ReasoningHypothesis": {
            "VulnerabilityExists": True,
            "decision": "BENIGN_NO_ISSUE",
        }
    }
    res = extract_decision(payload)
    assert res.decision == "INSUFFICIENT_EVIDENCE"
    assert res.is_valid is False
    assert "CONFLICTING_FIELDS" in (res.failure_reason or "")


def test_12_conflicting_false_plus_vulnerability_type():
    """12. conflicting false + vulnerability type -> fail-safe uncertain"""
    payload = {
        "ReasoningHypothesis": {
            "VulnerabilityExists": False,
            "VulnerabilityType": "Authentication Bypass",
        }
    }
    res = extract_decision(payload)
    assert res.decision == "INSUFFICIENT_EVIDENCE"
    assert res.is_valid is False
    assert "CONFLICTING_FIELDS" in (res.failure_reason or "")


def test_13_invalid_types_for_boolean_field():
    """13. invalid types for boolean field -> failure, never silently benign"""
    payload = {
        "ReasoningHypothesis": {
            "VulnerabilityExists": "unparseable_random_text",
        }
    }
    res = extract_decision(payload)
    assert res.decision == "INSUFFICIENT_EVIDENCE"
    assert res.is_valid is False
    assert "INVALID_FIELD_TYPE" in (res.failure_reason or "")


def test_14_case_variants_actually_observed():
    """14. case variants actually observed (vulnerability_exists, true string, etc.)"""
    payload1 = {"vulnerability_exists": True}
    res1 = extract_decision(payload1)
    assert res1.decision == "HYPOTHESIS"
    assert res1.vulnerability_exists is True

    payload2 = {"ReasoningHypothesis": {"VulnerabilityExists": "true"}}
    res2 = extract_decision(payload2)
    assert res2.decision == "HYPOTHESIS"
    assert res2.vulnerability_exists is True

    payload3 = {"ReasoningHypothesis": {"vulnerabilityExists": False}}
    res3 = extract_decision(payload3)
    assert res3.decision == "NO_RELEVANT_FUNCTIONALITY"
    assert res3.vulnerability_exists is False


def test_15_repeated_deterministic_extraction():
    """15. repeated deterministic extraction of identical payload yields identical output"""
    payload = {
        "ReasoningHypothesis": {
            "VulnerabilityExists": True,
            "VulnerabilityType": "BOLA/IDOR",
            "Reason": "Cross-identity access succeeded",
        }
    }
    results = [extract_decision(payload) for _ in range(50)]
    for r in results:
        assert r.decision == "HYPOTHESIS"
        assert r.vulnerability_exists is True
        assert r.vulnerability_type == "BOLA/IDOR"
        assert r.is_valid is True
        assert r == results[0]


def test_audited_example_hard_stop_condition():
    """
    HARD STOP AUDIT CHECK:
    {'ReasoningHypothesis': {'VulnerabilityExists': True, ...}} MUST NOT become NO_RELEVANT_FUNCTIONALITY.
    """
    payload = {
        "ReasoningHypothesis": {
            "VulnerabilityExists": True,
            "Reason": "The endpoint /api/v1/docs/{id}/export allows unauthenticated access...",
        }
    }
    dec_str = extract_decision_from_hypothesis(payload)
    assert dec_str == "HYPOTHESIS", f"HARD STOP VIOLATION: Audited positive became '{dec_str}' instead of 'HYPOTHESIS'!"


def test_failure_layer_taxonomy_chronology():
    """Verify 9-class failure taxonomy ordering and classification."""
    # 1. Model output failure
    p1, s1 = classify_earliest_failure(
        raw_output_present=False,
        raw_error="Timeout after 30s",
        json_parse_status="NONE",
        extraction_result=None,
        grounding_valid=None,
        is_breakout=False,
        escalated=None,
        ground_truth_vulnerable=True,
        called_7b=False,
        final_decision="INSUFFICIENT_EVIDENCE",
        useful=False,
    )
    assert p1 == FailureLayer.MODEL_OUTPUT_FAILURE

    # 2. JSON parse failure
    p2, s2 = classify_earliest_failure(
        raw_output_present=True,
        raw_error="JSONDecodeError",
        json_parse_status="FAILURE",
        extraction_result=None,
        grounding_valid=None,
        is_breakout=False,
        escalated=None,
        ground_truth_vulnerable=True,
        called_7b=False,
        final_decision="INSUFFICIENT_EVIDENCE",
        useful=False,
    )
    assert p2 == FailureLayer.JSON_PARSE_FAILURE

    # 3. Normalization failure (empty payload)
    empty_res = extract_decision({})
    p3, s3 = classify_earliest_failure(
        raw_output_present=True,
        raw_error=None,
        json_parse_status="SUCCESS",
        extraction_result=empty_res,
        grounding_valid=None,
        is_breakout=False,
        escalated=None,
        ground_truth_vulnerable=True,
        called_7b=False,
        final_decision="INSUFFICIENT_EVIDENCE",
        useful=False,
    )
    assert p3 == FailureLayer.HYPOTHESIS_NORMALIZATION_FAILURE

    # 4. Decision extraction failure (conflicting fields)
    conflict_res = extract_decision({"VulnerabilityExists": True, "decision": "BENIGN"})
    p4, s4 = classify_earliest_failure(
        raw_output_present=True,
        raw_error=None,
        json_parse_status="SUCCESS",
        extraction_result=conflict_res,
        grounding_valid=None,
        is_breakout=False,
        escalated=None,
        ground_truth_vulnerable=True,
        called_7b=False,
        final_decision="INSUFFICIENT_EVIDENCE",
        useful=False,
    )
    assert p4 == FailureLayer.DECISION_EXTRACTION_FAILURE

    # 5. Routing false negative (vulnerable scenario, 3B triage dropped it)
    p5, s5 = classify_earliest_failure(
        raw_output_present=True,
        raw_error=None,
        json_parse_status="SUCCESS",
        extraction_result=extract_decision({"VulnerabilityExists": False}),
        grounding_valid=True,
        is_breakout=False,
        escalated=False,
        ground_truth_vulnerable=True,
        called_7b=False,
        final_decision="NO_RELEVANT_FUNCTIONALITY",
        useful=False,
    )
    assert p5 == FailureLayer.ROUTING_FALSE_NEGATIVE

    # 6. Grounding failure
    p6, s6 = classify_earliest_failure(
        raw_output_present=True,
        raw_error=None,
        json_parse_status="SUCCESS",
        extraction_result=extract_decision({"VulnerabilityExists": True}),
        grounding_valid=False,
        is_breakout=False,
        escalated=True,
        ground_truth_vulnerable=True,
        called_7b=True,
        final_decision="HYPOTHESIS",
        useful=False,
    )
    assert p6 == FailureLayer.GROUNDING_FAILURE

    # 7. Reasoning incorrect logic (vulnerable target, but 7B reasoned benign)
    p7, s7 = classify_earliest_failure(
        raw_output_present=True,
        raw_error=None,
        json_parse_status="SUCCESS",
        extraction_result=extract_decision({"VulnerabilityExists": False}),
        grounding_valid=True,
        is_breakout=False,
        escalated=True,
        ground_truth_vulnerable=True,
        called_7b=True,
        final_decision="NO_RELEVANT_FUNCTIONALITY",
        useful=False,
    )
    assert p7 == FailureLayer.REASONING_INCORRECT_LOGIC

    # 8. Success case (vulnerable target, 7B reasoned HYPOTHESIS, grounded and useful)
    p8, s8 = classify_earliest_failure(
        raw_output_present=True,
        raw_error=None,
        json_parse_status="SUCCESS",
        extraction_result=extract_decision({"VulnerabilityExists": True}),
        grounding_valid=True,
        is_breakout=False,
        escalated=True,
        ground_truth_vulnerable=True,
        called_7b=True,
        final_decision="HYPOTHESIS",
        useful=True,
    )
    assert p8 is None
    assert len(s8) == 0


def test_18_explicit_insufficient_evidence():
    """Explicit decision=INSUFFICIENT_EVIDENCE maps to NO_RELEVANT_FUNCTIONALITY / EXPLICIT_ABSTENTION."""
    payload = {"decision": "INSUFFICIENT_EVIDENCE"}
    res = extract_decision(payload)
    assert res.decision == "NO_RELEVANT_FUNCTIONALITY"
    assert res.vulnerability_exists is False
    assert res.is_valid is True
    assert "EXPLICIT_ABSTENTION" in (res.failure_reason or "")


def test_19_explicit_benign():
    """Explicit decision=BENIGN_NO_ISSUE maps to NO_RELEVANT_FUNCTIONALITY."""
    payload = {"decision": "BENIGN_NO_ISSUE"}
    res = extract_decision(payload)
    assert res.decision == "NO_RELEVANT_FUNCTIONALITY"
    assert res.vulnerability_exists is False
    assert res.is_valid is True
    assert res.failure_reason is None


def test_20_explicit_vulnerability_exists_false():
    """Explicit vulnerability_exists=False maps to NO_RELEVANT_FUNCTIONALITY."""
    payload = {"vulnerability_exists": False}
    res = extract_decision(payload)
    assert res.decision == "NO_RELEVANT_FUNCTIONALITY"
    assert res.vulnerability_exists is False
    assert res.is_valid is True


def test_21_nested_explicit_abstention_with_both():
    """
    Audited abstention case:
    {"ReasoningHypothesis": {"decision": "INSUFFICIENT_EVIDENCE", "vulnerability_exists": False}}
    Must map to NO_RELEVANT_FUNCTIONALITY / EXPLICIT_ABSTENTION and NOT DECISION_EXTRACTION_FAILURE.
    """
    payload = {
        "ReasoningHypothesis": {
            "decision": "INSUFFICIENT_EVIDENCE",
            "vulnerability_exists": False,
        }
    }
    res = extract_decision(payload)
    assert res.decision == "NO_RELEVANT_FUNCTIONALITY"
    assert res.vulnerability_exists is False
    assert res.is_valid is True
    assert "EXPLICIT_ABSTENTION" in (res.failure_reason or "")

    # Assert taxonomy classification: on a vulnerable scenario it is REASONING_INCORRECT_LOGIC, not DECISION_EXTRACTION_FAILURE
    p, s = classify_earliest_failure(
        raw_output_present=True,
        raw_error=None,
        json_parse_status="SUCCESS",
        extraction_result=res,
        grounding_valid=True,
        is_breakout=False,
        escalated=True,
        ground_truth_vulnerable=True,
        called_7b=True,
        final_decision=res.decision,
        useful=False,
    )
    assert p == FailureLayer.REASONING_INCORRECT_LOGIC
    assert p != FailureLayer.DECISION_EXTRACTION_FAILURE

    # On a non-vulnerable scenario it is a correct abstention (Success / None)
    p_nonvuln, s_nonvuln = classify_earliest_failure(
        raw_output_present=True,
        raw_error=None,
        json_parse_status="SUCCESS",
        extraction_result=res,
        grounding_valid=True,
        is_breakout=False,
        escalated=True,
        ground_truth_vulnerable=False,
        called_7b=True,
        final_decision=res.decision,
        useful=False,
    )
    assert p_nonvuln is None


def test_22_conflicting_states_remain_invalid():
    """Conflicting states must remain invalid with CONFLICTING_FIELDS."""
    c1 = extract_decision({"VulnerabilityExists": True, "decision": "BENIGN"})
    assert c1.is_valid is False
    assert "CONFLICTING_FIELDS" in (c1.failure_reason or "")

    c2 = extract_decision({"VulnerabilityExists": False, "VulnerabilityType": "IDOR"})
    assert c2.is_valid is False
    assert "CONFLICTING_FIELDS" in (c2.failure_reason or "")

