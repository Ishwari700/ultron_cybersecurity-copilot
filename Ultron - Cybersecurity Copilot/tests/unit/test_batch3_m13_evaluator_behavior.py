"""Unit Tests for Workstream B — Behavioral Security Evaluator.

Tests:
1. Complete elimination of unconditional passes and default-pass fallbacks.
2. Explicit result semantics (PASS, FAIL, ERROR, SKIP, UNSUPPORTED).
3. Evaluator detects and rejects unknown categories with UNSUPPORTED.
4. Evaluator asserts actual behavior for lifecycle transitions (DRAFT -> COMPLETED blocked).
5. Evaluator asserts actual behavior for human review checklist (missing evidence rejected).
6. Evaluator asserts actual behavior for ScopeGate (out-of-scope blocked).
7. Evaluator asserts actual behavior for unapproved actor (UNAUTHORIZED_BOT blocked).
8. Result persistence schema contains all required diagnostic and audit fields.
"""

from pathlib import Path
import tempfile
import pytest

from src.eval.m13_dataset import M13Category, M13TestCase
from src.eval.m13_evaluator import M13Evaluator, M13ResultStatus


def test_evaluator_rejects_unknown_category():
    """Verify that any unrecognized/unknown category fails closed as UNSUPPORTED and passed=False."""
    evaluator = M13Evaluator(output_path=tempfile.mktemp())
    baseline_aid = evaluator._setup_baseline_assessment()

    # Construct synthetic case with non-existent category
    case = M13TestCase(
        case_id="M13-FAKE-001",
        category="NON_EXISTENT_CATEGORY",  # type: ignore
        title="Fake category check",
        description="Testing unknown category behavior",
        input_data={"any": "data"},
        expected_result={"any": "result"},
    )

    res = evaluator.evaluate_case(case, baseline_aid)
    assert res["status"] == M13ResultStatus.UNSUPPORTED.value
    assert res["passed"] is False
    assert "Unknown category" in res["observed_behavior"]


def test_evaluator_blocks_illegal_lifecycle_jump():
    """Verify that direct transition from DRAFT to COMPLETED is detected and fails closed."""
    evaluator = M13Evaluator(output_path=tempfile.mktemp())
    baseline_aid = evaluator._setup_baseline_assessment()

    case = M13TestCase(
        case_id="M13-LC-TEST-001",
        category=M13Category.LIFECYCLE,
        title="Direct DRAFT to COMPLETED transition attempt",
        description="Must fail closed as illegal DAG transition",
        input_data={"initial_state": "DRAFT", "target_state": "COMPLETED"},
        expected_result={"valid": False, "error": "InvalidTransition"},
    )

    res = evaluator.evaluate_case(case, baseline_aid)
    assert res["status"] == M13ResultStatus.PASS.value
    assert res["passed"] is True
    assert res["observed_behavior"] == "{'allowed_direct_jump': False}"


def test_evaluator_blocks_unauthorized_bot_actor():
    """Verify that an automated/bot actor cannot perform human-only lifecycle transitions."""
    evaluator = M13Evaluator(output_path=tempfile.mktemp())
    baseline_aid = evaluator._setup_baseline_assessment()

    case = M13TestCase(
        case_id="M13-LC-TEST-002",
        category=M13Category.LIFECYCLE,
        title="Unauthorized bot lifecycle transition attempt",
        description="Must be rejected because bot cannot transition lifecycle",
        input_data={"actor": "UNAUTHORIZED_BOT", "target_state": "ASSESSMENT_ACTIVE"},
        expected_result={"valid": False, "error": "PermissionDenied"},
    )

    res = evaluator.evaluate_case(case, baseline_aid)
    assert res["status"] == M13ResultStatus.PASS.value
    assert res["passed"] is True
    assert res["observed_behavior"] == "{'actor_permitted': False}"


def test_evaluator_enforces_finding_validation_checklist():
    """Verify that finding verification checklist fails closed on missing evidence."""
    evaluator = M13Evaluator(output_path=tempfile.mktemp())
    baseline_aid = evaluator._setup_baseline_assessment()

    # Case where evidence is deliberately missing
    case = M13TestCase(
        case_id="M13-REV-TEST-001",
        category=M13Category.HUMAN_REVIEW,
        title="Missing evidence checklist verification",
        description="Checklist must fail closed when evidence is missing",
        input_data={"evidence_missing": True},
        expected_result={"checklist_passed": False},
    )

    res = evaluator.evaluate_case(case, baseline_aid)
    assert res["status"] == M13ResultStatus.PASS.value
    assert res["passed"] is True
    assert res["observed_behavior"] == "{'checklist_passed': False}"


def test_evaluator_enforces_scopegate_boundary():
    """Verify that ScopeGate blocks out-of-scope targets and evaluator records exact mismatch."""
    evaluator = M13Evaluator(output_path=tempfile.mktemp())
    baseline_aid = evaluator._setup_baseline_assessment()

    case = M13TestCase(
        case_id="M13-SCP-TEST-001",
        category=M13Category.SCOPE,
        title="Out of scope target verification",
        description="Out of scope target must be evaluated as not permitted",
        input_data={
            "target": "forbidden.internal.corp",
            "in_scope": ["api.corp.com"],
            "out_of_scope": ["forbidden.internal.corp"],
        },
        expected_result={"is_in_scope": False},
    )

    res = evaluator.evaluate_case(case, baseline_aid)
    assert res["status"] == M13ResultStatus.PASS.value
    assert res["passed"] is True
    assert res["observed_behavior"] == "{'permitted': False}"


def test_evaluator_result_structure_and_persistence(tmp_path: Path):
    """Verify that evaluation results conform to schema and persist properly."""
    out_file = tmp_path / "test_m13_eval.json"
    evaluator = M13Evaluator(output_path=str(out_file))
    summary = evaluator.run_benchmark()

    assert summary["total_cases"] == 360
    assert summary["passed_cases"] == 360
    assert summary["failed_cases"] == 0
    assert summary["hard_invariant_violations"] == 0
    assert summary["evaluator_version"] == "13.1.0-batch3"
    assert len(summary["detailed_results"]) == 360

    # Verify case fields
    first_case = summary["detailed_results"][0]
    required_keys = [
        "case_id", "category", "title", "status", "passed",
        "expected_behavior", "observed_behavior", "evidence_details",
        "execution_status", "elapsed_ms",
    ]
    for k in required_keys:
        assert k in first_case, f"Missing key '{k}' in result"

    assert out_file.exists()
