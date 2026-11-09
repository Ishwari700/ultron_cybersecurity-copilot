"""
Unit Tests for Milestone M5 Phase 11.1 Failure Analysis & Corpus Pipeline.

Verifies:
1. Immutability of sealed historical datasets (Phases 7, 8, 9, 10).
2. Deterministic corpus extraction, record integrity, and schema compliance.
3. Rigid attribution precedence ladder (F02 -> F04 -> F05 -> F06 -> F08 -> F07 -> F09 -> F11 -> F01 -> F99).
4. Multi-contributing failure preservation.
5. Action selection compatibility and confusion resolution.
6. Polarity inversion and tautology detection.
7. Context package and RAG grounding failure isolation.
8. Secret pattern scrubbing and zero credential persistence.
9. Deterministic bit-for-bit reproducibility of corpus generation.
10. Unresolved fail-safe F99 for unclassifiable failure traces.
"""

import hashlib
import json
from pathlib import Path
import pytest

from src.eval.phase11_failure_analysis.taxonomy import (
    FailureCode,
    TAXONOMY_METADATA,
    FailureNature,
)
from src.eval.phase11_failure_analysis.attribution import (
    attribute_failure,
    evaluate_action_compatibility,
    is_exact_polarity_inversion,
    FailureAttributionResult,
)
from src.eval.phase11_failure_analysis.corpus_builder import (
    build_corpus_records,
    assert_zero_sensitive_data,
    compute_file_sha256,
    compute_record_checksum,
    HISTORICAL_SOURCE_CONFIGS,
)
from src.eval.phase11_failure_analysis.action_analysis import run_action_selection_analysis
from src.eval.phase11_failure_analysis.polarity_analysis import run_polarity_analysis
from src.eval.phase11_failure_analysis.context_analysis import run_context_package_analysis
from src.eval.phase11_failure_analysis.cascade_analysis import run_cascade_handoff_analysis
from src.eval.phase11_failure_analysis.rag_analysis import run_rag_knowledge_analysis


REPO_ROOT = Path(__file__).resolve().parent.parent.parent


# ---------------------------------------------------------------------------
# 1. Sealed Historical Datasets Immutability
# ---------------------------------------------------------------------------

SEALED_HASHES = {
    "data/eval/m5_phase7_benchmark_final.json": "1e0ed90c4aa672f135d2d2f2240a14d22fa0037c03efda33634f4bf10ff0b125",
    "data/eval/m5_phase8_semantic_study.json": "b1df9a62fb07d76e0abf6e3935ccbabdaa1713f4c594019ae30c9e59567a45c6",
    "data/eval/m5_phase9_semantic_budget_study.json": "3c0d3e503c7ed24470b14dfde0bd763c631a9b5dbf70c047bbca72cfaab07f95",
    "data/eval/m5_phase10_full_population_validation.json": "6821d207729de97ac99657a09e38c25895a73285fe9c485d299dc27f37d2bdba",
    "data/eval/m5_phase10_checkpoint.json": "40f9f725fca5fdf05a76836182960b7f0d4c303a182d6e8af068a1b57e8f4537",
}


@pytest.mark.parametrize("rel_path, expected_sha", SEALED_HASHES.items())
def test_sealed_historical_datasets_immutability(rel_path: str, expected_sha: str):
    """Verify that none of the sealed historical benchmark artifacts have been modified."""
    file_path = REPO_ROOT / rel_path
    assert file_path.exists(), f"Historical artifact missing: {rel_path}"

    with open(file_path, "rb") as f:
        actual_sha = hashlib.sha256(f.read()).hexdigest()

    assert actual_sha == expected_sha, (
        f"CRITICAL: Historical artifact '{rel_path}' has been mutated!\n"
        f"Expected: {expected_sha}\nActual:   {actual_sha}"
    )


# ---------------------------------------------------------------------------
# 2. Taxonomy and Attribution Precedence
# ---------------------------------------------------------------------------

def test_taxonomy_definitions():
    """Verify that all taxonomy codes have metadata, category types, and non-empty descriptions."""
    for code in FailureCode:
        assert code in TAXONOMY_METADATA
        meta = TAXONOMY_METADATA[code]
        assert code.name.startswith("F")
        assert len(meta["name"]) > 0
        assert isinstance(meta["nature"], FailureNature)
        assert len(meta["description"]) > 10


def test_attribution_precedence_runtime_timeout():
    """F02 (RUNTIME_TIMEOUT) must take precedence over schema, grounding, and polarity."""
    record = {
        "primary_failure_category": "RUNTIME_TIMEOUT",
        "timed_out": True,
        "candidate_decision": "HYPOTHESIS",
        "experiment_action": "INVALID_ACTION",
        "polarity_valid": False,
        "condition_id": "C2",
    }
    res = attribute_failure(record, scenario_category_id="API-BOLA-001")
    assert res.primary_code == FailureCode.F02
    assert FailureCode.F02 in res.contributing_codes
    assert res.is_valid_typed is False


def test_attribution_precedence_parser_failure():
    """F04 (PARSER_FAILURE) must take precedence over schema and polarity."""
    record = {
        "primary_failure_category": "PARSER_FAILURE",
        "candidate_decision": "HYPOTHESIS",
        "condition_id": "C1",
    }
    res = attribute_failure(record)
    assert res.primary_code == FailureCode.F04
    assert FailureCode.F04 in res.contributing_codes


def test_attribution_precedence_schema_failure():
    """F05 (SCHEMA_FAILURE) must take precedence over grounding and polarity."""
    record = {
        "primary_failure_category": "SCHEMA_VALIDITY_FAILURE",
        "candidate_decision": "HYPOTHESIS",
        "condition_id": "C4",
    }
    res = attribute_failure(record)
    assert res.primary_code == FailureCode.F05
    assert FailureCode.F05 in res.contributing_codes


def test_attribution_precedence_grounding_failure():
    """F06 (GROUNDING_FAILURE) must take precedence over action and polarity."""
    record = {
        "primary_failure_category": "SEMANTIC_GROUNDING_FAILURE",
        "candidate_decision": "HYPOTHESIS",
        "experiment_action": "SUBSTITUTE_RESOURCE_IDENTIFIER",
        "condition_id": "C2",
        "track_id": "TRACK_D",
    }
    res = attribute_failure(record, scenario_category_id="API-BOLA-001")
    assert res.primary_code == FailureCode.F06
    assert FailureCode.F15 in res.contributing_codes
    assert FailureCode.F12 in res.contributing_codes


def test_attribution_precedence_action_selection_over_polarity():
    """F08 (ACTION_SELECTION_FAILURE) must take precedence over polarity failure."""
    record = {
        "primary_failure_category": "SEMANTIC_EXPERIMENT_POLARITY_FAILURE",
        "candidate_decision": "HYPOTHESIS",
        "experiment_action": "EXECUTE_OUT_OF_ORDER_TRANSITION",  # Incompatible for BOLA
        "supporting_outcome": "HTTP_200_OK",
        "disproving_outcome": "HTTP_403_FORBIDDEN",
        "polarity_valid": False,
        "condition_id": "C3",
    }
    res = attribute_failure(record, scenario_category_id="API-BOLA-001")
    assert res.primary_code == FailureCode.F08
    assert res.is_action_compatible is False
    assert FailureCode.F07 in res.contributing_codes


def test_attribution_precedence_polarity_failure():
    """F07 (POLARITY_FAILURE) triggers when action is compatible but outcomes fail validator."""
    record = {
        "primary_failure_category": "SEMANTIC_EXPERIMENT_POLARITY_FAILURE",
        "candidate_decision": "HYPOTHESIS",
        "experiment_action": "SUBSTITUTE_RESOURCE_IDENTIFIER",
        "supporting_outcome": "HTTP_403_FORBIDDEN",
        "disproving_outcome": "HTTP_200_OK",
        "polarity_valid": False,
        "condition_id": "C1",
    }
    res = attribute_failure(record, scenario_category_id="API-BOLA-001")
    assert res.primary_code == FailureCode.F07
    assert res.is_action_compatible is True
    assert res.is_exact_polarity_inversion is True
    assert FailureCode.F16 in res.contributing_codes


def test_attribution_early_abstention_on_vulnerable():
    """F11 (ABSTENTION_TOO_EARLY) triggers when model abstains on a vulnerable variant."""
    record = {
        "primary_failure_category": "VALID",
        "candidate_decision": "ABSTAIN",
        "final_decision": "ABSTAIN",
        "condition_id": "C3",
    }
    res = attribute_failure(record, scenario_category_id="API-BOLA-001", ground_truth_vulnerable=True)
    assert res.primary_code == FailureCode.F11
    assert FailureCode.F10 in res.contributing_codes
    assert res.is_valid_typed is False


def test_attribution_valid_typed_experiment():
    """F01 (VALID_TYPED) triggers on compliant experiment proposal."""
    record = {
        "primary_failure_category": "VALID",
        "candidate_decision": "HYPOTHESIS",
        "experiment_action": "SUBSTITUTE_RESOURCE_IDENTIFIER",
        "supporting_outcome": "HTTP_200_OK",
        "disproving_outcome": "HTTP_403_FORBIDDEN",
        "polarity_valid": True,
        "skeleton_compliant": True,
        "condition_id": "C1",
    }
    res = attribute_failure(record, scenario_category_id="API-BOLA-001", ground_truth_vulnerable=True)
    assert res.primary_code == FailureCode.F01
    assert res.is_valid_typed is True


def test_attribution_unresolved_fail_safe():
    """Unknown, non-standard records must resolve to F99 rather than an arbitrary code."""
    record = {
        "primary_failure_category": "UNRECOGNIZED_WEIRD_ERROR",
        "candidate_decision": "CORRUPTED",
        "condition_id": "UNKNOWN",
    }
    res = attribute_failure(record)
    assert res.primary_code == FailureCode.F99


# ---------------------------------------------------------------------------
# 3. Action Selection Compatibility and Confusion Matrix
# ---------------------------------------------------------------------------

def test_action_compatibility_matrix():
    """Verify category-action compatibility against registry."""
    ok, reason, breaches, safes = evaluate_action_compatibility(
        "API-BOLA-001", "SUBSTITUTE_RESOURCE_IDENTIFIER"
    )
    assert ok is True
    assert "HTTP_200_OK" in breaches
    assert "HTTP_403_FORBIDDEN" in safes

    bad_ok, bad_reason, _, _ = evaluate_action_compatibility(
        "API-BOLA-001", "TAMPER_REQUEST_PARAMETER"
    )
    assert bad_ok is False
    assert "not permitted" in bad_reason


def test_exact_polarity_inversion_detection():
    """Verify detection of exact breach/safe polarity swaps."""
    valid_breaches = {"HTTP_200_OK"}
    valid_safes = {"HTTP_403_FORBIDDEN"}

    # Inverted: supporting is in safe set, disproving is in breach set
    assert is_exact_polarity_inversion(
        "HTTP_403_FORBIDDEN", "HTTP_200_OK", valid_breaches, valid_safes
    ) is True

    # Correct orientation: not an inversion
    assert is_exact_polarity_inversion(
        "HTTP_200_OK", "HTTP_403_FORBIDDEN", valid_breaches, valid_safes
    ) is False

    # Out of vocabulary: not an exact inversion
    assert is_exact_polarity_inversion(
        "HTTP_500_INTERNAL_SERVER_ERROR", "HTTP_404_NOT_FOUND", valid_breaches, valid_safes
    ) is False


# ---------------------------------------------------------------------------
# 4. Corpus Extraction and Secret Exclusion
# ---------------------------------------------------------------------------

def test_secret_scrubbing_assertion():
    """Assert zero sensitive credential patterns exist in text."""
    # Clean string should pass
    assert_zero_sensitive_data("This is a benign response with status 200 OK.")

    # Redacted placeholders should pass
    assert_zero_sensitive_data("Using token [REDACTED_API_KEY] and [REDACTED_JWT_1]")

    # Raw secrets must raise ValueError
    with pytest.raises(ValueError, match="Sensitive secret pattern detected"):
        assert_zero_sensitive_data('api_key = "secret_access_token_123456789"')

    with pytest.raises(ValueError, match="Sensitive secret pattern detected"):
        assert_zero_sensitive_data("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")


def test_corpus_extraction_integrity():
    """Test full extraction pipeline on authoritative datasets."""
    records, manifest = build_corpus_records(repo_root=REPO_ROOT)

    # 1. Total records count
    assert len(records) == 756
    assert manifest["total_corpus_records"] == 756

    # 2. Phase 10 exact partition
    assert manifest["breakdown_by_phase"]["PHASE_10"] == 336
    p10_records = [r for r in records if r["provenance"]["source_phase"] == "PHASE_10"]
    assert len(p10_records) == 336

    # 3. Factorial balance across C1, C2, C3, C4
    for cid in ["C1", "C2", "C3", "C4"]:
        c_count = sum(1 for r in p10_records if r["identity"]["condition_id"] == cid)
        assert c_count == 84, f"Condition {cid} count {c_count} != 84"

    # 4. Verify record structure completeness
    sample = records[0]
    required_keys = [
        "corpus_record_id",
        "provenance",
        "identity",
        "runtime_telemetry",
        "context_package",
        "model_output",
        "attribution",
    ]
    for k in required_keys:
        assert k in sample

    assert sample["provenance"]["source_artifact_sha256"] is not None
    assert sample["attribution"]["primary_failure_code"] in [c.value for c in FailureCode]


def test_deterministic_reproducibility():
    """Verify bit-for-bit identical corpus record extraction across consecutive runs."""
    records_1, _ = build_corpus_records(repo_root=REPO_ROOT)
    records_2, _ = build_corpus_records(repo_root=REPO_ROOT)

    assert len(records_1) == len(records_2)

    for r1, r2 in zip(records_1, records_2):
        s1 = json.dumps(r1, sort_keys=True)
        s2 = json.dumps(r2, sort_keys=True)
        assert s1 == s2


# ---------------------------------------------------------------------------
# 5. Specialized Analyses Determinism
# ---------------------------------------------------------------------------

def test_specialized_analyses_execution():
    """Verify that all specialized analysis routines execute and return structured results."""
    records, _ = build_corpus_records(repo_root=REPO_ROOT)

    # Action Analysis
    action_res = run_action_selection_analysis(records, phase_filter="PHASE_10")
    assert "total_candidate_attempts" in action_res
    assert "confusion_matrix" in action_res
    assert "condition_breakdown" in action_res
    # C1 and C2 (skeleton) have 100% action compatibility
    assert action_res["condition_breakdown"]["C1"]["action_incompatible"] == 0
    assert action_res["condition_breakdown"]["C2"]["action_incompatible"] == 0
    assert action_res["condition_breakdown"]["C3"]["action_incompatible"] == 23
    assert action_res["condition_breakdown"]["C4"]["action_incompatible"] == 18

    # Polarity Analysis
    polarity_res = run_polarity_analysis(records, phase_filter="PHASE_10")
    assert "failure_partition" in polarity_res
    assert "polarity_mechanism_details" in polarity_res
    assert polarity_res["polarity_mechanism_details"]["exact_polarity_inversion"] > 0

    # Context Analysis
    context_res = run_context_package_analysis(records, phase_filter="PHASE_10")
    assert "C1" in context_res["conditions"]
    assert "C2" in context_res["conditions"]
    # 26 grounding failures strictly in C2
    assert context_res["conditions"]["C1"]["grounding_failures"] == 0
    assert context_res["conditions"]["C2"]["grounding_failures"] == 26

    # Cascade Analysis
    cascade_res = run_cascade_handoff_analysis(records, phase_filter="PHASE_10")
    assert cascade_res["total_cascade_calls"] == 168
    assert cascade_res["total_non_cascade_calls"] == 168

    # RAG Analysis
    rag_res = run_rag_knowledge_analysis(records, phase_filter="PHASE_10")
    assert rag_res["rag_grounding_failures"] == 26
    assert rag_res["no_rag_grounding_failures"] == 0
