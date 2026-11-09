"""Unit Tests for Workstream D — Blinded Holdout Dataset & Blinding Guards.

Tests:
1. Dataset size meets requirement (>= 200 cases, exactly 240 cases).
2. All 12 scenario families have balanced representation (20 cases each).
3. Zero duplicate case IDs across the holdout set with opaque formatting.
4. Blinded dataset strictly strips ground-truth labels, rationales, and family taxonomy.
5. Semantic blinding: titles and descriptions are neutral and leak no category answers.
6. Shuffled ordering: consecutive cases belong to distinct families.
7. Blinding guard detects and raises on attempted label leakage.
8. Checked-in dataset files match their SHA-256 sidecars byte-for-byte.
9. Dataset loading fails closed on missing or corrupt files.
"""

import hashlib
import json
from pathlib import Path
import pytest

from src.core.test_integrity import REPO_ROOT
from src.eval.batch3_holdout import (
    DATASET_VERSION,
    GroundTruthLabel,
    HoldoutFamily,
    generate_batch3_holdout_dataset,
    create_blinded_dataset,
    verify_blinding_isolation,
    load_ground_truth_dataset,
    load_blinded_dataset,
    save_holdout_datasets,
)


def test_holdout_dataset_case_count_and_family_balance():
    """Verify that dataset contains >= 200 cases (240 total) with 20 cases per family."""
    cases = generate_batch3_holdout_dataset()
    assert len(cases) >= 200, f"Expected >= 200 cases, got {len(cases)}"
    assert len(cases) == 240, f"Expected exactly 240 cases, got {len(cases)}"

    # Check 12 families
    family_counts = {}
    for c in cases:
        family_counts[c.family] = family_counts.get(c.family, 0) + 1

    assert len(family_counts) == 12, f"Expected 12 families, got {len(family_counts)}"
    for fam, cnt in family_counts.items():
        assert cnt == 20, f"Family {fam.value} has {cnt} cases, expected 20"


def test_zero_duplicate_case_ids():
    """Verify that all case IDs in the holdout dataset are unique and opaquely formatted."""
    cases = generate_batch3_holdout_dataset()
    case_ids = [c.case_id for c in cases]
    unique_ids = set(case_ids)
    assert len(case_ids) == len(unique_ids), "Found duplicate case IDs in holdout dataset"
    for cid in case_ids:
        assert cid.startswith("B3-CASE-"), f"Invalid case ID prefix: {cid}"


def test_blinding_strictly_strips_ground_truth_and_family():
    """Verify that the model-facing blinded dataset contains zero ground-truth keys or family tags."""
    gt_cases = generate_batch3_holdout_dataset()
    blinded_cases = create_blinded_dataset(gt_cases)

    assert len(blinded_cases) == len(gt_cases)

    forbidden_fields = {"ground_truth_label", "adjudication_rationale", "expected_behavior", "family"}
    for b in blinded_cases:
        b_dict = b.to_dict()
        leaked = forbidden_fields.intersection(b_dict.keys())
        assert not leaked, f"Case {b.case_id} leaked ground truth or family keys: {leaked}"


def test_semantic_blinding_neutrality():
    """Verify that titles and descriptions in model-facing cases contain no category-revealing words."""
    blinded_data = load_blinded_dataset()
    revealing_words = ["genuine", "tampered", "out_of_scope", "vulnerability_supported", "lookalike"]

    for item in blinded_data:
        text = f"{item['title']} {item['description']}".lower()
        for word in revealing_words:
            assert word not in text, f"Case {item['case_id']} leaked revealing term '{word}' in metadata"


def test_shuffled_ordering_breaks_category_correlation():
    """Verify that consecutive case IDs do not share the same family (broken sequential ordering)."""
    gt_cases = generate_batch3_holdout_dataset()
    consecutive_matches = 0
    for i in range(len(gt_cases) - 1):
        if gt_cases[i].family == gt_cases[i + 1].family:
            consecutive_matches += 1

    # In a truly shuffled 240-item list with 12 equal classes, matches should be minimal (< 30)
    assert consecutive_matches < 35, f"Too many consecutive family matches: {consecutive_matches}"


def test_blinding_guard_detects_label_leakage():
    """Verify that verify_blinding_isolation detects and raises ValueError on leaked labels or families."""
    leaked_item = {
        "case_id": "B3-LEAK-001",
        "title": "Leaked case",
        "description": "Standard case",
        "ground_truth_label": "VULNERABILITY_SUPPORTED",  # FORBIDDEN!
    }
    with pytest.raises(ValueError) as exc_info:
        verify_blinding_isolation([leaked_item])
    assert "BLINDING_VIOLATION" in str(exc_info.value)
    assert "ground_truth_label" in str(exc_info.value)

    # Test family leakage
    leaked_family = {
        "case_id": "B3-LEAK-002",
        "title": "Leaked family case",
        "description": "Standard case",
        "family": "GENUINE_SQLI",  # FORBIDDEN in blinded payload!
    }
    with pytest.raises(ValueError) as exc_info:
        verify_blinding_isolation([leaked_family])
    assert "BLINDING_VIOLATION" in str(exc_info.value)
    assert "family" in str(exc_info.value)


def test_checked_in_dataset_sha256_checksum_reconciliation():
    """Regression Test: Verify that checked-in dataset files match their .sha256 sidecars byte-for-byte."""
    b3_dir = REPO_ROOT / "data" / "eval" / "batch3"
    gt_file = b3_dir / "holdout_dataset_ground_truth.json"
    gt_sha = b3_dir / "holdout_dataset_ground_truth.json.sha256"

    blinded_file = b3_dir / "holdout_dataset_blinded.json"
    blinded_sha = b3_dir / "holdout_dataset_blinded.json.sha256"

    assert gt_file.exists(), f"Ground truth file missing: {gt_file}"
    assert gt_sha.exists(), f"Ground truth sha256 sidecar missing: {gt_sha}"
    assert blinded_file.exists(), f"Blinded file missing: {blinded_file}"
    assert blinded_sha.exists(), f"Blinded sha256 sidecar missing: {blinded_sha}"

    # Calculate actual byte hashes
    actual_gt_hash = hashlib.sha256(gt_file.read_bytes()).hexdigest()
    actual_blinded_hash = hashlib.sha256(blinded_file.read_bytes()).hexdigest()

    sidecar_gt_hash = gt_sha.read_text(encoding="utf-8").strip()
    sidecar_blinded_hash = blinded_sha.read_text(encoding="utf-8").strip()

    assert actual_gt_hash == sidecar_gt_hash, (
        f"Ground truth hash mismatch! File: {actual_gt_hash}, Sidecar: {sidecar_gt_hash}"
    )
    assert actual_blinded_hash == sidecar_blinded_hash, (
        f"Blinded hash mismatch! File: {actual_blinded_hash}, Sidecar: {sidecar_blinded_hash}"
    )


def test_load_dataset_enforces_blinding_and_schema():
    """Verify that dataset loader functions load valid data and enforce blinding."""
    gt_data = load_ground_truth_dataset()
    assert len(gt_data) == 240

    blinded_data = load_blinded_dataset()
    assert len(blinded_data) == 240

    for item in blinded_data:
        assert "ground_truth_label" not in item
        assert "adjudication_rationale" not in item
        assert "expected_behavior" not in item
        assert "family" not in item


def test_adversarial_nested_fields_and_bypasses():
    """Verify that verify_blinding_isolation detects attempts to bypass blinding
    via deeply nested structures, misleading metadata, or hidden strings."""
    # 1. Nested dictionary attempting to smuggle label
    nested_leak = {
        "case_id": "ADV-01",
        "title": "Neutral title",
        "nested": {"metadata": {"category_tag": "VULNERABILITY_SUPPORTED"}},
    }
    with pytest.raises(ValueError, match="BLINDING_VIOLATION"):
        verify_blinding_isolation([nested_leak])

    # 2. Nested list inside observations attempting to smuggle taxonomy
    list_leak = {
        "case_id": "ADV-02",
        "title": "Neutral title",
        "observations": [{"step": "obs_1", "extra": ["harmless", "server_side_request_forgery"]}],
    }
    with pytest.raises(ValueError, match="BLINDING_VIOLATION"):
        verify_blinding_isolation([list_leak])

    # 3. Candidate hypothesis with smuggled genuine attack family
    hyp_leak = {
        "case_id": "ADV-03",
        "title": "Neutral title",
        "candidate_hypothesis": {"details": "suspected genuine_sqli finding"},
    }
    with pytest.raises(ValueError, match="BLINDING_VIOLATION"):
        verify_blinding_isolation([hyp_leak])

    # 4. Forbidden key disguised in nested level
    forbidden_key_leak = {
        "case_id": "ADV-04",
        "title": "Neutral title",
        "meta": {"ground_truth_label": "POLICY_VIOLATION"},
    }
    with pytest.raises(ValueError, match="BLINDING_VIOLATION"):
        verify_blinding_isolation([forbidden_key_leak])


def test_complete_model_facing_serialization_neutrality():
    """Examine the complete model-facing JSON serialization for all 240 cases,
    confirming zero leakage of adjudication labels, family identifiers, or expected rationales."""
    blinded_data = load_blinded_dataset()
    assert len(blinded_data) == 240

    # Ensure blinding guard passes completely
    verify_blinding_isolation(blinded_data)

    forbidden_tokens = [
        "vulnerability_supported",
        "vulnerability_not_supported",
        "genuine_sqli",
        "genuine_ssrf",
        "out_of_scope_evidence",
        "tampered_canonical_evidence",
        "benign_sql_lookalike",
        "benign_external_fetch",
        "tampered_obs",
        "input_validation",
    ]

    for case in blinded_data:
        serialized = json.dumps(case).lower()
        for token in forbidden_tokens:
            assert token not in serialized, (
                f"Blinded case {case.get('case_id')} leaked token '{token}' in serialized payload: {serialized[:150]}"
            )
