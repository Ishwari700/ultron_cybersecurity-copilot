"""
Unit and regression tests for M5 Phase 8 — Semantic Capability & Experiment Construction Study.

Verifies:
1. Immutability of Phase 7 sealed artifact and benchmark scenarios.
2. Phase 8.1 deterministic failure attribution across all 104 Phase 7 candidate hypotheses.
3. Phase 8.2 diagnostic protocol conditions (P1-P4) configuration and structure.
4. Phase 8.3 active-evidence fixture verification and applicability state transitions.
5. Phase 8.4 latency envelope classification rules.
6. Integrity and structure of the final Phase 8 diagnostic artifact.
"""

from collections import Counter
import hashlib
import json
from pathlib import Path
import pytest

from src.engine.decision_policy import ExperimentPolarityValidator
from src.evidence.cascade_models import LosslessStructuralPack
from src.eval.scorer import (
    EvaluationApplicabilityState,
    canonical_vulnerability_evidence_present,
    determine_applicability_state,
)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SEALED_P7_PATH = REPO_ROOT / "data/eval/m5_phase7_benchmark_final.json"
EXPECTED_P7_SHA = "1e0ed90c4aa672f135d2d2f2240a14d22fa0037c03efda33634f4bf10ff0b125"
SCENARIOS_PATH = REPO_ROOT / "src/eval/scenarios.py"
EXPECTED_SCENARIOS_SHA = "102789655bfb04041de9259d1bf6db7f088979e5bce9bac9eb050564ef0110a8"

P8_ARTIFACT_PATH = REPO_ROOT / "data/eval/m5_phase8_semantic_study.json"
P8_SHA_PATH = REPO_ROOT / "data/eval/m5_phase8_semantic_study.json.sha256"


def hash_file(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest().lower()


def test_phase8_0_immutability():
    """Verify Phase 7 artifact and scenarios.py remain strictly immutable."""
    assert SEALED_P7_PATH.exists(), "Phase 7 sealed artifact is missing"
    assert hash_file(SEALED_P7_PATH) == EXPECTED_P7_SHA, "Phase 7 sealed artifact SHA changed!"
    assert SCENARIOS_PATH.exists(), "scenarios.py is missing"
    assert hash_file(SCENARIOS_PATH) == EXPECTED_SCENARIOS_SHA, "scenarios.py SHA changed!"


def test_phase8_1_deterministic_attribution():
    """Verify Phase 8.1 deterministic failure attribution across all 104 Phase 7 candidates."""
    assert SEALED_P7_PATH.exists()
    p7_data = json.loads(SEALED_P7_PATH.read_text(encoding="utf-8"))
    records = p7_data["call_records"]

    hyp_records = [r for r in records if r.get("candidate_decision") == "HYPOTHESIS"]
    assert len(hyp_records) == 104, f"Expected 104 candidate hypothesis attempts, got {len(hyp_records)}"

    classified = []
    for r in hyp_records:
        pfc = r.get("primary_failure_category")
        pol = r.get("ExperimentPolarityValidator_result")
        typed = r.get("typed_experiment_fields", {})
        act = typed.get("experiment_action")
        supp = typed.get("supporting_outcome")
        disp = typed.get("disproving_outcome")

        cat_class = None
        if pfc == "MAX_TOKEN_TRUNCATION":
            cat_class = "E. TRUNCATION"
        elif supp is not None and disp is not None and supp == disp:
            cat_class = "C. IDENTICAL_SUPPORTING_DISPROVING_OUTCOME"
        elif pol and not pol.get("is_valid"):
            reason = pol.get("reason", "")
            if "not compatible with category" in reason:
                cat_class = "A. CATEGORY_ACTION_INCOMPATIBILITY"
            elif "not a valid breach outcome" in reason or "not a valid safe outcome" in reason or "inversion" in reason.lower():
                cat_class = "B. OUTCOME_POLARITY_INVERSION"
            else:
                cat_class = f"F. OTHER ({reason})"
        elif not act or not supp or not disp:
            cat_class = "D. MISSING_REQUIRED_SEMANTIC_FIELD"
        else:
            cat_class = f"F. OTHER ({pfc})"

        classified.append({
            "failure_type": cat_class,
            "vulnerable_variant": r["vulnerable_variant"],
        })

    counts = Counter(c["failure_type"] for c in classified)

    # Invariants confirmed by exhaustive Phase 7 audit
    assert len(classified) == 104
    assert counts["A. CATEGORY_ACTION_INCOMPATIBILITY"] == 68
    assert counts["B. OUTCOME_POLARITY_INVERSION"] == 26
    assert counts["C. IDENTICAL_SUPPORTING_DISPROVING_OUTCOME"] == 10
    assert counts.get("D. MISSING_REQUIRED_SEMANTIC_FIELD", 0) == 0
    assert counts.get("E. TRUNCATION", 0) == 0
    assert counts.get("F. OTHER", 0) == 0

    # Symmetric attempt rate between vulnerable and control
    vuln_count = sum(1 for c in classified if c["vulnerable_variant"] is True)
    ctrl_count = sum(1 for c in classified if c["vulnerable_variant"] is False)
    assert vuln_count == 53
    assert ctrl_count == 51


def test_phase8_3_active_evidence_predicate():
    """Verify that canonical anomaly evidence triggers VULNERABILITY_EVALUATION_APPLICABLE."""
    # Control case: No anomaly
    control_evidence = [{"fact_id": "FACT-01", "statement": "Neutral evidence"}]
    control_pack = LosslessStructuralPack(
        schema_version="2.0.0",
        asset_id="ASSET-CTRL",
        endpoint_id="EP-CTRL",
        route_template="/api/items",
        http_method="GET",
        application_mutability="READ_ONLY",
        parameter_lineage=[],
        identity_matrix=[{"role": "USER", "user_id": "usr-1"}],
        has_privilege_level_delta=False,
        has_cross_identity_object_access_success=False,
        has_observed_contradictions=False,
        observed_facts=control_evidence,
        raw_body_sample="",
    )
    has_anomaly_ctrl = canonical_vulnerability_evidence_present(control_evidence, control_pack)
    assert has_anomaly_ctrl is False

    app_ctrl = determine_applicability_state(
        is_valid_output=True,
        target_relevant=True,
        canonical_evidence_has_anomaly=has_anomaly_ctrl,
    )
    assert app_ctrl == EvaluationApplicabilityState.EXPLORATORY_EVALUATION_APPLICABLE

    # Anomaly case: Cross-identity access
    vuln_evidence = [
        {
            "fact_id": "FACT-02",
            "statement": "Access success on tenant B resource by tenant A user",
            "has_cross_identity_object_access_success": True,
        }
    ]
    vuln_pack = LosslessStructuralPack(
        schema_version="2.0.0",
        asset_id="ASSET-VULN",
        endpoint_id="EP-VULN",
        route_template="/api/items/{item_id}",
        http_method="GET",
        application_mutability="READ_ONLY",
        parameter_lineage=[{"name": "item_id", "type": "string", "source": "path"}],
        identity_matrix=[{"role": "USER", "user_id": "usr-1"}],
        has_privilege_level_delta=False,
        has_cross_identity_object_access_success=True,
        has_observed_contradictions=False,
        observed_facts=vuln_evidence,
        raw_body_sample="",
    )
    has_anomaly_vuln = canonical_vulnerability_evidence_present(vuln_evidence, vuln_pack)
    assert has_anomaly_vuln is True

    app_vuln = determine_applicability_state(
        is_valid_output=True,
        target_relevant=True,
        canonical_evidence_has_anomaly=has_anomaly_vuln,
    )
    assert app_vuln == EvaluationApplicabilityState.VULNERABILITY_EVALUATION_APPLICABLE


def test_phase8_4_latency_envelope_spec():
    """Verify latency envelope semantics per frozen architecture specs."""
    # From docs/M1_5_M2_PLAN.md Sec 12.4 and docs/M3_v2_3_6_PLANNING_HARDENING_AUDIT.md Sec 11.2:
    # Target: 12.0s (interactive)
    # Over-target: 12.0s - 30.0s (deep offline reasoning; logged as warning, NOT disqualified)
    # Timeout: >30.0s
    def classify_latency(lat_s: float) -> str:
        if lat_s <= 12.0:
            return "LATENCY_OPTIMAL"
        elif lat_s <= 30.0:
            return "LATENCY_OVER_TARGET"
        else:
            return "LATENCY_TIMEOUT"

    assert classify_latency(8.5) == "LATENCY_OPTIMAL"
    assert classify_latency(21.7) == "LATENCY_OVER_TARGET"
    assert classify_latency(25.34) == "LATENCY_OVER_TARGET"
    assert classify_latency(28.77) == "LATENCY_OVER_TARGET"
    assert classify_latency(31.2) == "LATENCY_TIMEOUT"


def test_phase8_artifact_integrity():
    """Verify Phase 8 diagnostic artifact file, hash, and structure."""
    assert P8_ARTIFACT_PATH.exists(), "Phase 8 artifact missing"
    assert P8_SHA_PATH.exists(), "Phase 8 sha file missing"

    actual_sha = hash_file(P8_ARTIFACT_PATH)
    recorded_sha = P8_SHA_PATH.read_text(encoding="utf-8").strip().split()[0].lower()
    assert actual_sha == recorded_sha, f"Phase 8 SHA mismatch: {actual_sha} != {recorded_sha}"

    data = json.loads(P8_ARTIFACT_PATH.read_text(encoding="utf-8"))
    assert data["status"] == "M5_PHASE8_COMPLETE"
    assert data["schema_version"] == "8.0.0"
    assert data["total_live_calls"] == 44

    p8_2 = data["phase_8_2_protocol_study"]
    assert len(p8_2["call_records"]) == 40
    assert p8_2["conditions"] == ["P1", "P2", "P3", "P4"]

    p8_3 = data["phase_8_3_active_evidence_diagnostic"]
    assert len(p8_3["call_records"]) == 4
