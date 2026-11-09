"""Unit tests verifying Milestone M4.8 Screening Harness and Parity Invariants."""

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
import pytest

from src.eval.m4_screening_manifest import generate_m4_dev_partition
from src.eval.m4_screening_harness import (
    M4ScreeningHarness,
    ScreeningTrackId,
    TrackActivationMatrix,
    TRACK_ACTIVATION_SPEC,
    FORBIDDEN_PROMPT_TOKENS,
)
from src.eval.m4_screening_selector import (
    compute_track_metrics,
    verify_evidence_parity_across_tracks,
    run_greedy_configuration_selection,
)


def test_dev_partition_manifest_integrity():
    """Verify development partition manifest properties and exact quotas."""
    manifest_path = Path("data/eval/m4_dev_partition_manifest.json")
    assert manifest_path.exists(), "Manifest file must exist"

    raw_bytes = manifest_path.read_bytes()
    expected_sha = (manifest_path.parent / f"{manifest_path.name}.sha256").read_text(encoding="utf-8").strip()
    actual_sha = hashlib.sha256(raw_bytes).hexdigest()
    assert actual_sha.lower() == expected_sha.lower(), "Manifest hash must match .sha256"

    data = json.loads(raw_bytes.decode("utf-8"))
    assert data["total_scenarios"] == 20
    assert data["vulnerable_count"] == 10
    assert data["control_count"] == 10

    scenarios = data["scenarios"]
    assert len(scenarios) == 20

    vulns = [s for s in scenarios if s["vulnerable_variant"] is True]
    ctrls = [s for s in scenarios if s["vulnerable_variant"] is False]
    assert len(vulns) == 10
    assert len(ctrls) == 10

    # Verify category distribution
    dist = data["category_distribution"]
    assert dist["API-AUTH-NONE"]["vulnerable"] == 0
    assert dist["API-AUTH-NONE"]["control"] == 1
    assert dist["API-CROSS-TENANT-001"]["vulnerable"] == 2
    assert dist["API-CROSS-TENANT-001"]["control"] == 1

    # Remaining 8 categories must each have exactly 1 vuln and 1 ctrl
    for cat, counts in dist.items():
        if cat not in ("API-AUTH-NONE", "API-CROSS-TENANT-001"):
            assert counts["vulnerable"] == 1, f"Category {cat} should have 1 vulnerable scenario"
            assert counts["control"] == 1, f"Category {cat} should have 1 control scenario"


def test_activation_matrices_single_factor_isolation():
    """Verify programmatic single-factor isolation of all screening tracks."""
    assert TRACK_ACTIVATION_SPEC[ScreeningTrackId.BASELINE].as_dict() == {"i1": 0, "i2": 0, "i3": 0, "i4": 0, "i5": 0, "i6": 0}
    assert TRACK_ACTIVATION_SPEC[ScreeningTrackId.E1].as_dict() == {"i1": 1, "i2": 0, "i3": 0, "i4": 0, "i5": 0, "i6": 0}
    assert TRACK_ACTIVATION_SPEC[ScreeningTrackId.E2].as_dict() == {"i1": 0, "i2": 1, "i3": 0, "i4": 0, "i5": 0, "i6": 0}
    assert TRACK_ACTIVATION_SPEC[ScreeningTrackId.E3].as_dict() == {"i1": 0, "i2": 0, "i3": 1, "i4": 0, "i5": 0, "i6": 0}
    assert TRACK_ACTIVATION_SPEC[ScreeningTrackId.E4].as_dict() == {"i1": 0, "i2": 0, "i3": 0, "i4": 1, "i5": 0, "i6": 0}
    assert TRACK_ACTIVATION_SPEC[ScreeningTrackId.E5].as_dict() == {"i1": 0, "i2": 0, "i3": 0, "i4": 0, "i5": 1, "i6": 0}
    assert TRACK_ACTIVATION_SPEC[ScreeningTrackId.E6].as_dict() == {"i1": 0, "i2": 0, "i3": 0, "i4": 0, "i5": 0, "i6": 1}


def test_canonical_evidence_parity_and_ground_truth_exclusion():
    """
    Verify canonical evidence fingerprint is identical and ground-truth tokens
    never enter prompt serialization across all tracks for all 20 scenarios.
    """
    harness = M4ScreeningHarness(live_mode=False)
    scenarios = harness.load_dev_partition()
    assert len(scenarios) == 20

    for s in scenarios:
        scen_id = s["scenario_id"]
        # 1. Canonical input fingerprint repeatability
        inp1 = harness.get_canonical_input(scen_id)
        inp2 = harness.get_canonical_input(scen_id)
        assert inp1["canonical_input_hash"] == inp2["canonical_input_hash"]
        assert len(inp1["canonical_input_hash"]) == 64

        # 2. Verify prompts across all 7 tracks
        for track_id in (
            ScreeningTrackId.BASELINE,
            ScreeningTrackId.E1,
            ScreeningTrackId.E2,
            ScreeningTrackId.E3,
            ScreeningTrackId.E4,
            ScreeningTrackId.E5,
            ScreeningTrackId.E6,
        ):
            act = TRACK_ACTIVATION_SPEC[track_id]
            prompt, _ = harness.build_prompt_for_track(scen_id, track_id, act)
            assert len(prompt) > 100
            prompt_lower = prompt.lower()
            for token in FORBIDDEN_PROMPT_TOKENS:
                assert token not in prompt_lower, f"Token {token} leaked into prompt for {scen_id} under {track_id.value}"


def test_hermetic_track_execution_and_scoring():
    """Verify end-to-end hermetic mock execution, evidence parity check, and scoring."""
    def mock_llm(prompt: str, schema: Any) -> str:
        if "<bair>" in prompt or "BOUNDED ANALYTICAL INFERENCE REPRESENTATION" in prompt:
            return (
                "<bair>\n"
                "<invariant>Invariant test</invariant>\n"
                "<evidence_gap>Gap test</evidence_gap>\n"
                "<affected_target>AST-01</affected_target>\n"
                "<decision>NO_RELEVANT_FUNCTIONALITY</decision>\n"
                "<facts>FACT-00000001</facts>\n"
                "<methodology></methodology>\n"
                "<falsification>supporting obs and contradicting obs</falsification>\n"
                "</bair>"
            )
        elif "empirical_fact_ids" in prompt:
            return json.dumps({
                "invariant": "Namespace invariant",
                "evidence_gap": "Namespace gap",
                "affected_target": "AST-01",
                "decision": "NO_RELEVANT_FUNCTIONALITY",
                "empirical_fact_ids": ["FACT-00000001"],
                "methodology_chunk_ids": [],
                "reasoning_summary": "Clean summary",
                "experiment_proposal": "None required",
            })
        else:
            return json.dumps({
                "invariant": "S0 invariant",
                "evidence_gap": "S0 gap",
                "affected_target": "AST-01",
                "decision": "NO_RELEVANT_FUNCTIONALITY",
                "supporting_evidence_ids": ["FACT-00000001"],
                "methodology_references": [],
                "reasoning_summary": "Clean S0 summary",
                "experiment_proposal": "None required",
            })

    harness = M4ScreeningHarness(live_mode=False, llm_caller=mock_llm)
    scenarios = harness.load_dev_partition()

    all_tracks_records = {}
    for track_id in (ScreeningTrackId.BASELINE, ScreeningTrackId.E1, ScreeningTrackId.E2):
        act = TRACK_ACTIVATION_SPEC[track_id]
        records = [harness.run_scenario_track(s["scenario_id"], track_id, act) for s in scenarios]
        assert len(records) == 20
        all_tracks_records[track_id.value] = records

    # Verify evidence parity across tracks
    ref_hashes = verify_evidence_parity_across_tracks(all_tracks_records)
    assert len(ref_hashes) == 20

    # Compute metrics
    b_report = compute_track_metrics(all_tracks_records["BASELINE"])
    assert b_report.total_scenarios == 20
    assert b_report.gate_1_safety_pass is True
    assert b_report.gate_2_envelope_pass is True
    assert b_report.gate_3_syntax_pass is True
    assert b_report.gate_4_namespace_pass is True

    # Test greedy combination selection
    reports = {"BASELINE": b_report}
    for t in ("E1", "E2"):
        reports[t] = compute_track_metrics(all_tracks_records[t], baseline_useful_rate=b_report.useful_hypothesis_rate)

    combined_act, selected, history = run_greedy_configuration_selection(reports)
    assert isinstance(selected, list)
    assert combined_act is not None
