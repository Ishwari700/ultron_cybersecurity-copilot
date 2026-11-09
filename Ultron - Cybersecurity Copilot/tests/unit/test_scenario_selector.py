"""Unit tests for M3.15.1 Deterministic Human-Study Scenario Selection."""

import hashlib
import json
from pathlib import Path
import pytest
from src.eval.scenario_selector import (
    FIXED_RANDOM_SEED,
    FROZEN_BENCHMARK_HASH,
    allocate_category_slots,
    run_deterministic_selection,
)


def test_allocate_category_slots_proportional():
    counts = {
        "CAT_A": 6,
        "CAT_B": 6,
        "CAT_C": 5,
        "CAT_D": 4,
    }
    # Total = 21, total_slots = 10
    quotas = allocate_category_slots(counts, total_slots=10)
    assert sum(quotas.values()) == 10
    # CAT_A: 10*6/21 = 2.857 -> floor 2, rem 0.857
    # CAT_B: 10*6/21 = 2.857 -> floor 2, rem 0.857
    # CAT_C: 10*5/21 = 2.381 -> floor 2, rem 0.381
    # CAT_D: 10*4/21 = 1.905 -> floor 1, rem 0.905
    # Floors sum = 7. Remainders to award: 3.
    # CAT_D (0.905), then CAT_A (0.857), then CAT_B (0.857)
    assert quotas["CAT_D"] == 2
    assert quotas["CAT_A"] == 3
    assert quotas["CAT_B"] == 3
    assert quotas["CAT_C"] == 2


def test_run_deterministic_selection_end_to_end(tmp_path: Path):
    benchmark_path = Path("data/benchmarks/m1_5_frozen_manifest.json")
    assert benchmark_path.exists()
    out_path = tmp_path / "human_study_scenario_manifest.json"

    manifest = run_deterministic_selection(
        benchmark_manifest_path=benchmark_path,
        output_manifest_path=out_path,
        selection_timestamp="2026-09-20T10:47:00Z",
    )

    assert manifest["total_selected_count"] == 20
    assert manifest["vulnerable_count"] == 10
    assert manifest["control_count"] == 10
    assert len(manifest["selected_scenario_ids"]) == 20

    # Repeat run should yield exact same JSON
    out_path_2 = tmp_path / "repeat_manifest.json"
    manifest_2 = run_deterministic_selection(
        benchmark_manifest_path=benchmark_path,
        output_manifest_path=out_path_2,
        selection_timestamp="2026-09-20T10:47:00Z",
    )

    assert out_path.read_bytes() == out_path_2.read_bytes()
    assert manifest["selected_scenario_ids"] == manifest_2["selected_scenario_ids"]


def test_frozen_manifest_file_matches_hash():
    manifest_path = Path("data/eval/human_study_scenario_manifest.json")
    assert manifest_path.exists()

    with open(manifest_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data["manifest_schema_version"] == "1.0.0"
    assert data["fixed_random_seed"] == FIXED_RANDOM_SEED
    assert data["source_benchmark_manifest_hash"] == FROZEN_BENCHMARK_HASH
    assert len(data["selected_scenario_ids"]) == 20
    assert data["vulnerable_count"] == 10
    assert data["control_count"] == 10
