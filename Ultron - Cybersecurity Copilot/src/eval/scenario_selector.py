"""Deterministic human-study scenario selector and manifest freezer.

Implements M3 Phase M3.15.1:
DeterministicStratifiedProportionalSelection_v1
Seed: 20260919
"""

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import random
from typing import Any, Dict, List, Tuple


SELECTION_ALGORITHM_VERSION = "DeterministicStratifiedProportionalSelection_v1"
FIXED_RANDOM_SEED = 20260919
MANIFEST_SCHEMA_VERSION = "1.0.0"
FROZEN_BENCHMARK_HASH = "b2b85a672124acf21066a257d8c7f5093000368b224ee013c02574c96a0ae707"


def allocate_category_slots(
    category_counts: Dict[str, int],
    total_slots: int = 10,
) -> Dict[str, int]:
    """
    Allocate slots using the Hamilton/Hare largest-remainder method.
    Ties broken by category_id ASC in ASCII byte order.
    """
    total_items = sum(category_counts.values())
    if total_items == 0:
        return {cat: 0 for cat in category_counts}

    # Step 3: Exact quotas and integer floors
    exact_quotas: Dict[str, float] = {}
    floors: Dict[str, int] = {}
    remainders: Dict[str, float] = {}

    for cat in sorted(category_counts.keys()):
        count = category_counts[cat]
        q = (total_slots * count) / total_items
        exact_quotas[cat] = q
        floors[cat] = int(q)
        remainders[cat] = q - int(q)

    assigned_slots = sum(floors.values())
    remaining_slots = total_slots - assigned_slots

    # Step 4 & 5: Sort remainders descending, tie-break by category_id ASC
    sorted_by_remainder = sorted(
        category_counts.keys(),
        key=lambda c: (-remainders[c], c),
    )

    quotas = dict(floors)
    for i in range(remaining_slots):
        cat_to_award = sorted_by_remainder[i]
        quotas[cat_to_award] += 1

    return quotas


def run_deterministic_selection(
    benchmark_manifest_path: Path,
    output_manifest_path: Path,
    selection_timestamp: str = None,
) -> Dict[str, Any]:
    """
    Executes DeterministicStratifiedProportionalSelection_v1 and freezes
    human_study_scenario_manifest.json.
    """
    if not benchmark_manifest_path.exists():
        raise FileNotFoundError(f"Benchmark manifest not found: {benchmark_manifest_path}")

    raw_manifest_bytes = benchmark_manifest_path.read_bytes()
    manifest_sha256 = hashlib.sha256(raw_manifest_bytes).hexdigest()

    if manifest_sha256.lower() != FROZEN_BENCHMARK_HASH.lower():
        raise ValueError(
            f"Benchmark manifest hash mismatch! Expected {FROZEN_BENCHMARK_HASH}, got {manifest_sha256}"
        )

    data = json.loads(raw_manifest_bytes.decode("utf-8"))
    scenarios: List[Dict[str, Any]] = data.get("scenarios", [])

    # Step 1: Partition candidates by ground-truth class
    vuln_candidates = [s for s in scenarios if s.get("vulnerable_variant") is True]
    ctrl_candidates = [s for s in scenarios if s.get("vulnerable_variant") is False]

    if len(vuln_candidates) == 0 or len(ctrl_candidates) == 0:
        raise ValueError("Missing candidate scenarios in benchmark manifest.")

    # Step 2: Partition by primary category
    vuln_cat_counts = Counter(s["category_id"] for s in vuln_candidates)
    ctrl_cat_counts = Counter(s["category_id"] for s in ctrl_candidates)

    # Step 3-5: Proportional category allocation with largest remainder
    vuln_quotas = allocate_category_slots(vuln_cat_counts, total_slots=10)
    ctrl_quotas = allocate_category_slots(ctrl_cat_counts, total_slots=10)

    selected_scenarios: List[Dict[str, Any]] = []
    strata_definitions: Dict[str, Any] = {
        "vulnerable": {},
        "control": {},
    }

    # Step 6 & 7: Draw scenarios within each category stratum
    for cat in sorted(vuln_quotas.keys()):
        quota = vuln_quotas[cat]
        cat_scens = sorted([s for s in vuln_candidates if s["category_id"] == cat], key=lambda x: x["scenario_id"])
        strata_definitions["vulnerable"][cat] = {
            "candidate_count": len(cat_scens),
            "allocated_quota": quota,
        }
        if quota > 0:
            rng = random.Random(FIXED_RANDOM_SEED)
            chosen = rng.sample(cat_scens, quota)
            selected_scenarios.extend(chosen)

    for cat in sorted(ctrl_quotas.keys()):
        quota = ctrl_quotas[cat]
        cat_scens = sorted([s for s in ctrl_candidates if s["category_id"] == cat], key=lambda x: x["scenario_id"])
        strata_definitions["control"][cat] = {
            "candidate_count": len(cat_scens),
            "allocated_quota": quota,
        }
        if quota > 0:
            rng = random.Random(FIXED_RANDOM_SEED)
            chosen = rng.sample(cat_scens, quota)
            selected_scenarios.extend(chosen)

    # Invariant: exactly 10 vulnerable, exactly 10 controls, exactly 20 total
    vuln_selected = [s for s in selected_scenarios if s["vulnerable_variant"] is True]
    ctrl_selected = [s for s in selected_scenarios if s["vulnerable_variant"] is False]
    assert len(vuln_selected) == 10, f"Expected exactly 10 vulnerable scenarios, got {len(vuln_selected)}"
    assert len(ctrl_selected) == 10, f"Expected exactly 10 control scenarios, got {len(ctrl_selected)}"
    assert len(selected_scenarios) == 20, f"Expected exactly 20 total scenarios, got {len(selected_scenarios)}"

    # Sort final selected IDs deterministically
    sorted_selected = sorted(selected_scenarios, key=lambda s: s["scenario_id"])
    selected_ids = [s["scenario_id"] for s in sorted_selected]

    ts = selection_timestamp or datetime.now(timezone.utc).isoformat()

    # Self-hash script
    script_path = Path(__file__).resolve()
    script_hash = hashlib.sha256(script_path.read_bytes()).hexdigest()

    manifest_payload: Dict[str, Any] = {
        "manifest_schema_version": MANIFEST_SCHEMA_VERSION,
        "selection_algorithm_version": SELECTION_ALGORITHM_VERSION,
        "fixed_random_seed": FIXED_RANDOM_SEED,
        "source_benchmark_manifest_hash": manifest_sha256,
        "selection_script_hash": script_hash,
        "selection_timestamp": ts,
        "total_selected_count": len(selected_ids),
        "vulnerable_count": len(vuln_selected),
        "control_count": len(ctrl_selected),
        "selected_scenario_ids": selected_ids,
        "scenarios": [
            {
                "scenario_id": s["scenario_id"],
                "name": s.get("name", ""),
                "app_family": s.get("app_family", ""),
                "category_id": s.get("category_id", ""),
                "ground_truth_class": "vulnerable" if s.get("vulnerable_variant") else "control",
                "vulnerable_variant": s.get("vulnerable_variant"),
            }
            for s in sorted_selected
        ],
        "selection_strata": strata_definitions,
    }

    output_manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest_payload, f, indent=2, sort_keys=True)

    return manifest_payload
