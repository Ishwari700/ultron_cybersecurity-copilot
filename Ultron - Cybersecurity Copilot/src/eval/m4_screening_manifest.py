"""Deterministic development partition manifest generator for Milestone M4.8.

Implements the frozen Section 12.1 deterministic selection rule with the
authoritative Option 1 specification clarification for the 10th vulnerable scenario:
1. Select first lexicographic vulnerable and control from each category with both variants (9v + 9c).
2. Select first lexicographic control from API-AUTH-NONE (0v + 1c -> 10c).
3. Allocate 10th vulnerable slot to category with largest number of vulnerable scenarios in benchmark
   (API-CROSS-TENANT-001, count=6, tie-broken by ASCII ASC against API-STATE-001).
4. Select 2nd lexicographic vulnerable scenario from API-CROSS-TENANT-001:
   SCEN-HEALTHCARE_PORTAL-CLINIC-REC-VULN-04.
5. Invariant: exactly 20 scenarios, exactly 10 vulnerable, exactly 10 controls.
"""

from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple


FROZEN_BENCHMARK_HASH = "b2b85a672124acf21066a257d8c7f5093000368b224ee013c02574c96a0ae707"
MANIFEST_SCHEMA_VERSION = "1.0.0"
PARTITION_NAME = "m4_exploratory_development_partition"


def generate_m4_dev_partition(
    benchmark_manifest_path: Path = Path("data/benchmarks/m1_5_frozen_manifest.json"),
    output_manifest_path: Path = Path("data/eval/m4_dev_partition_manifest.json"),
    decision_record_path: Path = Path("data/eval/m4_partition_decision_record.json"),
) -> Tuple[Dict[str, Any], str]:
    """
    Generates and seals the 20-scenario exploratory development partition for M4.8.
    """
    if not benchmark_manifest_path.exists():
        raise FileNotFoundError(f"Source benchmark manifest not found: {benchmark_manifest_path}")

    raw_benchmark_bytes = benchmark_manifest_path.read_bytes()
    benchmark_sha256 = hashlib.sha256(raw_benchmark_bytes).hexdigest()
    if benchmark_sha256.lower() != FROZEN_BENCHMARK_HASH.lower():
        raise ValueError(
            f"Benchmark manifest hash mismatch: expected {FROZEN_BENCHMARK_HASH}, got {benchmark_sha256}"
        )

    benchmark_data = json.loads(raw_benchmark_bytes.decode("utf-8"))
    all_scenarios: List[Dict[str, Any]] = benchmark_data.get("scenarios", [])

    # Group scenarios by category and ground truth class
    by_category: Dict[str, Dict[str, List[Dict[str, Any]]]] = defaultdict(
        lambda: {"vuln": [], "ctrl": []}
    )
    for s in all_scenarios:
        cat = s["category_id"]
        is_vuln = bool(s.get("vulnerable_variant"))
        by_category[cat]["vuln" if is_vuln else "ctrl"].append(s)

    # Sort scenarios within each category stratum lexicographically by scenario_id
    for cat in by_category:
        by_category[cat]["vuln"].sort(key=lambda x: x["scenario_id"])
        by_category[cat]["ctrl"].sort(key=lambda x: x["scenario_id"])

    selected_scenarios: List[Dict[str, Any]] = []
    selection_log: List[Dict[str, Any]] = []

    # Step 1: Paired categories (categories with both vulnerable and control variants)
    paired_categories = sorted(
        [cat for cat, splits in by_category.items() if len(splits["vuln"]) > 0 and len(splits["ctrl"]) > 0]
    )

    for cat in paired_categories:
        v_scen = by_category[cat]["vuln"][0]
        c_scen = by_category[cat]["ctrl"][0]
        selected_scenarios.append(v_scen)
        selected_scenarios.append(c_scen)
        selection_log.append({
            "category_id": cat,
            "rule": "first_lexicographic_paired",
            "selected_vulnerable": v_scen["scenario_id"],
            "selected_control": c_scen["scenario_id"],
        })

    # Step 2: Unauthenticated negative-control category (API-AUTH-NONE)
    auth_none_category = "API-AUTH-NONE"
    if auth_none_category in by_category:
        if len(by_category[auth_none_category]["ctrl"]) == 0:
            raise ValueError(f"Category {auth_none_category} has zero control scenarios")
        auth_none_ctrl = by_category[auth_none_category]["ctrl"][0]
        selected_scenarios.append(auth_none_ctrl)
        selection_log.append({
            "category_id": auth_none_category,
            "rule": "first_lexicographic_control_only",
            "selected_vulnerable": None,
            "selected_control": auth_none_ctrl["scenario_id"],
        })

    # Step 3: Allocate the 10th vulnerable slot to largest category tie-broken by ASCII ASC
    vuln_counts = {cat: len(splits["vuln"]) for cat, splits in by_category.items() if len(splits["vuln"]) > 0}
    max_vuln_count = max(vuln_counts.values())
    tied_largest_categories = sorted([cat for cat, cnt in vuln_counts.items() if cnt == max_vuln_count])
    target_category = tied_largest_categories[0]  # First alphabetically among largest

    if len(by_category[target_category]["vuln"]) < 2:
        raise ValueError(f"Target category {target_category} does not have a 2nd vulnerable scenario")

    extra_vuln_scen = by_category[target_category]["vuln"][1]  # 2nd lexicographic scenario
    selected_scenarios.append(extra_vuln_scen)
    selection_log.append({
        "category_id": target_category,
        "rule": "second_lexicographic_vulnerable_from_largest_category",
        "selected_vulnerable": extra_vuln_scen["scenario_id"],
        "selected_control": None,
        "tie_break_notes": f"Tied at count={max_vuln_count} with {tied_largest_categories}; resolved by ASCII ASC to {target_category}",
    })

    # Step 4: Validate exact quotas
    vuln_selected = [s for s in selected_scenarios if s.get("vulnerable_variant") is True]
    ctrl_selected = [s for s in selected_scenarios if s.get("vulnerable_variant") is False]

    if len(vuln_selected) != 10:
        raise ValueError(f"Partition validation failed: expected 10 vulnerable, got {len(vuln_selected)}")
    if len(ctrl_selected) != 10:
        raise ValueError(f"Partition validation failed: expected 10 controls, got {len(ctrl_selected)}")
    if len(selected_scenarios) != 20:
        raise ValueError(f"Partition validation failed: expected 20 scenarios, got {len(selected_scenarios)}")

    # Sort final selected scenarios deterministically by scenario_id
    selected_scenarios.sort(key=lambda s: s["scenario_id"])
    scenario_ids = [s["scenario_id"] for s in selected_scenarios]

    # Compute category distribution
    cat_dist: Dict[str, Dict[str, int]] = {}
    for s in selected_scenarios:
        c = s["category_id"]
        if c not in cat_dist:
            cat_dist[c] = {"vulnerable": 0, "control": 0, "total": 0}
        if s.get("vulnerable_variant"):
            cat_dist[c]["vulnerable"] += 1
        else:
            cat_dist[c]["control"] += 1
        cat_dist[c]["total"] += 1

    # Format final manifest payload
    manifest_payload: Dict[str, Any] = {
        "manifest_schema_version": MANIFEST_SCHEMA_VERSION,
        "partition_name": PARTITION_NAME,
        "source_benchmark_manifest_hash": benchmark_sha256,
        "creation_timestamp": "2026-09-21T04:36:00+00:00",
        "total_scenarios": len(selected_scenarios),
        "vulnerable_count": len(vuln_selected),
        "control_count": len(ctrl_selected),
        "category_distribution": cat_dist,
        "scenario_ids": scenario_ids,
        "scenarios": [
            {
                "scenario_id": s["scenario_id"],
                "name": s.get("name", ""),
                "app_family": s.get("app_family", ""),
                "category_id": s.get("category_id", ""),
                "ground_truth_class": "vulnerable" if s.get("vulnerable_variant") else "control",
                "vulnerable_variant": s.get("vulnerable_variant"),
                "target_asset_id": s.get("target_asset_id", ""),
            }
            for s in selected_scenarios
        ],
        "selection_specification_clarification": {
            "specification_gap": "Section 12.1 mandated 10v/10c while stating 1v/1c per category, but API-AUTH-NONE has 0 vulnerable scenarios in the benchmark.",
            "resolution": "Option 1 (Proportional Largest-Category Quota): 9 paired categories (1v+1c) + API-AUTH-NONE (1c) + 2nd lexicographic vulnerable from largest category API-CROSS-TENANT-001.",
            "selection_log": selection_log,
        },
    }

    canonical_manifest_bytes = json.dumps(manifest_payload, indent=2, sort_keys=True).encode("utf-8")
    manifest_sha256 = hashlib.sha256(canonical_manifest_bytes).hexdigest()

    output_manifest_path.parent.mkdir(parents=True, exist_ok=True)
    output_manifest_path.write_bytes(canonical_manifest_bytes)

    sha256_path = output_manifest_path.parent / f"{output_manifest_path.name}.sha256"
    sha256_path.write_text(manifest_sha256 + "\n", encoding="utf-8")

    # Write separate evaluation decision record
    decision_record = {
        "decision_record_version": "1.0.0",
        "timestamp": manifest_payload["creation_timestamp"],
        "context": "M4.8 Pre-Screening Specification Clarification",
        "parent_document": "docs/M4_REASONING_ENGINE_PLAN.md",
        "parent_section": "12.1 Exploratory Screening Partition Contract",
        "frozen_plan_status": "Frozen plan specification gap resolved BEFORE observing any E0-E6 screening results",
        "benchmark_source_hash": benchmark_sha256,
        "generated_manifest_hash": manifest_sha256,
        "justification": "Deterministic clarification necessitated by the mismatch between the frozen 10/10 requirement and the benchmark's 9-category vulnerable availability.",
        "authoritative_rules": [
            "1. Select the first lexicographic vulnerable and first lexicographic control from each category that contains both variants (9v + 9c).",
            "2. Select the first lexicographic control from API-AUTH-NONE, because that category contains controls only (0v + 1c -> 10c).",
            "3. The resulting deterministic selection is 9 vulnerable + 10 controls.",
            "4. Allocate the remaining 10th vulnerable slot to the category with the largest number of vulnerable scenarios in the frozen benchmark.",
            "5. Resolve ties by ASCII/lexicographic category_id.",
            "6. Select the second lexicographic vulnerable scenario from that category (API-CROSS-TENANT-001 -> SCEN-HEALTHCARE_PORTAL-CLINIC-REC-VULN-04).",
            "7. The final partition MUST be: 20 total, 10 vulnerable, 10 controls.",
            "8. Do not inspect any E0-E6 results before freezing this decision.",
            "9. Create and hash the final manifest BEFORE any live screening call.",
            "10. Do not use Option 2.",
            "11. Do not use the historical human-study manifest.",
            "12. Do not resample or substitute scenarios after screening begins."
        ],
        "resolution_details": manifest_payload["selection_specification_clarification"],
        "selected_scenario_ids": scenario_ids,
    }
    decision_record_path.parent.mkdir(parents=True, exist_ok=True)
    decision_record_bytes = json.dumps(decision_record, indent=2, sort_keys=True).encode("utf-8")
    decision_record_path.write_bytes(decision_record_bytes)
    (decision_record_path.parent / f"{decision_record_path.name}.sha256").write_text(
        hashlib.sha256(decision_record_bytes).hexdigest() + "\n", encoding="utf-8"
    )

    return manifest_payload, manifest_sha256


if __name__ == "__main__":
    manifest, digest = generate_m4_dev_partition()
    print(f"Generated M4 Dev Partition: {manifest['total_scenarios']} scenarios (vuln={manifest['vulnerable_count']}, ctrl={manifest['control_count']})")
    print(f"SHA-256: {digest}")
    print("Category Distribution:")
    for cat, counts in sorted(manifest["category_distribution"].items()):
        print(f"  {cat:25}: vuln={counts['vulnerable']}, ctrl={counts['control']}, total={counts['total']}")
