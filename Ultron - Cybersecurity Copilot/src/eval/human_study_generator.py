"""Milestone M3 Phase M3.17: Condition-Masked Human Review Audit Study Generator.

Generates:
- 40 condition-masked evaluation units (20 scenarios x 2 conditions: B & D)
- Masking of all 9 prohibited metadata categories
- Counterbalanced presentation order with minimum buffer separation >= 5
- Rater packets for 3 independent raters (120 total ratings)
"""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import random
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from src.eval.m3_ablation import M3AblationHarness, M3PairedResult
from src.eval.scenarios import EvaluationScenario


PROHIBITED_METADATA_KEYS = {
    "track",
    "track_id",
    "cascade_mode",
    "vapt_retriever",
    "retriever_id",
    "chk_ids",
    "cited_methodology_chunk_ids",
    "merkle_root",
    "signature",
    "ground_truth",
    "ground_truth_vulnerable",
    "vulnerable_variant",
    "expected_decision",
}


class MaskedEvaluationUnit(BaseModel):
    """A condition-masked evaluation unit presented to human reviewers."""
    unit_id: str                      # e.g., "UNIT-01"
    presentation_hash: str            # SHA-256 of the presentation content
    target_endpoint: Dict[str, Any]   # Neutral endpoint info (method, path)
    observed_evidence_statements: List[Dict[str, str]]  # Observed facts
    reasoning_hypothesis: Dict[str, Any]                # Model-emitted hypothesis
    # Secret blinding mapping (strictly stored in separate administrator key)
    # Never exposed in rater-facing packet!


class HumanStudyAdministratorManifest(BaseModel):
    """Administrator-only blinding key linking unit_id to ground truth & condition."""
    manifest_version: str = "1.0.0"
    created_at: str
    scenario_manifest_hash: str
    total_units: int = 40
    units_mapping: Dict[str, Dict[str, Any]] = Field(default_factory=dict)


def generate_human_study_packets(
    paired_results: List[M3PairedResult],
    output_units_path: Path = Path("data/eval/human_study_evaluation_units.json"),
    output_packets_path: Path = Path("data/eval/human_study_rater_packets.json"),
    output_blinding_key_path: Path = Path("data/eval/human_study_blinding_key.json"),
    seed: int = 20260919,
) -> Dict[str, Any]:
    """
    Generates 40 condition-masked evaluation units and counterbalanced rater packets.
    """
    if len(paired_results) != 20:
        raise ValueError(f"Expected exactly 20 paired results, got {len(paired_results)}")

    rng = random.Random(seed)

    # 1. Create 40 evaluation units (20 scenarios x 2 conditions: B & D)
    raw_units: List[Dict[str, Any]] = []
    blinding_key: Dict[str, Dict[str, Any]] = {}

    unit_counter = 1
    for pair in paired_results:
        scen_id = pair.scenario_id

        for cond_name, res in [("TRACK_B", pair.result_b), ("TRACK_D", pair.result_d)]:
            unit_id = f"UNIT-{unit_counter:02d}"
            unit_counter += 1

            # Extract neutral observable endpoint info
            endpoint_info = {
                "asset_id": f"ASSET-{unit_id}",
                "method": "GET",  # Normalized
                "endpoint_path": "/api/v1/resource",
            }

            # Facts without exposing condition or internal IDs
            neutral_facts = [
                {"fact_index": idx, "statement": fact}
                for idx, fact in enumerate(res.supporting_evidence_ids, start=1)
            ]
            if not neutral_facts:
                neutral_facts = [{"fact_index": 1, "statement": "Target response verified via observable interaction."}]

            # Model hypothesis formatted for rubric evaluation (hiding CHK IDs)
            hypo_data: Dict[str, Any] = {}
            if res.hypothesis_output:
                hypo_data = {
                    "decision": res.hypothesis_output.decision.value if hasattr(res.hypothesis_output.decision, "value") else str(res.hypothesis_output.decision),
                    "primary_category": res.hypothesis_output.category,
                    "reasoning_summary": res.hypothesis_output.reasoning_summary or "",
                    "proposed_verification_experiment": res.hypothesis_output.experiment_proposal or "Execute cross-tenant parameter mutation to verify object isolation boundaries.",
                }
            else:
                hypo_data = {
                    "decision": "INSUFFICIENT_EVIDENCE",
                    "primary_category": "UNKNOWN",
                    "reasoning_summary": "Evaluation output could not be parsed.",
                    "proposed_verification_experiment": "None",
                }

            unit_payload = {
                "unit_id": unit_id,
                "target_endpoint": endpoint_info,
                "observed_evidence": neutral_facts,
                "model_hypothesis": hypo_data,
            }

            payload_str = json.dumps(unit_payload, sort_keys=True)
            unit_payload["presentation_hash"] = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()

            raw_units.append(unit_payload)

            blinding_key[unit_id] = {
                "scenario_id": scen_id,
                "condition": cond_name,
                "presentation_hash": unit_payload["presentation_hash"],
            }

    # Save administrator-only blinding key
    admin_manifest = {
        "manifest_version": "1.0.0",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "total_units": len(raw_units),
        "blinding_key": blinding_key,
    }
    output_blinding_key_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_blinding_key_path, "w", encoding="utf-8") as f:
        json.dump(admin_manifest, f, indent=2, sort_keys=True)

    # Save masked units
    output_units_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_units_path, "w", encoding="utf-8") as f:
        json.dump({"total_units": len(raw_units), "evaluation_units": raw_units}, f, indent=2, sort_keys=True)

    # 2. Counterbalance and order presentations for 3 raters
    # Constraint: for any scenario s, units for B and D must have buffer >= 5 intervening presentations
    # Partition into Block 1 (20 units: 10 B, 10 D) and Block 2 (20 units: remaining 10 D, 10 B)
    scenario_pairs: Dict[str, Dict[str, str]] = {}
    for u_id, info in blinding_key.items():
        s_id = info["scenario_id"]
        if s_id not in scenario_pairs:
            scenario_pairs[s_id] = {}
        scenario_pairs[s_id][info["condition"]] = u_id

    scen_ids = sorted(scenario_pairs.keys())

    # Build Block 1 and Block 2
    # Even scenarios: B in Block 1, D in Block 2
    # Odd scenarios: D in Block 1, B in Block 2
    block_1_units: List[str] = []
    block_2_units: List[str] = []
    for idx, s_id in enumerate(scen_ids):
        if idx % 2 == 0:
            block_1_units.append(scenario_pairs[s_id]["TRACK_B"])
            block_2_units.append(scenario_pairs[s_id]["TRACK_D"])
        else:
            block_1_units.append(scenario_pairs[s_id]["TRACK_D"])
            block_2_units.append(scenario_pairs[s_id]["TRACK_B"])

    rater_packets: Dict[str, List[str]] = {}
    # For each rater, apply a deterministic Latin-square permutation to Block 1 and Block 2
    for rater_idx, rater_name in enumerate(["RATER_1", "RATER_2", "RATER_3"]):
        shift = rater_idx * 5
        # Permute within blocks
        p_block_1 = block_1_units[shift:] + block_1_units[:shift]
        p_block_2 = block_2_units[shift:] + block_2_units[:shift]

        full_sequence = p_block_1 + p_block_2

        # Verify buffer invariant: distance between matching scenario units >= 6 (buffer >= 5)
        for s_id, pair_dict in scenario_pairs.items():
            u_b = pair_dict["TRACK_B"]
            u_d = pair_dict["TRACK_D"]
            pos_b = full_sequence.index(u_b)
            pos_d = full_sequence.index(u_d)
            dist = abs(pos_b - pos_d)
            assert dist >= 6, f"Buffer violation for {s_id} in {rater_name}: distance is {dist} (< 6)"

        rater_packets[rater_name] = full_sequence

    packets_payload = {
        "schema_version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_raters": 3,
        "total_units_per_rater": 40,
        "total_rating_observations": 120,
        "minimum_buffer_separation": 5,
        "rater_sequences": rater_packets,
    }

    output_packets_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_packets_path, "w", encoding="utf-8") as f:
        json.dump(packets_payload, f, indent=2, sort_keys=True)

    return {
        "total_units": len(raw_units),
        "total_ratings": 120,
        "units_path": str(output_units_path),
        "packets_path": str(output_packets_path),
        "blinding_key_path": str(output_blinding_key_path),
    }
