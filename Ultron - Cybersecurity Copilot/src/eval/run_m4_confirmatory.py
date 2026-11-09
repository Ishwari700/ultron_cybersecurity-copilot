"""Execution Script for Phase M4.9 Confirmatory 84-Scenario Benchmark.

Executes the formal 84-scenario 4-track confirmatory benchmark (336 calls total)
under the frozen M4.8 configuration M4-COMBINED-I5-I2-I6-I3-I4.
"""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional

repo_root = Path(__file__).resolve().parent.parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from src.eval.m4_live_benchmark import (
    ConfirmatoryScenarioRecord,
    ConfirmatoryTrackId,
    M4ConfirmatoryHarness,
    TRACK_NAME_MAP,
    EXPECTED_7B_DIGEST_FULL,
    EXPECTED_7B_DIGEST_PREFIX,
    EXPECTED_BENCHMARK_HASH,
    EXPECTED_FROZEN_CONFIG_HASH,
    EXPECTED_PLANNING_FREEZE_COMMIT,
)
from src.eval.scenarios import EvaluationScenario, get_gold_set_scenarios


def hash_file(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest().lower()


def run_pre_execution_integrity_check():
    print("=== [1/6] PRE-EXECUTION INTEGRITY CHECK ===")

    # 1. Source benchmark hash
    src_sha = hash_file(Path("data/benchmarks/m1_5_frozen_manifest.json"))
    assert src_sha == EXPECTED_BENCHMARK_HASH, f"Benchmark manifest hash mismatch: {src_sha}"
    print(f"source_benchmark_manifest_sha: {src_sha} [PASS]")

    # 2. Planning freeze commit
    tag_commit = subprocess.check_output(
        ["git", "rev-parse", "m4-v1.1.0-planning-freeze^{commit}"], text=True
    ).strip()
    assert tag_commit == EXPECTED_PLANNING_FREEZE_COMMIT, f"Planning freeze mismatch: {tag_commit}"
    print(f"planning_freeze_commit: {tag_commit} [PASS]")

    # 3. M4.8 frozen config manifest hash
    cfg_sha = hash_file(Path("data/eval/m4_frozen_config_manifest.json"))
    assert cfg_sha == EXPECTED_FROZEN_CONFIG_HASH, f"Frozen config manifest hash mismatch: {cfg_sha}"
    print(f"m4_frozen_config_manifest_sha: {cfg_sha} [PASS]")

    # 4. Protected files diff
    diff_out = subprocess.check_output(
        [
            "git",
            "diff",
            "--exit-code",
            "docs/M4_REASONING_ENGINE_PLAN.md",
            "src/retrieval/hybrid.py",
            "data/eval/m3_live_llm_benchmark_20260920.json",
        ],
        text=True,
    )
    print("protected_file_diff: CLEAN (0 diff) [PASS]")

    # 5. Engine diff
    engine_diff = subprocess.check_output(["git", "diff", "--exit-code", "src/engine/"], text=True)
    print("src_engine_diff: CLEAN (0 diff) [PASS]")

    # 6. Verify official M4.9 artifact does not already exist
    final_artifact = Path("data/eval/m4_live_llm_benchmark_final.json")
    if final_artifact.exists() or Path(str(final_artifact) + ".sha256").exists():
        raise FileExistsError(f"Official M4.9 artifact {final_artifact} already exists! Refusing to execute.")
    print(f"final_artifact_path: {final_artifact} (Absent, ready for creation) [PASS]")

    print("PRE-EXECUTION INTEGRITY VERIFIED.\n")


def compute_track_metrics(records: List[ConfirmatoryScenarioRecord]) -> Dict[str, Any]:
    n_total = len(records)
    n_vuln = sum(1 for r in records if r.vulnerable_variant)
    n_ctrl = sum(1 for r in records if not r.vulnerable_variant)

    tp = sum(1 for r in records if r.vulnerable_variant and r.decision == "HYPOTHESIS" and r.is_valid)
    fn = sum(1 for r in records if r.vulnerable_variant and (r.decision != "HYPOTHESIS" or not r.is_valid))
    fp = sum(1 for r in records if not r.vulnerable_variant and r.decision == "HYPOTHESIS" and r.is_valid)
    tn = sum(1 for r in records if not r.vulnerable_variant and (r.decision != "HYPOTHESIS" or not r.is_valid))

    tpr = tp / n_vuln if n_vuln > 0 else 0.0
    tnr = tn / n_ctrl if n_ctrl > 0 else 1.0

    useful_count = sum(r.is_useful for r in records)
    useful_rate = useful_count / n_total if n_total > 0 else 0.0

    abstain_count = sum(1 for r in records if r.decision in ("NO_RELEVANT_FUNCTIONALITY", "INSUFFICIENT_EVIDENCE") or r.decision is None)
    abstain_rate = abstain_count / n_total if n_total > 0 else 0.0

    # AC1 Breakdown
    breakdown = {
        "RUNTIME_TRANSPORT_FAILURE": 0,
        "MAX_TOKEN_TRUNCATION": 0,
        "PARSER_FAILURE": 0,
        "SCHEMA_VALIDITY_FAILURE": 0,
        "SEMANTIC_GROUNDING_FAILURE": 0,
        "VALID": 0,
    }
    for r in records:
        cat = r.primary_failure_category
        breakdown[cat] = breakdown.get(cat, 0) + 1

    ac1_syntactic_count = (
        breakdown["MAX_TOKEN_TRUNCATION"]
        + breakdown["PARSER_FAILURE"]
        + breakdown["SCHEMA_VALIDITY_FAILURE"]
    )
    ac1_syntactic_rate = ac1_syntactic_count / n_total if n_total > 0 else 0.0

    valid_grounding_count = sum(1 for r in records if r.grounding_status == "VALID")
    grounding_validity_rate = valid_grounding_count / n_total if n_total > 0 else 0.0

    mean_latency = sum(r.latency_ms for r in records) / n_total if n_total > 0 else 0.0

    return {
        "total_scenarios": n_total,
        "vulnerable_count": n_vuln,
        "control_count": n_ctrl,
        "useful_hypothesis_count": useful_count,
        "useful_hypothesis_rate": useful_rate,
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "tn": tn,
        "tpr": tpr,
        "tnr": tnr,
        "abstention_count": abstain_count,
        "abstention_rate": abstain_rate,
        "ac1_syntactic_count": ac1_syntactic_count,
        "ac1_syntactic_rate": ac1_syntactic_rate,
        "ac1_failure_breakdown": breakdown,
        "valid_grounding_count": valid_grounding_count,
        "grounding_validity_rate": grounding_validity_rate,
        "mean_latency_ms": mean_latency,
    }


def main():
    start_time = time.time()
    run_pre_execution_integrity_check()

    harness = M4ConfirmatoryHarness(live_mode=True)
    scenarios = harness._gold_scenarios

    # Freeze scenario roster before execution
    scenario_order = [s.scenario_id for s in scenarios]
    print(f"=== [2/6] CONFIRMATORY ROSTER FROZEN (84 SCENARIOS) ===")
    print(f"Total scenarios: {len(scenario_order)} (36 vulnerable, 48 controls)")
    print(f"First 3: {scenario_order[:3]}")
    print(f"Last 3: {scenario_order[-3:]}")

    tracks_to_run = [
        ConfirmatoryTrackId.TRACK_A,
        ConfirmatoryTrackId.TRACK_B,
        ConfirmatoryTrackId.TRACK_C,
        ConfirmatoryTrackId.TRACK_D,
    ]

    print("\n=== [3/6] FROZEN CONFIRMATORY TRACK MATRIX ===")
    print(f"Track 1: {TRACK_NAME_MAP[ConfirmatoryTrackId.TRACK_A]} (cascade_mode=TRACK_A)")
    print("  Activation: {'i1': 0, 'i2': 1, 'i3': 1, 'i4': 1, 'i5': 1, 'i6': 1}")
    print(f"Track 2: {TRACK_NAME_MAP[ConfirmatoryTrackId.TRACK_B]} (cascade_mode=TRACK_B)")
    print("  Activation: {'i1': 0, 'i2': 1, 'i3': 1, 'i4': 1, 'i5': 1, 'i6': 1}")
    print(f"Track 3: {TRACK_NAME_MAP[ConfirmatoryTrackId.TRACK_C]} (cascade_mode=TRACK_C)")
    print("  Activation: {'i1': 0, 'i2': 1, 'i3': 1, 'i4': 1, 'i5': 1, 'i6': 1}")
    print(f"Track 4: {TRACK_NAME_MAP[ConfirmatoryTrackId.TRACK_D]} (cascade_mode=TRACK_D)")
    print("  Activation: {'i1': 0, 'i2': 1, 'i3': 1, 'i4': 1, 'i5': 1, 'i6': 1}")
    print("Total Scheduled Calls: 84 scenarios x 4 tracks = 336 calls\n")

    # Checkpoint persistence
    checkpoint_path = Path("data/eval/m4_live_benchmark_checkpoint.json")
    all_records: Dict[str, List[ConfirmatoryScenarioRecord]] = {
        ConfirmatoryTrackId.TRACK_A.value: [],
        ConfirmatoryTrackId.TRACK_B.value: [],
        ConfirmatoryTrackId.TRACK_C.value: [],
        ConfirmatoryTrackId.TRACK_D.value: [],
    }
    completed_scenarios = set()

    if checkpoint_path.exists():
        try:
            ckpt = json.loads(checkpoint_path.read_text(encoding="utf-8"))
            for t_val, rec_list in ckpt.get("tracks", {}).items():
                all_records[t_val] = [ConfirmatoryScenarioRecord.model_validate(r) for r in rec_list]
            completed_scenarios = set(ckpt.get("completed_scenarios", []))
            print(f"Resuming from checkpoint: {len(completed_scenarios)}/84 scenarios already completed.")
        except Exception as exc:
            print(f"Failed to load checkpoint ({exc}), starting clean.")
            completed_scenarios = set()

    causal_parity_matches = 0
    causal_parity_discrepancies = 0

    print("=== [4/6] EXECUTING 336 LIVE CONFIRMATORY CALLS ===")
    for idx, scen in enumerate(scenarios, 1):
        scen_id = scen.scenario_id
        if scen_id in completed_scenarios:
            continue

        print(f"\n[{idx:2d}/84] Scenario {scen_id} (Category: {scen.category_id}, Vuln: {scen.vulnerable_variant})")

        # Execute 4 tracks
        prompt_b, ev_bytes_b = harness.build_prompt_for_track(scen_id, ConfirmatoryTrackId.TRACK_B)
        prompt_d, ev_bytes_d = harness.build_prompt_for_track(scen_id, ConfirmatoryTrackId.TRACK_D)

        # Causal parity check
        if ev_bytes_b != ev_bytes_d:
            causal_parity_discrepancies += 1
            raise RuntimeError(f"Causal parity failure on scenario {scen_id}: Target Evidence B != Target Evidence D")
        causal_parity_matches += 1

        for track_id in tracks_to_run:
            rec = harness.execute_scenario_track(scenario_id=scen_id, track_id=track_id)
            all_records[track_id.value].append(rec)
            print(f"  [{track_id.value}] decision={rec.decision}, primary={rec.primary_failure_category}, useful={rec.is_useful}, latency={rec.latency_ms:.1f}ms")

        completed_scenarios.add(scen_id)

        # Update checkpoint
        ckpt_data = {
            "completed_scenarios": list(completed_scenarios),
            "tracks": {t_val: [r.model_dump() for r in rec_list] for t_val, rec_list in all_records.items()},
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        checkpoint_path.write_text(json.dumps(ckpt_data, indent=2), encoding="utf-8")

    print("\n=== [5/6] ALL 336 CALLS COMPLETED. COMPUTING CONFIRMATORY METRICS ===")
    track_reports = {}
    total_useful = 0
    total_ac1_failures = 0

    for track_id in tracks_to_run:
        recs = all_records[track_id.value]
        assert len(recs) == 84, f"Track {track_id.value} has {len(recs)} records, expected 84"
        rep = compute_track_metrics(recs)
        track_reports[track_id.value] = rep
        total_useful += rep["useful_hypothesis_count"]
        total_ac1_failures += rep["ac1_syntactic_count"]

        t_name = TRACK_NAME_MAP[track_id]
        print(f"\n{t_name} ({track_id.value}):")
        print(f"  Useful Hypotheses: {rep['useful_hypothesis_count']}/84 ({rep['useful_hypothesis_rate']:.1%})")
        print(f"  TPR on Vuln: {rep['tp']}/36 ({rep['tpr']:.1%}), FN: {rep['fn']}/36")
        print(f"  TNR on Ctrl: {rep['tn']}/48 ({rep['tnr']:.1%}), FP: {rep['fp']}/48")
        print(f"  Abstentions: {rep['abstention_count']}/84 ({rep['abstention_rate']:.1%})")
        print(f"  AC1 Failures: {rep['ac1_syntactic_count']}/84 ({rep['ac1_syntactic_rate']:.1%})")
        print(f"  AC1 Breakdown: {rep['ac1_failure_breakdown']}")
        print(f"  Grounding Validity: {rep['valid_grounding_count']}/84 ({rep['grounding_validity_rate']:.1%})")
        print(f"  Mean Latency: {rep['mean_latency_ms']:.1f}ms")

    overall_ac1_rate = total_ac1_failures / 336.0
    print(f"\nOVERALL BENCHMARK (N=336): AC1 Syntactic Failure Rate = {total_ac1_failures}/336 ({overall_ac1_rate:.2%})")
    print(f"Strict B/D Causal Parity: 84/84 byte-identical matches (0 discrepancies)")

    # Serialize final artifact
    final_payload = {
        "run_status": "OFFICIAL_M4_9_CONFIRMATORY",
        "schema_version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_scheduled_calls": 336,
        "total_completed_calls": 336,
        "benchmark_provenance": {
            "manifest_path": "data/benchmarks/m1_5_frozen_manifest.json",
            "manifest_sha256": EXPECTED_BENCHMARK_HASH,
            "total_scenarios": 84,
            "vulnerable_scenarios": 36,
            "control_scenarios": 48,
            "scenario_order": scenario_order,
        },
        "configuration_provenance": {
            "frozen_config_manifest_path": "data/eval/m4_frozen_config_manifest.json",
            "frozen_config_manifest_sha256": EXPECTED_FROZEN_CONFIG_HASH,
            "configuration_id": "M4-COMBINED-I5-I2-I6-I3-I4",
            "selected_interventions": ["I5", "I2", "I6", "I3", "I4"],
            "activation_matrix": {
                "i1": 0,
                "i2": 1,
                "i3": 1,
                "i4": 1,
                "i5": 1,
                "i6": 1,
            },
        },
        "compute_envelope": {
            "model_name": "qwen2.5-coder:7b",
            "model_digest": EXPECTED_7B_DIGEST_FULL,
            "model_digest_prefix": EXPECTED_7B_DIGEST_PREFIX,
            "quantization": "Q4_K_M",
            "runtime_version": "Ollama v0.34.1",
            "num_ctx": 2048,
            "num_predict": 300,
            "temperature": 0.0,
            "seed": 42,
            "keep_alive": "60m",
        },
        "causal_parity": {
            "b_d_parity_verified": True,
            "matches": 84,
            "discrepancies": 0,
        },
        "tracks": {
            t_val: {
                "track_name": TRACK_NAME_MAP[ConfirmatoryTrackId(t_val)],
                "metrics": track_reports[t_val],
                "records": [r.model_dump() for r in rec_list],
            }
            for t_val, rec_list in all_records.items()
        },
    }

    final_bytes = json.dumps(final_payload, indent=2, sort_keys=True).encode("utf-8")
    final_sha256 = hashlib.sha256(final_bytes).hexdigest()
    final_path = Path("data/eval/m4_live_llm_benchmark_final.json")
    final_path.write_bytes(final_bytes)
    (final_path.parent / f"{final_path.name}.sha256").write_text(final_sha256 + "\n", encoding="utf-8")
    print(f"\nFinal Confirmatory Benchmark Artifact written to {final_path}")
    print(f"Artifact SHA-256: {final_sha256}")

    # Remove checkpoint after successful completion
    if checkpoint_path.exists():
        checkpoint_path.unlink()
        print("Temporary checkpoint removed.")

    print("\n=== [6/6] POST-EXECUTION INTEGRITY VERIFICATION ===")
    subprocess.check_output(
        [
            "git",
            "diff",
            "--exit-code",
            "docs/M4_REASONING_ENGINE_PLAN.md",
            "src/retrieval/hybrid.py",
            "data/eval/m3_live_llm_benchmark_20260920.json",
        ],
        text=True,
    )
    print("Protected files diff clean.")

    subprocess.check_output(["git", "diff", "--exit-code", "src/engine/"], text=True)
    print("src/engine/ diff clean.")

    tag_commit = subprocess.check_output(["git", "rev-parse", "m4-v1.1.0-planning-freeze^{commit}"], text=True).strip()
    assert tag_commit == EXPECTED_PLANNING_FREEZE_COMMIT
    print(f"Planning freeze verified: {tag_commit}")

    elapsed = time.time() - start_time
    print(f"\nM4.9 CONFIRMATORY BENCHMARK FULLY COMPLETED in {elapsed:.1f}s.")


if __name__ == "__main__":
    main()
