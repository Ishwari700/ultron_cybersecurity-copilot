"""
Milestone M5 Phase 11.2: End-to-End Live Diagnostic Experiment Driver.

Runs preflight checks, executes the 16 live calls, saves results and manifest,
and generates the final research report.
"""

from datetime import datetime, timezone
import hashlib
import json
import sys
from pathlib import Path

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.eval.phase11_2_polarity.runner import Phase11PolarityDiagnosticRunner
from src.eval.phase11_2_polarity.analysis import analyze_diagnostic_results
from src.eval.phase11_2_polarity.report_generation import generate_phase11_2_report


def main() -> None:
    repo_root = Path(__file__).resolve().parent.parent.parent.parent
    print("=" * 80)
    print("M5 PHASE 11.2 — POLARITY REPRESENTATION DIAGNOSTIC EXECUTION")
    print("=" * 80)

    # 1. Initialize Runner & Preflight Checks
    runner = Phase11PolarityDiagnosticRunner(repo_root=repo_root)

    print("\n[Preflight 1] Verifying Ollama local daemon connection...")
    if not runner.ollama.is_available():
        print("ERROR: Ollama server is not running on http://127.0.0.1:11434")
        sys.exit(1)
    print("  -> Ollama is available.")

    print("\n[Preflight 2] Verifying model qwen2.5-coder:7b installed...")
    models = runner.ollama.list_models()
    model_names = [m.get("name") for m in models]
    if "qwen2.5-coder:7b" not in model_names and not any("qwen2.5-coder:7b" in str(n) for n in model_names):
        print(f"ERROR: Model qwen2.5-coder:7b not found. Available: {model_names}")
        sys.exit(1)
    print("  -> Model qwen2.5-coder:7b verified.")

    print(f"\n[Preflight 3] Verifying diagnostic scenarios ({len(runner.diagnostic_scenarios)} scenarios)...")
    for idx, scen in enumerate(runner.diagnostic_scenarios):
        print(f"  {idx+1}. {scen.scenario_id} [{scen.category_id}] (Vuln={scen.vulnerable_variant})")

    # 2. Live Execution
    print("\n" + "=" * 80)
    print("EXECUTING 16 LIVE DIAGNOSTIC INFERENCE CALLS (8 scenarios x 2 conditions)")
    print("=" * 80)

    def on_progress(call_num: int, total_calls: int, scenario_id: str, condition_id: str):
        now_str = datetime.now(timezone.utc).strftime("%H:%M:%S")
        print(f"[{now_str}] Call {call_num:02d}/{total_calls:02d}: {condition_id} -> {scenario_id}...", flush=True)

    records = runner.run_diagnostic(progress_callback=on_progress)

    print("\n" + "=" * 80)
    print("LIVE EXECUTION COMPLETE — COMPILING MANIFEST & ANALYSIS")
    print("=" * 80)

    # 3. Compile Manifest & Export
    results_path = repo_root / "data/eval/m5_phase11_2_live_results.json"
    manifest_path = repo_root / "data/eval/m5_phase11_2_manifest.json"

    with open(results_path, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, sort_keys=True)

    results_sha = hashlib.sha256(open(results_path, "rb").read()).hexdigest()

    manifest = {
        "manifest_version": "1.0.0",
        "phase": "PHASE_11_2",
        "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ"),
        "total_calls_executed": len(records),
        "results_file": "data/eval/m5_phase11_2_live_results.json",
        "results_sha256": results_sha,
        "runtime_configuration": {
            "model": "qwen2.5-coder:7b",
            "model_digest": "dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364",
            "num_ctx": 2048,
            "num_predict": 300,
            "temperature": 0.0,
            "seed": 42,
            "keep_alive": "60m",
            "timeout_seconds": 30.0,
        },
        "conditions_evaluated": ["P0", "P1"],
        "scenarios_evaluated": [s.scenario_id for s in runner.diagnostic_scenarios],
    }

    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)

    manifest_sha = hashlib.sha256(open(manifest_path, "rb").read()).hexdigest()

    # 4. Generate Comprehensive Research Report
    report_file = generate_phase11_2_report(
        diagnostic_records=records,
        manifest=manifest,
        repo_root=repo_root,
    )
    report_sha = hashlib.sha256(open(report_file, "rb").read()).hexdigest()

    # 5. Summary Output
    analysis = analyze_diagnostic_results(records)
    p0 = analysis["condition_statistics"].get("P0", {})
    p1 = analysis["condition_statistics"].get("P1", {})

    print("\n" + "=" * 80)
    print("PHASE 11.2 DIAGNOSTIC SUMMARY REPORT")
    print("=" * 80)
    print(f"Condition P0 (Control - Model Outcome Selection):")
    print(f"  - Total Calls:            {p0.get('total_calls')}")
    print(f"  - Candidate Hypotheses:   {p0.get('candidate_hypotheses')}")
    print(f"  - Valid Typed Exp:        {p0.get('valid_typed_experiments')}")
    print(f"  - Candidate VTER:         {p0.get('valid_typed_experiment_rate_vter')}%")
    print(f"  - Scenario Success:       {p0.get('scenario_success_rate')}%")
    print(f"  - Useful Vuln Hypotheses: {p0.get('useful_vulnerable_hypotheses')}")
    print(f"  - Failure Breakdown:      {p0.get('primary_failure_counts')}")

    print(f"\nCondition P1 (Treatment - Attack Predicate + Deterministic Binding):")
    print(f"  - Total Calls:            {p1.get('total_calls')}")
    print(f"  - Candidate Hypotheses:   {p1.get('candidate_hypotheses')}")
    print(f"  - Valid Typed Exp:        {p1.get('valid_typed_experiments')}")
    print(f"  - Candidate VTER:         {p1.get('valid_typed_experiment_rate_vter')}%")
    print(f"  - Scenario Success:       {p1.get('scenario_success_rate')}%")
    print(f"  - Useful Vuln Hypotheses: {p1.get('useful_vulnerable_hypotheses')}")
    print(f"  - Failure Breakdown:      {p1.get('primary_failure_counts')}")

    print(f"\nPaired Scenario Contingency: {analysis['paired_contingency']}")
    print(f"\nArtifact Hashes:")
    print(f"  - Results:  {results_sha}")
    print(f"  - Manifest: {manifest_sha}")
    print(f"  - Report:   {report_sha}")
    print("=" * 80)


if __name__ == "__main__":
    main()
