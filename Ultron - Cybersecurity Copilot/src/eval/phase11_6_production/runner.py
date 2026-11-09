"""Milestone M5 Phase 11.6: Production Validation Runner.

Executes:
1. 15 End-to-end production validation scenarios
2. 19 Targeted security boundary failure injections
3. Tamper-evident chained audit logging and verification
4. Generates structured JSON artifacts:
   - data/eval/m5_phase11_6_production_validation_results.json
   - data/eval/m5_phase11_6_failure_injection_results.json
   - data/eval/m5_phase11_6_manifest.json
"""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.core.logging import AuditLogger, verify_audit_log
from src.eval.phase11_6_production.fixtures import get_validation_fixtures
from src.eval.phase11_6_production.pipeline import ProductionPipelineHarness
from src.eval.phase11_6_production.failure_injection import run_failure_injections


def run_phase11_6_validation(output_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Execute complete Phase 11.6 production validation suite and write sealed artifacts."""
    out_dir = output_dir or Path("data/eval")
    out_dir.mkdir(parents=True, exist_ok=True)
    scratch_dir = out_dir / "phase11_6_scratch"
    scratch_dir.mkdir(parents=True, exist_ok=True)

    timestamp_start = datetime.now(timezone.utc).isoformat()

    # 1. Execute 19 Failure Injections
    audit_file = scratch_dir / "audit_injections.jsonl"
    if audit_file.exists():
        audit_file.unlink()
    injection_audit_logger = AuditLogger(audit_file_path=audit_file)
    injection_results = run_failure_injections(audit_logger=injection_audit_logger)
    inj_audit_verif = verify_audit_log(audit_file)

    # 2. Execute 15 Production Pipeline Scenarios
    harness = ProductionPipelineHarness(work_dir=scratch_dir)
    fixtures = get_validation_fixtures()
    pipeline_results = []
    for fix in fixtures:
        res = harness.execute_fixture(fix)
        pipeline_results.append(res)

    pipeline_audit_verif = verify_audit_log(harness.audit_file)

    timestamp_end = datetime.now(timezone.utc).isoformat()

    # 3. Format and serialize structured results
    fixtures_data = [r.model_dump() for r in pipeline_results]
    injections_data = [i.model_dump() for i in injection_results]

    validation_payload = {
        "milestone": "M5",
        "phase": "11.6",
        "title": "End-to-End Production Pipeline Validation",
        "timestamp_start": timestamp_start,
        "timestamp_end": timestamp_end,
        "total_scenarios": len(fixtures_data),
        "passed_scenarios": sum(1 for r in fixtures_data if r["success"]),
        "failed_scenarios": sum(1 for r in fixtures_data if not r["success"]),
        "pass_rate": sum(1 for r in fixtures_data if r["success"]) / len(fixtures_data),
        "scenarios": fixtures_data,
        "audit_verification": pipeline_audit_verif.model_dump(),
    }

    injections_payload = {
        "milestone": "M5",
        "phase": "11.6",
        "title": "Security Boundary Failure Injection Suite",
        "timestamp_start": timestamp_start,
        "timestamp_end": timestamp_end,
        "total_injections": len(injections_data),
        "passed_injections": sum(1 for i in injections_data if i["passed"]),
        "failed_injections": sum(1 for i in injections_data if not i["passed"]),
        "pass_rate": sum(1 for i in injections_data if i["passed"]) / len(injections_data),
        "injections": injections_data,
        "audit_verification": inj_audit_verif.model_dump(),
    }

    results_path = out_dir / "m5_phase11_6_production_validation_results.json"
    injections_path = out_dir / "m5_phase11_6_failure_injection_results.json"
    manifest_path = out_dir / "m5_phase11_6_manifest.json"

    with open(results_path, "w", encoding="utf-8") as f:
        json.dump(validation_payload, f, indent=2, sort_keys=True)

    with open(injections_path, "w", encoding="utf-8") as f:
        json.dump(injections_payload, f, indent=2, sort_keys=True)

    # Compute hashes for manifest
    with open(results_path, "rb") as f:
        results_hash = hashlib.sha256(f.read()).hexdigest()

    with open(injections_path, "rb") as f:
        injections_hash = hashlib.sha256(f.read()).hexdigest()

    prereg_path = Path("docs/M5_PHASE11_6_PRODUCTION_VALIDATION_PREREGISTRATION.md")
    prereg_hash = ""
    if prereg_path.exists():
        with open(prereg_path, "rb") as f:
            prereg_hash = hashlib.sha256(f.read()).hexdigest()

    manifest_payload = {
        "schema_version": "2.0.0",
        "milestone": "M5",
        "phase": "11.6",
        "generated_at": timestamp_end,
        "preregistration_hash": prereg_hash,
        "artifacts": {
            "m5_phase11_6_production_validation_results.json": results_hash,
            "m5_phase11_6_failure_injection_results.json": injections_hash,
        },
        "summary": {
            "all_fixtures_passed": all(r["success"] for r in fixtures_data),
            "all_injections_passed": all(i["passed"] for i in injections_data),
            "total_fixtures": len(fixtures_data),
            "total_injections": len(injections_data),
            "overall_status": "PASS" if all(r["success"] for r in fixtures_data) and all(i["passed"] for i in injections_data) else "FAIL",
        },
    }

    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest_payload, f, indent=2, sort_keys=True)

    return manifest_payload


if __name__ == "__main__":
    manifest = run_phase11_6_validation()
    print("Phase 11.6 validation run complete.")
    print("Manifest:", json.dumps(manifest, indent=2))
