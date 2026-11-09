"""
Standalone Verification Command for the 3B -> Router -> 7B Research Cascade.

Usage:
    python -m src.engine.verify_cascade --verify-cascade

Empirically executes the complete inference cascade through live local Ollama
and validates every stage: 3B triage, preservation gate, deterministic router,
immutable handoff packet, and 7B deep reasoning.
"""

import argparse
import sys
import time

from src.engine.cascade_orchestrator import CascadeOrchestrator
from src.engine.reasoning_runner import PINNED_7B_DIGEST, PINNED_7B_MODEL
from src.engine.triage_runner import PINNED_3B_DIGEST, PINNED_3B_MODEL
from src.evidence.cascade_models import LosslessStructuralPack


def run_cascade_verification(verbose: bool = False) -> bool:
    """
    Empirically execute and verify the complete 3B -> 7B cascade against live Ollama.
    Returns True if every stage passes, False otherwise.
    """
    print("=" * 40)
    print("CASCADE VERIFICATION")
    print("=" * 40)

    orchestrator = CascadeOrchestrator()
    runtime_status = orchestrator.check_runtime_status()

    # Step 0: Check Ollama connectivity
    print("\nRuntime:")
    if not runtime_status["ollama_available"]:
        print("Ollama: OFFLINE")
        print("\nCASCADE NOT VERIFIED (Ollama daemon unreachable at 127.0.0.1:11434)")
        print("=" * 40)
        return False
    print("Ollama READY")

    installed = runtime_status["installed_models"]
    has_3b = any(PINNED_3B_MODEL in m for m in installed)
    has_7b = any(PINNED_7B_MODEL in m for m in installed)

    if not has_3b:
        print(f"3B Model: MISSING ({PINNED_3B_MODEL} not installed in Ollama)")
        print("\nCASCADE NOT VERIFIED")
        print("=" * 40)
        return False

    if not has_7b:
        print(f"7B Model: MISSING ({PINNED_7B_MODEL} not installed in Ollama)")
        print("\nCASCADE NOT VERIFIED")
        print("=" * 40)
        return False

    # Create canonical verification pack
    pack = LosslessStructuralPack(
        schema_version="2.0.0",
        asset_id="ASSET-VERIFY-CASCADE-01",
        endpoint_id="EP-VERIFY-01",
        route_template="/api/v1/tenants/{tenant_id}/records",
        http_method="POST",
        application_mutability="STATE_CHANGING",
        observed_facts=[
            {
                "fact_id": "FACT-VERIFY-01",
                "statement": "POST /api/v1/tenants/{tenant_id}/records accepts JSON payload with record_id.",
            },
            {
                "fact_id": "FACT-VERIFY-02",
                "statement": "Server returns HTTP 200 with tenant record when tenant_id matches session context.",
            },
        ],
    )

    # Execute cascade
    trace, hypothesis = orchestrator.execute_cascade(pack, task_type="CASCADE_SWEEP")

    # Inspect Stage 1: 3B
    print(f"\n3B:\n{PINNED_3B_MODEL}")
    stage1 = next((s for s in trace.stages if "Stage 1" in s.stage_name), None)
    if not stage1 or stage1.status != "COMPLETED":
        print("INVOCATION: FAIL")
        print(f"Details: {stage1.details if stage1 else 'Stage missing'}")
        print("\nCASCADE NOT VERIFIED")
        print("=" * 40)
        return False
    print(f"INVOCATION: PASS (latency: {stage1.latency_seconds}s)")
    if verbose:
        print(f"  Decision: {stage1.details.get('decision')}")
        print(f"  Rationale: {stage1.details.get('rationale')}")

    # Inspect Stage 2: Router
    print("\nRouter:")
    stage2 = next((s for s in trace.stages if "Stage 2" in s.stage_name), None)
    if not stage2 or stage2.status != "COMPLETED":
        print("INVOCATION: FAIL")
        print("\nCASCADE NOT VERIFIED")
        print("=" * 40)
        return False
    print("INVOCATION: PASS")
    print(f"DECISION: {trace.routing_decision}")
    if verbose:
        print(f"  Escalation Reasons: {stage2.details.get('reasons')}")

    # Inspect Stage 3: Handoff
    print("\n3B -> 7B HANDOFF:")
    stage3 = next((s for s in trace.stages if "Stage 3" in s.stage_name), None)
    if not stage3 or stage3.status != "COMPLETED" or not trace.handoff_provenance_hash:
        print("FAIL")
        print("\nCASCADE NOT VERIFIED")
        print("=" * 40)
        return False
    print(f"PASS (provenance hash: {trace.handoff_provenance_hash[:16]}...)")

    # Inspect Stage 4: 7B
    print(f"\n7B:\n{PINNED_7B_MODEL}")
    stage4 = next((s for s in trace.stages if "Stage 4" in s.stage_name), None)
    if not stage4 or stage4.status != "COMPLETED":
        print("INVOCATION: FAIL")
        if stage4:
            print(f"Details: {stage4.details}")
        print("\nCASCADE NOT VERIFIED")
        print("=" * 40)
        return False
    print(f"INVOCATION: PASS (latency: {stage4.latency_seconds}s)")
    if verbose and hypothesis:
        print(f"  Category: {hypothesis.get('category')}")
        print(f"  Summary: {hypothesis.get('reasoning_summary')}")

    print("\nOverall:")
    print("CASCADE VERIFIED")
    print("=" * 40)
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify 3B -> Router -> 7B research cascade.")
    parser.add_argument("--verify-cascade", action="store_true", help="Run empirical cascade verification.")
    parser.add_argument("--verbose", "-v", action="store_true", help="Print detailed stage reasoning.")
    args = parser.parse_args()

    if args.verify_cascade:
        success = run_cascade_verification(verbose=args.verbose)
        sys.exit(0 if success else 1)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
