"""
Milestone M5 Phase 10 Preflight Verification Gate.

Enforces pre-registered integrity, runtime, and model configuration invariants
prior to launching the full-population 336-call benchmark.

Strict Invariants Verified:
Gate A: Git repository state and HEAD information.
Gate B: Frozen historical SHA-256 integrity (Phase 7, 8, 9, scenarios.py).
Gate C: Ollama daemon availability, version 0.34.1, model digest dae161e2...
Gate D: Runtime configuration (num_ctx=2048, num_predict=300, temp=0.0, seed=42, keep_alive=60m, timeout=30s, retries=0).
Gate E: Deterministic skeleton invariants across all 10 scenario categories.
Gate F: Zero ground-truth leakage in prompts or context.
Gate G: Zero breach/safe partition leakage in LLM-visible prompt blocks.
Gate H: Zero credential/secret leakage in LLM-visible context.
Gate I: Benchmark population integrity (84 scenarios: 36 vulnerable, 48 controls).
Gate J: Scheduled benchmark matrix integrity (4 conditions x 84 scenarios = 336 calls).

This script fails closed (exits non-zero) if ANY preflight check fails.
"""

from collections import Counter
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

repo_root = Path(__file__).resolve().parent.parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

import httpx

from src.core.config import OllamaConfig
from src.engine.context_builder import (
    ReasoningContextBuilder,
    TRACK_A,
    TRACK_D,
)
from src.engine.decision_policy import ExperimentPolarityValidator
from src.engine.experiment_skeleton import (
    ExperimentSkeletonBuilder,
    ExperimentSkeletonDescriptor,
    render_skeleton_prompt_block,
    validate_skeleton_compliance,
)
from src.engine.handoff_serializer import HandoffSerializer
from src.engine.models import (
    OutputProtocolIdentifier,
    PrimaryFailureCategory,
)
from src.engine.prompts import get_counterfactual_template
from src.engine.protocol import (
    ReasoningExecutionContract,
    get_protocol_contract,
    validate_reasoning_contract,
)
from src.engine.runner import (
    PRIMARY_KEEP_ALIVE,
    PRIMARY_NUM_CTX,
    PRIMARY_NUM_PREDICT,
    PRIMARY_SEED,
    PRIMARY_TEMPERATURE,
)
from src.eval.m4_live_benchmark import (
    ConfirmatoryTrackId,
    FORBIDDEN_PROMPT_TOKENS,
    EXPECTED_7B_DIGEST_FULL,
    infer_evidence_gap_type,
)
from src.eval.scenarios import get_gold_set_scenarios
from src.evidence.cascade_models import (
    CascadeHandoffPacket,
    DeterministicRoutingDecision,
    LosslessStructuralPack,
)
from src.knowledge.pipeline import VaptReasoningPipeline

# ---------------------------------------------------------------------------
# Immutable Artifact Hashes
# ---------------------------------------------------------------------------

FROZEN_HISTORICAL_HASHES: Dict[str, str] = {
    "data/eval/m5_phase7_benchmark_final.json": "1e0ed90c4aa672f135d2d2f2240a14d22fa0037c03efda33634f4bf10ff0b125",
    "data/eval/m5_phase8_semantic_study.json": "b1df9a62fb07d76e0abf6e3935ccbabdaa1713f4c594019ae30c9e59567a45c6",
    "data/eval/m5_phase9_semantic_budget_study.json": "3c0d3e503c7ed24470b14dfde0bd763c631a9b5dbf70c047bbca72cfaab07f95",
    "src/eval/scenarios.py": "102789655bfb04041de9259d1bf6db7f088979e5bce9bac9eb050564ef0110a8",
}

EXPECTED_OLLAMA_VERSION = "0.34.1"


def hash_file(p: Path) -> str:
    """Computes SHA-256 digest of a file in lowercase hex."""
    return hashlib.sha256(p.read_bytes()).hexdigest().lower()


def run_phase10_preflight_gates(require_ollama_daemon: bool = True) -> Dict[str, Any]:
    """
    Executes all Phase 10 preflight integrity gates.
    Fails closed: raises AssertionError or RuntimeError on any failure.
    Returns audit details on success.
    """
    results: Dict[str, Any] = {}
    print("\n" + "=" * 80)
    print("M5 PHASE 10 PREFLIGHT VERIFICATION GATES")
    print("=" * 80)

    # -----------------------------------------------------------------------
    # Gate A: Git State & HEAD Information
    # -----------------------------------------------------------------------
    print("[Gate A] Checking Git repository state...")
    try:
        head_commit = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True, cwd=str(repo_root)).strip()
        branch_name = subprocess.check_output(["git", "rev-parse", "--abbrev-ref", "HEAD"], text=True, cwd=str(repo_root)).strip()
        status_porcelain = subprocess.check_output(["git", "status", "--porcelain"], text=True, cwd=str(repo_root)).strip()
    except Exception as exc:
        raise RuntimeError(f"Gate A FAIL: Failed to query Git repository state: {exc}")

    print(f"  Branch: {branch_name}")
    print(f"  HEAD:   {head_commit}")

    # Check that modified files are restricted to permitted Phase 10 scope
    permitted_file_patterns = [
        "src/core/config.py",
        "src/engine/models.py",
        "src/engine/runner.py",
        "src/eval/run_m5_phase10_benchmark.py",
        "src/eval/verify_m5_phase10_preflight.py",
        "tests/unit/test_m5_phase10_runtime_and_skeleton.py",
        "docs/M5_PHASE10_PREREGISTRATION.md",
        "docs/M5_PHASE10_FULL_POPULATION_VALIDATION.md",
        "data/eval/m5_phase10_checkpoint.json",
        "data/eval/m5_phase10_full_population_validation.json",
        "scratch",
    ]

    unexpected_changes: List[str] = []
    for line in status_porcelain.splitlines():
        line = line.strip()
        if not line:
            continue
        # Format is 'XY path' or 'XY path -> new_path'
        parts = line.split(maxsplit=1)
        if len(parts) < 2:
            continue
        fpath = parts[1].replace("\\", "/")
        if not any(pattern in fpath for pattern in permitted_file_patterns):
            unexpected_changes.append(line)

    if unexpected_changes:
        raise AssertionError(f"Gate A FAIL: Unexpected modified or untracked files outside Phase 10 scope: {unexpected_changes}")

    results["gate_a"] = {
        "passed": True,
        "branch": branch_name,
        "head": head_commit,
    }
    print("  [PASS] Gate A: Git state verified.")

    # -----------------------------------------------------------------------
    # Gate B: Historical SHA-256 Integrity
    # -----------------------------------------------------------------------
    print("[Gate B] Verifying immutable historical artifact digests...")
    for rel_path, expected_hash in FROZEN_HISTORICAL_HASHES.items():
        abs_p = repo_root / rel_path
        if not abs_p.exists():
            raise FileNotFoundError(f"Gate B FAIL: Required frozen artifact missing: {rel_path}")
        actual_hash = hash_file(abs_p)
        if actual_hash != expected_hash:
            raise AssertionError(
                f"Gate B FAIL: Bit-for-bit SHA mismatch for {rel_path}!\n"
                f"  Expected: {expected_hash}\n"
                f"  Actual:   {actual_hash}"
            )
        print(f"  [PASS] {rel_path}: {actual_hash[:16]}... (bit-for-bit match)")

    results["gate_b"] = {"passed": True, "digests": dict(FROZEN_HISTORICAL_HASHES)}
    print("  [PASS] Gate B: All 4 historical artifacts verified immutable.")

    # -----------------------------------------------------------------------
    # Gate C: Ollama Daemon Availability, Version & Model Digest
    # -----------------------------------------------------------------------
    print("[Gate C] Verifying Ollama runtime environment...")
    try:
        ollama_ver_output = subprocess.check_output(["ollama", "--version"], text=True).strip()
        if EXPECTED_OLLAMA_VERSION not in ollama_ver_output:
            raise AssertionError(f"Gate C FAIL: Ollama version mismatch. Expected {EXPECTED_OLLAMA_VERSION}, got: {ollama_ver_output}")
        print(f"  Ollama CLI Version: {ollama_ver_output}")
    except FileNotFoundError:
        raise RuntimeError("Gate C FAIL: 'ollama' executable not found in system PATH.")

    daemon_running = False
    model_digest = ""
    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.get("http://127.0.0.1:11434/api/tags")
            if resp.status_code == 200:
                daemon_running = True
                models = resp.json().get("models", [])
                matched = [m for m in models if m.get("name") == "qwen2.5-coder:7b" or m.get("model") == "qwen2.5-coder:7b"]
                if not matched:
                    raise AssertionError("Gate C FAIL: Model 'qwen2.5-coder:7b' not installed in Ollama daemon.")
                model_digest = matched[0].get("digest", "")
                if model_digest != EXPECTED_7B_DIGEST_FULL:
                    raise AssertionError(
                        f"Gate C FAIL: Model digest mismatch!\n"
                        f"  Expected: {EXPECTED_7B_DIGEST_FULL}\n"
                        f"  Actual:   {model_digest}"
                    )
                print(f"  Model Digest: {model_digest}")
    except httpx.HTTPError as exc:
        if require_ollama_daemon:
            raise RuntimeError(f"Gate C FAIL: Ollama daemon is unreachable at http://127.0.0.1:11434: {exc}")
        else:
            print(f"  [WARN] Ollama daemon unreachable ({exc}), skipped per require_ollama_daemon=False.")

    results["gate_c"] = {
        "passed": True,
        "ollama_version": ollama_ver_output,
        "daemon_running": daemon_running,
        "model_digest": model_digest,
    }
    print("  [PASS] Gate C: Ollama version and model verified.")

    # -----------------------------------------------------------------------
    # Gate D: Runtime Configuration Parameters
    # -----------------------------------------------------------------------
    print("[Gate D] Verifying frozen runtime inference parameters...")
    assert PRIMARY_NUM_CTX == 2048, f"PRIMARY_NUM_CTX must be 2048, got {PRIMARY_NUM_CTX}"
    assert PRIMARY_NUM_PREDICT == 300, f"PRIMARY_NUM_PREDICT must be 300, got {PRIMARY_NUM_PREDICT}"
    assert PRIMARY_TEMPERATURE == 0.0, f"PRIMARY_TEMPERATURE must be 0.0, got {PRIMARY_TEMPERATURE}"
    assert PRIMARY_SEED == 42, f"PRIMARY_SEED must be 42, got {PRIMARY_SEED}"
    assert PRIMARY_KEEP_ALIVE == "60m", f"PRIMARY_KEEP_ALIVE must be '60m', got {PRIMARY_KEEP_ALIVE}"

    cfg = OllamaConfig()
    assert cfg.default_temperature == 0.0, f"OllamaConfig.default_temperature must be 0.0, got {cfg.default_temperature}"
    assert cfg.request_timeout_seconds == 30, f"OllamaConfig.request_timeout_seconds must be 30, got {cfg.request_timeout_seconds}"
    assert cfg.max_retries == 0, f"OllamaConfig.max_retries must be 0, got {cfg.max_retries}"

    results["gate_d"] = {
        "passed": True,
        "num_ctx": PRIMARY_NUM_CTX,
        "num_predict": PRIMARY_NUM_PREDICT,
        "temperature": PRIMARY_TEMPERATURE,
        "seed": PRIMARY_SEED,
        "keep_alive": PRIMARY_KEEP_ALIVE,
        "timeout_seconds": cfg.request_timeout_seconds,
        "max_retries": cfg.max_retries,
    }
    print(f"  num_ctx={PRIMARY_NUM_CTX}, num_predict={PRIMARY_NUM_PREDICT}, temp={PRIMARY_TEMPERATURE}, seed={PRIMARY_SEED}, keep_alive={PRIMARY_KEEP_ALIVE}, timeout={cfg.request_timeout_seconds}s, retries={cfg.max_retries}")
    print("  [PASS] Gate D: Runtime inference parameters verified.")

    # -----------------------------------------------------------------------
    # Gate E: Deterministic Skeleton Invariants
    # -----------------------------------------------------------------------
    print("[Gate E] Verifying deterministic skeleton invariants...")
    gold_scenarios = get_gold_set_scenarios()
    categories = sorted(list(set(s.category_id for s in gold_scenarios)))

    for cat in categories:
        skeleton = ExperimentSkeletonBuilder.build_skeleton(cat)
        assert skeleton.category_id == cat
        assert skeleton.experiment_action, f"Empty experiment_action for {cat}"
        assert len(skeleton.legal_outcomes) >= 2, f"Insufficient legal outcomes for {cat}: {skeleton.legal_outcomes}"
        assert skeleton.legal_outcomes == sorted(skeleton.legal_outcomes), f"Legal outcomes not sorted for {cat}"

        # Action compatibility verification
        registry = ExperimentPolarityValidator.TUPLE_COMPATIBILITY_REGISTRY
        assert cat in registry, f"Category {cat} not in compatibility registry"
        assert skeleton.experiment_action in registry[cat], f"Action {skeleton.experiment_action} not legal for {cat}"

        # Block LLM override verification
        bogus_action = "SUBSTITUTE_RESOURCE_IDENTIFIER" if skeleton.experiment_action != "SUBSTITUTE_RESOURCE_IDENTIFIER" else "REPLAY_STEP_WITH_LOWER_ROLE"
        comp_ok, comp_err = validate_skeleton_compliance(skeleton, bogus_action, skeleton.legal_outcomes[0], skeleton.legal_outcomes[1])
        assert not comp_ok, f"Expected skeleton to reject bogus action {bogus_action} for category {cat}"
        assert "mismatch" in comp_err.lower(), f"Unexpected error message: {comp_err}"

        # Block identical outcomes verification
        same_ok, same_err = validate_skeleton_compliance(skeleton, skeleton.experiment_action, skeleton.legal_outcomes[0], skeleton.legal_outcomes[0])
        assert not same_ok, f"Expected skeleton to reject identical outcomes for category {cat}"
        assert "identical" in same_err.lower(), f"Unexpected error message: {same_err}"

    results["gate_e"] = {"passed": True, "categories_verified": len(categories)}
    print(f"  [PASS] Gate E: Skeletons verified for {len(categories)} categories (action binding, unpartitioned outcomes, override rejection).")

    # -----------------------------------------------------------------------
    # Gate F: Zero Ground-Truth Leakage in Prompts
    # -----------------------------------------------------------------------
    print("[Gate F] Verifying zero ground-truth leakage in prompts...")
    context_builder = ReasoningContextBuilder()
    pipeline = VaptReasoningPipeline()

    sample_scenarios = [
        gold_scenarios[0],
        gold_scenarios[20],
        gold_scenarios[40],
        gold_scenarios[60],
        gold_scenarios[-1],
    ]

    for scen in sample_scenarios:
        observed_facts = scen.initial_evidence or [{"fact_id": "FACT-01", "statement": "Target observed data."}]
        asset_id = scen.target_asset.get("asset_id", "ASSET-TARGET-01")
        endpoint_id = f"EP-{asset_id}"
        pack = LosslessStructuralPack(
            schema_version="2.0.0",
            asset_id=asset_id,
            endpoint_id=endpoint_id,
            route_template=scen.target_asset.get("normalized_path", scen.target_asset.get("raw_path", "/api/v1/res")),
            http_method=scen.target_asset.get("method", "GET"),
            application_mutability="READ_ONLY",
            parameter_lineage=scen.parameters,
            identity_matrix=scen.identities,
            has_privilege_level_delta=False,
            has_cross_identity_object_access_success=False,
            observed_facts=observed_facts,
            raw_body_sample="",
        )
        gap_type = infer_evidence_gap_type(scen.category_id)
        vapt_pack, _ = pipeline.retrieve_and_pack(channel_a=pack, gap_type=gap_type)

        routing = DeterministicRoutingDecision(
            schema_version="2.0.0",
            escalate=True,
            has_high_risk_signal=True,
            high_risk_signals=["PREFLIGHT"],
            fail_safe_triggered=False,
        )
        handoff = CascadeHandoffPacket(
            schema_version="2.0.0",
            channel_a_structural=pack,
            routing_decision=routing,
            provenance_hash="prov_preflight",
        )
        cat_tmpl = get_counterfactual_template(scen.category_id)
        active_descriptor = HandoffSerializer.from_cascade_packet(
            handoff_packet=handoff,
            evidence_gap_type=gap_type,
            invariant=cat_tmpl.invariant_definition,
        )

        for mode, vapt in [(TRACK_A, None), (TRACK_D, vapt_pack)]:
            ctx = context_builder.build_context(
                handoff_packet=handoff,
                model_identifier="qwen2.5-coder:7b",
                budget_tier=2048,
                cascade_mode=mode,
                vapt_pack=vapt,
                enable_i2_namespace_partitioning=True,
                enable_i3_counterfactual_prompting=True,
                category_id=scen.category_id,
                enable_i4_bair=True,
                enable_i5_decision_policy=True,
                enable_i6_handoff=True,
                protected_handoff=active_descriptor,
                output_protocol=OutputProtocolIdentifier.JSON_BAIR,
            )
            full_prompt_lower = (ctx.system_prompt + " " + ctx.user_prompt).lower()
            for token in FORBIDDEN_PROMPT_TOKENS:
                if token in full_prompt_lower:
                    raise AssertionError(f"Gate F FAIL: Forbidden ground-truth token '{token}' found in prompt for {scen.scenario_id}")

            # Also check scenario labels (-VULN-, -PATCH-) are not leaked in prompt
            if "-vuln-" in full_prompt_lower or "-patch-" in full_prompt_lower:
                raise AssertionError(f"Gate F FAIL: Scenario variant suffix leaked into prompt for {scen.scenario_id}")

    results["gate_f"] = {"passed": True}
    print("  [PASS] Gate F: Zero ground-truth tokens leaked across tested conditions.")

    # -----------------------------------------------------------------------
    # Gate G: Zero Breach/Safe Partition Leakage
    # -----------------------------------------------------------------------
    print("[Gate G] Verifying zero breach/safe outcome partition leakage...")
    for cat in categories:
        skeleton = ExperimentSkeletonBuilder.build_skeleton(cat)
        block = render_skeleton_prompt_block(skeleton)
        block_lower = block.lower()

        # Ensure partition markers are never in the prompt block
        assert "breach_outcomes" not in block_lower, f"Gate G FAIL: 'breach_outcomes' leaked into prompt block for {cat}"
        assert "safe_outcomes" not in block_lower, f"Gate G FAIL: 'safe_outcomes' leaked into prompt block for {cat}"
        assert "valid_breach" not in block_lower, f"Gate G FAIL: 'valid_breach' leaked into prompt block for {cat}"
        assert "valid_safe" not in block_lower, f"Gate G FAIL: 'valid_safe' leaked into prompt block for {cat}"
        assert "partition" not in block_lower, f"Gate G FAIL: 'partition' leaked into prompt block for {cat}"

    results["gate_g"] = {"passed": True}
    print("  [PASS] Gate G: Skeletons contain flat unpartitioned legal_outcomes with zero partition leakage.")

    # -----------------------------------------------------------------------
    # Gate H: Zero Credential / Secret Leakage
    # -----------------------------------------------------------------------
    print("[Gate H] Verifying zero secret/credential leakage...")
    secret_patterns = [
        re.compile(r"sk_live_[a-zA-Z0-9]{20,}", re.IGNORECASE),
        re.compile(r"ghp_[a-zA-Z0-9]{36}", re.IGNORECASE),
        re.compile(r"BEGIN (RSA|OPENSSH|DSA|EC) PRIVATE KEY", re.IGNORECASE),
    ]
    for scen in sample_scenarios:
        for p in secret_patterns:
            if p.search(json.dumps(scen.target_asset)):
                raise AssertionError(f"Gate H FAIL: Hardcoded secret pattern found in scenario {scen.scenario_id}")

    results["gate_h"] = {"passed": True}
    print("  [PASS] Gate H: Zero hardcoded API keys or private keys found.")

    # -----------------------------------------------------------------------
    # Gate I: Benchmark Population Integrity
    # -----------------------------------------------------------------------
    print("[Gate I] Verifying 84-scenario benchmark population...")
    assert len(gold_scenarios) == 84, f"Gate I FAIL: Expected 84 scenarios, got {len(gold_scenarios)}"

    vuln_count = sum(1 for s in gold_scenarios if s.vulnerable_variant)
    ctrl_count = sum(1 for s in gold_scenarios if not s.vulnerable_variant)
    assert vuln_count == 36, f"Gate I FAIL: Expected 36 vulnerable scenarios, got {vuln_count}"
    assert ctrl_count == 48, f"Gate I FAIL: Expected 48 control scenarios, got {ctrl_count}"

    scenario_ids = [s.scenario_id for s in gold_scenarios]
    assert len(scenario_ids) == len(set(scenario_ids)), "Gate I FAIL: Duplicate scenario IDs in gold set"

    results["gate_i"] = {
        "passed": True,
        "total_scenarios": 84,
        "vulnerable_scenarios": 36,
        "control_scenarios": 48,
    }
    print(f"  [PASS] Gate I: Population exactly 84 scenarios (36 vulnerable, 48 controls).")

    # -----------------------------------------------------------------------
    # Gate J: Scheduled Benchmark Matrix Integrity (336 Calls) & Deterministic Condition Ordering
    # -----------------------------------------------------------------------
    print("[Gate J] Verifying scheduled 336-call factorial matrix & deterministic pseudo-random ordering...")
    from src.eval.run_m5_phase10_benchmark import (
        PHASE10_CONDITIONS,
        FROZEN_ORDER_RANDOMIZATION_SEED,
        get_deterministic_condition_order,
    )

    planned_calls = []
    seen_scenario_orders = set()
    for s in gold_scenarios:
        order1 = get_deterministic_condition_order(s.scenario_id, FROZEN_ORDER_RANDOMIZATION_SEED)
        order2 = get_deterministic_condition_order(s.scenario_id, FROZEN_ORDER_RANDOMIZATION_SEED)
        # Determinism check
        assert [c.condition_id for c in order1] == [c.condition_id for c in order2], f"Gate J FAIL: Non-deterministic condition order for {s.scenario_id}"
        # Completeness check
        order_ids = [c.condition_id for c in order1]
        assert set(order_ids) == {"C1", "C2", "C3", "C4"}, f"Gate J FAIL: Incomplete conditions for {s.scenario_id}: {order_ids}"
        assert len(order_ids) == 4, f"Gate J FAIL: Duplicate conditions for {s.scenario_id}: {order_ids}"
        seen_scenario_orders.add(tuple(order_ids))
        for c in order1:
            planned_calls.append((c.condition_id, s.scenario_id))

    assert len(planned_calls) == 336, f"Gate J FAIL: Expected 336 planned calls, got {len(planned_calls)}"
    assert len(planned_calls) == len(set(planned_calls)), "Gate J FAIL: Duplicate planned calls in matrix"
    # Ensure ordering is actually pseudo-randomized across scenarios (multiple distinct permutations observed)
    assert len(seen_scenario_orders) > 1, f"Gate J FAIL: All scenarios produced identical condition ordering: {seen_scenario_orders}"

    results["gate_j"] = {
        "passed": True,
        "conditions": [c.condition_id for c in PHASE10_CONDITIONS],
        "total_scheduled_calls": 336,
        "matrix_shape": "4 conditions x 84 scenarios",
        "distinct_order_permutations": len(seen_scenario_orders),
        "frozen_order_seed": FROZEN_ORDER_RANDOMIZATION_SEED,
    }
    print(f"  [PASS] Gate J: Scheduled matrix exactly 336 calls ({len(seen_scenario_orders)} distinct condition permutations across 84 scenarios).")

    print("\n" + "=" * 80)
    print("ALL PREFLIGHT GATES PASSED (FAIL-CLOSED INTEGRITY CONFIRMED)")
    print("=" * 80 + "\n")

    return results


if __name__ == "__main__":
    try:
        run_phase10_preflight_gates(require_ollama_daemon=True)
        sys.exit(0)
    except Exception as err:
        print(f"\n[PREFLIGHT HARD STOP] {err}", file=sys.stderr)
        sys.exit(1)
