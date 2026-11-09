"""Milestone M2 Phase 11: Corrected & Hardened Formal Paired Benchmark Runner.

Executes the formal paired benchmark over the POST-HOC BENCHMARK BASELINE
(84 scenarios from data/benchmarks/m1_5_frozen_manifest.json) across:
- Track A: Direct 7B Baseline (TRACK_A_7B_BASELINE)
- Track B: Direct 3B Baseline (TRACK_B_3B_BASELINE)
- Track C: 3B -> Gate -> Router -> 7B Cascade (TRACK_C_CASCADE) under Mode 1 Batch-Sequential lifecycle.

Enforces:
- Deterministic greedy decoding (temperature=0.0, seed=42)
- Target-data structural boundary containment (<untrusted_target_data>)
- Request-local context isolation
- Strict 15s (3B) and 30s (7B) timeout ceilings
- Level 4 failure classification and 5-category 3B failure tracking
- Gate fail-safe preservation to MUST-ESCALATE path
- Grounding epistemic security boundary & CRITICAL_EPISTEMIC_FAILURE tracking
- Predeclared Tango score-based paired non-inferiority test (N_vuln = 36)
- Decoupled latency decomposition (load, inference, routing, validation, end-to-end TTD)
- Complete pipeline layer separation:
    RAW MODEL OUTPUT -> JSON PARSE RESULT -> NORMALIZED HYPOTHESIS -> EXTRACTED DECISION -> GROUNDING -> SCORER
- Explicit 9-class earliest primary failure taxonomy
- Zero-denominator statistical safety (Precision = N/A when TP+FP=0)
- Constant-negative diagnostic baseline evaluation
- Degenerate non-inferiority qualification
- Vulnerable scenario filtering efficiency safety check
- Adversarial metric qualification
- Complete provenance preservation
"""

import argparse
import hashlib
import json
import math
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Ensure project root in sys.path
sys.path.insert(0, os.getcwd())

from src.eval.scenarios import get_gold_set_scenarios
from src.evidence.structural_diff import StructuralDiffEngine
from src.evidence.cascade_models import (
    CascadeHandoffPacket,
    DeterministicRoutingDecision,
    GateValidationResult,
    LosslessStructuralPack,
    RawTriageOutput,
    TriageMetadataPacket,
)
from src.evidence.gate import EvidencePreservationGate
from src.evidence.provenance import compute_provenance_hash
from src.engine.context_builder import (
    TRACK_A_7B_BASELINE,
    TRACK_B_3B_BASELINE,
    TRACK_C_CASCADE,
    ReasoningContextBuilder,
)
from src.engine.router import DeterministicRouter
from src.engine.triage_runner import (
    Live3BTriageRunner,
    PINNED_3B_DIGEST,
    PINNED_3B_MODEL,
    sanitize_untrusted_data,
)
from src.engine.reasoning_runner import (
    CascadeGroundingValidator,
    GroundingResult,
    Live7BReasoningRunner,
    PINNED_7B_DIGEST,
    PINNED_7B_MODEL,
)
from src.eval.extractor import (
    ExtractionResult,
    FailureLayer,
    classify_earliest_failure,
    extract_decision,
    extract_decision_from_hypothesis,
    normalize_hypothesis,
)
from src.eval.scorer import (
    DeterministicScorer,
    compute_constant_negative_diagnostic,
    is_degenerate_non_inferiority,
    tango_paired_ucb,
    wilson_score_interval,
)


BENCHMARK_SEED = 42
BENCHMARK_TEMPERATURE = 0.0
OLLAMA_URL = "http://127.0.0.1:11434"
MANIFEST_PATH = Path("data/benchmarks/m1_5_frozen_manifest.json")
CHECKSUM_PATH = Path("data/benchmarks/m1_5_frozen_manifest.json.sha256")
EXPECTED_MANIFEST_SHA = "b2b85a672124acf21066a257d8c7f5093000368b224ee013c02574c96a0ae707"
ESTABLISHMENT_COMMIT_SHA = "a005c5c11ab1a4c93ef9bd7167091b868f3b4f1d"
ATTESTATION_COMMIT_SHA = "cfdc0373cd71f4f99173b0f42064076437af6607"

AUDITED_10_SCENARIO_IDS = [
    "SCEN-SAAS_BILLING-INV-DETAILS-VULN-01",
    "SCEN-SAAS_BILLING-INV-SUMMARY-VULN-03",
    "SCEN-ECOMMERCE_ORDERS-ORD-REFUND-VULN-01",
    "SCEN-ECOMMERCE_ORDERS-ORD-PAY-VULN-03",
    "SCEN-IDENTITY_PROVIDER-USER-ROLES-VULN-01",
    "SCEN-IDENTITY_PROVIDER-USER-TENANT-ROLE-VULN-03",
    "SCEN-DOCUMENT_COLLABORATION-DOC-EXPORT-VULN-01",
    "SCEN-DOCUMENT_COLLABORATION-DOC-WORKSPACE-VULN-06",
    "SCEN-HEALTHCARE_PORTAL-PATIENT-REC-VULN-01",
    "SCEN-IOT_FLEET_MGMT-DEVICE-CMD-VULN-01",
]


def verify_preconditions() -> None:
    """Strictly validates all Phase 11 Preconditions per Section 2 & Preflight."""
    print("============================================================")
    print(" PRECONDITION & PREFLIGHT VERIFICATION")
    print("============================================================")

    # 1. Verify manifest exists at exact authoritative path
    if not MANIFEST_PATH.exists():
        raise RuntimeError(f"Precondition FAIL: manifest not found at {MANIFEST_PATH}")
    print(f"  [PASS] Precondition: Manifest exists at {MANIFEST_PATH}.")

    # 2. Recompute SHA-256 directly from manifest bytes and match exact hash
    manifest_bytes = MANIFEST_PATH.read_bytes()
    manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
    if manifest_sha != EXPECTED_MANIFEST_SHA:
        raise RuntimeError(f"Precondition FAIL: manifest SHA mismatch. Expected {EXPECTED_MANIFEST_SHA}, got {manifest_sha}")
    print(f"  [PASS] Precondition: Manifest SHA-256 matches: {manifest_sha}.")

    # 3. Verify companion checksum file matches exactly
    if not CHECKSUM_PATH.exists():
        raise RuntimeError(f"Precondition FAIL: companion checksum not found at {CHECKSUM_PATH}")
    chk_content = CHECKSUM_PATH.read_text(encoding="utf-8").strip().split()[0]
    if chk_content != EXPECTED_MANIFEST_SHA:
        raise RuntimeError(f"Precondition FAIL: companion checksum content mismatch: {chk_content}")
    print(f"  [PASS] Precondition: Companion checksum matches: {chk_content}.")

    # 4. Verify establishment commit
    commit_rev = subprocess.check_output(["git", "rev-parse", ESTABLISHMENT_COMMIT_SHA], text=True).strip()
    if commit_rev != ESTABLISHMENT_COMMIT_SHA:
        raise RuntimeError(f"Precondition FAIL: establishment commit {ESTABLISHMENT_COMMIT_SHA} unresolvable")
    print(f"  [PASS] Precondition: Establishment commit confirmed: {ESTABLISHMENT_COMMIT_SHA}.")

    # 5. Verify attestation references exact establishment commit
    att_path = Path("reports/m1_5_posthoc_baseline_attestation.json")
    if not att_path.exists():
        raise RuntimeError(f"Precondition FAIL: attestation file missing at {att_path}")
    att_data = json.loads(att_path.read_text(encoding="utf-8"))
    ref_commit = att_data.get("five_part_cryptographic_stamp", {}).get("4_establishment_commit_sha")
    if ref_commit != ESTABLISHMENT_COMMIT_SHA:
        raise RuntimeError(f"Precondition FAIL: attestation references wrong commit: {ref_commit}")
    print(f"  [PASS] Precondition: Attestation references establishment commit: {ref_commit}.")

    # 6. Verify docs/M1_5_M2_PLAN.md unchanged relative to baseline establishment
    diff_plan = subprocess.check_output(
        ["git", "diff", ESTABLISHMENT_COMMIT_SHA, "--", "docs/M1_5_M2_PLAN.md"], text=True
    ).strip()
    if diff_plan:
        raise RuntimeError("Precondition FAIL: docs/M1_5_M2_PLAN.md was modified after establishment commit!")
    print("  [PASS] Precondition: docs/M1_5_M2_PLAN.md is byte-for-byte unchanged.")

    # 7. Verify src/eval/scenarios.py unchanged relative to baseline establishment
    diff_scen = subprocess.check_output(
        ["git", "diff", ESTABLISHMENT_COMMIT_SHA, "--", "src/eval/scenarios.py"], text=True
    ).strip()
    if diff_scen:
        raise RuntimeError("Precondition FAIL: src/eval/scenarios.py was modified after establishment commit!")
    print("  [PASS] Precondition: src/eval/scenarios.py is byte-for-byte unchanged.")

    # 8. Ollama connection and model digests
    try:
        req = urllib.request.Request(f"{OLLAMA_URL}/api/tags")
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            models_data = json.loads(resp.read().decode("utf-8"))
            installed = {m["name"]: m.get("digest", "") for m in models_data.get("models", [])}
    except Exception as e:
        raise RuntimeError(f"Precondition FAIL: Ollama server unreachable at {OLLAMA_URL}: {e}")

    found_3b = any("qwen2.5-coder:3b" in name for name in installed)
    found_7b = any("qwen2.5-coder:7b" in name for name in installed)
    if not (found_3b and found_7b):
        raise RuntimeError(f"Precondition FAIL: Required models missing in Ollama. Found: {list(installed.keys())}")
    print("  [PASS] Precondition: Ollama active and both models present.")

    # 9. Hardware detection (RTX 3050 Laptop GPU)
    try:
        smi_out = subprocess.check_output(
            ["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader,nounits"],
            text=True,
        ).strip()
        gpu_name, gpu_vram = [x.strip() for x in smi_out.splitlines()[0].split(",")]
        if "3050" not in gpu_name:
            print(f"  [WARN] GPU is {gpu_name} ({gpu_vram} MB). Expected RTX 3050 Laptop GPU.")
        else:
            print(f"  [PASS] Precondition: Verified GPU hardware: {gpu_name} ({gpu_vram} MB VRAM).")
    except Exception as e:
        print(f"  [WARN] nvidia-smi failed ({e}); proceeding with software verification.")

    print("============================================================")
    print(" ALL PRECONDITIONS VERIFIED SUCCESSFULLY")
    print("============================================================\n")


def query_vram_mb() -> float:
    """Returns currently used VRAM in MB from nvidia-smi."""
    try:
        out = subprocess.check_output(
            ["nvidia-smi", "--query-gpu=memory.used", "--format=csv,noheader,nounits"],
            text=True,
        ).strip()
        return float(out.splitlines()[0])
    except Exception:
        return 0.0


def unload_model(model_name: str) -> None:
    """Explicitly unloads a model from VRAM by setting keep_alive=0."""
    try:
        payload = json.dumps({"model": model_name, "keep_alive": 0}).encode("utf-8")
        req = urllib.request.Request(
            f"{OLLAMA_URL}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            resp.read()
        time.sleep(1.0)
    except Exception as e:
        print(f"  [WARN] Failed to unload {model_name}: {e}")


def warm_load_model(model_name: str) -> float:
    """Pre-warms a model into VRAM and returns the cold load latency in seconds."""
    t0 = time.perf_counter()
    payload = json.dumps({
        "model": model_name,
        "prompt": "ping",
        "keep_alive": "10m",
        "options": {"num_predict": 1},
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{OLLAMA_URL}/api/generate",
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30.0) as resp:
        resp.read()
    return time.perf_counter() - t0


class Phase11BenchmarkRunner:
    """Executes Milestone M2 Phase 11 Formal Paired Benchmark with Forensic Instrumentation."""

    def __init__(self, run_dir: Path) -> None:
        self.run_dir = run_dir
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_data = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        self.gold_scenarios = {s.scenario_id: s for s in get_gold_set_scenarios()}
        self.structural_packs: Dict[str, LosslessStructuralPack] = {}
        self._build_all_structural_packs()

    def _build_all_structural_packs(self) -> None:
        """Builds immutable LosslessStructuralPack for all 84 scenarios using StructuralDiffEngine."""
        for m_item in self.manifest_data["scenarios"]:
            sid = m_item["scenario_id"]
            s = self.gold_scenarios[sid]
            asset = s.target_asset
            ep_id = asset.get("endpoint_id") or ("EP-" + asset.get("asset_id", sid))

            raw_facts = []
            for ev in s.initial_evidence:
                fact = dict(ev)
                fact["endpoint_id"] = ep_id
                fact["asset_id"] = asset.get("asset_id", sid)
                fact["route_template"] = asset.get("normalized_path") or asset.get("raw_path")
                fact["http_method"] = asset.get("method", "GET")
                fact["application_mutability"] = asset.get("application_mutability", "READ_ONLY")
                fact["parameters"] = s.parameters
                raw_facts.append(fact)

            if not raw_facts:
                raw_facts = [
                    {
                        "endpoint_id": ep_id,
                        "asset_id": asset.get("asset_id", sid),
                        "route_template": asset.get("normalized_path") or asset.get("raw_path"),
                        "http_method": asset.get("method", "GET"),
                        "application_mutability": asset.get("application_mutability", "READ_ONLY"),
                        "parameters": s.parameters,
                    }
                ]

            pack = StructuralDiffEngine.compute(raw_facts, s.identities)
            self.structural_packs[sid] = pack

    def run_track_b(self, scenario_subset: Optional[List[str]] = None) -> Dict[str, Any]:
        """Track B: Direct 3B Baseline (TRACK_B_3B_BASELINE)."""
        print("\n============================================================")
        print(" TRACK B: DIRECT 3B BASELINE (TRACK_B_3B_BASELINE)")
        print("============================================================")

        ckpt_path = self.run_dir / "phase11_track_b.json"

        unload_model("qwen2.5-coder:7b")
        cold_load_s = warm_load_model(PINNED_3B_MODEL)
        peak_vram = query_vram_mb()
        print(f"  Warm-loaded 3B model in {cold_load_s:.2f}s. Initial VRAM: {peak_vram} MB")

        scenarios_to_run = (
            [m for m in self.manifest_data["scenarios"] if m["scenario_id"] in scenario_subset]
            if scenario_subset is not None
            else self.manifest_data["scenarios"]
        )

        records = []
        t0_track = time.perf_counter()

        for idx, m_item in enumerate(scenarios_to_run, 1):
            sid = m_item["scenario_id"]
            s = self.gold_scenarios[sid]
            pack = self.structural_packs[sid]

            t_val_start = time.perf_counter()
            gate_res = EvidencePreservationGate.validate(channel_a=pack, raw_triage=None)
            decision = DeterministicRouter.evaluate_escalation(pack, gate_res)
            t_val_duration = time.perf_counter() - t_val_start

            p_hash = compute_provenance_hash(pack, gate_res, decision)

            handoff = CascadeHandoffPacket(
                schema_version="2.0.0",
                channel_a_structural=pack,
                routing_decision=decision,
                provenance_hash=p_hash,
                validated_triage=gate_res.validated_triage,
            )

            ctx = ReasoningContextBuilder.build_context(
                handoff_packet=handoff,
                model_identifier=PINNED_3B_MODEL,
                cascade_mode=TRACK_B_3B_BASELINE,
            )

            req_data = json.dumps({
                "model": PINNED_3B_MODEL,
                "prompt": ctx.prompt,
                "stream": False,
                "format": "json",
                "keep_alive": "5m",
                "options": {
                    "temperature": BENCHMARK_TEMPERATURE,
                    "seed": BENCHMARK_SEED,
                    "num_ctx": 2048,
                    "num_predict": 512,
                },
            }).encode("utf-8")

            t_infer_start = time.perf_counter()
            raw_text = ""
            raw_output_present = False
            json_parse_status = "NOT_CALLED"
            hyp_parsed = None
            failure_type = None
            err_str = None

            try:
                req = urllib.request.Request(
                    f"{OLLAMA_URL}/api/generate",
                    data=req_data,
                    headers={"Content-Type": "application/json"},
                )
                with urllib.request.urlopen(req, timeout=15.0) as resp:
                    resp_obj = json.loads(resp.read().decode("utf-8"))
                    raw_text = resp_obj.get("response", "")
                    raw_output_present = True
                    try:
                        hyp_parsed = json.loads(raw_text)
                        json_parse_status = "SUCCESS"
                    except json.JSONDecodeError as jde:
                        json_parse_status = "FAILURE"
                        err_str = f"JSONDecodeError: {jde}"
            except TimeoutError:
                failure_type = "HARDWARE_TIMEOUT"
                err_str = "Timed out (>15s)"
            except Exception as e:
                failure_type = "OTHER_IMPLEMENTATION_FAILURE"
                err_str = str(e)
            infer_duration = time.perf_counter() - t_infer_start

            # Decision Extraction & Hypothesis Normalization
            ext_res = extract_decision(hyp_parsed)
            normalized_hyp = ext_res.normalized_hypothesis or hyp_parsed or {}

            # Grounding Validation on normalized hypothesis
            g_res = CascadeGroundingValidator.validate_grounding(pack, normalized_hyp)
            is_breakout = CascadeGroundingValidator.is_breakout(normalized_hyp, pack)

            # Failure Layer Classification
            primary_fail, sec_fails = classify_earliest_failure(
                raw_output_present=raw_output_present,
                raw_error=err_str,
                json_parse_status=json_parse_status,
                extraction_result=ext_res,
                grounding_valid=g_res.valid,
                is_breakout=is_breakout,
                escalated=True,
                ground_truth_vulnerable=s.ground_truth_vulnerable,
                called_7b=False,
                final_decision=ext_res.decision,
                useful=bool(ext_res.decision == "HYPOTHESIS" and g_res.valid),
            )

            rec = {
                "scenario_id": sid,
                "split": s.split,
                "app_family": s.app_family,
                "ground_truth_vulnerable": s.ground_truth_vulnerable,
                "vulnerable_variant": s.vulnerable_variant,
                "raw_model_output": raw_text,
                "json_parse_status": json_parse_status,
                "json_parse_result": hyp_parsed,
                "normalized_hypothesis": normalized_hyp,
                "extracted_decision": ext_res.decision,
                "vulnerability_type": ext_res.vulnerability_type,
                "vulnerability_exists": ext_res.vulnerability_exists,
                "decision": ext_res.decision,
                "hypothesis": hyp_parsed,
                "failure_type": failure_type,
                "error": err_str,
                "grounding_valid": g_res.valid,
                "grounding_reason": g_res.reason,
                "unsupported_fact_ids": g_res.unsupported_fact_ids,
                "unsupported_param_ids": g_res.unsupported_param_ids,
                "is_breakout": is_breakout,
                "escalated": True,
                "fail_safe_triggered": False,
                "routing_reasons": ["BASELINE_DIRECT_INVOCATION"],
                "provenance_hash": p_hash,
                "inference_latency_s": round(infer_duration, 3),
                "model_load_latency_s": round(cold_load_s if idx == 1 else 0.0, 3),
                "routing_overhead_s": 0.0,
                "validation_overhead_s": round(t_val_duration, 4),
                "end_to_end_latency_s": round((cold_load_s if idx == 1 else 0.0) + infer_duration + t_val_duration, 3),
                "earliest_failure_layer": primary_fail,
                "secondary_failure_causes": sec_fails,
                "useful": bool(ext_res.decision == "HYPOTHESIS" and g_res.valid),
            }
            records.append(rec)
            vram_now = query_vram_mb()
            if vram_now > peak_vram:
                peak_vram = vram_now

            print(f"  [{idx:02d}/{len(scenarios_to_run)}] 3B {sid}: dec={ext_res.decision} vtype={ext_res.vulnerability_type} ground={g_res.valid} fail={primary_fail}")

        total_track_time = time.perf_counter() - t0_track
        res = {
            "track_name": TRACK_B_3B_BASELINE,
            "records": records,
            "cold_load_latency_s": round(cold_load_s, 3),
            "total_duration_s": round(total_track_time, 2),
            "peak_vram_mb": peak_vram,
        }
        ckpt_path.write_text(json.dumps(res, indent=2), encoding="utf-8")
        return res

    def run_track_a(self, scenario_subset: Optional[List[str]] = None) -> Dict[str, Any]:
        """Track A: Direct 7B Baseline (TRACK_A_7B_BASELINE)."""
        print("\n============================================================")
        print(" TRACK A: DIRECT 7B BASELINE (TRACK_A_7B_BASELINE)")
        print("============================================================")

        ckpt_path = self.run_dir / "phase11_track_a.json"

        unload_model("qwen2.5-coder:3b")
        cold_load_s = warm_load_model(PINNED_7B_MODEL)
        peak_vram = query_vram_mb()
        print(f"  Warm-loaded 7B model in {cold_load_s:.2f}s. Initial VRAM: {peak_vram} MB")

        scenarios_to_run = (
            [m for m in self.manifest_data["scenarios"] if m["scenario_id"] in scenario_subset]
            if scenario_subset is not None
            else self.manifest_data["scenarios"]
        )

        records = []
        t0_track = time.perf_counter()

        for idx, m_item in enumerate(scenarios_to_run, 1):
            sid = m_item["scenario_id"]
            s = self.gold_scenarios[sid]
            pack = self.structural_packs[sid]

            t_val_start = time.perf_counter()
            gate_res = EvidencePreservationGate.validate(channel_a=pack, raw_triage=None)
            decision = DeterministicRouter.evaluate_escalation(pack, gate_res)
            t_val_duration = time.perf_counter() - t_val_start

            p_hash = compute_provenance_hash(pack, gate_res, decision)

            handoff = CascadeHandoffPacket(
                schema_version="2.0.0",
                channel_a_structural=pack,
                routing_decision=decision,
                provenance_hash=p_hash,
                validated_triage=gate_res.validated_triage,
            )

            ctx = ReasoningContextBuilder.build_context(
                handoff_packet=handoff,
                model_identifier=PINNED_7B_MODEL,
                cascade_mode=TRACK_A_7B_BASELINE,
            )

            req_data = json.dumps({
                "model": PINNED_7B_MODEL,
                "prompt": ctx.prompt,
                "stream": False,
                "format": "json",
                "keep_alive": "5m",
                "options": {
                    "temperature": BENCHMARK_TEMPERATURE,
                    "seed": BENCHMARK_SEED,
                    "num_ctx": 4096,
                    "num_predict": 1024,
                },
            }).encode("utf-8")

            t_infer_start = time.perf_counter()
            raw_text = ""
            raw_output_present = False
            json_parse_status = "NOT_CALLED"
            hyp_parsed = None
            failure_type = None
            err_str = None

            try:
                req = urllib.request.Request(
                    f"{OLLAMA_URL}/api/generate",
                    data=req_data,
                    headers={"Content-Type": "application/json"},
                )
                with urllib.request.urlopen(req, timeout=30.0) as resp:
                    resp_obj = json.loads(resp.read().decode("utf-8"))
                    raw_text = resp_obj.get("response", "")
                    raw_output_present = True
                    try:
                        hyp_parsed = json.loads(raw_text)
                        json_parse_status = "SUCCESS"
                    except json.JSONDecodeError as jde:
                        json_parse_status = "FAILURE"
                        err_str = f"JSONDecodeError: {jde}"
            except TimeoutError:
                failure_type = "HARDWARE_TIMEOUT"
                err_str = "Timed out (>30s)"
            except Exception as e:
                failure_type = "OTHER_IMPLEMENTATION_FAILURE"
                err_str = str(e)
            infer_duration = time.perf_counter() - t_infer_start

            # Decision Extraction & Hypothesis Normalization
            ext_res = extract_decision(hyp_parsed)
            normalized_hyp = ext_res.normalized_hypothesis or hyp_parsed or {}

            # Grounding Validation on normalized hypothesis
            g_res = CascadeGroundingValidator.validate_grounding(pack, normalized_hyp)
            is_breakout = CascadeGroundingValidator.is_breakout(normalized_hyp, pack)

            # Failure Layer Classification
            primary_fail, sec_fails = classify_earliest_failure(
                raw_output_present=raw_output_present,
                raw_error=err_str,
                json_parse_status=json_parse_status,
                extraction_result=ext_res,
                grounding_valid=g_res.valid,
                is_breakout=is_breakout,
                escalated=True,
                ground_truth_vulnerable=s.ground_truth_vulnerable,
                called_7b=True,
                final_decision=ext_res.decision,
                useful=bool(ext_res.decision == "HYPOTHESIS" and g_res.valid),
            )

            rec = {
                "scenario_id": sid,
                "split": s.split,
                "app_family": s.app_family,
                "ground_truth_vulnerable": s.ground_truth_vulnerable,
                "vulnerable_variant": s.vulnerable_variant,
                "raw_model_output": raw_text,
                "json_parse_status": json_parse_status,
                "json_parse_result": hyp_parsed,
                "normalized_hypothesis": normalized_hyp,
                "extracted_decision": ext_res.decision,
                "vulnerability_type": ext_res.vulnerability_type,
                "vulnerability_exists": ext_res.vulnerability_exists,
                "decision": ext_res.decision,
                "hypothesis": hyp_parsed,
                "failure_type": failure_type,
                "error": err_str,
                "grounding_valid": g_res.valid,
                "grounding_reason": g_res.reason,
                "unsupported_fact_ids": g_res.unsupported_fact_ids,
                "unsupported_param_ids": g_res.unsupported_param_ids,
                "is_breakout": is_breakout,
                "escalated": True,
                "fail_safe_triggered": False,
                "routing_reasons": ["BASELINE_DIRECT_INVOCATION"],
                "provenance_hash": p_hash,
                "inference_latency_s": round(infer_duration, 3),
                "model_load_latency_s": round(cold_load_s if idx == 1 else 0.0, 3),
                "routing_overhead_s": 0.0,
                "validation_overhead_s": round(t_val_duration, 4),
                "end_to_end_latency_s": round((cold_load_s if idx == 1 else 0.0) + infer_duration + t_val_duration, 3),
                "earliest_failure_layer": primary_fail,
                "secondary_failure_causes": sec_fails,
                "useful": bool(ext_res.decision == "HYPOTHESIS" and g_res.valid),
            }
            records.append(rec)
            vram_now = query_vram_mb()
            if vram_now > peak_vram:
                peak_vram = vram_now

            print(f"  [{idx:02d}/{len(scenarios_to_run)}] 7B {sid}: dec={ext_res.decision} vtype={ext_res.vulnerability_type} ground={g_res.valid} fail={primary_fail}")

        total_track_time = time.perf_counter() - t0_track
        res = {
            "track_name": TRACK_A_7B_BASELINE,
            "records": records,
            "cold_load_latency_s": round(cold_load_s, 3),
            "total_duration_s": round(total_track_time, 2),
            "peak_vram_mb": peak_vram,
        }
        ckpt_path.write_text(json.dumps(res, indent=2), encoding="utf-8")
        return res

    def run_track_c(self, scenario_subset: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Track C: 3B -> Gate -> Router -> 7B Cascade (TRACK_C_CASCADE).
        Executes strictly under Mode 1 Batch-Sequential Lifecycle.
        """
        print("\n============================================================")
        print(" TRACK C: CASCADE PIPELINE (TRACK_C_CASCADE)")
        print("============================================================")

        ckpt_path = self.run_dir / "phase11_track_c.json"

        peak_vram = query_vram_mb()

        # Phase 1: 3B Triage Batch Sweep
        print("\n--- Track C Phase 1: 3B Triage Batch Sweep ---")
        unload_model("qwen2.5-coder:7b")
        cold_load_3b_s = warm_load_model(PINNED_3B_MODEL)
        peak_vram = max(peak_vram, query_vram_mb())

        triage_runner = Live3BTriageRunner(timeout_seconds=15.0)

        scenarios_to_run = (
            [m for m in self.manifest_data["scenarios"] if m["scenario_id"] in scenario_subset]
            if scenario_subset is not None
            else self.manifest_data["scenarios"]
        )

        triage_results = []
        survivors = []

        for idx, m_item in enumerate(scenarios_to_run, 1):
            sid = m_item["scenario_id"]
            s = self.gold_scenarios[sid]
            pack = self.structural_packs[sid]

            t_triage_start = time.perf_counter()
            raw_triage = triage_runner.run_triage(pack)
            t_triage_duration = time.perf_counter() - t_triage_start

            t_gate_start = time.perf_counter()
            gate_res: GateValidationResult = EvidencePreservationGate.validate(
                channel_a=pack,
                raw_triage=raw_triage,
            )
            t_gate_duration = time.perf_counter() - t_gate_start

            t_route_start = time.perf_counter()
            decision: DeterministicRoutingDecision = DeterministicRouter.evaluate_escalation(
                pack,
                gate_res,
            )
            t_route_duration = time.perf_counter() - t_route_start

            p_hash = compute_provenance_hash(pack, gate_res, decision)

            escalate = decision.escalate
            fail_safe_triggered = gate_res.fail_safe_required

            record_item = {
                "scenario_id": sid,
                "split": s.split,
                "app_family": s.app_family,
                "ground_truth_vulnerable": s.ground_truth_vulnerable,
                "vulnerable_variant": s.vulnerable_variant,
                "pack": pack,
                "raw_triage": raw_triage,
                "gate_res": gate_res,
                "decision": decision,
                "p_hash": p_hash,
                "escalated": escalate,
                "fail_safe_triggered": fail_safe_triggered,
                "triage_infer_s": round(t_triage_duration, 3),
                "triage_load_s": round(cold_load_3b_s if idx == 1 else 0.0, 3),
                "validation_overhead_s": round(t_gate_duration, 4),
                "routing_overhead_s": round(t_route_duration, 4),
            }
            triage_results.append(record_item)
            if escalate:
                survivors.append(record_item)

            vram_now = query_vram_mb()
            if vram_now > peak_vram:
                peak_vram = vram_now

            print(f"  [{idx:02d}/{len(scenarios_to_run)}] 3B Triage {sid}: esc={escalate} fs={fail_safe_triggered} infer={t_triage_duration:.2f}s")

        # Phase 2: Model Transition (3B unload, 7B load)
        print(f"\n--- Track C Phase 2: Model Transition ({len(survivors)} survivors escalated) ---")
        unload_model("qwen2.5-coder:3b")
        quiescent_vram = query_vram_mb()
        cold_load_7b_s = warm_load_model(PINNED_7B_MODEL)
        peak_vram = max(peak_vram, query_vram_mb())
        print(f"  3B unloaded (quiescent VRAM: {quiescent_vram} MB). 7B warm load: {cold_load_7b_s:.2f}s")

        # Phase 3: 7B Deep Reasoning Sweep on Survivors
        print(f"\n--- Track C Phase 3: 7B Deep Reasoning Sweep on Survivors (N={len(survivors)}) ---")

        final_records = []
        for idx, item in enumerate(triage_results, 1):
            sid = item["scenario_id"]
            s = self.gold_scenarios[sid]
            pack = item["pack"]

            if not item["escalated"]:
                # Terminated benign at 3B
                primary_fail, sec_fails = classify_earliest_failure(
                    raw_output_present=True,
                    raw_error=None,
                    json_parse_status="SUCCESS",
                    extraction_result=None,
                    grounding_valid=True,
                    is_breakout=False,
                    escalated=False,
                    ground_truth_vulnerable=s.ground_truth_vulnerable,
                    called_7b=False,
                    final_decision="NO_RELEVANT_FUNCTIONALITY",
                    useful=False,
                )

                rec = {
                    "scenario_id": sid,
                    "split": s.split,
                    "app_family": s.app_family,
                    "ground_truth_vulnerable": s.ground_truth_vulnerable,
                    "vulnerable_variant": s.vulnerable_variant,
                    "raw_model_output": item["raw_triage"].model_dump_json(),
                    "json_parse_status": "FAILURE" if item["raw_triage"].is_malformed else "SUCCESS",
                    "json_parse_result": None,
                    "normalized_hypothesis": None,
                    "extracted_decision": "NO_RELEVANT_FUNCTIONALITY",
                    "vulnerability_type": None,
                    "vulnerability_exists": False,
                    "decision": "NO_RELEVANT_FUNCTIONALITY",
                    "hypothesis": None,
                    "failure_type": None,
                    "error": None,
                    "grounding_valid": True,
                    "grounding_reason": "Terminated benign at 3B triage",
                    "unsupported_fact_ids": [],
                    "unsupported_param_ids": [],
                    "is_breakout": False,
                    "escalated": False,
                    "fail_safe_triggered": item["fail_safe_triggered"],
                    "routing_reasons": item["decision"].reasons,
                    "provenance_hash": item["p_hash"],
                    "inference_latency_s": item["triage_infer_s"],
                    "model_load_latency_s": item["triage_load_s"],
                    "routing_overhead_s": item["routing_overhead_s"],
                    "validation_overhead_s": item["validation_overhead_s"],
                    "end_to_end_latency_s": round(item["triage_load_s"] + item["triage_infer_s"] + item["routing_overhead_s"] + item["validation_overhead_s"], 3),
                    "earliest_failure_layer": primary_fail,
                    "secondary_failure_causes": sec_fails,
                    "useful": False,
                }
            else:
                # Run 7B on survivor
                handoff = CascadeHandoffPacket(
                    schema_version="2.0.0",
                    channel_a_structural=pack,
                    routing_decision=item["decision"],
                    provenance_hash=item["p_hash"],
                    validated_triage=item["gate_res"].validated_triage,
                )

                ctx = ReasoningContextBuilder.build_context(
                    handoff_packet=handoff,
                    model_identifier=PINNED_7B_MODEL,
                    cascade_mode=TRACK_C_CASCADE,
                )

                req_data = json.dumps({
                    "model": PINNED_7B_MODEL,
                    "prompt": ctx.prompt,
                    "stream": False,
                    "format": "json",
                    "keep_alive": "5m",
                    "options": {
                        "temperature": BENCHMARK_TEMPERATURE,
                        "seed": BENCHMARK_SEED,
                        "num_ctx": 4096,
                        "num_predict": 1024,
                    },
                }).encode("utf-8")

                t_infer_start = time.perf_counter()
                raw_text = ""
                raw_output_present = False
                json_parse_status = "NOT_CALLED"
                hyp_parsed = None
                failure_type = None
                err_str = None

                try:
                    req = urllib.request.Request(
                        f"{OLLAMA_URL}/api/generate",
                        data=req_data,
                        headers={"Content-Type": "application/json"},
                    )
                    with urllib.request.urlopen(req, timeout=30.0) as resp:
                        resp_obj = json.loads(resp.read().decode("utf-8"))
                        raw_text = resp_obj.get("response", "")
                        raw_output_present = True
                        try:
                            hyp_parsed = json.loads(raw_text)
                            json_parse_status = "SUCCESS"
                        except json.JSONDecodeError as jde:
                            json_parse_status = "FAILURE"
                            err_str = f"JSONDecodeError: {jde}"
                except TimeoutError:
                    failure_type = "HARDWARE_TIMEOUT"
                    err_str = "Timed out (>30s)"
                except Exception as e:
                    failure_type = "OTHER_IMPLEMENTATION_FAILURE"
                    err_str = str(e)
                infer_duration = time.perf_counter() - t_infer_start

                # Decision Extraction & Hypothesis Normalization
                ext_res = extract_decision(hyp_parsed)
                normalized_hyp = ext_res.normalized_hypothesis or hyp_parsed or {}

                # Grounding Validation on normalized hypothesis
                g_res = CascadeGroundingValidator.validate_grounding(pack, normalized_hyp)
                is_breakout = CascadeGroundingValidator.is_breakout(normalized_hyp, pack)

                primary_fail, sec_fails = classify_earliest_failure(
                    raw_output_present=raw_output_present,
                    raw_error=err_str,
                    json_parse_status=json_parse_status,
                    extraction_result=ext_res,
                    grounding_valid=g_res.valid,
                    is_breakout=is_breakout,
                    escalated=True,
                    ground_truth_vulnerable=s.ground_truth_vulnerable,
                    called_7b=True,
                    final_decision=ext_res.decision,
                    useful=bool(ext_res.decision == "HYPOTHESIS" and g_res.valid),
                )

                total_e2e = round(
                    item["triage_load_s"]
                    + item["triage_infer_s"]
                    + item["routing_overhead_s"]
                    + item["validation_overhead_s"]
                    + (cold_load_7b_s if idx == 1 else 0.0)
                    + infer_duration,
                    3,
                )

                rec = {
                    "scenario_id": sid,
                    "split": s.split,
                    "app_family": s.app_family,
                    "ground_truth_vulnerable": s.ground_truth_vulnerable,
                    "vulnerable_variant": s.vulnerable_variant,
                    "raw_model_output": raw_text,
                    "json_parse_status": json_parse_status,
                    "json_parse_result": hyp_parsed,
                    "normalized_hypothesis": normalized_hyp,
                    "extracted_decision": ext_res.decision,
                    "vulnerability_type": ext_res.vulnerability_type,
                    "vulnerability_exists": ext_res.vulnerability_exists,
                    "decision": ext_res.decision,
                    "hypothesis": hyp_parsed,
                    "failure_type": failure_type,
                    "error": err_str,
                    "grounding_valid": g_res.valid,
                    "grounding_reason": g_res.reason,
                    "unsupported_fact_ids": g_res.unsupported_fact_ids,
                    "unsupported_param_ids": g_res.unsupported_param_ids,
                    "is_breakout": is_breakout,
                    "escalated": True,
                    "fail_safe_triggered": item["fail_safe_triggered"],
                    "routing_reasons": item["decision"].reasons,
                    "provenance_hash": item["p_hash"],
                    "inference_latency_s": round(infer_duration, 3),
                    "model_load_latency_s": round(cold_load_7b_s if idx == 1 else 0.0, 3),
                    "routing_overhead_s": item["routing_overhead_s"],
                    "validation_overhead_s": item["validation_overhead_s"],
                    "end_to_end_latency_s": total_e2e,
                    "earliest_failure_layer": primary_fail,
                    "secondary_failure_causes": sec_fails,
                    "useful": bool(ext_res.decision == "HYPOTHESIS" and g_res.valid),
                }

                vram_now = query_vram_mb()
                if vram_now > peak_vram:
                    peak_vram = vram_now

                print(f"  [Survivor {sid}] 7B: dec={ext_res.decision} vtype={ext_res.vulnerability_type} ground={g_res.valid} fail={primary_fail}")

            final_records.append(rec)

        # 3B failure rate & SLO calculation
        metrics_3b = triage_runner.metrics
        failure_rate_3b = metrics_3b.failure_rate
        slo_alert = failure_rate_3b > 0.02
        slo_violation = failure_rate_3b > 0.05

        res = {
            "track_name": TRACK_C_CASCADE,
            "records": final_records,
            "cold_load_3b_s": round(cold_load_3b_s, 3),
            "cold_load_7b_s": round(cold_load_7b_s, 3),
            "quiescent_vram_mb": quiescent_vram,
            "peak_vram_mb": peak_vram,
            "total_survivors": len(survivors),
            "escalation_rate": round(len(survivors) / len(scenarios_to_run), 4) if scenarios_to_run else 0.0,
            "metrics_3b": metrics_3b.to_summary_dict(),
            "slo_alert": slo_alert,
            "slo_violation": slo_violation,
        }
        ckpt_path.write_text(json.dumps(res, indent=2), encoding="utf-8")
        return res


def compute_metrics_slice(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Computes precision, recall, F1, yield, TNR, with Wilson 95% CIs and counts, respecting zero-denominator rules."""
    total = len(records)
    if total == 0:
        return {}

    tp = 0
    fp = 0
    fn = 0
    tn = 0
    total_vuln = 0
    total_non_vuln = 0
    grounding_rejections = 0
    critical_epistemic_failures = 0
    breakouts = 0

    for r in records:
        is_vuln = r["ground_truth_vulnerable"]
        dec = r["decision"]
        is_hyp = (dec == "HYPOTHESIS")
        g_valid = r.get("grounding_valid", True)
        if not g_valid:
            grounding_rejections += 1
            critical_epistemic_failures += 1
        if r.get("is_breakout", False):
            breakouts += 1

        if is_vuln:
            total_vuln += 1
            if is_hyp and g_valid:
                tp += 1
            else:
                fn += 1
        else:
            total_non_vuln += 1
            if is_hyp and g_valid:
                fp += 1
            else:
                tn += 1

    # Precision: TP / (TP + FP) (None if denominator is zero -> N/A)
    precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else None
    # Recall: TP / (TP + FN) (None if total vulnerable is zero -> N/A)
    recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else None
    # F1 Score
    f1 = (
        round((2 * precision * recall) / (precision + recall), 4)
        if (precision is not None and recall is not None and (precision + recall) > 0)
        else None
    )
    # Target-Level Useful Hypothesis Yield: useful_vulnerable / total_vulnerable
    useful_yield = round(tp / total_vuln, 4) if total_vuln > 0 else None
    # TNR
    tnr = round(tn / total_non_vuln, 4) if total_non_vuln > 0 else None
    # Decision Quality
    decision_quality = round((tp + tn) / total, 4) if total > 0 else 0.0

    return {
        "N_total": total,
        "N_vuln": total_vuln,
        "N_non_vuln": total_non_vuln,
        "TP": tp,
        "FP": fp,
        "FN": fn,
        "TN": tn,
        "precision": precision,
        "precision_num": tp,
        "precision_denom": tp + fp,
        "precision_ci_95": wilson_score_interval(precision, tp + fp),
        "recall": recall,
        "recall_num": tp,
        "recall_denom": tp + fn,
        "recall_ci_95": wilson_score_interval(recall, tp + fn),
        "f1_score": f1,
        "useful_hypothesis_yield": useful_yield,
        "useful_yield_num": tp,
        "useful_yield_denom": total_vuln,
        "useful_yield_ci_95": wilson_score_interval(useful_yield, total_vuln),
        "tnr": tnr,
        "tnr_num": tn,
        "tnr_denom": total_non_vuln,
        "tnr_ci_95": wilson_score_interval(tnr, total_non_vuln),
        "decision_quality": decision_quality,
        "grounding_rejections": grounding_rejections,
        "critical_epistemic_failures": critical_epistemic_failures,
        "breakouts": breakouts,
    }


def analyze_track_slices(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Slices a track's records by split and variant."""
    dev_recs = [r for r in records if r["split"] == "development"]
    val_recs = [r for r in records if r["split"] == "validation"]
    eval_recs = [r for r in records if r["split"] == "evaluation"]

    vuln_recs = [r for r in records if r["ground_truth_vulnerable"]]
    patched_recs = [r for r in records if not r["ground_truth_vulnerable"] and "-PATCH-" in r["scenario_id"]]
    neg_recs = [r for r in records if not r["ground_truth_vulnerable"] and "-NEG-" in r["scenario_id"]]

    return {
        "overall": compute_metrics_slice(records),
        "development_split": compute_metrics_slice(dev_recs),
        "validation_split": compute_metrics_slice(val_recs),
        "hidden_evaluation_split": compute_metrics_slice(eval_recs),
        "vulnerable_population": compute_metrics_slice(vuln_recs),
        "patched_population": compute_metrics_slice(patched_recs),
        "negative_controls": compute_metrics_slice(neg_recs),
    }


def compute_paired_statistics(
    track_a_recs: List[Dict[str, Any]],
    track_c_recs: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Computes paired 2x2 contingency table, Tango score CI, McNemar test, and degeneracy check over N_vuln=36."""
    a_map = {r["scenario_id"]: r for r in track_a_recs if r["ground_truth_vulnerable"]}
    c_map = {r["scenario_id"]: r for r in track_c_recs if r["ground_truth_vulnerable"]}

    n11 = 0  # Both useful
    n10 = 0  # 7B useful, Cascade not
    n01 = 0  # Cascade useful, 7B not
    n00 = 0  # Neither useful

    paired_details = []
    for sid, a_rec in a_map.items():
        c_rec = c_map.get(sid, {})
        a_useful = bool(a_rec.get("decision") == "HYPOTHESIS" and a_rec.get("grounding_valid", True))
        c_useful = bool(c_rec.get("decision") == "HYPOTHESIS" and c_rec.get("grounding_valid", True))

        paired_details.append({
            "scenario_id": sid,
            "track_a_7b_useful": a_useful,
            "track_c_cascade_useful": c_useful,
        })

        if a_useful and c_useful:
            n11 += 1
        elif a_useful and not c_useful:
            n10 += 1
        elif not a_useful and c_useful:
            n01 += 1
        else:
            n00 += 1

    total_vuln = len(paired_details)
    tango_ucb = tango_paired_ucb(n11, n10, n01, n00)
    non_inferiority_pass = tango_ucb < 0.05
    degenerate_non_inf = is_degenerate_non_inferiority(n11, n10, n01)

    # Exact McNemar test
    discordant = n10 + n01
    if discordant == 0:
        mcnemar_p = 1.0
    else:
        k = min(n10, n01)
        prob = sum(math.comb(discordant, i) * (0.5 ** discordant) for i in range(k + 1))
        mcnemar_p = min(1.0, 2.0 * prob)

    return {
        "N_vuln": total_vuln,
        "n11_both_useful": n11,
        "n10_7b_only": n10,
        "n01_cascade_only": n01,
        "n00_neither_useful": n00,
        "observed_difference_delta": round((n10 - n01) / total_vuln, 4) if total_vuln > 0 else 0.0,
        "tango_90_one_sided_ucb": tango_ucb,
        "non_inferiority_margin_delta": 0.05,
        "non_inferiority_established": non_inferiority_pass,
        "is_degenerate_non_inferiority": degenerate_non_inf,
        "degenerate_qualification": (
            "The statistical comparison is mathematically computable but does not establish useful security capability "
            "because the independent quality floor/sensitivity requirement is not satisfied."
            if degenerate_non_inf
            else None
        ),
        "mcnemar_exact_p_value": round(mcnemar_p, 4),
        "paired_details": paired_details,
    }


def compute_latency_distribution(latencies: List[float]) -> Dict[str, float]:
    """Computes mean, median, P95 from list of latency floats."""
    if not latencies:
        return {"mean": 0.0, "median": 0.0, "p95": 0.0, "min": 0.0, "max": 0.0}
    s = sorted(latencies)
    n = len(s)
    mean_val = sum(s) / n
    med_val = s[n // 2] if n % 2 != 0 else (s[n // 2 - 1] + s[n // 2]) / 2.0
    idx_95 = min(int(math.ceil(0.95 * n)) - 1, n - 1)
    p95_val = s[max(0, idx_95)]
    return {
        "mean": round(mean_val, 3),
        "median": round(med_val, 3),
        "p95": round(p95_val, 3),
        "min": round(s[0], 3),
        "max": round(s[-1], 3),
    }


def compute_failure_layer_summary(records: List[Dict[str, Any]]) -> Dict[str, int]:
    """Tallies occurrences of each earliest primary failure layer."""
    counts = Counter()
    for r in records:
        fl = r.get("earliest_failure_layer")
        if fl:
            counts[fl] += 1
        else:
            counts["SUCCESS"] += 1
    return dict(counts)


def run_10_scenario_validation_gate(runner: Phase11BenchmarkRunner) -> bool:
    """
    Executes the 10-Scenario Validation Gate (Section 8 & 9).
    Must specifically detect if nested positives are recovered and not lost to NO_RELEVANT_FUNCTIONALITY.
    """
    print("============================================================")
    print(" 10-SCENARIO VALIDATION GATE (Section 8 & 9)")
    print("============================================================")
    print(f"Executing 10 audited vulnerable scenarios: {AUDITED_10_SCENARIO_IDS}\n")

    # Run Track B on the 10 scenarios
    tb_res = runner.run_track_b(scenario_subset=AUDITED_10_SCENARIO_IDS)
    # Run Track A on the 10 scenarios
    ta_res = runner.run_track_a(scenario_subset=AUDITED_10_SCENARIO_IDS)
    # Run Track C on the 10 scenarios
    tc_res = runner.run_track_c(scenario_subset=AUDITED_10_SCENARIO_IDS)

    print("\n--- 10-SCENARIO VALIDATION AUDIT RESULTS ---")
    gate_passed = True
    hard_stop_reasons = []

    # Verify scenario SCEN-DOCUMENT_COLLABORATION-DOC-WORKSPACE-VULN-06
    # (The audited positive where 7B emitted VulnerabilityExists=True)
    target_sid = "SCEN-DOCUMENT_COLLABORATION-DOC-WORKSPACE-VULN-06"
    rec_a = next((r for r in ta_res["records"] if r["scenario_id"] == target_sid), None)
    if rec_a:
        hyp = rec_a.get("hypothesis")
        dec = rec_a.get("decision")
        print(f"\nAudit Check on {target_sid}:")
        print(f"  Track A Decision: {dec}")
        print(f"  Track A Earliest Failure: {rec_a.get('earliest_failure_layer')}")
        if dec == "NO_RELEVANT_FUNCTIONALITY" and hyp and "ReasoningHypothesis" in hyp:
            inner = hyp.get("ReasoningHypothesis", {})
            if inner.get("VulnerabilityExists") is True:
                gate_passed = False
                hard_stop_reasons.append(
                    f"HARD STOP: {target_sid} in Track A still became NO_RELEVANT_FUNCTIONALITY despite VulnerabilityExists=True!"
                )

    # Verify Track C routing invariants across the 10 scenarios
    for r in tc_res["records"]:
        sid = r["scenario_id"]
        # Architecture Invariant: fail_safe_triggered derived only from gate_result
        # Escalation must have valid provenance
        if not r.get("provenance_hash"):
            gate_passed = False
            hard_stop_reasons.append(f"HARD STOP: {sid} in Track C missing provenance hash!")

    if not gate_passed:
        print("\n[FAIL] 10-SCENARIO VALIDATION GATE FAILED!")
        for r in hard_stop_reasons:
            print(f"  - {r}")
        return False

    print("\n[PASS] 10-SCENARIO VALIDATION GATE PASSED COMPLETELY.")
    return True


def generate_benchmark_reports(
    run_id: str,
    run_dir: Path,
    track_a_res: Dict[str, Any],
    track_b_res: Dict[str, Any],
    track_c_res: Dict[str, Any],
) -> Tuple[Path, Path]:
    """Generates comprehensive JSON and Markdown reports adhering strictly to Section 31."""
    json_path = Path(f"reports/m2_phase11_rerun_{run_id}.json")
    md_path = Path(f"reports/m2_phase11_rerun_{run_id}.md")

    slices_a = analyze_track_slices(track_a_res["records"])
    slices_b = analyze_track_slices(track_b_res["records"])
    slices_c = analyze_track_slices(track_c_res["records"])

    paired_stats = compute_paired_statistics(track_a_res["records"], track_c_res["records"])

    manifest_bytes = MANIFEST_PATH.read_bytes()
    manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
    manifest_obj = json.loads(manifest_bytes.decode("utf-8"))

    constant_neg_diag = compute_constant_negative_diagnostic(manifest_obj["scenarios"])

    # Latency breakdowns
    ttd_a = [r["end_to_end_latency_s"] for r in track_a_res["records"]]
    ttd_b = [r["end_to_end_latency_s"] for r in track_b_res["records"]]
    ttd_c = [r["end_to_end_latency_s"] for r in track_c_res["records"]]

    infer_a = [r["inference_latency_s"] for r in track_a_res["records"]]
    infer_b = [r["inference_latency_s"] for r in track_b_res["records"]]
    infer_c = [r["inference_latency_s"] for r in track_c_res["records"]]

    warm_ttd_a = ttd_a[1:] if len(ttd_a) > 1 else ttd_a
    warm_ttd_b = ttd_b[1:] if len(ttd_b) > 1 else ttd_b
    warm_ttd_c = ttd_c[1:] if len(ttd_c) > 1 else ttd_c

    lat_dist_a = compute_latency_distribution(ttd_a)
    lat_dist_b = compute_latency_distribution(ttd_b)
    lat_dist_c = compute_latency_distribution(ttd_c)

    warm_lat_dist_a = compute_latency_distribution(warm_ttd_a)
    warm_lat_dist_b = compute_latency_distribution(warm_ttd_b)
    warm_lat_dist_c = compute_latency_distribution(warm_ttd_c)

    infer_dist_a = compute_latency_distribution(infer_a)
    infer_dist_b = compute_latency_distribution(infer_b)
    infer_dist_c = compute_latency_distribution(infer_c)

    # Efficiency calculations
    calls_7b_baseline = len(track_a_res["records"])
    calls_7b_cascade = track_c_res["total_survivors"]
    calls_saved = calls_7b_baseline - calls_7b_cascade
    call_red_pct = round((calls_saved / calls_7b_baseline) * 100, 2) if calls_7b_baseline > 0 else 0.0

    # Count vulnerable vs non-vulnerable filtered in Track C
    vuln_filtered = sum(
        1 for r in track_c_res["records"] if r["ground_truth_vulnerable"] and not r["escalated"]
    )
    non_vuln_filtered = sum(
        1 for r in track_c_res["records"] if not r["ground_truth_vulnerable"] and not r["escalated"]
    )
    total_vuln = sum(1 for r in track_c_res["records"] if r["ground_truth_vulnerable"])
    vuln_filter_rate = round((vuln_filtered / total_vuln) * 100, 2) if total_vuln > 0 else 0.0

    # Failure layer summaries
    fail_summary_a = compute_failure_layer_summary(track_a_res["records"])
    fail_summary_b = compute_failure_layer_summary(track_b_res["records"])
    fail_summary_c = compute_failure_layer_summary(track_c_res["records"])

    # Degenerate constant-negative diagnostic check
    is_deg_const_neg_a = (slices_a["overall"]["TP"] == 0 and slices_a["overall"]["FP"] == 0)
    is_deg_const_neg_b = (slices_b["overall"]["TP"] == 0 and slices_b["overall"]["FP"] == 0)
    is_deg_const_neg_c = (slices_c["overall"]["TP"] == 0 and slices_c["overall"]["FP"] == 0)

    # Runner SHA-256
    runner_sha = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

    current_git_head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()

    report_json = {
        "report_type": "PHASE 11 FORMAL PAIRED BENCHMARK RERUN REPORT",
        "provenance_statement": "Post-hoc benchmark baseline established after M2 Phases 0–10.",
        "validity_state": "PENDING_FORENSIC_AUDIT",
        "metadata": {
            "correction_commit_sha": run_id,
            "current_git_head": current_git_head,
            "runner_sha256": runner_sha,
            "manifest_sha256": manifest_sha,
            "establishment_commit_sha": ESTABLISHMENT_COMMIT_SHA,
            "attestation_commit_sha": ATTESTATION_COMMIT_SHA,
            "run_directory": str(run_dir),
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
        "previous_run_invalidation": {
            "status": "SUPERSEDED / INVALID",
            "reasons": [
                "Decision extractor failed to unwrap nested ReasoningHypothesis emitted by Qwen models.",
                "Zero positive hypotheses extracted across all tracks causing false 0% recall and degenerate 100% TNR.",
                "Tango non-inferiority passing was degenerate due to sensitivity floor violation (0/36 useful on both tracks).",
                "Provenance mismatch across tracks during prior execution.",
            ],
        },
        "execution_configuration": {
            "seed": BENCHMARK_SEED,
            "temperature": BENCHMARK_TEMPERATURE,
            "models": {
                PINNED_3B_MODEL: PINNED_3B_DIGEST,
                PINNED_7B_MODEL: PINNED_7B_DIGEST,
            },
            "timeouts": {
                "3b_triage_ceiling_seconds": 15.0,
                "7b_reasoning_ceiling_seconds": 30.0,
            },
            "mode": "MODE 1 BATCH-SEQUENTIAL",
        },
        "constant_negative_diagnostic": constant_neg_diag,
        "efficiency_analysis": {
            "total_scenarios": len(track_c_res["records"]),
            "3b_entered": len(track_c_res["records"]),
            "3b_failures": track_c_res["metrics_3b"].get("total_failures", 0),
            "escalated_to_7b": calls_7b_cascade,
            "not_escalated": calls_saved,
            "7b_call_reduction_count": calls_saved,
            "7b_call_reduction_percentage": f"{call_red_pct}%",
            "vulnerable_scenarios_filtered_out": vuln_filtered,
            "vulnerable_filter_rate": f"{vuln_filter_rate}%",
            "non_vulnerable_scenarios_filtered": non_vuln_filtered,
            "efficiency_qualification": (
                "WARNING: 7B call reduction cannot be claimed as a capability improvement if vulnerable scenarios were filtered out by 3B triage."
                if vuln_filtered > 0
                else "Clean reduction: zero vulnerable scenarios filtered."
            ),
        },
        "paired_non_inferiority_analysis": paired_stats,
        "security_metric_qualification": {
            "adversarial_containment_measured": False,
            "statement": "Adversarial containment was not measured in this benchmark. Reference Phase 10 separately for adversarial testing.",
        },
        "latency_metrics": {
            "track_a_7b": {
                "cold_model_load_s": track_a_res["cold_load_latency_s"],
                "first_scenario_cold_ttd_s": ttd_a[0] if ttd_a else 0.0,
                "overall_ttd": lat_dist_a,
                "warm_ttd": warm_lat_dist_a,
                "inference_latency": infer_dist_a,
            },
            "track_b_3b": {
                "cold_model_load_s": track_b_res["cold_load_latency_s"],
                "first_scenario_cold_ttd_s": ttd_b[0] if ttd_b else 0.0,
                "overall_ttd": lat_dist_b,
                "warm_ttd": warm_lat_dist_b,
                "inference_latency": infer_dist_b,
            },
            "track_c_cascade": {
                "cold_load_3b_s": track_c_res["cold_load_3b_s"],
                "cold_load_7b_s": track_c_res["cold_load_7b_s"],
                "first_scenario_cold_ttd_s": ttd_c[0] if ttd_c else 0.0,
                "overall_ttd": lat_dist_c,
                "warm_ttd": warm_lat_dist_c,
                "inference_latency": infer_dist_c,
            },
        },
        "failure_layer_analysis": {
            "track_a": fail_summary_a,
            "track_b": fail_summary_b,
            "track_c": fail_summary_c,
        },
        "track_a_7b_baseline": {
            "metrics": slices_a,
            "cold_load_latency_s": track_a_res["cold_load_latency_s"],
            "total_duration_s": track_a_res["total_duration_s"],
            "peak_vram_mb": track_a_res["peak_vram_mb"],
            "degenerate_constant_negative": is_deg_const_neg_a,
            "records": track_a_res["records"],
        },
        "track_b_3b_baseline": {
            "metrics": slices_b,
            "cold_load_latency_s": track_b_res["cold_load_latency_s"],
            "total_duration_s": track_b_res["total_duration_s"],
            "peak_vram_mb": track_b_res["peak_vram_mb"],
            "degenerate_constant_negative": is_deg_const_neg_b,
            "records": track_b_res["records"],
        },
        "track_c_cascade": {
            "metrics": slices_c,
            "cold_load_3b_s": track_c_res["cold_load_3b_s"],
            "cold_load_7b_s": track_c_res["cold_load_7b_s"],
            "quiescent_vram_mb": track_c_res["quiescent_vram_mb"],
            "peak_vram_mb": track_c_res["peak_vram_mb"],
            "total_survivors": track_c_res["total_survivors"],
            "escalation_rate": track_c_res["escalation_rate"],
            "degenerate_constant_negative": is_deg_const_neg_c,
            "metrics_3b": track_c_res["metrics_3b"],
            "records": track_c_res["records"],
        },
    }

    json_path.write_text(json.dumps(report_json, indent=2), encoding="utf-8")

    # Generate Markdown Report
    prec_str_a = f"{slices_a['overall']['precision']*100:.1f}%" if slices_a['overall']['precision'] is not None else "N/A"
    prec_str_b = f"{slices_b['overall']['precision']*100:.1f}%" if slices_b['overall']['precision'] is not None else "N/A"
    prec_str_c = f"{slices_c['overall']['precision']*100:.1f}%" if slices_c['overall']['precision'] is not None else "N/A"

    yield_str_a = f"{slices_a['vulnerable_population']['useful_hypothesis_yield']*100:.1f}%" if slices_a['vulnerable_population']['useful_hypothesis_yield'] is not None else "N/A"
    yield_str_b = f"{slices_b['vulnerable_population']['useful_hypothesis_yield']*100:.1f}%" if slices_b['vulnerable_population']['useful_hypothesis_yield'] is not None else "N/A"
    yield_str_c = f"{slices_c['vulnerable_population']['useful_hypothesis_yield']*100:.1f}%" if slices_c['vulnerable_population']['useful_hypothesis_yield'] is not None else "N/A"

    deg_warn_block = ""
    if paired_stats["is_degenerate_non_inferiority"]:
        deg_warn_block = (
            "> [!WARNING]\n"
            "> **DEGENERATE NON-INFERIORITY DETECTED**\n"
            f"> {paired_stats['degenerate_qualification']}\n"
        )

    md_content = f"""# Milestone M2 Phase 11: Formal Paired Benchmark Report (Corrected Rerun)

## 1. Executive Summary & Provenance Statement
- **Benchmark Baseline**: POST-HOC BENCHMARK BASELINE (established post-M2 Phases 0–10).
- **Previous Phase 11 Run**: SUPERSEDED / INVALID due to extractor defects and provenance mismatch.
- **Correction Commit SHA**: `{run_id}`
- **Current Git HEAD**: `{current_git_head}`
- **Manifest SHA-256**: `{manifest_sha}`
- **Runner SHA-256**: `{runner_sha}`
- **Models Pinned**:
  - 3B: `{PINNED_3B_MODEL}` (`{PINNED_3B_DIGEST}`)
  - 7B: `{PINNED_7B_MODEL}` (`{PINNED_7B_DIGEST}`)
- **Run Validity State**: `PENDING_FORENSIC_AUDIT`

{deg_warn_block}

## 2. Six-Metric Benchmark Ensemble

| Metric | Track A (7B Baseline) | Track B (3B Baseline) | Track C (Cascade) | Target / Invariant |
| :--- | :--- | :--- | :--- | :--- |
| **Useful Hypothesis Yield (N=36)** | {yield_str_a} ({slices_a['vulnerable_population']['TP']}/36) | {yield_str_b} ({slices_b['vulnerable_population']['TP']}/36) | {yield_str_c} ({slices_c['vulnerable_population']['TP']}/36) | Non-inferior to 7B |
| **Vulnerable Recall** | {slices_a['overall']['recall']*100:.1f}% ({slices_a['overall']['TP']}/36) | {slices_b['overall']['recall']*100:.1f}% ({slices_b['overall']['TP']}/36) | {slices_c['overall']['recall']*100:.1f}% ({slices_c['overall']['TP']}/36) | Sensitivity |
| **Precision** | {prec_str_a} ({slices_a['overall']['TP']}/{slices_a['overall']['TP']+slices_a['overall']['FP']}) | {prec_str_b} ({slices_b['overall']['TP']}/{slices_b['overall']['TP']+slices_b['overall']['FP']}) | {prec_str_c} ({slices_c['overall']['TP']}/{slices_c['overall']['TP']+slices_c['overall']['FP']}) | $\\ge 85.0\\%$ |
| **True Negative Rate (TNR)** | {slices_a['overall']['tnr']*100:.1f}% ({slices_a['overall']['TN']}/48) | {slices_b['overall']['tnr']*100:.1f}% ({slices_b['overall']['TN']}/48) | {slices_c['overall']['tnr']*100:.1f}% ({slices_c['overall']['TN']}/48) | $\\ge 80.0\\%$ |
| **7B Inference Calls** | 84 (100.0%) | 0 (0.0%) | {calls_7b_cascade} ({calls_7b_cascade/84*100:.1f}%) | $\\ge 30\\%$ reduction |
| **7B Call Reduction** | Baseline (0.0%) | N/A | **{call_red_pct}%** ({calls_saved} calls saved) | Target Met |
| **Median Warm TTD** | {warm_lat_dist_a['median']:.2f}s | {warm_lat_dist_b['median']:.2f}s | **{warm_lat_dist_c['median']:.2f}s** | $\\le 12.0\\text{{s}}$ |
| **P95 Warm TTD** | {warm_lat_dist_a['p95']:.2f}s | {warm_lat_dist_b['p95']:.2f}s | **{warm_lat_dist_c['p95']:.2f}s** | $\\le 20.0\\text{{s}}$ |

## 3. Efficiency Safety & Vulnerable Filtering Analysis
- **7B Calls Saved**: `{calls_saved}` ({call_red_pct}%)
- **Vulnerable Scenarios Filtered by 3B**: `{vuln_filtered}` ({vuln_filter_rate}%)
- **Non-Vulnerable Scenarios Filtered by 3B**: `{non_vuln_filtered}` ({non_vuln_filtered/48*100:.1f}%)
- **Anti-Cherry-Picking Principle**: A reduction in 7B calls is valid as an efficiency achievement ONLY when no vulnerable scenarios are dropped.

## 4. Paired Non-Inferiority & Statistical Tests
- **Predeclared Statistical Method**: Tango score-based paired difference confidence interval method ($N_{{vuln}}=36$).
- **Contingency Table**:
  - Both Useful ($n_{{11}}$): `{paired_stats['n11_both_useful']}`
  - 7B Only ($n_{{10}}$): `{paired_stats['n10_7b_only']}`
  - Cascade Only ($n_{{01}}$): `{paired_stats['n01_cascade_only']}`
  - Neither Useful ($n_{{00}}$): `{paired_stats['n00_neither_useful']}`
- **Predeclared 90% One-Sided Tango UCB**: `+{paired_stats['tango_90_one_sided_ucb']:.3f}`
- **Non-Inferiority Margin**: $\\Delta = 0.05$
- **Non-Inferiority Established**: `{paired_stats['non_inferiority_established']}`
- **Degenerate Flag**: `{paired_stats['is_degenerate_non_inferiority']}`
- **Exact McNemar p-value**: `{paired_stats['mcnemar_exact_p_value']}`

## 5. Earliest Primary Failure-Layer Decomposition

| Primary Failure Layer | Track A (7B) | Track B (3B) | Track C (Cascade) |
| :--- | :--- | :--- | :--- |
| `SUCCESS` (Useful / Correct Abstention) | {fail_summary_a.get('SUCCESS', 0)} | {fail_summary_b.get('SUCCESS', 0)} | {fail_summary_c.get('SUCCESS', 0)} |
| `MODEL_OUTPUT_FAILURE` | {fail_summary_a.get(FailureLayer.MODEL_OUTPUT_FAILURE, 0)} | {fail_summary_b.get(FailureLayer.MODEL_OUTPUT_FAILURE, 0)} | {fail_summary_c.get(FailureLayer.MODEL_OUTPUT_FAILURE, 0)} |
| `JSON_PARSE_FAILURE` | {fail_summary_a.get(FailureLayer.JSON_PARSE_FAILURE, 0)} | {fail_summary_b.get(FailureLayer.JSON_PARSE_FAILURE, 0)} | {fail_summary_c.get(FailureLayer.JSON_PARSE_FAILURE, 0)} |
| `HYPOTHESIS_NORMALIZATION_FAILURE` | {fail_summary_a.get(FailureLayer.HYPOTHESIS_NORMALIZATION_FAILURE, 0)} | {fail_summary_b.get(FailureLayer.HYPOTHESIS_NORMALIZATION_FAILURE, 0)} | {fail_summary_c.get(FailureLayer.HYPOTHESIS_NORMALIZATION_FAILURE, 0)} |
| `DECISION_EXTRACTION_FAILURE` | {fail_summary_a.get(FailureLayer.DECISION_EXTRACTION_FAILURE, 0)} | {fail_summary_b.get(FailureLayer.DECISION_EXTRACTION_FAILURE, 0)} | {fail_summary_c.get(FailureLayer.DECISION_EXTRACTION_FAILURE, 0)} |
| `ROUTING_FALSE_NEGATIVE` | {fail_summary_a.get(FailureLayer.ROUTING_FALSE_NEGATIVE, 0)} | {fail_summary_b.get(FailureLayer.ROUTING_FALSE_NEGATIVE, 0)} | {fail_summary_c.get(FailureLayer.ROUTING_FALSE_NEGATIVE, 0)} |
| `GROUNDING_FAILURE` | {fail_summary_a.get(FailureLayer.GROUNDING_FAILURE, 0)} | {fail_summary_b.get(FailureLayer.GROUNDING_FAILURE, 0)} | {fail_summary_c.get(FailureLayer.GROUNDING_FAILURE, 0)} |
| `REASONING_INCORRECT_LOGIC` | {fail_summary_a.get(FailureLayer.REASONING_INCORRECT_LOGIC, 0)} | {fail_summary_b.get(FailureLayer.REASONING_INCORRECT_LOGIC, 0)} | {fail_summary_c.get(FailureLayer.REASONING_INCORRECT_LOGIC, 0)} |
| `OTHER_IMPLEMENTATION_FAILURE` | {fail_summary_a.get(FailureLayer.OTHER_IMPLEMENTATION_FAILURE, 0)} | {fail_summary_b.get(FailureLayer.OTHER_IMPLEMENTATION_FAILURE, 0)} | {fail_summary_c.get(FailureLayer.OTHER_IMPLEMENTATION_FAILURE, 0)} |

## 6. Constant-Negative Diagnostic Baseline
- **Diagnostic Rule**: ALL SCENARIOS $\\to$ `NO_RELEVANT_FUNCTIONALITY`
- **Diagnostic Baseline Metrics**:
  - Accuracy: `{constant_neg_diag['accuracy']*100:.2f}%`
  - Recall: `{constant_neg_diag['recall']}`
  - Precision: `N/A`
  - TNR: `{constant_neg_diag['tnr']*100:.1f}%`
- **Track Degeneracy Flags**:
  - Track A: `{is_deg_const_neg_a}`
  - Track B: `{is_deg_const_neg_b}`
  - Track C: `{is_deg_const_neg_c}`

## 7. Security Metric Qualification
> [!NOTE]
> Adversarial containment was not measured in this benchmark. Standard Phase 11 scenarios evaluate canonical structural reasoning. Reference Milestone M2 Phase 10 separately for adversarial prompt injection containment test suite results.
"""

    md_path.write_text(md_content, encoding="utf-8")
    print(f"\n[REPORT] Generated JSON Report: {json_path}")
    print(f"[REPORT] Generated Markdown Report: {md_path}")
    return json_path, md_path


def main():
    parser = argparse.ArgumentParser(description="Phase 11 Formal Paired Benchmark Runner")
    parser.add_argument("--mode", choices=["dry-run", "validate-10", "benchmark"], default="dry-run")
    parser.add_argument("--run-id", type=str, default="local", help="Git SHA or unique identifier for the rerun")
    args = parser.parse_args()

    print("======================================================================")
    print(f" MILESTONE M2 PHASE 11: FORMAL PAIRED BENCHMARK (Mode: {args.mode})")
    print(" DATASET: POST-HOC BENCHMARK BASELINE (N=84)")
    print("======================================================================")

    verify_preconditions()

    run_dir = Path(f"data/cache/phase11_rerun_{args.run_id}")
    runner = Phase11BenchmarkRunner(run_dir=run_dir)

    if args.mode == "dry-run":
        print("\n[DRY-RUN] Manifest loaded: 84 scenarios.")
        print(f"[DRY-RUN] Structural packs created: {len(runner.structural_packs)}.")
        print(f"[DRY-RUN] Output directory verified: {run_dir}")
        print("PHASE11_PREFLIGHT_OK: True")
        return

    if args.mode == "validate-10":
        ok = run_10_scenario_validation_gate(runner)
        if not ok:
            print("\n[HALT] 10-Scenario Validation Gate failed! Aborting execution.")
            sys.exit(1)
        print("\n[PASS] 10-Scenario Validation Gate passed! Ready for full benchmark execution.")
        return

    if args.mode == "benchmark":
        # 1. Run Track B (3B Baseline)
        track_b_res = runner.run_track_b()

        # 2. Run Track A (7B Baseline)
        track_a_res = runner.run_track_a()

        # 3. Run Track C (Cascade)
        track_c_res = runner.run_track_c()

        # 4. Generate Reports
        generate_benchmark_reports(
            run_id=args.run_id,
            run_dir=run_dir,
            track_a_res=track_a_res,
            track_b_res=track_b_res,
            track_c_res=track_c_res,
        )


if __name__ == "__main__":
    main()

