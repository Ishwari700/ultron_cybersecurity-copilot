"""
Milestone M5 Phase 9: Deterministic Experiment Skeleton & Output-Budget Sensitivity Study.

Executes the pre-registered 44-call diagnostic capability study:
1. Representative Benchmark Sample (36 calls):
   - 6 scenarios (4 vulnerable + 2 controls across BOLA, STATE, BFLA, CROSS-TENANT)
   - 2 tracks: Track A (Minimal Structural) and Track D (Full Cascade + RAG Pack)
   - 3 completion budgets:
     * P3-300 (num_predict = 300)
     * P3-512 (num_predict = 512)
     * P3-768 (num_predict = 768)
2. Active-Evidence Diagnostic Sample (8 calls):
   - 4 canonical anomaly fixtures from Phase 8.3
   - Track A only
   - 2 completion budgets: P3-300 (4 calls) and P3-512 (4 calls)

Strict Invariants:
- Exactly 44 live LLM calls total.
- Frozen Ollama v0.34.1, qwen2.5-coder:7b (dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364)
- num_ctx = 2048, temperature = 0.0, seed = 42, keep_alive = 60m
- Zero retries, zero semantic repair, single inference call per execution.
- Deterministic experiment skeleton provides fixed legal action and flat legal_outcomes.
- LLM does NOT see breach vs safe outcome partitions, ground truth, or expected decisions.
- Primary diagnostic metric: Valid Typed Experiment Rate.
"""

from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

repo_root = Path(__file__).resolve().parent.parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

import httpx
from pydantic import BaseModel, ConfigDict, Field

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
    HypothesisDecision,
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
    PRIMARY_SEED,
    PRIMARY_TEMPERATURE,
    ReasoningRunner,
)
from src.eval.m4_live_benchmark import (
    ConfirmatoryTrackId,
    infer_evidence_gap_type,
    EXPECTED_7B_DIGEST_FULL,
)
from src.eval.scenarios import get_gold_set_scenarios
from src.eval.scorer import (
    EvaluationApplicabilityState,
    canonical_vulnerability_evidence_present,
    determine_applicability_state,
)
from src.evidence.cascade_models import (
    CascadeHandoffPacket,
    DeterministicRoutingDecision,
    LosslessStructuralPack,
)
from src.knowledge.grounding_validator import KnowledgeGroundingValidator
from src.knowledge.pipeline import VaptReasoningPipeline

P9_OUTPUT_JSON = repo_root / "data/eval/m5_phase9_semantic_budget_study.json"
P9_OUTPUT_SHA = repo_root / "data/eval/m5_phase9_semantic_budget_study.json.sha256"
P9_CHECKPOINT_JSON = repo_root / "data/eval/m5_phase9_checkpoint.json"

SEALED_P7_PATH = repo_root / "data/eval/m5_phase7_benchmark_final.json"
EXPECTED_P7_SHA = "1e0ed90c4aa672f135d2d2f2240a14d22fa0037c03efda33634f4bf10ff0b125"

SEALED_P8_PATH = repo_root / "data/eval/m5_phase8_semantic_study.json"
EXPECTED_P8_SHA = "b1df9a62fb07d76e0abf6e3935ccbabdaa1713f4c594019ae30c9e59567a45c6"

SCENARIOS_PATH = repo_root / "src/eval/scenarios.py"
EXPECTED_SCENARIOS_SHA = "102789655bfb04041de9259d1bf6db7f088979e5bce9bac9eb050564ef0110a8"


def hash_file(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest().lower()


# ---------------------------------------------------------------------------
# Pre-Registered Condition Configuration
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Phase9ConditionConfig:
    condition_id: str
    num_predict: int
    description: str


PHASE9_CONDITIONS = [
    Phase9ConditionConfig(
        condition_id="P3-300",
        num_predict=300,
        description="Deterministic skeleton (engine-supplied action, unpartitioned legal outcomes), num_predict=300",
    ),
    Phase9ConditionConfig(
        condition_id="P3-512",
        num_predict=512,
        description="Deterministic skeleton (engine-supplied action, unpartitioned legal outcomes), num_predict=512",
    ),
    Phase9ConditionConfig(
        condition_id="P3-768",
        num_predict=768,
        description="Deterministic skeleton (engine-supplied action, unpartitioned legal outcomes), num_predict=768",
    ),
]

# ---------------------------------------------------------------------------
# Pre-Registered Scenario Manifest
# ---------------------------------------------------------------------------

REPRESENTATIVE_BENCHMARK_SCENARIOS = [
    {
        "scenario_id": "SCEN-SAAS_BILLING-INV-DETAILS-VULN-01",
        "category_id": "API-BOLA-001",
        "vulnerable_variant": True,
        "reason": "Major Phase 8 BOLA failure point; demonstrated P3 validity breakthrough in Call #03",
    },
    {
        "scenario_id": "SCEN-ECOMMERCE_ORDERS-ORD-REFUND-VULN-01",
        "category_id": "API-STATE-001",
        "vulnerable_variant": True,
        "reason": "Major Phase 8 State Machine failure point; 75% action incompatibility in Phase 7",
    },
    {
        "scenario_id": "SCEN-IDENTITY_PROVIDER-USER-ROLES-VULN-01",
        "category_id": "API-BFLA-001",
        "vulnerable_variant": True,
        "reason": "Major Phase 8 Role Boundary / BFLA failure point; 40% polarity inversion in Phase 7",
    },
    {
        "scenario_id": "SCEN-IOT_FLEET_MGMT-FLEET-CMD-VULN-03",
        "category_id": "API-CROSS-TENANT-001",
        "vulnerable_variant": True,
        "reason": "Major Phase 8 Cross-Tenant failure point; truncation pressure observed in Phase 7/8",
    },
    {
        "scenario_id": "SCEN-SAAS_BILLING-INV-DETAILS-PATCH-01",
        "category_id": "API-BOLA-001",
        "vulnerable_variant": False,
        "reason": "BOLA negative control; demonstrated P3 validity breakthrough in Call #35",
    },
    {
        "scenario_id": "SCEN-ECOMMERCE_ORDERS-ORD-REFUND-PATCH-01",
        "category_id": "API-STATE-001",
        "vulnerable_variant": False,
        "reason": "State Machine negative control; tests control symmetry under deterministic skeleton",
    },
]

ACTIVE_EVIDENCE_FIXTURES = [
    {
        "id": "DIAG-ACT-BOLA-01",
        "category_id": "API-BOLA-001",
        "route": "/api/v1/tenants/{tenant_id}/invoices/{invoice_id}",
        "method": "GET",
        "parameters": [
            {"name": "tenant_id", "type": "string", "source": "path"},
            {"name": "invoice_id", "type": "string", "source": "path"},
        ],
        "identities": [
            {"role": "TENANT_A_ADMIN", "user_id": "usr-admin-01"},
            {"role": "TENANT_B_USER", "user_id": "usr-user-02"},
        ],
        "evidence": [
            {
                "fact_id": "FACT-ACT-0001",
                "statement": "GET /api/v1/tenants/t-alpha/invoices/inv-999 with TENANT_B_USER credential returned HTTP 200 with tenant t-alpha invoice data.",
                "observed_cross_identity_access": True,
                "has_cross_identity_object_access_success": True,
            }
        ],
        "anomaly_key": "has_cross_identity_object_access_success",
    },
    {
        "id": "DIAG-ACT-STATE-01",
        "category_id": "API-STATE-001",
        "route": "/api/v1/orders/{order_id}/refund",
        "method": "POST",
        "parameters": [{"name": "order_id", "type": "string", "source": "path"}],
        "identities": [{"role": "CUSTOMER", "user_id": "cust-01"}],
        "evidence": [
            {
                "fact_id": "FACT-ACT-0002",
                "statement": "POST /api/v1/orders/ord-500/refund executed successfully on order in CREATED state, returning HTTP 200 and issuing refund before payment.",
                "observed_state_transition_violation": True,
                "has_observed_contradictions": True,
            }
        ],
        "anomaly_key": "has_observed_contradictions",
    },
    {
        "id": "DIAG-ACT-ROLE-01",
        "category_id": "API-ROLE-BOUNDARY-001",
        "route": "/api/v1/admin/users/{user_id}/roles",
        "method": "PUT",
        "parameters": [{"name": "user_id", "type": "string", "source": "path"}],
        "identities": [
            {"role": "MEMBER", "user_id": "usr-member-01"},
            {"role": "ADMIN", "user_id": "usr-admin-02"},
        ],
        "evidence": [
            {
                "fact_id": "FACT-ACT-0003",
                "statement": "PUT /api/v1/admin/users/usr-700/roles with MEMBER token returned HTTP 200 and granted ADMIN role.",
                "observed_privilege_delta": True,
                "has_privilege_level_delta": True,
            }
        ],
        "anomaly_key": "has_privilege_level_delta",
    },
    {
        "id": "DIAG-ACT-TENANT-01",
        "category_id": "API-CROSS-TENANT-001",
        "route": "/api/v1/fleets/{fleet_id}/telemetry",
        "method": "GET",
        "parameters": [{"name": "fleet_id", "type": "string", "source": "path"}],
        "identities": [
            {"role": "TENANT_A", "user_id": "usr-tenant-a"},
            {"role": "TENANT_B", "user_id": "usr-tenant-b"},
        ],
        "evidence": [
            {
                "fact_id": "FACT-ACT-0004",
                "statement": "GET /api/v1/fleets/flt-888/telemetry with Tenant A token successfully accessed Tenant B telemetry data.",
                "observed_cross_identity_access": True,
                "has_cross_identity_object_access_success": True,
            }
        ],
        "anomaly_key": "has_cross_identity_object_access_success",
    },
]

BENCHMARK_TRACKS = [
    ConfirmatoryTrackId.TRACK_A,
    ConfirmatoryTrackId.TRACK_D,
]


def compute_manifest_hash() -> str:
    manifest_data = {
        "benchmark_scenarios": REPRESENTATIVE_BENCHMARK_SCENARIOS,
        "active_evidence_fixtures": ACTIVE_EVIDENCE_FIXTURES,
        "tracks": [t.value for t in BENCHMARK_TRACKS],
        "conditions": [asdict(c) for c in PHASE9_CONDITIONS],
        "planned_benchmark_calls": len(REPRESENTATIVE_BENCHMARK_SCENARIOS) * len(BENCHMARK_TRACKS) * len(PHASE9_CONDITIONS),  # 6 x 2 x 3 = 36
        "planned_active_evidence_calls": len(ACTIVE_EVIDENCE_FIXTURES) * 1 * 2,  # 4 x 1 x 2 = 8
        "total_planned_calls": 44,
    }
    canonical_bytes = json.dumps(manifest_data, sort_keys=True).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest().lower()


# ---------------------------------------------------------------------------
# Preflight Validation
# ---------------------------------------------------------------------------

def run_preflight() -> Dict[str, Any]:
    print("\n=== [PHASE 9.6] PREFLIGHT INTEGRITY & RUNTIME AUDIT ===")

    # 1. Immutability checks
    assert SEALED_P7_PATH.exists(), f"Phase 7 sealed artifact missing: {SEALED_P7_PATH}"
    p7_sha = hash_file(SEALED_P7_PATH)
    assert p7_sha == EXPECTED_P7_SHA, f"Phase 7 SHA mismatch: {p7_sha} != {EXPECTED_P7_SHA}"
    print(f"  [PASS] Phase 7 Sealed Artifact: {p7_sha}")

    assert SEALED_P8_PATH.exists(), f"Phase 8 sealed artifact missing: {SEALED_P8_PATH}"
    p8_sha = hash_file(SEALED_P8_PATH)
    assert p8_sha == EXPECTED_P8_SHA, f"Phase 8 SHA mismatch: {p8_sha} != {EXPECTED_P8_SHA}"
    print(f"  [PASS] Phase 8 Sealed Artifact: {p8_sha}")

    assert SCENARIOS_PATH.exists(), f"scenarios.py missing: {SCENARIOS_PATH}"
    scen_sha = hash_file(SCENARIOS_PATH)
    assert scen_sha == EXPECTED_SCENARIOS_SHA, f"scenarios.py SHA mismatch: {scen_sha} != {EXPECTED_SCENARIOS_SHA}"
    print(f"  [PASS] Benchmark Scenarios: {scen_sha}")

    # 2. Ollama Runtime check
    ollama_ver = subprocess.check_output(["ollama", "--version"], text=True).strip()
    assert "0.34.1" in ollama_ver, f"Ollama version mismatch: {ollama_ver}"
    print(f"  [PASS] Ollama Version: {ollama_ver}")

    with httpx.Client(timeout=5.0) as client:
        tags_res = client.get("http://127.0.0.1:11434/api/tags")
        assert tags_res.status_code == 200, f"Ollama tags status: {tags_res.status_code}"
        models = tags_res.json().get("models", [])
        matched = [m for m in models if m.get("name") == "qwen2.5-coder:7b" or m.get("model") == "qwen2.5-coder:7b"]
        assert len(matched) > 0, "qwen2.5-coder:7b not found in Ollama"
        digest = matched[0].get("digest", "")
        assert digest == EXPECTED_7B_DIGEST_FULL, f"Model digest mismatch: {digest} != {EXPECTED_7B_DIGEST_FULL}"
        print(f"  [PASS] Model Digest: {digest}")

    manifest_hash = compute_manifest_hash()
    print(f"  [PASS] Manifest Hash: {manifest_hash}")
    print("Preflight audit completed successfully. Live calls authorized.\n")

    return {
        "p7_sha": p7_sha,
        "p8_sha": p8_sha,
        "scenarios_sha": scen_sha,
        "ollama_version": ollama_ver,
        "model_digest": digest,
        "manifest_hash": manifest_hash,
    }


# ---------------------------------------------------------------------------
# Phase 9 Live Runner
# ---------------------------------------------------------------------------

class Phase9StudyRunner:
    def __init__(self):
        self.runner = ReasoningRunner(model_name="qwen2.5-coder:7b", num_ctx=PRIMARY_NUM_CTX)
        self.context_builder = ReasoningContextBuilder()
        self.validator = KnowledgeGroundingValidator()
        self.pipeline = VaptReasoningPipeline()
        self.proto_contract = get_protocol_contract(OutputProtocolIdentifier.JSON_BAIR)
        self.gold_scenarios = {s.scenario_id: s for s in get_gold_set_scenarios()}

    def load_checkpoint(self) -> List[Dict[str, Any]]:
        if P9_CHECKPOINT_JSON.exists():
            try:
                data = json.loads(P9_CHECKPOINT_JSON.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    return data
            except Exception:
                pass
        return []

    def save_checkpoint(self, records: List[Dict[str, Any]]):
        P9_CHECKPOINT_JSON.write_text(json.dumps(records, indent=2), encoding="utf-8")

    def run_study(self) -> List[Dict[str, Any]]:
        records = self.load_checkpoint()
        completed_keys = {(r["call_type"], r["identifier"], r["track_id"], r["condition_id"]) for r in records}

        call_idx = len(records)
        total_calls = 44

        print(f"Starting Phase 9 Study: {len(records)}/{total_calls} calls loaded from checkpoint.")

        # Part 1: Representative Benchmark Study (36 calls)
        for scen_meta in REPRESENTATIVE_BENCHMARK_SCENARIOS:
            sid = scen_meta["scenario_id"]
            scen = self.gold_scenarios[sid]

            observed_facts = scen.initial_evidence or [
                {"fact_id": "FACT-00000001", "statement": "Neutral observable target evidence."}
            ]
            raw_sample = str(observed_facts[0].get("statement", "")) if observed_facts else ""

            pack = LosslessStructuralPack(
                schema_version="2.0.0",
                asset_id=scen.target_asset.get("asset_id", f"ASSET-{scen.scenario_id}"),
                endpoint_id=f"EP-{scen.scenario_id}",
                route_template=scen.target_asset.get("normalized_path", scen.target_asset.get("raw_path", "/api/v1/resource")),
                http_method=scen.target_asset.get("method", "GET"),
                application_mutability=scen.target_asset.get("application_mutability", "READ_ONLY"),
                parameter_lineage=scen.parameters,
                identity_matrix=scen.identities,
                has_privilege_level_delta=False,
                has_cross_identity_object_access_success=False,
                observed_facts=observed_facts,
                raw_body_sample=raw_sample,
            )

            gap_type = infer_evidence_gap_type(scen.category_id)
            vapt_pack, _ = self.pipeline.retrieve_and_pack(channel_a=pack, gap_type=gap_type)

            routing = DeterministicRoutingDecision(
                schema_version="2.0.0",
                escalate=True,
                has_high_risk_signal=True,
                high_risk_signals=["M5_PHASE9"],
                fail_safe_triggered=False,
            )
            handoff = CascadeHandoffPacket(
                schema_version="2.0.0",
                channel_a_structural=pack,
                routing_decision=routing,
                provenance_hash=f"prov_{pack.asset_id}",
            )
            cat_tmpl = get_counterfactual_template(scen.category_id)
            active_descriptor = HandoffSerializer.from_cascade_packet(
                handoff_packet=handoff,
                evidence_gap_type=gap_type,
                invariant=cat_tmpl.invariant_definition,
            )

            target_asset_enriched = dict(scen.target_asset)
            target_asset_enriched["parameters"] = list(scen.parameters)
            target_asset_enriched["identities"] = list(scen.identities)

            # Build deterministic experiment skeleton
            skeleton = ExperimentSkeletonBuilder.build_skeleton(
                category_id=scen.category_id,
                invariant_definition=cat_tmpl.invariant_definition,
                evidence_gap_type=gap_type.value,
            )
            skeleton_prompt_block = render_skeleton_prompt_block(skeleton)

            for track_id in BENCHMARK_TRACKS:
                cascade_mode = TRACK_A if track_id == ConfirmatoryTrackId.TRACK_A else TRACK_D
                effective_vapt = vapt_pack if track_id == ConfirmatoryTrackId.TRACK_D else None

                base_ctx = self.context_builder.build_context(
                    handoff_packet=handoff,
                    model_identifier="qwen2.5-coder:7b",
                    budget_tier=4096,
                    cascade_mode=cascade_mode,
                    vapt_pack=effective_vapt,
                    enable_i2_namespace_partitioning=True,
                    enable_i3_counterfactual_prompting=True,
                    category_id=scen.category_id,
                    enable_i4_bair=True,
                    enable_i5_decision_policy=True,
                    enable_i6_handoff=True,
                    protected_handoff=active_descriptor,
                    output_protocol=OutputProtocolIdentifier.JSON_BAIR,
                )

                # Additive prompt integration
                user_prompt_with_skeleton = base_ctx.user_prompt + "\n\n" + skeleton_prompt_block

                schema = self.proto_contract.runtime_schema_factory(True)
                contract = ReasoningExecutionContract(
                    protocol=OutputProtocolIdentifier.JSON_BAIR,
                    enable_i1=True,
                    enable_i2=True,
                    enable_i3=True,
                    enable_i4=True,
                    enable_i5=True,
                    enable_i6=True,
                    system_prompt=base_ctx.system_prompt,
                    user_prompt=user_prompt_with_skeleton,
                    runtime_schema=schema,
                    parser=self.proto_contract.parser,
                    validator=self.proto_contract.validator,
                    adapter=self.proto_contract.adapter,
                    budget_tier=4096,
                    floor_tokens=1000,
                    total_tokens=base_ctx.token_count,
                    protected_handoff_present=True,
                    category_id=scen.category_id,
                )
                validate_reasoning_contract(contract)

                for cond in PHASE9_CONDITIONS:
                    call_key = ("BENCHMARK", sid, track_id.value, cond.condition_id)
                    if call_key in completed_keys:
                        continue

                    call_idx += 1
                    print(f"  [Call #{call_idx:02d}/44] {sid} | {track_id.value} | {cond.condition_id} (num_predict={cond.num_predict}) ...", end=" ", flush=True)

                    t0 = time.perf_counter()
                    exec_res = self.runner.execute_m5_generation(
                        contract=contract,
                        empirical_evidence_present=True,
                        grounding_validator=self.validator,
                        channel_a=pack,
                        target_asset=target_asset_enriched,
                        category_id=scen.category_id,
                        vapt_pack=effective_vapt,
                        num_predict=cond.num_predict,
                    )
                    lat_ms = (time.perf_counter() - t0) * 1000.0

                    # Parse output details
                    parsed_dict = None
                    cand_dec = None
                    act = None
                    supp = None
                    disp = None

                    # If classification is valid, parsed_intermediate is BairJsonObject
                    if exec_res.classification.is_valid and exec_res.parsed_intermediate:
                        parsed_dict = exec_res.parsed_intermediate.model_dump() if hasattr(exec_res.parsed_intermediate, "model_dump") else exec_res.parsed_intermediate
                    elif exec_res.raw_response:
                        try:
                            parsed_dict = json.loads(exec_res.raw_response)
                        except Exception:
                            pass

                    if parsed_dict:
                        cand_dec = parsed_dict.get("decision")
                        act = parsed_dict.get("experiment_action")
                        supp = parsed_dict.get("supporting_outcome")
                        disp = parsed_dict.get("disproving_outcome")

                    final_dec = str(exec_res.canonical_hypothesis.decision) if exec_res.canonical_hypothesis else None

                    # Polarity validation
                    polarity_valid = False
                    polarity_reason = None
                    skeleton_compliant = False
                    skeleton_reason = None

                    if cand_dec == "HYPOTHESIS" or final_dec == "HypothesisDecision.HYPOTHESIS":
                        # 1. Skeleton compliance
                        s_ok, s_msg = validate_skeleton_compliance(skeleton, act, supp, disp)
                        skeleton_compliant = s_ok
                        skeleton_reason = s_msg

                        # 2. Authoritative polarity tuple validation
                        p_ok, p_msg = ExperimentPolarityValidator.validate_tuple(
                            category_id=scen.category_id,
                            experiment_action=act,
                            supporting_outcome=supp,
                            disproving_outcome=disp,
                        )
                        polarity_valid = p_ok
                        polarity_reason = p_msg

                    # Determine applicability
                    app_state = determine_applicability_state(
                        is_valid_output=exec_res.classification.is_valid,
                        target_relevant=True,
                        canonical_evidence_has_anomaly=False,
                    )

                    rec = {
                        "call_index": call_idx,
                        "call_type": "BENCHMARK",
                        "identifier": sid,
                        "track_id": track_id.value,
                        "condition_id": cond.condition_id,
                        "num_predict": cond.num_predict,
                        "category_id": scen.category_id,
                        "vulnerable_variant": scen.vulnerable_variant,
                        "latency_ms": lat_ms,
                        "is_valid": exec_res.classification.is_valid,
                        "primary_failure_category": exec_res.classification.primary_category.value,
                        "error_message": exec_res.classification.error_message,
                        "candidate_decision": cand_dec,
                        "final_decision": final_dec,
                        "experiment_action": act,
                        "supporting_outcome": supp,
                        "disproving_outcome": disp,
                        "skeleton_action_matched": (act == skeleton.experiment_action),
                        "skeleton_compliant": skeleton_compliant,
                        "skeleton_reason": skeleton_reason,
                        "polarity_valid": polarity_valid,
                        "polarity_reason": polarity_reason,
                        "grounding_valid": bool(exec_res.grounding_result and exec_res.grounding_result.get("is_valid", False)),
                        "applicability_state": app_state.value,
                        "eval_count": exec_res.eval_count,
                        "prompt_eval_count": exec_res.prompt_eval_count,
                        "skeleton_hash": skeleton.provenance_hash,
                    }
                    records.append(rec)
                    self.save_checkpoint(records)

                    status_tag = "VALID" if rec["is_valid"] else f"FAIL({rec['primary_failure_category']})"
                    dec_tag = f"Dec={final_dec}" if final_dec else f"Cand={cand_dec}"
                    pol_tag = "Pol=OK" if polarity_valid else ("Pol=FAIL" if cand_dec == "HYPOTHESIS" else "Pol=N/A")
                    print(f"{status_tag} | {dec_tag} | {pol_tag} | {lat_ms:.0f}ms | tok={exec_res.eval_count}")

        # Part 2: Active-Evidence Diagnostic Study (8 calls: 4 scenarios x Track A x 2 conditions)
        active_conditions = [c for c in PHASE9_CONDITIONS if c.condition_id in ("P3-300", "P3-512")]
        for f in ACTIVE_EVIDENCE_FIXTURES:
            fid = f["id"]

            pack_kwargs = {
                "schema_version": "2.0.0",
                "asset_id": f"ASSET-{fid}",
                "endpoint_id": f"EP-{fid}",
                "route_template": f["route"],
                "http_method": f["method"],
                "application_mutability": "STATE_CHANGING" if f["method"] in ("POST", "PUT") else "READ_ONLY",
                "parameter_lineage": f["parameters"],
                "identity_matrix": f["identities"],
                "has_privilege_level_delta": False,
                "has_cross_identity_object_access_success": False,
                "has_observed_contradictions": False,
                "observed_facts": f["evidence"],
                "raw_body_sample": f["evidence"][0]["statement"],
            }
            pack_kwargs[f["anomaly_key"]] = True
            pack = LosslessStructuralPack(**pack_kwargs)

            routing = DeterministicRoutingDecision(
                schema_version="2.0.0",
                escalate=True,
                has_high_risk_signal=True,
                high_risk_signals=["ACTIVE_ANOMALY"],
                fail_safe_triggered=False,
            )
            handoff = CascadeHandoffPacket(
                schema_version="2.0.0",
                channel_a_structural=pack,
                routing_decision=routing,
                provenance_hash=f"prov_{pack.asset_id}",
            )
            cat_tmpl = get_counterfactual_template(f["category_id"])
            gap_type = infer_evidence_gap_type(f["category_id"])
            active_descriptor = HandoffSerializer.from_cascade_packet(
                handoff_packet=handoff,
                evidence_gap_type=gap_type,
                invariant=cat_tmpl.invariant_definition,
            )

            # Build deterministic skeleton
            skeleton = ExperimentSkeletonBuilder.build_skeleton(
                category_id=f["category_id"],
                invariant_definition=cat_tmpl.invariant_definition,
                evidence_gap_type=gap_type.value,
            )
            skeleton_prompt_block = render_skeleton_prompt_block(skeleton)

            ctx = self.context_builder.build_context(
                handoff_packet=handoff,
                model_identifier="qwen2.5-coder:7b",
                budget_tier=4096,
                cascade_mode=TRACK_A,  # Mandatory Correction 3: Track A only
                vapt_pack=None,
                enable_i2_namespace_partitioning=True,
                enable_i3_counterfactual_prompting=True,
                category_id=f["category_id"],
                enable_i4_bair=True,
                enable_i5_decision_policy=True,
                enable_i6_handoff=True,
                protected_handoff=active_descriptor,
                output_protocol=OutputProtocolIdentifier.JSON_BAIR,
            )

            user_prompt_with_skeleton = ctx.user_prompt + "\n\n" + skeleton_prompt_block
            schema = self.proto_contract.runtime_schema_factory(True)
            contract = ReasoningExecutionContract(
                protocol=OutputProtocolIdentifier.JSON_BAIR,
                enable_i1=True,
                enable_i2=True,
                enable_i3=True,
                enable_i4=True,
                enable_i5=True,
                enable_i6=True,
                system_prompt=ctx.system_prompt,
                user_prompt=user_prompt_with_skeleton,
                runtime_schema=schema,
                parser=self.proto_contract.parser,
                validator=self.proto_contract.validator,
                adapter=self.proto_contract.adapter,
                budget_tier=4096,
                floor_tokens=1000,
                total_tokens=ctx.token_count,
                protected_handoff_present=True,
                category_id=f["category_id"],
            )
            validate_reasoning_contract(contract)

            target_asset = {
                "asset_id": pack.asset_id,
                "normalized_path": f["route"],
                "method": f["method"],
                "parameters": f["parameters"],
                "identities": f["identities"],
            }

            has_anomaly = canonical_vulnerability_evidence_present(
                evidence=f["evidence"],
                structural_pack=pack,
            )
            assert has_anomaly is True, "Active anomaly was not detected!"

            for cond in active_conditions:
                call_key = ("ACTIVE_EVIDENCE", fid, ConfirmatoryTrackId.TRACK_A.value, cond.condition_id)
                if call_key in completed_keys:
                    continue

                call_idx += 1
                print(f"  [Call #{call_idx:02d}/44] [ACTIVE] {fid} | {cond.condition_id} (num_predict={cond.num_predict}) ...", end=" ", flush=True)

                t0 = time.perf_counter()
                exec_res = self.runner.execute_m5_generation(
                    contract=contract,
                    empirical_evidence_present=True,
                    grounding_validator=self.validator,
                    channel_a=pack,
                    target_asset=target_asset,
                    category_id=f["category_id"],
                    num_predict=cond.num_predict,
                )
                lat_ms = (time.perf_counter() - t0) * 1000.0

                parsed_dict = None
                cand_dec = None
                act = None
                supp = None
                disp = None

                if exec_res.classification.is_valid and exec_res.parsed_intermediate:
                    parsed_dict = exec_res.parsed_intermediate.model_dump() if hasattr(exec_res.parsed_intermediate, "model_dump") else exec_res.parsed_intermediate
                elif exec_res.raw_response:
                    try:
                        parsed_dict = json.loads(exec_res.raw_response)
                    except Exception:
                        pass

                if parsed_dict:
                    cand_dec = parsed_dict.get("decision")
                    act = parsed_dict.get("experiment_action")
                    supp = parsed_dict.get("supporting_outcome")
                    disp = parsed_dict.get("disproving_outcome")

                final_dec = str(exec_res.canonical_hypothesis.decision) if exec_res.canonical_hypothesis else None

                polarity_valid = False
                polarity_reason = None
                skeleton_compliant = False
                skeleton_reason = None

                if cand_dec == "HYPOTHESIS" or final_dec == "HypothesisDecision.HYPOTHESIS":
                    s_ok, s_msg = validate_skeleton_compliance(skeleton, act, supp, disp)
                    skeleton_compliant = s_ok
                    skeleton_reason = s_msg

                    p_ok, p_msg = ExperimentPolarityValidator.validate_tuple(
                        category_id=f["category_id"],
                        experiment_action=act,
                        supporting_outcome=supp,
                        disproving_outcome=disp,
                    )
                    polarity_valid = p_ok
                    polarity_reason = p_msg

                app_state = determine_applicability_state(
                    is_valid_output=exec_res.classification.is_valid,
                    target_relevant=True,
                    canonical_evidence_has_anomaly=has_anomaly,
                )

                rec = {
                    "call_index": call_idx,
                    "call_type": "ACTIVE_EVIDENCE",
                    "identifier": fid,
                    "track_id": ConfirmatoryTrackId.TRACK_A.value,
                    "condition_id": cond.condition_id,
                    "num_predict": cond.num_predict,
                    "category_id": f["category_id"],
                    "vulnerable_variant": True,
                    "has_canonical_anomaly": True,
                    "latency_ms": lat_ms,
                    "is_valid": exec_res.classification.is_valid,
                    "primary_failure_category": exec_res.classification.primary_category.value,
                    "error_message": exec_res.classification.error_message,
                    "candidate_decision": cand_dec,
                    "final_decision": final_dec,
                    "experiment_action": act,
                    "supporting_outcome": supp,
                    "disproving_outcome": disp,
                    "skeleton_action_matched": (act == skeleton.experiment_action),
                    "skeleton_compliant": skeleton_compliant,
                    "skeleton_reason": skeleton_reason,
                    "polarity_valid": polarity_valid,
                    "polarity_reason": polarity_reason,
                    "grounding_valid": bool(exec_res.grounding_result and exec_res.grounding_result.get("is_valid", False)),
                    "applicability_state": app_state.value,
                    "eval_count": exec_res.eval_count,
                    "prompt_eval_count": exec_res.prompt_eval_count,
                    "skeleton_hash": skeleton.provenance_hash,
                }
                records.append(rec)
                self.save_checkpoint(records)

                status_tag = "VALID" if rec["is_valid"] else f"FAIL({rec['primary_failure_category']})"
                dec_tag = f"Dec={final_dec}" if final_dec else f"Cand={cand_dec}"
                pol_tag = "Pol=OK" if polarity_valid else ("Pol=FAIL" if cand_dec == "HYPOTHESIS" else "Pol=N/A")
                print(f"{status_tag} | {dec_tag} | {pol_tag} | App={app_state.value} | {lat_ms:.0f}ms | tok={exec_res.eval_count}")

        assert len(records) == 44, f"Expected exactly 44 records, got {len(records)}"
        return records


# ---------------------------------------------------------------------------
# Metrics Computation & Artifact Serialization
# ---------------------------------------------------------------------------

def compute_phase9_metrics(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    benchmark_records = [r for r in records if r["call_type"] == "BENCHMARK"]
    active_records = [r for r in records if r["call_type"] == "ACTIVE_EVIDENCE"]

    condition_metrics = {}
    for cond_id in ["P3-300", "P3-512", "P3-768"]:
        recs = [r for r in benchmark_records if r["condition_id"] == cond_id]
        n = len(recs)
        if n == 0:
            continue

        valid_execs = sum(1 for r in recs if r["is_valid"])
        cand_attempts = sum(1 for r in recs if r.get("candidate_decision") == "HYPOTHESIS" or r.get("polarity_valid"))
        valid_proposals = sum(1 for r in recs if r.get("polarity_valid"))

        type_rate = (valid_proposals / cand_attempts * 100.0) if cand_attempts > 0 else 0.0

        pol_fails = sum(1 for r in recs if r["primary_failure_category"] == "SEMANTIC_EXPERIMENT_POLARITY_FAILURE")
        schema_fails = sum(1 for r in recs if r["primary_failure_category"] == "SCHEMA_VALIDITY_FAILURE")
        truncations = sum(1 for r in recs if r["primary_failure_category"] == "MAX_TOKEN_TRUNCATION")
        grounding_fails = sum(1 for r in recs if r["primary_failure_category"] == "SEMANTIC_GROUNDING_FAILURE")
        action_incompat = sum(1 for r in recs if not r.get("skeleton_action_matched", True) and r.get("candidate_decision") == "HYPOTHESIS")

        lats = [r["latency_ms"] / 1000.0 for r in recs]
        tokens = [r["eval_count"] for r in recs if r.get("eval_count") is not None]

        sorted_lats = sorted(lats)
        sorted_tokens = sorted(tokens) if tokens else []

        dec_dist = Counter(r.get("final_decision") or r.get("candidate_decision") or r["primary_failure_category"] for r in recs)

        condition_metrics[cond_id] = {
            "total_calls": n,
            "valid_executions": valid_execs,
            "valid_execution_rate": round(valid_execs / n * 100.0, 2),
            "candidate_hypothesis_attempts": cand_attempts,
            "valid_typed_experiment_proposals": valid_proposals,
            "valid_typed_experiment_rate": round(type_rate, 2),
            "action_incompatibility_failures": action_incompat,
            "polarity_failures": pol_fails,
            "schema_failures": schema_fails,
            "truncations": truncations,
            "grounding_failures": grounding_fails,
            "decision_distribution": dict(dec_dist),
            "latency": {
                "mean_seconds": round(sum(lats) / n, 2),
                "median_seconds": round(sorted_lats[n // 2], 2),
                "min_seconds": round(min(lats), 2),
                "max_seconds": round(max(lats), 2),
            },
            "completion_tokens": {
                "mean_tokens": round(sum(tokens) / len(tokens), 1) if tokens else 0,
                "median_tokens": sorted_tokens[len(tokens) // 2] if tokens else 0,
                "min_tokens": min(tokens) if tokens else 0,
                "max_tokens": max(tokens) if tokens else 0,
            },
        }

    # Active evidence metrics
    active_summary = []
    for r in active_records:
        active_summary.append({
            "fixture_id": r["identifier"],
            "category_id": r["category_id"],
            "condition_id": r["condition_id"],
            "num_predict": r["num_predict"],
            "is_valid": r["is_valid"],
            "candidate_decision": r.get("candidate_decision"),
            "final_decision": r.get("final_decision"),
            "polarity_valid": r.get("polarity_valid"),
            "primary_failure_category": r["primary_failure_category"],
            "applicability_state": r["applicability_state"],
            "latency_seconds": round(r["latency_ms"] / 1000.0, 2),
            "completion_tokens": r.get("eval_count"),
        })

    return {
        "condition_metrics": condition_metrics,
        "active_evidence_diagnostic": active_summary,
    }


def main():
    start_time = time.time()
    print("================================================================================")
    print("STARTING M5 PHASE 9: DETERMINISTIC EXPERIMENT SKELETON & BUDGET STUDY")
    print("================================================================================")

    # 1. Preflight
    preflight_info = run_preflight()

    # 2. Run Study
    study_runner = Phase9StudyRunner()
    records = study_runner.run_study()

    # 3. Compute Metrics
    metrics = compute_phase9_metrics(records)

    total_time = time.time() - start_time

    # 4. Compile Artifact
    artifact = {
        "schema_version": "9.0.0",
        "milestone": "M5",
        "phase": "PHASE_9_DETERMINISTIC_EXPERIMENT_SKELETON",
        "status": "M5_PHASE9_COMPLETE",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_runtime_seconds": round(total_time, 2),
        "total_live_calls": len(records),
        "manifest_hash": preflight_info["manifest_hash"],
        "metadata": {
            "model_name": "qwen2.5-coder:7b",
            "model_digest": preflight_info["model_digest"],
            "runtime_version": preflight_info["ollama_version"],
            "inference_parameters": {
                "num_ctx": PRIMARY_NUM_CTX,
                "temperature": PRIMARY_TEMPERATURE,
                "seed": PRIMARY_SEED,
                "keep_alive": PRIMARY_KEEP_ALIVE,
            },
            "sealed_phase7_sha": preflight_info["p7_sha"],
            "sealed_phase8_sha": preflight_info["p8_sha"],
            "scenarios_sha": preflight_info["scenarios_sha"],
        },
        "study_design": {
            "representative_benchmark_scenarios": REPRESENTATIVE_BENCHMARK_SCENARIOS,
            "active_evidence_fixtures": [f["id"] for f in ACTIVE_EVIDENCE_FIXTURES],
            "tracks": [t.value for t in BENCHMARK_TRACKS],
            "conditions": [asdict(c) for c in PHASE9_CONDITIONS],
        },
        "metrics": metrics,
        "call_records": records,
    }

    P9_OUTPUT_JSON.write_text(json.dumps(artifact, indent=2), encoding="utf-8")
    p9_sha = hash_file(P9_OUTPUT_JSON)
    P9_OUTPUT_SHA.write_text(f"{p9_sha}  {P9_OUTPUT_JSON.name}\n", encoding="utf-8")

    # Remove temporary checkpoint on successful completion
    if P9_CHECKPOINT_JSON.exists():
        P9_CHECKPOINT_JSON.unlink()

    print("\n================================================================================")
    print(f"PHASE 9 STUDY ARTIFACT SAVED: {P9_OUTPUT_JSON}")
    print(f"PHASE 9 ARTIFACT SHA-256: {p9_sha}")
    print(f"Total Live Calls: {len(records)} (36 Benchmark + 8 Active Evidence)")
    print(f"Elapsed Time: {total_time/60.0:.1f} minutes")
    print("================================================================================")


if __name__ == "__main__":
    main()
