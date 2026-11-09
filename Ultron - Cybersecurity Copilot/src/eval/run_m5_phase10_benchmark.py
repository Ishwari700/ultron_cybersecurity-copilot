"""
Milestone M5 Phase 10: Full-Population Confirmatory Benchmark Runner.

Executes the pre-registered 336-call 2x2 factorial confirmatory benchmark:
  C1: Deterministic Skeleton + Track A (Minimal Structural)
  C2: Deterministic Skeleton + Track D (Full Cascade + RAG Pack)
  C3: Baseline Architecture   + Track A (Minimal Structural)
  C4: Baseline Architecture   + Track D (Full Cascade + RAG Pack)

Across all 84 benchmark scenarios (36 vulnerable variants + 48 negative controls).
84 scenarios x 4 conditions = exactly 336 scheduled live calls.

Strict Pre-Registered Invariants:
- Exactly 336 scheduled calls total.
- Exactly one attempt per call, zero retries, zero semantic repairs.
- Deterministic condition ordering (C1 -> C2 -> C3 -> C4).
- Deterministic scenario ordering (sorted alphabetically by scenario_id).
- Frozen Ollama v0.34.1, qwen2.5-coder:7b (dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364).
- num_ctx=2048, num_predict=300, temperature=0.0, seed=42, keep_alive=60m.
- Dual hard runtime control: 30.0s HTTP timeout + wall-clock deadline ceiling.
- Telemetry: prompt_build_latency_ms, inference_latency_ms (eval_duration ns->ms or 'unavailable'),
  response_parse_latency_ms, validation_latency_ms, total_latency_ms.
- Atomic checkpointing (data/eval/m5_phase10_checkpoint.json).
- Crash-safe resume, duplicate-call prevention.
- Raw dataset frozen to data/eval/m5_phase10_full_population_validation.json + SHA-256 sidecar.
- Zero ground-truth leakage, zero breach/safe partition leakage, zero secrets.
- Primary diagnostic metrics: Valid Typed Experiment Rate and Automated Useful Hypothesis Rate.
"""

from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

repo_root = Path(__file__).resolve().parent.parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from pydantic import BaseModel, ConfigDict, Field

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
    PRIMARY_NUM_PREDICT,
    PRIMARY_SEED,
    PRIMARY_TEMPERATURE,
    ReasoningRunner,
)
from src.eval.m4_live_benchmark import (
    ConfirmatoryTrackId,
    FORBIDDEN_PROMPT_TOKENS,
    EXPECTED_7B_DIGEST_FULL,
    infer_evidence_gap_type,
)
from src.eval.scenarios import EvaluationScenario, get_gold_set_scenarios
from src.eval.scorer import (
    EvaluationApplicabilityState,
    canonical_vulnerability_evidence_present,
    determine_applicability_state,
)
from src.eval.verify_m5_phase10_preflight import (
    FROZEN_HISTORICAL_HASHES,
    hash_file,
    run_phase10_preflight_gates,
)
from src.evidence.cascade_models import (
    CascadeHandoffPacket,
    DeterministicRoutingDecision,
    LosslessStructuralPack,
)
from src.knowledge.grounding_validator import KnowledgeGroundingValidator
from src.knowledge.models import EvidenceGapType, VaptKnowledgePack
from src.knowledge.pipeline import VaptReasoningPipeline

CHECKPOINT_PATH = repo_root / "data/eval/m5_phase10_checkpoint.json"
FINAL_RAW_PATH = repo_root / "data/eval/m5_phase10_full_population_validation.json"
FINAL_SHA_PATH = repo_root / "data/eval/m5_phase10_full_population_validation.json.sha256"


# ---------------------------------------------------------------------------
# Pre-Registered Factorial Design Conditions
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Phase10Condition:
    condition_id: str
    architecture: str
    track_id: ConfirmatoryTrackId
    description: str


PHASE10_CONDITIONS: List[Phase10Condition] = [
    Phase10Condition(
        condition_id="C1",
        architecture="DETERMINISTIC_EXPERIMENT_SKELETON",
        track_id=ConfirmatoryTrackId.TRACK_A,
        description="Deterministic Skeleton + Track A (Minimal Structural)",
    ),
    Phase10Condition(
        condition_id="C2",
        architecture="DETERMINISTIC_EXPERIMENT_SKELETON",
        track_id=ConfirmatoryTrackId.TRACK_D,
        description="Deterministic Skeleton + Track D (Full Cascade + RAG Pack)",
    ),
    Phase10Condition(
        condition_id="C3",
        architecture="BASELINE_EXISTING_ARCHITECTURE",
        track_id=ConfirmatoryTrackId.TRACK_A,
        description="Baseline Architecture + Track A (Minimal Structural)",
    ),
    Phase10Condition(
        condition_id="C4",
        architecture="BASELINE_EXISTING_ARCHITECTURE",
        track_id=ConfirmatoryTrackId.TRACK_D,
        description="Baseline Architecture + Track D (Full Cascade + RAG Pack)",
    ),
]


FROZEN_ORDER_RANDOMIZATION_SEED: str = "M5_PHASE10_FACTORIAL_ORDER_SEED_42"


def get_deterministic_condition_order(
    scenario_id: str,
    frozen_seed: str = FROZEN_ORDER_RANDOMIZATION_SEED,
    conditions: Optional[List[Phase10Condition]] = None,
) -> List[Phase10Condition]:
    """
    Deterministically pseudo-randomizes the 4 factorial conditions for a given scenario.
    
    Guarantees:
    - Same scenario + same frozen seed => identical condition ordering.
    - Different scenario IDs produce different condition orderings (de-biasing execution order).
    - All four conditions are executed exactly once per scenario.
    - Zero conditions omitted, zero conditions duplicated.
    - Deterministic, reproducible, independent of model outputs or runtime failures.
    """
    import random
    target_conditions = list(conditions or PHASE10_CONDITIONS)
    payload = f"{frozen_seed}:{scenario_id}".encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()
    seed_int = int(digest[:16], 16)
    rng = random.Random(seed_int)
    shuffled = list(target_conditions)
    rng.shuffle(shuffled)
    return shuffled


# ---------------------------------------------------------------------------
# Benchmark Runner
# ---------------------------------------------------------------------------

class M5Phase10BenchmarkRunner:
    """Authoritative execution runner for Phase 10 full-population benchmark."""

    def __init__(
        self,
        llm_caller: Optional[Callable[[str, Optional[Dict[str, Any]]], str]] = None,
        checkpoint_path: Optional[Path] = None,
        final_raw_path: Optional[Path] = None,
        order_seed: Optional[str] = None,
    ):
        self.runner = ReasoningRunner(
            model_name="qwen2.5-coder:7b",
            num_ctx=PRIMARY_NUM_CTX,
            llm_caller=llm_caller,
        )
        self.context_builder = ReasoningContextBuilder()
        self.validator = KnowledgeGroundingValidator()
        self.pipeline = VaptReasoningPipeline()
        self.proto_contract = get_protocol_contract(OutputProtocolIdentifier.JSON_BAIR)
        self.gold_scenarios: List[EvaluationScenario] = sorted(
            get_gold_set_scenarios(), key=lambda s: s.scenario_id
        )
        assert len(self.gold_scenarios) == 84, f"Expected 84 scenarios, got {len(self.gold_scenarios)}"

        self.checkpoint_path = checkpoint_path or CHECKPOINT_PATH
        self.final_raw_path = final_raw_path or FINAL_RAW_PATH
        self.final_sha_path = self.final_raw_path.with_suffix(".json.sha256")
        self.order_seed = order_seed or FROZEN_ORDER_RANDOMIZATION_SEED
        self._canonical_input_cache: Dict[str, Dict[str, Any]] = {}

    def get_canonical_input(self, scenario_id: str) -> Dict[str, Any]:
        """Builds cached canonical structural input packet and VAPT pack for scenario."""
        if scenario_id in self._canonical_input_cache:
            return self._canonical_input_cache[scenario_id]

        gold_scen = [s for s in self.gold_scenarios if s.scenario_id == scenario_id][0]
        observed_facts = gold_scen.initial_evidence or [
            {"fact_id": "FACT-00000001", "statement": "Neutral observable target evidence."}
        ]
        raw_sample = str(observed_facts[0].get("statement", "")) if observed_facts else ""

        asset_id = gold_scen.target_asset.get("asset_id", f"ASSET-{gold_scen.scenario_id}")
        endpoint_id = f"EP-{asset_id}"

        # Clean Channel A: Zero ground-truth leakage
        pack = LosslessStructuralPack(
            schema_version="2.0.0",
            asset_id=asset_id,
            endpoint_id=endpoint_id,
            route_template=gold_scen.target_asset.get(
                "normalized_path", gold_scen.target_asset.get("raw_path", "/api/v1/resource")
            ),
            http_method=gold_scen.target_asset.get("method", "GET"),
            application_mutability=gold_scen.target_asset.get("application_mutability", "READ_ONLY"),
            parameter_lineage=gold_scen.parameters,
            identity_matrix=gold_scen.identities,
            has_privilege_level_delta=False,
            has_cross_identity_object_access_success=False,
            observed_facts=observed_facts,
            raw_body_sample=raw_sample,
        )

        gap_type = infer_evidence_gap_type(gold_scen.category_id)
        vapt_pack, _ = self.pipeline.retrieve_and_pack(channel_a=pack, gap_type=gap_type)

        ev_bytes = json.dumps(observed_facts, sort_keys=True).encode("utf-8")
        meta_bytes = json.dumps(gold_scen.target_asset, sort_keys=True).encode("utf-8")
        input_hash = hashlib.sha256(ev_bytes + meta_bytes).hexdigest().lower()

        # Extract target evidence representation hash
        target_context_hash = hashlib.sha256(pack.model_dump_json().encode("utf-8")).hexdigest().lower()

        entry = {
            "gold_scenario": gold_scen,
            "pack": pack,
            "gap_type": gap_type,
            "vapt_pack": vapt_pack,
            "canonical_evidence_hash": input_hash,
            "target_context_hash": target_context_hash,
        }
        self._canonical_input_cache[scenario_id] = entry
        return entry

    def load_checkpoint(self) -> List[Dict[str, Any]]:
        """Loads completed records from atomic checkpoint."""
        if self.checkpoint_path.exists():
            try:
                data = json.loads(self.checkpoint_path.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    return data
            except Exception:
                pass
        return []

    def save_checkpoint(self, records: List[Dict[str, Any]]):
        """Atomically saves completed records to checkpoint file."""
        self.checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self.checkpoint_path.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(records, indent=2), encoding="utf-8")
        tmp_path.replace(self.checkpoint_path)

    def freeze_dataset(self, records: List[Dict[str, Any]]) -> str:
        """Freezes final benchmark raw JSON and generates bit-for-bit SHA-256 sidecar."""
        self.final_raw_path.parent.mkdir(parents=True, exist_ok=True)
        raw_json_str = json.dumps(records, indent=2, sort_keys=True)
        self.final_raw_path.write_text(raw_json_str, encoding="utf-8")
        sha256_digest = hashlib.sha256(raw_json_str.encode("utf-8")).hexdigest().lower()
        self.final_sha_path.write_text(f"{sha256_digest}  {self.final_raw_path.name}\n", encoding="utf-8")
        return sha256_digest

    def run_benchmark(
        self,
        require_live_ollama: bool = True,
        max_calls: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Executes the Phase 10 confirmatory benchmark.
        Fails closed on any unexpected error or protocol breach.
        """
        # 1. Preflight Verification Gate
        print("\n[Phase 10 Benchmark] Executing preflight integrity gate...")
        run_phase10_preflight_gates(require_ollama_daemon=require_live_ollama)

        # 2. Checkpoint Resume & Matrix Verification
        records = self.load_checkpoint()
        completed_keys: Set[Tuple[str, str]] = {
            (r["condition_id"], r["scenario_id"]) for r in records
        }
        print(f"[Phase 10 Benchmark] Loaded {len(records)} existing completed records from checkpoint.")

        total_scheduled = len(PHASE10_CONDITIONS) * len(self.gold_scenarios)
        assert total_scheduled == 336, f"Expected 336 scheduled calls, got {total_scheduled}"

        # 3. Factorial Execution Loop with Deterministic Pseudo-Random Condition Ordering per Scenario
        call_idx = len(records)
        for scen in self.gold_scenarios:
            sid = scen.scenario_id
            ordered_conditions = get_deterministic_condition_order(sid, self.order_seed)
            scenario_condition_order_str = [c.condition_id for c in ordered_conditions]

            for cond_order_idx, cond in enumerate(ordered_conditions, start=1):
                call_key = (cond.condition_id, sid)
                if call_key in completed_keys:
                    continue

                if max_calls is not None and call_idx >= max_calls:
                    print(f"[Phase 10 Benchmark] Reached max_calls cap ({max_calls}). Stopping early.")
                    return records

                call_idx += 1
                print(
                    f"  [Call #{call_idx:03d}/336] {sid} | {cond.condition_id} "
                    f"(order {cond_order_idx}/4: {cond.architecture[:8]}.. | {cond.track_id.value}) ...",
                    end=" ",
                    flush=True,
                )

                # Canonical structural input & VAPT
                canonical_data = self.get_canonical_input(sid)
                pack: LosslessStructuralPack = canonical_data["pack"]
                gap_type: EvidenceGapType = canonical_data["gap_type"]
                vapt_pack: Optional[VaptKnowledgePack] = canonical_data["vapt_pack"]

                routing = DeterministicRoutingDecision(
                    schema_version="2.0.0",
                    escalate=True,
                    has_high_risk_signal=True,
                    high_risk_signals=["M5_PHASE10"],
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

                # Track cascade configuration
                cascade_mode = TRACK_A if cond.track_id == ConfirmatoryTrackId.TRACK_A else TRACK_D
                effective_vapt = vapt_pack if cond.track_id == ConfirmatoryTrackId.TRACK_D else None

                t_prompt_start = time.perf_counter()
                base_ctx = self.context_builder.build_context(
                    handoff_packet=handoff,
                    model_identifier="qwen2.5-coder:7b",
                    budget_tier=2048,
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

                # Architecture Branching: Skeleton Injection vs Baseline
                skeleton_desc: Optional[ExperimentSkeletonDescriptor] = None
                skeleton_config_hash = "NONE"
                user_prompt = base_ctx.user_prompt

                if cond.architecture == "DETERMINISTIC_EXPERIMENT_SKELETON":
                    skeleton_desc = ExperimentSkeletonBuilder.build_skeleton(
                        category_id=scen.category_id,
                        invariant_definition=cat_tmpl.invariant_definition,
                        evidence_gap_type=gap_type.value,
                    )
                    skeleton_prompt_block = render_skeleton_prompt_block(skeleton_desc)
                    user_prompt = base_ctx.user_prompt + "\n\n" + skeleton_prompt_block
                    skeleton_config_hash = skeleton_desc.provenance_hash

                t_prompt_end = time.perf_counter()
                prompt_build_latency_ms = round((t_prompt_end - t_prompt_start) * 1000.0, 2)

                # Leakage assertions
                full_prompt = f"{base_ctx.system_prompt}\n{user_prompt}"
                prompt_hash = hashlib.sha256(full_prompt.encode("utf-8")).hexdigest().lower()
                prompt_lower = full_prompt.lower()
                for token in FORBIDDEN_PROMPT_TOKENS:
                    assert token not in prompt_lower, (
                        f"STOP CONDITION: Ground-truth token '{token}' leaked into prompt for {sid} ({cond.condition_id})"
                    )

                # Execution Contract
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
                    user_prompt=user_prompt,
                    runtime_schema=schema,
                    parser=self.proto_contract.parser,
                    validator=self.proto_contract.validator,
                    adapter=self.proto_contract.adapter,
                    budget_tier=2048,
                    floor_tokens=1000,
                    total_tokens=base_ctx.token_count,
                    protected_handoff_present=True,
                    category_id=scen.category_id,
                )
                validate_reasoning_contract(contract)

                # Runtime Configuration Hash
                runtime_config = {
                    "model": "qwen2.5-coder:7b",
                    "num_ctx": PRIMARY_NUM_CTX,
                    "num_predict": PRIMARY_NUM_PREDICT,
                    "temperature": PRIMARY_TEMPERATURE,
                    "seed": PRIMARY_SEED,
                    "keep_alive": PRIMARY_KEEP_ALIVE,
                    "timeout_seconds": 30.0,
                    "max_retries": 0,
                }
                runtime_config_hash = hashlib.sha256(
                    json.dumps(runtime_config, sort_keys=True).encode("utf-8")
                ).hexdigest().lower()

                # Single-attempt Live Inference Call with Hard Wall-Clock Ceiling
                exec_res = self.runner.execute_m5_generation(
                    contract=contract,
                    empirical_evidence_present=True,
                    grounding_validator=self.validator,
                    channel_a=pack,
                    target_asset=target_asset_enriched,
                    category_id=scen.category_id,
                    vapt_pack=effective_vapt,
                    num_predict=PRIMARY_NUM_PREDICT,
                )

                # Parse and Extract Response Fields
                parsed_dict: Optional[Dict[str, Any]] = None
                cand_dec: Optional[str] = None
                act: Optional[str] = None
                supp: Optional[str] = None
                disp: Optional[str] = None

                if exec_res.classification.is_valid and exec_res.parsed_intermediate:
                    parsed_dict = (
                        exec_res.parsed_intermediate.model_dump()
                        if hasattr(exec_res.parsed_intermediate, "model_dump")
                        else exec_res.parsed_intermediate
                    )
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

                # Skeleton & Polarity Compliance
                skeleton_compliant: Optional[bool] = None
                skeleton_reason: Optional[str] = None
                polarity_valid: bool = False
                polarity_reason: Optional[str] = None

                is_hypothesis_candidate = (
                    cand_dec == "HYPOTHESIS"
                    or cand_dec == "HypothesisDecision.HYPOTHESIS"
                    or final_dec == "HypothesisDecision.HYPOTHESIS"
                )

                if is_hypothesis_candidate and act and supp and disp:
                    if skeleton_desc is not None:
                        s_ok, s_msg = validate_skeleton_compliance(skeleton_desc, act, supp, disp)
                        skeleton_compliant = s_ok
                        skeleton_reason = s_msg

                    p_ok, p_msg = ExperimentPolarityValidator.validate_tuple(
                        category_id=scen.category_id,
                        experiment_action=act,
                        supporting_outcome=supp,
                        disproving_outcome=disp,
                    )
                    polarity_valid = p_ok
                    polarity_reason = p_msg

                # Grounding Result
                grounding_valid = bool(
                    exec_res.grounding_result and exec_res.grounding_result.get("is_valid", False)
                )

                # Capability Estimand: Valid Typed Experiment Rate
                if cond.architecture == "DETERMINISTIC_EXPERIMENT_SKELETON":
                    is_valid_typed_experiment = (
                        exec_res.classification.is_valid
                        and is_hypothesis_candidate
                        and bool(skeleton_compliant)
                        and polarity_valid
                        and grounding_valid
                    )
                else:
                    is_valid_typed_experiment = (
                        exec_res.classification.is_valid
                        and is_hypothesis_candidate
                        and polarity_valid
                        and grounding_valid
                    )

                # Applicability State & Useful Hypothesis
                has_anomaly = canonical_vulnerability_evidence_present(structural_pack=pack)
                app_state = determine_applicability_state(
                    is_valid_output=exec_res.classification.is_valid,
                    target_relevant=True,
                    canonical_evidence_has_anomaly=has_anomaly,
                )

                # Automated Useful Hypothesis: strictly true only on vulnerable variants with valid typed experiment
                is_useful_hypothesis = (
                    scen.vulnerable_variant and is_valid_typed_experiment
                )

                call_record = {
                    "call_index": call_idx,
                    "condition_id": cond.condition_id,
                    "architecture": cond.architecture,
                    "track_id": cond.track_id.value,
                    "scenario_id": sid,
                    "category_id": scen.category_id,
                    "vulnerable_variant": scen.vulnerable_variant,
                    "scenario_condition_order": scenario_condition_order_str,
                    "condition_order_index": cond_order_idx,
                    "order_randomization_seed": self.order_seed,
                    "model_name": "qwen2.5-coder:7b",
                    "model_digest": EXPECTED_7B_DIGEST_FULL,
                    "runtime_version": "0.34.1",
                    "inference_parameters": runtime_config,
                    "canonical_evidence_hash": canonical_data["canonical_evidence_hash"],
                    "target_context_hash": canonical_data["target_context_hash"],
                    "prompt_hash": prompt_hash,
                    "skeleton_config_hash": skeleton_config_hash,
                    "runtime_config_hash": runtime_config_hash,
                    "raw_response": exec_res.raw_response,
                    "timed_out": exec_res.timed_out,
                    "prompt_build_latency_ms": prompt_build_latency_ms,
                    "inference_latency_ms": exec_res.inference_latency_ms,
                    "response_parse_latency_ms": exec_res.response_parse_latency_ms,
                    "validation_latency_ms": exec_res.validation_latency_ms,
                    "total_latency_ms": exec_res.total_latency_ms,
                    "eval_count": exec_res.eval_count,
                    "prompt_eval_count": exec_res.prompt_eval_count,
                    "contract_valid": exec_res.contract_valid,
                    "is_valid": exec_res.classification.is_valid,
                    "primary_failure_category": exec_res.classification.primary_category.value,
                    "candidate_decision": cand_dec,
                    "final_decision": final_dec,
                    "experiment_action": act,
                    "supporting_outcome": supp,
                    "disproving_outcome": disp,
                    "skeleton_compliant": skeleton_compliant,
                    "skeleton_reason": skeleton_reason,
                    "polarity_valid": polarity_valid,
                    "polarity_reason": polarity_reason,
                    "grounding_valid": grounding_valid,
                    "is_valid_typed_experiment": is_valid_typed_experiment,
                    "applicability_state": app_state.value if app_state else None,
                    "is_useful_hypothesis": is_useful_hypothesis,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }

                records.append(call_record)
                completed_keys.add(call_key)
                self.save_checkpoint(records)

                status_str = "VALID" if is_valid_typed_experiment else exec_res.classification.primary_category.value
                print(f"[{status_str}] (total={exec_res.total_latency_ms:.1f}ms, infer={exec_res.inference_latency_ms})")

        # 4. Freeze Final Raw Dataset
        if len(records) == 336:
            dataset_sha = self.freeze_dataset(records)
            print(f"\n[Phase 10 Benchmark] COMPLETE: 336/336 calls executed.")
            print(f"  Frozen Dataset: {self.final_raw_path}")
            print(f"  SHA-256:        {dataset_sha}")

        return records


if __name__ == "__main__":
    print(
        "\n[SAFETY GATE] M5 Phase 10 full-population benchmark execution requires explicit approval.\n"
        "To execute the live 336-call benchmark, pass the --execute-live-benchmark flag.\n"
    )
    if "--execute-live-benchmark" in sys.argv:
        runner = M5Phase10BenchmarkRunner()
        runner.run_benchmark(require_live_ollama=True)
    else:
        print("Execution halted safely. No benchmark calls performed.\n")
        sys.exit(0)
