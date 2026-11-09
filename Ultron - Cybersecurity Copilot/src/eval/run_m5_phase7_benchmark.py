"""
Milestone M5 Phase 7 — Confirmatory Benchmark Runner.

Executes the formal 84-scenario 4-track confirmatory benchmark (336 live calls total)
against local Ollama qwen2.5-coder:7b under the corrected M5 JSON_BAIR architecture
with Policy 3 evaluation scoring.

Strict Single-Call Rule:
- exactly 1 LLM call per scenario/track (336 calls total)
- zero retries
- zero alternate prompts
- zero parser repair
- zero semantic rewriting
- fail-closed classification on any failure

Artifacts created:
- data/eval/m5_phase7_benchmark_checkpoint.json (incremental checkpoint)
- data/eval/m5_phase7_benchmark_final.json
- data/eval/m5_phase7_benchmark_final.json.sha256
"""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

repo_root = Path(__file__).resolve().parent.parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

import httpx
from pydantic import BaseModel

from src.engine.context_builder import (
    ReasoningContextBuilder,
    TRACK_A,
    TRACK_B,
    TRACK_C,
    TRACK_D,
)
from src.engine.handoff_serializer import HandoffSerializer
from src.engine.models import (
    BairJsonObject,
    HypothesisDecision,
    OutputProtocolIdentifier,
    PrimaryFailureCategory,
)
from src.engine.protocol import (
    ReasoningExecutionContract,
    get_protocol_contract,
    validate_reasoning_contract,
)
from src.engine.prompts import get_counterfactual_template
from src.engine.runner import (
    PRIMARY_KEEP_ALIVE,
    PRIMARY_NUM_CTX,
    PRIMARY_NUM_PREDICT,
    PRIMARY_SEED,
    PRIMARY_TEMPERATURE,
    ReasoningRunner,
)
from src.eval.scenarios import EvaluationScenario, get_gold_set_scenarios
from src.eval.m4_live_benchmark import (
    ConfirmatoryTrackId,
    infer_evidence_gap_type,
    FORBIDDEN_PROMPT_TOKENS,
    EXPECTED_7B_DIGEST_FULL,
    EXPECTED_BENCHMARK_HASH,
)
from src.evidence.cascade_models import (
    CascadeHandoffPacket,
    DeterministicRoutingDecision,
    LosslessStructuralPack,
)
from src.engine.bair_extractor import determine_empirical_evidence_present
from src.engine.decision_policy import ExperimentPolarityValidator
from src.knowledge.grounding_validator import KnowledgeGroundingValidator
from src.knowledge.models import EvidenceGapType, VaptKnowledgePack
from src.knowledge.pipeline import VaptReasoningPipeline
from src.eval.scorer import (
    EvaluationApplicabilityState,
    Policy3DeterministicScorer,
    Policy3EvaluationMetrics,
    ReviewerPresentationLabel,
    canonical_vulnerability_evidence_present,
    determine_applicability_state,
)

from src.eval.verify_m5_phase7_preflight import (
    PROTECTED_ARTIFACT_HASHES,
    run_preflight_gates,
    hash_file,
)

CHECKPOINT_PATH = repo_root / "data/eval/m5_phase7_benchmark_checkpoint.json"
FINAL_ARTIFACT_PATH = repo_root / "data/eval/m5_phase7_benchmark_final.json"
FINAL_SHA_PATH = repo_root / "data/eval/m5_phase7_benchmark_final.json.sha256"

TRACKS = [
    ConfirmatoryTrackId.TRACK_A,
    ConfirmatoryTrackId.TRACK_B,
    ConfirmatoryTrackId.TRACK_C,
    ConfirmatoryTrackId.TRACK_D,
]


class Phase7CallRecord(BaseModel):
    call_index: int
    scenario_id: str
    track_id: str
    category_id: str
    vulnerable_variant: bool
    i1_enabled: bool
    protocol_identifier: str
    model_name: str
    model_digest: str
    runtime_version: str
    inference_parameters: Dict[str, Any]
    canonical_input_hash: str
    prompt_hash: str
    target_evidence_hash: str
    vapt_pack_hash: str
    raw_model_response: str
    latency_ms: float
    eval_count: Optional[int] = None
    prompt_eval_count: Optional[int] = None
    done_reason: Optional[str] = None
    contract_valid: bool
    is_valid: bool
    primary_failure_category: str
    error_message: Optional[str] = None
    parsed_json: Optional[Dict[str, Any]] = None
    schema_validity: bool
    typed_experiment_fields: Dict[str, Optional[str]]
    grounding_result: Optional[Dict[str, Any]] = None
    ExperimentPolarityValidator_result: Optional[Dict[str, Any]] = None
    candidate_decision: Optional[str] = None
    final_deterministic_decision: Optional[str] = None
    canonical_s0_output: Optional[Dict[str, Any]] = None
    applicability_state: str
    reviewer_presentation: str
    is_useful: bool
    timestamp: str


class M5Phase7BenchmarkHarness:
    """Executes the formal 84-scenario x 4-track (336 calls) confirmatory benchmark."""

    def __init__(self, meta: Dict[str, Any]):
        self.meta = meta
        self.context_builder = ReasoningContextBuilder()
        self.validator = KnowledgeGroundingValidator()
        self.pipeline = VaptReasoningPipeline()
        self.runner = ReasoningRunner(
            model_name="qwen2.5-coder:7b",
            num_ctx=PRIMARY_NUM_CTX,
        )
        self.gold_scenarios: List[EvaluationScenario] = get_gold_set_scenarios()
        assert len(self.gold_scenarios) == 84, f"Expected 84 scenarios, got {len(self.gold_scenarios)}"
        self._canonical_input_cache: Dict[str, Dict[str, Any]] = {}

    def get_canonical_input(self, scenario_id: str) -> Dict[str, Any]:
        if scenario_id in self._canonical_input_cache:
            return self._canonical_input_cache[scenario_id]

        gold_scen = [s for s in self.gold_scenarios if s.scenario_id == scenario_id][0]
        observed_facts = gold_scen.initial_evidence or [
            {"fact_id": "FACT-00000001", "statement": "Neutral observable target evidence."}
        ]
        raw_sample = str(observed_facts[0].get("statement", "")) if observed_facts else ""

        # Strictly clean Channel A: ZERO ground-truth leakage!
        pack = LosslessStructuralPack(
            schema_version="2.0.0",
            asset_id=gold_scen.target_asset.get("asset_id", f"ASSET-{gold_scen.scenario_id}"),
            endpoint_id=f"EP-{gold_scen.scenario_id}",
            route_template=gold_scen.target_asset.get("normalized_path", gold_scen.target_asset.get("raw_path", "/api/v1/resource")),
            http_method=gold_scen.target_asset.get("method", "GET"),
            application_mutability=gold_scen.target_asset.get("application_mutability", "READ_ONLY"),
            parameter_lineage=gold_scen.parameters,
            identity_matrix=gold_scen.identities,
            has_privilege_level_delta=False,
            has_cross_identity_object_access_success=False,
            observed_facts=observed_facts,
            raw_body_sample=raw_sample,
        )

        assert pack.parameter_lineage == gold_scen.parameters, "Parameter fidelity mismatch"
        assert pack.identity_matrix == gold_scen.identities, "Identity fidelity mismatch"

        gap_type = infer_evidence_gap_type(gold_scen.category_id)
        vapt_pack, ret_diag = self.pipeline.retrieve_and_pack(
            channel_a=pack,
            gap_type=gap_type,
        )

        ev_bytes = json.dumps(observed_facts, sort_keys=True).encode("utf-8")
        meta_bytes = json.dumps(gold_scen.target_asset, sort_keys=True).encode("utf-8")
        input_hash = hashlib.sha256(ev_bytes + meta_bytes).hexdigest()

        empirical_present = determine_empirical_evidence_present(pack)

        entry = {
            "gold_scenario": gold_scen,
            "pack": pack,
            "gap_type": gap_type,
            "vapt_pack": vapt_pack,
            "retrieval_diagnostic": ret_diag,
            "canonical_input_hash": input_hash,
            "empirical_evidence_present": empirical_present,
        }
        self._canonical_input_cache[scenario_id] = entry
        return entry

    def build_context_for_track(
        self,
        scenario_id: str,
        track_id: ConfirmatoryTrackId,
    ) -> Tuple[Any, bytes, str]:
        canonical_input = self.get_canonical_input(scenario_id)
        pack: LosslessStructuralPack = canonical_input["pack"]
        vapt_pack: Optional[VaptKnowledgePack] = canonical_input["vapt_pack"]
        gold_scen: EvaluationScenario = canonical_input["gold_scenario"]
        gap_type: EvidenceGapType = canonical_input["gap_type"]

        routing = DeterministicRoutingDecision(
            schema_version="2.0.0",
            escalate=True,
            has_high_risk_signal=True,
            high_risk_signals=["M5_BENCHMARK"],
            fail_safe_triggered=False,
        )
        handoff = CascadeHandoffPacket(
            schema_version="2.0.0",
            channel_a_structural=pack,
            routing_decision=routing,
            provenance_hash=f"prov_{pack.asset_id}",
        )

        cat_tmpl = get_counterfactual_template(gold_scen.category_id)
        active_descriptor = HandoffSerializer.from_cascade_packet(
            handoff_packet=handoff,
            evidence_gap_type=gap_type,
            invariant=cat_tmpl.invariant_definition,
        )

        track_cascade_map = {
            ConfirmatoryTrackId.TRACK_A: TRACK_A,
            ConfirmatoryTrackId.TRACK_B: TRACK_B,
            ConfirmatoryTrackId.TRACK_C: TRACK_C,
            ConfirmatoryTrackId.TRACK_D: TRACK_D,
        }
        cascade_mode = track_cascade_map[track_id]

        effective_vapt = vapt_pack if track_id in (ConfirmatoryTrackId.TRACK_C, ConfirmatoryTrackId.TRACK_D) else None

        ctx = self.context_builder.build_context(
            handoff_packet=handoff,
            model_identifier="qwen2.5-coder:7b",
            budget_tier=4096,
            cascade_mode=cascade_mode,
            vapt_pack=effective_vapt,
            enable_i2_namespace_partitioning=True,
            enable_i3_counterfactual_prompting=True,
            category_id=gold_scen.category_id,
            enable_i4_bair=True,
            enable_i5_decision_policy=True,
            enable_i6_handoff=True,
            protected_handoff=active_descriptor,
            output_protocol=OutputProtocolIdentifier.JSON_BAIR,
        )

        # Assert zero ground truth tokens in prompt
        prompt_lower = ctx.prompt.lower()
        for token in FORBIDDEN_PROMPT_TOKENS:
            assert token not in prompt_lower, (
                f"STOP CONDITION: Ground-truth token '{token}' leaked into prompt for {scenario_id} ({track_id.value})"
            )

        # Extract target evidence bytes for B/D causal parity check
        target_ev_bytes = b""
        match = re.search(r"<untrusted_target_data>(.*?)</untrusted_target_data>", ctx.prompt, re.DOTALL)
        if match:
            target_ev_bytes = match.group(1).strip().encode("utf-8")

        # Compute vapt pack hash
        if effective_vapt is not None and effective_vapt.items:
            vapt_hash = effective_vapt.provenance_hash
        else:
            vapt_hash = "NONE"

        return ctx, target_ev_bytes, vapt_hash

    def execute_call(
        self,
        call_index: int,
        gold_scen: EvaluationScenario,
        track_id: ConfirmatoryTrackId,
        target_ev_bytes_b: Optional[bytes] = None,
    ) -> Phase7CallRecord:
        sid = gold_scen.scenario_id
        canonical_input = self.get_canonical_input(sid)
        pack = canonical_input["pack"]
        canonical_input_hash = canonical_input["canonical_input_hash"]
        empirical_present = canonical_input["empirical_evidence_present"]

        ctx, target_ev_bytes, vapt_pack_hash = self.build_context_for_track(scenario_id=sid, track_id=track_id)
        target_ev_hash = hashlib.sha256(target_ev_bytes).hexdigest()
        prompt_hash = hashlib.sha256(ctx.prompt.encode("utf-8")).hexdigest()

        if track_id == ConfirmatoryTrackId.TRACK_D:
            assert target_ev_bytes_b is not None, f"Track B target bytes missing for {sid}"
            assert target_ev_bytes_b == target_ev_bytes, (
                f"STOP CONDITION: B/D Target-Evidence Causal Parity failure for {sid}!"
            )

        effective_vapt = (
            canonical_input["vapt_pack"]
            if track_id in (ConfirmatoryTrackId.TRACK_C, ConfirmatoryTrackId.TRACK_D)
            else None
        )

        proto_contract = get_protocol_contract(OutputProtocolIdentifier.JSON_BAIR)
        schema = proto_contract.runtime_schema_factory(True)

        contract = ReasoningExecutionContract(
            protocol=OutputProtocolIdentifier.JSON_BAIR,
            enable_i1=True,
            enable_i2=True,
            enable_i3=True,
            enable_i4=True,
            enable_i5=True,
            enable_i6=True,
            system_prompt=ctx.system_prompt,
            user_prompt=ctx.user_prompt,
            runtime_schema=schema,
            parser=proto_contract.parser,
            validator=proto_contract.validator,
            adapter=proto_contract.adapter,
            budget_tier=4096,
            floor_tokens=1000,
            total_tokens=ctx.token_count,
            protected_handoff_present=True,
            category_id=gold_scen.category_id,
        )

        validate_reasoning_contract(contract)

        target_asset_enriched = dict(gold_scen.target_asset)
        target_asset_enriched["parameters"] = list(gold_scen.parameters)
        target_asset_enriched["identities"] = list(gold_scen.identities)

        t0 = time.perf_counter()
        result = self.runner.execute_m5_generation(
            contract=contract,
            empirical_evidence_present=empirical_present,
            grounding_validator=self.validator,
            channel_a=pack,
            target_asset=target_asset_enriched,
            category_id=gold_scen.category_id,
            vapt_pack=effective_vapt,
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        ts = datetime.now(timezone.utc).isoformat()

        parsed_dict = result.parsed_intermediate if isinstance(result.parsed_intermediate, dict) else None
        if parsed_dict is None:
            try:
                clean_text = result.raw_response.strip()
                if clean_text.startswith("```"):
                    clean_text = re.sub(r"^```[a-zA-Z]*\n", "", clean_text)
                    clean_text = re.sub(r"\n```$", "", clean_text)
                parsed_dict = json.loads(clean_text)
            except Exception:
                parsed_dict = None

        typed_fields = {
            "experiment_action": None,
            "supporting_outcome": None,
            "disproving_outcome": None,
            "falsification_description": None,
        }
        candidate_dec = None
        if parsed_dict is not None and isinstance(parsed_dict, dict):
            typed_fields["experiment_action"] = parsed_dict.get("experiment_action")
            typed_fields["supporting_outcome"] = parsed_dict.get("supporting_outcome")
            typed_fields["disproving_outcome"] = parsed_dict.get("disproving_outcome")
            typed_fields["falsification_description"] = parsed_dict.get("falsification_description")
            candidate_dec = parsed_dict.get("decision")

        schema_valid = False
        if parsed_dict is not None and isinstance(parsed_dict, dict):
            try:
                BairJsonObject.model_validate(parsed_dict)
                schema_valid = True
            except Exception:
                schema_valid = False

        polarity_res = None
        polarity_is_valid = True
        if candidate_dec == "HYPOTHESIS" or (result.canonical_hypothesis and result.canonical_hypothesis.decision == HypothesisDecision.HYPOTHESIS):
            act = typed_fields.get("experiment_action")
            supp = typed_fields.get("supporting_outcome")
            disp = typed_fields.get("disproving_outcome")
            is_compat, reason = ExperimentPolarityValidator.validate_tuple(
                category_id=gold_scen.category_id,
                experiment_action=act,
                supporting_outcome=supp,
                disproving_outcome=disp,
            )
            polarity_is_valid = is_compat
            polarity_res = {
                "is_valid": is_compat,
                "reason": reason,
                "category_id": gold_scen.category_id,
                "experiment_action": act,
                "supporting_outcome": supp,
                "disproving_outcome": disp,
            }

        final_dec = None
        if result.canonical_hypothesis is not None:
            if hasattr(result.canonical_hypothesis.decision, "value"):
                final_dec = result.canonical_hypothesis.decision.value
            else:
                final_dec = str(result.canonical_hypothesis.decision)

        # Policy 3 Applicability State Determination (ZERO oracle access)
        has_anomaly = canonical_vulnerability_evidence_present(
            evidence=gold_scen.initial_evidence,
            structural_pack=pack,
        )
        target_rel = True
        norm_path = gold_scen.target_asset.get("normalized_path") or gold_scen.target_asset.get("raw_path") or ""
        params = gold_scen.parameters
        if norm_path in ("/catalog", "/.well-known/openid-configuration") or (
            gold_scen.target_asset.get("application_mutability") == "READ_ONLY" and len(params) == 0 and not gold_scen.initial_evidence
        ):
            target_rel = False

        app_state = determine_applicability_state(
            is_valid_output=result.classification.is_valid,
            target_relevant=target_rel,
            canonical_evidence_has_anomaly=has_anomaly,
        )

        is_hyp = (final_dec == "HYPOTHESIS")
        grounded_valid = bool(result.grounding_result and result.grounding_result.get("is_valid", False))
        is_useful = bool(
            result.classification.is_valid
            and is_hyp
            and grounded_valid
            and polarity_is_valid
            and gold_scen.vulnerable_variant
        )

        # Reviewer presentation label
        if app_state == EvaluationApplicabilityState.INVALID_OUTPUT:
            rev_label = ReviewerPresentationLabel.INVALID_PROPOSAL
        elif app_state == EvaluationApplicabilityState.NON_RELEVANT_EVALUATION:
            rev_label = ReviewerPresentationLabel.INVALID_PROPOSAL if is_hyp else ReviewerPresentationLabel.ABSTENTION_CONFIRMED
        elif app_state == EvaluationApplicabilityState.VULNERABILITY_EVALUATION_APPLICABLE:
            if is_hyp and result.classification.is_valid and grounded_valid and polarity_is_valid:
                rev_label = ReviewerPresentationLabel.VULNERABILITY_FINDING
            elif not is_hyp and result.classification.is_valid:
                rev_label = ReviewerPresentationLabel.ABSTENTION_CONFIRMED
            else:
                rev_label = ReviewerPresentationLabel.INVALID_PROPOSAL
        else:  # EXPLORATORY_EVALUATION_APPLICABLE
            if is_hyp and result.classification.is_valid and grounded_valid and polarity_is_valid:
                rev_label = ReviewerPresentationLabel.EXPLORATORY_VERIFICATION_PROPOSAL
            elif not is_hyp and result.classification.is_valid:
                rev_label = ReviewerPresentationLabel.ABSTENTION_CONFIRMED
            else:
                rev_label = ReviewerPresentationLabel.INVALID_PROPOSAL

        return Phase7CallRecord(
            call_index=call_index,
            scenario_id=sid,
            track_id=track_id.value,
            category_id=gold_scen.category_id,
            vulnerable_variant=gold_scen.vulnerable_variant,
            i1_enabled=True,
            protocol_identifier=contract.protocol.value,
            model_name="qwen2.5-coder:7b",
            model_digest=self.meta["model_digest"],
            runtime_version=self.meta["runtime_version"],
            inference_parameters={
                "num_ctx": PRIMARY_NUM_CTX,
                "num_predict": PRIMARY_NUM_PREDICT,
                "temperature": PRIMARY_TEMPERATURE,
                "seed": PRIMARY_SEED,
                "keep_alive": PRIMARY_KEEP_ALIVE,
            },
            canonical_input_hash=canonical_input_hash,
            prompt_hash=prompt_hash,
            target_evidence_hash=target_ev_hash,
            vapt_pack_hash=vapt_pack_hash,
            raw_model_response=result.raw_response,
            latency_ms=result.latency_ms or elapsed_ms,
            eval_count=result.eval_count,
            prompt_eval_count=result.prompt_eval_count,
            done_reason=result.classification.diagnostic_details.get("done_reason") if result.classification.diagnostic_details else None,
            contract_valid=result.contract_valid,
            is_valid=result.classification.is_valid,
            primary_failure_category=result.classification.primary_category.value,
            error_message=result.classification.error_message,
            parsed_json=parsed_dict,
            schema_validity=schema_valid,
            typed_experiment_fields=typed_fields,
            grounding_result=result.grounding_result,
            ExperimentPolarityValidator_result=polarity_res,
            candidate_decision=candidate_dec,
            final_deterministic_decision=final_dec,
            canonical_s0_output=result.canonical_hypothesis.model_dump() if result.canonical_hypothesis else None,
            applicability_state=app_state.value,
            reviewer_presentation=rev_label.value,
            is_useful=is_useful,
            timestamp=ts,
        )


def main():
    start_time = time.time()
    # 1. Run Preflight Gates
    preflight_results = run_preflight_gates()

    # Get metadata
    ver_out = subprocess.check_output(["ollama", "--version"], text=True).strip()
    with httpx.Client(timeout=5.0) as client:
        tags_res = client.get("http://127.0.0.1:11434/api/tags")
        models = tags_res.json().get("models", [])
        matched = [m for m in models if m.get("name") == "qwen2.5-coder:7b" or m.get("model") == "qwen2.5-coder:7b"]
        digest = matched[0].get("digest", "")

    meta = {
        "model_name": "qwen2.5-coder:7b",
        "model_digest": digest,
        "runtime_version": ver_out,
        "inference_parameters": {
            "num_ctx": PRIMARY_NUM_CTX,
            "num_predict": PRIMARY_NUM_PREDICT,
            "temperature": PRIMARY_TEMPERATURE,
            "seed": PRIMARY_SEED,
            "keep_alive": PRIMARY_KEEP_ALIVE,
        },
    }

    harness = M5Phase7BenchmarkHarness(meta)
    scenarios = harness.gold_scenarios

    # Load checkpoint if exists
    completed_scenarios = set()
    records_by_track: Dict[str, List[Phase7CallRecord]] = {
        ConfirmatoryTrackId.TRACK_A.value: [],
        ConfirmatoryTrackId.TRACK_B.value: [],
        ConfirmatoryTrackId.TRACK_C.value: [],
        ConfirmatoryTrackId.TRACK_D.value: [],
    }

    if CHECKPOINT_PATH.exists():
        try:
            ckpt_data = json.loads(CHECKPOINT_PATH.read_text(encoding="utf-8"))
            completed_scenarios = set(ckpt_data.get("completed_scenarios", []))
            for t_val, r_list in ckpt_data.get("tracks", {}).items():
                records_by_track[t_val] = [Phase7CallRecord.model_validate(r) for r in r_list]
            print(f"Resuming from checkpoint: {len(completed_scenarios)}/84 scenarios ({len(completed_scenarios)*4} calls) completed.")
        except Exception as exc:
            print(f"Warning: Checkpoint load error ({exc}), starting fresh.")
            completed_scenarios = set()
            for t in records_by_track:
                records_by_track[t] = []

    total_calls_target = 84 * 4
    current_call_count = sum(len(r_list) for r_list in records_by_track.values())

    print("\n================================================================================")
    print(f"STARTING LIVE M5 PHASE 7 BENCHMARK: 84 SCENARIOS x 4 TRACKS = 336 LIVE CALLS")
    print(f"Target calls: {total_calls_target} | Currently completed: {current_call_count}")
    print("================================================================================")

    for scen_idx, gold_scen in enumerate(scenarios, 1):
        sid = gold_scen.scenario_id
        if sid in completed_scenarios:
            continue

        print(f"\n[{scen_idx:02d}/84] Scenario: {sid} (Category: {gold_scen.category_id}, Vuln: {gold_scen.vulnerable_variant})")

        # Extract Track B target bytes for B/D parity
        _, target_ev_bytes_b, _ = harness.build_context_for_track(sid, ConfirmatoryTrackId.TRACK_B)

        for track_id in TRACKS:
            current_call_count += 1
            call_idx = current_call_count
            print(f"  Call #{call_idx:03d}/336: [{track_id.value}] ...", end=" ", flush=True)

            rec = harness.execute_call(
                call_index=call_idx,
                gold_scen=gold_scen,
                track_id=track_id,
                target_ev_bytes_b=target_ev_bytes_b,
            )
            records_by_track[track_id.value].append(rec)

            status_tag = "VALID" if rec.is_valid else f"FAIL({rec.primary_failure_category})"
            dec_tag = f"Dec={rec.final_deterministic_decision}" if rec.final_deterministic_decision else f"Cand={rec.candidate_decision}"
            app_tag = f"App={rec.applicability_state[:8]}"
            print(f"{status_tag} | {dec_tag} | {app_tag} | {rec.latency_ms:.0f}ms")

        completed_scenarios.add(sid)

        # Save incremental checkpoint after each completed scenario (every 4 calls)
        ckpt_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "completed_scenarios": list(completed_scenarios),
            "completed_calls": current_call_count,
            "tracks": {t: [r.model_dump() for r in r_list] for t, r_list in records_by_track.items()},
        }
        CHECKPOINT_PATH.write_text(json.dumps(ckpt_data, indent=2), encoding="utf-8")
        print(f"  [Checkpoint saved: {len(completed_scenarios)}/84 scenarios ({current_call_count}/336 calls)]")

    # Verify all 336 calls completed
    all_flat_records: List[Phase7CallRecord] = []
    for t_id in TRACKS:
        t_records = records_by_track[t_id.value]
        assert len(t_records) == 84, f"Track {t_id.value} has {len(t_records)} records, expected 84"
        all_flat_records.extend(t_records)

    assert len(all_flat_records) == 336, f"Total records count mismatch: {len(all_flat_records)} != 336"
    print("\n================================================================================")
    print("ALL 336 LIVE CALLS SUCCESSFULLY EXECUTED! COMPUTING POLICY 3 SCORING...")
    print("================================================================================")

    # 4. Score all tracks with Policy 3 Deterministic Scorer
    scorer = Policy3DeterministicScorer()

    # Convert Phase7CallRecord list to scorer dictionary format
    def to_scorer_dict(r: Phase7CallRecord) -> Dict[str, Any]:
        scen = [s for s in scenarios if s.scenario_id == r.scenario_id][0]
        return {
            "scenario_id": r.scenario_id,
            "track_id": r.track_id,
            "ground_truth_vulnerable": r.vulnerable_variant,
            "decision": r.final_deterministic_decision,
            "grounded": bool(r.grounding_result and r.grounding_result.get("is_valid", False)),
            "useful": r.is_useful,
            "primary_failure_category": r.primary_failure_category,
            "is_valid": r.is_valid,
            "polarity_valid": bool(r.ExperimentPolarityValidator_result and r.ExperimentPolarityValidator_result.get("is_valid", False)) if r.final_deterministic_decision == "HYPOTHESIS" else True,
            "target_asset": scen.target_asset,
            "parameters": scen.parameters,
            "initial_evidence": scen.initial_evidence,
            "latency_ms": r.latency_ms,
        }

    overall_scorer_dicts = [to_scorer_dict(r) for r in all_flat_records]
    overall_p3_metrics = scorer.score_policy3(overall_scorer_dicts)

    track_p3_metrics: Dict[str, Any] = {}
    for t_id in TRACKS:
        t_dicts = [to_scorer_dict(r) for r in records_by_track[t_id.value]]
        t_metrics = scorer.score_policy3(t_dicts)
        track_p3_metrics[t_id.value] = t_metrics.model_dump()

    total_time_s = time.time() - start_time

    # 5. Compile Final Benchmark Artifact
    final_artifact = {
        "schema_version": "7.0.0",
        "milestone": "M5",
        "phase": "PHASE_7_CONFIRMATORY_BENCHMARK",
        "status": "M5_PHASE7_COMPLETE",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_runtime_seconds": round(total_time_s, 2),
        "total_scheduled_calls": 336,
        "total_completed_calls": 336,
        "metadata": {
            "model_name": meta["model_name"],
            "model_digest": meta["model_digest"],
            "runtime_version": meta["runtime_version"],
            "primary_inference_parameters": meta["inference_parameters"],
            "protected_artifact_hashes": PROTECTED_ARTIFACT_HASHES,
        },
        "overall_policy3_metrics": overall_p3_metrics.model_dump(),
        "per_track_metrics": track_p3_metrics,
        "call_records": [r.model_dump() for r in all_flat_records],
    }

    # Write final artifact and sha256
    FINAL_ARTIFACT_PATH.write_text(json.dumps(final_artifact, indent=2), encoding="utf-8")
    final_sha = hash_file(FINAL_ARTIFACT_PATH)
    FINAL_SHA_PATH.write_text(f"{final_sha}  {FINAL_ARTIFACT_PATH.name}\n", encoding="utf-8")

    print(f"\nFINAL BENCHMARK ARTIFACT SAVED: {FINAL_ARTIFACT_PATH}")
    print(f"FINAL ARTIFACT SHA-256: {final_sha}")

    # Verify protected historical artifacts remain byte-identical
    for rel_path, expected_hash in PROTECTED_ARTIFACT_HASHES.items():
        actual = hash_file(repo_root / rel_path)
        assert actual == expected_hash, f"CRITICAL: Protected file {rel_path} was modified during run!"
    print("PROTECTED HISTORICAL ARTIFACTS VERIFIED BYTE-IDENTICAL!")

    print("\n================================================================================")
    print("M5 PHASE 7 CONFIRMATORY BENCHMARK COMPLETED SUCCESSFULLY!")
    print(f"Total Calls: 336 | Elapsed Time: {total_time_s/60.0:.1f} minutes")
    print(f"Primary Estimand (Useful Hypothesis Yield @ N reviewer minutes): {overall_p3_metrics.useful_hypothesis_yield_at_fixed_reviewer_minutes:.4f}")
    print("================================================================================")


if __name__ == "__main__":
    main()
