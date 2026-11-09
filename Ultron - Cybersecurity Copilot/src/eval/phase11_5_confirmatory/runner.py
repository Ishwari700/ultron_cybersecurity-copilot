"""
Milestone M5 Phase 11.5: Confirmatory Benchmark Runner.

Executes the population-level confirmatory benchmark:
- Population: Exactly 84 scenarios (36 vulnerable, 48 controls)
- Conditions: Paired within-scenario evaluation of P4_TRACK_A vs P5_TRACK_D
- Total calls: Exactly 168 calls (84 scenarios x 2 conditions)
- Randomization: Seeded deterministic order via M5_PHASE11_5_ORDER_SEED_42
- Frozen Runtime: qwen2.5-coder:7b (dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364)
- num_ctx: 2048, num_predict: 300, temp: 0.0, seed: 42, keep_alive: 60m
- Timeout: 30.0s hard cutoff (+500ms teardown tolerance)
- Incremental persistence after every call to data/eval/m5_phase11_5_live_results.json
"""

import hashlib
import json
from pathlib import Path
import random
import time
from typing import Any, Dict, List, Optional, Tuple

from src.engine.context_builder import ReasoningContextBuilder, TRACK_A
from src.engine.decision_policy import ExperimentPolarityValidator
from src.engine.experiment_skeleton import (
    ExperimentSkeletonBuilder,
    ExperimentSkeletonDescriptor,
)
from src.engine.handoff_serializer import HandoffSerializer
from src.engine.models import OutputProtocolIdentifier
from src.engine.prompts import get_counterfactual_template
from src.engine.runner import (
    OllamaRunner,
    PRIMARY_KEEP_ALIVE,
    PRIMARY_NUM_CTX,
    PRIMARY_NUM_PREDICT,
    PRIMARY_SEED,
    PRIMARY_TEMPERATURE,
)
from src.eval.m4_live_benchmark import (
    FORBIDDEN_PROMPT_TOKENS,
    infer_evidence_gap_type,
)
from src.eval.phase11_failure_analysis.attribution import (
    attribute_failure,
    FailureAttributionResult,
)
from src.eval.phase11_failure_analysis.corpus_builder import assert_zero_sensitive_data
from src.eval.scenarios import EvaluationScenario, get_gold_set_scenarios
from src.evidence.cascade_models import (
    CascadeHandoffPacket,
    DeterministicRoutingDecision,
    LosslessStructuralPack,
)
from src.eval.phase11_2_polarity.attack_predicate import AttackPredicate
from src.eval.phase11_2_polarity.outcome_binding import (
    derive_outcomes_from_attack_predicate,
    OutcomeBindingResult,
)
from src.eval.phase11_2_polarity.protocol import parse_p1_response
from src.eval.phase11_3_grounding.allowed_sets import (
    build_scenario_allowed_sets,
    ScenarioAllowedSets,
)
from src.eval.phase11_3_grounding.validator import (
    GroundingValidationResult,
    Phase11GroundingValidator,
)
from src.eval.phase11_4_property_alignment.property_registry import (
    get_allowed_security_properties,
    PROPERTY_REGISTRY_VERSION,
)
from src.eval.phase11_4_property_alignment.property_validator import (
    PropertyValidationResult,
    validate_security_property,
)
from src.eval.phase11_4_property_alignment.protocol import (
    get_p4_inference_schema,
    render_p4_prompt_instruction,
)
from src.eval.phase11_4_property_alignment.track_d import AuthoritativeTrackDBuilder

FROZEN_ORDER_SEED: str = "M5_PHASE11_5_ORDER_SEED_42"
EXPECTED_PHASE10_POPULATION_DIGEST: str = (
    "6821d207729de97ac99657a09e38c25895a73285fe9c485d299dc27f37d2bdba"
)


def get_scenario_condition_order(scenario_id: str, seed: str = FROZEN_ORDER_SEED) -> List[str]:
    """Deterministically shuffles [P4_TRACK_A, P5_TRACK_D] for a scenario."""
    payload = f"{seed}:{scenario_id}".encode("utf-8")
    seed_int = int(hashlib.sha256(payload).hexdigest()[:16], 16)
    rng = random.Random(seed_int)
    conds = ["P4_TRACK_A", "P5_TRACK_D"]
    rng.shuffle(conds)
    return conds


class Phase11_5ConfirmatoryRunner:
    """Orchestrates the 168-call population-level confirmatory benchmark."""

    def __init__(
        self,
        ollama_runner: Optional[OllamaRunner] = None,
        repo_root: Optional[Path] = None,
    ) -> None:
        self.root = repo_root or Path(__file__).resolve().parent.parent.parent.parent
        self.ollama = ollama_runner or OllamaRunner(model_name="qwen2.5-coder:7b")
        self.context_builder = ReasoningContextBuilder()
        self.grounding_validator = Phase11GroundingValidator()
        self.track_d_builder = AuthoritativeTrackDBuilder()
        self.results_path = self.root / "data/eval/m5_phase11_5_live_results.json"
        self.manifest_path = self.root / "data/eval/m5_phase11_5_manifest.json"

        # Preflight verification
        self._verify_preflight_invariants()

    def _verify_preflight_invariants(self) -> None:
        """Verifies Phase 10 canonical population hash, model digest, and runtime."""
        # 1. Population digest
        p10_file = self.root / "data/eval/m5_phase10_full_population_validation.json"
        if not p10_file.exists():
            raise RuntimeError(f"STOP CONDITION: Phase 10 file not found at {p10_file}")
        digest = hashlib.sha256(p10_file.read_bytes()).hexdigest()
        if digest != EXPECTED_PHASE10_POPULATION_DIGEST:
            raise RuntimeError(
                f"STOP CONDITION: Phase 10 population digest mismatch! Expected {EXPECTED_PHASE10_POPULATION_DIGEST}, got {digest}"
            )

        # 2. Model digest
        models = self.ollama.list_models()
        target = "qwen2.5-coder:7b"
        found = False
        active_digest = ""
        for m in models:
            m_name = m.get("name", "")
            if target in m_name:
                found = True
                active_digest = m.get("digest", "")
                break
        if not found:
            raise RuntimeError(f"Preflight check failed: Model {target} not available in local Ollama.")
        expected_prefix = "dae161e27b0e"
        if not active_digest.startswith(expected_prefix):
            raise RuntimeError(
                f"STOP CONDITION: Model digest mismatch! Expected {expected_prefix}..., got {active_digest}"
            )

    def build_prompt_and_schema_for_cell(
        self,
        condition_id: str,
        track_id: str,
        scenario: EvaluationScenario,
        pack: LosslessStructuralPack,
        allowed_sets: ScenarioAllowedSets,
        allowed_security_properties: List[str],
        skeleton_desc: ExperimentSkeletonDescriptor,
    ) -> Tuple[str, Dict[str, Any], Optional[Any], str]:
        """
        Builds full prompt and constrained JSON schema for a cell.
        Returns: (full_prompt, schema, vapt_pack, context_provenance_hash)
        """
        cat_id = scenario.category_id
        gap_type = infer_evidence_gap_type(cat_id)
        cat_tmpl = get_counterfactual_template(cat_id)

        vapt_pack = None
        if track_id == "TRACK_D":
            base_ctx, vapt_pack, ctx_prov = self.track_d_builder.build_track_d_context(scenario, pack)
        else:
            # Track A
            routing = DeterministicRoutingDecision(
                escalate=True,
                has_high_risk_signal=True,
                high_risk_signals=["M5_PHASE11_5_CONFIRMATORY"],
                fail_safe_triggered=False,
            )
            handoff = CascadeHandoffPacket(
                schema_version="2.0.0",
                channel_a_structural=pack,
                routing_decision=routing,
                provenance_hash=f"prov_{pack.asset_id}",
            )
            active_descriptor = HandoffSerializer.from_cascade_packet(
                handoff_packet=handoff,
                evidence_gap_type=gap_type,
                invariant=cat_tmpl.invariant_definition,
            )
            base_ctx = self.context_builder.build_context(
                handoff_packet=handoff,
                model_identifier="qwen2.5-coder:7b",
                budget_tier=2048,
                cascade_mode=TRACK_A,
                vapt_pack=None,
                enable_i2_namespace_partitioning=True,
                enable_i3_counterfactual_prompting=True,
                category_id=scenario.category_id,
                enable_i4_bair=True,
                enable_i5_decision_policy=True,
                enable_i6_handoff=True,
                protected_handoff=active_descriptor,
                output_protocol=OutputProtocolIdentifier.JSON_BAIR,
            )
            ctx_prov = hashlib.sha256(f"{base_ctx.system_prompt}\n{base_ctx.user_prompt}".encode("utf-8")).hexdigest()

        user_prompt = base_ctx.user_prompt
        if "OUTPUT FORMAT (BOUNDED ANALYTICAL INFERENCE REPRESENTATION" in user_prompt:
            parts = user_prompt.split("OUTPUT FORMAT (BOUNDED ANALYTICAL INFERENCE REPRESENTATION")
            user_prompt = parts[0].strip()

        skeleton_block = (
            f"EXPERIMENT SKELETON SPECIFICATION:\n"
            f"- Supplied Vulnerability Category: {skeleton_desc.category_id}\n"
            f"- Supplied Deterministic Action: {skeleton_desc.experiment_action}\n"
            f"- Invariant Definition: {skeleton_desc.invariant_definition}\n"
            f"- Evidence Gap Type: {skeleton_desc.evidence_gap_type}\n\n"
            f"If your decision is HYPOTHESIS, you MUST construct an 'attack_predicate' testing the breach of this invariant "
            f"using operation '{skeleton_desc.experiment_action}'.\n"
            f"Do NOT emit outcome tokens (supporting_outcome / disproving_outcome). The deterministic engine binds outcomes "
            f"automatically from your validated attack_predicate."
        )

        instruction_block = render_p4_prompt_instruction(
            allowed_sets.allowed_fact_ids,
            allowed_sets.allowed_target_ids,
            allowed_security_properties,
        )
        schema = get_p4_inference_schema(
            allowed_fact_ids=allowed_sets.allowed_fact_ids,
            allowed_target_ids=allowed_sets.allowed_target_ids,
            allowed_security_properties=allowed_security_properties,
        )

        full_user_prompt = f"{user_prompt}\n\n{instruction_block}\n\n{skeleton_block}"
        full_prompt = f"{base_ctx.system_prompt}\n{full_user_prompt}"

        return full_prompt, schema, vapt_pack, ctx_prov

    def execute_call(
        self,
        scenario: EvaluationScenario,
        condition_id: str,
        track_id: str,
        call_index: int,
    ) -> Dict[str, Any]:
        """Executes a single live inference attempt and records complete audit telemetry."""
        sid = scenario.scenario_id
        cat_id = scenario.category_id
        is_vuln = scenario.vulnerable_variant

        asset_id = scenario.target_asset.get("asset_id", f"ASSET-{scenario.scenario_id}")
        endpoint_id = f"EP-{asset_id}"
        observed_facts = scenario.initial_evidence or [
            {"fact_id": "FACT-00000001", "statement": "Neutral observable target evidence."}
        ]
        raw_sample = str(observed_facts[0].get("statement", "")) if observed_facts else ""

        # Clean Channel A: Zero ground-truth leakage
        pack = LosslessStructuralPack(
            schema_version="2.0.0",
            asset_id=asset_id,
            endpoint_id=endpoint_id,
            route_template=scenario.target_asset.get(
                "normalized_path", scenario.target_asset.get("raw_path", "/api/v1/resource")
            ),
            http_method=scenario.target_asset.get("method", "GET"),
            application_mutability=scenario.target_asset.get("application_mutability", "READ_ONLY"),
            parameter_lineage=scenario.parameters,
            identity_matrix=scenario.identities,
            has_privilege_level_delta=False,
            has_cross_identity_object_access_success=False,
            observed_facts=observed_facts,
            raw_body_sample=raw_sample,
        )

        allowed_sets = build_scenario_allowed_sets(scenario, pack=pack)
        allowed_props = get_allowed_security_properties(cat_id)
        gap_type = infer_evidence_gap_type(cat_id)
        cat_tmpl = get_counterfactual_template(cat_id)
        skeleton_desc = ExperimentSkeletonBuilder.build_skeleton(
            category_id=cat_id,
            invariant_definition=cat_tmpl.invariant_definition,
            evidence_gap_type=gap_type.value,
        )

        # 2. Build prompt and schema
        full_prompt, schema, vapt_pack, ctx_prov = self.build_prompt_and_schema_for_cell(
            condition_id=condition_id,
            track_id=track_id,
            scenario=scenario,
            pack=pack,
            allowed_sets=allowed_sets,
            allowed_security_properties=allowed_props,
            skeleton_desc=skeleton_desc,
        )

        # Ground truth firewall assertions
        prompt_lower = full_prompt.lower()
        for token in FORBIDDEN_PROMPT_TOKENS:
            assert token not in prompt_lower, (
                f"STOP CONDITION: Ground truth token '{token}' leaked into prompt for {sid}"
            )

        prompt_hash = hashlib.sha256(full_prompt.encode("utf-8")).hexdigest().lower()

        # 3. Live LLM Generation via Ollama
        t_start = time.perf_counter()
        raw_resp_dict: Dict[str, Any] = {}
        timed_out: bool = False
        try:
            raw_resp_dict = self.ollama.generate_raw(
                prompt=full_prompt,
                schema=schema,
                temperature=PRIMARY_TEMPERATURE,
                num_predict=PRIMARY_NUM_PREDICT,
                num_ctx=PRIMARY_NUM_CTX,
                keep_alive=PRIMARY_KEEP_ALIVE,
                timeout_seconds=30.0,
            )
        except Exception as exc:
            if "timeout" in type(exc).__name__.lower() or "timed out" in str(exc).lower():
                timed_out = True
            else:
                raise
        t_end = time.perf_counter()
        total_latency_ms = round((t_end - t_start) * 1000.0, 2)
        if total_latency_ms >= 30500.0:
            timed_out = True

        raw_response = raw_resp_dict.get("response", "")
        if raw_response:
            assert_zero_sensitive_data(raw_response, context=f"{condition_id}-{sid}")

        prompt_eval_count = raw_resp_dict.get("prompt_eval_count")
        eval_count = raw_resp_dict.get("eval_count")

        # 4. Parsing and Model Output Extraction
        parsed_dict: Optional[Dict[str, Any]] = None
        cand_dec: Optional[str] = None
        act: Optional[str] = None
        supp: Optional[str] = None
        disp: Optional[str] = None
        attack_pred_obj: Optional[AttackPredicate] = None
        attack_pred_dict: Optional[Dict[str, Any]] = None
        binding_result: Optional[OutcomeBindingResult] = None
        parse_error: Optional[str] = None
        schema_valid: bool = False

        if not timed_out and raw_response:
            p1_obj, p1_err = parse_p1_response(raw_response)
            if p1_obj is not None:
                parsed_dict = p1_obj.model_dump()
                cand_dec = p1_obj.decision.value if hasattr(p1_obj.decision, "value") else str(p1_obj.decision)
                attack_pred_obj = p1_obj.attack_predicate
                schema_valid = True

                if attack_pred_obj is not None:
                    attack_pred_dict = attack_pred_obj.to_canonical_dict()
                    act = attack_pred_obj.operation

                    # Execute Deterministic Outcome Binding
                    binding_result = derive_outcomes_from_attack_predicate(
                        category_id=cat_id,
                        experiment_action=skeleton_desc.experiment_action,
                        attack_predicate=attack_pred_obj,
                        target_asset_id=pack.asset_id,
                    )
                    if binding_result.is_valid:
                        supp = binding_result.supporting_outcome
                        disp = binding_result.disproving_outcome
            else:
                parse_error = p1_err
                schema_valid = False

        is_hyp_cand = (cand_dec == "HYPOTHESIS")

        # 5. Security Property Validation
        selected_prop = attack_pred_dict.get("security_property") if attack_pred_dict else None
        prop_result: Optional[PropertyValidationResult] = None
        property_valid = False
        property_code = None
        property_reason = None

        if is_hyp_cand:
            prop_result = validate_security_property(
                category_id=cat_id,
                security_property=selected_prop,
                invariant_definition=cat_tmpl.invariant_definition,
                evidence_gap_type=gap_type.value,
            )
            property_valid = prop_result.is_valid
            property_code = prop_result.primary_code.value if prop_result.primary_code else None
            property_reason = prop_result.reason

        # 6. Skeleton Compliance and Polarity
        skeleton_compliant: Optional[bool] = None
        skeleton_reason: Optional[str] = None
        polarity_valid: bool = False
        polarity_reason: Optional[str] = None

        if is_hyp_cand and act and supp and disp:
            skeleton_compliant = (act == skeleton_desc.experiment_action) and (binding_result.is_valid if binding_result else False)
            skeleton_reason = "Enforced via deterministic outcome binding" if skeleton_compliant else (binding_result.error_message if binding_result else "Missing binding")

            p_ok, p_msg = ExperimentPolarityValidator.validate_tuple(
                category_id=cat_id,
                experiment_action=act,
                supporting_outcome=supp,
                disproving_outcome=disp,
            )
            polarity_valid = p_ok
            polarity_reason = p_msg

        # 7. Grounding Validation
        grounding_result: Optional[GroundingValidationResult] = None
        grounding_valid: bool = False
        grounding_reason: Optional[str] = None
        grounding_code: Optional[str] = None

        if parsed_dict and not timed_out:
            grounding_result = self.grounding_validator.validate_grounding(
                parsed_dict=parsed_dict,
                allowed_fact_ids=allowed_sets.allowed_fact_ids,
                allowed_target_ids=allowed_sets.allowed_target_ids,
                pack=pack,
                condition_id="P4",
            )
            grounding_valid = grounding_result.is_valid
            grounding_reason = grounding_result.reason
            grounding_code = grounding_result.primary_code.value if grounding_result.primary_code else None

        # 8. Primary Failure Classification adhering to precedence ladder
        raw_eval_rec = {
            "primary_failure_category": "RUNTIME_TIMEOUT" if timed_out else ("SCHEMA_VALIDITY_FAILURE" if not schema_valid else "VALID"),
            "candidate_decision": cand_dec,
            "final_decision": cand_dec,
            "timed_out": timed_out,
            "vulnerable_variant": is_vuln,
            "category_id": cat_id,
            "experiment_action": act,
            "supporting_outcome": supp,
            "disproving_outcome": disp,
            "condition_id": condition_id,
            "track_id": track_id,
            "polarity_valid": polarity_valid,
            "polarity_reason": polarity_reason,
            "skeleton_compliant": skeleton_compliant,
            "skeleton_reason": skeleton_reason,
        }
        if not grounding_valid and not timed_out and schema_valid:
            raw_eval_rec["primary_failure_category"] = "SEMANTIC_GROUNDING_FAILURE"
        elif is_hyp_cand and not property_valid and not timed_out and schema_valid and grounding_valid:
            raw_eval_rec["primary_failure_category"] = "SEMANTIC_EXPERIMENT_POLARITY_FAILURE"
        elif not polarity_valid and is_hyp_cand and not timed_out and schema_valid and grounding_valid:
            raw_eval_rec["primary_failure_category"] = "SEMANTIC_EXPERIMENT_POLARITY_FAILURE"

        attribution_res: FailureAttributionResult = attribute_failure(
            record=raw_eval_rec,
            scenario_category_id=cat_id,
            ground_truth_vulnerable=is_vuln,
        )

        is_valid_typed_exp = (
            schema_valid
            and is_hyp_cand
            and bool(skeleton_compliant)
            and polarity_valid
            and grounding_valid
            and property_valid
        )
        is_useful_vuln = bool(is_valid_typed_exp and is_vuln)

        # 9. Complete Record Construction
        call_record = {
            "call_index": call_index,
            "condition_id": condition_id,
            "scenario_id": sid,
            "vulnerable_variant": is_vuln,
            "category_id": cat_id,
            "protocol": "PHASE_11_5_CONFIRMATORY_SHIELDED",
            "context": {
                "context_track": track_id,
                "context_package_sha256": ctx_prov,
                "rag_present": bool(track_id == "TRACK_D" and vapt_pack is not None),
                "cascade_present": bool(track_id == "TRACK_D"),
            },
            "allowed_sets": {
                "allowed_fact_ids": allowed_sets.allowed_fact_ids,
                "allowed_target_ids": allowed_sets.allowed_target_ids,
                "allowed_security_properties": allowed_props,
                "allowed_fact_ids_hash": allowed_sets.allowed_fact_ids_hash,
                "allowed_target_ids_hash": allowed_sets.allowed_target_ids_hash,
                "count_allowed_facts": allowed_sets.count_allowed_facts,
                "count_allowed_targets": allowed_sets.count_allowed_targets,
                "count_allowed_properties": len(allowed_props),
            },
            "runtime_telemetry": {
                "model_name": "qwen2.5-coder:7b",
                "model_digest": "dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364",
                "temperature": PRIMARY_TEMPERATURE,
                "seed": PRIMARY_SEED,
                "num_ctx": PRIMARY_NUM_CTX,
                "num_predict": PRIMARY_NUM_PREDICT,
                "keep_alive": PRIMARY_KEEP_ALIVE,
                "total_latency_ms": total_latency_ms,
                "timed_out": timed_out,
                "prompt_eval_count": prompt_eval_count,
                "eval_count": eval_count,
            },
            "provenance": {
                "prompt_sha256": prompt_hash,
                "raw_response_sha256": hashlib.sha256(raw_response.encode("utf-8")).hexdigest() if raw_response else None,
                "property_registry_version": PROPERTY_REGISTRY_VERSION,
                "output_origin": "MODEL_GENERATED",
            },
            "model_output": {
                "raw_response": raw_response,
                "parse_error": parse_error,
                "parsed_dict": parsed_dict,
                "candidate_decision": cand_dec,
                "selected_security_property": selected_prop,
                "experiment_action": act,
                "supporting_outcome": supp,
                "disproving_outcome": disp,
                "attack_predicate": attack_pred_dict,
            },
            "outcome_binding": {
                "is_bound_deterministically": True,
                "origin": "DETERMINISTICALLY_DERIVED",
                "binding_result": binding_result.model_dump() if binding_result else None,
            },
            "validation": {
                "schema_valid": schema_valid,
                "skeleton_compliant": skeleton_compliant,
                "skeleton_reason": skeleton_reason,
                "polarity_valid": polarity_valid,
                "polarity_reason": polarity_reason,
                "grounding_valid": grounding_valid,
                "grounding_reason": grounding_reason,
                "grounding_failure_code": grounding_code,
                "property_valid": property_valid,
                "property_reason": property_reason,
                "security_property_failure_code": property_code,
                "is_valid_typed_experiment": is_valid_typed_exp,
                "is_useful_vulnerable_hypothesis": is_useful_vuln,
            },
            "attribution": {
                "primary_failure_code": attribution_res.primary_code.value,
                "primary_failure_name": attribution_res.primary_code.name,
                "contributing_failure_codes": [c.value for c in attribution_res.contributing_codes],
                "details": attribution_res.details,
            },
        }
        return call_record

    def run_benchmark(self) -> List[Dict[str, Any]]:
        """
        Executes complete population confirmatory benchmark across 84 scenarios x 2 conditions (168 calls).
        """
        all_scenarios = get_gold_set_scenarios()
        assert len(all_scenarios) == 84, f"Expected 84 scenarios, got {len(all_scenarios)}"

        # Build full paired execution schedule
        schedule: List[Tuple[EvaluationScenario, str, str]] = []
        for scen in all_scenarios:
            conds = get_scenario_condition_order(scen.scenario_id, seed=FROZEN_ORDER_SEED)
            for c in conds:
                track = "TRACK_A" if c == "P4_TRACK_A" else "TRACK_D"
                schedule.append((scen, c, track))

        assert len(schedule) == 168, f"Expected 168 schedule entries, got {len(schedule)}"

        all_results: List[Dict[str, Any]] = []
        completed_keys = set()

        # Resume support if file exists
        if self.results_path.exists():
            try:
                existing = json.loads(self.results_path.read_text(encoding="utf-8"))
                if isinstance(existing, list):
                    all_results = existing
                    for r in existing:
                        completed_keys.add((r["scenario_id"], r["condition_id"]))
                    print(f"Resuming benchmark: {len(all_results)} calls already completed.")
            except Exception:
                all_results = []
                completed_keys = set()

        print("\n=================================================================")
        print("M5 Phase 11.5: Population-Level Confirmatory Benchmark")
        print(f"Total Population: 84 scenarios (36 vulnerable, 48 controls)")
        print(f"Total Calls Scheduled: 168 (Paired P4_TRACK_A vs P5_TRACK_D)")
        print(f"Order Seed: {FROZEN_ORDER_SEED}")
        print("=================================================================\n")

        for idx, (scen, cond_id, track) in enumerate(schedule, start=1):
            key = (scen.scenario_id, cond_id)
            if key in completed_keys:
                continue

            print(
                f"[{idx:03d}/168] Scenario: {scen.scenario_id} | Cond: {cond_id} ({track}) ...",
                end=" ",
                flush=True,
            )
            record = self.execute_call(
                scenario=scen,
                condition_id=cond_id,
                track_id=track,
                call_index=idx,
            )
            all_results.append(record)
            completed_keys.add(key)

            # Incremental persistence after every call
            self.results_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.results_path, "w", encoding="utf-8") as f:
                json.dump(all_results, f, indent=2)

            lat = record["runtime_telemetry"]["total_latency_ms"]
            prim = record["attribution"]["primary_failure_code"]
            is_valid = record["validation"]["is_valid_typed_experiment"]
            print(f"Done ({lat}ms) -> Valid: {is_valid} | Primary: {prim}")

        # Final Manifest Generation
        results_bytes = json.dumps(all_results, sort_keys=True).encode("utf-8")
        results_sha256 = hashlib.sha256(results_bytes).hexdigest()

        manifest = {
            "manifest_version": "1.0.0",
            "phase": "PHASE_11_5_CONFIRMATORY",
            "timestamp_utc": time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime()),
            "order_seed": FROZEN_ORDER_SEED,
            "total_calls_executed": len(all_results),
            "total_scenarios_evaluated": len({r["scenario_id"] for r in all_results}),
            "vulnerable_scenarios_evaluated": len({r["scenario_id"] for r in all_results if r["vulnerable_variant"]}),
            "control_scenarios_evaluated": len({r["scenario_id"] for r in all_results if not r["vulnerable_variant"]}),
            "conditions_evaluated": ["P4_TRACK_A", "P5_TRACK_D"],
            "results_file": "data/eval/m5_phase11_5_live_results.json",
            "results_sha256": results_sha256,
            "property_registry_version": PROPERTY_REGISTRY_VERSION,
            "runtime_configuration": {
                "model": "qwen2.5-coder:7b",
                "model_digest": "dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364",
                "temperature": PRIMARY_TEMPERATURE,
                "seed": PRIMARY_SEED,
                "num_ctx": PRIMARY_NUM_CTX,
                "num_predict": PRIMARY_NUM_PREDICT,
                "keep_alive": PRIMARY_KEEP_ALIVE,
                "timeout_seconds": 30.0,
            },
        }
        with open(self.manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        print("\n=================================================================")
        print(f"Phase 11.5 Benchmark Completed Successfully.")
        print(f"Results saved to: {self.results_path} (SHA: {results_sha256})")
        print(f"Manifest saved to: {self.manifest_path}")
        print("=================================================================\n")

        return all_results
