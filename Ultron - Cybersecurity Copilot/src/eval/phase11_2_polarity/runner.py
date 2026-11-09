"""
Milestone M5 Phase 11.2: Polarity Representation Diagnostic Runner.

Executes the small 16-call diagnostic experiment across 8 balanced scenarios (4 vuln, 4 control)
comparing Condition P0 (Control: model outcome selection) vs Condition P1 (Treatment: attack predicate + deterministic outcome binding).

Frozen parameters:
- Model: qwen2.5-coder:7b (dae161e27b0e)
- Track: TRACK_A (Minimal structural context, zero RAG)
- num_ctx: 2048, num_predict: 300, temp: 0.0, seed: 42, keep_alive: 60m
- Timeout: 30.0s hard ceiling (+500ms teardown tolerance)
- Exactly one attempt per cell (no retries, no repairs)
"""

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import random
import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from src.engine.context_builder import ReasoningContextBuilder, TRACK_A
from src.engine.decision_policy import ExperimentPolarityValidator
from src.engine.experiment_skeleton import (
    ExperimentSkeletonBuilder,
    ExperimentSkeletonDescriptor,
    render_skeleton_prompt_block,
    validate_skeleton_compliance,
)
from src.engine.handoff_serializer import HandoffSerializer
from src.engine.models import (
    BairJsonObject,
    HypothesisDecision,
    OutputProtocolIdentifier,
    PrimaryFailureCategory,
)
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
from src.eval.phase11_failure_analysis.taxonomy import FailureCode
from src.eval.scenarios import EvaluationScenario, get_gold_set_scenarios
from src.evidence.cascade_models import (
    CascadeHandoffPacket,
    DeterministicRoutingDecision,
    LosslessStructuralPack,
)
from src.knowledge.grounding_validator import KnowledgeGroundingValidator
from src.knowledge.models import EvidenceGapType

from src.eval.phase11_2_polarity.attack_predicate import AttackPredicate
from src.eval.phase11_2_polarity.outcome_binding import (
    derive_outcomes_from_attack_predicate,
    OutcomeBindingResult,
)
from src.eval.phase11_2_polarity.protocol import (
    P1_PROMPT_INSTRUCTION,
    P1BairJsonObject,
    parse_p1_response,
)

# Authoritative pre-selected 8 diagnostic scenarios (4 vuln, 4 control)
DIAGNOSTIC_SCENARIO_IDS: List[str] = [
    # 1. BOLA / Ownership
    "SCEN-SAAS_BILLING-INV-DETAILS-VULN-01",
    "SCEN-SAAS_BILLING-INV-DETAILS-PATCH-01",
    # 2. State Machine / Lifecycle
    "SCEN-ECOMMERCE_ORDERS-ORD-CANCEL-REFUND-VULN-04",
    "SCEN-ECOMMERCE_ORDERS-ORD-CANCEL-REFUND-PATCH-04",
    # 3. Role Boundary / BFLA
    "SCEN-IDENTITY_PROVIDER-USER-TENANT-ROLE-VULN-03",
    "SCEN-IDENTITY_PROVIDER-USER-TENANT-ROLE-PATCH-03",
    # 4. Cross-Tenant Isolation
    "SCEN-SAAS_BILLING-INV-SUMMARY-VULN-03",
    "SCEN-SAAS_BILLING-INV-SUMMARY-PATCH-03",
]

FROZEN_ORDER_SEED: str = "M5_PHASE11_2_ORDER_SEED_42"


def get_diagnostic_condition_order(
    scenario_id: str,
    seed: str = FROZEN_ORDER_SEED,
) -> List[str]:
    """
    Deterministically computes pseudo-random condition order (P0, P1) for a scenario.
    """
    payload = f"{seed}:{scenario_id}".encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()
    seed_int = int(digest[:16], 16)
    rng = random.Random(seed_int)
    conds = ["P0", "P1"]
    rng.shuffle(conds)
    return conds


class Phase11PolarityDiagnosticRunner:
    """Orchestrates the 16-call diagnostic experiment."""

    def __init__(
        self,
        ollama_runner: Optional[OllamaRunner] = None,
        repo_root: Optional[Path] = None,
    ) -> None:
        self.repo_root = repo_root or Path(__file__).resolve().parent.parent.parent.parent
        self.ollama = ollama_runner or OllamaRunner(timeout_seconds=30.0)
        self.context_builder = ReasoningContextBuilder()
        self.grounding_validator = KnowledgeGroundingValidator()

        # Index gold scenarios
        all_scens = get_gold_set_scenarios()
        self.scenario_map: Dict[str, EvaluationScenario] = {s.scenario_id: s for s in all_scens}
        self.diagnostic_scenarios: List[EvaluationScenario] = [
            self.scenario_map[sid] for sid in DIAGNOSTIC_SCENARIO_IDS
        ]

    def build_p0_prompt_and_schema(
        self,
        scen: EvaluationScenario,
        handoff: CascadeHandoffPacket,
        active_descriptor: Any,
        cat_tmpl: Any,
        gap_type: EvidenceGapType,
        skeleton_desc: ExperimentSkeletonDescriptor,
    ) -> Tuple[str, Dict[str, Any]]:
        """Constructs P0 Control prompt and schema (standard Phase 10 JSON_BAIR)."""
        base_ctx = self.context_builder.build_context(
            handoff_packet=handoff,
            model_identifier="qwen2.5-coder:7b",
            budget_tier=2048,
            cascade_mode=TRACK_A,
            vapt_pack=None,
            enable_i2_namespace_partitioning=True,
            enable_i3_counterfactual_prompting=True,
            category_id=scen.category_id,
            enable_i4_bair=True,
            enable_i5_decision_policy=True,
            enable_i6_handoff=True,
            protected_handoff=active_descriptor,
            output_protocol=OutputProtocolIdentifier.JSON_BAIR,
        )
        skeleton_block = render_skeleton_prompt_block(skeleton_desc)
        full_user_prompt = f"{base_ctx.user_prompt}\n\n{skeleton_block}"
        full_prompt = f"{base_ctx.system_prompt}\n{full_user_prompt}"
        schema = BairJsonObject.get_inference_schema()
        return full_prompt, schema

    def build_p1_prompt_and_schema(
        self,
        scen: EvaluationScenario,
        handoff: CascadeHandoffPacket,
        active_descriptor: Any,
        cat_tmpl: Any,
        gap_type: EvidenceGapType,
        skeleton_desc: ExperimentSkeletonDescriptor,
    ) -> Tuple[str, Dict[str, Any]]:
        """Constructs P1 Treatment prompt and schema (Attack-Predicate representation)."""
        base_ctx = self.context_builder.build_context(
            handoff_packet=handoff,
            model_identifier="qwen2.5-coder:7b",
            budget_tier=2048,
            cascade_mode=TRACK_A,
            vapt_pack=None,
            enable_i2_namespace_partitioning=True,
            enable_i3_counterfactual_prompting=True,
            category_id=scen.category_id,
            enable_i4_bair=True,
            enable_i5_decision_policy=True,
            enable_i6_handoff=True,
            protected_handoff=active_descriptor,
            output_protocol=OutputProtocolIdentifier.JSON_BAIR,
        )

        # Replace default JSON_BAIR output instructions with P1 attack-predicate instructions
        user_prompt = base_ctx.user_prompt
        # Strip trailing output instructions from base prompt if present
        if "OUTPUT FORMAT (BOUNDED ANALYTICAL INFERENCE REPRESENTATION" in user_prompt:
            parts = user_prompt.split("OUTPUT FORMAT (BOUNDED ANALYTICAL INFERENCE REPRESENTATION")
            user_prompt = parts[0].strip()

        p1_skeleton_block = (
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

        full_user_prompt = f"{user_prompt}\n\n{P1_PROMPT_INSTRUCTION}\n\n{p1_skeleton_block}"
        full_prompt = f"{base_ctx.system_prompt}\n{full_user_prompt}"
        schema = P1BairJsonObject.get_inference_schema()
        return full_prompt, schema

    def execute_call(
        self,
        scenario: EvaluationScenario,
        condition_id: str,
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
        gap_type = infer_evidence_gap_type(cat_id)
        routing = DeterministicRoutingDecision(
            escalate=True,
            has_high_risk_signal=True,
            high_risk_signals=["M5_PHASE11_2"],
            fail_safe_triggered=False,
        )
        handoff = CascadeHandoffPacket(
            schema_version="2.0.0",
            channel_a_structural=pack,
            routing_decision=routing,
            provenance_hash=f"prov_{pack.asset_id}",
        )
        cat_tmpl = get_counterfactual_template(cat_id)
        active_descriptor = HandoffSerializer.from_cascade_packet(
            handoff_packet=handoff,
            evidence_gap_type=gap_type,
            invariant=cat_tmpl.invariant_definition,
        )
        skeleton_desc = ExperimentSkeletonBuilder.build_skeleton(
            category_id=cat_id,
            invariant_definition=cat_tmpl.invariant_definition,
            evidence_gap_type=gap_type.value,
        )

        target_asset_enriched = dict(scenario.target_asset)
        target_asset_enriched["parameters"] = list(scenario.parameters)
        target_asset_enriched["identities"] = list(scenario.identities)

        # 2. Prompt & Schema Construction
        if condition_id == "P0":
            full_prompt, schema = self.build_p0_prompt_and_schema(
                scenario, handoff, active_descriptor, cat_tmpl, gap_type, skeleton_desc
            )
        elif condition_id == "P1":
            full_prompt, schema = self.build_p1_prompt_and_schema(
                scenario, handoff, active_descriptor, cat_tmpl, gap_type, skeleton_desc
            )
        else:
            raise ValueError(f"Unknown condition_id: {condition_id}")

        # Assert no ground truth leakage in prompt
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

        # 4. Parsing and Condition-Specific Outcome Derivation
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
            if condition_id == "P0":
                try:
                    p0_obj = BairJsonObject.model_validate_json(raw_response)
                    parsed_dict = p0_obj.model_dump()
                    cand_dec = parsed_dict.get("decision")
                    act = parsed_dict.get("experiment_action")
                    supp = parsed_dict.get("supporting_outcome")
                    disp = parsed_dict.get("disproving_outcome")
                    schema_valid = True
                except Exception as exc:
                    parse_error = str(exc)
                    schema_valid = False
            elif condition_id == "P1":
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
                            supp = None
                            disp = None
                else:
                    parse_error = p1_err
                    schema_valid = False

        is_hyp_cand = (cand_dec == "HYPOTHESIS")

        # 5. Validation Checkers
        skeleton_compliant: Optional[bool] = None
        skeleton_reason: Optional[str] = None
        polarity_valid: bool = False
        polarity_reason: Optional[str] = None
        grounding_valid: bool = False
        grounding_reason: Optional[str] = None

        if is_hyp_cand and act and supp and disp:
            if condition_id == "P0":
                s_ok, s_msg = validate_skeleton_compliance(skeleton_desc, act, supp, disp)
                skeleton_compliant = s_ok
                skeleton_reason = s_msg
            else:
                # In P1, action was enforced by skeleton descriptor and binding
                skeleton_compliant = (act == skeleton_desc.experiment_action) and (binding_result.is_valid if binding_result else False)
                skeleton_reason = "Enforced via deterministic outcome binding" if skeleton_compliant else binding_result.error_message if binding_result else "Missing binding"

            p_ok, p_msg = ExperimentPolarityValidator.validate_tuple(
                category_id=cat_id,
                experiment_action=act,
                supporting_outcome=supp,
                disproving_outcome=disp,
            )
            polarity_valid = p_ok
            polarity_reason = p_msg

        # Grounding validation against structural slice
        if parsed_dict and not timed_out:
            target_ref = parsed_dict.get("affected_target")
            facts_cited = parsed_dict.get("empirical_facts", [])
            # Target endpoint or parameter must be grounded in Channel A pack
            is_endpoint_match = (
                target_ref == pack.route_template
                or target_ref == pack.asset_id
                or target_ref == pack.endpoint_id
                or any(target_ref == p for p in pack.parameter_lineage)
            )
            grounding_valid = is_endpoint_match
            if not is_endpoint_match:
                grounding_reason = f"affected_target '{target_ref}' not found in Channel A endpoint or parameters"

        # 6. Primary Failure Classification
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
            "track_id": "TRACK_A",
            "polarity_valid": polarity_valid,
            "polarity_reason": polarity_reason,
            "skeleton_compliant": skeleton_compliant,
            "skeleton_reason": skeleton_reason,
        }
        if not grounding_valid and not timed_out and schema_valid:
            raw_eval_rec["primary_failure_category"] = "SEMANTIC_GROUNDING_FAILURE"
        elif not polarity_valid and is_hyp_cand and not timed_out and schema_valid and grounding_valid:
            raw_eval_rec["primary_failure_category"] = "SEMANTIC_EXPERIMENT_POLARITY_FAILURE"

        attr_res: FailureAttributionResult = attribute_failure(
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
            and not timed_out
        )

        is_useful_vuln_hyp = is_valid_typed_exp and is_vuln

        # 7. Package Record
        record = {
            "call_index": call_index,
            "condition_id": condition_id,
            "scenario_id": sid,
            "category_id": cat_id,
            "vulnerable_variant": is_vuln,
            "protocol": "P1_ATTACK_PREDICATE" if condition_id == "P1" else "P0_TYPED_POLARITY",
            "runtime_telemetry": {
                "model_name": "qwen2.5-coder:7b",
                "model_digest": "dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364",
                "num_ctx": PRIMARY_NUM_CTX,
                "num_predict": PRIMARY_NUM_PREDICT,
                "temperature": PRIMARY_TEMPERATURE,
                "seed": PRIMARY_SEED,
                "keep_alive": PRIMARY_KEEP_ALIVE,
                "timed_out": timed_out,
                "total_latency_ms": total_latency_ms,
                "eval_count": eval_count,
                "prompt_eval_count": prompt_eval_count,
            },
            "provenance": {
                "prompt_sha256": prompt_hash,
                "raw_response_sha256": hashlib.sha256(raw_response.encode("utf-8")).hexdigest() if raw_response else None,
                "output_origin": "DETERMINISTICALLY_DERIVED" if condition_id == "P1" else "MODEL_GENERATED",
            },
            "model_output": {
                "raw_response": raw_response,
                "parsed_dict": parsed_dict,
                "parse_error": parse_error,
                "candidate_decision": cand_dec,
                "experiment_action": act,
                "supporting_outcome": supp,
                "disproving_outcome": disp,
                "attack_predicate": attack_pred_dict,
            },
            "outcome_binding": (
                binding_result.model_dump() if binding_result else None
            ),
            "validation": {
                "schema_valid": schema_valid,
                "skeleton_compliant": skeleton_compliant,
                "skeleton_reason": skeleton_reason,
                "polarity_valid": polarity_valid,
                "polarity_reason": polarity_reason,
                "grounding_valid": grounding_valid,
                "grounding_reason": grounding_reason,
                "is_valid_typed_experiment": is_valid_typed_exp,
                "is_useful_vulnerable_hypothesis": is_useful_vuln_hyp,
            },
            "attribution": {
                "primary_failure_code": attr_res.primary_code.value,
                "primary_failure_name": attr_res.primary_name,
                "contributing_failure_codes": [c.value for c in attr_res.contributing_codes],
                "details": attr_res.details,
            },
        }

        return record

    def run_diagnostic(
        self,
        progress_callback: Optional[Callable[[int, int, str, str], None]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Executes the 16 diagnostic calls in deterministic per-scenario order.
        """
        records: List[Dict[str, Any]] = []
        call_counter = 1

        for scen in self.diagnostic_scenarios:
            sid = scen.scenario_id
            cond_order = get_diagnostic_condition_order(sid)

            for cond_id in cond_order:
                if progress_callback:
                    progress_callback(call_counter, 16, sid, cond_id)

                rec = self.execute_call(
                    scenario=scen,
                    condition_id=cond_id,
                    call_index=call_counter,
                )
                records.append(rec)
                call_counter += 1

        return records
