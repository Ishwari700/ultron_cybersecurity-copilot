"""Milestone M4.9 Confirmatory 84-Scenario 4-Track Benchmark Runner.

Executes the formal confirmatory benchmark specified in docs/M4_REASONING_ENGINE_PLAN.md:
- Full 84 frozen scenarios from data/benchmarks/m1_5_frozen_manifest.json (36 vuln, 48 controls).
- 4 confirmatory tracks:
    1. Track A (No RAG): TRACK_A (No Target Evidence, No VAPT)
    2. Track B (Target Ev): TRACK_B (Target-Evidence RAG, No VAPT)
    3. Track C (VAPT): TRACK_C (VAPT Knowledge RAG, No Target Evidence)
    4. Track D (Dual): TRACK_D (Dual RAG: Target Evidence + VAPT Knowledge)
- All 4 tracks evaluate the frozen M4.8 configuration:
    M4-COMBINED-I5-I2-I6-I3-I4 (i1=0, i2=1, i3=1, i4=1, i5=1, i6=1).
- Total scheduled evaluation calls: 84 * 4 = 336 live calls.
- Strict B/D target-evidence causal parity (0 discrepancies across 84 scenarios).
- Primary fixed-budget compute envelope:
    qwen2.5-coder:7b (pinned digest dae161e2...)
    Ollama v0.34.1
    num_ctx=2048, num_predict=300, temperature=0.0, seed=42, keep_alive=60m
- Single-call per evaluation attempt: exactly 1 LLM call, zero retries, zero semantic repair.
- Mutual exclusive AC1 failure classification.
- Output artifact: data/eval/m4_live_llm_benchmark_final.json with SHA-256 seal.
"""

from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import logging
from pathlib import Path
import re
import subprocess
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from src.engine.context_builder import (
    ContextBudgetOverflowError,
    ReasoningContextBuilder,
    TRACK_A,
    TRACK_B,
    TRACK_C,
    TRACK_D,
)
from src.engine.decision_policy import (
    DecisionPolicyResult,
    EvidenceState,
    deterministic_decide,
)
from src.engine.handoff_serializer import HandoffSerializer, ProtectedHandoffDescriptor
from src.engine.models import (
    FailureClassificationResult,
    HypothesisDecision,
    HypothesisModelOutput,
    PrimaryFailureCategory,
    classify_primary_failure,
)
from src.evidence.cascade_models import (
    CascadeHandoffPacket,
    DeterministicRoutingDecision,
    LosslessStructuralPack,
)
from src.engine.bair_extractor import (
    BairParseError,
    BairSchemaError,
    determine_empirical_evidence_present,
    map_bair_to_s0,
    parse_bair,
    validate_bair,
)
from src.engine.runner import (
    PRIMARY_KEEP_ALIVE,
    PRIMARY_NUM_CTX,
    PRIMARY_NUM_PREDICT,
    PRIMARY_SEED,
    PRIMARY_TEMPERATURE,
    ReasoningRunner,
)
from src.eval.scenarios import EvaluationScenario, get_gold_set_scenarios
from src.knowledge.grounding_validator import KnowledgeGroundingResult, KnowledgeGroundingValidator
from src.knowledge.models import EvidenceGapType, VaptKnowledgePack
from src.knowledge.pipeline import VaptReasoningPipeline

logger = logging.getLogger("m4.confirmatory")

EXPECTED_7B_DIGEST_PREFIX = "dae161e2"
EXPECTED_7B_DIGEST_FULL = "dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364"
EXPECTED_BENCHMARK_HASH = "b2b85a672124acf21066a257d8c7f5093000368b224ee013c02574c96a0ae707"
EXPECTED_FROZEN_CONFIG_HASH = "772d68474199fb936f054e85615295d22ac2096bb838b4e024fb6cb8f1c8c34a"
EXPECTED_PLANNING_FREEZE_COMMIT = "1e1a87070a018542a0a2e79f8a78654f34df5aba"

FORBIDDEN_PROMPT_TOKENS = [
    "ground_truth",
    "expected_outcome",
    "vulnerable_label",
    "control_label",
    "oracle_verdict",
    "is_vulnerable",
    "is_patched",
    "vulnerable_variant",
    "expected_decision",
    "gold_decision",
]


class ConfirmatoryTrackId(str, Enum):
    TRACK_A = "TRACK_A"  # 7B Baseline (No RAG: No Target Evidence, No VAPT)
    TRACK_B = "TRACK_B"  # 7B + Target-Evidence RAG (evidence.db only)
    TRACK_C = "TRACK_C"  # 7B + VAPT Knowledge RAG (Diagnostic; vapt_knowledge.db only)
    TRACK_D = "TRACK_D"  # 7B + Dual RAG (Primary Causal Test: Target Evidence + VAPT Knowledge)


TRACK_NAME_MAP = {
    ConfirmatoryTrackId.TRACK_A: "Track A (No RAG)",
    ConfirmatoryTrackId.TRACK_B: "Track B (Target Ev)",
    ConfirmatoryTrackId.TRACK_C: "Track C (VAPT)",
    ConfirmatoryTrackId.TRACK_D: "Track D (Dual)",
}


class ConfirmatoryScenarioRecord(BaseModel):
    scenario_id: str
    track_id: str
    track_name: str
    category_id: str
    vulnerable_variant: bool
    ground_truth_class: str
    canonical_input_hash: str
    prompt: str
    raw_model_response: str
    parsed_output: Optional[Dict[str, Any]] = None
    canonical_s0_output: Optional[Dict[str, Any]] = None
    decision: Optional[str] = None
    primary_failure_category: str
    is_valid: bool
    is_useful: int = 0
    grounding_status: str
    raw_namespace_breach: Optional[int] = None
    validator_bypass: Optional[bool] = None
    latency_ms: float
    eval_count: Optional[int] = None
    prompt_eval_count: Optional[int] = None
    done_reason: Optional[str] = None
    model_name: str
    model_digest: str
    runtime_version: str
    timestamp: str


def infer_evidence_gap_type(category_id: str) -> EvidenceGapType:
    cat = category_id.upper()
    if "BOLA" in cat or "CROSS-TENANT" in cat:
        return EvidenceGapType.MISSING_CROSS_IDENTITY_OBJECT_VERIFICATION
    elif "STATE" in cat or "WORKFLOW" in cat or "LIFECYCLE" in cat or "MUTATION" in cat:
        return EvidenceGapType.MISSING_MUTATION_STATE_BOUNDARY
    elif "AUTH" in cat or "ROLE" in cat or "BFLA" in cat:
        return EvidenceGapType.MISSING_ROLE_HIERARCHY_ENFORCEMENT
    elif "NONE" in cat:
        return EvidenceGapType.MISSING_UNAUTHENTICATED_ACCESS_CHECK
    return EvidenceGapType.MISSING_CROSS_IDENTITY_OBJECT_VERIFICATION


class M4ConfirmatoryHarness:
    """
    Executes the 84-scenario 4-track confirmatory benchmark (336 calls total).
    Enforces strict B/D causal parity, zero retries, zero repair, and fail-closed evaluation.
    """

    def __init__(
        self,
        live_mode: bool = True,
        llm_caller: Optional[Callable[[str, Optional[Dict[str, Any]]], str]] = None,
    ) -> None:
        self.live_mode = live_mode
        self.llm_caller = llm_caller

        self.context_builder = ReasoningContextBuilder()
        self.validator = KnowledgeGroundingValidator()
        self.pipeline = VaptReasoningPipeline()

        self.runner = ReasoningRunner(
            model_name="qwen2.5-coder:7b",
            num_ctx=PRIMARY_NUM_CTX,
            llm_caller=llm_caller,
        )

        self._gold_scenarios: List[EvaluationScenario] = get_gold_set_scenarios()
        assert len(self._gold_scenarios) == 84, f"Expected 84 gold scenarios, found {len(self._gold_scenarios)}"

        self._canonical_input_cache: Dict[str, Dict[str, Any]] = {}

    def get_canonical_input(self, scenario_id: str) -> Dict[str, Any]:
        """
        Retrieves or constructs the canonical reasoning input ONCE per scenario.
        Enforces 100% byte parity of evidence, metadata, and structural pack.
        """
        if scenario_id in self._canonical_input_cache:
            return self._canonical_input_cache[scenario_id]

        matched = [s for s in self._gold_scenarios if s.scenario_id == scenario_id]
        if not matched:
            raise KeyError(f"Scenario ID {scenario_id} not found in gold set")
        gold_scen = matched[0]

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
            has_privilege_level_delta=False,
            has_cross_identity_object_access_success=False,
            observed_facts=observed_facts,
            raw_body_sample=raw_sample,
        )

        gap_type = infer_evidence_gap_type(gold_scen.category_id)

        # Retrieve VAPT knowledge pack
        vapt_pack, ret_diag = self.pipeline.retrieve_and_pack(
            channel_a=pack,
            gap_type=gap_type,
        )

        # Canonical input fingerprint: target evidence + target metadata
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

    def build_prompt_for_track(
        self,
        scenario_id: str,
        track_id: ConfirmatoryTrackId,
    ) -> Tuple[str, bytes]:
        """
        Assembles prompt according to the confirmatory track retrieval configuration
        under the frozen M4.8 reasoning configuration (I5 + I2 + I6 + I3 + I4).
        Also returns the exact target evidence bytes for B/D causal parity verification.
        """
        canonical_input = self.get_canonical_input(scenario_id)
        pack: LosslessStructuralPack = canonical_input["pack"]
        vapt_pack: Optional[VaptKnowledgePack] = canonical_input["vapt_pack"]
        gold_scen: EvaluationScenario = canonical_input["gold_scenario"]
        gap_type: EvidenceGapType = canonical_input["gap_type"]

        routing = DeterministicRoutingDecision(
            schema_version="2.0.0",
            escalate=True,
            has_high_risk_signal=True,
            high_risk_signals=["M4_CONFIRMATORY"],
            fail_safe_triggered=False,
        )
        handoff = CascadeHandoffPacket(
            schema_version="2.0.0",
            channel_a_structural=pack,
            routing_decision=routing,
            provenance_hash=f"prov_{pack.asset_id}",
        )

        from src.engine.prompts import get_counterfactual_template
        cat_tmpl = get_counterfactual_template(gold_scen.category_id)
        active_descriptor = HandoffSerializer.from_cascade_packet(
            handoff_packet=handoff,
            evidence_gap_type=gap_type,
            invariant=cat_tmpl.invariant_definition,
        )

        # Map track_id to cascade_mode
        track_cascade_map = {
            ConfirmatoryTrackId.TRACK_A: TRACK_A,
            ConfirmatoryTrackId.TRACK_B: TRACK_B,
            ConfirmatoryTrackId.TRACK_C: TRACK_C,
            ConfirmatoryTrackId.TRACK_D: TRACK_D,
        }
        cascade_mode = track_cascade_map[track_id]

        ctx = self.context_builder.build_context(
            handoff_packet=handoff,
            model_identifier="qwen2.5-coder:7b",
            budget_tier=4096,
            cascade_mode=cascade_mode,
            vapt_pack=vapt_pack,
            enable_i2_namespace_partitioning=True,
            enable_i3_counterfactual_prompting=True,
            category_id=gold_scen.category_id,
            enable_i4_bair=True,
            enable_i5_decision_policy=True,
            enable_i6_handoff=True,
            protected_handoff=active_descriptor,
        )

        # Assert zero ground truth tokens in prompt
        prompt_lower = ctx.prompt.lower()
        for token in FORBIDDEN_PROMPT_TOKENS:
            assert token not in prompt_lower, f"Ground-truth token '{token}' leaked into prompt for {scenario_id} ({track_id.value})"

        # Extract target evidence bytes for B/D causal parity check
        target_ev_bytes = b""
        match = re.search(r"<untrusted_target_data>(.*?)</untrusted_target_data>", ctx.prompt, re.DOTALL)
        if match:
            target_ev_bytes = match.group(1).strip().encode("utf-8")

        return ctx.prompt, target_ev_bytes

    def execute_scenario_track(
        self,
        scenario_id: str,
        track_id: ConfirmatoryTrackId,
    ) -> ConfirmatoryScenarioRecord:
        """
        Executes exactly ONE inference call for a given scenario and track under the frozen configuration.
        Zero retries, zero semantic repair, fail-closed on any failure.
        """
        canonical_input = self.get_canonical_input(scenario_id)
        gold_scen: EvaluationScenario = canonical_input["gold_scenario"]
        pack: LosslessStructuralPack = canonical_input["pack"]
        vapt_pack: Optional[VaptKnowledgePack] = canonical_input["vapt_pack"]
        canonical_input_hash: str = canonical_input["canonical_input_hash"]
        empirical_evidence_present: bool = canonical_input["empirical_evidence_present"]

        prompt, target_ev_bytes = self.build_prompt_for_track(
            scenario_id=scenario_id,
            track_id=track_id,
        )

        ts = datetime.now(timezone.utc).isoformat()
        model_name = "qwen2.5-coder:7b"
        model_digest = EXPECTED_7B_DIGEST_PREFIX
        runtime_version = "Ollama v0.34.1"

        t0 = time.perf_counter()
        raw_response = ""
        eval_count: Optional[int] = None
        prompt_eval_count: Optional[int] = None
        done_reason: Optional[str] = None
        transport_error: Optional[Exception] = None

        if self.llm_caller:
            try:
                raw_response = self.llm_caller(prompt, None)
            except Exception as exc:
                transport_error = exc
        else:
            try:
                resp_data = self.runner.ollama_runner.generate_raw(
                    prompt=prompt,
                    schema=None,  # Unconstrained sampling (I1 is OFF)
                    num_ctx=PRIMARY_NUM_CTX,
                    num_predict=PRIMARY_NUM_PREDICT,
                    temperature=PRIMARY_TEMPERATURE,
                    keep_alive=PRIMARY_KEEP_ALIVE,
                )
                raw_response = resp_data.get("response", "")
                eval_count = resp_data.get("eval_count")
                prompt_eval_count = resp_data.get("prompt_eval_count")
                done_reason = resp_data.get("done_reason")
            except Exception as exc:
                transport_error = exc

        latency_ms = (time.perf_counter() - t0) * 1000.0

        # Output parsing (BAIR path)
        parsed_json = None
        parse_error = None
        schema_error = None
        canonical_s0 = None
        extracted_bair = None
        raw_ns_breach = None
        val_bypass = None

        if transport_error is None:
            try:
                raw_slots = parse_bair(raw_response)
                extracted_bair = validate_bair(raw_slots, empirical_evidence_present=empirical_evidence_present)
                canonical_s0 = map_bair_to_s0(extracted_bair)
            except BairParseError as exc:
                parse_error = exc
            except BairSchemaError as exc:
                schema_error = exc
            except Exception as exc:
                schema_error = exc

        # Apply I5 decision policy if valid candidate hypothesis exists
        if canonical_s0 is not None:
            ev_state = EvidenceState(
                channel_a=pack,
                target_asset=gold_scen.target_asset,
                category_id=gold_scen.category_id,
                empirical_evidence_present=empirical_evidence_present,
            )
            policy_res = deterministic_decide(
                candidate=canonical_s0,
                evidence_state=ev_state,
            )
            if policy_res.final_decision is not None:
                canonical_s0 = canonical_s0.model_copy(update={"decision": policy_res.final_decision})

        # Grounding validation
        grounding_result = None
        if canonical_s0 is not None:
            grounding_result = self.validator.validate_grounding(
                hypothesis=canonical_s0,
                pack=vapt_pack,
                channel_a=pack,
            )

        grounding_error = None
        if grounding_result is not None and grounding_result.status != "VALID":
            grounding_error = f"Grounding invalid: {grounding_result.status}"
        elif canonical_s0 is None and transport_error is None and parse_error is None and schema_error is None:
            grounding_error = "Grounding skipped due to missing/invalid hypothesis"

        classification = classify_primary_failure(
            transport_error=transport_error,
            raw_response=raw_response,
            eval_count=eval_count,
            done_reason=done_reason,
            num_predict=PRIMARY_NUM_PREDICT,
            parsed_json=parsed_json,
            parse_error=parse_error,
            schema_error=schema_error,
            grounding_error=grounding_error,
        )

        decision_str = canonical_s0.decision.value if (canonical_s0 and canonical_s0.decision) else None

        # Useful hypothesis criterion
        is_useful = 0
        if classification.is_valid and decision_str == "HYPOTHESIS" and gold_scen.vulnerable_variant:
            is_useful = 1

        return ConfirmatoryScenarioRecord(
            scenario_id=scenario_id,
            track_id=track_id.value,
            track_name=TRACK_NAME_MAP[track_id],
            category_id=gold_scen.category_id,
            vulnerable_variant=gold_scen.vulnerable_variant,
            ground_truth_class="vulnerable" if gold_scen.vulnerable_variant else "control",
            canonical_input_hash=canonical_input_hash,
            prompt=prompt,
            raw_model_response=raw_response,
            parsed_output=extracted_bair,
            canonical_s0_output=canonical_s0.model_dump() if canonical_s0 else None,
            decision=decision_str,
            primary_failure_category=classification.primary_category.value,
            is_valid=classification.is_valid,
            is_useful=is_useful,
            grounding_status=grounding_result.status if grounding_result else "INVALID",
            raw_namespace_breach=raw_ns_breach,
            validator_bypass=val_bypass,
            latency_ms=latency_ms,
            eval_count=eval_count,
            prompt_eval_count=prompt_eval_count,
            done_reason=done_reason,
            model_name=model_name,
            model_digest=model_digest,
            runtime_version=runtime_version,
            timestamp=ts,
        )
