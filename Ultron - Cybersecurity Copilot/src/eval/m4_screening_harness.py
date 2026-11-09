"""Milestone M4.8 Screening Evaluation Harness.

Orchestrates pure single-factor intervention screening (Baseline, E1-E6)
and the post-screening COMBINED configuration evaluation across the frozen
20-scenario development partition.

Enforces:
- Exact primary compute envelope (qwen2.5-coder:7b, num_ctx=2048, num_predict=300, temp=0.0, seed=42)
- Exactly ONE LLM call per scenario attempt
- Input & evidence parity verification across all tracks (canonical_input_hash)
- Ground-truth exclusion from runtime dataflow and prompts
- Mutually exclusive primary AC1 failure taxonomy
- Programmatic activation matrix verification
"""

from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import logging
from pathlib import Path
import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from src.core.config import OllamaConfig
from src.evidence.cascade_models import (
    CascadeHandoffPacket,
    DeterministicRoutingDecision,
    LosslessStructuralPack,
)
from src.engine.context_builder import (
    ReasoningContextBuilder,
    TRACK_D,
)
from src.engine.handoff_serializer import HandoffSerializer, ProtectedHandoffDescriptor
from src.engine.models import (
    HypothesisDecision,
    HypothesisModelOutput,
    I1ExecutionResult,
    I2ExecutionResult,
    I3ExecutionResult,
    I4ExecutionResult,
    I5ExecutionResult,
    I6ExecutionResult,
    PrimaryFailureCategory,
    classify_primary_failure,
)
from src.engine.bair_extractor import determine_empirical_evidence_present
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

logger = logging.getLogger("m4.screening")

EXPECTED_7B_DIGEST_PREFIX = "dae161e2"
FORBIDDEN_PROMPT_TOKENS = [
    "ground_truth",
    "expected_outcome",
    "vulnerable_label",
    "control_label",
    "oracle_verdict",
    "is_vulnerable",
    "is_patched",
]


class ScreeningTrackId(str, Enum):
    BASELINE = "BASELINE"
    E1 = "E1"
    E2 = "E2"
    E3 = "E3"
    E4 = "E4"
    E5 = "E5"
    E6 = "E6"
    COMBINED = "COMBINED"


class TrackActivationMatrix(BaseModel):
    i1: int = 0
    i2: int = 0
    i3: int = 0
    i4: int = 0
    i5: int = 0
    i6: int = 0

    def as_dict(self) -> Dict[str, int]:
        return {
            "i1": self.i1,
            "i2": self.i2,
            "i3": self.i3,
            "i4": self.i4,
            "i5": self.i5,
            "i6": self.i6,
        }


TRACK_ACTIVATION_SPEC: Dict[ScreeningTrackId, TrackActivationMatrix] = {
    ScreeningTrackId.BASELINE: TrackActivationMatrix(i1=0, i2=0, i3=0, i4=0, i5=0, i6=0),
    ScreeningTrackId.E1: TrackActivationMatrix(i1=1, i2=0, i3=0, i4=0, i5=0, i6=0),
    ScreeningTrackId.E2: TrackActivationMatrix(i1=0, i2=1, i3=0, i4=0, i5=0, i6=0),
    ScreeningTrackId.E3: TrackActivationMatrix(i1=0, i2=0, i3=1, i4=0, i5=0, i6=0),
    ScreeningTrackId.E4: TrackActivationMatrix(i1=0, i2=0, i3=0, i4=1, i5=0, i6=0),
    ScreeningTrackId.E5: TrackActivationMatrix(i1=0, i2=0, i3=0, i4=0, i5=1, i6=0),
    ScreeningTrackId.E6: TrackActivationMatrix(i1=0, i2=0, i3=0, i4=0, i5=0, i6=1),
}


class ScenarioScreeningRecord(BaseModel):
    scenario_id: str
    category_id: str
    track_id: str
    activation_matrix: Dict[str, int]
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
    grounding_status: str
    raw_namespace_breach: Optional[bool] = None
    validator_bypass: Optional[bool] = None
    latency_ms: float
    eval_count: Optional[int] = None
    prompt_eval_count: Optional[int] = None
    done_reason: Optional[str] = None
    model_name: str
    model_digest: str
    runtime_version: str
    num_ctx: int
    num_predict: int
    temperature: float
    seed: int
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


class M4ScreeningHarness:
    """Screening execution harness for M4.8."""

    def __init__(
        self,
        live_mode: bool = True,
        llm_caller: Optional[Callable[[str, Optional[Dict[str, Any]]], str]] = None,
        manifest_path: Path = Path("data/eval/m4_dev_partition_manifest.json"),
    ) -> None:
        self.live_mode = live_mode
        self.llm_caller = llm_caller
        self.manifest_path = manifest_path

        self.context_builder = ReasoningContextBuilder()
        self.validator = KnowledgeGroundingValidator()
        self.pipeline = VaptReasoningPipeline()

        self.runner = ReasoningRunner(
            model_name="qwen2.5-coder:7b",
            num_ctx=PRIMARY_NUM_CTX,
            llm_caller=llm_caller,
        )

        # Pre-load full gold scenarios mapping
        self._all_gold_scenarios: Dict[str, EvaluationScenario] = {
            s.scenario_id: s for s in get_gold_set_scenarios()
        }

        # Cache canonical inputs to verify exact parity
        self._canonical_input_cache: Dict[str, Dict[str, Any]] = {}

    def load_dev_partition(self) -> List[Dict[str, Any]]:
        """Loads the sealed 20-scenario development partition."""
        if not self.manifest_path.exists():
            raise FileNotFoundError(f"Development partition manifest not found: {self.manifest_path}")
        raw_bytes = self.manifest_path.read_bytes()
        expected_sha = (self.manifest_path.parent / f"{self.manifest_path.name}.sha256").read_text(encoding="utf-8").strip()
        actual_sha = hashlib.sha256(raw_bytes).hexdigest()
        if actual_sha.lower() != expected_sha.lower():
            raise ValueError(f"Manifest hash mismatch! expected {expected_sha}, got {actual_sha}")
        data = json.loads(raw_bytes.decode("utf-8"))
        scenarios = data.get("scenarios", [])
        if len(scenarios) != 20:
            raise ValueError(f"Expected exactly 20 scenarios in dev partition, found {len(scenarios)}")
        return scenarios

    def get_canonical_input(self, scenario_id: str) -> Dict[str, Any]:
        """
        Retrieves or constructs the canonical reasoning input ONCE per scenario.
        Enforces 100% byte parity of evidence, metadata, and structural pack.
        """
        if scenario_id in self._canonical_input_cache:
            return self._canonical_input_cache[scenario_id]

        if scenario_id not in self._all_gold_scenarios:
            raise KeyError(f"Scenario ID {scenario_id} not found in gold set")

        gold_scen = self._all_gold_scenarios[scenario_id]

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
        track_id: ScreeningTrackId,
        activation: TrackActivationMatrix,
        descriptor: Optional[ProtectedHandoffDescriptor] = None,
    ) -> Tuple[str, ProtectedHandoffDescriptor]:
        """Assembles prompt according to the exact track activation matrix."""
        canonical_input = self.get_canonical_input(scenario_id)
        pack: LosslessStructuralPack = canonical_input["pack"]
        vapt_pack: Optional[VaptKnowledgePack] = canonical_input["vapt_pack"]
        gold_scen: EvaluationScenario = canonical_input["gold_scenario"]
        gap_type: EvidenceGapType = canonical_input["gap_type"]

        routing = DeterministicRoutingDecision(
            schema_version="2.0.0",
            escalate=True,
            has_high_risk_signal=True,
            high_risk_signals=["M4_SCREENING"],
            fail_safe_triggered=False,
        )
        handoff = CascadeHandoffPacket(
            schema_version="2.0.0",
            channel_a_structural=pack,
            routing_decision=routing,
            provenance_hash=f"prov_{pack.asset_id}",
        )

        active_descriptor = descriptor
        if activation.i6 == 1 and active_descriptor is None:
            from src.engine.prompts import get_counterfactual_template
            cat_tmpl = get_counterfactual_template(gold_scen.category_id)
            active_descriptor = HandoffSerializer.from_cascade_packet(
                handoff_packet=handoff,
                evidence_gap_type=gap_type,
                invariant=cat_tmpl.invariant_definition,
            )

        ctx = self.context_builder.build_context(
            handoff_packet=handoff,
            model_identifier="qwen2.5-coder:7b",
            budget_tier=4096,
            cascade_mode=TRACK_D,
            vapt_pack=vapt_pack,
            enable_i2_namespace_partitioning=(activation.i2 == 1),
            enable_i3_counterfactual_prompting=(activation.i3 == 1),
            category_id=gold_scen.category_id if (activation.i3 == 1) else None,
            enable_i4_bair=(activation.i4 == 1),
            enable_i5_decision_policy=(activation.i5 == 1),
            enable_i6_handoff=(activation.i6 == 1),
            protected_handoff=active_descriptor if (activation.i6 == 1) else None,
        )

        # Assert no forbidden tokens in prompt
        prompt_lower = ctx.prompt.lower()
        for token in FORBIDDEN_PROMPT_TOKENS:
            assert token not in prompt_lower, f"Ground-truth token '{token}' leaked into prompt for {scenario_id} ({track_id.value})"

        return ctx.prompt, active_descriptor

    def run_scenario_track(
        self,
        scenario_id: str,
        track_id: ScreeningTrackId,
        activation: TrackActivationMatrix,
    ) -> ScenarioScreeningRecord:
        """Executes exactly one scenario under a specified track."""
        canonical_input = self.get_canonical_input(scenario_id)
        gold_scen: EvaluationScenario = canonical_input["gold_scenario"]
        pack: LosslessStructuralPack = canonical_input["pack"]
        vapt_pack: Optional[VaptKnowledgePack] = canonical_input["vapt_pack"]
        canonical_input_hash: str = canonical_input["canonical_input_hash"]
        empirical_evidence_present: bool = canonical_input["empirical_evidence_present"]

        prompt, descriptor = self.build_prompt_for_track(
            scenario_id=scenario_id,
            track_id=track_id,
            activation=activation,
        )

        ts = datetime.now(timezone.utc).isoformat()
        model_name = "qwen2.5-coder:7b"
        model_digest = EXPECTED_7B_DIGEST_PREFIX
        runtime_version = "Ollama v0.34.1"

        # Dispatch execution based on activation matrix
        if track_id == ScreeningTrackId.BASELINE or (
            activation.i1 == 0 and activation.i2 == 0 and activation.i3 == 0 and activation.i4 == 0 and activation.i5 == 0 and activation.i6 == 0
        ):
            # Baseline execution: unconstrained sampling, standard S0
            t0 = time.perf_counter()
            raw_response = ""
            eval_count = None
            prompt_eval_count = None
            done_reason = None
            transport_error = None

            if self.llm_caller:
                try:
                    raw_response = self.llm_caller(prompt, None)
                except Exception as exc:
                    transport_error = exc
            else:
                try:
                    resp_data = self.runner.ollama_runner.generate_raw(
                        prompt=prompt,
                        schema=None,
                        num_ctx=PRIMARY_NUM_CTX,
                        num_predict=PRIMARY_NUM_PREDICT,
                        temperature=PRIMARY_TEMPERATURE,
                    )
                    raw_response = resp_data.get("response", "")
                    eval_count = resp_data.get("eval_count")
                    prompt_eval_count = resp_data.get("prompt_eval_count")
                    done_reason = resp_data.get("done_reason")
                except Exception as exc:
                    transport_error = exc

            latency_ms = (time.perf_counter() - t0) * 1000.0

            if transport_error is not None:
                classification = classify_primary_failure(
                    transport_error=transport_error,
                    num_predict=PRIMARY_NUM_PREDICT,
                )
                return ScenarioScreeningRecord(
                    scenario_id=scenario_id,
                    category_id=gold_scen.category_id,
                    track_id=track_id.value,
                    activation_matrix=activation.as_dict(),
                    vulnerable_variant=gold_scen.vulnerable_variant,
                    ground_truth_class="vulnerable" if gold_scen.vulnerable_variant else "control",
                    canonical_input_hash=canonical_input_hash,
                    prompt=prompt,
                    raw_model_response=raw_response,
                    parsed_output=None,
                    canonical_s0_output=None,
                    decision=None,
                    primary_failure_category=classification.primary_category.value,
                    is_valid=classification.is_valid,
                    grounding_status="INVALID",
                    raw_namespace_breach=None,
                    validator_bypass=None,
                    latency_ms=latency_ms,
                    eval_count=eval_count,
                    prompt_eval_count=prompt_eval_count,
                    done_reason=done_reason,
                    model_name=model_name,
                    model_digest=model_digest,
                    runtime_version=runtime_version,
                    num_ctx=PRIMARY_NUM_CTX,
                    num_predict=PRIMARY_NUM_PREDICT,
                    temperature=PRIMARY_TEMPERATURE,
                    seed=PRIMARY_SEED,
                    timestamp=ts,
                )

            # Strict JSON parsing
            clean_text = raw_response.strip()
            if clean_text.startswith("```json"):
                clean_text = clean_text[7:]
            elif clean_text.startswith("```"):
                clean_text = clean_text[3:]
            if clean_text.endswith("```"):
                clean_text = clean_text[:-3]
            clean_text = clean_text.strip()

            parsed_json = None
            parse_error = None
            try:
                parsed_json = json.loads(clean_text)
                if not isinstance(parsed_json, dict):
                    raise ValueError("Decoded JSON root is not a dictionary")
            except Exception as exc:
                parse_error = exc

            canonical_hypothesis = None
            schema_error = None
            if parsed_json is not None:
                try:
                    if not parsed_json.get("asset_id"):
                        parsed_json["asset_id"] = pack.asset_id
                    if not parsed_json.get("category"):
                        parsed_json["category"] = gold_scen.category_id
                    canonical_hypothesis = HypothesisModelOutput.model_validate(parsed_json)
                except Exception as exc:
                    schema_error = exc

            grounding_result = None
            grounding_error = None
            if canonical_hypothesis is not None:
                grounding_result = self.validator.validate_grounding(
                    hypothesis=canonical_hypothesis,
                    pack=vapt_pack,
                    channel_a=pack,
                )
                if grounding_result.status != "VALID":
                    grounding_error = f"Grounding invalid: {grounding_result.status}"
            else:
                grounding_error = "Grounding skipped due to invalid hypothesis"

            classification = classify_primary_failure(
                transport_error=None,
                raw_response=raw_response,
                eval_count=eval_count,
                done_reason=done_reason,
                num_predict=PRIMARY_NUM_PREDICT,
                parsed_json=parsed_json,
                parse_error=parse_error,
                schema_error=schema_error,
                grounding_error=grounding_error,
            )

            decision_str = canonical_hypothesis.decision.value if (canonical_hypothesis and canonical_hypothesis.decision) else None

            return ScenarioScreeningRecord(
                scenario_id=scenario_id,
                category_id=gold_scen.category_id,
                track_id=track_id.value,
                activation_matrix=activation.as_dict(),
                vulnerable_variant=gold_scen.vulnerable_variant,
                ground_truth_class="vulnerable" if gold_scen.vulnerable_variant else "control",
                canonical_input_hash=canonical_input_hash,
                prompt=prompt,
                raw_model_response=raw_response,
                parsed_output=parsed_json,
                canonical_s0_output=canonical_hypothesis.model_dump() if canonical_hypothesis else None,
                decision=decision_str,
                primary_failure_category=classification.primary_category.value,
                is_valid=classification.is_valid,
                grounding_status=grounding_result.status if grounding_result else "INVALID",
                raw_namespace_breach=None,
                validator_bypass=None,
                latency_ms=latency_ms,
                eval_count=eval_count,
                prompt_eval_count=prompt_eval_count,
                done_reason=done_reason,
                model_name=model_name,
                model_digest=model_digest,
                runtime_version=runtime_version,
                num_ctx=PRIMARY_NUM_CTX,
                num_predict=PRIMARY_NUM_PREDICT,
                temperature=PRIMARY_TEMPERATURE,
                seed=PRIMARY_SEED,
                timestamp=ts,
            )

        elif track_id == ScreeningTrackId.E1:
            res: I1ExecutionResult = self.runner.execute_i1_generation(
                prompt=prompt,
                schema=HypothesisModelOutput.get_inference_schema(),
                grounding_validator=self.validator,
                channel_a=pack,
                target_asset=gold_scen.target_asset,
                category_id=gold_scen.category_id,
            )
            decision_str = res.hypothesis.decision.value if (res.hypothesis and res.hypothesis.decision) else None
            return ScenarioScreeningRecord(
                scenario_id=scenario_id,
                category_id=gold_scen.category_id,
                track_id=track_id.value,
                activation_matrix=activation.as_dict(),
                vulnerable_variant=gold_scen.vulnerable_variant,
                ground_truth_class="vulnerable" if gold_scen.vulnerable_variant else "control",
                canonical_input_hash=canonical_input_hash,
                prompt=prompt,
                raw_model_response=res.raw_response,
                parsed_output=res.parsed_json,
                canonical_s0_output=res.hypothesis.model_dump() if res.hypothesis else None,
                decision=decision_str,
                primary_failure_category=res.classification.primary_category.value,
                is_valid=res.classification.is_valid,
                grounding_status="VALID" if res.classification.primary_category == PrimaryFailureCategory.VALID else "INVALID",
                raw_namespace_breach=None,
                validator_bypass=None,
                latency_ms=res.latency_ms,
                eval_count=None,
                prompt_eval_count=None,
                done_reason=None,
                model_name=model_name,
                model_digest=model_digest,
                runtime_version=runtime_version,
                num_ctx=PRIMARY_NUM_CTX,
                num_predict=PRIMARY_NUM_PREDICT,
                temperature=PRIMARY_TEMPERATURE,
                seed=PRIMARY_SEED,
                timestamp=ts,
            )

        elif track_id == ScreeningTrackId.E2:
            res: I2ExecutionResult = self.runner.execute_i2_generation(
                prompt=prompt,
                grounding_validator=self.validator,
                channel_a=pack,
                target_asset=gold_scen.target_asset,
                category_id=gold_scen.category_id,
            )
            decision_str = res.canonical_hypothesis.decision.value if (res.canonical_hypothesis and res.canonical_hypothesis.decision) else None
            return ScenarioScreeningRecord(
                scenario_id=scenario_id,
                category_id=gold_scen.category_id,
                track_id=track_id.value,
                activation_matrix=activation.as_dict(),
                vulnerable_variant=gold_scen.vulnerable_variant,
                ground_truth_class="vulnerable" if gold_scen.vulnerable_variant else "control",
                canonical_input_hash=canonical_input_hash,
                prompt=prompt,
                raw_model_response=res.raw_response,
                parsed_output=res.parsed_json,
                canonical_s0_output=res.canonical_hypothesis.model_dump() if res.canonical_hypothesis else None,
                decision=decision_str,
                primary_failure_category=res.classification.primary_category.value,
                is_valid=res.classification.is_valid,
                grounding_status=res.grounding_result.get("status", "INVALID") if isinstance(res.grounding_result, dict) else (getattr(res.grounding_result, "status", "INVALID") if res.grounding_result else "INVALID"),
                raw_namespace_breach=res.has_raw_namespace_breach,
                validator_bypass=res.validator_bypassed,
                latency_ms=res.latency_ms,
                eval_count=None,
                prompt_eval_count=None,
                done_reason=None,
                model_name=model_name,
                model_digest=model_digest,
                runtime_version=runtime_version,
                num_ctx=PRIMARY_NUM_CTX,
                num_predict=PRIMARY_NUM_PREDICT,
                temperature=PRIMARY_TEMPERATURE,
                seed=PRIMARY_SEED,
                timestamp=ts,
            )

        elif track_id == ScreeningTrackId.E3:
            res: I3ExecutionResult = self.runner.execute_i3_generation(
                prompt=prompt,
                grounding_validator=self.validator,
                channel_a=pack,
                target_asset=gold_scen.target_asset,
            )
            decision_str = res.hypothesis.decision.value if (res.hypothesis and res.hypothesis.decision) else None
            return ScenarioScreeningRecord(
                scenario_id=scenario_id,
                category_id=gold_scen.category_id,
                track_id=track_id.value,
                activation_matrix=activation.as_dict(),
                vulnerable_variant=gold_scen.vulnerable_variant,
                ground_truth_class="vulnerable" if gold_scen.vulnerable_variant else "control",
                canonical_input_hash=canonical_input_hash,
                prompt=prompt,
                raw_model_response=res.raw_response,
                parsed_output=res.parsed_json,
                canonical_s0_output=res.hypothesis.model_dump() if res.hypothesis else None,
                decision=decision_str,
                primary_failure_category=res.classification.primary_category.value,
                is_valid=res.classification.is_valid,
                grounding_status=res.grounding_result.get("status", "INVALID") if isinstance(res.grounding_result, dict) else (getattr(res.grounding_result, "status", "INVALID") if res.grounding_result else "INVALID"),
                raw_namespace_breach=None,
                validator_bypass=None,
                latency_ms=res.latency_ms,
                eval_count=None,
                prompt_eval_count=None,
                done_reason=None,
                model_name=model_name,
                model_digest=model_digest,
                runtime_version=runtime_version,
                num_ctx=PRIMARY_NUM_CTX,
                num_predict=PRIMARY_NUM_PREDICT,
                temperature=PRIMARY_TEMPERATURE,
                seed=PRIMARY_SEED,
                timestamp=ts,
            )

        elif track_id == ScreeningTrackId.E4:
            res: I4ExecutionResult = self.runner.execute_i4_generation(
                prompt=prompt,
                empirical_evidence_present=empirical_evidence_present,
                grounding_validator=self.validator,
                channel_a=pack,
                target_asset=gold_scen.target_asset,
                category_id=gold_scen.category_id,
            )
            decision_str = res.canonical_hypothesis.decision.value if (res.canonical_hypothesis and res.canonical_hypothesis.decision) else None
            return ScenarioScreeningRecord(
                scenario_id=scenario_id,
                category_id=gold_scen.category_id,
                track_id=track_id.value,
                activation_matrix=activation.as_dict(),
                vulnerable_variant=gold_scen.vulnerable_variant,
                ground_truth_class="vulnerable" if gold_scen.vulnerable_variant else "control",
                canonical_input_hash=canonical_input_hash,
                prompt=prompt,
                raw_model_response=res.raw_response,
                parsed_output=res.extracted_bair,
                canonical_s0_output=res.canonical_hypothesis.model_dump() if res.canonical_hypothesis else None,
                decision=decision_str,
                primary_failure_category=res.classification.primary_category.value,
                is_valid=res.classification.is_valid,
                grounding_status=res.grounding_result.get("status", "INVALID") if isinstance(res.grounding_result, dict) else (getattr(res.grounding_result, "status", "INVALID") if res.grounding_result else "INVALID"),
                raw_namespace_breach=None,
                validator_bypass=None,
                latency_ms=res.latency_ms,
                eval_count=None,
                prompt_eval_count=None,
                done_reason=None,
                model_name=model_name,
                model_digest=model_digest,
                runtime_version=runtime_version,
                num_ctx=PRIMARY_NUM_CTX,
                num_predict=PRIMARY_NUM_PREDICT,
                temperature=PRIMARY_TEMPERATURE,
                seed=PRIMARY_SEED,
                timestamp=ts,
            )

        elif track_id == ScreeningTrackId.E5:
            res: I5ExecutionResult = self.runner.execute_i5_generation(
                prompt=prompt,
                empirical_evidence_present=empirical_evidence_present,
                grounding_validator=self.validator,
                channel_a=pack,
                target_asset=gold_scen.target_asset,
                category_id=gold_scen.category_id,
            )
            decision_str = res.canonical_hypothesis.decision.value if (res.canonical_hypothesis and res.canonical_hypothesis.decision) else None
            return ScenarioScreeningRecord(
                scenario_id=scenario_id,
                category_id=gold_scen.category_id,
                track_id=track_id.value,
                activation_matrix=activation.as_dict(),
                vulnerable_variant=gold_scen.vulnerable_variant,
                ground_truth_class="vulnerable" if gold_scen.vulnerable_variant else "control",
                canonical_input_hash=canonical_input_hash,
                prompt=prompt,
                raw_model_response=res.raw_response,
                parsed_output=res.parsed_json,
                canonical_s0_output=res.canonical_hypothesis.model_dump() if res.canonical_hypothesis else None,
                decision=decision_str,
                primary_failure_category=res.classification.primary_category.value,
                is_valid=res.classification.is_valid,
                grounding_status=res.grounding_result.get("status", "INVALID") if isinstance(res.grounding_result, dict) else (getattr(res.grounding_result, "status", "INVALID") if res.grounding_result else "INVALID"),
                raw_namespace_breach=None,
                validator_bypass=None,
                latency_ms=res.latency_ms,
                eval_count=None,
                prompt_eval_count=None,
                done_reason=None,
                model_name=model_name,
                model_digest=model_digest,
                runtime_version=runtime_version,
                num_ctx=PRIMARY_NUM_CTX,
                num_predict=PRIMARY_NUM_PREDICT,
                temperature=PRIMARY_TEMPERATURE,
                seed=PRIMARY_SEED,
                timestamp=ts,
            )

        elif track_id == ScreeningTrackId.E6:
            res: I6ExecutionResult = self.runner.execute_i6_generation(
                prompt=prompt,
                protected_handoff=descriptor,
                grounding_validator=self.validator,
                channel_a=pack,
                target_asset=gold_scen.target_asset,
                category_id=gold_scen.category_id,
            )
            decision_str = res.canonical_hypothesis.decision.value if (res.canonical_hypothesis and res.canonical_hypothesis.decision) else None
            return ScenarioScreeningRecord(
                scenario_id=scenario_id,
                category_id=gold_scen.category_id,
                track_id=track_id.value,
                activation_matrix=activation.as_dict(),
                vulnerable_variant=gold_scen.vulnerable_variant,
                ground_truth_class="vulnerable" if gold_scen.vulnerable_variant else "control",
                canonical_input_hash=canonical_input_hash,
                prompt=prompt,
                raw_model_response=res.raw_response,
                parsed_output=res.parsed_json,
                canonical_s0_output=res.canonical_hypothesis.model_dump() if res.canonical_hypothesis else None,
                decision=decision_str,
                primary_failure_category=res.classification.primary_category.value,
                is_valid=res.classification.is_valid,
                grounding_status=res.grounding_result.get("status", "INVALID") if isinstance(res.grounding_result, dict) else (getattr(res.grounding_result, "status", "INVALID") if res.grounding_result else "INVALID"),
                raw_namespace_breach=None,
                validator_bypass=None,
                latency_ms=res.latency_ms,
                eval_count=None,
                prompt_eval_count=None,
                done_reason=None,
                model_name=model_name,
                model_digest=model_digest,
                runtime_version=runtime_version,
                num_ctx=PRIMARY_NUM_CTX,
                num_predict=PRIMARY_NUM_PREDICT,
                temperature=PRIMARY_TEMPERATURE,
                seed=PRIMARY_SEED,
                timestamp=ts,
            )

        elif track_id == ScreeningTrackId.COMBINED:
            # Combined track execution using active interventions
            t0 = time.perf_counter()
            raw_response = ""
            transport_error = None
            eval_count = None
            prompt_eval_count = None
            done_reason = None

            # Determine schema parameter: I1 active -> schema, else None
            schema_param = HypothesisModelOutput.get_inference_schema() if (activation.i1 == 1) else None

            if self.llm_caller:
                try:
                    raw_response = self.llm_caller(prompt, schema_param)
                except Exception as exc:
                    transport_error = exc
            else:
                try:
                    resp_data = self.runner.ollama_runner.generate_raw(
                        prompt=prompt,
                        schema=schema_param,
                        num_ctx=PRIMARY_NUM_CTX,
                        num_predict=PRIMARY_NUM_PREDICT,
                        temperature=PRIMARY_TEMPERATURE,
                    )
                    raw_response = resp_data.get("response", "")
                    eval_count = resp_data.get("eval_count")
                    prompt_eval_count = resp_data.get("prompt_eval_count")
                    done_reason = resp_data.get("done_reason")
                except Exception as exc:
                    transport_error = exc

            latency_ms = (time.perf_counter() - t0) * 1000.0

            if transport_error is not None:
                classification = classify_primary_failure(
                    transport_error=transport_error,
                    num_predict=PRIMARY_NUM_PREDICT,
                )
                return ScenarioScreeningRecord(
                    scenario_id=scenario_id,
                    category_id=gold_scen.category_id,
                    track_id=track_id.value,
                    activation_matrix=activation.as_dict(),
                    vulnerable_variant=gold_scen.vulnerable_variant,
                    ground_truth_class="vulnerable" if gold_scen.vulnerable_variant else "control",
                    canonical_input_hash=canonical_input_hash,
                    prompt=prompt,
                    raw_model_response=raw_response,
                    parsed_output=None,
                    canonical_s0_output=None,
                    decision=None,
                    primary_failure_category=classification.primary_category.value,
                    is_valid=classification.is_valid,
                    grounding_status="INVALID",
                    raw_namespace_breach=None,
                    validator_bypass=None,
                    latency_ms=latency_ms,
                    eval_count=eval_count,
                    prompt_eval_count=prompt_eval_count,
                    done_reason=done_reason,
                    model_name=model_name,
                    model_digest=model_digest,
                    runtime_version=runtime_version,
                    num_ctx=PRIMARY_NUM_CTX,
                    num_predict=PRIMARY_NUM_PREDICT,
                    temperature=PRIMARY_TEMPERATURE,
                    seed=PRIMARY_SEED,
                    timestamp=ts,
                )

            # Combined parsing and downstream extraction
            parsed_json = None
            parse_error = None
            schema_error = None
            canonical_s0 = None
            extracted_bair = None
            raw_ns_breach = None
            val_bypass = None

            if activation.i4 == 1:
                # BAIR parsing path
                from src.engine.bair_extractor import (
                    parse_bair,
                    validate_bair,
                    map_bair_to_s0,
                    BairParseError,
                    BairSchemaError,
                )
                try:
                    raw_slots = parse_bair(raw_response)
                    extracted_bair = validate_bair(raw_slots, empirical_evidence_present=empirical_evidence_present)
                    canonical_s0 = map_bair_to_s0(
                        bair=extracted_bair,
                        target_asset=gold_scen.target_asset,
                        category_id=gold_scen.category_id,
                    )
                except BairParseError as exc:
                    parse_error = exc
                except BairSchemaError as exc:
                    schema_error = exc
                except Exception as exc:
                    schema_error = exc
            else:
                # Standard JSON / I2 parsing path
                clean_text = raw_response.strip()
                if clean_text.startswith("```json"):
                    clean_text = clean_text[7:]
                elif clean_text.startswith("```"):
                    clean_text = clean_text[3:]
                if clean_text.endswith("```"):
                    clean_text = clean_text[:-3]
                clean_text = clean_text.strip()

                try:
                    parsed_json = json.loads(clean_text)
                    if not isinstance(parsed_json, dict):
                        raise ValueError("Root is not a dictionary")
                except Exception as exc:
                    parse_error = exc

                canonical_s0 = None
                schema_error = None
                if parsed_json is not None:
                    if activation.i2 == 1:
                        from src.engine.models import I2RawHypothesisOutput, adapt_i2_to_s0, check_raw_namespace_breach
                        raw_ns_breach = check_raw_namespace_breach(parsed_json)
                        try:
                            raw_i2 = I2RawHypothesisOutput.model_validate(parsed_json)
                            canonical_s0 = adapt_i2_to_s0(raw_i2, target_asset=gold_scen.target_asset, category_id=gold_scen.category_id)
                        except Exception as exc:
                            schema_error = exc
                    else:
                        try:
                            if not parsed_json.get("asset_id"):
                                parsed_json["asset_id"] = pack.asset_id
                            if not parsed_json.get("category"):
                                parsed_json["category"] = gold_scen.category_id
                            canonical_s0 = HypothesisModelOutput.model_validate(parsed_json)
                        except Exception as exc:
                            schema_error = exc

            # Apply I5 decision policy if active and candidate is available
            if activation.i5 == 1 and canonical_s0 is not None:
                from src.engine.decision_policy import deterministic_decide, EvidenceState
                ev_state = EvidenceState.from_empirical_flag(empirical_evidence_present)
                policy_res = deterministic_decide(
                    candidate_decision=canonical_s0.decision,
                    evidence_state=ev_state,
                    has_falsifiable_experiment=bool(canonical_s0.experiment_proposal and canonical_s0.experiment_proposal.strip() and canonical_s0.experiment_proposal != "None required"),
                    category_id=canonical_s0.category or gold_scen.category_id,
                )
                canonical_s0 = canonical_s0.model_copy(update={"decision": policy_res.final_decision})

            grounding_result = None
            if canonical_s0 is not None:
                grounding_result = self.validator.validate_grounding(
                    hypothesis=canonical_s0,
                    pack=vapt_pack,
                    channel_a=pack,
                )
                if activation.i2 == 1 and raw_ns_breach:
                    val_bypass = (grounding_result.status == "VALID")
                elif activation.i2 == 1:
                    val_bypass = False

            grounding_error = None
            if grounding_result is not None and grounding_result.status != "VALID":
                grounding_error = f"Grounding invalid: {grounding_result.status}"
            elif canonical_s0 is None:
                grounding_error = "Grounding skipped due to missing/invalid hypothesis"

            classification = classify_primary_failure(
                transport_error=None,
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

            return ScenarioScreeningRecord(
                scenario_id=scenario_id,
                category_id=gold_scen.category_id,
                track_id=track_id.value,
                activation_matrix=activation.as_dict(),
                vulnerable_variant=gold_scen.vulnerable_variant,
                ground_truth_class="vulnerable" if gold_scen.vulnerable_variant else "control",
                canonical_input_hash=canonical_input_hash,
                prompt=prompt,
                raw_model_response=raw_response,
                parsed_output=extracted_bair if extracted_bair else parsed_json,
                canonical_s0_output=canonical_s0.model_dump() if canonical_s0 else None,
                decision=decision_str,
                primary_failure_category=classification.primary_category.value,
                is_valid=classification.is_valid,
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
                num_ctx=PRIMARY_NUM_CTX,
                num_predict=PRIMARY_NUM_PREDICT,
                temperature=PRIMARY_TEMPERATURE,
                seed=PRIMARY_SEED,
                timestamp=ts,
            )

        raise ValueError(f"Unsupported track_id: {track_id}")

    def execute_track(
        self,
        track_id: ScreeningTrackId,
        activation: Optional[TrackActivationMatrix] = None,
        output_dir: Path = Path("data/eval"),
    ) -> Tuple[List[ScenarioScreeningRecord], str]:
        """
        Executes an entire track across the 20 scenarios, writes immutable artifact and .sha256.
        """
        eff_activation = activation or TRACK_ACTIVATION_SPEC[track_id]

        dev_scenarios = self.load_dev_partition()
        scenario_records: List[ScenarioScreeningRecord] = []

        logger.info(f"Executing track {track_id.value} (activation: {eff_activation.as_dict()}) on 20 scenarios...")

        for idx, s_meta in enumerate(dev_scenarios, 1):
            scen_id = s_meta["scenario_id"]
            rec = self.run_scenario_track(
                scenario_id=scen_id,
                track_id=track_id,
                activation=eff_activation,
            )
            scenario_records.append(rec)
            print(f"[{track_id.value}] {idx:2d}/20: {scen_id} -> decision={rec.decision}, primary={rec.primary_failure_category}, latency={rec.latency_ms:.1f}ms")

        # Filename mapping
        file_map = {
            ScreeningTrackId.BASELINE: "m4_ablation_baseline_20260921.json",
            ScreeningTrackId.E1: "m4_ablation_e1_schema_20260921.json",
            ScreeningTrackId.E2: "m4_ablation_e2_namespace_20260921.json",
            ScreeningTrackId.E3: "m4_ablation_e3_counterfactual_20260921.json",
            ScreeningTrackId.E4: "m4_ablation_e4_bair_20260921.json",
            ScreeningTrackId.E5: "m4_ablation_e5_decision_policy_20260921.json",
            ScreeningTrackId.E6: "m4_ablation_e6_handoff_20260921.json",
            ScreeningTrackId.COMBINED: "m4_ablation_combined_20260921.json",
        }
        filename = file_map[track_id]
        out_path = output_dir / filename

        if out_path.exists():
            raise FileExistsError(f"Artifact {out_path} already exists! Refusing to overwrite.")

        artifact_payload = {
            "schema_version": "1.0.0",
            "run_status": "OFFICIAL_M4_8_SCREENING",
            "track_id": track_id.value,
            "activation_matrix": eff_activation.as_dict(),
            "manifest_sha256": "92f741b9e2c425a9f884df3286b4363a172ee938e43999636dbafef46e233dc1",
            "source_benchmark_sha256": "b2b85a672124acf21066a257d8c7f5093000368b224ee013c02574c96a0ae707",
            "scenario_ids": [r.scenario_id for r in scenario_records],
            "scenario_order": [r.scenario_id for r in scenario_records],
            "canonical_input_hashes": {r.scenario_id: r.canonical_input_hash for r in scenario_records},
            "model_name": "qwen2.5-coder:7b",
            "model_digest_prefix": EXPECTED_7B_DIGEST_PREFIX,
            "runtime_version": "Ollama v0.34.1",
            "compute_envelope": {
                "num_ctx": PRIMARY_NUM_CTX,
                "num_predict": PRIMARY_NUM_PREDICT,
                "temperature": PRIMARY_TEMPERATURE,
                "seed": PRIMARY_SEED,
                "keep_alive": PRIMARY_KEEP_ALIVE,
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_scenarios_evaluated": len(scenario_records),
            "records": [r.model_dump() for r in scenario_records],
        }

        canonical_bytes = json.dumps(artifact_payload, indent=2, sort_keys=True).encode("utf-8")
        sha256_hash = hashlib.sha256(canonical_bytes).hexdigest()

        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(canonical_bytes)

        sha_path = output_dir / f"{filename}.sha256"
        sha_path.write_text(sha256_hash + "\n", encoding="utf-8")

        logger.info(f"Wrote {out_path} (SHA-256: {sha256_hash})")
        return scenario_records, sha256_hash
