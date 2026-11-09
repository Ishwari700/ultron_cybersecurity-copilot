"""Milestone M3 4-Track Ablation Harness.

Implements M3 Phase M3.15:
- Track A: 7B Baseline (No Target Evidence, No VAPT)
- Track B: 7B + Target-Evidence RAG
- Track C: 7B + VAPT Knowledge RAG (Diagnostic)
- Track D: 7B + Dual RAG (Primary Causal Test: B -> D)
- Track E: Optional Cascade (3B Triage -> Router -> 7B Deep)

Enforces strict causal parity:
TargetEvidencePayload(B) == TargetEvidencePayload(D) (byte-for-byte identical).
"""

from enum import Enum
import hashlib
import json
from pathlib import Path
import re
import time
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from src.engine.context_builder import ContextBudgetOverflowError, M3Track, ReasoningContextBuilder
from src.engine.models import (
    HypothesisDecision,
    HypothesisModelOutput,
    ReasoningHypothesis,
)
from src.evidence.cascade_models import LosslessStructuralPack
from src.knowledge.models import EvidenceGapType
from src.engine.runner import ReasoningRunner
from src.eval.scenarios import BudgetTier, EvaluationScenario
from src.knowledge.grounding_validator import KnowledgeGroundingResult, KnowledgeGroundingValidator
from src.knowledge.pipeline import VaptReasoningPipeline
from src.knowledge.retriever import OnnxVectorFts5Retriever


class CausalParityViolationError(RuntimeError):
    """Raised when Track B and Track D Target-Evidence payloads differ."""
    pass


class M3ScenarioExecutionResult(BaseModel):
    """Execution telemetry and validation output for a single scenario run under an M3 track."""
    scenario_id: str
    track: str
    prompt: str
    target_evidence_bytes: bytes
    raw_model_output: str
    hypothesis_output: Optional[ReasoningHypothesis] = None
    grounding_status: str = "VALID"
    cited_methodology_chunk_ids: List[str] = Field(default_factory=list)
    supporting_evidence_ids: List[str] = Field(default_factory=list)
    latency_ms: float = 0.0
    vapt_retrieval_metadata: Optional[Dict[str, Any]] = None


class M3PairedResult(BaseModel):
    """Paired evaluation of Track B and Track D on the identical scenario."""
    scenario_id: str
    result_b: M3ScenarioExecutionResult
    result_d: M3ScenarioExecutionResult
    parity_verified: bool
    decision_flipped: bool
    flip_type: Optional[str] = None  # e.g., "K_FP", "K_FN", "OTHER_FLIP", None


class M3AblationHarness:
    """
    Executes scenarios under M3 ablation tracks and enforces causal parity.
    """

    def __init__(
        self,
        retriever: Optional[Any] = None,
        pipeline: Optional[VaptReasoningPipeline] = None,
        context_builder: Optional[ReasoningContextBuilder] = None,
        grounding_validator: Optional[KnowledgeGroundingValidator] = None,
        live_mode: bool = False,
        runner_7b: Optional[ReasoningRunner] = None,
        runner_3b: Optional[ReasoningRunner] = None,
    ) -> None:
        self.live_mode = live_mode
        self.context_builder = context_builder or ReasoningContextBuilder()
        self.validator = grounding_validator or KnowledgeGroundingValidator()

        if pipeline is not None:
            self.pipeline = pipeline
        else:
            self.pipeline = VaptReasoningPipeline(retriever=retriever)

        if self.live_mode:
            self.runner_7b = runner_7b or ReasoningRunner(model_name="qwen2.5-coder:7b")
            self.runner_3b = runner_3b or ReasoningRunner(model_name="qwen2.5-coder:3b")
        else:
            self.runner_7b = runner_7b
            self.runner_3b = runner_3b

    @staticmethod
    def extract_target_evidence_bytes(prompt: str) -> bytes:
        """Extract canonical <untrusted_target_data> bytes from assembled prompt."""
        match = re.search(r"<untrusted_target_data>(.*?)</untrusted_target_data>", prompt, re.DOTALL)
        if not match:
            return b""
        return match.group(1).strip().encode("utf-8")

    def _build_structural_pack(self, scenario: EvaluationScenario) -> LosslessStructuralPack:
        """Build standard LosslessStructuralPack from an EvaluationScenario."""
        asset_info = scenario.target_asset or {}
        raw_sample = ""
        observed_facts = []
        if scenario.initial_evidence:
            raw_sample = str(scenario.initial_evidence[0].get("statement", ""))
            observed_facts = scenario.initial_evidence
        else:
            observed_facts = [{"fact_id": "FACT-00000001", "statement": "Neutral observable target evidence."}]

        return LosslessStructuralPack(
            schema_version="2.0.0",
            asset_id=asset_info.get("asset_id", f"ASSET-{scenario.scenario_id}"),
            endpoint_id=f"EP-{scenario.scenario_id}",
            route_template=asset_info.get("normalized_path", asset_info.get("raw_path", "/api/v1/resource")),
            http_method=asset_info.get("method", "GET"),
            application_mutability=asset_info.get("application_mutability", "READ_ONLY"),
            has_privilege_level_delta=scenario.ground_truth_vulnerable,
            has_cross_identity_object_access_success=scenario.ground_truth_vulnerable,
            observed_facts=observed_facts,
            raw_body_sample=raw_sample,
        )

    def _infer_evidence_gap(self, scenario: EvaluationScenario) -> EvidenceGapType:
        """Derive closed-set EvidenceGapType enum from scenario attributes."""
        cat = scenario.category_id.upper()
        if "BOLA" in cat or "CROSS-TENANT" in cat:
            return EvidenceGapType.MISSING_CROSS_IDENTITY_OBJECT_VERIFICATION
        elif "STATE" in cat or "WORKFLOW" in cat or "LIFECYCLE" in cat or "MUTATION" in cat:
            return EvidenceGapType.MISSING_MUTATION_STATE_BOUNDARY
        elif "AUTH" in cat or "ROLE" in cat or "BFLA" in cat:
            return EvidenceGapType.MISSING_ROLE_HIERARCHY_ENFORCEMENT
        elif "NONE" in cat:
            return EvidenceGapType.MISSING_UNAUTHENTICATED_ACCESS_CHECK
        return EvidenceGapType.MISSING_CROSS_IDENTITY_OBJECT_VERIFICATION

    def run_scenario(
        self,
        scenario: EvaluationScenario,
        track: M3Track,
        budget_tier: str = "TIER_1",
    ) -> M3ScenarioExecutionResult:
        """Executes a scenario under a specific M3 track."""
        pack = self._build_structural_pack(scenario)
        gap = self._infer_evidence_gap(scenario)

        t0 = time.perf_counter()

        cascade_mode = track.value if hasattr(track, "value") else str(track)
        prompt, vapt_pack, telemetry = self.pipeline.assemble_prompt(
            channel_a=pack,
            gap_type=gap,
            cascade_mode=cascade_mode,
        )

        vapt_meta = None
        cited_chks = []
        if vapt_pack and getattr(vapt_pack, "items", None):
            cited_chks = [item.chunk.chunk_id for item in vapt_pack.items if hasattr(item, "chunk") and hasattr(item.chunk, "chunk_id")]
            vapt_meta = {
                "selected_chunk_ids": cited_chks,
                "manifest_merkle_root": getattr(vapt_pack, "manifest_merkle_root", None),
                "telemetry": telemetry,
            }

        ev_bytes = self.extract_target_evidence_bytes(prompt)

        # Execute model or hermetic simulation
        if self.live_mode and self.runner_7b:
            raw_response = self.runner_7b.call_ollama(prompt)
            # Parse response
            try:
                hypothesis = HypothesisModelOutput.model_validate_json(raw_response)
            except Exception:
                try:
                    data = json.loads(raw_response)
                    if not data.get("asset_id"):
                        data["asset_id"] = pack.asset_id
                    if not data.get("category"):
                        data["category"] = scenario.category_id
                    hypothesis = HypothesisModelOutput.model_validate(data)
                except Exception:
                    hypothesis = None

        else:
            # Hermetic mode: deterministic response
            if scenario.ground_truth_vulnerable:
                decision = HypothesisDecision.HYPOTHESIS
                fact_ids = [f.get("fact_id") for f in pack.observed_facts if isinstance(f, dict) and f.get("fact_id")]
                fact_cites = fact_ids[:1] if fact_ids else ["FACT-00000001"]
                chk_cites = cited_chks[:1] if cited_chks else []
                summary = f"Identified potential vulnerability in {scenario.name}."
            else:
                decision = HypothesisDecision.INSUFFICIENT_EVIDENCE
                fact_cites = []
                chk_cites = []
                summary = f"No evidence of vulnerability found for {scenario.name}."

            hypothesis = ReasoningHypothesis(
                decision=decision,
                category=scenario.category_id,
                asset_id=pack.asset_id,
                reasoning_summary=summary,
                supporting_evidence_ids=fact_cites,
                cited_methodology_chunk_ids=chk_cites,
            )
            raw_response = hypothesis.model_dump_json()

        latency = (time.perf_counter() - t0) * 1000.0

        # Validate grounding
        grounding_status = "VALID"
        if hypothesis:
            val_res = self.validator.validate_grounding(
                hypothesis=hypothesis,
                pack=vapt_pack,
                channel_a=pack,
            )
            if not val_res.valid:
                grounding_status = "INVALID"

        return M3ScenarioExecutionResult(
            scenario_id=scenario.scenario_id,
            track=track.value,
            prompt=prompt,
            target_evidence_bytes=ev_bytes,
            raw_model_output=raw_response,
            hypothesis_output=hypothesis,
            grounding_status=grounding_status,
            cited_methodology_chunk_ids=hypothesis.cited_methodology_chunk_ids if hypothesis else [],
            supporting_evidence_ids=hypothesis.supporting_evidence_ids if hypothesis else [],
            latency_ms=latency,
            vapt_retrieval_metadata=vapt_meta,
        )

    def run_paired_b_d(
        self,
        scenario: EvaluationScenario,
        budget_tier: str = "TIER_1",
    ) -> M3PairedResult:
        """
        Executes paired Track B and Track D evaluation and strictly validates
        Target-Evidence payload byte-identity.
        """
        res_b = self.run_scenario(scenario, track=M3Track.TRACK_B, budget_tier=budget_tier)
        res_d = self.run_scenario(scenario, track=M3Track.TRACK_D, budget_tier=budget_tier)

        # Causal Parity Check
        if res_b.target_evidence_bytes != res_d.target_evidence_bytes:
            raise CausalParityViolationError(
                f"Causal parity failure on scenario {scenario.scenario_id}!\n"
                f"Track B bytes ({len(res_b.target_evidence_bytes)}): {res_b.target_evidence_bytes[:100]}...\n"
                f"Track D bytes ({len(res_d.target_evidence_bytes)}): {res_d.target_evidence_bytes[:100]}..."
            )

        dec_b = res_b.hypothesis_output.decision if res_b.hypothesis_output else None
        dec_d = res_d.hypothesis_output.decision if res_d.hypothesis_output else None
        flipped = (dec_b != dec_d)

        flip_type = None
        if flipped:
            # Check for K_FP or K_FN
            if not scenario.ground_truth_vulnerable and dec_b == HypothesisDecision.INSUFFICIENT_EVIDENCE and dec_d == HypothesisDecision.HYPOTHESIS:
                flip_type = "K_FP"
            elif scenario.ground_truth_vulnerable and dec_b == HypothesisDecision.HYPOTHESIS and dec_d == HypothesisDecision.INSUFFICIENT_EVIDENCE:
                flip_type = "K_FN"
            else:
                flip_type = "OTHER_FLIP"

        return M3PairedResult(
            scenario_id=scenario.scenario_id,
            result_b=res_b,
            result_d=res_d,
            parity_verified=True,
            decision_flipped=flipped,
            flip_type=flip_type,
        )
