"""
Milestone M5 Phase 6.7 — Typed Protocol Live Viability Smoke Harness.

Executes a pre-registered 24-call live smoke evaluation:
  3 scenarios x 4 tracks x 2 I1 conditions
against local Ollama qwen2.5-coder:7b under the newly implemented Typed Outcome Predicate protocol.

Strict Single-Call Rule:
- exactly 1 LLM call per scenario/track/condition (24 calls total)
- zero retries
- zero alternate prompts
- zero parser repair
- zero semantic rewriting
- fail-closed classification on any failure

Artifacts created:
- data/eval/m5_typed_protocol_live_smoke.json
- data/eval/m5_typed_protocol_live_smoke.json.sha256
- docs/M5_PHASE6_7_TYPED_PROTOCOL_LIVE_SMOKE_REPORT.md
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
    EXPECTED_PLANNING_FREEZE_COMMIT,
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

EXPECTED_M4_9_SHA = "459b9ec63c3a2dc760abde12ec196760f7e505fbab5317f0da0c46b32c5eaac7"
EXPECTED_PHASE6_SMOKE_SHA = "7ee8b6b2ec33eca0fcb8a3f0948d1f36b7e41877354ae4a64190f8e19c679b5e"
EXPECTED_PHASE6_2_SMOKE_SHA = "830c225b22f6767ee13b4ce3b443a14aede3ea767ee25ae7343c1a153c4a0818"
EXPECTED_OLLAMA_VERSION = "0.34.1"

# Pre-registered 3 representative scenarios (Phase 6B / 6.2 / 6.7)
PRE_REGISTERED_SCENARIOS = [
    # 1. Vulnerable access control (BOLA)
    "SCEN-SAAS_BILLING-INV-DETAILS-VULN-01",
    # 2. Vulnerable state/business logic
    "SCEN-ECOMMERCE_ORDERS-ORD-REFUND-VULN-01",
    # 3. Negative-control scenario (patched BOLA)
    "SCEN-SAAS_BILLING-INV-DETAILS-PATCH-01",
]

PRE_REGISTERED_TRACKS = [
    ConfirmatoryTrackId.TRACK_A,
    ConfirmatoryTrackId.TRACK_B,
    ConfirmatoryTrackId.TRACK_C,
    ConfirmatoryTrackId.TRACK_D,
]

PRE_REGISTERED_I1_CONDITIONS = [
    False,  # CONDITION 0: I1=0, schema=None
    True,   # CONDITION 1: I1=1, schema=BairJsonObject.get_inference_schema()
]


def hash_file(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest().lower()


class Phase67CallRecord(BaseModel):
    call_index: int
    scenario_id: str
    track_id: str
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
    typed_experiment_fields: Dict[str, Any]
    grounding_result: Optional[Dict[str, Any]] = None
    ExperimentPolarityValidator_result: Optional[Dict[str, Any]] = None
    candidate_decision: Optional[str] = None
    final_deterministic_decision: Optional[str] = None
    canonical_s0_output: Optional[Dict[str, Any]] = None
    timestamp: str


def run_pre_smoke_freeze_checks() -> Dict[str, Any]:
    print("=== [PHASE 6.7] PRE-SMOKE FREEZE VERIFICATION ===")

    # 1. Verify tracked files diff
    tracked_diff = subprocess.check_output(["git", "diff", "--name-only"], text=True).strip()
    assert tracked_diff == "", f"Git tracked files have unstaged modifications:\n{tracked_diff}"
    print("1. Git tracked files: CLEAN [PASS]")

    # 2. M4 planning freeze
    tag_commit = subprocess.check_output(
        ["git", "rev-parse", "m4-v1.1.0-planning-freeze^{commit}"], text=True
    ).strip()
    assert tag_commit == EXPECTED_PLANNING_FREEZE_COMMIT, f"Planning freeze mismatch: {tag_commit}"
    plan_diff = subprocess.check_output(
        ["git", "diff", "m4-v1.1.0-planning-freeze", "--", "docs/M4_REASONING_ENGINE_PLAN.md"],
        text=True,
    ).strip()
    assert plan_diff == "", "docs/M4_REASONING_ENGINE_PLAN.md differs from planning freeze tag!"
    print(f"2. M4 planning freeze commit: {tag_commit} [PASS]")

    # 3. M4.9 SHA
    m4_9_path = Path("data/eval/m4_live_llm_benchmark_final.json")
    assert m4_9_path.exists(), "M4.9 result file missing!"
    m4_9_sha = hash_file(m4_9_path)
    assert m4_9_sha == EXPECTED_M4_9_SHA, f"M4.9 SHA mismatch! Expected {EXPECTED_M4_9_SHA}, got {m4_9_sha}"
    print(f"3. M4.9 benchmark SHA: {m4_9_sha} [PASS]")

    # 4. Source benchmark manifest hash
    bm_sha = hash_file(Path("data/benchmarks/m1_5_frozen_manifest.json"))
    assert bm_sha == EXPECTED_BENCHMARK_HASH, f"Benchmark manifest hash mismatch: {bm_sha}"
    print(f"4. Benchmark manifest SHA: {bm_sha} [PASS]")

    # 5. Verify protected files
    subprocess.check_output(
        [
            "git",
            "diff",
            "--exit-code",
            "docs/M4_REASONING_ENGINE_PLAN.md",
            "src/retrieval/hybrid.py",
            "data/eval/m3_live_llm_benchmark_20260920.json",
            "src/eval/scenarios.py",
        ],
        text=True,
    )
    print("5. Protected files: CLEAN (0 diff) [PASS]")

    # 6. Verify Phase 6 and Phase 6.2 artifacts match pinned SHAs; Phase 6.7 artifact does not exist
    phase6_out = Path("data/eval/m5_live_smoke.json")
    assert phase6_out.exists(), f"Phase 6 artifact {phase6_out} missing!"
    p6_sha = hash_file(phase6_out)
    assert p6_sha == EXPECTED_PHASE6_SMOKE_SHA, f"Phase 6 artifact SHA altered: {p6_sha}"
    print(f"6a. Phase 6 smoke artifact: Pinned SHA verified ({p6_sha}) [PASS]")

    phase6_2_out = Path("data/eval/m5_live_smoke_v2.json")
    assert phase6_2_out.exists(), f"Phase 6.2 artifact {phase6_2_out} missing!"
    p6_2_sha = hash_file(phase6_2_out)
    assert p6_2_sha == EXPECTED_PHASE6_2_SMOKE_SHA, f"Phase 6.2 artifact SHA altered: {p6_2_sha}"
    print(f"6b. Phase 6.2 smoke artifact: Pinned SHA verified ({p6_2_sha}) [PASS]")

    smoke_out = Path("data/eval/m5_typed_protocol_live_smoke.json")
    if smoke_out.exists() or Path(str(smoke_out) + ".sha256").exists():
        raise FileExistsError(f"Phase 6.7 smoke artifact {smoke_out} already exists! Refusing to overwrite.")
    print("6c. Phase 6.7 smoke output file: Absent, ready for creation [PASS]")

    # 7 & 8. Check Ollama model and digest
    with httpx.Client(timeout=5.0) as client:
        tags_res = client.get("http://127.0.0.1:11434/api/tags")
        assert tags_res.status_code == 200, f"Ollama /api/tags returned {tags_res.status_code}"
        models = tags_res.json().get("models", [])
        matched_model = [m for m in models if m.get("name") == "qwen2.5-coder:7b" or m.get("model") == "qwen2.5-coder:7b"]
        assert len(matched_model) > 0, "Model qwen2.5-coder:7b not found in Ollama!"
        full_digest = matched_model[0].get("digest", "")
        assert full_digest == EXPECTED_7B_DIGEST_FULL, f"Model digest mismatch: {full_digest} != {EXPECTED_7B_DIGEST_FULL}"
    print(f"7. Ollama model: qwen2.5-coder:7b [PASS]")
    print(f"8. Pinned digest: {full_digest} [PASS]")

    # 9. Check Ollama version
    ver_out = subprocess.check_output(["ollama", "--version"], text=True).strip()
    assert EXPECTED_OLLAMA_VERSION in ver_out, f"Ollama version mismatch: {ver_out}"
    print(f"9. Ollama runtime: {ver_out} [PASS]")

    # 10. Primary parameters check
    assert PRIMARY_NUM_CTX == 2048
    assert PRIMARY_NUM_PREDICT == 300
    assert PRIMARY_TEMPERATURE == 0.0
    assert PRIMARY_SEED == 42
    assert PRIMARY_KEEP_ALIVE == "60m"
    print(f"10. Primary parameters: num_ctx=2048, num_predict=300, temp=0.0, seed=42, keep_alive=60m [PASS]")
    print("PRE-SMOKE FREEZE VERIFICATION COMPLETE.\n")

    return {
        "m4_9_sha": m4_9_sha,
        "benchmark_sha": bm_sha,
        "planning_freeze_commit": tag_commit,
        "phase6_sha": p6_sha,
        "phase6_2_sha": p6_2_sha,
        "model_digest": full_digest,
        "runtime_version": ver_out,
    }


class M5Phase67LiveSmokeHarness:
    """Executes the pre-registered 24-call live smoke test for Phase 6.7."""

    def __init__(self, pre_freeze_meta: Dict[str, Any]):
        self.meta = pre_freeze_meta
        self.context_builder = ReasoningContextBuilder()
        self.validator = KnowledgeGroundingValidator()
        self.pipeline = VaptReasoningPipeline()
        self.runner = ReasoningRunner(
            model_name="qwen2.5-coder:7b",
            num_ctx=PRIMARY_NUM_CTX,
        )

        gold_scenarios = get_gold_set_scenarios()
        scen_by_id = {s.scenario_id: s for s in gold_scenarios}
        for sid in PRE_REGISTERED_SCENARIOS:
            assert sid in scen_by_id, f"Pre-registered scenario {sid} not in gold set!"
        self.selected_scenarios: List[EvaluationScenario] = [scen_by_id[sid] for sid in PRE_REGISTERED_SCENARIOS]

        self._canonical_input_cache: Dict[str, Dict[str, Any]] = {}

    def get_canonical_input(self, scenario_id: str) -> Dict[str, Any]:
        if scenario_id in self._canonical_input_cache:
            return self._canonical_input_cache[scenario_id]

        gold_scen = [s for s in self.selected_scenarios if s.scenario_id == scenario_id][0]
        observed_facts = gold_scen.initial_evidence or [
            {"fact_id": "FACT-00000001", "statement": "Neutral observable target evidence."}
        ]
        raw_sample = str(observed_facts[0].get("statement", "")) if observed_facts else ""

        # Strictly clean Channel A: ZERO ground-truth leakage!
        # Faithful LosslessStructuralPack construction from frozen scenario
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

        # Verification of parameter and identity fidelity
        assert pack.parameter_lineage == gold_scen.parameters, "Parameter fidelity mismatch"
        assert pack.identity_matrix == gold_scen.identities, "Identity fidelity mismatch"

        gap_type = infer_evidence_gap_type(gold_scen.category_id)
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
            high_risk_signals=["M5_SMOKE"],
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

        # Explicit RAG inputs per track
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

    def execute_live_smoke(self) -> List[Phase67CallRecord]:
        print("=== [PHASE 6.7] EXECUTING PRE-REGISTERED 24-CALL LIVE SMOKE TEST ===")
        records: List[Phase67CallRecord] = []
        call_counter = 0

        # Scenario-level causal parity tracker: (scenario_id, i1) -> target_ev_bytes for Track B
        track_b_target_bytes: Dict[Tuple[str, bool], bytes] = {}

        for scen_idx, gold_scen in enumerate(self.selected_scenarios, 1):
            sid = gold_scen.scenario_id
            print(f"\n[{scen_idx}/3] Scenario: {sid} (Category: {gold_scen.category_id}, Vuln: {gold_scen.vulnerable_variant})")

            canonical_input = self.get_canonical_input(sid)
            pack = canonical_input["pack"]
            canonical_input_hash = canonical_input["canonical_input_hash"]
            empirical_present = canonical_input["empirical_evidence_present"]

            for track_id in PRE_REGISTERED_TRACKS:
                ctx, target_ev_bytes, vapt_pack_hash = self.build_context_for_track(scenario_id=sid, track_id=track_id)
                target_ev_hash = hashlib.sha256(target_ev_bytes).hexdigest()
                prompt_hash = hashlib.sha256(ctx.prompt.encode("utf-8")).hexdigest()

                # Get effective vapt pack for runner
                effective_vapt = (
                    canonical_input["vapt_pack"]
                    if track_id in (ConfirmatoryTrackId.TRACK_C, ConfirmatoryTrackId.TRACK_D)
                    else None
                )

                for enable_i1 in PRE_REGISTERED_I1_CONDITIONS:
                    call_counter += 1
                    cond_name = "I1=1 (Schema Constrained)" if enable_i1 else "I1=0 (Unconstrained)"
                    print(f"  Call #{call_counter:02d}: {track_id.value} | {cond_name} ...", end=" ", flush=True)

                    if track_id == ConfirmatoryTrackId.TRACK_B:
                        track_b_target_bytes[(sid, enable_i1)] = target_ev_bytes
                    elif track_id == ConfirmatoryTrackId.TRACK_D:
                        b_bytes = track_b_target_bytes.get((sid, enable_i1))
                        assert b_bytes is not None, f"Track B target bytes missing for {sid} (I1={enable_i1})"
                        assert b_bytes == target_ev_bytes, (
                            f"STOP CONDITION: B/D Target-Evidence Causal Parity failure for {sid} (I1={enable_i1})!"
                        )

                    # 1. Compile Reasoning Execution Contract
                    proto_contract = get_protocol_contract(OutputProtocolIdentifier.JSON_BAIR)
                    schema = proto_contract.runtime_schema_factory(True) if enable_i1 else None

                    contract = ReasoningExecutionContract(
                        protocol=OutputProtocolIdentifier.JSON_BAIR,
                        enable_i1=enable_i1,
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

                    # Verify contract before calling
                    validate_reasoning_contract(contract)

                    # Target-asset enrichment (copy without mutating EvaluationScenario)
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
                        # Try parsing raw response for inspection even if invalid
                        try:
                            clean_text = result.raw_response.strip()
                            if clean_text.startswith("```"):
                                clean_text = re.sub(r"^```[a-zA-Z]*\n", "", clean_text)
                                clean_text = re.sub(r"\n```$", "", clean_text)
                            parsed_dict = json.loads(clean_text)
                        except Exception:
                            parsed_dict = None

                    # Extract typed experiment fields
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

                    # Check schema validity (Pydantic validation)
                    schema_valid = False
                    if parsed_dict is not None and isinstance(parsed_dict, dict):
                        try:
                            BairJsonObject.model_validate(parsed_dict)
                            schema_valid = True
                        except Exception:
                            schema_valid = False

                    # Check ExperimentPolarityValidator result
                    polarity_res = None
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

                    rec = Phase67CallRecord(
                        call_index=call_counter,
                        scenario_id=sid,
                        track_id=track_id.value,
                        i1_enabled=enable_i1,
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
                        timestamp=ts,
                    )
                    records.append(rec)

                    status_tag = "VALID" if rec.is_valid else f"FAIL ({rec.primary_failure_category})"
                    dec_tag = f"Decision={rec.final_deterministic_decision}" if rec.final_deterministic_decision else f"Cand={rec.candidate_decision}"
                    act_tag = f"Act={typed_fields.get('experiment_action')}" if typed_fields.get("experiment_action") else "NoAct"
                    print(f"{status_tag} | {dec_tag} | {act_tag} | {rec.latency_ms:.0f}ms")

        print(f"\nLive smoke execution complete: {len(records)} calls completed.\n")
        return records


def main():
    # 1. Pre-flight freeze verification
    freeze_meta = run_pre_smoke_freeze_checks()

    # 2. Execute live smoke test
    harness = M5Phase67LiveSmokeHarness(freeze_meta)
    records = harness.execute_live_smoke()

    assert len(records) == 24, f"Expected exactly 24 records, got {len(records)}"

    # 3. Compile Smoke Artifact
    artifact = {
        "schema_version": "6.0.0",
        "milestone": "M5",
        "phase": "PHASE_6_7_TYPED_PROTOCOL_LIVE_SMOKE",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "metadata": {
            "m4_9_sha": freeze_meta["m4_9_sha"],
            "benchmark_manifest_sha": freeze_meta["benchmark_sha"],
            "planning_freeze_commit": freeze_meta["planning_freeze_commit"],
            "phase6_sha": freeze_meta["phase6_sha"],
            "phase6_2_sha": freeze_meta["phase6_2_sha"],
            "model_name": "qwen2.5-coder:7b",
            "model_digest": freeze_meta["model_digest"],
            "runtime_version": freeze_meta["runtime_version"],
            "primary_inference_parameters": {
                "num_ctx": PRIMARY_NUM_CTX,
                "num_predict": PRIMARY_NUM_PREDICT,
                "temperature": PRIMARY_TEMPERATURE,
                "seed": PRIMARY_SEED,
                "keep_alive": PRIMARY_KEEP_ALIVE,
            },
        },
        "pre_registered_matrix": {
            "scenarios": PRE_REGISTERED_SCENARIOS,
            "tracks": [t.value for t in PRE_REGISTERED_TRACKS],
            "i1_conditions": PRE_REGISTERED_I1_CONDITIONS,
            "total_calls": len(records),
            "retries_count": 0,
            "semantic_repairs_count": 0,
        },
        "summary": {
            "total_calls": len(records),
            "valid_executions": sum(1 for r in records if r.is_valid),
            "failed_executions": sum(1 for r in records if not r.is_valid),
            "parser_failures": sum(1 for r in records if r.primary_failure_category == PrimaryFailureCategory.PARSER_FAILURE.value),
            "schema_failures": sum(1 for r in records if r.primary_failure_category == PrimaryFailureCategory.SCHEMA_VALIDITY_FAILURE.value),
            "truncation_failures": sum(1 for r in records if r.primary_failure_category == PrimaryFailureCategory.MAX_TOKEN_TRUNCATION.value),
            "grounding_rejections": sum(1 for r in records if r.primary_failure_category == PrimaryFailureCategory.SEMANTIC_GROUNDING_FAILURE.value),
            "polarity_rejections": sum(1 for r in records if r.primary_failure_category == PrimaryFailureCategory.SEMANTIC_EXPERIMENT_POLARITY_FAILURE.value),
            "transport_failures": sum(1 for r in records if r.primary_failure_category == PrimaryFailureCategory.RUNTIME_TRANSPORT_FAILURE.value),
            "mean_latency_ms": sum(r.latency_ms for r in records) / len(records) if records else 0.0,
            "min_latency_ms": min(r.latency_ms for r in records) if records else 0.0,
            "max_latency_ms": max(r.latency_ms for r in records) if records else 0.0,
            "decisions_reached": {
                "HYPOTHESIS": sum(1 for r in records if r.final_deterministic_decision == "HYPOTHESIS"),
                "INSUFFICIENT_EVIDENCE": sum(1 for r in records if r.final_deterministic_decision == "INSUFFICIENT_EVIDENCE"),
                "NO_RELEVANT_FUNCTIONALITY": sum(1 for r in records if r.final_deterministic_decision == "NO_RELEVANT_FUNCTIONALITY"),
                "NONE": sum(1 for r in records if r.final_deterministic_decision is None),
            },
            "candidate_decisions": {
                "HYPOTHESIS": sum(1 for r in records if r.candidate_decision == "HYPOTHESIS"),
                "INSUFFICIENT_EVIDENCE": sum(1 for r in records if r.candidate_decision == "INSUFFICIENT_EVIDENCE"),
                "NO_RELEVANT_FUNCTIONALITY": sum(1 for r in records if r.candidate_decision == "NO_RELEVANT_FUNCTIONALITY"),
                "NONE": sum(1 for r in records if r.candidate_decision is None),
            },
            "typed_fields_completeness": {
                "action_present": sum(1 for r in records if r.typed_experiment_fields.get("experiment_action") is not None),
                "supporting_present": sum(1 for r in records if r.typed_experiment_fields.get("supporting_outcome") is not None),
                "disproving_present": sum(1 for r in records if r.typed_experiment_fields.get("disproving_outcome") is not None),
                "description_present": sum(1 for r in records if r.typed_experiment_fields.get("falsification_description") is not None),
            },
            "i1_comparison": {
                "i1_off": {
                    "calls": sum(1 for r in records if not r.i1_enabled),
                    "valid": sum(1 for r in records if not r.i1_enabled and r.is_valid),
                    "parser_failures": sum(1 for r in records if not r.i1_enabled and r.primary_failure_category == PrimaryFailureCategory.PARSER_FAILURE.value),
                    "schema_failures": sum(1 for r in records if not r.i1_enabled and r.primary_failure_category == PrimaryFailureCategory.SCHEMA_VALIDITY_FAILURE.value),
                    "polarity_failures": sum(1 for r in records if not r.i1_enabled and r.primary_failure_category == PrimaryFailureCategory.SEMANTIC_EXPERIMENT_POLARITY_FAILURE.value),
                    "mean_latency_ms": sum(r.latency_ms for r in records if not r.i1_enabled) / 12.0,
                },
                "i1_on": {
                    "calls": sum(1 for r in records if r.i1_enabled),
                    "valid": sum(1 for r in records if r.i1_enabled and r.is_valid),
                    "parser_failures": sum(1 for r in records if r.i1_enabled and r.primary_failure_category == PrimaryFailureCategory.PARSER_FAILURE.value),
                    "schema_failures": sum(1 for r in records if r.i1_enabled and r.primary_failure_category == PrimaryFailureCategory.SCHEMA_VALIDITY_FAILURE.value),
                    "polarity_failures": sum(1 for r in records if r.i1_enabled and r.primary_failure_category == PrimaryFailureCategory.SEMANTIC_EXPERIMENT_POLARITY_FAILURE.value),
                    "mean_latency_ms": sum(r.latency_ms for r in records if r.i1_enabled) / 12.0,
                },
            },
        },
        "records": [r.model_dump() for r in records],
    }

    # 4. Write data/eval/m5_typed_protocol_live_smoke.json and compute SHA
    out_path = Path("data/eval/m5_typed_protocol_live_smoke.json")
    out_bytes = json.dumps(artifact, indent=2).encode("utf-8")
    out_path.write_bytes(out_bytes)
    out_sha = hashlib.sha256(out_bytes).hexdigest().lower()
    sha_path = Path("data/eval/m5_typed_protocol_live_smoke.json.sha256")
    sha_path.write_text(out_sha + "\n", encoding="utf-8")

    print(f"Artifact serialized: {out_path}")
    print(f"Artifact SHA-256:    {out_sha}")
    print(f"SHA written to:      {sha_path}")

    # 5. Final Post-Smoke Integrity Verification
    m4_9_post_sha = hash_file(Path("data/eval/m4_live_llm_benchmark_final.json"))
    assert m4_9_post_sha == EXPECTED_M4_9_SHA, f"M4.9 SHA altered during smoke test! {m4_9_post_sha}"
    p6_post_sha = hash_file(Path("data/eval/m5_live_smoke.json"))
    assert p6_post_sha == EXPECTED_PHASE6_SMOKE_SHA, f"Phase 6 artifact altered! {p6_post_sha}"
    p6_2_post_sha = hash_file(Path("data/eval/m5_live_smoke_v2.json"))
    assert p6_2_post_sha == EXPECTED_PHASE6_2_SMOKE_SHA, f"Phase 6.2 artifact altered! {p6_2_post_sha}"
    print("Post-execution M4.9 SHA verified identical [PASS]")
    print("Post-execution Phase 6 smoke artifact verified identical [PASS]")
    print("Post-execution Phase 6.2 smoke artifact verified identical [PASS]")


if __name__ == "__main__":
    main()
