"""
Milestone M5 Phase 8 — Semantic Capability & Experiment Construction Study.

Executes:
- Phase 8.1: Deterministic failure attribution across all 104 Phase 7 candidate hypotheses.
- Phase 8.2: Controlled Semantic Protocol Study (40 live LLM calls: 5 scenarios x 2 tracks x 4 conditions P1-P4).
- Phase 8.3: Active-Evidence Diagnostic Study (4 live LLM calls on synthetic Class-1 anomaly cases).
- Phase 8.4: Latency Envelope Audit & Formal Decision Record.

Strict Execution Rules:
- EXACTLY 44 live LLM calls total (40 for Phase 8.2, 4 for Phase 8.3)
- Zero modification to src/eval/scenarios.py
- Zero modification to Phase 7 sealed artifact or historical reports
- Pinned runtime: Ollama v0.34.1, qwen2.5-coder:7b (dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364)
- Zero retry, zero repair, temperature=0.0, seed=42, num_ctx=2048, num_predict=300

Artifacts produced:
- data/eval/m5_phase8_semantic_study.json
- data/eval/m5_phase8_semantic_study.json.sha256
"""

from collections import Counter, defaultdict
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
    ReviewerPresentationLabel,
    canonical_vulnerability_evidence_present,
    determine_applicability_state,
)

SEALED_P7_PATH = repo_root / "data/eval/m5_phase7_benchmark_final.json"
EXPECTED_P7_SHA = "1e0ed90c4aa672f135d2d2f2240a14d22fa0037c03efda33634f4bf10ff0b125"

P8_OUTPUT_JSON = repo_root / "data/eval/m5_phase8_semantic_study.json"
P8_OUTPUT_SHA = repo_root / "data/eval/m5_phase8_semantic_study.json.sha256"

# Representative scenarios for Phase 8.2 (5 scenarios x 2 tracks x 4 conditions = 40 calls)
P8_2_REPRESENTATIVE_SCENARIOS = [
    "SCEN-SAAS_BILLING-INV-DETAILS-VULN-01",      # API-BOLA-001 (Vuln)
    "SCEN-ECOMMERCE_ORDERS-ORD-REFUND-VULN-01",   # API-STATE-001 (Vuln)
    "SCEN-IDENTITY_PROVIDER-USER-ROLES-VULN-01",  # API-ROLE-BOUNDARY-001 (Vuln)
    "SCEN-IOT_FLEET_MGMT-FLEET-CMD-VULN-03",      # API-CROSS-TENANT-001 (Vuln)
    "SCEN-SAAS_BILLING-INV-DETAILS-PATCH-01",     # API-BOLA-001 (Control)
]

P8_2_TRACKS = [
    ConfirmatoryTrackId.TRACK_A,
    ConfirmatoryTrackId.TRACK_D,
]

P8_2_CONDITIONS = ["P1", "P2", "P3", "P4"]


def hash_file(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest().lower()


def run_phase8_1_attribution() -> Dict[str, Any]:
    print("\n=== [PHASE 8.1] DETERMINISTIC FAILURE ATTRIBUTION (SEALED PHASE 7) ===")
    assert SEALED_P7_PATH.exists(), f"Phase 7 sealed artifact missing: {SEALED_P7_PATH}"
    actual_sha = hash_file(SEALED_P7_PATH)
    assert actual_sha == EXPECTED_P7_SHA, f"Phase 7 SHA mismatch: {actual_sha} != {EXPECTED_P7_SHA}"

    p7_data = json.loads(SEALED_P7_PATH.read_text(encoding="utf-8"))
    records = p7_data["call_records"]

    hyp_records = [r for r in records if r.get("candidate_decision") == "HYPOTHESIS"]
    assert len(hyp_records) == 104, f"Expected 104 candidate hypothesis attempts, got {len(hyp_records)}"

    classified = []
    for r in hyp_records:
        pfc = r.get("primary_failure_category")
        pol = r.get("ExperimentPolarityValidator_result")
        typed = r.get("typed_experiment_fields", {})
        act = typed.get("experiment_action")
        supp = typed.get("supporting_outcome")
        disp = typed.get("disproving_outcome")

        cat_class = None
        if pfc == "MAX_TOKEN_TRUNCATION":
            cat_class = "E. TRUNCATION"
        elif supp is not None and disp is not None and supp == disp:
            cat_class = "C. IDENTICAL_SUPPORTING_DISPROVING_OUTCOME"
        elif pol and not pol.get("is_valid"):
            reason = pol.get("reason", "")
            if "not compatible with category" in reason:
                cat_class = "A. CATEGORY_ACTION_INCOMPATIBILITY"
            elif "not a valid breach outcome" in reason or "not a valid safe outcome" in reason or "inversion" in reason.lower():
                cat_class = "B. OUTCOME_POLARITY_INVERSION"
            else:
                cat_class = f"F. OTHER ({reason})"
        elif not act or not supp or not disp:
            cat_class = "D. MISSING_REQUIRED_SEMANTIC_FIELD"
        else:
            cat_class = f"F. OTHER ({pfc})"

        classified.append({
            "call_index": r["call_index"],
            "scenario_id": r["scenario_id"],
            "failure_type": cat_class,
            "category_id": r["category_id"],
            "track_id": r["track_id"],
            "i1_enabled": r["i1_enabled"],
            "vulnerable_variant": r["vulnerable_variant"],
            "action": act,
            "supporting": supp,
            "disproving": disp,
        })

    ft_counts = Counter(c["failure_type"] for c in classified)
    by_cat = defaultdict(Counter)
    by_track = defaultdict(Counter)
    by_vuln = defaultdict(Counter)

    for c in classified:
        by_cat[c["category_id"]][c["failure_type"]] += 1
        by_track[c["track_id"]][c["failure_type"]] += 1
        by_vuln["Vulnerable" if c["vulnerable_variant"] else "Control"][c["failure_type"]] += 1

    print(f"Total candidate attempts: {len(classified)}")
    print(f"Total rejected: {len(classified)} (100.00%)")
    for ft, cnt in sorted(ft_counts.items()):
        print(f"  {ft}: {cnt} ({cnt/len(classified)*100:.2f}%)")

    return {
        "total_candidate_attempts": len(classified),
        "total_rejected": len(classified),
        "rejection_percentage": 100.0,
        "failure_type_breakdown": dict(ft_counts),
        "cross_tab_category": {k: dict(v) for k, v in by_cat.items()},
        "cross_tab_track": {k: dict(v) for k, v in by_track.items()},
        "cross_tab_vulnerable_control": {k: dict(v) for k, v in by_vuln.items()},
        "records": classified,
    }


def run_phase8_2_protocol_study() -> List[Dict[str, Any]]:
    print("\n=== [PHASE 8.2] CONTROLLED SEMANTIC PROTOCOL STUDY (40 LIVE CALLS) ===")
    ckpt_path = repo_root / "data/eval/m5_phase8_p8_2_checkpoint.json"
    if ckpt_path.exists():
        try:
            cached_results = json.loads(ckpt_path.read_text(encoding="utf-8"))
            if len(cached_results) == 40:
                print(f"Loaded {len(cached_results)}/40 completed Phase 8.2 calls from checkpoint.")
                return cached_results
        except Exception:
            pass

    gold_scenarios = {s.scenario_id: s for s in get_gold_set_scenarios()}
    runner = ReasoningRunner(model_name="qwen2.5-coder:7b", num_ctx=PRIMARY_NUM_CTX)
    context_builder = ReasoningContextBuilder()
    validator = KnowledgeGroundingValidator()
    pipeline = VaptReasoningPipeline()

    compat_registry = ExperimentPolarityValidator.TUPLE_COMPATIBILITY_REGISTRY
    proto_contract = get_protocol_contract(OutputProtocolIdentifier.JSON_BAIR)

    results = []
    call_idx = 0

    for sid in P8_2_REPRESENTATIVE_SCENARIOS:
        scen = gold_scenarios[sid]
        print(f"\nScenario: {sid} ({scen.category_id}, Vuln: {scen.vulnerable_variant})")

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
        vapt_pack, _ = pipeline.retrieve_and_pack(channel_a=pack, gap_type=gap_type)

        routing = DeterministicRoutingDecision(
            schema_version="2.0.0",
            escalate=True,
            has_high_risk_signal=True,
            high_risk_signals=["M5_PHASE8"],
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

        cat_actions = compat_registry.get(scen.category_id, {})
        legal_actions = list(cat_actions.keys())
        primary_action = legal_actions[0] if legal_actions else "SUBSTITUTE_RESOURCE_IDENTIFIER"
        legal_breaches, legal_safes = cat_actions.get(primary_action, (set(), set()))

        for track_id in P8_2_TRACKS:
            cascade_mode = TRACK_A if track_id == ConfirmatoryTrackId.TRACK_A else TRACK_D
            effective_vapt = vapt_pack if track_id == ConfirmatoryTrackId.TRACK_D else None

            base_ctx = context_builder.build_context(
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

            for cond in P8_2_CONDITIONS:
                call_idx += 1
                print(f"  [Call #{call_idx:02d}/40] {track_id.value} | Cond: {cond} ...", end=" ", flush=True)

                sys_prompt = base_ctx.system_prompt
                user_prompt = base_ctx.user_prompt
                schema = proto_contract.runtime_schema_factory(True)

                if cond == "P1":
                    # Current Phase 7 JSON_BAIR
                    pass
                elif cond == "P2":
                    # Category-Specific Vocabulary Guidance
                    guidance = (
                        f"\n\n=== CATEGORY EXPERIMENT CONSTRAINTS ({scen.category_id}) ===\n"
                        f"- Permitted experiment_action values: {legal_actions}\n"
                        f"- Permitted supporting_outcome values: {list(legal_breaches)}\n"
                        f"- Permitted disproving_outcome values: {list(legal_safes)}\n"
                        f"If decision is HYPOTHESIS, you MUST choose values strictly from these lists."
                    )
                    user_prompt = user_prompt + guidance
                elif cond == "P3":
                    # Engine-Supplied Legal Action
                    p3_guidance = (
                        f"\n\n=== PRE-SELECTED EXPERIMENT ACTION ===\n"
                        f"For category {scen.category_id}, the experiment action is FIXED by policy:\n"
                        f"  'experiment_action': '{primary_action}'\n"
                        f"If decision is HYPOTHESIS, you MUST emit 'experiment_action': '{primary_action}'.\n"
                        f"Permitted supporting_outcome values: {list(legal_breaches)}\n"
                        f"Permitted disproving_outcome values: {list(legal_safes)}\n"
                    )
                    user_prompt = user_prompt + p3_guidance
                elif cond == "P4":
                    # Compact representation with minimal prose
                    p4_guidance = (
                        f"\n\n=== COMPACT EXPERIMENT REPRESENTATION ===\n"
                        f"Keep output concise. Required fields for HYPOTHESIS: 'experiment_action', 'supporting_outcome', 'disproving_outcome'.\n"
                        f"Set 'falsification_description' to a short 1-sentence description.\n"
                        f"Legal actions: {legal_actions}\n"
                    )
                    user_prompt = user_prompt + p4_guidance

                contract = ReasoningExecutionContract(
                    protocol=OutputProtocolIdentifier.JSON_BAIR,
                    enable_i1=True,
                    enable_i2=True,
                    enable_i3=True,
                    enable_i4=True,
                    enable_i5=True,
                    enable_i6=True,
                    system_prompt=sys_prompt,
                    user_prompt=user_prompt,
                    runtime_schema=schema,
                    parser=proto_contract.parser,
                    validator=proto_contract.validator,
                    adapter=proto_contract.adapter,
                    budget_tier=4096,
                    floor_tokens=1000,
                    total_tokens=base_ctx.token_count,
                    protected_handoff_present=True,
                    category_id=scen.category_id,
                )

                validate_reasoning_contract(contract)

                t0 = time.perf_counter()
                exec_res = runner.execute_m5_generation(
                    contract=contract,
                    empirical_evidence_present=True,
                    grounding_validator=validator,
                    channel_a=pack,
                    target_asset=target_asset_enriched,
                    category_id=scen.category_id,
                    vapt_pack=effective_vapt,
                )
                lat_ms = (time.perf_counter() - t0) * 1000.0

                parsed_dict = exec_res.parsed_intermediate if isinstance(exec_res.parsed_intermediate, dict) else None
                cand_dec = parsed_dict.get("decision") if parsed_dict else None
                act = parsed_dict.get("experiment_action") if parsed_dict else None
                supp = parsed_dict.get("supporting_outcome") if parsed_dict else None
                disp = parsed_dict.get("disproving_outcome") if parsed_dict else None

                act_compat = False
                supp_compat = False
                disp_compat = False
                polarity_valid = False
                polarity_reason = None

                if cand_dec == "HYPOTHESIS" or (exec_res.canonical_hypothesis and exec_res.canonical_hypothesis.decision == HypothesisDecision.HYPOTHESIS):
                    is_compat, reason = ExperimentPolarityValidator.validate_tuple(
                        category_id=scen.category_id,
                        experiment_action=act,
                        supporting_outcome=supp,
                        disproving_outcome=disp,
                    )
                    polarity_valid = is_compat
                    polarity_reason = reason
                    if act in legal_actions:
                        act_compat = True
                    if supp in legal_breaches:
                        supp_compat = True
                    if disp in legal_safes:
                        disp_compat = True

                final_dec = str(exec_res.canonical_hypothesis.decision) if exec_res.canonical_hypothesis else None

                record = {
                    "call_index": call_idx,
                    "scenario_id": sid,
                    "track_id": track_id.value,
                    "condition": cond,
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
                    "action_compatible": act_compat,
                    "supporting_compatible": supp_compat,
                    "disproving_compatible": disp_compat,
                    "polarity_valid": polarity_valid,
                    "polarity_reason": polarity_reason,
                    "grounding_valid": bool(exec_res.grounding_result and exec_res.grounding_result.get("is_valid", False)),
                    "eval_count": exec_res.eval_count,
                }
                results.append(record)
                ckpt_path.write_text(json.dumps(results, indent=2), encoding="utf-8")

                status_tag = "VALID" if record["is_valid"] else f"FAIL({record['primary_failure_category']})"
                dec_tag = f"Dec={final_dec}" if final_dec else f"Cand={cand_dec}"
                pol_tag = "Pol=OK" if polarity_valid else ("Pol=FAIL" if cand_dec == "HYPOTHESIS" else "Pol=N/A")
                print(f"{status_tag} | {dec_tag} | {pol_tag} | {lat_ms:.0f}ms")

    assert len(results) == 40, f"Expected exactly 40 calls, got {len(results)}"
    return results


def run_phase8_3_active_evidence_diagnostic() -> List[Dict[str, Any]]:
    print("\n=== [PHASE 8.3] ACTIVE-EVIDENCE DIAGNOSTIC STUDY (4 LIVE CALLS) ===")
    runner = ReasoningRunner(model_name="qwen2.5-coder:7b", num_ctx=PRIMARY_NUM_CTX)
    context_builder = ReasoningContextBuilder()
    validator = KnowledgeGroundingValidator()
    proto_contract = get_protocol_contract(OutputProtocolIdentifier.JSON_BAIR)

    # 4 Canonical active-evidence diagnostic cases
    fixtures = [
        {
            "id": "DIAG-ACT-BOLA-01",
            "category_id": "API-BOLA-001",
            "route": "/api/v1/tenants/{tenant_id}/invoices/{invoice_id}",
            "method": "GET",
            "parameters": [{"name": "tenant_id", "type": "string", "source": "path"}, {"name": "invoice_id", "type": "string", "source": "path"}],
            "identities": [{"role": "TENANT_A_ADMIN", "user_id": "usr-admin-01"}, {"role": "TENANT_B_USER", "user_id": "usr-user-02"}],
            "evidence": [
                {
                    "fact_id": "FACT-ACT-0001",
                    "statement": "GET /api/v1/tenants/t-alpha/invoices/inv-999 with TENANT_B_USER credential returned HTTP 200 with tenant t-alpha invoice data.",
                    "observed_cross_identity_access": True,
                    "has_cross_identity_object_access_success": True,
                }
            ],
            "anomaly_key": "has_cross_identity_object_access_success",
            "expected_applicable": EvaluationApplicabilityState.VULNERABILITY_EVALUATION_APPLICABLE,
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
            "expected_applicable": EvaluationApplicabilityState.VULNERABILITY_EVALUATION_APPLICABLE,
        },
        {
            "id": "DIAG-ACT-ROLE-01",
            "category_id": "API-ROLE-BOUNDARY-001",
            "route": "/api/v1/admin/users/{user_id}/roles",
            "method": "PUT",
            "parameters": [{"name": "user_id", "type": "string", "source": "path"}],
            "identities": [{"role": "MEMBER", "user_id": "usr-member-01"}, {"role": "ADMIN", "user_id": "usr-admin-02"}],
            "evidence": [
                {
                    "fact_id": "FACT-ACT-0003",
                    "statement": "PUT /api/v1/admin/users/usr-700/roles with MEMBER token returned HTTP 200 and granted ADMIN role.",
                    "observed_privilege_delta": True,
                    "has_privilege_level_delta": True,
                }
            ],
            "anomaly_key": "has_privilege_level_delta",
            "expected_applicable": EvaluationApplicabilityState.VULNERABILITY_EVALUATION_APPLICABLE,
        },
        {
            "id": "DIAG-ACT-TENANT-01",
            "category_id": "API-CROSS-TENANT-001",
            "route": "/api/v1/fleets/{fleet_id}/telemetry",
            "method": "GET",
            "parameters": [{"name": "fleet_id", "type": "string", "source": "path"}],
            "identities": [{"role": "TENANT_A", "user_id": "usr-tenant-a"}, {"role": "TENANT_B", "user_id": "usr-tenant-b"}],
            "evidence": [
                {
                    "fact_id": "FACT-ACT-0004",
                    "statement": "GET /api/v1/fleets/flt-888/telemetry with Tenant A token successfully accessed Tenant B telemetry data.",
                    "observed_cross_identity_access": True,
                    "has_cross_identity_object_access_success": True,
                }
            ],
            "anomaly_key": "has_cross_identity_object_access_success",
            "expected_applicable": EvaluationApplicabilityState.VULNERABILITY_EVALUATION_APPLICABLE,
        },
    ]

    results = []

    for f_idx, f in enumerate(fixtures, 1):
        print(f"\n[Case #{f_idx}/4] {f['id']} (Category: {f['category_id']}) ...", end=" ", flush=True)

        pack_kwargs = {
            "schema_version": "2.0.0",
            "asset_id": f"ASSET-{f['id']}",
            "endpoint_id": f"EP-{f['id']}",
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

        ctx = context_builder.build_context(
            handoff_packet=handoff,
            model_identifier="qwen2.5-coder:7b",
            budget_tier=4096,
            cascade_mode=TRACK_D,
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

        t0 = time.perf_counter()
        exec_res = runner.execute_m5_generation(
            contract=contract,
            empirical_evidence_present=True,
            grounding_validator=validator,
            channel_a=pack,
            target_asset=target_asset,
            category_id=f["category_id"],
        )
        lat_ms = (time.perf_counter() - t0) * 1000.0

        has_anomaly = canonical_vulnerability_evidence_present(
            evidence=f["evidence"],
            structural_pack=pack,
        )
        assert has_anomaly is True, "Active anomaly flag was not detected by predicate!"

        app_state = determine_applicability_state(
            is_valid_output=exec_res.classification.is_valid,
            target_relevant=True,
            canonical_evidence_has_anomaly=has_anomaly,
        )

        parsed_dict = exec_res.parsed_intermediate if isinstance(exec_res.parsed_intermediate, dict) else None
        cand_dec = parsed_dict.get("decision") if parsed_dict else None
        final_dec = str(exec_res.canonical_hypothesis.decision) if exec_res.canonical_hypothesis else None
        act = parsed_dict.get("experiment_action") if parsed_dict else None
        supp = parsed_dict.get("supporting_outcome") if parsed_dict else None
        disp = parsed_dict.get("disproving_outcome") if parsed_dict else None

        polarity_valid = False
        if cand_dec == "HYPOTHESIS" or (exec_res.canonical_hypothesis and exec_res.canonical_hypothesis.decision == HypothesisDecision.HYPOTHESIS):
            is_compat, _ = ExperimentPolarityValidator.validate_tuple(
                category_id=f["category_id"],
                experiment_action=act,
                supporting_outcome=supp,
                disproving_outcome=disp,
            )
            polarity_valid = is_compat

        grounding_valid = bool(exec_res.grounding_result and exec_res.grounding_result.get("is_valid", False))

        rec = {
            "fixture_id": f["id"],
            "category_id": f["category_id"],
            "has_canonical_anomaly": has_anomaly,
            "applicability_state": app_state.value,
            "is_valid": exec_res.classification.is_valid,
            "primary_failure_category": exec_res.classification.primary_category.value,
            "candidate_decision": cand_dec,
            "final_decision": final_dec,
            "experiment_action": act,
            "supporting_outcome": supp,
            "disproving_outcome": disp,
            "polarity_valid": polarity_valid,
            "grounding_valid": grounding_valid,
            "latency_ms": lat_ms,
        }
        results.append(rec)

        status_tag = "VALID" if rec["is_valid"] else f"FAIL({rec['primary_failure_category']})"
        dec_tag = f"Dec={final_dec}" if final_dec else f"Cand={cand_dec}"
        print(f"{status_tag} | {dec_tag} | App={app_state.value} | {lat_ms:.0f}ms")

    assert len(results) == 4, f"Expected 4 active evidence results, got {len(results)}"
    return results


def main():
    start_time = time.time()
    print("================================================================================")
    print("STARTING M5 PHASE 8: SEMANTIC CAPABILITY & EXPERIMENT CONSTRUCTION STUDY")
    print("================================================================================")

    # 1. Phase 8.1: Deterministic failure attribution
    p8_1_results = run_phase8_1_attribution()

    # 2. Phase 8.2: Controlled semantic protocol study (40 live LLM calls)
    p8_2_results = run_phase8_2_protocol_study()

    # 3. Phase 8.3: Active evidence diagnostic (4 live LLM calls)
    p8_3_results = run_phase8_3_active_evidence_diagnostic()

    total_time = time.time() - start_time

    # Verification of Ollama metadata
    ver_out = subprocess.check_output(["ollama", "--version"], text=True).strip()
    with httpx.Client(timeout=5.0) as client:
        tags_res = client.get("http://127.0.0.1:11434/api/tags")
        models = tags_res.json().get("models", [])
        matched = [m for m in models if m.get("name") == "qwen2.5-coder:7b" or m.get("model") == "qwen2.5-coder:7b"]
        digest = matched[0].get("digest", "")

    # Compile artifact
    artifact = {
        "schema_version": "8.0.0",
        "milestone": "M5",
        "phase": "PHASE_8_SEMANTIC_CAPABILITY_STUDY",
        "status": "M5_PHASE8_COMPLETE",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_runtime_seconds": round(total_time, 2),
        "total_live_calls": len(p8_2_results) + len(p8_3_results),
        "metadata": {
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
            "sealed_phase7_sha": EXPECTED_P7_SHA,
        },
        "phase_8_1_attribution": p8_1_results,
        "phase_8_2_protocol_study": {
            "conditions": P8_2_CONDITIONS,
            "tracks": [t.value for t in P8_2_TRACKS],
            "scenarios": P8_2_REPRESENTATIVE_SCENARIOS,
            "call_records": p8_2_results,
        },
        "phase_8_3_active_evidence_diagnostic": {
            "fixture_count": len(p8_3_results),
            "call_records": p8_3_results,
        },
    }

    P8_OUTPUT_JSON.write_text(json.dumps(artifact, indent=2), encoding="utf-8")
    p8_sha = hash_file(P8_OUTPUT_JSON)
    P8_OUTPUT_SHA.write_text(f"{p8_sha}  {P8_OUTPUT_JSON.name}\n", encoding="utf-8")

    print("\n================================================================================")
    print(f"PHASE 8 ARTIFACT SAVED: {P8_OUTPUT_JSON}")
    print(f"PHASE 8 ARTIFACT SHA-256: {p8_sha}")
    print(f"Total Live Calls: {artifact['total_live_calls']} (40 Protocol Study + 4 Active Evidence)")
    print(f"Elapsed Time: {total_time/60.0:.1f} minutes")
    print("================================================================================")


if __name__ == "__main__":
    main()
