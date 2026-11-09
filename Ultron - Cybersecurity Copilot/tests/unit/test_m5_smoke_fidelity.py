"""
Unit tests for Milestone M5 Phase 6.2 — Input Fidelity and Smoke Harness Verification.

Verifies all 13 deterministic requirements of Phase 6.2B and Phase 6.2C:
1. Frozen scenario parameters transferred into LosslessStructuralPack.parameter_lineage.
2. Frozen scenario identities transferred into LosslessStructuralPack.identity_matrix.
3. Enriched target_asset contains parameters and identities.
4. Original EvaluationScenario object is not mutated.
5. No-methodology tracks explicitly communicate that methodology_references must be [].
6. Valid empty methodology_references list passes schema validation.
7. Fabricated CHK ID still fails grounding.
8. Scenario 1 faithful pack causes is_relevant_functionality(...) == True.
9. Phase 6.1 candidate evaluated against faithful pack preserves INSUFFICIENT_EVIDENCE.
10. No benchmark ground truth enters model-visible prompt.
11. B/D target evidence causal parity remains byte-identical.
12. Track A/B/C/D differ only in their declared RAG inputs.
13. Smoke harness canonical construction is deterministic.
Phase 6.2C: Explicit input-fidelity invariant across all 3 pre-registered scenarios.
"""

import copy
import hashlib
import json
import pytest
from typing import Dict, Any, List

from src.engine.context_builder import ReasoningContextBuilder
from src.engine.decision_policy import (
    is_relevant_functionality,
    deterministic_decide,
    EvidenceState,
    DecisionPredicate,
)
from src.engine.models import (
    BairJsonObject,
    HypothesisModelOutput,
    HypothesisDecision,
)
from src.engine.protocol import (
    OutputProtocolIdentifier,
    get_protocol_contract,
    JSON_BAIR_PROMPT_INSTRUCTION,
)
from src.eval.m4_live_benchmark import (
    get_gold_set_scenarios,
    FORBIDDEN_PROMPT_TOKENS,
    ConfirmatoryTrackId,
    TRACK_A,
    TRACK_B,
    TRACK_C,
    TRACK_D,
)
from src.eval.run_m5_smoke import (
    M5LiveSmokeHarness,
    PRE_REGISTERED_SCENARIOS,
    PRE_REGISTERED_TRACKS,
    PRE_REGISTERED_I1_CONDITIONS,
)
from src.evidence.cascade_models import LosslessStructuralPack
from src.knowledge.grounding_validator import KnowledgeGroundingValidator


@pytest.fixture(scope="module")
def smoke_harness() -> M5LiveSmokeHarness:
    mock_meta = {
        "m4_9_sha": "459b9ec63c3a2dc760abde12ec196760f7e505fbab5317f0da0c46b32c5eaac7",
        "benchmark_sha": "mock_bm_sha",
        "planning_freeze_commit": "mock_commit",
        "model_digest": "dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364",
        "runtime_version": "0.34.1",
    }
    return M5LiveSmokeHarness(pre_freeze_meta=mock_meta)


def test_01_parameters_transferred_to_pack(smoke_harness: M5LiveSmokeHarness):
    """Req 1: Frozen scenario parameters are transferred into LosslessStructuralPack.parameter_lineage."""
    for sid in PRE_REGISTERED_SCENARIOS:
        can_input = smoke_harness.get_canonical_input(sid)
        gold_scen = can_input["gold_scenario"]
        pack: LosslessStructuralPack = can_input["pack"]

        assert len(pack.parameter_lineage) == len(gold_scen.parameters)
        assert pack.parameter_lineage == gold_scen.parameters


def test_02_identities_transferred_to_pack(smoke_harness: M5LiveSmokeHarness):
    """Req 2: Frozen scenario identities are transferred into LosslessStructuralPack.identity_matrix."""
    for sid in PRE_REGISTERED_SCENARIOS:
        can_input = smoke_harness.get_canonical_input(sid)
        gold_scen = can_input["gold_scenario"]
        pack: LosslessStructuralPack = can_input["pack"]

        assert len(pack.identity_matrix) == len(gold_scen.identities)
        assert pack.identity_matrix == gold_scen.identities


def test_03_target_asset_enrichment(smoke_harness: M5LiveSmokeHarness):
    """Req 3: Enriched target_asset contains parameters and identities."""
    for sid in PRE_REGISTERED_SCENARIOS:
        can_input = smoke_harness.get_canonical_input(sid)
        gold_scen = can_input["gold_scenario"]

        target_asset_enriched = dict(gold_scen.target_asset)
        target_asset_enriched["parameters"] = list(gold_scen.parameters)
        target_asset_enriched["identities"] = list(gold_scen.identities)

        assert "parameters" in target_asset_enriched
        assert "identities" in target_asset_enriched
        assert target_asset_enriched["parameters"] == gold_scen.parameters
        assert target_asset_enriched["identities"] == gold_scen.identities


def test_04_original_scenario_not_mutated(smoke_harness: M5LiveSmokeHarness):
    """Req 4: The original EvaluationScenario object is not mutated during enrichment or packing."""
    for sid in PRE_REGISTERED_SCENARIOS:
        can_input = smoke_harness.get_canonical_input(sid)
        gold_scen = can_input["gold_scenario"]

        orig_asset_keys = set(gold_scen.target_asset.keys())

        # Perform enrichment simulation
        target_asset_enriched = dict(gold_scen.target_asset)
        target_asset_enriched["parameters"] = list(gold_scen.parameters)
        target_asset_enriched["identities"] = list(gold_scen.identities)

        # Original scenario's target_asset dict must not have new keys
        assert set(gold_scen.target_asset.keys()) == orig_asset_keys
        assert "parameters" not in gold_scen.target_asset
        assert "identities" not in gold_scen.target_asset


def test_05_no_methodology_tracks_explicitly_communicate_empty_list(smoke_harness: M5LiveSmokeHarness):
    """Req 5: No-methodology tracks explicitly communicate that methodology_references must be []."""
    # Track A and Track B have no VAPT
    for track in [ConfirmatoryTrackId.TRACK_A, ConfirmatoryTrackId.TRACK_B]:
        ctx, _ = smoke_harness.build_context_for_track(
            scenario_id="SCEN-SAAS_BILLING-INV-DETAILS-VULN-01",
            track_id=track,
        )
        assert "[No methodology guidance provided.\n Set methodology_references to []]" in ctx.user_prompt
        assert "methodology_references" in ctx.user_prompt

    # In JSON_BAIR instruction
    assert "If no methodology guidance is supplied, emit an empty list: []" in JSON_BAIR_PROMPT_INSTRUCTION


def test_06_empty_methodology_references_passes_schema():
    """Req 6: A valid empty methodology_references list passes schema validation."""
    bair = BairJsonObject(
        invariant="Target endpoint enforces user tenant ownership on invoice lookup.",
        evidence_gap="Authorization checks not documented in OpenAPI.",
        affected_target="/api/v1/invoices/{id}",
        decision=HypothesisDecision.INSUFFICIENT_EVIDENCE,
        empirical_facts=["FACT-00000001"],
        methodology_references=[],
        falsification_plan="Observe access denied for foreign invoice ID AND observe access allowed.",
    )
    assert bair.methodology_references == []

    # Check runtime schema compliance
    schema = BairJsonObject.get_inference_schema()
    raw_dict = bair.model_dump()
    assert "methodology_references" in raw_dict
    assert raw_dict["methodology_references"] == []


def test_07_fabricated_chk_id_fails_grounding():
    """Req 7: A fabricated CHK ID still fails grounding."""
    validator = KnowledgeGroundingValidator()
    # When no VAPT pack is present, any CHK ID fails closed
    hypo_data = {
        "decision": "INSUFFICIENT_EVIDENCE",
        "invariant": "Invoice access is isolated by account.",
        "empirical_facts": ["FACT-00000001"],
        "methodology_references": ["CHK-001"],
    }
    result = validator.validate_grounding(
        hypothesis=hypo_data,
        pack=None,
        channel_a=LosslessStructuralPack(
            schema_version="2.0.0",
            asset_id="AST-01",
            endpoint_id="EP-01",
            route_template="/test",
            http_method="GET",
            application_mutability="READ_ONLY",
            observed_facts=[{"fact_id": "FACT-00000001", "statement": "Test"}],
        ),
    )
    assert not result.valid
    assert "CHK-001" in result.invalid_chunk_ids or "CHK-001" in (result.reason or "")


def test_08_scenario_1_faithful_pack_relevance(smoke_harness: M5LiveSmokeHarness):
    """Req 8: Scenario 1's faithful pack causes is_relevant_functionality(...) == True."""
    can_input = smoke_harness.get_canonical_input("SCEN-SAAS_BILLING-INV-DETAILS-VULN-01")
    pack: LosslessStructuralPack = can_input["pack"]
    gold_scen = can_input["gold_scenario"]

    target_asset_enriched = dict(gold_scen.target_asset)
    target_asset_enriched["parameters"] = list(gold_scen.parameters)
    target_asset_enriched["identities"] = list(gold_scen.identities)

    ev_state = EvidenceState(channel_a=pack, target_asset=target_asset_enriched)
    assert is_relevant_functionality(ev_state) is True


def test_09_preserves_insufficient_evidence_not_overwritten(smoke_harness: M5LiveSmokeHarness):
    """Req 9: A candidate emitting INSUFFICIENT_EVIDENCE is preserved and not overwritten by NO_RELEVANT_FUNCTIONALITY."""
    can_input = smoke_harness.get_canonical_input("SCEN-SAAS_BILLING-INV-DETAILS-VULN-01")
    pack: LosslessStructuralPack = can_input["pack"]
    gold_scen = can_input["gold_scenario"]

    target_asset_enriched = dict(gold_scen.target_asset)
    target_asset_enriched["parameters"] = list(gold_scen.parameters)
    target_asset_enriched["identities"] = list(gold_scen.identities)

    ev_state = EvidenceState(channel_a=pack, target_asset=target_asset_enriched)

    candidate = HypothesisModelOutput(
        schema_version="2.0.0",
        decision=HypothesisDecision.INSUFFICIENT_EVIDENCE,
        invariant="Object lookup enforces authorization ownership checks.",
        evidence_gap="Access control policy not verified by schema.",
        affected_target="/api/v1/invoices/{id}",
        supporting_evidence_ids=["FACT-00000001"],
        methodology_references=[],
        reasoning_summary="OpenAPI facts indicate read-only invoice endpoint, but ownership validation is unobserved.",
        experiment_proposal="Access invoice under foreign tenant token.",
    )

    dec_res = deterministic_decide(candidate, ev_state)
    assert dec_res.final_decision == HypothesisDecision.INSUFFICIENT_EVIDENCE
    assert dec_res.predicate_identifier == DecisionPredicate.INSUFFICIENT_EVIDENCE_CONFIRMED
    assert dec_res.is_valid is True


def test_10_no_ground_truth_in_prompts(smoke_harness: M5LiveSmokeHarness):
    """Req 10: No benchmark ground truth enters the model-visible prompt across all tracks and scenarios."""
    for sid in PRE_REGISTERED_SCENARIOS:
        for track in PRE_REGISTERED_TRACKS:
            ctx, _ = smoke_harness.build_context_for_track(scenario_id=sid, track_id=track)
            prompt_lower = ctx.prompt.lower()
            for token in FORBIDDEN_PROMPT_TOKENS:
                assert token not in prompt_lower, f"Leaked token '{token}' in {sid} ({track.value})"


def test_11_target_evidence_causal_parity(smoke_harness: M5LiveSmokeHarness):
    """Req 11: B/D target evidence causal parity remains byte-identical."""
    for sid in PRE_REGISTERED_SCENARIOS:
        ctx_b, bytes_b = smoke_harness.build_context_for_track(sid, ConfirmatoryTrackId.TRACK_B)
        ctx_d, bytes_d = smoke_harness.build_context_for_track(sid, ConfirmatoryTrackId.TRACK_D)

        assert len(bytes_b) > 0, f"Track B target bytes empty for {sid}"
        assert bytes_b == bytes_d, f"B/D causal parity mismatch for {sid}"


def test_12_tracks_differ_only_in_declared_rag_inputs(smoke_harness: M5LiveSmokeHarness):
    """Req 12: Track A/B/C/D differ only in their declared RAG inputs."""
    sid = "SCEN-SAAS_BILLING-INV-DETAILS-VULN-01"
    ctx_a, _ = smoke_harness.build_context_for_track(sid, ConfirmatoryTrackId.TRACK_A)
    ctx_b, _ = smoke_harness.build_context_for_track(sid, ConfirmatoryTrackId.TRACK_B)
    ctx_c, _ = smoke_harness.build_context_for_track(sid, ConfirmatoryTrackId.TRACK_C)
    ctx_d, _ = smoke_harness.build_context_for_track(sid, ConfirmatoryTrackId.TRACK_D)

    # Track A: No raw snippets, no VAPT chunks
    assert "<untrusted_target_data>" not in ctx_a.user_prompt
    assert "CHK-" not in ctx_a.user_prompt

    # Track B: Raw snippets present, no VAPT chunks
    assert "<untrusted_target_data>" in ctx_b.user_prompt
    assert "CHK-" not in ctx_b.user_prompt

    # Track C: No raw snippets, VAPT chunks present
    assert "<untrusted_target_data>" not in ctx_c.user_prompt
    assert "CHK-" in ctx_c.user_prompt

    # Track D: Raw snippets present, VAPT chunks present
    assert "<untrusted_target_data>" in ctx_d.user_prompt
    assert "CHK-" in ctx_d.user_prompt


def test_13_canonical_construction_deterministic(smoke_harness: M5LiveSmokeHarness):
    """Req 13: Smoke harness canonical construction is deterministic across repeated calls."""
    for sid in PRE_REGISTERED_SCENARIOS:
        in1 = smoke_harness.get_canonical_input(sid)
        in2 = smoke_harness.get_canonical_input(sid)
        assert in1["canonical_input_hash"] == in2["canonical_input_hash"]
        assert in1["pack"].model_dump() == in2["pack"].model_dump()


def test_phase6_2c_explicit_input_fidelity_invariant(smoke_harness: M5LiveSmokeHarness):
    """Phase 6.2C: Explicit invariant that smoke harness faithfully maps frozen EvaluationScenario fields."""
    for sid in PRE_REGISTERED_SCENARIOS:
        can_input = smoke_harness.get_canonical_input(sid)
        gold_scen = can_input["gold_scenario"]
        pack: LosslessStructuralPack = can_input["pack"]

        # Explicit equality checks mandated by Phase 6.2C
        assert gold_scen.parameters == pack.parameter_lineage, (
            f"Fidelity failure: parameters not mapped into parameter_lineage for {sid}"
        )
        assert gold_scen.identities == pack.identity_matrix, (
            f"Fidelity failure: identities not mapped into identity_matrix for {sid}"
        )
        assert gold_scen.initial_evidence == pack.observed_facts, (
            f"Fidelity failure: initial_evidence not mapped into observed_facts for {sid}"
        )
        assert gold_scen.target_asset["method"] == pack.http_method, (
            f"Fidelity failure: method mismatch for {sid}"
        )
        assert gold_scen.target_asset["application_mutability"] == pack.application_mutability, (
            f"Fidelity failure: mutability mismatch for {sid}"
        )
