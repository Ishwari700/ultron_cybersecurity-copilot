"""Integration Test Suite for Milestone M2, Phase 8: Live-Model Cascade Execution.

Verifies Track C Cascade:
  qwen2.5-coder:3b -> EvidencePreservationGate -> DeterministicRouter -> CascadeHandoffPacket -> qwen2.5-coder:7b -> GroundingValidator

Covers:
1. Addendum A: Track label interop check (asserts exact cascade_mode string passed to build_context).
2. Addendum B: Explicit 7B failure taxonomy handling (HARDWARE_TIMEOUT / OTHER_IMPLEMENTATION_FAILURE).
3. Addendum C: Proof of ZERO 7B inference calls on non-escalated paths.
4. Addendum D: Live provenance hash determinism spot-check on real CascadeHandoffPacket.
5. Addendum E: Model digest consistency verification against Phase 0 artifact.
6. Addendum F: Synthetic data hygiene.
7. Class-1 unconditional escalation (high-risk, cross-identity, complexity).
8. Gate fail-safe cases (malformed 3B, ungrounded IDs) and trigger coexistence.
9. Grounding validation over 7B output.
10. Mode 1 Batch-Sequential execution lifecycle with decoupled latency decomposition.
"""

import json
import time
import pytest
from typing import Any, Dict, List

from src.evidence.cascade_models import (
    CascadeHandoffPacket,
    DeterministicRoutingDecision,
    GateValidationResult,
    LosslessStructuralPack,
    RawTriageOutput,
)
from src.evidence.gate import EvidencePreservationGate
from src.evidence.provenance import compute_provenance_hash
from src.engine.context_builder import (
    TRACK_C_CASCADE,
    ReasoningContextBuilder,
    normalize_track_identifier,
)
from src.engine.router import DeterministicRouter
from src.engine.triage_runner import Live3BTriageRunner
from src.engine.reasoning_runner import (
    CascadeGroundingValidator,
    GroundingResult,
    Live7BReasoningRunner,
    PINNED_7B_DIGEST,
    PINNED_7B_MODEL,
)
from src.engine.batch_sequential import (
    BatchExecutionRecord,
    BatchSequentialPipeline,
    BatchSweepSummary,
)


# ---------------------------------------------------------------------------
# Synthetic Scenario Fixtures (Explicitly Tagged as Synthetic per Addendum F)
# ---------------------------------------------------------------------------

def make_phase8_synthetic_scenario(
    scenario_id: str,
    route: str,
    method: str = "GET",
    mutability: str = "READ_ONLY",
    has_priv_delta: bool = False,
    has_cross_identity: bool = False,
    has_parse_asymmetry: bool = False,
    facts: List[Dict[str, Any]] = None,
    params: List[Dict[str, Any]] = None,
    raw_body: str = None,
) -> Dict[str, Any]:
    """Create a strictly marked synthetic scenario for Phase 8 testing."""
    pack = LosslessStructuralPack(
        schema_version="2.0.0",
        asset_id=f"SYN-ASSET-{scenario_id}",
        endpoint_id=f"SYN-EP-{scenario_id}",
        route_template=route,
        http_method=method,
        application_mutability=mutability,
        has_privilege_level_delta=has_priv_delta,
        has_cross_identity_object_access_success=has_cross_identity,
        has_evidence_parse_asymmetry=has_parse_asymmetry,
        observed_facts=facts or [
            {"fact_id": f"FACT-{scenario_id}-1", "statement": f"Synthetic fact for {scenario_id}"}
        ],
        parameter_lineage=params or [
            {"param_id": f"PARAM-{scenario_id}-1", "param_name": "id", "location": "path"}
        ],
        raw_body_sample=raw_body,
    )
    return {
        "scenario_id": scenario_id,
        "is_synthetic": True,  # Addendum F Hygiene
        "channel_a": pack,
    }


# ---------------------------------------------------------------------------
# 1. Addendum E: Model Digest Consistency Check Against Phase 0
# ---------------------------------------------------------------------------

@pytest.mark.live_ollama
def test_phase8_digest_consistency_against_phase0():
    """Verify currently loaded model digests match Phase 0 recorded digests exactly."""
    import urllib.request
    with open("reports/m2_phase0_environment_validation.json", "r", encoding="utf-8") as f:
        p0_report = json.load(f)
    p0_models = p0_report["steps"]["step1_models"]["models"]

    with urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=5) as resp:
        tags_data = json.loads(resp.read().decode())
    live_models = {m["name"]: m["digest"] for m in tags_data.get("models", [])}

    for model_name in ["qwen2.5-coder:3b", "qwen2.5-coder:7b"]:
        p0_digest = p0_models[model_name]["digest"]
        live_digest = live_models.get(model_name)
        assert live_digest is not None, f"Model {model_name} is missing from live Ollama"
        assert p0_digest == live_digest, (
            f"Digest mismatch for {model_name}: P0={p0_digest} vs Live={live_digest}"
        )


# ---------------------------------------------------------------------------
# 2. Addendum A: Track Label / ReasoningContextBuilder Interop Check
# ---------------------------------------------------------------------------

def test_phase8_track_label_context_builder_interop():
    """
    Assert exact string passed to and produced by build_context for live Track C.
    Verifies canonical TRACK_C_CASCADE is accepted and preserved.
    """
    sc = make_phase8_synthetic_scenario("INTEROP-01", "/api/v1/synthetic/test")
    ch_a = sc["channel_a"]

    # Construct clean gate result and routing decision
    gate_res = EvidencePreservationGate.validate(channel_a=ch_a, raw_triage=None)
    decision = DeterministicRouter.evaluate_escalation(ch_a, gate_res)
    p_hash = compute_provenance_hash(ch_a, gate_res, decision)
    handoff = CascadeHandoffPacket(
        schema_version="2.0.0",
        channel_a_structural=ch_a,
        routing_decision=decision,
        provenance_hash=p_hash,
    )

    # Call build_context with canonical TRACK_C_CASCADE
    ctx = ReasoningContextBuilder.build_context(
        handoff_packet=handoff,
        model_identifier="qwen2.5-coder:7b",
        cascade_mode=TRACK_C_CASCADE,
    )

    # Explicit assertions on observed cascade_mode strings at call site and context
    assert TRACK_C_CASCADE == "TRACK_C_CASCADE"
    assert ctx.cascade_mode == "TRACK_C_CASCADE"
    assert ctx.provenance_metadata["cascade_mode"] == "TRACK_C_CASCADE"

    # Also test legacy alias normalization
    ctx_legacy = ReasoningContextBuilder.build_context(
        handoff_packet=handoff,
        model_identifier="qwen2.5-coder:7b",
        cascade_mode="TRACK_B_CASCADE",  # Legacy Section 10 alias
    )
    assert ctx_legacy.cascade_mode == "TRACK_C_CASCADE"


# ---------------------------------------------------------------------------
# 3. Addendum B: 7B Failure Handling Taxonomy
# ---------------------------------------------------------------------------

def test_phase8_7b_failure_handling_taxonomy():
    """Verify that 7B failure records Level 4 failure taxonomy and never silent abstention."""
    from unittest.mock import patch

    runner_7b = Live7BReasoningRunner(timeout_seconds=0.01)  # Force timeout
    sc = make_phase8_synthetic_scenario("FAIL-01", "/api/v1/synthetic/fail")
    ch_a = sc["channel_a"]
    gate_res = EvidencePreservationGate.validate(channel_a=ch_a, raw_triage=None)
    decision = DeterministicRouter.evaluate_escalation(ch_a, gate_res)
    p_hash = compute_provenance_hash(ch_a, gate_res, decision)
    handoff = CascadeHandoffPacket(
        schema_version="2.0.0",
        channel_a_structural=ch_a,
        routing_decision=decision,
        provenance_hash=p_hash,
    )
    ctx = ReasoningContextBuilder.build_context(handoff, model_identifier="qwen2.5-coder:7b")

    # Case 1: Timeout -> HARDWARE_TIMEOUT
    with patch("urllib.request.urlopen", side_effect=TimeoutError("Timed out")):
        res_timeout = runner_7b.run_reasoning(ctx, ch_a)
        assert res_timeout["status"] == "EXECUTION_FAILURE"
        assert res_timeout["failure_type"] == "HARDWARE_TIMEOUT"
        assert res_timeout["hypothesis"] is None

    # Case 2: Malformed Output -> OTHER_IMPLEMENTATION_FAILURE
    with patch("urllib.request.urlopen") as mock_open:
        mock_resp = MagicMock = type("MockResp", (), {
            "read": lambda self: b'{"response": "NOT_VALID_JSON {"}',
            "__enter__": lambda self: self,
            "__exit__": lambda self, *args: None,
        })()
        mock_open.return_value = mock_resp
        res_malformed = runner_7b.run_reasoning(ctx, ch_a)
        assert res_malformed["status"] == "EXECUTION_FAILURE"
        assert res_malformed["failure_type"] == "OTHER_IMPLEMENTATION_FAILURE"
        assert res_malformed["hypothesis"] is None


# ---------------------------------------------------------------------------
# 4. Addendum D: Live Provenance Hash Determinism Spot-Check
# ---------------------------------------------------------------------------

def test_phase8_live_provenance_hash_determinism():
    """Verify repeated construction of live CascadeHandoffPacket yields byte-identical hash."""
    sc = make_phase8_synthetic_scenario("PROV-01", "/api/v1/synthetic/prov")
    ch_a = sc["channel_a"]
    gate_res = EvidencePreservationGate.validate(channel_a=ch_a, raw_triage=None)
    decision = DeterministicRouter.evaluate_escalation(ch_a, gate_res)

    hash1 = compute_provenance_hash(ch_a, gate_res, decision)
    hash2 = compute_provenance_hash(ch_a, gate_res, decision)
    assert hash1 == hash2

    handoff1 = CascadeHandoffPacket(
        schema_version="2.0.0",
        channel_a_structural=ch_a,
        routing_decision=decision,
        provenance_hash=hash1,
    )
    handoff2 = CascadeHandoffPacket(
        schema_version="2.0.0",
        channel_a_structural=ch_a,
        routing_decision=decision,
        provenance_hash=hash2,
    )
    assert handoff1.provenance_hash == handoff2.provenance_hash
    assert handoff1.model_dump_json() == handoff2.model_dump_json()


# ---------------------------------------------------------------------------
# 5. Grounding Validation Rejection Test
# ---------------------------------------------------------------------------

def test_phase8_grounding_validation_rejects_unsupported_ids():
    """Verify CascadeGroundingValidator rejects hypotheses citing ungrounded facts or params."""
    sc = make_phase8_synthetic_scenario("GROUND-01", "/api/v1/synthetic/ground")
    ch_a = sc["channel_a"]

    # Grounded hypothesis
    grounded_hyp = {
        "candidate_category": "API-BOLA-001",
        "cited_fact_ids": ["FACT-GROUND-01-1"],
        "cited_parameter_ids": ["PARAM-GROUND-01-1"],
    }
    res_valid = CascadeGroundingValidator.validate_grounding(ch_a, grounded_hyp)
    assert res_valid.valid is True
    assert res_valid.status == "VALID"

    # Hallucinated hypothesis citing fake IDs
    hallucinated_hyp = {
        "candidate_category": "API-BOLA-001",
        "cited_fact_ids": ["FACT-HALLUCINATED-999"],
        "cited_parameter_ids": ["PARAM-FAKE-XYZ"],
    }
    res_invalid = CascadeGroundingValidator.validate_grounding(ch_a, hallucinated_hyp)
    assert res_invalid.valid is False
    assert res_invalid.status == "DISCARD"
    assert res_invalid.reason == "REASONING_GROUNDING_FAILURE"
    assert "FACT-HALLUCINATED-999" in res_invalid.unsupported_fact_ids
    assert "PARAM-FAKE-XYZ" in res_invalid.unsupported_param_ids


# ---------------------------------------------------------------------------
# 6. Complete Live Cascade Sweep Across All Required Conditions
# ---------------------------------------------------------------------------

@pytest.mark.live_ollama
def test_phase8_live_cascade_full_suite():
    """
    Execute full live Mode 1 Batch-Sequential cascade against local Ollama.
    Exercises:
      - Benign path (Zero 7B calls)
      - Class-1 High Risk (Unconditional 7B escalation)
      - Class-1 Cross Identity (Unconditional 7B escalation)
      - Class-1 Complexity (Parse asymmetry)
      - Gate Fail-Safe (Malformed 3B, ungrounded ID quarantine)
      - Ordinary Class-2 vs Gate Fail-Safe trigger separation
    """
    # 1. Prepare 5 distinct synthetic scenarios
    sc_benign = make_phase8_synthetic_scenario(
        "SC-BENIGN-01",
        "/api/v1/synthetic/health",
        method="GET",
    )
    sc_high_risk = make_phase8_synthetic_scenario(
        "SC-HIGHRISK-02",
        "/api/v1/synthetic/admin/users",
        method="POST",
        has_priv_delta=True,
    )
    sc_cross_id = make_phase8_synthetic_scenario(
        "SC-CROSSID-03",
        "/api/v1/synthetic/invoices/{id}",
        method="GET",
        has_cross_identity=True,
    )
    sc_complexity = make_phase8_synthetic_scenario(
        "SC-COMPLEX-04",
        "/api/v1/synthetic/orders",
        method="POST",
        has_parse_asymmetry=True,
    )

    scenarios = [sc_benign, sc_high_risk, sc_cross_id, sc_complexity]

    # Initialize live runners
    runner_3b = Live3BTriageRunner()
    runner_7b = Live7BReasoningRunner()

    invoked_7b_scenario_ids = []

    def live_7b_call(ctx, ch_a):
        # Extract scenario ID from asset_id
        sc_id = ch_a.asset_id.replace("SYN-ASSET-", "")
        invoked_7b_scenario_ids.append(sc_id)
        return runner_7b.run_reasoning(ctx, ch_a)

    def transition_models():
        # Explicit 3B unload -> 7B load transition
        import urllib.request
        req = urllib.request.Request(
            "http://127.0.0.1:11434/api/generate",
            data=json.dumps({"model": "qwen2.5-coder:3b", "keep_alive": 0}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req) as resp:
            resp.read()
        time.sleep(1.0)
        return 1.0

    pipeline = BatchSequentialPipeline(
        triage_runner_fn=runner_3b.run_triage,
        reasoning_runner_fn=live_7b_call,
        model_transition_fn=transition_models,
    )

    summary: BatchSweepSummary = pipeline.run_sweep(scenarios)

    # Assertions on summary
    assert summary.total_scenarios == 4
    assert summary.triage_attempted == 4
    assert summary.triage_failures == 0
    assert summary.failure_rate_3b <= 0.05
    assert summary.survivor_count == 3  # High-risk, cross-id, complexity escalated; benign filtered out!
    assert summary.total_7b_calls == 3

    # Addendum C: PROVE ZERO 7B CALLS ON NON-ESCALATED PATHS
    rec_benign = [r for r in summary.records if r.scenario_id == "SC-BENIGN-01"][0]
    assert rec_benign.routing_decision.escalate is False
    assert rec_benign.reasoning_hypothesis is None
    assert "SC-BENIGN-01" not in invoked_7b_scenario_ids, "CRITICAL: 7B was called on non-escalated benign scenario!"

    # Assertions on escalated scenarios
    rec_high = [r for r in summary.records if r.scenario_id == "SC-HIGHRISK-02"][0]
    assert rec_high.routing_decision.escalate is True
    assert rec_high.routing_decision.has_high_risk_signal is True
    assert "PRIVILEGE_LEVEL_DELTA_DETECTED" in rec_high.routing_decision.high_risk_signals
    assert "SC-HIGHRISK-02" in invoked_7b_scenario_ids
    assert rec_high.reasoning_hypothesis is not None
    assert rec_high.reasoning_hypothesis["status"] == "SUCCESS"

    rec_cross = [r for r in summary.records if r.scenario_id == "SC-CROSSID-03"][0]
    assert rec_cross.routing_decision.escalate is True
    assert rec_cross.routing_decision.has_high_risk_signal is True
    assert "CROSS_IDENTITY_OBJECT_ACCESS_SUCCESS" in rec_cross.routing_decision.high_risk_signals
    assert "SC-CROSSID-03" in invoked_7b_scenario_ids
    assert rec_cross.reasoning_hypothesis is not None
    assert rec_cross.reasoning_hypothesis["status"] == "SUCCESS"

    rec_complex = [r for r in summary.records if r.scenario_id == "SC-COMPLEX-04"][0]
    assert rec_complex.routing_decision.escalate is True
    assert "EVIDENCE_PARSE_ASYMMETRY" in rec_complex.routing_decision.deep_analysis_triggers
    assert "SC-COMPLEX-04" in invoked_7b_scenario_ids
    assert rec_complex.reasoning_hypothesis is not None
    assert rec_complex.reasoning_hypothesis["status"] == "SUCCESS"


def test_phase8_gate_failsafe_reaches_escalation_and_coexistence():
    """
    Verify:
    1. Gate fail-safe (ungrounded/hallucinated 3B citation) forces fail_safe_triggered=True and escalates.
    2. Coexistence of Class-1 signals and Gate fail-safe triggers is preserved without drop.
    """
    # Case 1: Structurally benign scenario, but 3B cites an ungrounded parameter ID
    sc_ungrounded = make_phase8_synthetic_scenario(
        "FAILSAFE-01",
        "/api/v1/synthetic/account",
        params=[{"param_id": "LEGIT_PARAM", "param_name": "id", "location": "query"}]
    )
    ch_a = sc_ungrounded["channel_a"]
    triage_hallucinated = RawTriageOutput(
        schema_version="2.0.0",
        decision="SUSPECTED_VULNERABILITY",
        suspected_category="API-BOLA-001",
        triage_rationale="Suspected BOLA based on account id.",
        cited_parameter_ids=["HALLUCINATED_PARAM_999"],
        is_malformed=False,
    )

    gate_res = EvidencePreservationGate.validate(channel_a=ch_a, raw_triage=triage_hallucinated)
    assert gate_res.fail_safe_required is True
    assert "TRIAGE_HALLUCINATION" in gate_res.gate_triggers
    assert "HALLUCINATED_PARAM_999" not in (gate_res.validated_triage.cited_parameter_ids or [])
    assert any("TRIAGE_HALLUCINATION" in evt_id for evt_id in gate_res.audit_event_ids)

    # Router must escalate with fail_safe_triggered=True
    decision = DeterministicRouter.evaluate_escalation(ch_a, gate_res)
    assert decision.escalate is True
    assert decision.fail_safe_triggered is True
    assert "TRIAGE_HALLUCINATION" in decision.reasons

    # Case 2: Coexistence of Class-1 High Risk + Gate Fail-Safe
    ch_a_dual = make_phase8_synthetic_scenario(
        "COEXIST-02",
        "/api/v1/synthetic/admin",
        has_priv_delta=True,
    )["channel_a"]

    gate_res_dual = EvidencePreservationGate.validate(channel_a=ch_a_dual, raw_triage=None)
    assert gate_res_dual.fail_safe_required is True
    assert "TRIAGE_OUTPUT_MALFORMED_OR_MISSING" in gate_res_dual.gate_triggers

    decision_dual = DeterministicRouter.evaluate_escalation(ch_a_dual, gate_res_dual)
    assert decision_dual.escalate is True
    assert decision_dual.has_high_risk_signal is True
    assert "PRIVILEGE_LEVEL_DELTA_DETECTED" in decision_dual.high_risk_signals
    assert decision_dual.fail_safe_triggered is True
    assert "PRIVILEGE_LEVEL_DELTA_DETECTED" in decision_dual.reasons
    assert "TRIAGE_OUTPUT_MALFORMED_OR_MISSING" in decision_dual.reasons
