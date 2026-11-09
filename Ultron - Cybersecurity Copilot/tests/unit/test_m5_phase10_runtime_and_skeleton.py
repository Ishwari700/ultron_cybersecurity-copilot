"""
Unit Tests for Phase 10: Runtime Control, Deterministic Skeleton, Preflight & Matrix Integrity.

Comprehensive 25-point test suite covering:
 1. HTTP timeout configuration
 2. Absolute wall-clock timeout
 3. Timeout cancellation
 4. Connection/socket closure behavior
 5. RUNTIME_TIMEOUT classification
 6. Timeout does not become parser/schema/grounding failure
 7. Total latency telemetry
 8. Prompt-build latency telemetry
 9. Parse latency telemetry
10. Validation latency telemetry
11. eval_duration conversion (nanoseconds -> milliseconds)
12. Exact 'unavailable' fallback for missing eval_duration
13. Deterministic category -> action mapping
14. LLM action override blocked
15. Flat legal_outcomes vocabulary
16. Breach/safe partition never exposed
17. Ground-truth never exposed
18. Evidence equivalence across paired conditions
19. Checkpoint determinism and atomic write
20. Duplicate-call prevention
21. Semantic/protocol failure separation
22. Historical artifact immutability
23. 84-scenario population integrity (36 vuln, 48 ctrl)
24. 336-call matrix integrity (4 conditions x 84 scenarios)
25. Hard teardown tolerance boundary (>30,500ms failure)
"""

from collections import Counter
import hashlib
import json
from pathlib import Path
import tempfile
import time
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import httpx
import pytest

repo_root = Path(__file__).resolve().parent.parent.parent

from src.core.config import OllamaConfig
from src.engine.context_builder import ReasoningContextBuilder, TRACK_A, TRACK_D
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
    FailureClassificationResult,
    HypothesisDecision,
    M5ExecutionResult,
    OutputProtocolIdentifier,
    PrimaryFailureCategory,
    classify_primary_failure,
)
from src.engine.prompts import get_counterfactual_template
from src.engine.protocol import (
    ReasoningExecutionContract,
    get_protocol_contract,
    validate_reasoning_contract,
)
from src.engine.runner import (
    PRIMARY_KEEP_ALIVE,
    PRIMARY_NUM_CTX,
    PRIMARY_NUM_PREDICT,
    PRIMARY_SEED,
    PRIMARY_TEMPERATURE,
    OllamaRunner,
    ReasoningRunner,
)
from src.eval.m4_live_benchmark import (
    ConfirmatoryTrackId,
    FORBIDDEN_PROMPT_TOKENS,
    EXPECTED_7B_DIGEST_FULL,
    infer_evidence_gap_type,
)
from src.eval.run_m5_phase10_benchmark import (
    M5Phase10BenchmarkRunner,
    PHASE10_CONDITIONS,
    FROZEN_ORDER_RANDOMIZATION_SEED,
    get_deterministic_condition_order,
)
from src.eval.scenarios import get_gold_set_scenarios
from src.eval.verify_m5_phase10_preflight import (
    FROZEN_HISTORICAL_HASHES,
    hash_file,
    run_phase10_preflight_gates,
)
from src.evidence.cascade_models import (
    CascadeHandoffPacket,
    DeterministicRoutingDecision,
    LosslessStructuralPack,
)
from src.knowledge.grounding_validator import KnowledgeGroundingValidator
from src.knowledge.pipeline import VaptReasoningPipeline


def _create_valid_test_contract() -> ReasoningExecutionContract:
    """Helper to build a fully compliant ReasoningExecutionContract for testing."""
    pack = LosslessStructuralPack(
        schema_version="2.0.0",
        asset_id="ASSET-TEST-01",
        endpoint_id="EP-TEST-01",
        route_template="/api/v1/resource/{id}",
        http_method="GET",
        application_mutability="READ_ONLY",
        parameter_lineage=[{"location": "path", "param_name": "id", "param_type": "string"}],
        identity_matrix=[{"identity_id": "user_a", "role": "customer"}],
        has_privilege_level_delta=False,
        has_cross_identity_object_access_success=False,
        observed_facts=[{"fact_id": "F1", "statement": "Target observed data"}],
        raw_body_sample="",
    )
    routing = DeterministicRoutingDecision(
        schema_version="2.0.0",
        escalate=True,
        has_high_risk_signal=True,
        fail_safe_triggered=False,
    )
    handoff = CascadeHandoffPacket(
        schema_version="2.0.0",
        channel_a_structural=pack,
        routing_decision=routing,
        provenance_hash="prov_test",
    )
    cat_tmpl = get_counterfactual_template("API-BOLA-001")
    gap_type = infer_evidence_gap_type("API-BOLA-001")
    active_desc = HandoffSerializer.from_cascade_packet(handoff, gap_type, cat_tmpl.invariant_definition)
    ctx = ReasoningContextBuilder().build_context(
        handoff_packet=handoff,
        model_identifier="qwen2.5-coder:7b",
        budget_tier=4096,
        cascade_mode=TRACK_A,
        enable_i2_namespace_partitioning=True,
        enable_i3_counterfactual_prompting=True,
        category_id="API-BOLA-001",
        enable_i4_bair=True,
        enable_i5_decision_policy=True,
        enable_i6_handoff=True,
        protected_handoff=active_desc,
        output_protocol=OutputProtocolIdentifier.JSON_BAIR,
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
        category_id="API-BOLA-001",
    )
    validate_reasoning_contract(contract)
    return contract


# ===========================================================================
# 1. HTTP Timeout Configuration
# ===========================================================================

def test_01_http_timeout_configuration():
    """Verify OllamaRunner and OllamaConfig enforce 30.0s timeout."""
    cfg = OllamaConfig()
    assert cfg.request_timeout_seconds == 30
    assert cfg.max_retries == 0

    runner = OllamaRunner(timeout_seconds=30.0)
    assert runner.timeout_seconds == 30.0

    with patch("httpx.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"response": "{}", "eval_duration": 500000000}
        mock_client.post.return_value = mock_resp

        runner.generate_raw("test prompt", schema=None)

        # Verify Client was initialized with httpx.Timeout(30.0, connect=5.0, read=30.0, write=5.0)
        mock_client_cls.assert_called_once()
        timeout_arg = mock_client_cls.call_args[1]["timeout"]
        assert isinstance(timeout_arg, httpx.Timeout)
        assert timeout_arg.connect == 5.0
        assert timeout_arg.read == 30.0
        assert timeout_arg.write == 5.0


# ===========================================================================
# 2. Absolute Wall-Clock Timeout
# ===========================================================================

def test_02_absolute_wall_clock_timeout():
    """Verify wall-clock ceiling raises TimeoutError and aborts."""
    runner = OllamaRunner(timeout_seconds=0.1)

    with patch("httpx.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client

        def slow_post(*args, **kwargs):
            time.sleep(0.15)
            raise httpx.ReadTimeout("Read timed out")

        mock_client.post.side_effect = slow_post

        with pytest.raises(TimeoutError) as exc_info:
            runner.generate_raw("test prompt")
        assert "Hard runtime ceiling exceeded" in str(exc_info.value)


# ===========================================================================
# 3. Timeout Cancellation
# ===========================================================================

def test_03_timeout_cancellation():
    """Verify request aborts cleanly on timeout exception."""
    runner = OllamaRunner(timeout_seconds=0.05)

    with patch("httpx.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.post.side_effect = httpx.TimeoutException("Connection timed out")

        with pytest.raises(TimeoutError):
            runner.generate_raw("test")


# ===========================================================================
# 4. Connection/Socket Closure Behavior
# ===========================================================================

def test_04_connection_socket_closure_behavior():
    """Verify client.close() is called to abort runner slot upon timeout."""
    runner = OllamaRunner(timeout_seconds=0.05)

    with patch("httpx.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.post.side_effect = httpx.ReadTimeout("Read timed out")

        with pytest.raises(TimeoutError):
            runner.generate_raw("test")

        # Must close client to release socket and cancel Ollama Go context
        assert mock_client.close.called


# ===========================================================================
# 5. RUNTIME_TIMEOUT Classification
# ===========================================================================

def test_05_runtime_timeout_classification():
    """Verify timeout is explicitly classified as RUNTIME_TIMEOUT."""
    res1 = classify_primary_failure(is_timeout=True)
    assert res1.primary_category == PrimaryFailureCategory.RUNTIME_TIMEOUT
    assert not res1.is_valid

    res2 = classify_primary_failure(transport_error=TimeoutError("Wall-clock ceiling exceeded"))
    assert res2.primary_category == PrimaryFailureCategory.RUNTIME_TIMEOUT
    assert not res2.is_valid

    res3 = classify_primary_failure(transport_error=httpx.ReadTimeout("Read timed out"))
    assert res3.primary_category == PrimaryFailureCategory.RUNTIME_TIMEOUT
    assert not res3.is_valid


# ===========================================================================
# 6. Timeout Precedence: Never Masquerades as Other Failures
# ===========================================================================

def test_06_timeout_precedence_over_all_failures():
    """Verify timeout takes precedence over parser, schema, and grounding errors."""
    res = classify_primary_failure(
        is_timeout=True,
        transport_error=TimeoutError("Ceiling exceeded"),
        parse_error=json.JSONDecodeError("Unterminated string", "", 0),
        schema_error=ValueError("Missing required field 'experiment_action'"),
        grounding_error="Fact ungrounded in target context",
        polarity_error="Invalid polarity",
    )
    assert res.primary_category == PrimaryFailureCategory.RUNTIME_TIMEOUT
    assert res.primary_category != PrimaryFailureCategory.PARSER_FAILURE
    assert res.primary_category != PrimaryFailureCategory.SCHEMA_VALIDITY_FAILURE
    assert res.primary_category != PrimaryFailureCategory.SEMANTIC_GROUNDING_FAILURE


# ===========================================================================
# 7. Total Latency Telemetry
# ===========================================================================

def test_07_total_latency_telemetry():
    """Verify total_latency_ms is recorded and represents overall execution."""
    contract = _create_valid_test_contract()

    def mock_caller(prompt, schema):
        time.sleep(0.02)
        return json.dumps({
            "decision": "INSUFFICIENT_EVIDENCE",
            "reasoning": "Neutral",
            "experiment_action": None,
            "supporting_outcome": None,
            "disproving_outcome": None,
        })

    runner = ReasoningRunner(model_name="qwen2.5-coder:7b", llm_caller=mock_caller)
    res = runner.execute_m5_generation(contract=contract)
    assert res.total_latency_ms > 15.0
    assert res.total_latency_ms == res.latency_ms


# ===========================================================================
# 8. Prompt-Build Latency Telemetry
# ===========================================================================

def test_08_prompt_build_latency_telemetry():
    """Verify prompt_build_latency_ms is populated and >= 0.0."""
    contract = _create_valid_test_contract()

    runner = ReasoningRunner(
        model_name="qwen2.5-coder:7b",
        llm_caller=lambda p, s: json.dumps({
            "invariant": "Resource access must be restricted to resource owner",
            "evidence_gap": "None",
            "decision": "INSUFFICIENT_EVIDENCE",
            "reasoning_summary": "Neutral",
            "experiment_action": None,
            "supporting_outcome": None,
            "disproving_outcome": None,
        }),
    )
    res = runner.execute_m5_generation(contract=contract)
    assert res.prompt_build_latency_ms is not None
    assert res.prompt_build_latency_ms >= 0.0


# ===========================================================================
# 9. Response Parse Latency Telemetry
# ===========================================================================

def test_09_response_parse_latency_telemetry():
    """Verify response_parse_latency_ms measures JSON parsing time."""
    contract = _create_valid_test_contract()

    runner = ReasoningRunner(
        model_name="qwen2.5-coder:7b",
        llm_caller=lambda p, s: json.dumps({
            "invariant": "Resource access must be restricted to resource owner",
            "evidence_gap": "None",
            "decision": "INSUFFICIENT_EVIDENCE",
            "reasoning_summary": "Neutral",
            "experiment_action": None,
            "supporting_outcome": None,
            "disproving_outcome": None,
        }),
    )
    res = runner.execute_m5_generation(contract=contract)
    assert res.response_parse_latency_ms is not None
    assert res.response_parse_latency_ms >= 0.0


# ===========================================================================
# 10. Validation Latency Telemetry
# ===========================================================================

def test_10_validation_latency_telemetry():
    """Verify validation_latency_ms measures schema/grounding validation time."""
    contract = _create_valid_test_contract()

    runner = ReasoningRunner(
        model_name="qwen2.5-coder:7b",
        llm_caller=lambda p, s: json.dumps({
            "invariant": "Resource access must be restricted to resource owner",
            "evidence_gap": "None",
            "decision": "INSUFFICIENT_EVIDENCE",
            "reasoning_summary": "Neutral",
            "experiment_action": None,
            "supporting_outcome": None,
            "disproving_outcome": None,
        }),
    )
    res = runner.execute_m5_generation(contract=contract)
    assert res.validation_latency_ms is not None
    assert res.validation_latency_ms >= 0.0


# ===========================================================================
# 11. eval_duration Conversion
# ===========================================================================

def test_11_eval_duration_conversion():
    """Verify eval_duration in nanoseconds is accurately converted to milliseconds."""
    contract = _create_valid_test_contract()
    runner = ReasoningRunner(model_name="qwen2.5-coder:7b")

    # Mock OllamaRunner.generate_raw returning eval_duration = 2_450_000_000 ns (2450.0 ms)
    with patch.object(runner.ollama_runner, "generate_raw") as mock_gen:
        mock_gen.return_value = {
            "response": json.dumps({
                "decision": "INSUFFICIENT_EVIDENCE",
                "reasoning": "Neutral",
                "experiment_action": None,
                "supporting_outcome": None,
                "disproving_outcome": None,
            }),
            "eval_duration": 2450000000,
            "eval_count": 50,
            "prompt_eval_count": 200,
        }
        res = runner.execute_m5_generation(contract=contract)
        assert res.inference_latency_ms == 2450.0


# ===========================================================================
# 12. Exact "unavailable" Fallback
# ===========================================================================

def test_12_exact_unavailable_fallback():
    """Verify missing or zero eval_duration falls back to 'unavailable' string."""
    contract = _create_valid_test_contract()
    runner = ReasoningRunner(model_name="qwen2.5-coder:7b")

    # Case A: eval_duration is None
    with patch.object(runner.ollama_runner, "generate_raw") as mock_gen:
        mock_gen.return_value = {
            "response": json.dumps({
                "decision": "INSUFFICIENT_EVIDENCE",
                "reasoning": "Neutral",
                "experiment_action": None,
                "supporting_outcome": None,
                "disproving_outcome": None,
            }),
            "eval_duration": None,
        }
        res = runner.execute_m5_generation(contract=contract)
        assert res.inference_latency_ms == "unavailable"

    # Case B: On timeout
    with patch.object(runner.ollama_runner, "generate_raw") as mock_gen:
        mock_gen.side_effect = TimeoutError("Deadline exceeded")
        res = runner.execute_m5_generation(contract=contract)
        assert res.timed_out
        assert res.inference_latency_ms == "unavailable"


# ===========================================================================
# 13. Deterministic Category -> Action Mapping
# ===========================================================================

def test_13_deterministic_category_action_mapping():
    """Verify all 10 benchmark scenario categories resolve deterministic legal actions."""
    gold_scenarios = get_gold_set_scenarios()
    categories = sorted(list(set(s.category_id for s in gold_scenarios)))
    assert len(categories) == 10

    expected_actions = {
        "API-AUTH-NONE": "INVOKE_WITHOUT_CREDENTIALS",
        "API-BFLA-001": "REPLAY_STEP_WITH_LOWER_ROLE",
        "API-BOLA-001": "SUBSTITUTE_RESOURCE_IDENTIFIER",
        "API-CROSS-TENANT-001": "SUBSTITUTE_RESOURCE_IDENTIFIER",
        "API-DEVICE-BOLA-001": "SUBSTITUTE_RESOURCE_IDENTIFIER",
        "API-LIFECYCLE-001": "EXECUTE_OUT_OF_ORDER_TRANSITION",
        "API-MULTI-STEP-AUTH-001": "EXECUTE_OUT_OF_ORDER_TRANSITION",
        "API-MUTATION-001": "TAMPER_REQUEST_PARAMETER",
        "API-ROLE-BOUNDARY-001": "REPLAY_STEP_WITH_LOWER_ROLE",
        "API-STATE-001": "EXECUTE_OUT_OF_ORDER_TRANSITION",
    }

    for cat in categories:
        skeleton = ExperimentSkeletonBuilder.build_skeleton(cat)
        assert skeleton.experiment_action == expected_actions[cat], (
            f"Action mismatch for {cat}: {skeleton.experiment_action} != {expected_actions[cat]}"
        )


# ===========================================================================
# 14. LLM Action Override Blocked
# ===========================================================================

def test_14_llm_action_override_blocked():
    """Verify validator rejects hypothesis when candidate alters skeleton action."""
    skeleton = ExperimentSkeletonBuilder.build_skeleton("API-BOLA-001")
    assert skeleton.experiment_action == "SUBSTITUTE_RESOURCE_IDENTIFIER"

    # LLM attempts to substitute a different action
    overridden_action = "REPLAY_STEP_WITH_LOWER_ROLE"
    valid, msg = validate_skeleton_compliance(
        skeleton=skeleton,
        candidate_action=overridden_action,
        candidate_supporting=skeleton.legal_outcomes[0],
        candidate_disproving=skeleton.legal_outcomes[1],
    )
    assert not valid
    assert "mismatch" in msg.lower()
    assert "SUBSTITUTE_RESOURCE_IDENTIFIER" in msg


# ===========================================================================
# 15. Flat legal_outcomes Vocabulary
# ===========================================================================

def test_15_flat_legal_outcomes_vocabulary():
    """Verify legal_outcomes is a flat, unpartitioned, alphabetically sorted list."""
    for cat in ["API-BOLA-001", "API-STATE-001", "API-BFLA-001", "API-CROSS-TENANT-001"]:
        skeleton = ExperimentSkeletonBuilder.build_skeleton(cat)
        assert isinstance(skeleton.legal_outcomes, list)
        assert len(skeleton.legal_outcomes) >= 2
        # Check alphabetical sorting
        assert skeleton.legal_outcomes == sorted(skeleton.legal_outcomes)
        # Check all entries are non-empty strings
        for outcome in skeleton.legal_outcomes:
            assert isinstance(outcome, str) and len(outcome) > 0


# ===========================================================================
# 16. Breach/Safe Partition Never Exposed
# ===========================================================================

def test_16_breach_safe_partition_never_exposed():
    """Verify rendered skeleton prompt block never contains partition labels."""
    for cat in ["API-BOLA-001", "API-STATE-001", "API-BFLA-001", "API-CROSS-TENANT-001"]:
        skeleton = ExperimentSkeletonBuilder.build_skeleton(cat)
        block = render_skeleton_prompt_block(skeleton)
        block_lower = block.lower()

        assert "breach_outcomes" not in block_lower
        assert "safe_outcomes" not in block_lower
        assert "valid_breaches" not in block_lower
        assert "valid_safes" not in block_lower
        assert "partition" not in block_lower


# ===========================================================================
# 17. Ground-Truth Never Exposed in Prompts
# ===========================================================================

def test_17_ground_truth_never_exposed_in_prompts():
    """Verify forbidden ground-truth tokens are strictly absent from prompts."""
    scenarios = get_gold_set_scenarios()
    builder = ReasoningContextBuilder()

    for scen in scenarios[:5]:
        observed_facts = scen.initial_evidence or [{"fact_id": "F1", "statement": "Target data"}]
        asset_id = scen.target_asset.get("asset_id", "ASSET-01")
        pack = LosslessStructuralPack(
            schema_version="2.0.0",
            asset_id=asset_id,
            endpoint_id=f"EP-{asset_id}",
            route_template=scen.target_asset.get("normalized_path", "/api/v1/test"),
            http_method=scen.target_asset.get("method", "GET"),
            application_mutability="READ_ONLY",
            parameter_lineage=scen.parameters,
            identity_matrix=scen.identities,
            has_privilege_level_delta=False,
            has_cross_identity_object_access_success=False,
            observed_facts=observed_facts,
            raw_body_sample="",
        )
        handoff = CascadeHandoffPacket(
            schema_version="2.0.0",
            channel_a_structural=pack,
            routing_decision=DeterministicRoutingDecision(
                schema_version="2.0.0",
                escalate=True,
                has_high_risk_signal=True,
                fail_safe_triggered=False,
            ),
            provenance_hash="prov_test",
        )
        cat_tmpl = get_counterfactual_template(scen.category_id)
        gap_type = infer_evidence_gap_type(scen.category_id)
        active_desc = HandoffSerializer.from_cascade_packet(handoff, gap_type, cat_tmpl.invariant_definition)

        ctx = builder.build_context(
            handoff_packet=handoff,
            model_identifier="qwen2.5-coder:7b",
            budget_tier=2048,
            cascade_mode=TRACK_A,
            enable_i2_namespace_partitioning=True,
            enable_i3_counterfactual_prompting=True,
            category_id=scen.category_id,
            enable_i4_bair=True,
            enable_i5_decision_policy=True,
            enable_i6_handoff=True,
            protected_handoff=active_desc,
            output_protocol=OutputProtocolIdentifier.JSON_BAIR,
        )

        prompt_lower = (ctx.system_prompt + " " + ctx.user_prompt).lower()
        for token in FORBIDDEN_PROMPT_TOKENS:
            assert token not in prompt_lower, f"Forbidden token '{token}' in prompt for {scen.scenario_id}"


# ===========================================================================
# 18. Evidence Equivalence Across Paired Conditions
# ===========================================================================

def test_18_evidence_equivalence_across_paired_conditions():
    """Verify Channel A structural pack and evidence hash are identical across conditions."""
    runner = M5Phase10BenchmarkRunner()
    for scen in runner.gold_scenarios[:10]:
        canon1 = runner.get_canonical_input(scen.scenario_id)
        canon2 = runner.get_canonical_input(scen.scenario_id)

        assert canon1["canonical_evidence_hash"] == canon2["canonical_evidence_hash"]
        assert canon1["target_context_hash"] == canon2["target_context_hash"]
        assert canon1["pack"].model_dump() == canon2["pack"].model_dump()


# ===========================================================================
# 19. Checkpoint Determinism & Atomic Write
# ===========================================================================

def test_19_checkpoint_determinism_and_atomic_write():
    """Verify checkpoint save/load preserves byte-for-byte JSON fidelity atomically."""
    with tempfile.TemporaryDirectory() as tmpdir:
        chk_path = Path(tmpdir) / "test_checkpoint.json"
        runner = M5Phase10BenchmarkRunner(checkpoint_path=chk_path)

        dummy_records = [
            {"condition_id": "C1", "scenario_id": "SCEN-01", "is_valid": True},
            {"condition_id": "C2", "scenario_id": "SCEN-01", "is_valid": False},
        ]
        runner.save_checkpoint(dummy_records)
        assert chk_path.exists()

        loaded = runner.load_checkpoint()
        assert loaded == dummy_records


# ===========================================================================
# 20. Duplicate-Call Prevention
# ===========================================================================

def test_20_duplicate_call_prevention():
    """Verify completed condition-scenario pairs are skipped and never re-executed."""
    with tempfile.TemporaryDirectory() as tmpdir:
        chk_path = Path(tmpdir) / "test_checkpoint.json"
        call_counter = {"calls": 0}

        def mock_llm(prompt, schema):
            call_counter["calls"] += 1
            return json.dumps({
                "decision": "INSUFFICIENT_EVIDENCE",
                "reasoning": "Neutral",
                "experiment_action": None,
                "supporting_outcome": None,
                "disproving_outcome": None,
            })

        runner = M5Phase10BenchmarkRunner(
            llm_caller=mock_llm,
            checkpoint_path=chk_path,
        )

        # Pre-seed checkpoint with 1 completed call: (first condition of first scenario, first scenario)
        first_scen_id = runner.gold_scenarios[0].scenario_id
        first_order = get_deterministic_condition_order(first_scen_id, runner.order_seed)
        first_cond = first_order[0]
        second_cond = first_order[1]

        pre_seeded = [{
            "call_index": 1,
            "condition_id": first_cond.condition_id,
            "architecture": first_cond.architecture,
            "track_id": first_cond.track_id.value,
            "scenario_id": first_scen_id,
            "category_id": runner.gold_scenarios[0].category_id,
            "vulnerable_variant": runner.gold_scenarios[0].vulnerable_variant,
            "scenario_condition_order": [c.condition_id for c in first_order],
            "condition_order_index": 1,
            "order_randomization_seed": runner.order_seed,
            "raw_response": "{}",
            "timed_out": False,
            "prompt_build_latency_ms": 1.0,
            "inference_latency_ms": "unavailable",
            "response_parse_latency_ms": 1.0,
            "validation_latency_ms": 1.0,
            "total_latency_ms": 10.0,
            "eval_count": 10,
            "prompt_eval_count": 50,
            "contract_valid": True,
            "is_valid": True,
            "primary_failure_category": "VALID",
            "candidate_decision": "INSUFFICIENT_EVIDENCE",
            "final_decision": "HypothesisDecision.INSUFFICIENT_EVIDENCE",
            "experiment_action": None,
            "supporting_outcome": None,
            "disproving_outcome": None,
            "skeleton_compliant": None,
            "skeleton_reason": None,
            "polarity_valid": False,
            "polarity_reason": None,
            "grounding_valid": True,
            "is_valid_typed_experiment": False,
            "applicability_state": "EVAL_APPLICABLE_INSUFFICIENT_EVIDENCE",
            "is_useful_hypothesis": False,
            "timestamp": "2026-09-22T00:00:00Z",
        }]
        runner.save_checkpoint(pre_seeded)

        # Run benchmark with max_calls=2 (so it should execute exactly 1 more call)
        with patch("src.eval.run_m5_phase10_benchmark.run_phase10_preflight_gates"):
            records = runner.run_benchmark(require_live_ollama=False, max_calls=2)

        # The first condition for first_scen_id was skipped; call_counter must be 1, total records 2
        assert call_counter["calls"] == 1
        assert len(records) == 2
        assert records[0]["condition_id"] == first_cond.condition_id
        assert records[0]["scenario_id"] == first_scen_id
        assert records[1]["condition_id"] == second_cond.condition_id
        assert records[1]["scenario_id"] == first_scen_id


# ===========================================================================
# 21. Semantic / Protocol Failure Separation
# ===========================================================================

def test_21_semantic_protocol_failure_separation():
    """Verify protocol failures (e.g. RUNTIME_TIMEOUT) cannot produce valid typed experiments."""
    contract = _create_valid_test_contract()
    runner = ReasoningRunner(model_name="qwen2.5-coder:7b")

    # Simulate timeout
    with patch.object(runner.ollama_runner, "generate_raw", side_effect=TimeoutError("Wall-clock ceiling exceeded")):
        res = runner.execute_m5_generation(contract=contract)
        assert res.timed_out
        assert res.classification.primary_category == PrimaryFailureCategory.RUNTIME_TIMEOUT
        assert not res.classification.is_valid
        assert res.canonical_hypothesis is None


# ===========================================================================
# 22. Historical Artifact Immutability
# ===========================================================================

def test_22_historical_artifact_immutability():
    """Verify SHA-256 digests of all 4 frozen historical files match exact constants."""
    for rel_path, expected_sha in FROZEN_HISTORICAL_HASHES.items():
        abs_path = repo_root / rel_path
        assert abs_path.exists(), f"Frozen file missing: {rel_path}"
        actual_sha = hash_file(abs_path)
        assert actual_sha == expected_sha, (
            f"Immutability breach in {rel_path}!\n  Expected: {expected_sha}\n  Actual:   {actual_sha}"
        )


# ===========================================================================
# 23. 84-Scenario Population Integrity
# ===========================================================================

def test_23_population_integrity():
    """Verify benchmark population is exactly 84 scenarios (36 vulnerable, 48 controls)."""
    scenarios = get_gold_set_scenarios()
    assert len(scenarios) == 84

    vuln = [s for s in scenarios if s.vulnerable_variant]
    ctrl = [s for s in scenarios if not s.vulnerable_variant]
    assert len(vuln) == 36
    assert len(ctrl) == 48

    ids = [s.scenario_id for s in scenarios]
    assert len(ids) == len(set(ids))


# ===========================================================================
# 24. 336-Call Matrix Integrity
# ===========================================================================

def test_24_336_call_matrix_integrity():
    """Verify scheduled 2x2 factorial matrix has exactly 336 calls with deterministic order."""
    assert len(PHASE10_CONDITIONS) == 4
    cond_ids = [c.condition_id for c in PHASE10_CONDITIONS]
    assert cond_ids == ["C1", "C2", "C3", "C4"]

    scenarios = sorted(get_gold_set_scenarios(), key=lambda s: s.scenario_id)
    assert len(scenarios) == 84

    planned_matrix = [
        (cond.condition_id, scen.scenario_id)
        for cond in PHASE10_CONDITIONS
        for scen in scenarios
    ]
    assert len(planned_matrix) == 336
    assert len(planned_matrix) == len(set(planned_matrix))


# ===========================================================================
# 25. Hard Teardown Tolerance Boundary (>30,500ms Failure)
# ===========================================================================

def test_25_hard_teardown_tolerance_boundary():
    """Verify elapsed inference beyond ceiling + 500ms fails with RUNTIME_TIMEOUT."""
    runner = OllamaRunner(timeout_seconds=1.0)

    with patch("httpx.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client

        # Mock returns 200 after 1.55s (exceeding 1.0s + 0.5s = 1.5s teardown tolerance)
        def delayed_post(*args, **kwargs):
            time.sleep(1.55)
            mock_res = MagicMock()
            mock_res.status_code = 200
            mock_res.json.return_value = {"response": "{}", "eval_duration": 100}
            return mock_res

        mock_client.post.side_effect = delayed_post

        with pytest.raises(TimeoutError) as exc_info:
            runner.generate_raw("test")

        assert "teardown tolerance 500ms" in str(exc_info.value)


# ===========================================================================
# 26. Deterministic Condition Order Reproducibility
# ===========================================================================

def test_26_deterministic_condition_order_reproducibility():
    """Verify same scenario + same frozen seed => 100% identical ordering every time."""
    scenarios = get_gold_set_scenarios()
    for scen in scenarios[:15]:
        order_baseline = [
            c.condition_id
            for c in get_deterministic_condition_order(scen.scenario_id, FROZEN_ORDER_RANDOMIZATION_SEED)
        ]
        for _ in range(25):
            repeated = [
                c.condition_id
                for c in get_deterministic_condition_order(scen.scenario_id, FROZEN_ORDER_RANDOMIZATION_SEED)
            ]
            assert repeated == order_baseline, f"Non-reproducible condition order for {scen.scenario_id}"


# ===========================================================================
# 27. Deterministic Condition Order Diversity Across Scenarios
# ===========================================================================

def test_27_deterministic_condition_order_diversity():
    """Verify different scenario IDs produce different condition orderings (de-biasing execution order)."""
    scenarios = get_gold_set_scenarios()
    unique_orders = set()
    first_position_counts = Counter()

    for scen in scenarios:
        order = tuple(
            c.condition_id
            for c in get_deterministic_condition_order(scen.scenario_id, FROZEN_ORDER_RANDOMIZATION_SEED)
        )
        unique_orders.add(order)
        first_position_counts[order[0]] += 1

    # In 84 scenarios with 4! = 24 possible permutations, multiple distinct permutations must occur
    assert len(unique_orders) >= 10, f"Expected high diversity of condition orders, got only {len(unique_orders)}"
    # Every condition must appear at position 1 across scenarios
    assert len(first_position_counts) == 4, f"Not all conditions appeared in position 1: {first_position_counts}"
    for cond_id in ["C1", "C2", "C3", "C4"]:
        assert first_position_counts[cond_id] >= 10, (
            f"Condition {cond_id} under-represented at position 1: {first_position_counts[cond_id]}"
        )


# ===========================================================================
# 28. Condition Completeness and Zero Duplication per Scenario
# ===========================================================================

def test_28_deterministic_condition_order_completeness_and_no_duplicates():
    """Verify every scenario executes all four conditions exactly once with zero omissions and zero duplicates."""
    scenarios = get_gold_set_scenarios()
    total_calls = []

    for scen in scenarios:
        order = get_deterministic_condition_order(scen.scenario_id, FROZEN_ORDER_RANDOMIZATION_SEED)
        cond_ids = [c.condition_id for c in order]
        # Exact set of 4 conditions
        assert set(cond_ids) == {"C1", "C2", "C3", "C4"}, f"Incomplete condition set for {scen.scenario_id}: {cond_ids}"
        assert len(cond_ids) == 4, f"Condition count mismatch for {scen.scenario_id}: {cond_ids}"
        assert len(cond_ids) == len(set(cond_ids)), f"Duplicate conditions in order for {scen.scenario_id}: {cond_ids}"
        for c in cond_ids:
            total_calls.append((c, scen.scenario_id))

    assert len(total_calls) == 336, f"Expected 336 total calls, got {len(total_calls)}"
    assert len(total_calls) == len(set(total_calls)), "Duplicate scheduled calls in full matrix"

