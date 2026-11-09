"""
Unit tests for Milestone M5 Phase 5: Deterministic End-to-End M5 Contract Validation.

Guarantees:
- Strictly offline: active network blocking prevents any real Ollama or external HTTP calls.
- Deterministic mock runner: exercises full production parser, validator, adapter, I5 decision policy,
  and grounding validation without live inference.
- Complete coverage of:
  - Phase 5C: Valid HYPOTHESIS path under full composition
  - Phase 5D: Valid INSUFFICIENT_EVIDENCE path
  - Phase 5E: Valid NO_RELEVANT_FUNCTIONALITY path
  - Phase 5F: 12 negative parser/schema fail-closed cases
  - Phase 5G: Fail-closed zero-call verification on pre-flight rejection
  - Phase 5H: Budget end-to-end accounting, pruning, and overflow protection
  - Phase 5I: I1=0 / I1=1 contract parity
  - Phase 5J: Ground-truth isolation
  - Phase 5K: End-to-end pipeline determinism and repeatability
"""

import json
import pytest
from typing import Any, Callable, Dict, List, Optional

from src.engine.bair_extractor import (
    BairExtractor,
    BairParseError,
    BairSchemaError,
    map_bair_json_to_s0,
    parse_bair,
    parse_bair_json,
    validate_bair_json,
)
from src.engine.context_builder import (
    TRACK_A,
    TRACK_D,
    PromptContractCompiler,
    ReasoningContextBuilder,
)
from src.engine.decision_policy import EvidenceState, deterministic_decide
from src.engine.handoff_serializer import (
    HandoffSerializer,
    ProtectedHandoffDescriptor,
)
from src.engine.models import (
    BairJsonObject,
    ContractCompilationError,
    HypothesisDecision,
    HypothesisModelOutput,
    M5ExecutionResult,
    OutputProtocolIdentifier,
    PrimaryFailureCategory,
)
from src.engine.protocol import (
    OutputProtocolContract,
    ReasoningExecutionContract,
    get_protocol_contract,
    validate_reasoning_contract,
)
from src.engine.runner import ReasoningRunner
from src.evidence.cascade_models import (
    CascadeHandoffPacket,
    ContextBudgetOverflowError,
    DeterministicRoutingDecision,
    LosslessStructuralPack,
    TriageMetadataPacket,
)
from src.knowledge.models import (
    EvidenceGapType,
    KnowledgeChunk,
    KnowledgeRetrievalItem,
    KnowledgeSourceType,
    KnowledgeType,
    VaptKnowledgePack,
)


# ---------------------------------------------------------------------------
# Phase 5M: Active Network Blocking Fixture
# ---------------------------------------------------------------------------

class OfflineAssertionError(AssertionError):
    """Raised when any code attempts live network access or real Ollama calls in Phase 5."""
    pass


@pytest.fixture(autouse=True)
def block_all_network(monkeypatch):
    """Actively prevents and detects any network call or real Ollama transport."""
    def forbidden_call(*args, **kwargs):
        raise OfflineAssertionError("LIVE NETWORK ACCESS STRICTLY FORBIDDEN IN PHASE 5")

    # Block raw Ollama generation
    monkeypatch.setattr("src.engine.runner.OllamaRunner.generate_raw", forbidden_call)
    monkeypatch.setattr("src.engine.runner.OllamaRunner.generate_structured", forbidden_call)
    monkeypatch.setattr("src.engine.runner.OllamaRunner.is_available", lambda self: False)
    monkeypatch.setattr("src.engine.runner.OllamaRunner.list_models", forbidden_call)
    # Block HTTP clients and sockets
    monkeypatch.setattr("httpx.Client.post", forbidden_call)
    monkeypatch.setattr("httpx.Client.get", forbidden_call)
    monkeypatch.setattr("http.client.HTTPConnection.connect", forbidden_call)
    monkeypatch.setattr("urllib.request.urlopen", forbidden_call)
    monkeypatch.setattr("socket.socket.connect", forbidden_call)


def test_network_blocking_active():
    """Phase 5M: Verify that any live network attempt immediately raises OfflineAssertionError."""
    with pytest.raises(OfflineAssertionError):
        import socket
        s = socket.socket()
        s.connect(("127.0.0.1", 11434))


# ---------------------------------------------------------------------------
# Phase 5B: Deterministic Mock Inference Runner
# ---------------------------------------------------------------------------

class DeterministicMockCaller:
    """Deterministic mock model caller tracking call count and prompt inspection."""

    def __init__(self, response_generator: Optional[Callable[[str, Any], str]] = None) -> None:
        self.calls: int = 0
        self.call_history: List[Dict[str, Any]] = []
        self.response_generator = response_generator

    def __call__(self, prompt: str, schema: Optional[Dict[str, Any]] = None) -> str:
        self.calls += 1
        self.call_history.append({"prompt": prompt, "schema": schema})
        if self.response_generator:
            return self.response_generator(prompt, schema)
        return "{}"


# ---------------------------------------------------------------------------
# Synthetic Test Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def synthetic_structural_pack():
    return LosslessStructuralPack(
        schema_version="2.0.0",
        asset_id="AST-ORDERS-01",
        endpoint_id="EP-01",
        route_template="/api/v1/orders/{id}",
        http_method="GET",
        application_mutability="READ_ONLY",
        has_privilege_level_delta=True,
        has_cross_identity_object_access_success=True,
        has_observed_contradictions=False,
        observed_facts=[
            {"fact_id": "FACT-SYNTH-01", "statement": "User B accessed order owned by User A"},
            {"fact_id": "FACT-SYNTH-02", "statement": "HTTP 200 returned with full order body"},
        ],
        parameter_lineage=[
            {"param_id": "P-ID", "param_name": "id", "location": "path"},
        ],
        raw_body_sample='{"order_id": 42, "user_id": "A", "total": 99.50}',
    )


@pytest.fixture
def synthetic_vapt_pack():
    chunk = KnowledgeChunk(
        chunk_id="CHK-DOC-WSTG-ATHZ-04-001-01",
        document_id="DOC-WSTG-ATHZ-04",
        source_type=KnowledgeSourceType.OWASP_WSTG,
        knowledge_type=KnowledgeType.TESTING_METHODOLOGY,
        title="OWASP WSTG BOLA Testing",
        section_heading="Testing for Insecure Direct Object References",
        content="Test whether resource identifiers can be manipulated across tenants.",
        token_estimate=15,
        content_hash="hash123",
    )
    return VaptKnowledgePack(
        pack_id="PACK-BOLA-01",
        items=[
            KnowledgeRetrievalItem(
                chunk=chunk,
                dense_score=0.95,
                sparse_score=0.90,
                fused_score=0.93,
                retrieval_rank=1,
                query_id="Q-01",
            ),
        ],
        total_tokens=15,
        rendered_query_text="Testing for BOLA",
        retrieval_timestamp="2026-09-20T00:00:00Z",
        corpus_manifest_hash="manifest_hash",
        provenance_hash="prov_hash",
        serialized_p4_wire="=== VAPT METHODOLOGY ===\n[CHK-DOC-WSTG-ATHZ-04-001-01] Testing whether resource identifiers can be manipulated.",
    )


@pytest.fixture
def synthetic_handoff(synthetic_structural_pack):
    routing = DeterministicRoutingDecision(
        schema_version="2.0.0",
        escalate=True,
        has_high_risk_signal=True,
        high_risk_signals=["PRIVILEGE_LEVEL_DELTA_DETECTED"],
        fail_safe_triggered=False,
    )
    triage = TriageMetadataPacket(
        schema_version="2.0.0",
        suspected_category="API-BOLA-001",
        decision="SUSPECTED_VULNERABILITY",
        triage_rationale="Cross-identity object access observed",
    )
    return CascadeHandoffPacket(
        schema_version="2.0.0",
        channel_a_structural=synthetic_structural_pack,
        validated_triage=triage,
        routing_decision=routing,
        provenance_hash="mock_hash_32chars_hex_12345678",
    )


@pytest.fixture
def synthetic_protected_handoff(synthetic_structural_pack):
    return HandoffSerializer.serialize(
        invariant="Resource access must be restricted to resource owner",
        evidence_gap_type=EvidenceGapType.MISSING_CROSS_IDENTITY_OBJECT_VERIFICATION,
        class1_predicates=synthetic_structural_pack,
    )


# ---------------------------------------------------------------------------
# Phase 5C: End-to-End Valid-Hypothesis Path
# ---------------------------------------------------------------------------

def test_m5_end_to_end_valid_hypothesis_path(
    synthetic_handoff,
    synthetic_vapt_pack,
    synthetic_protected_handoff,
):
    """
    Phase 5C: End-to-end valid hypothesis execution:
    I1=0, I2=1, I3=1, I4=1, I5=1, I6=1.
    Verifies full coherence from canonical input to final evaluation object.
    """
    # 1. Compile prompt context
    ctx = ReasoningContextBuilder.build_context(
        handoff_packet=synthetic_handoff,
        model_identifier="qwen2.5-coder:7b",
        cascade_mode=TRACK_D,
        vapt_pack=synthetic_vapt_pack,
        category_id="API-BOLA-001",
        enable_i2_namespace_partitioning=True,
        enable_i3_counterfactual_prompting=True,
        enable_i4_bair=True,
        enable_i5_decision_policy=True,
        enable_i6_handoff=True,
        protected_handoff=synthetic_protected_handoff,
        output_protocol=OutputProtocolIdentifier.JSON_BAIR,
    )

    proto_contract = get_protocol_contract(OutputProtocolIdentifier.JSON_BAIR)

    # 2. Build execution contract
    contract = ReasoningExecutionContract(
        protocol=OutputProtocolIdentifier.JSON_BAIR,
        enable_i1=False,
        enable_i2=True,
        enable_i3=True,
        enable_i4=True,
        enable_i5=True,
        enable_i6=True,
        system_prompt=ctx.system_prompt,
        user_prompt=ctx.user_prompt,
        runtime_schema=None,
        parser=proto_contract.parser,
        validator=proto_contract.validator,
        adapter=proto_contract.adapter,
        budget_tier=4096,
        floor_tokens=1000,
        total_tokens=ctx.token_count,
        protected_handoff_present=True,
        category_id="API-BOLA-001",
    )

    # 3. Deterministic mock response with markdown wrapper
    mock_emission = """```json
{
  "invariant": "Resource access must be restricted to resource owner",
  "evidence_gap": "Missing tenant ownership check on GET order",
  "affected_target": "/api/v1/orders/{id}",
  "decision": "HYPOTHESIS",
  "empirical_facts": ["FACT-SYNTH-01", "FACT-SYNTH-02"],
  "methodology_references": ["CHK-DOC-WSTG-ATHZ-04-001-01"],
  "experiment_action": "SUBSTITUTE_RESOURCE_IDENTIFIER",
  "supporting_outcome": "CROSS_IDENTITY_OBJECT_ACCESSIBLE",
  "disproving_outcome": "CROSS_IDENTITY_OBJECT_DENIED",
  "falsification_description": "Support if user B reads order of user A; disprove if returns 403 Forbidden"
}
```"""

    mock_caller = DeterministicMockCaller(response_generator=lambda p, s: mock_emission)
    runner = ReasoningRunner(llm_caller=mock_caller)

    result = runner.execute_m5_generation(
        contract=contract,
        empirical_evidence_present=True,
        channel_a=synthetic_handoff.channel_a_structural,
        target_asset={"asset_id": "AST-ORDERS-01"},
        category_id="API-BOLA-001",
        vapt_pack=synthetic_vapt_pack,
    )

    # Verifications
    assert mock_caller.calls == 1
    assert result.contract_valid is True
    assert result.classification.is_valid is True
    assert result.classification.primary_category == PrimaryFailureCategory.VALID
    assert result.canonical_hypothesis is not None
    assert result.canonical_hypothesis.decision == HypothesisDecision.HYPOTHESIS
    assert result.canonical_hypothesis.invariant == "Resource access must be restricted to resource owner"
    assert result.canonical_hypothesis.supporting_evidence_ids == ["FACT-SYNTH-01", "FACT-SYNTH-02"]
    assert result.canonical_hypothesis.experiment_action == "SUBSTITUTE_RESOURCE_IDENTIFIER"
    assert result.canonical_hypothesis.supporting_outcome == "CROSS_IDENTITY_OBJECT_ACCESSIBLE"
    assert result.canonical_hypothesis.disproving_outcome == "CROSS_IDENTITY_OBJECT_DENIED"
    assert result.canonical_hypothesis.falsification_description == "Support if user B reads order of user A; disprove if returns 403 Forbidden"
    assert "SUBSTITUTE_RESOURCE_IDENTIFIER" in result.canonical_hypothesis.experiment_proposal


# ---------------------------------------------------------------------------
# Phase 5D: Valid INSUFFICIENT-EVIDENCE Path
# ---------------------------------------------------------------------------

def test_m5_end_to_end_valid_insufficient_evidence_path(
    synthetic_handoff,
    synthetic_protected_handoff,
):
    """
    Phase 5D: Decision-dependent validation and policy evaluation for INSUFFICIENT_EVIDENCE.
    Ensures correct evidence state handling and no false HYPOTHESIS scoring.
    """
    ctx = ReasoningContextBuilder.build_context(
        handoff_packet=synthetic_handoff,
        category_id="API-BOLA-001",
        enable_i4_bair=True,
        enable_i5_decision_policy=True,
        enable_i6_handoff=True,
        protected_handoff=synthetic_protected_handoff,
        output_protocol=OutputProtocolIdentifier.JSON_BAIR,
    )
    proto_contract = get_protocol_contract(OutputProtocolIdentifier.JSON_BAIR)

    contract = ReasoningExecutionContract(
        protocol=OutputProtocolIdentifier.JSON_BAIR,
        enable_i1=False,
        enable_i4=True,
        enable_i5=True,
        enable_i6=True,
        system_prompt=ctx.system_prompt,
        user_prompt=ctx.user_prompt,
        runtime_schema=None,
        parser=proto_contract.parser,
        validator=proto_contract.validator,
        adapter=proto_contract.adapter,
        budget_tier=4096,
        floor_tokens=500,
        total_tokens=ctx.token_count,
        protected_handoff_present=True,
        category_id="API-BOLA-001",
    )

    mock_emission = json.dumps({
        "invariant": "Resource access must be restricted to resource owner",
        "evidence_gap": "Need cross-tenant verification request across organization boundary",
        "affected_target": "/api/v1/orders/{id}",
        "decision": "INSUFFICIENT_EVIDENCE",
        "empirical_facts": ["FACT-SYNTH-01"],
        "methodology_references": [],
        "falsification_plan": "Support if cross-tenant read succeeds; disprove if 403 Forbidden is returned",
    })

    mock_caller = DeterministicMockCaller(response_generator=lambda p, s: mock_emission)
    runner = ReasoningRunner(llm_caller=mock_caller)

    result = runner.execute_m5_generation(
        contract=contract,
        empirical_evidence_present=True,
        channel_a=synthetic_handoff.channel_a_structural,
        target_asset={"asset_id": "AST-ORDERS-01"},
        category_id="API-BOLA-001",
    )

    assert mock_caller.calls == 1
    assert result.contract_valid is True
    assert result.classification.is_valid is True
    assert result.canonical_hypothesis is not None
    assert result.canonical_hypothesis.decision == HypothesisDecision.INSUFFICIENT_EVIDENCE
    assert result.canonical_hypothesis.decision != HypothesisDecision.HYPOTHESIS


# ---------------------------------------------------------------------------
# Phase 5E: Valid NO-RELEVANT-FUNCTIONALITY Path
# ---------------------------------------------------------------------------

def test_m5_end_to_end_valid_no_relevant_functionality_path(
    synthetic_handoff,
    synthetic_protected_handoff,
):
    """
    Phase 5E: Validation and policy evaluation for NO_RELEVANT_FUNCTIONALITY.
    Ensures no vulnerability hypothesis is fabricated.
    """
    irrelevant_channel_a = LosslessStructuralPack(
        schema_version="2.0.0",
        asset_id="AST-HEALTH-01",
        endpoint_id="EP-HEALTH-01",
        route_template="/api/v1/health",
        http_method="GET",
        application_mutability="READ_ONLY",
        has_privilege_level_delta=False,
        has_cross_identity_object_access_success=False,
        has_observed_contradictions=False,
        observed_facts=[],
        parameter_lineage=[],
        raw_body_sample='{"status": "healthy"}',
    )
    irrelevant_handoff = CascadeHandoffPacket(
        schema_version="2.0.0",
        channel_a_structural=irrelevant_channel_a,
        validated_triage=synthetic_handoff.validated_triage,
        routing_decision=synthetic_handoff.routing_decision,
        provenance_hash="mock_hash_health_endpoint",
    )

    ctx = ReasoningContextBuilder.build_context(
        handoff_packet=irrelevant_handoff,
        category_id="API-BOLA-001",
        enable_i4_bair=True,
        enable_i5_decision_policy=True,
        output_protocol=OutputProtocolIdentifier.JSON_BAIR,
    )
    proto_contract = get_protocol_contract(OutputProtocolIdentifier.JSON_BAIR)

    contract = ReasoningExecutionContract(
        protocol=OutputProtocolIdentifier.JSON_BAIR,
        enable_i1=False,
        enable_i4=True,
        enable_i5=True,
        system_prompt=ctx.system_prompt,
        user_prompt=ctx.user_prompt,
        runtime_schema=None,
        parser=proto_contract.parser,
        validator=proto_contract.validator,
        adapter=proto_contract.adapter,
        budget_tier=4096,
        floor_tokens=500,
        total_tokens=ctx.token_count,
        category_id="API-BOLA-001",
    )

    mock_emission = json.dumps({
        "invariant": "Public status endpoint does not enforce tenant boundary",
        "evidence_gap": None,
        "affected_target": "/api/v1/health",
        "decision": "NO_RELEVANT_FUNCTIONALITY",
        "empirical_facts": [],
        "methodology_references": [],
        "falsification_plan": "Endpoint provides no tenant isolation functionality to falsify",
    })

    mock_caller = DeterministicMockCaller(response_generator=lambda p, s: mock_emission)
    runner = ReasoningRunner(llm_caller=mock_caller)

    result = runner.execute_m5_generation(
        contract=contract,
        empirical_evidence_present=False,
        channel_a=irrelevant_channel_a,
        target_asset={"asset_id": "AST-HEALTH-01", "is_irrelevant_target": True},
        category_id="API-BOLA-001",
    )

    assert mock_caller.calls == 1
    assert result.contract_valid is True
    assert result.classification.is_valid is True
    assert result.canonical_hypothesis is not None
    assert result.canonical_hypothesis.decision == HypothesisDecision.NO_RELEVANT_FUNCTIONALITY


# ---------------------------------------------------------------------------
# Phase 5F: Negative Parser / Schema Tests (12 Fail-Closed Cases)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "case_id,emission,expected_primary_category,expected_error_substr",
    [
        # 1. Malformed JSON (syntax error)
        (
            "malformed_json",
            '{"invariant": "missing closing brace"',
            PrimaryFailureCategory.PARSER_FAILURE,
            "Invalid JSON",
        ),
        # 2. Wrong top-level type (JSON list instead of object)
        (
            "wrong_top_level_type",
            '[{"invariant": "test"}]',
            PrimaryFailureCategory.PARSER_FAILURE,
            "not a dictionary",
        ),
        # 3. Missing required field (missing invariant)
        (
            "missing_required_field",
            json.dumps({
                "evidence_gap": "gap",
                "affected_target": "/api",
                "decision": "HYPOTHESIS",
                "empirical_facts": ["FACT-SYNTH-01"],
                "methodology_references": [],
                "falsification_plan": "Support if X; disprove if Y",
            }),
            PrimaryFailureCategory.SCHEMA_VALIDITY_FAILURE,
            "Field required",
        ),
        # 4. Invalid decision
        (
            "invalid_decision",
            json.dumps({
                "invariant": "valid invariant",
                "evidence_gap": "gap",
                "affected_target": "/api",
                "decision": "PROBABLY_VULNERABLE",
                "empirical_facts": ["FACT-SYNTH-01"],
                "methodology_references": [],
                "falsification_plan": "Support if X; disprove if Y",
            }),
            PrimaryFailureCategory.SCHEMA_VALIDITY_FAILURE,
            "Input should be",
        ),
        # 5. CONFIRMED decision strictly rejected
        (
            "confirmed_decision",
            json.dumps({
                "invariant": "valid invariant",
                "evidence_gap": "gap",
                "affected_target": "/api",
                "decision": "CONFIRMED",
                "empirical_facts": ["FACT-SYNTH-01"],
                "methodology_references": [],
                "falsification_plan": "Support if X; disprove if Y",
            }),
            PrimaryFailureCategory.SCHEMA_VALIDITY_FAILURE,
            "Input should be",
        ),
        # 6. Invalid FACT identifier
        (
            "invalid_fact_identifier",
            json.dumps({
                "invariant": "valid invariant",
                "evidence_gap": "gap",
                "affected_target": "/api",
                "decision": "HYPOTHESIS",
                "empirical_facts": ["INVALID_FACT_SYNTAX!"],
                "methodology_references": [],
                "falsification_plan": "Support if X; disprove if Y",
            }),
            PrimaryFailureCategory.SCHEMA_VALIDITY_FAILURE,
            "does not match ^FACT",
        ),
        # 7. Invalid CHK identifier
        (
            "invalid_chk_identifier",
            json.dumps({
                "invariant": "valid invariant",
                "evidence_gap": "gap",
                "affected_target": "/api",
                "decision": "HYPOTHESIS",
                "empirical_facts": ["FACT-SYNTH-01"],
                "methodology_references": ["INVALID_CHK_FORMAT"],
                "falsification_plan": "Support if X; disprove if Y",
            }),
            PrimaryFailureCategory.SCHEMA_VALIDITY_FAILURE,
            "does not match ^CHK",
        ),
        # 8. Cross-namespace confusion (CHK in empirical_facts)
        (
            "cross_namespace_confusion",
            json.dumps({
                "invariant": "valid invariant",
                "evidence_gap": "gap",
                "affected_target": "/api",
                "decision": "HYPOTHESIS",
                "empirical_facts": ["CHK-DOC-WSTG-01"],
                "methodology_references": [],
                "falsification_plan": "Support if X; disprove if Y",
            }),
            PrimaryFailureCategory.SCHEMA_VALIDITY_FAILURE,
            "does not match ^FACT",
        ),
        # 9. Malformed falsification plan (legacy free-text only)
        (
            "malformed_falsification_plan",
            json.dumps({
                "invariant": "valid invariant",
                "evidence_gap": "gap",
                "affected_target": "/api",
                "decision": "HYPOTHESIS",
                "empirical_facts": ["FACT-SYNTH-01"],
                "methodology_references": [],
                "falsification_plan": "   ",
            }),
            PrimaryFailureCategory.SCHEMA_VALIDITY_FAILURE,
            "Legacy free-text falsification_plan cannot authorize a HYPOTHESIS",
        ),
        # 10. Empty invariant placeholder
        (
            "placeholder_invariant",
            json.dumps({
                "invariant": "N/A",
                "evidence_gap": "gap",
                "affected_target": "/api",
                "decision": "HYPOTHESIS",
                "empirical_facts": ["FACT-SYNTH-01"],
                "methodology_references": [],
                "falsification_plan": "Support if X; disprove if Y",
            }),
            PrimaryFailureCategory.SCHEMA_VALIDITY_FAILURE,
            "cannot be a placeholder value",
        ),
        # 11. Truncated output
        (
            "truncated_output",
            '{"invariant": "Something was being eva',
            PrimaryFailureCategory.PARSER_FAILURE,
            "Invalid JSON",
        ),
        # 12. Hypothesis missing supporting empirical facts
        (
            "hypothesis_missing_facts",
            json.dumps({
                "invariant": "valid invariant",
                "evidence_gap": "gap",
                "affected_target": "/api",
                "decision": "HYPOTHESIS",
                "empirical_facts": [],
                "methodology_references": [],
                "falsification_plan": "Support if X; disprove if Y",
            }),
            PrimaryFailureCategory.SCHEMA_VALIDITY_FAILURE,
            "mandatory empirical_facts slot missing or empty",
        ),
    ],
)
def test_m5_negative_parser_schema_fail_closed(
    synthetic_handoff,
    case_id,
    emission,
    expected_primary_category,
    expected_error_substr,
):
    """
    Phase 5F: Negative parser and schema tests.
    Each test must fail closed with the exact expected failure category and never score as a hypothesis.
    """
    ctx = ReasoningContextBuilder.build_context(
        handoff_packet=synthetic_handoff,
        category_id="API-BOLA-001",
        enable_i4_bair=True,
        output_protocol=OutputProtocolIdentifier.JSON_BAIR,
    )
    proto_contract = get_protocol_contract(OutputProtocolIdentifier.JSON_BAIR)

    contract = ReasoningExecutionContract(
        protocol=OutputProtocolIdentifier.JSON_BAIR,
        enable_i1=False,
        enable_i4=True,
        system_prompt=ctx.system_prompt,
        user_prompt=ctx.user_prompt,
        runtime_schema=None,
        parser=proto_contract.parser,
        validator=proto_contract.validator,
        adapter=proto_contract.adapter,
        budget_tier=4096,
        floor_tokens=500,
        total_tokens=ctx.token_count,
        category_id="API-BOLA-001",
    )

    mock_caller = DeterministicMockCaller(response_generator=lambda p, s: emission)
    runner = ReasoningRunner(llm_caller=mock_caller)

    result = runner.execute_m5_generation(
        contract=contract,
        empirical_evidence_present=True,
        channel_a=synthetic_handoff.channel_a_structural,
        target_asset={"asset_id": "AST-ORDERS-01"},
        category_id="API-BOLA-001",
    )

    assert result.classification.is_valid is False
    assert result.classification.primary_category == expected_primary_category
    assert result.canonical_hypothesis is None
    assert expected_error_substr.lower() in result.classification.error_message.lower()


# ---------------------------------------------------------------------------
# Phase 5G: Fail-Closed "Zero Call" Tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "test_name,contract_mutator",
    [
        (
            "protocol_mismatch",
            lambda c: setattr(c, "protocol", OutputProtocolIdentifier.BAIR_XML),
        ),
        (
            "parser_mismatch",
            lambda c: setattr(c, "parser", parse_bair),
        ),
        (
            "validator_mismatch",
            lambda c: setattr(c, "validator", None),
        ),
        (
            "adapter_mismatch",
            lambda c: setattr(c, "adapter", None),
        ),
        (
            "mandatory_budget_overflow",
            lambda c: setattr(c, "floor_tokens", 999999),
        ),
        (
            "missing_i6_protected_handoff",
            lambda c: (setattr(c, "enable_i6", True), setattr(c, "protected_handoff_present", False)),
        ),
        (
            "invalid_runtime_schema",
            lambda c: (setattr(c, "enable_i1", True), setattr(c, "runtime_schema", None)),
        ),
        (
            "forbidden_ground_truth_leakage",
            lambda c: setattr(c, "system_prompt", c.system_prompt + "\nis_vulnerable: true"),
        ),
    ],
)
def test_m5_fail_closed_zero_call_gating(
    synthetic_handoff,
    test_name,
    contract_mutator,
):
    """
    Phase 5G: Pre-flight gating guarantees exactly call_count == 0 when contract is invalid.
    Zero LLM or mock calls occur.
    """
    ctx = ReasoningContextBuilder.build_context(
        handoff_packet=synthetic_handoff,
        category_id="API-BOLA-001",
        enable_i4_bair=True,
        output_protocol=OutputProtocolIdentifier.JSON_BAIR,
    )
    proto_contract = get_protocol_contract(OutputProtocolIdentifier.JSON_BAIR)

    contract = ReasoningExecutionContract(
        protocol=OutputProtocolIdentifier.JSON_BAIR,
        enable_i1=False,
        enable_i4=True,
        system_prompt=ctx.system_prompt,
        user_prompt=ctx.user_prompt,
        runtime_schema=None,
        parser=proto_contract.parser,
        validator=proto_contract.validator,
        adapter=proto_contract.adapter,
        budget_tier=4096,
        floor_tokens=500,
        total_tokens=ctx.token_count,
        category_id="API-BOLA-001",
    )

    # Mutate contract to trigger failure
    contract_mutator(contract)

    mock_caller = DeterministicMockCaller(response_generator=lambda p, s: "{}")
    runner = ReasoningRunner(llm_caller=mock_caller)

    result = runner.execute_m5_generation(
        contract=contract,
        empirical_evidence_present=True,
        channel_a=synthetic_handoff.channel_a_structural,
        target_asset={"asset_id": "AST-ORDERS-01"},
        category_id="API-BOLA-001",
    )

    # MUST assert ZERO calls
    assert mock_caller.calls == 0, f"Failed for {test_name}: model was called despite contract violation!"
    assert result.contract_valid is False
    assert result.classification.is_valid is False
    assert result.classification.primary_category == PrimaryFailureCategory.SCHEMA_VALIDITY_FAILURE
    assert "Pre-flight contract compilation failed" in result.classification.error_message


# ---------------------------------------------------------------------------
# Phase 5H: Budget End-to-End Tests
# ---------------------------------------------------------------------------

def test_m5_budget_exact_fit_mandatory_context(synthetic_handoff, synthetic_protected_handoff):
    """Exact-fit mandatory context compiles without error."""
    # First measure exact mandatory floor tokens under TRACK_A (no advisory snippets/VAPT)
    ctx_probe = ReasoningContextBuilder.build_context(
        handoff_packet=synthetic_handoff,
        budget_tier=4096,
        cascade_mode=TRACK_A,
        category_id="API-BOLA-001",
        enable_i3_counterfactual_prompting=True,
        enable_i6_handoff=True,
        protected_handoff=synthetic_protected_handoff,
        output_protocol=OutputProtocolIdentifier.JSON_BAIR,
    )
    exact_floor = ctx_probe.token_count

    # Compile with budget_tier set exactly to floor
    ctx_exact = ReasoningContextBuilder.build_context(
        handoff_packet=synthetic_handoff,
        budget_tier=exact_floor,
        cascade_mode=TRACK_A,
        category_id="API-BOLA-001",
        enable_i3_counterfactual_prompting=True,
        enable_i6_handoff=True,
        protected_handoff=synthetic_protected_handoff,
        output_protocol=OutputProtocolIdentifier.JSON_BAIR,
    )
    assert ctx_exact.token_count == exact_floor


def test_m5_budget_one_token_overflow_fails_closed(synthetic_handoff, synthetic_protected_handoff):
    """One token below mandatory floor raises ContextBudgetOverflowError deterministically."""
    ctx_probe = ReasoningContextBuilder.build_context(
        handoff_packet=synthetic_handoff,
        budget_tier=4096,
        cascade_mode=TRACK_A,
        category_id="API-BOLA-001",
        enable_i3_counterfactual_prompting=True,
        enable_i6_handoff=True,
        protected_handoff=synthetic_protected_handoff,
        output_protocol=OutputProtocolIdentifier.JSON_BAIR,
    )
    exact_floor = ctx_probe.token_count

    with pytest.raises(ContextBudgetOverflowError) as exc:
        ReasoningContextBuilder.build_context(
            handoff_packet=synthetic_handoff,
            budget_tier=exact_floor - 1,  # 1-token underflow
            cascade_mode=TRACK_A,
            category_id="API-BOLA-001",
            enable_i3_counterfactual_prompting=True,
            enable_i6_handoff=True,
            protected_handoff=synthetic_protected_handoff,
            output_protocol=OutputProtocolIdentifier.JSON_BAIR,
        )
    assert "floor" in str(exc.value).lower() or "overflow" in str(exc.value).lower()


def test_m5_budget_advisory_content_pruned_before_mandatory(
    synthetic_handoff,
    synthetic_vapt_pack,
    synthetic_protected_handoff,
):
    """Advisory content (P4 snippets, P4 VAPT) is pruned when budget is tight; mandatory floor is preserved."""
    # 1. Measure full token count when budget is unconstrained (4096)
    ctx_full = ReasoningContextBuilder.build_context(
        handoff_packet=synthetic_handoff,
        budget_tier=4096,
        cascade_mode=TRACK_D,
        vapt_pack=synthetic_vapt_pack,
        category_id="API-BOLA-001",
        enable_i3_counterfactual_prompting=True,
        enable_i6_handoff=True,
        protected_handoff=synthetic_protected_handoff,
        output_protocol=OutputProtocolIdentifier.JSON_BAIR,
    )

    # 2. Measure mandatory floor (TRACK_A without advisory snippets/VAPT)
    ctx_floor = ReasoningContextBuilder.build_context(
        handoff_packet=synthetic_handoff,
        budget_tier=4096,
        cascade_mode=TRACK_A,
        category_id="API-BOLA-001",
        enable_i3_counterfactual_prompting=True,
        enable_i6_handoff=True,
        protected_handoff=synthetic_protected_handoff,
        output_protocol=OutputProtocolIdentifier.JSON_BAIR,
    )
    floor_tokens = ctx_floor.token_count

    # 3. Set budget tier to floor_tokens + 10 (less than full advisory content)
    budget_tight = floor_tokens + 10
    ctx_tight = ReasoningContextBuilder.build_context(
        handoff_packet=synthetic_handoff,
        budget_tier=budget_tight,
        cascade_mode=TRACK_D,
        vapt_pack=synthetic_vapt_pack,
        category_id="API-BOLA-001",
        enable_i3_counterfactual_prompting=True,
        enable_i6_handoff=True,
        protected_handoff=synthetic_protected_handoff,
        output_protocol=OutputProtocolIdentifier.JSON_BAIR,
    )

    # Mandatory I6 must be retained
    assert "PROTECTED 3B -> 7B INVARIANT HANDOFF" in ctx_tight.user_prompt
    assert ctx_tight.token_count <= budget_tight
    # Advisory content was pruned: tight prompt has fewer tokens than full unconstrained prompt
    assert ctx_tight.token_count < ctx_full.token_count


# ---------------------------------------------------------------------------
# Phase 5I: I1=0 / I1=1 Parity
# ---------------------------------------------------------------------------

def test_m5_i1_zero_and_one_contract_parity(
    synthetic_handoff,
    synthetic_vapt_pack,
    synthetic_protected_handoff,
):
    """
    Phase 5I: Same synthetic scenario run under I1=0 and I1=1.
    Verifies identical semantic contract, parser, validator, and adapter.
    """
    ctx = ReasoningContextBuilder.build_context(
        handoff_packet=synthetic_handoff,
        model_identifier="qwen2.5-coder:7b",
        cascade_mode=TRACK_D,
        vapt_pack=synthetic_vapt_pack,
        category_id="API-BOLA-001",
        enable_i2_namespace_partitioning=True,
        enable_i3_counterfactual_prompting=True,
        enable_i4_bair=True,
        enable_i5_decision_policy=True,
        enable_i6_handoff=True,
        protected_handoff=synthetic_protected_handoff,
        output_protocol=OutputProtocolIdentifier.JSON_BAIR,
    )

    proto_contract = get_protocol_contract(OutputProtocolIdentifier.JSON_BAIR)

    # Case A: I1=0
    contract_i1_off = ReasoningExecutionContract(
        protocol=OutputProtocolIdentifier.JSON_BAIR,
        enable_i1=False,
        enable_i2=True,
        enable_i3=True,
        enable_i4=True,
        enable_i5=True,
        enable_i6=True,
        system_prompt=ctx.system_prompt,
        user_prompt=ctx.user_prompt,
        runtime_schema=None,
        parser=proto_contract.parser,
        validator=proto_contract.validator,
        adapter=proto_contract.adapter,
        budget_tier=4096,
        floor_tokens=1000,
        total_tokens=ctx.token_count,
        protected_handoff_present=True,
        category_id="API-BOLA-001",
    )

    # Case B: I1=1
    schema = proto_contract.runtime_schema_factory(True)
    contract_i1_on = ReasoningExecutionContract(
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

    validate_reasoning_contract(contract_i1_off)
    validate_reasoning_contract(contract_i1_on)

    # Compare pipeline components
    assert contract_i1_off.parser == contract_i1_on.parser == parse_bair_json
    assert contract_i1_off.validator == contract_i1_on.validator == validate_bair_json
    assert contract_i1_off.adapter == contract_i1_on.adapter == map_bair_json_to_s0
    assert contract_i1_off.system_prompt == contract_i1_on.system_prompt
    assert contract_i1_off.user_prompt == contract_i1_on.user_prompt

    # Only runtime schema differs
    assert contract_i1_off.runtime_schema is None
    assert contract_i1_on.runtime_schema == BairJsonObject.get_inference_schema()


# ---------------------------------------------------------------------------
# Phase 5J: Ground-Truth Isolation
# ---------------------------------------------------------------------------

def test_m5_ground_truth_isolation(
    synthetic_handoff,
    synthetic_vapt_pack,
    synthetic_protected_handoff,
):
    """
    Phase 5J: Prompt text inspection proves complete absence of ground-truth leakage tokens.
    """
    ctx = ReasoningContextBuilder.build_context(
        handoff_packet=synthetic_handoff,
        model_identifier="qwen2.5-coder:7b",
        cascade_mode=TRACK_D,
        vapt_pack=synthetic_vapt_pack,
        category_id="API-BOLA-001",
        enable_i2_namespace_partitioning=True,
        enable_i3_counterfactual_prompting=True,
        enable_i4_bair=True,
        enable_i5_decision_policy=True,
        enable_i6_handoff=True,
        protected_handoff=synthetic_protected_handoff,
        output_protocol=OutputProtocolIdentifier.JSON_BAIR,
    )

    forbidden_tokens = [
        "is_vulnerable",
        "ground_truth",
        "gold_decision",
        "oracle_verdict",
        "oracle_vulnerability_status",
        "vulnerable_label",
        "control_label",
        "oracle_label",
        "expected_outcome",
        "expected_decision",
        "expected_verdict",
        "gold_standard_hypothesis",
        "human_annotation",
    ]

    full_prompt_lower = ctx.prompt.lower()
    for token in forbidden_tokens:
        assert token not in full_prompt_lower, f"Forbidden ground-truth token '{token}' detected in prompt!"


# ---------------------------------------------------------------------------
# Phase 5K: Repeatability and Determinism
# ---------------------------------------------------------------------------

def test_m5_end_to_end_repeatability(
    synthetic_handoff,
    synthetic_vapt_pack,
    synthetic_protected_handoff,
):
    """
    Phase 5K: Repeat complete pipeline execution twice.
    Verifies byte-for-byte identical output, hashes, and decisions.
    """
    def run_pipeline():
        ctx = ReasoningContextBuilder.build_context(
            handoff_packet=synthetic_handoff,
            model_identifier="qwen2.5-coder:7b",
            cascade_mode=TRACK_D,
            vapt_pack=synthetic_vapt_pack,
            category_id="API-BOLA-001",
            enable_i2_namespace_partitioning=True,
            enable_i3_counterfactual_prompting=True,
            enable_i4_bair=True,
            enable_i5_decision_policy=True,
            enable_i6_handoff=True,
            protected_handoff=synthetic_protected_handoff,
            output_protocol=OutputProtocolIdentifier.JSON_BAIR,
        )
        proto_contract = get_protocol_contract(OutputProtocolIdentifier.JSON_BAIR)
        contract = ReasoningExecutionContract(
            protocol=OutputProtocolIdentifier.JSON_BAIR,
            enable_i1=False,
            enable_i2=True,
            enable_i3=True,
            enable_i4=True,
            enable_i5=True,
            enable_i6=True,
            system_prompt=ctx.system_prompt,
            user_prompt=ctx.user_prompt,
            runtime_schema=None,
            parser=proto_contract.parser,
            validator=proto_contract.validator,
            adapter=proto_contract.adapter,
            budget_tier=4096,
            floor_tokens=1000,
            total_tokens=ctx.token_count,
            protected_handoff_present=True,
            category_id="API-BOLA-001",
        )
        mock_emission = json.dumps({
            "invariant": "Resource access must be restricted to resource owner",
            "evidence_gap": "Missing tenant ownership check on GET order",
            "affected_target": "/api/v1/orders/{id}",
            "decision": "HYPOTHESIS",
            "empirical_facts": ["FACT-SYNTH-01", "FACT-SYNTH-02"],
            "methodology_references": ["CHK-DOC-WSTG-ATHZ-04-001-01"],
            "experiment_action": "SUBSTITUTE_RESOURCE_IDENTIFIER",
            "supporting_outcome": "CROSS_IDENTITY_OBJECT_ACCESSIBLE",
            "disproving_outcome": "CROSS_IDENTITY_OBJECT_DENIED",
            "falsification_description": "Support if user B reads order of user A; disprove if returns 403 Forbidden",
        })
        runner = ReasoningRunner(llm_caller=lambda p, s: mock_emission)
        res = runner.execute_m5_generation(
            contract=contract,
            empirical_evidence_present=True,
            channel_a=synthetic_handoff.channel_a_structural,
            target_asset={"asset_id": "AST-ORDERS-01"},
            category_id="API-BOLA-001",
            vapt_pack=synthetic_vapt_pack,
        )
        return ctx, contract, res

    ctx_run1, contract_run1, res_run1 = run_pipeline()
    ctx_run2, contract_run2, res_run2 = run_pipeline()

    # Identical context builder hashes
    assert ctx_run1.context_builder_hash == ctx_run2.context_builder_hash
    assert ctx_run1.prompt == ctx_run2.prompt
    assert ctx_run1.token_count == ctx_run2.token_count

    # Identical contracts
    assert contract_run1.system_prompt == contract_run2.system_prompt
    assert contract_run1.user_prompt == contract_run2.user_prompt
    assert contract_run1.floor_tokens == contract_run2.floor_tokens

    # Identical canonical hypothesis outputs
    assert res_run1.canonical_hypothesis is not None
    assert res_run2.canonical_hypothesis is not None
    assert res_run1.canonical_hypothesis.model_dump() == res_run2.canonical_hypothesis.model_dump()
    assert res_run1.classification.primary_category == res_run2.classification.primary_category
