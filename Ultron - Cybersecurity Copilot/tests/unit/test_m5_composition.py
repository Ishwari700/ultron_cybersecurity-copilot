"""M5 Comprehensive Composition Test Suite.

Milestone M5: Reasoning Interface & Protocol Reconciliation.
Validates:
- All 15 pairwise intervention combinations (I2+I3, I2+I4, I2+I5, I2+I6, I3+I4, I3+I5, I3+I6, I4+I5, I4+I6, I5+I6)
- Full composition invariants (I1=0 and I1=1 with I2..I6)
- Prompt/protocol contradiction detection
- I6 protection and zero silent dropping
- I3 pre-allocation budgeting and zero leakage
- BairJsonObject validation and schema conformity
- Deterministic S0 adaptation
- Pre-flight contract validation (16 checks)
- Offline mock execution with zero live LLM calls
"""

import json
import re
from typing import Any, Dict, List, Optional
import pytest
from pydantic import ValidationError

from src.engine.bair_extractor import (
    BairParseError,
    BairSchemaError,
    map_bair_json_to_s0,
    parse_bair_json,
    validate_bair_json,
)
from src.engine.context_builder import (
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
# Test Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def structural_pack():
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
            {"fact_id": "FACT-ORDERS-01", "statement": "User B accessed order owned by User A"},
            {"fact_id": "FACT-ORDERS-02", "statement": "HTTP 200 returned with full order body"},
        ],
        parameter_lineage=[
            {"param_id": "P-ID", "param_name": "id", "location": "path"},
        ],
        raw_body_sample='{"order_id": 42, "user_id": "A", "total": 99.50}',
    )


@pytest.fixture
def vapt_pack():
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
def sample_handoff(structural_pack):
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
        channel_a_structural=structural_pack,
        validated_triage=triage,
        routing_decision=routing,
        provenance_hash="mock_hash_32chars_hex_12345678",
    )


@pytest.fixture
def protected_handoff(structural_pack):
    return HandoffSerializer.serialize(
        invariant="Resource access must be restricted to the resource owner",
        evidence_gap_type=EvidenceGapType.MISSING_CROSS_IDENTITY_OBJECT_VERIFICATION,
        class1_predicates=structural_pack,
    )


# ---------------------------------------------------------------------------
# Phase 4C: BairJsonObject Unit Tests
# ---------------------------------------------------------------------------

def test_bair_json_object_valid_hypothesis():
    """BairJsonObject accepts a valid HYPOTHESIS structure with all slots."""
    obj = BairJsonObject(
        invariant="Tenants must not access other tenants' data",
        evidence_gap="Missing server-side ownership verification check",
        affected_target="/api/v1/orders/{id}",
        decision=HypothesisDecision.HYPOTHESIS,
        empirical_facts=["FACT-ORDERS-01", "FACT-ORDERS-02"],
        methodology_references=["CHK-DOC-WSTG-ATHZ-04-001-01"],
        experiment_action="SUBSTITUTE_RESOURCE_IDENTIFIER",
        supporting_outcome="CROSS_IDENTITY_OBJECT_ACCESSIBLE",
        disproving_outcome="CROSS_IDENTITY_OBJECT_DENIED",
        falsification_description="Support if user B reads user A order; disprove if returns 403 Forbidden",
    )
    assert obj.decision == HypothesisDecision.HYPOTHESIS
    assert obj.experiment_action == "SUBSTITUTE_RESOURCE_IDENTIFIER"
    assert obj.supporting_outcome == "CROSS_IDENTITY_OBJECT_ACCESSIBLE"
    assert obj.disproving_outcome == "CROSS_IDENTITY_OBJECT_DENIED"
    assert len(obj.empirical_facts) == 2
    assert len(obj.methodology_references) == 1


def test_bair_json_object_rejects_confirmed():
    """CONFIRMED decision is unconditionally rejected across models and validators."""
    with pytest.raises(ValidationError) as exc:
        BairJsonObject(
            invariant="Security invariant",
            evidence_gap="Some gap",
            affected_target="/api/v1/resource",
            decision="CONFIRMED",  # type: ignore
            empirical_facts=["FACT-01"],
            methodology_references=["CHK-01"],
            falsification_plan="Support if 200, disprove if 403",
        )
    assert "CONFIRMED" in str(exc.value)


def test_bair_json_object_namespace_isolation():
    """Facts must match FACT regex and cannot contain CHK; methodology must match CHK and cannot contain FACT."""
    # CHK in empirical_facts
    with pytest.raises(ValidationError) as exc:
        BairJsonObject(
            invariant="Invariant",
            evidence_gap="Gap",
            affected_target="/api",
            decision=HypothesisDecision.HYPOTHESIS,
            empirical_facts=["CHK-DOC-01"],
            methodology_references=[],
            falsification_plan="Support if 200, disprove if 403",
        )
    assert "INVALID_NAMESPACE_BREACH" in str(exc.value)

    # FACT in methodology_references
    with pytest.raises(ValidationError) as exc:
        BairJsonObject(
            invariant="Invariant",
            evidence_gap="Gap",
            affected_target="/api",
            decision=HypothesisDecision.HYPOTHESIS,
            empirical_facts=["FACT-01"],
            methodology_references=["FACT-02"],
            falsification_plan="Support if 200, disprove if 403",
        )
    assert "INVALID_NAMESPACE_BREACH" in str(exc.value)


def test_bair_json_object_falsification_completeness():
    """Falsification plan must contain both supporting and disproving observations for HYPOTHESIS."""
    with pytest.raises(ValidationError) as exc:
        BairJsonObject(
            invariant="Invariant",
            evidence_gap="Gap",
            affected_target="/api",
            decision=HypothesisDecision.HYPOTHESIS,
            empirical_facts=["FACT-01"],
            methodology_references=[],
            falsification_plan="Only supporting observation is stated here",
        )
    assert "falsifying observation" in str(exc.value).lower() or "disproving" in str(exc.value).lower()


# ---------------------------------------------------------------------------
# Phase 4E & 4F: Parser, Validator, and Adapter Tests
# ---------------------------------------------------------------------------

def test_parse_bair_json_strips_markdown():
    """parse_bair_json cleanly strips markdown code fences."""
    raw = """```json
    {
      "invariant": "Test invariant",
      "evidence_gap": "Test gap",
      "affected_target": "/test",
      "decision": "HYPOTHESIS",
      "empirical_facts": ["FACT-01"],
      "methodology_references": ["CHK-01"],
      "falsification_plan": "Support if 200, disprove if 403"
    }
    ```"""
    data = parse_bair_json(raw)
    assert isinstance(data, dict)
    assert data["decision"] == "HYPOTHESIS"
    assert data["empirical_facts"] == ["FACT-01"]


def test_map_bair_json_to_s0():
    """Deterministic 1:1 mapping from BairJsonObject to canonical HypothesisModelOutput."""
    bair = BairJsonObject(
        invariant="Tenant invariant",
        evidence_gap="Auth gap",
        affected_target="/api/orders/42",
        decision=HypothesisDecision.HYPOTHESIS,
        empirical_facts=["FACT-A", "FACT-B"],
        methodology_references=["CHK-1"],
        experiment_action="SUBSTITUTE_RESOURCE_IDENTIFIER",
        supporting_outcome="CROSS_IDENTITY_OBJECT_ACCESSIBLE",
        disproving_outcome="CROSS_IDENTITY_OBJECT_DENIED",
        falsification_description="Support if 200, disprove if 403",
    )
    s0 = map_bair_json_to_s0(bair, target_asset={"asset_id": "AST-ORDERS"}, category_id="API-BOLA-001")
    assert s0.invariant == "Tenant invariant"
    assert s0.evidence_gap == "Auth gap"
    assert s0.affected_target == "/api/orders/42"
    assert s0.decision == HypothesisDecision.HYPOTHESIS
    assert s0.supporting_evidence_ids == ["FACT-A", "FACT-B"]
    assert s0.methodology_references == ["CHK-1"]
    assert s0.experiment_action == "SUBSTITUTE_RESOURCE_IDENTIFIER"
    assert s0.supporting_outcome == "CROSS_IDENTITY_OBJECT_ACCESSIBLE"
    assert s0.disproving_outcome == "CROSS_IDENTITY_OBJECT_DENIED"
    assert s0.falsification_description == "Support if 200, disprove if 403"
    assert "Action: SUBSTITUTE_RESOURCE_IDENTIFIER" in s0.experiment_proposal
    assert s0.category == "API-BOLA-001"
    assert s0.asset_id == "AST-ORDERS"


# ---------------------------------------------------------------------------
# Phase 4J: Pairwise Intervention Composition Tests (All 10 Pairwise Variants)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "enable_i2,enable_i3,enable_i4,enable_i5,enable_i6,pair_name",
    [
        (True, True, False, False, False, "I2+I3"),
        (True, False, True, False, False, "I2+I4"),
        (True, False, False, True, False, "I2+I5"),
        (True, False, False, False, True, "I2+I6"),
        (False, True, True, False, False, "I3+I4"),
        (False, True, False, True, False, "I3+I5"),
        (False, True, False, False, True, "I3+I6"),
        (False, False, True, True, False, "I4+I5"),
        (False, False, True, False, True, "I4+I6"),
        (False, False, False, True, True, "I5+I6"),
    ],
)
def test_m5_pairwise_composition(
    sample_handoff,
    vapt_pack,
    protected_handoff,
    enable_i2,
    enable_i3,
    enable_i4,
    enable_i5,
    enable_i6,
    pair_name,
):
    """Test all 10 pairwise intervention combinations for zero prompt shadowing."""
    ctx = ReasoningContextBuilder.build_context(
        handoff_packet=sample_handoff,
        model_identifier="qwen2.5-coder:7b",
        cascade_mode=TRACK_D,
        vapt_pack=vapt_pack,
        category_id="API-BOLA-001",
        enable_i2_namespace_partitioning=enable_i2,
        enable_i3_counterfactual_prompting=enable_i3,
        enable_i4_bair=enable_i4,
        enable_i5_decision_policy=enable_i5,
        enable_i6_handoff=enable_i6,
        protected_handoff=protected_handoff if enable_i6 else None,
        output_protocol=OutputProtocolIdentifier.JSON_BAIR,
    )

    full_prompt = ctx.prompt

    # Protocol instruction must ALWAYS be present
    assert "OUTPUT FORMAT (BOUNDED ANALYTICAL INFERENCE REPRESENTATION - JSON_BAIR)" in full_prompt
    assert "<bair>" not in full_prompt  # No XML collision!

    # Assert individual intervention semantics are present without shadowing
    if enable_i2:
        assert "EPISTEMIC BOUNDARY RULES & NAMESPACE CONSTRAINTS" in full_prompt
        assert "<empirical_target_evidence>" in full_prompt
    if enable_i3:
        assert "EVALUATION FRAMEWORK (DO NOT ASSUME A VULNERABILITY EXISTS)" in full_prompt
        assert "COUNTERFACTUAL REASONING INSTRUCTIONS" in full_prompt
    if enable_i5:
        assert "CALIBRATED ABSTENTION CONTRACT" in full_prompt
    if enable_i6:
        assert "PROTECTED 3B -> 7B INVARIANT HANDOFF" in full_prompt
        assert protected_handoff.invariant in full_prompt


@pytest.mark.parametrize(
    "enable_i2,enable_i3,enable_i4,enable_i5,enable_i6,pair_name",
    [
        (True, False, False, False, False, "I1+I2"),
        (False, True, False, False, False, "I1+I3"),
        (False, False, True, False, False, "I1+I4"),
        (False, False, False, True, False, "I1+I5"),
        (False, False, False, False, True, "I1+I6"),
    ],
)
def test_m5_i1_pairwise_composition(
    sample_handoff,
    vapt_pack,
    protected_handoff,
    enable_i2,
    enable_i3,
    enable_i4,
    enable_i5,
    enable_i6,
    pair_name,
):
    """
    Test all 5 I1 pairwise combinations (I1+I2, I1+I3, I1+I4, I1+I5, I1+I6).
    Enforces all 11 Phase 4.1 contract and isolation invariants.
    """
    ctx = ReasoningContextBuilder.build_context(
        handoff_packet=sample_handoff,
        model_identifier="qwen2.5-coder:7b",
        cascade_mode=TRACK_D,
        vapt_pack=vapt_pack if enable_i2 else None,
        category_id="API-BOLA-001",
        enable_i2_namespace_partitioning=enable_i2,
        enable_i3_counterfactual_prompting=enable_i3,
        enable_i4_bair=enable_i4,
        enable_i5_decision_policy=enable_i5,
        enable_i6_handoff=enable_i6,
        protected_handoff=protected_handoff if enable_i6 else None,
        output_protocol=OutputProtocolIdentifier.JSON_BAIR,
    )

    # 1. Exactly one OutputProtocolContract
    proto_contract = get_protocol_contract(OutputProtocolIdentifier.JSON_BAIR)
    assert isinstance(proto_contract, OutputProtocolContract)
    assert proto_contract.identifier == OutputProtocolIdentifier.JSON_BAIR

    # 2. JSON_BAIR remains the selected protocol
    assert ctx.provenance_metadata["output_protocol"] == OutputProtocolIdentifier.JSON_BAIR.value
    assert "OUTPUT FORMAT (BOUNDED ANALYTICAL INFERENCE REPRESENTATION - JSON_BAIR)" in ctx.system_prompt

    # 3. I1=1 binds the runtime schema to the JSON_BAIR schema
    runtime_schema = proto_contract.runtime_schema_factory(True)
    assert runtime_schema is not None
    assert runtime_schema == BairJsonObject.get_inference_schema()
    assert "properties" in runtime_schema
    assert "empirical_facts" in runtime_schema["properties"]
    assert "methodology_references" in runtime_schema["properties"]
    assert "falsification_plan" in runtime_schema["properties"]

    # 4. Parser remains parse_bair_json
    assert proto_contract.parser == parse_bair_json

    # 5. Validator remains validate_bair_json
    assert proto_contract.validator == validate_bair_json

    # 6. Adapter remains map_bair_json_to_s0
    assert proto_contract.adapter == map_bair_json_to_s0

    # 7. The enabled second intervention remains present
    if enable_i2:
        assert "EPISTEMIC BOUNDARY RULES & NAMESPACE CONSTRAINTS" in ctx.system_prompt
        assert "<empirical_target_evidence>" in ctx.user_prompt
    if enable_i3:
        assert "EVALUATION FRAMEWORK (DO NOT ASSUME A VULNERABILITY EXISTS)" in ctx.system_prompt
        assert "COUNTERFACTUAL REASONING INSTRUCTIONS" in ctx.user_prompt
    if enable_i4:
        assert ctx.provenance_metadata.get("i4_bair_enabled") is True
        assert "falsification_plan" in ctx.system_prompt
    if enable_i5:
        assert "CALIBRATED ABSTENTION CONTRACT" in ctx.system_prompt
    if enable_i6:
        assert "PROTECTED 3B -> 7B INVARIANT HANDOFF" in ctx.user_prompt
        assert protected_handoff.invariant in ctx.user_prompt

    # 8. No intervention shadows another
    assert "OUTPUT FORMAT (BOUNDED ANALYTICAL INFERENCE REPRESENTATION - JSON_BAIR)" in ctx.system_prompt

    # 9. No contradictory serialization directives exist
    assert "<bair>" not in ctx.prompt
    assert "</bair>" not in ctx.prompt
    assert "Emit your evaluation strictly as XML" not in ctx.prompt

    # 10. Contract validation succeeds for a valid configuration
    valid_contract = ReasoningExecutionContract(
        protocol=OutputProtocolIdentifier.JSON_BAIR,
        enable_i1=True,
        enable_i2=enable_i2,
        enable_i3=enable_i3,
        enable_i4=enable_i4,
        enable_i5=enable_i5,
        enable_i6=enable_i6,
        system_prompt=ctx.system_prompt,
        user_prompt=ctx.user_prompt,
        runtime_schema=runtime_schema,
        parser=proto_contract.parser,
        validator=proto_contract.validator,
        adapter=proto_contract.adapter,
        budget_tier=4096,
        floor_tokens=500,
        total_tokens=ctx.token_count,
        protected_handoff_present=enable_i6,
        category_id="API-BOLA-001",
    )
    validate_reasoning_contract(valid_contract)

    # 11. Contract validation fails closed when deliberately given a mismatched protocol
    mismatched_protocol_contract = ReasoningExecutionContract(
        protocol=OutputProtocolIdentifier.BAIR_XML,
        enable_i1=True,
        enable_i2=enable_i2,
        enable_i3=enable_i3,
        enable_i4=enable_i4,
        enable_i5=enable_i5,
        enable_i6=enable_i6,
        system_prompt=ctx.system_prompt,
        user_prompt=ctx.user_prompt,
        runtime_schema=runtime_schema,
        parser=proto_contract.parser,
        validator=proto_contract.validator,
        adapter=proto_contract.adapter,
        budget_tier=4096,
        floor_tokens=500,
        total_tokens=ctx.token_count,
        protected_handoff_present=enable_i6,
        category_id="API-BOLA-001",
    )
    with pytest.raises(ContractCompilationError):
        validate_reasoning_contract(mismatched_protocol_contract)

    mismatched_schema_contract = ReasoningExecutionContract(
        protocol=OutputProtocolIdentifier.JSON_BAIR,
        enable_i1=True,
        enable_i2=enable_i2,
        enable_i3=enable_i3,
        enable_i4=enable_i4,
        enable_i5=enable_i5,
        enable_i6=enable_i6,
        system_prompt=ctx.system_prompt,
        user_prompt=ctx.user_prompt,
        runtime_schema=None,  # Deliberate missing schema when I1=True
        parser=proto_contract.parser,
        validator=proto_contract.validator,
        adapter=proto_contract.adapter,
        budget_tier=4096,
        floor_tokens=500,
        total_tokens=ctx.token_count,
        protected_handoff_present=enable_i6,
        category_id="API-BOLA-001",
    )
    with pytest.raises(ContractCompilationError):
        validate_reasoning_contract(mismatched_schema_contract)


# ---------------------------------------------------------------------------
# Phase 4K: Full-Composition Invariant ({I1:0, I2:1, I3:1, I4:1, I5:1, I6:1})
# ---------------------------------------------------------------------------

def test_full_composition_invariant_i1_off(sample_handoff, vapt_pack, protected_handoff):
    """
    Key M4.9 regression case:
    I1=0, I2=1, I3=1, I4=1, I5=1, I6=1.
    Must satisfy all 14 architectural points.
    """
    ctx = ReasoningContextBuilder.build_context(
        handoff_packet=sample_handoff,
        model_identifier="qwen2.5-coder:7b",
        cascade_mode=TRACK_D,
        vapt_pack=vapt_pack,
        category_id="API-BOLA-001",
        enable_i2_namespace_partitioning=True,
        enable_i3_counterfactual_prompting=True,
        enable_i4_bair=True,
        enable_i5_decision_policy=True,
        enable_i6_handoff=True,
        protected_handoff=protected_handoff,
        output_protocol=OutputProtocolIdentifier.JSON_BAIR,
    )

    # 1. I2 semantics present
    assert "EPISTEMIC BOUNDARY RULES & NAMESPACE CONSTRAINTS" in ctx.system_prompt
    assert "<empirical_target_evidence>" in ctx.user_prompt
    assert "<security_testing_methodology>" in ctx.user_prompt

    # 2. I3 semantics present
    assert "EVALUATION FRAMEWORK (DO NOT ASSUME A VULNERABILITY EXISTS)" in ctx.system_prompt
    assert "COUNTERFACTUAL REASONING INSTRUCTIONS" in ctx.user_prompt

    # 3. I5 semantics present
    assert "CALIBRATED ABSTENTION CONTRACT" in ctx.system_prompt

    # 4. I6 protected handoff present
    assert "PROTECTED 3B -> 7B INVARIANT HANDOFF" in ctx.user_prompt
    assert protected_handoff.invariant in ctx.user_prompt

    # 5. JSON_BAIR protocol instructions present
    assert "OUTPUT FORMAT (BOUNDED ANALYTICAL INFERENCE REPRESENTATION - JSON_BAIR)" in ctx.system_prompt

    # 6. NO XML BAIR serialization instructions present
    assert "<bair>" not in ctx.prompt
    assert "</bair>" not in ctx.prompt
    assert "Emit your evaluation strictly as XML" not in ctx.prompt

    # 7. No conflicting "output JSON" instructions duplicated by I2/I3/I5
    # Verify protocol owns serialization format
    json_instructions = [
        line for line in ctx.system_prompt.splitlines()
        if "output valid json" in line.lower() or "strictly as a single json object" in line.lower()
    ]
    assert len(json_instructions) == 1

    proto_contract = get_protocol_contract(OutputProtocolIdentifier.JSON_BAIR)

    # 8. Exactly one output protocol is selected
    assert ctx.provenance_metadata["output_protocol"] == OutputProtocolIdentifier.JSON_BAIR.value

    # 9. Parser is JSON_BAIR parser
    assert proto_contract.parser == parse_bair_json

    # 10. Validator is JSON_BAIR validator
    assert proto_contract.validator == validate_bair_json

    # 11. Adapter is JSON_BAIR adapter
    assert proto_contract.adapter == map_bair_json_to_s0

    # 12. Runtime schema is None for I1=0
    assert proto_contract.runtime_schema_factory(False) is None

    # 13. Ground truth remains absent
    assert "is_vulnerable" not in ctx.prompt.lower()
    assert "expected_label" not in ctx.prompt.lower()

    # 14. No intervention is silently suppressed
    assert ctx.provenance_metadata.get("i3_counterfactual_enabled") is True
    assert ctx.provenance_metadata.get("i4_bair_enabled") is True
    assert ctx.provenance_metadata.get("i5_decision_policy_enabled") is True
    assert ctx.provenance_metadata.get("i6_handoff_enabled") is True


def test_full_composition_invariant_i1_on(sample_handoff, vapt_pack, protected_handoff):
    """
    Full composition with I1=1:
    I1=1, I2=1, I3=1, I4=1, I5=1, I6=1.
    Verifies runtime schema is the JSON_BAIR schema, prompt invariants hold,
    and contract validation passes.
    """
    ctx = ReasoningContextBuilder.build_context(
        handoff_packet=sample_handoff,
        model_identifier="qwen2.5-coder:7b",
        cascade_mode=TRACK_D,
        vapt_pack=vapt_pack,
        category_id="API-BOLA-001",
        enable_i2_namespace_partitioning=True,
        enable_i3_counterfactual_prompting=True,
        enable_i4_bair=True,
        enable_i5_decision_policy=True,
        enable_i6_handoff=True,
        protected_handoff=protected_handoff,
        output_protocol=OutputProtocolIdentifier.JSON_BAIR,
    )

    proto_contract = get_protocol_contract(OutputProtocolIdentifier.JSON_BAIR)
    schema = proto_contract.runtime_schema_factory(True)

    # 1. Runtime schema is JSON_BAIR schema
    assert schema is not None
    assert schema == BairJsonObject.get_inference_schema()
    assert "properties" in schema
    assert "empirical_facts" in schema["properties"]
    assert "methodology_references" in schema["properties"]
    assert "falsification_plan" in schema["properties"]

    # 2. I2 semantics present
    assert "EPISTEMIC BOUNDARY RULES & NAMESPACE CONSTRAINTS" in ctx.system_prompt
    assert "<empirical_target_evidence>" in ctx.user_prompt
    assert "<security_testing_methodology>" in ctx.user_prompt

    # 3. I3 semantics present
    assert "EVALUATION FRAMEWORK (DO NOT ASSUME A VULNERABILITY EXISTS)" in ctx.system_prompt
    assert "COUNTERFACTUAL REASONING INSTRUCTIONS" in ctx.user_prompt

    # 4. I5 semantics present
    assert "CALIBRATED ABSTENTION CONTRACT" in ctx.system_prompt

    # 5. I6 protected handoff present
    assert "PROTECTED 3B -> 7B INVARIANT HANDOFF" in ctx.user_prompt
    assert protected_handoff.invariant in ctx.user_prompt

    # 6. JSON_BAIR protocol instructions present
    assert "OUTPUT FORMAT (BOUNDED ANALYTICAL INFERENCE REPRESENTATION - JSON_BAIR)" in ctx.system_prompt

    # 7. NO XML BAIR serialization instructions
    assert "<bair>" not in ctx.prompt
    assert "</bair>" not in ctx.prompt
    assert "Emit your evaluation strictly as XML" not in ctx.prompt

    # 8. Protocol exclusivity & no duplicate formatting commands
    json_instructions = [
        line for line in ctx.system_prompt.splitlines()
        if "output valid json" in line.lower() or "strictly as a single json object" in line.lower()
    ]
    assert len(json_instructions) == 1
    assert ctx.provenance_metadata["output_protocol"] == OutputProtocolIdentifier.JSON_BAIR.value

    # 9. Pipeline bindings
    assert proto_contract.parser == parse_bair_json
    assert proto_contract.validator == validate_bair_json
    assert proto_contract.adapter == map_bair_json_to_s0

    # 10. Ground truth absent
    assert "is_vulnerable" not in ctx.prompt.lower()
    assert "expected_label" not in ctx.prompt.lower()

    # 11. No intervention silently suppressed
    assert ctx.provenance_metadata.get("i3_counterfactual_enabled") is True
    assert ctx.provenance_metadata.get("i4_bair_enabled") is True
    assert ctx.provenance_metadata.get("i5_decision_policy_enabled") is True
    assert ctx.provenance_metadata.get("i6_handoff_enabled") is True

    # 12. Full contract validation succeeds under I1=1
    full_contract = ReasoningExecutionContract(
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
    validate_reasoning_contract(full_contract)


# ---------------------------------------------------------------------------
# Phase 4L: Prompt / Protocol Contradiction Test
# ---------------------------------------------------------------------------

def test_prompt_protocol_contradiction_detection(sample_handoff, protected_handoff):
    """
    Fails closed if prompt commands JSON but parser expects XML,
    or prompt commands XML but parser expects JSON.
    """
    ctx = ReasoningContextBuilder.build_context(
        handoff_packet=sample_handoff,
        model_identifier="qwen2.5-coder:7b",
        enable_i4_bair=True,
        output_protocol=OutputProtocolIdentifier.JSON_BAIR,
    )

    # Contradiction Case 1: Prompt is JSON_BAIR, but parser passed is parse_bair (XML)
    contract_mismatch_1 = ReasoningExecutionContract(
        protocol=OutputProtocolIdentifier.JSON_BAIR,
        enable_i1=False,
        system_prompt=ctx.system_prompt,
        user_prompt=ctx.user_prompt,
        runtime_schema=None,
        parser=lambda x: {},  # Wrong parser
        validator=validate_bair_json,
        adapter=map_bair_json_to_s0,
        budget_tier=4096,
        floor_tokens=100,
        total_tokens=200,
    )
    with pytest.raises(ContractCompilationError) as exc:
        validate_reasoning_contract(contract_mismatch_1)
    assert "Parser mismatch" in str(exc.value)

    # Contradiction Case 2: Protocol is BAIR_XML, but prompt is JSON_BAIR
    contract_mismatch_2 = ReasoningExecutionContract(
        protocol=OutputProtocolIdentifier.BAIR_XML,
        enable_i1=False,
        system_prompt=ctx.system_prompt,  # Contains JSON_BAIR formatting!
        user_prompt=ctx.user_prompt,
        runtime_schema=None,
        parser=get_protocol_contract(OutputProtocolIdentifier.BAIR_XML).parser,
        validator=get_protocol_contract(OutputProtocolIdentifier.BAIR_XML).validator,
        adapter=get_protocol_contract(OutputProtocolIdentifier.BAIR_XML).adapter,
        budget_tier=4096,
        floor_tokens=100,
        total_tokens=200,
    )
    with pytest.raises(ContractCompilationError) as exc:
        validate_reasoning_contract(contract_mismatch_2)
    assert "Prompt missing BAIR XML tags" in str(exc.value) or "contains JSON_BAIR" in str(exc.value)


# ---------------------------------------------------------------------------
# Phase 4M: I6 Protection Tests
# ---------------------------------------------------------------------------

def test_i6_fits_normally_retained(sample_handoff, protected_handoff):
    """I6 fits within budget -> retained in user prompt."""
    ctx = ReasoningContextBuilder.build_context(
        handoff_packet=sample_handoff,
        budget_tier=4096,
        enable_i6_handoff=True,
        protected_handoff=protected_handoff,
    )
    assert "PROTECTED 3B -> 7B INVARIANT HANDOFF" in ctx.user_prompt
    assert protected_handoff.invariant in ctx.user_prompt


def test_i6_does_not_fit_deterministic_overflow_failure(sample_handoff, protected_handoff):
    """I6 does not fit -> deterministic ContextBudgetOverflowError (never silently dropped)."""
    with pytest.raises(ContextBudgetOverflowError):
        ReasoningContextBuilder.build_context(
            handoff_packet=sample_handoff,
            budget_tier=50,  # Insufficient budget for mandatory floor + I6
            enable_i6_handoff=True,
            protected_handoff=protected_handoff,
        )


def test_i6_missing_protected_handoff_fails_closed(sample_handoff):
    """If enable_i6_handoff=True but protected_handoff is None, raises ContractCompilationError."""
    with pytest.raises(ContractCompilationError):
        ReasoningContextBuilder.build_context(
            handoff_packet=sample_handoff,
            budget_tier=4096,
            enable_i6_handoff=True,
            protected_handoff=None,
        )


# ---------------------------------------------------------------------------
# Phase 4N: I3 Budget Tests
# ---------------------------------------------------------------------------

def test_i3_contributes_to_pre_allocation_floor(sample_handoff):
    """I3 counterfactual instructions contribute to pre-allocation floor tokens."""
    ctx_without_i3 = ReasoningContextBuilder.build_context(
        handoff_packet=sample_handoff,
        category_id="API-BOLA-001",
        enable_i3_counterfactual_prompting=False,
    )

    ctx_with_i3 = ReasoningContextBuilder.build_context(
        handoff_packet=sample_handoff,
        category_id="API-BOLA-001",
        enable_i3_counterfactual_prompting=True,
    )

    # I3 must increase token count by counterfactual instructions
    assert ctx_with_i3.token_count > ctx_without_i3.token_count
    assert "p1_counterfactual_instructions" in ctx_with_i3.partition_tokens
    assert ctx_with_i3.partition_tokens["p1_counterfactual_instructions"] > 0


def test_i3_overflow_results_in_deterministic_failure(sample_handoff):
    """If I3 pushes the mandatory floor above budget, ContextBudgetOverflowError is raised."""
    # Compute base tokens
    ctx = ReasoningContextBuilder.build_context(
        handoff_packet=sample_handoff,
        category_id="API-BOLA-001",
        enable_i3_counterfactual_prompting=False,
    )
    exact_base_floor = ctx.partition_tokens["p0_system_policy"] + ctx.partition_tokens["p1_target_envelope"]

    with pytest.raises(ContextBudgetOverflowError):
        ReasoningContextBuilder.build_context(
            handoff_packet=sample_handoff,
            budget_tier=exact_base_floor + 5,  # Too tight to fit I3 counterfactual block
            category_id="API-BOLA-001",
            enable_i3_counterfactual_prompting=True,
        )


# ---------------------------------------------------------------------------
# Phase 4H: Pre-Flight Contract Validation (16 Checks)
# ---------------------------------------------------------------------------

def test_validate_reasoning_contract_success(sample_handoff, protected_handoff):
    """A fully coherent contract compiles successfully."""
    ctx = ReasoningContextBuilder.build_context(
        handoff_packet=sample_handoff,
        category_id="API-BOLA-001",
        enable_i2_namespace_partitioning=True,
        enable_i3_counterfactual_prompting=True,
        enable_i4_bair=True,
        enable_i5_decision_policy=True,
        enable_i6_handoff=True,
        protected_handoff=protected_handoff,
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
    # Must validate without error
    validate_reasoning_contract(contract)


def test_validate_reasoning_contract_detects_forbidden_tokens(sample_handoff):
    """Pre-flight validator rejects forbidden ground-truth tokens."""
    ctx = ReasoningContextBuilder.build_context(
        handoff_packet=sample_handoff,
        output_protocol=OutputProtocolIdentifier.JSON_BAIR,
    )
    proto_contract = get_protocol_contract(OutputProtocolIdentifier.JSON_BAIR)

    contract = ReasoningExecutionContract(
        protocol=OutputProtocolIdentifier.JSON_BAIR,
        system_prompt=ctx.system_prompt + "\nis_vulnerable: true",  # Forbidden ground truth!
        user_prompt=ctx.user_prompt,
        runtime_schema=None,
        parser=proto_contract.parser,
        validator=proto_contract.validator,
        adapter=proto_contract.adapter,
        budget_tier=4096,
        floor_tokens=100,
        total_tokens=200,
    )
    with pytest.raises(ContractCompilationError) as exc:
        validate_reasoning_contract(contract)
    assert "Forbidden ground-truth token" in str(exc.value)


# ---------------------------------------------------------------------------
# Phase 4G & 4P: Mock End-to-End Pipeline Execution (Zero Live LLM Calls)
# ---------------------------------------------------------------------------

def test_m5_runner_end_to_end_mock_success(sample_handoff, protected_handoff):
    """Deterministic end-to-end execution of M5 pipeline using mock model caller."""
    ctx = ReasoningContextBuilder.build_context(
        handoff_packet=sample_handoff,
        category_id="API-BOLA-001",
        enable_i2_namespace_partitioning=True,
        enable_i3_counterfactual_prompting=True,
        enable_i4_bair=True,
        enable_i5_decision_policy=True,
        enable_i6_handoff=True,
        protected_handoff=protected_handoff,
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
        floor_tokens=500,
        total_tokens=ctx.token_count,
        protected_handoff_present=True,
        category_id="API-BOLA-001",
    )

    mock_llm_emission = json.dumps({
        "invariant": "Resource access restricted to owner",
        "evidence_gap": "Missing ownership check on GET order",
        "affected_target": "/api/v1/orders/{id}",
        "decision": "HYPOTHESIS",
        "empirical_facts": ["FACT-ORDERS-01", "FACT-ORDERS-02"],
        "methodology_references": ["CHK-DOC-WSTG-ATHZ-04-001-01"],
        "experiment_action": "SUBSTITUTE_RESOURCE_IDENTIFIER",
        "supporting_outcome": "CROSS_IDENTITY_OBJECT_ACCESSIBLE",
        "disproving_outcome": "CROSS_IDENTITY_OBJECT_DENIED",
        "falsification_description": "Support if 200 returned with other user order; disprove if 403 Forbidden returned",
    })

    runner = ReasoningRunner(llm_caller=lambda prompt, schema: mock_llm_emission)
    result = runner.execute_m5_generation(
        contract=contract,
        empirical_evidence_present=True,
        channel_a=sample_handoff.channel_a_structural,
        target_asset={"asset_id": "AST-ORDERS-01"},
        category_id="API-BOLA-001",
    )

    assert result.contract_valid is True
    assert result.classification.is_valid is True
    assert result.classification.primary_category == PrimaryFailureCategory.VALID
    assert result.canonical_hypothesis is not None
    assert result.canonical_hypothesis.decision == HypothesisDecision.HYPOTHESIS
    assert result.canonical_hypothesis.supporting_evidence_ids == ["FACT-ORDERS-01", "FACT-ORDERS-02"]


def test_m5_runner_preflight_rejection_zero_llm_calls(sample_handoff):
    """Pre-flight contract failure stops execution before any LLM call."""
    llm_called = False

    def recording_caller(prompt, schema):
        nonlocal llm_called
        llm_called = True
        return "{}"

    ctx = ReasoningContextBuilder.build_context(
        handoff_packet=sample_handoff,
        output_protocol=OutputProtocolIdentifier.JSON_BAIR,
    )

    # Invalid contract: missing parser
    contract = ReasoningExecutionContract(
        protocol=OutputProtocolIdentifier.JSON_BAIR,
        system_prompt=ctx.system_prompt,
        user_prompt=ctx.user_prompt,
        parser=None,  # Invalid!
        validator=validate_bair_json,
        adapter=map_bair_json_to_s0,
        budget_tier=4096,
        floor_tokens=100,
        total_tokens=200,
    )

    runner = ReasoningRunner(llm_caller=recording_caller)
    result = runner.execute_m5_generation(contract=contract)

    assert result.contract_valid is False
    assert "missing a callable parser" in result.compilation_error
    assert llm_called is False  # ZERO LLM calls executed!
