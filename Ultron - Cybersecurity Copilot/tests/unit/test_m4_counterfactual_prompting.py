"""Unit tests for Milestone M4 Phase M4.4: Intervention I3 (Counterfactual Evidence-Gap Reasoning).

Tests strict single-factor isolation, template completeness across all 10 OWASP API categories,
invariant and falsification requirements, deterministic template selection, and non-leading prompt framing.
"""

import json
import os
import pytest
from typing import Any, Dict, List

from src.engine.context_builder import (
    ReasoningContextBuilder,
    TRACK_D,
)
from src.engine.models import (
    FailureClassificationResult,
    HypothesisDecision,
    HypothesisModelOutput,
    I3ExecutionResult,
    PrimaryFailureCategory,
)
from src.engine.prompts import (
    CounterfactualTemplate,
    OWASP_API_COUNTERFACTUAL_TEMPLATES,
    UnknownCounterfactualCategoryError,
    format_counterfactual_reasoning_prompt,
    get_counterfactual_template,
)
from src.engine.runner import (
    OllamaRunner,
    ReasoningRunner,
)
from src.evidence.cascade_models import (
    CascadeHandoffPacket,
    DeterministicRoutingDecision,
    LosslessStructuralPack,
)
from src.knowledge.grounding_validator import KnowledgeGroundingValidator


EXPECTED_OWASP_API_CATEGORIES = [
    "API-AUTH-NONE",
    "API-BFLA-001",
    "API-BOLA-001",
    "API-CROSS-TENANT-001",
    "API-DEVICE-BOLA-001",
    "API-LIFECYCLE-001",
    "API-MULTI-STEP-AUTH-001",
    "API-MUTATION-001",
    "API-ROLE-BOUNDARY-001",
    "API-STATE-001",
]


def test_01_i3_templates_exist_for_all_10_owasp_categories():
    """Requirement 1: I3 template exists for all 10 OWASP API categories in the frozen benchmark."""
    for cat in EXPECTED_OWASP_API_CATEGORIES:
        assert cat in OWASP_API_COUNTERFACTUAL_TEMPLATES, f"Missing template for category: {cat}"
        tmpl = OWASP_API_COUNTERFACTUAL_TEMPLATES[cat]
        assert isinstance(tmpl, CounterfactualTemplate)
        assert tmpl.category_id == cat
        assert len(tmpl.category_name) > 0


def test_02_every_template_contains_invariant_evaluation():
    """Requirement 2: Every template explicitly contains invariant evaluation."""
    for cat, tmpl in OWASP_API_COUNTERFACTUAL_TEMPLATES.items():
        assert len(tmpl.invariant_definition) > 20, f"Invariant definition too short in {cat}"
        lower_inv = tmpl.invariant_definition.lower()
        assert any(term in lower_inv for term in ["must", "invariant", "require", "enforce", "strictly"]), (
            f"Template {cat} does not clearly specify a normative security invariant"
        )


def test_03_every_template_contains_evidence_gap_evaluation():
    """Requirement 3: Every template explicitly contains evidence-gap evaluation."""
    for cat, tmpl in OWASP_API_COUNTERFACTUAL_TEMPLATES.items():
        assert len(tmpl.evidence_gap_focus) > 20, f"Evidence gap focus too short in {cat}"
        lower_gap = tmpl.evidence_gap_focus.lower()
        assert any(term in lower_gap for term in ["examine", "evaluate", "evidence", "gap", "observed", "whether"]), (
            f"Template {cat} does not clearly specify evidence-gap analysis instructions"
        )


def test_04_every_template_requests_falsification_observation():
    """Requirement 4: Every template explicitly requests a falsification observation."""
    for cat, tmpl in OWASP_API_COUNTERFACTUAL_TEMPLATES.items():
        assert len(tmpl.falsification_condition) > 20, f"Falsification condition too short in {cat}"
        lower_fals = tmpl.falsification_condition.lower()
        assert any(term in lower_fals for term in ["disproved", "falsif", "rejected", "reject", "403", "404", "400"]), (
            f"Template {cat} does not specify concrete falsification observation"
        )


def test_05_templates_do_not_assert_vulnerability_exists():
    """Requirement 5: Templates do not assert that a vulnerability exists."""
    forbidden_phrases = [
        "is vulnerable",
        "assume a vulnerability exists",
        "assume this is vulnerable",
        "must find a bug",
        "this endpoint is broken",
    ]
    for cat, tmpl in OWASP_API_COUNTERFACTUAL_TEMPLATES.items():
        text_corpus = (
            f"{tmpl.invariant_definition} {tmpl.evidence_gap_focus} "
            f"{tmpl.counterfactual_violation_condition} {tmpl.falsification_condition} "
            f"{tmpl.negative_control_indicator}"
        ).lower()
        for phrase in forbidden_phrases:
            assert phrase not in text_corpus, f"Forbidden biased phrase '{phrase}' in template {cat}"

    # Verify formatted prompt contains explicit non-leading instruction
    prompt = format_counterfactual_reasoning_prompt(
        target_asset={"asset_id": "AST-01", "method": "GET", "normalized_path": "/api/users"},
        category_id="API-BOLA-001",
        retrieved_evidence=[],
    )
    assert "DO NOT ASSUME A VULNERABILITY EXISTS" in prompt


def test_06_templates_preserve_observed_fact_vs_inference_separation():
    """Requirement 6: Templates preserve observed-fact vs inference separation."""
    prompt = format_counterfactual_reasoning_prompt(
        target_asset={"asset_id": "AST-01", "method": "GET", "normalized_path": "/api/items"},
        category_id="API-BOLA-001",
        retrieved_evidence=[
            {"fact_id": "FACT-01", "source_tool": "proxy", "trust": "UNTRUSTED", "statement": "User requests item 123"}
        ],
        invariants=[{"invariant_id": "INV-01", "statement": "Items scoped to owner"}],
    )
    assert "AVAILABLE EVIDENCE:" in prompt
    assert "EVIDENCE [FACT-01]" in prompt
    assert "DERIVED INVARIANTS:" in prompt
    assert "INV-01" in prompt
    assert "COUNTERFACTUAL INSTRUCTIONS:" in prompt
    assert "Rely strictly on canonical facts and verified structural diffs" in prompt


def test_07_templates_do_not_introduce_unrestricted_cot():
    """Requirement 7: Templates do not introduce unrestricted Chain-of-Thought."""
    for cat in EXPECTED_OWASP_API_CATEGORIES:
        prompt = format_counterfactual_reasoning_prompt(
            target_asset={"asset_id": "AST-01", "method": "GET", "normalized_path": "/api/test"},
            category_id=cat,
            retrieved_evidence=[],
        )
        assert "<thought>" not in prompt
        assert "<scratchpad>" not in prompt
        assert "chain of thought" not in prompt.lower()
        assert "think step by step" not in prompt.lower()


def test_08_templates_remain_within_bounded_prompt_structure():
    """Requirement 8: Templates remain within bounded prompt structure (< 1200 tokens)."""
    for cat in EXPECTED_OWASP_API_CATEGORIES:
        prompt = format_counterfactual_reasoning_prompt(
            target_asset={"asset_id": "AST-01", "method": "POST", "normalized_path": "/api/resource/update"},
            category_id=cat,
            retrieved_evidence=[
                {"fact_id": "FACT-01", "source_tool": "proxy", "trust": "UNTRUSTED", "statement": "Test fact 1"},
                {"fact_id": "FACT-02", "source_tool": "proxy", "trust": "UNTRUSTED", "statement": "Test fact 2"},
            ],
            parameters=[{"param_id": "PRM-01", "name": "user_id", "location": "body"}],
        )
        token_est = ReasoningContextBuilder.estimate_tokens(prompt)
        assert token_est < 1200, f"Prompt for {cat} exceeds token budget: {token_est} tokens"


def test_09_i3_does_not_invoke_i1_constrained_decoding():
    """Requirement 9: I3 does not invoke I1 constrained decoding (schema=None)."""
    captured_schema = "NOT_CALLED"

    def mock_caller(prompt: str, schema: Any) -> str:
        nonlocal captured_schema
        captured_schema = schema
        return json.dumps({
            "decision": "NO_RELEVANT_FUNCTIONALITY",
            "reasoning_summary": "Clean public resource",
        })

    runner = ReasoningRunner(llm_caller=mock_caller)
    res = runner.execute_i3_generation(prompt="test prompt", category_id="API-BOLA-001")
    assert captured_schema is None, "I3 execution must NOT pass schema constraint (must be unconstrained sampling)"
    assert res.classification.is_valid is True


def test_10_i3_does_not_invoke_i2_segregated_namespace_fields():
    """Requirement 10: I3 does not invoke I2 segregated namespace fields."""
    prompt = format_counterfactual_reasoning_prompt(
        target_asset={"asset_id": "AST-01", "method": "GET", "normalized_path": "/api/users"},
        category_id="API-BOLA-001",
        retrieved_evidence=[],
    )
    # Must NOT mention I2 raw fields in requested JSON schema
    assert "empirical_fact_ids" not in prompt
    assert "methodology_chunk_ids" not in prompt
    # Must use canonical S0 fields
    assert "supporting_evidence_ids" in prompt
    assert "methodology_references" in prompt


def test_11_existing_canonical_output_schema_remains_intact():
    """Requirement 11: Existing canonical output schema remains intact."""
    s0 = HypothesisModelOutput(
        decision=HypothesisDecision.HYPOTHESIS,
        invariant="Ownership check required",
        evidence_gap="Missing cross-account verification",
        affected_target="AST-01",
        supporting_evidence_ids=["FACT-01"],
        methodology_references=[],
        reasoning_summary="Observed IDOR condition",
        experiment_proposal="Replay with secondary user token",
    )
    assert s0.decision == HypothesisDecision.HYPOTHESIS
    assert s0.invariant == "Ownership check required"
    assert s0.evidence_gap == "Missing cross-account verification"
    assert s0.affected_target == "AST-01"
    assert s0.supporting_evidence_ids == ["FACT-01"]
    assert s0.methodology_references == []
    assert s0.reasoning_summary == "Observed IDOR condition"
    assert s0.experiment_proposal == "Replay with secondary user token"


def test_12_existing_decision_semantics_remain_intact():
    """Requirement 12: Existing decision semantics remain intact."""
    valid_decisions = {d.value for d in HypothesisDecision}
    assert valid_decisions == {"NO_RELEVANT_FUNCTIONALITY", "INSUFFICIENT_EVIDENCE", "HYPOTHESIS"}
    assert "CONFIRMED" not in valid_decisions


def test_13_confirmed_cannot_be_emitted_by_reasoning_engine():
    """Requirement 13: CONFIRMED cannot be emitted by the reasoning engine (fails closed)."""
    def mock_caller(prompt: str, schema: Any) -> str:
        return json.dumps({
            "decision": "CONFIRMED",
            "invariant": "Some invariant",
            "reasoning_summary": "Attacker verified exploit",
        })

    runner = ReasoningRunner(llm_caller=mock_caller)
    res = runner.execute_i3_generation(prompt="test prompt", category_id="API-BOLA-001")
    assert res.classification.is_valid is False
    assert res.hypothesis is None
    assert res.classification.primary_category == PrimaryFailureCategory.SCHEMA_VALIDITY_FAILURE


def test_14_missing_evidence_does_not_get_fabricated():
    """Requirement 14: Missing evidence does not get fabricated (fails grounding gating)."""
    ch_a = LosslessStructuralPack(
        asset_id="AST-01",
        endpoint_id="EP-01",
        route_template="/api/users/{id}",
        http_method="GET",
        application_mutability="READ_ONLY",
        observed_facts=[
            {"fact_id": "FACT-CANONICAL-01", "statement": "User fetched their own profile."},
        ],
    )
    validator = KnowledgeGroundingValidator()

    def mock_caller(prompt: str, schema: Any) -> str:
        return json.dumps({
            "decision": "HYPOTHESIS",
            "invariant": "Owner check required",
            "evidence_gap": "Missing auth check",
            "affected_target": "AST-01",
            "supporting_evidence_ids": ["FACT-FABRICATED-999"],
            "reasoning_summary": "Fabricated fact citation",
            "experiment_proposal": "Probe endpoint",
        })

    runner = ReasoningRunner(llm_caller=mock_caller)
    res = runner.execute_i3_generation(
        prompt="test prompt",
        category_id="API-BOLA-001",
        grounding_validator=validator,
        channel_a=ch_a,
    )
    assert res.classification.is_valid is False
    assert res.hypothesis is None
    assert res.classification.primary_category == PrimaryFailureCategory.SEMANTIC_GROUNDING_FAILURE


def test_15_i3_prompt_selection_is_deterministic():
    """Requirement 15: I3 prompt selection is deterministic from category/evidence-gap type."""
    # 1. All 10 exact canonical categories resolve identically across repeated calls
    for _ in range(3):
        for cat in EXPECTED_OWASP_API_CATEGORIES:
            tmpl = get_counterfactual_template(cat)
            assert tmpl.category_id == cat
            assert tmpl.category_name == OWASP_API_COUNTERFACTUAL_TEMPLATES[cat].category_name

            # Case insensitivity for canonical IDs
            lower_tmpl = get_counterfactual_template(cat.lower())
            assert lower_tmpl.category_id == cat

    # 2. Exact predefined aliases resolve identically
    alias_expectations = {
        "BOLA": "API-BOLA-001",
        "IDOR": "API-BOLA-001",
        "BFLA": "API-BFLA-001",
        "CROSS-TENANT": "API-CROSS-TENANT-001",
        "DEVICE-BOLA": "API-DEVICE-BOLA-001",
        "LIFECYCLE": "API-LIFECYCLE-001",
        "MULTI-STEP": "API-MULTI-STEP-AUTH-001",
        "MUTATION": "API-MUTATION-001",
        "ROLE-BOUNDARY": "API-ROLE-BOUNDARY-001",
        "STATE": "API-STATE-001",
        "AUTH-NONE": "API-AUTH-NONE",
        "API-BFLA-002": "API-BFLA-001",
        "STATE-MACHINE-001": "API-STATE-001",
        "INFO-EXPOSURE-001": "API-MUTATION-001",
    }
    for alias, expected_target in alias_expectations.items():
        assert get_counterfactual_template(alias).category_id == expected_target
        assert get_counterfactual_template(alias.lower()).category_id == expected_target


def test_15b_unknown_category_fails_closed():
    """Safety Patch: Unknown category fails closed with UnknownCounterfactualCategoryError."""
    unknown_categories = [
        "UNKNOWN-NONEXISTENT-CATEGORY",
        "SQLI-001",
        "XSS-REFLECTED",
        "API-INJECTION-999",
        "RANDOM-SECURITY-LABEL",
    ]
    for cat in unknown_categories:
        with pytest.raises(UnknownCounterfactualCategoryError) as exc_info:
            get_counterfactual_template(cat)
        assert "Unsupported or unknown counterfactual category" in str(exc_info.value)


def test_15c_empty_category_fails_closed():
    """Safety Patch: Empty, whitespace, or None category fails closed."""
    for empty_val in ["", "   ", "\t\n", None]:
        with pytest.raises(UnknownCounterfactualCategoryError) as exc_info:
            get_counterfactual_template(empty_val)
        assert "Category ID cannot be empty or malformed" in str(exc_info.value)


def test_15d_malformed_category_fails_closed():
    """Safety Patch: Malformed category identifiers fail closed."""
    malformed_categories = [
        "12345",
        "!@#$%^&*()",
        "A",  # Short prefix must NOT loosely match API-AUTH-NONE
        "API-",
        "NONE",
    ]
    for malformed in malformed_categories:
        with pytest.raises(UnknownCounterfactualCategoryError):
            get_counterfactual_template(malformed)


def test_15e_no_unknown_input_can_resolve_to_api_bola_001():
    """Safety Patch: No unknown input can resolve to API-BOLA-001 (silent fallback eliminated)."""
    probe_inputs = [
        "UNKNOWN-NONEXISTENT-CATEGORY",
        "BOLA-ATTACK-SIMULATOR",
        "API-UNKNOWN",
        "GENERIC_AUTH",
        "",
        "   ",
        None,
        "default",
        "fallback",
    ]
    for probe in probe_inputs:
        with pytest.raises(UnknownCounterfactualCategoryError):
            template = get_counterfactual_template(probe)
            # Extra assertion if somehow it didn't raise
            assert template.category_id != "API-BOLA-001"


def test_15f_context_builder_fails_closed_on_unknown_category():
    """Safety Patch: ReasoningContextBuilder fails closed when I3 category is unknown or missing."""
    ch_a = LosslessStructuralPack(
        asset_id="AST-01",
        endpoint_id="EP-01",
        route_template="/api/users",
        http_method="GET",
        application_mutability="READ_ONLY",
    )
    routing = DeterministicRoutingDecision(
        schema_version="2.0.0",
        escalate=False,
        has_high_risk_signal=False,
        high_risk_signals=[],
        fail_safe_triggered=False,
    )
    handoff = CascadeHandoffPacket(
        schema_version="2.0.0",
        channel_a_structural=ch_a,
        validated_triage=None,
        routing_decision=routing,
        provenance_hash="hash123",
    )

    # Unknown category passed explicitly
    with pytest.raises(UnknownCounterfactualCategoryError):
        ReasoningContextBuilder.build_context(
            handoff_packet=handoff,
            model_identifier="qwen2.5-coder:7b",
            cascade_mode=TRACK_D,
            enable_i3_counterfactual_prompting=True,
            category_id="UNKNOWN-CATEGORY",
        )

    # Missing category_id and triage is None
    with pytest.raises(UnknownCounterfactualCategoryError):
        ReasoningContextBuilder.build_context(
            handoff_packet=handoff,
            model_identifier="qwen2.5-coder:7b",
            cascade_mode=TRACK_D,
            enable_i3_counterfactual_prompting=True,
            category_id=None,
        )


def test_15g_decorated_prefixed_suffixed_and_natural_language_fail_closed():
    """Hardening: Decorated, prefixed, suffixed, and natural language category strings fail closed."""
    # 1. Decorated canonical IDs
    decorated_cases = [
        "[API-BOLA-001]",
        "{API-BOLA-001}",
        "<API-BOLA-001>",
        "**API-BOLA-001**",
        "(API-BOLA-001)",
        "API-BOLA-001.",
    ]
    for dec in decorated_cases:
        with pytest.raises(UnknownCounterfactualCategoryError):
            get_counterfactual_template(dec)

    # 2. Prefixed canonical IDs
    prefixed_cases = [
        "PREFIX_API-BOLA-001",
        "VULN_API-BOLA-001",
        "CATEGORY_API-BFLA-001",
        "OWASP_API-CROSS-TENANT-001",
    ]
    for pref in prefixed_cases:
        with pytest.raises(UnknownCounterfactualCategoryError):
            get_counterfactual_template(pref)

    # 3. Suffixed canonical IDs
    suffixed_cases = [
        "API-BOLA-001_SUFFIX",
        "API-BOLA-001-EXTRA",
        "API-BOLA-001_v2",
        "API-BFLA-001_VARIANT",
    ]
    for suff in suffixed_cases:
        with pytest.raises(UnknownCounterfactualCategoryError):
            get_counterfactual_template(suff)

    # 4. Natural-language strings containing a canonical ID
    natural_lang_cases = [
        "This looks like an API-BOLA-001 vulnerability",
        "Endpoint exhibits API-BFLA-001 behavior",
        "Testing for API-CROSS-TENANT-001 in customer endpoints",
        "API-AUTH-NONE is suspected here",
    ]
    for nl in natural_lang_cases:
        with pytest.raises(UnknownCounterfactualCategoryError):
            get_counterfactual_template(nl)


def test_16_negative_control_wording_remains_non_leading():
    """Requirement 16: Negative-control wording remains non-leading."""
    for cat, tmpl in OWASP_API_COUNTERFACTUAL_TEMPLATES.items():
        assert "NO_RELEVANT_FUNCTIONALITY" in tmpl.negative_control_indicator
        assert len(tmpl.negative_control_indicator) > 20


def test_17_vulnerable_scenarios_receive_counterfactual_framing():
    """Requirement 17: Vulnerable scenarios receive the counterfactual framing."""
    runner = ReasoningRunner()
    prompt = runner.build_i3_counterfactual_prompt(
        target_asset={"asset_id": "AST-VULN-01", "method": "GET", "normalized_path": "/api/tenants/{id}/data"},
        category_id="API-CROSS-TENANT-001",
        retrieved_evidence=[
            {"fact_id": "FACT-01", "statement": "Tenant A receives Tenant B records"},
        ],
    )
    assert "EVALUATION FRAMEWORK (DO NOT ASSUME A VULNERABILITY EXISTS):" in prompt
    assert "1. RELEVANT INVARIANT:" in prompt
    assert "2. EVIDENCE-GAP ANALYSIS:" in prompt
    assert "3. COUNTERFACTUAL VIOLATION CONDITION:" in prompt
    assert "4. FALSIFICATION REQUIREMENT:" in prompt
    assert "NEGATIVE-CONTROL SAFETY RULE:" in prompt
    assert "API-CROSS-TENANT-001" in prompt


def test_18_baseline_prompt_remains_available_for_clean_comparison():
    """Requirement 18: Baseline prompt remains available for clean comparison."""
    runner = ReasoningRunner()
    baseline_prompt = runner.build_prompt(
        target_asset={"asset_id": "AST-01", "method": "GET", "normalized_path": "/api/users"},
        category_id="API-BOLA-001",
        retrieved_evidence=[],
    )
    # Baseline prompt should NOT have the counterfactual framing header
    assert "COUNTERFACTUAL REASONING PROTOCOL" not in baseline_prompt
    assert "EVALUATION FRAMEWORK (DO NOT ASSUME A VULNERABILITY EXISTS):" not in baseline_prompt

    # ReasoningContextBuilder without I3 flag also produces clean baseline
    ch_a = LosslessStructuralPack(
        asset_id="AST-01",
        endpoint_id="EP-01",
        route_template="/api/users",
        http_method="GET",
        application_mutability="READ_ONLY",
    )
    routing = DeterministicRoutingDecision(
        schema_version="2.0.0",
        escalate=False,
        has_high_risk_signal=False,
        high_risk_signals=[],
        fail_safe_triggered=False,
    )
    handoff = CascadeHandoffPacket(
        schema_version="2.0.0",
        channel_a_structural=ch_a,
        validated_triage=None,
        routing_decision=routing,
        provenance_hash="hash123",
    )
    ctx_baseline = ReasoningContextBuilder.build_context(
        handoff_packet=handoff,
        model_identifier="qwen2.5-coder:7b",
        cascade_mode=TRACK_D,
        enable_i3_counterfactual_prompting=False,
    )
    assert "COUNTERFACTUAL REASONING INSTRUCTIONS" not in ctx_baseline.prompt

    ctx_i3 = ReasoningContextBuilder.build_context(
        handoff_packet=handoff,
        model_identifier="qwen2.5-coder:7b",
        cascade_mode=TRACK_D,
        enable_i3_counterfactual_prompting=True,
        category_id="API-BOLA-001",
    )
    assert "COUNTERFACTUAL REASONING INSTRUCTIONS" in ctx_i3.prompt


@pytest.mark.live_ollama
@pytest.mark.skipif(
    os.environ.get("SKIP_LIVE_OLLAMA") == "1",
    reason="Live Ollama execution skipped by environment flag",
)
def test_19_live_ollama_i3_unconstrained_sanity_check():
    """Requirement 19: Lightweight live Ollama sanity check under unconstrained sampling."""
    runner = OllamaRunner(num_predict=300, temperature=0.0)
    if not runner.is_available():
        pytest.skip("Local Ollama daemon is not reachable at 127.0.0.1:11434")

    reasoning_runner = ReasoningRunner(ollama_runner=runner)
    prompt = reasoning_runner.build_i3_counterfactual_prompt(
        target_asset={
            "asset_id": "AST-PUBLIC-HEALTH",
            "method": "GET",
            "normalized_path": "/health",
            "application_mutability": "READ_ONLY",
        },
        category_id="API-AUTH-NONE",
        retrieved_evidence=[
            {"fact_id": "FACT-HEALTH-01", "statement": "GET /health returns HTTP 200 with status UP."},
        ],
    )

    # Execute I3 generation under UNCONSTRAINED sampling
    result = reasoning_runner.execute_i3_generation(prompt=prompt, category_id="API-AUTH-NONE")
    assert isinstance(result, I3ExecutionResult)
    assert len(result.raw_response) > 0
    assert result.latency_ms > 0
    assert result.template_category_id == "API-AUTH-NONE"
    assert result.classification.primary_category in (
        PrimaryFailureCategory.VALID,
        PrimaryFailureCategory.SCHEMA_VALIDITY_FAILURE,
        PrimaryFailureCategory.MAX_TOKEN_TRUNCATION,
        PrimaryFailureCategory.PARSER_FAILURE,
    )
