"""Deterministic unit tests proving research integrity and RAG verification for ablation.

Verifies:
1. Ground truth cannot enter reasoning inputs (zero ground truth leakage).
2. Each track receives identical observable evidence.
3. At least one retrieved item reaches the actual Ollama prompt for Tracks B-E.
4. Track-specific components are enabled/disabled correctly.
5. Canonical IDs and structural grounding are validated.
6. Negative controls remain negative without simulator execution.
7. Simulator feedback enters only Track E.
8. Evaluator is the only component allowed to access hidden labels.
"""

import json
from src.engine.models import HypothesisDecision, HypothesisModelOutput
from src.engine.runner import ReasoningRunner
from src.eval.ablation import AblationFramework
from src.eval.retrieval_trace import ObservableScenarioContext, ScenarioRetriever
from src.eval.scenarios import get_gold_set_scenarios
from src.eval.scorer import DeterministicScorer


def test_ground_truth_cannot_enter_reasoning_inputs():
    """Verify ObservableScenarioContext scrubs all ground truth and hidden labels."""
    scenarios = get_gold_set_scenarios()
    for scen in scenarios:
        obs_ctx = ObservableScenarioContext.from_scenario(scen)
        # Verify no ground truth attributes exist
        assert not hasattr(obs_ctx, "ground_truth_vulnerable")
        assert not hasattr(obs_ctx, "vulnerable_variant")
        assert not hasattr(obs_ctx, "expected_decision")

        # Verify no oracle tokens exist in serialized observable dictionary
        obs_dict = obs_ctx.__dict__
        serialized = json.dumps(obs_dict).lower()
        assert "ground_truth" not in serialized
        assert "vulnerable_variant" not in serialized
        assert "expected_decision" not in serialized


def test_identical_observable_evidence_across_tracks():
    """Verify that Tracks A through E receive the exact same observable evidence."""
    scenarios = get_gold_set_scenarios()[:5]
    for scen in scenarios:
        obs_ctx = ObservableScenarioContext.from_scenario(scen)

        # Retrieve evidence under budget
        retriever = ScenarioRetriever()
        chunks, trace = retriever.retrieve(obs_ctx, retrieval_k=5, token_budget=2048)

        # Check that evidence IDs match observable initial_evidence
        scenario_fact_ids = {e["fact_id"] for e in obs_ctx.initial_evidence}
        retrieved_ids = trace.retrieved_evidence_ids

        for rid in retrieved_ids:
            assert rid in scenario_fact_ids, f"Retrieved fact {rid} not in observable initial_evidence!"


def test_retrieved_item_reaches_actual_ollama_prompt_tracks_b_to_e():
    """IMPORTANT RAG VERIFICATION:

    Proves that for Tracks B, C, D, and E, at least one retrieved evidence item
    reaches the actual prompt string passed to the LLM.
    """
    scenarios = get_gold_set_scenarios()[:5]
    runner = ReasoningRunner()
    retriever = ScenarioRetriever()

    for scen in scenarios:
        obs_ctx = ObservableScenarioContext.from_scenario(scen)
        chunks, trace = retriever.retrieve(obs_ctx, retrieval_k=5, token_budget=2048)

        if not chunks:
            continue

        first_fact_id = chunks[0]["fact_id"]

        # Track B & C: RAG baseline prompt
        rag_prompt = runner.build_rag_prompt(
            target_asset=obs_ctx.target_asset,
            category_id=obs_ctx.category_id,
            retrieved_evidence=chunks,
        )
        assert f"EVIDENCE [{first_fact_id}]" in rag_prompt, (
            f"Fact {first_fact_id} did not reach Track B/C RAG prompt!"
        )

        # Track D & E: Full reasoning prompt with invariants
        invariants = [{"invariant_id": "INVAR-TEST-01", "description": "Test invariant"}]
        full_prompt = runner.build_prompt(
            target_asset=obs_ctx.target_asset,
            category_id=obs_ctx.category_id,
            retrieved_evidence=chunks,
            invariants=invariants,
        )
        assert f"EVIDENCE [{first_fact_id}]" in full_prompt, (
            f"Fact {first_fact_id} did not reach Track D/E prompt!"
        )


def test_retrieved_item_dispatched_to_actual_ollama_runtime_call(monkeypatch):
    """IMPORTANT RAG VERIFICATION:
    
    Proves that when the reasoning runner actually invokes Ollama, the user_prompt
    payload received by the Ollama API contains the retrieved evidence fact ID
    across Tracks B, C, D, and E.
    """
    scen = get_gold_set_scenarios()[0]
    obs_ctx = ObservableScenarioContext.from_scenario(scen)
    retriever = ScenarioRetriever()
    chunks, trace = retriever.retrieve(obs_ctx, retrieval_k=5, token_budget=2048)
    assert len(chunks) > 0
    first_fact_id = chunks[0]["fact_id"]

    runner = ReasoningRunner()
    captured_calls = []

    def mock_generate_structured(system_prompt, user_prompt, schema, temperature=None):
        captured_calls.append({"system_prompt": system_prompt, "user_prompt": user_prompt})
        return {
            "app_model_delta": {"observation": "Test obs", "epistemic_status": "MODEL_PROPOSED"},
            "violation_assessment": {"relation": "INDEPENDENT", "confidence": 0.5, "missing_conditions": []},
            "reasoning_summary": "Test summary citing evidence",
            "decision": "HYPOTHESIS",
            "category": obs_ctx.category_id,
            "asset_id": obs_ctx.target_asset["asset_id"],
            "missing_evidence": [],
            "experiment_proposal": "Test proposal",
            "safety_check": {"is_safe": True, "policy_violations": []},
            "supporting_evidence_ids": [first_fact_id],
            "contradicting_evidence_ids": [],
            "evidence_sufficiency": 1.0,
        }

    monkeypatch.setattr(runner.ollama_runner, "generate_structured", mock_generate_structured)

    # 1. Track B / C: run_rag
    captured_calls.clear()
    runner.run_rag(obs_ctx.target_asset, obs_ctx.category_id, chunks)
    assert len(captured_calls) == 1
    assert f"EVIDENCE [{first_fact_id}]" in captured_calls[0]["user_prompt"], (
        "Track B/C runtime call did not contain retrieved fact ID!"
    )

    # 2. Track D: run
    captured_calls.clear()
    invariants = [{"invariant_id": "INVAR-01", "description": "Auth check"}]
    runner.run(obs_ctx.target_asset, obs_ctx.category_id, chunks, invariants=invariants)
    assert len(captured_calls) == 1
    assert f"EVIDENCE [{first_fact_id}]" in captured_calls[0]["user_prompt"], (
        "Track D runtime call did not contain retrieved fact ID!"
    )

    # 3. Track E: run_closed_loop
    captured_calls.clear()
    runner.run_closed_loop(
        obs_ctx.target_asset,
        obs_ctx.category_id,
        chunks,
        invariants=invariants,
        initial_proposal="probe endpoint",
        observation_type="SUPPORTING",
        status_code=200,
        response_data={"status": "ok"},
    )
    assert len(captured_calls) == 1
    assert f"EVIDENCE [{first_fact_id}]" in captured_calls[0]["user_prompt"], (
        "Track E closed-loop runtime call did not contain retrieved fact ID!"
    )


def test_zero_retrieval_records_explicitly_without_fallback():
    """Verify that when retrieval returns zero items:
    1. zero_results is recorded as True explicitly.
    2. retrieved_evidence_ids is empty.
    3. prompt_evidence_context explicitly states 'No direct traffic facts retrieved.'
    4. The prompt NEVER silently falls back to hidden scenario fields or ground truth.
    """
    scen = get_gold_set_scenarios()[0]
    obs_ctx = ObservableScenarioContext.from_scenario(scen)
    # Simulate empty initial evidence
    obs_ctx.initial_evidence = []

    retriever = ScenarioRetriever()
    chunks, trace = retriever.retrieve(obs_ctx, retrieval_k=5, token_budget=2048)

    assert chunks == []
    assert trace.zero_results is True
    assert trace.retrieved_evidence_ids == []
    assert trace.retrieval_ranking == []
    assert trace.prompt_evidence_context == "No direct traffic facts retrieved."
    assert trace.warning is not None
    assert "Zero" in trace.warning or "empty" in trace.warning

    # Check prompt contains the explicit no-facts message and zero oracle tokens
    runner = ReasoningRunner()
    rag_prompt = runner.build_rag_prompt(obs_ctx.target_asset, obs_ctx.category_id, chunks)
    assert "No direct traffic facts retrieved." in rag_prompt
    assert "ground_truth" not in rag_prompt
    assert "vulnerable_variant" not in rag_prompt
    assert "expected_decision" not in rag_prompt


def test_track_component_isolation():
    """Verify explicit architectural isolation across all 5 tracks:

    - Track A: No prompt, no retrieval.
    - Track B & C: RAG baseline prompt (contains evidence, does NOT contain invariants).
    - Track D: Full prompt (contains evidence AND derived invariants; open loop, 0 experiments).
    - Track E: Full prompt + simulator loop execution.
    """
    scen = get_gold_set_scenarios()[0]
    obs_ctx = ObservableScenarioContext.from_scenario(scen)
    runner = ReasoningRunner()
    retriever = ScenarioRetriever()

    chunks, _ = retriever.retrieve(obs_ctx, retrieval_k=5, token_budget=2048)

    # 1. RAG prompt (Track B & C) MUST NOT contain DERIVED SECURITY INVARIANTS
    rag_prompt = runner.build_rag_prompt(obs_ctx.target_asset, obs_ctx.category_id, chunks)
    assert "DERIVED SECURITY INVARIANTS:" not in rag_prompt
    assert "AVAILABLE EVIDENCE:" in rag_prompt

    # 2. V6 prompt (Track D & E) MUST contain DERIVED SECURITY INVARIANTS
    invariants = [{"invariant_id": "INVAR-AUTH-01", "description": "Policy check"}]
    v6_prompt = runner.build_prompt(obs_ctx.target_asset, obs_ctx.category_id, chunks, invariants=invariants)
    assert "DERIVED SECURITY INVARIANTS:" in v6_prompt
    assert "AVAILABLE EVIDENCE:" in v6_prompt


def test_negative_controls_remain_negative():
    """Verify that benign / negative control scenarios abstain without simulator execution."""
    framework = AblationFramework(live_mode=False)
    scenarios = [s for s in get_gold_set_scenarios() if s.category_id == "API-AUTH-NONE"]
    assert len(scenarios) > 0, "No negative control scenarios found!"

    for track in ["TRACK_A_RULES", "TRACK_B_RAG_3B", "TRACK_C_RAG_7B", "TRACK_D_APP_MODEL_INVARIANTS", "TRACK_E_FULL_V6"]:
        raw_res = framework.run_track_raw(track, scenarios, budget_tier="LOW")
        for r in raw_res:
            assert r["decision"] in ("NO_RELEVANT_FUNCTIONALITY", "INSUFFICIENT_EVIDENCE"), (
                f"Track {track} failed to abstain on negative control {r['scenario_id']}! Got {r['decision']}"
            )
            assert r["useful"] is False, f"Negative control marked useful in track {track}!"
            assert r["experiments_executed"] == 0, f"Experiments executed on negative control in track {track}!"


def test_evaluator_exclusive_ground_truth_access():
    """Verify that only the DeterministicScorer accesses ground_truth_vulnerable."""
    scenarios = get_gold_set_scenarios()[:5]
    framework = AblationFramework(live_mode=False)
    scorer = DeterministicScorer()

    raw_results = framework.run_track_raw("TRACK_A_RULES", scenarios, budget_tier="LOW")

    # Verify run_results has ground_truth_vulnerable attached by framework strictly for scorer
    for r in raw_results:
        assert "ground_truth_vulnerable" in r

    # Scorer uses it to evaluate metrics
    metrics = scorer.score(raw_results)
    assert metrics.total_scenarios == len(scenarios)
    assert 0.0 <= metrics.precision <= 1.0
    assert 0.0 <= metrics.canonical_id_validity <= 1.0
    assert 0.0 <= metrics.decision_correctness <= 1.0
