"""Integration tests for live local LLM ablation pilot (EXP-0006).

Validates:
1. Real Ollama models (qwen2.5-coder:3b, qwen2.5-coder:7b) execute without mock fallback.
2. Retrieval traces are logged with all 6 required fields.
3. Retrieved items reach actual Ollama prompts.
4. Track E executes simulator loop and closed-loop feedback inference.
"""

import os
import pytest

pytestmark = [pytest.mark.live_ollama]
from src.eval.ablation import AblationFramework
from src.eval.run_pilot_ablation import get_pilot_scenarios
from src.eval.scorer import DeterministicScorer


@pytest.mark.skipif(
    os.environ.get("V6_REQUIRE_LIVE_OLLAMA") != "1",
    reason="Requires live local Ollama daemon (set V6_REQUIRE_LIVE_OLLAMA=1)",
)
def test_live_ablation_pilot_execution_and_rag_trace():
    """Execute live pilot ablation on representative paired scenarios."""
    scenarios = get_pilot_scenarios()[:2]  # 1 vulnerable, 1 non-vulnerable
    framework = AblationFramework(live_mode=True)
    scorer = DeterministicScorer()

    # Run Track B (3B RAG)
    res_b = framework.run_track_raw("TRACK_B_RAG_3B", scenarios, budget_tier="LOW")
    assert len(res_b) == 2
    for r in res_b:
        assert r["model_name"] == "qwen2.5-coder:3b"
        assert r["retrieval_trace"] is not None
        trace = r["retrieval_trace"]
        assert "query" in trace
        assert "retrieved_evidence_ids" in trace
        assert "retrieval_method" in trace
        assert "retrieval_ranking" in trace
        assert "token_budget_cropping" in trace
        assert "prompt_evidence_context" in trace
        assert trace["zero_results"] is False

    # Run Track C (7B RAG)
    res_c = framework.run_track_raw("TRACK_C_RAG_7B", scenarios, budget_tier="LOW")
    assert len(res_c) == 2
    for r in res_c:
        assert r["model_name"] == "qwen2.5-coder:7b"
        assert r["retrieval_trace"] is not None

    # Run Track D (7B App Model + Invariants, open loop)
    res_d = framework.run_track_raw("TRACK_D_APP_MODEL_INVARIANTS", scenarios, budget_tier="LOW")
    assert len(res_d) == 2
    for r in res_d:
        assert r["model_name"] == "qwen2.5-coder:7b"
        assert r["experiments_executed"] == 0

    # Run Track E (7B Full V6 with closed-loop simulator feedback)
    res_e = framework.run_track_raw("TRACK_E_FULL_V6", scenarios, budget_tier="LOW")
    assert len(res_e) == 2
    for r in res_e:
        assert r["model_name"] == "qwen2.5-coder:7b"
        # If vulnerable, simulator should return SUPPORTING and hypothesis confirmed
        if r["ground_truth_vulnerable"]:
            assert r["experiments_executed"] == 1
            assert r["useful"] is True
            assert r["decision"] == "HYPOTHESIS"
        else:
            # If patched, simulator returns CONTRADICTING and model abstains
            assert r["experiments_executed"] == 1
            assert r["useful"] is False
            assert r["decision"] in ("INSUFFICIENT_EVIDENCE", "NO_RELEVANT_FUNCTIONALITY")
