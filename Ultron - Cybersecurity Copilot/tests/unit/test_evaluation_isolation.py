"""Unit tests verifying research evaluation readiness and ground-truth isolation (Priority 6)."""

import inspect
import json
from pathlib import Path
from src.eval.ablation import AblationFramework
from src.eval.scenarios import get_gold_set_scenarios
from src.eval.scorer import DeterministicScorer
import src.engine.runner as runner_module
import src.engine.models as engine_models_module


def test_ablation_framework_executes_all_five_tracks():
    """
    Priority 6: Verify the evaluation harness can execute all 5 tracks:
    1. Rules baseline (TRACK_A_RULES)
    2. RAG + 3B (TRACK_B_RAG_3B)
    3. RAG + 7B (TRACK_C_RAG_7B)
    4. RAG + Application Model (TRACK_D_APP_MODEL_INVARIANTS)
    5. Full v6 (TRACK_E_FULL_V6)
    """
    framework = AblationFramework()
    results = framework.run_all_ablations()

    required_tracks = [
        "TRACK_A_RULES",
        "TRACK_B_RAG_3B",
        "TRACK_C_RAG_7B",
        "TRACK_D_APP_MODEL_INVARIANTS",
        "TRACK_E_FULL_V6",
    ]
    for track in required_tracks:
        assert track in results, f"Missing required evaluation track: {track}"
        metrics = results[track]
        assert metrics.total_scenarios == len(get_gold_set_scenarios())
        assert 0.0 <= metrics.grounding_accuracy <= 1.0
        assert 0.0 <= metrics.precision <= 1.0
        assert 0.0 <= metrics.recall <= 1.0


def test_ground_truth_isolation_from_reasoning_engine():
    """
    Priority 6: Verify that ground truth is strictly inaccessible to the reasoning engine:
    - src.engine does NOT import src.eval
    - ReasoningRunner.build_prompt does not take ground truth parameters
    - HypothesisModelOutput schema does not contain ground truth labels
    """
    runner_source = inspect.getsource(runner_module)
    models_source = inspect.getsource(engine_models_module)

    # 1. Verify no imports of eval or ground truth in engine
    assert "src.eval" not in runner_source
    assert "src.eval" not in models_source
    assert "ground_truth" not in runner_source
    assert "ground_truth" not in models_source

    # 2. Inspect signature of build_prompt
    sig = inspect.signature(runner_module.ReasoningRunner.build_prompt)
    param_names = list(sig.parameters.keys())
    assert "ground_truth" not in param_names
    assert "expected_decision" not in param_names
    assert "vulnerable_variant" not in param_names


def test_application_family_dataset_separation():
    """
    Priority 6: Verify application-family-level dataset separation.
    Scenarios must represent distinct business domains without cross-contamination.
    """
    scenarios = get_gold_set_scenarios()
    families = {scen.app_family for scen in scenarios}

    # Must contain at least 3 distinct application families
    assert len(families) >= 3
    assert "saas_billing" in families
    assert "ecommerce_orders" in families
    assert "identity_provider" in families

    # Verify each family has designated assets and distinct hosts
    hosts = set()
    for scen in scenarios:
        host = scen.target_asset.get("host")
        assert host is not None, f"Scenario {scen.scenario_id} missing host"
        hosts.add(host)
    assert len(hosts) >= 2


def test_experiment_log_has_no_premature_superiority_claims():
    """
    Priority 6: Verify EXPERIMENT_LOG.md does not claim v6 outperforms RAG
    before formal evaluation has taken place.
    """
    log_path = Path("docs/EXPERIMENT_LOG.md") if Path("docs/EXPERIMENT_LOG.md").exists() else Path("EXPERIMENT_LOG.md")
    assert log_path.exists()
    content = log_path.read_text(encoding="utf-8")

    forbidden_phrases = [
        "v6 outperforms",
        "V6 outperforms",
        "eliminates false positive reporting on patched",
        "achieves 100% discriminative experiment quality",
    ]
    for phrase in forbidden_phrases:
        assert phrase.lower() not in content.lower(), f"Premature claim detected in EXPERIMENT_LOG.md: {phrase}"


def test_runtime_dataflow_and_prompt_contain_no_hidden_ground_truth_labels():
    """
    Priority 6 & EXP-0003 Audit: Verify that hidden ground truth labels
    NEVER leak into reasoning prompts or simulator observable outputs.
    """
    from src.eval.scenarios import get_gold_set_scenarios
    from src.eval.simulator import HeadlessSimulator
    from src.eval.synthetic_app import SyntheticApp
    from src.hypothesis.experiment import ExperimentProposal, MutationClass, ExpectedObservations

    scenarios = get_gold_set_scenarios()
    sim = HeadlessSimulator()
    runner = runner_module.ReasoningRunner()

    forbidden_tokens = [
        "ground_truth_vulnerable",
        "is_vulnerable",
        "is_patched",
        "oracle_label",
        "expected_class",
    ]

    for scen in scenarios:
        # 1. Build prompt for scenario
        prompt = runner.build_prompt(
            target_asset=scen.target_asset,
            category_id=scen.category_id,
            retrieved_evidence=scen.initial_evidence,
            invariants=[
                {"invariant_id": "INV-TEST", "statement": "Test invariant", "asset_id": scen.target_asset["asset_id"]}
            ],
        )

        for token in forbidden_tokens:
            assert token not in prompt, f"Forbidden token '{token}' leaked into prompt for {scen.scenario_id}"

        # 2. Execute experiment against synthetic app
        app = SyntheticApp(scen.scenario_id, vulnerable_variant=scen.vulnerable_variant)
        exp = ExperimentProposal(
            objective="Verify authorization boundary",
            target_asset_id=scen.target_asset["asset_id"],
            mutation_class=MutationClass.CROSS_IDENTITY_REPLAY,
            actor_identity_id="user_b",
            target_identity_id="user_a",
            expected_observations=ExpectedObservations(
                supporting_observation="Returns HTTP 200",
                contradicting_observation="Returns HTTP 403",
            ),
        )
        res = sim.execute_experiment(exp, app)

        # 3. Check observable observation emitted to engine
        obs_str = f"{res.observation_type} {res.status_code} {res.response_data} {res.evidence_item.statement}"
        for token in forbidden_tokens:
            assert token not in obs_str, f"Forbidden token '{token}' leaked into simulator observation"
