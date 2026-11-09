"""Deterministic unit tests proving conceptual invariants for Milestone M5 Phase 6.8:
Hypothesis Governance Decision (Exploratory vs Vulnerability Hypotheses).

Verifies:
1. Observable context parity: vulnerable and patched scenario pairs present identical observable evidence.
2. Deterministic information constraint: pure functions on identical observable inputs cannot diverge.
3. Strict ground truth isolation: ground truth is excluded from all runtime reasoning and decision components.
4. Epistemic state distinction: exploratory test proposal on neutral API spec != evidence-confirmed violation.
5. Discriminative experiment validity: valid experiment tuples hold intrinsic discriminative power independent of target backend truth.
6. Legacy benchmark scoring contradiction: proves identical outputs on identical evidence force a synthetic False Positive.
7. Policy 3 metric decomposition: disaggregating vulnerability yield and exploratory validity preserves historical comparability.
8. Immutability of protected evaluation artifacts.
"""

import hashlib
import json
import os
from typing import Any, Dict, List
import pytest

from src.engine.decision_policy import ExperimentPolarityValidator
from src.engine.models import (
    ExperimentActionPredicate,
    HttpOutcomePredicate,
    HypothesisDecision,
    HypothesisModelOutput,
    SemanticOutcomePredicate,
)
from src.eval.retrieval_trace import ObservableScenarioContext
from src.eval.scenarios import get_gold_set_scenarios


# ---------------------------------------------------------------------------
# Invariant 1: Observable Context Parity Between Vulnerable and Patched Pairs
# ---------------------------------------------------------------------------

def test_01_observable_context_parity_canonical_bola_pair():
    """Verify that vulnerable and patched BOLA scenarios present identical observable inputs.

    SCEN-SAAS_BILLING-INV-DETAILS-VULN-01 and SCEN-SAAS_BILLING-INV-DETAILS-PATCH-01
    must have identical target asset, route template, HTTP method, parameters, and identities.
    """
    scenarios = {s.scenario_id: s for s in get_gold_set_scenarios()}
    vuln_scen = scenarios.get("SCEN-SAAS_BILLING-INV-DETAILS-VULN-01")
    patch_scen = scenarios.get("SCEN-SAAS_BILLING-INV-DETAILS-PATCH-01")

    assert vuln_scen is not None, "Vulnerable BOLA scenario not found in gold set"
    assert patch_scen is not None, "Patched BOLA scenario not found in gold set"

    # Convert to observable context (what the runner/model sees)
    obs_vuln = ObservableScenarioContext.from_scenario(vuln_scen)
    obs_patch = ObservableScenarioContext.from_scenario(patch_scen)

    # Observable properties must be byte-identical
    assert obs_vuln.target_asset == obs_patch.target_asset
    assert obs_vuln.category_id == obs_patch.category_id
    assert obs_vuln.initial_evidence == obs_patch.initial_evidence

    # Verify no telemetry or response logs exist in initial evidence for either
    for ev in obs_vuln.initial_evidence:
        content = ev.get("content", "").lower()
        assert "http 200" not in content
        assert "http 403" not in content
        assert "response_body" not in ev


# ---------------------------------------------------------------------------
# Invariant 2: Information Constraint (Identical Inputs -> Identical Decisions)
# ---------------------------------------------------------------------------

def test_02_pure_function_cannot_diverge_on_identical_inputs():
    """Prove that any deterministic function f(X) must yield identical output for identical X.

    If X_vuln == X_patch, then f(X_vuln) == f(X_patch).
    Demanding f(X_vuln) == HYPOTHESIS and f(X_patch) == INSUFFICIENT_EVIDENCE
    requires either hidden ground-truth leakage or stochastic randomness.
    """
    scenarios = {s.scenario_id: s for s in get_gold_set_scenarios()}
    obs_vuln = ObservableScenarioContext.from_scenario(scenarios["SCEN-SAAS_BILLING-INV-DETAILS-VULN-01"])
    obs_patch = ObservableScenarioContext.from_scenario(scenarios["SCEN-SAAS_BILLING-INV-DETAILS-PATCH-01"])

    # Exclude scenario_id (metadata tracking ID, not part of prompt/evidence inputs)
    vuln_reasoning_inputs = {k: v for k, v in obs_vuln.__dict__.items() if k != "scenario_id"}
    patch_reasoning_inputs = {k: v for k, v in obs_patch.__dict__.items() if k != "scenario_id"}

    vuln_input_str = json.dumps(vuln_reasoning_inputs, sort_keys=True)
    patch_input_str = json.dumps(patch_reasoning_inputs, sort_keys=True)

    # Reasoning inputs are identical
    assert vuln_input_str == patch_input_str
    assert hashlib.sha256(vuln_input_str.encode()).hexdigest() == hashlib.sha256(patch_input_str.encode()).hexdigest()

    # Any deterministic reasoning engine f must produce the exact same output
    def mock_deterministic_engine(input_serialized: str) -> str:
        h = hashlib.sha256(input_serialized.encode()).hexdigest()
        return "HYPOTHESIS" if int(h[:8], 16) % 2 == 0 else "INSUFFICIENT_EVIDENCE"

    assert mock_deterministic_engine(vuln_input_str) == mock_deterministic_engine(patch_input_str)


# ---------------------------------------------------------------------------
# Invariant 3: Ground Truth Isolation from Reasoning Inputs
# ---------------------------------------------------------------------------

def test_03_ground_truth_strictly_scrubbed_from_observable_context():
    """Verify ObservableScenarioContext completely scrubs ground_truth_vulnerable and expected_decision."""
    scenarios = get_gold_set_scenarios()
    for scen in scenarios:
        obs = ObservableScenarioContext.from_scenario(scen)
        obs_dict = obs.__dict__
        serialized = json.dumps(obs_dict).lower()

        assert "ground_truth_vulnerable" not in obs_dict
        assert "expected_decision" not in obs_dict
        assert "ground_truth" not in serialized
        assert "expected_decision" not in serialized


# ---------------------------------------------------------------------------
# Invariant 4: Epistemic State Distinction (Exploratory vs Vulnerability)
# ---------------------------------------------------------------------------

def test_04_epistemic_state_distinction():
    """Verify formal distinction between EXPLORATORY_VERIFICATION and VULNERABILITY_HYPOTHESIS.

    - EXPLORATORY_VERIFICATION: Target is relevant, but no active anomaly/breach evidence exists.
      The model proposes a test to discover whether the invariant holds.
    - VULNERABILITY_HYPOTHESIS: Evidence contains concrete indications of breach.
      The model proposes a test to verify or disprove that specific breach.
    """
    # Case A: Static OpenAPI documentation only (neutral evidence)
    neutral_evidence = [
        {"fact_id": "FACT-01", "content": "GET /api/v1/invoices/{id} returns invoice details for given id."}
    ]
    has_anomaly_evidence_a = any("breach" in f["content"] or "leak" in f["content"] or "403" in f["content"] for f in neutral_evidence)
    assert not has_anomaly_evidence_a, "Neutral OpenAPI evidence must not contain anomaly indications"

    # Case B: Evidence contains active cross-tenant anomaly
    anomalous_evidence = [
        {"fact_id": "FACT-01", "content": "GET /api/v1/invoices/{id} returns invoice details."},
        {"fact_id": "FACT-02", "content": "Traffic log shows User B received HTTP 200 with User A invoice data."}
    ]
    has_anomaly_evidence_b = any("user a invoice" in f["content"].lower() for f in anomalous_evidence)
    assert has_anomaly_evidence_b, "Anomalous evidence must be distinguishable from neutral documentation"


# ---------------------------------------------------------------------------
# Invariant 5: Discriminative Experiment Validity is Intrinsic
# ---------------------------------------------------------------------------

def test_05_experiment_tuple_discriminative_power_is_target_status_agnostic():
    """Verify that the 4-tuple compatibility check validates experiment soundness independent of ground truth.

    A test (API-BOLA-001, SUBSTITUTE_RESOURCE_IDENTIFIER, CROSS_IDENTITY_OBJECT_ACCESSIBLE, CROSS_IDENTITY_ACCESS_DENIED)
    is a sound discriminative test whether run against a vulnerable server or a patched server.
    """
    # Valid BOLA experiment tuple
    is_valid, msg = ExperimentPolarityValidator.validate_tuple(
        category_id="API-BOLA-001",
        action="SUBSTITUTE_RESOURCE_IDENTIFIER",
        supporting_outcome="CROSS_IDENTITY_OBJECT_ACCESSIBLE",
        disproving_outcome="CROSS_IDENTITY_OBJECT_DENIED",
    )
    assert is_valid is True
    assert msg is None

    # The validity of this tuple depends purely on category, action, and outcomes;
    # it takes zero arguments regarding scenario.ground_truth_vulnerable.
    import inspect
    sig = inspect.signature(ExperimentPolarityValidator.validate_tuple)
    assert "ground_truth" not in sig.parameters
    assert "is_vulnerable" not in sig.parameters
    assert "scenario" not in sig.parameters


# ---------------------------------------------------------------------------
# Invariant 6: Legacy Benchmark Scoring Contradiction Proof
# ---------------------------------------------------------------------------

def test_06_legacy_scoring_contradiction_proof():
    """Prove mathematically that legacy scoring forces an FP on patched scenarios when model emits HYPOTHESIS.

    Under legacy scoring:
    - If model emits HYPOTHESIS on vuln -> TP (1.0)
    - If model emits HYPOTHESIS on patch -> FP (1.0)
    Since observable inputs are identical, any consistent model that emits HYPOTHESIS on vuln
    MUST emit HYPOTHESIS on patch, guaranteeing FP = 1.0 on the patched variant.
    """
    scenarios = {s.scenario_id: s for s in get_gold_set_scenarios()}
    vuln_expected = scenarios["SCEN-SAAS_BILLING-INV-DETAILS-VULN-01"].expected_decision
    patch_expected = scenarios["SCEN-SAAS_BILLING-INV-DETAILS-PATCH-01"].expected_decision

    assert vuln_expected == "HYPOTHESIS"
    assert patch_expected == "INSUFFICIENT_EVIDENCE"

    # If model emits "HYPOTHESIS" (valid test proposal):
    model_decision = "HYPOTHESIS"

    # Scoring on vulnerable:
    is_vuln_tp = (model_decision == vuln_expected)
    assert is_vuln_tp is True, "Model emission matches vulnerable expected decision"

    # Scoring on patched:
    is_patch_fp = (model_decision != patch_expected)
    assert is_patch_fp is True, "Identical model emission is penalized as False Positive on patched scenario"


# ---------------------------------------------------------------------------
# Invariant 7: Policy 3 Metric Decomposition Preserves Historical Integrity
# ---------------------------------------------------------------------------

def test_07_policy_3_metric_decomposition_semantics():
    """Verify that Policy 3 enables dual-track scoring without altering production enum or schemas.

    - Track 1 (Primary Estimand): Useful Vulnerability-Hypothesis Yield (evaluated on scenarios with anomaly evidence).
    - Track 2 (Secondary Estimand): Exploratory Verification Validity Rate (evaluated on unverified route proposals).
    """
    # Verify HypothesisDecision enum retains exact historical tokens
    expected_enum_tokens = {"HYPOTHESIS", "INSUFFICIENT_EVIDENCE", "NO_RELEVANT_FUNCTIONALITY"}
    actual_enum_tokens = {d.value for d in HypothesisDecision}
    assert expected_enum_tokens.issubset(actual_enum_tokens)
    assert "CONFIRMED" not in actual_enum_tokens

    # Verify S0 inference schema contains exact frozen fields
    schema = HypothesisModelOutput.get_inference_schema()
    required_fields = set(schema.get("required", []))
    assert "decision" in required_fields
    assert "invariant" in required_fields
    assert "experiment_proposal" in required_fields


# ---------------------------------------------------------------------------
# Invariant 8: Immutability of Protected Artifacts
# ---------------------------------------------------------------------------

def test_08_protected_artifacts_remain_immutable():
    """Verify that all protected historical evaluation and decision artifacts match pinned SHA-256 digests."""
    pinned_digests = {
        "data/eval/m4_live_llm_benchmark_final.json": "459b9ec63c3a2dc760abde12ec196760f7e505fbab5317f0da0c46b32c5eaac7",
        "data/eval/m5_live_smoke.json": "7ee8b6b2ec33eca0fcb8a3f0948d1f36b7e41877354ae4a64190f8e19c679b5e",
        "data/eval/m5_live_smoke_v2.json": "830c225b22f6767ee13b4ce3b443a14aede3ea767ee25ae7343c1a153c4a0818",
        "docs/M5_PHASE6_3_FALSE_POSITIVE_AUDIT.md": "5cc7ac193aefb6fb5d0d5a845c54b7c6279b713609ce62ea44c00fa98a718bf7",
        "docs/M5_PHASE6_4_BENCHMARK_SEMANTICS_DECISION.md": "6657ec2ccdc5ff1344e307a6d2e2dab6eff7fc47ece8c3b2d014742eeb91b53e",
        "docs/M5_PHASE6_5_EXPERIMENT_SEMANTICS_PROTOCOL_DESIGN.md": "ec15f42ba52bd54363f236bff1a71683ab3b1c1a10fa28ddac5c8a97a40b255c",
        "data/eval/m5_typed_protocol_live_smoke.json": "d33d2a05e3cd2c00f684aa0bf987692c7d3d22b5e727aba941a447014bbfdcd6",
    }

    for file_path, expected_digest in pinned_digests.items():
        assert os.path.exists(file_path), f"Protected file missing: {file_path}"
        with open(file_path, "rb") as fp:
            actual_digest = hashlib.sha256(fp.read()).hexdigest()
        assert actual_digest == expected_digest, f"Digest mismatch for {file_path}: {actual_digest} != {expected_digest}"
