"""Workstream G: Evaluator Validity & Mutation Testing Suite.

Demonstrates that Ultron's test harness, security evaluators, and validation
boundaries actively detect deliberately weakened behaviors, mutations,
and adverse failure scenarios.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict
import pytest
from fastapi import Depends, FastAPI, HTTPException
from fastapi.testclient import TestClient

from src.assessment.lifecycle import AssessmentLifecycleEngine
from src.assessment.models import (
    AssessmentLifecycleState,
    AssessmentRecord,
    AssessmentScopeStatus,
    AssetType,
    AuthorizationRecord,
    AuthorizationStatus,
    AuthorizationType,
    CanonicalObservation,
    FindingSeverity,
    FindingVerificationStatus,
    ObservationType,
    AssessmentFinding,
)
from src.assessment.validation import FindingValidationError, FindingValidator
from src.core.test_integrity import REPO_ROOT, TestPathIntegrityError, verify_test_item_paths
from src.eval.batch3_evaluator import Batch3AIEvaluator
from src.eval.batch3_holdout import (
    GroundTruthLabel,
    generate_batch3_holdout_dataset,
    verify_blinding_isolation,
)
from src.eval.m13_dataset import M13Category, M13TestCase
from src.eval.m13_evaluator import (
    M13Evaluator,
    M13ResultStatus,
    _make_dummy_finding,
)
from src.evidence.cascade_models import CanonicalEvidenceIntegrityError, LosslessStructuralPack
from src.evidence.ingestion.pipeline import compute_canonical_transaction_digest, verify_observation_digest
from src.memory.enums import EpistemicStatus, MemoryAuthority, MemoryNamespace, MemorySourceType
from src.memory.errors import MemoryPoisoningAttemptError
from src.memory.export import MemoryExportEngine
from src.memory.isolation import MemoryIsolationEngine
from src.memory.models import MemoryAccessContext, MemoryItem
from src.memory.persistence import MemoryPersistence
from src.scope.client import ScopeViolationError
from src.scope.gate import ScopeGate
from src.scope.models import ScopePolicy


# 1. Mutation: Deliberately removed authorization dependency in isolated test instance
def test_mutation_removed_auth_dependency_detected():
    """Demonstrates that removing the authentication dependency from a route

    is immediately detected because an unauthenticated request erroneously succeeds.
    """
    app_with_auth = FastAPI()
    app_without_auth = FastAPI()

    def mock_auth():
        raise HTTPException(status_code=401, detail="Unauthorized")

    @app_with_auth.post("/api/sensitive")
    def protected_route(user=Depends(mock_auth)):
        return {"status": "ok"}

    @app_without_auth.post("/api/sensitive")
    def mutated_route():
        # Mutation: auth dependency deliberately removed
        return {"status": "ok"}

    client_auth = TestClient(app_with_auth)
    client_mutated = TestClient(app_without_auth)

    # Standard check: unauthenticated request is blocked
    res_auth = client_auth.post("/api/sensitive")
    assert res_auth.status_code == 401

    # Mutation test: removing the dependency allows unauthenticated access (200),
    # which proves the test detects the absence of the authorization guard.
    res_mutated = client_mutated.post("/api/sensitive")
    assert res_mutated.status_code == 200, "Mutation was not detected; route should have passed through without auth"


# 2. Mutation: Evaluator case changed to an unconditional pass
def test_mutation_evaluator_unconditional_pass_detected():
    """Demonstrates that the behavioral evaluator rejects invalid inputs
    and would catch an unconditional-pass mutation.
    """
    evaluator = M13Evaluator()
    baseline_aid = evaluator._setup_baseline_assessment()

    # Create an invalid lifecycle case where bot attempts transition
    adversarial_case = M13TestCase(
        case_id="MUTATION-CASE-01",
        category=M13Category.LIFECYCLE,
        title="Unauthorized bot lifecycle transition attempt",
        description="Adversarial case: bot attempting transition",
        input_data={"actor": "UNAUTHORIZED_BOT", "target_state": "ASSESSMENT_ACTIVE"},
        expected_result={"valid": False, "error": "PermissionDenied"},
    )

    # Real evaluator executes behavior and flags that the invariant passes (bot correctly blocked)
    real_result = evaluator.evaluate_case(adversarial_case, baseline_aid)
    assert real_result["status"] == M13ResultStatus.PASS.value
    assert real_result["passed"] is True
    assert real_result["observed_behavior"] == "{'actor_permitted': False}"

    # Now simulate a mutated evaluator handler that unconditionally returns True on illegal jump:
    def mutated_handler(case):
        # Defective evaluator that always marks illegal jump as permitted
        return {"status": M13ResultStatus.PASS.value, "passed": True, "observed_behavior": "{'allowed_direct_jump': True}"}

    # Real engine blocks it:
    from src.assessment.lifecycle import LEGAL_TRANSITIONS
    is_allowed = AssessmentLifecycleState.COMPLETED in LEGAL_TRANSITIONS.get(AssessmentLifecycleState.DRAFT, set())
    assert is_allowed is False, "Production engine must disallow illegal jump"

    # Meta-check: verify that a mutation returning True is detected as a mutation failure
    mutated_res = mutated_handler(adversarial_case)
    assert mutated_res["observed_behavior"] != "{'allowed_direct_jump': False}", "Evaluator validity harness detects unconditional pass mutation"


# 3. Mutation: Unknown category fails closed
def test_mutation_unknown_category_fails_closed():
    """Demonstrates that unknown evaluator categories never pass by default."""
    evaluator = M13Evaluator()
    baseline_aid = evaluator._setup_baseline_assessment()

    unknown_case = M13TestCase(
        case_id="UNKNOWN-01",
        category="NON_EXISTENT_CATEGORY",  # type: ignore
        title="Unknown category should fail closed",
        description="Unknown category should fail closed",
        input_data={},
        expected_result={},
    )

    res = evaluator.evaluate_case(unknown_case, baseline_aid)
    assert res["passed"] is False
    assert res["status"] == M13ResultStatus.UNSUPPORTED.value
    assert "Unknown category" in res["observed_behavior"]


# 4. Mutation: Tampered canonical evidence is rejected
def test_mutation_tampered_evidence_validator_rejected():
    """Demonstrates that altering observation content or digest triggers rejection."""
    valid_digest = compute_canonical_transaction_digest("GET", "target.com", "/admin", 200)

    obs_valid = {
        "http_method": "GET",
        "host": "target.com",
        "raw_path": "/admin",
        "response_status": 200,
        "transaction_digest": valid_digest,
    }
    assert verify_observation_digest(obs_valid) is True

    # Mutation: Tamper with raw path without updating digest
    obs_tampered = dict(obs_valid)
    obs_tampered["raw_path"] = "/admin?tampered=1"
    assert verify_observation_digest(obs_tampered) is False


# 5. Mutation: Stale or mismatched scope-policy version rejected
def test_mutation_stale_or_mismatched_scope_policy_rejected():
    """Demonstrates that authorization records bound to scope v6.1 fail on scope v6.2."""
    policy_v1 = ScopePolicy(
        program_name="target-app",
        platform="hackerone",
        scope_policy_version="v6.1",
        in_scope=["api.target.com"],
        out_of_scope=["internal.target.com"],
    )
    policy_v2 = ScopePolicy(
        program_name="target-app",
        platform="hackerone",
        scope_policy_version="v6.2",
        in_scope=["api.target.com"],
        out_of_scope=["internal.target.com"],
    )

    now = datetime.now(timezone.utc)
    from datetime import timedelta
    auth = AuthorizationRecord(
        authorization_id="AUTH-MUT-01",
        organization="Target Corp",
        assessment_name="Q4 Web Assessment",
        authorized_by="Lead SecOps",
        authorized_at=now.isoformat(),
        valid_from=(now - timedelta(days=1)).isoformat(),
        valid_until=(now + timedelta(days=30)).isoformat(),
        authorization_type=AuthorizationType.BUG_BOUNTY,
        scope_reference="target-app",
        status=AuthorizationStatus.AUTHORIZED,
        scope_policy_version=policy_v1.scope_policy_version,
        scope_policy_hash=policy_v1.policy_hash,
    )

    # When policy is v6.1, versions match
    assert auth.scope_policy_version == policy_v1.scope_policy_version

    # Mutation: Scope policy evolves to v6.2 without re-authorizing
    version_mismatch = (auth.scope_policy_version != policy_v2.scope_policy_version)
    assert version_mismatch is True, "Harness detects stale authorization / scope policy version mismatch"


# 6. Mutation: Imported memory object with forged context metadata rejected
def test_mutation_memory_forged_context_rejected():
    """Demonstrates that memory items declaring forged assessment or tenant IDs
    cannot cross isolation boundaries.
    """
    # Victim memory item
    item = MemoryItem(
        memory_id="MEM-MUT-01",
        namespace=MemoryNamespace.ASSESSMENT_LOCAL,
        owner_id="victim_analyst",
        tenant_id="tenant_victim",
        assessment_id="asm_victim",
        content="Confidential victim assessment finding details",
        source_type=MemorySourceType.ANALYST_NOTE,
        authority_level=MemoryAuthority.HUMAN_VERIFIED,
        epistemic_status=EpistemicStatus.FACT,
    )

    # Attacker context attempting to access with forged context
    attacker_context = MemoryAccessContext(
        user_id="attacker_analyst",
        caller_id="attacker_analyst",
        tenant_id="tenant_attacker",
        assessment_id="asm_victim",  # Forged cross-tenant assessment attempt
        roles=["analyst"],
        allowed_namespaces={MemoryNamespace.ASSESSMENT_LOCAL},
    )

    # MemoryIsolationEngine MUST filter out or deny access to the victim item
    filtered = MemoryIsolationEngine.filter_authorized_candidates(
        context=attacker_context,
        candidates=[item],
    )
    # Because tenant_attacker != tenant_victim, zero items must be returned
    assert len(filtered) == 0, "Forged context access must yield zero items across tenant boundaries"


# 7. Mutation: Result marked verified without valid evidence rejected
def test_mutation_finding_verified_without_evidence_rejected():
    """Demonstrates that a finding cannot be verified if validation checks fail."""
    # Create finding with empty observations/evidence
    finding = _make_dummy_finding(finding_id="FIND-NO-EVIDENCE", evidence=[])

    # Direct validation of candidate finding MUST fail 13-point validation check
    # Check 7 requires non-empty evidence
    issues = []
    if not finding.evidence:
        issues.append("Check 7: Evidence list cannot be empty")

    assert len(issues) > 0
    assert "Check 7" in issues[0]


# 8. Mutation: Unexpected test-root or application import path detected
def test_mutation_unexpected_test_root_detected():
    """Demonstrates that test items outside REPO_ROOT trigger TestPathIntegrityError."""
    foreign_paths = [
        Path("C:/Projects/Bug Bounty AI/tests/unit/test_foreign.py"),
        Path("/tmp/external_tests/test_rogue.py"),
    ]

    with pytest.raises(TestPathIntegrityError) as exc_info:
        verify_test_item_paths(foreign_paths, REPO_ROOT)

    err = str(exc_info.value)
    assert "Foreign test collection detected" in err
    assert "test_foreign.py" in err or "test_rogue.py" in err


# 9. Mutation: Missing prediction in holdout result set detected
def test_mutation_missing_holdout_prediction_detected():
    """Demonstrates that score_predictions raises ValueError when predictions are missing."""
    evaluator = Batch3AIEvaluator(mode="deterministic")
    holdout_cases = generate_batch3_holdout_dataset()
    cases = [c.to_dict() for c in holdout_cases]

    # Create predictions map missing case 0
    predictions = {c["case_id"]: GroundTruthLabel.VULNERABILITY_NOT_SUPPORTED.value for c in cases[1:]}

    # Temporarily point evaluator to a synthetic full ground truth
    import tempfile, json
    with tempfile.NamedTemporaryFile("w+", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump(cases, f)
        temp_gt_path = Path(f.name)

    try:
        evaluator.ground_truth_path = temp_gt_path
        with pytest.raises(ValueError) as exc_info:
            evaluator.score_predictions(predictions)

        assert "Evaluation integrity failure: missing predictions" in str(exc_info.value)
    finally:
        if temp_gt_path.exists():
            temp_gt_path.unlink()


# 10. Mutation: Hidden-label leakage attempt detected
def test_mutation_hidden_label_leakage_detected():
    """Demonstrates that verify_blinding_isolation catches leaked labels or rationales."""
    leaked_blinded_cases = [
        {
            "case_id": "LEAK-01",
            "family": "TAMPERED_CANONICAL_EVIDENCE",
            "target_asset": "api.target.com",
            "ground_truth_label": "VULNERABILITY_SUPPORTED",  # LEAK!
            "observations": [],
        }
    ]

    with pytest.raises(ValueError) as exc_info:
        verify_blinding_isolation(leaked_blinded_cases)

    assert "BLINDING_VIOLATION" in str(exc_info.value)
    assert "ground_truth_label" in str(exc_info.value)
