"""Adversarial and Concurrency Test Suite for Milestone M2.75.

Covers security hardening requirements AH through AX and adversarial threat scenarios:
AH. Auth-refresh SSRF attempt (private IP / out-of-scope refresh URL blocked)
AI. Auth-refresh cross-target attempt (target A credential using target B endpoint)
AJ. Auth-refresh cross-identity attempt (user_a credential using user_b token)
AK. Approval before CSRF consumption (CSRF token remains UNCONSUMED if approval fails)
AL. Approval before refresh
AM. Approval before signing
AN. Final TOCTOU descriptor mismatch
AO. Final destination/IP mismatch
AP. Signing-key ownership mismatch
AQ. State string collision with evidence taxonomy
AR. Concurrent CSRF consumption (multithreaded race)
AS. Concurrent refresh (multithreaded race)
AT. Stale session replacement
AU. Nonce race (multithreaded race)
AV. Observation cannot become vulnerability-confirmed
AW. Raw credential never appears in state objects
AX. Raw credential never appears in exception/audit output
"""

import concurrent.futures
import time
import pytest
from unittest.mock import MagicMock

from src.core.logging import AuditLogger
from src.engine.models import HypothesisDecision
from src.evidence.models import EpistemicCertainty
from src.evidence.vault import RedactionVault
from src.execution import (
    ApprovalGate,
    CredentialLifecycleState,
    CredentialRecord,
    CredentialType,
    CsrfLifecycleState,
    CsrfManager,
    CsrfRecord,
    DeterministicExecutionEngine,
    DeterministicStateManager,
    DeterministicTTLValidator,
    ExecutionDescriptor,
    ExecutionResult,
    ExecutionStatus,
    HmacRequestSigner,
    HumanApproval,
    JwtRefreshAdapter,
    SessionLifecycleState,
    SessionRecord,
    SigningKeyRecord,
    SigningProfile,
    SigningLifecycleState,
)
from src.hypothesis.experiment import (
    ExpectedObservations,
    ExperimentProposal,
    MutationClass,
    SafetyLevel,
)
from src.hypothesis.state_machine import EvidenceState, HypothesisState
from src.scope.client import ScopedHttpClient
from src.scope.gate import ScopeGate
from src.scope.models import ScopeDecision, ScopePolicy, ToolPolicy


@pytest.fixture
def test_scope_policy() -> ScopePolicy:
    return ScopePolicy(
        program_name="adversarial-test",
        platform="test-platform",
        in_scope=["*.target.com", "api.target.com", "auth.target.com"],
        out_of_scope=["internal.target.com"],
        rules_of_engagement={"rate_limit_rps": 50},
    )


@pytest.fixture
def vault() -> RedactionVault:
    v = RedactionVault()
    v.redact_text("super_secret_raw_jwt_value_1234567890")
    v.redact_text("super_secret_raw_refresh_value_1234567890")
    v.redact_text("super_secret_raw_signing_key_1234567890")
    return v


@pytest.fixture
def scope_gate(test_scope_policy) -> ScopeGate:
    # Resolves public IP for target.com, rejects loopback/private
    return ScopeGate(policy=test_scope_policy, dns_resolver=lambda h: ["93.184.216.34"])


@pytest.fixture
def state_manager(vault, tmp_path) -> DeterministicStateManager:
    audit_file = tmp_path / "adversarial_audit.log"
    logger = AuditLogger(audit_file)
    return DeterministicStateManager(vault=vault, audit_logger=logger)


# ---------------------------------------------------------------------------
# Tests AH - AJ: Auth Refresh Security & SSRF Defense
# ---------------------------------------------------------------------------

def test_ah_auth_refresh_ssrf_attempt(scope_gate, vault):
    """AH: Refresh request attempting SSRF to internal/private IP is blocked by ScopeGate."""
    adapter = JwtRefreshAdapter()
    client = ScopedHttpClient(scope_gate=scope_gate)
    cred = CredentialRecord(
        token_ref="[REDACTED_JWT_1]",
        identity_id="user_a",
        target_authority="api.target.com",
        credential_type=CredentialType.BEARER_JWT,
        refresh_token_ref="[REDACTED_SECRET_1]",
    )
    vault._placeholder_to_raw["[REDACTED_SECRET_1]"] = "raw_refresh"

    # Malicious SSRF refresh URL targeting internal domain
    with pytest.raises(Exception) as exc_info:
        adapter.refresh(
            credential=cred,
            vault=vault,
            client=client,
            config={"refresh_url": "https://internal.target.com/oauth/refresh"},
        )
    assert "blocked by ScopeGate" in str(exc_info.value) or "Scope Violation" in str(exc_info.value)


def test_ai_auth_refresh_cross_target_attempt(state_manager):
    """AI: Validating credential bound to api.target.com against other.target.com fails."""
    rec = CredentialRecord(
        token_ref="[REDACTED_JWT_1]",
        identity_id="user_a",
        target_authority="api.target.com",
        credential_type=CredentialType.BEARER_JWT,
    )
    state_manager.register_credential(rec)
    valid, err, _ = state_manager.validate_credential_ownership(
        token_ref="[REDACTED_JWT_1]",
        expected_identity_id="user_a",
        expected_target_authority="other.target.com",  # Cross-target attack
    )
    assert valid is False
    assert err == "CROSS_TARGET_SUBSTITUTION_BLOCKED"


def test_aj_auth_refresh_cross_identity_attempt(state_manager):
    """AJ: Validating credential bound to user_a against user_b fails."""
    rec = CredentialRecord(
        token_ref="[REDACTED_JWT_1]",
        identity_id="user_a",
        target_authority="api.target.com",
        credential_type=CredentialType.BEARER_JWT,
    )
    state_manager.register_credential(rec)
    valid, err, _ = state_manager.validate_credential_ownership(
        token_ref="[REDACTED_JWT_1]",
        expected_identity_id="user_b",  # Cross-identity attack
    )
    assert valid is False
    assert err == "CROSS_IDENTITY_SUBSTITUTION_BLOCKED"


# ---------------------------------------------------------------------------
# Tests AK - AM: Human Approval Gates Execution
# ---------------------------------------------------------------------------

def test_ak_approval_before_csrf_consumption(scope_gate, state_manager, vault):
    """AK: If approval fails, CSRF token remains UNCONSUMED (atomic preservation)."""
    client = ScopedHttpClient(scope_gate=scope_gate)
    csrf_mgr = CsrfManager(state_manager=state_manager, vault=vault)
    csrf_mgr.register_discovered_token(
        raw_token="precious_csrf_123",
        identity_id="user_a",
        session_id=None,
        target_authority="api.target.com",
    )

    # State-changing proposal with NO approval
    proposal = ExperimentProposal(
        objective="Delete order",
        target_asset_id="ORDER-1",
        mutation_class=MutationClass.STEP_SKIPPING,
        actor_identity_id="user_a",
        safety_level=SafetyLevel.STATE_CHANGING_REQUIRES_APPROVAL,
        expected_observations=ExpectedObservations(
            supporting_observation="Deleted",
            contradicting_observation="Forbidden",
        ),
    )

    engine = DeterministicExecutionEngine(
        scope_gate=scope_gate,
        scoped_client=client,
        state_manager=state_manager,
        vault=vault,
        csrf_manager=csrf_mgr,
        live_execution_enabled=True,
    )

    res = engine.execute_proposal(
        experiment=proposal,
        destination_url="https://api.target.com/v1/orders/1/delete",
        http_method="POST",
        csrf_token_ref="[REDACTED_CSRF_1]",
    )
    assert res.status == ExecutionStatus.BLOCKED_APPROVAL

    # Verify CSRF token is STILL UNCONSUMED
    csrf_rec = state_manager._csrf_tokens.get("[REDACTED_CSRF_1]")
    assert csrf_rec.consumed is False
    assert csrf_rec.lifecycle_state == CsrfLifecycleState.CSRF_VALID


def test_al_approval_before_refresh(scope_gate, state_manager, vault):
    """AL: State-changing proposal blocked by approval check does not trigger adapter refresh."""
    mock_adapter = MagicMock()
    ttl_val = DeterministicTTLValidator(
        state_manager=state_manager,
        adapters={"BEARER_JWT": mock_adapter},
    )
    client = ScopedHttpClient(scope_gate=scope_gate)
    proposal = ExperimentProposal(
        objective="Delete order",
        target_asset_id="ORDER-1",
        mutation_class=MutationClass.STEP_SKIPPING,
        actor_identity_id="user_a",
        safety_level=SafetyLevel.STATE_CHANGING_REQUIRES_APPROVAL,
        expected_observations=ExpectedObservations(
            supporting_observation="Deleted",
            contradicting_observation="Forbidden",
        ),
    )
    engine = DeterministicExecutionEngine(
        scope_gate=scope_gate,
        scoped_client=client,
        state_manager=state_manager,
        vault=vault,
        ttl_validator=ttl_val,
        live_execution_enabled=True,
    )
    res = engine.execute_proposal(proposal, destination_url="https://api.target.com/v1/delete", http_method="POST")
    assert res.status == ExecutionStatus.BLOCKED_APPROVAL
    assert not mock_adapter.refresh.called


def test_am_approval_before_signing(scope_gate, state_manager, vault):
    """AM: State-changing proposal blocked by approval does not invoke request signing."""
    mock_signer = MagicMock()
    client = ScopedHttpClient(scope_gate=scope_gate)
    proposal = ExperimentProposal(
        objective="Delete order",
        target_asset_id="ORDER-1",
        mutation_class=MutationClass.STEP_SKIPPING,
        actor_identity_id="user_a",
        safety_level=SafetyLevel.STATE_CHANGING_REQUIRES_APPROVAL,
        expected_observations=ExpectedObservations(
            supporting_observation="Deleted",
            contradicting_observation="Forbidden",
        ),
    )
    engine = DeterministicExecutionEngine(
        scope_gate=scope_gate,
        scoped_client=client,
        state_manager=state_manager,
        vault=vault,
        signer=mock_signer,
        live_execution_enabled=True,
    )
    res = engine.execute_proposal(proposal, destination_url="https://api.target.com/v1/delete", http_method="POST")
    assert res.status == ExecutionStatus.BLOCKED_APPROVAL
    assert not mock_signer.sign.called


# ---------------------------------------------------------------------------
# Tests AN - AP: TOCTOU & Key Ownership
# ---------------------------------------------------------------------------

def test_an_final_toctou_descriptor_mismatch(scope_gate, state_manager, vault):
    """AN: Recomputed descriptor digest mismatch fails verification immediately."""
    gate = ApprovalGate()
    desc = ExecutionDescriptor(
        experiment_id="EXP-1",
        identity_id="user_a",
        target_authority="api.target.com",
        destination="https://api.target.com/orders",
        http_method="POST",
        normalized_route="/orders",
        request_body_digest="digest_a",
        safety_classification=SafetyLevel.STATE_CHANGING_REQUIRES_APPROVAL.value,
        affected_resource="RES-1",
        expected_state_transition="Create order",
    )
    approved_digest = desc.compute_digest()
    gate.register_approval(
        HumanApproval(
            approval_id="APP-1",
            experiment_id="EXP-1",
            approved_descriptor_digest=approved_digest,
            actor="sec_team",
        )
    )

    # In-flight tampering of body digest
    tampered_desc = desc.model_copy()
    tampered_desc.request_body_digest = "digest_b"
    ok, err, _ = gate.verify_approval(tampered_desc)
    assert ok is False
    assert err == "APPROVAL_DESCRIPTOR_DIGEST_MISMATCH"


def test_ao_final_destination_ip_mismatch(scope_gate, state_manager, vault):
    """AO: If destination scope check fails immediately prior to transmission, execution blocks."""
    client = ScopedHttpClient(scope_gate=scope_gate)
    engine = DeterministicExecutionEngine(
        scope_gate=scope_gate,
        scoped_client=client,
        state_manager=state_manager,
        vault=vault,
        live_execution_enabled=True,
    )
    proposal = ExperimentProposal(
        objective="Read safe asset",
        target_asset_id="ORDER-1",
        mutation_class=MutationClass.UNAUTHENTICATED_ACCESS,
        expected_observations=ExpectedObservations(
            supporting_observation="200",
            contradicting_observation="403",
        ),
    )
    # Simulate final destination check failing (e.g. TOCTOU re-evaluation returns DENY)
    scope_gate.evaluate = MagicMock(return_value=scope_gate._record_decision(
        ScopeDecision.DENY,
        "https://api.target.com/orders",
        "api.target.com",
        ["127.0.0.1"],  # DNS rebinding to loopback
        tool_policy=ToolPolicy.ACTIVE,
        reason="Resolved loopback address prohibited (SSRF defense)",
    ))
    res = engine.execute_proposal(proposal, destination_url="https://api.target.com/orders")
    assert res.status == ExecutionStatus.BLOCKED_SCOPE
    assert "blocked by ScopeGate" in res.error_message or "SSRF" in res.error_message


def test_ap_signing_key_ownership_mismatch(scope_gate, state_manager, vault):
    """AP: Attempting to sign Identity A's request with Identity B's key returns BLOCKED_AUTH_STATE."""
    client = ScopedHttpClient(scope_gate=scope_gate)
    profile = SigningProfile(
        profile_id="prof-1",
        identity_id="user_b",  # Profile belongs to user_b
        target_authority="api.target.com",
    )
    key_rec = SigningKeyRecord(
        key_id="prof-1",
        identity_id="user_b",  # Key belongs to user_b
        target_authority="api.target.com",
        secret_ref="[REDACTED_SECRET_1]",
    )
    state_manager.register_signing_key(key_rec)

    proposal = ExperimentProposal(
        objective="Read orders",
        target_asset_id="ORDER-1",
        mutation_class=MutationClass.CROSS_IDENTITY_REPLAY,
        actor_identity_id="user_a",  # Experiment actor is user_a
        expected_observations=ExpectedObservations(
            supporting_observation="200",
            contradicting_observation="403",
        ),
    )
    engine = DeterministicExecutionEngine(
        scope_gate=scope_gate,
        scoped_client=client,
        state_manager=state_manager,
        vault=vault,
        live_execution_enabled=True,
    )
    engine.register_signing_profile(profile)

    res = engine.execute_proposal(
        experiment=proposal,
        destination_url="https://api.target.com/orders",
        signing_profile_id="prof-1",
    )
    assert res.status == ExecutionStatus.BLOCKED_AUTH_STATE
    assert "Signing key ownership mismatch" in res.error_message


# ---------------------------------------------------------------------------
# Test AQ: Namespace Isolation & Zero Taxonomy Collisions
# ---------------------------------------------------------------------------

def test_aq_state_string_collision_with_evidence_taxonomy():
    """AQ: Verify ZERO collision between M2.75 lifecycle state strings and existing taxonomy enums."""
    m2_75_states = {
        s.value
        for enum_cls in (
            CredentialLifecycleState,
            SessionLifecycleState,
            CsrfLifecycleState,
            SigningLifecycleState,
            ExecutionStatus,
        )
        for s in enum_cls
    }

    # Hypothesis decisions
    hypo_decisions = {d.value for d in HypothesisDecision}
    # Hypothesis states
    hypo_states = {s.value for s in HypothesisState}
    # Evidence states
    ev_states = {s.value for s in EvidenceState}
    # Epistemic certainty
    epistemic_states = {s.value for s in EpistemicCertainty}

    # Verify zero intersection
    assert not (m2_75_states & hypo_decisions), f"Collision with HypothesisDecision: {m2_75_states & hypo_decisions}"
    assert not (m2_75_states & hypo_states), f"Collision with HypothesisState: {m2_75_states & hypo_states}"
    assert not (m2_75_states & ev_states), f"Collision with EvidenceState: {m2_75_states & ev_states}"
    assert not (m2_75_states & epistemic_states), f"Collision with EpistemicCertainty: {m2_75_states & epistemic_states}"


# ---------------------------------------------------------------------------
# Tests AR - AU: Concurrency & Atomic Race Defenses
# ---------------------------------------------------------------------------

def test_ar_concurrent_csrf_consumption(state_manager, vault):
    """AR: 10 concurrent threads racing to consume the same CSRF token: exactly 1 succeeds, 9 fail."""
    csrf_mgr = CsrfManager(state_manager=state_manager, vault=vault)
    csrf_mgr.register_discovered_token(
        raw_token="shared_race_csrf_token_123",
        identity_id="user_a",
        session_id=None,
        target_authority="api.target.com",
    )

    results = []

    def _attempt_consumption():
        ok, err, pair = csrf_mgr.prepare_and_consume_csrf(
            token_ref="[REDACTED_CSRF_1]",
            identity_id="user_a",
            target_authority="api.target.com",
        )
        return ok

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(_attempt_consumption) for _ in range(10)]
        for f in concurrent.futures.as_completed(futures):
            results.append(f.result())

    assert results.count(True) == 1, f"Expected exactly 1 success, got {results.count(True)}"
    assert results.count(False) == 9


def test_as_concurrent_refresh(state_manager):
    """AS: Concurrent credential transitions are serialized atomically."""
    rec = CredentialRecord(
        token_ref="[REDACTED_JWT_RACE]",
        identity_id="user_a",
        target_authority="api.target.com",
        credential_type=CredentialType.BEARER_JWT,
    )
    state_manager.register_credential(rec)

    def _attempt_transition(idx: int):
        return state_manager.transition_credential(
            token_ref="[REDACTED_JWT_RACE]",
            new_state=CredentialLifecycleState.CRED_ACTIVE,
            reason=f"REFRESH_THREAD_{idx}",
            new_expires_at=time.time() + idx,
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(_attempt_transition, i) for i in range(5)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    assert len(results) == 5
    final = state_manager.get_credential("[REDACTED_JWT_RACE]")
    assert final is not None
    assert "REFRESH_THREAD_" in final.last_transition_reason


def test_at_stale_session_replacement(state_manager):
    """AT: Session replacement atomically terminates old and activates new."""
    s1 = SessionRecord(
        session_id="SESS-1",
        identity_id="user_a",
        target_authority="api.target.com",
    )
    state_manager.register_session(s1)

    s2 = SessionRecord(
        session_id="SESS-2",
        identity_id="user_a",
        target_authority="api.target.com",
    )
    state_manager.replace_session(old_session_id="SESS-1", new_record=s2, reason="ROTATION")

    old_s = state_manager.get_session("SESS-1")
    new_s = state_manager.get_session("SESS-2")

    assert old_s.lifecycle_state == SessionLifecycleState.SESS_TERMINATED
    assert new_s.lifecycle_state == SessionLifecycleState.SESS_ACTIVE


def test_au_nonce_race(state_manager):
    """AU: 10 concurrent threads racing to consume the same signing nonce: exactly 1 succeeds, 9 fail."""
    results = []

    def _attempt_nonce():
        ok, _ = state_manager.consume_signing_nonce("profile_1", "single_use_nonce_race")
        return ok

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(_attempt_nonce) for _ in range(10)]
        for f in concurrent.futures.as_completed(futures):
            results.append(f.result())

    assert results.count(True) == 1
    assert results.count(False) == 9


# ---------------------------------------------------------------------------
# Tests AV - AX: Invariant & Secret Protections
# ---------------------------------------------------------------------------

def test_av_observation_cannot_become_vulnerability_confirmed(scope_gate, state_manager, vault):
    """AV: Execution output emits strictly OBSERVATION evidence, NEVER VULNERABILITY_CONFIRMED."""
    client = ScopedHttpClient(scope_gate=scope_gate)
    proposal = ExperimentProposal(
        objective="Read customer data",
        target_asset_id="CUST-1",
        mutation_class=MutationClass.UNAUTHENTICATED_ACCESS,
        expected_observations=ExpectedObservations(
            supporting_observation="Customer data leaked",
            contradicting_observation="403 Forbidden",
        ),
    )
    engine = DeterministicExecutionEngine(
        scope_gate=scope_gate,
        scoped_client=client,
        state_manager=state_manager,
        vault=vault,
        mock_transport_fn=lambda m, u, h, b: (200, {"Content-Type": "application/json"}, b'{"id": 1}'),
        live_execution_enabled=True,
    )
    res = engine.execute_proposal(proposal, destination_url="https://api.target.com/cust")
    assert res.status == ExecutionStatus.EXECUTED
    assert res.observation_record is not None
    assert res.observation_record["epistemic_status"] == "OBSERVED"
    # Verify no field claims a vulnerability is confirmed
    record_str = str(res.model_dump())
    assert "VULNERABILITY_CONFIRMED" not in record_str


def test_aw_raw_credential_never_appears_in_state_objects(state_manager, vault):
    """AW: State records store strictly references/placeholders, never raw secret literals."""
    raw_secret = "ultra_sensitive_secret_never_leak_me"
    placeholder = vault._get_or_create_placeholder(raw_secret, "KEY")

    cred = CredentialRecord(
        token_ref=placeholder,
        identity_id="user_a",
        target_authority="api.target.com",
        credential_type=CredentialType.API_KEY,
    )
    state_manager.register_credential(cred)

    serialized = state_manager.get_credential(placeholder).model_dump_json()
    assert raw_secret not in serialized
    assert placeholder in serialized


def test_ax_raw_credential_never_appears_in_exception_audit_output(scope_gate, state_manager, vault, tmp_path):
    """AX: Raw credentials never leak into exceptions, audit logs, or error strings."""
    audit_file = tmp_path / "secret_leak_audit.log"
    logger = AuditLogger(audit_file)
    client = ScopedHttpClient(scope_gate=scope_gate)

    raw_pass = "super_duper_password_9999"
    vault._placeholder_to_raw["[REDACTED_SECRET_1]"] = raw_pass

    engine = DeterministicExecutionEngine(
        scope_gate=scope_gate,
        scoped_client=client,
        state_manager=state_manager,
        vault=vault,
        audit_logger=logger,
        live_execution_enabled=True,
    )

    # Force an exception with raw secret in it
    client.request = MagicMock(side_effect=RuntimeError(f"Connection failed for password: {raw_pass}"))

    proposal = ExperimentProposal(
        objective="Probe auth",
        target_asset_id="AUTH-1",
        mutation_class=MutationClass.STEP_SKIPPING,
        expected_observations=ExpectedObservations(
            supporting_observation="200",
            contradicting_observation="403",
        ),
    )
    res = engine.execute_proposal(proposal, destination_url="https://api.target.com/auth")
    assert res.status == ExecutionStatus.EXECUTION_ERROR
    assert raw_pass not in res.error_message

    # Inspect audit log content
    log_content = audit_file.read_text(encoding="utf-8")
    assert raw_pass not in log_content


# ---------------------------------------------------------------------------
# Tests AY - BC: SigningProfile Rigor, Header Integrity & In-Flight TOCTOU
# ---------------------------------------------------------------------------

def test_ay_signing_profile_canonicalization_version_enforced(vault, state_manager):
    """AY: Profile with canonicalization_version != 'v1' (e.g. 'aws-v4') fails closed with UNSUPPORTED_SIGNING_FLOW."""
    signer = HmacRequestSigner()
    profile = SigningProfile(
        profile_id="aws-profile",
        canonicalization_version="aws-v4",
        identity_id="user_a",
        target_authority="api.target.com",
    )
    key_rec = SigningKeyRecord(
        key_id="aws-profile",
        identity_id="user_a",
        target_authority="api.target.com",
        secret_ref="[REDACTED_SECRET_1]",
    )
    from src.execution.signing import UnsupportedSigningFlowError
    with pytest.raises(UnsupportedSigningFlowError) as exc_info:
        signer.sign(
            method="GET",
            url="https://api.target.com/v1/orders",
            headers={},
            body=None,
            profile=profile,
            key_record=key_rec,
            vault=vault,
            state_manager=state_manager,
        )
    assert "Unsupported canonicalization version: aws-v4" in str(exc_info.value)
    assert signer.verify("GET", "https://api.target.com/v1/orders", {}, None, profile, key_rec, vault) is False


def test_az_signing_profile_signed_components_enforced(vault, state_manager):
    """AZ: Profile with altered signed_components fails closed with UNSUPPORTED_SIGNING_FLOW."""
    signer = HmacRequestSigner()
    profile = SigningProfile(
        profile_id="custom-comp-profile",
        signed_components=["method", "route"],  # Missing query, body, timestamp, nonce
        identity_id="user_a",
        target_authority="api.target.com",
    )
    key_rec = SigningKeyRecord(
        key_id="custom-comp-profile",
        identity_id="user_a",
        target_authority="api.target.com",
        secret_ref="[REDACTED_SECRET_1]",
    )
    from src.execution.signing import UnsupportedSigningFlowError
    with pytest.raises(UnsupportedSigningFlowError) as exc_info:
        signer.sign(
            method="GET",
            url="https://api.target.com/v1/orders",
            headers={},
            body=None,
            profile=profile,
            key_record=key_rec,
            vault=vault,
            state_manager=state_manager,
        )
    assert "Unsupported signed components" in str(exc_info.value)


def test_ba_signing_environment_context_mismatch(scope_gate, state_manager, vault):
    """BA: Using production signing key/profile in staging experiment returns BLOCKED_AUTH_STATE."""
    client = ScopedHttpClient(scope_gate=scope_gate)
    profile = SigningProfile(
        profile_id="prod-profile",
        identity_id="user_a",
        target_authority="api.target.com",
        environment_context="production",  # Production profile
    )
    key_rec = SigningKeyRecord(
        key_id="prod-profile",
        identity_id="user_a",
        target_authority="api.target.com",
        environment_context="production",  # Production key
        secret_ref="[REDACTED_SECRET_1]",
    )
    state_manager.register_signing_key(key_rec)

    proposal = ExperimentProposal(
        objective="Execute staging call",
        target_asset_id="ORDER-1",
        mutation_class=MutationClass.UNAUTHENTICATED_ACCESS,
        actor_identity_id="user_a",
        expected_observations=ExpectedObservations(
            supporting_observation="200",
            contradicting_observation="403",
        ),
    )
    engine = DeterministicExecutionEngine(
        scope_gate=scope_gate,
        scoped_client=client,
        state_manager=state_manager,
        vault=vault,
        live_execution_enabled=True,
    )
    engine.register_signing_profile(profile)

    res = engine.execute_proposal(
        experiment=proposal,
        destination_url="https://api.target.com/orders",
        environment_context="staging",  # Staging experiment
        signing_profile_id="prod-profile",
    )
    assert res.status == ExecutionStatus.BLOCKED_AUTH_STATE
    assert "Signing key ownership mismatch" in res.error_message


def test_bb_header_mutation_after_approval_blocked(scope_gate, state_manager, vault):
    """BB: Tampering with approved security headers between approval and transmission returns BLOCKED_APPROVAL."""
    gate = ApprovalGate()
    client = ScopedHttpClient(scope_gate=scope_gate)
    proposal = ExperimentProposal(
        objective="Mutate order",
        target_asset_id="ORDER-1",
        mutation_class=MutationClass.STEP_SKIPPING,
        actor_identity_id="user_a",
        safety_level=SafetyLevel.STATE_CHANGING_REQUIRES_APPROVAL,
        expected_observations=ExpectedObservations(
            supporting_observation="200",
            contradicting_observation="403",
        ),
    )

    engine = DeterministicExecutionEngine(
        scope_gate=scope_gate,
        scoped_client=client,
        state_manager=state_manager,
        vault=vault,
        approval_gate=gate,
        live_execution_enabled=True,
    )

    from src.execution.engine import compute_headers_digest
    approved_headers = {"X-Security-Level": "standard"}
    h_digest = compute_headers_digest(approved_headers, vault)

    # Approve descriptor
    desc = ExecutionDescriptor(
        experiment_id="Mutate_order",
        identity_id="user_a",
        environment_context="staging",
        target_authority="api.target.com",
        destination="https://api.target.com/orders/1",
        http_method="POST",
        normalized_route="/orders/1",
        headers_digest=h_digest,
        request_body_digest="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        safety_classification=SafetyLevel.STATE_CHANGING_REQUIRES_APPROVAL.value,
        affected_resource="ORDER-1",
        expected_state_transition="No rollback needed for read-only operations",
    )
    approval = HumanApproval(
        approval_id="APP-HEADER-1",
        experiment_id="Mutate_order",
        approved_descriptor_digest=desc.compute_digest(),
        actor="lead_auditor",
    )
    gate.register_approval(approval)

    # Request submitted with modified security header
    tampered_headers = {"X-Security-Level": "admin"}
    res = engine.execute_proposal(
        experiment=proposal,
        destination_url="https://api.target.com/orders/1",
        http_method="POST",
        request_headers=tampered_headers,
        approval_id="APP-HEADER-1",
    )
    assert res.status == ExecutionStatus.BLOCKED_APPROVAL
    assert "ApprovalGate" in res.error_message or "MISMATCH" in res.error_message


def test_bc_toctou_in_flight_tampering_blocked_by_engine(scope_gate, state_manager, vault):
    """BC: End-to-end engine Step 10 catches descriptor tampering occurring after Step 4."""
    gate = ApprovalGate()
    client = ScopedHttpClient(scope_gate=scope_gate)
    proposal = ExperimentProposal(
        objective="Delete critical record",
        target_asset_id="RECORD-1",
        mutation_class=MutationClass.STEP_SKIPPING,
        actor_identity_id="user_a",
        safety_level=SafetyLevel.STATE_CHANGING_REQUIRES_APPROVAL,
        expected_observations=ExpectedObservations(
            supporting_observation="200",
            contradicting_observation="403",
        ),
    )

    engine = DeterministicExecutionEngine(
        scope_gate=scope_gate,
        scoped_client=client,
        state_manager=state_manager,
        vault=vault,
        approval_gate=gate,
        live_execution_enabled=True,
        mock_transport_fn=lambda m, u, h, b: (200, {}, b"ok"),
    )

    desc = ExecutionDescriptor(
        experiment_id="Delete_critical_record",
        identity_id="user_a",
        environment_context="staging",
        target_authority="api.target.com",
        destination="https://api.target.com/records/1",
        resolved_ip="93.184.216.34",
        http_method="POST",
        normalized_route="/records/1",
        request_body_digest="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        safety_classification=SafetyLevel.STATE_CHANGING_REQUIRES_APPROVAL.value,
        affected_resource="RECORD-1",
        expected_state_transition="No rollback needed for read-only operations",
    )
    approval = HumanApproval(
        approval_id="APP-TOCTOU-1",
        experiment_id="Delete_critical_record",
        approved_descriptor_digest=desc.compute_digest(),
        actor="sec_officer",
    )
    gate.register_approval(approval)

    # Wrap mock transport to simulate in-flight tampering test
    # If approval is revoked or descriptor tampered before Step 10
    original_verify = gate.verify_approval
    call_count = 0

    def tamper_on_second_call(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count > 1:
            # Step 10 final TOCTOU check
            return False, "APPROVAL_REVOKED_IN_FLIGHT", None
        return original_verify(*args, **kwargs)

    gate.verify_approval = tamper_on_second_call

    res = engine.execute_proposal(
        experiment=proposal,
        destination_url="https://api.target.com/records/1",
        http_method="POST",
        approval_id="APP-TOCTOU-1",
    )
    assert res.status == ExecutionStatus.BLOCKED_APPROVAL
    assert "Final TOCTOU approval check failed: APPROVAL_REVOKED_IN_FLIGHT" in res.error_message
