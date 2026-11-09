"""Unit Test Suite for Milestone M2.75: Deterministic Execution Engine.

Covers specification requirements A through AG:
A. Valid token
B. Missing token
C. Expired token
D. Expired token successful refresh
E. Refresh failure
F. Cross-identity credential use
G. Retry limit
H. Stale credential replacement
I. Valid CSRF
J. Consumed CSRF replay
K. Expired CSRF
L. Rotation
M. Cross-session CSRF
N. Cross-identity CSRF
O. Unsupported auth flow
P. Valid signing
Q. Expired timestamp
R. Nonce replay
S. Modified path
T. Modified query/body
U. Unsupported signing profile
V. Out-of-scope destination
W. Out-of-scope redirect
X. Rate-limit enforcement
Y. Missing approval
Z. Expired approval
AA. Experiment mismatch
AB. Method mutation after approval
AC. Body mutation after approval
AD. Destination mutation after approval
AE. Identity/environment mutation after approval
AF. Live execution default-off
AG. Exception secret scrubbing
"""

import time
import pytest
from unittest.mock import MagicMock

from src.core.logging import AuditLogger
from src.evidence.vault import RedactionVault
from src.execution import (
    ApprovalGate,
    CookieSessionAdapter,
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
    ExpiredSigningTimestampError,
    HmacRequestSigner,
    HumanApproval,
    JwtRefreshAdapter,
    OAuthRefreshAdapter,
    ReauthenticationAdapter,
    ReplayedSigningNonceError,
    RetryExhaustionError,
    SessionLifecycleState,
    SessionRecord,
    SigningKeyRecord,
    SigningProfile,
    UnsupportedAuthFlowError,
    UnsupportedSigningFlowError,
    scrub_exception_text,
)
from src.hypothesis.experiment import (
    ExpectedObservations,
    ExperimentProposal,
    MutationClass,
    SafetyLevel,
)
from src.scope.client import ScopedHttpClient, ScopeViolationError
from src.scope.gate import ScopeGate
from src.scope.models import ScopeDecision, ScopePolicy


@pytest.fixture
def test_scope_policy() -> ScopePolicy:
    return ScopePolicy(
        program_name="test-prog",
        platform="test-platform",
        in_scope=["*.target.com", "api.target.com", "auth.target.com"],
        out_of_scope=["internal.target.com"],
        rules_of_engagement={"rate_limit_rps": 50},
    )


@pytest.fixture
def vault() -> RedactionVault:
    v = RedactionVault()
    # Pre-register some secrets
    v.redact_text("secret_jwt_user_a_raw_value_1234567890")
    v.redact_text("secret_refresh_user_a_raw_value_1234567890")
    v.redact_text("secret_signing_key_hmac_1234567890")
    return v


@pytest.fixture
def scope_gate(test_scope_policy) -> ScopeGate:
    return ScopeGate(policy=test_scope_policy, dns_resolver=lambda h: ["93.184.216.34"])


@pytest.fixture
def state_manager(vault, tmp_path) -> DeterministicStateManager:
    audit_file = tmp_path / "test_audit.log"
    logger = AuditLogger(audit_file)
    return DeterministicStateManager(vault=vault, audit_logger=logger)


@pytest.fixture
def base_proposal() -> ExperimentProposal:
    return ExperimentProposal(
        objective="Test BOLA order details access",
        target_asset_id="ASSET-ORDER-01",
        mutation_class=MutationClass.CROSS_IDENTITY_REPLAY,
        actor_identity_id="user_a",
        target_identity_id="user_b",
        expected_observations=ExpectedObservations(
            supporting_observation="HTTP 200 with order details",
            contradicting_observation="HTTP 403 Forbidden",
        ),
        safety_level=SafetyLevel.READ_ONLY_SAFE,
        required_token_references=["[REDACTED_JWT_1]"],
    )


# ---------------------------------------------------------------------------
# Tests A - H: Token Lifecycle & TTL
# ---------------------------------------------------------------------------

def test_a_valid_token(state_manager, vault, base_proposal):
    """A: Valid, fresh token succeeds pre-execution TTL validation."""
    state_manager.register_credential(
        CredentialRecord(
            token_ref="[REDACTED_JWT_1]",
            identity_id="user_a",
            target_authority="api.target.com",
            credential_type=CredentialType.BEARER_JWT,
            expires_at=time.time() + 3600,
        )
    )
    validator = DeterministicTTLValidator(state_manager=state_manager)
    res = validator.validate_proposal(base_proposal, vault)
    assert res.valid is True
    assert res.error is None


def test_b_missing_token(state_manager, vault, base_proposal):
    """B: Missing token fails with TOKEN_REFERENCE_NOT_FOUND."""
    validator = DeterministicTTLValidator(state_manager=state_manager)
    res = validator.validate_proposal(base_proposal, vault)
    assert res.valid is False
    assert res.error == "TOKEN_REFERENCE_NOT_FOUND"


def test_c_expired_token_without_adapter(state_manager, vault, base_proposal):
    """C: Expired token without registered adapter fails with TOKEN_EXPIRED."""
    state_manager.register_credential(
        CredentialRecord(
            token_ref="[REDACTED_JWT_1]",
            identity_id="user_a",
            target_authority="api.target.com",
            credential_type=CredentialType.BEARER_JWT,
            expires_at=time.time() - 10,  # Expired
        )
    )
    validator = DeterministicTTLValidator(state_manager=state_manager)
    res = validator.validate_proposal(base_proposal, vault)
    assert res.valid is False
    assert res.error == "TOKEN_EXPIRED"
    assert res.requires_refresh is True


def test_d_expired_token_successful_refresh(state_manager, vault, base_proposal):
    """D: Expired token with registered adapter successfully refreshes and passes."""
    state_manager.register_credential(
        CredentialRecord(
            token_ref="[REDACTED_JWT_1]",
            identity_id="user_a",
            target_authority="api.target.com",
            credential_type=CredentialType.BEARER_JWT,
            expires_at=time.time() - 10,
            refresh_token_ref="[REDACTED_SECRET_1]",
        )
    )
    mock_adapter = MagicMock()
    mock_adapter.refresh.return_value = CredentialRecord(
        token_ref="[REDACTED_JWT_1]",
        identity_id="user_a",
        target_authority="api.target.com",
        credential_type=CredentialType.BEARER_JWT,
        expires_at=time.time() + 3600,
        last_transition_reason="JWT_REFRESH_SUCCESS",
    )
    mock_client = MagicMock()
    validator = DeterministicTTLValidator(
        state_manager=state_manager,
        adapters={"BEARER_JWT": mock_adapter},
        scoped_client=mock_client,
    )
    res = validator.validate_proposal(base_proposal, vault)
    assert res.valid is True
    assert mock_adapter.refresh.called


def test_e_refresh_failure(state_manager, vault, base_proposal):
    """E: Failed refresh produces deterministic error and fails closed."""
    from src.execution.auth_adapters import AuthAdapterError

    state_manager.register_credential(
        CredentialRecord(
            token_ref="[REDACTED_JWT_1]",
            identity_id="user_a",
            target_authority="api.target.com",
            credential_type=CredentialType.BEARER_JWT,
            expires_at=time.time() - 10,
        )
    )
    mock_adapter = MagicMock()
    mock_adapter.refresh.side_effect = AuthAdapterError("Server 500 error during refresh")
    mock_client = MagicMock()
    validator = DeterministicTTLValidator(
        state_manager=state_manager,
        adapters={"BEARER_JWT": mock_adapter},
        scoped_client=mock_client,
    )
    res = validator.validate_proposal(base_proposal, vault)
    assert res.valid is False
    assert "REFRESH_FAILED" in res.error


def test_f_cross_identity_credential_use(state_manager, vault, base_proposal):
    """F: Proposing Identity B's token for Identity A's experiment is blocked."""
    state_manager.register_credential(
        CredentialRecord(
            token_ref="[REDACTED_JWT_1]",
            identity_id="user_b",  # Owner is user_b, but experiment is user_a
            target_authority="api.target.com",
            credential_type=CredentialType.BEARER_JWT,
            expires_at=time.time() + 3600,
        )
    )
    validator = DeterministicTTLValidator(state_manager=state_manager)
    res = validator.validate_proposal(base_proposal, vault)
    assert res.valid is False
    assert res.error == "CROSS_IDENTITY_SUBSTITUTION_BLOCKED"


def test_g_retry_limit(state_manager, vault):
    """G: Refresh retry budget exhaustion fails closed."""
    adapter = JwtRefreshAdapter(max_retries=2)
    adapter._check_and_increment_retry("[REDACTED_JWT_1]")
    adapter._check_and_increment_retry("[REDACTED_JWT_1]")
    with pytest.raises(RetryExhaustionError):
        adapter._check_and_increment_retry("[REDACTED_JWT_1]")


def test_h_stale_credential_replacement(state_manager):
    """H: Credential transition atomically updates metadata and preserves history."""
    rec = CredentialRecord(
        token_ref="[REDACTED_JWT_1]",
        identity_id="user_a",
        target_authority="api.target.com",
        credential_type=CredentialType.BEARER_JWT,
        expires_at=time.time() + 100,
    )
    state_manager.register_credential(rec)
    updated = state_manager.transition_credential(
        token_ref="[REDACTED_JWT_1]",
        new_state=CredentialLifecycleState.CRED_ROTATED,
        reason="ROTATED_FOR_SECURITY",
        new_expires_at=time.time() + 7200,
    )
    assert updated.lifecycle_state == CredentialLifecycleState.CRED_ROTATED
    assert updated.last_transition_reason == "ROTATED_FOR_SECURITY"


# ---------------------------------------------------------------------------
# Tests I - O: CSRF & Nonce Lifecycle
# ---------------------------------------------------------------------------

def test_i_valid_csrf(state_manager, vault):
    """I: Valid registered CSRF token is successfully prepared and consumed."""
    csrf_mgr = CsrfManager(state_manager=state_manager, vault=vault)
    csrf_mgr.register_discovered_token(
        raw_token="raw_csrf_token_secret_123",
        identity_id="user_a",
        session_id="sess_1",
        target_authority="api.target.com",
        header_name="X-CSRF-Token",
    )
    ok, err, pair = csrf_mgr.prepare_and_consume_csrf(
        token_ref="[REDACTED_CSRF_1]",
        identity_id="user_a",
        session_id="sess_1",
        target_authority="api.target.com",
    )
    assert ok is True
    assert err is None
    assert pair[0] == "X-CSRF-Token"
    assert pair[1] == "raw_csrf_token_secret_123"


def test_j_consumed_csrf_replay(state_manager, vault):
    """J: Replaying an already-consumed CSRF token is blocked."""
    csrf_mgr = CsrfManager(state_manager=state_manager, vault=vault)
    csrf_mgr.register_discovered_token(
        raw_token="raw_csrf_token_secret_123",
        identity_id="user_a",
        session_id="sess_1",
        target_authority="api.target.com",
    )
    # First consumption
    ok1, _, _ = csrf_mgr.prepare_and_consume_csrf(
        token_ref="[REDACTED_CSRF_1]",
        identity_id="user_a",
        session_id="sess_1",
    )
    assert ok1 is True

    # Replay attempt
    ok2, err2, _ = csrf_mgr.prepare_and_consume_csrf(
        token_ref="[REDACTED_CSRF_1]",
        identity_id="user_a",
        session_id="sess_1",
    )
    assert ok2 is False
    assert err2 == "CSRF_ALREADY_CONSUMED"


def test_k_expired_csrf(state_manager, vault):
    """K: Expired CSRF token is blocked."""
    csrf_mgr = CsrfManager(state_manager=state_manager, vault=vault)
    csrf_mgr.register_discovered_token(
        raw_token="raw_csrf_expired_123",
        identity_id="user_a",
        session_id="sess_1",
        target_authority="api.target.com",
        expires_at=time.time() - 100,
    )
    ok, err, _ = csrf_mgr.prepare_and_consume_csrf(
        token_ref="[REDACTED_CSRF_1]",
        identity_id="user_a",
    )
    assert ok is False
    assert err == "CSRF_TOKEN_EXPIRED"


def test_l_csrf_rotation(state_manager, vault):
    """L: Rotating CSRF token invalidates old token and validates new token."""
    csrf_mgr = CsrfManager(state_manager=state_manager, vault=vault)
    csrf_mgr.register_discovered_token(
        raw_token="old_csrf_token",
        identity_id="user_a",
        session_id="sess_1",
        target_authority="api.target.com",
    )
    new_rec = csrf_mgr.rotate_token(
        old_token_ref="[REDACTED_CSRF_1]",
        new_raw_token="new_csrf_token_rotated",
        identity_id="user_a",
        session_id="sess_1",
        target_authority="api.target.com",
    )
    # Old token cannot be consumed
    ok_old, err_old, _ = csrf_mgr.prepare_and_consume_csrf("[REDACTED_CSRF_1]", "user_a")
    assert ok_old is False
    assert err_old == "CSRF_ALREADY_CONSUMED"

    # New token can be consumed
    ok_new, _, _ = csrf_mgr.prepare_and_consume_csrf(new_rec.token_ref, "user_a")
    assert ok_new is True


def test_m_cross_session_csrf(state_manager, vault):
    """M: CSRF token bound to Session 1 cannot be consumed by Session 2."""
    csrf_mgr = CsrfManager(state_manager=state_manager, vault=vault)
    csrf_mgr.register_discovered_token(
        raw_token="sess_1_token",
        identity_id="user_a",
        session_id="sess_1",
        target_authority="api.target.com",
    )
    ok, err, _ = csrf_mgr.prepare_and_consume_csrf(
        token_ref="[REDACTED_CSRF_1]",
        identity_id="user_a",
        session_id="sess_2",  # Different session
    )
    assert ok is False
    assert err == "CROSS_SESSION_CSRF_BLOCKED"


def test_n_cross_identity_csrf(state_manager, vault):
    """N: CSRF token bound to Identity A cannot be consumed by Identity B."""
    csrf_mgr = CsrfManager(state_manager=state_manager, vault=vault)
    csrf_mgr.register_discovered_token(
        raw_token="user_a_token",
        identity_id="user_a",
        session_id=None,
        target_authority="api.target.com",
    )
    ok, err, _ = csrf_mgr.prepare_and_consume_csrf(
        token_ref="[REDACTED_CSRF_1]",
        identity_id="user_b",  # Different identity
    )
    assert ok is False
    assert err == "CROSS_IDENTITY_CSRF_BLOCKED"


def test_o_unsupported_auth_flow():
    """O: Calling an unsupported or unconfigured auth flow raises UnsupportedAuthFlowError."""
    adapter = JwtRefreshAdapter()
    with pytest.raises(UnsupportedAuthFlowError):
        adapter.refresh(
            credential=CredentialRecord(
                token_ref="tok_1",
                identity_id="u1",
                target_authority="api.target.com",
                credential_type=CredentialType.BEARER_JWT,
            ),
            vault=MagicMock(),
            client=MagicMock(),
            config={},  # Missing refresh_url
        )


# ---------------------------------------------------------------------------
# Tests P - U: Request Signing
# ---------------------------------------------------------------------------

def test_p_valid_signing(state_manager, vault):
    """P: Valid HMAC-SHA256 signature generated and verified."""
    signer = HmacRequestSigner()
    profile = SigningProfile(
        profile_id="custom-hmac-v1",
        identity_id="user_a",
        target_authority="api.target.com",
    )
    key_rec = SigningKeyRecord(
        key_id="custom-hmac-v1",
        identity_id="user_a",
        target_authority="api.target.com",
        secret_ref="[REDACTED_SECRET_1]",
    )
    vault._placeholder_to_raw["[REDACTED_SECRET_1]"] = "my_super_secret_signing_key_12345"

    headers, sig = signer.sign(
        method="POST",
        url="https://api.target.com/v1/transfer?amount=100&to=bob",
        headers={"Content-Type": "application/json"},
        body=b'{"confirm": true}',
        profile=profile,
        key_record=key_rec,
        vault=vault,
        state_manager=state_manager,
    )
    assert "X-Signature" in headers
    assert "X-Signature-Timestamp" in headers
    assert "X-Signature-Nonce" in headers

    # Verify signature
    valid = signer.verify(
        method="POST",
        url="https://api.target.com/v1/transfer?amount=100&to=bob",
        headers=headers,
        body=b'{"confirm": true}',
        profile=profile,
        key_record=key_rec,
        vault=vault,
    )
    assert valid is True


def test_q_expired_signing_timestamp(state_manager, vault):
    """Q: Signature with timestamp outside freshness window fails."""
    signer = HmacRequestSigner()
    profile = SigningProfile(
        profile_id="custom-hmac-v1",
        identity_id="user_a",
        target_authority="api.target.com",
        timestamp_window_seconds=60,
    )
    key_rec = SigningKeyRecord(
        key_id="custom-hmac-v1",
        identity_id="user_a",
        target_authority="api.target.com",
        secret_ref="[REDACTED_SECRET_1]",
    )
    with pytest.raises(ExpiredSigningTimestampError):
        signer.sign(
            method="GET",
            url="https://api.target.com/v1/orders",
            headers={},
            body=None,
            profile=profile,
            key_record=key_rec,
            vault=vault,
            state_manager=state_manager,
            timestamp=time.time() - 120,  # 2 mins old
        )


def test_r_nonce_replay(state_manager, vault):
    """R: Reusing the same signing nonce fails with ReplayedSigningNonceError."""
    signer = HmacRequestSigner()
    profile = SigningProfile(
        profile_id="custom-hmac-v1",
        identity_id="user_a",
        target_authority="api.target.com",
    )
    key_rec = SigningKeyRecord(
        key_id="custom-hmac-v1",
        identity_id="user_a",
        target_authority="api.target.com",
        secret_ref="[REDACTED_SECRET_1]",
    )
    vault._placeholder_to_raw["[REDACTED_SECRET_1]"] = "my_key"

    signer.sign(
        method="GET",
        url="https://api.target.com/v1/orders",
        headers={},
        body=None,
        profile=profile,
        key_record=key_rec,
        vault=vault,
        state_manager=state_manager,
        nonce="fixed_nonce_123",
    )
    # Replay
    with pytest.raises(ReplayedSigningNonceError):
        signer.sign(
            method="GET",
            url="https://api.target.com/v1/orders",
            headers={},
            body=None,
            profile=profile,
            key_record=key_rec,
            vault=vault,
            state_manager=state_manager,
            nonce="fixed_nonce_123",
        )


def test_s_modified_path_signature_rejection(state_manager, vault):
    """S: Modifying the path after signing invalidates verification."""
    signer = HmacRequestSigner()
    profile = SigningProfile(
        profile_id="custom-hmac-v1",
        identity_id="user_a",
        target_authority="api.target.com",
    )
    key_rec = SigningKeyRecord(
        key_id="custom-hmac-v1",
        identity_id="user_a",
        target_authority="api.target.com",
        secret_ref="[REDACTED_SECRET_1]",
    )
    vault._placeholder_to_raw["[REDACTED_SECRET_1]"] = "key"

    headers, _ = signer.sign(
        method="GET",
        url="https://api.target.com/v1/orders/101",
        headers={},
        body=None,
        profile=profile,
        key_record=key_rec,
        vault=vault,
        state_manager=state_manager,
    )
    # Verify with modified path
    valid = signer.verify(
        method="GET",
        url="https://api.target.com/v1/orders/102",  # Tampered
        headers=headers,
        body=None,
        profile=profile,
        key_record=key_rec,
        vault=vault,
    )
    assert valid is False


def test_t_modified_query_body_rejection(state_manager, vault):
    """T: Modifying query or body after signing breaks signature."""
    signer = HmacRequestSigner()
    profile = SigningProfile(
        profile_id="custom-hmac-v1",
        identity_id="user_a",
        target_authority="api.target.com",
    )
    key_rec = SigningKeyRecord(
        key_id="custom-hmac-v1",
        identity_id="user_a",
        target_authority="api.target.com",
        secret_ref="[REDACTED_SECRET_1]",
    )
    vault._placeholder_to_raw["[REDACTED_SECRET_1]"] = "key"

    headers, _ = signer.sign(
        method="POST",
        url="https://api.target.com/v1/pay?amount=50",
        headers={},
        body=b'{"account": "acc_1"}',
        profile=profile,
        key_record=key_rec,
        vault=vault,
        state_manager=state_manager,
    )
    # Query tampering
    assert signer.verify(
        method="POST",
        url="https://api.target.com/v1/pay?amount=5000",
        headers=headers,
        body=b'{"account": "acc_1"}',
        profile=profile,
        key_record=key_rec,
        vault=vault,
    ) is False

    # Body tampering
    assert signer.verify(
        method="POST",
        url="https://api.target.com/v1/pay?amount=50",
        headers=headers,
        body=b'{"account": "acc_hacked"}',
        profile=profile,
        key_record=key_rec,
        vault=vault,
    ) is False


def test_u_unsupported_signing_profile(state_manager, vault):
    """U: Unsupported signing algorithm fails with UnsupportedSigningFlowError."""
    signer = HmacRequestSigner()
    profile = SigningProfile(
        profile_id="rsa-profile",
        algorithm="RSA-SHA256",  # Not supported by HMAC signer
        identity_id="user_a",
        target_authority="api.target.com",
    )
    key_rec = SigningKeyRecord(
        key_id="rsa-profile",
        identity_id="user_a",
        target_authority="api.target.com",
        secret_ref="[REDACTED_SECRET_1]",
    )
    with pytest.raises(UnsupportedSigningFlowError):
        signer.sign(
            method="GET",
            url="https://api.target.com/v1/test",
            headers={},
            body=None,
            profile=profile,
            key_record=key_rec,
            vault=vault,
            state_manager=state_manager,
        )


# ---------------------------------------------------------------------------
# Tests V - X: Scope & Rate Limiting Integration
# ---------------------------------------------------------------------------

def test_v_out_of_scope_destination(scope_gate, state_manager, vault):
    """V: Target outside ScopeGate policy is rejected with BLOCKED_SCOPE."""
    client = ScopedHttpClient(scope_gate=scope_gate)
    engine = DeterministicExecutionEngine(
        scope_gate=scope_gate,
        scoped_client=client,
        state_manager=state_manager,
        vault=vault,
        live_execution_enabled=True,
    )
    proposal = ExperimentProposal(
        objective="Probe internal dashboard",
        target_asset_id="ASSET-INT-01",
        mutation_class=MutationClass.UNAUTHENTICATED_ACCESS,
        expected_observations=ExpectedObservations(
            supporting_observation="200 OK",
            contradicting_observation="403 Forbidden",
        ),
    )
    result = engine.execute_proposal(
        experiment=proposal,
        destination_url="https://internal.target.com/admin",
    )
    assert result.status == ExecutionStatus.BLOCKED_SCOPE
    assert "Destination blocked by ScopeGate" in result.error_message


def test_w_out_of_scope_redirect(scope_gate, state_manager, vault):
    """W: Redirect hopping to an out-of-scope domain is blocked by ScopedHttpClient."""
    # When ScopedHttpClient encounters out-of-scope redirect, it raises ScopeViolationError
    client = ScopedHttpClient(scope_gate=scope_gate)
    mock_engine = DeterministicExecutionEngine(
        scope_gate=scope_gate,
        scoped_client=client,
        state_manager=state_manager,
        vault=vault,
        live_execution_enabled=True,
    )
    # Simulate ScopedHttpClient raising ScopeViolationError
    client.request = MagicMock(side_effect=ScopeViolationError(
        scope_gate.evaluate("https://attacker.com/evil")
    ))
    proposal = ExperimentProposal(
        objective="Follow redirect",
        target_asset_id="ASSET-REDIR",
        mutation_class=MutationClass.STEP_SKIPPING,
        expected_observations=ExpectedObservations(
            supporting_observation="200",
            contradicting_observation="403",
        ),
    )
    result = mock_engine.execute_proposal(
        experiment=proposal,
        destination_url="https://api.target.com/redirect",
    )
    assert result.status == ExecutionStatus.BLOCKED_SCOPE


def test_x_rate_limit_enforcement(scope_gate):
    """X: Requests obey configured rate limiting intervals."""
    # Configure 10 rps -> minimum 0.1s interval
    client = ScopedHttpClient(scope_gate=scope_gate, rate_limit_rps=10)
    t_start = time.perf_counter()
    client._enforce_rate_limit()
    client._enforce_rate_limit()
    elapsed = time.perf_counter() - t_start
    assert elapsed >= 0.08  # Account for clock resolution


# ---------------------------------------------------------------------------
# Tests Y - AE: Human Approval Binding
# ---------------------------------------------------------------------------

def test_y_missing_approval():
    """Y: State-changing experiment without human approval fails with BLOCKED_APPROVAL."""
    gate = ApprovalGate()
    descriptor = ExecutionDescriptor(
        experiment_id="EXP-1",
        identity_id="user_a",
        target_authority="api.target.com",
        destination="https://api.target.com/v1/delete",
        http_method="DELETE",
        normalized_route="/v1/delete",
        request_body_digest="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        safety_classification=SafetyLevel.STATE_CHANGING_REQUIRES_APPROVAL.value,
        affected_resource="ORDER-01",
        expected_state_transition="Order is permanently deleted",
    )
    approved, err, _ = gate.verify_approval(descriptor)
    assert approved is False
    assert err == "APPROVAL_REQUIRED_BUT_NOT_FOUND"


def test_z_expired_approval():
    """Z: Expired approval fails with APPROVAL_EXPIRED."""
    gate = ApprovalGate()
    descriptor = ExecutionDescriptor(
        experiment_id="EXP-1",
        identity_id="user_a",
        target_authority="api.target.com",
        destination="https://api.target.com/v1/delete",
        http_method="DELETE",
        normalized_route="/v1/delete",
        request_body_digest="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        safety_classification=SafetyLevel.STATE_CHANGING_REQUIRES_APPROVAL.value,
        affected_resource="ORDER-01",
        expected_state_transition="Order is deleted",
    )
    digest = descriptor.compute_digest()
    gate.register_approval(
        HumanApproval(
            approval_id="APP-1",
            experiment_id="EXP-1",
            approved_descriptor_digest=digest,
            actor="sec_reviewer",
            expires_at=time.time() - 10,  # Expired
        )
    )
    approved, err, _ = gate.verify_approval(descriptor)
    assert approved is False
    assert err == "APPROVAL_EXPIRED"


def test_aa_experiment_mismatch():
    """AA: Approval for Experiment A cannot authorize Experiment B."""
    gate = ApprovalGate()
    descriptor_b = ExecutionDescriptor(
        experiment_id="EXP-B",
        identity_id="user_a",
        target_authority="api.target.com",
        destination="https://api.target.com/v1/patch",
        http_method="PATCH",
        normalized_route="/v1/patch",
        request_body_digest="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        safety_classification=SafetyLevel.STATE_CHANGING_REQUIRES_APPROVAL.value,
        affected_resource="ORDER-01",
        expected_state_transition="Order patched",
    )
    gate.register_approval(
        HumanApproval(
            approval_id="APP-A",
            experiment_id="EXP-A",  # Bound to EXP-A
            approved_descriptor_digest="some_digest",
            actor="sec_reviewer",
        )
    )
    approved, err, _ = gate.verify_approval(descriptor_b, approval_id="APP-A")
    assert approved is False
    assert err == "APPROVAL_EXPERIMENT_ID_MISMATCH"


def test_ab_method_mutation_after_approval():
    """AB: Approved GET mutated to POST fails digest verification."""
    gate = ApprovalGate()
    desc_get = ExecutionDescriptor(
        experiment_id="EXP-1",
        identity_id="user_a",
        target_authority="api.target.com",
        destination="https://api.target.com/v1/resource",
        http_method="GET",
        normalized_route="/v1/resource",
        request_body_digest="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        safety_classification=SafetyLevel.STATE_CHANGING_REQUIRES_APPROVAL.value,
        affected_resource="RES-1",
        expected_state_transition="Read state",
    )
    approved_digest = desc_get.compute_digest()
    gate.register_approval(
        HumanApproval(
            approval_id="APP-1",
            experiment_id="EXP-1",
            approved_descriptor_digest=approved_digest,
            actor="sec_reviewer",
        )
    )

    # Execution attempts POST instead of GET
    desc_post = desc_get.model_copy()
    desc_post.http_method = "POST"
    approved, err, _ = gate.verify_approval(desc_post, approval_id="APP-1")
    assert approved is False
    assert err == "APPROVAL_DESCRIPTOR_DIGEST_MISMATCH"


def test_ac_body_mutation_after_approval():
    """AC: Mutating request body after approval breaks digest verification."""
    gate = ApprovalGate()
    desc = ExecutionDescriptor(
        experiment_id="EXP-1",
        identity_id="user_a",
        target_authority="api.target.com",
        destination="https://api.target.com/v1/update",
        http_method="POST",
        normalized_route="/v1/update",
        request_body_digest="original_digest_111",
        safety_classification=SafetyLevel.STATE_CHANGING_REQUIRES_APPROVAL.value,
        affected_resource="RES-1",
        expected_state_transition="Update",
    )
    gate.register_approval(
        HumanApproval(
            approval_id="APP-1",
            experiment_id="EXP-1",
            approved_descriptor_digest=desc.compute_digest(),
            actor="sec_reviewer",
        )
    )
    # Tamper body
    desc_tampered = desc.model_copy()
    desc_tampered.request_body_digest = "malicious_payload_digest_999"
    approved, err, _ = gate.verify_approval(desc_tampered, approval_id="APP-1")
    assert approved is False
    assert err == "APPROVAL_DESCRIPTOR_DIGEST_MISMATCH"


def test_ad_destination_mutation_after_approval():
    """AD: Changing destination URL after approval fails verification."""
    gate = ApprovalGate()
    desc = ExecutionDescriptor(
        experiment_id="EXP-1",
        identity_id="user_a",
        target_authority="api.target.com",
        destination="https://api.target.com/v1/safe",
        http_method="POST",
        normalized_route="/v1/safe",
        request_body_digest="digest",
        safety_classification=SafetyLevel.STATE_CHANGING_REQUIRES_APPROVAL.value,
        affected_resource="RES-1",
        expected_state_transition="Safe state",
    )
    gate.register_approval(
        HumanApproval(
            approval_id="APP-1",
            experiment_id="EXP-1",
            approved_descriptor_digest=desc.compute_digest(),
            actor="sec_reviewer",
        )
    )
    desc_tampered = desc.model_copy()
    desc_tampered.destination = "https://api.target.com/v1/danger"
    desc_tampered.normalized_route = "/v1/danger"
    approved, err, _ = gate.verify_approval(desc_tampered, approval_id="APP-1")
    assert approved is False
    assert err == "APPROVAL_DESCRIPTOR_DIGEST_MISMATCH"


def test_ae_identity_environment_mutation_after_approval():
    """AE: Mutating identity or environment (staging -> prod) breaks approval."""
    gate = ApprovalGate()
    desc_staging = ExecutionDescriptor(
        experiment_id="EXP-1",
        identity_id="user_a",
        environment_context="staging",
        target_authority="api.target.com",
        destination="https://api.target.com/v1/test",
        http_method="POST",
        normalized_route="/v1/test",
        request_body_digest="digest",
        safety_classification=SafetyLevel.STATE_CHANGING_REQUIRES_APPROVAL.value,
        affected_resource="RES-1",
        expected_state_transition="Staging test",
    )
    gate.register_approval(
        HumanApproval(
            approval_id="APP-1",
            experiment_id="EXP-1",
            approved_descriptor_digest=desc_staging.compute_digest(),
            actor="sec_reviewer",
        )
    )
    # Tamper environment to production
    desc_prod = desc_staging.model_copy()
    desc_prod.environment_context = "production"
    approved_env, _, _ = gate.verify_approval(desc_prod, approval_id="APP-1")
    assert approved_env is False

    # Tamper identity to user_b
    desc_user_b = desc_staging.model_copy()
    desc_user_b.identity_id = "user_b"
    approved_id, _, _ = gate.verify_approval(desc_user_b, approval_id="APP-1")
    assert approved_id is False


# ---------------------------------------------------------------------------
# Tests AF - AG: Mode & Scrubber
# ---------------------------------------------------------------------------

def test_af_live_execution_default_off(scope_gate, state_manager, vault):
    """AF: Live network execution is disabled by default; returns BLOCKED_EXECUTION_MODE."""
    client = ScopedHttpClient(scope_gate=scope_gate)
    engine = DeterministicExecutionEngine(
        scope_gate=scope_gate,
        scoped_client=client,
        state_manager=state_manager,
        vault=vault,
        live_execution_enabled=False,  # Default
    )
    proposal = ExperimentProposal(
        objective="Probe orders",
        target_asset_id="ASSET-1",
        mutation_class=MutationClass.CROSS_IDENTITY_REPLAY,
        expected_observations=ExpectedObservations(
            supporting_observation="200",
            contradicting_observation="403",
        ),
    )
    res = engine.execute_proposal(proposal, destination_url="https://api.target.com/orders")
    assert res.status == ExecutionStatus.BLOCKED_EXECUTION_MODE
    assert "Live network execution is disabled by default" in res.error_message


def test_ag_exception_secret_scrubbing(vault):
    """AG: Exceptions containing authorization headers, cookies, and query params are sanitized."""
    raw_error = (
        "HTTP Connection error: GET https://api.target.com/v1/auth?token=super_secret_token_value&api_key=secret_key_123 "
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.xyz1234567890 "
        "Cookie: session_id=top_secret_cookie_val_9999; path=/ "
        "Failed with status 502 Bad Gateway"
    )
    clean = scrub_exception_text(raw_error, vault)
    assert "super_secret_token_value" not in clean
    assert "secret_key_123" not in clean
    assert "top_secret_cookie_val_9999" not in clean
    assert "Bearer [REDACTED" in clean or "[REDACTED_AUTH_HEADER]" in clean
    assert "[REDACTED_QUERY_PARAM]" in clean
