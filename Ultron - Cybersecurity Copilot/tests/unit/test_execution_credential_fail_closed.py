"""
Regression and security invariant tests for Finding 2:
Execution Engine Credential References Fail-Closed Enforcement.
"""

import time
from unittest.mock import MagicMock
import pytest

from src.core.logging import AuditLogger
from src.evidence.vault import RedactionVault
from src.execution import (
    CredentialRecord,
    CredentialType,
    DeterministicExecutionEngine,
    DeterministicStateManager,
    ExecutionStatus,
)
from src.execution.models import CredentialLifecycleState
from src.hypothesis.experiment import (
    ExpectedObservations,
    ExperimentProposal,
    MutationClass,
    SafetyLevel,
)
from src.scope.client import ScopedHttpClient
from src.scope.gate import ScopeGate
from src.scope.models import ScopePolicy


@pytest.fixture
def test_scope_policy() -> ScopePolicy:
    return ScopePolicy(
        program_name="test-prog",
        platform="test-platform",
        in_scope=["*.target.com", "api.target.com"],
        out_of_scope=["internal.target.com"],
        rules_of_engagement={"rate_limit_rps": 50},
    )


@pytest.fixture
def vault() -> RedactionVault:
    v = RedactionVault()
    v.redact_text("secret_jwt_user_a_raw_value_1234567890")
    return v


@pytest.fixture
def scope_gate(test_scope_policy) -> ScopeGate:
    return ScopeGate(policy=test_scope_policy, dns_resolver=lambda h: ["93.184.216.34"])


@pytest.fixture
def scoped_client(scope_gate) -> ScopedHttpClient:
    return ScopedHttpClient(scope_gate=scope_gate)


@pytest.fixture
def state_manager(vault, tmp_path) -> DeterministicStateManager:
    audit_file = tmp_path / "test_audit.log"
    logger = AuditLogger(audit_file)
    return DeterministicStateManager(vault=vault, audit_logger=logger)


def build_proposal(token_ref: str = "[REDACTED_JWT_1]", actor: str = "user_a") -> ExperimentProposal:
    return ExperimentProposal(
        objective="Test credential fail closed",
        target_asset_id="ASSET-ORDER-01",
        mutation_class=MutationClass.CROSS_IDENTITY_REPLAY,
        actor_identity_id=actor,
        target_identity_id="user_b",
        expected_observations=ExpectedObservations(
            supporting_observation="HTTP 200",
            contradicting_observation="HTTP 403",
        ),
        safety_level=SafetyLevel.READ_ONLY_SAFE,
        required_token_references=[token_ref],
    )


def test_missing_credential_reference_fails_closed(scope_gate, scoped_client, state_manager, vault):
    """Missing credential reference must immediately prevent execution and block dispatch."""
    mock_transport = MagicMock()
    engine = DeterministicExecutionEngine(
        scope_gate=scope_gate,
        scoped_client=scoped_client,
        state_manager=state_manager,
        vault=vault,
        mock_transport_fn=mock_transport,
        live_execution_enabled=True,
    )
    # Token not registered in state_manager
    proposal = build_proposal("[NONEXISTENT_TOKEN_REF]")

    result = engine.execute_proposal(
        experiment=proposal,
        destination_url="https://api.target.com/orders/ORD-100",
    )

    assert result.status in (ExecutionStatus.BLOCKED_TTL, ExecutionStatus.BLOCKED_AUTH_STATE)
    assert "TOKEN_REFERENCE_NOT_FOUND" in result.error_message
    mock_transport.assert_not_called()


def test_expired_credential_fails_closed(scope_gate, scoped_client, state_manager, vault):
    """Expired credential without refresh adapter fails closed."""
    state_manager.register_credential(
        CredentialRecord(
            token_ref="[REDACTED_JWT_1]",
            identity_id="user_a",
            target_authority="api.target.com",
            credential_type=CredentialType.BEARER_JWT,
            expires_at=time.time() - 60,  # Expired
        )
    )
    mock_transport = MagicMock()
    engine = DeterministicExecutionEngine(
        scope_gate=scope_gate,
        scoped_client=scoped_client,
        state_manager=state_manager,
        vault=vault,
        mock_transport_fn=mock_transport,
        live_execution_enabled=True,
    )
    proposal = build_proposal("[REDACTED_JWT_1]")

    result = engine.execute_proposal(
        experiment=proposal,
        destination_url="https://api.target.com/orders/ORD-100",
    )

    assert result.status == ExecutionStatus.BLOCKED_TTL
    assert "EXPIRED" in result.error_message
    mock_transport.assert_not_called()


def test_invalid_credential_identity_fails_closed(scope_gate, scoped_client, state_manager, vault):
    """Token owned by user_b cannot be used by user_a."""
    state_manager.register_credential(
        CredentialRecord(
            token_ref="[REDACTED_JWT_1]",
            identity_id="user_b",  # Belongs to user_b
            target_authority="api.target.com",
            credential_type=CredentialType.BEARER_JWT,
            expires_at=time.time() + 3600,
        )
    )
    mock_transport = MagicMock()
    engine = DeterministicExecutionEngine(
        scope_gate=scope_gate,
        scoped_client=scoped_client,
        state_manager=state_manager,
        vault=vault,
        mock_transport_fn=mock_transport,
        live_execution_enabled=True,
    )
    # user_a attempts to execute using user_b's credential
    proposal = build_proposal("[REDACTED_JWT_1]", actor="user_a")

    result = engine.execute_proposal(
        experiment=proposal,
        destination_url="https://api.target.com/orders/ORD-100",
    )

    assert result.status == ExecutionStatus.BLOCKED_AUTH_STATE
    assert "CROSS_IDENTITY_SUBSTITUTION_BLOCKED" in result.error_message
    mock_transport.assert_not_called()


def test_wrong_target_authority_fails_closed(scope_gate, scoped_client, state_manager, vault):
    """Token registered for auth.target.com cannot be dispatched to api.target.com."""
    state_manager.register_credential(
        CredentialRecord(
            token_ref="[REDACTED_JWT_1]",
            identity_id="user_a",
            target_authority="auth.target.com",  # Different authority
            credential_type=CredentialType.BEARER_JWT,
            expires_at=time.time() + 3600,
        )
    )
    mock_transport = MagicMock()
    engine = DeterministicExecutionEngine(
        scope_gate=scope_gate,
        scoped_client=scoped_client,
        state_manager=state_manager,
        vault=vault,
        mock_transport_fn=mock_transport,
        live_execution_enabled=True,
    )
    proposal = build_proposal("[REDACTED_JWT_1]")

    result = engine.execute_proposal(
        experiment=proposal,
        destination_url="https://api.target.com/orders/ORD-100",
    )

    assert result.status == ExecutionStatus.BLOCKED_AUTH_STATE
    assert "CROSS_TARGET_SUBSTITUTION_BLOCKED" in result.error_message
    mock_transport.assert_not_called()


def test_wrong_environment_context_fails_closed(scope_gate, scoped_client, state_manager, vault):
    """Token registered for staging cannot be dispatched to production."""
    state_manager.register_credential(
        CredentialRecord(
            token_ref="[REDACTED_JWT_1]",
            identity_id="user_a",
            target_authority="api.target.com",
            environment_context="staging",
            credential_type=CredentialType.BEARER_JWT,
            expires_at=time.time() + 3600,
        )
    )
    mock_transport = MagicMock()
    engine = DeterministicExecutionEngine(
        scope_gate=scope_gate,
        scoped_client=scoped_client,
        state_manager=state_manager,
        vault=vault,
        mock_transport_fn=mock_transport,
        live_execution_enabled=True,
    )
    proposal = build_proposal("[REDACTED_JWT_1]")

    result = engine.execute_proposal(
        experiment=proposal,
        destination_url="https://api.target.com/orders/ORD-100",
        environment_context="production",
    )

    assert result.status == ExecutionStatus.BLOCKED_AUTH_STATE
    assert "CROSS_ENVIRONMENT_SUBSTITUTION_BLOCKED" in result.error_message
    mock_transport.assert_not_called()


def test_token_unresolvable_from_vault_fails_closed(scope_gate, scoped_client, state_manager):
    """Token valid in state manager but missing from vault fails closed immediately before dispatch."""
    empty_vault = RedactionVault()  # Empty vault
    state_manager.vault = empty_vault
    state_manager.register_credential(
        CredentialRecord(
            token_ref="[REDACTED_JWT_1]",
            identity_id="user_a",
            target_authority="api.target.com",
            credential_type=CredentialType.BEARER_JWT,
            expires_at=time.time() + 3600,
        )
    )
    mock_transport = MagicMock()
    engine = DeterministicExecutionEngine(
        scope_gate=scope_gate,
        scoped_client=scoped_client,
        state_manager=state_manager,
        vault=empty_vault,
        mock_transport_fn=mock_transport,
        live_execution_enabled=True,
    )
    proposal = build_proposal("[REDACTED_JWT_1]")

    result = engine.execute_proposal(
        experiment=proposal,
        destination_url="https://api.target.com/orders/ORD-100",
    )

    assert result.status == ExecutionStatus.BLOCKED_AUTH_STATE
    assert "could not be resolved from vault" in result.error_message
    mock_transport.assert_not_called()


def test_unresolved_redaction_marker_in_header_fails_closed(scope_gate, scoped_client, state_manager, vault):
    """If Authorization header contains '******', engine aborts before dispatch."""
    mock_transport = MagicMock()
    engine = DeterministicExecutionEngine(
        scope_gate=scope_gate,
        scoped_client=scoped_client,
        state_manager=state_manager,
        vault=vault,
        mock_transport_fn=mock_transport,
        live_execution_enabled=True,
    )
    proposal = ExperimentProposal(
        objective="Send redacted header directly",
        target_asset_id="ASSET-ORDER-01",
        mutation_class=MutationClass.UNAUTHENTICATED_ACCESS,
        expected_observations=ExpectedObservations(
            supporting_observation="200",
            contradicting_observation="403",
        ),
        safety_level=SafetyLevel.READ_ONLY_SAFE,
    )

    result = engine.execute_proposal(
        experiment=proposal,
        destination_url="https://api.target.com/orders/ORD-100",
        request_headers={"Authorization": "Bearer ******"},
    )

    assert result.status == ExecutionStatus.BLOCKED_AUTH_STATE
    assert "unresolved redacted placeholder" in result.error_message
    mock_transport.assert_not_called()


def test_toctou_revocation_race_fails_closed(scope_gate, scoped_client, state_manager, vault):
    """Simulate credential revocation immediately before final dispatch."""
    token_ref = "[REDACTED_JWT_1]"
    state_manager.register_credential(
        CredentialRecord(
            token_ref=token_ref,
            identity_id="user_a",
            target_authority="api.target.com",
            credential_type=CredentialType.BEARER_JWT,
            expires_at=time.time() + 3600,
        )
    )
    mock_transport = MagicMock()
    engine = DeterministicExecutionEngine(
        scope_gate=scope_gate,
        scoped_client=scoped_client,
        state_manager=state_manager,
        vault=vault,
        mock_transport_fn=mock_transport,
        live_execution_enabled=True,
    )
    proposal = build_proposal(token_ref)

    # Wrap validate_credential_ownership so that on the second call (Step 10e), it revokes
    orig_validate = state_manager.validate_credential_ownership
    call_count = [0]

    def racing_validate(*args, **kwargs):
        call_count[0] += 1
        if call_count[0] == 2:
            # Revoke token right before final dispatch
            state_manager._credentials.pop(token_ref, None)
        return orig_validate(*args, **kwargs)

    state_manager.validate_credential_ownership = racing_validate

    result = engine.execute_proposal(
        experiment=proposal,
        destination_url="https://api.target.com/orders/ORD-100",
    )

    assert result.status == ExecutionStatus.BLOCKED_AUTH_STATE
    assert "Final TOCTOU credential ownership check failed" in result.error_message
    mock_transport.assert_not_called()
