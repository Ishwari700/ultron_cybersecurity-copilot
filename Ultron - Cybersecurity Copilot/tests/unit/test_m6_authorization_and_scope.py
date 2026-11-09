"""Unit tests for M6 Authorization Engine and Extended ScopeGate."""

from datetime import datetime, timezone, timedelta
import pytest

from src.assessment.models import (
    AssessmentScopeStatus,
    AuthorizationRecord,
    AuthorizationStatus,
    AuthorizationType,
)
from src.assessment.authorization import AuthorizationValidator, AuthorizationValidationError
from src.scope.gate import ScopeGate, ScopeValidationError
from src.scope.models import ScopePolicy


def test_authorization_hash_determinism():
    """Verify cryptographic hash computation is bit-for-bit deterministic."""
    auth = AuthorizationRecord(
        authorization_id="AUTH-1",
        organization="FinCorp",
        assessment_name="Audit",
        authorized_by="SecurityDirector",
        authorized_at="2026-10-01T00:00:00Z",
        valid_from="2026-10-01T00:00:00Z",
        valid_until="2026-10-31T00:00:00Z",
        authorization_type=AuthorizationType.PENETRATION_TEST,
        scope_reference="SCOPE-1",
        rules=["Rule1", "Rule2"],
    )
    h1 = auth.compute_hash()
    h2 = auth.compute_hash()
    assert h1 == h2
    assert h1.startswith("AUTH-")


def test_extended_scope_cidrs_and_ips():
    """Verify IP and CIDR subnet scope matching."""
    gate = ScopeGate(
        policy=ScopePolicy(
            program_name="SubnetTest",
            platform="LOCAL",
            in_scope=["192.168.10.0/24", "10.50.0.1"],
        ),
        allow_private_ranges=True,
    )
    # Inside CIDR
    res1 = gate.evaluate_extended_scope("192.168.10.45")
    assert res1.scope_status == AssessmentScopeStatus.IN_SCOPE
    assert res1.is_permitted is True

    # Exact IP
    res2 = gate.evaluate_extended_scope("10.50.0.1")
    assert res2.scope_status == AssessmentScopeStatus.IN_SCOPE

    # Outside CIDR
    res3 = gate.evaluate_extended_scope("192.168.11.1")
    assert res3.scope_status == AssessmentScopeStatus.UNKNOWN
    assert res3.is_permitted is False


def test_extended_scope_mobile_and_repositories():
    """Verify mobile package identifiers and source repository scope."""
    gate = ScopeGate(
        policy=ScopePolicy(
            program_name="MobileRepoTest",
            platform="LOCAL",
            in_scope=["com.example.bankapp.*", "github.com/myorg/*"],
        ),
        allow_private_ranges=True,
    )
    # Mobile app
    res1 = gate.evaluate_extended_scope("com.example.bankapp.auth")
    assert res1.scope_status == AssessmentScopeStatus.IN_SCOPE

    # Repository
    res2 = gate.evaluate_extended_scope("github.com/myorg/payment-gateway")
    assert res2.scope_status == AssessmentScopeStatus.IN_SCOPE

    # Foreign repo
    res3 = gate.evaluate_extended_scope("github.com/evilcorp/payment-gateway")
    assert res3.scope_status == AssessmentScopeStatus.UNKNOWN
    assert res3.is_permitted is False


def test_extended_scope_cloud_and_files():
    """Verify cloud ARNs and local file path scopes."""
    gate = ScopeGate(
        policy=ScopePolicy(
            program_name="CloudFileTest",
            platform="LOCAL",
            in_scope=["arn:aws:s3:::target-assets-*", "/app/src/*"],
        ),
        allow_private_ranges=True,
    )
    # Cloud ARN
    res1 = gate.evaluate_extended_scope("arn:aws:s3:::target-assets-prod")
    assert res1.scope_status == AssessmentScopeStatus.IN_SCOPE

    # File path
    res2 = gate.evaluate_extended_scope("/app/src/handlers/auth.py")
    assert res2.scope_status == AssessmentScopeStatus.IN_SCOPE

    # Foreign file
    res3 = gate.evaluate_extended_scope("/etc/shadow")
    assert res3.scope_status == AssessmentScopeStatus.UNKNOWN
    assert res3.is_permitted is False


def test_recheck_scope_raises_on_out_of_scope():
    """Verify recheck_scope enforces fail closed with ScopeValidationError."""
    gate = ScopeGate(
        policy=ScopePolicy(
            program_name="RecheckTest",
            platform="LOCAL",
            in_scope=["authorized.com"],
            out_of_scope=["forbidden.authorized.com"],
        ),
        allow_private_ranges=True,
    )
    # Allowed target passes
    res = gate.recheck_scope("authorized.com", "TestOp")
    assert res.is_permitted is True

    # Excluded target raises
    with pytest.raises(ScopeValidationError) as exc:
        gate.recheck_scope("forbidden.authorized.com", "ExploitProposal")
    assert "SCOPE RECHECK FAILED" in str(exc.value)
