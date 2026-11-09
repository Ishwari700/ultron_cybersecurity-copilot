"""
Regression and security invariant tests for Finding 6:
Reversible Secret Vault Authorization, Purpose Limitation, and Audit Controls.
"""

from pathlib import Path
from typing import Tuple
from unittest.mock import MagicMock
import pytest

from src.core.logging import AuditLogger
from src.evidence.vault import (
    RedactionVault,
    VaultAccessContext,
    VaultAccessDeniedError,
    VaultAuditError,
    VaultDataTamperedError,
    VaultReversalPurpose,
)


@pytest.fixture
def audit_file(tmp_path: Path) -> Path:
    return tmp_path / "vault_test_audit.log"


@pytest.fixture
def auditor(audit_file: Path) -> AuditLogger:
    return AuditLogger(audit_file)


@pytest.fixture
def vault_with_secret(auditor: AuditLogger) -> Tuple[RedactionVault, str, str]:
    vault = RedactionVault(audit_logger=auditor)
    raw_secret = "ghp_VerySensitiveGithubToken9876543210ABC"
    placeholder = vault.redact_text(f"Authorization: Bearer {raw_secret}")
    # Extract the placeholder
    import re
    match = re.search(r"\[REDACTED_BEARER_TOKEN_\d+\]", placeholder)
    assert match is not None
    token_ph = match.group(0)
    return vault, raw_secret, token_ph


def test_authorized_reversal_succeeds_and_audits(vault_with_secret, audit_file):
    """Authorized reversal with valid context returns raw secret and writes audit record."""
    vault, raw_secret, placeholder = vault_with_secret
    context = VaultAccessContext(
        actor="security_analyst_alice",
        purpose=VaultReversalPurpose.AUTHENTICATED_HUMAN_VERIFICATION,
        justification="Manual verification of repro evidence",
    )

    reversed_val = vault.reverse_placeholder(placeholder, context=context)
    assert reversed_val == raw_secret

    # Verify audit log recorded the access without raw secret
    log_content = audit_file.read_text(encoding="utf-8")
    assert "VAULT_REVERSAL_ACCESSED" in log_content
    assert "security_analyst_alice" in log_content
    assert placeholder in log_content
    assert raw_secret not in log_content  # Raw secret must NEVER appear in logs!


def test_unauthorized_reversal_without_context_fails_closed(vault_with_secret):
    """Calling reverse_placeholder without context raises VaultAccessDeniedError."""
    vault, _, placeholder = vault_with_secret

    with pytest.raises(VaultAccessDeniedError, match="valid VaultAccessContext is required"):
        vault.reverse_placeholder(placeholder, context=None)


def test_wrong_or_empty_actor_fails_closed(vault_with_secret):
    """Calling reverse_placeholder with empty actor raises VaultAccessDeniedError."""
    vault, _, placeholder = vault_with_secret

    with pytest.raises(Exception):
        # Empty string violates Pydantic min_length=1 or VaultAccessDeniedError
        context = VaultAccessContext(
            actor="",
            purpose=VaultReversalPurpose.AUTHENTICATED_HUMAN_VERIFICATION,
        )
        vault.reverse_placeholder(placeholder, context=context)


def test_audit_failure_fails_closed_without_releasing_secret(vault_with_secret):
    """If audit logging fails, reversal fails closed and raises VaultAuditError."""
    vault, raw_secret, placeholder = vault_with_secret

    # Mock auditor to raise an error
    failing_auditor = MagicMock()
    failing_auditor.log_event.side_effect = IOError("Disk full / permission denied")
    vault.audit_logger = failing_auditor

    context = VaultAccessContext(
        actor="lead_auditor",
        purpose=VaultReversalPurpose.EXECUTION_DISPATCH,
    )

    with pytest.raises(VaultAuditError, match="Vault audit logging failed"):
        vault.reverse_placeholder(placeholder, context=context)


def test_nonexistent_placeholder_returns_none(vault_with_secret):
    """Reversing a nonexistent placeholder returns None without leaking."""
    vault, _, _ = vault_with_secret
    context = VaultAccessContext(
        actor="lead_auditor",
        purpose=VaultReversalPurpose.AUTHENTICATED_HUMAN_VERIFICATION,
    )

    res = vault.reverse_placeholder("[REDACTED_JWT_99999]", context=context)
    assert res is None


def test_tampered_vault_in_memory_data_detected(vault_with_secret):
    """If internal vault memory is tampered with, integrity verification detects it and aborts."""
    vault, _, placeholder = vault_with_secret
    context = VaultAccessContext(
        actor="security_analyst_alice",
        purpose=VaultReversalPurpose.AUTHENTICATED_HUMAN_VERIFICATION,
    )

    # Tamper with the in-memory value
    vault._placeholder_to_raw[placeholder] = "TAMPERED_INJECTED_VALUE"

    with pytest.raises(VaultDataTamperedError, match="Vault in-memory integrity violation"):
        vault.reverse_placeholder(placeholder, context=context)


def test_reverse_text_requires_authorization(vault_with_secret):
    """reverse_text strictly requires authorized VaultAccessContext."""
    vault, raw_secret, placeholder = vault_with_secret
    sample_text = f"User token was {placeholder} in test"

    # Without context
    with pytest.raises(VaultAccessDeniedError):
        vault.reverse_text(sample_text, context=None)

    # With authorized context
    context = VaultAccessContext(
        actor="lead_auditor",
        purpose=VaultReversalPurpose.AUTHENTICATED_HUMAN_VERIFICATION,
    )
    reconstituted = vault.reverse_text(sample_text, context=context)
    assert raw_secret in reconstituted
    assert placeholder not in reconstituted
