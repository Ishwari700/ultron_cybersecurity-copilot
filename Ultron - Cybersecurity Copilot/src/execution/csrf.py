"""Deterministic CSRF and Anti-Replay Nonce Manager for Milestone M2.75.

Enforces:
- Explicit CSRF acquisition from configured headers, response extractors, or prior evidence.
- ZERO autonomous crawling or page scraping for tokens.
- Strict identity, session, and target authority binding.
- Single-use consumption with atomic check-and-consume semantics.
- Replay prevention: re-using a consumed CSRF token immediately fails with BLOCKED_CSRF.
- Cross-identity and cross-session CSRF substitution immediately fails with BLOCKED_CSRF.
"""

from typing import Any, Dict, Optional, Tuple

from src.evidence.vault import RedactionVault, VaultAccessContext, VaultReversalPurpose
from src.execution.models import CsrfLifecycleState
from src.execution.state import CsrfRecord
from src.execution.state_manager import DeterministicStateManager


class CsrfManager:
    """Manages CSRF token acquisition, validation, atomic consumption, and injection."""

    def __init__(
        self,
        state_manager: DeterministicStateManager,
        vault: RedactionVault,
    ) -> None:
        self.state_manager = state_manager
        self.vault = vault

    def register_discovered_token(
        self,
        raw_token: str,
        identity_id: str,
        session_id: Optional[str],
        target_authority: str,
        header_name: str = "X-CSRF-Token",
        expires_at: Optional[float] = None,
    ) -> CsrfRecord:
        """Register a newly discovered CSRF token without leaking raw secrets to logs."""
        # Redact raw token through vault to obtain a typed placeholder
        token_ref = self.vault.redact_text(raw_token)
        if not token_ref.startswith("[REDACTED_"):
            # Ensure placeholder format
            token_ref = self.vault._get_or_create_placeholder(raw_token, "CSRF")

        rec = CsrfRecord(
            token_ref=token_ref,
            identity_id=identity_id,
            session_id=session_id,
            target_authority=target_authority,
            header_name=header_name,
            lifecycle_state=CsrfLifecycleState.CSRF_VALID,
            consumed=False,
            expires_at=expires_at,
        )
        return self.state_manager.register_csrf(rec)

    def prepare_and_consume_csrf(
        self,
        token_ref: str,
        identity_id: str,
        session_id: Optional[str] = None,
        target_authority: Optional[str] = None,
    ) -> Tuple[bool, Optional[str], Optional[Tuple[str, str]]]:
        """Atomically validate ownership, single-use, and freshness, then return (header_name, raw_value).

        Returns:
            (success, error_reason, (header_name, raw_value))
        """
        success, reason, rec = self.state_manager.consume_csrf_token(
            token_ref=token_ref,
            expected_identity_id=identity_id,
            expected_session_id=session_id,
            expected_target_authority=target_authority,
        )

        if not success or not rec:
            return False, reason, None

        # Resolve raw value from vault immediately before outbound request transmission
        try:
            vault_ctx = VaultAccessContext(
                actor=identity_id or "csrf_manager",
                purpose=VaultReversalPurpose.CSRF_CONSUMPTION,
                justification="CSRF token consumption for HTTP dispatch",
            )
            raw_token = self.vault.reverse_placeholder(rec.token_ref, context=vault_ctx)
        except Exception:
            raw_token = None
        if not raw_token:
            # If the placeholder itself was a direct value or stored directly
            raw_token = rec.token_ref

        return True, None, (rec.header_name, raw_token)

    def rotate_token(
        self,
        old_token_ref: str,
        new_raw_token: str,
        identity_id: str,
        session_id: Optional[str],
        target_authority: str,
        header_name: str = "X-CSRF-Token",
        expires_at: Optional[float] = None,
    ) -> CsrfRecord:
        """Atomically rotate CSRF token."""
        new_token_ref = self.vault._get_or_create_placeholder(new_raw_token, "CSRF")
        new_rec = CsrfRecord(
            token_ref=new_token_ref,
            identity_id=identity_id,
            session_id=session_id,
            target_authority=target_authority,
            header_name=header_name,
            lifecycle_state=CsrfLifecycleState.CSRF_VALID,
            consumed=False,
            expires_at=expires_at,
        )
        self.state_manager.rotate_csrf_token(old_token_ref, new_rec)
        return new_rec
