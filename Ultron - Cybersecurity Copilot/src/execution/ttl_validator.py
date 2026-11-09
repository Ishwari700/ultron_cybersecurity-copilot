"""Concrete Pre-Execution TTL Validator for Milestone M2.75.

Implements IPreExecutionTTLValidator to enforce deterministic token freshness,
strict identity ownership binding, and bounded adapter-driven refresh.
Preserves MockPreExecutionTTLValidator contract completely.
"""

from typing import Any, Dict, Optional
from src.evidence.vault import RedactionVault
from src.execution.auth_adapters import (
    AuthAdapter,
    AuthAdapterError,
    RetryExhaustionError,
    UnsupportedAuthFlowError,
)
from src.execution.state import CredentialRecord
from src.execution.state_manager import DeterministicStateManager
from src.hypothesis.experiment import ExperimentProposal
from src.hypothesis.ttl_validator import IPreExecutionTTLValidator, TTLValidationResult
from src.scope.client import ScopedHttpClient


class DeterministicTTLValidator(IPreExecutionTTLValidator):
    """Concrete pre-execution token freshness and identity binding validator."""

    def __init__(
        self,
        state_manager: Optional[DeterministicStateManager] = None,
        adapters: Optional[Dict[str, AuthAdapter]] = None,
        scoped_client: Optional[ScopedHttpClient] = None,
        adapter_configs: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> None:
        self.state_manager = state_manager
        self.adapters = adapters or {}
        self.scoped_client = scoped_client
        self.adapter_configs = adapter_configs or {}

    def register_adapter(
        self,
        credential_type: str,
        adapter: AuthAdapter,
        config: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.adapters[credential_type] = adapter
        if config:
            self.adapter_configs[credential_type] = config

    def validate_proposal(
        self,
        experiment: ExperimentProposal,
        vault: RedactionVault,
    ) -> TTLValidationResult:
        """Validate presence, freshness, and identity binding of required tokens.

        Initiates bounded refresh if token is expired and an adapter is registered.
        """
        actor_id = experiment.actor_identity_id

        for token_ref in experiment.required_token_references:
            # 1. Resolve from state manager if available, else vault
            rec: Optional[CredentialRecord] = None
            if self.state_manager:
                rec = self.state_manager.get_credential(token_ref)

            if rec is None:
                # Fallback to vault token metadata
                meta = vault.get_token_metadata(token_ref)
                if meta is None:
                    return TTLValidationResult(
                        valid=False,
                        error="TOKEN_REFERENCE_NOT_FOUND",
                    )
                # Check identity binding on metadata
                if actor_id and meta.identity_id and meta.identity_id.lower().strip() != actor_id.lower().strip():
                    return TTLValidationResult(
                        valid=False,
                        error="CROSS_IDENTITY_SUBSTITUTION_BLOCKED",
                        identity_id=meta.identity_id,
                    )
                # Check expiration on metadata
                if meta.is_expired(clock_skew_seconds=30):
                    return TTLValidationResult(
                        valid=False,
                        error="TOKEN_EXPIRED",
                        requires_refresh=True,
                        identity_id=meta.identity_id,
                    )
                continue

            # 2. Strict identity binding enforcement from CredentialRecord
            if actor_id and rec.identity_id.lower().strip() != actor_id.lower().strip():
                return TTLValidationResult(
                    valid=False,
                    error="CROSS_IDENTITY_SUBSTITUTION_BLOCKED",
                    identity_id=rec.identity_id,
                )

            # 3. Check expiration
            if rec.is_expired(clock_skew_seconds=30):
                cred_type_str = rec.credential_type.value
                adapter = self.adapters.get(cred_type_str)

                # If no adapter or no client, fail closed with TOKEN_EXPIRED
                if not adapter or not self.scoped_client:
                    return TTLValidationResult(
                        valid=False,
                        error="TOKEN_EXPIRED",
                        requires_refresh=True,
                        identity_id=rec.identity_id,
                    )

                # Attempt bounded refresh
                adapter_cfg = self.adapter_configs.get(cred_type_str, {})
                try:
                    refreshed = adapter.refresh(
                        credential=rec,
                        vault=vault,
                        client=self.scoped_client,
                        config=adapter_cfg,
                    )
                    # Update state manager
                    if self.state_manager:
                        self.state_manager.transition_credential(
                            token_ref=refreshed.token_ref,
                            new_state=refreshed.lifecycle_state,
                            reason=refreshed.last_transition_reason,
                            new_expires_at=refreshed.expires_at,
                            new_refresh_token_ref=refreshed.refresh_token_ref,
                        )

                    # Revalidate post-refresh
                    if refreshed.is_expired(clock_skew_seconds=30):
                        return TTLValidationResult(
                            valid=False,
                            error="REFRESH_PRODUCED_EXPIRED_TOKEN",
                            requires_refresh=False,
                            identity_id=refreshed.identity_id,
                        )
                except RetryExhaustionError:
                    return TTLValidationResult(
                        valid=False,
                        error="REFRESH_RETRY_LIMIT_EXHAUSTED",
                        requires_refresh=False,
                        identity_id=rec.identity_id,
                    )
                except UnsupportedAuthFlowError:
                    return TTLValidationResult(
                        valid=False,
                        error="UNSUPPORTED_AUTH_FLOW",
                        requires_refresh=False,
                        identity_id=rec.identity_id,
                    )
                except AuthAdapterError as e:
                    return TTLValidationResult(
                        valid=False,
                        error=f"REFRESH_FAILED: {e}",
                        requires_refresh=False,
                        identity_id=rec.identity_id,
                    )

        return TTLValidationResult(valid=True)
