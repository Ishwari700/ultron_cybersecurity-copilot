"""Deterministic Authentication Adapters for Milestone M2.75.

Enforces:
- Explicit, pre-configured protocol adapters only (JwtRefreshAdapter, CookieSessionAdapter,
  OAuthRefreshAdapter, ReauthenticationAdapter).
- ZERO autonomous flow discovery, ZERO guessed endpoints, ZERO LLM-generated auth requests.
- All outbound refresh requests MUST route through ScopedHttpClient and pass ScopeGate
  (DNS TOCTOU, IP pinning, private range blocking, redirect scope, rate limiting).
- Strict ownership preservation: refreshed state MUST remain bound to the same identity,
  target authority, and environment.
- Bounded retry guard: max_retries = 2. On exhaustion, fails closed with BLOCKED_AUTH_STATE.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Tuple
import httpx

from src.evidence.vault import RedactionVault, VaultAccessContext, VaultReversalPurpose
from src.execution.models import CredentialLifecycleState, CredentialType, SessionLifecycleState
from src.execution.state import CredentialRecord, SessionRecord
from src.scope.client import ScopedHttpClient, ScopeViolationError
from src.scope.gate import ScopeGate


class AuthAdapterError(Exception):
    """Base exception for authentication adapter failures."""
    pass


class UnsupportedAuthFlowError(AuthAdapterError):
    """Raised when an unsupported or unconfigured authentication flow is requested."""
    pass


class RetryExhaustionError(AuthAdapterError):
    """Raised when the bounded authentication refresh retry limit is reached."""
    pass


class AuthAdapter(ABC):
    """Abstract base contract for deterministic authentication adapters."""

    def __init__(self, max_retries: int = 2) -> None:
        self.max_retries = max_retries
        self._retry_counts: Dict[str, int] = {}

    def _check_and_increment_retry(self, credential_ref: str) -> None:
        count = self._retry_counts.get(credential_ref, 0)
        if count >= self.max_retries:
            raise RetryExhaustionError(
                f"Refresh retry budget exhausted ({self.max_retries} retries) for {credential_ref}"
            )
        self._retry_counts[credential_ref] = count + 1

    def reset_retries(self, credential_ref: str) -> None:
        if credential_ref in self._retry_counts:
            del self._retry_counts[credential_ref]

    @abstractmethod
    def refresh(
        self,
        credential: CredentialRecord,
        vault: RedactionVault,
        client: ScopedHttpClient,
        config: Dict[str, Any],
    ) -> CredentialRecord:
        """Execute a deterministic refresh flow and return updated CredentialRecord."""
        pass


class JwtRefreshAdapter(AuthAdapter):
    """Refreshes a JWT using an explicitly configured refresh endpoint and refresh token."""

    def refresh(
        self,
        credential: CredentialRecord,
        vault: RedactionVault,
        client: ScopedHttpClient,
        config: Dict[str, Any],
    ) -> CredentialRecord:
        self._check_and_increment_retry(credential.token_ref)

        refresh_url = config.get("refresh_url")
        if not refresh_url:
            raise UnsupportedAuthFlowError("JwtRefreshAdapter requires explicit 'refresh_url' configuration")

        if not credential.refresh_token_ref:
            raise UnsupportedAuthFlowError(f"No refresh_token_ref available for credential {credential.token_ref}")

        # Resolve raw refresh token from vault immediately before outbound request
        try:
            vault_ctx = VaultAccessContext(
                actor=credential.identity_id or "auth_adapter",
                purpose=VaultReversalPurpose.CREDENTIAL_ROTATION,
                justification="JWT refresh adapter execution",
            )
            raw_refresh_token = vault.reverse_placeholder(credential.refresh_token_ref, context=vault_ctx)
        except Exception as e:
            raise AuthAdapterError(f"Vault authorization failed: {e}")
        if not raw_refresh_token:
            raise AuthAdapterError(f"Refresh token placeholder {credential.refresh_token_ref} not found in vault")

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {raw_refresh_token}",
        }
        payload = {"refresh_token": raw_refresh_token}

        try:
            response, scope_decision = client.post(
                refresh_url,
                headers=headers,
                json_data=payload,
            )
        except ScopeViolationError as e:
            raise AuthAdapterError(f"Refresh request blocked by ScopeGate: {e}")
        except Exception as e:
            raise AuthAdapterError(f"Refresh HTTP request failed: {e}")

        if response.status_code != 200:
            raise AuthAdapterError(f"Refresh endpoint returned HTTP {response.status_code}")

        try:
            data = response.json()
        except Exception:
            raise AuthAdapterError("Refresh endpoint returned non-JSON response")

        new_access_token = data.get("access_token") or data.get("token")
        if not new_access_token or not isinstance(new_access_token, str):
            raise AuthAdapterError("Refresh response missing valid 'access_token' string")

        expires_in = data.get("expires_in", 3600)
        import time
        new_expires_at = time.time() + float(expires_in)

        # Redact new token and store in vault
        clean_text = vault.redact_text(new_access_token)
        # Check if new refresh token is rotated
        new_refresh = data.get("refresh_token")
        new_refresh_ref = credential.refresh_token_ref
        if new_refresh and isinstance(new_refresh, str):
            new_refresh_ref = vault.redact_text(new_refresh)

        # Update record strictly preserving identity and target
        credential.lifecycle_state = CredentialLifecycleState.CRED_ACTIVE
        credential.expires_at = new_expires_at
        credential.refresh_token_ref = new_refresh_ref
        credential.last_transition_reason = "JWT_REFRESH_SUCCESS"
        self.reset_retries(credential.token_ref)
        return credential


class OAuthRefreshAdapter(AuthAdapter):
    """Executes standard OAuth2 token refresh grant (grant_type=refresh_token)."""

    def refresh(
        self,
        credential: CredentialRecord,
        vault: RedactionVault,
        client: ScopedHttpClient,
        config: Dict[str, Any],
    ) -> CredentialRecord:
        self._check_and_increment_retry(credential.token_ref)

        token_endpoint = config.get("token_endpoint")
        client_id = config.get("client_id")
        if not token_endpoint or not client_id:
            raise UnsupportedAuthFlowError("OAuthRefreshAdapter requires 'token_endpoint' and 'client_id'")

        if not credential.refresh_token_ref:
            raise UnsupportedAuthFlowError(f"No refresh_token_ref for {credential.token_ref}")

        try:
            vault_ctx = VaultAccessContext(
                actor=credential.identity_id or "auth_adapter",
                purpose=VaultReversalPurpose.CREDENTIAL_ROTATION,
                justification="OAuth refresh token execution",
            )
            raw_refresh_token = vault.reverse_placeholder(credential.refresh_token_ref, context=vault_ctx)
        except Exception as e:
            raise AuthAdapterError(f"Vault authorization failed: {e}")
        if not raw_refresh_token:
            raise AuthAdapterError("OAuth refresh token placeholder missing from vault")

        body_data = {
            "grant_type": "refresh_token",
            "refresh_token": raw_refresh_token,
            "client_id": client_id,
        }
        client_secret_ref = config.get("client_secret_ref")
        if client_secret_ref:
            try:
                secret_ctx = VaultAccessContext(
                    actor=credential.identity_id or "auth_adapter",
                    purpose=VaultReversalPurpose.CREDENTIAL_ROTATION,
                    justification="OAuth client secret lookup",
                )
                raw_secret = vault.reverse_placeholder(client_secret_ref, context=secret_ctx)
            except Exception:
                raw_secret = None
            if raw_secret:
                body_data["client_secret"] = raw_secret

        try:
            response, scope_decision = client.post(
                token_endpoint,
                data=body_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        except Exception as e:
            raise AuthAdapterError(f"OAuth refresh request failed: {e}")

        if response.status_code != 200:
            raise AuthAdapterError(f"OAuth refresh failed with status {response.status_code}")

        try:
            data = response.json()
        except Exception:
            raise AuthAdapterError("OAuth token endpoint returned invalid JSON")

        new_token = data.get("access_token")
        if not new_token:
            raise AuthAdapterError("OAuth token response missing access_token")

        expires_in = data.get("expires_in", 3600)
        import time
        new_expires_at = time.time() + float(expires_in)

        clean_placeholder = vault.redact_text(new_token)
        new_refresh = data.get("refresh_token")
        new_refresh_ref = credential.refresh_token_ref
        if new_refresh:
            new_refresh_ref = vault.redact_text(new_refresh)

        credential.lifecycle_state = CredentialLifecycleState.CRED_ACTIVE
        credential.expires_at = new_expires_at
        credential.refresh_token_ref = new_refresh_ref
        credential.last_transition_reason = "OAUTH_REFRESH_SUCCESS"
        self.reset_retries(credential.token_ref)
        return credential


class CookieSessionAdapter(AuthAdapter):
    """Re-authenticates cookie session via explicitly configured credentials."""

    def refresh(
        self,
        credential: CredentialRecord,
        vault: RedactionVault,
        client: ScopedHttpClient,
        config: Dict[str, Any],
    ) -> CredentialRecord:
        self._check_and_increment_retry(credential.token_ref)

        login_url = config.get("login_url")
        username = config.get("username")
        password_ref = config.get("password_ref")

        if not login_url or not username or not password_ref:
            raise UnsupportedAuthFlowError("CookieSessionAdapter requires login_url, username, and password_ref")

        try:
            vault_ctx = VaultAccessContext(
                actor=username or "auth_adapter",
                purpose=VaultReversalPurpose.CREDENTIAL_ROTATION,
                justification="Cookie session re-authentication",
            )
            raw_password = vault.reverse_placeholder(password_ref, context=vault_ctx)
        except Exception as e:
            raise AuthAdapterError(f"Vault authorization failed: {e}")
        if not raw_password:
            raise AuthAdapterError(f"Password placeholder {password_ref} not found in vault")

        login_payload = {"username": username, "password": raw_password}

        try:
            response, scope_decision = client.post(
                login_url,
                json_data=login_payload,
            )
        except Exception as e:
            raise AuthAdapterError(f"Session re-authentication failed: {e}")

        if response.status_code not in (200, 204, 302):
            raise AuthAdapterError(f"Session login returned HTTP {response.status_code}")

        # Validate that cookies were received
        set_cookie = response.headers.get("set-cookie")
        if not set_cookie:
            raise AuthAdapterError("Session login response contained no Set-Cookie header")

        import time
        credential.lifecycle_state = CredentialLifecycleState.CRED_ACTIVE
        credential.expires_at = time.time() + 3600
        credential.last_transition_reason = "SESSION_LOGIN_SUCCESS"
        self.reset_retries(credential.token_ref)
        return credential


class ReauthenticationAdapter(AuthAdapter):
    """Executes a declared multi-step re-authentication sequence."""

    def refresh(
        self,
        credential: CredentialRecord,
        vault: RedactionVault,
        client: ScopedHttpClient,
        config: Dict[str, Any],
    ) -> CredentialRecord:
        self._check_and_increment_retry(credential.token_ref)

        steps = config.get("steps")
        if not steps or not isinstance(steps, list):
            raise UnsupportedAuthFlowError("ReauthenticationAdapter requires explicit list of 'steps'")

        # Execute each step deterministically
        for idx, step in enumerate(steps):
            method = step.get("method", "POST").upper()
            url = step.get("url")
            if not url:
                raise UnsupportedAuthFlowError(f"Reauthentication step {idx} missing 'url'")

            payload = dict(step.get("payload", {}))
            # Resolve any password/secret references in payload
            for k, v in list(payload.items()):
                if isinstance(v, str) and v.startswith("[REDACTED_"):
                    try:
                        vault_ctx = VaultAccessContext(
                            actor=credential.identity_id or "auth_adapter",
                            purpose=VaultReversalPurpose.CREDENTIAL_ROTATION,
                            justification="Reauthentication payload substitution",
                        )
                        raw = vault.reverse_placeholder(v, context=vault_ctx)
                    except Exception:
                        raw = None
                    if raw:
                        payload[k] = raw

            try:
                response, _ = client.request(method=method, url=url, json_data=payload)
            except Exception as e:
                raise AuthAdapterError(f"Reauthentication step {idx} failed: {e}")

            expected_status = step.get("expected_status", 200)
            if response.status_code != expected_status:
                raise AuthAdapterError(
                    f"Reauthentication step {idx} returned {response.status_code} (expected {expected_status})"
                )

        import time
        credential.lifecycle_state = CredentialLifecycleState.CRED_ACTIVE
        credential.expires_at = time.time() + 3600
        credential.last_transition_reason = "REAUTHENTICATION_SUCCESS"
        self.reset_retries(credential.token_ref)
        return credential
