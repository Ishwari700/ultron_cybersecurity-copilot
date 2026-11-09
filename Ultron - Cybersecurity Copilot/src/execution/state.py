"""State record models for M2.75 deterministic state engine.

All secret values are strictly referenced by typed placeholders / references;
raw credentials, cookies, tokens, and keys MUST NEVER be placed in state records.
"""

from datetime import datetime, timezone
import time
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field

from src.execution.models import (
    CredentialLifecycleState,
    CredentialType,
    CsrfLifecycleState,
    SessionLifecycleState,
    SigningLifecycleState,
)


class CredentialRecord(BaseModel):
    """Deterministic record tracking a credential or token lifecycle."""
    token_ref: str                              # Typed placeholder e.g. [REDACTED_JWT_1]
    identity_id: str                            # Owner identity e.g. 'user_a'
    session_id: Optional[str] = None            # Associated session if applicable
    target_authority: str                       # e.g. 'api.target.com'
    environment_context: str = "staging"        # e.g. 'staging', 'production'
    credential_type: CredentialType             # Protocol type
    lifecycle_state: CredentialLifecycleState = CredentialLifecycleState.CRED_ACTIVE
    expires_at: Optional[float] = None          # Unix epoch seconds
    refresh_token_ref: Optional[str] = None     # Reference to refresh token if available
    last_transition_reason: str = "INITIAL_REGISTRATION"
    created_at: float = Field(default_factory=lambda: datetime.now(timezone.utc).timestamp())
    updated_at: float = Field(default_factory=lambda: datetime.now(timezone.utc).timestamp())
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def is_expired(self, clock_skew_seconds: int = 30) -> bool:
        """Check if credential is expired with clock skew safety margin."""
        if self.expires_at is None:
            return False
        return (time.time() + clock_skew_seconds) >= self.expires_at

    def is_usable(self, clock_skew_seconds: int = 30) -> bool:
        """Check if credential is active and not expired."""
        if self.lifecycle_state != CredentialLifecycleState.CRED_ACTIVE:
            return False
        return not self.is_expired(clock_skew_seconds=clock_skew_seconds)


class SessionRecord(BaseModel):
    """Deterministic record tracking a cookie-backed session.

    Never stores raw cookies; stores only cookie name -> token_ref mappings.
    """
    session_id: str
    identity_id: str
    target_authority: str
    environment_context: str = "staging"
    cookie_refs: Dict[str, str] = Field(default_factory=dict)  # cookie_name -> token_ref
    lifecycle_state: SessionLifecycleState = SessionLifecycleState.SESS_ACTIVE
    expires_at: Optional[float] = None
    last_transition_reason: str = "INITIAL_SESSION_CREATION"
    created_at: float = Field(default_factory=lambda: datetime.now(timezone.utc).timestamp())
    updated_at: float = Field(default_factory=lambda: datetime.now(timezone.utc).timestamp())

    def is_expired(self, clock_skew_seconds: int = 30) -> bool:
        if self.expires_at is None:
            return False
        return (time.time() + clock_skew_seconds) >= self.expires_at

    def is_usable(self, clock_skew_seconds: int = 30) -> bool:
        if self.lifecycle_state != SessionLifecycleState.SESS_ACTIVE:
            return False
        return not self.is_expired(clock_skew_seconds=clock_skew_seconds)


class CsrfRecord(BaseModel):
    """Deterministic record tracking a CSRF token or anti-replay nonce."""
    token_ref: str                              # Typed placeholder or reference
    identity_id: str                            # Bound identity
    session_id: Optional[str] = None            # Bound session
    target_authority: str                       # Bound target authority
    header_name: str = "X-CSRF-Token"           # Header to inject
    lifecycle_state: CsrfLifecycleState = CsrfLifecycleState.CSRF_VALID
    consumed: bool = False
    expires_at: Optional[float] = None
    created_at: float = Field(default_factory=lambda: datetime.now(timezone.utc).timestamp())

    def is_expired(self, clock_skew_seconds: int = 0) -> bool:
        if self.expires_at is None:
            return False
        return (time.time() + clock_skew_seconds) >= self.expires_at

    def is_usable(self) -> bool:
        return (
            self.lifecycle_state == CsrfLifecycleState.CSRF_VALID
            and not self.consumed
            and not self.is_expired()
        )


class SigningKeyRecord(BaseModel):
    """Deterministic record tracking a request signing key."""
    key_id: str
    identity_id: str
    target_authority: str
    environment_context: str = "staging"
    algorithm: str = "HMAC-SHA256"
    secret_ref: str                             # Vault reference, NEVER raw key
    lifecycle_state: SigningLifecycleState = SigningLifecycleState.SIGN_KEY_ACTIVE
    created_at: float = Field(default_factory=lambda: datetime.now(timezone.utc).timestamp())

    def is_usable(self) -> bool:
        return self.lifecycle_state == SigningLifecycleState.SIGN_KEY_ACTIVE
