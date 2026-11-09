"""Milestone M2.75: Deterministic State and Execution Engine.

Exports authoritative state management, TTL freshness validation, authentication adapters,
CSRF/nonce lifecycle tracking, dynamic request signing, human approval binding,
and controlled execution engine.
"""

from src.execution.approval import ApprovalGate
from src.execution.auth_adapters import (
    AuthAdapter,
    AuthAdapterError,
    CookieSessionAdapter,
    JwtRefreshAdapter,
    OAuthRefreshAdapter,
    ReauthenticationAdapter,
    RetryExhaustionError,
    UnsupportedAuthFlowError,
)
from src.execution.csrf import CsrfManager
from src.execution.engine import DeterministicExecutionEngine
from src.execution.models import (
    CredentialLifecycleState,
    CredentialType,
    CsrfLifecycleState,
    ExecutionDescriptor,
    ExecutionResult,
    ExecutionStatus,
    HumanApproval,
    SessionLifecycleState,
    SigningLifecycleState,
    SigningProfile,
)
from src.execution.scrubber import scrub_exception_text
from src.execution.signing import (
    ExpiredSigningTimestampError,
    HmacRequestSigner,
    ReplayedSigningNonceError,
    RequestSigner,
    RequestSigningError,
    UnsupportedSigningFlowError,
)
from src.execution.state import (
    CredentialRecord,
    CsrfRecord,
    SessionRecord,
    SigningKeyRecord,
)
from src.execution.state_manager import DeterministicStateManager
from src.execution.ttl_validator import DeterministicTTLValidator

__all__ = [
    # Models & Enums
    "CredentialLifecycleState",
    "SessionLifecycleState",
    "CsrfLifecycleState",
    "SigningLifecycleState",
    "CredentialType",
    "ExecutionStatus",
    "ExecutionDescriptor",
    "HumanApproval",
    "SigningProfile",
    "ExecutionResult",
    # State Records
    "CredentialRecord",
    "SessionRecord",
    "CsrfRecord",
    "SigningKeyRecord",
    # Managers & Engines
    "DeterministicStateManager",
    "ApprovalGate",
    "CsrfManager",
    "DeterministicTTLValidator",
    "RequestSigner",
    "HmacRequestSigner",
    "DeterministicExecutionEngine",
    # Adapters
    "AuthAdapter",
    "JwtRefreshAdapter",
    "OAuthRefreshAdapter",
    "CookieSessionAdapter",
    "ReauthenticationAdapter",
    # Exceptions
    "AuthAdapterError",
    "UnsupportedAuthFlowError",
    "RetryExhaustionError",
    "RequestSigningError",
    "UnsupportedSigningFlowError",
    "ExpiredSigningTimestampError",
    "ReplayedSigningNonceError",
    # Utilities
    "scrub_exception_text",
]
