"""Milestone M2.75: Deterministic State and Execution Engine Models.

Defines:
- Distinct lifecycle state enums for credentials, sessions, CSRF tokens, and signing keys,
  guaranteeing ZERO collision with hypothesis, evidence, or vulnerability taxonomy enums.
- ExecutionStatus taxonomy distinguishing all deterministic blocked states.
- Canonical ExecutionDescriptor and HumanApproval binding models.
- ExecutionResult and SigningProfile definitions.
"""

from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# 1. State & Lifecycle Namespaces (Isolated from Vulnerability Taxonomy)
# ---------------------------------------------------------------------------

class CredentialLifecycleState(str, Enum):
    """Lifecycle states for credentials and tokens."""
    CRED_DISCOVERED = "CRED_DISCOVERED"
    CRED_ACTIVE = "CRED_ACTIVE"
    CRED_EXPIRING = "CRED_EXPIRING"
    CRED_EXPIRED = "CRED_EXPIRED"
    CRED_ROTATED = "CRED_ROTATED"
    CRED_REVOKED = "CRED_REVOKED"
    CRED_INVALID = "CRED_INVALID"


class SessionLifecycleState(str, Enum):
    """Lifecycle states for cookie-backed sessions."""
    SESS_ACTIVE = "SESS_ACTIVE"
    SESS_EXPIRED = "SESS_EXPIRED"
    SESS_TERMINATED = "SESS_TERMINATED"
    SESS_INVALID = "SESS_INVALID"


class CsrfLifecycleState(str, Enum):
    """Lifecycle states for CSRF tokens and anti-replay nonces."""
    CSRF_DISCOVERED = "CSRF_DISCOVERED"
    CSRF_VALID = "CSRF_VALID"
    CSRF_CONSUMED = "CSRF_CONSUMED"
    CSRF_ROTATED = "CSRF_ROTATED"
    CSRF_EXPIRED = "CSRF_EXPIRED"
    CSRF_INVALID = "CSRF_INVALID"


class SigningLifecycleState(str, Enum):
    """Lifecycle states for request signing keys."""
    SIGN_KEY_ACTIVE = "SIGN_KEY_ACTIVE"
    SIGN_KEY_ROTATED = "SIGN_KEY_ROTATED"
    SIGN_KEY_EXPIRED = "SIGN_KEY_EXPIRED"
    SIGN_KEY_REVOKED = "SIGN_KEY_REVOKED"


class CredentialType(str, Enum):
    """Supported credential protocols."""
    BEARER_JWT = "BEARER_JWT"
    COOKIE_SESSION = "COOKIE_SESSION"
    OAUTH_TOKEN = "OAUTH_TOKEN"
    API_KEY = "API_KEY"
    BASIC_AUTH = "BASIC_AUTH"


# ---------------------------------------------------------------------------
# 2. Execution Status Taxonomy (Section 17)
# ---------------------------------------------------------------------------

class ExecutionStatus(str, Enum):
    """Deterministic execution result statuses.

    Must NOT be overloaded with hypothesis states or vulnerability verdicts.
    """
    EXECUTED = "EXECUTED"
    BLOCKED_SCOPE = "BLOCKED_SCOPE"
    BLOCKED_SAFETY = "BLOCKED_SAFETY"
    BLOCKED_APPROVAL = "BLOCKED_APPROVAL"
    BLOCKED_AUTH_STATE = "BLOCKED_AUTH_STATE"
    BLOCKED_TTL = "BLOCKED_TTL"
    BLOCKED_CSRF = "BLOCKED_CSRF"
    BLOCKED_RATE_LIMIT = "BLOCKED_RATE_LIMIT"
    UNSUPPORTED_AUTH_FLOW = "UNSUPPORTED_AUTH_FLOW"
    UNSUPPORTED_SIGNING_FLOW = "UNSUPPORTED_SIGNING_FLOW"
    BLOCKED_EXECUTION_MODE = "BLOCKED_EXECUTION_MODE"
    EXECUTION_ERROR = "EXECUTION_ERROR"


# ---------------------------------------------------------------------------
# 3. Canonical Execution Descriptor & Human Approval (Section 11 & 15)
# ---------------------------------------------------------------------------

class ExecutionDescriptor(BaseModel):
    """Immutable execution descriptor capturing complete security context.

    Recomputed immediately prior to transmission to guarantee zero TOCTOU tampering.
    """
    experiment_id: str
    identity_id: str
    environment_context: str = "staging"  # e.g., 'staging', 'test', 'sandbox'
    target_authority: str                 # e.g., 'api.target.com'
    destination: str                      # Fully qualified URL
    resolved_ip: Optional[str] = None     # Pinned IP address
    http_method: str                      # Uppercase: GET, POST, etc.
    normalized_route: str                 # E.g., /api/v1/orders/{id}
    normalized_query: str = ""            # Canonical sorted query string
    headers_digest: str = ""              # SHA-256 hex digest of non-secret/placeholder headers
    request_body_digest: str              # SHA-256 hex digest of raw request body
    safety_classification: str            # READ_ONLY_SAFE, STATE_CHANGING_REQUIRES_APPROVAL, etc.
    affected_resource: str                # Identifier of affected resource
    expected_state_transition: str        # Description of expected state change

    def compute_digest(self) -> str:
        """Compute authoritative SHA-256 cryptographic digest of this descriptor."""
        data = {
            "experiment_id": self.experiment_id,
            "identity_id": self.identity_id,
            "environment_context": self.environment_context,
            "target_authority": self.target_authority.lower().strip(),
            "destination": self.destination.strip(),
            "resolved_ip": self.resolved_ip or "",
            "http_method": self.http_method.upper().strip(),
            "normalized_route": self.normalized_route.strip(),
            "normalized_query": self.normalized_query.strip(),
            "headers_digest": self.headers_digest.strip(),
            "request_body_digest": self.request_body_digest.strip(),
            "safety_classification": self.safety_classification.strip(),
            "affected_resource": self.affected_resource.strip(),
            "expected_state_transition": self.expected_state_transition.strip(),
        }
        canonical_bytes = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(canonical_bytes).hexdigest()


class HumanApproval(BaseModel):
    """Explicit human approval bound to an immutable execution descriptor digest."""
    approval_id: str
    experiment_id: str
    approved_descriptor_digest: str
    actor: str
    granted_at: float = Field(default_factory=lambda: datetime.now(timezone.utc).timestamp())
    expires_at: Optional[float] = None
    notes: Optional[str] = None

    def is_valid(self, current_time: Optional[float] = None) -> bool:
        """Check if approval is current and not expired."""
        now = current_time if current_time is not None else datetime.now(timezone.utc).timestamp()
        if self.expires_at is not None and now >= self.expires_at:
            return False
        return True


# ---------------------------------------------------------------------------
# 4. Request Signing Profile (Section 12)
# ---------------------------------------------------------------------------

class SigningProfile(BaseModel):
    """Explicitly configured request signing profile.

    Unsupported signing configurations fail closed with UNSUPPORTED_SIGNING_FLOW.
    """
    profile_id: str
    algorithm: str = "HMAC-SHA256"
    canonicalization_version: str = "v1"
    signed_components: List[str] = Field(
        default_factory=lambda: ["method", "route", "query", "body", "timestamp", "nonce"]
    )
    timestamp_header: str = "X-Signature-Timestamp"
    signature_header: str = "X-Signature"
    nonce_header: str = "X-Signature-Nonce"
    timestamp_window_seconds: int = 300
    identity_id: str
    target_authority: str
    environment_context: str = "staging"


# ---------------------------------------------------------------------------
# 5. Execution Result (Section 17 & 19)
# ---------------------------------------------------------------------------

class ExecutionResult(BaseModel):
    """Result of a controlled experiment execution through M2.75.

    Always emits OBSERVATION evidence; NEVER directly emits VULNERABILITY_CONFIRMED.
    """
    experiment_id: str
    status: ExecutionStatus
    status_code: Optional[int] = None
    response_headers: Dict[str, str] = Field(default_factory=dict)
    response_body_redacted: Optional[str] = None
    scope_decision_id: Optional[str] = None
    latency_seconds: float = 0.0
    audit_record_hash: Optional[str] = None
    error_message: Optional[str] = None
    observation_record: Optional[Dict[str, Any]] = None
    descriptor_digest: Optional[str] = None
