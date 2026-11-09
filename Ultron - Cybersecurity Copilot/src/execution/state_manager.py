"""Deterministic State Manager for Milestone M2.75.

Deployment Model: Single-Process, Multi-Threaded.
Concurrency Model: Thread-safe synchronized state authority using threading.RLock.
Guarantees atomic check-and-transition operations, eliminating TOCTOU races in:
- credential rotation and refresh
- CSRF token validation and single-use consumption
- session replacement
- anti-replay nonce tracking
- signing key lifecycle

Enforces strict ownership: cross-identity, cross-target, and cross-environment
credential substitution is immediately rejected.
"""

from datetime import datetime, timezone
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from src.core.logging import AuditLogger
from src.evidence.vault import RedactionVault
from src.execution.models import (
    CredentialLifecycleState,
    CsrfLifecycleState,
    SessionLifecycleState,
    SigningLifecycleState,
)
from src.execution.state import (
    CredentialRecord,
    CsrfRecord,
    SessionRecord,
    SigningKeyRecord,
)


class DeterministicStateManager:
    """Thread-safe state manager for credential, session, CSRF, and signing state."""

    def __init__(
        self,
        vault: Optional[RedactionVault] = None,
        audit_logger: Optional[AuditLogger] = None,
    ) -> None:
        self.vault = vault or RedactionVault()
        self.audit_logger = audit_logger
        self._lock = threading.RLock()

        # In-memory authoritative stores:
        # token_ref -> CredentialRecord
        self._credentials: Dict[str, CredentialRecord] = {}
        # session_id -> SessionRecord
        self._sessions: Dict[str, SessionRecord] = {}
        # token_ref -> CsrfRecord
        self._csrf_tokens: Dict[str, CsrfRecord] = {}
        # key_id -> SigningKeyRecord
        self._signing_keys: Dict[str, SigningKeyRecord] = {}
        # (profile_id, nonce) -> timestamp consumed
        self._consumed_nonces: Dict[Tuple[str, str], float] = {}

    def _log_audit(
        self,
        event_type: str,
        subject_id: str,
        previous_state: Optional[str] = None,
        new_state: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Helper to safely record an audit event without secrets."""
        if self.audit_logger:
            self.audit_logger.log_event(
                event_type=event_type,
                actor="DeterministicStateManager",
                subject_id=subject_id,
                previous_state=previous_state,
                new_state=new_state,
                details=details or {},
            )

    # -----------------------------------------------------------------------
    # Credential Lifecycle Management
    # -----------------------------------------------------------------------

    def register_credential(self, record: CredentialRecord) -> CredentialRecord:
        """Register a new credential record under lock."""
        with self._lock:
            self._credentials[record.token_ref] = record.model_copy()
            self._log_audit(
                event_type="CREDENTIAL_REGISTERED",
                subject_id=record.token_ref,
                new_state=record.lifecycle_state.value,
                details={
                    "identity_id": record.identity_id,
                    "target_authority": record.target_authority,
                    "environment_context": record.environment_context,
                    "credential_type": record.credential_type.value,
                    "expires_at": record.expires_at,
                },
            )
            return record

    def get_credential(self, token_ref: str) -> Optional[CredentialRecord]:
        """Retrieve a copy of credential record."""
        with self._lock:
            rec = self._credentials.get(token_ref)
            return rec.model_copy() if rec else None

    def transition_credential(
        self,
        token_ref: str,
        new_state: CredentialLifecycleState,
        reason: str,
        new_expires_at: Optional[float] = None,
        new_refresh_token_ref: Optional[str] = None,
    ) -> Optional[CredentialRecord]:
        """Atomically transition credential lifecycle state."""
        with self._lock:
            rec = self._credentials.get(token_ref)
            if not rec:
                return None

            old_state = rec.lifecycle_state.value
            rec.lifecycle_state = new_state
            rec.last_transition_reason = reason
            rec.updated_at = datetime.now(timezone.utc).timestamp()
            if new_expires_at is not None:
                rec.expires_at = new_expires_at
            if new_refresh_token_ref is not None:
                rec.refresh_token_ref = new_refresh_token_ref

            self._log_audit(
                event_type="CREDENTIAL_TRANSITION",
                subject_id=token_ref,
                previous_state=old_state,
                new_state=new_state.value,
                details={
                    "reason": reason,
                    "identity_id": rec.identity_id,
                    "target_authority": rec.target_authority,
                },
            )
            return rec.model_copy()

    def validate_credential_ownership(
        self,
        token_ref: str,
        expected_identity_id: str,
        expected_target_authority: Optional[str] = None,
        expected_environment_context: Optional[str] = None,
    ) -> Tuple[bool, Optional[str], Optional[CredentialRecord]]:
        """Validate that a token exists and is bound to the expected identity, target, and environment."""
        with self._lock:
            rec = self._credentials.get(token_ref)
            if not rec:
                return False, "TOKEN_REFERENCE_NOT_FOUND", None

            # 1. Identity binding
            if rec.identity_id.lower().strip() != expected_identity_id.lower().strip():
                self._log_audit(
                    event_type="CROSS_IDENTITY_CREDENTIAL_REJECTED",
                    subject_id=token_ref,
                    details={
                        "token_owner": rec.identity_id,
                        "attempted_user": expected_identity_id,
                    },
                )
                return False, "CROSS_IDENTITY_SUBSTITUTION_BLOCKED", rec.model_copy()

            # 2. Target authority binding
            if expected_target_authority:
                if rec.target_authority.lower().strip() != expected_target_authority.lower().strip():
                    self._log_audit(
                        event_type="CROSS_TARGET_CREDENTIAL_REJECTED",
                        subject_id=token_ref,
                        details={
                            "token_target": rec.target_authority,
                            "attempted_target": expected_target_authority,
                        },
                    )
                    return False, "CROSS_TARGET_SUBSTITUTION_BLOCKED", rec.model_copy()

            # 3. Environment context binding
            if expected_environment_context:
                if rec.environment_context.lower().strip() != expected_environment_context.lower().strip():
                    return False, "CROSS_ENVIRONMENT_SUBSTITUTION_BLOCKED", rec.model_copy()

            return True, None, rec.model_copy()

    # -----------------------------------------------------------------------
    # Session Lifecycle Management
    # -----------------------------------------------------------------------

    def register_session(self, record: SessionRecord) -> SessionRecord:
        with self._lock:
            self._sessions[record.session_id] = record.model_copy()
            self._log_audit(
                event_type="SESSION_REGISTERED",
                subject_id=record.session_id,
                new_state=record.lifecycle_state.value,
                details={
                    "identity_id": record.identity_id,
                    "target_authority": record.target_authority,
                },
            )
            return record

    def get_session(self, session_id: str) -> Optional[SessionRecord]:
        with self._lock:
            s = self._sessions.get(session_id)
            return s.model_copy() if s else None

    def replace_session(
        self,
        old_session_id: str,
        new_record: SessionRecord,
        reason: str,
    ) -> bool:
        """Atomically terminate old session and activate new session."""
        with self._lock:
            old_s = self._sessions.get(old_session_id)
            if old_s:
                old_s.lifecycle_state = SessionLifecycleState.SESS_TERMINATED
                old_s.last_transition_reason = f"REPLACED_BY_{new_record.session_id}: {reason}"
                old_s.updated_at = datetime.now(timezone.utc).timestamp()

            self._sessions[new_record.session_id] = new_record.model_copy()
            self._log_audit(
                event_type="SESSION_REPLACED",
                subject_id=new_record.session_id,
                previous_state=old_session_id if old_s else "NONE",
                new_state=new_record.session_id,
                details={"reason": reason, "identity_id": new_record.identity_id},
            )
            return True

    # -----------------------------------------------------------------------
    # CSRF & Anti-Replay Nonce Lifecycle Management (Section 10 & 13)
    # -----------------------------------------------------------------------

    def register_csrf(self, record: CsrfRecord) -> CsrfRecord:
        with self._lock:
            self._csrf_tokens[record.token_ref] = record.model_copy()
            self._log_audit(
                event_type="CSRF_REGISTERED",
                subject_id=record.token_ref,
                new_state=record.lifecycle_state.value,
                details={
                    "identity_id": record.identity_id,
                    "session_id": record.session_id,
                    "target_authority": record.target_authority,
                },
            )
            return record

    def consume_csrf_token(
        self,
        token_ref: str,
        expected_identity_id: str,
        expected_session_id: Optional[str] = None,
        expected_target_authority: Optional[str] = None,
    ) -> Tuple[bool, Optional[str], Optional[CsrfRecord]]:
        """Atomically validate ownership, freshness, and single-use status, then mark CONSUMED."""
        with self._lock:
            rec = self._csrf_tokens.get(token_ref)
            if not rec:
                return False, "CSRF_TOKEN_NOT_FOUND", None

            # 1. Identity binding check
            if rec.identity_id.lower().strip() != expected_identity_id.lower().strip():
                self._log_audit(
                    event_type="CROSS_IDENTITY_CSRF_REJECTED",
                    subject_id=token_ref,
                    details={
                        "csrf_owner": rec.identity_id,
                        "attempted_user": expected_identity_id,
                    },
                )
                return False, "CROSS_IDENTITY_CSRF_BLOCKED", rec.model_copy()

            # 2. Session binding check
            if expected_session_id and rec.session_id:
                if rec.session_id != expected_session_id:
                    self._log_audit(
                        event_type="CROSS_SESSION_CSRF_REJECTED",
                        subject_id=token_ref,
                        details={
                            "csrf_session": rec.session_id,
                            "attempted_session": expected_session_id,
                        },
                    )
                    return False, "CROSS_SESSION_CSRF_BLOCKED", rec.model_copy()

            # 3. Target authority check
            if expected_target_authority:
                if rec.target_authority.lower().strip() != expected_target_authority.lower().strip():
                    return False, "CROSS_TARGET_CSRF_BLOCKED", rec.model_copy()

            # 4. Check already consumed (Replay Protection)
            if rec.consumed or rec.lifecycle_state == CsrfLifecycleState.CSRF_CONSUMED:
                self._log_audit(
                    event_type="CSRF_REPLAY_REJECTED",
                    subject_id=token_ref,
                    details={"identity_id": expected_identity_id},
                )
                return False, "CSRF_ALREADY_CONSUMED", rec.model_copy()

            # 5. Check expiry
            if rec.is_expired():
                rec.lifecycle_state = CsrfLifecycleState.CSRF_EXPIRED
                return False, "CSRF_TOKEN_EXPIRED", rec.model_copy()

            # 6. Check validity
            if rec.lifecycle_state != CsrfLifecycleState.CSRF_VALID:
                return False, f"CSRF_INVALID_STATE_{rec.lifecycle_state.value}", rec.model_copy()

            # Atomic consumption
            rec.consumed = True
            rec.lifecycle_state = CsrfLifecycleState.CSRF_CONSUMED
            self._log_audit(
                event_type="CSRF_CONSUMED",
                subject_id=token_ref,
                previous_state=CsrfLifecycleState.CSRF_VALID.value,
                new_state=CsrfLifecycleState.CSRF_CONSUMED.value,
                details={"identity_id": expected_identity_id},
            )
            return True, None, rec.model_copy()

    def rotate_csrf_token(
        self,
        old_token_ref: str,
        new_record: CsrfRecord,
    ) -> bool:
        """Atomically transition old token to ROTATED and register new token."""
        with self._lock:
            old_rec = self._csrf_tokens.get(old_token_ref)
            if old_rec:
                old_rec.lifecycle_state = CsrfLifecycleState.CSRF_ROTATED
                old_rec.consumed = True

            self._csrf_tokens[new_record.token_ref] = new_record.model_copy()
            self._log_audit(
                event_type="CSRF_ROTATED",
                subject_id=new_record.token_ref,
                previous_state=old_token_ref,
                new_state=new_record.token_ref,
                details={"identity_id": new_record.identity_id},
            )
            return True

    # -----------------------------------------------------------------------
    # Request Signing Key & Nonce Management (Section 11 & 12)
    # -----------------------------------------------------------------------

    def register_signing_key(self, record: SigningKeyRecord) -> SigningKeyRecord:
        with self._lock:
            self._signing_keys[record.key_id] = record.model_copy()
            self._log_audit(
                event_type="SIGNING_KEY_REGISTERED",
                subject_id=record.key_id,
                new_state=record.lifecycle_state.value,
                details={
                    "identity_id": record.identity_id,
                    "target_authority": record.target_authority,
                    "algorithm": record.algorithm,
                },
            )
            return record

    def get_signing_key(self, key_id: str) -> Optional[SigningKeyRecord]:
        with self._lock:
            k = self._signing_keys.get(key_id)
            return k.model_copy() if k else None

    def consume_signing_nonce(self, profile_id: str, nonce: str) -> Tuple[bool, Optional[str]]:
        """Atomically verify and consume an anti-replay nonce."""
        with self._lock:
            key = (profile_id, nonce)
            if key in self._consumed_nonces:
                self._log_audit(
                    event_type="NONCE_REPLAY_REJECTED",
                    subject_id=nonce,
                    details={"profile_id": profile_id},
                )
                return False, "SIGNING_NONCE_REPLAYED"

            self._consumed_nonces[key] = time.time()
            return True, None
