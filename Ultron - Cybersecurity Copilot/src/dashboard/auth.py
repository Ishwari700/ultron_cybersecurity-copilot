"""Authentication, Credential Verification, and Session Management Authority.

Implements Batch 1.1 requirements:
- Cryptographically secure password hashing (scrypt with 16-byte random salt)
- Constant-time password verification via secrets.compare_digest
- Server-authoritative role assignment from persistent DatabaseManager
- In-memory session tracking with expiry, revocation, and fresh issuance
- Login abuse mitigation and rate-limiting (sliding window per IP/identity)
- CSRF token generation and validation for cookie-authenticated sessions
- Safe administrator bootstrap from environment or CLI
"""

from datetime import datetime, timezone
from enum import Enum
import hashlib
import os
from pathlib import Path
import secrets
import time
from typing import Any, Dict, List, Optional
from pydantic import BaseModel

from src.core.logging import get_logger
from src.database.manager import DatabaseManager

logger = get_logger("DashboardAuth")


def hash_password(password: str) -> str:
    """Hash password using scrypt with unique cryptographically random salt."""
    if not password:
        raise ValueError("Password cannot be empty")
    salt = secrets.token_bytes(16)
    # Scrypt parameters: N=16384, r=8, p=1 (standard OWASP recommendation)
    derived = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=16384, r=8, p=1)
    return f"scrypt$16384$8$1${salt.hex()}${derived.hex()}"


def verify_password(password: str, encoded_hash: str) -> bool:
    """Verify password against scrypt hash in constant time."""
    if not password or not encoded_hash:
        return False
    try:
        parts = encoded_hash.split("$")
        if len(parts) != 6 or parts[0] != "scrypt":
            return False
        n = int(parts[1])
        r = int(parts[2])
        p = int(parts[3])
        salt = bytes.fromhex(parts[4])
        expected_key = bytes.fromhex(parts[5])
        computed_key = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p)
        return secrets.compare_digest(computed_key, expected_key)
    except Exception:
        return False


def generate_csrf_token() -> str:
    """Generate a high-entropy CSRF synchronizer token."""
    return secrets.token_hex(32)


def verify_csrf_token(token_a: Optional[str], token_b: Optional[str]) -> bool:
    """Compare two CSRF tokens in constant time."""
    if not token_a or not token_b:
        return False
    return secrets.compare_digest(token_a.strip(), token_b.strip())


class DashboardRole(str, Enum):
    OBSERVER = "observer"
    REVIEWER = "reviewer"
    OPERATOR = "operator"
    ADMIN = "admin"


class DashboardSession(BaseModel):
    token: str
    username: str
    role: DashboardRole
    expires_at: Optional[float] = None
    revoked: bool = False

    @property
    def user_id(self) -> str:
        return self.username


class DashboardAuthManager:
    """Authoritative local session and user authentication manager."""

    def __init__(self, db_manager: Optional[DatabaseManager] = None) -> None:
        self.db = db_manager or DatabaseManager()
        self._sessions: Dict[str, DashboardSession] = {}
        # Rate-limiting tracking: key (ip or username) -> list of failure timestamps
        self._failed_attempts: Dict[str, List[float]] = {}
        self.max_attempts = 5
        self.lockout_window_seconds = 60.0

        # Auto-provision initial administrator from environment if configured
        self._bootstrap_admin_from_env()

    def _bootstrap_admin_from_env(self) -> None:
        """Provision initial administrator if configured via environment and no users exist."""
        admin_user = os.environ.get("ULTRON_ADMIN_USERNAME", "").strip()
        admin_pass = os.environ.get("ULTRON_ADMIN_PASSWORD", "").strip()

        if admin_user and admin_pass:
            try:
                existing = self.db.get_user(admin_user)
                if not existing:
                    hashed = hash_password(admin_pass)
                    self.db.create_user(
                        username=admin_user,
                        password_hash=hashed,
                        role="admin",
                        is_active=True,
                    )
                    logger.info(f"SECURITY NOTICE: Initial administrator account '{admin_user}' provisioned from environment.")
                else:
                    # Do NOT overwrite existing credentials if user already exists
                    logger.debug(f"Administrator account '{admin_user}' already exists; bootstrap ignored.")
            except Exception as e:
                logger.error(f"Failed to bootstrap administrator account from environment: {e}")

    # -------------------------------------------------------------------------
    # Abuse Mitigation / Rate Limiting
    # -------------------------------------------------------------------------

    def check_rate_limit(self, key: str) -> bool:
        """Returns True if within rate limit, False if rate-limited (too many failures)."""
        clean_key = str(key).strip().lower()
        now = time.time()
        failures = self._failed_attempts.get(clean_key, [])
        # Purge failures outside the sliding window
        valid_failures = [t for t in failures if (now - t) < self.lockout_window_seconds]
        self._failed_attempts[clean_key] = valid_failures
        return len(valid_failures) < self.max_attempts

    def record_failure(self, key: str) -> None:
        """Record an authentication failure for rate limiting."""
        clean_key = str(key).strip().lower()
        now = time.time()
        failures = self._failed_attempts.get(clean_key, [])
        valid_failures = [t for t in failures if (now - t) < self.lockout_window_seconds]
        valid_failures.append(now)
        self._failed_attempts[clean_key] = valid_failures

    def record_success(self, key: str) -> None:
        """Reset rate-limit tracking upon successful authentication."""
        clean_key = str(key).strip().lower()
        if clean_key in self._failed_attempts:
            del self._failed_attempts[clean_key]

    # -------------------------------------------------------------------------
    # Credential Verification & Session Issuance
    # -------------------------------------------------------------------------

    def authenticate_credentials(self, username: str, password: str) -> Optional[DashboardSession]:
        """
        Verify submitted username and password against persistent DatabaseManager.
        Role is authoritatively derived from the stored record.
        Returns a newly issued DashboardSession if valid, None otherwise.
        """
        if not username or not password:
            return None

        clean_user = username.strip().lower()
        user_record = self.db.get_user(clean_user)
        if not user_record:
            return None

        if not user_record.get("is_active", False):
            logger.warning(f"SECURITY NOTICE: Login rejected for disabled account '{clean_user}'.")
            return None

        pw_hash = user_record.get("password_hash", "")
        if not verify_password(password, pw_hash):
            return None

        # Authoritatively assign role from database
        stored_role_str = str(user_record.get("role", "reviewer")).lower()
        try:
            authoritative_role = DashboardRole(stored_role_str)
        except ValueError:
            authoritative_role = DashboardRole.REVIEWER

        # Issue fresh session
        return self.create_session(
            username=user_record["username"],
            role=authoritative_role,
            ttl_seconds=86400.0,
        )

    def create_session(
        self,
        username: str,
        role: DashboardRole,
        token: Optional[str] = None,
        ttl_seconds: Optional[float] = None,
    ) -> DashboardSession:
        """Issue an opaque high-entropy session token."""
        tok = token or secrets.token_urlsafe(32)
        exp = time.time() + ttl_seconds if ttl_seconds is not None else None
        sess = DashboardSession(
            token=tok,
            username=username,
            role=role,
            expires_at=exp,
            revoked=False,
        )
        self._sessions[tok] = sess
        return sess

    def revoke_session(self, token: str) -> bool:
        """Revoke a session immediately server-side."""
        if token in self._sessions:
            self._sessions[token].revoked = True
            return True
        return False

    def authenticate(self, token: Optional[str]) -> Optional[DashboardSession]:
        """Validate an existing session token."""
        if not token:
            return None
        sess = self._sessions.get(token)
        if not sess:
            return None
        if sess.revoked:
            return None
        if sess.expires_at is not None and time.time() > sess.expires_at:
            return None
        return sess

    def user_count(self) -> int:
        """Return total number of users in the persistent database."""
        return self.db.user_count()
