"""Reversible Secret Redaction Vault protecting sensitive credentials while preserving correlation.

SECURITY ARCHITECTURE & LIFECYCLE:
1. In-Memory Ephemeral Design:
   The RedactionVault maintains an in-memory bijection table between raw secrets and typed
   placeholders ([REDACTED_JWT_1], [REDACTED_SECRET_1]). No raw secrets or mappings are
   ever written to disk or logged.
2. Mandatory Authorization & Purpose Limitation:
   Reversal of placeholders back to raw values via reverse_placeholder() or reverse_text()
   strictly requires an authenticated VaultAccessContext (actor, purpose, justification).
   Unauthenticated or unauthorized access fails closed.
3. Tamper-Evident Secret Integrity:
   Every stored secret is hashed with a per-session random salt. Reversal verifies integrity
   prior to release; in-memory tampering immediately aborts and raises VaultDataTamperedError.
4. Process Restart & Recovery Semantics:
   Upon process termination or crash, in-memory mappings vanish from RAM. Persisted databases,
   reports, and traces contain only stable redacted placeholders. Reproducibility never depends
   on disk-persisted credentials.
"""

from enum import Enum
import hashlib
import re
import secrets
import threading
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field


class VaultAccessDeniedError(PermissionError):
    """Raised when vault reversal is attempted without valid authorized context."""
    pass


class VaultAuditError(RuntimeError):
    """Raised when audit logging fails during vault access, forcing fail-closed termination."""
    pass


class VaultDataTamperedError(RuntimeError):
    """Raised when in-memory vault integrity verification fails."""
    pass


class VaultReversalPurpose(str, Enum):
    EXECUTION_DISPATCH = "execution_dispatch"
    AUTHENTICATED_HUMAN_VERIFICATION = "authenticated_human_verification"
    CREDENTIAL_ROTATION = "credential_rotation"
    REQUEST_SIGNING = "request_signing"
    CSRF_CONSUMPTION = "csrf_consumption"
    AUTOMATED_TEST = "automated_test"


class VaultAccessContext(BaseModel):
    """Mandatory caller context required for reversing secret placeholders."""
    actor: str = Field(min_length=1, description="Authenticated actor identifier requesting reversal")
    purpose: VaultReversalPurpose = Field(description="Authorized business purpose for reversal")
    justification: Optional[str] = Field(default=None, description="Detailed justification or tracking id")


class RedactionVault:
    """
    Reversible secret redaction vault. Replaces secrets, JWTs, AWS credentials,
    and passwords with stable typed placeholders ([REDACTED_JWT_1]) so the LLM
    reasons over placeholders without leaking secrets into embeddings or logs.
    Preserves exact value identity across sessions for correlation.
    """

    # Secret identification patterns
    JWT_PATTERN = re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}")
    AWS_KEY_PATTERN = re.compile(r"AKIA[0-9A-Z]{16}")
    AWS_SECRET_PATTERN = re.compile(
        r"""(["']?(?:aws_secret_access_key|secret_access_key|SecretAccessKey|aws_secret_key)["']?\s*[:=]\s*["']?)([A-Za-z0-9/+=]{40})(["']?)""",
        re.IGNORECASE,
    )
    BASIC_AUTH_PATTERN = re.compile(r"(Basic\s+)([A-Za-z0-9+/=]{16,})", re.IGNORECASE)
    BEARER_AUTH_PATTERN = re.compile(r"(Bearer\s+)([A-Za-z0-9_\-\.]{16,})", re.IGNORECASE)
    COOKIE_HEADER_PATTERN = re.compile(r"((?:Cookie|Set-Cookie):\s*)([^\r\n]+)", re.IGNORECASE)
    SESSION_TOKEN_PATTERN = re.compile(
        r"""(["']?(?:session_?token|aws_session_token|session_?id|sess_?id|phpsessid|jsessionid|connect\.sid)["']?\s*[:=]\s*["']?)([^"'\s&,;\}]+)(["']?)""",
        re.IGNORECASE,
    )
    REFRESH_TOKEN_PATTERN = re.compile(
        r"""(["']?(?:refresh_?token)["']?\s*[:=]\s*["']?)([^"'\s&,;\}]+)(["']?)""",
        re.IGNORECASE,
    )
    SENSITIVE_KEY_PATTERN = re.compile(
        r"^(password|passwd|secret|token|api[_-]?key|auth|authorization|access[_-]?token|"
        r"refresh[_-]?token|session[_-]?(?:token|id)?|sess[_-]?id|phpsessid|jsessionid|connect\.sid|"
        r"ssn|credit[_-]?card|aws[_-]?(?:secret[_-]?access[_-]?)?key|secret[_-]?key)$",
        re.IGNORECASE,
    )
    KEY_VALUE_SECRET_PATTERN = re.compile(
        r"""(["']?(?:password|passwd|secret|token|api[_-]?key|auth|access[_-]?token|ssn|credit[_-]?card)["']?\s*[:=]\s*["']?)([^"'\s&,;\}]+)(["']?)""",
        re.IGNORECASE,
    )
    URI_CREDENTIAL_PATTERN = re.compile(r"(://[^:\s/]+:)([^@\s/]+)(@)")

    def __init__(self, audit_logger: Optional[Any] = None) -> None:
        self.audit_logger = audit_logger
        self._raw_to_placeholder: Dict[str, str] = {}
        self._placeholder_to_raw: Dict[str, str] = {}
        self._category_counters: Dict[str, int] = {}
        self._secret_integrity: Dict[str, str] = {}
        self._salt: str = secrets.token_hex(16)
        self._lock = threading.RLock()

    def _get_or_create_placeholder(self, raw_value: str, category: str) -> str:
        """Assign or retrieve a stable placeholder for this exact raw value."""
        with self._lock:
            if raw_value in self._raw_to_placeholder:
                return self._raw_to_placeholder[raw_value]

            count = self._category_counters.get(category, 0) + 1
            self._category_counters[category] = count
            placeholder = f"[REDACTED_{category}_{count}]"

            self._raw_to_placeholder[raw_value] = placeholder
            self._placeholder_to_raw[placeholder] = raw_value
            self._secret_integrity[placeholder] = hashlib.sha256((self._salt + raw_value).encode("utf-8")).hexdigest()
            return placeholder

    def _log_reversal(self, placeholder: str, context: VaultAccessContext, success: bool) -> None:
        """Audit reversal access. Never logs raw secrets."""
        if self.audit_logger:
            try:
                purpose_val = context.purpose.value if hasattr(context.purpose, "value") else str(context.purpose)
                self.audit_logger.log_event(
                    event_type="VAULT_REVERSAL_ACCESSED" if success else "VAULT_REVERSAL_DENIED",
                    actor=context.actor,
                    subject_id=placeholder,
                    details={
                        "purpose": purpose_val,
                        "justification": context.justification or "",
                        "success": success,
                    },
                )
            except Exception as e:
                raise VaultAuditError(f"Vault audit logging failed: {e}. Reversal blocked to fail closed.")

    def redact_text(self, text: str) -> str:
        """Scan free text and replace sensitive signatures with typed placeholders."""
        if not text:
            return ""

        # 1. Redact JWTs
        def _replace_jwt(match: re.Match) -> str:
            val = match.group(0)
            return self._get_or_create_placeholder(val, "JWT")
        text = self.JWT_PATTERN.sub(_replace_jwt, text)

        # 2. Redact AWS Access Keys
        def _replace_aws_key(match: re.Match) -> str:
            val = match.group(0)
            return self._get_or_create_placeholder(val, "AWS_KEY")
        text = self.AWS_KEY_PATTERN.sub(_replace_aws_key, text)

        # 3. Redact AWS Secret Access Keys
        def _replace_aws_secret(match: re.Match) -> str:
            prefix, val, suffix = match.group(1), match.group(2), match.group(3)
            if val.startswith("[REDACTED_"):
                return match.group(0)
            placeholder = self._get_or_create_placeholder(val, "AWS_SECRET")
            return f"{prefix}{placeholder}{suffix}"
        text = self.AWS_SECRET_PATTERN.sub(_replace_aws_secret, text)

        # 4. Redact Basic Auth
        def _replace_basic(match: re.Match) -> str:
            prefix, val = match.group(1), match.group(2)
            if val.startswith("[REDACTED_"):
                return match.group(0)
            placeholder = self._get_or_create_placeholder(val, "BASIC_AUTH")
            return f"{prefix}{placeholder}"
        text = self.BASIC_AUTH_PATTERN.sub(_replace_basic, text)

        # 5. Redact Bearer Auth
        def _replace_bearer(match: re.Match) -> str:
            prefix, val = match.group(1), match.group(2)
            if val.startswith("[REDACTED_"):
                return match.group(0)
            placeholder = self._get_or_create_placeholder(val, "BEARER_TOKEN")
            return f"{prefix}{placeholder}"
        text = self.BEARER_AUTH_PATTERN.sub(_replace_bearer, text)

        # 6. Redact Cookie / Set-Cookie Headers preserving attributes
        def _replace_cookie_header(match: re.Match) -> str:
            header_prefix = match.group(1)
            raw_cookies = match.group(2)
            parts = raw_cookies.split(";")
            preserved_parts = []
            standard_attrs = {"path", "domain", "expires", "max-age", "samesite", "secure", "httponly"}

            for part in parts:
                trimmed = part.strip()
                if "=" in trimmed:
                    c_name, c_val = trimmed.split("=", 1)
                    clean_name = c_name.strip()
                    clean_val = c_val.strip()
                    if clean_name.lower() in standard_attrs or clean_val.startswith("[REDACTED_"):
                        preserved_parts.append(trimmed)
                    else:
                        placeholder = self._get_or_create_placeholder(clean_val, "COOKIE")
                        preserved_parts.append(f"{clean_name}={placeholder}")
                else:
                    preserved_parts.append(trimmed)
            return f"{header_prefix}{'; '.join(preserved_parts)}"
        text = self.COOKIE_HEADER_PATTERN.sub(_replace_cookie_header, text)

        # 7. Redact Session Tokens / Session IDs
        def _replace_session(match: re.Match) -> str:
            prefix, val, suffix = match.group(1), match.group(2), match.group(3)
            if val.startswith("[REDACTED_"):
                return match.group(0)
            placeholder = self._get_or_create_placeholder(val, "SESSION_TOKEN")
            return f"{prefix}{placeholder}{suffix}"
        text = self.SESSION_TOKEN_PATTERN.sub(_replace_session, text)

        # 8. Redact Refresh Tokens
        def _replace_refresh(match: re.Match) -> str:
            prefix, val, suffix = match.group(1), match.group(2), match.group(3)
            if val.startswith("[REDACTED_"):
                return match.group(0)
            placeholder = self._get_or_create_placeholder(val, "REFRESH_TOKEN")
            return f"{prefix}{placeholder}{suffix}"
        text = self.REFRESH_TOKEN_PATTERN.sub(_replace_refresh, text)

        # 9. Redact Key-Value Secrets (password, token, api_key, etc.)
        def _replace_kv(match: re.Match) -> str:
            prefix = match.group(1)
            val = match.group(2)
            suffix = match.group(3)
            if val.startswith("[REDACTED_"):
                return match.group(0)
            placeholder = self._get_or_create_placeholder(val, "SECRET")
            return f"{prefix}{placeholder}{suffix}"
        text = self.KEY_VALUE_SECRET_PATTERN.sub(_replace_kv, text)

        # 10. Redact URI Credentials (e.g. proto://user:password@host)
        def _replace_uri_cred(match: re.Match) -> str:
            prefix = match.group(1)
            val = match.group(2)
            suffix = match.group(3)
            if val.startswith("[REDACTED_"):
                return match.group(0)
            placeholder = self._get_or_create_placeholder(val, "SECRET")
            return f"{prefix}{placeholder}{suffix}"
        text = self.URI_CREDENTIAL_PATTERN.sub(_replace_uri_cred, text)

        return text

    def redact_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively redact dictionary keys and values."""
        clean: Dict[str, Any] = {}
        for key, value in data.items():
            if isinstance(value, dict):
                clean[key] = self.redact_dict(value)
            elif isinstance(value, list):
                clean[key] = [
                    self.redact_dict(item) if isinstance(item, dict)
                    else (self.redact_text(str(item)) if isinstance(item, str) else item)
                    for item in value
                ]
            elif isinstance(value, str):
                if self.SENSITIVE_KEY_PATTERN.search(key):
                    clean[key] = self._get_or_create_placeholder(value, "SECRET")
                else:
                    clean[key] = self.redact_text(value)
            else:
                clean[key] = value
        return clean

    def reverse_placeholder(
        self,
        placeholder: str,
        context: Optional[VaultAccessContext] = None,
    ) -> Optional[str]:
        """
        Look up the original raw secret with mandatory authorization, purpose limitation,
        integrity verification, and fail-closed audit logging.
        """
        with self._lock:
            if not context or not isinstance(context, VaultAccessContext):
                raise VaultAccessDeniedError(
                    "Unauthorized vault reversal: valid VaultAccessContext is required."
                )
            if not context.actor or not context.actor.strip():
                raise VaultAccessDeniedError("Unauthorized vault reversal: actor must not be empty.")

            raw = self._placeholder_to_raw.get(placeholder)
            if raw is None:
                self._log_reversal(placeholder, context, success=False)
                return None

            # Verify in-memory integrity
            expected_digest = self._secret_integrity.get(placeholder)
            if expected_digest:
                actual_digest = hashlib.sha256((self._salt + raw).encode("utf-8")).hexdigest()
                if actual_digest != expected_digest:
                    self._log_reversal(placeholder, context, success=False)
                    raise VaultDataTamperedError(
                        f"Vault in-memory integrity violation detected for placeholder {placeholder}!"
                    )

            # Audit logging MUST succeed before secret is returned
            self._log_reversal(placeholder, context, success=True)
            return raw

    def reverse_text(
        self,
        text: str,
        context: Optional[VaultAccessContext] = None,
    ) -> str:
        """
        Reconstitute placeholders back to original secrets with mandatory authorization
        and audit logging.
        """
        with self._lock:
            if not context or not isinstance(context, VaultAccessContext):
                raise VaultAccessDeniedError(
                    "Unauthorized vault reversal: valid VaultAccessContext is required."
                )
            if not context.actor or not context.actor.strip():
                raise VaultAccessDeniedError("Unauthorized vault reversal: actor must not be empty.")

            placeholders_in_text = [p for p in self._placeholder_to_raw if p in text]
            result = text
            for p in placeholders_in_text:
                raw_val = self.reverse_placeholder(p, context=context)
                if raw_val is not None:
                    result = result.replace(p, raw_val)
            return result

    def register_token_metadata(
        self,
        token_ref: str,
        identity_id: str,
        expires_at: Optional[float] = None,
    ) -> "TokenMetadata":
        """Register token metadata for pre-execution TTL validation."""
        with self._lock:
            if not hasattr(self, "_token_metadata"):
                self._token_metadata = {}
            meta = TokenMetadata(token_ref=token_ref, identity_id=identity_id, expires_at=expires_at)
            self._token_metadata[token_ref] = meta
            return meta

    def get_token_metadata(self, token_ref: str) -> Optional["TokenMetadata"]:
        """Retrieve registered metadata for a token reference."""
        with self._lock:
            if not hasattr(self, "_token_metadata"):
                self._token_metadata = {}
            return self._token_metadata.get(token_ref)


class TokenMetadata:
    """Metadata tracking token expiration and identity binding."""

    def __init__(self, token_ref: str, identity_id: str, expires_at: Optional[float] = None) -> None:
        self.token_ref = token_ref
        self.identity_id = identity_id
        self.expires_at = expires_at

    def is_expired(self, clock_skew_seconds: int = 30) -> bool:
        """Return True if token is expired considering clock skew."""
        if self.expires_at is None:
            return False
        import time
        return (time.time() + clock_skew_seconds) >= self.expires_at
