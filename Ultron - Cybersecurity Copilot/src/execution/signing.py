"""Deterministic Request Signing Engine for Milestone M2.75.

Enforces:
- Explicit SigningProfile abstraction. Unmapped requests fail with UNSUPPORTED_SIGNING_FLOW.
- Canonical request construction: Method + Normalized Route + Sorted Canonical Query + SHA-256(Body) + Timestamp + Nonce.
- Replay defense: Anti-replay nonce tracking through DeterministicStateManager.
- Clock skew defense: Timestamp freshness window enforcement (default +/- 300s).
- Tamper defense: Mutation of method, path, query, body, identity, or key after signing breaks the signature.
- Zero secret leakage: Signing keys remain strictly inside RedactionVault.
"""

from abc import ABC, abstractmethod
import hashlib
import hmac
import time
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse

from src.evidence.vault import RedactionVault, VaultAccessContext, VaultReversalPurpose
from src.execution.models import SigningProfile
from src.execution.state import SigningKeyRecord
from src.execution.state_manager import DeterministicStateManager


class RequestSigningError(Exception):
    """Base exception for request signing failures."""
    pass


class UnsupportedSigningFlowError(RequestSigningError):
    """Raised when an unsupported signing profile or algorithm is requested."""
    pass


class ExpiredSigningTimestampError(RequestSigningError):
    """Raised when a signature timestamp falls outside the valid freshness window."""
    pass


class ReplayedSigningNonceError(RequestSigningError):
    """Raised when a signing nonce has already been consumed."""
    pass


class RequestSigner(ABC):
    """Abstract contract for dynamic request signing."""

    @abstractmethod
    def sign(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: Optional[bytes],
        profile: SigningProfile,
        key_record: SigningKeyRecord,
        vault: RedactionVault,
        state_manager: DeterministicStateManager,
        timestamp: Optional[float] = None,
        nonce: Optional[str] = None,
    ) -> Tuple[Dict[str, str], str]:
        """Sign the outbound request and return (updated_headers, signature_hex)."""
        pass

    @abstractmethod
    def verify(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: Optional[bytes],
        profile: SigningProfile,
        key_record: SigningKeyRecord,
        vault: RedactionVault,
    ) -> bool:
        """Verify the signature on a prepared request."""
        pass


class HmacRequestSigner(RequestSigner):
    """Deterministic HMAC-SHA256 request signer."""

    def canonicalize_request(
        self,
        method: str,
        url: str,
        body: Optional[bytes],
        timestamp_str: str,
        nonce_str: str,
    ) -> str:
        """Construct canonical string for signing."""
        parsed = urlparse(url)
        norm_method = method.upper().strip()
        norm_path = (parsed.path or "/").strip()
        if not norm_path.startswith("/"):
            norm_path = "/" + norm_path

        # Canonical query: parse, sort by key, re-encode
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        sorted_pairs = sorted(query_pairs, key=lambda x: (x[0], x[1]))
        norm_query = urlencode(sorted_pairs)

        # Body digest
        body_bytes = body if body is not None else b""
        body_sha256 = hashlib.sha256(body_bytes).hexdigest()

        canonical = (
            f"{norm_method}\n"
            f"{norm_path}\n"
            f"{norm_query}\n"
            f"{body_sha256}\n"
            f"{timestamp_str}\n"
            f"{nonce_str}"
        )
        return canonical

    def sign(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: Optional[bytes],
        profile: SigningProfile,
        key_record: SigningKeyRecord,
        vault: RedactionVault,
        state_manager: DeterministicStateManager,
        timestamp: Optional[float] = None,
        nonce: Optional[str] = None,
    ) -> Tuple[Dict[str, str], str]:
        if profile.algorithm != "HMAC-SHA256":
            raise UnsupportedSigningFlowError(f"Unsupported signing algorithm: {profile.algorithm}")

        if profile.canonicalization_version != "v1":
            raise UnsupportedSigningFlowError(
                f"Unsupported canonicalization version: {profile.canonicalization_version}. Only 'v1' is supported."
            )

        expected_components = {"method", "route", "query", "body", "timestamp", "nonce"}
        if set(profile.signed_components) != expected_components:
            raise UnsupportedSigningFlowError(
                f"Unsupported signed components for v1 canonicalization: {profile.signed_components}"
            )

        # Ownership binding between key_record and profile
        if (
            key_record.identity_id.lower().strip() != profile.identity_id.lower().strip()
            or key_record.target_authority.lower().strip() != profile.target_authority.lower().strip()
            or key_record.environment_context.lower().strip() != profile.environment_context.lower().strip()
        ):
            raise UnsupportedSigningFlowError("Signing key record does not match profile ownership binding")

        now = timestamp if timestamp is not None else time.time()
        ts_str = str(int(now))

        # Check timestamp window
        window = profile.timestamp_window_seconds
        if abs(time.time() - now) > window:
            raise ExpiredSigningTimestampError(f"Timestamp {ts_str} outside window (+/- {window}s)")

        # Generate or check nonce
        nonce_str = nonce or hashlib.sha256(f"{now}:{url}:{key_record.key_id}".encode("utf-8")).hexdigest()[:16]
        consumed_ok, err = state_manager.consume_signing_nonce(profile.profile_id, nonce_str)
        if not consumed_ok:
            raise ReplayedSigningNonceError(f"Nonce {nonce_str} has already been consumed")

        # Resolve raw key from vault
        try:
            vault_ctx = VaultAccessContext(
                actor=profile.identity_id or "request_signer",
                purpose=VaultReversalPurpose.REQUEST_SIGNING,
                justification=f"Signing profile {profile.profile_id}",
            )
            raw_key = vault.reverse_placeholder(key_record.secret_ref, context=vault_ctx)
        except Exception as e:
            raise RequestSigningError(f"Vault authorization failed for signing key {key_record.secret_ref}: {e}")
        if not raw_key:
            raise RequestSigningError(f"Signing key placeholder {key_record.secret_ref} not found in vault")

        canonical = self.canonicalize_request(method, url, body, ts_str, nonce_str)
        sig = hmac.new(raw_key.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()

        out_headers = dict(headers)
        out_headers[profile.timestamp_header] = ts_str
        out_headers[profile.nonce_header] = nonce_str
        out_headers[profile.signature_header] = sig
        return out_headers, sig

    def verify(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: Optional[bytes],
        profile: SigningProfile,
        key_record: SigningKeyRecord,
        vault: RedactionVault,
    ) -> bool:
        if profile.algorithm != "HMAC-SHA256":
            return False

        if profile.canonicalization_version != "v1":
            return False

        expected_components = {"method", "route", "query", "body", "timestamp", "nonce"}
        if set(profile.signed_components) != expected_components:
            return False

        if (
            key_record.identity_id.lower().strip() != profile.identity_id.lower().strip()
            or key_record.target_authority.lower().strip() != profile.target_authority.lower().strip()
            or key_record.environment_context.lower().strip() != profile.environment_context.lower().strip()
        ):
            return False

        ts_str = headers.get(profile.timestamp_header)
        nonce_str = headers.get(profile.nonce_header)
        sig_str = headers.get(profile.signature_header)

        if not ts_str or not nonce_str or not sig_str:
            return False

        try:
            ts_val = float(ts_str)
            if abs(time.time() - ts_val) > profile.timestamp_window_seconds:
                return False
        except ValueError:
            return False

        try:
            vault_ctx = VaultAccessContext(
                actor=profile.identity_id or "request_signer",
                purpose=VaultReversalPurpose.REQUEST_SIGNING,
                justification=f"Verifying signature for profile {profile.profile_id}",
            )
            raw_key = vault.reverse_placeholder(key_record.secret_ref, context=vault_ctx)
        except Exception:
            return False
        if not raw_key:
            return False

        canonical = self.canonicalize_request(method, url, body, ts_str, nonce_str)
        expected_sig = hmac.new(raw_key.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig_str, expected_sig)
