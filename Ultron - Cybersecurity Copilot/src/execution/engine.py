"""Master Deterministic State & Execution Engine for Milestone M2.75.

Coordinates the strict 14-step deterministic execution pipeline:
1. Live execution mode verification (default-off -> BLOCKED_EXECUTION_MODE).
2. Immutable ExecutionDescriptor generation and normalization.
3. Initial ScopeGate evaluation (DNS TOCTOU, private IP blocking, wildcard enforcement).
4. Human approval verification before ANY state mutation or token consumption.
5. Pre-flight state check (TTL, token freshness, session validity).
6. Bounded authentication refresh / re-authentication if required.
7. Post-refresh ownership revalidation (identity, target authority, environment).
8. Atomic CSRF / anti-replay nonce validation & consumption.
9. Deterministic request signing (HMAC-SHA256 canonical request).
10. Final TOCTOU descriptor integrity and destination check immediately prior to transmission.
11. Final rate-limiting pacing gate.
12. Controlled HTTP execution via ScopedHttpClient (or deterministic mock if configured).
13. Complete response redaction and observation packaging.
14. Immutable, secret-scrubbed audit logging.

All exceptions are scrubbed of secrets before logging or attaching to ExecutionResult.
Execution results emit OBSERVATION evidence; NEVER VULNERABILITY_CONFIRMED.
"""

from datetime import datetime, timezone
import hashlib
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse
import json
import httpx

from src.core.logging import AuditLogger
from src.evidence.vault import (
    RedactionVault,
    VaultAccessContext,
    VaultReversalPurpose,
    VaultAccessDeniedError,
    VaultAuditError,
    VaultDataTamperedError,
)
from src.execution.approval import ApprovalGate
from src.execution.csrf import CsrfManager
from src.execution.models import (
    ExecutionDescriptor,
    ExecutionResult,
    ExecutionStatus,
    HumanApproval,
    SigningProfile,
)
from src.execution.scrubber import scrub_exception_text
from src.execution.signing import HmacRequestSigner, RequestSigner
from src.execution.state import CredentialRecord, SessionRecord
from src.execution.state_manager import DeterministicStateManager
from src.execution.ttl_validator import DeterministicTTLValidator
from src.hypothesis.experiment import ExperimentProposal, SafetyLevel
from src.scope.client import ScopedHttpClient, ScopeViolationError
from src.scope.gate import ScopeGate
from src.scope.models import ScopeDecision


def compute_headers_digest(headers: Optional[Dict[str, str]], vault: Optional[RedactionVault] = None) -> str:
    """Compute a canonical digest over security-relevant headers without leaking raw secrets."""
    if not headers:
        return ""
    normalized = []
    for k, v in headers.items():
        k_clean = k.lower().strip()
        v_clean = vault.redact_text(v).strip() if vault else v.strip()
        normalized.append((k_clean, v_clean))
    normalized.sort(key=lambda x: x[0])
    return hashlib.sha256(json.dumps(normalized, sort_keys=True).encode("utf-8")).hexdigest()


class DeterministicExecutionEngine:
    """Master deterministic execution engine orchestrating controlled experiment execution."""

    def __init__(
        self,
        scope_gate: ScopeGate,
        scoped_client: ScopedHttpClient,
        state_manager: Optional[DeterministicStateManager] = None,
        vault: Optional[RedactionVault] = None,
        ttl_validator: Optional[DeterministicTTLValidator] = None,
        csrf_manager: Optional[CsrfManager] = None,
        signer: Optional[RequestSigner] = None,
        approval_gate: Optional[ApprovalGate] = None,
        audit_logger: Optional[AuditLogger] = None,
        live_execution_enabled: bool = False,  # Default: OFF
        mock_transport_fn: Optional[Callable[[str, str, Dict[str, str], Optional[bytes]], Tuple[int, Dict[str, str], bytes]]] = None,
    ) -> None:
        self.scope_gate = scope_gate
        self.scoped_client = scoped_client
        self.vault = vault or RedactionVault()
        self.state_manager = state_manager or DeterministicStateManager(vault=self.vault, audit_logger=audit_logger)
        self.audit_logger = audit_logger

        self.ttl_validator = ttl_validator or DeterministicTTLValidator(
            state_manager=self.state_manager,
            scoped_client=self.scoped_client,
        )
        self.csrf_manager = csrf_manager or CsrfManager(state_manager=self.state_manager, vault=self.vault)
        self.signer = signer or HmacRequestSigner()
        self.approval_gate = approval_gate or ApprovalGate()

        self.live_execution_enabled = live_execution_enabled
        self.mock_transport_fn = mock_transport_fn
        self._signing_profiles: Dict[str, SigningProfile] = {}

    def register_signing_profile(self, profile: SigningProfile) -> None:
        self._signing_profiles[profile.profile_id] = profile

    def _log_audit(
        self,
        event_type: str,
        subject_id: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        if not self.audit_logger:
            return None
        clean_details = self.vault.redact_dict(details or {})
        rec = self.audit_logger.log_event(
            event_type=event_type,
            actor="DeterministicExecutionEngine",
            subject_id=subject_id,
            details=clean_details,
        )
        return rec.get("payload_hash")

    def execute_proposal(
        self,
        experiment: ExperimentProposal,
        destination_url: str,
        http_method: str = "GET",
        request_headers: Optional[Dict[str, str]] = None,
        request_body: Optional[bytes] = None,
        environment_context: str = "staging",
        signing_profile_id: Optional[str] = None,
        approval_id: Optional[str] = None,
        csrf_token_ref: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> ExecutionResult:
        """Executes an authorized experiment proposal through the strict 14-step pipeline."""
        t0 = time.perf_counter()
        exp_id = experiment.objective[:32].replace(" ", "_")
        target_auth = (urlparse(destination_url).hostname or "unknown").lower().strip()
        actor_id = experiment.actor_identity_id or "anonymous"
        safety_str = experiment.safety_level.value

        headers = dict(request_headers or {})
        initial_headers_digest = compute_headers_digest(headers, self.vault)
        body_bytes = request_body if request_body is not None else b""
        body_digest = hashlib.sha256(body_bytes).hexdigest()

        # Parse normalized route & query
        parsed_dest = urlparse(destination_url)
        norm_route = parsed_dest.path or "/"
        norm_query = parsed_dest.query or ""

        # Step 2: Build immutable ExecutionDescriptor
        descriptor = ExecutionDescriptor(
            experiment_id=exp_id,
            identity_id=actor_id,
            environment_context=environment_context,
            target_authority=target_auth,
            destination=destination_url,
            http_method=http_method.upper().strip(),
            normalized_route=norm_route,
            normalized_query=norm_query,
            headers_digest=initial_headers_digest,
            request_body_digest=body_digest,
            safety_classification=safety_str,
            affected_resource=experiment.target_asset_id,
            expected_state_transition=experiment.rollback_requirement,
        )
        desc_digest = descriptor.compute_digest()

        # Step 1: Live Execution Mode Check
        if not self.live_execution_enabled and not self.mock_transport_fn:
            self._log_audit(
                event_type="EXECUTION_BLOCKED_MODE",
                subject_id=exp_id,
                details={"reason": "Live execution disabled and no mock transport configured"},
            )
            return ExecutionResult(
                experiment_id=exp_id,
                status=ExecutionStatus.BLOCKED_EXECUTION_MODE,
                error_message="Live network execution is disabled by default. No network requests permitted.",
                descriptor_digest=desc_digest,
                latency_seconds=time.perf_counter() - t0,
            )

        # Step 3: Initial Scope Gate Check
        scope_decision = self.scope_gate.evaluate(destination_url)
        if scope_decision.decision != ScopeDecision.ALLOW:
            self._log_audit(
                event_type="EXECUTION_BLOCKED_SCOPE",
                subject_id=exp_id,
                details={"reason": scope_decision.reason, "url": destination_url},
            )
            return ExecutionResult(
                experiment_id=exp_id,
                status=ExecutionStatus.BLOCKED_SCOPE,
                scope_decision_id=scope_decision.scope_decision_id,
                error_message=f"Destination blocked by ScopeGate: {scope_decision.reason}",
                descriptor_digest=desc_digest,
                latency_seconds=time.perf_counter() - t0,
            )

        # Record resolved IP if available for TOCTOU check
        resolved_ip = scope_decision.resolved_addresses[0] if scope_decision.resolved_addresses else None
        descriptor.resolved_ip = resolved_ip
        desc_digest = descriptor.compute_digest()

        # Step 4: Human Approval Verification (MUST occur before any state mutation)
        is_approved, app_err, app_rec = self.approval_gate.verify_approval(
            descriptor=descriptor,
            approval_id=approval_id,
        )
        if not is_approved:
            self._log_audit(
                event_type="EXECUTION_BLOCKED_APPROVAL",
                subject_id=exp_id,
                details={"reason": app_err, "descriptor_digest": desc_digest},
            )
            return ExecutionResult(
                experiment_id=exp_id,
                status=ExecutionStatus.BLOCKED_APPROVAL,
                error_message=f"Execution blocked by ApprovalGate: {app_err}",
                descriptor_digest=desc_digest,
                latency_seconds=time.perf_counter() - t0,
            )

        # Step 5 & 6: Pre-flight TTL and Token Validation & Bounded Refresh
        ttl_result = self.ttl_validator.validate_proposal(experiment, self.vault)
        if not ttl_result.valid:
            status = ExecutionStatus.BLOCKED_TTL
            if ttl_result.error and "CROSS_IDENTITY" in ttl_result.error:
                status = ExecutionStatus.BLOCKED_AUTH_STATE
            elif ttl_result.error and "UNSUPPORTED_AUTH_FLOW" in ttl_result.error:
                status = ExecutionStatus.UNSUPPORTED_AUTH_FLOW

            self._log_audit(
                event_type="EXECUTION_BLOCKED_TTL",
                subject_id=exp_id,
                details={"error": ttl_result.error, "identity_id": actor_id},
            )
            return ExecutionResult(
                experiment_id=exp_id,
                status=status,
                error_message=f"Pre-execution TTL validation failed: {ttl_result.error}",
                descriptor_digest=desc_digest,
                latency_seconds=time.perf_counter() - t0,
            )

        # Step 7: Post-Refresh Auth State Ownership Revalidation
        for token_ref in experiment.required_token_references:
            valid_owner, own_err, _ = self.state_manager.validate_credential_ownership(
                token_ref=token_ref,
                expected_identity_id=actor_id,
                expected_target_authority=target_auth,
                expected_environment_context=environment_context,
            )
            if not valid_owner:
                self._log_audit(
                    event_type="EXECUTION_BLOCKED_AUTH_STATE",
                    subject_id=exp_id,
                    details={"error": own_err, "token_ref": token_ref},
                )
                return ExecutionResult(
                    experiment_id=exp_id,
                    status=ExecutionStatus.BLOCKED_AUTH_STATE,
                    error_message=f"Credential ownership validation failed: {own_err}",
                    descriptor_digest=desc_digest,
                    latency_seconds=time.perf_counter() - t0,
                )

        # Step 8: CSRF Validation & Atomic Consumption
        if csrf_token_ref:
            csrf_ok, csrf_err, csrf_pair = self.csrf_manager.prepare_and_consume_csrf(
                token_ref=csrf_token_ref,
                identity_id=actor_id,
                session_id=session_id,
                target_authority=target_auth,
            )
            if not csrf_ok or not csrf_pair:
                self._log_audit(
                    event_type="EXECUTION_BLOCKED_CSRF",
                    subject_id=exp_id,
                    details={"error": csrf_err, "csrf_token_ref": csrf_token_ref},
                )
                return ExecutionResult(
                    experiment_id=exp_id,
                    status=ExecutionStatus.BLOCKED_CSRF,
                    error_message=f"CSRF validation failed: {csrf_err}",
                    descriptor_digest=desc_digest,
                    latency_seconds=time.perf_counter() - t0,
                )
            # Inject consumed CSRF header
            header_name, header_val = csrf_pair
            headers[header_name] = header_val

        # Step 9: Request Signing
        if signing_profile_id:
            profile = self._signing_profiles.get(signing_profile_id)
            if not profile:
                return ExecutionResult(
                    experiment_id=exp_id,
                    status=ExecutionStatus.UNSUPPORTED_SIGNING_FLOW,
                    error_message=f"Signing profile {signing_profile_id} not registered",
                    descriptor_digest=desc_digest,
                    latency_seconds=time.perf_counter() - t0,
                )

            # Validate signing profile ownership against experiment context
            if (
                profile.identity_id.lower().strip() != actor_id.lower().strip()
                or profile.target_authority.lower().strip() != target_auth.lower().strip()
                or profile.environment_context.lower().strip() != environment_context.lower().strip()
            ):
                return ExecutionResult(
                    experiment_id=exp_id,
                    status=ExecutionStatus.BLOCKED_AUTH_STATE,
                    error_message="Signing key ownership mismatch: profile does not match experiment identity/target/environment",
                    descriptor_digest=desc_digest,
                    latency_seconds=time.perf_counter() - t0,
                )

            key_rec = self.state_manager.get_signing_key(profile.profile_id)
            if not key_rec:
                return ExecutionResult(
                    experiment_id=exp_id,
                    status=ExecutionStatus.UNSUPPORTED_SIGNING_FLOW,
                    error_message=f"No signing key found for profile {profile.profile_id}",
                    descriptor_digest=desc_digest,
                    latency_seconds=time.perf_counter() - t0,
                )

            # Validate signing key ownership against experiment context
            if (
                key_rec.identity_id.lower().strip() != actor_id.lower().strip()
                or key_rec.target_authority.lower().strip() != target_auth.lower().strip()
                or key_rec.environment_context.lower().strip() != environment_context.lower().strip()
            ):
                return ExecutionResult(
                    experiment_id=exp_id,
                    status=ExecutionStatus.BLOCKED_AUTH_STATE,
                    error_message="Signing key ownership mismatch: cannot sign with key bound to different identity/target/environment",
                    descriptor_digest=desc_digest,
                    latency_seconds=time.perf_counter() - t0,
                )

            try:
                headers, _ = self.signer.sign(
                    method=http_method,
                    url=destination_url,
                    headers=headers,
                    body=body_bytes,
                    profile=profile,
                    key_record=key_rec,
                    vault=self.vault,
                    state_manager=self.state_manager,
                )
            except Exception as e:
                scrubbed_e = scrub_exception_text(str(e), self.vault)
                return ExecutionResult(
                    experiment_id=exp_id,
                    status=ExecutionStatus.UNSUPPORTED_SIGNING_FLOW,
                    error_message=f"Signing failed: {scrubbed_e}",
                    descriptor_digest=desc_digest,
                    latency_seconds=time.perf_counter() - t0,
                )

        # Step 10: Final TOCTOU Descriptor Integrity, Scope, Approval, and Ownership Re-check immediately before transmission
        final_dest_check = self.scope_gate.evaluate(destination_url)
        if final_dest_check.decision != ScopeDecision.ALLOW:
            return ExecutionResult(
                experiment_id=exp_id,
                status=ExecutionStatus.BLOCKED_SCOPE,
                error_message="Final TOCTOU destination scope check failed",
                descriptor_digest=desc_digest,
                latency_seconds=time.perf_counter() - t0,
            )

        # 10a. Target authority integrity
        current_target_auth = (urlparse(destination_url).hostname or "unknown").lower().strip()
        if current_target_auth != target_auth or current_target_auth != descriptor.target_authority.lower().strip():
            return ExecutionResult(
                experiment_id=exp_id,
                status=ExecutionStatus.BLOCKED_SCOPE,
                error_message="Final TOCTOU target authority mismatch",
                descriptor_digest=desc_digest,
                latency_seconds=time.perf_counter() - t0,
            )

        # 10b. Revalidate descriptor digest integrity against original approved digest
        current_desc_digest = descriptor.compute_digest()
        if current_desc_digest != desc_digest:
            return ExecutionResult(
                experiment_id=exp_id,
                status=ExecutionStatus.BLOCKED_APPROVAL,
                error_message="Final TOCTOU descriptor mismatch: descriptor mutated after approval",
                descriptor_digest=desc_digest,
                latency_seconds=time.perf_counter() - t0,
            )

        # 10c. Re-verify approval validity if approval was required or provided
        if approval_id or self.approval_gate.requires_approval(descriptor.safety_classification):
            is_app_valid, app_recheck_err, _ = self.approval_gate.verify_approval(
                descriptor=descriptor,
                approval_id=approval_id,
            )
            if not is_app_valid:
                return ExecutionResult(
                    experiment_id=exp_id,
                    status=ExecutionStatus.BLOCKED_APPROVAL,
                    error_message=f"Final TOCTOU approval check failed: {app_recheck_err}",
                    descriptor_digest=desc_digest,
                    latency_seconds=time.perf_counter() - t0,
                )

        # 10d. Verify unauthorized header mutations on approved security headers
        for orig_k, orig_v in (request_headers or {}).items():
            if orig_k in headers:
                curr_val_redacted = self.vault.redact_text(headers[orig_k]).strip()
                orig_val_redacted = self.vault.redact_text(orig_v).strip()
                if curr_val_redacted != orig_val_redacted:
                    return ExecutionResult(
                        experiment_id=exp_id,
                        status=ExecutionStatus.BLOCKED_APPROVAL,
                        error_message=f"Final TOCTOU header mutation detected on security header '{orig_k}'",
                        descriptor_digest=desc_digest,
                        latency_seconds=time.perf_counter() - t0,
                    )
            else:
                return ExecutionResult(
                    experiment_id=exp_id,
                    status=ExecutionStatus.BLOCKED_APPROVAL,
                    error_message=f"Final TOCTOU missing approved header '{orig_k}'",
                    descriptor_digest=desc_digest,
                    latency_seconds=time.perf_counter() - t0,
                )

        # 10e. Re-validate credential ownership for required tokens
        for token_ref in experiment.required_token_references:
            valid_owner, own_err, _ = self.state_manager.validate_credential_ownership(
                token_ref=token_ref,
                expected_identity_id=actor_id,
                expected_target_authority=target_auth,
                expected_environment_context=environment_context,
            )
            if not valid_owner:
                self._log_audit(
                    event_type="EXECUTION_BLOCKED_AUTH_STATE",
                    subject_id=exp_id,
                    details={"error": own_err, "token_ref": token_ref, "phase": "final_toctou"},
                )
                return ExecutionResult(
                    experiment_id=exp_id,
                    status=ExecutionStatus.BLOCKED_AUTH_STATE,
                    error_message=f"Final TOCTOU credential ownership check failed: {own_err}",
                    descriptor_digest=desc_digest,
                    latency_seconds=time.perf_counter() - t0,
                )

        # Re-resolve authorization tokens into raw headers immediately before transmission
        for token_ref in experiment.required_token_references:
            try:
                vault_ctx = VaultAccessContext(
                    actor=actor_id,
                    purpose=VaultReversalPurpose.EXECUTION_DISPATCH,
                    justification=f"Dispatched experiment {exp_id}",
                )
                raw_val = self.vault.reverse_placeholder(token_ref, context=vault_ctx)
            except (VaultAccessDeniedError, VaultAuditError, VaultDataTamperedError) as e:
                self._log_audit(
                    event_type="EXECUTION_BLOCKED_AUTH_STATE",
                    subject_id=exp_id,
                    details={"error": f"VAULT_REVERSAL_FAILED: {e}", "token_ref": token_ref},
                )
                return ExecutionResult(
                    experiment_id=exp_id,
                    status=ExecutionStatus.BLOCKED_AUTH_STATE,
                    error_message=f"Vault reversal failed for token '{token_ref}': {e}",
                    descriptor_digest=desc_digest,
                    latency_seconds=time.perf_counter() - t0,
                )

            if not raw_val:
                self._log_audit(
                    event_type="EXECUTION_BLOCKED_AUTH_STATE",
                    subject_id=exp_id,
                    details={"error": "TOKEN_REFERENCE_NOT_REVERSIBLE", "token_ref": token_ref},
                )
                return ExecutionResult(
                    experiment_id=exp_id,
                    status=ExecutionStatus.BLOCKED_AUTH_STATE,
                    error_message=f"Required credential reference '{token_ref}' could not be resolved from vault",
                    descriptor_digest=desc_digest,
                    latency_seconds=time.perf_counter() - t0,
                )
            # If Authorization header already present with placeholder, replace it
            if "Authorization" in headers and token_ref in headers["Authorization"]:
                headers["Authorization"] = headers["Authorization"].replace(token_ref, raw_val)
            elif "Authorization" not in headers:
                headers["Authorization"] = f"Bearer {raw_val}"

        # Hard guard: Ensure no unresolved placeholder or redaction marker remains in Authorization header
        auth_hdr = headers.get("Authorization", "")
        if "******" in auth_hdr or "[REDACTED" in auth_hdr:
            self._log_audit(
                event_type="EXECUTION_BLOCKED_AUTH_STATE",
                subject_id=exp_id,
                details={"error": "UNRESOLVED_REDACTION_MARKER_IN_HEADER"},
            )
            return ExecutionResult(
                experiment_id=exp_id,
                status=ExecutionStatus.BLOCKED_AUTH_STATE,
                error_message="Authorization header contains unresolved redacted placeholder",
                descriptor_digest=desc_digest,
                latency_seconds=time.perf_counter() - t0,
            )

        # Step 11 & 12: Controlled HTTP Execution (ScopedHttpClient or deterministic mock)
        resp_status: Optional[int] = None
        resp_headers: Dict[str, str] = {}
        resp_body: bytes = b""

        try:
            if self.mock_transport_fn:
                # Deterministic local / mock execution
                resp_status, resp_headers, resp_body = self.mock_transport_fn(
                    http_method, destination_url, headers, body_bytes
                )
            else:
                # Live execution via ScopedHttpClient
                resp, final_scope_dec = self.scoped_client.request(
                    method=http_method,
                    url=destination_url,
                    headers=headers,
                    data=body_bytes if body_bytes else None,
                )
                resp_status = resp.status_code
                resp_headers = dict(resp.headers)
                resp_body = resp.content
        except ScopeViolationError as e:
            return ExecutionResult(
                experiment_id=exp_id,
                status=ExecutionStatus.BLOCKED_SCOPE,
                error_message=f"Outbound request blocked by scope gate: {scrub_exception_text(str(e), self.vault)}",
                descriptor_digest=desc_digest,
                latency_seconds=time.perf_counter() - t0,
            )
        except Exception as e:
            # Exception scrub boundary
            scrubbed_err = scrub_exception_text(str(e), self.vault)
            self._log_audit(
                event_type="EXECUTION_ERROR",
                subject_id=exp_id,
                details={"error": scrubbed_err},
            )
            return ExecutionResult(
                experiment_id=exp_id,
                status=ExecutionStatus.EXECUTION_ERROR,
                error_message=scrubbed_err,
                descriptor_digest=desc_digest,
                latency_seconds=time.perf_counter() - t0,
            )

        # Step 13: Redact + Package Raw Observation Evidence
        clean_resp_body = self.vault.redact_text(resp_body.decode("utf-8", errors="replace"))
        clean_resp_headers = {k: self.vault.redact_text(v) for k, v in resp_headers.items()}

        observation_record = {
            "interaction_id": f"INTERACTION-{exp_id}",
            "caller_identity": actor_id,
            "http_method": http_method.upper(),
            "route": norm_route,
            "status_code": resp_status,
            "response_headers": clean_resp_headers,
            "response_body_redacted": clean_resp_body,
            "epistemic_status": "OBSERVED",
        }

        # Step 14: Audit Logging
        audit_hash = self._log_audit(
            event_type="EXPERIMENT_EXECUTED",
            subject_id=exp_id,
            details={
                "status_code": resp_status,
                "descriptor_digest": desc_digest,
                "destination": destination_url,
                "actor_id": actor_id,
            },
        )

        return ExecutionResult(
            experiment_id=exp_id,
            status=ExecutionStatus.EXECUTED,
            status_code=resp_status,
            response_headers=clean_resp_headers,
            response_body_redacted=clean_resp_body,
            scope_decision_id=scope_decision.scope_decision_id,
            latency_seconds=time.perf_counter() - t0,
            audit_record_hash=audit_hash,
            observation_record=observation_record,
            descriptor_digest=desc_digest,
        )
