"""Milestone M11.3: Deterministic Preflight Safety Engine.

Enforces:
1. Strict authorization verification via AuthorizationValidator (INV-M11-01).
2. Strict scope verification via ScopeGate (INV-M11-02).
3. Two-Plane Execution Model:
   - Plane A (Local Lab): Can be executed in isolated sandbox upon approval.
   - Plane B (Real Target): Plan only, NO autonomous execution (Section 2).
4. Deterministic Risk Classification: LOW, MEDIUM, HIGH, BLOCKED.
5. Resource Ceiling Verification: timeout <= 60s, request caps, memory limits (INV-M11-07).
6. Prompt Injection Defense: detects and blocks untrusted instruction overrides (INV-M11-16).
7. Secret Protection: scans and redacts credentials before context exposure (INV-M11-15).
"""

from datetime import datetime, timezone
from enum import Enum
import json
import re
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from src.experiment.models import (
    ControlledExperiment,
    ExecutionPlane,
    ExperimentEnvironmentType,
    ExperimentRiskLevel,
    ExperimentStatus,
)
from src.experiment.poc import SafePoC, SafePoCValidator
from src.assessment.models import AuthorizationRecord, AuthorizationStatus
from src.assessment.authorization import AuthorizationValidator
from src.assessment.secrets import SecretRedactor
from src.scope.gate import ScopeGate, canonicalize_host


class PreflightDecision(str, Enum):
    """Deterministic decisions produced by the Preflight Safety Engine."""
    CAN_EXECUTE_LAB = "CAN_EXECUTE_LAB"                    # Validated for isolated Plane A lab execution
    AWAITING_HUMAN_APPROVAL = "AWAITING_HUMAN_APPROVAL"    # Valid specification, but holds human approval requirement
    PLAN_ONLY = "PLAN_ONLY"                                # Validated for Plane B real target (no autonomous execution)
    BLOCKED = "BLOCKED"                                    # Failed safety, authorization, scope, or invariant checks


class PreflightReport(BaseModel):
    """Comprehensive, deterministic preflight evaluation outcome."""
    experiment_id: str
    assessment_id: str
    decision: PreflightDecision
    risk_level: ExperimentRiskLevel
    execution_plane: ExecutionPlane
    authorization_valid: bool
    authorization_detail: str
    scope_valid: bool
    scope_detail: str
    environment_valid: bool
    resource_checks_passed: bool
    human_approval_required: bool
    violations: List[str] = Field(default_factory=list)
    redacted_actions: List[Dict[str, Any]] = Field(default_factory=list)
    canary_marker: Optional[str] = None
    evaluated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class PreflightSafetyEngine:
    """
    Deterministic safety preflight engine for security experiments.
    Evaluates experiments before any state progression towards execution.
    """

    PROMPT_INJECTION_PATTERNS = [
        re.compile(r"ignore\s+(?:all\s+)?previous\s+instructions", re.I),
        re.compile(r"bypass\s+(?:the\s+)?(?:authorization|scope|sandbox|safety)", re.I),
        re.compile(r"disable\s+(?:the\s+)?(?:sandbox|safety|controls|checks)", re.I),
        re.compile(r"override\s+(?:scope|authorization|policy|permission)", re.I),
        re.compile(r"mark\s+(?:this\s+)?as\s+(?:verified|approved)", re.I),
        re.compile(r"system\s*prompt\s*override", re.I),
        re.compile(r"execute\s+arbitrary\s+(?:command|payload)", re.I),
        re.compile(r"i\s+am\s+the\s+administrator", re.I),
        re.compile(r"grant\s+(?:all\s+)?permissions", re.I),
    ]

    LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "0.0.0.0", "test.local", "lab.local"}

    @classmethod
    def evaluate(
        cls,
        experiment: ControlledExperiment,
        poc: Optional[SafePoC] = None,
        auth_record: Optional[AuthorizationRecord] = None,
        scope_gate: Optional[ScopeGate] = None,
    ) -> PreflightReport:
        """
        Executes complete preflight safety evaluation.
        Fails closed on any security invariant or boundary violation.
        """
        violations: List[str] = []

        # 1. Prompt Injection Defense (INV-M11-16)
        content_to_scan = json.dumps({
            "preconditions": experiment.preconditions,
            "proposed_actions": experiment.proposed_actions,
            "expected_observations": experiment.expected_observations,
            "safety_constraints": experiment.safety_constraints,
            "target_id": experiment.target_id,
            "asset_id": experiment.asset_id,
        }).lower()

        for pattern in cls.PROMPT_INJECTION_PATTERNS:
            if pattern.search(content_to_scan):
                violations.append(
                    f"Prompt injection / instruction override pattern detected: '{pattern.pattern}' (INV-M11-16)"
                )

        # 2. Safe PoC Validation (Section 5, INV-M11-03)
        canary = None
        if poc:
            canary = poc.canary_marker
            is_poc_safe, poc_violations = SafePoCValidator.validate_poc(poc)
            if not is_poc_safe:
                violations.extend(poc_violations)

        # 3. Authorization Verification (INV-M11-01)
        auth_valid = False
        auth_detail = "AUTHORIZATION_NOT_EVALUATED"

        if experiment.execution_plane == ExecutionPlane.PLANE_B_AUTHORIZED_TARGET:
            if not auth_record:
                violations.append("Plane B target requires active AuthorizationRecord (INV-M11-01)")
                auth_detail = "AUTHORIZATION_MISSING"
            else:
                is_valid, reason = AuthorizationValidator.validate_authorization(auth_record)
                auth_valid = is_valid
                auth_detail = reason
                if not is_valid:
                    violations.append(f"Authorization validation failed: {reason}")
        else:
            # Plane A Local Lab: Requires valid authorization reference string
            if not experiment.authorization_reference or not experiment.authorization_reference.strip():
                violations.append("Missing authorization reference for local lab experiment")
                auth_detail = "MISSING_LOCAL_REFERENCE"
            elif any(bad in experiment.authorization_reference.lower() for bad in ("unauthorized", "revoked", "expired", "invalid")):
                violations.append("Explicitly unauthorized, revoked, or expired experiment reference")
                auth_detail = "EXPLICITLY_UNAUTHORIZED"
            else:
                auth_valid = True
                auth_detail = f"LOCAL_LAB_AUTH_OK ({experiment.authorization_reference})"

        # 4. Scope Verification (INV-M11-02)
        scope_valid = False
        scope_detail = "SCOPE_NOT_EVALUATED"

        target_host = None
        if experiment.target_id:
            target_host = canonicalize_host(experiment.target_id)
        elif experiment.proposed_actions:
            # Extract target from first action url if available
            for act in experiment.proposed_actions:
                target_url = act.get("target_url") or act.get("url") or act.get("host")
                if target_url:
                    target_host = canonicalize_host(str(target_url))
                    break

        if experiment.execution_plane == ExecutionPlane.PLANE_A_LOCAL_LAB:
            # Lab must remain on loopback / lab addresses by default (INV-M11-06)
            if target_host and target_host not in cls.LOOPBACK_HOSTS:
                violations.append(
                    f"Plane A Local Lab cannot target non-loopback address '{target_host}' (INV-M11-06)"
                )
                scope_valid = False
                scope_detail = f"EXTERNAL_TARGET_IN_LOCAL_LAB: {target_host}"
            else:
                scope_valid = True
                scope_detail = "LOCAL_LAB_LOOPBACK_SCOPE_OK"
        else:
            # Plane B Authorized Target: Must pass ScopeGate if available
            if not target_host:
                violations.append("Plane B experiment requires explicit target host/URL")
                scope_detail = "MISSING_TARGET_HOST"
            elif scope_gate:
                decision_obj = scope_gate.evaluate(target_host)
                if decision_obj.decision.value not in ("ALLOW", "IN_SCOPE"):
                    violations.append(
                        f"Target '{target_host}' is not in approved scope: {decision_obj.reason} (INV-M11-02)"
                    )
                    scope_valid = False
                    scope_detail = f"OUT_OF_SCOPE: {decision_obj.reason}"
                else:
                    scope_valid = True
                    scope_detail = "IN_SCOPE_VERIFIED"
            else:
                # If ScopeGate not directly passed, check scope_reference validity
                if not experiment.scope_reference or not experiment.scope_reference.strip():
                    violations.append("Missing scope_reference for Plane B target")
                    scope_detail = "MISSING_SCOPE_REFERENCE"
                else:
                    scope_valid = True
                    scope_detail = f"SCOPE_REFERENCE_PRESENT ({experiment.scope_reference})"

        # 5. Environment & Plane Check
        env_valid = True
        if experiment.execution_plane == ExecutionPlane.PLANE_A_LOCAL_LAB:
            if experiment.environment_type not in (
                ExperimentEnvironmentType.LOCAL_LAB,
                ExperimentEnvironmentType.SYNTHETIC_FIXTURE,
                ExperimentEnvironmentType.ISOLATED_CONTAINER,
                ExperimentEnvironmentType.DISPOSABLE_PROCESS,
                ExperimentEnvironmentType.ANDROID_STATIC_TEST,
            ):
                env_valid = False
                violations.append(f"Invalid environment type '{experiment.environment_type.value}' for Plane A")
        elif experiment.execution_plane == ExecutionPlane.PLANE_B_AUTHORIZED_TARGET:
            if experiment.environment_type != ExperimentEnvironmentType.AUTHORIZED_TARGET:
                env_valid = False
                violations.append(f"Environment type must be AUTHORIZED_TARGET for Plane B")

        # 6. Resource Ceiling Check (INV-M11-07)
        resource_passed = True
        if poc:
            if poc.timeout_seconds > 60:
                resource_passed = False
                violations.append(f"PoC timeout exceeds maximum 60s limit: {poc.timeout_seconds}")
            limits = poc.resource_limits or {}
            if limits.get("max_memory_mb", 0) > 512:
                resource_passed = False
                violations.append(f"PoC memory limit exceeds 512MB: {limits.get('max_memory_mb')}")
            if limits.get("max_requests", 0) > 50:
                resource_passed = False
                violations.append(f"PoC request limit exceeds 50 requests: {limits.get('max_requests')}")

        # 7. Deterministic Risk Classification
        if violations:
            risk_level = ExperimentRiskLevel.BLOCKED
        else:
            risk_level = cls._classify_risk(experiment, poc)

        # 8. Secret Redaction (INV-M11-15)
        redacted_actions = [
            SecretRedactor.redact_dict(act) for act in experiment.proposed_actions
        ]

        # 9. Human Approval & Execution Decision Determination
        # Plane B targets NEVER execute autonomously (Section 2)
        if risk_level == ExperimentRiskLevel.BLOCKED:
            decision = PreflightDecision.BLOCKED
            approval_required = False
        elif experiment.execution_plane == ExecutionPlane.PLANE_B_AUTHORIZED_TARGET:
            decision = PreflightDecision.PLAN_ONLY
            approval_required = True
        else:
            # Plane A Local Lab:
            # If experiment has already received valid human approval, it can execute;
            # otherwise it awaits human approval.
            approval_required = True
            if experiment.human_approval and experiment.human_approval.get("approved") is True:
                decision = PreflightDecision.CAN_EXECUTE_LAB
            else:
                decision = PreflightDecision.AWAITING_HUMAN_APPROVAL

        return PreflightReport(
            experiment_id=experiment.experiment_id,
            assessment_id=experiment.assessment_id,
            decision=decision,
            risk_level=risk_level,
            execution_plane=experiment.execution_plane,
            authorization_valid=auth_valid,
            authorization_detail=auth_detail,
            scope_valid=scope_valid,
            scope_detail=scope_detail,
            environment_valid=env_valid,
            resource_checks_passed=resource_passed,
            human_approval_required=approval_required,
            violations=violations,
            redacted_actions=redacted_actions,
            canary_marker=canary,
        )

    @classmethod
    def _classify_risk(
        cls,
        experiment: ControlledExperiment,
        poc: Optional[SafePoC] = None,
    ) -> ExperimentRiskLevel:
        """
        Deterministically classifies the experiment risk level.
        """
        # Plane B is inherently at least HIGH risk
        if experiment.execution_plane == ExecutionPlane.PLANE_B_AUTHORIZED_TARGET:
            return ExperimentRiskLevel.HIGH

        # Check for state changes or file writes in actions
        actions = experiment.proposed_actions
        has_state_change = False
        has_network_activity = False

        for act in actions:
            action_type = str(act.get("type", "")).lower()
            if any(k in action_type for k in ("write", "update", "delete", "post", "put", "patch", "modify")):
                has_state_change = True
            if any(k in action_type for k in ("http", "request", "socket", "network", "fetch")):
                has_network_activity = True

        if has_state_change:
            return ExperimentRiskLevel.MEDIUM
        elif has_network_activity:
            return ExperimentRiskLevel.LOW
        else:
            # Read-only or synthetic fixture test
            return ExperimentRiskLevel.LOW
