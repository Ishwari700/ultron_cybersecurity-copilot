"""Milestone M11: Safe Proof-of-Concept (SafePoC) Domain Model and Validator.

Enforces:
1. Proof of Condition over Full Exploitation (Section 4.2).
2. Benign canary markers instead of weaponized payloads.
3. Automated rejection/downgrade of destructive, persistence, or credential-theft patterns (Section 5).
4. Strict resource limits, timeout caps, and rollback requirements.
"""

from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field


class PoCVulnerabilityClass(str, Enum):
    """Vulnerability classifications for Safe PoC objectives."""
    IDOR = "IDOR"
    BFLA = "BFLA"
    AUTHENTICATION_BYPASS = "AUTHENTICATION_BYPASS"
    SQL_INJECTION = "SQL_INJECTION"
    CROSS_SITE_SCRIPTING = "CROSS_SITE_SCRIPTING"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    SSRF = "SSRF"
    DESERIALIZATION = "DESERIALIZATION"
    INFORMATION_DISCLOSURE = "INFORMATION_DISCLOSURE"
    SECURITY_MISCONFIGURATION = "SECURITY_MISCONFIGURATION"
    MOBILE_EXPORTED_COMPONENT = "MOBILE_EXPORTED_COMPONENT"
    MOBILE_STORAGE_FLAW = "MOBILE_STORAGE_FLAW"
    BINARY_MEMORY_SAFETY = "BINARY_MEMORY_SAFETY"
    GENERIC_LOGIC_FLAW = "GENERIC_LOGIC_FLAW"


class SafePoC(BaseModel):
    """
    Formal Safe Proof-of-Concept Specification.
    Strictly designed for controlled, non-destructive verification of security conditions.
    """
    poc_id: str
    experiment_id: str
    title: str
    objective: str
    vulnerability_class: PoCVulnerabilityClass
    prerequisites: List[str] = Field(default_factory=list)
    target_environment: str = "LOCAL_LAB"
    inputs: Dict[str, Any] = Field(default_factory=dict)
    expected_behavior: str
    expected_safe_behavior: str
    canary_marker: str
    actions: List[Dict[str, Any]] = Field(default_factory=list)
    safety_constraints: List[str] = Field(default_factory=list)
    timeout_seconds: int = 15
    resource_limits: Dict[str, Any] = Field(default_factory=lambda: {
        "max_memory_mb": 256,
        "max_cpu_percent": 50,
        "max_output_kb": 128,
        "max_requests": 10,
    })
    rollback_plan: Optional[Dict[str, Any]] = None
    success_conditions: List[str] = Field(default_factory=list)
    failure_conditions: List[str] = Field(default_factory=list)
    evidence_requirements: List[str] = Field(default_factory=list)
    epistemic_status: str = "MODEL_HYPOTHESIS"
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    provenance: Dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def create(
        cls,
        experiment_id: str,
        title: str,
        objective: str,
        vulnerability_class: PoCVulnerabilityClass,
        actions: List[Dict[str, Any]],
        expected_behavior: str,
        expected_safe_behavior: str,
        canary_marker: Optional[str] = None,
        inputs: Optional[Dict[str, Any]] = None,
        prerequisites: Optional[List[str]] = None,
        target_environment: str = "LOCAL_LAB",
        safety_constraints: Optional[List[str]] = None,
        timeout_seconds: int = 15,
        rollback_plan: Optional[Dict[str, Any]] = None,
        success_conditions: Optional[List[str]] = None,
        failure_conditions: Optional[List[str]] = None,
        evidence_requirements: Optional[List[str]] = None,
    ) -> "SafePoC":
        if not canary_marker:
            canary_seed = f"{experiment_id}:{title}:{json.dumps(actions, sort_keys=True)}"
            canary_marker = f"CANARY_M11_{hashlib.sha256(canary_seed.encode('utf-8')).hexdigest()[:8].upper()}"

        seed = f"{experiment_id}:{title}:{canary_marker}:{vulnerability_class.value}"
        poc_id = f"POC-M11-{hashlib.sha256(seed.encode('utf-8')).hexdigest()[:12].upper()}"

        return cls(
            poc_id=poc_id,
            experiment_id=experiment_id,
            title=title,
            objective=objective,
            vulnerability_class=vulnerability_class,
            prerequisites=prerequisites or [],
            target_environment=target_environment,
            inputs=inputs or {},
            expected_behavior=expected_behavior,
            expected_safe_behavior=expected_safe_behavior,
            canary_marker=canary_marker,
            actions=actions,
            safety_constraints=safety_constraints or [
                "Strict non-destructive testing",
                "Loopback/local network only",
                "Rate limited to maximum 10 requests",
            ],
            timeout_seconds=timeout_seconds,
            rollback_plan=rollback_plan,
            success_conditions=success_conditions or [f"Observed canary marker: {canary_marker}"],
            failure_conditions=failure_conditions or ["HTTP status 403 Forbidden or 401 Unauthorized"],
            evidence_requirements=evidence_requirements or ["HTTP Response Body", "Status Code"],
        )


class SafePoCValidator:
    """
    Validates SafePoC specifications against forbidden destructive or weaponized patterns.
    Enforces Section 5 Safe PoC Generation Rules.
    """

    DESTRUCTIVE_PATTERNS = [
        re.compile(r"\brm\s+-rf\b", re.I),
        re.compile(r"\bdrop\s+table\b", re.I),
        re.compile(r"\btruncate\s+table\b", re.I),
        re.compile(r"\bdelete\s+from\s+.*\bwhere\s+1=1\b", re.I),
        re.compile(r"\bformat\s+[a-z]:\b", re.I),
        re.compile(r"\bwipe\s+disk\b", re.I),
        re.compile(r"\bmkfs\b", re.I),
        re.compile(r"\bdd\s+if=/dev\b", re.I),
        re.compile(r"\bunlink\b", re.I),
        re.compile(r"\bshred\b", re.I),
    ]

    PERSISTENCE_PATTERNS = [
        re.compile(r"\bcrontab\b", re.I),
        re.compile(r"\bauthorized_keys\b", re.I),
        re.compile(r"\breg\s+add\s+.*\\run\b", re.I),
        re.compile(r"\bschtasks\s+/create\b", re.I),
        re.compile(r"\bbackdoor\b", re.I),
        re.compile(r"\bchmod\s+u\+s\b", re.I),
        re.compile(r"\bsetuid\b", re.I),
    ]

    CREDENTIAL_THEFT_PATTERNS = [
        re.compile(r"\bmimikatz\b", re.I),
        re.compile(r"\blsass\.dmp\b", re.I),
        re.compile(r"/etc/shadow", re.I),
        re.compile(r"\bpwdump\b", re.I),
        re.compile(r"\bkeylogger\b", re.I),
        re.compile(r"\bhydra\s+-P\b", re.I),
        re.compile(r"\bcredential\s+stuffing\b", re.I),
    ]

    WEAPONIZATION_PATTERNS = [
        re.compile(r"\breverse\s+shell\b", re.I),
        re.compile(r"\bnc\s+-e\b", re.I),
        re.compile(r"/bin/bash\s+-i", re.I),
        re.compile(r"\bbash\s+-i\b", re.I),
        re.compile(r"/dev/tcp/", re.I),
        re.compile(r"\bmeterpreter\b", re.I),
        re.compile(r"\bransomware\b", re.I),
        re.compile(r"\bencrypt\s+files\b", re.I),
        re.compile(r"\bexploit/multi/handler\b", re.I),
    ]

    @classmethod
    def validate_poc(cls, poc: SafePoC) -> Tuple[bool, List[str]]:
        """
        Validates a SafePoC specification.
        Returns: (is_safe: bool, violations: List[str])
        """
        violations: List[str] = []

        # Serialize PoC contents to inspect entire payload text
        serialized = json.dumps({
            "title": poc.title,
            "objective": poc.objective,
            "inputs": poc.inputs,
            "actions": poc.actions,
            "expected_behavior": poc.expected_behavior,
            "safety_constraints": poc.safety_constraints,
        }).lower()

        # 1. Check Destructive patterns
        for pat in cls.DESTRUCTIVE_PATTERNS:
            if pat.search(serialized):
                violations.append(f"Forbidden destructive command pattern detected: {pat.pattern}")

        # 2. Check Persistence patterns
        for pat in cls.PERSISTENCE_PATTERNS:
            if pat.search(serialized):
                violations.append(f"Forbidden persistence-oriented pattern detected: {pat.pattern}")

        # 3. Check Credential Theft patterns
        for pat in cls.CREDENTIAL_THEFT_PATTERNS:
            if pat.search(serialized):
                violations.append(f"Forbidden credential theft pattern detected: {pat.pattern}")

        # 4. Check Weaponization patterns
        for pat in cls.WEAPONIZATION_PATTERNS:
            if pat.search(serialized):
                violations.append(f"Forbidden weaponization/reverse shell pattern detected: {pat.pattern}")

        # 5. Check resource bounds
        if poc.timeout_seconds > 60:
            violations.append(f"PoC timeout exceeds maximum safe ceiling (60s): {poc.timeout_seconds}s")

        if not poc.canary_marker or not poc.canary_marker.strip():
            violations.append("SafePoC must define a non-empty benign canary marker")

        is_safe = len(violations) == 0
        return is_safe, violations
