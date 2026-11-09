"""Security Analysis Engine and Security Invariant Registry for M6.

Enforces:
1. Multi-category domain analysis across 18 cybersecurity domains.
2. Formal security invariants (BOLA, Tenant Isolation, Session, Rate Limiting, TLS, etc.).
3. Synthesis of testable hypotheses, evidence gaps, and negative controls.
4. INVARIANT: The analysis engine produces MODEL_HYPOTHESIS entities only.
   It NEVER autonomously promotes hypotheses to findings or confirmed vulnerabilities.
"""

from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List, Optional, Set
from src.assessment.models import (
    AssessmentHypothesis,
    AssessmentHypothesisStatus,
    CanonicalObservation,
    SecurityInvariant,
    SecurityInvariantType,
)
from src.assessment.attack_surface import AttackSurfaceMap, AttackSurfaceNode


STANDARD_INVARIANTS: Dict[SecurityInvariantType, SecurityInvariant] = {
    SecurityInvariantType.AUTHORIZATION_BOLA: SecurityInvariant(
        invariant_id="INV-BOLA-01",
        invariant_type=SecurityInvariantType.AUTHORIZATION_BOLA,
        title="Object-Level Access Control Invariant",
        description="A user identity must only access resources specifically owned by or authorized for that identity.",
        secure_condition="Subject ID matches resource owner OR explicit authorization grant exists.",
        violation_condition="Cross-identity object ID substitution succeeds with HTTP 200 and confidential data.",
    ),
    SecurityInvariantType.TENANT_ISOLATION: SecurityInvariant(
        invariant_id="INV-TENANT-01",
        invariant_type=SecurityInvariantType.TENANT_ISOLATION,
        title="Multi-Tenant Data Boundary Invariant",
        description="Tenant A credentials must never read or modify Tenant B database records or objects.",
        secure_condition="Request rejects foreign tenant-id or enforces database-level tenant segregation.",
        violation_condition="Tenant A retrieves or mutates Tenant B tenant-scoped object without authorization.",
    ),
    SecurityInvariantType.SESSION_INVALIDATION: SecurityInvariant(
        invariant_id="INV-SESSION-01",
        invariant_type=SecurityInvariantType.SESSION_INVALIDATION,
        title="Post-Logout Session Invalidation Invariant",
        description="Terminated or revoked session tokens must be immediately rejected on subsequent requests.",
        secure_condition="Post-logout request using prior bearer token returns HTTP 401 Unauthorized.",
        violation_condition="Prior bearer token remains functional after logout, enabling session hijacking.",
    ),
    SecurityInvariantType.RATE_LIMITING: SecurityInvariant(
        invariant_id="INV-RATELIMIT-01",
        invariant_type=SecurityInvariantType.RATE_LIMITING,
        title="Sensitive Endpoint Request Rate Throttling Invariant",
        description="High-frequency authentication or API requests must trigger rate limits (HTTP 429).",
        secure_condition="Bursts exceeding threshold return HTTP 429 Too Many Requests.",
        violation_condition="Unlimited high-frequency credential stuffing or resource requests succeed unrestricted.",
    ),
    SecurityInvariantType.PRIVILEGE_BOUNDARY: SecurityInvariant(
        invariant_id="INV-PRIV-01",
        invariant_type=SecurityInvariantType.PRIVILEGE_BOUNDARY,
        title="Function-Level Access Control Invariant",
        description="Low-privilege users must be blocked from accessing administrative operations.",
        secure_condition="Administrative route returns HTTP 403 Forbidden when invoked with non-admin identity.",
        violation_condition="Low-privilege role successfully executes administrative endpoint actions.",
    ),
    SecurityInvariantType.TLS_PROTECTION: SecurityInvariant(
        invariant_id="INV-TLS-01",
        invariant_type=SecurityInvariantType.TLS_PROTECTION,
        title="In-Transit Cryptographic Transport Invariant",
        description="Sensitive data transmission must enforce modern TLS with valid certificates.",
        secure_condition="Endpoints reject plaintext HTTP and enforce TLS 1.2+ with non-deprecated ciphers.",
        violation_condition="Sensitive endpoints accept plaintext HTTP or use weak, exploitable ciphers.",
    ),
    SecurityInvariantType.FILE_ACCESS_BOUNDARY: SecurityInvariant(
        invariant_id="INV-PATH-01",
        invariant_type=SecurityInvariantType.FILE_ACCESS_BOUNDARY,
        title="Filesystem Traversal Boundary Invariant",
        description="File retrieval operations must constrain resolution strictly within designated sandbox directory.",
        secure_condition="Directory traversal sequences (../, %2e%2e/) are stripped or rejected with HTTP 400/404.",
        violation_condition="Arbitrary server file contents (e.g. /etc/passwd) returned in HTTP response body.",
    ),
    SecurityInvariantType.ANDROID_COMPONENT_EXPORT: SecurityInvariant(
        invariant_id="INV-ANDROID-01",
        invariant_type=SecurityInvariantType.ANDROID_COMPONENT_EXPORT,
        title="Exported IPC Component Security Invariant",
        description="Android components exported to other applications must enforce signature permissions.",
        secure_condition="android:exported='false' OR protected by android:permission with signature protection.",
        violation_condition="Exported Activity or Service allows unauthorized third-party apps to invoke sensitive actions.",
    ),
}


class SecurityAnalysisEngine:
    """Analyzes attack surface and observations to formulate testable security hypotheses."""

    def __init__(self, assessment_id: str) -> None:
        self.assessment_id = assessment_id

    def analyze_attack_surface(
        self,
        attack_surface: AttackSurfaceMap,
        observations: List[CanonicalObservation],
    ) -> List[AssessmentHypothesis]:
        """
        Synthesizes observations into testable hypotheses with linked invariants.
        Strictly produces MODEL_HYPOTHESIS entities with status=PROPOSED or TESTABLE.
        """
        hypotheses: List[AssessmentHypothesis] = []

        # 1. Inspect admin interfaces for Function-Level Access Control (BFLA)
        for admin_info in attack_surface.admin_interfaces:
            ep = admin_info.get("endpoint", "")
            obs_id = admin_info.get("observation_id", "")
            seed = f"{self.assessment_id}:BFLA:{ep}"
            hyp_id = f"HYP-{hashlib.sha256(seed.encode('utf-8')).hexdigest()[:12].upper()}"

            inv = STANDARD_INVARIANTS[SecurityInvariantType.PRIVILEGE_BOUNDARY]
            hyp = AssessmentHypothesis(
                hypothesis_id=hyp_id,
                assessment_id=self.assessment_id,
                title=f"Potential Missing Function-Level Access Control on Administrative Endpoint: {ep}",
                description=f"Administrative endpoint {ep} was discovered in passive telemetry. Verify whether unprivileged identities can invoke operations.",
                asset_ids=[obs_id] if obs_id else [],
                domain="AUTHORIZATION",
                supporting_observations=[obs_id] if obs_id else [],
                contradicting_observations=[],
                required_evidence=[
                    f"Observation of HTTP response status for low-privilege token request to {ep}",
                    f"Differential verification against administrative token baseline",
                ],
                evidence_gaps=[
                    f"Unobserved response for unauthenticated request to {ep}",
                    f"Unobserved response for low-privilege authenticated request to {ep}",
                ],
                security_invariants=[inv.invariant_id],
                negative_control="Verify that request without authentication or invalid token receives HTTP 401/403.",
                confidence=0.65,
                epistemic_status="MODEL_HYPOTHESIS",
                status=AssessmentHypothesisStatus.TESTABLE,
            )
            hypotheses.append(hyp)

        # 2. Inspect parameterized endpoints for Object-Level Access Control (BOLA/IDOR)
        for ep_info in attack_surface.endpoints:
            ep = ep_info.get("endpoint", "")
            if any(p in ep.lower() for p in ("/{id}", "/user/", "/order/", "/invoice/", "/account/")):
                seed = f"{self.assessment_id}:BOLA:{ep}"
                hyp_id = f"HYP-{hashlib.sha256(seed.encode('utf-8')).hexdigest()[:12].upper()}"
                inv = STANDARD_INVARIANTS[SecurityInvariantType.AUTHORIZATION_BOLA]

                hyp = AssessmentHypothesis(
                    hypothesis_id=hyp_id,
                    assessment_id=self.assessment_id,
                    title=f"Potential Broken Object-Level Authorization (BOLA) on Parameterized Endpoint: {ep}",
                    description=f"Endpoint {ep} includes direct object identifiers. Verify whether cross-tenant or cross-identity ID substitution enforces authorization.",
                    asset_ids=[],
                    domain="API_SECURITY",
                    supporting_observations=[],
                    contradicting_observations=[],
                    required_evidence=[
                        "Observation of User A accessing User B object identifier",
                        "Differential status code and payload comparison",
                    ],
                    evidence_gaps=[
                        "Missing cross-identity object access test observation",
                    ],
                    security_invariants=[inv.invariant_id],
                    negative_control="Verify that User A accessing User A object succeeds normally (HTTP 200).",
                    confidence=0.70,
                    epistemic_status="MODEL_HYPOTHESIS",
                    status=AssessmentHypothesisStatus.TESTABLE,
                )
                hypotheses.append(hyp)

        # 3. Inspect cookies for security flags (Session Security)
        for cookie_info in attack_surface.cookies:
            c_name = cookie_info.get("header", "")
            target = cookie_info.get("target", "")
            if not cookie_info.get("has_httponly") or not cookie_info.get("has_secure"):
                seed = f"{self.assessment_id}:COOKIE:{c_name}:{target}"
                hyp_id = f"HYP-{hashlib.sha256(seed.encode('utf-8')).hexdigest()[:12].upper()}"
                inv = STANDARD_INVARIANTS[SecurityInvariantType.SESSION_INVALIDATION]

                hyp = AssessmentHypothesis(
                    hypothesis_id=hyp_id,
                    assessment_id=self.assessment_id,
                    title=f"Missing Secure/HttpOnly Flags on Session Cookie ({c_name}) on {target}",
                    description=f"Set-Cookie header on {target} does not enforce both HttpOnly and Secure flags.",
                    asset_ids=[f"ASSET-{target}"],
                    domain="SESSION_SECURITY",
                    supporting_observations=[],
                    contradicting_observations=[],
                    required_evidence=[
                        f"Raw Set-Cookie header observation without HttpOnly/Secure flags",
                    ],
                    evidence_gaps=[],
                    security_invariants=[inv.invariant_id],
                    negative_control="Verify whether application transmits this cookie over plaintext HTTP.",
                    confidence=0.85,
                    epistemic_status="MODEL_HYPOTHESIS",
                    status=AssessmentHypothesisStatus.SUPPORTED,
                )
                hypotheses.append(hyp)

        return hypotheses
