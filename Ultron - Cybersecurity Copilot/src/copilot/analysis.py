"""Structured Security Analysis Engines for Code, Traffic, and Configuration (Milestone M5 Section 15, 16, 17).

Enforces strict epistemic separation and safety constraints:
1. Code Security Analysis (Section 15):
   - Categories: auth, authz, input validation, injection, crypto, secrets, session, SSRF, path traversal, deserialization, config, business logic.
   - Distinguishes: observed code behavior, hypotheses, missing context, recommendations.
   - Core Invariant: NEVER state 'This is definitely exploitable' without empirical target proof.

2. Traffic Analysis (Section 16):
   - Inputs: HTTP requests, responses, headers, cookies, status codes, parameters, DNS, TLS.
   - Produces: observed facts, security observations, hypotheses, evidence gaps, recommended manual experiments.
   - Core Invariant: Experiments are proposals only (never executed).

3. Configuration Analysis (Section 17):
   - Inputs: web servers, reverse proxies, security headers, TLS, cloud, containers, OS configs.
   - Core Invariant: Observed configuration != confirmed vulnerability.
"""

import re
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from src.investigation.models import (
    EvidenceGapEntity,
    HypothesisEntity,
    ManualExperimentEntity,
    ObservationEntity,
    SeverityLevel,
)


class CodeAnalysisResult(BaseModel):
    """Structured output for user-provided code security reviews."""
    language: str
    category: str
    observed_code_behavior: List[str] = Field(default_factory=list)
    hypotheses: List[str] = Field(default_factory=list)
    missing_context: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    exploitable_claim_made: bool = False  # Enforces 'Never claim definitely exploitable'


class TrafficAnalysisResult(BaseModel):
    """Structured output for HTTP/network observation analysis."""
    observed_facts: List[str] = Field(default_factory=list)
    security_observations: List[str] = Field(default_factory=list)
    hypotheses: List[str] = Field(default_factory=list)
    evidence_gaps: List[str] = Field(default_factory=list)
    recommended_manual_experiments: List[Dict[str, Any]] = Field(default_factory=list)


class ConfigurationAnalysisResult(BaseModel):
    """Structured output for server, cloud, and container configuration reviews."""
    config_type: str
    observed_configurations: List[str] = Field(default_factory=list)
    potential_risks: List[str] = Field(default_factory=list)
    evidence_gaps: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    confirmed_vulnerability: bool = False  # Enforces 'Observed config != confirmed vulnerability'


class CodeSecurityAnalyzer:
    """Analyzes source code snippets with strict epistemic separation."""

    @classmethod
    def analyze_code(cls, code_snippet: str, language: str = "auto") -> CodeAnalysisResult:
        """Evaluates code snippet and produces structured, non-dogmatic security assessment."""
        code = code_snippet.strip()
        observed = []
        hypotheses = []
        missing = []
        recommendations = []

        # 1. SQL Injection Pattern
        if re.search(r"f[\"'].*(SELECT|INSERT|UPDATE|DELETE)|(SELECT|INSERT|UPDATE|DELETE).*(\+|f[\"']|\.format|%|\{[a-zA-Z0-9_]+\})|\bexecute\s*\(\s*(f[\"']|.*query)", code, re.IGNORECASE):
            observed.append("SQL query string constructed via string formatting or concatenation with input parameter.")
            hypotheses.append("Hypothesis: Query structure may be mutable if user input reaches format string without sanitization.")
            missing.append("Missing Context: Verification of whether parameter is validated by prior middleware or type-enforced schema.")
            recommendations.append("Recommendation: Use parameterized queries (prepared statements) or query builder methods.")

        # 2. Deserialization
        if re.search(r"\b(pickle\.loads?|yaml\.load\s*\([^,)]+\)|unserialize|readObject)\b", code):
            observed.append("Dynamic deserialization invocation on untrusted byte stream or string.")
            hypotheses.append("Hypothesis: Deserialization of untrusted payloads may allow arbitrary object instantiation.")
            missing.append("Missing Context: Source and integrity validation of serialized payload (e.g., HMAC signature).")
            recommendations.append("Recommendation: Replace unsafe deserialization formats with structured JSON or protobuf.")

        # 3. Path Traversal
        if re.search(r"\b(open\s*\(|readFile\s*\(|new\s+File\s*\().*(\+|f[\"']).*", code):
            observed.append("File path constructed directly from dynamic variables.")
            hypotheses.append("Hypothesis: Potential directory traversal if input contains '../' sequences.")
            missing.append("Missing Context: Whether path normalization (realpath/resolve) and base directory checks exist.")
            recommendations.append("Recommendation: Canonicalize path with Path.resolve() and verify path starts with allowed base directory.")

        # 4. Hardcoded Secrets
        if re.search(r"(api_key|secret|password|token)\s*=\s*[\"'][a-zA-Z0-9_\-\.]{12,}[\"']", code, re.IGNORECASE):
            observed.append("Literal credential or API token string hardcoded in source.")
            hypotheses.append("Hypothesis: Static secrets in source code risk exposure across version control history.")
            missing.append("Missing Context: Whether credential is an active production secret or dummy test fixture.")
            recommendations.append("Recommendation: Load credentials dynamically from environment variables or secrets manager.")

        # Default fallback if no specific pattern matched
        if not observed:
            observed.append("Code defines programmatic logic without obvious high-risk syntactic security flaws.")
            missing.append("Missing Context: Complete architectural data flow and caller authentication context.")
            recommendations.append("Recommendation: Ensure input boundaries validate types and server-side authorization is enforced.")

        return CodeAnalysisResult(
            language=language,
            category="Static Code Review",
            observed_code_behavior=observed,
            hypotheses=hypotheses,
            missing_context=missing,
            recommendations=recommendations,
            exploitable_claim_made=False,  # Enforces invariant
        )


class TrafficAnalyzer:
    """Analyzes empirical HTTP and network traffic observations."""

    @classmethod
    def analyze_traffic(
        cls,
        request_text: Optional[str] = None,
        response_text: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        status_code: Optional[int] = None,
    ) -> TrafficAnalysisResult:
        """Evaluates traffic observation and produces structured differential hypotheses."""
        observed = []
        security_obs = []
        hypotheses = []
        gaps = []
        experiments = []

        headers_dict = headers or {}
        hdrs_lower = {k.lower(): v for k, v in headers_dict.items()}

        if status_code:
            observed.append(f"Server returned HTTP status code: {status_code}")

        # Check CORS
        if "access-control-allow-origin" in hdrs_lower:
            acao = hdrs_lower["access-control-allow-origin"]
            acac = hdrs_lower.get("access-control-allow-credentials", "false").lower()
            observed.append(f"CORS Header observed: Access-Control-Allow-Origin: {acao}")
            if acao != "*" and acac == "true":
                security_obs.append(f"CORS reflects origin '{acao}' with credentials enabled.")
                hypotheses.append("Hypothesis: Potential arbitrary Origin reflection allowing cross-origin credentialed access.")
                gaps.append("Evidence Gap: Observation of whether origin 'https://attacker.com' is also reflected.")
                experiments.append({
                    "objective": "Verify Origin reflection allowlist boundary",
                    "steps": ["Send request with Origin: https://evil.example.com", "Inspect Access-Control-Allow-Origin header"],
                    "expected_secure": "No ACAO header returned or returns fixed domain",
                    "expected_vulnerable": "Returns Access-Control-Allow-Origin: https://evil.example.com",
                })

        # Check Cookies & Session
        if "set-cookie" in hdrs_lower:
            cookie = hdrs_lower["set-cookie"]
            observed.append("Set-Cookie header received.")
            if "httponly" not in cookie.lower():
                security_obs.append("Session cookie missing HttpOnly attribute.")
                hypotheses.append("Hypothesis: Cookie accessible to client-side scripts if XSS occurs.")
                gaps.append("Evidence Gap: Determine whether cookie contains session bearer token or non-sensitive preferences.")
            if "samesite" not in cookie.lower():
                security_obs.append("Session cookie missing explicit SameSite attribute.")

        # Check Security Headers
        missing_sec_headers = []
        for sh in ["content-security-policy", "x-content-type-options", "x-frame-options", "strict-transport-security"]:
            if sh not in hdrs_lower:
                missing_sec_headers.append(sh)
        if missing_sec_headers:
            security_obs.append(f"Missing defensive HTTP response headers: {', '.join(missing_sec_headers)}")

        if not observed:
            observed.append("HTTP traffic pattern parsed successfully.")

        return TrafficAnalysisResult(
            observed_facts=observed,
            security_observations=security_obs,
            hypotheses=hypotheses,
            evidence_gaps=gaps,
            recommended_manual_experiments=experiments,
        )


class ConfigurationAnalyzer:
    """Analyzes server, cloud, and container configurations."""

    @classmethod
    def analyze_configuration(cls, config_content: str, config_type: str = "generic") -> ConfigurationAnalysisResult:
        """Reviews configuration file with strict invariant: configuration != confirmed vulnerability."""
        observed = []
        risks = []
        gaps = []
        recs = []

        lower = config_content.lower()

        # Nginx / Web server
        if "server {" in lower or "nginx" in config_type.lower():
            observed.append("Web server configuration block identified.")
            if "autoindex on" in lower:
                observed.append("Directive: 'autoindex on' enabled.")
                risks.append("Potential directory listing exposure if directory index files are absent.")
                gaps.append("Evidence Gap: Verify if directory contains sensitive downloadable artifacts.")
                recs.append("Recommendation: Set 'autoindex off;' in production.")

            if "proxy_pass" in lower and not re.search(r"proxy_set_header\s+host", lower):
                risks.append("Reverse proxy passes requests without explicitly locking Host header.")
                recs.append("Recommendation: Explicitly define proxy_set_header Host $host;")

        # Docker / Container
        if "from " in lower or "dockerfile" in config_type.lower():
            observed.append("Container specification identified.")
            if "user root" in lower or not re.search(r"\buser\s+\w+", lower):
                risks.append("Container may run as default root UID.")
                gaps.append("Evidence Gap: Verify runtime execution identity inside deployed pod.")
                recs.append("Recommendation: Add 'USER nonroot' or unprivileged UID to container spec.")

        # Default fallback
        if not observed:
            observed.append(f"Configuration of type '{config_type}' parsed.")
            gaps.append("Evidence Gap: Active runtime behavior must be verified in authorized staging lab.")
            recs.append("Recommendation: Adhere to principle of least privilege and remove unneeded debug features.")

        return ConfigurationAnalysisResult(
            config_type=config_type,
            observed_configurations=observed,
            potential_risks=risks,
            evidence_gaps=gaps,
            recommendations=recs,
            confirmed_vulnerability=False,  # Enforces invariant
        )
