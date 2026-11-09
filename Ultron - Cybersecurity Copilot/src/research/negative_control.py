"""Domain-Aware Negative-Control and Counterfactual Guidance Layer (Milestone M5 Section 24).

Solves the semantic retrieval false-positive problem by pairing positive vulnerability methodology
with explicit negative-evidence, counterfactual context, and falsification conditions:
- Positive hypothesis explanation
- Legitimate / Benign operational explanations
- Concrete negative control test cases
- Deterministic falsification conditions
- Required missing evidence before declaring a hypothesis credible

Domain-aware across all 26 security domains.
"""

from typing import Dict, List, Optional
from src.copilot.domain import SecurityDomain
from src.research.models import NegativeControlGuidance


class NegativeControlEngine:
    """Provides structured counterfactual and negative-control guidance for security reasoning."""

    GUIDANCE_CATALOG: Dict[str, NegativeControlGuidance] = {
        "BOLA": NegativeControlGuidance(
            guidance_id="NCG-BOLA-001",
            topic="Broken Object Level Authorization (BOLA/IDOR)",
            legitimate_explanations=[
                "The endpoint is intentionally public (e.g. public directory, marketing catalog, public profile).",
                "The requested resource belongs to a global shared workspace intentionally visible to all tenants.",
                "Actor credentials belong to a cross-tenant auditor or system admin authorized by policy.",
            ],
            negative_control_checks=[
                "Perform request with unauthenticated client to verify whether the object is publicly readable.",
                "Test accessing a known private object belonging to an unrelated tenant to establish the boundary.",
                "Verify if the endpoint strictly permits READ operations while rejecting state-altering MUTATIONS (PUT/POST/DELETE).",
            ],
            falsification_conditions=[
                "If accessing another tenant's object returns HTTP 403 Forbidden or HTTP 404 Not Found, cross-tenant isolation holds.",
                "If the resource metadata confirms the object is marked public or shared, the hypothesis is disproved.",
            ],
            required_missing_evidence=[
                "Evidence that the requested object contains confidential private data of another tenant.",
                "Evidence that Tenant B never granted explicit sharing permission to Tenant A.",
            ],
        ),
        "BFLA": NegativeControlGuidance(
            guidance_id="NCG-BFLA-001",
            topic="Broken Function Level Authorization (BFLA)",
            legitimate_explanations=[
                "The function is intentionally accessible to standard users for self-service actions.",
                "Role escalation occurred through an authorized invitation, delegation, or administrative grant.",
                "The endpoint only reads non-sensitive status metrics rather than mutating system state.",
            ],
            negative_control_checks=[
                "Execute the same function using an unprivileged or guest identity.",
                "Attempt destructive mutations (e.g. DELETE/PUT) rather than simple status queries.",
            ],
            falsification_conditions=[
                "If non-admin identities receive HTTP 403 Forbidden when invoking the endpoint, role hierarchy is intact.",
                "If the function does not alter privileged state or access administrative records, BFLA is falsified.",
            ],
            required_missing_evidence=[
                "Evidence of a lower-privileged role successfully altering administrative configurations.",
                "Evidence that the endpoint was documented as administrative-only.",
            ],
        ),
        "TENANT_ISOLATION": NegativeControlGuidance(
            guidance_id="NCG-TENANT-001",
            topic="Multi-Tenant Isolation",
            legitimate_explanations=[
                "The tenant identifier is used strictly for public branding/catalog lookup.",
                "The resource is a global template or standard platform asset.",
            ],
            negative_control_checks=[
                "Test with an invalid/random tenant ID to verify server response format.",
                "Verify whether data returned contains private tenant records or only metadata.",
            ],
            falsification_conditions=[
                "If cross-tenant requests fail or return empty datasets, isolation invariant holds.",
            ],
            required_missing_evidence=[
                "Evidence that data from Tenant B was exposed to Tenant A without authorization.",
            ],
        ),
        "OAUTH": NegativeControlGuidance(
            guidance_id="NCG-OAUTH-001",
            topic="OAuth 2.0 / OIDC Authorization Code & PKCE",
            legitimate_explanations=[
                "Client is a confidential server-side web app utilizing client_secret rather than public PKCE.",
                "State parameter verification is enforced via encrypted SameSite session cookies.",
            ],
            negative_control_checks=[
                "Test code exchange without code_verifier from a public client.",
                "Test authorization callback without valid state parameter.",
            ],
            falsification_conditions=[
                "If the authorization server rejects code exchange without valid PKCE or returns invalid_grant, OAuth flow is secure.",
            ],
            required_missing_evidence=[
                "Evidence that authorization code can be exchanged without client authentication or code_verifier.",
            ],
        ),
        "RATE_LIMITING": NegativeControlGuidance(
            guidance_id="NCG-RATELIMIT-001",
            topic="Rate Limiting & Anti-Automation",
            legitimate_explanations=[
                "Low request volumes during testing did not exceed the operational threshold.",
                "The endpoint is behind an asynchronous queue or cached CDN layer.",
            ],
            negative_control_checks=[
                "Send requests at a rate exceeding the declared SLA to test 429 Too Many Requests response.",
            ],
            falsification_conditions=[
                "If the server emits HTTP 429 Too Many Requests or drops traffic, rate limiting is functioning.",
            ],
            required_missing_evidence=[
                "Evidence of sustained high-velocity requests without throttling or defensive backoff.",
            ],
        ),
        "CORS": NegativeControlGuidance(
            guidance_id="NCG-CORS-001",
            topic="Cross-Origin Resource Sharing (CORS) Misconfiguration",
            legitimate_explanations=[
                "The API endpoint is public and serves non-sensitive promotional or static content.",
                "Access-Control-Allow-Credentials header is absent or set to false.",
            ],
            negative_control_checks=[
                "Check if Access-Control-Allow-Credentials: true is returned with the reflected origin.",
                "Verify if authenticated user cookies are transmitted on the cross-origin fetch.",
            ],
            falsification_conditions=[
                "If Access-Control-Allow-Credentials is false or omitted, browser will not expose sensitive response data.",
                "If Origin reflection is restricted to exact trusted domains, CORS is secure.",
            ],
            required_missing_evidence=[
                "Evidence that private session cookies or Bearer tokens are exposed across unauthorized origins.",
            ],
        ),
        "SQLI": NegativeControlGuidance(
            guidance_id="NCG-SQLI-001",
            topic="SQL Injection (SQLi)",
            legitimate_explanations=[
                "Database error string is reflected from an application logging wrapper without altering query grammar.",
                "Input parameter is passed via a parameterized prepared statement with type binding.",
            ],
            negative_control_checks=[
                "Test boolean differential payloads (e.g., AND 1=1 vs AND 1=2) and compare response lengths.",
                "Test sleep/time-delay payloads to detect asynchronous query execution.",
            ],
            falsification_conditions=[
                "If both AND 1=1 and AND 1=2 return identical responses or identical errors, syntax was not evaluated as SQL.",
                "If database framework logs prove parameter binding, SQLi hypothesis is falsified.",
            ],
            required_missing_evidence=[
                "Evidence of observable changes in database response or query execution time driven by injected SQL syntax.",
            ],
        ),
        "SSRF": NegativeControlGuidance(
            guidance_id="NCG-SSRF-001",
            topic="Server-Side Request Forgery (SSRF)",
            legitimate_explanations=[
                "The server verifies webhook URLs against an internal DNS resolver and blocks RFC 1918 addresses.",
                "The outbound request is handled by a sandboxed proxy with egress filtering.",
            ],
            negative_control_checks=[
                "Request internal loopback (127.0.0.1) and cloud metadata (169.254.169.254).",
                "Test with DNS rebinding or redirect chains to verify secondary resolver checks.",
            ],
            falsification_conditions=[
                "If backend client throws connection refused or blocks private IP ranges with 400 Bad Request, egress filtering is active.",
            ],
            required_missing_evidence=[
                "Evidence of inbound TCP connection received by internal target or metadata response body returned.",
            ],
        ),
        "ANDROID_COMPONENT": NegativeControlGuidance(
            guidance_id="NCG-ANDROID-001",
            topic="Android Exported Component Vulnerability",
            legitimate_explanations=[
                "The activity is the main launcher activity (android.intent.action.MAIN) intentionally accessible.",
                "The component enforces custom signature-level permissions required by system applications.",
            ],
            negative_control_checks=[
                "Inspect manifest for android:permission attribute and protectionLevel='signature'.",
                "Invoke component from a third-party unprivileged application identity.",
            ],
            falsification_conditions=[
                "If calling the exported component results in SecurityException, permission check is active.",
                "If component contains no state-altering operations or sensitive data leakage, vulnerability is falsified.",
            ],
            required_missing_evidence=[
                "Evidence that unprivileged external apps can execute privileged functions or leak data via intent extras.",
            ],
        ),
    }

    @classmethod
    def get_guidance(
        cls,
        query_or_category: str,
        domain: Optional[SecurityDomain] = None,
    ) -> List[NegativeControlGuidance]:
        """Returns relevant domain-aware negative-control guidance."""
        text = query_or_category.upper()
        results: List[NegativeControlGuidance] = []

        if domain == SecurityDomain.ANDROID_SECURITY or "ANDROID" in text or "APK" in text:
            results.append(cls.GUIDANCE_CATALOG["ANDROID_COMPONENT"])

        if domain == SecurityDomain.CLOUD_SECURITY or "SSRF" in text or "METADATA" in text:
            results.append(cls.GUIDANCE_CATALOG["SSRF"])

        if domain == SecurityDomain.SECURE_CODING or "SQL" in text or "INJECTION" in text:
            results.append(cls.GUIDANCE_CATALOG["SQLI"])

        if "CORS" in text or "ORIGIN" in text:
            results.append(cls.GUIDANCE_CATALOG["CORS"])

        if "BOLA" in text or "IDOR" in text or "OBJECT" in text:
            results.append(cls.GUIDANCE_CATALOG["BOLA"])

        if "BFLA" in text or "ROLE" in text or "FUNCTION" in text or "ADMIN" in text:
            results.append(cls.GUIDANCE_CATALOG["BFLA"])

        if "TENANT" in text or "ISOLATION" in text:
            results.append(cls.GUIDANCE_CATALOG["TENANT_ISOLATION"])

        if "OAUTH" in text or "PKCE" in text or "OIDC" in text or "TOKEN" in text:
            results.append(cls.GUIDANCE_CATALOG["OAUTH"])

        if "RATE" in text or "LIMIT" in text or "BRUTE" in text:
            results.append(cls.GUIDANCE_CATALOG["RATE_LIMITING"])

        if not results:
            results.append(cls.GUIDANCE_CATALOG["BOLA"])

        return results
