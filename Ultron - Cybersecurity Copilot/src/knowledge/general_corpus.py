"""General Cybersecurity Knowledge Corpus (Milestone M5 Section 12-13).

Expands the local knowledge base beyond authorization into broad cybersecurity domains:
- HTTP, DNS, TLS, Protocols
- Authentication, Authorization, Sessions, JWT, OAuth, OpenID Connect
- Web & API Security (CORS, CSRF, XSS, SSRF, SQLi, Command Injection, Path Traversal,
  File Upload, Deserialization, Prototype Pollution, Request Smuggling, Cache Poisoning, Race Conditions)
- Cryptography & Secrets Management
- Cloud & Container Security
- Linux & Windows Security, Active Directory
- Android & Mobile Security
- Secure Coding & Tool Guidance

Each item preserves strict provenance and immutable content hashes.
"""

import hashlib
from typing import Dict, List, Optional
from pydantic import BaseModel

from src.copilot.domain import SecurityDomain
from src.knowledge.models import (
    KnowledgeChunk,
    KnowledgeSourceType,
    KnowledgeType,
)


class GeneralSecurityKnowledgeCorpus:
    """Provides curated high-quality local cybersecurity knowledge chunks."""

    _CHUNKS: List[KnowledgeChunk] = []

    @classmethod
    def _create_chunk(
        cls,
        doc_id: str,
        sec_idx: int,
        title: str,
        section_heading: str,
        content: str,
        ktype: KnowledgeType,
        domain: SecurityDomain,
        tags: List[str],
    ) -> KnowledgeChunk:
        content_clean = content.strip()
        chash = hashlib.sha256(content_clean.encode("utf-8")).hexdigest()
        chunk_id = f"CHK-GEN-{doc_id}-{sec_idx:03d}-01"
        return KnowledgeChunk(
            chunk_id=chunk_id,
            document_id=f"DOC-GEN-{doc_id}",
            source_type=KnowledgeSourceType.PLATFORM_INVARIANT,
            knowledge_type=ktype,
            category_tags=tags + [domain.value],
            title=title,
            section_heading=section_heading,
            content=content_clean,
            token_estimate=len(content_clean.split()),
            content_hash=chash,
            trust_tier="CURATED_ADVISORY",
        )

    @classmethod
    def get_all_chunks(cls) -> List[KnowledgeChunk]:
        """Returns all curated general knowledge chunks."""
        if not cls._CHUNKS:
            cls._initialize_corpus()
        return list(cls._CHUNKS)

    @classmethod
    def find_chunks_by_domain(cls, domain: SecurityDomain) -> List[KnowledgeChunk]:
        """Returns chunks relevant to a specific security domain."""
        all_chunks = cls.get_all_chunks()
        return [c for c in all_chunks if domain.value in c.category_tags]

    @classmethod
    def _initialize_corpus(cls) -> None:
        """Seeds curated multi-domain cybersecurity knowledge."""
        chunks: List[KnowledgeChunk] = []

        # 1. HTTP & Request Smuggling
        chunks.append(
            cls._create_chunk(
                doc_id="HTTP-SMUGGLING",
                sec_idx=1,
                title="HTTP Request Smuggling Invariants (CL.TE / TE.CL)",
                section_heading="HTTP Protocol Desync",
                content=(
                    "HTTP Request Smuggling arises when front-end reverse proxies and backend servers disagree "
                    "on message boundary delineation using Content-Length and Transfer-Encoding headers. "
                    "Security Invariant: When both Content-Length and Transfer-Encoding are present in HTTP/1.1, "
                    "RFC 7230 Section 3.3.3 mandates that Transfer-Encoding overrides Content-Length. "
                    "Testing Methodology: Differential timeout probing without executing second-order state mutations."
                ),
                ktype=KnowledgeType.SECURITY_INVARIANT,
                domain=SecurityDomain.NETWORK_PROTOCOLS,
                tags=["http", "smuggling", "rfc7230", "desync"],
            )
        )

        # 2. DNS & Rebinding
        chunks.append(
            cls._create_chunk(
                doc_id="DNS-REBINDING",
                sec_idx=1,
                title="DNS Rebinding and Origin Boundary Defenses",
                section_heading="DNS Name Resolution Security",
                content=(
                    "DNS Rebinding exploits short TTL records where an attacker domain initially resolves to a public IP "
                    "and subsequently resolves to loopback (127.0.0.1) or RFC 1918 private IP addresses. "
                    "Security Invariant: Internal service listeners must validate the HTTP Host header against an explicit "
                    "server name allowlist rather than trusting socket origin alone. "
                    "Mitigation: Implement DNS pinning and strict Host header validation."
                ),
                ktype=KnowledgeType.SECURITY_INVARIANT,
                domain=SecurityDomain.NETWORK_PROTOCOLS,
                tags=["dns", "rebinding", "host_header", "ssrf"],
            )
        )

        # 3. TLS & Cipher Suites
        chunks.append(
            cls._create_chunk(
                doc_id="TLS-SECURITY",
                sec_idx=1,
                title="TLS 1.3 Handshake and Cipher Suite Configuration",
                section_heading="Transport Layer Security",
                content=(
                    "TLS 1.3 eliminates vulnerable cryptographic primitives including static RSA key exchange, "
                    "CBC mode ciphers, and arbitrary renegotiation. All key exchanges in TLS 1.3 enforce Forward Secrecy "
                    "using ECDHE or DHE. "
                    "Testing Methodology: Check server hello response for negotiated cipher suite and ALPN support. "
                    "False Positive Guidance: Self-signed certificates in isolated staging environments do not imply production risk."
                ),
                ktype=KnowledgeType.SECURE_CONFIGURATION,
                domain=SecurityDomain.TLS_SECURITY,
                tags=["tls", "handshake", "cipher_suite", "pfs"],
            )
        )

        # 4. JWT & Algorithm Enforcement
        chunks.append(
            cls._create_chunk(
                doc_id="JWT-ALGORITHM",
                sec_idx=1,
                title="JSON Web Token (JWT) Algorithm Verification Invariant",
                section_heading="JWT Cryptographic Verification",
                content=(
                    "JWT signature verification must be asymmetric and strictly bound to the expected algorithm family. "
                    "Security Invariant: The verifier must explicitly reject tokens specifying 'alg': 'none' or mismatched "
                    "HMAC keys derived from public RSA keys (key confusion / algorithm confusion attacks). "
                    "Testing Protocol: Submit token with 'none' alg or tampered signature; observe whether server returns HTTP 401 Unauthorized."
                ),
                ktype=KnowledgeType.SECURITY_INVARIANT,
                domain=SecurityDomain.AUTHENTICATION,
                tags=["jwt", "token", "signature", "algorithm_confusion"],
            )
        )

        # 5. OAuth 2.0 & PKCE
        chunks.append(
            cls._create_chunk(
                doc_id="OAUTH-PKCE",
                sec_idx=1,
                title="OAuth 2.0 PKCE and Exact Redirect URI Matching",
                section_heading="OAuth Authorization Code Flow",
                content=(
                    "Proof Key for Code Exchange (RFC 7636) prevents authorization code interception in public and single-page apps. "
                    "Security Invariant: The authorization server must mandate code_challenge and code_challenge_method=S256. "
                    "Redirect URI Validation Invariant: Redirect URIs must be validated using exact string matching. Partial matching, "
                    "subdomain wildcards, and path traversals in callback URLs are forbidden by OAuth 2.1."
                ),
                ktype=KnowledgeType.SECURITY_INVARIANT,
                domain=SecurityDomain.AUTHENTICATION,
                tags=["oauth", "pkce", "redirect_uri", "rfc7636"],
            )
        )

        # 6. CORS & Origin Reflections
        chunks.append(
            cls._create_chunk(
                doc_id="CORS-SECURITY",
                sec_idx=1,
                title="CORS Access-Control-Allow-Origin Configuration Invariant",
                section_heading="Cross-Origin Resource Sharing",
                content=(
                    "CORS relaxes the Same-Origin Policy when explicitly instructed by server headers. "
                    "Security Invariant: A server must never dynamically reflect the untrusted client 'Origin' header into "
                    "Access-Control-Allow-Origin while simultaneously returning 'Access-Control-Allow-Credentials: true'. "
                    "Mitigation: Validate Origin against an immutable server-side allowlist of trusted partner domains."
                ),
                ktype=KnowledgeType.SECURITY_INVARIANT,
                domain=SecurityDomain.WEB_APPLICATION_SECURITY,
                tags=["cors", "origin", "credentials", "sop"],
            )
        )

        # 7. SSRF & Cloud Metadata
        chunks.append(
            cls._create_chunk(
                doc_id="SSRF-METADATA",
                sec_idx=1,
                title="Server-Side Request Forgery and Cloud Instance Metadata (IMDSv2)",
                section_heading="SSRF Protection Architecture",
                content=(
                    "Server-Side Request Forgery allows an attacker to coerce backend network requests to internal systems. "
                    "Cloud Security Invariant: Cloud instance metadata endpoints (169.254.169.254) must require session token headers "
                    "(IMDSv2 PUT X-aws-ec2-metadata-token) to prevent unauthorized credential exfiltration via blind SSRF. "
                    "Mitigation: Block loopback and link-local ranges at the application HTTP client layer."
                ),
                ktype=KnowledgeType.MITIGATION,
                domain=SecurityDomain.CLOUD_SECURITY,
                tags=["ssrf", "imds", "metadata", "aws", "cloud"],
            )
        )

        # 8. SQL Injection & Parameterization
        chunks.append(
            cls._create_chunk(
                doc_id="SQLI-PARAMETRIZATION",
                sec_idx=1,
                title="SQL Injection Prevention via Contextual Parameterization",
                section_heading="Database Query Security",
                content=(
                    "SQL Injection occurs when untrusted user input alters database query structure. "
                    "Code Security Pattern: Use parameterized prepared statements or compile-time typed ORMs. "
                    "Security Invariant: String concatenation or format string interpolation in SQL query construction is strictly prohibited. "
                    "Negative Control: Database error messages alone do not confirm exploitability without proof of query structure modification."
                ),
                ktype=KnowledgeType.CODE_SECURITY_PATTERN,
                domain=SecurityDomain.SECURE_CODING,
                tags=["sqli", "prepared_statements", "parameterized", "orm"],
            )
        )

        # 9. Container Security & Capabilities
        chunks.append(
            cls._create_chunk(
                doc_id="CONTAINER-SECURITY",
                sec_idx=1,
                title="Container Boundary Invariants and Linux Capability Dropping",
                section_heading="Container Runtime Isolation",
                content=(
                    "Containers share the host Linux kernel and rely on namespaces and cgroups for process isolation. "
                    "Security Invariant: Containers must not run with privileged mode (--privileged) or CAP_SYS_ADMIN capabilities. "
                    "Root filesystem should be mounted read-only with a non-root UID. "
                    "Escape Vectors: Exposed /var/run/docker.sock, hostPID sharing, or unconfined seccomp profiles."
                ),
                ktype=KnowledgeType.SECURE_CONFIGURATION,
                domain=SecurityDomain.CONTAINER_SECURITY,
                tags=["docker", "kubernetes", "cgroups", "capabilities", "escape"],
            )
        )

        # 10. Android & Mobile Component Security
        chunks.append(
            cls._create_chunk(
                doc_id="ANDROID-COMPONENTS",
                sec_idx=1,
                title="Android IPC Security: Exported Activities and Broadcast Receivers",
                section_heading="Android App Manifest Security",
                content=(
                    "Android components (Activities, Services, Broadcast Receivers, Content Providers) can be invoked across applications. "
                    "Security Invariant: Any component declared with android:exported='true' must either enforce custom signature-level "
                    "permissions or perform strict caller identity validation (Binder.getCallingUid()). "
                    "Testing Methodology: Use adb am start or jadx analysis to verify if exported components accept arbitrary intent extras."
                ),
                ktype=KnowledgeType.TESTING_METHODOLOGY,
                domain=SecurityDomain.ANDROID_SECURITY,
                tags=["android", "apk", "manifest", "intent", "broadcast_receiver"],
            )
        )

        # 11. Active Directory & Kerberos
        chunks.append(
            cls._create_chunk(
                doc_id="AD-KERBEROS",
                sec_idx=1,
                title="Active Directory Kerberos Invariants and Kerberoasting Defenses",
                section_heading="Active Directory Security",
                content=(
                    "Kerberos uses Service Principal Names (SPNs) associated with domain user accounts for service ticket issuance. "
                    "Attack Surface: Accounts with SPNs can be requested by any authenticated domain user and brute-forced offline (Kerberoasting). "
                    "Mitigation: Use Group Managed Service Accounts (gMSA) with 128-character rotating passwords and AES-256 Kerberos encryption."
                ),
                ktype=KnowledgeType.MITIGATION,
                domain=SecurityDomain.ACTIVE_DIRECTORY,
                tags=["active_directory", "kerberos", "spn", "kerberoasting", "gmsa"],
            )
        )

        # 12. Security Tooling - Burp Suite & Nmap
        chunks.append(
            cls._create_chunk(
                doc_id="TOOL-BURP-NMAP",
                sec_idx=1,
                title="Security Tooling Guidance: Burp Suite and Nmap Safe Usage",
                section_heading="Diagnostic Security Tool Guidance",
                content=(
                    "Tool Guidance: Burp Suite is an intercepting HTTP proxy for manual differential traffic analysis. "
                    "Safe Usage: Restrict Burp Suite Target Scope to authorized assets; disable automatic crawl and active scanner against production. "
                    "Nmap: Port scanner for service discovery. Safe Lab Flags: -sS (SYN stealth), -sV (version detection), -Pn (no ping). "
                    "Defensive Implication: High rate scanning triggers IDS/WAF IP reputation throttling and produces operational noise."
                ),
                ktype=KnowledgeType.TOOL_GUIDANCE,
                domain=SecurityDomain.SECURITY_TOOLING,
                tags=["burp", "nmap", "tool_guidance", "scope", "flags"],
            )
        )

        cls._CHUNKS = chunks
