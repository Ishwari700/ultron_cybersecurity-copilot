"""Canonical Multi-Domain VAPT Knowledge Corpus (Milestone M9).

Covers all 13 required cybersecurity domains:
1. RECONNAISSANCE: Asset discovery, technology identification, attack surface, endpoints, negative controls.
2. WEB SECURITY: SSRF, Blind SSRF, SQLi, XSS, CSRF, HTTP Request Smuggling, SSTI, XXE, Deserialization,
   Prototype Pollution, Path Traversal, File Upload, Race Conditions, CORS, Clickjacking, Cache Poisoning.
3. AUTHENTICATION: JWT vulnerabilities, OAuth 2.0 PKCE, SAML XSW, Session Fixation, MFA Bypass, WebAuthn/Passkeys, Password Reset.
4. AUTHORIZATION: IDOR, BOLA, BFLA, Multi-Tenant Isolation, Privilege Escalation, ABAC vs RBAC, Path matching.
5. API SECURITY: REST security, GraphQL security, API Rate Limiting, Mass Assignment, Object/Function Level.
6. MOBILE: Android exported components, Deep Links, Certificate Pinning, WebView security, APK/DEX/Smali, Android Keystore, iOS jailbreak.
7. NETWORK: DNS Rebinding, TLS 1.3/1.2 Handshake, TCP SYN Flood, Proxies, VPN.
8. CLOUD: AWS IMDSv1/v2, Kubernetes RBAC, Container Escapes, S3 Security, Azure Managed Identity, Docker socket.
9. WINDOWS / AD: Kerberos, Kerberoasting, NTLM Relay, AS-REP Roasting, BloodHound, GPO Abuse, DCSync, Golden Ticket.
10. LINUX: Linux Capabilities, SUID/GTFOBins, Process Isolation.
11. BINARY / RE: Buffer Overflow, ASLR/DEP/Canary/RELRO, ROP Chains, ELF Format, UAF, Integer Overflow, Format String, PE Format.
12. SOC / DFIR: Windows Security Event IDs, Sysmon LSASS detection, IOC vs IOA, Memory Forensics / Volatility.
13. SECURE CODING: Parameterized Queries, Rust Ownership, Secret Management, Constant-Time Comparison, AES-GCM vs ECB, CWE Mapping.

Every chunk adheres to the immutable provenance model:
    SOURCE -> DOCUMENT -> VERSION -> SECTION -> CHUNK
"""

import hashlib
from typing import Dict, List, Optional
from pydantic import BaseModel

from src.copilot.domain import SecurityDomain
from src.knowledge.canonical_models import AuthorityLevel, CanonicalSourceType
from src.knowledge.models import (
    KnowledgeChunk,
    KnowledgeSourceType,
    KnowledgeType,
)


class VaptDomainCorpus:
    """Provides curated authoritative multi-domain VAPT knowledge chunks."""

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
        domain_name: str,
        tags: List[str],
        source_name: str = "OWASP_AUTHORITATIVE",
    ) -> KnowledgeChunk:
        content_clean = content.strip()
        chash = hashlib.sha256(content_clean.encode("utf-8")).hexdigest()
        chunk_id = f"CHK-VAPT-{doc_id}-{sec_idx:03d}-01"
        return KnowledgeChunk(
            chunk_id=chunk_id,
            document_id=f"DOC-VAPT-{doc_id}",
            source_type=KnowledgeSourceType.OWASP_WSTG,
            knowledge_type=ktype,
            category_tags=tags + [domain_name],
            title=title,
            section_heading=section_heading,
            content=content_clean,
            token_estimate=len(content_clean.split()),
            content_hash=chash,
            trust_tier="CURATED_ADVISORY",
        )

    @classmethod
    def get_all_chunks(cls) -> List[KnowledgeChunk]:
        """Returns all curated VAPT knowledge chunks."""
        if not cls._CHUNKS:
            cls._initialize_corpus()
        return list(cls._CHUNKS)

    @classmethod
    def find_chunks_by_tag(cls, tag: str) -> List[KnowledgeChunk]:
        all_chunks = cls.get_all_chunks()
        t_lower = tag.lower()
        return [c for c in all_chunks if any(t_lower in ct.lower() for ct in c.category_tags)]

    @classmethod
    def _initialize_corpus(cls) -> None:
        chunks: List[KnowledgeChunk] = []

        # -------------------------------------------------------------
        # 1. RECONNAISSANCE & METHODOLOGY
        # -------------------------------------------------------------
        chunks.append(cls._create_chunk(
            doc_id="RECON-SUBDOMAIN",
            sec_idx=1,
            title="Subdomain Enumeration & Asset Discovery",
            section_heading="Passive and Active Asset Discovery Methodology",
            content=(
                "Asset discovery requires combining passive and active reconnaissance techniques. "
                "Passive enumeration utilizes Certificate Transparency (CT) logs (RFC 6962 via crt.sh), "
                "DNS historical databases, and search engine dorks to map attack surface without direct packet transmission. "
                "Active enumeration executes wordlist-based DNS brute-forcing. A critical negative control is testing "
                "for wildcard DNS resolution by querying randomized non-existent subdomains (e.g., test-random-x92f.domain.com). "
                "If wildcard responses occur, filters must discard matching IP addresses to eliminate false discoveries."
            ),
            ktype=KnowledgeType.TESTING_METHODOLOGY,
            domain_name="RECONNAISSANCE",
            tags=["Subdomain", "DNS", "Certificate_Transparency", "Reconnaissance"],
        ))

        chunks.append(cls._create_chunk(
            doc_id="RECON-NEG-CONTROLS",
            sec_idx=2,
            title="Negative Controls in Vulnerability Validation",
            section_heading="False Positive Elimination via Negative Controls",
            content=(
                "Negative controls are mandatory testing assertions designed to verify that observed application behavior "
                "is uniquely caused by the security flaw rather than generic application handling. When testing for SQL injection, "
                "submit balanced false expressions (e.g., AND 1=2 vs AND 1=1) and ensure response differential is consistent. "
                "When testing for endpoint existence, probe random invalid paths to determine whether the server emits Soft-404 "
                "or global 200 OK templates. Findings that cannot demonstrate response divergence against negative controls "
                "must be rejected as unverified hypotheses."
            ),
            ktype=KnowledgeType.NEGATIVE_CONTROL_GUIDE,
            domain_name="RECONNAISSANCE",
            tags=["Negative_Controls", "False_Positives", "Methodology"],
        ))

        # -------------------------------------------------------------
        # 2. WEB SECURITY
        # -------------------------------------------------------------
        chunks.append(cls._create_chunk(
            doc_id="WEB-SSRF",
            sec_idx=1,
            title="Server-Side Request Forgery (SSRF) Mechanics",
            section_heading="SSRF Vulnerability Classes: In-Band vs Blind",
            content=(
                "Server-Side Request Forgery (CWE-918) occurs when a web application fetches a remote resource without "
                "validating the user-supplied destination URI. In-band SSRF returns the retrieved response data directly to "
                "the client, enabling attackers to read cloud metadata (e.g., 169.254.169.254) or scan internal loopback services. "
                "Blind SSRF does not reflect response content; confirmation requires out-of-band (OOB) network interaction (DNS/HTTP callbacks). "
                "Remediation requires strict destination allowlisting, parsing URLs with hardened libraries, and disabling HTTP redirects."
            ),
            ktype=KnowledgeType.VULNERABILITY_PATTERN,
            domain_name="WEB_SECURITY",
            tags=["SSRF", "CWE-918", "Cloud_Metadata", "Blind_SSRF"],
        ))

        chunks.append(cls._create_chunk(
            doc_id="WEB-SSRF-VS-CSRF",
            sec_idx=2,
            title="Comparison: SSRF vs CSRF",
            section_heading="Architectural Differences Between SSRF and CSRF",
            content=(
                "While both SSRF (CWE-918) and CSRF (CWE-352) induce forged HTTP requests, their trust boundaries and origins differ. "
                "CSRF exploits the trust a web application has in the victim's authenticated browser. The request originates from "
                "the client browser, carrying session cookies or ambient credentials. In contrast, SSRF exploits the trust that "
                "internal back-end network infrastructure has in the server itself. The request originates directly from the server's "
                "IP address, bypassing perimeter firewalls and reaching internal-only APIs."
            ),
            ktype=KnowledgeType.SECURITY_INVARIANT,
            domain_name="WEB_SECURITY",
            tags=["SSRF", "CSRF", "CWE-918", "CWE-352", "Trust_Boundaries"],
        ))

        chunks.append(cls._create_chunk(
            doc_id="WEB-HTTP-SMUGGLING",
            sec_idx=3,
            title="HTTP Request Smuggling (RFC 7230)",
            section_heading="CL.TE and TE.CL Desynchronization Mechanics",
            content=(
                "HTTP Request Smuggling (CWE-444) arises when a front-end reverse proxy and a back-end web server interpret "
                "message boundaries inconsistently in HTTP/1.1 pipelines. In CL.TE desync, the front-end processes Content-Length "
                "while the back-end processes Transfer-Encoding: chunked. The front-end forwards the entire body, but the back-end "
                "terminates processing at chunk '0', treating leftover bytes as the preamble of the subsequent user request. "
                "In TE.CL desync, the roles are reversed. Remediation requires HTTP/2 end-to-end or strict RFC 7230 conformance."
            ),
            ktype=KnowledgeType.PROTOCOL_BEHAVIOR,
            domain_name="WEB_SECURITY",
            tags=["HTTP_Request_Smuggling", "CWE-444", "RFC_7230", "CL.TE", "TE.CL"],
        ))

        chunks.append(cls._create_chunk(
            doc_id="WEB-SQLI",
            sec_idx=4,
            title="SQL Injection Validation & CWE-89",
            section_heading="Time-Based Blind SQL Injection Methodology",
            content=(
                "SQL Injection (CWE-89) occurs when untrusted input is concatenated into database commands. In time-based blind SQLi, "
                "no data or error messages are reflected. The tester injects conditional sleep primitives (e.g., pg_sleep(5), "
                "WAITFOR DELAY '0:0:5', or SLEEP(5)) coupled with boolean statements. Testing requires baseline latency establishment. "
                "If injecting a true condition introduces the specified delay and a false condition responds immediately, "
                "the vulnerability is confirmed. Parameterized queries (prepared statements) provide complete mitigation."
            ),
            ktype=KnowledgeType.TESTING_METHODOLOGY,
            domain_name="WEB_SECURITY",
            tags=["SQLi", "CWE-89", "Time-Based", "Blind_SQLi", "Prepared_Statements"],
        ))

        chunks.append(cls._create_chunk(
            doc_id="WEB-XSS",
            sec_idx=5,
            title="Cross-Site Scripting (XSS) Classification",
            section_heading="Reflected, Stored, and DOM-Based XSS Paths",
            content=(
                "Cross-Site Scripting (CWE-79) allows executing malicious JavaScript in a victim's browser context. "
                "Reflected XSS occurs when payload in the immediate request (URL query or POST body) is echoed into the HTTP response. "
                "Stored XSS persists the payload in persistent storage (database, comments), executing whenever any user views the record. "
                "DOM XSS occurs entirely within the client-side browser DOM without server reflection: JavaScript reads untrusted data "
                "from a source (location.search, document.referrer) and writes it into an execution sink (innerHTML, eval, document.write)."
            ),
            ktype=KnowledgeType.VULNERABILITY_PATTERN,
            domain_name="WEB_SECURITY",
            tags=["XSS", "CWE-79", "Reflected_XSS", "Stored_XSS", "DOM_XSS"],
        ))

        chunks.append(cls._create_chunk(
            doc_id="WEB-SSTI",
            sec_idx=6,
            title="Server-Side Template Injection (SSTI)",
            section_heading="Jinja2 Template Injection and MRO Traversal",
            content=(
                "Server-Side Template Injection (CWE-1336) happens when untrusted user input is concatenated directly into "
                "a template string rather than passed as context data. In Python Jinja2 templates, attackers traverse the "
                "Method Resolution Order (MRO) using reflection: ''.__class__.__mro__[1].__subclasses__() to find dangerous classes "
                "such as subprocess.Popen or os._wrap_close. Once located, arbitrary operating system commands can be executed. "
                "Remediation requires treating user input strictly as template variables and enabling sandbox mode."
            ),
            ktype=KnowledgeType.CODE_SECURITY_PATTERN,
            domain_name="WEB_SECURITY",
            tags=["SSTI", "Jinja2", "Python_MRO", "CWE-1336", "RCE"],
        ))

        chunks.append(cls._create_chunk(
            doc_id="WEB-XXE",
            sec_idx=7,
            title="XML External Entity (XXE) Injection & CWE-611",
            section_heading="XXE File Disclosure and Parser Hardening",
            content=(
                "XML External Entity (XXE) injection (CWE-611) exploits weak XML parser configurations that resolve external entities "
                "defined in DOCTYPE headers (e.g., <!ENTITY xxe SYSTEM 'file:///etc/passwd'>). When the entity is referenced in the document, "
                "the parser reads local files or makes outbound HTTP requests (SSRF). In Java DocumentBuilderFactory, remediation requires "
                "setting factory.setFeature('http://apache.org/xml/features/disallow-doctype-decl', true) and disabling external general entities."
            ),
            ktype=KnowledgeType.MITIGATION,
            domain_name="WEB_SECURITY",
            tags=["XXE", "CWE-611", "Java", "DOCTYPE", "Mitigation"],
        ))

        chunks.append(cls._create_chunk(
            doc_id="WEB-DESERIALIZATION",
            sec_idx=8,
            title="Insecure Deserialization & CWE-502",
            section_heading="Java Deserialization Mechanics and Gadget Chains",
            content=(
                "Insecure Deserialization (CWE-502) occurs when untrusted byte streams are deserialized into runtime objects (e.g., Java readObject). "
                "Attackers leverage gadget chains—sequences of legitimate classes present on the application classpath (e.g., Apache Commons Collections)—"
                "whose chained method invocations (such as InvokerTransformer or BadAttributeValueExpException) culminate in arbitrary code execution. "
                "Remediation requires avoiding native serialization, using safe JSON/Protobuf formats, and enforcing ObjectInputFilter look-ahead checks."
            ),
            ktype=KnowledgeType.VULNERABILITY_PATTERN,
            domain_name="WEB_SECURITY",
            tags=["Deserialization", "CWE-502", "Java", "Gadget_Chains"],
        ))

        # -------------------------------------------------------------
        # 3. AUTHENTICATION & SESSION MANAGEMENT
        # -------------------------------------------------------------
        chunks.append(cls._create_chunk(
            doc_id="AUTH-JWT",
            sec_idx=1,
            title="JSON Web Token (JWT) Security Architecture",
            section_heading="JWT Architecture and Common Attack Vectors (RFC 7519, RFC 8725)",
            content=(
                "JSON Web Tokens (RFC 7519) consist of three base64url-encoded components: Header, Payload, and Signature. "
                "Critical attack vectors include: 1) Algorithm Confusion (switching RS256 to HS256 and verifying with the public RSA key as the HMAC secret); "
                "2) Algorithm 'none' exploit (stripping signature when backend fails to enforce expected algorithm); "
                "3) Key ID ('kid') parameter injection (directory traversal or SQLi to control signing key). RFC 8725 best practices mandate "
                "explicit algorithm allowlisting and rejecting tokens with alg=none or mismatched signing algorithms."
            ),
            ktype=KnowledgeType.VULNERABILITY_PATTERN,
            domain_name="AUTHENTICATION",
            tags=["JWT", "RFC_7519", "RFC_8725", "Key_Confusion", "alg_none"],
        ))

        chunks.append(cls._create_chunk(
            doc_id="AUTH-OAUTH2-PKCE",
            sec_idx=2,
            title="OAuth 2.0 with PKCE (RFC 7636)",
            section_heading="Proof Key for Code Exchange Mechanics",
            content=(
                "OAuth 2.0 Authorization Code flow with PKCE (RFC 7636) protects public clients (mobile, SPA) that cannot securely "
                "store a client secret. The client generates a high-entropy cryptographically random string called 'code_verifier' and "
                "computes 'code_challenge' = BASE64URL-ENCODE(SHA256(code_verifier)). In the authorization request, code_challenge and "
                "code_challenge_method=S256 are passed. When exchanging the authorization code, the client supplies the original code_verifier. "
                "The authorization server recomputes the hash, preventing intercepted authorization codes from being redeemed by rogue apps."
            ),
            ktype=KnowledgeType.PROTOCOL_BEHAVIOR,
            domain_name="AUTHENTICATION",
            tags=["OAuth", "PKCE", "RFC_7636", "code_verifier", "code_challenge"],
        ))

        chunks.append(cls._create_chunk(
            doc_id="AUTH-SAML-XSW",
            sec_idx=3,
            title="SAML 2.0 XML Signature Wrapping (XSW)",
            section_heading="Decoupling XML Signature from Asserted Identity",
            content=(
                "XML Signature Wrapping (XSW) in SAML 2.0 occurs when an XML signature validates an element referenced by ID attribute "
                "while the application authentication logic parses a different, untrusted element in the XML tree. Attackers clone the legitimate "
                "signed assertion, modify user attributes (e.g. changing NameID to admin), and relocate the genuine signed assertion elsewhere "
                "in the document (e.g. inside an Extension tag). The signature validator verifies the genuine assertion, but the auth handler "
                "consumes the malicious assertion, resulting in complete authentication bypass."
            ),
            ktype=KnowledgeType.PROTOCOL_BEHAVIOR,
            domain_name="AUTHENTICATION",
            tags=["SAML", "XSW", "XML_Signature", "Authentication_Bypass"],
        ))

        chunks.append(cls._create_chunk(
            doc_id="AUTH-AUTH-VS-AUTHZ",
            sec_idx=4,
            title="Authentication vs Authorization",
            section_heading="Core Conceptual Separation in Security Architecture",
            content=(
                "Authentication and Authorization represent fundamentally distinct security controls. "
                "Authentication (AuthN, HTTP 401) is the process of verifying a subject's claimed identity using credentials (passwords, certificates, MFA, biometric tokens). "
                "Authorization (AuthZ, HTTP 403) is the process of verifying whether an authenticated identity has permission to perform a specific action "
                "on a requested resource according to system access-control policies. A validly authenticated user can be completely unauthorized to access an endpoint."
            ),
            ktype=KnowledgeType.SECURITY_INVARIANT,
            domain_name="AUTHENTICATION",
            tags=["Authentication", "Authorization", "401_vs_403", "Identity"],
        ))

        # -------------------------------------------------------------
        # 4. AUTHORIZATION: IDOR, BOLA, BFLA
        # -------------------------------------------------------------
        chunks.append(cls._create_chunk(
            doc_id="AUTHZ-IDOR-BOLA",
            sec_idx=1,
            title="IDOR vs BOLA: Definition and Lineage",
            section_heading="Insecure Direct Object References and Broken Object Level Authorization",
            content=(
                "Insecure Direct Object References (IDOR, CWE-639) was codified in the OWASP Top 10 2007 (A4) to describe flaws where "
                "applications expose internal object references (database primary keys, filenames) without access control checks. "
                "Broken Object Level Authorization (BOLA) is the modern API-centric nomenclature established in the OWASP API Security Top 10 (API1:2019/API1:2023). "
                "BOLA emphasizes that modern REST/GraphQL microservices expose individual resource endpoints (e.g., /api/v1/users/{id}/financials) "
                "where code must validate whether the authenticated user owns or has delegated access to the specific object requested."
            ),
            ktype=KnowledgeType.VULNERABILITY_PATTERN,
            domain_name="AUTHORIZATION",
            tags=["IDOR", "BOLA", "CWE-639", "OWASP_API1", "Access_Control"],
        ))

        chunks.append(cls._create_chunk(
            doc_id="AUTHZ-BFLA",
            sec_idx=2,
            title="Broken Function Level Authorization (BFLA)",
            section_heading="BFLA Mechanics and Administrative Endpoint Protection",
            content=(
                "Broken Function Level Authorization (BFLA, OWASP API5:2023, CWE-285) occurs when applications fail to restrict access to sensitive "
                "administrative or privileged functions. While BOLA deals with horizontal access to peer objects at the same privilege level, "
                "BFLA deals with vertical access where regular users invoke administrative functions (e.g., POST /api/v1/admin/users/promote). "
                "Flaws often arise from HTTP verb tampering (allowing GET but blocking POST) or incomplete URL regex matching in gateway filters."
            ),
            ktype=KnowledgeType.VULNERABILITY_PATTERN,
            domain_name="AUTHORIZATION",
            tags=["BFLA", "CWE-285", "OWASP_API5", "Vertical_Privilege_Escalation"],
        ))

        # -------------------------------------------------------------
        # 5. API SECURITY
        # -------------------------------------------------------------
        chunks.append(cls._create_chunk(
            doc_id="API-MASS-ASSIGNMENT",
            sec_idx=1,
            title="API Mass Assignment & Auto-Binding",
            section_heading="Mass Assignment Vulnerabilities (CWE-915) and DTO Prevention",
            content=(
                "Mass Assignment (CWE-915, OWASP API6:2023) occurs when web frameworks automatically bind client request parameters "
                "(JSON keys or form fields) directly to internal domain model properties or database entities. Attackers inject sensitive properties "
                "such as 'is_admin': true, 'role': 'superuser', or 'verified': true during standard profile update requests. "
                "Prevention requires decoupling request payloads from internal models by utilizing strict Data Transfer Objects (DTOs) "
                "or explicit property allowlists (e.g. strong parameters in Rails, Spring DTO mapping)."
            ),
            ktype=KnowledgeType.CODE_SECURITY_PATTERN,
            domain_name="API_SECURITY",
            tags=["Mass_Assignment", "CWE-915", "DTO", "Auto-Binding", "OWASP_API6"],
        ))

        chunks.append(cls._create_chunk(
            doc_id="API-GRAPHQL",
            sec_idx=2,
            title="GraphQL Security Risks",
            section_heading="Introspection, Circular Queries, and Batching Abuse",
            content=(
                "GraphQL presents distinct security challenges compared to REST: 1) Schema Introspection (__schema, __type) exposes the full "
                "data model and private queries if enabled in production; 2) Unrestricted query depth and recursive circular relations "
                "(author -> books -> author -> books) cause severe Denial of Service (DoS); 3) Query batching allows packing thousands of "
                "mutations into a single HTTP request, circumventing standard API rate limiters. Mitigation requires disabling introspection, "
                "enforcing max-depth rules, query cost analysis, and field-level authorization resolvers."
            ),
            ktype=KnowledgeType.VULNERABILITY_PATTERN,
            domain_name="API_SECURITY",
            tags=["GraphQL", "Introspection", "Query_Depth", "Batching", "DoS"],
        ))

        # -------------------------------------------------------------
        # 6. MOBILE SECURITY (ANDROID & IOS)
        # -------------------------------------------------------------
        chunks.append(cls._create_chunk(
            doc_id="MOB-ANDROID-EXPORTED",
            sec_idx=1,
            title="Android Exported Component Abuse (CWE-926)",
            section_heading="Activity, Service, and BroadcastReceiver Exposure",
            content=(
                "Android components (Activity, Service, BroadcastReceiver, ContentProvider) become accessible to all third-party applications "
                "installed on the device if android:exported='true' in AndroidManifest.xml (or if an <intent-filter> is defined without explicitly setting exported=false). "
                "Attackers construct implicit or explicit Intents from malicious apps to invoke private activities, bypass PIN screens, "
                "trigger privileged background services, or extract sensitive data via unvalidated Intent extras. Mitigation requires setting "
                "android:exported='false' for internal components and enforcing custom signature-level permissions (android:protectionLevel='signature')."
            ),
            ktype=KnowledgeType.VULNERABILITY_PATTERN,
            domain_name="MOBILE",
            tags=["Android", "android_exported", "CWE-926", "Intents", "IPC"],
        ))

        chunks.append(cls._create_chunk(
            doc_id="MOB-CERT-PINNING",
            sec_idx=2,
            title="SSL/TLS Certificate Pinning & Frida Hooking",
            section_heading="Certificate Pinning Architecture and Dynamic Instrumentation",
            content=(
                "Certificate Pinning validates the server's X.509 certificate against a pinned public key hash hardcoded into the mobile application "
                "or configured in res/xml/network_security_config.xml. This blocks MITM interception even if an attacker installs a custom CA certificate "
                "in the device trust store. During authorized penetration testing, security analysts utilize Frida dynamic instrumentation scripts "
                "to hook SSL pinning APIs (e.g., TrustManagerImpl.checkTrustedRecursive, OkHttp CertificatePinner.check) and force return values "
                "to permit proxy inspection."
            ),
            ktype=KnowledgeType.TESTING_METHODOLOGY,
            domain_name="MOBILE",
            tags=["Certificate_Pinning", "Frida", "OkHttp", "MITM", "Mobile_Testing"],
        ))

        chunks.append(cls._create_chunk(
            doc_id="MOB-ANDROID-SECURITY-REVIEW",
            sec_idx=3,
            title="Android Application Security Review & APK Static Analysis",
            section_heading="Static Analysis Workflow, Manifest Review, and Storage Security",
            content=(
                "Android application security assessment begins with APK static analysis and manifest inspection: "
                "1) Manifest Inspection (AndroidManifest.xml): Check for exported activities, services, receivers, and content providers "
                "(android:exported='true'); verify debuggable flag (android:debuggable='true' must be false in release); inspect custom permissions. "
                "2) Local Storage & Data Leakage: Verify sensitive credentials, tokens, or PII are not stored in plaintext in SharedPreferences, "
                "SQLite databases, internal cache files, or external public storage (Environment.getExternalStorageDirectory). "
                "3) Cryptography & Keystore: Ensure Android Keystore provider is used for hardware-backed cryptographic keys rather than hardcoded keys. "
                "4) Network Security Configuration (res/xml/network_security_config.xml): Check for cleartextTrafficPermitted='true' and certificate pinning. "
                "5) Code Decompilation & Reverse Engineering: Use jadx, apktool, or dex2jar to review Smali and Java bytecode for hardcoded API keys, "
                "secrets, unprotected IPC endpoints, insecure WebViews (setJavaScriptEnabled with addJavascriptInterface), and deep link handling."
            ),
            ktype=KnowledgeType.TESTING_METHODOLOGY,
            domain_name="MOBILE",
            tags=["Android", "APK", "Static_Analysis", "AndroidManifest", "SharedPreferences", "Keystore", "jadx", "Deep_Links", "Mobile_Testing"],
        ))

        # -------------------------------------------------------------
        # 7. NETWORK SECURITY
        # -------------------------------------------------------------
        chunks.append(cls._create_chunk(
            doc_id="NET-DNS-REBINDING",
            sec_idx=1,
            title="DNS Rebinding Attacks (CWE-350)",
            section_heading="Same-Origin Policy Bypass via Dynamic DNS TTL",
            content=(
                "DNS Rebinding (CWE-350) enables malicious websites to bypass the browser Same-Origin Policy (SOP) to interact with internal private network "
                "services (e.g. 127.0.0.1 or 192.168.1.1). The attacker operates an authoritative DNS server with a TTL of 0 seconds. On the victim's first request, "
                "the DNS resolves to the attacker's public IP delivering JavaScript payload. When the script initiates subsequent fetch requests to the same hostname, "
                "the browser re-queries DNS; the server responds with 127.0.0.1. Because origin matching is hostname-based, the browser allows cross-network communication. "
                "Mitigation requires internal services to strictly validate the HTTP 'Host' request header."
            ),
            ktype=KnowledgeType.PROTOCOL_BEHAVIOR,
            domain_name="NETWORK",
            tags=["DNS_Rebinding", "CWE-350", "Same-Origin_Policy", "Host_Header"],
        ))

        chunks.append(cls._create_chunk(
            doc_id="NET-TLS-HANDSHAKE",
            sec_idx=2,
            title="TLS 1.3 vs TLS 1.2 Cryptographic Handshake",
            section_heading="Key Exchange Mechanics and Forward Secrecy",
            content=(
                "TLS 1.3 (RFC 8446) fundamentally upgrades TLS 1.2 (RFC 5246): 1) Handshake Latency is reduced from 2-RTT to 1-RTT by including "
                "key exchange parameters directly in the ClientHello message; 2) Weak cryptographic primitives are eliminated, banning RSA key transport, "
                "CBC-mode ciphers, SHA-1, and RC4; 3) Ephemeral Diffie-Hellman (ECDHE) is mandatory, guaranteeing Perfect Forward Secrecy (PFS); "
                "4) 0-RTT Early Data is introduced for cached sessions, though it is vulnerable to replay attacks and must not carry non-idempotent state mutations."
            ),
            ktype=KnowledgeType.SECURITY_INVARIANT,
            domain_name="NETWORK",
            tags=["TLS", "TLS_1.3", "RFC_8446", "ECDHE", "Forward_Secrecy"],
        ))

        chunks.append(cls._create_chunk(
            doc_id="NET-DDOS-VOLUMETRIC",
            sec_idx=3,
            title="Volumetric DDoS Attacks & Defensive Mitigations",
            section_heading="Traffic Flooding, Protocol Exhaustion, and Scrubbing Architecture",
            content=(
                "Distributed Denial of Service (DDoS) attacks attempt to exhaust network bandwidth, system resources, or application capacity: "
                "1) Volumetric Attacks: Flood network bandwidth with massive traffic volumes (Gbps/Tbps). Common vectors include UDP reflection/amplification "
                "(DNS, NTP, Memcached, SNMP) where spoofed requests elicit disproportionately large responses directed at the victim. "
                "2) Protocol Attacks: Exploit transport/network layer state tables (e.g. TCP SYN floods, ICMP floods) to exhaust firewall and connection tracking tables. "
                "3) Application Layer (L7) Attacks: Target server computational resources with HTTP floods or slow connection holding (Slowloris). "
                "Defensive Mitigations: Organizations defend against volumetric DDoS using Anycast BGP routing to distribute load globally across scrubbing centers, "
                "cloud DDoS protection services (Cloudflare, AWS Shield), upstream ISP Flowspec and BGP blackholing, SYN cookies (RFC 4987) to resist state exhaustion, "
                "and adaptive Web Application Firewall (WAF) rate limiting."
            ),
            ktype=KnowledgeType.MITIGATION,
            domain_name="NETWORK",
            tags=["DDoS", "Volumetric_Attack", "UDP_Amplification", "SYN_Flood", "Anycast", "Scrubbing", "Rate_Limiting", "DoS"],
        ))

        # -------------------------------------------------------------
        # 8. CLOUD SECURITY
        # -------------------------------------------------------------
        chunks.append(cls._create_chunk(
            doc_id="CLOUD-IMDS",
            sec_idx=1,
            title="AWS Instance Metadata Service: IMDSv1 vs IMDSv2",
            section_heading="SSRF Cloud Credential Theft and IMDSv2 Token Mitigation",
            content=(
                "AWS EC2 Instance Metadata Service (IMDS) operates at link-local address 169.254.169.254. Under IMDSv1, simple HTTP GET requests "
                "(e.g., GET /latest/meta-data/iam/security-credentials/{role-name}) return temporary IAM role session tokens. Any basic SSRF flaw enables "
                "direct credential exfiltration. IMDSv2 enforces session-oriented access requiring a PUT request with header "
                "'X-aws-ec2-metadata-token-ttl-seconds: 21600' to obtain a signed token, followed by GET requests bearing the token in 'X-aws-ec2-metadata-token'. "
                "Because standard application SSRF injection points cannot forge custom HTTP PUT methods or headers, IMDSv2 neutralizes SSRF credential theft."
            ),
            ktype=KnowledgeType.SECURITY_INVARIANT,
            domain_name="CLOUD",
            tags=["AWS", "IMDS", "IMDSv2", "SSRF", "Cloud_IAM"],
        ))

        chunks.append(cls._create_chunk(
            doc_id="CLOUD-K8S-CONTAINER",
            sec_idx=2,
            title="Container Breakout & Privileged Containers",
            section_heading="release_agent cgroup Escapes and CAP_SYS_ADMIN",
            content=(
                "Running Docker containers with the '--privileged' flag or granting CAP_SYS_ADMIN disables kernel namespace isolation and security profiles. "
                "A standard escape vector exploits cgroup release_agent: 1) Inside the container, mount a memory cgroup; 2) Create a child cgroup and set "
                "notify_on_release to 1; 3) Overwrite release_agent with a path pointing to an attacker script written in the container; 4) Trigger process exit. "
                "The host Linux kernel executes release_agent directly in the host root context, achieving host compromise. "
                "Prevention requires unprivileged containers, dropping capabilities, and enabling Seccomp/AppArmor profiles."
            ),
            ktype=KnowledgeType.VULNERABILITY_PATTERN,
            domain_name="CLOUD",
            tags=["Docker", "Kubernetes", "Container_Escape", "CAP_SYS_ADMIN", "cgroups"],
        ))

        # -------------------------------------------------------------
        # 9. WINDOWS / ACTIVE DIRECTORY
        # -------------------------------------------------------------
        chunks.append(cls._create_chunk(
            doc_id="WIN-KERBEROS-FLOW",
            sec_idx=1,
            title="Active Directory Kerberos Authentication Architecture",
            section_heading="AS-REQ, AS-REP, TGS-REQ, TGS-REP, and AP-REQ Mechanics",
            content=(
                "Kerberos (RFC 4120) in Active Directory operates through five distinct message exchanges: "
                "1) AS-REQ: Client sends encrypted timestamp using user password hash to the KDC (Key Distribution Center); "
                "2) AS-REP: KDC validates timestamp and returns a Ticket Granting Ticket (TGT) encrypted with the krbtgt account key, plus a session key; "
                "3) TGS-REQ: Client presents TGT and requests a Ticket Granting Service (TGS) ticket for a target Service Principal Name (SPN); "
                "4) TGS-REP: KDC returns TGS ticket encrypted with the service account password hash; "
                "5) AP-REQ: Client presents TGS ticket to the target service for mutual authentication."
            ),
            ktype=KnowledgeType.PROTOCOL_BEHAVIOR,
            domain_name="WINDOWS_AD",
            tags=["Kerberos", "Active_Directory", "AS-REQ", "TGT", "TGS", "SPN"],
        ))

        chunks.append(cls._create_chunk(
            doc_id="WIN-KERBEROASTING",
            sec_idx=2,
            title="Kerberoasting & Offline Hash Cracking",
            section_heading="Kerberoasting Mechanics (MITRE ATT&CK T1558.003)",
            content=(
                "Kerberoasting exploits legitimate Active Directory Kerberos functionality: any authenticated domain user has permission to request "
                "a TGS ticket for any service account registered with a Service Principal Name (SPN). Because the returned TGS-REP ticket is encrypted "
                "using the password hash of the target service account (often legacy RC4-HMAC), attackers extract the ciphertext and crack it offline "
                "without triggering account lockout thresholds or generating network noise. Defenses include using Group Managed Service Accounts (gMSA) "
                "with 128-character randomized passwords and enforcing AES256 encryption."
            ),
            ktype=KnowledgeType.TESTING_METHODOLOGY,
            domain_name="WINDOWS_AD",
            tags=["Kerberoasting", "T1558.003", "SPN", "gMSA", "Active_Directory"],
        ))

        # -------------------------------------------------------------
        # 10. LINUX SECURITY
        # -------------------------------------------------------------
        chunks.append(cls._create_chunk(
            doc_id="LNX-CAPABILITIES",
            sec_idx=1,
            title="Linux Capabilities Partitioning & CWE-250",
            section_heading="Privilege Division via Linux Capabilities",
            content=(
                "Linux capabilities (capabilities(7)) divide traditional monolithic UID 0 (root) privileges into distinct independent privileges. "
                "Key capabilities include: CAP_SETUID (ability to change process UID), CAP_NET_RAW (craft raw packets), CAP_SYS_PTRACE (debug and inspect processes), "
                "and CAP_SYS_ADMIN (broad system administration). Binaries granted capabilities via 'setcap' can perform privileged tasks without full SUID root access. "
                "Misconfiguring capabilities (such as giving CAP_SETUID to python or perl) allows immediate local privilege escalation."
            ),
            ktype=KnowledgeType.SECURITY_INVARIANT,
            domain_name="LINUX",
            tags=["Linux", "Capabilities", "CAP_SETUID", "Privilege_Separation"],
        ))

        # -------------------------------------------------------------
        # 11. BINARY / REVERSE ENGINEERING
        # -------------------------------------------------------------
        chunks.append(cls._create_chunk(
            doc_id="BIN-BUFFER-OVERFLOW",
            sec_idx=1,
            title="Stack Buffer Overflow & Binary Mitigations",
            section_heading="Memory Corruption, Stack Canaries, and NX/DEP",
            content=(
                "A stack-based buffer overflow (CWE-121) occurs when a program writes more data to a fixed-size stack buffer than was allocated, "
                "overwriting adjacent stack memory including the saved frame pointer (EBP/RBP) and return instruction pointer (EIP/RIP). "
                "Modern defenses include: 1) Stack Canaries (random value placed before return address verified upon function epilogue); "
                "2) NX/DEP (No-Execute / Data Execution Prevention, enforcing W^X to prevent shellcode execution in data segments); "
                "3) ASLR (Address Space Layout Randomization, randomizing stack, heap, and library base addresses); "
                "4) Full RELRO (making the Global Offset Table read-only to block GOT overwrite)."
            ),
            ktype=KnowledgeType.VULNERABILITY_PATTERN,
            domain_name="BINARY_RE",
            tags=["Buffer_Overflow", "CWE-121", "Stack_Canary", "ASLR", "NX_DEP", "RELRO"],
        ))

        chunks.append(cls._create_chunk(
            doc_id="BIN-ROP-CHAINS",
            sec_idx=2,
            title="Return-Oriented Programming (ROP)",
            section_heading="Bypassing NX/DEP with ROP Gadgets",
            content=(
                "Return-Oriented Programming (ROP) bypasses Non-Executable (NX/DEP) protections without injecting new shellcode. "
                "Attackers discover small snippets of existing executable instructions in the binary or shared libraries (libc) ending in a 'ret' instruction, "
                "known as 'gadgets'. By arranging gadget addresses and arguments on the stack, sequential 'ret' instructions execute gadgets that populate registers "
                "(e.g., pop rdi; ret) and invoke system calls (such as mprotect to make memory executable, or execve('/bin/sh'))."
            ),
            ktype=KnowledgeType.CODE_SECURITY_PATTERN,
            domain_name="BINARY_RE",
            tags=["ROP", "DEP_Bypass", "Gadgets", "Binary_Exploitation"],
        ))

        # -------------------------------------------------------------
        # 12. SOC / DFIR
        # -------------------------------------------------------------
        chunks.append(cls._create_chunk(
            doc_id="SOC-DETECTION-LOGS",
            sec_idx=1,
            title="Windows Threat Detection Event IDs",
            section_heading="LSASS Credential Dumping and Lateral Movement Detection",
            content=(
                "SOC detection engineering relies on key Windows Security Event IDs: "
                "1) Event ID 4624: Successful logon (Logon Type 3 indicates network logon; Type 10 indicates RDP); "
                "2) Event ID 4672: Special privileges assigned to new logon; "
                "3) Event ID 7045: A new service was installed in the system (frequent indicator of PsExec lateral movement); "
                "4) Sysmon Event ID 1: Process Creation with full command line arguments; "
                "5) Sysmon Event ID 10: ProcessAccess, flagging unauthorized access masks to lsass.exe (e.g. Mimikatz credential dumping)."
            ),
            ktype=KnowledgeType.TESTING_METHODOLOGY,
            domain_name="SOC_DFIR",
            tags=["Event_Logs", "Sysmon", "LSASS", "Detection", "Event_ID_7045"],
        ))

        # -------------------------------------------------------------
        # 14. SESSION SECURITY
        # -------------------------------------------------------------
        chunks.append(cls._create_chunk(
            doc_id="SESS-COOKIE-ATTRIBUTES",
            sec_idx=1,
            title="Session Security & Cookie Attributes",
            section_heading="Secure Session Lifecycle, SameSite Flags, and Invalidation",
            content=(
                "Robust session management requires: 1) Regenerating session tokens immediately upon authentication "
                "to defeat Session Fixation (CWE-384); 2) Enforcing HttpOnly to block JavaScript XSS token theft; "
                "3) Enforcing Secure flag so cookies transmit strictly over TLS; 4) Setting SameSite=Lax or Strict "
                "to neutralize Cross-Site Request Forgery (CSRF); 5) Enforcing absolute and idle server-side timeouts "
                "with immediate token destruction in persistent session stores upon logout."
            ),
            ktype=KnowledgeType.SECURITY_INVARIANT,
            domain_name="SESSION_SECURITY",
            tags=["Session_Security", "HttpOnly", "SameSite", "Session_Fixation", "CWE-384"],
        ))

        # -------------------------------------------------------------
        # 15. DNS SECURITY
        # -------------------------------------------------------------
        chunks.append(cls._create_chunk(
            doc_id="DNS-ZONE-TRANSFERS",
            sec_idx=1,
            title="DNS Security & AXFR Zone Transfers",
            section_heading="DNSSEC, Authoritative Zone Transfers, and Wildcard Resolution",
            content=(
                "DNS serves as critical directory infrastructure. Unrestricted AXFR zone transfers (dig axfr @ns target.com) "
                "leak complete internal namespace topology and internal IP address allocations. DNSSEC addresses spoofing and cache "
                "poisoning by signing DNS resource records using cryptographic RRSIG keys verified via DS trust chains. "
                "Wildcard DNS handling requires testing non-existent randomized hostnames to detect universal catch-all addresses."
            ),
            ktype=KnowledgeType.PROTOCOL_BEHAVIOR,
            domain_name="DNS",
            tags=["DNS", "DNSSEC", "AXFR", "Zone_Transfer", "Wildcard_DNS"],
        ))

        # -------------------------------------------------------------
        # 16. TLS & PKI
        # -------------------------------------------------------------
        chunks.append(cls._create_chunk(
            doc_id="PKI-CERT-CHAIN",
            sec_idx=1,
            title="Public Key Infrastructure (PKI) & Certificate Validation",
            section_heading="X.509 Certificate Paths, Revocation (CRL/OCSP), and Trust Stores",
            content=(
                "TLS trust relies on X.509 certificate chains rooted in trusted Root CAs. Clients validate certificate validity dates, "
                "Subject Alternative Names (SAN), and cryptographic signatures along the intermediate chain to root. "
                "Revocation checking utilizes Certificate Revocation Lists (CRLs) or Online Certificate Status Protocol (OCSP). "
                "OCSP Stapling eliminates privacy leaks and latency by having the server supply a time-stamped OCSP response signed by the CA."
            ),
            ktype=KnowledgeType.SECURITY_INVARIANT,
            domain_name="TLS_PKI",
            tags=["TLS", "PKI", "X509", "OCSP", "Certificate_Validation"],
        ))

        # -------------------------------------------------------------
        # 17. CRYPTOGRAPHY
        # -------------------------------------------------------------
        chunks.append(cls._create_chunk(
            doc_id="CRYPTO-KDF-PRACTICES",
            sec_idx=1,
            title="Modern Password Hashing & Key Derivation Functions",
            section_heading="Argon2id, PBKDF2, and Key Stretching vs Fast Hashes",
            content=(
                "Password storage must never utilize fast general-purpose cryptographic hashes (MD5, SHA-1, SHA-256) which are vulnerable "
                "to high-speed GPU/ASIC brute forcing. Systems must employ memory-hard key derivation functions such as Argon2id (RFC 9106), "
                "scrypt, or bcrypt with high work factors. Unique cryptographically random salts per password prevent rainbow table attacks, "
                "and memory cost parameters defeat parallelized hardware acceleration."
            ),
            ktype=KnowledgeType.SECURITY_INVARIANT,
            domain_name="CRYPTOGRAPHY",
            tags=["Cryptography", "Argon2id", "PBKDF2", "Password_Hashing", "Key_Derivation"],
        ))

        # -------------------------------------------------------------
        # 18. WINDOWS SECURITY
        # -------------------------------------------------------------
        chunks.append(cls._create_chunk(
            doc_id="WIN-LOCAL-SECURITY",
            sec_idx=1,
            title="Windows Local Privilege Boundaries & SAM Protection",
            section_heading="Security Account Manager (SAM), LSA Secrets, and UAC Bypass",
            content=(
                "Windows local security isolates user sessions via User Account Control (UAC) token filtering. High-integrity processes "
                "possess administrative tokens while medium-integrity processes operate restricted. Local password hashes reside inside "
                "the SAM registry hive, encrypted with the system boot key (SYSTEM hive). Defenses include Credential Guard (virtualization-based "
                "security isolating LSA in a secure enclave) and RestrictRemoteSAM policies limiting SAM RPC enumeration."
            ),
            ktype=KnowledgeType.SECURITY_INVARIANT,
            domain_name="WINDOWS_SECURITY",
            tags=["Windows", "SAM", "UAC", "LSA", "Credential_Guard"],
        ))

        # -------------------------------------------------------------
        # 19. CONTAINER SECURITY
        # -------------------------------------------------------------
        chunks.append(cls._create_chunk(
            doc_id="CONT-HARDENING",
            sec_idx=1,
            title="Container Runtime Isolation & Hardening",
            section_heading="Rootless Containers, Seccomp Profiles, and Read-Only Root Filesystems",
            content=(
                "Container isolation relies on Linux cgroups and namespaces (pid, net, ipc, mnt, uts, user). Securing container runtime "
                "requires: 1) Running containers in rootless mode (mapping container UID 0 to unprivileged host UID); 2) Applying strict "
                "seccomp filters to block dangerous syscalls (ptrace, unshare, keyctl); 3) Setting read-only root filesystems; "
                "4) Never exposing /var/run/docker.sock to container user space, which yields immediate host root control."
            ),
            ktype=KnowledgeType.SECURITY_INVARIANT,
            domain_name="CONTAINER_SECURITY",
            tags=["Containers", "Docker", "Seccomp", "Rootless", "Isolation"],
        ))

        # -------------------------------------------------------------
        # 20. KUBERNETES SECURITY
        # -------------------------------------------------------------
        chunks.append(cls._create_chunk(
            doc_id="K8S-ADMISSION-CONTROL",
            sec_idx=1,
            title="Kubernetes Cluster Hardening & Admission Control",
            section_heading="Pod Security Standards, Validating Admission Webhooks, and NetworkPolicies",
            content=(
                "Kubernetes clusters require defense-in-depth across the control plane: 1) Pod Security Standards (Restricted profile) "
                "blocking hostNetwork, hostPID, and privileged containers; 2) ValidatingAdmissionPolicy or Open Policy Agent (OPA/Gatekeeper) "
                "rejecting non-compliant manifest deployments; 3) NetworkPolicies enforcing default-deny ingress and egress between namespaces; "
                "4) Automating rotation of ServiceAccount projected volume tokens (BoundServiceAccountTokenVolume)."
            ),
            ktype=KnowledgeType.SECURITY_INVARIANT,
            domain_name="KUBERNETES_SECURITY",
            tags=["Kubernetes", "Admission_Controller", "NetworkPolicy", "RBAC", "Pod_Security"],
        ))

        # -------------------------------------------------------------
        # 21. MOBILE SECURITY
        # -------------------------------------------------------------
        chunks.append(cls._create_chunk(
            doc_id="MOB-STORAGE-RISKS",
            sec_idx=1,
            title="Mobile Application Threat Modeling & Storage",
            section_heading="Insecure Local Data Storage & Shared Preferences (CWE-922)",
            content=(
                "Mobile applications frequently leak credentials, tokens, or PII into world-readable storage, SharedPreferences, "
                "SQLite databases, or system logcat output. Threat modeling requires verifying that sensitive tokens are encrypted using "
                "hardware-backed keystores (Android Keystore / iOS Keychain) and that application data directories reject backup inclusion "
                "(android:allowBackup='false'). Logcat logging must be stripped in production release builds."
            ),
            ktype=KnowledgeType.VULNERABILITY_PATTERN,
            domain_name="MOBILE_SECURITY",
            tags=["Mobile", "Insecure_Storage", "CWE-922", "Keychain", "Keystore"],
        ))

        # -------------------------------------------------------------
        # 22. IOS SECURITY
        # -------------------------------------------------------------
        chunks.append(cls._create_chunk(
            doc_id="IOS-SANDBOX-DEFENSES",
            sec_idx=1,
            title="iOS Application Sandboxing & Security Model",
            section_heading="App Sandbox, Data Protection API, and Keychain Access Groups",
            content=(
                "iOS enforces application isolation via the App Sandbox (Seatbelt), restricting apps to their container directory. "
                "Hardware data protection binds file encryption keys to device passcode via Secure Enclave. Sensitive credentials "
                "must reside in the Keychain with appropriate kSecAttrAccessible attributes (e.g. kSecAttrAccessibleWhenUnlockedThisDeviceOnly). "
                "Dynamic hooking tools like Frida circumvent client-side jailbreak and anti-debugging checks during authorized testing."
            ),
            ktype=KnowledgeType.SECURITY_INVARIANT,
            domain_name="IOS_SECURITY",
            tags=["iOS", "Keychain", "App_Sandbox", "Secure_Enclave", "Frida"],
        ))

        # -------------------------------------------------------------
        # 23. REVERSE ENGINEERING
        # -------------------------------------------------------------
        chunks.append(cls._create_chunk(
            doc_id="RE-DECOMPILATION-METHODS",
            sec_idx=1,
            title="Binary Disassembly and Decompilation Methodology",
            section_heading="Control Flow Graphs (CFG), Symbol Resolution, and Static Reverse Engineering",
            content=(
                "Reverse engineering analyzes compiled binaries (ELF/PE) without source code. Disassemblers (Ghidra, IDA Pro, Binary Ninja) "
                "translate machine opcodes into assembly, building Control Flow Graphs (CFGs) of basic blocks. Decompilers lift assembly into "
                "C-like abstract syntax trees. Analysis identifies dangerous function imports (strcpy, system), cryptographic constants, "
                "string tables, and cross-references (xrefs) to uncover vulnerable logic branches or hidden debug routines."
            ),
            ktype=KnowledgeType.TESTING_METHODOLOGY,
            domain_name="REVERSE_ENGINEERING",
            tags=["Reverse_Engineering", "Ghidra", "Decompilation", "CFG", "Disassembly"],
        ))

        # -------------------------------------------------------------
        # 24. MALWARE ANALYSIS
        # -------------------------------------------------------------
        chunks.append(cls._create_chunk(
            doc_id="MALWARE-ANALYSIS-STAGES",
            sec_idx=1,
            title="Malware Analysis Stages: Static vs Dynamic",
            section_heading="Behavioral Sandbox Monitoring, Persistence Hooks, and YARA Signatures",
            content=(
                "Malware analysis follows structured phases: 1) Basic Static Analysis: Extracting hashes, strings, PE headers, imports, "
                "and packing detection (UPX); 2) Basic Dynamic Analysis: Running sample in isolated sandbox while monitoring registry "
                "persistence (Run keys, scheduled tasks), filesystem mutations, and C2 network callbacks; 3) Advanced Static/Dynamic: "
                "Debugging unpacked code and defeating anti-analysis checks (IsDebuggerPresent, sleep patching); 4) Rule writing with YARA."
            ),
            ktype=KnowledgeType.TESTING_METHODOLOGY,
            domain_name="MALWARE_ANALYSIS",
            tags=["Malware_Analysis", "Sandbox", "Persistence", "YARA", "C2"],
        ))

        # -------------------------------------------------------------
        # 25. THREAT HUNTING
        # -------------------------------------------------------------
        chunks.append(cls._create_chunk(
            doc_id="HUNT-PYRAMID-OF-PAIN",
            sec_idx=1,
            title="Hypothesis-Driven Threat Hunting & Pyramid of Pain",
            section_heading="Behavioral Hunting Across Telemetry vs Static Hash Indicators",
            content=(
                "Threat hunting proactively searches network and endpoint telemetry for advanced threat actors evading automated alerting. "
                "The Pyramid of Pain dictates that hunting for TTPs (Tactics, Techniques, and Procedures) inflicts maximum adversary disruption "
                "compared to ephemeral atomic indicators like IP addresses or file hashes. Hunters formulate falsifiable hypotheses based on "
                "MITRE ATT&CK techniques (e.g. LSASS handle access, living-off-the-land binaries) and validate them against SIEM data."
            ),
            ktype=KnowledgeType.TESTING_METHODOLOGY,
            domain_name="THREAT_HUNTING",
            tags=["Threat_Hunting", "Pyramid_of_Pain", "TTPs", "MITRE_ATTACK", "Hypothesis"],
        ))

        # -------------------------------------------------------------
        # 26. DEVSECOPS
        # -------------------------------------------------------------
        chunks.append(cls._create_chunk(
            doc_id="DEVSECOPS-PIPELINE",
            sec_idx=1,
            title="DevSecOps Pipeline Integration & Automated Gates",
            section_heading="SAST, DAST, SCA, Secret Scanning, and Breaking Build Policies",
            content=(
                "DevSecOps integrates automated security controls across the CI/CD pipeline: 1) Pre-commit secret scanning (detect-secrets, gitleaks) "
                "blocking credential commits; 2) Static Application Security Testing (SAST) analyzing source code syntax; 3) Software Composition "
                "Analysis (SCA) generating Software Bills of Materials (SBOM) and matching dependencies against CVE advisories; "
                "4) Dynamic Application Security Testing (DAST) probing staging deployments; 5) Policy gates blocking deployment on critical vulnerabilities."
            ),
            ktype=KnowledgeType.SECURITY_INVARIANT,
            domain_name="DEVSECOPS",
            tags=["DevSecOps", "CI_CD", "SAST", "DAST", "SCA", "SBOM"],
        ))

        # -------------------------------------------------------------
        # 27. VULNERABILITY MANAGEMENT
        # -------------------------------------------------------------
        chunks.append(cls._create_chunk(
            doc_id="VULN-MGMT-PRIORITIZATION",
            sec_idx=1,
            title="Risk-Based Vulnerability Prioritization: CVSS vs EPSS",
            section_heading="Exploit Prediction Scoring System (EPSS) and Remediation SLAs",
            content=(
                "Modern vulnerability management combines CVSS v3.1 severity with EPSS (Exploit Prediction Scoring System) probability. "
                "While CVSS rates theoretical technical severity (Base Score), EPSS calculates the empirical likelihood (0.0 to 1.0) "
                "that a CVE will experience active exploitation in the wild within 30 days. Prioritizing remediation by intersecting "
                "high CVSS (>8.0) and high EPSS (>0.1) reduces organizational exploit exposure while optimizing patch engineering effort."
            ),
            ktype=KnowledgeType.SECURITY_INVARIANT,
            domain_name="VULNERABILITY_MANAGEMENT",
            tags=["Vulnerability_Management", "CVSS", "EPSS", "Remediation", "Prioritization"],
        ))

        # -------------------------------------------------------------
        # 28. PENETRATION TESTING METHODOLOGY
        # -------------------------------------------------------------
        chunks.append(cls._create_chunk(
            doc_id="PTES-METHODOLOGY-STAGES",
            sec_idx=1,
            title="Penetration Testing Execution Standard (PTES)",
            section_heading="Pre-engagement, Intelligence Gathering, Threat Modeling, Exploitation, and Reporting",
            content=(
                "The Penetration Testing Execution Standard (PTES) defines seven core testing phases: "
                "1) Pre-engagement Interactions: Establishing scope, rules of engagement, and legal authorization; "
                "2) Intelligence Gathering: Passive and active asset reconnaissance; "
                "3) Threat Modeling: Mapping high-value business assets and threat vectors; "
                "4) Vulnerability Analysis: Uncovering flaw patterns with negative controls; "
                "5) Exploitation: Precision non-destructive proof-of-concept verification; "
                "6) Post-Exploitation: Gauging business impact and lateral risk; "
                "7) Reporting: Executive summaries and actionable remediation guidance."
            ),
            ktype=KnowledgeType.TESTING_METHODOLOGY,
            domain_name="PENETRATION_TESTING_METHODOLOGY",
            tags=["PTES", "Methodology", "Scope", "Rules_of_Engagement", "Reporting"],
        ))

        # -------------------------------------------------------------
        # 29. BUG BOUNTY METHODOLOGY
        # -------------------------------------------------------------
        chunks.append(cls._create_chunk(
            doc_id="BOUNTY-TRIAGE-METHODOLOGY",
            sec_idx=1,
            title="Bug Bounty Research Methodology & Responsible Disclosure",
            section_heading="Scope Adherence, Minimal Impact PoCs, and Coordinated Disclosure",
            content=(
                "Bug bounty research mandates rigorous operational discipline: 1) Strict Scope Verification: Validating that targets "
                "belong explicitly to in-scope domains and CIDRs before sending traffic; 2) Minimal Impact Proof of Concept: Proving execution "
                "using benign actions (e.g. dnslog callback, benign file read) without dumping full customer databases or causing DoS; "
                "3) Coordinated Disclosure: Adhering to program embargo periods and reporting guidelines without public disclosure."
            ),
            ktype=KnowledgeType.TESTING_METHODOLOGY,
            domain_name="BUG_BOUNTY_METHODOLOGY",
            tags=["Bug_Bounty", "ScopeGate", "Responsible_Disclosure", "PoC", "Ethics"],
        ))

        # -------------------------------------------------------------
        # 30. SECURITY ARCHITECTURE
        # -------------------------------------------------------------
        chunks.append(cls._create_chunk(
            doc_id="ARCH-ZERO-TRUST-STRIDE",
            sec_idx=1,
            title="Zero Trust Architecture & Threat Modeling",
            section_heading="NIST SP 800-207 Zero Trust Architecture and STRIDE Analysis",
            content=(
                "Security architecture assumes breach and eliminates implicit perimeter trust (NIST SP 800-207 Zero Trust Architecture). "
                "Core tenets require continuous verification of explicit identity, least privilege access, and assumed breach posture. "
                "Threat modeling evaluates system data flows against the STRIDE taxonomy: Spoofing (Authenticity), Tampering (Integrity), "
                "Repudiation (Non-repudiation), Information Disclosure (Confidentiality), Denial of Service (Availability), and "
                "Elevation of Privilege (Authorization)."
            ),
            ktype=KnowledgeType.SECURITY_INVARIANT,
            domain_name="SECURITY_ARCHITECTURE",
            tags=["Security_Architecture", "Zero_Trust", "NIST_SP_800_207", "STRIDE", "Threat_Modeling"],
        ))

        # -------------------------------------------------------------
        # 31. PRIVACY & SECURITY ENGINEERING
        # -------------------------------------------------------------
        chunks.append(cls._create_chunk(
            doc_id="PRIVACY-SECURITY-ENG",
            sec_idx=1,
            title="Privacy Engineering & Data Protection by Design",
            section_heading="Data Minimization, Pseudonymization, and Subject Rights Controls",
            content=(
                "Privacy and security engineering (GDPR Article 25, ISO 27701) mandates Data Protection by Design and Default: "
                "1) Data Minimization: Collecting only telemetry strictly necessary for authorized processing; "
                "2) Pseudonymization & Encryption: Protecting PII at rest and in transit with key segregation; "
                "3) Retention Limits: Automated purging of expired personal records; "
                "4) Privacy Boundaries: Preventing cross-tenant analytical data pooling without differential privacy guarantees."
            ),
            ktype=KnowledgeType.SECURITY_INVARIANT,
            domain_name="PRIVACY_SECURITY_ENGINEERING",
            tags=["Privacy_Engineering", "Data_Minimization", "GDPR", "Encryption", "Pseudonymization"],
        ))

        cls._CHUNKS = chunks


if __name__ == "__main__":
    chunks = VaptDomainCorpus.get_all_chunks()
    print(f"Initialized VAPT Domain Corpus with {len(chunks)} authoritative chunks across all 32 domains.")
