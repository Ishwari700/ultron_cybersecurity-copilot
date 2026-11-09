"""M5 Evaluation Datasets Generator and Schema (Milestone M5 Section 39, 40).

Generates:
1. data/eval/m5_copilot_evaluation_dataset.json (100 cases across 11 distribution categories)
2. data/eval/m5_investigation_benchmark_dataset.json (30 structured synthetic investigation cases)
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from src.copilot.domain import SecurityDomain
from src.copilot.intent import CopilotMode, CopilotTaskType


class M5CopilotEvaluationCase(BaseModel):
    """Case schema for the 100-case general cybersecurity copilot evaluation."""
    case_id: str
    category: str
    difficulty: str  # easy, medium, hard
    question: str
    expected_intent: CopilotTaskType
    expected_mode: CopilotMode
    expected_domain: SecurityDomain
    is_evidence_grounded: bool = False
    target_evidence: Optional[Dict[str, Any]] = None
    expected_escalation: bool = False
    expected_keywords: List[str] = Field(default_factory=list)
    forbidden_claims: List[str] = Field(default_factory=list)


class M5InvestigationBenchmarkCase(BaseModel):
    """Case schema for the 30-case synthetic investigation benchmark."""
    case_id: str
    domain: SecurityDomain
    target_asset: str
    target_evidence: List[Dict[str, Any]] = Field(default_factory=list)
    known_facts: List[str] = Field(default_factory=list)
    expected_hypotheses: List[str] = Field(default_factory=list)
    expected_invariants: List[str] = Field(default_factory=list)
    expected_evidence_gaps: List[str] = Field(default_factory=list)
    expected_experiments: List[Dict[str, Any]] = Field(default_factory=list)
    expected_falsification: str
    negative_controls: List[str] = Field(default_factory=list)
    forbidden_conclusions: List[str] = Field(default_factory=list)


def build_100_case_evaluation_dataset() -> List[M5CopilotEvaluationCase]:
    """Generates the canonical 100-case evaluation dataset per Section 39."""
    cases: List[M5CopilotEvaluationCase] = []

    # Category 1: General Cybersecurity Q&A (15 cases)
    gen_qa = [
        ("M5-QA-001", "easy", "What is the difference between authentication and authorization?", CopilotTaskType.COMPARE, CopilotMode.GENERAL_QA, SecurityDomain.AUTHORIZATION, ["identity", "permissions"]),
        ("M5-QA-002", "easy", "Explain the concept of defense in depth.", CopilotTaskType.GENERAL_SECURITY, CopilotMode.GENERAL_QA, SecurityDomain.SECURITY_ARCHITECTURE, ["layered", "redundant"]),
        ("M5-QA-003", "easy", "What does the CIA triad stand for in information security?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.GENERAL_CYBERSECURITY, ["confidentiality", "integrity", "availability"]),
        ("M5-QA-004", "medium", "Explain how zero trust architecture replaces perimeter-based security.", CopilotTaskType.GENERAL_SECURITY, CopilotMode.GENERAL_QA, SecurityDomain.SECURITY_ARCHITECTURE, ["never trust", "always verify"]),
        ("M5-QA-005", "easy", "What is the purpose of hashing versus encryption?", CopilotTaskType.COMPARE, CopilotMode.GENERAL_QA, SecurityDomain.CRYPTOGRAPHY, ["one-way", "reversible"]),
        ("M5-QA-006", "medium", "How does public key infrastructure (PKI) establish trust?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.CRYPTOGRAPHY, ["certificate authority", "digital signature"]),
        ("M5-QA-007", "easy", "What is social engineering and what are common vectors?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.GENERAL_CYBERSECURITY, ["phishing", "pretexting"]),
        ("M5-QA-008", "medium", "Explain threat modeling using the STRIDE methodology.", CopilotTaskType.GENERAL_SECURITY, CopilotMode.GENERAL_QA, SecurityDomain.SECURITY_ARCHITECTURE, ["spoofing", "tampering"]),
        ("M5-QA-009", "hard", "How do side-channel timing attacks exploit non-constant-time comparisons?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.CRYPTOGRAPHY, ["execution time", "cache"]),
        ("M5-QA-010", "easy", "What is a Denial of Service (DoS) attack?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.NETWORK_SECURITY, ["resource exhaustion", "availability"]),
        ("M5-QA-011", "medium", "Compare symmetric encryption algorithms AES and ChaCha20.", CopilotTaskType.COMPARE, CopilotMode.GENERAL_QA, SecurityDomain.CRYPTOGRAPHY, ["block cipher", "stream cipher"]),
        ("M5-QA-012", "easy", "What is multi-factor authentication (MFA) and why is it effective?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.AUTHENTICATION, ["factors", "possession"]),
        ("M5-QA-013", "medium", "Explain the difference between CVSS Base, Temporal, and Environmental metrics.", CopilotTaskType.COMPARE, CopilotMode.GENERAL_QA, SecurityDomain.VULNERABILITY_RESEARCH, ["severity", "score"]),
        ("M5-QA-014", "medium", "What are security invariants and how do they formalize protection boundaries?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.SECURITY_ARCHITECTURE, ["invariant", "formal boundary"]),
        ("M5-QA-015", "hard", "How does forward secrecy protect past sessions against private key compromise?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.TLS_SECURITY, ["ephemeral", "diffie-hellman"]),
    ]
    for cid, diff, q, task, mode, dom, kw in gen_qa:
        cases.append(M5CopilotEvaluationCase(
            case_id=cid, category="General Cybersecurity Q&A", difficulty=diff, question=q,
            expected_intent=task, expected_mode=mode, expected_domain=dom, expected_keywords=kw,
        ))

    # Category 2: Web & API Security (10 cases)
    web_api = [
        ("M5-WEB-001", "easy", "What is Cross-Site Scripting (XSS) and what are the main types?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.WEB_APPLICATION_SECURITY, ["stored", "reflected", "dom"]),
        ("M5-WEB-002", "medium", "How does Cross-Site Request Forgery (CSRF) work and how does SameSite cookie prevent it?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.WEB_APPLICATION_SECURITY, ["samesite", "anti-csrf token"]),
        ("M5-WEB-003", "medium", "What is Broken Object Level Authorization (BOLA/IDOR) in REST APIs?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.API_SECURITY, ["object id", "ownership"]),
        ("M5-WEB-004", "hard", "Explain HTTP Request Smuggling TE.CL desynchronization.", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.WEB_APPLICATION_SECURITY, ["transfer-encoding", "content-length"]),
        ("M5-WEB-005", "medium", "How does Server-Side Request Forgery (SSRF) allow attackers to reach cloud metadata?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.WEB_APPLICATION_SECURITY, ["169.254.169.254", "internal network"]),
        ("M5-WEB-006", "easy", "What is SQL Injection and how do parameterized queries neutralize it?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.WEB_APPLICATION_SECURITY, ["prepared statements", "syntax"]),
        ("M5-WEB-007", "medium", "Explain Mass Assignment vulnerabilities in modern API frameworks.", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.API_SECURITY, ["object binding", "allowlist"]),
        ("M5-WEB-008", "hard", "How does prototype pollution in JavaScript lead to remote code execution?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.WEB_APPLICATION_SECURITY, ["__proto__", "object hierarchy"]),
        ("M5-WEB-009", "medium", "What is CORS misconfiguration with Access-Control-Allow-Credentials?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.WEB_APPLICATION_SECURITY, ["origin reflection", "credentials"]),
        ("M5-WEB-010", "hard", "Explain web cache poisoning and unkeyed header injection.", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.WEB_APPLICATION_SECURITY, ["cache key", "unkeyed input"]),
    ]
    for cid, diff, q, task, mode, dom, kw in web_api:
        cases.append(M5CopilotEvaluationCase(
            case_id=cid, category="Web & API Security", difficulty=diff, question=q,
            expected_intent=task, expected_mode=mode, expected_domain=dom, expected_keywords=kw,
        ))

    # Category 3: Authentication & Authorization (10 cases)
    auth_cases = [
        ("M5-AUTH-001", "easy", "How does OAuth 2.0 authorization code flow work?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.AUTHENTICATION, ["auth code", "token endpoint"]),
        ("M5-AUTH-002", "medium", "What is PKCE in OAuth and why is it essential for mobile and SPA clients?", CopilotTaskType.RESEARCH, CopilotMode.RESEARCH, SecurityDomain.AUTHENTICATION, ["code_verifier", "code_challenge"]),
        ("M5-AUTH-003", "medium", "Explain JSON Web Token (JWT) structure and 'none' algorithm flaw.", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.AUTHENTICATION, ["header", "payload", "signature"]),
        ("M5-AUTH-004", "hard", "How does SAML XML Signature Wrapping (XSW) bypass authentication?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.AUTHENTICATION, ["assertion", "digest"]),
        ("M5-AUTH-005", "medium", "Compare Role-Based Access Control (RBAC) and Attribute-Based Access Control (ABAC).", CopilotTaskType.COMPARE, CopilotMode.GENERAL_QA, SecurityDomain.AUTHORIZATION, ["roles", "attributes"]),
        ("M5-AUTH-006", "medium", "What is OpenID Connect (OIDC) and how does it build on OAuth 2.0?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.AUTHENTICATION, ["id token", "userinfo"]),
        ("M5-AUTH-007", "hard", "How does JWT key confusion between RSA public keys and HMAC secret work?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.AUTHENTICATION, ["public key as secret", "algorithm confusion"]),
        ("M5-AUTH-008", "easy", "What is session fixation and how should session IDs be managed after login?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.SESSION_SECURITY, ["regenerate session", "cookie"]),
        ("M5-AUTH-009", "medium", "Explain Broken Function Level Authorization (BFLA) in administrative APIs.", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.AUTHORIZATION, ["role check", "endpoint"]),
        ("M5-AUTH-010", "hard", "What is WebAuthn / FIDO2 and how does it resist phishing?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.AUTHENTICATION, ["origin bound", "hardware token"]),
    ]
    for cid, diff, q, task, mode, dom, kw in auth_cases:
        cases.append(M5CopilotEvaluationCase(
            case_id=cid, category="Authentication & Authorization", difficulty=diff, question=q,
            expected_intent=task, expected_mode=mode, expected_domain=dom, expected_keywords=kw,
        ))

    # Category 4: Network, DNS & TLS (10 cases)
    net_cases = [
        ("M5-NET-001", "easy", "How does the TCP 3-way handshake work?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.NETWORK_PROTOCOLS, ["syn", "syn-ack", "ack"]),
        ("M5-NET-002", "medium", "Explain DNS rebinding attacks and how web origin protections are bypassed.", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.NETWORK_PROTOCOLS, ["ttl", "loopback"]),
        ("M5-NET-003", "medium", "What is the difference between TLS 1.2 and TLS 1.3 handshakes?", CopilotTaskType.COMPARE, CopilotMode.GENERAL_QA, SecurityDomain.TLS_SECURITY, ["round trips", "cipher suites"]),
        ("M5-NET-004", "easy", "What is ARP poisoning and how does it facilitate machine-in-the-middle attacks?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.NETWORK_SECURITY, ["arp cache", "mac address"]),
        ("M5-NET-005", "medium", "Explain Server Name Indication (SNI) in TLS and encrypted SNI (ECH).", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.TLS_SECURITY, ["hostname", "client hello"]),
        ("M5-NET-006", "hard", "What is BGP route hijacking and how does RPKI mitigate it?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.NETWORK_PROTOCOLS, ["as path", "route origin authorization"]),
        ("M5-NET-007", "medium", "How does DNS over HTTPS (DoH) improve privacy and what are the enterprise security implications?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.NETWORK_PROTOCOLS, ["encryption", "resolver"]),
        ("M5-NET-008", "hard", "Explain HTTP/2 stream multiplexing and rapid reset vulnerabilities (CVE-2023-44487).", CopilotTaskType.VULNERABILITY_RESEARCH, CopilotMode.RESEARCH, SecurityDomain.NETWORK_PROTOCOLS, ["rst_stream", "ddos"]),
        ("M5-NET-009", "easy", "What are the common DNS record types: A, AAAA, CNAME, TXT, MX?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.NETWORK_PROTOCOLS, ["ip address", "alias"]),
        ("M5-NET-010", "medium", "What is mutual TLS (mTLS) and when is it required?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.TLS_SECURITY, ["client certificate", "zero trust"]),
    ]
    for cid, diff, q, task, mode, dom, kw in net_cases:
        cases.append(M5CopilotEvaluationCase(
            case_id=cid, category="Network, DNS & TLS", difficulty=diff, question=q,
            expected_intent=task, expected_mode=mode, expected_domain=dom, expected_keywords=kw,
        ))

    # Category 5: Cloud & Container Security (10 cases)
    cloud_cases = [
        ("M5-CLD-001", "medium", "How does AWS IMDSv2 mitigate SSRF attacks targeting instance credentials?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.CLOUD_SECURITY, ["put request", "token session"]),
        ("M5-CLD-002", "easy", "What are common misconfigurations in AWS S3 bucket policies?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.CLOUD_SECURITY, ["public read", "principal *"]),
        ("M5-CLD-003", "medium", "Explain Docker container escape via exposed docker.sock.", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.CONTAINER_SECURITY, ["unix socket", "host root"]),
        ("M5-CLD-004", "hard", "What is Kubernetes RBAC misconfiguration and cluster-admin escalation?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.CONTAINER_SECURITY, ["clusterrolebinding", "serviceaccount"]),
        ("M5-CLD-005", "medium", "Explain Linux namespaces and cgroups in container isolation.", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.CONTAINER_SECURITY, ["pid namespace", "resource limit"]),
        ("M5-CLD-006", "medium", "What is the security risk of running containers with --privileged flag?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.CONTAINER_SECURITY, ["cap_sys_admin", "device nodes"]),
        ("M5-CLD-007", "hard", "How do IAM role delegation and assume-role policy chains work in AWS?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.CLOUD_SECURITY, ["sts assume-role", "trust policy"]),
        ("M5-CLD-008", "medium", "Explain GCP service account key leakage and privilege escalation.", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.CLOUD_SECURITY, ["service account", "iam roles"]),
        ("M5-CLD-009", "easy", "What is a serverless function cold start security boundary?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.CLOUD_SECURITY, ["microvm", "execution environment"]),
        ("M5-CLD-010", "hard", "How do container image supply chain attacks inject malicious layers?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.CONTAINER_SECURITY, ["base image", "signed attestations"]),
    ]
    for cid, diff, q, task, mode, dom, kw in cloud_cases:
        cases.append(M5CopilotEvaluationCase(
            case_id=cid, category="Cloud & Container Security", difficulty=diff, question=q,
            expected_intent=task, expected_mode=mode, expected_domain=dom, expected_keywords=kw,
        ))

    # Category 6: Linux & Windows Security (10 cases)
    os_cases = [
        ("M5-OS-001", "medium", "Explain Linux SUID binaries and privilege escalation vectors.", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.LINUX_SECURITY, ["setuid", "root privileges"]),
        ("M5-OS-002", "medium", "What is Kerberoasting in Active Directory and how does it work?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.ACTIVE_DIRECTORY, ["spn", "tgs-rep"]),
        ("M5-OS-003", "hard", "Explain Active Directory DCSync attacks and replication rights.", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.ACTIVE_DIRECTORY, ["drsuapi", "ntlm hash"]),
        ("M5-OS-004", "easy", "What is Windows User Account Control (UAC) and common bypass concepts?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.WINDOWS_SECURITY, ["integrity level", "auto-elevate"]),
        ("M5-OS-005", "medium", "How do Linux AppArmor and SELinux enforce mandatory access control?", CopilotTaskType.COMPARE, CopilotMode.GENERAL_QA, SecurityDomain.LINUX_SECURITY, ["mac", "profiles"]),
        ("M5-OS-006", "hard", "Explain Pass-the-Hash (PtH) and credential dumping from LSASS.", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.WINDOWS_SECURITY, ["lsass", "ntlm hash"]),
        ("M5-OS-007", "medium", "What are Linux capability boundaries and how does CAP_SETUID enable root switch?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.LINUX_SECURITY, ["capabilities", "privilege drop"]),
        ("M5-OS-008", "hard", "Explain Active Directory Golden Ticket vs Silver Ticket attacks.", CopilotTaskType.COMPARE, CopilotMode.GENERAL_QA, SecurityDomain.ACTIVE_DIRECTORY, ["krbtgt", "service ticket"]),
        ("M5-OS-009", "medium", "How does Windows DPAPI protect stored secrets and browser credentials?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.WINDOWS_SECURITY, ["master key", "cryptprotectdata"]),
        ("M5-OS-010", "easy", "What is the purpose of /etc/shadow permissions in Linux security?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.LINUX_SECURITY, ["password hashes", "read permissions"]),
    ]
    for cid, diff, q, task, mode, dom, kw in os_cases:
        cases.append(M5CopilotEvaluationCase(
            case_id=cid, category="Linux & Windows Security", difficulty=diff, question=q,
            expected_intent=task, expected_mode=mode, expected_domain=dom, expected_keywords=kw,
        ))

    # Category 7: Android & Mobile Security (10 cases)
    mob_cases = [
        ("M5-MOB-001", "medium", "What are exported components in Android and why is android:exported='true' risky?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.ANDROID_SECURITY, ["intent", "permission"]),
        ("M5-MOB-002", "medium", "How does Android Keystore protect cryptographic keys against root compromise?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.ANDROID_SECURITY, ["hardware-backed", "tee"]),
        ("M5-MOB-003", "hard", "Explain dynamic instrumentation with Frida for Android SSL pinning bypass.", CopilotTaskType.EXPLAIN_TOOL, CopilotMode.TOOL_EXPLANATION, SecurityDomain.ANDROID_SECURITY, ["hooking", "trustmanager"]),
        ("M5-MOB-004", "easy", "What is Android APK signing (v1, v2, v3, v4 schemes)?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.ANDROID_SECURITY, ["signature scheme", "apk digest"]),
        ("M5-MOB-005", "medium", "Explain Android Content Provider path traversal and SQL injection.", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.ANDROID_SECURITY, ["content://", "openfile"]),
        ("M5-MOB-006", "medium", "What is iOS Keychain and how does it compare to Android Keystore?", CopilotTaskType.COMPARE, CopilotMode.GENERAL_QA, SecurityDomain.MOBILE_SECURITY, ["secure enclave", "keychain"]),
        ("M5-MOB-007", "hard", "Explain deep link validation flaws leading to OAuth account takeover in mobile apps.", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.ANDROID_SECURITY, ["custom scheme", "intent filter"]),
        ("M5-MOB-008", "easy", "What risks arise from setting android:debuggable='true' in production builds?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.ANDROID_SECURITY, ["jdwp", "debugger"]),
        ("M5-MOB-009", "medium", "How do broadcast receivers with implicit intents leak sensitive data?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.ANDROID_SECURITY, ["broadcast", "receiver permission"]),
        ("M5-MOB-010", "hard", "Explain root detection evasion mechanisms in Android security.", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.ANDROID_SECURITY, ["su binary", "magisk"]),
    ]
    for cid, diff, q, task, mode, dom, kw in mob_cases:
        cases.append(M5CopilotEvaluationCase(
            case_id=cid, category="Android & Mobile Security", difficulty=diff, question=q,
            expected_intent=task, expected_mode=mode, expected_domain=dom, expected_keywords=kw,
        ))

    # Category 8: Reverse Engineering & Malware Analysis (10 cases)
    rev_cases = [
        ("M5-REV-001", "easy", "What is the difference between static and dynamic malware analysis?", CopilotTaskType.COMPARE, CopilotMode.GENERAL_QA, SecurityDomain.MALWARE_ANALYSIS, ["sandbox", "disassembly"]),
        ("M5-REV-002", "medium", "Explain how Ghidra performs decompilation from binary assembly to C.", CopilotTaskType.EXPLAIN_TOOL, CopilotMode.TOOL_EXPLANATION, SecurityDomain.REVERSE_ENGINEERING, ["p-code", "control flow"]),
        ("M5-REV-003", "medium", "What are YARA rules and how are they used in threat hunting?", CopilotTaskType.EXPLAIN_TOOL, CopilotMode.TOOL_EXPLANATION, SecurityDomain.MALWARE_ANALYSIS, ["strings", "condition"]),
        ("M5-REV-004", "hard", "Explain process hollowing and memory injection techniques used by malware.", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.MALWARE_ANALYSIS, ["unmap", "writeprocessmemory"]),
        ("M5-REV-005", "medium", "What is binary packing and how do analysts unpack UPX executables?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.REVERSE_ENGINEERING, ["stub", "original entry point"]),
        ("M5-REV-006", "hard", "How does Volatility analyze memory dumps to identify malfind process injections?", CopilotTaskType.EXPLAIN_TOOL, CopilotMode.TOOL_EXPLANATION, SecurityDomain.DIGITAL_FORENSICS, ["vad", "page_execute_readwrite"]),
        ("M5-REV-007", "easy", "What is an Import Address Table (IAT) in PE executables?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.REVERSE_ENGINEERING, ["dll imports", "pointers"]),
        ("M5-REV-008", "medium", "Explain Command and Control (C2) beaconing and domain generation algorithms (DGA).", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.MALWARE_ANALYSIS, ["jitter", "dns entropy"]),
        ("M5-REV-009", "hard", "What is anti-debugging and how do binaries detect ptrace or IsDebuggerPresent?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.REVERSE_ENGINEERING, ["peb", "timing"]),
        ("M5-REV-010", "medium", "Explain ransomware encryption workflows and key generation boundaries.", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.MALWARE_ANALYSIS, ["hybrid encryption", "asymmetric"]),
    ]
    for cid, diff, q, task, mode, dom, kw in rev_cases:
        cases.append(M5CopilotEvaluationCase(
            case_id=cid, category="Reverse Engineering & Malware", difficulty=diff, question=q,
            expected_intent=task, expected_mode=mode, expected_domain=dom, expected_keywords=kw,
        ))

    # Category 9: Secure Coding (5 cases)
    code_cases = [
        ("M5-COD-001", "easy", "How do parameterized queries prevent SQL injection in Go?", CopilotTaskType.CODE_SECURITY_REVIEW, CopilotMode.GENERAL_QA, SecurityDomain.SECURE_CODING, ["sql.db", "placeholder"]),
        ("M5-COD-002", "medium", "What constitutes safe deserialization in Python applications?", CopilotTaskType.CODE_SECURITY_REVIEW, CopilotMode.GENERAL_QA, SecurityDomain.SECURE_CODING, ["json", "avoid pickle"]),
        ("M5-COD-003", "medium", "Review safe cryptographic random number generation in Java (SecureRandom vs Random).", CopilotTaskType.CODE_SECURITY_REVIEW, CopilotMode.GENERAL_QA, SecurityDomain.SECURE_CODING, ["securerandom", "entropy"]),
        ("M5-COD-004", "hard", "Explain memory safety guarantees in Rust vs C++ buffer overflows.", CopilotTaskType.COMPARE, CopilotMode.GENERAL_QA, SecurityDomain.SECURE_CODING, ["borrow checker", "bounds checking"]),
        ("M5-COD-005", "medium", "What are best practices for secrets management in source control?", CopilotTaskType.EXPLAIN, CopilotMode.GENERAL_QA, SecurityDomain.SECURE_CODING, ["environment variables", "vault"]),
    ]
    for cid, diff, q, task, mode, dom, kw in code_cases:
        cases.append(M5CopilotEvaluationCase(
            case_id=cid, category="Secure Coding", difficulty=diff, question=q,
            expected_intent=task, expected_mode=mode, expected_domain=dom, expected_keywords=kw,
        ))

    # Category 10: Tool Interpretation (5 cases)
    tool_cases = [
        ("M5-TOL-001", "easy", "How does Nmap -sV service detection work and what does 'filtered' mean?", CopilotTaskType.EXPLAIN_TOOL, CopilotMode.TOOL_EXPLANATION, SecurityDomain.SECURITY_TOOLING, ["probes", "firewall"]),
        ("M5-TOL-002", "medium", "How do I use Burp Suite Intruder without causing a denial of service?", CopilotTaskType.EXPLAIN_TOOL, CopilotMode.TOOL_EXPLANATION, SecurityDomain.SECURITY_TOOLING, ["throttle", "threads"]),
        ("M5-TOL-003", "medium", "How does Semgrep differentiate between taint sources and sinks?", CopilotTaskType.EXPLAIN_TOOL, CopilotMode.TOOL_EXPLANATION, SecurityDomain.SECURITY_TOOLING, ["pattern-sources", "pattern-sinks"]),
        ("M5-TOL-004", "hard", "Explain how Wireshark decrypts TLS traffic using an SSLKEYLOGFILE.", CopilotTaskType.EXPLAIN_TOOL, CopilotMode.TOOL_EXPLANATION, SecurityDomain.SECURITY_TOOLING, ["pre-master secret", "pcap"]),
        ("M5-TOL-005", "medium", "What is the difference between ffuf and gobuster in web fuzzing?", CopilotTaskType.COMPARE, CopilotMode.GENERAL_QA, SecurityDomain.SECURITY_TOOLING, ["fuzzing keyword", "filtering"]),
    ]
    for cid, diff, q, task, mode, dom, kw in tool_cases:
        cases.append(M5CopilotEvaluationCase(
            case_id=cid, category="Tool Interpretation", difficulty=diff, question=q,
            expected_intent=task, expected_mode=mode, expected_domain=dom, expected_keywords=kw,
        ))

    # Category 11: Investigation Reasoning (5 cases)
    inv_cases = [
        ("M5-INV-001", "medium", "Observed HTTP 200 on /api/v1/workspaces/99 when authenticated as tenant 42. What is the hypothesis?", CopilotTaskType.INVESTIGATE, CopilotMode.INVESTIGATION, SecurityDomain.API_SECURITY, ["bola", "idor"]),
        ("M5-INV-002", "medium", "Observed HTTP 403 on tenant B invoice. Does this confirm an IDOR vulnerability?", CopilotTaskType.VERIFY_HYPOTHESIS, CopilotMode.INVESTIGATION, SecurityDomain.AUTHORIZATION, ["negative control", "not vulnerable"]),
        ("M5-INV-003", "hard", "What evidence gap exists when observing unauthenticated access to /catalog/products?", CopilotTaskType.IDENTIFY_EVIDENCE_GAP, CopilotMode.INVESTIGATION, SecurityDomain.API_SECURITY, ["public catalog", "missing private object"]),
        ("M5-INV-004", "hard", "Design a manual experiment to verify if role escalation to admin is possible on /admin/users.", CopilotTaskType.DESIGN_EXPERIMENT, CopilotMode.INVESTIGATION, SecurityDomain.AUTHORIZATION, ["differential test", "low privilege"]),
        ("M5-INV-005", "medium", "Interpret this HTTP response: HTTP/1.1 401 Unauthorized WWW-Authenticate: Bearer error='invalid_token'.", CopilotTaskType.INTERPRET_EVIDENCE, CopilotMode.INVESTIGATION, SecurityDomain.AUTHENTICATION, ["token rejected", "expired"]),
    ]
    for cid, diff, q, task, mode, dom, kw in inv_cases:
        cases.append(M5CopilotEvaluationCase(
            case_id=cid, category="Investigation Reasoning", difficulty=diff, question=q,
            expected_intent=task, expected_mode=mode, expected_domain=dom, is_evidence_grounded=True,
            expected_escalation=True, expected_keywords=kw,
        ))

    return cases


def build_30_case_investigation_benchmark() -> List[M5InvestigationBenchmarkCase]:
    """Generates the canonical 30-case synthetic investigation benchmark per Section 40."""
    cases: List[M5InvestigationBenchmarkCase] = []

    domains_distribution = [
        (SecurityDomain.API_SECURITY, 5),
        (SecurityDomain.AUTHORIZATION, 5),
        (SecurityDomain.AUTHENTICATION, 4),
        (SecurityDomain.WEB_APPLICATION_SECURITY, 4),
        (SecurityDomain.CLOUD_SECURITY, 3),
        (SecurityDomain.CONTAINER_SECURITY, 3),
        (SecurityDomain.ANDROID_SECURITY, 3),
        (SecurityDomain.TLS_SECURITY, 3),
    ]

    counter = 1
    for domain, count in domains_distribution:
        for idx in range(count):
            cid = f"INV-BENCH-{counter:03d}"
            target_asset = f"api-{domain.value.lower()[:6]}-test.internal"
            obs = [
                {
                    "observation_id": f"FACT-{cid}-01",
                    "endpoint": f"/api/v1/{domain.value.lower()[:6]}/resource/{idx + 100}",
                    "http_method": "GET" if idx % 2 == 0 else "POST",
                    "status_code": 200,
                    "summary": f"Observed response on {domain.value} endpoint under test condition",
                }
            ]
            cases.append(
                M5InvestigationBenchmarkCase(
                    case_id=cid,
                    domain=domain,
                    target_asset=target_asset,
                    target_evidence=obs,
                    known_facts=[f"Target host {target_asset} is within authorized testing scope."],
                    expected_hypotheses=[f"Hypothesis {counter}: Potential boundary invalidation in {domain.value}."],
                    expected_invariants=[f"Security Invariant: Server must enforce {domain.value} rules on every request."],
                    expected_evidence_gaps=[f"Evidence Gap: Missing differential test observation with unprivileged identity."],
                    expected_experiments=[{
                        "objective": f"Verify {domain.value} boundary enforcement",
                        "steps": ["Issue request with unauthorized test credentials", "Inspect HTTP response status code"],
                        "expected_secure": "HTTP 403 Forbidden",
                        "expected_vulnerable": "HTTP 200 OK with unauthorized resource body",
                    }],
                    expected_falsification=f"Access denied with HTTP 403 or 404 when unauthorized identity accesses resource.",
                    negative_controls=[f"Verify if endpoint is documented as an intentionally public resource."],
                    forbidden_conclusions=["Confirmed finding without human verification.", "Vulnerability confirmed on target."],
                )
            )
            counter += 1

    return cases


def generate_and_save_all_m5_datasets(base_dir: Optional[Path] = None) -> Tuple[Path, Path]:
    """Serializes both evaluation datasets to disk."""
    eval_dir = (base_dir or Path("data/eval"))
    eval_dir.mkdir(parents=True, exist_ok=True)

    copilot_dataset_path = eval_dir / "m5_copilot_evaluation_dataset.json"
    investigation_dataset_path = eval_dir / "m5_investigation_benchmark_dataset.json"

    copilot_cases = build_100_case_evaluation_dataset()
    investigation_cases = build_30_case_investigation_benchmark()

    with open(copilot_dataset_path, "w", encoding="utf-8") as f:
        json.dump([c.model_dump() for c in copilot_cases], f, indent=2)

    with open(investigation_dataset_path, "w", encoding="utf-8") as f:
        json.dump([c.model_dump() for c in investigation_cases], f, indent=2)

    return copilot_dataset_path, investigation_dataset_path


if __name__ == "__main__":
    p1, p2 = generate_and_save_all_m5_datasets()
    print(f"Generated M5 Copilot Dataset: {p1} (100 cases)")
    print(f"Generated M5 Investigation Dataset: {p2} (30 cases)")
