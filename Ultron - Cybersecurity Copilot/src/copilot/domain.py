"""Security Domain Classifier and Multi-Domain Router (Milestone M5).

Maps user questions and investigation artifacts into 26 structured cybersecurity domains:
- NETWORK_SECURITY, WEB_APPLICATION_SECURITY, API_SECURITY, AUTHENTICATION, AUTHORIZATION
- SESSION_SECURITY, CLOUD_SECURITY, CONTAINER_SECURITY, LINUX_SECURITY, WINDOWS_SECURITY
- ACTIVE_DIRECTORY, CRYPTOGRAPHY, MALWARE_ANALYSIS, REVERSE_ENGINEERING, ANDROID_SECURITY
- MOBILE_SECURITY, NETWORK_PROTOCOLS, TLS_SECURITY, SECURE_CODING, VULNERABILITY_RESEARCH
- BUG_BOUNTY_RESEARCH, SECURITY_ARCHITECTURE, INCIDENT_ANALYSIS, DIGITAL_FORENSICS
- SECURITY_TOOLING, GENERAL_CYBERSECURITY
"""

from enum import Enum
import re
from typing import Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field


class SecurityDomain(str, Enum):
    """The 26 authoritative cybersecurity domains supported by M5."""
    NETWORK_SECURITY = "NETWORK_SECURITY"
    WEB_APPLICATION_SECURITY = "WEB_APPLICATION_SECURITY"
    API_SECURITY = "API_SECURITY"
    AUTHENTICATION = "AUTHENTICATION"
    AUTHORIZATION = "AUTHORIZATION"
    SESSION_SECURITY = "SESSION_SECURITY"
    CLOUD_SECURITY = "CLOUD_SECURITY"
    CONTAINER_SECURITY = "CONTAINER_SECURITY"
    LINUX_SECURITY = "LINUX_SECURITY"
    WINDOWS_SECURITY = "WINDOWS_SECURITY"
    ACTIVE_DIRECTORY = "ACTIVE_DIRECTORY"
    CRYPTOGRAPHY = "CRYPTOGRAPHY"
    MALWARE_ANALYSIS = "MALWARE_ANALYSIS"
    REVERSE_ENGINEERING = "REVERSE_ENGINEERING"
    ANDROID_SECURITY = "ANDROID_SECURITY"
    MOBILE_SECURITY = "MOBILE_SECURITY"
    NETWORK_PROTOCOLS = "NETWORK_PROTOCOLS"
    TLS_SECURITY = "TLS_SECURITY"
    SECURE_CODING = "SECURE_CODING"
    VULNERABILITY_RESEARCH = "VULNERABILITY_RESEARCH"
    BUG_BOUNTY_RESEARCH = "BUG_BOUNTY_RESEARCH"
    SECURITY_ARCHITECTURE = "SECURITY_ARCHITECTURE"
    INCIDENT_ANALYSIS = "INCIDENT_ANALYSIS"
    DIGITAL_FORENSICS = "DIGITAL_FORENSICS"
    SECURITY_TOOLING = "SECURITY_TOOLING"
    GENERAL_CYBERSECURITY = "GENERAL_CYBERSECURITY"


class DomainClassificationResult(BaseModel):
    """Structured result of security domain classification."""
    primary_domain: SecurityDomain
    secondary_domains: List[SecurityDomain] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0, default=0.85)
    matched_keywords: List[str] = Field(default_factory=list)


class DomainRouter:
    """Deterministic keyword- and pattern-driven security domain classifier."""

    DOMAIN_KEYWORDS: Dict[SecurityDomain, List[str]] = {
        SecurityDomain.ANDROID_SECURITY: [
            "android", "apk", "apktool", "jadx", "frida", "intent", "broadcast receiver",
            "manifest.xml", "dex", "smali", "shared preferences", "keystore"
        ],
        SecurityDomain.MOBILE_SECURITY: [
            "mobile", "ios", "ipa", "jailbreak", "root detection", "keychain", "plist"
        ],
        SecurityDomain.API_SECURITY: [
            "api", "rest", "graphql", "endpoint", "bola", "bfla", "idor", "swagger", "openapi", "postman", "jwt"
        ],
        SecurityDomain.AUTHORIZATION: [
            "authorization", "rbac", "abac", "role", "privilege", "tenant", "access control", "permission", "bfla", "bola", "idor", "invoice"
        ],
        SecurityDomain.AUTHENTICATION: [
            "authentication", "oauth", "oidc", "saml", "pkce", "password", "mfa", "2fa", "credential", "login", "jwt", "token"
        ],
        SecurityDomain.SESSION_SECURITY: [
            "session", "cookie", "samesite", "httponly", "csrf", "fixation", "session hijacking", "jwt revocation"
        ],
        SecurityDomain.WEB_APPLICATION_SECURITY: [
            "xss", "sqli", "sql injection", "ssrf", "cors", "csrf", "path traversal", "lfi", "rfi", "file upload",
            "prototype pollution", "template injection", "ssti", "owasp top 10"
        ],
        SecurityDomain.CRYPTOGRAPHY: [
            "cryptography", "crypto", "aes", "rsa", "ecc", "sha-256", "hmac", "encryption", "decryption", "hash", "cipher", "nonce", "signature", "jwt"
        ],
        SecurityDomain.TLS_SECURITY: [
            "tls", "ssl", "certificate", "sni", "x509", "handshake", "cipher suite", "mTLS", "hsts", "heartbleed"
        ],
        SecurityDomain.NETWORK_PROTOCOLS: [
            "dns", "tcp", "udp", "ip", "http", "http/2", "http/3", "quic", "bgp", "arp", "icmp", "dhcp"
        ],
        SecurityDomain.NETWORK_SECURITY: [
            "firewall", "ids", "ips", "wireshark", "pcap", "nmap", "packet", "vpn", "port scan", "subdomain"
        ],
        SecurityDomain.CLOUD_SECURITY: [
            "aws", "azure", "gcp", "s3", "iam", "cloudtrail", "cloudwatch", "lambda", "ec2", "metadata service", "169.254.169.254"
        ],
        SecurityDomain.CONTAINER_SECURITY: [
            "docker", "kubernetes", "k8s", "container", "pod", "namespace", "cgroups", "container escape", "helm"
        ],
        SecurityDomain.LINUX_SECURITY: [
            "linux", "sudo", "suid", "cron", "etc/shadow", "etc/passwd", "selinux", "apparmor", "kernel", "chroot"
        ],
        SecurityDomain.WINDOWS_SECURITY: [
            "windows", "uac", "registry", "powershell", "lsass", "sam", "defender", "bitlocker", "kerberos", "ntlm"
        ],
        SecurityDomain.ACTIVE_DIRECTORY: [
            "active directory", "ad", "domain controller", "gpo", "bloodhound", "mimikatz", "dcsync", "pass-the-hash", "golden ticket"
        ],
        SecurityDomain.REVERSE_ENGINEERING: [
            "reverse engineering", "ghidra", "ida pro", "disassembly", "decompile", "binary", "elf", "pe", "gdb", "radare2"
        ],
        SecurityDomain.MALWARE_ANALYSIS: [
            "malware", "ransomware", "trojan", "c2", "command and control", "sandbox", "yara", "persistence", "dropper"
        ],
        SecurityDomain.DIGITAL_FORENSICS: [
            "forensics", "volatility", "memory dump", "disk image", "autopsy", "timeline", "mft", "prefetch"
        ],
        SecurityDomain.INCIDENT_ANALYSIS: [
            "incident response", "soc", "siem", "splunk", "elastic", "alert", "triage", "breach", "ioc", "sigma"
        ],
        SecurityDomain.SECURITY_TOOLING: [
            "burp", "zap", "nmap", "ffuf", "sqlmap", "semgrep", "curl", "gobuster", "nuclei", "metasploit"
        ],
        SecurityDomain.SECURE_CODING: [
            "secure coding", "code review", "sast", "semgrep", "sanitization", "prepared statement", "parameterized", "safe api"
        ],
        SecurityDomain.BUG_BOUNTY_RESEARCH: [
            "bug bounty", "hackerone", "bugcrowd", "scope", "hall of fame", "triaged", "bounty", "impact"
        ],
        SecurityDomain.VULNERABILITY_RESEARCH: [
            "cve", "zero-day", "advisory", "vulnerability research", "exploit-db", "poc", "cvss"
        ],
        SecurityDomain.SECURITY_ARCHITECTURE: [
            "security architecture", "threat model", "stride", "zero trust", "defense in depth", "boundary"
        ],
    }

    @classmethod
    def classify_domain(cls, query: str) -> DomainClassificationResult:
        """
        Deterministically classifies query into primary and secondary security domains.
        """
        text = query.lower()
        domain_scores: Dict[SecurityDomain, Tuple[int, List[str]]] = {}

        for domain, keywords in cls.DOMAIN_KEYWORDS.items():
            matches = []
            for kw in keywords:
                if re.search(rf"\b{re.escape(kw)}\b", text):
                    matches.append(kw)
            if matches:
                domain_scores[domain] = (len(matches), matches)

        if not domain_scores:
            return DomainClassificationResult(
                primary_domain=SecurityDomain.GENERAL_CYBERSECURITY,
                secondary_domains=[],
                confidence=0.50,
                matched_keywords=[],
            )

        # Sort domains by match count
        sorted_domains = sorted(domain_scores.items(), key=lambda item: item[1][0], reverse=True)
        primary = sorted_domains[0][0]
        primary_matches = sorted_domains[0][1][1]

        secondary = [d[0] for d in sorted_domains[1:3]]

        confidence = min(0.60 + 0.15 * len(primary_matches), 0.98)

        return DomainClassificationResult(
            primary_domain=primary,
            secondary_domains=secondary,
            confidence=confidence,
            matched_keywords=primary_matches,
        )
