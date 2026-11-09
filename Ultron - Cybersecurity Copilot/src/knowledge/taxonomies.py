"""Authoritative Cybersecurity Taxonomy Resolver (Milestone M9 Phase 15).

Provides structured data lookup for:
- CVE (Common Vulnerabilities and Exposures)
- CWE (Common Weakness Enumeration)
- CAPEC (Common Attack Pattern Enumeration and Classification)
- CVSS v3.1 Metrics
- MITRE ATT&CK Enterprise Matrix

Hard Invariant:
    INV-M9-12: No unsupported CVE/CWE/CAPEC attribution.
    When an unknown identifier is queried, the resolver must deterministically return
    'UNKNOWN / NOT FOUND' rather than hallucinating fake descriptions or scores.
"""

from enum import Enum
import re
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class TaxonomyLookupResult(BaseModel):
    identifier: str
    found: bool
    taxonomy_type: str  # "CVE", "CWE", "CAPEC", "ATT&CK", "CVSS"
    name: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    remediation: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    raw_record: Optional[Dict[str, Any]] = None


class TaxonomyResolver:
    """Deterministic resolver for cybersecurity taxonomies with strict fail-closed lookup."""

    _CWES: Dict[str, Dict[str, Any]] = {
        "CWE-89": {
            "name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
            "description": "The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command.",
            "severity": "HIGH",
            "remediation": "Use parameterized queries (prepared statements) or stored procedures that bind variables rather than string concatenation.",
            "references": ["https://cwe.mitre.org/data/definitions/89.html", "OWASP SQL Injection Prevention Cheat Sheet"]
        },
        "CWE-79": {
            "name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
            "description": "The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.",
            "severity": "MEDIUM",
            "remediation": "Context-aware output encoding, strict Content Security Policy (CSP), and utilizing safe templating frameworks.",
            "references": ["https://cwe.mitre.org/data/definitions/79.html", "OWASP XSS Prevention Cheat Sheet"]
        },
        "CWE-78": {
            "name": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
            "description": "The software constructs an OS command using externally-influenced input, allowing attackers to execute arbitrary system commands.",
            "severity": "CRITICAL",
            "remediation": "Avoid invoking operating system shells. Use programming language built-in APIs with argument arrays (e.g. execFile, subprocess.run([cmd, arg])).",
            "references": ["https://cwe.mitre.org/data/definitions/78.html"]
        },
        "CWE-918": {
            "name": "Server-Side Request Forgery (SSRF)",
            "description": "The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination.",
            "severity": "HIGH",
            "remediation": "Validate destination URLs against a strict allowlist. Disable HTTP redirects. Block loopback and link-local IP addresses (127.0.0.1, 169.254.169.254).",
            "references": ["https://cwe.mitre.org/data/definitions/918.html", "OWASP SSRF Prevention Cheat Sheet"]
        },
        "CWE-639": {
            "name": "Authorization Bypass Through User-Controlled Key (IDOR)",
            "description": "The system's authorization functionality does not prevent one user from accessing another user's data or resources by directly providing the key or identifier associated with that resource.",
            "severity": "HIGH",
            "remediation": "Implement robust server-side authorization checks verifying that the authenticated user owns or has access rights to the requested object identifier.",
            "references": ["https://cwe.mitre.org/data/definitions/639.html", "OWASP API Security Top 10 API1:2023"]
        },
        "CWE-285": {
            "name": "Improper Authorization",
            "description": "The software does not perform or incorrectly performs an authorization check when an actor attempts to access a resource or perform an action.",
            "severity": "HIGH",
            "remediation": "Apply role-based and function-level access control checks uniformly at the controller and business logic layers.",
            "references": ["https://cwe.mitre.org/data/definitions/285.html"]
        },
        "CWE-502": {
            "name": "Deserialization of Untrusted Data",
            "description": "The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid.",
            "severity": "CRITICAL",
            "remediation": "Avoid native serialization formats. Use pure data formats like JSON or Protocol Buffers. Implement ObjectInputFilter type checking.",
            "references": ["https://cwe.mitre.org/data/definitions/502.html"]
        },
        "CWE-121": {
            "name": "Stack-based Buffer Overflow",
            "description": "A stack-based buffer overflow condition exists when a program writes more data to a buffer located on the stack than what is actually allocated for that buffer.",
            "severity": "CRITICAL",
            "remediation": "Use safe string handling functions (e.g., strncpy instead of strcpy). Enable compiler protections (-fstack-protector-all, ASLR, DEP).",
            "references": ["https://cwe.mitre.org/data/definitions/121.html"]
        },
        "CWE-352": {
            "name": "Cross-Site Request Forgery (CSRF)",
            "description": "The web application does not, or can not, sufficiently verify whether a well-formed, valid, consistent request was intentionally provided by the user who submitted the request.",
            "severity": "MEDIUM",
            "remediation": "Enforce anti-CSRF synchronizer tokens, SameSite=Strict cookies, and require re-authentication for sensitive actions.",
            "references": ["https://cwe.mitre.org/data/definitions/352.html"]
        },
        "CWE-327": {
            "name": "Use of a Broken or Risky Cryptographic Algorithm",
            "description": "The use of a broken or risky cryptographic algorithm will result in weak security or complete compromise of confidentiality and integrity.",
            "severity": "HIGH",
            "remediation": "Utilize modern authenticated encryption algorithms like AES-GCM or ChaCha20-Poly1305. Deprecate ECB mode, DES, and RC4.",
            "references": ["https://cwe.mitre.org/data/definitions/327.html"]
        }
    }

    _CVES: Dict[str, Dict[str, Any]] = {
        "CVE-2021-44228": {
            "name": "Log4Shell",
            "description": "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.",
            "severity": "CRITICAL",
            "cvss_score": 10.0,
            "remediation": "Upgrade to Apache Log4j 2.17.1 or higher. In legacy versions, set log4j2.formatMsgNoLookups=true or remove JndiLookup class.",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228", "Apache Log4j Security Vulnerabilities"]
        },
        "CVE-2022-22965": {
            "name": "Spring4Shell",
            "description": "Spring Framework RCE via Data Binding on JDK 9+. A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution via class loader binding to Tomcat AccessLogValve.",
            "severity": "CRITICAL",
            "cvss_score": 9.8,
            "remediation": "Upgrade Spring Framework to 5.3.18 / 5.2.20 or newer, or run on JDK 8.",
            "references": ["https://tanzu.vmware.com/security/cve-2022-22965", "https://nvd.nist.gov/vuln/detail/CVE-2022-22965"]
        },
        "CVE-2014-0160": {
            "name": "Heartbleed",
            "description": "The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, allowing remote attackers to obtain sensitive information from process memory.",
            "severity": "HIGH",
            "cvss_score": 7.5,
            "remediation": "Upgrade OpenSSL to version 1.0.1g or compile with -DOPENSSL_NO_HEARTBEATS.",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2014-0160"]
        },
        "CVE-2021-42278": {
            "name": "Active Directory sAMAccountName Spoofing",
            "description": "Active Directory Domain Services Privilege Escalation Vulnerability. Attackers bypass sAMAccountName trailing dollar sign validation on computer accounts to spoof domain controllers.",
            "severity": "HIGH",
            "cvss_score": 8.8,
            "remediation": "Apply Microsoft Security Update KB5008380 / KB5008602.",
            "references": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278"]
        }
    }

    _CAPECS: Dict[str, Dict[str, Any]] = {
        "CAPEC-66": {
            "name": "SQL Injection",
            "description": "An attacker exploits vulnerabilities in input validation to inject malicious SQL commands that modify the database query execution.",
            "severity": "HIGH",
            "references": ["https://capec.mitre.org/data/definitions/66.html"]
        },
        "CAPEC-63": {
            "name": "Simple Script Injection",
            "description": "An attacker injects malicious client-side scripts into a web application which executes within a victim user's browser context.",
            "severity": "MEDIUM",
            "references": ["https://capec.mitre.org/data/definitions/63.html"]
        }
    }

    _ATTACK_TACTICS: Dict[str, Dict[str, Any]] = {
        "T1558.003": {
            "name": "Steal or Forge Kerberos Tickets: Kerberoasting",
            "description": "Adversaries may look for service accounts registered with Service Principal Names (SPNs) and request Kerberos ticket-granting service (TGS) tickets to crack the hashes offline.",
            "severity": "HIGH",
            "references": ["https://attack.mitre.org/techniques/T1558/003/"]
        },
        "T1003.001": {
            "name": "OS Credential Dumping: LSASS Memory",
            "description": "Adversaries may attempt to dump credentials from the Local Security Authority Subsystem Service (LSASS) process memory.",
            "severity": "HIGH",
            "references": ["https://attack.mitre.org/techniques/T1003/001/"]
        }
    }

    @classmethod
    def lookup_cwe(cls, cwe_id: str) -> TaxonomyLookupResult:
        """Looks up a CWE identifier. Returns NOT FOUND if unknown."""
        norm_id = cwe_id.strip().upper().replace(" ", "-")
        if not norm_id.startswith("CWE-"):
            norm_id = f"CWE-{norm_id}"

        if norm_id in cls._CWES:
            data = cls._CWES[norm_id]
            return TaxonomyLookupResult(
                identifier=norm_id,
                found=True,
                taxonomy_type="CWE",
                name=data["name"],
                description=data["description"],
                severity=data.get("severity"),
                remediation=data.get("remediation"),
                references=data.get("references", []),
                raw_record=data,
            )
        return TaxonomyLookupResult(
            identifier=norm_id,
            found=False,
            taxonomy_type="CWE",
            description="UNKNOWN / NOT FOUND in local CWE registry.",
        )

    @classmethod
    def lookup_cve(cls, cve_id: str) -> TaxonomyLookupResult:
        """Looks up a CVE identifier. Returns NOT FOUND if unknown."""
        norm_id = cve_id.strip().upper()
        if norm_id in cls._CVES:
            data = cls._CVES[norm_id]
            return TaxonomyLookupResult(
                identifier=norm_id,
                found=True,
                taxonomy_type="CVE",
                name=data["name"],
                description=data["description"],
                severity=data.get("severity"),
                cvss_score=data.get("cvss_score"),
                remediation=data.get("remediation"),
                references=data.get("references", []),
                raw_record=data,
            )
        return TaxonomyLookupResult(
            identifier=norm_id,
            found=False,
            taxonomy_type="CVE",
            description="UNKNOWN / NOT FOUND in local CVE registry.",
        )

    @classmethod
    def lookup_capec(cls, capec_id: str) -> TaxonomyLookupResult:
        """Looks up a CAPEC identifier. Returns NOT FOUND if unknown."""
        norm_id = capec_id.strip().upper()
        if not norm_id.startswith("CAPEC-"):
            norm_id = f"CAPEC-{norm_id}"

        if norm_id in cls._CAPECS:
            data = cls._CAPECS[norm_id]
            return TaxonomyLookupResult(
                identifier=norm_id,
                found=True,
                taxonomy_type="CAPEC",
                name=data["name"],
                description=data["description"],
                severity=data.get("severity"),
                references=data.get("references", []),
                raw_record=data,
            )
        return TaxonomyLookupResult(
            identifier=norm_id,
            found=False,
            taxonomy_type="CAPEC",
            description="UNKNOWN / NOT FOUND in local CAPEC registry.",
        )

    @classmethod
    def lookup_attack(cls, tech_id: str) -> TaxonomyLookupResult:
        """Looks up a MITRE ATT&CK technique. Returns NOT FOUND if unknown."""
        norm_id = tech_id.strip().upper()
        if norm_id in cls._ATTACK_TACTICS:
            data = cls._ATTACK_TACTICS[norm_id]
            return TaxonomyLookupResult(
                identifier=norm_id,
                found=True,
                taxonomy_type="ATT&CK",
                name=data["name"],
                description=data["description"],
                severity=data.get("severity"),
                references=data.get("references", []),
                raw_record=data,
            )
        return TaxonomyLookupResult(
            identifier=norm_id,
            found=False,
            taxonomy_type="ATT&CK",
            description="UNKNOWN / NOT FOUND in local MITRE ATT&CK registry.",
        )
