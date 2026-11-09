"""Cybersecurity Query Rewriter & Identifier Normalizer (Milestone M9 Phase 6).

Implements cybersecurity-aware query expansion and normalization:
- Acronym expansion (SSRF, CSRF, XSS, IDOR, BOLA, BFLA, ROP, UAF, PKCE, ASLR, etc.)
- Canonical CWE mapping (CWE-89, CWE-79, CWE-78, CWE-918, CWE-639, CWE-352, etc.)
- Major CVE alias mapping (CVE-2021-44228 -> Log4Shell, CVE-2022-22965 -> Spring4Shell, etc.)
- Security terminology and taxonomy normalization
- Hard Invariant: Query expansion MUST improve search without asserting unfounded conclusions.
"""

import re
from typing import Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field

from src.knowledge.canonical_models import KnowledgeQuery


class QueryExpansionResult(BaseModel):
    raw_query: str
    rewritten_query: str
    expanded_terms: List[str] = Field(default_factory=list)
    identified_cwes: List[str] = Field(default_factory=list)
    identified_cves: List[str] = Field(default_factory=list)
    identified_acronyms: List[str] = Field(default_factory=list)
    extracted_domain: str = "GENERAL_VAPT"


class CybersecurityQueryRewriter:
    """Expands queries with domain synonyms without jumping to unsupported exploit conclusions."""

    # Acronym Dictionary with conservative conceptual expansions
    ACRONYMS: Dict[str, Tuple[str, List[str]]] = {
        "ssrf": ("Server-Side Request Forgery", ["CWE-918", "metadata endpoint", "loopback access"]),
        "csrf": ("Cross-Site Request Forgery", ["CWE-352", "SameSite", "anti-CSRF token"]),
        "xss": ("Cross-Site Scripting", ["CWE-79", "DOM XSS", "Reflected XSS", "Stored XSS"]),
        "sqli": ("SQL Injection", ["CWE-89", "parameterized queries", "database query"]),
        "idor": ("Insecure Direct Object References", ["CWE-639", "object level authorization", "horizontal access"]),
        "bola": ("Broken Object Level Authorization", ["API1:2023", "object level authorization", "CWE-639"]),
        "bfla": ("Broken Function Level Authorization", ["API5:2023", "administrative access", "CWE-285"]),
        "jwt": ("JSON Web Token", ["RFC 7519", "RFC 8725", "token signature", "claims validation"]),
        "oauth": ("OAuth 2.0 Authorization Framework", ["RFC 6749", "authorization code", "access token"]),
        "pkce": ("Proof Key for Code Exchange", ["RFC 7636", "code_verifier", "code_challenge"]),
        "saml": ("Security Assertion Markup Language", ["SAML 2.0", "XML Signature", "assertion"]),
        "xxe": ("XML External Entity", ["CWE-611", "DOCTYPE entity", "XML parser"]),
        "ssti": ("Server-Side Template Injection", ["CWE-1336", "template engine"]),
        "rop": ("Return-Oriented Programming", ["ROP gadgets", "DEP NX bypass", "binary exploitation"]),
        "uaf": ("Use-After-Free", ["CWE-416", "heap exploitation", "dangling pointer"]),
        "aslr": ("Address Space Layout Randomization", ["binary mitigation", "memory randomization"]),
        "dep": ("Data Execution Prevention", ["W^X", "non-executable stack", "NX bit"]),
        "nx": ("No-Execute", ["Data Execution Prevention", "binary mitigation"]),
        "relro": ("Relocation Read-Only", ["GOT overwrite mitigation", "Global Offset Table"]),
        "smali": ("Smali Bytecode", ["DEX disassembly", "Apktool", "Android reversing"]),
        "apk": ("Android Application Package", ["AndroidManifest.xml", "classes.dex", "mobile app"]),
        "mfa": ("Multi-Factor Authentication", ["two-factor authentication", "OTP", "authentication step"]),
        "rbac": ("Role-Based Access Control", ["roles", "permissions", "access control policy"]),
        "abac": ("Attribute-Based Access Control", ["attributes", "dynamic policy", "NIST SP 800-162"]),
        "imds": ("Instance Metadata Service", ["AWS metadata", "169.254.169.254", "IMDSv2"]),
        "gpo": ("Group Policy Object", ["Active Directory GPO", "domain policy"]),
        "tgt": ("Ticket Granting Ticket", ["Kerberos KDC", "AS-REP", "krbtgt"]),
        "tgs": ("Ticket Granting Service", ["Kerberos SPN", "service ticket"]),
        "spn": ("Service Principal Name", ["Active Directory service account", "Kerberoasting"]),
        "ddos": ("Distributed Denial of Service", ["volumetric attack", "traffic flooding", "amplification", "rate limiting"]),
        "dos": ("Denial of Service", ["resource exhaustion", "availability impact", "service disruption"]),
        "authn": ("Authentication", ["identity verification", "credentials", "401 Unauthorized"]),
        "authz": ("Authorization", ["access control", "permissions", "403 Forbidden"]),
        "owasp": ("Open Web Application Security Project", ["OWASP Top 10", "ASVS"]),
        "oswap": ("Open Web Application Security Project", ["OWASP Top 10", "ASVS"]),
    }

    # Conservative typo normalization mapping for standard security terms
    TYPO_MAP: Dict[str, str] = {
        "oswap": "owasp",
    }

    # Famous CVE mappings to authoritative names
    CVE_ALIASES: Dict[str, str] = {
        "cve-2021-44228": "Log4Shell (Apache Log4j JNDI RCE)",
        "cve-2022-22965": "Spring4Shell (Spring Framework Data Binding RCE)",
        "cve-2014-0160": "Heartbleed (OpenSSL TLS Heartbeat Buffer Over-read)",
        "cve-2021-42278": "sAMAccountName Spoofing (Active Directory Privilege Escalation)",
        "cve-2021-42287": "sAMAccountName Spoofing (Active Directory Privilege Escalation)",
    }

    # Canonical CWE patterns
    CWE_PATTERN = re.compile(r"\b(cwe[-\s]?\d+)\b", re.IGNORECASE)
    CVE_PATTERN = re.compile(r"\b(cve-\d{4}-\d{4,})\b", re.IGNORECASE)

    @classmethod
    def rewrite_query(cls, query: str) -> QueryExpansionResult:
        """Expands and normalizes technical terms while preserving non-leading intent."""
        # Apply conservative typo normalization for well-known security acronyms/terms
        normalized_query = query
        for typo, correction in cls.TYPO_MAP.items():
            if re.search(r"\b" + re.escape(typo) + r"\b", normalized_query, re.IGNORECASE):
                normalized_query = re.sub(r"\b" + re.escape(typo) + r"\b", correction, normalized_query, flags=re.IGNORECASE)

        normalized_lower = normalized_query.lower()
        words = set(re.findall(r"\b[a-zA-Z0-9_\-]+\b", normalized_lower))

        expanded_terms: List[str] = []
        identified_acronyms: List[str] = []
        identified_cwes: List[str] = []
        identified_cves: List[str] = []

        # 1. Identify and normalize CWEs
        for match in cls.CWE_PATTERN.finditer(query):
            raw_cwe = match.group(1).upper().replace(" ", "-")
            identified_cwes.append(raw_cwe)
            expanded_terms.append(raw_cwe)

        # 2. Identify and normalize CVEs
        for match in cls.CVE_PATTERN.finditer(query):
            raw_cve = match.group(1).upper()
            identified_cves.append(raw_cve)
            alias = cls.CVE_ALIASES.get(raw_cve.lower())
            if alias:
                expanded_terms.append(alias)

        # 3. Identify and expand Acronyms
        for word in words:
            if word in cls.ACRONYMS:
                full_name, related_concepts = cls.ACRONYMS[word]
                identified_acronyms.append(word.upper())
                expanded_terms.append(full_name)
                # Add up to 2 high-level concepts for better retrieval
                expanded_terms.extend(related_concepts[:2])

        # Deduplicate expanded terms preserving order
        seen = set()
        clean_expansions = []
        for term in expanded_terms:
            t_norm = term.lower()
            if t_norm not in seen and t_norm not in normalized_lower:
                seen.add(t_norm)
                clean_expansions.append(term)

        # Construct rewritten query string using normalized query
        if clean_expansions:
            rewritten_str = f"{normalized_query.strip()} ({' '.join(clean_expansions)})"
        else:
            rewritten_str = normalized_query.strip()

        # Deduce broad domain
        domain = "GENERAL_VAPT"
        if any(k in words for k in ["android", "apk", "smali", "dex", "webview", "keystore", "frida"]):
            domain = "MOBILE"
        elif any(k in words for k in ["kerberos", "activedirectory", "ad", "ntlm", "spn", "tgt", "gpo"]):
            domain = "WINDOWS_AD"
        elif any(k in words for k in ["rop", "buffer", "overflow", "aslr", "elf", "pe", "canary", "relro"]):
            domain = "BINARY_RE"
        elif any(k in words for k in ["aws", "kubernetes", "k8s", "docker", "imds", "s3", "container"]):
            domain = "CLOUD"
        elif any(k in words for k in ["ssrf", "xss", "sqli", "csrf", "smuggling", "ssti", "xxe"]):
            domain = "WEB_SECURITY"
        elif any(k in words for k in ["jwt", "oauth", "pkce", "saml", "webauthn", "session"]):
            domain = "AUTHENTICATION"

        return QueryExpansionResult(
            raw_query=query,
            rewritten_query=rewritten_str,
            expanded_terms=clean_expansions,
            identified_cwes=identified_cwes,
            identified_cves=identified_cves,
            identified_acronyms=identified_acronyms,
            extracted_domain=domain,
        )

    @classmethod
    def generate_multi_query_formulations(cls, query: str, max_formulations: int = 4) -> List[str]:
        """
        Generates bounded alternative query formulations for complex or multi-concept questions.
        Enforces a strict upper bound to prevent retrieval explosion.
        """
        res = cls.rewrite_query(query)
        formulations = [query.strip()]
        
        # 1. Formulation with canonical expanded terms
        if res.expanded_terms:
            core_expanded = " ".join(res.expanded_terms[:3])
            formulations.append(f"{query.strip()} {core_expanded}")
            
        # 2. Formulation targeting identified CWEs / CVEs
        if res.identified_cwes or res.identified_cves:
            ids = " ".join(res.identified_cwes + res.identified_cves)
            formulations.append(f"{ids} security weakness definition and remediation")
            
        # 3. Domain-specific focused formulation
        if res.extracted_domain and res.extracted_domain != "GENERAL_VAPT":
            formulations.append(f"{res.extracted_domain} {' '.join(res.expanded_terms[:2])}")
            
        # Deduplicate while preserving order and limit to max_formulations
        seen = set()
        deduped = []
        for f in formulations:
            cleaned = f.strip()
            if cleaned and cleaned.lower() not in seen:
                seen.add(cleaned.lower())
                deduped.append(cleaned)
                if len(deduped) >= max_formulations:
                    break
        return deduped
