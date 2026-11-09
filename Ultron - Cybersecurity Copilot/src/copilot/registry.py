"""Domain Knowledge Registry and Coverage Catalog (Milestone M5).

Tracks local knowledge coverage levels across all 26 cybersecurity domains:
- NONE: No local documents exist.
- LIMITED: Basic conceptual summaries available.
- PARTIAL: Several methodology chunks present.
- GOOD: Comprehensive testing patterns available.
- STRONG: Deep invariant, testing, and counterfactual coverage (e.g., API / Authorization).

Enforces Section 8: Informs KnowledgeSufficiencyEngine to prevent unnecessary searches.
"""

from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field

from src.copilot.domain import SecurityDomain
from src.copilot.intent import CopilotTaskType


class CoverageLevel(str, Enum):
    """Authoritative local knowledge coverage depth."""
    NONE = "NONE"
    LIMITED = "LIMITED"
    PARTIAL = "PARTIAL"
    GOOD = "GOOD"
    STRONG = "STRONG"


class DomainRegistryEntry(BaseModel):
    """Metadata describing local knowledge depth for a specific cybersecurity domain."""
    domain: SecurityDomain
    display_name: str
    coverage_level: CoverageLevel
    knowledge_chunk_count: int
    supported_task_types: List[CopilotTaskType] = Field(default_factory=list)
    corpus_version: str = "4.0.0"
    last_updated: str = "2026-10-06"
    primary_topics: List[str] = Field(default_factory=list)


class DomainKnowledgeRegistry:
    """Central catalog of available local cybersecurity knowledge."""

    _CATALOG: Dict[SecurityDomain, DomainRegistryEntry] = {
        SecurityDomain.API_SECURITY: DomainRegistryEntry(
            domain=SecurityDomain.API_SECURITY,
            display_name="API Security & Endpoint Boundaries",
            coverage_level=CoverageLevel.STRONG,
            knowledge_chunk_count=12,
            supported_task_types=[CopilotTaskType.EXPLAIN, CopilotTaskType.INVESTIGATE, CopilotTaskType.DESIGN_EXPERIMENT, CopilotTaskType.IDENTIFY_EVIDENCE_GAP],
            primary_topics=["BOLA", "BFLA", "Mass Assignment", "Rate Limiting", "Tenant Boundaries"],
        ),
        SecurityDomain.AUTHORIZATION: DomainRegistryEntry(
            domain=SecurityDomain.AUTHORIZATION,
            display_name="Authorization & Access Control",
            coverage_level=CoverageLevel.STRONG,
            knowledge_chunk_count=11,
            supported_task_types=[CopilotTaskType.EXPLAIN, CopilotTaskType.INVESTIGATE, CopilotTaskType.DESIGN_EXPERIMENT, CopilotTaskType.VERIFY_HYPOTHESIS],
            primary_topics=["RBAC", "ABAC", "Tenant Isolation", "Object Ownership", "Role Hierarchy"],
        ),
        SecurityDomain.AUTHENTICATION: DomainRegistryEntry(
            domain=SecurityDomain.AUTHENTICATION,
            display_name="Authentication & Identity Protocols",
            coverage_level=CoverageLevel.PARTIAL,
            knowledge_chunk_count=4,
            supported_task_types=[CopilotTaskType.EXPLAIN, CopilotTaskType.RESEARCH, CopilotTaskType.TROUBLESHOOT],
            primary_topics=["OAuth 2.0", "OIDC", "PKCE", "JWT", "SAML 2.0"],
        ),
        SecurityDomain.SESSION_SECURITY: DomainRegistryEntry(
            domain=SecurityDomain.SESSION_SECURITY,
            display_name="Session Management & Cookie Security",
            coverage_level=CoverageLevel.GOOD,
            knowledge_chunk_count=6,
            supported_task_types=[CopilotTaskType.EXPLAIN, CopilotTaskType.ANALYZE],
            primary_topics=["SameSite", "HttpOnly", "CSRF Tokens", "Session Fixation"],
        ),
        SecurityDomain.WEB_APPLICATION_SECURITY: DomainRegistryEntry(
            domain=SecurityDomain.WEB_APPLICATION_SECURITY,
            display_name="Web Application Security & OWASP Top 10",
            coverage_level=CoverageLevel.GOOD,
            knowledge_chunk_count=8,
            supported_task_types=[CopilotTaskType.EXPLAIN, CopilotTaskType.INVESTIGATE, CopilotTaskType.CODE_SECURITY_REVIEW],
            primary_topics=["XSS", "SQLi", "SSRF", "CORS", "Path Traversal"],
        ),
        SecurityDomain.CRYPTOGRAPHY: DomainRegistryEntry(
            domain=SecurityDomain.CRYPTOGRAPHY,
            display_name="Applied Cryptography & Key Management",
            coverage_level=CoverageLevel.PARTIAL,
            knowledge_chunk_count=3,
            supported_task_types=[CopilotTaskType.EXPLAIN, CopilotTaskType.COMPARE],
            primary_topics=["AES-GCM", "RSA", "HMAC", "Key Derivation", "Ed25519"],
        ),
        SecurityDomain.TLS_SECURITY: DomainRegistryEntry(
            domain=SecurityDomain.TLS_SECURITY,
            display_name="Transport Layer Security & Certificates",
            coverage_level=CoverageLevel.PARTIAL,
            knowledge_chunk_count=3,
            supported_task_types=[CopilotTaskType.EXPLAIN, CopilotTaskType.CONFIGURATION_ANALYSIS],
            primary_topics=["TLS 1.3", "Certificate Transparency", "SNI", "HSTS"],
        ),
        SecurityDomain.NETWORK_PROTOCOLS: DomainRegistryEntry(
            domain=SecurityDomain.NETWORK_PROTOCOLS,
            display_name="Network Protocols & Transport Architecture",
            coverage_level=CoverageLevel.LIMITED,
            knowledge_chunk_count=2,
            supported_task_types=[CopilotTaskType.EXPLAIN, CopilotTaskType.TRAFFIC_ANALYSIS],
            primary_topics=["HTTP/2", "DNS", "TCP/IP"],
        ),
        SecurityDomain.NETWORK_SECURITY: DomainRegistryEntry(
            domain=SecurityDomain.NETWORK_SECURITY,
            display_name="Network Defense & Traffic Inspection",
            coverage_level=CoverageLevel.LIMITED,
            knowledge_chunk_count=2,
            supported_task_types=[CopilotTaskType.EXPLAIN, CopilotTaskType.TRAFFIC_ANALYSIS],
            primary_topics=["Firewall Rules", "Packet Filtering", "Wireshark"],
        ),
        SecurityDomain.CLOUD_SECURITY: DomainRegistryEntry(
            domain=SecurityDomain.CLOUD_SECURITY,
            display_name="Cloud Infrastructure & IAM Security",
            coverage_level=CoverageLevel.LIMITED,
            knowledge_chunk_count=2,
            supported_task_types=[CopilotTaskType.EXPLAIN, CopilotTaskType.CONFIGURATION_ANALYSIS],
            primary_topics=["AWS IAM", "S3 Bucket Policies", "Metadata Service"],
        ),
        SecurityDomain.CONTAINER_SECURITY: DomainRegistryEntry(
            domain=SecurityDomain.CONTAINER_SECURITY,
            display_name="Container & Orchestration Security",
            coverage_level=CoverageLevel.LIMITED,
            knowledge_chunk_count=2,
            supported_task_types=[CopilotTaskType.EXPLAIN, CopilotTaskType.CONFIGURATION_ANALYSIS],
            primary_topics=["Docker Isolation", "Kubernetes RBAC", "Pod Security"],
        ),
        SecurityDomain.LINUX_SECURITY: DomainRegistryEntry(
            domain=SecurityDomain.LINUX_SECURITY,
            display_name="Linux OS Hardening & Permissions",
            coverage_level=CoverageLevel.LIMITED,
            knowledge_chunk_count=2,
            supported_task_types=[CopilotTaskType.EXPLAIN, CopilotTaskType.CONFIGURATION_ANALYSIS],
            primary_topics=["SUID/SGID", "Sudoers", "File Permissions"],
        ),
        SecurityDomain.WINDOWS_SECURITY: DomainRegistryEntry(
            domain=SecurityDomain.WINDOWS_SECURITY,
            display_name="Windows OS Security & Privilege Boundaries",
            coverage_level=CoverageLevel.LIMITED,
            knowledge_chunk_count=1,
            supported_task_types=[CopilotTaskType.EXPLAIN],
            primary_topics=["User Account Control", "Registry ACLs"],
        ),
        SecurityDomain.ACTIVE_DIRECTORY: DomainRegistryEntry(
            domain=SecurityDomain.ACTIVE_DIRECTORY,
            display_name="Active Directory & Kerberos Architecture",
            coverage_level=CoverageLevel.LIMITED,
            knowledge_chunk_count=1,
            supported_task_types=[CopilotTaskType.EXPLAIN],
            primary_topics=["Kerberos Tickets", "Group Policy"],
        ),
        SecurityDomain.ANDROID_SECURITY: DomainRegistryEntry(
            domain=SecurityDomain.ANDROID_SECURITY,
            display_name="Android Application Security",
            coverage_level=CoverageLevel.LIMITED,
            knowledge_chunk_count=2,
            supported_task_types=[CopilotTaskType.EXPLAIN, CopilotTaskType.CODE_SECURITY_REVIEW],
            primary_topics=["AndroidManifest Exported Components", "Intent Spoofing", "Keystore"],
        ),
        SecurityDomain.MOBILE_SECURITY: DomainRegistryEntry(
            domain=SecurityDomain.MOBILE_SECURITY,
            display_name="Mobile Application Architecture & Storage",
            coverage_level=CoverageLevel.LIMITED,
            knowledge_chunk_count=1,
            supported_task_types=[CopilotTaskType.EXPLAIN],
            primary_topics=["Insecure Data Storage", "Jailbreak/Root Detection"],
        ),
        SecurityDomain.REVERSE_ENGINEERING: DomainRegistryEntry(
            domain=SecurityDomain.REVERSE_ENGINEERING,
            display_name="Binary Reverse Engineering & Decompilation",
            coverage_level=CoverageLevel.LIMITED,
            knowledge_chunk_count=1,
            supported_task_types=[CopilotTaskType.EXPLAIN, CopilotTaskType.EXPLAIN_TOOL],
            primary_topics=["Ghidra", "Disassembly Basics", "Static Analysis"],
        ),
        SecurityDomain.MALWARE_ANALYSIS: DomainRegistryEntry(
            domain=SecurityDomain.MALWARE_ANALYSIS,
            display_name="Malware Analysis & Behavioral Triage",
            coverage_level=CoverageLevel.LIMITED,
            knowledge_chunk_count=1,
            supported_task_types=[CopilotTaskType.EXPLAIN],
            primary_topics=["Static Properties", "YARA Rules", "Sandboxing"],
        ),
        SecurityDomain.DIGITAL_FORENSICS: DomainRegistryEntry(
            domain=SecurityDomain.DIGITAL_FORENSICS,
            display_name="Digital Forensics & Artifact Analysis",
            coverage_level=CoverageLevel.LIMITED,
            knowledge_chunk_count=1,
            supported_task_types=[CopilotTaskType.EXPLAIN],
            primary_topics=["Timeline Analysis", "Evidence Preservation"],
        ),
        SecurityDomain.INCIDENT_ANALYSIS: DomainRegistryEntry(
            domain=SecurityDomain.INCIDENT_ANALYSIS,
            display_name="Security Operations & Incident Triage",
            coverage_level=CoverageLevel.LIMITED,
            knowledge_chunk_count=1,
            supported_task_types=[CopilotTaskType.EXPLAIN],
            primary_topics=["Alert Triage", "IoC Verification"],
        ),
        SecurityDomain.SECURITY_TOOLING: DomainRegistryEntry(
            domain=SecurityDomain.SECURITY_TOOLING,
            display_name="Security Tooling Usage & Safe Lab Practices",
            coverage_level=CoverageLevel.GOOD,
            knowledge_chunk_count=8,
            supported_task_types=[CopilotTaskType.EXPLAIN_TOOL, CopilotTaskType.EXPLAIN],
            primary_topics=["Burp Suite", "Nmap", "Wireshark", "curl", "Semgrep", "sqlmap"],
        ),
        SecurityDomain.SECURE_CODING: DomainRegistryEntry(
            domain=SecurityDomain.SECURE_CODING,
            display_name="Secure Coding Principles & Remediation",
            coverage_level=CoverageLevel.GOOD,
            knowledge_chunk_count=6,
            supported_task_types=[CopilotTaskType.CODE_SECURITY_REVIEW, CopilotTaskType.EXPLAIN],
            primary_topics=["Parameterized Queries", "Contextual Encoding", "Safe Deserialization"],
        ),
        SecurityDomain.BUG_BOUNTY_RESEARCH: DomainRegistryEntry(
            domain=SecurityDomain.BUG_BOUNTY_RESEARCH,
            display_name="Bug Bounty Methodology & Triage Standards",
            coverage_level=CoverageLevel.STRONG,
            knowledge_chunk_count=10,
            supported_task_types=[CopilotTaskType.INVESTIGATE, CopilotTaskType.REPORTING, CopilotTaskType.DESIGN_EXPERIMENT],
            primary_topics=["Scope Compliance", "Evidence Preservation", "Differential Falsification"],
        ),
        SecurityDomain.VULNERABILITY_RESEARCH: DomainRegistryEntry(
            domain=SecurityDomain.VULNERABILITY_RESEARCH,
            display_name="Vulnerability Research & Root Cause Analysis",
            coverage_level=CoverageLevel.GOOD,
            knowledge_chunk_count=5,
            supported_task_types=[CopilotTaskType.VULNERABILITY_RESEARCH, CopilotTaskType.RESEARCH],
            primary_topics=["CVE Root Cause", "Patch Diffing", "Invariant Invalidation"],
        ),
        SecurityDomain.SECURITY_ARCHITECTURE: DomainRegistryEntry(
            domain=SecurityDomain.SECURITY_ARCHITECTURE,
            display_name="Security Architecture & Threat Modeling",
            coverage_level=CoverageLevel.PARTIAL,
            knowledge_chunk_count=4,
            supported_task_types=[CopilotTaskType.EXPLAIN, CopilotTaskType.COMPARE],
            primary_topics=["Defense in Depth", "Zero Trust", "Trust Boundaries"],
        ),
        SecurityDomain.GENERAL_CYBERSECURITY: DomainRegistryEntry(
            domain=SecurityDomain.GENERAL_CYBERSECURITY,
            display_name="General Cybersecurity Foundations",
            coverage_level=CoverageLevel.PARTIAL,
            knowledge_chunk_count=6,
            supported_task_types=[CopilotTaskType.EXPLAIN, CopilotTaskType.GENERAL_SECURITY],
            primary_topics=["CIA Triad", "Risk Management", "Security Concepts"],
        ),
    }

    @classmethod
    def get_all_domains(cls) -> Dict[SecurityDomain, DomainRegistryEntry]:
        """Returns the full domain registry catalog."""
        return dict(cls._CATALOG)

    @classmethod
    def get_entry(cls, domain: SecurityDomain) -> DomainRegistryEntry:
        """Retrieves registry record for a domain, defaulting to GENERAL_CYBERSECURITY."""
        return cls._CATALOG.get(domain, cls._CATALOG[SecurityDomain.GENERAL_CYBERSECURITY])

    @classmethod
    def get_coverage(cls, domain: SecurityDomain) -> CoverageLevel:
        """Returns the coverage level for a security domain."""
        return cls.get_entry(domain).coverage_level
