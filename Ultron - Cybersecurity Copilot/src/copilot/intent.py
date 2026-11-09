"""Task Intent Classifier and Operating Mode Router (Milestone M5).

Classifies user input into deterministic task types and operational modes:
- GENERAL_QA (knowledge explanations, definitions, concept comparisons)
- RESEARCH (standards inquiries, RFC exploration, external research)
- INVESTIGATION (target evidence analysis, hypothesis testing, experiment design)
- TOOL_EXPLANATION (security tool usage, flags, output interpretation)
- REPORTING (vulnerability report drafting, remediation guidance)
"""

from enum import Enum
import re
from typing import List, Optional, Tuple
from pydantic import BaseModel, Field


class CopilotTaskType(str, Enum):
    """Deterministic security task classifications."""
    EXPLAIN = "EXPLAIN"
    ANALYZE = "ANALYZE"
    INVESTIGATE = "INVESTIGATE"
    RESEARCH = "RESEARCH"
    TROUBLESHOOT = "TROUBLESHOOT"
    COMPARE = "COMPARE"
    DESIGN_EXPERIMENT = "DESIGN_EXPERIMENT"
    INTERPRET_EVIDENCE = "INTERPRET_EVIDENCE"
    IDENTIFY_EVIDENCE_GAP = "IDENTIFY_EVIDENCE_GAP"
    VERIFY_HYPOTHESIS = "VERIFY_HYPOTHESIS"
    EXPLAIN_TOOL = "EXPLAIN_TOOL"
    CODE_SECURITY_REVIEW = "CODE_SECURITY_REVIEW"
    TRAFFIC_ANALYSIS = "TRAFFIC_ANALYSIS"
    CONFIGURATION_ANALYSIS = "CONFIGURATION_ANALYSIS"
    VULNERABILITY_RESEARCH = "VULNERABILITY_RESEARCH"
    REPORTING = "REPORTING"
    GENERAL_SECURITY = "GENERAL_SECURITY"


class CopilotMode(str, Enum):
    """Operational mode governing copilot behavior and state tracking."""
    GENERAL_QA = "GENERAL_QA"
    RESEARCH = "RESEARCH"
    INVESTIGATION = "INVESTIGATION"
    TOOL_EXPLANATION = "TOOL_EXPLANATION"
    REPORTING = "REPORTING"


class IntentClassificationResult(BaseModel):
    """Structured result of task and mode routing."""
    primary_task: CopilotTaskType
    secondary_tasks: List[CopilotTaskType] = Field(default_factory=list)
    mode: CopilotMode
    confidence: float = Field(ge=0.0, le=1.0, default=0.85)
    matched_patterns: List[str] = Field(default_factory=list)
    requires_investigation_workspace: bool = False


class IntentRouter:
    """Deterministic classifier for user tasks and operational modes."""

    # Tool keywords
    TOOL_PATTERNS = [
        re.compile(r"\b(burp(?:\s+suite)?|zap|owasp\s+zap|nmap|wireshark|tcpdump|curl|dig|nslookup|openssl|ffuf|gobuster|sqlmap|semgrep|ghidra|jadx|apktool|frida|adb|volatility|yara|sigma|splunk|elastic)\b", re.IGNORECASE),
        re.compile(r"\bhow\s+do(?:es)?\s+(?:i\s+use|the\s+tool)\b", re.IGNORECASE),
    ]

    # Reporting patterns
    REPORT_PATTERNS = [
        re.compile(r"\b(generate|draft|create|write)\s+(?:a\s+)?(?:bug\s+bounty\s+report|vulnerability\s+report|remediation\s+report|report)\b", re.IGNORECASE),
        re.compile(r"\b(report\s+template|cvss|severity\s+rating|executive\s+summary)\b", re.IGNORECASE),
    ]

    # Vulnerability research patterns
    VULN_RESEARCH_PATTERNS = [
        re.compile(r"\b(cve-\d{4}-\d{4,}|ghsa-[a-z0-9\-]+)\b", re.IGNORECASE),
        re.compile(r"\b(zero-day|exploit-db|poc|proof\s+of\s+concept|advisory\s+details|vulnerability\s+research)\b", re.IGNORECASE),
    ]

    # Research patterns (RFC, specs, formal standards)
    RESEARCH_PATTERNS = [
        re.compile(r"\b(rfc\s*\d{3,5}|nist\s*sp\s*\d+|ietf|w3c\s*spec(?:ification)?)\b", re.IGNORECASE),
        re.compile(r"\b(research|investigate\s+external\s+standards|deep\s+dive\s+into\s+spec)\b", re.IGNORECASE),
    ]

    # Troubleshooting patterns
    TROUBLESHOOT_PATTERNS = [
        re.compile(r"\bwhy\s+(?:does|can|is|cannot|can't)\b", re.IGNORECASE),
        re.compile(r"\b(troubleshoot|debug|diagnose|failing|validation\s+fails?|error\s+code|why\s+can\s+tenant)\b", re.IGNORECASE),
    ]

    # Hypothesis verification patterns
    VERIFY_HYP_PATTERNS = [
        re.compile(r"\b(verify|validate|confirm|falsify|disprove)\s+(?:this\s+)?hypothesis\b", re.IGNORECASE),
        re.compile(r"\bis\s+(?:this\s+)?hypothesis\s+(?:true|supported|valid|falsified)\b", re.IGNORECASE),
    ]

    # Evidence interpretation patterns
    INTERPRET_EVIDENCE_PATTERNS = [
        re.compile(r"\b(interpret|explain)\s+(?:this\s+)?(?:evidence|observation|response|payload|status\s+code)\b", re.IGNORECASE),
        re.compile(r"\bwhat\s+does\s+this\s+(?:evidence|observation|403|401|200)\s+(?:mean|imply|indicate)\b", re.IGNORECASE),
    ]

    # Code review patterns
    CODE_PATTERNS = [
        re.compile(r"\b(review|audit|analyze)\s+(?:this\s+)?(?:code|function|snippet|script|solidity|go|python|javascript|c\+\+|java)\b", re.IGNORECASE),
        re.compile(r"(def\s+\w+|function\s+\w+|package\s+\w+|import\s+\w+|class\s+\w+)", re.IGNORECASE),
    ]

    # Traffic / HTTP patterns
    TRAFFIC_PATTERNS = [
        re.compile(r"\b(http\s+request|http\s+response|traffic|pcap|har|packet|http\s+headers?|response\s+headers?|request\s+headers?|status\s+code)\b", re.IGNORECASE),
        re.compile(r"(GET|POST|PUT|DELETE|PATCH)\s+/[a-zA-Z0-9_\-\.\/]+\s+HTTP/"),
    ]

    # Configuration patterns
    CONFIG_PATTERNS = [
        re.compile(r"\b(nginx|apache|caddy|cors|csp|hsts|security\s+headers|nginx\.conf|dockerfile|kubernetes|k8s|yaml|terraform)\s*(?:config|configuration)?\b", re.IGNORECASE),
    ]

    # Experiment design patterns
    EXPERIMENT_PATTERNS = [
        re.compile(r"\b(design|propose|suggest)\s+(?:an?\s+)?(?:experiment|manual\s+test|verification\s+test|falsification)\b", re.IGNORECASE),
        re.compile(r"\bhow\s+to\s+(?:test|verify|falsify)\s+(?:this\s+)?hypothesis\b", re.IGNORECASE),
    ]

    # Evidence gap patterns
    GAP_PATTERNS = [
        re.compile(r"\b(what\s+(?:evidence\s+)?is\s+missing|evidence\s+gap|missing\s+observation)\b", re.IGNORECASE),
    ]

    # Analysis patterns
    ANALYZE_PATTERNS = [
        re.compile(r"\b(analyze|assess|evaluate)\s+(?:the\s+)?(?:attack\s+surface|architecture|risk|impact|observations?)\b", re.IGNORECASE),
    ]

    # General Q&A comparison & explanation
    EXPLAIN_PATTERNS = [
        re.compile(r"\b(?:what\s+is|what\s+are|explain|how\s+does|difference\s+between|compare)\b", re.IGNORECASE),
    ]

    @classmethod
    def classify_intent(
        cls,
        query: str,
        has_active_evidence: bool = False,
    ) -> IntentClassificationResult:
        """
        Deterministically maps user query to primary task type and operational mode.
        """
        text = query.strip()
        matched: List[str] = []

        # 1. Reporting Mode Check
        for pat in cls.REPORT_PATTERNS:
            if pat.search(text):
                matched.append("REPORT_PATTERN")
                return IntentClassificationResult(
                    primary_task=CopilotTaskType.REPORTING,
                    mode=CopilotMode.REPORTING,
                    confidence=0.95,
                    matched_patterns=matched,
                    requires_investigation_workspace=has_active_evidence,
                )

        # 2. Tool Explanation Mode Check
        for pat in cls.TOOL_PATTERNS:
            if pat.search(text):
                matched.append("TOOL_PATTERN")
                if any(k in text.lower() for k in ["how", "what", "options", "flags", "syntax", "usage", "work", "explain", "command"]):
                    return IntentClassificationResult(
                        primary_task=CopilotTaskType.EXPLAIN_TOOL,
                        mode=CopilotMode.TOOL_EXPLANATION,
                        confidence=0.92,
                        matched_patterns=matched,
                        requires_investigation_workspace=False,
                    )

        # 3. Vulnerability Research Check (CVE, 0-day, advisory)
        for pat in cls.VULN_RESEARCH_PATTERNS:
            if pat.search(text):
                matched.append("VULN_RESEARCH_PATTERN")
                return IntentClassificationResult(
                    primary_task=CopilotTaskType.VULNERABILITY_RESEARCH,
                    secondary_tasks=[CopilotTaskType.RESEARCH],
                    mode=CopilotMode.RESEARCH,
                    confidence=0.94,
                    matched_patterns=matched,
                    requires_investigation_workspace=has_active_evidence,
                )

        # 4. Standards & Specifications Research Check
        for pat in cls.RESEARCH_PATTERNS:
            if pat.search(text):
                matched.append("RESEARCH_PATTERN")
                return IntentClassificationResult(
                    primary_task=CopilotTaskType.RESEARCH,
                    secondary_tasks=[CopilotTaskType.EXPLAIN],
                    mode=CopilotMode.RESEARCH,
                    confidence=0.92,
                    matched_patterns=matched,
                    requires_investigation_workspace=has_active_evidence,
                )

        # 5. Code Security Review Check
        for pat in cls.CODE_PATTERNS:
            if pat.search(text):
                matched.append("CODE_PATTERN")
                return IntentClassificationResult(
                    primary_task=CopilotTaskType.CODE_SECURITY_REVIEW,
                    secondary_tasks=[CopilotTaskType.ANALYZE],
                    mode=CopilotMode.INVESTIGATION if has_active_evidence else CopilotMode.GENERAL_QA,
                    confidence=0.90,
                    matched_patterns=matched,
                    requires_investigation_workspace=has_active_evidence,
                )

        # 6. Traffic / HTTP Analysis Check
        for pat in cls.TRAFFIC_PATTERNS:
            if pat.search(text):
                matched.append("TRAFFIC_PATTERN")
                return IntentClassificationResult(
                    primary_task=CopilotTaskType.TRAFFIC_ANALYSIS,
                    secondary_tasks=[CopilotTaskType.INTERPRET_EVIDENCE],
                    mode=CopilotMode.INVESTIGATION if has_active_evidence else CopilotMode.GENERAL_QA,
                    confidence=0.90,
                    matched_patterns=matched,
                    requires_investigation_workspace=has_active_evidence,
                )

        # 7. Configuration Analysis Check
        for pat in cls.CONFIG_PATTERNS:
            if pat.search(text):
                matched.append("CONFIG_PATTERN")
                return IntentClassificationResult(
                    primary_task=CopilotTaskType.CONFIGURATION_ANALYSIS,
                    secondary_tasks=[CopilotTaskType.ANALYZE],
                    mode=CopilotMode.INVESTIGATION if has_active_evidence else CopilotMode.GENERAL_QA,
                    confidence=0.88,
                    matched_patterns=matched,
                    requires_investigation_workspace=has_active_evidence,
                )

        # 8. Hypothesis Verification Check
        for pat in cls.VERIFY_HYP_PATTERNS:
            if pat.search(text):
                matched.append("VERIFY_HYPOTHESIS_PATTERN")
                return IntentClassificationResult(
                    primary_task=CopilotTaskType.VERIFY_HYPOTHESIS,
                    secondary_tasks=[CopilotTaskType.ANALYZE],
                    mode=CopilotMode.INVESTIGATION if has_active_evidence else CopilotMode.GENERAL_QA,
                    confidence=0.92,
                    matched_patterns=matched,
                    requires_investigation_workspace=has_active_evidence,
                )

        # 9. Evidence Interpretation Check
        for pat in cls.INTERPRET_EVIDENCE_PATTERNS:
            if pat.search(text):
                matched.append("INTERPRET_EVIDENCE_PATTERN")
                return IntentClassificationResult(
                    primary_task=CopilotTaskType.INTERPRET_EVIDENCE,
                    secondary_tasks=[CopilotTaskType.ANALYZE],
                    mode=CopilotMode.INVESTIGATION if has_active_evidence else CopilotMode.GENERAL_QA,
                    confidence=0.90,
                    matched_patterns=matched,
                    requires_investigation_workspace=has_active_evidence,
                )

        # 10. Experiment Design Check
        for pat in cls.EXPERIMENT_PATTERNS:
            if pat.search(text):
                matched.append("EXPERIMENT_PATTERN")
                return IntentClassificationResult(
                    primary_task=CopilotTaskType.DESIGN_EXPERIMENT,
                    secondary_tasks=[CopilotTaskType.VERIFY_HYPOTHESIS],
                    mode=CopilotMode.INVESTIGATION if has_active_evidence else CopilotMode.GENERAL_QA,
                    confidence=0.92,
                    matched_patterns=matched,
                    requires_investigation_workspace=has_active_evidence,
                )

        # 11. Evidence Gap Check
        for pat in cls.GAP_PATTERNS:
            if pat.search(text):
                matched.append("GAP_PATTERN")
                return IntentClassificationResult(
                    primary_task=CopilotTaskType.IDENTIFY_EVIDENCE_GAP,
                    secondary_tasks=[CopilotTaskType.ANALYZE],
                    mode=CopilotMode.INVESTIGATION if has_active_evidence else CopilotMode.GENERAL_QA,
                    confidence=0.90,
                    matched_patterns=matched,
                    requires_investigation_workspace=has_active_evidence,
                )

        # 12. Troubleshooting / Diagnosis
        for pat in cls.TROUBLESHOOT_PATTERNS:
            if pat.search(text):
                matched.append("TROUBLESHOOT_PATTERN")
                return IntentClassificationResult(
                    primary_task=CopilotTaskType.TROUBLESHOOT,
                    secondary_tasks=[CopilotTaskType.ANALYZE],
                    mode=CopilotMode.INVESTIGATION if has_active_evidence else CopilotMode.GENERAL_QA,
                    confidence=0.88,
                    matched_patterns=matched,
                    requires_investigation_workspace=has_active_evidence,
                )

        # 13. Analysis Check
        for pat in cls.ANALYZE_PATTERNS:
            if pat.search(text):
                matched.append("ANALYZE_PATTERN")
                return IntentClassificationResult(
                    primary_task=CopilotTaskType.ANALYZE,
                    secondary_tasks=[CopilotTaskType.EXPLAIN],
                    mode=CopilotMode.INVESTIGATION if has_active_evidence else CopilotMode.GENERAL_QA,
                    confidence=0.86,
                    matched_patterns=matched,
                    requires_investigation_workspace=has_active_evidence,
                )

        # 14. Target Evidence Investigation (if active observations provided)
        if has_active_evidence:
            return IntentClassificationResult(
                primary_task=CopilotTaskType.INVESTIGATE,
                secondary_tasks=[CopilotTaskType.INTERPRET_EVIDENCE, CopilotTaskType.ANALYZE],
                mode=CopilotMode.INVESTIGATION,
                confidence=0.88,
                matched_patterns=["ACTIVE_EVIDENCE_PRESENT"],
                requires_investigation_workspace=True,
            )

        # 15. Comparison Check
        if "compare" in text.lower() or "difference between" in text.lower():
            return IntentClassificationResult(
                primary_task=CopilotTaskType.COMPARE,
                secondary_tasks=[CopilotTaskType.EXPLAIN],
                mode=CopilotMode.GENERAL_QA,
                confidence=0.90,
                matched_patterns=["COMPARE_PATTERN"],
                requires_investigation_workspace=False,
            )

        # 16. General Security Principles / Architecture
        if any(term in text.lower() for term in ["zero trust", "defense in depth", "stride", "threat model", "cia triad"]):
            return IntentClassificationResult(
                primary_task=CopilotTaskType.GENERAL_SECURITY,
                secondary_tasks=[CopilotTaskType.EXPLAIN],
                mode=CopilotMode.GENERAL_QA,
                confidence=0.85,
                matched_patterns=["GENERAL_SECURITY_PATTERN"],
                requires_investigation_workspace=False,
            )

        # 17. Default to General Explanation
        return IntentClassificationResult(
            primary_task=CopilotTaskType.EXPLAIN,
            secondary_tasks=[CopilotTaskType.GENERAL_SECURITY],
            mode=CopilotMode.GENERAL_QA,
            confidence=0.80,
            matched_patterns=["DEFAULT_EXPLAIN"],
            requires_investigation_workspace=False,
        )
