"""Code Security Analysis Engine (Milestone M9 Phase 14).

Pipeline:
    CODE -> LANGUAGE DETECTION -> STATIC PATTERN ANALYSIS -> KNOWLEDGE RETRIEVAL -> CWE MAPPING -> EXPLANATION

Critical Epistemic Boundary:
    'THIS_CODE_CONTAINS_A_RISKY_PATTERN' != 'THIS_TARGET_IS_EXPLOITABLE'
    The analyzer reports static code risks and CWE mappings. It never asserts target exploitability
    without concrete running target observations and human verification.
"""

from enum import Enum
import re
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from src.knowledge.taxonomies import TaxonomyResolver


class SupportedLanguage(str, Enum):
    PYTHON = "PYTHON"
    JAVASCRIPT = "JAVASCRIPT"
    TYPESCRIPT = "TYPESCRIPT"
    JAVA = "JAVA"
    KOTLIN = "KOTLIN"
    C = "C"
    CPP = "CPP"
    PHP = "PHP"
    GO = "GO"
    RUST = "RUST"
    SQL = "SQL"
    SHELL = "SHELL"
    UNKNOWN = "UNKNOWN"


class CodeSecurityFinding(BaseModel):
    finding_id: str
    rule_name: str
    cwe_id: str
    severity: str
    line_number: Optional[int] = None
    matched_snippet: str
    risk_description: str
    remediation_advice: str
    is_target_exploitable: bool = False  # Mandatory invariant: static review cannot assert exploitability


class CodeAnalysisReport(BaseModel):
    detected_language: SupportedLanguage
    total_lines: int
    findings: List[CodeSecurityFinding] = Field(default_factory=list)
    risk_level: str = "LOW"
    disclaimer: str = (
        "STATIC CODE ANALYSIS NOTICE: Identifying a risky pattern in source code does NOT prove "
        "that a running target is exploitable. Runtime defenses, framework sanitizers, or unreachable code "
        "may neutralize the condition."
    )


class CodeSecurityAnalyzer:
    """Multi-language static pattern analyzer with deterministic CWE mapping."""

    @classmethod
    def detect_language(cls, code: str, filename: Optional[str] = None) -> SupportedLanguage:
        """Determines programming language from file extension or syntactic signatures."""
        if filename:
            ext = filename.lower().split(".")[-1]
            ext_map = {
                "py": SupportedLanguage.PYTHON,
                "js": SupportedLanguage.JAVASCRIPT,
                "ts": SupportedLanguage.TYPESCRIPT,
                "java": SupportedLanguage.JAVA,
                "kt": SupportedLanguage.KOTLIN,
                "c": SupportedLanguage.C,
                "cpp": SupportedLanguage.CPP,
                "h": SupportedLanguage.C,
                "hpp": SupportedLanguage.CPP,
                "php": SupportedLanguage.PHP,
                "go": SupportedLanguage.GO,
                "rs": SupportedLanguage.RUST,
                "sql": SupportedLanguage.SQL,
                "sh": SupportedLanguage.SHELL,
                "bash": SupportedLanguage.SHELL,
            }
            if ext in ext_map:
                return ext_map[ext]

        # Heuristic syntactic signatures
        if "def " in code and (":" in code or "import " in code):
            return SupportedLanguage.PYTHON
        if "function " in code or "const " in code or "let " in code or "console.log" in code:
            return SupportedLanguage.JAVASCRIPT
        if "public class " in code or "System.out.println" in code:
            return SupportedLanguage.JAVA
        if "fun " in code and "val " in code:
            return SupportedLanguage.KOTLIN
        if "#include <" in code and "int main(" in code:
            return SupportedLanguage.C
        if "<?php" in code or "$_GET" in code or "$_POST" in code:
            return SupportedLanguage.PHP
        if "package " in code and "func " in code:
            return SupportedLanguage.GO
        if "fn main()" in code or "let mut " in code:
            return SupportedLanguage.RUST
        if "SELECT " in code.upper() and "FROM " in code.upper():
            return SupportedLanguage.SQL
        if "#!/bin/bash" in code or "#!/bin/sh" in code:
            return SupportedLanguage.SHELL

        return SupportedLanguage.UNKNOWN

    @classmethod
    def analyze_code(cls, code: str, filename: Optional[str] = None) -> CodeAnalysisReport:
        """Analyzes source code for risky programming patterns across supported languages."""
        lang = cls.detect_language(code, filename)
        lines = code.split("\n")
        findings: List[CodeSecurityFinding] = []

        # Rule Definitions: (Pattern, Rule Name, CWE, Severity, Description, Remediation)
        rules = [
            (
                re.compile(r"""((cursor\.execute|execute)\s*\(\s*(f["'].*?\{.*?\}["']|["'].*?(%s|\{\}|\+).*?["']|.*?\.format\(|.*?\+\s*[a-zA-Z_])|(query|sql|cmd|stmt)\s*=\s*(f["'].*?(select|insert|update|delete).*?\{.*?\}["']|["'].*?(select|insert|update|delete).*?\+))""", re.IGNORECASE),
                "STRING_CONCAT_SQL_QUERY",
                "CWE-89",
                "HIGH",
                "SQL query appears to be constructed using direct string concatenation, f-string, or formatting.",
                "Use parameterized queries (e.g. cursor.execute(query, (params,))) with database placeholders.",
            ),
            (
                re.compile(r"""(subprocess\.Popen|subprocess\.run|subprocess\.call|os\.system)\s*\(\s*.*shell\s*=\s*True""", re.IGNORECASE),
                "SUBPROCESS_SHELL_TRUE",
                "CWE-78",
                "HIGH",
                "Invoking shell command with shell=True allows command chaining and shell metacharacter injection.",
                "Pass an argument list without shell=True: subprocess.run([cmd, arg1, arg2]).",
            ),
            (
                re.compile(r"""(strcpy|strcat|sprintf|gets)\s*\(""", re.IGNORECASE),
                "UNSAFE_C_STRING_FUNCTION",
                "CWE-121",
                "CRITICAL",
                "Usage of legacy unbounded C string copy/print functions prone to stack buffer overflows.",
                "Replace with bounded alternatives (strncpy, snprintf) or modern memory-safe containers.",
            ),
            (
                re.compile(r"""(pickle\.loads|yaml\.load\s*\([^,)]+\))""", re.IGNORECASE),
                "UNSAFE_DESERIALIZATION_LOAD",
                "CWE-502",
                "CRITICAL",
                "Deserializing untrusted data with pickle or unconstrained yaml.load can lead to arbitrary code execution.",
                "Use safe deserialization (json.loads, yaml.safe_load) or cryptographic signature verification.",
            ),
            (
                re.compile(r"""(innerHTML|document\.write)\s*=""", re.IGNORECASE),
                "DOM_XSS_SINK_ASSIGNMENT",
                "CWE-79",
                "MEDIUM",
                "Direct assignment to innerHTML or document.write without HTML encoding risks DOM-based Cross-Site Scripting.",
                "Use textContent, innerText, or DOMPurify.sanitize() before setting HTML.",
            ),
            (
                re.compile(r"""(AES\.new\s*\([^,]+,\s*AES\.MODE_ECB)""", re.IGNORECASE),
                "INSECURE_CIPHER_MODE_ECB",
                "CWE-327",
                "HIGH",
                "AES ECB mode encrypts identical blocks identically, leaking structural patterns.",
                "Use authenticated encryption modes such as AES-GCM with a unique nonce/IV per message.",
            ),
            (
                re.compile(r"""(?i)(password|secret|api[_-]?key|token)\s*=\s*["'][A-Za-z0-9_\-]{8,}["']"""),
                "HARDCODED_CREDENTIAL_PATTERN",
                "CWE-798",
                "HIGH",
                "Apparent hardcoded secret or token detected in source code.",
                "Move secrets to environment variables, .env (gitignored), or a secure secret management vault.",
            ),
        ]

        finding_counter = 1
        for line_num, line in enumerate(lines, start=1):
            for pattern, rname, cwe, sev, desc, remed in rules:
                m = pattern.search(line)
                if m:
                    findings.append(CodeSecurityFinding(
                        finding_id=f"CODE-FINDING-{finding_counter:03d}",
                        rule_name=rname,
                        cwe_id=cwe,
                        severity=sev,
                        line_number=line_num,
                        matched_snippet=line.strip()[:100],
                        risk_description=desc,
                        remediation_advice=remed,
                        is_target_exploitable=False,
                    ))
                    finding_counter += 1

        # Determine overall report risk level
        severities = {f.severity for f in findings}
        risk_lvl = "LOW"
        if "CRITICAL" in severities:
            risk_lvl = "CRITICAL"
        elif "HIGH" in severities:
            risk_lvl = "HIGH"
        elif "MEDIUM" in severities:
            risk_lvl = "MEDIUM"

        return CodeAnalysisReport(
            detected_language=lang,
            total_lines=len(lines),
            findings=findings,
            risk_level=risk_lvl,
        )
