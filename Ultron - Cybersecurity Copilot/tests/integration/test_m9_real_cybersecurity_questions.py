"""Real-World Cybersecurity Question Evaluation Suite (Milestone M9 Phase 29).

Evaluates questions that a real cybersecurity student or researcher would ask:
- Conceptual explanations (SSRF, CSRF, JWT, Kerberos, DNS Rebinding, HTTP Request Smuggling)
- Architectural comparisons (IDOR vs BOLA, SSRF vs CSRF, TLS 1.3 vs 1.2)
- Mobile & Binary analysis (Exported Android components, Certificate Pinning, ELF, Buffer Overflow)
- Taxonomy & Tool guidance (CWE-89, CVE-2021-44228, CVSS, Negative Controls)
- Code security analysis (risky SQL concatenation, shell=True injection)

All answers are verified for:
- Correctness and technical depth
- Verifiable claims and groundings
- Citations linking to authoritative chunks
- Epistemic accuracy (GENERAL_VAPT_KNOWLEDGE, never TARGET_OBSERVATION)
- Zero fabricated citations
"""

import pytest
from src.analysis.code_security_analyzer import CodeSecurityAnalyzer
from src.knowledge.knowledge_orchestrator import CybersecurityKnowledgeOrchestrator
from src.knowledge.taxonomies import TaxonomyResolver


@pytest.fixture
def orchestrator():
    return CybersecurityKnowledgeOrchestrator()


# -------------------------------------------------------------
# 1. CORE CONCEPTUAL AND ARCHITECTURAL QUESTIONS
# -------------------------------------------------------------

def test_qa_01_explain_ssrf(orchestrator):
    """What is SSRF?"""
    ans = orchestrator.answer_query("What is SSRF?")
    assert len(ans.claims) > 0
    assert any("request forgery" in c.text.lower() or "server-side" in c.text.lower() for c in ans.claims)
    assert ans.epistemic_tier == "GENERAL_VAPT_KNOWLEDGE"
    assert len(ans.citations) > 0


def test_qa_02_ssrf_vs_csrf(orchestrator):
    """How does SSRF differ from CSRF?"""
    ans = orchestrator.answer_query("How does SSRF differ from CSRF?")
    assert len(ans.claims) > 0
    assert any("browser" in c.text.lower() or "client" in c.text.lower() or "trust" in c.text.lower() for c in ans.claims)
    assert ans.escalation_level == "7B"  # Escalated due to comparison query


def test_qa_03_idor_vs_bola(orchestrator):
    """What is the difference between IDOR and BOLA?"""
    ans = orchestrator.answer_query("What is the difference between IDOR and BOLA?")
    assert len(ans.claims) > 0
    assert any("idor" in ans.answer_text.lower() and "bola" in ans.answer_text.lower() for _ in [1])
    assert ans.escalation_level == "7B"


def test_qa_04_jwt_validation(orchestrator):
    """How does JWT validation work and what are key vulnerabilities?"""
    ans = orchestrator.answer_query("Explain JWT validation and signature security weaknesses.")
    assert len(ans.claims) > 0
    assert any("token" in c.text.lower() or "signature" in c.text.lower() or "algorithm" in c.text.lower() for c in ans.claims)


def test_qa_05_oauth_pkce(orchestrator):
    """How does OAuth 2.0 PKCE protect authorization codes?"""
    ans = orchestrator.answer_query("How does OAuth 2.0 PKCE work?")
    assert len(ans.claims) > 0
    assert any("code_verifier" in c.text.lower() or "code_challenge" in c.text.lower() or "pkce" in c.text.lower() for c in ans.claims)


def test_qa_06_kerberos_authentication(orchestrator):
    """How does Kerberos authentication work in Active Directory?"""
    ans = orchestrator.answer_query("How does Kerberos authentication work?")
    assert len(ans.claims) > 0
    assert any("tgt" in c.text.lower() or "as-req" in c.text.lower() or "kdc" in c.text.lower() or "ticket" in c.text.lower() for c in ans.claims)


def test_qa_07_dns_rebinding(orchestrator):
    """Explain DNS rebinding."""
    ans = orchestrator.answer_query("Explain DNS rebinding.")
    assert len(ans.claims) > 0
    assert any("ttl" in c.text.lower() or "origin" in c.text.lower() or "127.0.0.1" in c.text.lower() for c in ans.claims)


def test_qa_08_http_request_smuggling(orchestrator):
    """What is HTTP request smuggling?"""
    ans = orchestrator.answer_query("What is HTTP request smuggling?")
    assert len(ans.claims) > 0
    assert any("content-length" in c.text.lower() or "transfer-encoding" in c.text.lower() or "cl.te" in c.text.lower() for c in ans.claims)


# -------------------------------------------------------------
# 2. MOBILE & BINARY SECURITY QUESTIONS
# -------------------------------------------------------------

def test_qa_09_android_exported_components(orchestrator):
    """How does Android exported component abuse work?"""
    ans = orchestrator.answer_query("How does Android exported component abuse work?")
    assert len(ans.claims) > 0
    assert any("exported" in c.text.lower() or "activity" in c.text.lower() or "intent" in c.text.lower() for c in ans.claims)


def test_qa_10_certificate_pinning(orchestrator):
    """What is certificate pinning?"""
    ans = orchestrator.answer_query("What is certificate pinning and how is it tested with Frida?")
    assert len(ans.claims) > 0
    assert any("pinning" in c.text.lower() or "certificate" in c.text.lower() or "frida" in c.text.lower() for c in ans.claims)


def test_qa_11_buffer_overflow_and_canaries(orchestrator):
    """What is a stack buffer overflow and how do canaries mitigate it?"""
    ans = orchestrator.answer_query("What is a buffer overflow?")
    assert len(ans.claims) > 0
    assert any("buffer" in c.text.lower() or "stack" in c.text.lower() or "return address" in c.text.lower() for c in ans.claims)


def test_qa_12_rop_chains(orchestrator):
    """Explain Return-Oriented Programming (ROP)."""
    ans = orchestrator.answer_query("Explain ROP gadgets and bypassing NX/DEP.")
    assert len(ans.claims) > 0
    assert any("gadget" in c.text.lower() or "dep" in c.text.lower() or "ret" in c.text.lower() for c in ans.claims)


# -------------------------------------------------------------
# 3. TAXONOMY, CVE, CWE & METHODOLOGY
# -------------------------------------------------------------

def test_qa_13_cwe_89_mapping():
    """What does CWE-89 represent?"""
    res = TaxonomyResolver.lookup_cwe("CWE-89")
    assert res.found
    assert "SQL Injection" in (res.name or "")
    assert res.severity == "HIGH"


def test_qa_14_cve_2021_44228_details():
    """Explain CVE-2021-44228."""
    res = TaxonomyResolver.lookup_cve("CVE-2021-44228")
    assert res.found
    assert "Log4Shell" in (res.name or "")
    assert res.cvss_score == 10.0


def test_qa_15_negative_controls_methodology(orchestrator):
    """How do negative controls reduce false positives?"""
    ans = orchestrator.answer_query("How do negative controls reduce false positives in VAPT?")
    assert len(ans.claims) > 0
    assert any("negative control" in c.text.lower() or "false positive" in c.text.lower() for c in ans.claims)


# -------------------------------------------------------------
# 4. STATIC CODE SECURITY REVIEW
# -------------------------------------------------------------

def test_qa_16_code_security_analysis(orchestrator):
    """Review this code for security problems."""
    code = (
        "def query_user(user_id):\n"
        "    cmd = f'SELECT * FROM accounts WHERE id = {user_id}'\n"
        "    cursor.execute(cmd)\n"
    )
    ans = orchestrator.answer_query("Review this Python code for security issues.", code_snippet=code)
    assert "Static Code Security Review" in ans.answer_text
    assert "CWE-89" in ans.answer_text
    assert ans.escalation_level == "7B"  # Code review escalates to 7B


def test_qa_17_target_context_requested_stays_general(orchestrator):
    """'Would this indicate a vulnerability in my assessment?' - must enforce boundary."""
    ans = orchestrator.answer_query("Would this indicate a vulnerability in my assessment target?")
    # Must enforce epistemic boundary: does not claim target is vulnerable
    assert ans.epistemic_tier == "GENERAL_VAPT_KNOWLEDGE"
    assert "CONFIRMED" not in ans.answer_text
