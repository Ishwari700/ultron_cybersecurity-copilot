"""Unit Tests for Security Tool Knowledge, Code Analysis, Traffic Analysis, and Configuration Analysis."""

import pytest
from src.copilot.analysis import (
    CodeSecurityAnalyzer,
    ConfigurationAnalyzer,
    TrafficAnalyzer,
)
from src.copilot.tools import ToolKnowledgeBase


def test_tool_knowledge_base_covers_core_tools():
    """Verify ToolKnowledgeBase provides guidance for key tools."""
    tools = ["burp", "zap", "nmap", "wireshark", "tcpdump", "curl", "openssl", "ffuf", "sqlmap", "semgrep", "ghidra", "jadx", "volatility", "yara"]
    for t in tools:
        entry = ToolKnowledgeBase.get_tool_guidance(t)
        assert entry is not None, f"Missing tool guidance for {t}"
        assert len(entry.relevant_options) >= 1
        assert len(entry.safe_lab_usage) > 10
        assert len(entry.result_interpretation) > 10
        assert len(entry.defensive_implications) > 5


def test_code_security_analysis_epistemic_separation():
    """Code analysis distinguishes observed behavior, hypothesis, missing context, and never claims definitely exploitable."""
    vulnerable_code = """
    def query_user(user_id):
        query = f"SELECT * FROM users WHERE id = '{user_id}'"
        return db.execute(query)
    """
    res = CodeSecurityAnalyzer.analyze_code(vulnerable_code, language="python")

    assert len(res.observed_code_behavior) >= 1
    assert len(res.hypotheses) >= 1
    assert len(res.missing_context) >= 1
    assert len(res.recommendations) >= 1

    # Invariant: Never claim definitely exploitable
    assert res.exploitable_claim_made is False
    assert not any("definitely exploitable" in h.lower() for h in res.hypotheses)


def test_traffic_analysis_generates_hypotheses_and_experiments():
    """Traffic analysis produces observed facts, hypotheses, evidence gaps, and experiment proposals."""
    headers = {
        "Access-Control-Allow-Origin": "https://client.target.local",
        "Access-Control-Allow-Credentials": "true",
        "Set-Cookie": "session=abc123xyz; Path=/",
    }
    res = TrafficAnalyzer.analyze_traffic(headers=headers, status_code=200)

    assert any("CORS" in o for o in res.observed_facts)
    assert any("HttpOnly" in so for so in res.security_observations)
    assert len(res.hypotheses) >= 1
    assert len(res.evidence_gaps) >= 1
    assert len(res.recommended_manual_experiments) >= 1
    exp = res.recommended_manual_experiments[0]
    assert "objective" in exp
    assert "steps" in exp
    assert "expected_secure" in exp
    assert "expected_vulnerable" in exp


def test_configuration_analysis_invariant():
    """Configuration analysis evaluates risks but never claims confirmed vulnerability."""
    nginx_conf = """
    server {
        listen 80;
        server_name api.target.local;
        autoindex on;
    }
    """
    res = ConfigurationAnalyzer.analyze_configuration(nginx_conf, config_type="nginx")
    assert any("autoindex on" in o for o in res.observed_configurations)
    assert len(res.potential_risks) >= 1
    assert len(res.recommendations) >= 1
    # Core invariant: Observed config != confirmed vulnerability
    assert res.confirmed_vulnerability is False
