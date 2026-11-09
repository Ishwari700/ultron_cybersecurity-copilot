"""Unit Tests for M5 Task Intent Classifier and Mode Router."""

import pytest
from src.copilot.intent import CopilotMode, CopilotTaskType, IntentRouter


def test_intent_routing_reporting():
    res = IntentRouter.classify_intent("Draft a bug bounty report for this verified finding")
    assert res.primary_task == CopilotTaskType.REPORTING
    assert res.mode == CopilotMode.REPORTING


def test_intent_routing_tool_explanation():
    res = IntentRouter.classify_intent("How does Burp Suite Intruder sniper mode work?")
    assert res.primary_task == CopilotTaskType.EXPLAIN_TOOL
    assert res.mode == CopilotMode.TOOL_EXPLANATION

    res2 = IntentRouter.classify_intent("Explain nmap -sV flags and usage")
    assert res2.primary_task == CopilotTaskType.EXPLAIN_TOOL
    assert res2.mode == CopilotMode.TOOL_EXPLANATION


def test_intent_routing_vulnerability_research():
    res = IntentRouter.classify_intent("What is CVE-2024-21413 and how does it work?")
    assert res.primary_task == CopilotTaskType.VULNERABILITY_RESEARCH
    assert res.mode == CopilotMode.RESEARCH


def test_intent_routing_standards_research():
    res = IntentRouter.classify_intent("What are the PKCE requirements according to RFC 7636?")
    assert res.primary_task == CopilotTaskType.RESEARCH
    assert res.mode == CopilotMode.RESEARCH


def test_intent_routing_code_security_review():
    res = IntentRouter.classify_intent("Review this python code snippet for SQL injection: def get_user(id): ...")
    assert res.primary_task == CopilotTaskType.CODE_SECURITY_REVIEW

    res_ev = IntentRouter.classify_intent("Review this code", has_active_evidence=True)
    assert res_ev.mode == CopilotMode.INVESTIGATION
    assert res_ev.requires_investigation_workspace is True


def test_intent_routing_traffic_analysis():
    res = IntentRouter.classify_intent("Analyze this HTTP response: HTTP/1.1 200 OK Set-Cookie: session=xyz")
    assert res.primary_task == CopilotTaskType.TRAFFIC_ANALYSIS


def test_intent_routing_configuration_analysis():
    res = IntentRouter.classify_intent("Audit this nginx.conf configuration for missing security headers")
    assert res.primary_task == CopilotTaskType.CONFIGURATION_ANALYSIS


def test_intent_routing_experiment_design():
    res = IntentRouter.classify_intent("Design an experiment to test if Tenant A can access Tenant B's invoices")
    assert res.primary_task == CopilotTaskType.DESIGN_EXPERIMENT


def test_intent_routing_evidence_gap():
    res = IntentRouter.classify_intent("What evidence is missing before we can confirm BFLA?")
    assert res.primary_task == CopilotTaskType.IDENTIFY_EVIDENCE_GAP


def test_intent_routing_verify_hypothesis():
    res = IntentRouter.classify_intent("Verify this hypothesis regarding IDOR on user profile update")
    assert res.primary_task == CopilotTaskType.VERIFY_HYPOTHESIS


def test_intent_routing_troubleshoot():
    res = IntentRouter.classify_intent("Why does this JWT signature validation fail?")
    assert res.primary_task == CopilotTaskType.TROUBLESHOOT


def test_intent_routing_compare():
    res = IntentRouter.classify_intent("Compare authentication vs authorization")
    assert res.primary_task == CopilotTaskType.COMPARE
    assert res.mode == CopilotMode.GENERAL_QA


def test_intent_routing_general_security():
    res = IntentRouter.classify_intent("Explain the zero trust architecture model")
    assert res.primary_task == CopilotTaskType.GENERAL_SECURITY
    assert res.mode == CopilotMode.GENERAL_QA


def test_intent_routing_investigate():
    res = IntentRouter.classify_intent("Analyze endpoint response", has_active_evidence=True)
    assert res.mode == CopilotMode.INVESTIGATION
    assert res.requires_investigation_workspace is True


def test_intent_routing_default_explain():
    res = IntentRouter.classify_intent("What is cross-site scripting (XSS)?")
    assert res.primary_task == CopilotTaskType.EXPLAIN
    assert res.mode == CopilotMode.GENERAL_QA
