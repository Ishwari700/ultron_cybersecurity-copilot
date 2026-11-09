"""Unit Tests for Domain-Aware NegativeControlEngine (Milestone M5)."""

import pytest
from src.copilot.domain import SecurityDomain
from src.research.negative_control import NegativeControlEngine


def test_negative_control_bola():
    guidance = NegativeControlEngine.get_guidance("Test BOLA on workspace endpoint")
    assert len(guidance) >= 1
    item = guidance[0]
    assert "public directory" in item.legitimate_explanations[0].lower() or "public" in item.legitimate_explanations[0].lower()
    assert len(item.falsification_conditions) >= 1
    assert any("403" in cond for cond in item.falsification_conditions)


def test_negative_control_sqli():
    guidance = NegativeControlEngine.get_guidance("SQL injection hypothesis", domain=SecurityDomain.SECURE_CODING)
    assert any(g.topic == "SQL Injection (SQLi)" for g in guidance)
    sqli_g = next(g for g in guidance if g.topic == "SQL Injection (SQLi)")
    assert any("prepared statement" in expl.lower() for expl in sqli_g.legitimate_explanations)
    assert any("AND 1=1" in chk for chk in sqli_g.negative_control_checks)


def test_negative_control_cors():
    guidance = NegativeControlEngine.get_guidance("CORS header misconfiguration")
    cors_g = next((g for g in guidance if "CORS" in g.topic), None)
    assert cors_g is not None
    assert any("Access-Control-Allow-Credentials" in chk for chk in cors_g.negative_control_checks)


def test_negative_control_android():
    guidance = NegativeControlEngine.get_guidance("Exported activity intent bypass", domain=SecurityDomain.ANDROID_SECURITY)
    android_g = next((g for g in guidance if "Android" in g.topic), None)
    assert android_g is not None
    assert any("MAIN" in expl for expl in android_g.legitimate_explanations)
    assert any("SecurityException" in fals for fals in android_g.falsification_conditions)
