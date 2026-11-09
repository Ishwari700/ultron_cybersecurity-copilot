"""Unit tests evaluating the M8 Real-World Vulnerable Lab Fixtures.

Verifies:
- All 13 fixtures represent valid, parseable security test patterns.
- INVARIANT: PATTERN DETECTED != VULNERABILITY CONFIRMED.
- All fixtures define negative controls and falsification conditions.
- No fixture can be automatically confirmed without human verification.
"""

import pytest
from tests.lab.fixtures import LAB_FIXTURES, LabFixture


def test_all_13_lab_fixtures_configured():
    assert len(LAB_FIXTURES) == 13
    categories = {f.category for f in LAB_FIXTURES}
    assert "BOLA_IDOR" in categories
    assert "BROKEN_ACCESS_CONTROL" in categories
    assert "INSECURE_SESSION" in categories
    assert "SSRF" in categories
    assert "REFLECTED_XSS" in categories
    assert "SQL_INJECTION" in categories
    assert "ANDROID_EXPORTED_COMPONENT" in categories
    assert "ANDROID_WEBVIEW" in categories
    assert "INSECURE_TLS" in categories
    assert "HARDCODED_SECRET" in categories
    assert "DANGEROUS_NATIVE_SINK" in categories
    assert "PATH_TRAVERSAL" in categories
    assert "INSECURE_DESERIALIZATION" in categories


def test_pattern_detected_is_not_vulnerability_confirmed():
    """INVARIANT: Every lab fixture must have is_confirmed=False initially."""
    for fix in LAB_FIXTURES:
        assert fix.pattern_detected != ""
        assert fix.is_confirmed is False, f"Fixture {fix.fixture_id} cannot be auto-confirmed!"
        assert fix.negative_control != "", f"Fixture {fix.fixture_id} must have negative control"
        assert fix.falsification_condition != "", f"Fixture {fix.fixture_id} must have falsification condition"
        assert len(fix.required_evidence_to_confirm) >= 1
