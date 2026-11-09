"""Unit tests for Scope Gate, DNS TOCTOU protection, and ScopedHttpClient."""

import pytest
from pathlib import Path
from src.database.manager import DatabaseManager
from src.scope.gate import ScopeGate, ScopeValidationError
from src.scope.models import ScopeDecision, ScopePolicy, ToolPolicy
from src.scope.client import ScopedHttpClient, ScopeViolationError


@pytest.fixture
def mock_resolver():
    """Mock DNS resolver returning controlled IPs."""
    ip_map = {
        "api.target.com": ["93.184.216.34"],
        "sub.api.target.com": ["93.184.216.35"],
        "staging.target.com": ["93.184.216.36"],
        "internal.target.com": ["10.0.0.1"],
        "loopback.target.com": ["127.0.0.1"],
        "metadata.target.com": ["169.254.169.254"],
        "ipv6-loopback.target.com": ["::1"],
        "multi-ip.target.com": ["198.51.100.5", "10.0.0.2"], # One public, one private
        "unresolvable.target.com": [],
        "attacker.com": ["203.0.113.1"],
    }
    return lambda host: ip_map.get(host, [])


@pytest.fixture
def scope_policy():
    return ScopePolicy(
        program_name="test-program",
        platform="hackerone",
        in_scope=["*.target.com", "target.com"],
        out_of_scope=["staging.target.com", "*.dev.target.com"],
        tool_policy={"httpx": ToolPolicy.LOW_IMPACT_ACTIVE, "katana": ToolPolicy.ACTIVE},
    )


def test_in_scope_destination(scope_policy, mock_resolver):
    """Verify in-scope destination allows request."""
    gate = ScopeGate(policy=scope_policy, dns_resolver=mock_resolver)
    decision = gate.evaluate("https://api.target.com/v1/users", tool_name="httpx")

    assert decision.decision == ScopeDecision.ALLOW
    assert decision.canonical_host == "api.target.com"
    assert decision.resolved_addresses == ["93.184.216.34"]
    assert decision.matched_rule == "*.target.com"
    assert decision.scope_decision_id.startswith("SCOPE-")


def test_out_of_scope_destination(scope_policy, mock_resolver):
    """Verify out-of-scope rule overrides in-scope wildcard."""
    gate = ScopeGate(policy=scope_policy, dns_resolver=mock_resolver)
    decision = gate.evaluate("https://staging.target.com/admin", tool_name="httpx")

    assert decision.decision == ScopeDecision.DENY
    assert decision.out_of_scope_rule == "staging.target.com"
    assert "out_of_scope rule" in decision.reason


def test_unmatched_destination(scope_policy, mock_resolver):
    """Verify non-matching destination is rejected."""
    gate = ScopeGate(policy=scope_policy, dns_resolver=mock_resolver)
    decision = gate.evaluate("https://attacker.com/steal", tool_name="httpx")

    assert decision.decision == ScopeDecision.DENY
    assert "does not match any authorized in_scope rule" in decision.reason


def test_overbroad_wildcard_rejected():
    """Verify loading a policy with *.com or *.co.uk raises ScopeValidationError."""
    invalid_policy = ScopePolicy(
        program_name="bad-program",
        platform="hackerone",
        in_scope=["*.com"],
    )
    with pytest.raises(ScopeValidationError, match="Dangerous overbroad wildcard"):
        ScopeGate(policy=invalid_policy)


def test_ssrf_private_ip_blocked(scope_policy, mock_resolver):
    """Verify in-scope name resolving to private IP is blocked (DNS rebinding / SSRF defense)."""
    gate = ScopeGate(policy=scope_policy, dns_resolver=mock_resolver, allow_private_ranges=False)
    decision = gate.evaluate("https://internal.target.com/admin")

    assert decision.decision == ScopeDecision.DENY
    assert "private IP address" in decision.reason


def test_loopback_and_metadata_blocked(scope_policy, mock_resolver):
    """Verify 127.0.0.1, ::1, and 169.254.169.254 are blocked."""
    gate = ScopeGate(policy=scope_policy, dns_resolver=mock_resolver)

    # 127.0.0.1
    d1 = gate.evaluate("https://loopback.target.com")
    assert d1.decision == ScopeDecision.DENY
    assert "loopback address" in d1.reason

    # AWS metadata
    d2 = gate.evaluate("https://metadata.target.com")
    assert d2.decision == ScopeDecision.DENY
    assert "link-local address" in d2.reason

    # IPv6 loopback
    d3 = gate.evaluate("https://ipv6-loopback.target.com")
    assert d3.decision == ScopeDecision.DENY
    assert "loopback address" in d3.reason


def test_multi_ip_host_with_one_private_blocked(scope_policy, mock_resolver):
    """Verify round-robin DNS with one private and one public IP fails closed."""
    gate = ScopeGate(policy=scope_policy, dns_resolver=mock_resolver)
    decision = gate.evaluate("https://multi-ip.target.com")

    assert decision.decision == ScopeDecision.DENY
    assert "private IP address" in decision.reason


def test_unresolvable_dns_fails_closed(scope_policy, mock_resolver):
    """Verify host that fails DNS resolution fails closed."""
    gate = ScopeGate(policy=scope_policy, dns_resolver=mock_resolver)
    decision = gate.evaluate("https://unresolvable.target.com")

    assert decision.decision == ScopeDecision.DENY
    assert "DNS resolution failed" in decision.reason


def test_scope_decision_persisted_to_database(scope_policy, mock_resolver, tmp_path: Path):
    """Verify decisions are persisted to evidence.db."""
    db_manager = DatabaseManager(db_path=tmp_path / "scope_test.db")
    db_manager.initialize_schema()

    gate = ScopeGate(policy=scope_policy, dns_resolver=mock_resolver, db_manager=db_manager)
    decision = gate.evaluate("https://api.target.com/info")

    retrieved = db_manager.get_scope_decision(decision.scope_decision_id)
    assert retrieved is not None
    assert retrieved["canonical_host"] == "api.target.com"
    assert retrieved["decision"] == "ALLOW"


def test_scoped_http_client_blocks_out_of_scope(scope_policy, mock_resolver):
    """Verify ScopedHttpClient raises ScopeViolationError on unauthorized destinations."""
    gate = ScopeGate(policy=scope_policy, dns_resolver=mock_resolver)
    client = ScopedHttpClient(scope_gate=gate)

    with pytest.raises(ScopeViolationError, match="Scope Violation"):
        client.get("https://attacker.com/test")
