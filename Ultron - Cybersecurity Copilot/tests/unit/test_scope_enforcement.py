"""Focused tests for Scope Rule Enforcement (Task 1) and DNS TOCTOU IP-Pinning (Task 6)."""

import time
from pathlib import Path
from typing import List, Optional
import httpx
import pytest

from src.scope.client import ScopedHttpClient, ScopeViolationError
from src.scope.gate import ScopeGate, ScopeValidationError
from src.scope.models import ScopeDecision, ScopePolicy, ToolPolicy


@pytest.fixture
def base_policy() -> ScopePolicy:
    return ScopePolicy(
        program_name="target-bounty-program",
        platform="hackerone",
        in_scope=["*.target.com", "api.target.com"],
        out_of_scope=["staging.target.com", "internal.target.com"],
        rules_of_engagement={
            "rate_limit_rps": 4,
            "no_automated_scanning_on": [
                "auth.target.com/oauth/token",
                "/admin/restricted",
                "api.target.com/v1/wildcard/*",
            ],
            "disallowed_techniques": [
                "denial_of_service",
                "brute_force",
                "spamming",
            ],
        },
        tool_policy={
            "subfinder": ToolPolicy.PASSIVE,
            "gau": ToolPolicy.PASSIVE,
            "httpx": ToolPolicy.LOW_IMPACT_ACTIVE,
            "katana": ToolPolicy.ACTIVE,
        },
    )


def test_scope_enforcement_allow_in_scope(base_policy):
    """Verify legitimate in-scope target produces ALLOW."""
    gate = ScopeGate(policy=base_policy, dns_resolver=lambda h: ["93.184.216.34"])
    decision = gate.evaluate("https://api.target.com/v1/users")
    assert decision.decision == ScopeDecision.ALLOW
    assert "93.184.216.34" in decision.resolved_addresses


def test_scope_enforcement_deny_disallowed_technique(base_policy):
    """Verify disallowed techniques are blocked by gate."""
    gate = ScopeGate(policy=base_policy, dns_resolver=lambda h: ["93.184.216.34"])

    # Disallowed: brute_force
    d1 = gate.evaluate("https://api.target.com/v1/login", technique="brute_force")
    assert d1.decision == ScopeDecision.DENY
    assert "Technique 'brute_force' is prohibited" in d1.reason

    # Disallowed: case-insensitive check
    d2 = gate.evaluate("https://api.target.com/v1/login", technique="DENIAL_OF_SERVICE")
    assert d2.decision == ScopeDecision.DENY
    assert "Technique 'DENIAL_OF_SERVICE' is prohibited" in d2.reason

    # Allowed technique
    d3 = gate.evaluate("https://api.target.com/v1/login", technique="passive_fingerprint")
    assert d3.decision == ScopeDecision.ALLOW


def test_scope_enforcement_deny_no_automated_scanning_paths(base_policy):
    """Verify prohibited paths in no_automated_scanning_on are blocked."""
    gate = ScopeGate(policy=base_policy, dns_resolver=lambda h: ["93.184.216.34"])

    # Exact host/path match
    d1 = gate.evaluate("https://auth.target.com/oauth/token")
    assert d1.decision == ScopeDecision.DENY
    assert "no_automated_scanning_on" in d1.reason

    # Trailing slash match
    d2 = gate.evaluate("https://auth.target.com/oauth/token/")
    assert d2.decision == ScopeDecision.DENY
    assert "no_automated_scanning_on" in d2.reason

    # Case-insensitive path match
    d3 = gate.evaluate("https://auth.target.com/OAuth/Token")
    assert d3.decision == ScopeDecision.DENY
    assert "no_automated_scanning_on" in d3.reason

    # Query string stripped and blocked
    d4 = gate.evaluate("https://auth.target.com/oauth/token?grant_type=authorization_code&client_id=123")
    assert d4.decision == ScopeDecision.DENY
    assert "no_automated_scanning_on" in d4.reason

    # Path-only rule: /admin/restricted
    d5 = gate.evaluate("https://api.target.com/admin/restricted")
    assert d5.decision == ScopeDecision.DENY
    assert "no_automated_scanning_on" in d5.reason

    # Wildcard path rule: api.target.com/v1/wildcard/*
    d6 = gate.evaluate("https://api.target.com/v1/wildcard/deep/subpath")
    assert d6.decision == ScopeDecision.DENY
    assert "no_automated_scanning_on" in d6.reason

    # Unrestricted path allowed
    d7 = gate.evaluate("https://auth.target.com/public/login")
    assert d7.decision == ScopeDecision.ALLOW


def test_scope_enforcement_passive_tool_policy_blocked(base_policy):
    """Verify tool configured with PASSIVE policy cannot make active requests."""
    gate = ScopeGate(policy=base_policy, dns_resolver=lambda h: ["93.184.216.34"])

    # subfinder is PASSIVE in base_policy
    d_passive = gate.evaluate("https://api.target.com/v1/users", tool_name="subfinder")
    assert d_passive.decision == ScopeDecision.DENY
    assert "Tool 'subfinder' has passive policy" in d_passive.reason

    # katana is ACTIVE
    d_active = gate.evaluate("https://api.target.com/v1/users", tool_name="katana")
    assert d_active.decision == ScopeDecision.ALLOW


def test_scope_enforcement_malformed_configuration():
    """Verify Gate handles malformed or missing policy sections gracefully."""
    # Empty rules of engagement
    malformed_policy = ScopePolicy(
        program_name="malformed-program",
        platform="bugcrowd",
        in_scope=["api.target.com"],
        rules_of_engagement={},
        tool_policy={},
    )
    gate = ScopeGate(policy=malformed_policy, dns_resolver=lambda h: ["93.184.216.34"])
    d = gate.evaluate("https://api.target.com/test", technique=None)
    assert d.decision == ScopeDecision.ALLOW


def test_scoped_http_client_rate_limiting(base_policy):
    """Verify ScopedHttpClient enforces rate_limit_rps by throttling requests."""
    gate = ScopeGate(policy=base_policy, dns_resolver=lambda h: ["93.184.216.34"])

    # Configure a mock transport that returns immediately
    class MockTransport(httpx.BaseTransport):
        def handle_request(self, request):
            return httpx.Response(200, request=request, text="OK")

    # 4 RPS means ~0.25 seconds interval between requests
    client = ScopedHttpClient(
        scope_gate=gate,
        transport=MockTransport(),
        enforce_ip_pinning=False,
    )

    t0 = time.monotonic()
    client.get("https://api.target.com/req1")
    client.get("https://api.target.com/req2")
    t1 = time.monotonic()

    elapsed = t1 - t0
    # 2 requests at 4 RPS requires at least ~0.20s elapsed
    assert elapsed >= 0.20, f"Expected rate limiting delay of >=0.20s, but elapsed was {elapsed:.4f}s"


def test_dns_ip_pinning_ipv4_and_sni_preservation(base_policy):
    """Verify IP pinning connects to pinned IPv4 and preserves Host and TLS SNI."""
    gate = ScopeGate(policy=base_policy, dns_resolver=lambda h: ["93.184.216.99"])

    captured_requests = []

    class CapturingTransport(httpx.BaseTransport):
        def handle_request(self, request):
            captured_requests.append(request)
            return httpx.Response(200, request=request, text="OK")

    client = ScopedHttpClient(
        scope_gate=gate,
        transport=CapturingTransport(),
        enforce_ip_pinning=True,
    )

    resp, dec = client.get("https://api.target.com/v1/profile?user=42")
    assert resp.status_code == 200
    assert dec.decision == ScopeDecision.ALLOW
    assert len(captured_requests) == 1

    req = captured_requests[0]
    # URL destination must be the pinned IP
    assert req.url.host == "93.184.216.99"
    assert (req.url.port or 443) == 443
    assert req.url.path == "/v1/profile"
    assert req.url.query == b"user=42"

    # Host header must preserve the canonical hostname
    assert req.headers["Host"] == "api.target.com"

    # TLS SNI extension must preserve the canonical hostname
    assert req.extensions.get("sni_hostname") == "api.target.com"


def test_dns_ip_pinning_ipv6_formatting(base_policy):
    """Verify IP pinning formats IPv6 address in bracket notation."""
    gate = ScopeGate(policy=base_policy, dns_resolver=lambda h: ["2606:2800:220:1:248:1893:25c8:1946"])

    captured_requests = []

    class CapturingTransport(httpx.BaseTransport):
        def handle_request(self, request):
            captured_requests.append(request)
            return httpx.Response(200, request=request, text="OK")

    client = ScopedHttpClient(
        scope_gate=gate,
        transport=CapturingTransport(),
        enforce_ip_pinning=True,
    )

    resp, dec = client.get("https://api.target.com/v1/ipv6-test")
    assert resp.status_code == 200
    assert len(captured_requests) == 1

    req = captured_requests[0]
    # IPv6 host
    assert req.url.host == "2606:2800:220:1:248:1893:25c8:1946"
    assert req.headers["Host"] == "api.target.com"
    assert req.extensions.get("sni_hostname") == "api.target.com"


def test_scoped_http_client_redirect_re_evaluates_and_pins(base_policy):
    """Verify redirect hop is re-evaluated by ScopeGate and pinned to new destination."""
    resolver_map = {
        "api.target.com": ["93.184.216.34"],
        "sub.target.com": ["93.184.216.20"],
    }
    gate = ScopeGate(policy=base_policy, dns_resolver=lambda h: resolver_map.get(h, []))

    captured_requests = []

    class RedirectTransport(httpx.BaseTransport):
        def handle_request(self, request):
            captured_requests.append(request)
            if request.headers.get("Host") == "api.target.com":
                # Redirect to sub.target.com
                return httpx.Response(
                    302,
                    headers={"Location": "https://sub.target.com/redirected_target"},
                    request=request,
                )
            return httpx.Response(200, request=request, text="Redirect Complete")

    client = ScopedHttpClient(
        scope_gate=gate,
        transport=RedirectTransport(),
        enforce_ip_pinning=True,
    )

    resp, dec = client.get("https://api.target.com/start")
    assert resp.status_code == 200
    assert dec.requested_url == "https://sub.target.com/redirected_target"
    assert dec.canonical_host == "sub.target.com"

    assert len(captured_requests) == 2
    # Hop 1
    assert captured_requests[0].url.host == "93.184.216.34"
    assert captured_requests[0].headers["Host"] == "api.target.com"

    # Hop 2 (pinned to new resolved IP)
    assert captured_requests[1].url.host == "93.184.216.20"
    assert captured_requests[1].headers["Host"] == "sub.target.com"
    assert captured_requests[1].extensions.get("sni_hostname") == "sub.target.com"


def test_scoped_http_client_redirect_to_disallowed_path_blocked(base_policy):
    """Verify redirect to no_automated_scanning_on path is blocked with ScopeViolationError."""
    resolver_map = {
        "api.target.com": ["93.184.216.34"],
        "auth.target.com": ["93.184.216.30"],
    }
    gate = ScopeGate(policy=base_policy, dns_resolver=lambda h: resolver_map.get(h, []))

    class BadRedirectTransport(httpx.BaseTransport):
        def handle_request(self, request):
            return httpx.Response(
                302,
                headers={"Location": "https://auth.target.com/oauth/token"},
                request=request,
            )

    client = ScopedHttpClient(
        scope_gate=gate,
        transport=BadRedirectTransport(),
    )

    with pytest.raises(ScopeViolationError, match="no_automated_scanning_on"):
        client.get("https://api.target.com/start")
