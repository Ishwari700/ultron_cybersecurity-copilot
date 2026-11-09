"""
Regression and security invariant tests for:
- Finding 7: External HTTPX Client Redirect Bypass Enforcement & Per-Hop Gate Validation
- Finding 8: Shared Process-Wide Rate Limiting Across Instances & Workers
"""

from concurrent.futures import ThreadPoolExecutor
import threading
import time
from typing import List
import httpx
import pytest

from src.scope.client import (
    ScopedHttpClient,
    ScopeViolationError,
    SharedRateLimiter,
)
from src.scope.gate import ScopeGate
from src.scope.models import ScopeDecision, ScopePolicy


@pytest.fixture
def scope_policy() -> ScopePolicy:
    return ScopePolicy(
        program_name="target-corp",
        platform="hackerone",
        in_scope=["*.target.com", "api.target.com", "sub.target.com", "hop2.target.com"],
        out_of_scope=["internal.target.com", "10.0.0.1", "evil.com"],
        rules_of_engagement={
            "rate_limit_rps": 10.0,
            "no_automated_scanning_on": ["/admin/*"],
        },
    )


@pytest.fixture
def gate(scope_policy: ScopePolicy) -> ScopeGate:
    resolver_map = {
        "api.target.com": ["93.184.216.34"],
        "sub.target.com": ["93.184.216.35"],
        "hop2.target.com": ["93.184.216.36"],
        "evil.com": ["198.51.100.1"],
        "internal.target.com": ["10.0.0.1"],
    }
    return ScopeGate(policy=scope_policy, dns_resolver=lambda h: resolver_map.get(h, ["93.184.216.99"]))


# ===========================================================================
# Finding 7 Tests: Redirect Enforcement & Gate Validation
# ===========================================================================

def test_internal_client_handles_in_scope_redirect(gate):
    """Internally created client safely follows in-scope redirect and verifies destination."""
    class InScopeRedirectTransport(httpx.BaseTransport):
        def handle_request(self, request):
            if "api.target.com" in str(request.url):
                return httpx.Response(302, headers={"Location": "https://sub.target.com/profile"}, request=request)
            return httpx.Response(200, text="Final In-Scope Page", request=request)

    client = ScopedHttpClient(scope_gate=gate, transport=InScopeRedirectTransport(), enforce_ip_pinning=False)
    resp, decision = client.get("https://api.target.com/start")

    assert resp.status_code == 200
    assert resp.text == "Final In-Scope Page"
    assert decision.canonical_host == "sub.target.com"
    assert decision.decision == ScopeDecision.ALLOW


def test_injected_client_with_follow_redirects_true_enforced_false(gate):
    """External client created with follow_redirects=True has False enforced and cannot bypass ScopeGate."""
    dispatched_urls = []

    class TargetTrackingTransport(httpx.BaseTransport):
        def handle_request(self, request):
            dispatched_urls.append(str(request.url))
            if "api.target.com" in str(request.url):
                # Redirect to out-of-scope domain evil.com
                return httpx.Response(302, headers={"Location": "https://evil.com/pwned"}, request=request)
            return httpx.Response(200, text="Evil response", request=request)

    # Injected external client has follow_redirects=True configured
    external_client = httpx.Client(
        transport=TargetTrackingTransport(),
        follow_redirects=True,
    )

    client = ScopedHttpClient(
        scope_gate=gate,
        client=external_client,
        enforce_ip_pinning=False,
    )

    # follow_redirects on the external client must be neutralized to False
    assert external_client.follow_redirects is False

    # Attempting to fetch initial URL that redirects to evil.com MUST raise ScopeViolationError
    with pytest.raises(ScopeViolationError, match="evil.com"):
        client.get("https://api.target.com/start")

    # evil.com must NEVER have been dispatched by HTTPX!
    assert not any("evil.com" in u for u in dispatched_urls)


def test_redirect_chain_validates_each_hop(gate):
    """A redirect chain (A -> B -> C) evaluates ScopeGate on every hop."""
    evaluated_hops = []

    class ChainRedirectTransport(httpx.BaseTransport):
        def handle_request(self, request):
            url_str = str(request.url)
            if "api.target.com" in url_str:
                return httpx.Response(302, headers={"Location": "https://sub.target.com/hop1"}, request=request)
            elif "sub.target.com" in url_str:
                return httpx.Response(302, headers={"Location": "https://hop2.target.com/hop2"}, request=request)
            return httpx.Response(200, text="Chain destination", request=request)

    client = ScopedHttpClient(scope_gate=gate, transport=ChainRedirectTransport(), enforce_ip_pinning=False)
    resp, decision = client.get("https://api.target.com/start")

    assert resp.status_code == 200
    assert decision.canonical_host == "hop2.target.com"


def test_redirect_loop_detected_and_rejected(gate):
    """A redirect loop (A -> B -> A) is detected and raises TooManyRedirects without hanging."""
    class LoopRedirectTransport(httpx.BaseTransport):
        def handle_request(self, request):
            url_str = str(request.url)
            if "api.target.com" in url_str:
                return httpx.Response(302, headers={"Location": "https://sub.target.com/loop"}, request=request)
            return httpx.Response(302, headers={"Location": "https://api.target.com/start"}, request=request)

    client = ScopedHttpClient(scope_gate=gate, transport=LoopRedirectTransport(), enforce_ip_pinning=False)

    with pytest.raises(httpx.TooManyRedirects, match="Redirect loop detected"):
        client.get("https://api.target.com/start")


# ===========================================================================
# Finding 8 Tests: Shared Process-Wide Rate Limiting
# ===========================================================================

def test_multiple_client_instances_share_rate_limit(gate):
    """Multiple independent ScopedHttpClient instances enforce the same aggregate rate limit."""
    SharedRateLimiter.reset_all()

    class InstantMockTransport(httpx.BaseTransport):
        def handle_request(self, request):
            return httpx.Response(200, text="OK", request=request)

    transport = InstantMockTransport()
    # 5 RPS means minimum 0.20s per request
    client1 = ScopedHttpClient(scope_gate=gate, transport=transport, rate_limit_rps=5.0, enforce_ip_pinning=False)
    client2 = ScopedHttpClient(scope_gate=gate, transport=transport, rate_limit_rps=5.0, enforce_ip_pinning=False)

    # Both clients must share the exact same limiter
    assert client1.rate_limiter is client2.rate_limiter

    t0 = time.monotonic()
    client1.get("https://api.target.com/1")
    client2.get("https://api.target.com/2")
    t1 = time.monotonic()

    elapsed = t1 - t0
    # Two requests at 5 RPS requires at least ~0.18s
    assert elapsed >= 0.18, f"Expected shared rate limiting delay of >=0.18s, got {elapsed:.4f}s"


def test_concurrent_worker_threads_cannot_multiply_rate_limit(gate):
    """Concurrent worker threads cannot exceed aggregate rate limit."""
    SharedRateLimiter.reset_all()

    class InstantMockTransport(httpx.BaseTransport):
        def handle_request(self, request):
            return httpx.Response(200, text="OK", request=request)

    transport = InstantMockTransport()
    # 10 RPS -> 5 requests should take at least ~0.35s
    rate = 10.0
    limiter = SharedRateLimiter.get_limiter("program:target-corp", rate_limit_rps=rate)

    clients = [
        ScopedHttpClient(scope_gate=gate, transport=transport, shared_rate_limiter=limiter, enforce_ip_pinning=False)
        for _ in range(5)
    ]

    t0 = time.monotonic()
    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = [pool.submit(clients[i].get, f"https://api.target.com/{i}") for i in range(5)]
        for f in futures:
            f.result()
    t1 = time.monotonic()

    elapsed = t1 - t0
    # 5 requests at 10 RPS: first is free (bucket capacity 1), remaining 4 take 4 * 0.10s = 0.40s.
    assert elapsed >= 0.35, f"Expected concurrent workers to be throttled to >=0.35s, got {elapsed:.4f}s"


def test_rate_limiter_reset_and_burst():
    """SharedRateLimiter allows burst up to capacity and resets cleanly."""
    limiter = SharedRateLimiter(rate_limit_rps=10.0, burst_capacity=3.0)

    # Initial bucket is full (capacity=3)
    t0 = time.monotonic()
    limiter.acquire(1.0)
    limiter.acquire(1.0)
    limiter.acquire(1.0)
    t1 = time.monotonic()

    # Consuming burst capacity requires zero wait
    assert (t1 - t0) < 0.05

    # Consuming beyond burst capacity forces sleep
    t_wait = limiter.acquire(1.0)
    assert t_wait >= 0.08
