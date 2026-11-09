"""Scoped HTTP client enforcing Scope Gate validation, shared rate limiting, and DNS TOCTOU IP-pinning."""

import ipaddress
import ssl
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse
import httpcore
import httpx

from src.scope.gate import ScopeGate
from src.scope.models import ScopeDecision, ScopeDecisionObject, ToolPolicy


class ScopeViolationError(Exception):
    """Raised when an outbound HTTP request or redirect violates the program scope."""
    def __init__(self, decision: ScopeDecisionObject) -> None:
        self.decision = decision
        super().__init__(
            f"Scope Violation ({decision.decision.value}): Destination '{decision.requested_url}' "
            f"blocked by Scope Gate: {decision.reason} [ID: {decision.scope_decision_id}]"
        )


def _normalize_ip(ip_str: str) -> str:
    """Normalizes an IPv4 or IPv6 address string for deterministic comparison."""
    clean = ip_str.strip().strip("[]")
    try:
        return str(ipaddress.ip_address(clean))
    except ValueError:
        return clean


class PeerVerifyingSyncBackend(httpcore.SyncBackend):
    """
    HTTPCore network backend that inspects the connected socket peer address
    immediately upon TCP connection establishment and BEFORE any TLS negotiation
    or HTTP request headers/body are transmitted over the wire.
    """
    def __init__(
        self,
        allowed_peers_provider: Callable[[], Optional[List[str]]],
        require_peer_verification: bool = True,
    ) -> None:
        super().__init__()
        self._allowed_peers_provider = allowed_peers_provider
        self._require_peer_verification = require_peer_verification

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: Optional[float] = None,
        local_address: Optional[str] = None,
        socket_options: Any = None,
    ) -> httpcore.NetworkStream:
        stream = super().connect_tcp(
            host,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )
        # Sockets just connected! Check peer address BEFORE TLS handshake or HTTP request transmission
        server_addr = stream.get_extra_info("server_addr")
        if server_addr is None and hasattr(stream, "_sock"):
            try:
                server_addr = stream._sock.getpeername()
            except Exception:
                server_addr = None

        peer_ip = None
        if server_addr is not None:
            if isinstance(server_addr, (tuple, list)) and len(server_addr) > 0:
                raw_ip = server_addr[0]
                peer_ip = raw_ip.decode() if isinstance(raw_ip, bytes) else str(raw_ip)
            elif isinstance(server_addr, bytes):
                peer_ip = server_addr.decode()
            elif isinstance(server_addr, str):
                peer_ip = server_addr

        allowed_peers = self._allowed_peers_provider()
        if allowed_peers is not None:
            if not peer_ip:
                try:
                    stream.close()
                except Exception:
                    pass
                raise httpcore.ConnectError(
                    f"PEER_VERIFICATION_UNAVAILABLE: Connection to {host}:{port} established but actual connected peer address could not be verified from socket."
                )

            normalized_peer = _normalize_ip(peer_ip)
            normalized_allowed = {_normalize_ip(a) for a in allowed_peers}

            if normalized_peer not in normalized_allowed:
                try:
                    stream.close()
                except Exception:
                    pass
                raise httpcore.ConnectError(
                    f"ACTUAL_PEER_VIOLATION: Connected peer address '{peer_ip}' does not match authorized resolved addresses {allowed_peers}."
                )

        setattr(stream, "_verified_peer_addr", peer_ip)
        return stream


class PeerVerifyingHTTPTransport(httpx.HTTPTransport):
    """
    Production HTTPTransport guaranteeing:
    1. trust_env=False to prevent uncontrolled environment proxy configuration from altering connection routes.
    2. Installation of PeerVerifyingSyncBackend into the connection pool to enforce pre-request peer address checks.
    """
    def __init__(
        self,
        allowed_peers_provider: Callable[[], Optional[List[str]]],
        require_peer_verification: bool = True,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        kwargs.setdefault("trust_env", False)
        super().__init__(*args, **kwargs)
        self._allowed_peers_provider = allowed_peers_provider
        self._require_peer_verification = require_peer_verification
        if hasattr(self, "_pool") and hasattr(self._pool, "_network_backend"):
            self._pool._network_backend = PeerVerifyingSyncBackend(
                allowed_peers_provider=allowed_peers_provider,
                require_peer_verification=require_peer_verification,
            )


class SharedRateLimiter:
    """
    Thread-safe, process-wide shared rate limiter.
    Enforces requests-per-second limits across multiple client instances and concurrent workers.
    """
    _registry: Dict[str, "SharedRateLimiter"] = {}
    _registry_lock = threading.Lock()

    def __init__(self, rate_limit_rps: float, burst_capacity: Optional[float] = None) -> None:
        self.rate_limit_rps = float(rate_limit_rps)
        self.capacity = float(burst_capacity) if burst_capacity is not None else 1.0
        self.tokens = self.capacity
        self.last_update = time.monotonic()
        self.lock = threading.Lock()

    @classmethod
    def get_limiter(
        cls,
        key: str,
        rate_limit_rps: float,
        burst_capacity: Optional[float] = None,
    ) -> "SharedRateLimiter":
        with cls._registry_lock:
            if key not in cls._registry:
                cls._registry[key] = cls(rate_limit_rps=rate_limit_rps, burst_capacity=burst_capacity)
            else:
                limiter = cls._registry[key]
                if rate_limit_rps > 0 and limiter.rate_limit_rps != rate_limit_rps:
                    limiter.rate_limit_rps = rate_limit_rps
            return cls._registry[key]

    @classmethod
    def reset_all(cls) -> None:
        with cls._registry_lock:
            cls._registry.clear()

    def acquire(self, tokens: float = 1.0) -> float:
        """
        Acquires tokens from bucket under lock.
        Sleeps if insufficient tokens are available to pace requests.
        Returns time waited in seconds.
        """
        if self.rate_limit_rps <= 0:
            return 0.0

        with self.lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            self.last_update = now
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate_limit_rps)

            if self.tokens >= tokens:
                self.tokens -= tokens
                return 0.0

            needed = tokens - self.tokens
            sleep_time = needed / self.rate_limit_rps
            time.sleep(sleep_time)
            self.last_update = time.monotonic()
            self.tokens = 0.0
            return sleep_time


def select_pinned_address(resolved_addresses: List[str]) -> str:
    """Explicit deterministic address selection policy for multiple resolved IP addresses.
    1. Filter out malformed IP entries.
    2. Prefer IPv4 over IPv6 for broader protocol support, then sort deterministically.
    """
    if not resolved_addresses:
        raise ValueError("No resolved addresses available for pinning.")
    ipv4 = []
    ipv6 = []
    for a in resolved_addresses:
        try:
            ip = ipaddress.ip_address(a)
            if ip.version == 4:
                ipv4.append(a)
            else:
                ipv6.append(a)
        except ValueError:
            continue
    if ipv4:
        return sorted(ipv4)[0]
    if ipv6:
        return sorted(ipv6)[0]
    return sorted(resolved_addresses)[0]


class ScopedHttpClient:
    """
    HTTP client that guarantees no network request or redirect executes
    without authorization from the ScopeGate, with shared rate limiting and
    DNS TOCTOU IP-pinning with pre-request connection-level peer validation.
    """

    def __init__(
        self,
        scope_gate: ScopeGate,
        tool_name: str = "httpx",
        max_redirects: int = 5,
        timeout: float = 15.0,
        rate_limit_rps: Optional[float] = None,
        enforce_ip_pinning: bool = True,
        transport: Optional[httpx.BaseTransport] = None,
        client: Optional[httpx.Client] = None,
        shared_rate_limiter: Optional[SharedRateLimiter] = None,
        allow_mock_transport: bool = False,
        require_peer_verification: Optional[bool] = None,
        authorization_record: Optional[Any] = None,
        authorization_guard: Optional[Callable[[], bool]] = None,
    ) -> None:
        self.scope_gate = scope_gate
        self.tool_name = tool_name
        self.max_redirects = max_redirects
        self.timeout = timeout
        self.enforce_ip_pinning = enforce_ip_pinning
        self.transport = transport
        self.allow_mock_transport = allow_mock_transport
        self.require_peer_verification = require_peer_verification
        self.authorization_record = authorization_record
        self.authorization_guard = authorization_guard

        # Capture initial scope policy revision state for execution-boundary validation
        self._initial_policy_hash = getattr(self.scope_gate.policy, "policy_hash", None)
        self._initial_policy_version = getattr(self.scope_gate.policy, "scope_policy_version", None)
        self._thread_local = threading.local()

        # Validate and harden injected client against redirect bypass and TLS verification disablement
        self._external_client = client
        if self._external_client is not None:
            if hasattr(self._external_client, "follow_redirects"):
                try:
                    self._external_client.follow_redirects = False
                except Exception as e:
                    raise ValueError(f"Cannot control redirect behavior on injected client: {e}")

            if hasattr(self._external_client, "_trust_env"):
                self._external_client._trust_env = False

            ext_transport = getattr(self._external_client, "_transport", None)
            is_http_transport = isinstance(ext_transport, httpx.HTTPTransport)

            # Check 1: Custom transport without established TLS guarantees
            if not is_http_transport:
                if not self.allow_mock_transport:
                    if self.enforce_ip_pinning:
                        raise ValueError(
                            "TLS_VERIFICATION_REQUIRED: Injected client uses a custom transport whose TLS guarantees "
                            "cannot be established. Production transports must use verified httpx.HTTPTransport or "
                            "explicitly set allow_mock_transport=True for testing."
                        )
            else:
                self._configure_http_transport(ext_transport)

        # Validate and harden injected transport
        if self.transport is not None:
            if isinstance(self.transport, httpx.HTTPTransport):
                self._configure_http_transport(self.transport)
            elif self.require_peer_verification and not self.allow_mock_transport:
                raise ValueError(
                    "TLS_VERIFICATION_REQUIRED: Injected custom transport has unverified security properties. "
                    "Production transports must use verified httpx.HTTPTransport or explicitly set allow_mock_transport=True for testing."
                )

        # Configure rate limit (rps)
        if rate_limit_rps is not None:
            self.rate_limit_rps = float(rate_limit_rps) if rate_limit_rps > 0 else None
        else:
            pol_rps = scope_gate.policy.rules_of_engagement.get("rate_limit_rps")
            try:
                self.rate_limit_rps = float(pol_rps) if pol_rps and float(pol_rps) > 0 else None
            except (ValueError, TypeError):
                self.rate_limit_rps = None

        # Bind to shared process-wide rate limiter
        if shared_rate_limiter:
            self.rate_limiter = shared_rate_limiter
        elif self.rate_limit_rps and self.rate_limit_rps > 0:
            program_key = scope_gate.policy.program_name or "default_program"
            self.rate_limiter = SharedRateLimiter.get_limiter(
                key=f"program:{program_key}",
                rate_limit_rps=self.rate_limit_rps,
            )
        else:
            self.rate_limiter = None

    def _get_current_allowed_peers(self) -> Optional[List[str]]:
        return getattr(self._thread_local, "current_allowed_peers", None)

    def _configure_http_transport(self, transport: httpx.HTTPTransport) -> None:
        """Inspects TLS settings on HTTPTransport and installs pre-request peer verification."""
        pool = getattr(transport, "_pool", None)
        ssl_ctx = getattr(pool, "_ssl_context", None) if pool else None

        if self._external_client is not None and getattr(self._external_client, "_verify", None) is False:
            raise ValueError("TLS_VERIFICATION_REQUIRED: Injected HTTP client has TLS certificate verification disabled.")

        if ssl_ctx is not None:
            if not getattr(ssl_ctx, "check_hostname", True):
                raise ValueError("TLS_VERIFICATION_REQUIRED: Injected HTTP client has TLS hostname checking disabled.")
            verify_mode = getattr(ssl_ctx, "verify_mode", None)
            if verify_mode is not None and verify_mode != ssl.CERT_REQUIRED:
                raise ValueError(
                    "TLS_VERIFICATION_REQUIRED: Injected HTTP client has TLS certificate verification disabled (must be ssl.CERT_REQUIRED)."
                )

        if pool is not None and hasattr(pool, "_network_backend"):
            if not isinstance(pool._network_backend, PeerVerifyingSyncBackend):
                pool._network_backend = PeerVerifyingSyncBackend(
                    allowed_peers_provider=self._get_current_allowed_peers,
                    require_peer_verification=bool(self.require_peer_verification),
                )
            else:
                pool._network_backend._allowed_peers_provider = self._get_current_allowed_peers
                pool._network_backend._require_peer_verification = bool(self.require_peer_verification)

    def _enforce_rate_limit(self) -> None:
        """Paces requests across all clients and workers using shared limiter."""
        if self.rate_limiter:
            self.rate_limiter.acquire(1.0)

    @staticmethod
    def extract_peer_address(response: httpx.Response) -> Optional[str]:
        """
        Extract the actual connected peer IP address from supported transport response extensions:
        1. 'network_stream' (HTTPCore / AnyIO socket stream -> get_extra_info('peername') or _verified_peer_addr)
        2. 'peer_address' (HTTPX / proxy / test extension)
        3. 'server_addr' (ASGI / Uvicorn / HTTPCore extension)
        """
        if "network_stream" in response.extensions:
            stream = response.extensions["network_stream"]
            if hasattr(stream, "_verified_peer_addr"):
                return getattr(stream, "_verified_peer_addr")
            if hasattr(stream, "get_extra_info"):
                try:
                    extra = (
                        stream.get_extra_info("peername")
                        or stream.get_extra_info("peer_address")
                        or stream.get_extra_info("server_addr")
                    )
                except Exception:
                    extra = None
                if extra:
                    if isinstance(extra, (tuple, list)):
                        val = extra[0]
                        return val.decode() if isinstance(val, bytes) else str(val)
                    elif isinstance(extra, bytes):
                        return extra.decode()
                    return str(extra)
        if "peer_address" in response.extensions:
            addr = response.extensions["peer_address"]
            if isinstance(addr, (tuple, list)):
                val = addr[0]
                return val.decode() if isinstance(val, bytes) else str(val)
            elif isinstance(addr, bytes):
                return addr.decode()
            return str(addr)
        if "server_addr" in response.extensions:
            addr = response.extensions["server_addr"]
            if isinstance(addr, (tuple, list)):
                val = addr[0]
                return val.decode() if isinstance(val, bytes) else str(val)
            elif isinstance(addr, bytes):
                return addr.decode()
            return str(addr)
        return None

    def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Any] = None,
        json_data: Optional[Any] = None,
        follow_redirects: bool = True,
        technique: Optional[str] = None,
        **kwargs: Any,
    ) -> Tuple[httpx.Response, ScopeDecisionObject]:
        """
        Execute request after verifying initial URL and every redirect hop.
        Guarantees that no redirect occurs without ScopeGate evaluation,
        and enforces pre-request connected peer verification.
        """
        current_url = url
        redirect_count = 0
        visited_urls: Set[str] = set()

        # Reject attempts to disable TLS certificate verification
        if kwargs.get("verify") is False:
            raise ValueError("TLS_VERIFICATION_REQUIRED: Disabling TLS certificate verification is forbidden by ScopedHttpClient security policy.")
        kwargs.pop("verify", None)

        # Execution boundary authorization and scope policy re-validation
        current_policy_hash = getattr(self.scope_gate.policy, "policy_hash", None)
        current_policy_version = getattr(self.scope_gate.policy, "scope_policy_version", None)

        if self.authorization_guard is not None:
            if not self.authorization_guard():
                raise ScopeViolationError(
                    ScopeDecisionObject.create(
                        decision=ScopeDecision.DENY,
                        requested_url=current_url,
                        canonical_host=urlparse(current_url).hostname or "",
                        resolved_addresses=[],
                        tool_policy=ToolPolicy.PASSIVE,
                        reason="AUTHORIZATION_INVALID: Execution boundary guard rejected dispatch.",
                        scope_policy_version=current_policy_version or "v6",
                        scope_policy_hash=current_policy_hash,
                    )
                )

        if self.authorization_record is not None:
            if hasattr(self.authorization_record, "is_currently_valid") and not self.authorization_record.is_currently_valid():
                raise ScopeViolationError(
                    ScopeDecisionObject.create(
                        decision=ScopeDecision.DENY,
                        requested_url=current_url,
                        canonical_host=urlparse(current_url).hostname or "",
                        resolved_addresses=[],
                        tool_policy=ToolPolicy.PASSIVE,
                        reason="AUTHORIZATION_EXPIRED: Authorization record is no longer valid at execution boundary.",
                        scope_policy_version=current_policy_version or "v6",
                        scope_policy_hash=current_policy_hash,
                    )
                )
            if hasattr(self.authorization_record, "scope_policy_hash") and self.authorization_record.scope_policy_hash:
                if current_policy_hash and self.authorization_record.scope_policy_hash != current_policy_hash:
                    raise ScopeViolationError(
                        ScopeDecisionObject.create(
                            decision=ScopeDecision.DENY,
                            requested_url=current_url,
                            canonical_host=urlparse(current_url).hostname or "",
                            resolved_addresses=[],
                            tool_policy=ToolPolicy.PASSIVE,
                            reason="SCOPE_POLICY_MUTATED: Scope policy hash changed after authorization at execution boundary.",
                            scope_policy_version=current_policy_version or "v6",
                            scope_policy_hash=current_policy_hash,
                        )
                    )

        if self._initial_policy_hash is not None and current_policy_hash is not None:
            if self._initial_policy_hash != current_policy_hash:
                raise ScopeViolationError(
                    ScopeDecisionObject.create(
                        decision=ScopeDecision.DENY,
                        requested_url=current_url,
                        canonical_host=urlparse(current_url).hostname or "",
                        resolved_addresses=[],
                        tool_policy=ToolPolicy.PASSIVE,
                        reason="SCOPE_POLICY_MUTATED: Scope policy modified since client initialization.",
                        scope_policy_version=current_policy_version or "v6",
                        scope_policy_hash=current_policy_hash,
                    )
                )

        is_production_transport = (
            self.transport is None
            and (self._external_client is None or isinstance(getattr(self._external_client, "_transport", None), httpx.HTTPTransport))
            and not self.allow_mock_transport
        )
        should_require_peer = (
            self.require_peer_verification
            if self.require_peer_verification is not None
            else is_production_transport
        )

        if self._external_client is not None:
            client_cm = self._external_client
            should_close = False
        elif self.transport is not None:
            client_cm = httpx.Client(
                timeout=self.timeout,
                follow_redirects=False,
                transport=self.transport,
                verify=True,
                trust_env=False,
            )
            should_close = True
        else:
            transport = PeerVerifyingHTTPTransport(
                allowed_peers_provider=self._get_current_allowed_peers,
                require_peer_verification=should_require_peer,
                verify=True,
                trust_env=False,
            )
            client_cm = httpx.Client(
                timeout=self.timeout,
                follow_redirects=False,
                transport=transport,
                verify=True,
                trust_env=False,
            )
            should_close = True

        # Always enforce follow_redirects=False on HTTP transport
        kwargs["follow_redirects"] = False

        try:
            while True:
                # 1. Gate check for current target (initial URL or redirect destination)
                decision = self.scope_gate.evaluate(
                    current_url,
                    tool_name=self.tool_name,
                    technique=technique,
                )
                if decision.decision != ScopeDecision.ALLOW:
                    raise ScopeViolationError(decision)

                # 2. Shared Rate limit pacing
                self._enforce_rate_limit()

                # 3. DNS TOCTOU Defense: IP-Pinning with TLS SNI and Host preservation
                req_headers = dict(headers or {})
                req_extensions = dict(kwargs.pop("extensions", {}) or {})

                parsed = urlparse(current_url)
                canonical_host = parsed.hostname or ""
                scheme = parsed.scheme.lower()
                port = parsed.port or (443 if scheme == "https" else 80)
                path_and_query = parsed.path or "/"
                if parsed.query:
                    path_and_query += f"?{parsed.query}"

                if self.enforce_ip_pinning and decision.resolved_addresses:
                    pinned_ip = select_pinned_address(decision.resolved_addresses)
                    if pinned_ip not in decision.resolved_addresses:
                        raise ValueError(f"Selected peer address '{pinned_ip}' not in approved resolved addresses.")
                    try:
                        ip_obj = ipaddress.ip_address(pinned_ip)
                        formatted_ip = f"[{pinned_ip}]" if ip_obj.version == 6 else pinned_ip
                    except ValueError:
                        formatted_ip = pinned_ip

                    dest_url = f"{scheme}://{formatted_ip}:{port}{path_and_query}"

                    # Host header preservation
                    if "Host" not in req_headers and "host" not in req_headers:
                        req_headers["Host"] = f"{canonical_host}:{port}" if parsed.port else canonical_host

                    # TLS SNI preservation
                    if scheme == "https":
                        req_extensions["sni_hostname"] = canonical_host
                else:
                    dest_url = current_url

                # Bind current target's approved resolved addresses to thread-local provider for connection-time validation
                self._thread_local.current_allowed_peers = list(decision.resolved_addresses) if decision.resolved_addresses else None

                # 4. Execute request for current target strictly without automatic redirects
                kwargs.pop("verify", None)
                try:
                    response = client_cm.request(
                        method=method,
                        url=dest_url,
                        headers=req_headers,
                        data=data,
                        json=json_data,
                        extensions=req_extensions,
                        **kwargs,
                    )
                except (httpx.ConnectError, httpcore.ConnectError) as exc:
                    err_text = f"{exc} {getattr(exc, '__cause__', '')}"
                    if "ACTUAL_PEER_VIOLATION" in err_text:
                        raise ScopeViolationError(
                            ScopeDecisionObject.create(
                                decision=ScopeDecision.DENY,
                                requested_url=current_url,
                                canonical_host=canonical_host,
                                resolved_addresses=decision.resolved_addresses,
                                tool_policy=decision.tool_policy,
                                reason=f"ACTUAL_PEER_VIOLATION: Pre-request connection to unauthorized peer aborted before transmission: {exc}",
                                scope_policy_version=self.scope_gate.policy.scope_policy_version,
                                scope_policy_hash=getattr(self.scope_gate.policy, "scope_policy_hash", None),
                            )
                        ) from exc
                    elif "PEER_VERIFICATION_UNAVAILABLE" in err_text:
                        raise ScopeViolationError(
                            ScopeDecisionObject.create(
                                decision=ScopeDecision.DENY,
                                requested_url=current_url,
                                canonical_host=canonical_host,
                                resolved_addresses=decision.resolved_addresses,
                                tool_policy=decision.tool_policy,
                                reason=f"PEER_VERIFICATION_UNAVAILABLE: Actual connected peer address could not be verified at connection boundary for host '{canonical_host}': {exc}",
                                scope_policy_version=self.scope_gate.policy.scope_policy_version,
                                scope_policy_hash=getattr(self.scope_gate.policy, "scope_policy_hash", None),
                            )
                        ) from exc
                    raise

                # 4b. Connected Peer Verification: Validate actual connected peer against authorized resolved addresses (Defense in Depth)
                peer_addr = self.extract_peer_address(response)

                if decision.resolved_addresses:
                    if peer_addr:
                        if peer_addr not in decision.resolved_addresses:
                            raise ScopeViolationError(
                                ScopeDecisionObject.create(
                                    decision=ScopeDecision.DENY,
                                    requested_url=current_url,
                                    canonical_host=canonical_host,
                                    resolved_addresses=decision.resolved_addresses,
                                    tool_policy=decision.tool_policy,
                                    reason=f"ACTUAL_PEER_VIOLATION: Connected peer address '{peer_addr}' does not match authorized resolved addresses {decision.resolved_addresses}.",
                                    scope_policy_version=self.scope_gate.policy.scope_policy_version,
                                    scope_policy_hash=getattr(self.scope_gate.policy, "scope_policy_hash", None),
                                )
                            )
                    elif should_require_peer:
                        raise ScopeViolationError(
                            ScopeDecisionObject.create(
                                decision=ScopeDecision.DENY,
                                requested_url=current_url,
                                canonical_host=canonical_host,
                                resolved_addresses=decision.resolved_addresses,
                                tool_policy=decision.tool_policy,
                                reason=f"PEER_VERIFICATION_UNAVAILABLE: Actual connected peer address could not be verified from transport metadata for host '{canonical_host}'.",
                                scope_policy_version=self.scope_gate.policy.scope_policy_version,
                                scope_policy_hash=getattr(self.scope_gate.policy, "scope_policy_hash", None),
                            )
                        )

                # 5. Check for redirect hop
                if follow_redirects and response.is_redirect and "location" in response.headers:
                    redirect_count += 1
                    if redirect_count > self.max_redirects:
                        raise httpx.TooManyRedirects(f"Exceeded maximum redirects ({self.max_redirects})")

                    location = response.headers["location"]
                    next_url = urljoin(current_url, location)

                    # Redirect loop detection
                    if next_url in visited_urls:
                        raise httpx.TooManyRedirects(f"Redirect loop detected: {next_url}")
                    visited_urls.add(current_url)

                    # Next hop will be evaluated by ScopeGate at the start of next loop iteration
                    current_url = next_url
                    if response.status_code in (302, 303):
                        method = "GET"
                        data = None
                        json_data = None
                    continue

                return response, decision
        finally:
            self._thread_local.current_allowed_peers = None
            if should_close:
                client_cm.close()

    def get(self, url: str, **kwargs: Any) -> Tuple[httpx.Response, ScopeDecisionObject]:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Tuple[httpx.Response, ScopeDecisionObject]:
        return self.request("POST", url, **kwargs)
