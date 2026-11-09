"""Scope Gate enforcement engine with DNS TOCTOU hardening and auditable decisions."""

import ipaddress
import socket
from pathlib import Path
from typing import List, Optional, Tuple
from urllib.parse import urlparse
import tldextract
import yaml

from src.core.logging import AuditLogger, get_logger
from src.database.manager import DatabaseManager
from src.scope.models import (
    ScopeDecision,
    ScopeDecisionObject,
    ScopePolicy,
    ToolPolicy,
    AssessmentScopeStatus,
    ExtendedScopeDecisionResult,
)

logger = get_logger("ScopeGate")


class ScopeValidationError(Exception):
    """Raised when scope configuration contains dangerous or invalid rules."""
    pass


def extract_host_port(val: Optional[str]) -> Tuple[Optional[str], Optional[int]]:
    """Extract lowercased host and port integer from URL or host[:port] string."""
    if not val or not isinstance(val, str):
        return None, None
    from urllib.parse import unquote
    clean = unquote(val).strip()
    if not clean or "\x00" in clean:
        return None, None
    if "://" in clean:
        try:
            p = urlparse(clean)
            h = (p.hostname or "").strip().lower().rstrip(".")
            return (h if h else None), p.port
        except Exception:
            return None, None
    if ":" in clean and not clean.startswith("[") and clean.count(":") == 1:
        parts = clean.split(":")
        try:
            port = int(parts[1])
            h = parts[0].strip().lower().rstrip(".")
            return (h if h else None), port
        except ValueError:
            pass
    if clean.startswith("[") and "]:" in clean:
        parts = clean.split("]:")
        try:
            port = int(parts[1])
            h = parts[0].lstrip("[").strip().lower()
            return (h if h else None), port
        except ValueError:
            pass
    h = canonicalize_host(clean)
    return h, None


def canonicalize_host(raw_input: Optional[str]) -> Optional[str]:
    """
    Extract canonical lowercased host without port.
    Consistently handles:
    - Host headers ('api.target.local', 'api.target.local:443', 'API.TARGET.LOCAL')
    - Full URLs ('https://api.target.local/path', 'http://api.target.local:8080')
    - IPv4 ('127.0.0.1', '127.0.0.1:8080')
    - IPv6 ('[::1]', '[::1]:8080', '::1')
    - FQDN with trailing dot ('api.target.local.')
    - Whitespace trimming
    - Wildcards ('*.target.local')
    - Fails closed on malformed input (returns None)
    """
    if not raw_input or not isinstance(raw_input, str):
        return None

    from urllib.parse import unquote
    clean = unquote(raw_input).strip()
    if not clean:
        return None

    # Disallow null bytes and non-printable control characters
    if "\x00" in clean or any(ord(c) < 32 for c in clean):
        return None

    # Disallow userinfo (@) which creates parser ambiguity / credential confusion in scope definitions
    if "@" in clean:
        return None

    # Handle wildcards
    if clean.startswith("*."):
        sub = canonicalize_host(clean[2:])
        return f"*.{sub}" if sub else None

    # Handle raw IPv6 address without scheme or brackets
    try:
        ip = ipaddress.ip_address(clean)
        return str(ip).lower()
    except ValueError:
        # If string contains multiple colons but fails ipaddress parsing and is not bracketed IPv6, reject as malformed
        if "::" in clean and not clean.startswith("["):
            return None

    # If no scheme, add https:// to allow urlparse to process host[:port][/path]
    if "://" not in clean:
        clean_url = f"https://{clean}"
    else:
        clean_url = clean

    try:
        parsed = urlparse(clean_url)
        if parsed.username or parsed.password:
            return None
        host = parsed.hostname
        if not host:
            return None
        host = host.strip().lower().rstrip(".")
        if not host:
            return None
        # Disallow control chars, whitespace, or invalid host characters
        if any(c.isspace() or c in "<>\"'{}\\|^`@" for c in host):
            return None
        return host
    except (ValueError, AttributeError):
        return None


class ScopeGate:
    """
    Architectural gatekeeper validating all network targets against program scope.
    Guarantees that every network action has an explicit, valid ScopeDecisionObject.
    """

    def __init__(
        self,
        policy_path: Optional[Path] = None,
        policy: Optional[ScopePolicy] = None,
        db_manager: Optional[DatabaseManager] = None,
        audit_logger: Optional[AuditLogger] = None,
        allow_private_ranges: bool = False,
        allow_loopback: bool = False,
        dns_resolver=None,
    ) -> None:
        self.db_manager = db_manager
        self.audit_logger = audit_logger
        self.allow_private_ranges = allow_private_ranges
        self.allow_loopback = allow_loopback
        self.dns_resolver = dns_resolver or self._default_resolve_addresses

        # Initialize TLDExtract with offline local cache
        cache_dir = Path("data/cache/tld_cache")
        cache_dir.mkdir(parents=True, exist_ok=True)
        self._extractor = tldextract.TLDExtract(cache_dir=str(cache_dir), suffix_list_urls=None)

        if policy:
            self.policy = policy
        elif policy_path:
            self.policy = self.load_policy(policy_path)
        else:
            default_path = Path("scope.yaml")
            if default_path.exists():
                self.policy = self.load_policy(default_path)
            else:
                self.policy = ScopePolicy(
                    program_name="unconfigured",
                    platform="unknown",
                    in_scope=[],
                )

        self._validate_policy_patterns()

    def load_policy(self, path: Path) -> ScopePolicy:
        """Load and parse scope policy from YAML file."""
        with open(path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}

        # Parse tool policies
        tool_policies = {}
        for tool, pol_str in (raw.get("tool_policy") or {}).items():
            try:
                tool_policies[tool.lower()] = ToolPolicy(pol_str)
            except ValueError:
                tool_policies[tool.lower()] = ToolPolicy.ACTIVE

        # Normalize rules of engagement
        roe = dict(raw.get("rules_of_engagement") or {})
        no_scan = roe.get("no_automated_scanning_on", [])
        if isinstance(no_scan, str):
            no_scan = [no_scan]
        elif not isinstance(no_scan, list):
            no_scan = []
        roe["no_automated_scanning_on"] = no_scan

        disallowed = roe.get("disallowed_techniques", [])
        if isinstance(disallowed, str):
            disallowed = [disallowed]
        elif not isinstance(disallowed, list):
            disallowed = []
        roe["disallowed_techniques"] = disallowed

        return ScopePolicy(
            program_name=raw.get("program_name", "unnamed"),
            platform=raw.get("platform", "unknown"),
            scope_policy_version=raw.get("scope_policy_version", "v6"),
            in_scope=raw.get("in_scope", []),
            out_of_scope=raw.get("out_of_scope", []),
            program_constraints=raw.get("program_constraints", {}) or {},
            rules_of_engagement=roe,
            tool_policy=tool_policies,
        )

    def _validate_policy_patterns(self) -> None:
        """Reject overbroad wildcard patterns that would place entire TLDs in scope."""
        all_patterns = self.policy.in_scope + self.policy.out_of_scope
        for pat in all_patterns:
            clean = pat.lower().strip()
            if clean.startswith("*."):
                domain_part = clean[2:]
                ext = self._extractor(domain_part)
                # If there is no domain or domain equals suffix, it's an entire TLD (e.g. *.com, *.co.uk)
                if not ext.domain:
                    raise ScopeValidationError(
                        f"Dangerous overbroad wildcard scope pattern '{pat}': cannot target an entire TLD."
                    )

    @staticmethod
    def canonicalize_host(raw_url: Optional[str]) -> Optional[str]:
        """Extract canonical lowercased host without port."""
        return canonicalize_host(raw_url)

    @staticmethod
    def matches_pattern(host: Optional[str], pattern: Optional[str]) -> bool:
        """
        Check if a canonical host matches a scope pattern.
        - Host is normalized.
        - If pattern starts with '*.' (e.g. '*.target.local'), matches exact suffix ('target.local')
          or any valid subdomain ending with '.suffix' ('api.target.local').
          Does NOT match substring boundaries (e.g. 'evil-target.local' or 'target.local.evil.com').
        - If pattern does not start with '*.' (e.g. 'api.target.local'), requires an exact match.
          Subdomains (e.g. 'evil.api.target.local') do NOT match an exact host pattern.
        """
        if not host or not pattern:
            return False

        c_host = canonicalize_host(host)
        if not c_host:
            return False

        clean_pat = pattern.strip().lower()
        if clean_pat.startswith("*."):
            c_suffix = canonicalize_host(clean_pat[2:])
            if not c_suffix:
                return False
            return c_host == c_suffix or c_host.endswith("." + c_suffix)
        else:
            c_pat = canonicalize_host(clean_pat)
            if not c_pat:
                return False
            return c_host == c_pat

    def _matches_pattern(self, host: str, pattern: str) -> bool:
        """Check if canonical host matches a scope pattern."""
        return self.matches_pattern(host, pattern)

    def _matches_path_rule(self, canonical_host: str, requested_url: str, pattern: str) -> bool:
        """Check if requested URL matches a no_automated_scanning_on rule pattern."""
        if not pattern or not isinstance(pattern, str):
            return False
        clean_pat = pattern.lower().strip()

        parsed = urlparse(requested_url if "://" in requested_url else f"https://{requested_url}")
        req_path = (parsed.path or "/").rstrip("/").lower()
        if not req_path:
            req_path = "/"

        # Pattern format 1: host/path (e.g. "auth.target.com/oauth/token")
        if "/" in clean_pat and not clean_pat.startswith("/"):
            parts = clean_pat.split("/", 1)
            rule_host = parts[0]
            rule_path = "/" + parts[1].rstrip("/")
            if self._matches_pattern(canonical_host, rule_host):
                if req_path == rule_path or req_path.startswith(f"{rule_path}/"):
                    return True
                if rule_path.endswith("*") and req_path.startswith(rule_path[:-1]):
                    return True
            return False

        # Pattern format 2: path only (e.g. "/oauth/token" or "oauth/token")
        rule_path = clean_pat if clean_pat.startswith("/") else f"/{clean_pat}"
        rule_path = rule_path.rstrip("/")
        if req_path == rule_path or req_path.startswith(f"{rule_path}/"):
            return True
        if rule_path.endswith("*") and req_path.startswith(rule_path[:-1]):
            return True
        return False

    def _default_resolve_addresses(self, host: str) -> List[str]:
        """Resolve all IPv4 and IPv6 addresses for a given host."""
        try:
            # Look up both A and AAAA records
            records = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
            addresses = set()
            for rec in records:
                sockaddr = rec[4]
                ip_str = sockaddr[0]
                addresses.add(ip_str)
            return sorted(list(addresses))
        except (socket.gaierror, socket.herror, ValueError):
            return []

    def evaluate(
        self,
        requested_url: str,
        tool_name: str = "httpx",
        technique: Optional[str] = None,
        allow_passive: bool = False,
        target_scope: Optional[str] = None,
    ) -> ScopeDecisionObject:
        """
        Evaluate requested target URL against Scope Gate invariants.
        Returns an immutable ScopeDecisionObject.
        """
        canonical_host = self.canonicalize_host(requested_url)
        tool_policy = self.policy.tool_policy.get(tool_name.lower(), ToolPolicy.ACTIVE)

        if not canonical_host:
            return self._record_decision(
                ScopeDecision.DENY,
                requested_url,
                canonical_host or "invalid-host",
                [],
                tool_policy,
                "Failed to parse valid canonical host from URL",
            )

        # 1. Tool policy enforcement: passive tools cannot perform active network requests
        if tool_policy == ToolPolicy.PASSIVE and not allow_passive:
            return self._record_decision(
                ScopeDecision.DENY,
                requested_url,
                canonical_host,
                [],
                tool_policy,
                f"Tool '{tool_name}' has passive policy; active network requests are prohibited by tool policy",
            )

        # 2. Rules of Engagement: Disallowed techniques enforcement
        if technique:
            clean_tech = technique.lower().strip()
            disallowed = [t.lower().strip() for t in self.policy.rules_of_engagement.get("disallowed_techniques", [])]
            if clean_tech in disallowed:
                return self._record_decision(
                    ScopeDecision.DENY,
                    requested_url,
                    canonical_host,
                    [],
                    tool_policy,
                    f"Technique '{technique}' is prohibited by rules of engagement",
                )

        # 3. Rules of Engagement: Prohibited automated scanning paths (no_automated_scanning_on)
        for pat in self.policy.rules_of_engagement.get("no_automated_scanning_on", []):
            if self._matches_path_rule(canonical_host, requested_url, pat):
                return self._record_decision(
                    ScopeDecision.DENY,
                    requested_url,
                    canonical_host,
                    [],
                    tool_policy,
                    f"Target endpoint matches no_automated_scanning_on rule: {pat}",
                )

        # 4. Check out-of-scope rules (Out-of-scope always wins)
        for out_rule in self.policy.out_of_scope:
            if self._matches_pattern(canonical_host, out_rule):
                return self._record_decision(
                    ScopeDecision.DENY,
                    requested_url,
                    canonical_host,
                    [],
                    tool_policy,
                    f"Host matches explicit out_of_scope rule: {out_rule}",
                    out_of_scope_rule=out_rule,
                )

        # 5. Check in-scope rules
        matched_in_rule = None
        if target_scope is not None:
            canonical_target = self.canonicalize_host(target_scope)
            if not canonical_target:
                return self._record_decision(
                    ScopeDecision.DENY,
                    requested_url,
                    canonical_host,
                    [],
                    tool_policy,
                    f"Ambiguous or invalid target scope: '{target_scope}'",
                )
            if not self._matches_pattern(canonical_host, canonical_target):
                return self._record_decision(
                    ScopeDecision.DENY,
                    requested_url,
                    canonical_host,
                    [],
                    tool_policy,
                    f"Host '{canonical_host}' does not match authorized target scope: '{canonical_target}'",
                )
            matched_in_rule = canonical_target
            # If the scope policy explicitly defines program-level in_scope, also verify host is authorized
            if self.policy.in_scope:
                program_allowed = any(self._matches_pattern(canonical_host, r) for r in self.policy.in_scope)
                if not program_allowed:
                    return self._record_decision(
                        ScopeDecision.DENY,
                        requested_url,
                        canonical_host,
                        [],
                        tool_policy,
                        f"Host '{canonical_host}' is outside program-level authorized in_scope policy",
                    )
        else:
            if not self.policy.in_scope:
                return self._record_decision(
                    ScopeDecision.DENY,
                    requested_url,
                    canonical_host,
                    [],
                    tool_policy,
                    "No in_scope rules configured (fail-closed policy)",
                )
            for in_rule in self.policy.in_scope:
                if self._matches_pattern(canonical_host, in_rule):
                    matched_in_rule = in_rule
                    break

            if not matched_in_rule:
                return self._record_decision(
                    ScopeDecision.DENY,
                    requested_url,
                    canonical_host,
                    [],
                    tool_policy,
                    "Host does not match any authorized in_scope rule",
                )

        # 6. DNS TOCTOU Defense: Resolve all A and AAAA addresses (active requests only)
        if allow_passive:
            return self._record_decision(
                ScopeDecision.ALLOW,
                requested_url,
                canonical_host,
                [],
                tool_policy,
                f"Authorized destination matching rule: {matched_in_rule}",
                matched_rule=matched_in_rule,
            )

        resolved_ips = self.dns_resolver(canonical_host)
        if not resolved_ips:
            return self._record_decision(
                ScopeDecision.DENY,
                requested_url,
                canonical_host,
                [],
                tool_policy,
                "DNS resolution failed (fail-closed policy)",
                matched_rule=matched_in_rule,
            )

        # Validate every resolved IP against prohibited ranges (SSRF / DNS rebinding defense)
        for ip_str in resolved_ips:
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if not self.allow_loopback and ip_obj.is_loopback:
                    return self._record_decision(
                        ScopeDecision.DENY,
                        requested_url,
                        canonical_host,
                        resolved_ips,
                        tool_policy,
                        f"Resolved address {ip_str} is a loopback address",
                        matched_rule=matched_in_rule,
                    )
                if ip_obj.is_link_local:
                    return self._record_decision(
                        ScopeDecision.DENY,
                        requested_url,
                        canonical_host,
                        resolved_ips,
                        tool_policy,
                        f"Resolved address {ip_str} is a link-local address",
                        matched_rule=matched_in_rule,
                    )
                if ip_obj.is_multicast:
                    return self._record_decision(
                        ScopeDecision.DENY,
                        requested_url,
                        canonical_host,
                        resolved_ips,
                        tool_policy,
                        f"Resolved address {ip_str} is a multicast address",
                        matched_rule=matched_in_rule,
                    )
                if not self.allow_private_ranges and ip_obj.is_private:
                    return self._record_decision(
                        ScopeDecision.DENY,
                        requested_url,
                        canonical_host,
                        resolved_ips,
                        tool_policy,
                        f"Resolved address {ip_str} is a private IP address (SSRF blocked)",
                        matched_rule=matched_in_rule,
                    )
                if ip_obj.is_reserved:
                    return self._record_decision(
                        ScopeDecision.DENY,
                        requested_url,
                        canonical_host,
                        resolved_ips,
                        tool_policy,
                        f"Resolved address {ip_str} is an IETF reserved address",
                        matched_rule=matched_in_rule,
                    )
            except ValueError:
                return self._record_decision(
                    ScopeDecision.DENY,
                    requested_url,
                    canonical_host,
                    resolved_ips,
                    tool_policy,
                    f"Invalid IP address format: {ip_str}",
                    matched_rule=matched_in_rule,
                )

        # All invariants passed!
        return self._record_decision(
            ScopeDecision.ALLOW,
            requested_url,
            canonical_host,
            resolved_ips,
            tool_policy,
            f"Authorized destination matching rule: {matched_in_rule}",
            matched_rule=matched_in_rule,
        )

    def _record_decision(
        self,
        decision: ScopeDecision,
        requested_url: str,
        canonical_host: str,
        resolved_addresses: List[str],
        tool_policy: ToolPolicy,
        reason: str,
        matched_rule: Optional[str] = None,
        out_of_scope_rule: Optional[str] = None,
    ) -> ScopeDecisionObject:
        """Create, audit, and persist the ScopeDecisionObject."""
        pol_hash = self.policy.policy_hash if hasattr(self.policy, "policy_hash") else None
        obj = ScopeDecisionObject.create(
            decision=decision,
            requested_url=requested_url,
            canonical_host=canonical_host,
            resolved_addresses=resolved_addresses,
            tool_policy=tool_policy,
            reason=reason,
            matched_rule=matched_rule,
            out_of_scope_rule=out_of_scope_rule,
            scope_policy_version=self.policy.scope_policy_version,
            scope_policy_hash=pol_hash,
        )

        if self.db_manager:
            try:
                self.db_manager.insert_scope_decision(obj.model_dump())
            except Exception as exc:
                logger.error(f"Failed to persist scope decision {obj.scope_decision_id} to database: {exc}")
                if decision == ScopeDecision.ALLOW:
                    # Fail closed: cannot permit network request if audit persistence fails
                    return ScopeDecisionObject.create(
                        decision=ScopeDecision.DENY,
                        requested_url=requested_url,
                        canonical_host=canonical_host,
                        resolved_addresses=resolved_addresses,
                        tool_policy=tool_policy,
                        reason=f"Audit database failure on ALLOW decision (fail-closed): {exc}",
                        scope_policy_version=self.policy.scope_policy_version,
                        scope_policy_hash=pol_hash,
                    )

        if self.audit_logger:
            try:
                self.audit_logger.log_event(
                    event_type="SCOPE_DECISION",
                    actor="ScopeGate",
                    subject_id=obj.scope_decision_id,
                    new_state=obj.decision.value,
                    details=obj.model_dump(),
                )
            except Exception as exc:
                logger.error(f"Failed to write scope decision {obj.scope_decision_id} to audit log: {exc}")
                if decision == ScopeDecision.ALLOW:
                    # Fail closed: cannot permit network request if audit log write fails
                    return ScopeDecisionObject.create(
                        decision=ScopeDecision.DENY,
                        requested_url=requested_url,
                        canonical_host=canonical_host,
                        resolved_addresses=resolved_addresses,
                        tool_policy=tool_policy,
                        reason=f"Audit logger failure on ALLOW decision (fail-closed): {exc}",
                        scope_policy_version=self.policy.scope_policy_version,
                        scope_policy_hash=pol_hash,
                    )

        return obj

    @classmethod
    def matches_extended_pattern(
        cls,
        target: Optional[str],
        pattern: Optional[str],
        allow_wildcard_root: bool = False,
    ) -> bool:
        """
        M6 boundary-safe multi-target scope matcher.
        Supports:
        - Domain / Subdomain (exact host, wildcard prefix *.domain)
        - IP address & CIDR (e.g. 192.168.1.0/24)
        - Host + Port (e.g. host:8443 or :8443)
        - URLs & API endpoints (e.g. /api/v1/*, https://api.target.com/v1/*)
        - Mobile package identifiers (e.g. com.example.app, com.example.*)
        - Repositories (e.g. github.com/org/repo, org/repo)
        - Files (e.g. /path/to/file.py, *.py)
        - Cloud resources (e.g. arn:aws:s3:::bucket, s3://bucket)
        """
        if not target or not pattern:
            return False

        t_clean = str(target).strip()
        p_clean = str(pattern).strip()
        if not t_clean or not p_clean:
            return False

        # 1. CIDR matching
        if "/" in p_clean and not p_clean.startswith("http") and not p_clean.startswith("/"):
            try:
                net = ipaddress.ip_network(p_clean, strict=False)
                t_host = canonicalize_host(t_clean) or t_clean
                target_ip = ipaddress.ip_address(t_host)
                return target_ip in net
            except (ValueError, AttributeError):
                pass

        # 2. IP exact match
        try:
            p_ip = ipaddress.ip_address(p_clean)
            t_host = canonicalize_host(t_clean) or t_clean
            t_ip = ipaddress.ip_address(t_host)
            return p_ip == t_ip
        except (ValueError, AttributeError):
            pass

        # 3. Mobile package identifier (e.g. com.example.app)
        if "." in p_clean and not any(p_clean.startswith(proto) for proto in ("http://", "https://", "ftp://")):
            if p_clean.endswith(".*"):
                prefix = p_clean[:-2].lower()
                if t_clean.lower().startswith(prefix) and (len(t_clean) == len(prefix) or t_clean[len(prefix)] == "."):
                    return True
            if p_clean.lower() == t_clean.lower():
                return True

        # 4. Repository match (e.g. github.com/org/repo or org/repo)
        if "/" in p_clean and not p_clean.startswith("/") and not p_clean.startswith("http"):
            t_repo = t_clean.lower()
            p_repo = p_clean.lower()
            for prefix in ("https://", "http://", "git@github.com:"):
                if t_repo.startswith(prefix):
                    t_repo = t_repo[len(prefix):]
            if p_repo.endswith("/*"):
                base_repo = p_repo[:-2]
                if t_repo.startswith(base_repo):
                    return True
            if t_repo.rstrip("/") == p_repo.rstrip("/"):
                return True

        # 5. Cloud resources (e.g. arn:aws:... or s3://...)
        if any(p_clean.lower().startswith(p) for p in ("arn:", "s3://", "azure://", "gcp://")):
            if p_clean.endswith("*"):
                prefix = p_clean[:-1].lower()
                return t_clean.lower().startswith(prefix)
            return p_clean.lower() == t_clean.lower()

        # 6. File path match
        if p_clean.startswith("/") or p_clean.startswith("\\"):
            p_norm = p_clean.replace("\\", "/").lower()
            t_norm = t_clean.replace("\\", "/").lower()
            if p_norm.endswith("/*"):
                dir_prefix = p_norm[:-2]
                return t_norm.startswith(dir_prefix)
            if p_norm == t_norm:
                return True

        # 7. URL / API Endpoint path match
        if p_clean.startswith("http://") or p_clean.startswith("https://"):
            import posixpath
            from urllib.parse import unquote
            parsed_p = urlparse(p_clean)
            parsed_t = urlparse(t_clean if "://" in t_clean else f"https://{t_clean}")
            if not cls.matches_pattern(parsed_t.hostname, parsed_p.hostname):
                return False
            # Check port match if pattern specified a port
            port_p = parsed_p.port or (443 if parsed_p.scheme == "https" else 80)
            port_t = parsed_t.port or (443 if parsed_t.scheme == "https" else 80)
            if parsed_p.port is not None and port_p != port_t:
                return False
            # Normalize paths to defend against directory traversal (/api/v1/../../admin) and percent-encodings
            p_path_raw = unquote(parsed_p.path or "/")
            t_path_raw = unquote(parsed_t.path or "/")
            p_path = posixpath.normpath(p_path_raw).lower()
            t_path = posixpath.normpath(t_path_raw).lower()
            if p_clean.endswith("/*"):
                prefix = posixpath.normpath(unquote(parsed_p.path.rstrip("/*"))).lower()
                return t_path.startswith(prefix)
            if p_path.endswith("*"):
                return t_path.startswith(p_path[:-1])
            return p_path == t_path

        # 8. Domain / Subdomain matching (Strict boundary safety per Section 5)
        if "/" in p_clean:
            return False

        c_target = canonicalize_host(t_clean)
        if not c_target:
            return False

        # Port validation if pattern specified a port
        _, p_port = extract_host_port(p_clean)
        _, t_port = extract_host_port(t_clean)
        if p_port is not None:
            # Pattern has explicit port restriction
            eff_t_port = t_port
            if eff_t_port is None and "://" in t_clean:
                eff_t_port = 443 if t_clean.startswith("https://") else (80 if t_clean.startswith("http://") else None)
            if eff_t_port != p_port:
                return False

        p_lower = p_clean.lower().strip()
        if p_lower.startswith("*."):
            c_suffix = canonicalize_host(p_lower[2:])
            if not c_suffix:
                return False
            if c_target.endswith("." + c_suffix):
                return True
            if c_target == c_suffix:
                return allow_wildcard_root
            return False
        else:
            c_pat = canonicalize_host(p_lower)
            if not c_pat:
                return False
            return c_target == c_pat

    def evaluate_extended_scope(
        self,
        target_identifier: str,
        asset_type: Optional[str] = None,
        allow_wildcard_root: bool = False,
    ) -> ExtendedScopeDecisionResult:
        """
        M6 deterministic scope evaluator returning IN_SCOPE, OUT_OF_SCOPE, or UNKNOWN.
        UNKNOWN is treated as OUT_OF_SCOPE (fail closed).
        """
        pol_hash = self.policy.policy_hash if hasattr(self.policy, "policy_hash") else None
        pol_ver = getattr(self.policy, "scope_policy_version", "v6")

        if not target_identifier or not str(target_identifier).strip():
            return ExtendedScopeDecisionResult(
                scope_status=AssessmentScopeStatus.UNKNOWN,
                is_permitted=False,
                target_identifier=str(target_identifier),
                asset_type=asset_type,
                reason="Target identifier is empty or invalid. UNKNOWN treated as OUT_OF_SCOPE.",
                scope_policy_version=pol_ver,
                scope_policy_hash=pol_hash,
            )

        target_clean = str(target_identifier).strip()

        # 1. Check explicit exclusions (out_of_scope)
        for out_rule in self.policy.out_of_scope:
            if self.matches_extended_pattern(target_clean, out_rule, allow_wildcard_root=allow_wildcard_root):
                return ExtendedScopeDecisionResult(
                    scope_status=AssessmentScopeStatus.OUT_OF_SCOPE,
                    is_permitted=False,
                    target_identifier=target_clean,
                    asset_type=asset_type,
                    out_of_scope_rule=out_rule,
                    reason=f"Target explicitly excluded by out-of-scope rule: {out_rule}",
                    scope_policy_version=pol_ver,
                    scope_policy_hash=pol_hash,
                )

        # 2. Check in_scope rules
        for in_rule in self.policy.in_scope:
            if self.matches_extended_pattern(target_clean, in_rule, allow_wildcard_root=allow_wildcard_root):
                return ExtendedScopeDecisionResult(
                    scope_status=AssessmentScopeStatus.IN_SCOPE,
                    is_permitted=True,
                    target_identifier=target_clean,
                    asset_type=asset_type,
                    matched_rule=in_rule,
                    reason=f"Target matches authorized in-scope rule: {in_rule}",
                    scope_policy_version=pol_ver,
                    scope_policy_hash=pol_hash,
                )

        # 3. Default fail-closed: UNKNOWN treated as OUT_OF_SCOPE
        return ExtendedScopeDecisionResult(
            scope_status=AssessmentScopeStatus.UNKNOWN,
            is_permitted=False,
            target_identifier=target_clean,
            asset_type=asset_type,
            reason="Target does not match any authorized in-scope rule. UNKNOWN treated as OUT_OF_SCOPE (fail closed).",
            scope_policy_version=pol_ver,
            scope_policy_hash=pol_hash,
        )

    def recheck_scope(
        self,
        target_identifier: str,
        operation_name: str = "Operation",
    ) -> ExtendedScopeDecisionResult:
        """
        Revalidates target scope before experiment proposal, command generation,
        human execution handoff, result import, finding creation, or report inclusion.
        Raises ScopeValidationError if not permitted.
        """
        res = self.evaluate_extended_scope(target_identifier)
        if not res.is_permitted:
            raise ScopeValidationError(
                f"SCOPE RECHECK FAILED for {operation_name} on target '{target_identifier}': {res.reason}"
            )
        return res
