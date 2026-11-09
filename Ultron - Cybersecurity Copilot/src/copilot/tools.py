"""Security Tool Knowledge Base and Safe Diagnostic Guidance (Milestone M5 Section 14).

Provides authoritative conceptual guidance for 23 standard security tools:
- Web & Proxy: Burp Suite, OWASP ZAP
- Network & Recon: Nmap, Wireshark, tcpdump, curl, dig, nslookup, openssl, ffuf, gobuster
- Application & Code: sqlmap, Semgrep
- Binary, Mobile & Reverse Engineering: Ghidra, JADX, apktool, Frida, ADB
- Forensics & Detection: Volatility, YARA, Sigma, Splunk, Elastic Stack

Enforces:
1. Explain purpose, safe options, interpretation, mistakes, and defensive implications.
2. Strictly passive advisory: NO autonomous tool execution.
"""

from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class ToolGuidanceEntry(BaseModel):
    """Authoritative conceptual reference for a security diagnostic tool."""
    tool_name: str
    category: str
    description: str
    relevant_options: List[str] = Field(default_factory=list)
    safe_lab_usage: str
    result_interpretation: str
    common_mistakes: List[str] = Field(default_factory=list)
    defensive_implications: str


class ToolKnowledgeBase:
    """Catalog of security diagnostic tools."""

    _CATALOG: Dict[str, ToolGuidanceEntry] = {
        "burp": ToolGuidanceEntry(
            tool_name="Burp Suite",
            category="Web Application Proxy",
            description="Intercepting HTTP/S proxy and manual web security testing suite.",
            relevant_options=["Repeater (manual request tampering)", "Intruder (rate-limited differential fuzzing)", "Target Scope (scope filtering)"],
            safe_lab_usage="Set explicit Target Scope in Proxy options. Disable active scan on staging/production environments to prevent unintended state mutations.",
            result_interpretation="Analyze HTTP status codes, body diffs, and timing variations between authenticated user sessions.",
            common_mistakes=["Testing out-of-scope third-party assets", "Running high-concurrency intruder threads that cause DoS"],
            defensive_implications="High request volumes trigger WAF rate-limiting, IP reputation blocks, and alert SIEM rules.",
        ),
        "zap": ToolGuidanceEntry(
            tool_name="OWASP ZAP",
            category="Web Application Proxy",
            description="Open-source web application security scanner and intercepting proxy.",
            relevant_options=["Passive Scan (non-intrusive traffic inspection)", "Active Scan (safe lab only)", "Context Scope"],
            safe_lab_usage="Use passive scanning during normal browsing to inspect headers and cookies without generating disruptive traffic.",
            result_interpretation="Review alert confidence levels; treat passive findings as indicators requiring manual verification.",
            common_mistakes=["Assuming all high-confidence alerts are verified vulnerabilities", "Failing to configure authentication context correctly"],
            defensive_implications="Active scanning generates observable traffic patterns easily fingerprinted by ModSecurity and cloud WAFs.",
        ),
        "nmap": ToolGuidanceEntry(
            tool_name="Nmap",
            category="Network Scanning",
            description="Network exploration and service discovery scanner.",
            relevant_options=["-sS (SYN stealth scan)", "-sV (Service version detection)", "-p- (Full port range)", "-Pn (Treat all hosts as online)", "--open (Show open ports only)"],
            safe_lab_usage="Use -sV with default timing (-T3 or -T4) against authorized test subnets. Avoid aggressive scan (-T5 or -A) in shared environments.",
            result_interpretation="Distinguish between 'open' (listening service), 'closed' (RST received), and 'filtered' (firewall/probe dropped).",
            common_mistakes=["Scanning unauthorized networks", "Misinterpreting filtered ports as service failures"],
            defensive_implications="SYN scans generate firewall alerts and trigger automated network intrusion detection systems (Snort/Suricata).",
        ),
        "wireshark": ToolGuidanceEntry(
            tool_name="Wireshark",
            category="Packet Analysis",
            description="Graphical network protocol analyzer for packet capture (PCAP) inspection.",
            relevant_options=["Display Filters (e.g., http.response.code == 403, tls.handshake.type == 1)", "Follow TCP Stream", "SSL/TLS Keylog decryption"],
            safe_lab_usage="Inspect captured PCAP files locally. Ensure capture filters isolate traffic to authorized lab interfaces.",
            result_interpretation="Analyze cleartext protocol payloads, sequence numbers, handshake renegotiations, and retransmissions.",
            common_mistakes=["Capturing promiscuous traffic containing third-party credentials", "Analyzing raw frames without appropriate protocol dissecting"],
            defensive_implications="Passive packet inspection generates 0 network noise on the wire.",
        ),
        "tcpdump": ToolGuidanceEntry(
            tool_name="tcpdump",
            category="Packet Capture",
            description="Command-line packet analyzer for capturing raw network flows.",
            relevant_options=["-i <interface>", "-n (No DNS resolution)", "-w <file.pcap>", "-c <count>", "port <port>"],
            safe_lab_usage="Capture bounded frame counts with specific BPF filters (e.g. 'tcp port 443 and host 10.0.0.1').",
            result_interpretation="Use for connection setup verification (SYN, SYN-ACK, ACK) and TCP RST troubleshooting.",
            common_mistakes=["Unbounded capture filling up root disk partition", "DNS overhead when omitting -n flag"],
            defensive_implications="Passive monitoring on network interfaces; produces no outbound traffic.",
        ),
        "curl": ToolGuidanceEntry(
            tool_name="curl",
            category="HTTP Client",
            description="Command-line tool for transferring data with URL syntax.",
            relevant_options=["-i (Include response headers)", "-v (Verbose TLS & connection details)", "-H 'Header: Value'", "-X POST", "-d 'data'"],
            safe_lab_usage="Use for precise manual verification of HTTP response status, cookies, and CORS headers without browser side-effects.",
            result_interpretation="Review HTTP response status code, Location headers on redirects, and Content-Type matching.",
            common_mistakes=["Silent redirect following without -L", "Omitting quotes around URLs containing query parameters (&)"],
            defensive_implications="Default User-Agent 'curl/x.y.z' is often blocked by commercial bot-protection suites.",
        ),
        "dig": ToolGuidanceEntry(
            tool_name="dig",
            category="DNS Lookup",
            description="DNS lookup utility for querying domain name servers.",
            relevant_options=["+short", "+trace", "ANY", "TXT", "MX", "@<nameserver>"],
            safe_lab_usage="Verify SPF, DKIM, DMARC records and DNS resolution paths for authorized domains.",
            result_interpretation="Inspect ANSWER, AUTHORITY, and ADDITIONAL sections; verify TTL decay and authoritative SOA.",
            common_mistakes=["Relying on cached resolver responses rather than querying authoritative nameservers directly"],
            defensive_implications="DNS queries are logged at local and recursive resolvers.",
        ),
        "nslookup": ToolGuidanceEntry(
            tool_name="nslookup",
            category="DNS Lookup",
            description="Network administration tool for querying DNS records.",
            relevant_options=["set type=mx", "set type=txt", "server <ip>"],
            safe_lab_usage="Perform basic DNS record resolution and reverse lookups.",
            result_interpretation="Analyze returned canonical names (CNAME) and IP mappings.",
            common_mistakes=["Using interactive mode in non-interactive shell scripts"],
            defensive_implications="Standard DNS traffic recorded in security telemetry.",
        ),
        "openssl": ToolGuidanceEntry(
            tool_name="OpenSSL",
            category="Cryptography & TLS",
            description="Command-line toolkit for TLS/SSL and cryptographic operations.",
            relevant_options=["s_client -connect <host:port> -servername <sni>", "-showcerts", "x509 -text -noout", "dgst -sha256"],
            safe_lab_usage="Inspect server TLS certificate chain, SAN entries, and supported protocol versions (TLS 1.2 vs 1.3).",
            result_interpretation="Verify validity dates, issuer trust chain, Subject Alternative Names, and negotiated cipher suite.",
            common_mistakes=["Forgetting -servername for SNI-hosted environments leading to wrong certificate"],
            defensive_implications="Full TLS handshakes logged in server access logs and TLS termination proxies.",
        ),
        "ffuf": ToolGuidanceEntry(
            tool_name="ffuf",
            category="Web Fuzzing",
            description="Fast web fuzzer written in Go for discovering endpoints and parameters.",
            relevant_options=["-u <url>/FUZZ", "-w <wordlist>", "-mc <status_codes>", "-fc 404", "-rate <requests_per_sec>"],
            safe_lab_usage="Rate-limit fuzzing with -rate 10 to avoid overwhelming test instances. Filter out expected 404 responses.",
            result_interpretation="Evaluate response word counts and line counts to filter out generic custom error pages.",
            common_mistakes=["Fuzzing production without authorization", "Not filtering wildcard responses resulting in 100,000 false positives"],
            defensive_implications="High request velocity triggers automated IP bans and Web Application Firewall rate controls.",
        ),
        "gobuster": ToolGuidanceEntry(
            tool_name="gobuster",
            category="Directory & DNS Enumeration",
            description="Directory and DNS brute-forcing tool written in Go.",
            relevant_options=["dir -u <url> -w <wordlist>", "dns -d <domain> -w <subdomains>", "-t <threads>", "-s <status_codes>"],
            safe_lab_usage="Use small curated wordlists (e.g. raft-small-words) with modest thread counts (-t 10).",
            result_interpretation="Confirm status codes: 200 (Found), 301/302 (Redirect), 403 (Forbidden directory).",
            common_mistakes=["Excessive threads causing HTTP 503 service throttling"],
            defensive_implications="Rapid directory traversal scanning is flagged in web server access logs.",
        ),
        "sqlmap": ToolGuidanceEntry(
            tool_name="sqlmap",
            category="Database Security",
            description="Automatic SQL injection and database takeover diagnostic tool.",
            relevant_options=["-u <url>", "--batch", "--technique=B (Boolean-based only)", "--risk=1 --level=1", "--banner"],
            safe_lab_usage="In authorized testing, start with --risk 1 --level 1. Do NOT use --os-shell or destructive update queries.",
            result_interpretation="Verify whether DBMS fingerprint and parameter injection were confirmed via differential responses.",
            common_mistakes=["Running aggressive techniques that corrupt database tables or trigger stored procedures"],
            defensive_implications="Heavy SQL syntax injection triggers database firewalls and SIEM SQLi alerts immediately.",
        ),
        "semgrep": ToolGuidanceEntry(
            tool_name="Semgrep",
            category="Static Code Analysis (SAST)",
            description="Fast, open-source static analysis engine for code security pattern matching.",
            relevant_options=["semgrep scan --config auto", "semgrep --config 'p/owasp-top-ten'", "--json"],
            safe_lab_usage="Run locally against source code repositories; 100% passive, zero target interaction.",
            result_interpretation="Treat rule matches as syntactic pattern indicators; verify whether tainted input reaches sink without sanitizer.",
            common_mistakes=["Reporting raw Semgrep matches as confirmed vulnerabilities without reviewing context"],
            defensive_implications="Local offline analysis; zero offensive footprint.",
        ),
        "ghidra": ToolGuidanceEntry(
            tool_name="Ghidra",
            category="Reverse Engineering",
            description="NSA-developed software reverse engineering (SRE) suite with decompiler.",
            relevant_options=["Auto-analysis", "Decompiler Window", "Cross-Reference (XREF) analysis", "Symbol Tree"],
            safe_lab_usage="Analyze unknown binaries in an isolated analysis VM. Inspect imports, exports, and decompiled functions.",
            result_interpretation="Identify logic bugs, hardcoded secrets, unsafe string functions (strcpy), and cryptographic constants.",
            common_mistakes=["Trusting variable names generated by heuristics without analyzing calling conventions"],
            defensive_implications="Local offline binary analysis; zero network footprint.",
        ),
        "jadx": ToolGuidanceEntry(
            tool_name="JADX",
            category="Android Decompiler",
            description="Dex to Java decompiler for Android APK and DEX file inspection.",
            relevant_options=["jadx-gui <apk>", "Decompile AndroidManifest.xml", "Find Usages"],
            safe_lab_usage="Inspect APK manifest permissions, exported components, and cryptographic storage calls locally.",
            result_interpretation="Review Java source reconstruction; identify hardcoded API keys and insecure Intent handling.",
            common_mistakes=["Assuming obfuscated code is unexploitable or decompiled source is 100% bug-free"],
            defensive_implications="Offline static analysis of client applications.",
        ),
        "apktool": ToolGuidanceEntry(
            tool_name="Apktool",
            category="Android Reverse Engineering",
            description="Tool for reverse engineering Android APK files, extracting resources and Smali code.",
            relevant_options=["d <apk> (Decode)", "b <dir> (Build)"],
            safe_lab_usage="Decode APK to examine raw resources (res/values/strings.xml) and AndroidManifest.xml.",
            result_interpretation="Check network security config (cleartextTrafficPermitted) and debuggable flags.",
            common_mistakes=["Confusing Smali byte representations with decompiled Java source"],
            defensive_implications="Local static analysis tool.",
        ),
        "frida": ToolGuidanceEntry(
            tool_name="Frida",
            category="Dynamic Instrumentation",
            description="Dynamic binary instrumentation toolkit for developers, reverse-engineers, and researchers.",
            relevant_options=["frida -U -f <package> -l <script.js>", "Frida-ps -U", "Memory scanning and hooking"],
            safe_lab_usage="Hook target application functions in local emulator or rooted lab device under research scope.",
            result_interpretation="Inspect function arguments, return values, and SSL pinning bypass validation.",
            common_mistakes=["Attaching to production processes causing stability crashes"],
            defensive_implications="Client-side runtime instrumentation; detectable by anti-tamper and root-detection modules.",
        ),
        "adb": ToolGuidanceEntry(
            tool_name="ADB",
            category="Android Debug Bridge",
            description="Command-line tool that enables communication with an Android device or emulator.",
            relevant_options=["adb devices", "adb shell am start -n <pkg/act>", "adb logcat", "adb pull <path>"],
            safe_lab_usage="Inspect application logs (logcat) for sensitive data leakage; test exported activity invocation in lab.",
            result_interpretation="Verify intent routing and permission enforcement responses.",
            common_mistakes=["Leaving ADB open over network on production hardware"],
            defensive_implications="Development and diagnostic debugging interface.",
        ),
        "volatility": ToolGuidanceEntry(
            tool_name="Volatility",
            category="Digital Forensics",
            description="Advanced memory forensics framework for volatile memory (RAM) dumps.",
            relevant_options=["windows.pslist", "windows.netscan", "linux.bash", "malfind"],
            safe_lab_usage="Analyze forensically acquired memory images (.raw, .vmem) offline.",
            result_interpretation="Identify hidden processes, injected DLLs, unlinked memory segments, and network sockets active at dump time.",
            common_mistakes=["Selecting incompatible OS kernel profile or memory format"],
            defensive_implications="Forensic defensive analysis tool; passive.",
        ),
        "yara": ToolGuidanceEntry(
            tool_name="YARA",
            category="Malware Identification",
            description="Pattern matching tool for identifying and classifying malware based on text/binary rules.",
            relevant_options=["yara -r <rules.yar> <directory>", "-s (Print matching strings)"],
            safe_lab_usage="Scan file samples and memory segments against defensive rule catalogs.",
            result_interpretation="Evaluate rule matches and string offsets to categorize malware families.",
            common_mistakes=["Overly broad regex patterns causing performance slowdowns and false positives"],
            defensive_implications="Core defensive detection engine used in EDR and SIEM solutions.",
        ),
        "sigma": ToolGuidanceEntry(
            tool_name="Sigma",
            category="Detection Engineering",
            description="Generic, open signature format for SIEM detection rules.",
            relevant_options=["sigmac -t splunk <rule.yml>", "sigmac -t elasticsearch <rule.yml>"],
            safe_lab_usage="Convert standardized detection logic into vendor-specific SIEM queries.",
            result_interpretation="Review rule field mappings and false positive descriptions.",
            common_mistakes=["Unoptimized aggregation queries causing high SIEM CPU load"],
            defensive_implications="Detection engineering artifact used to build defensive alerts.",
        ),
        "splunk": ToolGuidanceEntry(
            tool_name="Splunk",
            category="SIEM & Analytics",
            description="Security Information and Event Management (SIEM) data analytics platform.",
            relevant_options=["SPL queries (Search Processing Language)", "index=security sourcetype=access_combined", "stats count by src_ip"],
            safe_lab_usage="Investigate security incidents, correlate authentication failures, and detect anomalies.",
            result_interpretation="Correlate timestamps across diverse log sources (web, firewall, domain controller).",
            common_mistakes=["Searching without index or time boundaries resulting in slow query performance"],
            defensive_implications="Central defensive log analysis platform.",
        ),
        "elastic": ToolGuidanceEntry(
            tool_name="Elastic Stack",
            category="SIEM & Log Analysis",
            description="Elasticsearch, Logstash, Kibana (ELK) log aggregation and security analytics suite.",
            relevant_options=["KQL queries (Kibana Query Language)", "Elastic Security Detection Rules", "Fleet agent management"],
            safe_lab_usage="Query audit logs, monitor endpoint telemetry, and track indicators of compromise (IoCs).",
            result_interpretation="Analyze document hits, timeline visualizations, and alert severities.",
            common_mistakes=["Over-indexing high-volume debug logs leading to storage exhaustion"],
            defensive_implications="Central security logging and observability system.",
        ),
    }

    @classmethod
    def get_tool_guidance(cls, tool_name_or_query: str) -> Optional[ToolGuidanceEntry]:
        """Resolves tool guidance by name or query substring."""
        query = tool_name_or_query.lower()
        for key, entry in cls._CATALOG.items():
            if key in query or entry.tool_name.lower() in query:
                return entry
        return None

    @classmethod
    def get_all_tools(cls) -> List[ToolGuidanceEntry]:
        """Returns all 23 tool entries."""
        return list(cls._CATALOG.values())
