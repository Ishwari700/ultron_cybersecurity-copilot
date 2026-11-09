"""Telemetry Parsers for M6 Passive Evidence Ingestion.

Supports:
- HTTP Archive (HAR)
- Burp Suite / Caido proxy exports
- Raw RFC 7230 HTTP requests / responses
- DNS and TLS certificate records
- Common security tools (nmap, httpx, ffuf, semgrep, nuclei)
- Mobile application artifacts (APK manifests)

Guarantees fault-tolerant parsing: malformed entries are quarantined
and never terminate or crash the entire ingestion batch.
"""

import base64
import json
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse


class HARParser:
    """Parses standard HTTP Archive (HAR) JSON files."""

    @staticmethod
    def parse(raw_data: Any) -> List[Dict[str, Any]]:
        records = []
        if isinstance(raw_data, str):
            if "\x00" in raw_data:
                raw_data = raw_data.replace("\x00", "")
            try:
                raw_data = json.loads(raw_data)
            except Exception as e:
                # Attempt partial recovery from truncated HAR
                match_entries = re.findall(r'"url"\s*:\s*"([^"]+)"', raw_data)
                if match_entries:
                    for idx, u in enumerate(match_entries):
                        try:
                            p = urlparse(u)
                            if p.hostname:
                                records.append({
                                    "source": "HAR_PROXY_EXPORT_RECOVERED",
                                    "target_identifier": p.hostname,
                                    "url": u,
                                    "method": "GET",
                                    "status_code": 200,
                                    "request_headers": {},
                                    "response_headers": {},
                                    "path": p.path or "/",
                                    "entry_index": idx,
                                })
                        except Exception:
                            continue
                    if records:
                        return records
                raise ValueError(f"HAR_JSON_PARSE_ERROR: {e}")

        if not isinstance(raw_data, dict):
            return records

        log_data = raw_data.get("log", {})
        entries = log_data.get("entries", [])
        for idx, entry in enumerate(entries):
            try:
                req = entry.get("request", {})
                resp = entry.get("response", {})
                url = req.get("url", "")
                if not url:
                    continue
                parsed_url = urlparse(url)
                host = parsed_url.hostname or ""
                method = req.get("method", "GET")
                status = resp.get("status", 0)

                headers = {h.get("name", ""): h.get("value", "") for h in req.get("headers", [])}
                resp_headers = {h.get("name", ""): h.get("value", "") for h in resp.get("headers", [])}

                rec = {
                    "source": "HAR_PROXY_EXPORT",
                    "target_identifier": host,
                    "url": url,
                    "method": method,
                    "status_code": status,
                    "request_headers": headers,
                    "response_headers": resp_headers,
                    "path": parsed_url.path or "/",
                    "entry_index": idx,
                }
                records.append(rec)
            except Exception:
                continue
        return records


class BurpCaidoParser:
    """Parses Burp Suite XML/JSON and Caido JSON proxy exports."""

    @staticmethod
    def parse(raw_data: Any) -> List[Dict[str, Any]]:
        records = []
        if isinstance(raw_data, str):
            # Check if JSON
            try:
                data = json.loads(raw_data)
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            records.append(BurpCaidoParser._normalize_caido_item(item))
                    return [r for r in records if r]
                elif isinstance(data, dict):
                    # Burp or Caido root object
                    items = data.get("items", data.get("requests", []))
                    for item in items:
                        rec = BurpCaidoParser._normalize_caido_item(item)
                        if rec:
                            records.append(rec)
                    return records
            except Exception:
                pass

            # Fallback: XML regex parsing for Burp XML
            item_pattern = re.compile(r"<item>(.*?)</item>", re.DOTALL)
            url_pattern = re.compile(r"<url><!\[CDATA\[(.*?)\]\]></url>|<url>(.*?)</url>")
            host_pattern = re.compile(r"<host.*?>(.*?)</host>")
            method_pattern = re.compile(r"<method><!\[CDATA\[(.*?)\]\]></method>|<method>(.*?)</method>")
            status_pattern = re.compile(r"<status>(.*?)</status>")

            for match in item_pattern.finditer(raw_data):
                block = match.group(1)
                u_m = url_pattern.search(block)
                url = (u_m.group(1) or u_m.group(2) or "").strip() if u_m else ""
                h_m = host_pattern.search(block)
                host = h_m.group(1).strip() if h_m else ""
                m_m = method_pattern.search(block)
                method = (m_m.group(1) or m_m.group(2) or "GET").strip() if m_m else "GET"
                s_m = status_pattern.search(block)
                status = int(s_m.group(1).strip()) if s_m and s_m.group(1).isdigit() else 200

                if not host and url:
                    host = urlparse(url).hostname or ""

                if host or url:
                    records.append({
                        "source": "BURP_SUITE_XML",
                        "target_identifier": host,
                        "url": url,
                        "method": method,
                        "status_code": status,
                    })
        return records

    @staticmethod
    def _normalize_caido_item(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        url = item.get("url", item.get("path", ""))
        host = item.get("host", "")
        if not host and url and "://" in url:
            host = urlparse(url).hostname or ""
        if not host:
            return None
        return {
            "source": "CAIDO_EXPORT",
            "target_identifier": host,
            "url": url,
            "method": item.get("method", "GET"),
            "status_code": item.get("statusCode", item.get("status", 200)),
            "headers": item.get("headers", {}),
        }


class RawHTTPParser:
    """Parses raw RFC 7230 plaintext HTTP requests."""

    @staticmethod
    def parse_request(raw_text: str, default_host: str = "") -> Optional[Dict[str, Any]]:
        if not raw_text or not raw_text.strip():
            return None
        if "\x00" in raw_text:
            return None
        lines = [l.strip("\r") for l in raw_text.strip().split("\n")]
        if not lines:
            return None

        # Request line: METHOD PATH HTTP/1.1
        request_line = lines[0].strip().split()
        if len(request_line) < 2:
            return None
        method, path = request_line[0], request_line[1]

        headers = {}
        for line in lines[1:]:
            if not line:
                break
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        host = headers.get("host", default_host).split(":")[0].strip()
        url = f"https://{host}{path}" if host else path

        return {
            "source": "RAW_HTTP_REQUEST",
            "target_identifier": host,
            "method": method.upper(),
            "path": path,
            "url": url,
            "headers": headers,
        }


class DNSTLSParser:
    """Parses DNS query observations and TLS certificate inspection data."""

    @staticmethod
    def parse_dns(raw_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        host = raw_data.get("host", raw_data.get("domain", "")).strip().lower()
        if not host:
            return None
        return {
            "source": "DNS_TELEMETRY",
            "target_identifier": host,
            "query_type": raw_data.get("query_type", "A"),
            "resolved_ips": raw_data.get("ips", []),
            "cnames": raw_data.get("cnames", []),
            "ttl": raw_data.get("ttl", 300),
        }

    @staticmethod
    def parse_tls(raw_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        host = raw_data.get("host", "").strip().lower()
        if not host:
            return None
        return {
            "source": "TLS_INSPECTION",
            "target_identifier": host,
            "subject": raw_data.get("subject", {}),
            "issuer": raw_data.get("issuer", {}),
            "sans": raw_data.get("sans", []),
            "valid_from": raw_data.get("valid_from", ""),
            "valid_until": raw_data.get("valid_until", ""),
            "protocol_version": raw_data.get("protocol_version", "TLSv1.3"),
            "cipher_suite": raw_data.get("cipher_suite", ""),
        }


class SecurityToolParser:
    """Parses structured JSON output from diagnostic tools (nmap, httpx, ffuf, semgrep)."""

    @staticmethod
    def parse(tool_name: str, raw_data: Any) -> List[Dict[str, Any]]:
        records = []
        if isinstance(raw_data, str):
            try:
                raw_data = json.loads(raw_data)
            except Exception:
                # Attempt newline-delimited JSON (e.g. httpx -json)
                lines = [l.strip() for l in raw_data.split("\n") if l.strip()]
                parsed_lines = []
                for line in lines:
                    try:
                        parsed_lines.append(json.loads(line))
                    except Exception:
                        pass
                raw_data = parsed_lines

        if isinstance(raw_data, dict):
            raw_data = [raw_data]

        if not isinstance(raw_data, list):
            return records

        tool_lower = tool_name.lower()
        for item in raw_data:
            if not isinstance(item, dict):
                continue
            if tool_lower == "httpx":
                host = item.get("host", item.get("input", ""))
                url = item.get("url", "")
                records.append({
                    "source": "HTTPX_JSON",
                    "target_identifier": host,
                    "url": url,
                    "status_code": item.get("status_code", 0),
                    "title": item.get("title", ""),
                    "webserver": item.get("webserver", ""),
                    "technologies": item.get("tech", []),
                })
            elif tool_lower == "nmap":
                host = item.get("host", item.get("ip", ""))
                ports = item.get("ports", [])
                records.append({
                    "source": "NMAP_JSON",
                    "target_identifier": host,
                    "ports": ports,
                    "os_match": item.get("os", ""),
                })
            elif tool_lower == "ffuf":
                results = item.get("results", [item])
                for res in results:
                    url = res.get("url", "")
                    host = urlparse(url).hostname or ""
                    records.append({
                        "source": "FFUF_JSON",
                        "target_identifier": host,
                        "url": url,
                        "status": res.get("status", 0),
                        "words": res.get("words", 0),
                        "input": res.get("input", {}),
                    })
            elif tool_lower == "semgrep":
                results = item.get("results", [])
                for res in results:
                    path = res.get("path", "")
                    records.append({
                        "source": "SEMGREP_JSON",
                        "target_identifier": path,
                        "check_id": res.get("check_id", ""),
                        "line": res.get("start", {}).get("line", 1),
                        "message": res.get("extra", {}).get("message", ""),
                    })
            else:
                target = item.get("target", item.get("host", item.get("url", "unknown")))
                records.append({
                    "source": f"{tool_name.upper()}_OUTPUT",
                    "target_identifier": target,
                    "details": item,
                })
        return records


class MobileArtifactParser:
    """Parses Android / iOS mobile application metadata."""

    @staticmethod
    def parse_manifest(manifest_dict: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        pkg = manifest_dict.get("package_name", manifest_dict.get("package", "")).strip()
        if not pkg:
            return None
        return {
            "source": "APK_MANIFEST",
            "target_identifier": pkg,
            "version_name": manifest_dict.get("version_name", ""),
            "exported_components": manifest_dict.get("exported_components", []),
            "permissions": manifest_dict.get("permissions", []),
            "min_sdk": manifest_dict.get("min_sdk", 21),
            "target_sdk": manifest_dict.get("target_sdk", 34),
        }
