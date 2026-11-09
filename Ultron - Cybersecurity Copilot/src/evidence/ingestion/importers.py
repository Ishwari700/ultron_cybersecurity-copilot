"""Modular evidence importers for HAR, Raw HTTP text, and Burp Suite captures."""

from abc import ABC, abstractmethod
import base64
import json
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from src.evidence.ingestion.models import RawTransactionRecord
from src.scope.gate import canonicalize_host


class EvidenceImporter(ABC):
    """Abstract adapter interface converting tool-specific captures into RawTransactionRecords."""

    @abstractmethod
    def parse(self, raw_content: str, source_artifact: str = "") -> Tuple[List[RawTransactionRecord], List[str]]:
        """
        Parse raw content string into a list of normalized RawTransactionRecord items.
        Returns: (records, errors)
        """
        pass


class HarImporter(EvidenceImporter):
    """Parses HTTP Archive (.har) format exports."""

    def parse(self, raw_content: str, source_artifact: str = "") -> Tuple[List[RawTransactionRecord], List[str]]:
        errors: List[str] = []
        records: List[RawTransactionRecord] = []

        if not raw_content or not raw_content.strip():
            return [], ["Empty HAR content"]

        try:
            data = json.loads(raw_content)
        except Exception as e:
            return [], [f"Failed to parse HAR JSON: {e}"]

        entries = []
        if isinstance(data, dict):
            entries = data.get("log", {}).get("entries", [])
            if not entries and "entries" in data:
                entries = data["entries"]
        elif isinstance(data, list):
            entries = data

        if not entries:
            return [], ["No HTTP entries found in HAR data"]

        for idx, entry in enumerate(entries):
            try:
                req = entry.get("request", {})
                resp = entry.get("response", {})

                method = (req.get("method") or "GET").upper().strip()
                url = (req.get("url") or "").strip()
                if not url:
                    errors.append(f"Entry {idx + 1}: Missing URL")
                    continue

                parsed = urlparse(url if "://" in url else f"https://{url}")
                path = parsed.path or "/"
                if parsed.query:
                    path = f"{path}?{parsed.query}"

                # Request headers
                req_headers: Dict[str, str] = {}
                for h in req.get("headers", []):
                    if isinstance(h, dict) and "name" in h and "value" in h:
                        req_headers[h["name"]] = str(h["value"])

                raw_h = None
                for k, v in req_headers.items():
                    if k.strip().lower() == "host":
                        raw_h = v.strip()
                        break

                host = canonicalize_host(raw_h) or canonicalize_host(url) or ""
                if "Host" not in req_headers and host:
                    req_headers["Host"] = host

                # Request body
                req_body = ""
                post_data = req.get("postData")
                if isinstance(post_data, dict):
                    req_body = post_data.get("text", "") or ""

                # Response status
                status = 200
                if "status" in resp:
                    try:
                        status = int(resp["status"])
                    except (ValueError, TypeError):
                        status = 200

                # Response headers
                resp_headers: Dict[str, str] = {}
                for h in resp.get("headers", []):
                    if isinstance(h, dict) and "name" in h and "value" in h:
                        resp_headers[h["name"]] = str(h["value"])

                # Response body
                resp_body = ""
                content = resp.get("content")
                if isinstance(content, dict):
                    resp_body = content.get("text", "") or ""

                started_time = entry.get("startedDateTime")

                records.append(
                    RawTransactionRecord(
                        method=method,
                        url=url,
                        host=host,
                        path=path,
                        request_headers=req_headers,
                        request_body=req_body,
                        response_status=status,
                        response_headers=resp_headers,
                        response_body=resp_body,
                        timestamp=started_time,
                        source_tool="har_importer",
                        source_artifact=source_artifact,
                    )
                )
            except Exception as e:
                errors.append(f"Entry {idx + 1} processing error: {e}")

        return records, errors


class RawHttpImporter(EvidenceImporter):
    """
    Parses raw HTTP request/response text into RawTransactionRecords.
    Supports single transactions or multiple transactions separated by delimiter lines (e.g. '---' or '===').
    """

    METHOD_PATTERN = re.compile(r"^(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+(\S+)(?:\s+HTTP/\S+)?", re.IGNORECASE)
    STATUS_PATTERN = re.compile(r"^HTTP/\S+\s+(\d{3})(?:\s+.*)?", re.IGNORECASE)

    def parse(self, raw_content: str, source_artifact: str = "") -> Tuple[List[RawTransactionRecord], List[str]]:
        errors: List[str] = []
        records: List[RawTransactionRecord] = []

        if not raw_content or not raw_content.strip():
            return [], ["Empty HTTP content"]

        # Split multiple transactions by delimiter if present
        delimiter_pattern = re.compile(r"^(?:={3,}|-{3,}|#{3,})\s*$", re.MULTILINE)
        raw_blocks = delimiter_pattern.split(raw_content)
        cleaned_blocks = [b.strip() for b in raw_blocks if b.strip()]

        # If no explicit delimiters, check if multiple requests are stacked together
        if len(cleaned_blocks) <= 1 and raw_content.count("HTTP/") > 2:
            # Attempt to split on subsequent Request lines
            subsequent_req = re.compile(r"\n(?=(?:GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+\S+\s+HTTP/)", re.IGNORECASE)
            sub_blocks = subsequent_req.split(raw_content)
            if len(sub_blocks) > 1:
                cleaned_blocks = [b.strip() for b in sub_blocks if b.strip()]

        for idx, block in enumerate(cleaned_blocks):
            record, err = self._parse_single_block(block, idx + 1, source_artifact)
            if err:
                errors.append(err)
            if record:
                records.append(record)

        return records, errors

    def _parse_single_block(
        self, block: str, block_idx: int, source_artifact: str
    ) -> Tuple[Optional[RawTransactionRecord], Optional[str]]:
        """Parse a single raw HTTP request/response block."""
        lines = block.splitlines()
        if not lines:
            return None, f"Block {block_idx}: Empty block"

        # If block contains only comment lines (e.g. leading '#' or '//'), skip cleanly without error
        non_comment_lines = [l for l in lines if l.strip() and not l.strip().startswith(("#", "//"))]
        if not non_comment_lines:
            return None, None

        # Locate Request line
        req_line_idx = -1
        for i, line in enumerate(lines):
            if self.METHOD_PATTERN.match(line.strip()):
                req_line_idx = i
                break

        if req_line_idx == -1:
            return None, f"Block {block_idx}: Could not find valid HTTP request line (GET, POST, etc.)"

        method_match = self.METHOD_PATTERN.match(lines[req_line_idx].strip())
        if not method_match:
            return None, f"Block {block_idx}: Invalid request line"

        method = method_match.group(1).upper()
        raw_path_or_url = method_match.group(2).strip()

        # Separate request and response sections
        # Look for HTTP/1.x 200 OK status line
        resp_line_idx = -1
        for i in range(req_line_idx + 1, len(lines)):
            if self.STATUS_PATTERN.match(lines[i].strip()):
                resp_line_idx = i
                break

        if resp_line_idx != -1:
            req_lines = lines[req_line_idx + 1 : resp_line_idx]
            resp_lines = lines[resp_line_idx:]
        else:
            req_lines = lines[req_line_idx + 1 :]
            resp_lines = []

        # Parse request headers and body
        req_headers, req_body = self._parse_headers_and_body(req_lines)

        # Determine canonical host and URL
        raw_host = None
        for h_name, h_val in req_headers.items():
            if h_name.strip().lower() == "host":
                raw_host = h_val.strip()
                break

        host_from_header = canonicalize_host(raw_host) if raw_host else None
        host_from_url = canonicalize_host(raw_path_or_url) if "://" in raw_path_or_url else None
        tx_host = host_from_header or host_from_url or ""

        if "://" in raw_path_or_url:
            parsed = urlparse(raw_path_or_url)
            path = parsed.path or "/"
            if parsed.query:
                path = f"{path}?{parsed.query}"
            full_url = raw_path_or_url
        else:
            path = raw_path_or_url
            if not path.startswith("/"):
                path = "/" + path
            full_url = f"https://{tx_host}{path}" if tx_host else path

        # Parse response if present
        resp_status = 200
        resp_headers: Dict[str, str] = {}
        resp_body = ""

        if resp_lines:
            status_match = self.STATUS_PATTERN.match(resp_lines[0].strip())
            if status_match:
                try:
                    resp_status = int(status_match.group(1))
                except ValueError:
                    resp_status = 200
            resp_headers, resp_body = self._parse_headers_and_body(resp_lines[1:])

        record = RawTransactionRecord(
            method=method,
            url=full_url,
            host=tx_host,
            path=path,
            request_headers=req_headers,
            request_body=req_body,
            response_status=resp_status,
            response_headers=resp_headers,
            response_body=resp_body,
            source_tool="raw_http_importer",
            source_artifact=source_artifact,
        )
        return record, None

    def _parse_headers_and_body(self, lines: List[str]) -> Tuple[Dict[str, str], str]:
        """Split a list of HTTP lines into headers dictionary and body string."""
        headers: Dict[str, str] = {}
        body_lines: List[str] = []
        in_body = False

        for line in lines:
            if in_body:
                body_lines.append(line)
            else:
                if not line.strip():
                    in_body = True
                    continue
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip()] = v.strip()
                else:
                    # Trailing line or non-header line transitions to body
                    in_body = True
                    body_lines.append(line)

        return headers, "\n".join(body_lines).strip()


class BurpImporter(EvidenceImporter):
    """Adapter preparing for Burp Suite XML/JSON proxy export items."""

    def parse(self, raw_content: str, source_artifact: str = "") -> Tuple[List[RawTransactionRecord], List[str]]:
        errors: List[str] = []
        records: List[RawTransactionRecord] = []

        if not raw_content or not raw_content.strip():
            return [], ["Empty Burp export content"]

        # 1. Try parsing as JSON first
        try:
            data = json.loads(raw_content)
            items = data.get("items", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
            for idx, item in enumerate(items):
                try:
                    method = (item.get("method") or "GET").upper()
                    url = item.get("url") or f"https://{item.get('host', 'unknown')}{item.get('path', '/')}"
                    parsed = urlparse(url)
                    host = parsed.hostname or item.get("host") or ""
                    path = parsed.path or item.get("path") or "/"
                    if parsed.query:
                        path = f"{path}?{parsed.query}"
                    status = int(item.get("status", 200))

                    req_data = item.get("request", "")
                    if item.get("request_base64"):
                        try:
                            req_data = base64.b64decode(req_data).decode("utf-8", errors="replace")
                        except Exception:
                            pass

                    resp_data = item.get("response", "")
                    if item.get("response_base64"):
                        try:
                            resp_data = base64.b64decode(resp_data).decode("utf-8", errors="replace")
                        except Exception:
                            pass

                    records.append(
                        RawTransactionRecord(
                            method=method,
                            url=url,
                            host=host,
                            path=path,
                            request_headers=item.get("headers", {}),
                            request_body=str(req_data),
                            response_status=status,
                            response_headers=item.get("response_headers", {}),
                            response_body=str(resp_data),
                            source_tool="burp_importer",
                            source_artifact=source_artifact,
                        )
                    )
                except Exception as e:
                    errors.append(f"Burp JSON item {idx + 1} error: {e}")
            return records, errors
        except Exception:
            pass

        # 2. If not JSON, try parsing via RawHttpImporter if it's raw request/response text
        raw_http = RawHttpImporter()
        return raw_http.parse(raw_content, source_artifact=source_artifact)
