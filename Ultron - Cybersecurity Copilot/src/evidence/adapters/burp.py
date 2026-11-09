"""Burp Suite observation adapter for proxy history and scanner exports."""

import base64
import binascii
from typing import Any, Dict, List, Optional
from src.evidence.adapters.generic_http import GenericHttpAdapter
from src.evidence.models import CanonicalEvidence


class BurpAdapter(GenericHttpAdapter):
    """Parses Burp Suite proxy JSON / HAR exports into CanonicalEvidence."""

    def ingest(self, raw_data: Any, scope_decision_id: Optional[str] = None) -> List[CanonicalEvidence]:
        """
        Accepts Burp JSON items list or dictionary with 'items':
        [
            {
                "host": "api.target.com",
                "method": "POST",
                "path": "/api/v1/auth",
                "url": "https://api.target.com/api/v1/auth",
                "status": 200,
                "request": "...", # string or base64
                "response": "...", # string or base64
                "headers": {"User-Agent": "Mozilla..."}
            }
        ]
        """
        raw_items = raw_data.get("items", []) if isinstance(raw_data, dict) else raw_data
        if not isinstance(raw_items, list):
            raw_items = [raw_items]

        standardized = []
        for item in raw_items:
            method = item.get("method", "GET")
            url = item.get("url") or f"https://{item.get('host', 'unknown')}{item.get('path', '/')}"
            status = int(item.get("status", 200))

            req_content = item.get("request", "")
            resp_content = item.get("response", "")

            # Attempt base64 decode if indicated
            if item.get("request_base64"):
                try:
                    req_content = base64.b64decode(req_content).decode("utf-8", errors="replace")
                except (binascii.Error, ValueError):
                    pass
            if item.get("response_base64"):
                try:
                    resp_content = base64.b64decode(resp_content).decode("utf-8", errors="replace")
                except (binascii.Error, ValueError):
                    pass

            standardized.append({
                "method": method,
                "url": url,
                "request_headers": item.get("headers", {}),
                "request_body": req_content,
                "response_status": status,
                "response_headers": item.get("response_headers", {}),
                "response_body": resp_content,
                "source_tool": "burp",
                "source_version": "2024.x",
            })

        return super().ingest(standardized, scope_decision_id=scope_decision_id)
