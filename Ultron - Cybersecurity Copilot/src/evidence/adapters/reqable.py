"""Reqable observation adapter for exported HAR / JSON traffic captures."""

from typing import Any, Dict, List, Optional
from src.evidence.adapters.generic_http import GenericHttpAdapter
from src.evidence.models import CanonicalEvidence


class ReqableAdapter(GenericHttpAdapter):
    """Parses Reqable HAR (HTTP Archive) files into CanonicalEvidence."""

    def ingest(self, raw_data: Any, scope_decision_id: Optional[str] = None) -> List[CanonicalEvidence]:
        """
        Accepts standard HAR dict or list of entries.
        """
        entries = []
        if isinstance(raw_data, dict) and "log" in raw_data:
            entries = raw_data["log"].get("entries", [])
        elif isinstance(raw_data, list):
            entries = raw_data
        elif isinstance(raw_data, dict) and "entries" in raw_data:
            entries = raw_data["entries"]

        standardized = []
        for entry in entries:
            req = entry.get("request", {})
            resp = entry.get("response", {})

            # Convert headers list [{'name': '...', 'value': '...'}] to dict
            req_headers = {}
            for h in req.get("headers", []):
                req_headers[h.get("name", "")] = h.get("value", "")

            resp_headers = {}
            for h in resp.get("headers", []):
                resp_headers[h.get("name", "")] = h.get("value", "")

            post_data = req.get("postData", {}).get("text", "")
            resp_data = resp.get("content", {}).get("text", "")

            standardized.append({
                "method": req.get("method", "GET"),
                "url": req.get("url", ""),
                "request_headers": req_headers,
                "request_body": post_data,
                "response_status": resp.get("status", 200),
                "response_headers": resp_headers,
                "response_body": resp_data,
                "source_tool": "reqable",
                "source_version": "2.x",
            })

        return super().ingest(standardized, scope_decision_id=scope_decision_id)
