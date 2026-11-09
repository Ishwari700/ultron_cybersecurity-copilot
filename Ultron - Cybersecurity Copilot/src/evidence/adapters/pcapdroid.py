"""PCAPdroid observation adapter for mobile flow captures."""

from typing import Any, Dict, List, Optional
from src.evidence.adapters.generic_http import GenericHttpAdapter
from src.evidence.models import CanonicalEvidence


class PCAPdroidAdapter(GenericHttpAdapter):
    """Parses PCAPdroid mobile network flow captures into CanonicalEvidence."""

    def ingest(self, raw_data: Any, scope_decision_id: Optional[str] = None) -> List[CanonicalEvidence]:
        """
        Accepts PCAPdroid flow export JSON (list or dict with 'flows').
        """
        flows = raw_data.get("flows", []) if isinstance(raw_data, dict) else raw_data
        if not isinstance(flows, list):
            flows = [flows]

        standardized = []
        for flow in flows:
            # PCAPdroid HTTP flow format
            host = flow.get("host") or flow.get("dst_ip", "unknown")
            path = flow.get("path") or flow.get("uri", "/")
            method = flow.get("method", "GET")
            url = flow.get("url") or f"https://{host}{path}"

            standardized.append({
                "method": method,
                "url": url,
                "request_headers": flow.get("request_headers", {}),
                "request_body": flow.get("payload_hex", ""),
                "response_status": flow.get("status_code", 200),
                "response_headers": flow.get("response_headers", {}),
                "response_body": flow.get("response_payload", ""),
                "source_tool": "pcapdroid",
                "source_version": "1.7+",
            })

        return super().ingest(standardized, scope_decision_id=scope_decision_id)
