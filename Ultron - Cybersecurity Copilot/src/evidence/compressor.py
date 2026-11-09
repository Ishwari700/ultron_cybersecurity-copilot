"""Semantic compressor summarizing large HTTP payloads without losing schema or ID context."""

import json
import re
from typing import Any, Dict, List, Optional


class SemanticCompressor:
    """
    Compresses large HTTP request and response bodies (e.g., 2MB GraphQL responses)
    by extracting keys, schemas, and high-entropy identifiers (UUIDs) while discarding
    repetitive array elements.
    """

    UUID_REGEX = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)

    def __init__(self, max_summary_chars: int = 1200) -> None:
        self.max_summary_chars = max_summary_chars

    def compress(self, raw_body: str, content_type: Optional[str] = None) -> str:
        """Compress raw text or JSON body into a semantic structural summary."""
        if not raw_body or not raw_body.strip():
            return ""

        body_str = raw_body.strip()
        # Attempt JSON compression
        if (content_type and "json" in content_type.lower()) or (body_str.startswith("{") or body_str.startswith("[")):
            try:
                parsed = json.loads(body_str)
                compressed = self._compress_json(parsed)
                summary = json.dumps(compressed, indent=2)
                if len(summary) > self.max_summary_chars:
                    return summary[:self.max_summary_chars] + "... [truncated schema]"
                return summary
            except (json.JSONDecodeError, ValueError, TypeError):
                pass

        # Text / HTML summary
        if len(body_str) > self.max_summary_chars:
            head = body_str[: self.max_summary_chars // 2]
            tail = body_str[-self.max_summary_chars // 4 :]
            return f"{head}\n... [TRUNCATED {len(body_str) - len(head) - len(tail)} CHARS] ...\n{tail}"
        return body_str

    def _compress_json(self, data: Any, depth: int = 0) -> Any:
        """Recursively extract schema and high-entropy identifiers while sampling lists."""
        if depth > 4:
            return "..."

        if isinstance(data, dict):
            summary: Dict[str, Any] = {}
            for key, val in data.items():
                if isinstance(val, (dict, list)):
                    summary[key] = self._compress_json(val, depth + 1)
                elif isinstance(val, str) and self.UUID_REGEX.match(val):
                    summary[key] = f"<UUID: {val}>"
                elif isinstance(val, (int, float, bool)) or val is None:
                    summary[key] = val
                else:
                    # String: preserve type and length hint if long
                    s_val = str(val)
                    if len(s_val) > 40:
                        summary[key] = f"<str len={len(s_val)}: {s_val[:20]}...>"
                    else:
                        summary[key] = s_val
            return summary

        elif isinstance(data, list):
            if not data:
                return []
            count = len(data)
            sample = self._compress_json(data[0], depth + 1)
            if count == 1:
                return [sample]
            return {"_list_count": count, "_sample_item": sample}

        return data
