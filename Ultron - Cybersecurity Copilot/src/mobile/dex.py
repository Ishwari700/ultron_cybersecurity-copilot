"""DEX Bytecode Analyzer for M7 Mobile Evidence Pipelines.

Parses class tables, method signatures, embedded URLs, and dangerous API calls.
"""

import re
from typing import Any, Dict, List


class DexAnalyzer:
    """Extracts security intelligence from DEX class summaries and string pools."""

    @staticmethod
    def analyze_dex_metadata(dex_data: Dict[str, Any]) -> Dict[str, Any]:
        classes = dex_data.get("classes", [])
        strings = dex_data.get("strings", [])

        embedded_urls = []
        suspicious_apis = []

        url_regex = re.compile(r"https?://[a-zA-Z0-9.\-_]+(?::\d+)?(?:/[^\s]*)?")
        for s in strings:
            if isinstance(s, str):
                matches = url_regex.findall(s)
                embedded_urls.extend(matches)

                # Check for suspicious API invocations
                if any(api in s for api in ("Cipher.getInstance", "Runtime.getRuntime().exec", "DexClassLoader", "WebView.loadUrl")):
                    suspicious_apis.append(s)

        return {
            "layer": "DEX",
            "class_count": len(classes),
            "embedded_urls": list(set(embedded_urls)),
            "suspicious_apis": list(set(suspicious_apis)),
        }
