"""String and Secret Security Analyzer for Android / Native Binaries in M10.

Enforces:
1. Extraction of URLs, domains, cloud endpoints, and suspicious API strings.
2. Secret detection: AWS keys, JWTs, private keys, API credentials, GitHub tokens.
3. Strict redaction via SecretRedactor before exposure to LLM context (INV-M10-10).
4. Epistemic boundary: A suspicious string != confirmed vulnerability (INV-M10-18).
"""

import re
from typing import Any, Dict, List, Optional
from src.assessment.secrets import SecretRedactor


class StringSecretAnalyzer:
    """Analyzes string tables for network endpoints and credentials with redaction."""

    URL_REGEX = re.compile(r"https?://[a-zA-Z0-9.\-_]+(?::\d+)?(?:/[^\s\"'<>]*)?")
    CLOUD_PATTERNS = [
        (re.compile(r"https?://[a-zA-Z0-9.\-_]+\.s3(?:\.[a-zA-Z0-9\-]+)?\.amazonaws\.com[^\s\"']*"), "AWS_S3_BUCKET"),
        (re.compile(r"https?://[a-zA-Z0-9.\-_]+\.firebaseio\.com[^\s\"']*"), "FIREBASE_DATABASE"),
        (re.compile(r"https?://[a-zA-Z0-9.\-_]+\.blob\.core\.windows\.net[^\s\"']*"), "AZURE_BLOB_STORAGE"),
        (re.compile(r"https?://storage\.googleapis\.com/[a-zA-Z0-9.\-_/]+"), "GCP_STORAGE_BUCKET"),
    ]

    @classmethod
    def analyze_strings(cls, strings: List[str]) -> Dict[str, Any]:
        """
        Analyzes a list of strings, detects endpoints and potential credentials,
        and returns redacted intelligence structures.
        """
        endpoints: List[str] = []
        cloud_endpoints: List[Dict[str, str]] = []
        detected_secrets: List[Dict[str, str]] = []
        indicators: List[Dict[str, Any]] = []

        for s in strings:
            if not isinstance(s, str) or not s.strip():
                continue

            # Check URLs
            urls = cls.URL_REGEX.findall(s)
            for u in urls:
                endpoints.append(u)

            # Check Cloud patterns
            for pat, ctype in cls.CLOUD_PATTERNS:
                m = pat.search(s)
                if m:
                    cloud_endpoints.append({"type": ctype, "endpoint": m.group(0)})
                    indicators.append({
                        "type": "STATIC_INDICATOR",
                        "subtype": f"CLOUD_ENDPOINT_{ctype}",
                        "description": f"Found embedded {ctype} reference: {m.group(0)}",
                        "severity": "LOW",
                    })

            # Check for secrets and redact
            redacted_str, count = SecretRedactor.redact_text(s)
            if count > 0:
                detected_secrets.append({
                    "raw_redacted": redacted_str,
                    "redaction_count": count,
                })
                indicators.append({
                    "type": "STATIC_INDICATOR",
                    "subtype": "HARDCODED_CREDENTIAL_INDICATOR",
                    "description": f"Potential embedded credential detected and redacted: {redacted_str}",
                    "severity": "HIGH",
                })

        return {
            "total_strings_scanned": len(strings),
            "endpoints": list(set(endpoints)),
            "cloud_endpoints": cloud_endpoints,
            "detected_secrets": detected_secrets,
            "indicators": indicators,
        }
