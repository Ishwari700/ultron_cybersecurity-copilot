"""Secret Redaction and Classification Engine for M6.

Guarantees:
1. Identifies and redacts sensitive credentials, tokens, session IDs,
   and private keys before telemetry or context is exposed to LLM reasoning.
2. Preserves evidence store hashes and audit provenance without leaking secrets.
"""

import re
from typing import Any, Dict, List, Tuple

SECRET_PATTERNS = [
    # Authorization bearer / basic tokens
    (re.compile(r"(?i)(bearer\s+)[a-zA-Z0-9_\-\.]{15,}"), r"\1SECRET_REDACTED"),
    (re.compile(r"(?i)(basic\s+)[a-zA-Z0-9+/=]{15,}"), r"\1SECRET_REDACTED"),
    # JWT tokens
    (re.compile(r"eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}"), "JWT_TOKEN_REDACTED"),
    # API keys / generic tokens
    (re.compile(r"(?i)(api[_-]?key|access[_-]?token|secret[_-]?key|auth[_-]?token)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{16,})['\"]?"), r"\1=SECRET_REDACTED"),
    # Private keys
    (re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", re.DOTALL), "PRIVATE_KEY_REDACTED"),
    # Passwords in query params or forms
    (re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?([^&\s'\"]+)['\"]?"), r"\1=SECRET_REDACTED"),
    # Session cookies
    (re.compile(r"(?i)(sessionid|jsessionid|phpsessid|connect\.sid)\s*=\s*([^;\s&]+)"), r"\1=SECRET_REDACTED"),
    # AWS Access Key ID
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS_KEY_REDACTED"),
    # GitHub personal access tokens
    (re.compile(r"\bghp_[a-zA-Z0-9]{20,}\b"), "GH_TOKEN_REDACTED"),
]


class SecretRedactor:
    """Detects and redacts credentials from text, headers, and dictionaries."""

    @staticmethod
    def redact_text(text: str) -> Tuple[str, int]:
        """Redacts sensitive credentials from string. Returns (redacted_str, replacement_count)."""
        if not text:
            return text, 0
        total_redactions = 0
        redacted = text
        for pattern, replacement in SECRET_PATTERNS:
            new_text, count = pattern.subn(replacement, redacted)
            if count > 0:
                total_redactions += count
                redacted = new_text
        return redacted, total_redactions

    @classmethod
    def redact_dict(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively traverses dictionary and redacts string values and sensitive keys."""
        out = {}
        for k, v in data.items():
            k_lower = str(k).lower()
            if any(s in k_lower for s in ("password", "secret", "private_key", "authorization", "api-key", "api_key", "apikey", "token")):
                out[k] = "SECRET_REDACTED"
            elif isinstance(v, str):
                redacted_v, _ = cls.redact_text(v)
                out[k] = redacted_v
            elif isinstance(v, dict):
                out[k] = cls.redact_dict(v)
            elif isinstance(v, list):
                out[k] = [cls.redact_dict(item) if isinstance(item, dict) else (cls.redact_text(str(item))[0] if isinstance(item, str) else item) for item in v]
            else:
                out[k] = v
        return out
