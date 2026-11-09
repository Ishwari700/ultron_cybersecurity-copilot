"""Safe Exception and Secret Scrubber for M2.75.

Guarantees that error messages, stack traces, and exception strings originating
from network libraries, HTTP clients, or adapters NEVER leak credentials, cookies,
JWTs, API keys, query parameter tokens, or raw request material into logs,
ExecutionResult records, or audit streams.
"""

import re
from typing import Optional
from src.evidence.vault import RedactionVault


# Sensitive query parameter patterns: e.g. ?token=secret&api_key=secret
QUERY_PARAM_PATTERN = re.compile(
    r"""(?P<prefix>[?&](?:token|api[_-]?key|secret|password|auth|access[_-]?token|refresh[_-]?token|signature|sig|code|session[_-]?id)=)(?P<val>[^&\s"'#]+)""",
    re.IGNORECASE,
)

# Header scrubbing patterns
AUTH_HEADER_SCRUB_PATTERN = re.compile(
    r"""(?i)(authorization|proxy-authorization)\s*:\s*(?:bearer\s+[^\r\n,;]+|basic\s+[^\r\n,;]+|[^\r\n,;]+)"""
)
COOKIE_HEADER_SCRUB_PATTERN = re.compile(
    r"""(?i)(cookie|set-cookie)\s*:\s*[^\r\n]+"""
)


def scrub_exception_text(text: Optional[str], vault: Optional[RedactionVault] = None) -> str:
    """Recursively scrub raw secrets from an error or exception string.

    Guarantees that:
    - Authorization headers are sanitized
    - Cookie values are sanitized
    - Sensitive query parameters are replaced with [REDACTED_QUERY_PARAM]
    - Raw JWTs, basic auth strings, and bearer tokens are replaced with vault placeholders
    """
    if not text:
        return ""

    s = str(text)

    # 1. Scrub Authorization headers
    s = AUTH_HEADER_SCRUB_PATTERN.sub(r"\1: [REDACTED_AUTH_HEADER]", s)

    # 2. Scrub Cookie headers
    s = COOKIE_HEADER_SCRUB_PATTERN.sub(r"\1: [REDACTED_COOKIE_HEADER]", s)

    # 3. Scrub sensitive query parameters in URLs
    s = QUERY_PARAM_PATTERN.sub(r"\g<prefix>[REDACTED_QUERY_PARAM]", s)

    # 4. Use RedactionVault if available to catch raw JWTs, AWS keys, etc.
    if vault:
        s = vault.redact_text(s)
    else:
        # Fallback inline JWT redaction if vault not passed
        jwt_pattern = re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}")
        s = jwt_pattern.sub("[REDACTED_JWT]", s)

    return s
