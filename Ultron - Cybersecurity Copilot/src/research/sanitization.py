"""Deterministic Query Sanitization and Secret Protection Layer (M4).

Prevents target secrets, credentials, tokens, PII, and sensitive resource IDs
from leaking into external web searches or GitHub queries.

Enforces Section 15 & Architectural Invariant:
    Target-data leakage = 0
"""

import re
from typing import List, Tuple
from pydantic import BaseModel, Field


class SanitizationResult(BaseModel):
    """Result of query sanitization and leak prevention."""
    original_query: str
    sanitized_query: str
    redacted_items_count: int
    redacted_categories: List[str] = Field(default_factory=list)
    is_safe_for_external_transmission: bool = True
    blocking_reason: str = ""


class QuerySanitizer:
    """Deterministic sanitizer for external research queries."""

    # Patterns for sensitive tokens and credentials
    PATTERNS = [
        # Authorization header format
        (
            re.compile(r"Authorization:\s*(?:Bearer|Basic|Token)\s+[^\s\n;,]+", re.IGNORECASE),
            "Authorization: [REDACTED_AUTH_HEADER]",
            "AUTH_HEADER",
        ),
        # Bearer tokens & JWTs
        (
            re.compile(r"(?:Bearer\s+)?eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", re.IGNORECASE),
            "[REDACTED_JWT]",
            "JWT_TOKEN",
        ),
        # API Keys & Secrets (e.g. sk_live_..., key-..., api_key=...)
        (
            re.compile(r"(?:api_?key|secret|token|password|auth_token)\s*[:=]\s*['\"]?[a-zA-Z0-9_\-\.]{8,}['\"]?", re.IGNORECASE),
            "[REDACTED_SECRET]",
            "SECRET_KEY",
        ),
        # Session cookies
        (
            re.compile(r"(?:Cookie:\s*)?(?:session|token|auth|sid|jsessionid)=[a-zA-Z0-9_\-\.]{8,}", re.IGNORECASE),
            "[REDACTED_COOKIE]",
            "SESSION_COOKIE",
        ),
        # Email / PII
        (
            re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"),
            "[REDACTED_EMAIL]",
            "PII_EMAIL",
        ),
        # Generic Basic Auth base64
        (
            re.compile(r"Basic\s+[a-zA-Z0-9+/=]{16,}", re.IGNORECASE),
            "Basic [REDACTED_BASIC_AUTH]",
            "BASIC_AUTH",
        ),
        # Specific target tenant IDs (e.g. tenant-alpha-corp, tenant-101)
        (
            re.compile(r"\btenant-[a-zA-Z0-9_\-]+\b", re.IGNORECASE),
            "{tenant_id}",
            "TENANT_IDENTIFIER",
        ),
        # Specific target user IDs (e.g. user-101, user-999)
        (
            re.compile(r"\buser-\d+\b", re.IGNORECASE),
            "{user_id}",
            "USER_IDENTIFIER",
        ),
        # Numeric path parameters (e.g. /invoices/839291 -> /invoices/{id})
        (
            re.compile(r"/(invoices|users|orders|accounts|workspaces|items)/(\d+)\b", re.IGNORECASE),
            r"/\1/{\1_id}",
            "NUMERIC_OBJECT_ID",
        ),
        # UUID path parameters (e.g. /workspaces/550e8400-e29b-41d4-a716-446655440000 -> /workspaces/{id})
        (
            re.compile(r"/(workspaces|documents|reports|tenants|assets)/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b", re.IGNORECASE),
            r"/\1/{\1_id}",
            "UUID_OBJECT_ID",
        ),
    ]

    @classmethod
    def sanitize(cls, query: str) -> SanitizationResult:
        """
        Sanitizes an outgoing query text by redacting secrets, tokens,
        PII, and specific target resource IDs into generalized placeholders.
        """
        sanitized = query
        redacted_categories: List[str] = []
        count = 0

        for pattern, replacement, category in cls.PATTERNS:
            matches = pattern.findall(sanitized)
            if matches:
                sanitized = pattern.sub(replacement, sanitized)
                redacted_categories.append(category)
                count += len(matches)

        # Check for remaining obvious raw Bearer or JWT signatures
        is_safe = True
        blocking_reason = ""
        if "eyJ" in sanitized and "." in sanitized:
            is_safe = False
            blocking_reason = "Residual unredacted JWT signature detected in query."

        return SanitizationResult(
            original_query=query,
            sanitized_query=sanitized.strip(),
            redacted_items_count=count,
            redacted_categories=redacted_categories,
            is_safe_for_external_transmission=is_safe,
            blocking_reason=blocking_reason,
        )
