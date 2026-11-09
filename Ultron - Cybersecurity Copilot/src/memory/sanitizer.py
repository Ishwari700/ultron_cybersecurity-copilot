"""Sanitizer, Redaction, and Poisoning Defense Engine for Memory Subsystem.

Ensures:
1. No API keys, passwords, bearer tokens, or private keys are persisted in memory.
2. If text cannot be safely sanitized, admission is strictly rejected.
3. Target-specific identifiers (internal IPs, customer IDs, private URLs) are stripped during promotion.
4. Prompt injection attempts are detected and defanged; memory content remains untrusted DATA.
"""

import re
from typing import List, Tuple
from src.assessment.secrets import SecretRedactor
from src.evidence.vault import RedactionVault
from src.memory.errors import (
    MemoryPoisoningAttemptError,
    SecretPersistenceForbiddenError,
)

# Active prompt injection patterns attempting to manipulate AI authority
POISONING_PATTERNS = [
    re.compile(r"(?i)ignore\s+(?:all\s+)?previous\s+(?:instructions|system\s+rules|rules)"),
    re.compile(r"(?i)disregard\s+(?:system\s+)?(?:rules|policies|instructions|scope)"),
    re.compile(r"(?i)system\s*(?:directive|prompt)?\s*:\s*(?:you\s+are\s+now|execute|run|authorize|grant)"),
    re.compile(r"(?i)<\s*script\b"),
    re.compile(r"(?i)<\s*system\s*>.*<\s*/\s*system\s*>", re.DOTALL),
    re.compile(r"(?i)(?:treat|mark)?\s*(?:this\s+)?(?:target|url|endpoint)\s+as\s+authorized"),
    re.compile(r"(?i)authorize\s+target"),
    re.compile(r"(?i)bypass\s+(?:scope\s*gate|scopegate|scope|authorizationvalidator|findingvalidator)"),
    re.compile(r"(?i)grant\s+autonomous\s+execution\s+authority"),
    re.compile(r"(?i)mark\s+(?:this\s+)?(?:finding|vulnerability)\s+as\s+verified\s+without\s+evidence"),
    re.compile(r"(?i)execute\s+(?:rm|del|format)\b"),
]

# Unredactable raw credential patterns that force hard admission rejection
CRITICAL_UNREDACTABLE_PATTERNS = [
    re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bghp_[a-zA-Z0-9]{20,}\b"),
]

# Patterns for target-specific infrastructure to scrub during abstraction
TARGET_SPECIFIC_PATTERNS = [
    (re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"), "[INTERNAL_IP]"),
    (re.compile(r"https?://(?:[a-zA-Z0-9-]+\.)+(?:internal|corp|local|lan)(?::\d+)?\b"), "[INTERNAL_URL]"),
    (re.compile(r"(?i)\buser_[a-zA-Z0-9]{8,}\b"), "[CUSTOMER_USER_ID]"),
    (re.compile(r"(?i)\bacct_[a-zA-Z0-9]{8,}\b"), "[CUSTOMER_ACCT_ID]"),
]


class MemorySanitizer:
    """
    Sanitizes candidate memory items and guards against secret leakage and prompt poisoning.
    """

    def __init__(self) -> None:
        self.secret_redactor = SecretRedactor()
        self.vault = RedactionVault()

    def sanitize_content(self, content: str, reject_on_critical: bool = True) -> Tuple[str, int]:
        """
        Redacts credentials, tokens, and secrets from candidate memory text.
        If reject_on_critical is True and an unredactable raw key is found,
        raises SecretPersistenceForbiddenError.
        """
        if not content:
            return "", 0

        # Check for hard unredactable credentials
        if reject_on_critical:
            for pattern in CRITICAL_UNREDACTABLE_PATTERNS:
                if pattern.search(content):
                    raise SecretPersistenceForbiddenError(
                        f"Candidate memory contains critical credential matching {pattern.pattern} which cannot be persisted"
                    )

        # Apply SecretRedactor and RedactionVault
        redacted_text, count = self.secret_redactor.redact_text(content)
        vault_redacted = self.vault.redact_text(redacted_text)
        if vault_redacted != redacted_text:
            count += 1

        return vault_redacted, count

    def check_poisoning_defense(self, content: str, strict: bool = True) -> bool:
        """
        Detects adversarial prompt injection or policy overrides in memory text.
        If strict is True, raises MemoryPoisoningAttemptError.
        """
        for pattern in POISONING_PATTERNS:
            if pattern.search(content):
                if strict:
                    raise MemoryPoisoningAttemptError(
                        f"Candidate memory rejected due to adversarial injection pattern: {pattern.pattern}"
                    )
                return False
        return True

    def abstract_pattern(self, content: str) -> str:
        """
        Scrubs concrete target details (internal IPs, tenant IDs, hostnames)
        producing an abstracted, safe cybersecurity research pattern.
        """
        sanitized, _ = self.sanitize_content(content, reject_on_critical=False)
        abstracted = sanitized
        for pattern, replacement in TARGET_SPECIFIC_PATTERNS:
            abstracted = pattern.sub(replacement, abstracted)
        return abstracted
