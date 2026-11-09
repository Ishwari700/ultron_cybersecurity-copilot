"""Knowledge Poisoning Defense, Quarantine Policy, and Safe Telemetry Enclosure.

Implements M3.12 / M5 hardened poisoning defense:
1. Strict telemetry sanitization:
   - Strip ANSI control sequences
   - Escape newlines and carriage returns to prevent log injection
   - Strip non-printable control characters
   - Bound fragment lengths (max 64 characters)
   - Redact secret-like patterns from telemetry
2. Quarantine policy:
   - Differentiates legitimate cybersecurity discussions (PRESERVED_NON_DESTRUCTIVE) from
     severe adversarial prompt injections / system overrides (QUARANTINED).
   - Quarantined chunks are excluded from trusted knowledge packs delivered to the LLM.
   - Quarantined items are held in an isolated forensic retention store.
3. Safe enclosure escaping (&, <, >) preventing XML delimiter breakout.
4. Non-overridable execution boundaries (M2.75 execution engine retains exclusive authority).
"""

from enum import Enum
import html
import logging
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

from src.knowledge.models import (
    CorpusManifest,
    KnowledgeChunk,
    KnowledgeRetrievalItem,
    TrustRootRecord,
    VaptKnowledgePack,
)
from src.knowledge.provenance import (
    CryptographicTrustAuthority,
    ProvenanceVerificationError,
)

logger = logging.getLogger("m3.poisoning_defense")


class ChunkSecurityStatus(str, Enum):
    CLEAN = "CLEAN"
    AUDITED_FLAGGED = "AUDITED_FLAGGED"
    QUARANTINED = "QUARANTINED"


# Patterns indicating severe hostile injection directives that warrant quarantine
SEVERE_INJECTION_PATTERNS = [
    re.compile(r"(ignore|disregard)\s+(all\s+)?(previous|prior)\s+instructions?", re.IGNORECASE),
    re.compile(r"disregard\s+(the\s+)?(system|prompt|above)", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(in\s+)?(DAN|developer\s+mode|unrestricted)", re.IGNORECASE),
    re.compile(r"system\s+(prompt|override)\s*:\s*", re.IGNORECASE),
    re.compile(r"admin\s+override\s*:\s*", re.IGNORECASE),
    re.compile(r"execute\s+(tool\s+)?command\s*:\s*", re.IGNORECASE),
    re.compile(r"<\s*script[^>]*>", re.IGNORECASE),
    re.compile(r"javascript\s*:\s*", re.IGNORECASE),
]

# Patterns indicating general security markers (audited and preserved if not hostile directives)
INFORMATIONAL_MARKER_PATTERNS = [
    re.compile(r"</?vapt_methodology_advisory>", re.IGNORECASE),
    re.compile(r"</?advisory_chunk>", re.IGNORECASE),
    re.compile(r"</?untrusted_target_data>", re.IGNORECASE),
    re.compile(r"curl\s+https?://", re.IGNORECASE),
    re.compile(r"rm\s+-rf", re.IGNORECASE),
]

# Sanitization regexes for log telemetry
ANSI_ESCAPE_PATTERN = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
SECRET_LIKE_PATTERN = re.compile(
    r"(?:bearer\s+[a-zA-Z0-9_\-\.]{16,}|akia[0-9a-z]{16}|eyjh[a-za-z0-9_\-\.]{20,})",
    re.IGNORECASE,
)


def sanitize_telemetry_fragment(raw_text: str, max_length: int = 64) -> str:
    """
    Sanitize captured hostile or suspicious text fragments before logging:
    - Strips ANSI escape sequences
    - Replaces newlines and carriage returns to block log injection attacks
    - Strips unprintable control characters
    - Redacts secret-like tokens
    - Enforces maximum character length
    """
    if not raw_text:
        return ""

    # 1. Strip ANSI escape codes
    cleaned = ANSI_ESCAPE_PATTERN.sub("", raw_text)

    # 2. Redact secret-like strings
    cleaned = SECRET_LIKE_PATTERN.sub("[REDACTED_TELEMETRY_SECRET]", cleaned)

    # 3. Escape newlines and control characters to prevent log injection
    cleaned = cleaned.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    cleaned = "".join(c for c in cleaned if c.isprintable() or c in (" ", "\\"))

    # 4. Truncate to maximum length
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length] + "...[TRUNCATED]"

    return cleaned


class KnowledgePoisoningDefense:
    """
    Guards the reasoning pipeline against adversarial corpus manipulation,
    log injection attacks, and prompt injection attempts.
    """

    # In-memory isolated forensic quarantine store
    _isolated_forensic_store: Dict[str, Dict[str, Any]] = {}

    @staticmethod
    def escape_advisory_text(text: str) -> str:
        """
        Non-destructively escape XML/HTML special characters (&, <, >)
        to prevent XML tag breakout while preserving text content verbatim.
        """
        if not text:
            return ""
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )

    @classmethod
    def scan_for_injection_markers(
        cls,
        text: str,
        chunk_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Inspect chunk text for injection and directive patterns.
        Strictly sanitizes telemetry snippets before emitting to logger.
        Returns list of detection records.
        """
        detections: List[Dict[str, Any]] = []

        # 1. Check severe injection patterns (Quarantine triggers)
        for pattern in SEVERE_INJECTION_PATTERNS:
            for m in pattern.finditer(text):
                sanitized_fragment = sanitize_telemetry_fragment(m.group(0))
                event = {
                    "event_type": "POISONING_MARKER_DETECTED",
                    "chunk_id": chunk_id,
                    "severity": "QUARANTINE",
                    "matched_pattern": pattern.pattern,
                    "matched_text": m.group(0),
                    "sanitized_snippet": sanitized_fragment,
                    "start_offset": m.start(),
                    "end_offset": m.end(),
                    "action": "PRESERVED_NON_DESTRUCTIVE",
                }
                detections.append(event)
                # Log strictly sanitized single-line snippet
                logger.warning(
                    f"Advisory text marker quarantined: pattern='{pattern.pattern}' snippet='{sanitized_fragment}'"
                )

        # 2. Check informational / audited patterns
        for pattern in INFORMATIONAL_MARKER_PATTERNS:
            for m in pattern.finditer(text):
                sanitized_fragment = sanitize_telemetry_fragment(m.group(0))
                event = {
                    "event_type": "POISONING_MARKER_DETECTED",
                    "chunk_id": chunk_id,
                    "severity": "INFORMATIONAL",
                    "matched_pattern": pattern.pattern,
                    "matched_text": m.group(0),
                    "sanitized_snippet": sanitized_fragment,
                    "start_offset": m.start(),
                    "end_offset": m.end(),
                    "action": "PRESERVED_NON_DESTRUCTIVE",
                }
                detections.append(event)
                # Log strictly sanitized single-line snippet
                logger.info(
                    f"Advisory text marker logged: pattern='{pattern.pattern}' snippet='{sanitized_fragment}'"
                )

        return detections

    @classmethod
    def sanitize_pack_for_serialization(
        cls,
        pack: VaptKnowledgePack,
        quarantine_poisoned: bool = True,
    ) -> VaptKnowledgePack:
        """
        Apply safe escaping and quarantine filtering to all chunks in a pack.
        Quarantined chunks are excluded from the LLM prompt payload and isolated.
        """
        sanitized_items = []

        for item in pack.items:
            chunk = item.chunk
            detections = cls.scan_for_injection_markers(
                chunk.content, chunk_id=chunk.chunk_id
            )

            is_quarantined = any(
                d.get("severity") == "QUARANTINE" or d.get("action") == "QUARANTINED_FROM_CONTEXT"
                for d in detections
            )

            # If severe injection detected, quarantine the chunk
            if is_quarantined and quarantine_poisoned:
                # Store in isolated forensic retention store
                cls._isolated_forensic_store[chunk.chunk_id] = {
                    "chunk": chunk.model_dump(),
                    "detections": detections,
                }
                logger.warning(
                    f"Chunk '{chunk.chunk_id}' quarantined and excluded from active knowledge pack."
                )
                continue  # Exclude quarantined chunk from active pack

            # Non-quarantined chunks: escape XML delimiters safely
            escaped_content = cls.escape_advisory_text(chunk.content)
            chunk_copy = chunk.model_copy(update={"content": escaped_content})
            item_copy = item.model_copy(update={"chunk": chunk_copy})
            sanitized_items.append(item_copy)

        return pack.model_copy(update={"items": sanitized_items})

    @classmethod
    def verify_corpus_integrity(
        cls,
        manifest: CorpusManifest,
        signature_bytes: bytes,
        trust_root: TrustRootRecord,
        chunks: Sequence[KnowledgeChunk],
    ) -> Tuple[bool, Optional[str]]:
        """
        Verify cryptographic integrity of advisory corpus.
        """
        try:
            CryptographicTrustAuthority.verify_corpus_integrity(
                manifest=manifest,
                signature_bytes=signature_bytes,
                trust_root=trust_root,
                chunks=chunks,
            )
            return True, None
        except ProvenanceVerificationError as e:
            logger.error(f"Corpus verification error [{e.code}]: {e.message}")
            return False, e.code
        except Exception as e:
            logger.error(f"Unexpected corpus verification error: {e}")
            return False, "CORPUS_INTEGRITY_UNKNOWN_ERROR"

    @staticmethod
    def enforce_execution_boundary(
        action_name: str,
        attempted_parameters: Dict[str, Any],
    ) -> None:
        """
        Enforce that advisory knowledge cannot alter M2.75 execution invariants.
        """
        forbidden_keys = {
            "credentials",
            "cookies",
            "cookie",
            "csrf_token",
            "session_token",
            "refresh_token",
            "nonce",
            "signing_key",
            "cidr_scope",
            "execution_approval",
            "rate_limit_bypass",
        }
        found_keys = forbidden_keys.intersection(set(attempted_parameters.keys()))
        if found_keys:
            raise PermissionError(
                f"EXECUTION_BOUNDARY_VIOLATION: Advisory reasoning attempted to set execution-privileged parameter(s): {found_keys}"
            )
