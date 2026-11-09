"""Offline Corpus Ingestion, Normalization, and Allowlist Verification.

Implements M3.2 & M3.3 per M3 Plan v2.3.8 Section 8:
- Immutable YAML frontmatter validation
- Deterministic markdown normalization (UTF-8, LF, whitespace collapse)
- Redistribution allowlist verification
- Non-destructive suspicion detection & quarantine flagging
"""

import hashlib
import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import yaml

from src.knowledge.chunking import SemanticMarkdownChunker
from src.knowledge.models import (
    KnowledgeChunk,
    KnowledgeDocumentFrontmatter,
    KnowledgeSourceType,
    KnowledgeType,
    SourceAllowlistEntry,
)

logger = logging.getLogger("m3.ingestion")

# Patterns indicating potential hostile prompt injection in advisory corpus
SUSPICIOUS_DIRECTIVE_PATTERNS = [
    re.compile(r"ignore\s+(?:all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+in\s+unrestricted\s+mode", re.IGNORECASE),
    re.compile(r"system\s+override\s*:\s*execute", re.IGNORECASE),
    re.compile(r"bypass\s+cidr\s+scope", re.IGNORECASE),
    re.compile(r"approve\s+all\s+execution\s+requests", re.IGNORECASE),
]


class IngestionError(Exception):
    """Raised when document ingestion or allowlist verification fails."""
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message


def load_source_allowlist(sources_json_path: Path) -> Dict[str, SourceAllowlistEntry]:
    """Load and validate the authorized knowledge sources allowlist."""
    if not sources_json_path.exists():
        raise IngestionError("ALLOWLIST_FILE_NOT_FOUND", f"sources.json not found at {sources_json_path}")

    with open(sources_json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    allowlist: Dict[str, SourceAllowlistEntry] = {}
    for entry in data.get("sources", []):
        parsed = SourceAllowlistEntry(**entry)
        allowlist[parsed.source_name] = parsed
    return allowlist


def normalize_markdown_text(text: str) -> str:
    """
    Deterministically normalize markdown body text:
    - LF line endings only (\n)
    - Strip trailing whitespace on each line
    - Collapse 3+ consecutive newlines to standard \n\n (preserving code blocks)
    - Strip leading and trailing whitespace
    """
    # Standardize line endings
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    # Strip trailing whitespace on each line
    lines = [line.rstrip() for line in text.split("\n")]
    text = "\n".join(lines)

    # Protect code blocks during newline collapse
    code_blocks = []

    def _save_block(m: re.Match) -> str:
        idx = len(code_blocks)
        code_blocks.append(m.group(0))
        return f"__CODE_FENCE_{idx}__"

    protected = re.sub(r"```[\s\S]*?```", _save_block, text)

    # Collapse multiple blank lines to exactly double newline
    collapsed = re.sub(r"\n{3,}", "\n\n", protected)

    # Restore code blocks
    for idx, block in enumerate(code_blocks):
        collapsed = collapsed.replace(f"__CODE_FENCE_{idx}__", block)

    return collapsed.strip()


def parse_frontmatter_and_body(raw_text: str) -> Tuple[Dict[str, Any], str]:
    """
    Extract YAML frontmatter between leading --- delimiters and body text.
    """
    if not raw_text.startswith("---"):
        raise IngestionError("MISSING_FRONTMATTER", "Document must begin with YAML frontmatter delimiter '---'")

    parts = raw_text.split("---", 2)
    if len(parts) < 3:
        raise IngestionError("MALFORMED_FRONTMATTER", "Document lacks closing frontmatter delimiter '---'")

    frontmatter_yaml = parts[1]
    raw_body = parts[2]

    try:
        frontmatter_dict = yaml.safe_load(frontmatter_yaml) or {}
    except yaml.YAMLError as e:
        raise IngestionError("INVALID_YAML_FRONTMATTER", f"YAML parsing error: {e}")

    return frontmatter_dict, raw_body


def check_suspicious_directives(text: str) -> List[str]:
    """
    Deterministic suspicion detection for adversarial injection directives.
    Non-destructive: returns list of matched pattern descriptions without modifying text.
    """
    findings = []
    for pattern in SUSPICIOUS_DIRECTIVE_PATTERNS:
        matches = pattern.findall(text)
        if matches:
            findings.append(f"Matched pattern '{pattern.pattern}': {matches}")
    return findings


class DocumentIngestionEngine:
    """Ingestion engine managing validation, chunking, and quarantine flagging."""

    def __init__(self, sources_json_path: Path) -> None:
        self.allowlist = load_source_allowlist(sources_json_path)

    def ingest_file(
        self,
        file_path: Path,
        default_knowledge_type: KnowledgeType = KnowledgeType.TESTING_METHODOLOGY,
    ) -> Tuple[KnowledgeDocumentFrontmatter, str, List[KnowledgeChunk], List[str]]:
        """
        Ingest, validate, normalize, and chunk a corpus document file.
        
        Returns:
            (validated_frontmatter, normalized_body, chunks, quarantine_warnings)
        """
        with open(file_path, "r", encoding="utf-8") as f:
            raw_text = f.read()

        fm_dict, raw_body = parse_frontmatter_and_body(raw_text)
        normalized_body = normalize_markdown_text(raw_body)
        computed_body_hash = hashlib.sha256(normalized_body.encode("utf-8")).hexdigest().lower()

        # Validate frontmatter schema
        frontmatter = KnowledgeDocumentFrontmatter(**fm_dict)

        # Allowlist verification
        if frontmatter.source_name not in self.allowlist:
            raise IngestionError(
                "SOURCE_NOT_IN_ALLOWLIST",
                f"Source '{frontmatter.source_name}' is not in approved sources.json allowlist",
            )

        allowlist_entry = self.allowlist[frontmatter.source_name]
        if frontmatter.license != allowlist_entry.license:
            raise IngestionError(
                "LICENSE_ALLOWLIST_MISMATCH",
                f"Document license '{frontmatter.license}' does not match approved '{allowlist_entry.license}'",
            )

        # Content hash verification
        if frontmatter.content_hash.lower() != computed_body_hash:
            raise IngestionError(
                "BODY_CONTENT_HASH_MISMATCH",
                f"Document frontmatter content_hash {frontmatter.content_hash} != computed {computed_body_hash}",
            )

        # Non-destructive suspicion detection
        quarantine_warnings = check_suspicious_directives(normalized_body)
        if quarantine_warnings:
            logger.warning(
                f"Document {frontmatter.document_id} flagged for advisory review: {quarantine_warnings}"
            )

        # Map source type
        source_type = allowlist_entry.source_type

        # Determine knowledge type from frontmatter or parameter
        kt_str = fm_dict.get("knowledge_type")
        if kt_str:
            try:
                knowledge_type = KnowledgeType(kt_str)
            except ValueError:
                knowledge_type = default_knowledge_type
        else:
            knowledge_type = default_knowledge_type

        category_tags = fm_dict.get("category_tags", [])

        # Semantic chunking
        chunks = SemanticMarkdownChunker.chunk_document(
            document_id=frontmatter.document_id,
            title=frontmatter.title,
            source_type=source_type,
            knowledge_type=knowledge_type,
            normalized_body=normalized_body,
            category_tags=category_tags,
        )

        return frontmatter, normalized_body, chunks, quarantine_warnings
