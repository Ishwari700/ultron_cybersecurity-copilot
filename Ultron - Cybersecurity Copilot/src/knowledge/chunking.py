"""Deterministic Semantic Chunking for VAPT Knowledge Corpus.

Implements SemanticMarkdownChunker v1.0.0 per M3 Plan v2.3.8 Section 10:
- Target size: 150-250 tokens (~600-1000 characters)
- Maximum ceiling: 300 tokens (~1200 characters)
- Minimum floor: 50 tokens
- 4-level deterministic semantic recursive subdivision
- Code block atomicity preservation
- Breadcrumb propagation & CHK-xxx naming contract
"""

import hashlib
import inspect
import re
from typing import List, Optional, Tuple

from src.knowledge.models import (
    KnowledgeChunk,
    KnowledgeSourceType,
    KnowledgeType,
)


class SemanticMarkdownChunker:
    """Deterministic Semantic Markdown Chunker v1.0.0."""

    VERSION: str = "1.0.0"
    TARGET_MIN_TOKENS: int = 150
    TARGET_MAX_TOKENS: int = 250
    HARD_MAX_TOKENS: int = 300
    MIN_FLOOR_TOKENS: int = 50
    CHARS_PER_TOKEN: float = 4.0

    @classmethod
    def get_chunker_code_hash(cls) -> str:
        """Compute SHA-256 hash of chunker implementation for manifest provenance."""
        source = inspect.getsource(cls)
        return hashlib.sha256(source.encode("utf-8")).hexdigest().lower()

    @classmethod
    def estimate_tokens(cls, text: str) -> int:
        """Estimate token count from string length using standard character ratio."""
        if not text:
            return 0
        return max(1, int(len(text) / cls.CHARS_PER_TOKEN))

    @classmethod
    def chunk_document(
        cls,
        document_id: str,
        title: str,
        source_type: KnowledgeSourceType,
        knowledge_type: KnowledgeType,
        normalized_body: str,
        category_tags: Optional[List[str]] = None,
    ) -> List[KnowledgeChunk]:
        """
        Split a normalized markdown document body into deterministic semantic chunks.
        """
        tags = category_tags or []
        sections = cls._split_into_sections(normalized_body)
        chunks: List[KnowledgeChunk] = []

        for sec_idx, (sec_heading, sec_content) in enumerate(sections, start=1):
            subdivided_parts = cls._subdivide_content(sec_content)

            # Ensure parts respect the min floor where possible by merging small sibling parts
            merged_parts = cls._merge_undersized_parts(subdivided_parts)
            total_parts = len(merged_parts)

            for part_idx, part_text in enumerate(merged_parts, start=1):
                breadcrumb = f"[DOC: {title}] [SEC: {sec_heading}] (Part {part_idx:02d} of {total_parts:02d})"
                final_content = f"{breadcrumb}\n\n{part_text.strip()}"
                content_hash = hashlib.sha256(final_content.encode("utf-8")).hexdigest().lower()
                chunk_id = f"CHK-{document_id}-{sec_idx:03d}-{part_idx:02d}"

                chunk = KnowledgeChunk(
                    schema_version="3.0.0",
                    chunk_id=chunk_id,
                    document_id=document_id,
                    source_type=source_type,
                    knowledge_type=knowledge_type,
                    category_tags=tags,
                    title=title,
                    section_heading=sec_heading,
                    content=final_content,
                    token_estimate=cls.estimate_tokens(final_content),
                    content_hash=content_hash,
                    trust_tier="CURATED_ADVISORY",
                )
                chunks.append(chunk)

        return chunks

    @classmethod
    def _split_into_sections(cls, markdown: str) -> List[Tuple[str, str]]:
        """
        Split document into major sections based on ## or ### headings.
        """
        lines = markdown.split("\n")
        sections: List[Tuple[str, List[str]]] = []
        current_heading = "Overview"
        current_lines: List[str] = []

        heading_pattern = re.compile(r"^(#{2,3})\s+(.+)$")

        for line in lines:
            match = heading_pattern.match(line)
            if match:
                if current_lines:
                    sections.append((current_heading, current_lines))
                    current_lines = []
                current_heading = match.group(2).strip()
            else:
                current_lines.append(line)

        if current_lines:
            sections.append((current_heading, current_lines))

        result = []
        for heading, lines_list in sections:
            content = "\n".join(lines_list).strip()
            if content:
                result.append((heading, content))
        return result

    @classmethod
    def _subdivide_content(cls, content: str) -> List[str]:
        """
        Subdivide content using 4-level semantic recursive subdivision if it exceeds ceiling:
        Level 1: Subheadings (####)
        Level 2: Procedural steps / lists (1., -, *)
        Level 3: Paragraph boundaries (\n\n)
        Level 4: Sentence boundaries (. , ! , ? )
        Preserves code blocks atomically.
        """
        if cls.estimate_tokens(content) <= cls.HARD_MAX_TOKENS:
            return [content]

        # Level 1: Subheadings (####)
        parts = cls._split_by_subheadings(content)
        if len(parts) > 1 and all(cls.estimate_tokens(p) <= cls.HARD_MAX_TOKENS for p in parts):
            return parts

        # If any part still exceeds hard max, apply Level 2 to it
        level2_parts: List[str] = []
        for part in parts:
            if cls.estimate_tokens(part) > cls.HARD_MAX_TOKENS:
                level2_parts.extend(cls._split_by_lists(part))
            else:
                level2_parts.append(part)

        if all(cls.estimate_tokens(p) <= cls.HARD_MAX_TOKENS for p in level2_parts):
            return level2_parts

        # Level 3: Paragraphs
        level3_parts: List[str] = []
        for part in level2_parts:
            if cls.estimate_tokens(part) > cls.HARD_MAX_TOKENS:
                level3_parts.extend(cls._split_by_paragraphs(part))
            else:
                level3_parts.append(part)

        if all(cls.estimate_tokens(p) <= cls.HARD_MAX_TOKENS for p in level3_parts):
            return level3_parts

        # Level 4: Sentences (avoiding breaking code blocks)
        final_parts: List[str] = []
        for part in level3_parts:
            if cls.estimate_tokens(part) > cls.HARD_MAX_TOKENS:
                final_parts.extend(cls._split_by_sentences(part))
            else:
                final_parts.append(part)

        return final_parts

    @classmethod
    def _split_by_subheadings(cls, text: str) -> List[str]:
        """Split text along #### headings."""
        parts = re.split(r"(?=(?:^|\n)####\s+)", text)
        return [p.strip() for p in parts if p.strip()]

    @classmethod
    def _split_by_lists(cls, text: str) -> List[str]:
        """Split text along list items (1. or - or *) while keeping code blocks atomic."""
        # Check if inside code block
        code_blocks, placeholders = cls._extract_code_blocks(text)
        pattern = re.compile(r"(?=(?:^|\n)(?:\d+\.\s+|[-*]\s+))")
        raw_parts = pattern.split(placeholders)
        parts = [cls._restore_code_blocks(p.strip(), code_blocks) for p in raw_parts if p.strip()]
        return parts if len(parts) > 1 else [text]

    @classmethod
    def _split_by_paragraphs(cls, text: str) -> List[str]:
        """Split text on paragraph breaks (\n\n) while protecting code blocks."""
        code_blocks, placeholders = cls._extract_code_blocks(text)
        raw_parts = placeholders.split("\n\n")
        parts = [cls._restore_code_blocks(p.strip(), code_blocks) for p in raw_parts if p.strip()]
        return parts if len(parts) > 1 else [text]

    @classmethod
    def _split_by_sentences(cls, text: str) -> List[str]:
        """Split text on sentence boundaries while keeping code blocks intact."""
        code_blocks, placeholders = cls._extract_code_blocks(text)
        # Sentence splitting pattern
        raw_sentences = re.split(r"(?<=[.!?])\s+", placeholders)
        
        # Re-pack sentences into target-sized clusters
        clusters: List[str] = []
        current: List[str] = []
        current_len = 0

        for s in raw_sentences:
            s_len = cls.estimate_tokens(s)
            if current and (current_len + s_len > cls.TARGET_MAX_TOKENS):
                clusters.append(" ".join(current))
                current = [s]
                current_len = s_len
            else:
                current.append(s)
                current_len += s_len

        if current:
            clusters.append(" ".join(current))

        parts = [cls._restore_code_blocks(c.strip(), code_blocks) for c in clusters if c.strip()]
        return parts if parts else [text]

    @classmethod
    def _extract_code_blocks(cls, text: str) -> Tuple[List[str], str]:
        """Extract code blocks so that splitting doesn't bisect them."""
        code_blocks: List[str] = []

        def _repl(match: re.Match) -> str:
            idx = len(code_blocks)
            code_blocks.append(match.group(0))
            return f"__CODE_BLOCK_{idx}__"

        replaced = re.sub(r"```[\s\S]*?```", _repl, text)
        return code_blocks, replaced

    @classmethod
    def _restore_code_blocks(cls, text: str, code_blocks: List[str]) -> str:
        """Restore extracted code blocks."""
        for idx, block in enumerate(code_blocks):
            text = text.replace(f"__CODE_BLOCK_{idx}__", block)
        return text

    @classmethod
    def _merge_undersized_parts(cls, parts: List[str]) -> List[str]:
        """Merge parts smaller than MIN_FLOOR_TOKENS into adjacent siblings if possible."""
        if len(parts) <= 1:
            return parts

        merged: List[str] = []
        buffer = ""

        for part in parts:
            if not buffer:
                buffer = part
            else:
                buf_tokens = cls.estimate_tokens(buffer)
                part_tokens = cls.estimate_tokens(part)
                # If buffer is undersized or combining stays within ceiling
                if buf_tokens < cls.MIN_FLOOR_TOKENS or (buf_tokens + part_tokens <= cls.TARGET_MAX_TOKENS):
                    buffer = f"{buffer}\n\n{part}"
                else:
                    merged.append(buffer)
                    buffer = part

        if buffer:
            if merged and cls.estimate_tokens(buffer) < cls.MIN_FLOOR_TOKENS:
                # Merge into last part if small
                merged[-1] = f"{merged[-1]}\n\n{buffer}"
            else:
                merged.append(buffer)

        return merged
