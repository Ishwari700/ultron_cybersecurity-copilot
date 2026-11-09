"""Canonical P4 Serialization Grammar & Capacity Oracle Contract.

Implements M3.7 per M3 Plan v2.3.8 Sections 13.6 and 13.7:
- Authoritative CanonicalP4Serialization wire grammar
- Deterministic 4-class advisory priority ordering
- Greedy capacity allocation within 256-token budget ceiling
- Cryptographically pinned tokenizer identity
- Scorer-side qualification reference for InjectionHit@P4_256
"""

import hashlib
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

from src.knowledge.models import (
    KnowledgeChunk,
    KnowledgeRetrievalItem,
    KnowledgeType,
)
from src.retrieval.budget import TokenBudgetController

ADVISORY_NOTICE_HEADER = (
    "[NOTICE: The following sections provide general security testing methodology and invariant definitions.\n"
    "This is REFERENCE KNOWLEDGE, NOT observed evidence from the target application.\n"
    "Do NOT cite these items as target facts. Use them solely to evaluate the canonical evidence above.]"
)

# Semantic Priority Class Mapping (Section 13.7)
PRIORITY_MAP = {
    KnowledgeType.SECURITY_INVARIANT: 1,       # Priority 1: Invariant Guidance
    KnowledgeType.FALSE_POSITIVE_GUIDANCE: 2,   # Priority 2: Discrimination Guidance
    KnowledgeType.EXPERIMENT_PATTERN: 3,        # Priority 3: Verification Pattern
    KnowledgeType.NEGATIVE_CONTROL_GUIDE: 3,    # Priority 3: Verification Pattern
    KnowledgeType.TESTING_METHODOLOGY: 4,       # Priority 4: General Background
}


def escape_xml_content(text: str) -> str:
    """Escape XML special characters within technical text & code samples."""
    text = text.replace("&", "&amp;")
    text = text.replace("<", "&lt;")
    text = text.replace(">", "&gt;")
    return text


def normalize_chunk_body(text: str) -> str:
    """Normalize body text whitespace and line endings."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.rstrip() for line in text.split("\n")]
    return "\n".join(lines).strip()


class CanonicalP4CapacityOracle:
    """
    Scorer-Side P4 Capacity Oracle and Canonical Serialization Engine.
    
    Acts as the authoritative reference for P4 wire serialization, token capacity,
    and InjectionHit@P4_256 evaluation.
    """

    ORACLE_VERSION: str = "3.0.0"
    P4_CAPACITY_BUDGET: int = 256

    # Cryptographically Pinned Tokenizer Metadata (Section 13.6)
    TOKENIZER_NAME: str = "Qwen2.5-Coder-7B-Tokenizer"
    TOKENIZER_VERSION: str = "v2.5.0-pinned"
    TOKENIZER_ARTIFACT_HASH: str = "9b43d2f7823e59392e2cb68ff813476442657e0f31c25141b714f3a4b953d611"
    TOKENIZER_CONFIG_HASH: str = "5f7e411b0284dfa52bb88a44b81566418ef4128f7004f21350a80e1c27bf6329"
    NORMALIZATION_POLICY: str = "NFC"

    def __init__(self, chars_per_token: float = 4.0) -> None:
        self.budget_controller = TokenBudgetController(chars_per_token=chars_per_token)

    @classmethod
    def get_oracle_version_hash(cls) -> str:
        """Compute SHA-256 hash of oracle identity for provenance binding."""
        raw = f"{cls.ORACLE_VERSION}:{cls.P4_CAPACITY_BUDGET}:{cls.TOKENIZER_ARTIFACT_HASH}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest().lower()

    def estimate_tokens(self, text: str) -> int:
        """Estimate token count for serialized text."""
        if not text:
            return 0
        return self.budget_controller.estimate_tokens(text)

    @classmethod
    def get_priority_class(cls, knowledge_type: KnowledgeType) -> int:
        """Return integer priority class (1 to 4)."""
        return PRIORITY_MAP.get(knowledge_type, 4)

    @classmethod
    def format_single_chunk(cls, chunk: KnowledgeChunk) -> str:
        """Format an individual advisory chunk under CanonicalP4Serialization."""
        priority = cls.get_priority_class(chunk.knowledge_type)
        category = chunk.category_tags[0].upper() if chunk.category_tags else "GENERAL_VAPT_METHODOLOGY"
        # Strip redundant internal chunker breadcrumb if present
        raw_content = chunk.content
        cleaned_content = re.sub(r"^\[DOC:[^\]]+\]\s*\[SEC:[^\]]+\]\s*\(Part \d+ of \d+\)\s*", "", raw_content).strip()
        escaped_content = escape_xml_content(normalize_chunk_body(cleaned_content))

        return (
            f'<advisory_chunk id="{chunk.chunk_id}" priority="{priority}" category="{category}">\n'
            f"[DOCUMENT: {chunk.title}] [SECTION: {chunk.section_heading}]\n"
            f"{escaped_content}\n"
            f"</advisory_chunk>"
        )

    def serialize_pack(
        self,
        retrieval_items: Sequence[KnowledgeRetrievalItem],
        token_budget: Optional[int] = None,
    ) -> Tuple[str, int, List[KnowledgeRetrievalItem]]:
        """
        Serialize candidate retrieval items into CanonicalP4Serialization wire format.
        
        Applies Section 13.7 Advisory-Chunk Prioritization Policy:
        1. Sort candidates: Priority ASC -> Fused Score DESC -> chunk_id ASC
        2. Greedy packing up to token_budget (default 256)
        3. If 0 chunks fit, returns empty string "" (0 tokens)
        
        Returns:
            (serialized_wire_text, total_tokens, accepted_retrieval_items)
        """
        budget = token_budget if token_budget is not None else self.P4_CAPACITY_BUDGET

        if not retrieval_items:
            return "", 0, []

        # Sort candidates deterministically per Section 13.7
        # Priority Class ASC -> Fused Score DESC -> chunk_id ASC
        sorted_candidates = sorted(
            retrieval_items,
            key=lambda item: (
                self.get_priority_class(item.chunk.knowledge_type),
                -float(item.fused_score),
                item.chunk.chunk_id.encode("utf-8"),
            ),
        )

        accepted_items: List[KnowledgeRetrievalItem] = []
        accepted_chunk_blocks: List[str] = []

        for item in sorted_candidates:
            candidate_block = self.format_single_chunk(item.chunk)
            trial_blocks = accepted_chunk_blocks + [candidate_block]

            # Construct trial full envelope
            trial_inner = "\n\n".join(trial_blocks)
            trial_envelope = (
                f"<vapt_methodology_advisory>\n"
                f"{ADVISORY_NOTICE_HEADER}\n\n"
                f"{trial_inner}\n"
                f"</vapt_methodology_advisory>"
            )

            trial_tokens = self.estimate_tokens(trial_envelope)
            if trial_tokens <= budget:
                accepted_items.append(item)
                accepted_chunk_blocks.append(candidate_block)
            else:
                # Chunk does not fit; skip and evaluate subsequent chunks
                continue

        if not accepted_items:
            # Empty-Pack Behavior: zero tokens, empty string
            return "", 0, []

        # Build final canonical envelope
        final_inner = "\n\n".join(accepted_chunk_blocks)
        serialized_wire = (
            f"<vapt_methodology_advisory>\n"
            f"{ADVISORY_NOTICE_HEADER}\n\n"
            f"{final_inner}\n"
            f"</vapt_methodology_advisory>"
        )
        total_tokens = self.estimate_tokens(serialized_wire)

        return serialized_wire, total_tokens, accepted_items

    def is_injection_hit(
        self,
        retrieval_items: Sequence[KnowledgeRetrievalItem],
        gold_chunk_ids: Sequence[str],
        token_budget: Optional[int] = None,
    ) -> bool:
        """
        Evaluate InjectionHit@P4_256:
        Returns True iff at least one chunk in gold_chunk_ids survived into the
        final packed P4 serialized envelope within budget.
        """
        _wire, _tokens, accepted_items = self.serialize_pack(retrieval_items, token_budget)
        accepted_ids = {item.chunk.chunk_id for item in accepted_items}
        gold_set = set(gold_chunk_ids)
        return bool(accepted_ids & gold_set)
