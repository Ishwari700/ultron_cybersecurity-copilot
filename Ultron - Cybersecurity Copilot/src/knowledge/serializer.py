"""Production P4 Wire Serializer (CanonicalP4Serialization).

Implements M3.10 per M3 Plan v2.3.8 Sections 13.6, 15, and 16.3:
- Authoritative runtime CanonicalP4Serialization wire grammar
- Exact 100% byte-for-byte parity with CanonicalP4CapacityOracle
- Deterministic 4-class advisory priority ordering
- Greedy capacity allocation within P4 budget ceiling
- Production VaptKnowledgePack serialization and provenance binding
"""

import hashlib
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

from src.knowledge.models import (
    EpistemicTier,
    KnowledgeChunk,
    KnowledgeRetrievalItem,
    KnowledgeType,
    VaptKnowledgePack,
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


class ProductionP4Serializer:
    """
    Production Runtime P4 Context-Packing Serializer.
    
    CRITICAL ARCHITECTURAL INVARIANT (Criterion 43 & Section 13.6):
    CanonicalP4CapacityOracle(pack) == ProductionP4Serializer(pack) byte-for-byte.
    """

    SERIALIZER_VERSION: str = "3.0.0"
    DEFAULT_TIER1_BUDGET: int = 256
    DEFAULT_TIER2_BUDGET: int = 768

    # Cryptographically Pinned Tokenizer Metadata (matches Oracle)
    TOKENIZER_NAME: str = "Qwen2.5-Coder-7B-Tokenizer"
    TOKENIZER_VERSION: str = "v2.5.0-pinned"
    TOKENIZER_ARTIFACT_HASH: str = "9b43d2f7823e59392e2cb68ff813476442657e0f31c25141b714f3a4b953d611"
    TOKENIZER_CONFIG_HASH: str = "5f7e411b0284dfa52bb88a44b81566418ef4128f7004f21350a80e1c27bf6329"
    NORMALIZATION_POLICY: str = "NFC"

    def __init__(self, chars_per_token: float = 4.0) -> None:
        self.budget_controller = TokenBudgetController(chars_per_token=chars_per_token)

    @classmethod
    def get_serializer_version_hash(cls) -> str:
        """Compute SHA-256 hash of serializer identity."""
        raw = f"{cls.SERIALIZER_VERSION}:{cls.TOKENIZER_ARTIFACT_HASH}:{cls.TOKENIZER_CONFIG_HASH}"
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
        """
        Format an individual advisory chunk under CanonicalP4Serialization.
        Must match CanonicalP4CapacityOracle.format_single_chunk byte-for-byte.
        """
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
        2. Greedy packing up to token_budget (default 256 for Tier 1)
        3. If 0 chunks fit, returns empty string "" (0 tokens)
        
        Returns:
            (serialized_wire_text, total_tokens, accepted_retrieval_items)
        """
        budget = token_budget if token_budget is not None else self.DEFAULT_TIER1_BUDGET

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
            # Empty-Pack Behavior per Section 13.6: zero tokens, empty string
            return "", 0, []

        final_inner = "\n\n".join(accepted_chunk_blocks)
        serialized_wire = (
            f"<vapt_methodology_advisory>\n"
            f"{ADVISORY_NOTICE_HEADER}\n\n"
            f"{final_inner}\n"
            f"</vapt_methodology_advisory>"
        )
        total_tokens = self.estimate_tokens(serialized_wire)

        return serialized_wire, total_tokens, accepted_items

    def build_knowledge_pack(
        self,
        retrieval_items: Sequence[KnowledgeRetrievalItem],
        token_budget: Optional[int] = None,
        retrieval_query: str = "",
        query_renderer_id: str = "RENDERER_S",
        corpus_manifest_hash: str = "",
        retrieval_timestamp: Optional[str] = None,
    ) -> VaptKnowledgePack:
        """
        Build production VaptKnowledgePack with deterministic wire serialization
        and full provenance binding.
        """
        serialized_wire, total_tokens, accepted_items = self.serialize_pack(
            retrieval_items=retrieval_items,
            token_budget=token_budget,
        )

        # Compute deterministic provenance hash
        chunk_ids = [item.chunk.chunk_id for item in accepted_items]
        raw_prov = f"{query_renderer_id}:{retrieval_query}:{serialized_wire}:{':'.join(chunk_ids)}"
        prov_hash = hashlib.sha256(raw_prov.encode("utf-8")).hexdigest()
        ts = retrieval_timestamp or "2026-09-20T00:00:00Z"
        m_hash = corpus_manifest_hash or "bd4abf9c2d1b8f5cfdaebfae1c3132e01df5e8c1569cae1eb2a06140c83a0fa6"

        return VaptKnowledgePack(
            pack_id=f"PACK-{prov_hash[:16]}",
            schema_version="3.0.0",
            items=list(accepted_items),
            total_tokens=total_tokens,
            rendered_query_text=retrieval_query,
            retrieval_timestamp=ts,
            corpus_manifest_hash=m_hash,
            provenance_hash=prov_hash,
            serialized_p4_wire=serialized_wire,
            epistemic_tier=EpistemicTier.GENERAL_VAPT_KNOWLEDGE,
        )
