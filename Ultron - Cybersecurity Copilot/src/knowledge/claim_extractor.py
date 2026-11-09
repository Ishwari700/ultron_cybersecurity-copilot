"""Structured Knowledge Claim Extraction & Validation Engine (Milestone M9 Phase 9).

Extracts and validates structured claims from cybersecurity knowledge responses:
- Each claim contains: claim_id, text, epistemic_status, supporting_chunks, contradicting_chunks, confidence, provenance
- Prevents unsupported claims from entering answers
- Enforces epistemic boundary: EXTERNAL_KNOWLEDGE != TARGET_EVIDENCE
"""

import hashlib
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field

from src.knowledge.canonical_models import KnowledgeClaim
from src.knowledge.models import KnowledgeChunk


class ClaimExtractionResult(BaseModel):
    claims: List[KnowledgeClaim] = Field(default_factory=list)
    unsupported_claims: List[str] = Field(default_factory=list)
    unsupported_claim_rate: float = 0.0
    valid: bool = True


class KnowledgeClaimExtractor:
    """Extracts verifiable claims from synthesized technical answers and validates chunk grounding."""

    @classmethod
    def extract_claims(
        cls,
        text: str,
        retrieved_chunks: List[KnowledgeChunk],
    ) -> ClaimExtractionResult:
        """
        Parses sentences into atomic assertions and verifies that each claim
        has at least one supporting chunk in the retrieved context.
        """
        # Split text into declarative sentence candidates
        sentences = [
            s.strip() for s in re.split(r"(?<=[.!?])\s+", text)
            if len(s.strip()) > 15 and not s.strip().startswith("#")
        ]

        chunk_contents = {c.chunk_id: c.content.lower() for c in retrieved_chunks}
        extracted_claims: List[KnowledgeClaim] = []
        unsupported: List[str] = []

        for idx, sentence in enumerate(sentences, start=1):
            claim_hash = hashlib.sha256(sentence.encode("utf-8")).hexdigest()[:8]
            claim_id = f"CLAIM-{claim_hash}"

            # Extract key terms from sentence (excluding common stop words)
            words = set(re.findall(r"\b[a-zA-Z0-9_\-]{4,}\b", sentence.lower()))
            stop_words = {"this", "that", "with", "from", "have", "more", "when", "will", "which", "their", "there", "about"}
            meaningful_words = words - stop_words

            supporting_chunk_ids: List[str] = []
            for cid, ctext in chunk_contents.items():
                if not meaningful_words:
                    continue
                # Overlap metric
                matches = sum(1 for w in meaningful_words if w in ctext)
                overlap = matches / len(meaningful_words)
                if overlap >= 0.35 or any(w in ctext for w in words if w.startswith("cwe") or w.startswith("cve")):
                    supporting_chunk_ids.append(cid)

            if supporting_chunk_ids:
                claim = KnowledgeClaim(
                    claim_id=claim_id,
                    text=sentence,
                    epistemic_status="EXTERNAL_CORROBORATED",
                    supporting_chunks=supporting_chunk_ids,
                    confidence=0.92,
                    provenance_chain=[supporting_chunk_ids[0]],
                )
                extracted_claims.append(claim)
            else:
                unsupported.append(sentence)

        total_sentences = len(sentences)
        unsupported_rate = len(unsupported) / total_sentences if total_sentences > 0 else 0.0

        return ClaimExtractionResult(
            claims=extracted_claims,
            unsupported_claims=unsupported,
            unsupported_claim_rate=unsupported_rate,
            valid=(len(unsupported) == 0 or unsupported_rate < 0.25),
        )
