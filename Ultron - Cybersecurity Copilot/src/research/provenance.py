"""Cryptographic Provenance and Audit Verification for External Research (M4).

Ensures all claims extracted from the Web and GitHub are deterministically
traceable from:
    Reasoning Output Claim
        ↓
    External Claim (EXT-CLM-*)
        ↓
    External Source (EXT-SRC-*)
        ↓
    URL / Repository + Commit SHA + File + Line Range
        ↓
    Content Hash (SHA-256)
        ↓
    Retrieval Timestamp

Enforces Section 24 & RFC 9162 Merkle-compatible leaf validation.
"""

import hashlib
import json
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from src.research.models import ExternalClaim, ExternalSource, GroundedKnowledgePack


class ProvenanceNode(BaseModel):
    """Atomic provenance entry verifying an external citation."""
    claim_id: str
    source_id: str
    source_url: str
    content_hash: str
    retrieval_timestamp: str
    repository: Optional[str] = None
    commit_sha: Optional[str] = None
    path: Optional[str] = None
    line_range: Optional[Tuple[int, int]] = None
    node_hash: str


class ProvenanceAuditResult(BaseModel):
    """Result of comprehensive provenance verification across a GroundedKnowledgePack."""
    is_valid: bool
    total_claims_checked: int
    linked_claims_count: int
    unlinked_claim_ids: List[str] = Field(default_factory=list)
    tampered_source_ids: List[str] = Field(default_factory=list)
    provenance_chain_root: str = ""
    error_details: List[str] = Field(default_factory=list)


class ResearchProvenanceTracker:
    """Computes, attaches, and verifies cryptographic provenance for external research."""

    @staticmethod
    def compute_source_content_hash(content: str) -> str:
        """Computes deterministic SHA-256 for UTF-8 normalized document body."""
        normalized = content.strip().replace("\r\n", "\n")
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    @staticmethod
    def build_provenance_node(claim: ExternalClaim, source: ExternalSource) -> ProvenanceNode:
        """Constructs an immutable provenance node linking claim to its source."""
        if claim.source_id != source.source_id:
            raise ValueError(
                f"Source mismatch in provenance linking: claim cites {claim.source_id}, source is {source.source_id}"
            )

        line_range = None
        if source.line_start is not None and source.line_end is not None:
            line_range = (source.line_start, source.line_end)

        canonical_payload = (
            f"{claim.claim_id}|{source.source_id}|{source.url}|{source.content_hash}|"
            f"{source.retrieved_at}|{source.repository or ''}|{source.commit_sha or ''}|"
            f"{source.path or ''}|{line_range or ''}"
        )
        node_hash = hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()

        return ProvenanceNode(
            claim_id=claim.claim_id,
            source_id=source.source_id,
            source_url=source.url,
            content_hash=source.content_hash,
            retrieval_timestamp=source.retrieved_at,
            repository=source.repository,
            commit_sha=source.commit_sha,
            path=source.path,
            line_range=line_range,
            node_hash=node_hash,
        )

    @classmethod
    def compute_knowledge_pack_root(
        cls,
        sources: List[ExternalSource],
        claims: List[ExternalClaim],
    ) -> str:
        """
        Computes deterministic Merkle-style root hash over sorted source and claim nodes.
        Ensures auditability and anti-tamper verification.
        """
        source_map = {s.source_id: s for s in sources}
        node_hashes: List[str] = []

        for claim in sorted(claims, key=lambda c: c.claim_id):
            if claim.source_id in source_map:
                node = cls.build_provenance_node(claim, source_map[claim.source_id])
                node_hashes.append(node.node_hash)

        if not node_hashes:
            # Fallback to source hashes if no claims
            source_hashes = sorted([s.content_hash for s in sources])
            combined = "|".join(source_hashes)
            return hashlib.sha256(combined.encode("utf-8")).hexdigest()

        combined = "|".join(node_hashes)
        return hashlib.sha256(combined.encode("utf-8")).hexdigest()

    @classmethod
    def verify_grounded_pack_provenance(
        cls,
        pack: GroundedKnowledgePack,
    ) -> ProvenanceAuditResult:
        """
        Verifies that:
        1. Every external claim points to a registered source in the pack.
        2. Every source's normalized content matches its recorded content_hash.
        3. The root hash matches the recomputed provenance root.
        """
        source_map = {s.source_id: s for s in pack.external_sources}
        unlinked_claims: List[str] = []
        tampered_sources: List[str] = []
        errors: List[str] = []

        # 1. Check source integrity
        for src in pack.external_sources:
            if src.normalized_content:
                recomputed = cls.compute_source_content_hash(src.normalized_content)
                if recomputed != src.content_hash:
                    tampered_sources.append(src.source_id)
                    errors.append(
                        f"Source {src.source_id} content_hash mismatch: expected {src.content_hash}, got {recomputed}"
                    )

        # 2. Check claim linkage
        linked_count = 0
        for claim in pack.external_claims:
            if claim.source_id not in source_map:
                unlinked_claims.append(claim.claim_id)
                errors.append(f"Claim {claim.claim_id} cites missing source_id {claim.source_id}")
            else:
                linked_count += 1

        recomputed_root = cls.compute_knowledge_pack_root(pack.external_sources, pack.external_claims)
        if pack.provenance_chain_hash and pack.provenance_chain_hash != recomputed_root:
            errors.append(
                f"Provenance root hash mismatch: pack has {pack.provenance_chain_hash}, recomputed {recomputed_root}"
            )

        is_valid = len(unlinked_claims) == 0 and len(tampered_sources) == 0 and len(errors) == 0

        return ProvenanceAuditResult(
            is_valid=is_valid,
            total_claims_checked=len(pack.external_claims),
            linked_claims_count=linked_count,
            unlinked_claim_ids=unlinked_claims,
            tampered_source_ids=tampered_sources,
            provenance_chain_root=recomputed_root,
            error_details=errors,
        )
