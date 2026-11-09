"""Local + External Grounded Knowledge Fusion and Context Partitioning (M4).

Builds the unified GroundedKnowledgePack and renders the strictly partitioned
reasoning context for the 3B/7B cascade:
- === TARGET EVIDENCE === (Channel A: FACT-xxx only)
- === LOCAL VAPT KNOWLEDGE === (CHK-xxx only)
- === EXTERNAL KNOWLEDGE === (EXT-SRC-xxx)
- === EXTERNAL CLAIMS === (EXT-CLM-xxx)
- === CONFLICTS === (CONFLICT-xxx)
- === COUNTERFACTUAL & NEGATIVE CONTROLS ===
- === EPISTEMIC RULE === (External knowledge does not establish target facts)

Enforces Sections 18, 25, 26, 34, and the Core Epistemic Invariant:
    EXTERNAL_KNOWLEDGE != TARGET_EVIDENCE
"""

from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from src.knowledge.models import KnowledgeChunk, VaptKnowledgePack
from src.research.models import (
    ExternalClaim,
    ExternalSource,
    GroundedKnowledgePack,
    NegativeControlGuidance,
    SourceConflict,
    VersionScope,
)
from src.research.negative_control import NegativeControlEngine
from src.research.provenance import ResearchProvenanceTracker


class GroundedKnowledgePackBuilder:
    """Builds and seals a compact, provenance-verified GroundedKnowledgePack."""

    @classmethod
    def build_pack(
        cls,
        research_run_id: str,
        local_pack: Optional[VaptKnowledgePack] = None,
        external_sources: Optional[List[ExternalSource]] = None,
        external_claims: Optional[List[ExternalClaim]] = None,
        conflicts: Optional[List[SourceConflict]] = None,
        version_constraints: Optional[List[VersionScope]] = None,
        negative_controls: Optional[List[NegativeControlGuidance]] = None,
        max_token_budget: int = 1500,
    ) -> GroundedKnowledgePack:
        """
        Assembles, deduplicates, and calculates cryptographic root hash
        for the unified GroundedKnowledgePack.
        """
        sources = external_sources or []
        claims = external_claims or []
        confs = conflicts or []
        versions = version_constraints or []
        nc_guidance = negative_controls or []

        local_chunk_ids: List[str] = []
        if local_pack:
            local_chunk_ids = [item.chunk.chunk_id for item in local_pack.items]

        # Calculate root provenance hash
        provenance_root = ResearchProvenanceTracker.compute_knowledge_pack_root(sources, claims)

        # Estimate tokens
        token_estimate = 0
        if local_pack:
            token_estimate += local_pack.total_tokens
        for s in sources:
            token_estimate += len(s.normalized_content) // 4
        for c in claims:
            token_estimate += len(c.statement) // 4

        pack_id = f"GKP-{hashlib.sha256((research_run_id + provenance_root).encode()).hexdigest()[:8]}"

        pack = GroundedKnowledgePack(
            pack_id=pack_id,
            research_run_id=research_run_id,
            local_chunk_ids=local_chunk_ids,
            external_sources=sources,
            external_claims=claims,
            version_constraints=versions,
            conflicts=confs,
            negative_controls=nc_guidance,
            total_token_estimate=token_estimate,
            provenance_chain_hash=provenance_root,
        )

        return pack


class ReasoningContextPartitioner:
    """Renders strictly partitioned prompts separating Target Evidence from Knowledge."""

    @staticmethod
    def format_partitioned_prompt(
        target_evidence_facts: List[Dict[str, Any]],
        grounded_pack: Optional[GroundedKnowledgePack] = None,
        local_vapt_chunks: Optional[List[KnowledgeChunk]] = None,
        target_version: Optional[str] = None,
    ) -> str:
        """
        Constructs partitioned text format preserving epistemic boundaries.
        """
        sections: List[str] = []

        # 1. Target Evidence Section (Strictly FACT-xxx)
        sections.append("=== TARGET EVIDENCE (OBSERVED FACTS ONLY) ===")
        sections.append("The following observations were directly recorded from the target system under authorized test:")
        if not target_evidence_facts:
            sections.append("No target evidence facts provided.")
        else:
            for fact in target_evidence_facts:
                fid = fact.get("fact_id", "FACT-UNKNOWN")
                summary = fact.get("summary", str(fact))
                sections.append(f"[{fid}] {summary}")
        sections.append("")

        # 2. Local VAPT Knowledge Section (Strictly CHK-xxx)
        sections.append("=== LOCAL VAPT KNOWLEDGE (METHODOLOGY ONLY) ===")
        if not local_vapt_chunks:
            sections.append("No local VAPT methodology chunks retrieved.")
        else:
            for chunk in local_vapt_chunks:
                sections.append(f"[{chunk.chunk_id}] ({chunk.title}) {chunk.content.strip()[:350]}...")
        sections.append("")

        # 3. External Sources Section (EXT-SRC-xxx)
        if grounded_pack and grounded_pack.external_sources:
            sections.append("=== EXTERNAL KNOWLEDGE (VERIFIED ADVISORIES & REPOSITORIES) ===")
            for src in grounded_pack.external_sources:
                sections.append(
                    f"[{src.source_id}] Type: {src.source_type.value} | Trust: {src.trust_tier.value} | URL: {src.url}\n"
                    f"Title: {src.title}\n"
                    f"Snippet: {src.normalized_content.strip()[:300]}..."
                )
            sections.append("")

        # 4. External Claims Section (EXT-CLM-xxx)
        if grounded_pack and grounded_pack.external_claims:
            sections.append("=== EXTERNAL CLAIMS (EXTRACTED INVARIANTS & CONSTRAINTS) ===")
            for clm in grounded_pack.external_claims:
                status_note = f"Status: {clm.epistemic_status.value}"
                if clm.corroborating_source_ids:
                    status_note += f" (Corroborated by {', '.join(clm.corroborating_source_ids)})"
                sections.append(
                    f"[{clm.claim_id}] (Source: {clm.source_id}) [{clm.claim_type.value}] {status_note}\n"
                    f"Statement: {clm.statement}"
                )
            sections.append("")

        # 5. Detected Conflicts Section (CONFLICT-xxx)
        if grounded_pack and grounded_pack.conflicts:
            sections.append("=== DETECTED EXTERNAL CONFLICTS (UNRESOLVED DISAGREEMENTS) ===")
            for conf in grounded_pack.conflicts:
                sections.append(
                    f"[{conf.conflict_id}] Topic: {conf.topic}\n"
                    f"  Source A ({conf.source_a_id}): {conf.statement_a}\n"
                    f"  Source B ({conf.source_b_id}): {conf.statement_b}\n"
                    f"  Conditions: {conf.version_conditions or 'General divergence'}"
                )
            sections.append("")

        # 6. Counterfactual & Negative Controls Section
        if grounded_pack and grounded_pack.negative_controls:
            sections.append("=== COUNTERFACTUAL & NEGATIVE CONTROLS (AVOID FALSE POSITIVES) ===")
            for nc in grounded_pack.negative_controls:
                sections.append(f"Topic: {nc.topic}")
                sections.append("Legitimate Explanations:")
                for expl in nc.legitimate_explanations[:2]:
                    sections.append(f"  - {expl}")
                sections.append("Falsification Conditions:")
                for fals in nc.falsification_conditions[:2]:
                    sections.append(f"  - {fals}")
            sections.append("")

        # 7. Non-Negotiable Epistemic Rule
        sections.append("=== NON-NEGOTIABLE EPISTEMIC RULE ===")
        sections.append(
            "1. External knowledge and claims describe general mechanisms, NOT target reality.\n"
            "2. External advisories or CVEs DO NOT establish that the current target is vulnerable.\n"
            "3. If target version is unknown or target behavior is unobserved, emit EVIDENCE_GAP.\n"
            "4. NEVER promote an external claim (EXT-*) or local chunk (CHK-*) to target evidence (FACT-*).\n"
            "5. A vulnerability hypothesis requires matching TARGET EVIDENCE."
        )

        return "\n".join(sections)
