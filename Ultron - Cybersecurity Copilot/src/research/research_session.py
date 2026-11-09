"""Cybersecurity Research Mode & Session Manager (Milestone M9 Phase 12).

Orchestrates multi-turn deep cybersecurity research workflows:
    Question -> Decomposition -> Retrieval -> Source Comparison -> Claim Extraction -> Synthesis -> Citation -> Unresolved Questions

Maintains persistent ResearchSession state allowing follow-up investigations
against the same research context.
"""

from datetime import datetime, timezone
import hashlib
import uuid
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from src.knowledge.canonical_models import (
    AuthorityLevel,
    KnowledgeAnswer,
    KnowledgeCitation,
    KnowledgeClaim,
    KnowledgeConflict,
    KnowledgeResearchSession,
)
from src.knowledge.claim_extractor import KnowledgeClaimExtractor
from src.knowledge.citation_engine import GroundedCitationEngine
from src.knowledge.models import KnowledgeChunk
from src.knowledge.vapt_corpus import VaptDomainCorpus
from src.retrieval.query_rewriter import CybersecurityQueryRewriter


class ResearchDecomposition(BaseModel):
    main_question: str
    subquestions: List[str] = Field(default_factory=list)
    key_entities: List[str] = Field(default_factory=list)


class ResearchSessionManager:
    """Manages multi-turn research sessions with iterative evidence synthesis."""

    def __init__(self) -> None:
        self._sessions: Dict[str, KnowledgeResearchSession] = {}

    def create_session(self, question: str) -> KnowledgeResearchSession:
        """Initializes a new research session and decomposes the initial question."""
        session_id = f"RS-{uuid.uuid4().hex[:8]}"
        now = datetime.now(timezone.utc).isoformat()
        
        # Decompose question into logical subquestions
        decomposition = self._decompose_question(question)

        session = KnowledgeResearchSession(
            session_id=session_id,
            initial_question=question,
            subquestions=decomposition.subquestions,
            retrieved_sources=[],
            claims=[],
            contradictions=[],
            conclusions=[],
            evidence_gaps=[],
            unresolved_questions=[],
            history=[],
            created_at=now,
            updated_at=now,
        )
        self._sessions[session_id] = session
        return session

    def get_session(self, session_id: str) -> Optional[KnowledgeResearchSession]:
        return self._sessions.get(session_id)

    def execute_research_turn(
        self,
        session_id: str,
        turn_query: str,
        retrieved_chunks: List[KnowledgeChunk],
    ) -> KnowledgeAnswer:
        """
        Executes a turn in the research session:
        Retrieval -> Claim Extraction -> Citation Grounding -> Synthesis.
        """
        session = self.get_session(session_id)
        if not session:
            session = self.create_session(turn_query)

        # 1. Expand query
        expansion = CybersecurityQueryRewriter.rewrite_query(turn_query)

        # 2. Extract grounded claims from retrieved chunks
        chunk_text_blob = "\n\n".join([c.content for c in retrieved_chunks]) if retrieved_chunks else ""
        extraction_res = KnowledgeClaimExtractor.extract_claims(chunk_text_blob, retrieved_chunks)

        # 3. Grounded citations
        candidate_citations = []
        for claim in extraction_res.claims:
            for chk_id in claim.supporting_chunks:
                candidate_citations.append({
                    "chunk_id": chk_id,
                    "claim_id": claim.claim_id,
                })

        citation_res = GroundedCitationEngine.verify_citations(
            claims=extraction_res.claims,
            candidate_citations=candidate_citations,
            corpus_chunks=retrieved_chunks,
        )

        # 4. Synthesize structured answer text
        answer_id = f"ANS-{uuid.uuid4().hex[:8]}"
        if retrieved_chunks:
            synthesis_points = [f"- {claim.text}" for claim in extraction_res.claims[:5]]
            citations_summary = [f"[{c.source_title} ({c.chunk_id})]" for c in citation_res.valid_citations[:3]]
            ans_text = (
                f"### Research Findings for '{turn_query}'\n\n"
                f"{chr(10).join(synthesis_points)}\n\n"
                f"**Authoritative Sources**: {', '.join(set(citations_summary)) if citations_summary else 'Local Corpus'}"
            )
        else:
            ans_text = (
                f"Insufficient local cybersecurity knowledge is available to reliably investigate '{turn_query}'. "
                "Refusing to generate ungrounded conjectures."
            )

        # 5. Update session state
        session.retrieved_sources = list(set(session.retrieved_sources + [c.document_id for c in retrieved_chunks]))
        session.claims.extend(extraction_res.claims)
        if len(retrieved_chunks) < 2:
            session.unresolved_questions.append(f"Detailed version edge cases for: {turn_query}")
        session.history.append({
            "query": turn_query,
            "answer_id": answer_id,
            "claims_count": len(extraction_res.claims),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        session.updated_at = datetime.now(timezone.utc).isoformat()

        return KnowledgeAnswer(
            answer_id=answer_id,
            query_id=f"QRY-{uuid.uuid4().hex[:8]}",
            answer_text=ans_text,
            claims=extraction_res.claims,
            citations=citation_res.valid_citations,
            sufficiency_status="LOCAL_SUFFICIENT" if retrieved_chunks else "INSUFFICIENT",
            epistemic_tier="GENERAL_VAPT_KNOWLEDGE",
            escalation_level="7B" if len(retrieved_chunks) > 3 or len(expansion.expanded_terms) > 3 else "3B",
        )

    def _decompose_question(self, question: str) -> ResearchDecomposition:
        """Decomposes a broad research question into focused subquestions."""
        q_lower = question.lower()
        subquestions = []
        entities = []

        if "ssrf" in q_lower:
            entities.append("SSRF")
            subquestions.extend([
                "What is the core request forgery mechanism?",
                "How does in-band differ from blind SSRF?",
                "What internal assets are targeted (e.g. cloud metadata)?",
                "What defense-in-depth mitigations prevent bypasses?",
            ])
        elif "jwt" in q_lower:
            entities.append("JWT")
            subquestions.extend([
                "How does JWT structure and signature verification work?",
                "What are common cryptographic algorithm confusion vectors?",
                "How should session revocation be architected?",
            ])
        elif "kerberos" in q_lower:
            entities.append("Kerberos")
            subquestions.extend([
                "What are the message exchanges in Kerberos (AS-REQ to TGS-REP)?",
                "How do ticket-granting service requests enable Kerberoasting?",
                "What Active Directory defenses mitigate offline cracking?",
            ])
        else:
            subquestions.extend([
                f"What is the architectural definition of {question.strip('?')}?",
                "What are common security failure modes?",
                "How do researchers safely validate this weakness?",
                "What remediation controls exist?",
            ])

        return ResearchDecomposition(
            main_question=question,
            subquestions=subquestions,
            key_entities=entities,
        )
