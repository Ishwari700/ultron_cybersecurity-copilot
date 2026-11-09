"""Graph-Assisted Retrieval, Hybrid Query Routing & Evidence Fusion Engine (Milestone M9 Stage D).

Coordinates bounded knowledge graph traversal with baseline retrieval:
User question -> existing retrieval -> bounded graph-assisted expansion ->
source-grounded evidence fusion -> existing knowledge-answer pipeline -> citations and grounded response.

Hard Architectural Invariants Enforced:
1. Original source passages remain authoritative evidence (Section 3.2). Graph nodes and edges
   are derived traversal aids; factual answers are grounded exclusively in recoverable source chunks.
2. Epistemic status preservation (Section 3.3):
   - SOURCE_SUPPORTED: Traceable to verified source quotation.
   - INFERRED: Usable as discovery signal for passage retrieval, never asserted as factual truth.
   - CANDIDATE / UNVERIFIED: Insufficiently supported; excluded from factual citations.
   - REJECTED: Strictly excluded from graph expansion.
3. Source lifecycle protection (Section 3.2 & 4):
   - Deactivated, failed, quarantined, or deleted sources cannot re-enter the context via graph edges.
4. Bounded execution (Section 3.1 & 6):
   - Max matching entities, max edges per node, max graph chunks, and max total context limits.
5. Zero privilege escalation (Section 3.4):
   - Retrieval is an informational research aid; never overrides ScopeGate, RBAC, or human verification.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from pydantic import BaseModel, Field

from src.knowledge.models import KnowledgeChunk
from src.knowledge.store import VaptKnowledgeStore
from src.knowledge.knowledge_graph import RelationalKnowledgeGraph

logger = logging.getLogger("m9.graph_retriever")

# Common English stop words to filter out during lexical entity term extraction
ENTITY_STOP_WORDS: Set[str] = {
    "a", "an", "the", "and", "or", "but", "in", "on", "at", "to", "for",
    "with", "by", "from", "up", "about", "into", "over", "after", "is",
    "are", "was", "were", "be", "been", "being", "have", "has", "had",
    "do", "does", "did", "can", "could", "will", "would", "shall", "should",
    "may", "might", "must", "what", "which", "who", "whom", "this", "that",
    "these", "those", "am", "it", "its", "how", "why", "where", "when",
    "tell", "me", "explain", "describe", "show", "give", "find", "list",
}


class GraphExpansionEvidence(BaseModel):
    """Lineage record for a source chunk reached via graph relationship traversal."""
    chunk_id: str
    source_id: str
    document_id: str
    page_number: Optional[int] = None
    supporting_quote: Optional[str] = None
    epistemic_status: str = "SOURCE_SUPPORTED"  # "SOURCE_SUPPORTED" | "INFERRED"
    relation_type: Optional[str] = None
    matched_entity_id: str
    matched_entity_label: str
    connected_entity_id: Optional[str] = None
    connected_entity_label: Optional[str] = None
    edge_id: Optional[str] = None
    quote_verified: bool = False


class GraphRetrieverMetadata(BaseModel):
    """Forensic audit metadata detailing the bounded graph traversal and fusion."""
    entities_matched: List[Dict[str, Any]] = Field(default_factory=list)
    edges_inspected: int = 0
    candidate_citations_found: int = 0
    stale_or_ineligible_skipped: int = 0
    missing_chunks_skipped: int = 0
    graph_chunks_admitted: int = 0
    epistemic_breakdown: Dict[str, int] = Field(default_factory=dict)
    traversal_successful: bool = True
    error_message: Optional[str] = None


class GraphAssistedRetriever:
    """
    Integrates RelationalKnowledgeGraph with VaptKnowledgeStore and existing retrieval.
    Expands query terms through verified graph relationships and recovers authoritative source passages.
    """

    def __init__(
        self,
        knowledge_store: Optional[VaptKnowledgeStore] = None,
        knowledge_graph: Optional[RelationalKnowledgeGraph] = None,
        base_retriever: Optional[Any] = None,
        max_entities: int = 4,
        max_edges_per_node: int = 6,
        max_graph_chunks: int = 4,
        max_total_chunks: int = 8,
        include_inferred: bool = True,
    ) -> None:
        self.store = knowledge_store
        self.graph = knowledge_graph
        self.base_retriever = base_retriever
        self.max_entities = max_entities
        self.max_edges_per_node = max_edges_per_node
        self.max_graph_chunks = max_graph_chunks
        self.max_total_chunks = max_total_chunks
        self.include_inferred = include_inferred

    @staticmethod
    def extract_entity_terms(query: str) -> List[str]:
        """
        Deterministically extracts potential entity terms and identifiers from query.
        Extracts formal cybersecurity identifiers (CVE, CWE, CAPEC, ATT&CK) and substantial n-grams.
        """
        terms: List[str] = []
        seen: Set[str] = set()

        def _add(t: str) -> None:
            clean = t.strip()
            key = clean.lower()
            if key and key not in seen and len(clean) >= 2 and key not in ENTITY_STOP_WORDS:
                seen.add(key)
                terms.append(clean)

        # 1. Regex pattern matches for formal cybersecurity taxonomies
        cve_matches = re.findall(r"\bCVE-\d{4}-\d+\b", query, re.IGNORECASE)
        for m in cve_matches:
            _add(m.upper())

        cwe_matches = re.findall(r"\bCWE-\d+\b", query, re.IGNORECASE)
        for m in cwe_matches:
            _add(m.upper())

        capec_matches = re.findall(r"\bCAPEC-\d+\b", query, re.IGNORECASE)
        for m in capec_matches:
            _add(m.upper())

        attack_matches = re.findall(r"\bT\d{4}(?:\.\d{3})?\b", query, re.IGNORECASE)
        for m in attack_matches:
            _add(m.upper())

        # 2. Extract multi-word phrases and key tokens
        clean_q = re.sub(r"[^\w\s\-]", " ", query).strip()
        if len(clean_q) >= 3 and clean_q.lower() not in ENTITY_STOP_WORDS:
            _add(clean_q)

        words = re.findall(r"\b[A-Za-z0-9_\-]{2,}\b", query)
        filtered_words = [w for w in words if w.lower() not in ENTITY_STOP_WORDS]

        # Trigrams (e.g. "Broken Object Level", "Object Level Authorization")
        for i in range(len(words) - 2):
            w1, w2, w3 = words[i], words[i + 1], words[i + 2]
            if any(w.lower() not in ENTITY_STOP_WORDS for w in (w1, w2, w3)):
                _add(f"{w1} {w2} {w3}")

        # Bigrams (e.g. "SQL Injection", "Authentication Bypass", "Remote Code")
        for i in range(len(words) - 1):
            w1, w2 = words[i], words[i + 1]
            if w1.lower() not in ENTITY_STOP_WORDS or w2.lower() not in ENTITY_STOP_WORDS:
                _add(f"{w1} {w2}")

        # Individual significant words
        for w in filtered_words:
            if len(w) >= 3:
                _add(w)

        return terms

    def is_source_eligible(self, source_id: str, document_id: Optional[str] = None) -> bool:
        """
        Validates that a source and document remain eligible for retrieval.
        Returns False if the source is DEACTIVATED, FAILED, QUARANTINED, MALFORMED, or DELETED.
        """
        if not self.store:
            return True

        # Check explicit source_id in registry
        if source_id:
            src_rec = self.store.get_source(source_id)
            if src_rec:
                status = str(src_rec.get("status", "")).upper()
                if status in {"DEACTIVATED", "FAILED", "QUARANTINED", "MALFORMED", "DELETED"}:
                    return False

        # Check document_id mapping if it points to a source (DOC-<source_id>)
        if document_id and document_id.startswith("DOC-"):
            cand_src_id = document_id[4:]
            cand_rec = self.store.get_source(cand_src_id)
            if cand_rec:
                status = str(cand_rec.get("status", "")).upper()
                if status in {"DEACTIVATED", "FAILED", "QUARANTINED", "MALFORMED", "DELETED"}:
                    return False

        return True

    def find_relevant_entities(self, query: str) -> List[Dict[str, Any]]:
        """
        Identifies relevant graph nodes from query text using deterministic multi-tier matching.
        """
        if not self.graph:
            return []

        entity_terms = self.extract_entity_terms(query)
        if not entity_terms:
            return []

        try:
            matched_nodes = self.graph.find_nodes(entity_terms, limit=self.max_entities)
            return matched_nodes
        except Exception as e:
            logger.warning(f"Error querying graph nodes: {e}")
            return []

    def expand_graph_evidence(
        self,
        matched_nodes: List[Dict[str, Any]],
        existing_chunk_ids: Optional[Set[str]] = None,
    ) -> Tuple[List[KnowledgeChunk], List[GraphExpansionEvidence], GraphRetrieverMetadata]:
        """
        Binds graph traversal to source evidence recovery.
        Traverses incident edges of matched nodes, filters by epistemic status,
        verifies source eligibility, and recovers authoritative source chunks.
        """
        meta = GraphRetrieverMetadata(
            entities_matched=[
                {"node_id": n["node_id"], "label": n.get("label", ""), "node_type": n.get("node_type", "")}
                for n in matched_nodes
            ]
        )
        seen_chunks = set(existing_chunk_ids or set())
        recovered_chunks: List[KnowledgeChunk] = []
        evidence_records: List[GraphExpansionEvidence] = []

        if not self.graph or not self.store:
            return recovered_chunks, evidence_records, meta

        for node in matched_nodes:
            node_id = node["node_id"]
            node_label = node.get("label", node_id)

            # 1. Recover citations directly anchored to the matched node
            node_cites = node.get("metadata", {}).get("evidence_citations", [])
            for cite in node_cites:
                meta.candidate_citations_found += 1
                chunk_id = cite.get("chunk_id")
                source_id = cite.get("source_id", "")
                doc_id = cite.get("document_id", "")
                epistemic = cite.get("epistemic_status", "SOURCE_SUPPORTED")

                meta.epistemic_breakdown[epistemic] = meta.epistemic_breakdown.get(epistemic, 0) + 1

                if not self.is_source_eligible(source_id, doc_id):
                    meta.stale_or_ineligible_skipped += 1
                    continue

                if not chunk_id or chunk_id in seen_chunks:
                    continue

                chunk = self.store.get_chunk(chunk_id)
                if not chunk:
                    meta.missing_chunks_skipped += 1
                    continue

                # Secondary eligibility check on recovered chunk's document_id
                if not self.is_source_eligible(source_id, chunk.document_id):
                    meta.stale_or_ineligible_skipped += 1
                    continue

                seen_chunks.add(chunk_id)
                recovered_chunks.append(chunk)
                evidence_records.append(
                    GraphExpansionEvidence(
                        chunk_id=chunk_id,
                        source_id=source_id,
                        document_id=doc_id or chunk.document_id,
                        page_number=cite.get("page_number"),
                        supporting_quote=cite.get("supporting_quote"),
                        epistemic_status=epistemic,
                        relation_type="NODE_ANCHOR",
                        matched_entity_id=node_id,
                        matched_entity_label=node_label,
                        quote_verified=cite.get("quote_verified", False),
                    )
                )

                if len(recovered_chunks) >= self.max_graph_chunks:
                    break

            if len(recovered_chunks) >= self.max_graph_chunks:
                break

            # 2. Traverse incident relationships
            try:
                edges = self.graph.get_incident_edges(
                    node_id=node_id,
                    max_edges=self.max_edges_per_node,
                    exclude_rejected=True,
                )
            except Exception as e:
                logger.warning(f"Error traversing edges for {node_id}: {e}")
                edges = []

            for edge in edges:
                meta.edges_inspected += 1
                edge_meta = edge.get("metadata", {})
                edge_epistemic = edge_meta.get("epistemic_status", "SOURCE_SUPPORTED")

                # Epistemic Gate: Strictly skip REJECTED / CANDIDATE
                if edge_epistemic in {"REJECTED", "CANDIDATE", "UNVERIFIED"}:
                    continue

                if edge_epistemic == "INFERRED" and not self.include_inferred:
                    continue

                citations = edge_meta.get("evidence_citations", [])
                for cite in citations:
                    meta.candidate_citations_found += 1
                    chunk_id = cite.get("chunk_id")
                    source_id = cite.get("source_id", "")
                    doc_id = cite.get("document_id", "")
                    cite_epistemic = cite.get("epistemic_status", edge_epistemic)

                    meta.epistemic_breakdown[cite_epistemic] = meta.epistemic_breakdown.get(cite_epistemic, 0) + 1

                    if not self.is_source_eligible(source_id, doc_id):
                        meta.stale_or_ineligible_skipped += 1
                        continue

                    if not chunk_id or chunk_id in seen_chunks:
                        continue

                    chunk = self.store.get_chunk(chunk_id)
                    if not chunk:
                        meta.missing_chunks_skipped += 1
                        continue

                    if not self.is_source_eligible(source_id, chunk.document_id):
                        meta.stale_or_ineligible_skipped += 1
                        continue

                    # Determine connected entity
                    connected_id = edge["target_id"] if edge["source_id"] == node_id else edge["source_id"]

                    seen_chunks.add(chunk_id)
                    recovered_chunks.append(chunk)
                    evidence_records.append(
                        GraphExpansionEvidence(
                            chunk_id=chunk_id,
                            source_id=source_id,
                            document_id=doc_id or chunk.document_id,
                            page_number=cite.get("page_number"),
                            supporting_quote=cite.get("supporting_quote"),
                            epistemic_status=cite_epistemic,
                            relation_type=edge.get("relation_type"),
                            matched_entity_id=node_id,
                            matched_entity_label=node_label,
                            connected_entity_id=connected_id,
                            edge_id=edge.get("edge_id"),
                            quote_verified=cite.get("quote_verified", False),
                        )
                    )

                    if len(recovered_chunks) >= self.max_graph_chunks:
                        break

                if len(recovered_chunks) >= self.max_graph_chunks:
                    break

        meta.graph_chunks_admitted = len(recovered_chunks)
        return recovered_chunks, evidence_records, meta

    def fuse_and_rank(
        self,
        baseline_chunks: List[KnowledgeChunk],
        graph_chunks: List[KnowledgeChunk],
    ) -> List[KnowledgeChunk]:
        """
        Performs deterministic fusion of baseline and graph-expanded chunks.
        Preserves baseline search order and priority while interleaving novel graph chunks up to limits.
        """
        seen_ids: Set[str] = set()
        fused: List[KnowledgeChunk] = []

        # 1. Baseline chunks take precedence
        for chunk in baseline_chunks:
            if chunk.chunk_id not in seen_ids:
                seen_ids.add(chunk.chunk_id)
                fused.append(chunk)
                if len(fused) >= self.max_total_chunks:
                    return fused

        # 2. Add novel graph-derived chunks
        for chunk in graph_chunks:
            if chunk.chunk_id not in seen_ids:
                seen_ids.add(chunk.chunk_id)
                fused.append(chunk)
                if len(fused) >= self.max_total_chunks:
                    break

        return fused

    def retrieve(
        self,
        query: str,
        baseline_chunks: Optional[List[KnowledgeChunk]] = None,
        top_k: int = 5,
    ) -> Tuple[List[KnowledgeChunk], List[GraphExpansionEvidence], GraphRetrieverMetadata]:
        """
        Executes bounded graph-assisted retrieval:
        1. Accepts or defaults baseline retrieved chunks.
        2. Identifies matching graph entities.
        3. Bounded traversal to recover verified source chunks.
        4. Fuses and deduplicates without exceeding maximum context bounds.
        """
        if baseline_chunks is not None:
            baseline = list(baseline_chunks)
        elif self.base_retriever is not None:
            try:
                retrieval_items = self.base_retriever.retrieve(query, top_k=top_k)
                baseline = [item.chunk for item in retrieval_items if hasattr(item, "chunk")]
            except Exception as e:
                logger.warning(f"Base retriever query error: {e}")
                baseline = []
        elif self.store is not None:
            try:
                hits = self.store.query_lexical(query, top_k=top_k)
                baseline = [chunk for chunk, _score in hits]
            except Exception as e:
                logger.warning(f"Store lexical query error: {e}")
                baseline = []
        else:
            baseline = []

        # If graph is not configured or unavailable, return baseline directly
        if not self.graph:
            empty_meta = GraphRetrieverMetadata(traversal_successful=False, error_message="Graph not configured")
            return baseline[:top_k], [], empty_meta

        try:
            matched_nodes = self.find_relevant_entities(query)
            if not matched_nodes:
                meta = GraphRetrieverMetadata(traversal_successful=True)
                return baseline[:top_k], [], meta

            existing_cids = {c.chunk_id for c in baseline}
            graph_chunks, evidence_records, meta = self.expand_graph_evidence(
                matched_nodes=matched_nodes,
                existing_chunk_ids=existing_cids,
            )

            fused_chunks = self.fuse_and_rank(baseline, graph_chunks)
            return fused_chunks[:top_k], evidence_records, meta

        except Exception as e:
            logger.warning(f"Graph-assisted retrieval encountered error, falling back to baseline: {e}")
            err_meta = GraphRetrieverMetadata(traversal_successful=False, error_message=str(e))
            return baseline[:top_k], [], err_meta
