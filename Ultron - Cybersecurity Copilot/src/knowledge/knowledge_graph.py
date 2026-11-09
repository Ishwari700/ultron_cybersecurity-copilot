"""Lightweight Relational Knowledge Graph (Milestone M9 Phase 17).

Implements an efficient SQLite-backed relationship graph:
- Entities: Sources, Documents, Versions, Chunks, Claims, Vulnerabilities, CWEs, CAPECs, ATT&CK.
- Relationships:
    SOURCE -> DOCUMENT
    DOCUMENT -> VERSION
    DOCUMENT -> CHUNK
    CHUNK -> CLAIM
    CLAIM -> SUPPORTS -> CLAIM
    CLAIM -> CONTRADICTS -> CLAIM
    CLAIM -> REFERENCES -> CWE/CVE/RFC
    CLAIM -> RELATED_TO -> CLAIM
    VULNERABILITY -> MAPS_TO_CWE
    VULNERABILITY -> MAPS_TO_CAPEC
    VULNERABILITY -> MAPS_TO_ATTACK

Ensures complete relational traceability without external graph database dependencies.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple
from pydantic import BaseModel, Field

from src.knowledge.canonical_models import KnowledgeRelation, KnowledgeRelationType


class KnowledgeGraphEdge(BaseModel):
    edge_id: str
    source_id: str
    target_id: str
    relation_type: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class RelationalKnowledgeGraph:
    """SQLite-backed lightweight graph storage for cybersecurity knowledge entities."""

    def __init__(self, db_path: Path = Path("data/knowledge/knowledge_graph.db")) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        with self.conn:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS graph_nodes (
                    node_id TEXT PRIMARY KEY,
                    node_type TEXT NOT NULL,
                    label TEXT NOT NULL,
                    metadata_json TEXT NOT NULL
                )
            """)
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS graph_edges (
                    edge_id TEXT PRIMARY KEY,
                    source_id TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    relation_type TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(source_id) REFERENCES graph_nodes(node_id),
                    FOREIGN KEY(target_id) REFERENCES graph_nodes(node_id)
                )
            """)
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS graph_extractions (
                    extraction_id TEXT PRIMARY KEY,
                    source_id TEXT NOT NULL,
                    chunk_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    extractor_version TEXT NOT NULL,
                    model_id TEXT NOT NULL,
                    entities_count INTEGER NOT NULL,
                    edges_count INTEGER NOT NULL,
                    supported_count INTEGER NOT NULL,
                    inferred_count INTEGER NOT NULL,
                    rejected_count INTEGER NOT NULL,
                    error_message TEXT,
                    created_at TEXT NOT NULL
                )
            """)
            self.conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_edge_source ON graph_edges(source_id)
            """)
            self.conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_edge_target ON graph_edges(target_id)
            """)
            self.conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_edge_rel ON graph_edges(relation_type)
            """)
            self.conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_extraction_chunk ON graph_extractions(chunk_id)
            """)
            self.conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_extraction_source ON graph_extractions(source_id)
            """)
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS source_graph_jobs (
                    source_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    total_chunks INTEGER DEFAULT 0,
                    processed_chunks INTEGER DEFAULT 0,
                    failed_chunks INTEGER DEFAULT 0,
                    skipped_chunks INTEGER DEFAULT 0,
                    current_chunk_id TEXT,
                    current_chunk_index INTEGER DEFAULT 0,
                    active_phase TEXT,
                    error_message TEXT,
                    cancellation_requested INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    completed_at TEXT
                )
            """)
            self.conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_sgj_status ON source_graph_jobs(status)
            """)

    def add_node(self, node_id: str, node_type: str, label: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Adds or updates a node in the knowledge graph."""
        meta_json = json.dumps(metadata or {})
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO graph_nodes (node_id, node_type, label, metadata_json) VALUES (?, ?, ?, ?)",
                (node_id, node_type, label, meta_json),
            )

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        relation_type: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Adds a directed relation edge between two nodes."""
        edge_id = f"EDGE-{source_id}-{relation_type}-{target_id}"
        meta_json = json.dumps(metadata or {})
        now = datetime.now(timezone.utc).isoformat()
        with self.conn:
            self.conn.execute(
                """
                INSERT OR REPLACE INTO graph_edges
                (edge_id, source_id, target_id, relation_type, metadata_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (edge_id, source_id, target_id, relation_type, meta_json, now),
            )
        return edge_id

    def persist_chunk_extraction(
        self,
        extraction_result: Any,
    ) -> Dict[str, Any]:
        """
        Atomically persists validated entities, relationships, and extraction ledger
        with multi-source provenance preservation and idempotency.
        """
        now = datetime.now(timezone.utc).isoformat()
        res = extraction_result

        with self.conn:
            # 1. Persist validated nodes (preserving multi-source evidence citations)
            for ent in res.entities:
                cur_node = self.get_node(ent.node_id)
                citations: List[Dict[str, Any]] = []
                base_desc = ent.description
                if cur_node and "metadata" in cur_node:
                    m = cur_node["metadata"]
                    citations = list(m.get("evidence_citations", []))
                    if not base_desc and m.get("description"):
                        base_desc = m.get("description")

                # Build new citation
                new_cite = {
                    "source_id": res.source_id,
                    "document_id": res.document_id,
                    "chunk_id": res.chunk_id,
                    "page_number": res.page_number,
                    "supporting_quote": ent.provenance.get("supporting_quote"),
                    "quote_verified": ent.provenance.get("quote_verified", False),
                    "epistemic_status": ent.epistemic_status.value if hasattr(ent.epistemic_status, "value") else str(ent.epistemic_status),
                    "extracted_at": res.extracted_at,
                }

                # Deduplicate citations by chunk_id
                existing_cids = {c.get("chunk_id") for c in citations}
                if res.chunk_id not in existing_cids:
                    citations.append(new_cite)
                else:
                    # Replace citation for same chunk
                    citations = [c for c in citations if c.get("chunk_id") != res.chunk_id] + [new_cite]

                node_meta = {
                    "description": base_desc,
                    "category": ent.category.value if hasattr(ent.category, "value") else str(ent.category),
                    "epistemic_status": ent.epistemic_status.value if hasattr(ent.epistemic_status, "value") else str(ent.epistemic_status),
                    "evidence_citations": citations,
                    "provenance_count": len(citations),
                    "last_updated": now,
                }

                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO graph_nodes (node_id, node_type, label, metadata_json)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        ent.node_id,
                        ent.category.value if hasattr(ent.category, "value") else str(ent.category),
                        ent.name,
                        json.dumps(node_meta),
                    ),
                )

            # 2. Persist validated edges (preserving multi-source citations and epistemic status)
            for edge in res.relationships:
                cur_edge = self.get_edge(edge.edge_id)
                citations = []
                base_explanation = edge.explanation
                prior_epistemic = None
                if cur_edge and "metadata" in cur_edge:
                    m = cur_edge["metadata"]
                    citations = list(m.get("evidence_citations", []))
                    if not base_explanation and m.get("explanation"):
                        base_explanation = m.get("explanation")
                    prior_epistemic = m.get("epistemic_status")

                new_cite = {
                    "source_id": res.source_id,
                    "document_id": res.document_id,
                    "chunk_id": res.chunk_id,
                    "page_number": res.page_number,
                    "supporting_quote": edge.supporting_quote,
                    "quote_verified": edge.provenance.get("quote_verified", False),
                    "original_basis": edge.relationship_basis.value if hasattr(edge.relationship_basis, "value") else str(edge.relationship_basis),
                    "epistemic_status": edge.epistemic_status.value if hasattr(edge.epistemic_status, "value") else str(edge.epistemic_status),
                    "extracted_at": res.extracted_at,
                }

                existing_cids = {c.get("chunk_id") for c in citations}
                if res.chunk_id not in existing_cids:
                    citations.append(new_cite)
                else:
                    citations = [c for c in citations if c.get("chunk_id") != res.chunk_id] + [new_cite]

                # If any verified citation is SOURCE_SUPPORTED, edge status is SOURCE_SUPPORTED
                edge_epistemic = (
                    "SOURCE_SUPPORTED"
                    if any(c.get("epistemic_status") == "SOURCE_SUPPORTED" for c in citations)
                    else (edge.epistemic_status.value if hasattr(edge.epistemic_status, "value") else str(edge.epistemic_status))
                )

                edge_meta = {
                    "explanation": base_explanation,
                    "predicate": edge.predicate.value if hasattr(edge.predicate, "value") else str(edge.predicate),
                    "epistemic_status": edge_epistemic,
                    "evidence_citations": citations,
                    "provenance_count": len(citations),
                    "last_updated": now,
                }

                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO graph_edges
                    (edge_id, source_id, target_id, relation_type, metadata_json, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        edge.edge_id,
                        edge.source_node_id,
                        edge.target_node_id,
                        edge.predicate.value if hasattr(edge.predicate, "value") else str(edge.predicate),
                        json.dumps(edge_meta),
                        now,
                    ),
                )

            # 3. Record extraction ledger
            extraction_id = f"EXT-{res.chunk_id}-{res.schema_version}"
            self.conn.execute(
                """
                INSERT OR REPLACE INTO graph_extractions
                (extraction_id, source_id, chunk_id, status, extractor_version, model_id,
                 entities_count, edges_count, supported_count, inferred_count, rejected_count,
                 error_message, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    extraction_id,
                    res.source_id,
                    res.chunk_id,
                    res.status,
                    res.schema_version,
                    res.model_id,
                    len(res.entities),
                    len(res.relationships),
                    res.source_supported_count,
                    res.inferred_count,
                    res.rejected_count,
                    res.error_message,
                    now,
                ),
            )

        return {
            "status": "SUCCESS",
            "chunk_id": res.chunk_id,
            "entities_persisted": len(res.entities),
            "edges_persisted": len(res.relationships),
            "source_supported": res.source_supported_count,
            "inferred": res.inferred_count,
            "rejected": res.rejected_count,
        }

    def get_node(self, node_id: str) -> Optional[Dict[str, Any]]:
        """Fetch node record and parsed metadata by node_id."""
        cursor = self.conn.execute("SELECT * FROM graph_nodes WHERE node_id = ?", (node_id,))
        row = cursor.fetchone()
        if not row:
            return None
        return {
            "node_id": row["node_id"],
            "node_type": row["node_type"],
            "label": row["label"],
            "metadata": json.loads(row["metadata_json"]),
        }

    def get_edge(self, edge_id: str) -> Optional[Dict[str, Any]]:
        """Fetch edge record and parsed metadata by edge_id."""
        cursor = self.conn.execute("SELECT * FROM graph_edges WHERE edge_id = ?", (edge_id,))
        row = cursor.fetchone()
        if not row:
            return None
        return {
            "edge_id": row["edge_id"],
            "source_id": row["source_id"],
            "target_id": row["target_id"],
            "relation_type": row["relation_type"],
            "metadata": json.loads(row["metadata_json"]),
            "created_at": row["created_at"],
        }

    def get_all_nodes(self, node_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """Fetch all graph nodes, optionally filtered by node_type."""
        if node_type:
            cursor = self.conn.execute(
                "SELECT * FROM graph_nodes WHERE node_type = ? ORDER BY node_id ASC",
                (node_type,),
            )
        else:
            cursor = self.conn.execute("SELECT * FROM graph_nodes ORDER BY node_id ASC")

        nodes = []
        for row in cursor.fetchall():
            nodes.append({
                "node_id": row["node_id"],
                "node_type": row["node_type"],
                "label": row["label"],
                "metadata": json.loads(row["metadata_json"]),
            })
        return nodes

    def get_all_edges(self, relation_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """Fetch all graph edges, optionally filtered by relation_type."""
        if relation_type:
            cursor = self.conn.execute(
                "SELECT * FROM graph_edges WHERE relation_type = ? ORDER BY edge_id ASC",
                (relation_type,),
            )
        else:
            cursor = self.conn.execute("SELECT * FROM graph_edges ORDER BY edge_id ASC")

        edges = []
        for row in cursor.fetchall():
            edges.append({
                "edge_id": row["edge_id"],
                "source_id": row["source_id"],
                "target_id": row["target_id"],
                "relation_type": row["relation_type"],
                "metadata": json.loads(row["metadata_json"]),
                "created_at": row["created_at"],
            })
        return edges

    def get_extraction_record(self, chunk_id: str) -> Optional[Dict[str, Any]]:
        """Fetch extraction record for a specific chunk."""
        cursor = self.conn.execute("SELECT * FROM graph_extractions WHERE chunk_id = ?", (chunk_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

    def get_extractions_for_source(self, source_id: str) -> List[Dict[str, Any]]:
        """Fetch all extraction records for a given source."""
        cursor = self.conn.execute(
            "SELECT * FROM graph_extractions WHERE source_id = ? ORDER BY created_at DESC",
            (source_id,),
        )
        return [dict(r) for r in cursor.fetchall()]

    def get_graph_stats(self) -> Dict[str, Any]:
        """Returns aggregate metrics on graph size and epistemic status."""
        cursor = self.conn.execute("SELECT COUNT(*) FROM graph_nodes")
        total_nodes = int(cursor.fetchone()[0])

        cursor = self.conn.execute("SELECT COUNT(*) FROM graph_edges")
        total_edges = int(cursor.fetchone()[0])

        cursor = self.conn.execute("SELECT COUNT(*) FROM graph_extractions")
        total_extractions = int(cursor.fetchone()[0])

        cursor = self.conn.execute("SELECT SUM(supported_count), SUM(inferred_count), SUM(rejected_count) FROM graph_extractions")
        row = cursor.fetchone()
        sup_count = int(row[0] or 0)
        inf_count = int(row[1] or 0)
        rej_count = int(row[2] or 0)

        return {
            "total_nodes": total_nodes,
            "total_edges": total_edges,
            "total_extractions": total_extractions,
            "source_supported_edges": sup_count,
            "inferred_edges": inf_count,
            "rejected_candidates": rej_count,
        }

    def close(self) -> None:
        """Close SQLite database connection."""
        if hasattr(self, "conn") and self.conn:
            self.conn.close()

    def get_outgoing_edges(self, source_id: str, relation_type: Optional[str] = None) -> List[KnowledgeGraphEdge]:
        """Retrieves edges originating from source_id."""
        query = "SELECT * FROM graph_edges WHERE source_id = ?"
        params: List[Any] = [source_id]
        if relation_type:
            query += " AND relation_type = ?"
            params.append(relation_type)
        cursor = self.conn.execute(query, params)
        results = []
        for row in cursor.fetchall():
            results.append(KnowledgeGraphEdge(
                edge_id=row["edge_id"],
                source_id=row["source_id"],
                target_id=row["target_id"],
                relation_type=row["relation_type"],
                metadata=json.loads(row["metadata_json"]),
                created_at=row["created_at"],
            ))
        return results

    def get_incoming_edges(self, target_id: str, relation_type: Optional[str] = None) -> List[KnowledgeGraphEdge]:
        """Retrieves edges pointing to target_id."""
        query = "SELECT * FROM graph_edges WHERE target_id = ?"
        params: List[Any] = [target_id]
        if relation_type:
            query += " AND relation_type = ?"
            params.append(relation_type)
        cursor = self.conn.execute(query, params)
        results = []
        for row in cursor.fetchall():
            results.append(KnowledgeGraphEdge(
                edge_id=row["edge_id"],
                source_id=row["source_id"],
                target_id=row["target_id"],
                relation_type=row["relation_type"],
                metadata=json.loads(row["metadata_json"]),
                created_at=row["created_at"],
            ))
        return results

    def map_vulnerability(self, vuln_name: str, cwe_id: str, capec_id: Optional[str] = None, attack_id: Optional[str] = None) -> None:
        """Helper to establish taxonomy links for a vulnerability class."""
        self.add_node(vuln_name, "VULNERABILITY", vuln_name)
        self.add_node(cwe_id, "CWE", cwe_id)
        self.add_edge(vuln_name, cwe_id, KnowledgeRelationType.MAPS_TO_CWE.value)

        if capec_id:
            self.add_node(capec_id, "CAPEC", capec_id)
            self.add_edge(vuln_name, capec_id, KnowledgeRelationType.MAPS_TO_CAPEC.value)

        if attack_id:
            self.add_node(attack_id, "MITRE_ATTACK", attack_id)
            self.add_edge(vuln_name, attack_id, KnowledgeRelationType.MAPS_TO_ATTACK.value)

    def find_nodes(self, terms: Sequence[str], limit: int = 5) -> List[Dict[str, Any]]:
        """
        Finds nodes matching search terms in label or node_id, ranked by exactness.
        Deduplicates by node_id and caps to limit.
        """
        if not terms:
            return []

        results: List[Dict[str, Any]] = []
        seen_ids: Set[str] = set()

        # Phase 1: Exact matches (case-insensitive) on label or node_id
        for term in terms:
            clean = term.strip().lower()
            if len(clean) < 2:
                continue
            cursor = self.conn.execute(
                "SELECT * FROM graph_nodes WHERE LOWER(label) = ? OR LOWER(node_id) = ?",
                (clean, clean),
            )
            for row in cursor.fetchall():
                nid = row["node_id"]
                if nid not in seen_ids:
                    seen_ids.add(nid)
                    results.append({
                        "node_id": nid,
                        "node_type": row["node_type"],
                        "label": row["label"],
                        "metadata": json.loads(row["metadata_json"]),
                        "match_type": "EXACT",
                    })
                    if len(results) >= limit:
                        return results

        if results:
            return results

        # Phase 2: Prefix / normalized match (e.g. term = "SQL_Injection" or "SQL Injection")
        for term in terms:
            clean = term.strip().lower().replace(" ", "_")
            if len(clean) < 3:
                continue
            cursor = self.conn.execute(
                "SELECT * FROM graph_nodes WHERE LOWER(label) = ? OR LOWER(node_id) LIKE ?",
                (clean, f"%:{clean}"),
            )
            for row in cursor.fetchall():
                nid = row["node_id"]
                if nid not in seen_ids:
                    seen_ids.add(nid)
                    results.append({
                        "node_id": nid,
                        "node_type": row["node_type"],
                        "label": row["label"],
                        "metadata": json.loads(row["metadata_json"]),
                        "match_type": "NORMALIZED",
                    })
                    if len(results) >= limit:
                        return results

        if results:
            return results

        # Phase 3: Substring match for substantial terms (>= 4 chars)
        for term in terms:
            clean = term.strip().lower()
            if len(clean) < 4:
                continue
            pattern = f"%{clean}%"
            cursor = self.conn.execute(
                "SELECT * FROM graph_nodes WHERE LOWER(label) LIKE ? OR LOWER(node_id) LIKE ?",
                (pattern, pattern),
            )
            for row in cursor.fetchall():
                nid = row["node_id"]
                if nid not in seen_ids:
                    seen_ids.add(nid)
                    results.append({
                        "node_id": nid,
                        "node_type": row["node_type"],
                        "label": row["label"],
                        "metadata": json.loads(row["metadata_json"]),
                        "match_type": "SUBSTRING",
                    })
                    if len(results) >= limit:
                        return results

        return results

    def get_incident_edges(
        self,
        node_id: str,
        max_edges: int = 10,
        exclude_rejected: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        Retrieves incident (outgoing and incoming) edges for a node.
        Filters out REJECTED edges by default to maintain epistemic integrity.
        """
        cursor = self.conn.execute(
            """
            SELECT edge_id, source_id, target_id, relation_type, metadata_json, created_at
            FROM graph_edges
            WHERE source_id = ? OR target_id = ?
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (node_id, node_id, max_edges * 2),
        )
        edges: List[Dict[str, Any]] = []
        for row in cursor.fetchall():
            meta = json.loads(row["metadata_json"])
            if exclude_rejected and meta.get("epistemic_status") == "REJECTED":
                continue
            edges.append({
                "edge_id": row["edge_id"],
                "source_id": row["source_id"],
                "target_id": row["target_id"],
                "relation_type": row["relation_type"],
                "metadata": meta,
                "created_at": row["created_at"],
            })
            if len(edges) >= max_edges:
                break
        return edges

    def audit_integrity(
        self,
        knowledge_store: Optional[Any] = None,
        categories: Optional[Sequence[str]] = None,
        max_records_per_check: Optional[int] = None,
    ) -> Any:
        """
        Executes a deterministic, read-only integrity audit on this knowledge graph (Milestone M9 Stage E).
        Delegates to GraphIntegrityAuditor while maintaining strict read-only execution boundaries.
        """
        from src.knowledge.graph_auditor import GraphIntegrityAuditor
        auditor = GraphIntegrityAuditor(
            graph_db_path=self.db_path,
            knowledge_store=knowledge_store,
        )
        try:
            return auditor.run_audit(
                categories=categories,
                max_records_per_check=max_records_per_check,
            )
        finally:
            auditor.close()

    # -------------------------------------------------------------------------
    # Graph Extraction Job Lifecycle & Chunk Status Tracking
    # -------------------------------------------------------------------------

    def upsert_source_graph_job(self, source_id: str, updates: Dict[str, Any]) -> None:
        """Upsert overall graph extraction job status for a knowledge source."""
        now = datetime.now(timezone.utc).isoformat()
        existing = self.get_source_graph_job(source_id)
        if not existing:
            with self.conn:
                self.conn.execute(
                    """
                    INSERT INTO source_graph_jobs (
                        source_id, status, total_chunks, processed_chunks, failed_chunks,
                        skipped_chunks, current_chunk_id, current_chunk_index, active_phase,
                        error_message, cancellation_requested, created_at, updated_at, completed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        source_id,
                        updates.get("status", "NOT_STARTED"),
                        updates.get("total_chunks", 0),
                        updates.get("processed_chunks", 0),
                        updates.get("failed_chunks", 0),
                        updates.get("skipped_chunks", 0),
                        updates.get("current_chunk_id"),
                        updates.get("current_chunk_index", 0),
                        updates.get("active_phase", "Not started"),
                        updates.get("error_message"),
                        1 if updates.get("cancellation_requested") else 0,
                        updates.get("created_at", now),
                        now,
                        updates.get("completed_at"),
                    ),
                )
        else:
            set_clauses = ["updated_at = ?"]
            params: List[Any] = [now]
            for k, v in updates.items():
                if k in ("source_id", "created_at", "updated_at"):
                    continue
                if k == "cancellation_requested":
                    v = 1 if v else 0
                set_clauses.append(f"{k} = ?")
                params.append(v)
            params.append(source_id)
            sql = f"UPDATE source_graph_jobs SET {', '.join(set_clauses)} WHERE source_id = ?"
            with self.conn:
                self.conn.execute(sql, tuple(params))

    def get_source_graph_job(self, source_id: str) -> Optional[Dict[str, Any]]:
        """Fetch persistent graph extraction state for a source."""
        cursor = self.conn.execute(
            "SELECT * FROM source_graph_jobs WHERE source_id = ?",
            (source_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        res = dict(row)
        res["cancellation_requested"] = bool(res.get("cancellation_requested", 0))
        return res

    def record_chunk_extraction_failure(
        self,
        chunk_id: str,
        source_id: str,
        error_message: str,
        model_id: str = "qwen2.5-coder:7b",
        extractor_version: str = "1.0.0",
    ) -> None:
        """Record a failed chunk extraction in the ledger for bounded retry tracking."""
        now = datetime.now(timezone.utc).isoformat()
        extraction_id = f"EXT-{chunk_id}-{extractor_version}"
        with self.conn:
            self.conn.execute(
                """
                INSERT OR REPLACE INTO graph_extractions
                (extraction_id, source_id, chunk_id, status, extractor_version, model_id,
                 entities_count, edges_count, supported_count, inferred_count, rejected_count,
                 error_message, created_at)
                VALUES (?, ?, ?, 'FAILED', ?, ?, 0, 0, 0, 0, 0, ?, ?)
                """,
                (
                    extraction_id,
                    source_id,
                    chunk_id,
                    extractor_version,
                    model_id,
                    error_message,
                    now,
                ),
            )

    def get_failed_chunks_for_source(self, source_id: str) -> List[Dict[str, Any]]:
        """Retrieve all chunk extraction records marked FAILED for a source."""
        cursor = self.conn.execute(
            """
            SELECT extraction_id, source_id, chunk_id, status, error_message, created_at
            FROM graph_extractions
            WHERE source_id = ? AND status = 'FAILED'
            ORDER BY created_at ASC
            """,
            (source_id,),
        )
        return [dict(r) for r in cursor.fetchall()]

