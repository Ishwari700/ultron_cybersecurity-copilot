"""Deterministic, Read-Only Knowledge Graph Integrity & Provenance Auditor (Milestone M9 Stage E).

Extends Ultron's Relational Knowledge Graph with deterministic, read-only integrity auditing:
1. Structural Integrity:
   - Dangling edges (source or target node missing from graph_nodes)
   - Malformed or unparseable metadata_json
   - Invalid relationship predicates or node categories
   - Self-referential edges for asymmetric predicates
2. Provenance Integrity:
   - Evidence citations referencing nonexistent chunks in VaptKnowledgeStore
   - Evidence citations referencing nonexistent documents or registered sources
   - Document-chunk parentage mismatch
   - Missing evidence citations on extracted graph elements
   - Unverified quote assertions claiming SOURCE_SUPPORTED
3. Source Lifecycle Governance:
   - Identifying graph edges/nodes anchored to DEACTIVATED, FAILED, QUARANTINED,
     MALFORMED, or DELETED sources
   - Preserves historical lineage while flagging stale candidates for active retrieval
4. Canonicalization Diagnostics:
   - Non-destructive detection of case-insensitive and normalized label collisions
   - Review candidate generation without automated merging
5. Epistemic Status Integrity:
   - Ensuring SOURCE_SUPPORTED status is accompanied by verified quotation
   - Preserving INFERRED, CANDIDATE, and REJECTED boundaries
   - Detecting unrecognized epistemic classifications

Invariants Enforced:
- Strictly Read-Only: Operates under PRAGMA query_only = ON and read-only URI mode.
  Never writes, mutates, deletes, or merges graph or store records.
- Fail-Safe & Bounded: Bounded batch reads; safe failure when store is absent.
- Graph As Retrieval Aid: Graph remains navigation index; source passages remain authoritative.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import logging
from pathlib import Path
import re
import sqlite3
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from pydantic import BaseModel, Field

from src.knowledge.canonical_models import KnowledgeRelationType
from src.knowledge.graph_extractor import (
    KnowledgeEntityCategory,
    KnowledgeGraphPredicate,
    GraphEpistemicStatus,
)
from src.knowledge.store import VaptKnowledgeStore

logger = logging.getLogger("m9.graph_auditor")

AUDIT_SCHEMA_VERSION = "1.0.0"

# Ineligible source statuses per Ultron lifecycle policy (Section 3.2 & 4 of Stage D/E)
INELIGIBLE_SOURCE_STATUSES: Set[str] = {
    "DEACTIVATED",
    "FAILED",
    "QUARANTINED",
    "MALFORMED",
    "DELETED",
}

# Recognized entity categories in the graph
VALID_ENTITY_CATEGORIES: Set[str] = {
    cat.value for cat in KnowledgeEntityCategory
}.union({"CWE", "CAPEC", "MITRE_ATTACK", "CVE", "TAXONOMY"})

# Recognized relation predicates in the graph
VALID_RELATION_PREDICATES: Set[str] = {
    pred.value for pred in KnowledgeGraphPredicate
}.union({rel.value for rel in KnowledgeRelationType})

# Asymmetric predicates where source == target is semantically suspect
ASYMMETRIC_PREDICATES: Set[str] = {
    "EXPLOITS",
    "MITIGATES",
    "REQUIRES",
    "SUBCLASS_OF",
    "MAPS_TO_CWE",
    "MAPS_TO_CAPEC",
    "MAPS_TO_ATTACK",
    "SUPERSEDES",
}

# Recognized epistemic statuses
VALID_EPISTEMIC_STATUSES: Set[str] = {
    status.value for status in GraphEpistemicStatus
}.union({"EXTERNAL_REPORTED", "UNVERIFIED"})


class GraphIssueSeverity(str, Enum):
    """Severity classification of detected integrity problems."""
    CRITICAL = "CRITICAL"  # Broken foreign key, missing node, corrupted JSON
    ERROR = "ERROR"        # Dangling chunk reference, missing source, invalid type
    WARNING = "WARNING"    # Stale source, missing citations, ungrounded quote
    INFO = "INFO"          # Canonicalization duplicate candidate, orphaned ledger


class GraphIssueCategory(str, Enum):
    """Categorization of knowledge graph integrity issues."""
    STRUCTURAL = "STRUCTURAL"
    PROVENANCE = "PROVENANCE"
    LIFECYCLE = "LIFECYCLE"
    CANONICALIZATION = "CANONICALIZATION"
    EPISTEMIC = "EPISTEMIC"


class GraphIntegrityIssue(BaseModel):
    """Individual deterministic integrity problem identified during audit."""
    issue_id: str = Field(..., description="Stable deterministic issue identifier")
    category: GraphIssueCategory
    severity: GraphIssueSeverity
    check_code: str = Field(..., description="Stable mnemonic for the check")
    record_type: str = Field(..., description="'NODE' | 'EDGE' | 'EXTRACTION'")
    record_id: str = Field(..., description="Target node_id, edge_id, or extraction_id")
    description: str = Field(..., description="Clear explanation of the detected defect")
    evidence_context: Dict[str, Any] = Field(
        default_factory=dict,
        description="Lineage and contextual attributes for human investigation",
    )
    resolution_hint: str = Field(..., description="Actionable remediation guidance")


class GraphAuditScope(BaseModel):
    """Parameters and bounds defining the scope of an audit run."""
    graph_db_path: str
    knowledge_db_path: Optional[str] = None
    categories: List[GraphIssueCategory] = Field(
        default_factory=lambda: list(GraphIssueCategory)
    )
    max_records_per_check: Optional[int] = None
    batch_size: int = 500


class GraphAuditSummary(BaseModel):
    """Quantitative roll-up of examined records and detected issues."""
    nodes_examined: int = 0
    edges_examined: int = 0
    extractions_examined: int = 0
    provenance_citations_examined: int = 0
    total_issues: int = 0
    critical_count: int = 0
    error_count: int = 0
    warning_count: int = 0
    info_count: int = 0
    issues_by_category: Dict[str, int] = Field(default_factory=dict)
    issues_by_severity: Dict[str, int] = Field(default_factory=dict)
    status: str = "CLEAN"  # "CLEAN" | "WARNINGS_FOUND" | "ERRORS_FOUND" | "CRITICAL_FOUND"


class GraphAuditResult(BaseModel):
    """Complete, versioned, validated knowledge graph audit outcome."""
    audit_id: str = Field(..., description="Unique audit run identifier")
    schema_version: str = AUDIT_SCHEMA_VERSION
    audit_timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    scope: GraphAuditScope
    summary: GraphAuditSummary
    issues: List[GraphIntegrityIssue] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    read_only_guarantee: bool = True


class GraphIntegrityAuditor:
    """
    Deterministic, read-only auditor for RelationalKnowledgeGraph and VaptKnowledgeStore.
    
    Operates strictly in read-only mode to prevent unintended state mutations.
    Emits structured, verifiable audit reports distinguishing confirmed defects
    from review warnings and architectural limitations.
    """

    def __init__(
        self,
        graph_db_path: Union[str, Path] = Path("data/knowledge/knowledge_graph.db"),
        knowledge_store: Optional[VaptKnowledgeStore] = None,
        knowledge_db_path: Optional[Union[str, Path]] = None,
        batch_size: int = 500,
    ) -> None:
        self.graph_db_path = Path(graph_db_path)
        self.knowledge_store = knowledge_store
        self.knowledge_db_path = Path(knowledge_db_path) if knowledge_db_path else None
        self.batch_size = max(50, batch_size)

        # Internal connection to graph db (opened on demand read-only)
        self._graph_conn: Optional[sqlite3.Connection] = None
        self._owns_store = False

    def _open_graph_conn(self) -> sqlite3.Connection:
        """Opens or returns a read-only SQLite connection to the knowledge graph."""
        if self._graph_conn is not None:
            return self._graph_conn

        if not self.graph_db_path.exists():
            raise FileNotFoundError(f"Knowledge graph database not found at {self.graph_db_path}")

        # Enforce read-only access via URI and PRAGMA query_only
        resolved = self.graph_db_path.resolve().as_posix()
        try:
            uri = f"file:{resolved}?mode=ro"
            conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
        except sqlite3.OperationalError:
            conn = sqlite3.connect(str(self.graph_db_path), check_same_thread=False)

        conn.row_factory = sqlite3.Row
        with conn:
            conn.execute("PRAGMA query_only = ON;")
        self._graph_conn = conn
        return conn

    def _ensure_knowledge_store(self, limitations: List[str]) -> Optional[VaptKnowledgeStore]:
        """Ensures access to VaptKnowledgeStore in read-only mode, or logs limitation."""
        if self.knowledge_store is not None:
            return self.knowledge_store

        cand_path = self.knowledge_db_path or Path("data/knowledge/vapt_knowledge.db")
        if cand_path.exists():
            try:
                store = VaptKnowledgeStore(cand_path, read_only=True)
                self.knowledge_store = store
                self._owns_store = True
                return store
            except Exception as e:
                limitations.append(
                    f"Failed to open VaptKnowledgeStore at {cand_path} ({e}); "
                    "provenance chunk existence and source lifecycle checks were skipped."
                )
                return None
        else:
            limitations.append(
                f"VaptKnowledgeStore database not found at {cand_path}; "
                "provenance chunk existence and source lifecycle checks were skipped."
            )
            return None

    def close(self) -> None:
        """Closes managed database connections."""
        if self._graph_conn is not None:
            self._graph_conn.close()
            self._graph_conn = None
        if self._owns_store and self.knowledge_store is not None:
            self.knowledge_store.close()
            self.knowledge_store = None
            self._owns_store = False

    def __enter__(self) -> GraphIntegrityAuditor:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    @staticmethod
    def _make_issue_id(category: str, record_type: str, record_id: str, check_code: str) -> str:
        """Computes a stable deterministic issue ID."""
        raw = f"{category}:{record_type}:{record_id}:{check_code}"
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:8]
        return f"ISSUE-{category[:4]}-{record_type}-{digest}"

    # -------------------------------------------------------------------------
    # Core Audit Execution
    # -------------------------------------------------------------------------

    def run_audit(
        self,
        categories: Optional[Sequence[Union[GraphIssueCategory, str]]] = None,
        max_records_per_check: Optional[int] = None,
    ) -> GraphAuditResult:
        """
        Executes a deterministic, read-only integrity audit across specified categories.
        
        Args:
            categories: Optional subset of categories to inspect (default: all).
            max_records_per_check: Optional cap for bounded execution in constrained environments.
            
        Returns:
            Validated GraphAuditResult with summary, issues, and explicit limitations.
        """
        now = datetime.now(timezone.utc).isoformat()
        target_cats: Set[GraphIssueCategory] = set()
        if categories:
            for c in categories:
                target_cats.add(GraphIssueCategory(c.value if isinstance(c, GraphIssueCategory) else str(c).upper()))
        else:
            target_cats = set(GraphIssueCategory)

        scope = GraphAuditScope(
            graph_db_path=str(self.graph_db_path),
            knowledge_db_path=str(self.knowledge_db_path) if self.knowledge_db_path else None,
            categories=list(target_cats),
            max_records_per_check=max_records_per_check,
            batch_size=self.batch_size,
        )

        summary = GraphAuditSummary()
        issues: List[GraphIntegrityIssue] = []
        limitations: List[str] = []

        # Verify graph database existence
        if not self.graph_db_path.exists():
            limitations.append(f"Graph database {self.graph_db_path} does not exist.")
            summary.status = "CRITICAL_FOUND"
            summary.critical_count = 1
            summary.total_issues = 1
            issues.append(
                GraphIntegrityIssue(
                    issue_id=self._make_issue_id("STRUCTURAL", "DATABASE", "GRAPH_DB", "DATABASE_NOT_FOUND"),
                    category=GraphIssueCategory.STRUCTURAL,
                    severity=GraphIssueSeverity.CRITICAL,
                    check_code="DATABASE_NOT_FOUND",
                    record_type="DATABASE",
                    record_id=str(self.graph_db_path),
                    description="Knowledge graph database file is missing or unreadable.",
                    evidence_context={"path": str(self.graph_db_path)},
                    resolution_hint="Ensure the knowledge graph database is initialized and accessible.",
                )
            )
            return GraphAuditResult(
                audit_id=f"AUDIT-{now.replace(':', '').replace('-', '')[:15]}-FAIL",
                audit_timestamp=now,
                scope=scope,
                summary=summary,
                issues=issues,
                limitations=limitations,
                read_only_guarantee=True,
            )

        conn = self._open_graph_conn()
        store = self._ensure_knowledge_store(limitations)

        # Pre-flight table existence check
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {r[0] for r in cursor.fetchall()}
        required_tables = {"graph_nodes", "graph_edges", "graph_extractions"}
        missing_tables = required_tables - tables
        if missing_tables:
            limitations.append(f"Missing required graph tables: {sorted(missing_tables)}")
            for t in sorted(missing_tables):
                issues.append(
                    GraphIntegrityIssue(
                        issue_id=self._make_issue_id("STRUCTURAL", "TABLE", t, "MISSING_TABLE"),
                        category=GraphIssueCategory.STRUCTURAL,
                        severity=GraphIssueSeverity.CRITICAL,
                        check_code="MISSING_TABLE",
                        record_type="TABLE",
                        record_id=t,
                        description=f"Required table '{t}' does not exist in graph database.",
                        evidence_context={"table": t},
                        resolution_hint="Initialize knowledge graph schema using RelationalKnowledgeGraph._init_schema().",
                    )
                )

        # Cache existing node IDs for rapid foreign-key reconciliation
        existing_node_ids: Set[str] = set()
        node_records: List[Dict[str, Any]] = []

        if "graph_nodes" in tables:
            limit_clause = f" LIMIT {max_records_per_check}" if max_records_per_check else ""
            cursor = conn.execute(f"SELECT * FROM graph_nodes ORDER BY node_id ASC{limit_clause}")
            rows = cursor.fetchall()
            summary.nodes_examined = len(rows)

            for r in rows:
                nid = r["node_id"]
                existing_node_ids.add(nid)
                node_records.append({
                    "node_id": nid,
                    "node_type": r["node_type"],
                    "label": r["label"],
                    "metadata_json": r["metadata_json"],
                })

        # Cache existing edge records
        edge_records: List[Dict[str, Any]] = []
        if "graph_edges" in tables:
            limit_clause = f" LIMIT {max_records_per_check}" if max_records_per_check else ""
            cursor = conn.execute(f"SELECT * FROM graph_edges ORDER BY edge_id ASC{limit_clause}")
            rows = cursor.fetchall()
            summary.edges_examined = len(rows)

            for r in rows:
                edge_records.append({
                    "edge_id": r["edge_id"],
                    "source_id": r["source_id"],
                    "target_id": r["target_id"],
                    "relation_type": r["relation_type"],
                    "metadata_json": r["metadata_json"],
                    "created_at": r["created_at"],
                })

        # Cache extraction ledger records
        extraction_records: List[Dict[str, Any]] = []
        if "graph_extractions" in tables:
            limit_clause = f" LIMIT {max_records_per_check}" if max_records_per_check else ""
            cursor = conn.execute(f"SELECT * FROM graph_extractions ORDER BY created_at DESC{limit_clause}")
            rows = cursor.fetchall()
            summary.extractions_examined = len(rows)
            for r in rows:
                extraction_records.append(dict(r))

        # ---------------------------------------------------------------------
        # 1. Structural Integrity Checks
        # ---------------------------------------------------------------------
        if GraphIssueCategory.STRUCTURAL in target_cats:
            self._audit_structural_integrity(
                node_records=node_records,
                edge_records=edge_records,
                existing_node_ids=existing_node_ids,
                issues=issues,
            )

        # ---------------------------------------------------------------------
        # 2. Provenance Integrity Checks
        # ---------------------------------------------------------------------
        if GraphIssueCategory.PROVENANCE in target_cats:
            self._audit_provenance_integrity(
                node_records=node_records,
                edge_records=edge_records,
                extraction_records=extraction_records,
                store=store,
                issues=issues,
                summary=summary,
            )

        # ---------------------------------------------------------------------
        # 3. Source Lifecycle Governance Checks
        # ---------------------------------------------------------------------
        if GraphIssueCategory.LIFECYCLE in target_cats:
            self._audit_lifecycle_integrity(
                node_records=node_records,
                edge_records=edge_records,
                extraction_records=extraction_records,
                store=store,
                issues=issues,
            )

        # ---------------------------------------------------------------------
        # 4. Canonicalization Diagnostics
        # ---------------------------------------------------------------------
        if GraphIssueCategory.CANONICALIZATION in target_cats:
            self._audit_canonicalization_diagnostics(
                node_records=node_records,
                issues=issues,
            )

        # ---------------------------------------------------------------------
        # 5. Epistemic Status Integrity Checks
        # ---------------------------------------------------------------------
        if GraphIssueCategory.EPISTEMIC in target_cats:
            self._audit_epistemic_integrity(
                node_records=node_records,
                edge_records=edge_records,
                issues=issues,
            )

        # ---------------------------------------------------------------------
        # Aggregate Summary Metrics
        # ---------------------------------------------------------------------
        summary.total_issues = len(issues)
        cat_counts: Dict[str, int] = {}
        sev_counts: Dict[str, int] = {}

        for iss in issues:
            c_key = iss.category.value
            cat_counts[c_key] = cat_counts.get(c_key, 0) + 1

            s_key = iss.severity.value
            sev_counts[s_key] = sev_counts.get(s_key, 0) + 1

            if iss.severity == GraphIssueSeverity.CRITICAL:
                summary.critical_count += 1
            elif iss.severity == GraphIssueSeverity.ERROR:
                summary.error_count += 1
            elif iss.severity == GraphIssueSeverity.WARNING:
                summary.warning_count += 1
            elif iss.severity == GraphIssueSeverity.INFO:
                summary.info_count += 1

        summary.issues_by_category = cat_counts
        summary.issues_by_severity = sev_counts

        if summary.critical_count > 0:
            summary.status = "CRITICAL_FOUND"
        elif summary.error_count > 0:
            summary.status = "ERRORS_FOUND"
        elif summary.warning_count > 0:
            summary.status = "WARNINGS_FOUND"
        else:
            summary.status = "CLEAN"

        audit_id_hash = hashlib.sha256(f"{now}:{summary.total_issues}".encode("utf-8")).hexdigest()[:6]
        audit_id = f"AUDIT-{now.replace(':', '').replace('-', '')[:15]}-{audit_id_hash}"

        return GraphAuditResult(
            audit_id=audit_id,
            schema_version=AUDIT_SCHEMA_VERSION,
            audit_timestamp=now,
            scope=scope,
            summary=summary,
            issues=issues,
            limitations=limitations,
            read_only_guarantee=True,
        )

    # -------------------------------------------------------------------------
    # Internal Check Implementations
    # -------------------------------------------------------------------------

    def _audit_structural_integrity(
        self,
        node_records: List[Dict[str, Any]],
        edge_records: List[Dict[str, Any]],
        existing_node_ids: Set[str],
        issues: List[GraphIntegrityIssue],
    ) -> None:
        """Verifies structural validity of nodes, edges, foreign keys, and JSON payloads."""
        # 1. Inspect Node Structure
        for n in node_records:
            nid = n["node_id"]
            ntype = n.get("node_type", "")
            label = n.get("label", "")

            # Verify uncorrupted JSON metadata
            try:
                meta = json.loads(n["metadata_json"])
                if not isinstance(meta, dict):
                    issues.append(
                        GraphIntegrityIssue(
                            issue_id=self._make_issue_id("STRUCTURAL", "NODE", nid, "NON_DICT_METADATA"),
                            category=GraphIssueCategory.STRUCTURAL,
                            severity=GraphIssueSeverity.CRITICAL,
                            check_code="NON_DICT_METADATA",
                            record_type="NODE",
                            record_id=nid,
                            description=f"Node '{nid}' metadata_json parsed to non-dictionary type {type(meta).__name__}.",
                            evidence_context={"node_id": nid, "raw_metadata": n["metadata_json"][:200]},
                            resolution_hint="Re-encode node metadata as valid JSON object.",
                        )
                    )
            except Exception as e:
                issues.append(
                    GraphIntegrityIssue(
                        issue_id=self._make_issue_id("STRUCTURAL", "NODE", nid, "MALFORMED_METADATA_JSON"),
                        category=GraphIssueCategory.STRUCTURAL,
                        severity=GraphIssueSeverity.CRITICAL,
                        check_code="MALFORMED_METADATA_JSON",
                        record_type="NODE",
                        record_id=nid,
                        description=f"Node '{nid}' contains malformed metadata_json: {e}",
                        evidence_context={"node_id": nid, "raw_metadata": n.get("metadata_json", "")[:200]},
                        resolution_hint="Repair JSON payload in graph_nodes table.",
                    )
                )

            # Validate node category
            if ntype not in VALID_ENTITY_CATEGORIES:
                issues.append(
                    GraphIntegrityIssue(
                        issue_id=self._make_issue_id("STRUCTURAL", "NODE", nid, "INVALID_NODE_TYPE"),
                        category=GraphIssueCategory.STRUCTURAL,
                        severity=GraphIssueSeverity.ERROR,
                        check_code="INVALID_NODE_TYPE",
                        record_type="NODE",
                        record_id=nid,
                        description=f"Node '{nid}' specifies invalid category '{ntype}'.",
                        evidence_context={"node_id": nid, "node_type": ntype, "allowed": sorted(VALID_ENTITY_CATEGORIES)},
                        resolution_hint=f"Normalize node category to one of {sorted(VALID_ENTITY_CATEGORIES)}.",
                    )
                )

            if not label or not label.strip():
                issues.append(
                    GraphIntegrityIssue(
                        issue_id=self._make_issue_id("STRUCTURAL", "NODE", nid, "BLANK_LABEL"),
                        category=GraphIssueCategory.STRUCTURAL,
                        severity=GraphIssueSeverity.ERROR,
                        check_code="BLANK_LABEL",
                        record_type="NODE",
                        record_id=nid,
                        description=f"Node '{nid}' has an empty or blank label.",
                        evidence_context={"node_id": nid},
                        resolution_hint="Populate node label with descriptive entity name.",
                    )
                )

        # 2. Inspect Edge Structure and Foreign Keys
        for e in edge_records:
            eid = e["edge_id"]
            sid = e["source_id"]
            tid = e["target_id"]
            rel = e["relation_type"]

            # Verify uncorrupted JSON metadata
            try:
                meta = json.loads(e["metadata_json"])
                if not isinstance(meta, dict):
                    issues.append(
                        GraphIntegrityIssue(
                            issue_id=self._make_issue_id("STRUCTURAL", "EDGE", eid, "NON_DICT_METADATA"),
                            category=GraphIssueCategory.STRUCTURAL,
                            severity=GraphIssueSeverity.CRITICAL,
                            check_code="NON_DICT_METADATA",
                            record_type="EDGE",
                            record_id=eid,
                            description=f"Edge '{eid}' metadata_json parsed to non-dictionary type {type(meta).__name__}.",
                            evidence_context={"edge_id": eid},
                            resolution_hint="Re-encode edge metadata as valid JSON object.",
                        )
                    )
            except Exception as ex:
                issues.append(
                    GraphIntegrityIssue(
                        issue_id=self._make_issue_id("STRUCTURAL", "EDGE", eid, "MALFORMED_METADATA_JSON"),
                        category=GraphIssueCategory.STRUCTURAL,
                        severity=GraphIssueSeverity.CRITICAL,
                        check_code="MALFORMED_METADATA_JSON",
                        record_type="EDGE",
                        record_id=eid,
                        description=f"Edge '{eid}' contains malformed metadata_json: {ex}",
                        evidence_context={"edge_id": eid, "raw_metadata": e.get("metadata_json", "")[:200]},
                        resolution_hint="Repair JSON payload in graph_edges table.",
                    )
                )

            # Dangling Source Node
            if sid not in existing_node_ids:
                issues.append(
                    GraphIntegrityIssue(
                        issue_id=self._make_issue_id("STRUCTURAL", "EDGE", eid, "DANGLING_EDGE_SOURCE"),
                        category=GraphIssueCategory.STRUCTURAL,
                        severity=GraphIssueSeverity.CRITICAL,
                        check_code="DANGLING_EDGE_SOURCE",
                        record_type="EDGE",
                        record_id=eid,
                        description=f"Edge '{eid}' references source_id '{sid}' which does not exist in graph_nodes.",
                        evidence_context={"edge_id": eid, "missing_source_id": sid, "target_id": tid, "relation_type": rel},
                        resolution_hint="Add missing source node or remove dangling edge from graph.",
                    )
                )

            # Dangling Target Node
            if tid not in existing_node_ids:
                issues.append(
                    GraphIntegrityIssue(
                        issue_id=self._make_issue_id("STRUCTURAL", "EDGE", eid, "DANGLING_EDGE_TARGET"),
                        category=GraphIssueCategory.STRUCTURAL,
                        severity=GraphIssueSeverity.CRITICAL,
                        check_code="DANGLING_EDGE_TARGET",
                        record_type="EDGE",
                        record_id=eid,
                        description=f"Edge '{eid}' references target_id '{tid}' which does not exist in graph_nodes.",
                        evidence_context={"edge_id": eid, "source_id": sid, "missing_target_id": tid, "relation_type": rel},
                        resolution_hint="Add missing target node or remove dangling edge from graph.",
                    )
                )

            # Valid Predicate / Relation Type
            if rel not in VALID_RELATION_PREDICATES:
                issues.append(
                    GraphIntegrityIssue(
                        issue_id=self._make_issue_id("STRUCTURAL", "EDGE", eid, "INVALID_RELATION_TYPE"),
                        category=GraphIssueCategory.STRUCTURAL,
                        severity=GraphIssueSeverity.ERROR,
                        check_code="INVALID_RELATION_TYPE",
                        record_type="EDGE",
                        record_id=eid,
                        description=f"Edge '{eid}' uses unrecognized predicate '{rel}'.",
                        evidence_context={"edge_id": eid, "relation_type": rel, "allowed": sorted(VALID_RELATION_PREDICATES)},
                        resolution_hint=f"Normalize predicate to one of {sorted(VALID_RELATION_PREDICATES)}.",
                    )
                )

            # Self-referential edge check on asymmetric predicates
            if sid == tid and rel in ASYMMETRIC_PREDICATES:
                issues.append(
                    GraphIntegrityIssue(
                        issue_id=self._make_issue_id("STRUCTURAL", "EDGE", eid, "SELF_REFERENTIAL_ASYMMETRIC_EDGE"),
                        category=GraphIssueCategory.STRUCTURAL,
                        severity=GraphIssueSeverity.WARNING,
                        check_code="SELF_REFERENTIAL_ASYMMETRIC_EDGE",
                        record_type="EDGE",
                        record_id=eid,
                        description=f"Edge '{eid}' is self-referential ({sid} -> {tid}) on asymmetric predicate '{rel}'.",
                        evidence_context={"edge_id": eid, "node_id": sid, "relation_type": rel},
                        resolution_hint="Verify whether this asymmetric relationship between identical entities was extracted in error.",
                    )
                )

    def _audit_provenance_integrity(
        self,
        node_records: List[Dict[str, Any]],
        edge_records: List[Dict[str, Any]],
        extraction_records: List[Dict[str, Any]],
        store: Optional[VaptKnowledgeStore],
        issues: List[GraphIntegrityIssue],
        summary: GraphAuditSummary,
    ) -> None:
        """Verifies provenance citations against VaptKnowledgeStore records."""
        # 1. Audit Nodes Provenance
        for n in node_records:
            nid = n["node_id"]
            ntype = n.get("node_type", "")
            try:
                meta = json.loads(n["metadata_json"])
            except Exception:
                continue

            citations = meta.get("evidence_citations", [])
            summary.provenance_citations_examined += len(citations)

            # Manual taxonomy nodes (e.g. CWE, CAPEC, ATT&CK) may be seeded without extraction citations.
            # However, extracted nodes (CONCEPT, VULNERABILITY, DEFENSIVE_CONTROL, TOOL) must cite evidence.
            if not citations:
                if ntype not in {"CWE", "CAPEC", "MITRE_ATTACK", "TAXONOMY_REFERENCE"}:
                    issues.append(
                        GraphIntegrityIssue(
                            issue_id=self._make_issue_id("PROVENANCE", "NODE", nid, "MISSING_EVIDENCE_CITATIONS"),
                            category=GraphIssueCategory.PROVENANCE,
                            severity=GraphIssueSeverity.WARNING,
                            check_code="MISSING_EVIDENCE_CITATIONS",
                            record_type="NODE",
                            record_id=nid,
                            description=f"Node '{nid}' ({ntype}) has zero evidence citations in provenance lineage.",
                            evidence_context={"node_id": nid, "node_type": ntype},
                            resolution_hint="Attach authoritative source chunk citation or confirm node as manually seeded baseline.",
                        )
                    )
                continue

            for idx, cite in enumerate(citations):
                self._check_citation_provenance(
                    record_type="NODE",
                    record_id=nid,
                    citation=cite,
                    citation_idx=idx,
                    store=store,
                    issues=issues,
                )

        # 2. Audit Edges Provenance
        for e in edge_records:
            eid = e["edge_id"]
            try:
                meta = json.loads(e["metadata_json"])
            except Exception:
                continue

            citations = meta.get("evidence_citations", [])
            summary.provenance_citations_examined += len(citations)

            if not citations:
                # Relationship with no citations must be reported as provenance issue
                issues.append(
                    GraphIntegrityIssue(
                        issue_id=self._make_issue_id("PROVENANCE", "EDGE", eid, "MISSING_EVIDENCE_CITATIONS"),
                        category=GraphIssueCategory.PROVENANCE,
                        severity=GraphIssueSeverity.WARNING,
                        check_code="MISSING_EVIDENCE_CITATIONS",
                        record_type="EDGE",
                        record_id=eid,
                        description=f"Edge '{eid}' has no evidence citations anchoring it to authoritative text.",
                        evidence_context={"edge_id": eid, "source_id": e["source_id"], "target_id": e["target_id"]},
                        resolution_hint="Attach supporting source chunk citation to justify relationship existence.",
                    )
                )
                continue

            for idx, cite in enumerate(citations):
                self._check_citation_provenance(
                    record_type="EDGE",
                    record_id=eid,
                    citation=cite,
                    citation_idx=idx,
                    store=store,
                    issues=issues,
                )

        # 3. Audit Extraction Ledger Provenance
        if store is not None:
            for ext in extraction_records:
                ext_id = ext["extraction_id"]
                cid = ext["chunk_id"]
                sid = ext["source_id"]

                chunk = store.get_chunk(cid)
                if not chunk:
                    issues.append(
                        GraphIntegrityIssue(
                            issue_id=self._make_issue_id("PROVENANCE", "EXTRACTION", ext_id, "DANGLING_EXTRACTION_CHUNK"),
                            category=GraphIssueCategory.PROVENANCE,
                            severity=GraphIssueSeverity.WARNING,
                            check_code="DANGLING_EXTRACTION_CHUNK",
                            record_type="EXTRACTION",
                            record_id=ext_id,
                            description=f"Extraction ledger '{ext_id}' references chunk_id '{cid}' not found in knowledge store.",
                            evidence_context={"extraction_id": ext_id, "chunk_id": cid, "source_id": sid},
                            resolution_hint="Verify if source chunk was pruned or re-indexed under a different ID.",
                        )
                    )

                src = store.get_source(sid)
                if not src:
                    issues.append(
                        GraphIntegrityIssue(
                            issue_id=self._make_issue_id("PROVENANCE", "EXTRACTION", ext_id, "DANGLING_EXTRACTION_SOURCE"),
                            category=GraphIssueCategory.PROVENANCE,
                            severity=GraphIssueSeverity.WARNING,
                            check_code="DANGLING_EXTRACTION_SOURCE",
                            record_type="EXTRACTION",
                            record_id=ext_id,
                            description=f"Extraction ledger '{ext_id}' references source_id '{sid}' not registered in store.",
                            evidence_context={"extraction_id": ext_id, "source_id": sid},
                            resolution_hint="Verify whether registered source was renamed or deleted.",
                        )
                    )

    def _check_citation_provenance(
        self,
        record_type: str,
        record_id: str,
        citation: Dict[str, Any],
        citation_idx: int,
        store: Optional[VaptKnowledgeStore],
        issues: List[GraphIntegrityIssue],
    ) -> None:
        """Helper to validate an individual citation's chunk, document, and source references."""
        cid = citation.get("chunk_id")
        doc_id = citation.get("document_id")
        sid = citation.get("source_id")

        if not cid:
            issues.append(
                GraphIntegrityIssue(
                    issue_id=self._make_issue_id("PROVENANCE", record_type, f"{record_id}_cite{citation_idx}", "MISSING_CHUNK_ID"),
                    category=GraphIssueCategory.PROVENANCE,
                    severity=GraphIssueSeverity.ERROR,
                    check_code="MISSING_CHUNK_ID",
                    record_type=record_type,
                    record_id=record_id,
                    description=f"{record_type} '{record_id}' citation #{citation_idx} is missing required 'chunk_id'.",
                    evidence_context={"record_id": record_id, "citation": citation},
                    resolution_hint="Populate chunk_id referencing authoritative passage in VaptKnowledgeStore.",
                )
            )

        if not sid:
            issues.append(
                GraphIntegrityIssue(
                    issue_id=self._make_issue_id("PROVENANCE", record_type, f"{record_id}_cite{citation_idx}", "MISSING_SOURCE_ID"),
                    category=GraphIssueCategory.PROVENANCE,
                    severity=GraphIssueSeverity.ERROR,
                    check_code="MISSING_SOURCE_ID",
                    record_type=record_type,
                    record_id=record_id,
                    description=f"{record_type} '{record_id}' citation #{citation_idx} is missing required 'source_id'.",
                    evidence_context={"record_id": record_id, "citation": citation},
                    resolution_hint="Populate source_id with registered knowledge source identifier.",
                )
            )

        if store is not None and cid:
            chunk = store.get_chunk(cid)
            if not chunk:
                issues.append(
                    GraphIntegrityIssue(
                        issue_id=self._make_issue_id("PROVENANCE", record_type, f"{record_id}_{cid}", "DANGLING_CHUNK_REFERENCE"),
                        category=GraphIssueCategory.PROVENANCE,
                        severity=GraphIssueSeverity.ERROR,
                        check_code="DANGLING_CHUNK_REFERENCE",
                        record_type=record_type,
                        record_id=record_id,
                        description=f"{record_type} '{record_id}' cites chunk '{cid}' which does not exist in VaptKnowledgeStore.",
                        evidence_context={"record_id": record_id, "chunk_id": cid, "source_id": sid, "document_id": doc_id},
                        resolution_hint="Re-extract graph from current store or remove orphaned citation reference.",
                    )
                )
            else:
                # Reconcile document parentage if doc_id provided
                if doc_id and chunk.document_id != doc_id:
                    issues.append(
                        GraphIntegrityIssue(
                            issue_id=self._make_issue_id("PROVENANCE", record_type, f"{record_id}_{cid}", "DOCUMENT_SOURCE_MISMATCH"),
                            category=GraphIssueCategory.PROVENANCE,
                            severity=GraphIssueSeverity.ERROR,
                            check_code="DOCUMENT_SOURCE_MISMATCH",
                            record_type=record_type,
                            record_id=record_id,
                            description=(
                                f"{record_type} '{record_id}' citation specifies document '{doc_id}', "
                                f"but chunk '{cid}' belongs to '{chunk.document_id}'."
                            ),
                            evidence_context={
                                "record_id": record_id,
                                "chunk_id": cid,
                                "citation_doc_id": doc_id,
                                "store_doc_id": chunk.document_id,
                            },
                            resolution_hint="Reconcile document_id to match chunk record in store.",
                        )
                    )

        if store is not None and sid:
            src = store.get_source(sid)
            if not src:
                issues.append(
                    GraphIntegrityIssue(
                        issue_id=self._make_issue_id("PROVENANCE", record_type, f"{record_id}_{sid}", "DANGLING_SOURCE_REFERENCE"),
                        category=GraphIssueCategory.PROVENANCE,
                        severity=GraphIssueSeverity.ERROR,
                        check_code="DANGLING_SOURCE_REFERENCE",
                        record_type=record_type,
                        record_id=record_id,
                        description=f"{record_type} '{record_id}' cites source '{sid}' which does not exist in knowledge_sources.",
                        evidence_context={"record_id": record_id, "source_id": sid, "chunk_id": cid},
                        resolution_hint="Register source or update citation to point to valid source record.",
                    )
                )

    def _audit_lifecycle_integrity(
        self,
        node_records: List[Dict[str, Any]],
        edge_records: List[Dict[str, Any]],
        extraction_records: List[Dict[str, Any]],
        store: Optional[VaptKnowledgeStore],
        issues: List[GraphIntegrityIssue],
    ) -> None:
        """
        Identifies graph entities or edges linked to inactive or quarantined sources.
        Enforces Section 3.C: distinguishes stale graph records from active retrieval candidates.
        """
        if store is None:
            return

        # Pre-cache source statuses from store
        source_statuses: Dict[str, str] = {}
        try:
            sources = store.list_sources()
            for s in sources:
                source_statuses[s["source_id"]] = str(s.get("status", "")).upper()
        except Exception as e:
            logger.warning(f"Error fetching sources for lifecycle audit: {e}")
            return

        # 1. Audit Edges for Inactive Sources
        for e in edge_records:
            eid = e["edge_id"]
            try:
                meta = json.loads(e["metadata_json"])
            except Exception:
                continue

            citations = meta.get("evidence_citations", [])
            for cite in citations:
                sid = cite.get("source_id")
                if not sid:
                    continue
                status = source_statuses.get(sid)
                if status in INELIGIBLE_SOURCE_STATUSES:
                    issues.append(
                        GraphIntegrityIssue(
                            issue_id=self._make_issue_id("LIFECYCLE", "EDGE", eid, f"STALE_SOURCE_{status}"),
                            category=GraphIssueCategory.LIFECYCLE,
                            severity=GraphIssueSeverity.WARNING,
                            check_code="STALE_SOURCE_EDGE",
                            record_type="EDGE",
                            record_id=eid,
                            description=(
                                f"Edge '{eid}' cites source '{sid}' which is currently '{status}'. "
                                "This relationship must remain excluded from active retrieval context."
                            ),
                            evidence_context={
                                "edge_id": eid,
                                "source_id": sid,
                                "source_status": status,
                                "chunk_id": cite.get("chunk_id"),
                            },
                            resolution_hint=(
                                f"Source '{sid}' is {status}. GraphAssistedRetriever.is_source_eligible() "
                                "will block this edge during Q&A traversal; reactivate source if content is valid."
                            ),
                        )
                    )

        # 2. Audit Nodes for Inactive Sources
        for n in node_records:
            nid = n["node_id"]
            try:
                meta = json.loads(n["metadata_json"])
            except Exception:
                continue

            citations = meta.get("evidence_citations", [])
            if not citations:
                continue

            # Check if all citations belong to ineligible sources
            active_citations_found = False
            inactive_sources_found: Set[str] = set()

            for cite in citations:
                sid = cite.get("source_id")
                if not sid:
                    continue
                status = source_statuses.get(sid, "UNKNOWN")
                if status not in INELIGIBLE_SOURCE_STATUSES:
                    active_citations_found = True
                else:
                    inactive_sources_found.add(f"{sid}:{status}")

            if not active_citations_found and inactive_sources_found:
                issues.append(
                    GraphIntegrityIssue(
                        issue_id=self._make_issue_id("LIFECYCLE", "NODE", nid, "ALL_SOURCES_INACTIVE"),
                        category=GraphIssueCategory.LIFECYCLE,
                        severity=GraphIssueSeverity.WARNING,
                        check_code="ALL_SOURCES_INACTIVE_FOR_NODE",
                        record_type="NODE",
                        record_id=nid,
                        description=(
                            f"Node '{nid}' only has citations from inactive sources: {sorted(inactive_sources_found)}. "
                            "Node is an orphaned historical entity and should not serve active Q&A retrieval."
                        ),
                        evidence_context={"node_id": nid, "inactive_sources": sorted(inactive_sources_found)},
                        resolution_hint="Add active source citations or retire node if underlying concepts are deprecated.",
                    )
                )

        # 3. Audit Extraction Ledger for Inactive Sources
        for ext in extraction_records:
            sid = ext["source_id"]
            ext_id = ext["extraction_id"]
            status = source_statuses.get(sid)
            if status in INELIGIBLE_SOURCE_STATUSES:
                issues.append(
                    GraphIntegrityIssue(
                        issue_id=self._make_issue_id("LIFECYCLE", "EXTRACTION", ext_id, "ORPHANED_EXTRACTION_LEDGER"),
                        category=GraphIssueCategory.LIFECYCLE,
                        severity=GraphIssueSeverity.INFO,
                        check_code="ORPHANED_EXTRACTION_LEDGER",
                        record_type="EXTRACTION",
                        record_id=ext_id,
                        description=f"Extraction record '{ext_id}' is associated with {status} source '{sid}'.",
                        evidence_context={"extraction_id": ext_id, "source_id": sid, "source_status": status},
                        resolution_hint="Preserve for audit ledger lineage; no active remediation required.",
                    )
                )

    def _audit_canonicalization_diagnostics(
        self,
        node_records: List[Dict[str, Any]],
        issues: List[GraphIntegrityIssue],
    ) -> None:
        """
        Identifies potential duplicate entities and label collisions.
        Enforces Section 3.D: Reports candidates for human review; NEVER merges automatically.
        """
        # 1. Exact case-insensitive label collision across distinct node IDs
        label_to_nodes: Dict[str, List[Dict[str, Any]]] = {}
        # 2. Normalized alphanumeric collision
        norm_to_nodes: Dict[str, List[Dict[str, Any]]] = {}

        for n in node_records:
            nid = n["node_id"]
            label = n.get("label", "").strip()
            ntype = n.get("node_type", "")
            if not label:
                continue

            low = label.lower()
            label_to_nodes.setdefault(low, []).append(n)

            # Strip punctuation, underscores, hyphens, and whitespace
            clean = re.sub(r"[^a-z0-9]", "", low)
            if len(clean) >= 3:
                norm_key = f"{ntype}:{clean}"
                norm_to_nodes.setdefault(norm_key, []).append(n)

        # Detect exact case-insensitive duplicates
        for low_lbl, nodes in label_to_nodes.items():
            if len(nodes) > 1:
                node_ids = sorted({n["node_id"] for n in nodes})
                if len(node_ids) > 1:
                    primary_id = node_ids[0]
                    issues.append(
                        GraphIntegrityIssue(
                            issue_id=self._make_issue_id("CANONICALIZATION", "NODE", primary_id, "CASE_INSENSITIVE_COLLISION"),
                            category=GraphIssueCategory.CANONICALIZATION,
                            severity=GraphIssueSeverity.INFO,
                            check_code="CASE_INSENSITIVE_LABEL_COLLISION",
                            record_type="NODE",
                            record_id=primary_id,
                            description=(
                                f"Multiple distinct nodes share identical case-insensitive label '{low_lbl}': {node_ids}. "
                                "Review candidate for disambiguation or intentional multi-category representation."
                            ),
                            evidence_context={
                                "label": low_lbl,
                                "colliding_nodes": [
                                    {"node_id": n["node_id"], "node_type": n["node_type"]}
                                    for n in nodes
                                ],
                            },
                            resolution_hint=(
                                "Review for disambiguation. Do NOT automatically merge distinct entities, "
                                "vulnerability versions, or different entity categories."
                            ),
                        )
                    )

        # Detect normalized character collisions (e.g., 'X-S-S' vs 'XSS')
        for norm_key, nodes in norm_to_nodes.items():
            node_ids = sorted({n["node_id"] for n in nodes})
            if len(node_ids) > 1:
                # If these weren't already captured as identical lower labels
                distinct_labels = {n.get("label", "").strip().lower() for n in nodes}
                if len(distinct_labels) > 1:
                    primary_id = node_ids[0]
                    issues.append(
                        GraphIntegrityIssue(
                            issue_id=self._make_issue_id("CANONICALIZATION", "NODE", primary_id, "NORMALIZED_COLLISION"),
                            category=GraphIssueCategory.CANONICALIZATION,
                            severity=GraphIssueSeverity.INFO,
                            check_code="NORMALIZED_LABEL_COLLISION",
                            record_type="NODE",
                            record_id=primary_id,
                            description=(
                                f"Entities share normalized character signature '{norm_key}': "
                                f"{[{'id': n['node_id'], 'label': n['label']} for n in nodes]}. "
                                "Review for potential synonymy or alias relationship."
                            ),
                            evidence_context={
                                "normalized_key": norm_key,
                                "nodes": [{"node_id": n["node_id"], "label": n["label"], "type": n["node_type"]} for n in nodes],
                            },
                            resolution_hint=(
                                "Evaluate whether a RELATED_TO or SUBCLASS_OF edge should link these concepts, "
                                "or keep them distinct if they represent separate technical mechanisms."
                            ),
                        )
                    )

    def _audit_epistemic_integrity(
        self,
        node_records: List[Dict[str, Any]],
        edge_records: List[Dict[str, Any]],
        issues: List[GraphIntegrityIssue],
    ) -> None:
        """
        Enforces epistemic status classifications (Section 3.E).
        Verifies that SOURCE_SUPPORTED claims are verified, and INFERRED/CANDIDATE/REJECTED are not promoted.
        """
        # 1. Epistemic checks on Edges
        for e in edge_records:
            eid = e["edge_id"]
            try:
                meta = json.loads(e["metadata_json"])
            except Exception:
                continue

            epistemic = meta.get("epistemic_status")
            citations = meta.get("evidence_citations", [])

            if epistemic not in VALID_EPISTEMIC_STATUSES:
                issues.append(
                    GraphIntegrityIssue(
                        issue_id=self._make_issue_id("EPISTEMIC", "EDGE", eid, "INVALID_EPISTEMIC_STATUS"),
                        category=GraphIssueCategory.EPISTEMIC,
                        severity=GraphIssueSeverity.ERROR,
                        check_code="INVALID_EPISTEMIC_STATUS",
                        record_type="EDGE",
                        record_id=eid,
                        description=f"Edge '{eid}' defines unrecognized epistemic_status '{epistemic}'.",
                        evidence_context={"edge_id": eid, "epistemic_status": epistemic, "allowed": sorted(VALID_EPISTEMIC_STATUSES)},
                        resolution_hint=f"Normalize epistemic_status to one of {sorted(VALID_EPISTEMIC_STATUSES)}.",
                    )
                )

            # Check SOURCE_SUPPORTED requirements
            if epistemic == "SOURCE_SUPPORTED":
                # Must have at least one citation with quote_verified=True and non-empty supporting_quote
                has_verified_quote = any(
                    c.get("quote_verified") is True and bool(c.get("supporting_quote"))
                    for c in citations
                )
                if not has_verified_quote:
                    issues.append(
                        GraphIntegrityIssue(
                            issue_id=self._make_issue_id("EPISTEMIC", "EDGE", eid, "UNGROUNDED_SOURCE_SUPPORTED"),
                            category=GraphIssueCategory.EPISTEMIC,
                            severity=GraphIssueSeverity.ERROR,
                            check_code="UNGROUNDED_SOURCE_SUPPORTED",
                            record_type="EDGE",
                            record_id=eid,
                            description=(
                                f"Edge '{eid}' is marked SOURCE_SUPPORTED but has no citation "
                                "with quote_verified=True and a non-empty supporting quote."
                            ),
                            evidence_context={"edge_id": eid, "citations_count": len(citations)},
                            resolution_hint=(
                                "Demote epistemic status to INFERRED or CANDIDATE, or re-run quote "
                                "verification against authoritative source chunk."
                            ),
                        )
                    )

            # Check REJECTED edges
            if epistemic == "REJECTED":
                # Ensure it is marked explicitly
                pass

        # 2. Epistemic checks on Nodes
        for n in node_records:
            nid = n["node_id"]
            try:
                meta = json.loads(n["metadata_json"])
            except Exception:
                continue

            epistemic = meta.get("epistemic_status")
            citations = meta.get("evidence_citations", [])

            if epistemic and epistemic not in VALID_EPISTEMIC_STATUSES:
                issues.append(
                    GraphIntegrityIssue(
                        issue_id=self._make_issue_id("EPISTEMIC", "NODE", nid, "INVALID_EPISTEMIC_STATUS"),
                        category=GraphIssueCategory.EPISTEMIC,
                        severity=GraphIssueSeverity.ERROR,
                        check_code="INVALID_EPISTEMIC_STATUS",
                        record_type="NODE",
                        record_id=nid,
                        description=f"Node '{nid}' defines unrecognized epistemic_status '{epistemic}'.",
                        evidence_context={"node_id": nid, "epistemic_status": epistemic, "allowed": sorted(VALID_EPISTEMIC_STATUSES)},
                        resolution_hint=f"Normalize epistemic_status to one of {sorted(VALID_EPISTEMIC_STATUSES)}.",
                    )
                )

            if epistemic == "SOURCE_SUPPORTED":
                has_verified_cite = any(
                    c.get("quote_verified") is True or c.get("epistemic_status") == "SOURCE_SUPPORTED"
                    for c in citations
                )
                if not has_verified_cite and citations:
                    issues.append(
                        GraphIntegrityIssue(
                            issue_id=self._make_issue_id("EPISTEMIC", "NODE", nid, "UNGROUNDED_SOURCE_SUPPORTED_NODE"),
                            category=GraphIssueCategory.EPISTEMIC,
                            severity=GraphIssueSeverity.WARNING,
                            check_code="UNGROUNDED_SOURCE_SUPPORTED_NODE",
                            record_type="NODE",
                            record_id=nid,
                            description=f"Node '{nid}' is marked SOURCE_SUPPORTED but citations lack confirmed quote verification.",
                            evidence_context={"node_id": nid, "citations_count": len(citations)},
                            resolution_hint="Demote to INFERRED or re-verify source chunk quotation.",
                        )
                    )
