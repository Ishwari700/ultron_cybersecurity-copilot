"""Unit tests for Deterministic Knowledge Graph Integrity Auditor (Milestone M9 Stage E).

Verifies:
1. Consistent graph producing zero issues (CLEAN status).
2. Dangling edge source and target node detection (CRITICAL).
3. Dangling chunk and source references in evidence provenance (ERROR).
4. Stale source lifecycle detection for DEACTIVATED / FAILED sources (WARNING).
5. Epistemic status enforcement (SOURCE_SUPPORTED quote groundings, invalid statuses).
6. Canonicalization duplicate detection without automated merging (INFO).
7. Missing and malformed store / corrupted JSON fail-safe handling with explicit limitations.
8. Strict read-only invariance (byte-for-byte file hash preservation).
9. Bounded pagination and category scope filtering.
10. RelationalKnowledgeGraph.audit_integrity() delegation.
"""

import hashlib
import json
from pathlib import Path
import sqlite3
import pytest

from src.knowledge.canonical_models import KnowledgeRelationType
from src.knowledge.graph_auditor import (
    GraphAuditResult,
    GraphAuditScope,
    GraphAuditSummary,
    GraphIntegrityAuditor,
    GraphIntegrityIssue,
    GraphIssueCategory,
    GraphIssueSeverity,
)
from src.knowledge.knowledge_graph import RelationalKnowledgeGraph
from src.knowledge.models import (
    KnowledgeChunk,
    KnowledgeDocumentFrontmatter,
    KnowledgeSourceType,
    KnowledgeType,
)
from src.knowledge.store import VaptKnowledgeStore


@pytest.fixture
def temp_graph_db(tmp_path: Path) -> Path:
    """Fixture providing a temporary SQLite database for RelationalKnowledgeGraph."""
    return tmp_path / "test_knowledge_graph.db"


@pytest.fixture
def temp_store_db(tmp_path: Path) -> Path:
    """Fixture providing a temporary SQLite database for VaptKnowledgeStore."""
    return tmp_path / "test_vapt_knowledge.db"


@pytest.fixture
def clean_environment(temp_graph_db: Path, temp_store_db: Path):
    """Sets up a fully consistent, grounded graph and store pair."""
    store = VaptKnowledgeStore(temp_store_db)
    graph = RelationalKnowledgeGraph(temp_graph_db)

    # 1. Register Source
    store.insert_source(
        source_id="SRC-OWASP-WSTG",
        title="OWASP Web Security Testing Guide",
        source_type="OWASP",
        authority_level="AUTHORITATIVE",
        filename="wstg.md",
        format="MARKDOWN",
        content_hash="hash-wstg-content",
        original_checksum="sha256-original",
        status="ACTIVE",
    )

    # 2. Insert Document
    doc = KnowledgeDocumentFrontmatter(
        document_id="DOC-SRC-OWASP-WSTG",
        title="SQL Injection Testing Guide",
        source_name="OWASP WSTG",
        source_version="v4.2",
        source_url="https://owasp.org/wstg",
        license="CC-BY-SA-4.0",
        author="OWASP Foundation",
        content_hash="hash-doc-wstg",
    )
    store.insert_document(doc, "Complete SQL Injection Testing and Parameterized Queries Guide.")

    # 3. Insert Chunks
    chunk1 = KnowledgeChunk(
        chunk_id="CHK-SQLI-DEF",
        document_id="DOC-SRC-OWASP-WSTG",
        source_type=KnowledgeSourceType.OWASP_WSTG,
        knowledge_type=KnowledgeType.TESTING_METHODOLOGY,
        category_tags=["sqli", "injection"],
        title="SQL Injection Definition",
        section_heading="Overview",
        content="SQL injection occurs when user input is directly concatenated into SQL statements without sanitization.",
        token_estimate=18,
        content_hash="hash-chk-1",
        trust_tier="AUTHORITATIVE",
    )
    chunk2 = KnowledgeChunk(
        chunk_id="CHK-SQLI-REM",
        document_id="DOC-SRC-OWASP-WSTG",
        source_type=KnowledgeSourceType.OWASP_WSTG,
        knowledge_type=KnowledgeType.MITIGATION,
        category_tags=["sqli", "remediation"],
        title="SQL Injection Remediation",
        section_heading="Mitigation",
        content="Use parameterized queries and prepared statements to prevent SQL injection vulnerabilities.",
        token_estimate=15,
        content_hash="hash-chk-2",
        trust_tier="AUTHORITATIVE",
    )
    store.insert_chunks([chunk1, chunk2])

    # 4. Add Consistent Nodes with Provenance Citations
    sqli_cite = {
        "source_id": "SRC-OWASP-WSTG",
        "document_id": "DOC-SRC-OWASP-WSTG",
        "chunk_id": "CHK-SQLI-DEF",
        "page_number": 1,
        "supporting_quote": "SQL injection occurs when user input is directly concatenated",
        "quote_verified": True,
        "epistemic_status": "SOURCE_SUPPORTED",
    }
    graph.add_node(
        node_id="NODE:VULNERABILITY:sql_injection",
        node_type="VULNERABILITY",
        label="SQL Injection",
        metadata={
            "description": "Improper neutralization of special elements in SQL query",
            "epistemic_status": "SOURCE_SUPPORTED",
            "evidence_citations": [sqli_cite],
            "provenance_count": 1,
        },
    )

    rem_cite = {
        "source_id": "SRC-OWASP-WSTG",
        "document_id": "DOC-SRC-OWASP-WSTG",
        "chunk_id": "CHK-SQLI-REM",
        "page_number": 2,
        "supporting_quote": "Use parameterized queries and prepared statements",
        "quote_verified": True,
        "epistemic_status": "SOURCE_SUPPORTED",
    }
    graph.add_node(
        node_id="NODE:DEFENSIVE_CONTROL:parameterized_queries",
        node_type="DEFENSIVE_CONTROL",
        label="Parameterized Queries",
        metadata={
            "description": "Database query abstraction preventing code-data mixing",
            "epistemic_status": "SOURCE_SUPPORTED",
            "evidence_citations": [rem_cite],
            "provenance_count": 1,
        },
    )

    # 5. Add Consistent Edge with Provenance Citations
    edge_cite = {
        "source_id": "SRC-OWASP-WSTG",
        "document_id": "DOC-SRC-OWASP-WSTG",
        "chunk_id": "CHK-SQLI-REM",
        "page_number": 2,
        "supporting_quote": "prevent SQL injection vulnerabilities",
        "quote_verified": True,
        "epistemic_status": "SOURCE_SUPPORTED",
    }
    graph.add_edge(
        source_id="NODE:DEFENSIVE_CONTROL:parameterized_queries",
        target_id="NODE:VULNERABILITY:sql_injection",
        relation_type="MITIGATES",
        metadata={
            "explanation": "Parameterized queries mitigate SQL injection vulnerabilities",
            "epistemic_status": "SOURCE_SUPPORTED",
            "evidence_citations": [edge_cite],
            "provenance_count": 1,
        },
    )

    return graph, store, temp_graph_db, temp_store_db


# -----------------------------------------------------------------------------
# 1. Consistent Graph Test
# -----------------------------------------------------------------------------

def test_consistent_graph_clean_audit(clean_environment):
    """Verifies that a fully grounded, consistent graph produces status CLEAN with zero issues."""
    graph, store, graph_db, store_db = clean_environment
    auditor = GraphIntegrityAuditor(
        graph_db_path=graph_db,
        knowledge_store=store,
    )
    result = auditor.run_audit()

    assert result.summary.status == "CLEAN"
    assert result.summary.total_issues == 0
    assert result.summary.critical_count == 0
    assert result.summary.error_count == 0
    assert result.summary.warning_count == 0
    assert result.summary.nodes_examined == 2
    assert result.summary.edges_examined == 1
    assert result.summary.provenance_citations_examined == 3
    assert result.read_only_guarantee is True
    assert len(result.issues) == 0
    auditor.close()


# -----------------------------------------------------------------------------
# 2. Structural Integrity: Dangling Edges
# -----------------------------------------------------------------------------

def test_dangling_edge_source_and_target(clean_environment):
    """Verifies that edges referencing nonexistent nodes trigger CRITICAL dangling issues."""
    graph, store, graph_db, _ = clean_environment

    # Inject an edge with non-existent source and non-existent target
    graph.add_edge(
        source_id="NODE:CONCEPT:nonexistent_source",
        target_id="NODE:VULNERABILITY:sql_injection",
        relation_type="RELATED_TO",
        metadata={},
    )
    graph.add_edge(
        source_id="NODE:VULNERABILITY:sql_injection",
        target_id="NODE:CONCEPT:nonexistent_target",
        relation_type="RELATED_TO",
        metadata={},
    )

    auditor = GraphIntegrityAuditor(graph_db_path=graph_db, knowledge_store=store)
    result = auditor.run_audit(categories=[GraphIssueCategory.STRUCTURAL])

    assert result.summary.critical_count >= 2
    assert result.summary.status == "CRITICAL_FOUND"

    check_codes = [iss.check_code for iss in result.issues]
    assert "DANGLING_EDGE_SOURCE" in check_codes
    assert "DANGLING_EDGE_TARGET" in check_codes

    source_issue = next(i for i in result.issues if i.check_code == "DANGLING_EDGE_SOURCE")
    assert source_issue.severity == GraphIssueSeverity.CRITICAL
    assert source_issue.evidence_context["missing_source_id"] == "NODE:CONCEPT:nonexistent_source"

    target_issue = next(i for i in result.issues if i.check_code == "DANGLING_EDGE_TARGET")
    assert target_issue.severity == GraphIssueSeverity.CRITICAL
    assert target_issue.evidence_context["missing_target_id"] == "NODE:CONCEPT:nonexistent_target"
    auditor.close()


def test_invalid_predicate_and_self_referential_edge(clean_environment):
    """Verifies that invalid predicates and self-referential asymmetric edges are flagged."""
    graph, store, graph_db, _ = clean_environment

    # Invalid predicate
    graph.add_edge(
        source_id="NODE:VULNERABILITY:sql_injection",
        target_id="NODE:DEFENSIVE_CONTROL:parameterized_queries",
        relation_type="INVALID_CUSTOM_ACTION",
        metadata={},
    )
    # Self-referential asymmetric edge
    graph.add_edge(
        source_id="NODE:VULNERABILITY:sql_injection",
        target_id="NODE:VULNERABILITY:sql_injection",
        relation_type="MITIGATES",
        metadata={},
    )

    auditor = GraphIntegrityAuditor(graph_db_path=graph_db, knowledge_store=store)
    result = auditor.run_audit(categories=[GraphIssueCategory.STRUCTURAL])

    check_codes = [iss.check_code for iss in result.issues]
    assert "INVALID_RELATION_TYPE" in check_codes
    assert "SELF_REFERENTIAL_ASYMMETRIC_EDGE" in check_codes
    auditor.close()


# -----------------------------------------------------------------------------
# 3. Provenance Integrity: Dangling Chunks and Missing Citations
# -----------------------------------------------------------------------------

def test_dangling_chunk_and_source_references(clean_environment):
    """Verifies that evidence citations pointing to missing chunks or sources are flagged as ERROR."""
    graph, store, graph_db, _ = clean_environment

    # Add node with citation pointing to phantom chunk and phantom source
    bad_cite = {
        "source_id": "SRC-PHANTOM",
        "document_id": "DOC-PHANTOM",
        "chunk_id": "CHK-NONEXISTENT",
        "page_number": 99,
        "supporting_quote": "phantom quote",
        "quote_verified": True,
        "epistemic_status": "SOURCE_SUPPORTED",
    }
    graph.add_node(
        node_id="NODE:CONCEPT:orphaned_concept",
        node_type="CONCEPT",
        label="Orphaned Concept",
        metadata={
            "description": "Concept citing phantom passages",
            "epistemic_status": "SOURCE_SUPPORTED",
            "evidence_citations": [bad_cite],
        },
    )

    auditor = GraphIntegrityAuditor(graph_db_path=graph_db, knowledge_store=store)
    result = auditor.run_audit(categories=[GraphIssueCategory.PROVENANCE])

    assert result.summary.error_count >= 2
    check_codes = [iss.check_code for iss in result.issues]
    assert "DANGLING_CHUNK_REFERENCE" in check_codes
    assert "DANGLING_SOURCE_REFERENCE" in check_codes
    auditor.close()


def test_document_chunk_mismatch_detection(clean_environment):
    """Verifies that a chunk claiming a mismatched document_id is flagged as ERROR."""
    graph, store, graph_db, _ = clean_environment

    # Node cites existing chunk CHK-SQLI-DEF, but gives wrong document_id
    mismatched_cite = {
        "source_id": "SRC-OWASP-WSTG",
        "document_id": "DOC-WRONG-DOC-ID",
        "chunk_id": "CHK-SQLI-DEF",
        "quote_verified": True,
        "epistemic_status": "SOURCE_SUPPORTED",
    }
    graph.add_node(
        node_id="NODE:CONCEPT:mismatch_test",
        node_type="CONCEPT",
        label="Mismatch Test",
        metadata={
            "epistemic_status": "SOURCE_SUPPORTED",
            "evidence_citations": [mismatched_cite],
        },
    )

    auditor = GraphIntegrityAuditor(graph_db_path=graph_db, knowledge_store=store)
    result = auditor.run_audit(categories=[GraphIssueCategory.PROVENANCE])

    check_codes = [iss.check_code for iss in result.issues]
    assert "DOCUMENT_SOURCE_MISMATCH" in check_codes
    auditor.close()


# -----------------------------------------------------------------------------
# 4. Source Lifecycle Integrity: Deactivated and Inactive Sources
# -----------------------------------------------------------------------------

def test_stale_source_lifecycle_detection(clean_environment):
    """Verifies that relationships anchored to DEACTIVATED sources are flagged as WARNING."""
    graph, store, graph_db, _ = clean_environment

    # Deactivate the source
    store.deactivate_source("SRC-OWASP-WSTG")

    auditor = GraphIntegrityAuditor(graph_db_path=graph_db, knowledge_store=store)
    result = auditor.run_audit(categories=[GraphIssueCategory.LIFECYCLE])

    assert result.summary.warning_count >= 1
    check_codes = [iss.check_code for iss in result.issues]
    assert "STALE_SOURCE_EDGE" in check_codes

    stale_issue = next(i for i in result.issues if i.check_code == "STALE_SOURCE_EDGE")
    assert stale_issue.severity == GraphIssueSeverity.WARNING
    assert stale_issue.evidence_context["source_id"] == "SRC-OWASP-WSTG"
    assert stale_issue.evidence_context["source_status"] == "DEACTIVATED"
    auditor.close()


# -----------------------------------------------------------------------------
# 5. Epistemic Status Integrity: SOURCE_SUPPORTED vs Inferred/Candidate
# -----------------------------------------------------------------------------

def test_ungrounded_source_supported_detection(clean_environment):
    """Verifies that an edge claiming SOURCE_SUPPORTED without verified quote is flagged as ERROR."""
    graph, store, graph_db, _ = clean_environment

    # Edge marked SOURCE_SUPPORTED but quote_verified=False and empty quote
    unverified_cite = {
        "source_id": "SRC-OWASP-WSTG",
        "document_id": "DOC-SRC-OWASP-WSTG",
        "chunk_id": "CHK-SQLI-DEF",
        "quote_verified": False,
        "supporting_quote": None,
        "epistemic_status": "CANDIDATE",
    }
    graph.add_edge(
        source_id="NODE:VULNERABILITY:sql_injection",
        target_id="NODE:DEFENSIVE_CONTROL:parameterized_queries",
        relation_type="RELATED_TO",
        metadata={
            "epistemic_status": "SOURCE_SUPPORTED",  # Falsely promoted
            "evidence_citations": [unverified_cite],
        },
    )

    auditor = GraphIntegrityAuditor(graph_db_path=graph_db, knowledge_store=store)
    result = auditor.run_audit(categories=[GraphIssueCategory.EPISTEMIC])

    check_codes = [iss.check_code for iss in result.issues]
    assert "UNGROUNDED_SOURCE_SUPPORTED" in check_codes
    err_issue = next(i for i in result.issues if i.check_code == "UNGROUNDED_SOURCE_SUPPORTED")
    assert err_issue.severity == GraphIssueSeverity.ERROR
    auditor.close()


def test_invalid_epistemic_status_detection(clean_environment):
    """Verifies that unrecognized epistemic classifications are flagged as ERROR."""
    graph, store, graph_db, _ = clean_environment

    graph.add_edge(
        source_id="NODE:VULNERABILITY:sql_injection",
        target_id="NODE:DEFENSIVE_CONTROL:parameterized_queries",
        relation_type="SUPPORTS",
        metadata={
            "epistemic_status": "HALLUCINATED_FACT",
            "evidence_citations": [],
        },
    )

    auditor = GraphIntegrityAuditor(graph_db_path=graph_db, knowledge_store=store)
    result = auditor.run_audit(categories=[GraphIssueCategory.EPISTEMIC])

    check_codes = [iss.check_code for iss in result.issues]
    assert "INVALID_EPISTEMIC_STATUS" in check_codes
    auditor.close()


# -----------------------------------------------------------------------------
# 6. Canonicalization Diagnostics: Duplicate Entities without Merging
# -----------------------------------------------------------------------------

def test_canonicalization_duplicate_detection_without_merging(clean_environment):
    """Verifies that potential duplicate labels generate review candidates without destructive merging."""
    graph, store, graph_db, _ = clean_environment

    # Add two nodes with identical lower-cased labels but different IDs
    graph.add_node(
        node_id="NODE:CONCEPT:xss_flaw",
        node_type="CONCEPT",
        label="Cross-Site Scripting",
        metadata={"epistemic_status": "INFERRED", "evidence_citations": []},
    )
    graph.add_node(
        node_id="NODE:VULNERABILITY:cwe_79",
        node_type="VULNERABILITY",
        label="cross-site scripting",
        metadata={"epistemic_status": "INFERRED", "evidence_citations": []},
    )

    auditor = GraphIntegrityAuditor(graph_db_path=graph_db, knowledge_store=store)
    result = auditor.run_audit(categories=[GraphIssueCategory.CANONICALIZATION])

    check_codes = [iss.check_code for iss in result.issues]
    assert "CASE_INSENSITIVE_LABEL_COLLISION" in check_codes

    # Crucial Invariant: Verify NO nodes were deleted or merged!
    all_nodes = graph.get_all_nodes()
    node_ids = {n["node_id"] for n in all_nodes}
    assert "NODE:CONCEPT:xss_flaw" in node_ids
    assert "NODE:VULNERABILITY:cwe_79" in node_ids
    auditor.close()


# -----------------------------------------------------------------------------
# 7. Fail-Safe Handling: Missing Store and Corrupted JSON
# -----------------------------------------------------------------------------

def test_missing_store_produces_explicit_limitation(temp_graph_db: Path, tmp_path: Path):
    """Verifies that an unavailable store logs an explicit limitation rather than giving a false pass."""
    graph = RelationalKnowledgeGraph(temp_graph_db)
    graph.add_node("NODE:CONCEPT:test", "CONCEPT", "Test Concept", metadata={})

    auditor = GraphIntegrityAuditor(
        graph_db_path=temp_graph_db,
        knowledge_db_path=tmp_path / "nonexistent_store.db",
    )
    result = auditor.run_audit()

    assert any("VaptKnowledgeStore" in lim for lim in result.limitations)
    assert result.summary.nodes_examined == 1
    auditor.close()


def test_corrupted_json_handled_safely(temp_graph_db: Path):
    """Verifies that malformed JSON in node or edge metadata triggers CRITICAL issue without crash."""
    graph = RelationalKnowledgeGraph(temp_graph_db)

    # Force malformed JSON directly into database
    with graph.conn:
        graph.conn.execute(
            "INSERT INTO graph_nodes (node_id, node_type, label, metadata_json) VALUES (?, ?, ?, ?)",
            ("NODE:CONCEPT:corrupted", "CONCEPT", "Corrupted Node", "{malformed_json: true, unterminated"),
        )

    auditor = GraphIntegrityAuditor(graph_db_path=temp_graph_db)
    result = auditor.run_audit(categories=[GraphIssueCategory.STRUCTURAL])

    assert result.summary.critical_count >= 1
    check_codes = [iss.check_code for iss in result.issues]
    assert "MALFORMED_METADATA_JSON" in check_codes
    auditor.close()


# -----------------------------------------------------------------------------
# 8. Read-Only Invariance Check
# -----------------------------------------------------------------------------

def test_read_only_invariance_guarantee(clean_environment):
    """Verifies that running an audit does not alter the database file (cryptographic hash matches)."""
    graph, store, graph_db, store_db = clean_environment

    def _file_hash(p: Path) -> str:
        return hashlib.sha256(p.read_bytes()).hexdigest()

    graph_hash_before = _file_hash(graph_db)
    store_hash_before = _file_hash(store_db)

    auditor = GraphIntegrityAuditor(graph_db_path=graph_db, knowledge_store=store)
    result = auditor.run_audit()
    auditor.close()

    graph_hash_after = _file_hash(graph_db)
    store_hash_after = _file_hash(store_db)

    assert graph_hash_before == graph_hash_after, "Graph database was mutated during audit!"
    assert store_hash_before == store_hash_after, "Knowledge store database was mutated during audit!"
    assert result.read_only_guarantee is True


# -----------------------------------------------------------------------------
# 9. Bounded Pagination and Scope Filtering
# -----------------------------------------------------------------------------

def test_scope_category_filtering(clean_environment):
    """Verifies that specifying categories restricts checks to only those requested."""
    graph, store, graph_db, _ = clean_environment

    auditor = GraphIntegrityAuditor(graph_db_path=graph_db, knowledge_store=store)
    result = auditor.run_audit(categories=[GraphIssueCategory.STRUCTURAL])

    assert set(result.scope.categories) == {GraphIssueCategory.STRUCTURAL}
    auditor.close()


def test_bounded_execution_cap(clean_environment):
    """Verifies that max_records_per_check bounds the number of inspected entities."""
    graph, store, graph_db, _ = clean_environment

    auditor = GraphIntegrityAuditor(graph_db_path=graph_db, knowledge_store=store)
    result = auditor.run_audit(max_records_per_check=1)

    assert result.summary.nodes_examined == 1
    assert result.summary.edges_examined == 1
    auditor.close()


# -----------------------------------------------------------------------------
# 10. RelationalKnowledgeGraph.audit_integrity() Integration
# -----------------------------------------------------------------------------

def test_relational_knowledge_graph_audit_integrity_method(clean_environment):
    """Verifies the direct audit_integrity() method on RelationalKnowledgeGraph."""
    graph, store, _, _ = clean_environment

    result = graph.audit_integrity(knowledge_store=store)
    assert isinstance(result, GraphAuditResult)
    assert result.summary.status == "CLEAN"
    assert result.summary.total_issues == 0
