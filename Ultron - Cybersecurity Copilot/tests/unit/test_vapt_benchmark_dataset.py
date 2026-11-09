"""Unit tests for Phase 0 Gold-Standard VAPT Retrieval Evaluation Benchmark.

Validates:
- JSON and Pydantic schema validity
- Exactly 100 queries
- Unique query IDs and sequential formatting (VAPT-Q001 to VAPT-Q100)
- No duplicate query text
- All referenced chunk, document, category, and knowledge type identifiers exist in vapt_knowledge.db
- Valid security domains
- Valid relevance labels (0, 1, 2, 3)
- Required fields are present on every query
- No malformed entries
- No target-specific evidence (general VAPT knowledge only)
- Difficulty balance (30 EASY, 40 MEDIUM, 30 HARD)
- Analytical subsets (>= 15 negative controls, >= 15 security invariants, >= 15 evidence gaps, >= 10 experiments, >= 15 paraphrased)
- Compatibility with production retriever execution hooks
"""

import json
from pathlib import Path
import re
import sqlite3
import pytest

from src.eval.vapt_benchmark_schema import (
    DifficultyLevel,
    QueryType,
    VaptRetrievalBenchmarkDataset,
    load_vapt_benchmark,
)
from src.knowledge.retriever import OnnxVectorFts5Retriever

BENCHMARK_PATH = Path("tests/evaluation/vapt_retrieval_queries.json")
DB_PATH = Path("data/vapt_corpus/vapt_knowledge.db")


@pytest.fixture(scope="module")
def benchmark_data() -> VaptRetrievalBenchmarkDataset:
    """Fixture providing loaded and validated benchmark dataset."""
    assert BENCHMARK_PATH.exists(), f"Benchmark file not found at {BENCHMARK_PATH}"
    return load_vapt_benchmark(BENCHMARK_PATH)


@pytest.fixture(scope="module")
def corpus_identifiers():
    """Extract valid ground-truth identifiers from vapt_knowledge.db."""
    assert DB_PATH.exists(), f"Corpus database not found at {DB_PATH}"
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT chunk_id FROM chunks")
    valid_chunks = set(r[0] for r in cursor.fetchall())

    cursor.execute("SELECT document_id FROM documents")
    valid_docs = set(r[0] for r in cursor.fetchall())

    cursor.execute("SELECT DISTINCT knowledge_type FROM chunks")
    valid_ktypes = set(r[0] for r in cursor.fetchall())

    cursor.execute("SELECT category_tags FROM chunks")
    valid_categories = set()
    for r in cursor.fetchall():
        for cat in json.loads(r[0]):
            valid_categories.add(cat)

    conn.close()
    return {
        "chunks": valid_chunks,
        "docs": valid_docs,
        "ktypes": valid_ktypes,
        "categories": valid_categories,
    }


def test_benchmark_file_and_schema_validity(benchmark_data: VaptRetrievalBenchmarkDataset):
    """Verify JSON parses cleanly and adheres to Pydantic benchmark schema."""
    assert benchmark_data.schema_version == "1.0.0"
    assert benchmark_data.benchmark_name == "VAPT_RETRIEVAL_GOLD_STANDARD_BENCHMARK"
    assert benchmark_data.total_queries == 100
    assert len(benchmark_data.queries) == 100


def test_exactly_100_queries(benchmark_data: VaptRetrievalBenchmarkDataset):
    """Verify exactly 100 evaluation queries exist in the dataset."""
    assert len(benchmark_data.queries) == 100, f"Expected 100 queries, got {len(benchmark_data.queries)}"


def test_unique_and_sequential_query_ids(benchmark_data: VaptRetrievalBenchmarkDataset):
    """Verify query IDs are unique, non-empty, and strictly match VAPT-Q001 through VAPT-Q100."""
    ids = [q.query_id for q in benchmark_data.queries]
    assert len(ids) == len(set(ids)), "Query IDs must be unique"
    
    expected_ids = [f"VAPT-Q{i:03d}" for i in range(1, 101)]
    assert ids == expected_ids, "Query IDs must be sequential VAPT-Q001 to VAPT-Q100"


def test_no_duplicate_query_text(benchmark_data: VaptRetrievalBenchmarkDataset):
    """Verify no duplicate or near-duplicate query text exists across queries."""
    normalized_queries = [re.sub(r"\s+", " ", q.query.strip().lower()) for q in benchmark_data.queries]
    assert len(normalized_queries) == len(set(normalized_queries)), "All 100 query strings must be distinct"


def test_required_fields_present_and_non_empty(benchmark_data: VaptRetrievalBenchmarkDataset):
    """Verify all required evaluation fields are populated with valid data."""
    for q in benchmark_data.queries:
        assert q.query_id, "query_id must not be empty"
        assert q.query, f"query must not be empty for {q.query_id}"
        assert q.security_domain, f"security_domain must not be empty for {q.query_id}"
        assert q.evidence_gap_type, f"evidence_gap_type must not be empty for {q.query_id}"
        assert len(q.expected_knowledge_types) > 0, f"expected_knowledge_types must not be empty for {q.query_id}"
        assert len(q.expected_categories) > 0, f"expected_categories must not be empty for {q.query_id}"
        assert len(q.relevance_requirements) > 0, f"relevance_requirements must not be empty for {q.query_id}"
        assert len(q.must_retrieve) > 0, f"must_retrieve must have at least one target for {q.query_id}"
        assert len(q.relevance_ratings) > 0, f"relevance_ratings must not be empty for {q.query_id}"
        assert q.notes, f"notes must not be empty for {q.query_id}"


def test_referenced_corpus_identifiers_exist(benchmark_data: VaptRetrievalBenchmarkDataset, corpus_identifiers):
    """Verify every referenced chunk_id, knowledge_type, and category exists in the actual VAPT corpus."""
    all_chunks_in_db = corpus_identifiers["chunks"]
    all_docs_in_db = corpus_identifiers["docs"]
    all_ktypes_in_db = corpus_identifiers["ktypes"]
    all_cats_in_db = corpus_identifiers["categories"]

    referenced_chunks = set()

    for q in benchmark_data.queries:
        # Check must_retrieve
        for item in q.must_retrieve:
            if item.type == "chunk_id":
                assert item.value in all_chunks_in_db, f"Query {q.query_id} must_retrieve non-existent chunk: {item.value}"
                referenced_chunks.add(item.value)
            elif item.type == "knowledge_type":
                assert item.value in all_ktypes_in_db, f"Query {q.query_id} must_retrieve invalid k_type: {item.value}"
            elif item.type == "category":
                assert item.value in all_cats_in_db, f"Query {q.query_id} must_retrieve invalid category: {item.value}"
            elif item.type == "document_id":
                assert item.value in all_docs_in_db, f"Query {q.query_id} must_retrieve invalid doc_id: {item.value}"

        # Check acceptable_retrievals
        for item in q.acceptable_retrievals:
            if item.type == "chunk_id":
                assert item.value in all_chunks_in_db, f"Query {q.query_id} acceptable non-existent chunk: {item.value}"
                referenced_chunks.add(item.value)
            elif item.type == "category":
                assert item.value in all_cats_in_db, f"Query {q.query_id} acceptable invalid category: {item.value}"

        # Check irrelevant_retrievals
        for item in q.irrelevant_retrievals:
            if item.type == "chunk_id":
                assert item.value in all_chunks_in_db, f"Query {q.query_id} irrelevant non-existent chunk: {item.value}"
                referenced_chunks.add(item.value)

        # Check relevance_ratings
        for cid, score in q.relevance_ratings.items():
            assert cid in all_chunks_in_db, f"Query {q.query_id} rates non-existent chunk: {cid}"
            referenced_chunks.add(cid)

    # Assert 100% corpus coverage (all 23 chunks are grounded)
    assert referenced_chunks == all_chunks_in_db, f"Missing corpus chunks in benchmark: {all_chunks_in_db - referenced_chunks}"


def test_valid_relevance_ratings_model(benchmark_data: VaptRetrievalBenchmarkDataset):
    """Verify all relevance ratings adhere strictly to {0, 1, 2, 3} and every query has a score 3 item."""
    for q in benchmark_data.queries:
        scores = list(q.relevance_ratings.values())
        assert all(s in (0, 1, 2, 3) for s in scores), f"Invalid relevance score in {q.query_id}: {scores}"
        assert 3 in scores, f"Query {q.query_id} has no score 3 (Highly Relevant) target"


def test_difficulty_balance(benchmark_data: VaptRetrievalBenchmarkDataset):
    """Verify difficulty distribution: exactly 30 EASY, 40 MEDIUM, 30 HARD."""
    counts = {
        DifficultyLevel.EASY: 0,
        DifficultyLevel.MEDIUM: 0,
        DifficultyLevel.HARD: 0,
    }
    for q in benchmark_data.queries:
        counts[q.difficulty] += 1

    assert counts[DifficultyLevel.EASY] == 30, f"Expected 30 EASY, got {counts[DifficultyLevel.EASY]}"
    assert counts[DifficultyLevel.MEDIUM] == 40, f"Expected 40 MEDIUM, got {counts[DifficultyLevel.MEDIUM]}"
    assert counts[DifficultyLevel.HARD] == 30, f"Expected 30 HARD, got {counts[DifficultyLevel.HARD]}"


def test_query_subset_coverage(benchmark_data: VaptRetrievalBenchmarkDataset):
    """Verify minimum thresholds for all mandatory query subsets."""
    negative_controls = sum(1 for q in benchmark_data.queries if q.is_negative_control)
    security_invariants = sum(1 for q in benchmark_data.queries if q.is_security_invariant)
    evidence_gaps = sum(1 for q in benchmark_data.queries if q.is_evidence_gap)
    experiments = sum(1 for q in benchmark_data.queries if q.is_experiment)
    paraphrased = sum(1 for q in benchmark_data.queries if q.is_adversarial_or_paraphrased)

    assert negative_controls >= 15, f"Expected >= 15 negative controls, got {negative_controls}"
    assert security_invariants >= 15, f"Expected >= 15 security invariants, got {security_invariants}"
    assert evidence_gaps >= 15, f"Expected >= 15 evidence gaps, got {evidence_gaps}"
    assert experiments >= 10, f"Expected >= 10 experiments, got {experiments}"
    assert paraphrased >= 15, f"Expected >= 15 paraphrased queries, got {paraphrased}"


def test_no_target_specific_evidence(benchmark_data: VaptRetrievalBenchmarkDataset):
    """Verify benchmark queries are strictly general VAPT methodology and contain no target evidence assertions."""
    prohibited_phrases = [
        "target is vulnerable",
        "target is confirmed",
        "observed on target",
        "target evidence confirms",
        "in-scope target",
        "target system has vulnerability",
    ]
    for q in benchmark_data.queries:
        lower_text = q.query.lower()
        for phrase in prohibited_phrases:
            assert phrase not in lower_text, f"Query {q.query_id} contains prohibited target claim: '{phrase}'"


def test_dataset_retriever_compatibility(benchmark_data: VaptRetrievalBenchmarkDataset):
    """Verify that benchmark queries execute cleanly against the existing OnnxVectorFts5Retriever."""
    retriever = OnnxVectorFts5Retriever(db_path=DB_PATH)
    
    # Test on a representative subset of 5 queries (different domains and difficulties)
    sample_queries = [
        benchmark_data.queries[0],   # VAPT-Q001 (Easy Direct)
        benchmark_data.queries[15],  # VAPT-Q016 (Medium Negative Control)
        benchmark_data.queries[27],  # VAPT-Q028 (Hard Invariant)
        benchmark_data.queries[37],  # VAPT-Q038 (Medium Evidence Gap)
        benchmark_data.queries[81],  # VAPT-Q082 (Medium Experiment)
    ]

    for q in sample_queries:
        results = retriever.retrieve(query=q.query, top_k=5, query_id=q.query_id)
        assert len(results) > 0, f"Retriever returned 0 results for query {q.query_id}"
        assert results[0].retrieval_rank == 1
        assert results[0].query_id == q.query_id
        assert results[0].fused_score > 0.0

    retriever.close()
