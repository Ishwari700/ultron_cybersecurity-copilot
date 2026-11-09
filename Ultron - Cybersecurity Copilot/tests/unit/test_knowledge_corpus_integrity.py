"""Unit test verifying end-to-end cryptographic integrity of the shipped VAPT knowledge corpus."""

import json
from pathlib import Path
import pytest

from src.knowledge.ingestion import DocumentIngestionEngine
from src.knowledge.models import CorpusManifest, TrustRootRecord
from src.knowledge.provenance import CryptographicTrustAuthority
from src.knowledge.store import VaptKnowledgeStore


def test_shipped_vapt_corpus_integrity():
    """
    Verify complete trust chain of data/vapt_corpus:
    1. All 6 documents parse and match sources.json allowlist
    2. Body hashes match frontmatter
    3. Merkle root matches RFC 9162 MTH
    4. Ed25519 detached signature verifies against trust_root.json
    5. SQLite FTS5 database matches manifest chunk count
    """
    corpus_dir = Path("data/vapt_corpus")
    sources_file = corpus_dir / "sources.json"
    manifest_file = corpus_dir / "manifest.json"
    sig_file = corpus_dir / "manifest.sig"
    trust_root_file = corpus_dir / "trust_root.json"
    db_file = corpus_dir / "vapt_knowledge.db"

    assert sources_file.exists()
    assert manifest_file.exists()
    assert sig_file.exists()
    assert trust_root_file.exists()
    assert db_file.exists()

    # Load Trust Root
    with open(trust_root_file, "r", encoding="utf-8") as f:
        trust_root = TrustRootRecord(**json.load(f))

    # Load Manifest
    with open(manifest_file, "r", encoding="utf-8") as f:
        manifest_data = json.load(f)
    manifest = CorpusManifest(**manifest_data)

    # Load Signature
    with open(sig_file, "rb") as f:
        sig_bytes = f.read()

    # Ingest documents
    engine = DocumentIngestionEngine(sources_file)
    md_files = sorted(corpus_dir.glob("*.md"))
    assert len(md_files) == 6

    all_chunks = []
    for md_file in md_files:
        fm, norm_body, chunks, warnings = engine.ingest_file(md_file)
        all_chunks.extend(chunks)
        assert fm.document_id in manifest.document_hashes
        assert fm.content_hash == manifest.document_hashes[fm.document_id]

    assert len(all_chunks) == manifest.chunk_count

    # Verify Cryptographic Trust Chain
    assert CryptographicTrustAuthority.verify_corpus_integrity(
        manifest=manifest,
        signature_bytes=sig_bytes,
        trust_root=trust_root,
        chunks=all_chunks,
    )

    # Verify SQLite FTS5 Store
    store = VaptKnowledgeStore(db_file, read_only=True)
    assert store.get_document_count() == 6
    assert store.get_chunk_count() == len(all_chunks)

    # Test sample search
    results = store.query_lexical("IDOR authorization parameter substitution", top_k=5)
    assert len(results) > 0
    top_chunk, score = results[0]
    assert "IDOR" in top_chunk.category_tags or "Authorization" in top_chunk.title
    store.close()
