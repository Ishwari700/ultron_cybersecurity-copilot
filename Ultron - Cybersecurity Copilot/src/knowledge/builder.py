"""Corpus Build and Cryptographic Sealing Pipeline.

Builds the frozen offline VAPT knowledge corpus:
1. Ingests and normalizes markdown documents
2. Generates deterministic semantic chunks
3. Computes RFC 9162 Merkle tree root
4. Signs canonical JCS manifest with Ed25519 offline root
5. Populates vapt_knowledge.db SQLite FTS5 database
6. Performs self-verification of the generated trust chain
"""

import json
import logging
from pathlib import Path
from typing import Optional, Tuple
from cryptography.hazmat.primitives.asymmetric import ed25519

from src.knowledge.chunking import SemanticMarkdownChunker
from src.knowledge.ingestion import DocumentIngestionEngine
from src.knowledge.models import CorpusManifest, TrustRootRecord
from src.knowledge.provenance import (
    CryptographicTrustAuthority,
    canonical_jcs_serialize,
    compute_corpus_merkle_root,
)
from src.knowledge.store import VaptKnowledgeStore

logger = logging.getLogger("m3.builder")


class CorpusBuilder:
    """Builds and cryptographically seals the offline VAPT knowledge corpus."""

    def __init__(self, corpus_dir: Path) -> None:
        self.corpus_dir = Path(corpus_dir)
        self.sources_file = self.corpus_dir / "sources.json"
        self.ingestion_engine = DocumentIngestionEngine(self.sources_file)

    def build_and_seal(
        self,
        private_key: Optional[ed25519.Ed25519PrivateKey] = None,
        builder_commit: str = "819b83399e24080bf2942c3941cc96728885df49",
        build_timestamp: str = "2026-09-20T00:00:00Z",
    ) -> Tuple[CorpusManifest, bytes, TrustRootRecord]:
        """
        Execute the complete corpus build and cryptographic sealing sequence.
        """
        # Step 1: Scan and ingest all markdown documents
        md_files = sorted(self.corpus_dir.glob("*.md"))
        if not md_files:
            raise ValueError(f"No markdown documents found in {self.corpus_dir}")

        all_docs = []
        all_chunks = []
        doc_hashes = {}
        chunk_hashes = {}

        for md_file in md_files:
            fm, norm_body, chunks, warnings = self.ingestion_engine.ingest_file(md_file)
            all_docs.append((fm, norm_body))
            all_chunks.extend(chunks)
            doc_hashes[fm.document_id] = fm.content_hash

        for chunk in all_chunks:
            chunk_hashes[chunk.chunk_id] = chunk.content_hash

        # Step 2: Compute RFC 9162 Merkle root over sorted leaves
        merkle_root = compute_corpus_merkle_root(all_chunks, doc_hashes)

        # Step 3: Keypair and Trust Root Setup
        if private_key is None:
            private_key, public_key = CryptographicTrustAuthority.generate_keypair()
        else:
            public_key = private_key.public_key()

        trust_root = CryptographicTrustAuthority.create_trust_root_record(
            key_id="KEY-M3-OFFLINE-ROOT-01",
            public_key=public_key,
            description="Pinned Offline Signing Root for Milestone M3 VAPT Knowledge Corpus",
            created_at=build_timestamp,
        )

        # Step 4: Construct CorpusManifest
        sources_data = []
        with open(self.sources_file, "r", encoding="utf-8") as f:
            sources_json = json.load(f)
            sources_data = sources_json.get("sources", [])

        manifest = CorpusManifest(
            manifest_version="3.0.0",
            corpus_version="3.0.0",
            merkle_root=merkle_root,
            document_hashes=doc_hashes,
            chunk_hashes=chunk_hashes,
            chunk_count=len(all_chunks),
            document_count=len(all_docs),
            build_timestamp=build_timestamp,
            builder_commit=builder_commit,
            build_environment="Local Offline Deterministic Build Node",
            toolchain_version="Python 3.13 / Cryptography 50.0",
            chunker_version=SemanticMarkdownChunker.VERSION,
            chunker_code_hash=SemanticMarkdownChunker.get_chunker_code_hash(),
            sources=sources_data,
        )

        # Step 5: Generate Detached Ed25519 Signature over JCS manifest bytes
        signature_bytes = CryptographicTrustAuthority.sign_manifest(manifest, private_key)

        # Step 6: Persist Manifest, Signature, and Trust Root
        manifest_path = self.corpus_dir / "manifest.json"
        sig_path = self.corpus_dir / "manifest.sig"
        trust_root_path = self.corpus_dir / "trust_root.json"

        # Serialize manifest using canonical JCS
        jcs_bytes = canonical_jcs_serialize(manifest)
        with open(manifest_path, "wb") as f:
            f.write(jcs_bytes)

        with open(sig_path, "wb") as f:
            f.write(signature_bytes)

        with open(trust_root_path, "w", encoding="utf-8") as f:
            f.write(trust_root.model_dump_json(indent=2))

        # Step 7: Populate vapt_knowledge.db
        db_path = self.corpus_dir / "vapt_knowledge.db"
        if db_path.exists():
            db_path.unlink()

        store = VaptKnowledgeStore(db_path, read_only=False)
        for fm, norm_body in all_docs:
            store.insert_document(fm, norm_body)
        store.insert_chunks(all_chunks)
        store.close()

        # Step 8: Self-Verification
        CryptographicTrustAuthority.verify_corpus_integrity(
            manifest=manifest,
            signature_bytes=signature_bytes,
            trust_root=trust_root,
            chunks=all_chunks,
        )

        logger.info(
            f"Successfully built and cryptographically sealed corpus: "
            f"{len(all_docs)} docs, {len(all_chunks)} chunks, Merkle root: {merkle_root}"
        )
        return manifest, signature_bytes, trust_root
