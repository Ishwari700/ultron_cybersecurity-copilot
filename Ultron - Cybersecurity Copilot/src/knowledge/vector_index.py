"""Persistent Vector Index for VAPT Knowledge Chunks.

Implements M2 Phase 4 & 5:
- Persistent JSON index format with full provenance metadata
- Content-hash based stale embedding detection
- Model and dimension mismatch detection
- Full rebuild and incremental index update workflows
- Deterministic cosine similarity search with ASCII chunk_id tie-breaking
"""

from datetime import datetime, timezone
import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import numpy as np

from src.knowledge.embedding_backend import MiniLMEmbeddingBackend
from src.knowledge.models import KnowledgeChunk
from src.knowledge.store import VaptKnowledgeStore

logger = logging.getLogger("m2.vector_index")


class IndexHealthStatus:
    """Diagnostic health report for a persistent vector index."""

    def __init__(
        self,
        is_healthy: bool,
        status_code: str,
        missing_chunk_ids: List[str],
        stale_chunk_ids: List[str],
        message: str,
    ) -> None:
        self.is_healthy = is_healthy
        self.status_code = status_code
        self.missing_chunk_ids = missing_chunk_ids
        self.stale_chunk_ids = stale_chunk_ids
        self.message = message

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_healthy": self.is_healthy,
            "status_code": self.status_code,
            "missing_count": len(self.missing_chunk_ids),
            "stale_count": len(self.stale_chunk_ids),
            "message": self.message,
        }


class PersistentVectorIndex:
    """
    Persistent dense vector storage with content-hash stale detection.
    """

    SCHEMA_VERSION: str = "2.0.0"
    PREPROCESSING_VERSION: str = "v1.0.0"

    def __init__(
        self,
        index_path: Path,
        embedding_backend: Optional[MiniLMEmbeddingBackend] = None,
    ) -> None:
        self.index_path = Path(index_path)
        self.backend = embedding_backend or MiniLMEmbeddingBackend()
        self.metadata: Dict[str, Any] = {}
        self.entries: Dict[str, Dict[str, Any]] = {}
        self._vectors_matrix: Optional[np.ndarray] = None
        self._chunk_ids_order: List[str] = []

        if self.index_path.exists():
            self.load()

    def load(self) -> None:
        """Load index from persistent disk file."""
        with open(self.index_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.metadata = {
            "schema_version": data.get("schema_version"),
            "embedding_model": data.get("embedding_model"),
            "embedding_dimension": data.get("embedding_dimension"),
            "preprocessing_version": data.get("preprocessing_version"),
            "created_at": data.get("created_at"),
            "chunk_count": data.get("chunk_count", 0),
        }
        self.entries = data.get("entries", {})
        self._build_fast_matrix()

    def _build_fast_matrix(self) -> None:
        """Construct contiguous numpy matrix for sub-millisecond vector querying."""
        self._chunk_ids_order = sorted(self.entries.keys())
        if not self._chunk_ids_order:
            self._vectors_matrix = None
            return

        vec_list = [self.entries[cid]["vector"] for cid in self._chunk_ids_order]
        self._vectors_matrix = np.array(vec_list, dtype=np.float32)

    def save(self) -> None:
        """Save index to persistent disk file atomically."""
        self.index_path.parent.mkdir(parents=True, exist_ok=True)
        now_iso = datetime.now(timezone.utc).isoformat()
        payload = {
            "schema_version": self.SCHEMA_VERSION,
            "embedding_model": self.backend.MODEL_NAME,
            "embedding_dimension": self.backend.EMBEDDING_DIMENSION,
            "preprocessing_version": self.PREPROCESSING_VERSION,
            "created_at": now_iso,
            "chunk_count": len(self.entries),
            "entries": self.entries,
        }
        self.metadata = {
            "schema_version": self.SCHEMA_VERSION,
            "embedding_model": self.backend.MODEL_NAME,
            "embedding_dimension": self.backend.EMBEDDING_DIMENSION,
            "preprocessing_version": self.PREPROCESSING_VERSION,
            "created_at": now_iso,
            "chunk_count": len(self.entries),
        }
        temp_path = self.index_path.with_suffix(".tmp")
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        temp_path.replace(self.index_path)
        self._build_fast_matrix()

    def check_health(self, store: VaptKnowledgeStore) -> IndexHealthStatus:
        """
        Verify index consistency against current store chunks and active embedding backend.
        Detects missing chunks, stale chunks, model mismatch, and dimension mismatch.
        """
        if not self.index_path.exists() or not self.entries:
            return IndexHealthStatus(
                is_healthy=False,
                status_code="INDEX_MISSING",
                missing_chunk_ids=[],
                stale_chunk_ids=[],
                message="Index file does not exist or has zero entries.",
            )

        # Check model and dimension compatibility
        stored_model = self.metadata.get("embedding_model")
        if stored_model != self.backend.MODEL_NAME:
            return IndexHealthStatus(
                is_healthy=False,
                status_code="MODEL_MISMATCH",
                missing_chunk_ids=[],
                stale_chunk_ids=[],
                message=f"Model mismatch: index uses '{stored_model}', backend uses '{self.backend.MODEL_NAME}'.",
            )

        stored_dim = self.metadata.get("embedding_dimension")
        if stored_dim != self.backend.EMBEDDING_DIMENSION:
            return IndexHealthStatus(
                is_healthy=False,
                status_code="DIMENSION_MISMATCH",
                missing_chunk_ids=[],
                stale_chunk_ids=[],
                message=f"Dimension mismatch: index has {stored_dim}, backend requires {self.backend.EMBEDDING_DIMENSION}.",
            )

        # Check content hashes for every chunk in store
        all_store_chunks = store.get_all_chunks()
        missing: List[str] = []
        stale: List[str] = []

        for chunk in all_store_chunks:
            if chunk.chunk_id not in self.entries:
                missing.append(chunk.chunk_id)
            else:
                entry = self.entries[chunk.chunk_id]
                # Compare content hash
                if entry.get("content_hash") != chunk.content_hash:
                    stale.append(chunk.chunk_id)

        if missing or stale:
            return IndexHealthStatus(
                is_healthy=False,
                status_code="CHUNKS_OUT_OF_SYNC",
                missing_chunk_ids=missing,
                stale_chunk_ids=stale,
                message=f"Index out of sync: {len(missing)} missing, {len(stale)} stale chunks.",
            )

        return IndexHealthStatus(
            is_healthy=True,
            status_code="HEALTHY",
            missing_chunk_ids=[],
            stale_chunk_ids=[],
            message="Vector index is healthy, synchronized, and up-to-date.",
        )

    def is_stale(self, chunk_id: str, content_hash: str) -> bool:
        """Return True if chunk is missing from index or its content hash differs."""
        if chunk_id not in self.entries:
            return True
        return self.entries[chunk_id].get("content_hash") != content_hash

    def build_or_update(
        self,
        store: VaptKnowledgeStore,
        force_rebuild: bool = False,
    ) -> Tuple[int, int]:
        """
        Build or incrementally update index against store chunks.
        Returns (num_new_embedded, num_reused).
        """
        all_store_chunks = store.get_all_chunks()

        if force_rebuild:
            self.entries = {}

        to_embed: List[KnowledgeChunk] = []
        reused_count = 0

        # Determine which chunks need embedding
        for chunk in all_store_chunks:
            if chunk.chunk_id in self.entries and not force_rebuild:
                existing = self.entries[chunk.chunk_id]
                if existing.get("content_hash") == chunk.content_hash:
                    reused_count += 1
                    continue
            to_embed.append(chunk)

        # Remove orphan chunks no longer in store
        valid_store_cids = {c.chunk_id for c in all_store_chunks}
        self.entries = {
            cid: rec for cid, rec in self.entries.items() if cid in valid_store_cids
        }

        # Embed batch of missing/stale chunks
        if to_embed:
            texts = [
                f"{chunk.title} {chunk.section_heading} {chunk.content}"
                for chunk in to_embed
            ]
            vectors = self.backend.embed_batch(texts)
            now_iso = datetime.now(timezone.utc).isoformat()

            for chunk, vec in zip(to_embed, vectors):
                self.entries[chunk.chunk_id] = {
                    "chunk_id": chunk.chunk_id,
                    "document_id": chunk.document_id,
                    "content_hash": chunk.content_hash,
                    "created_at": now_iso,
                    "vector": vec,
                }

        self.save()
        return len(to_embed), reused_count

    def search_dense(
        self,
        query_vector: List[float],
        top_k: int = 10,
    ) -> List[Tuple[str, float]]:
        """
        Execute cosine similarity search against stored chunk vectors.
        Enforces deterministic tie-breaking: score DESC, chunk_id ASC in ASCII order.
        """
        if self._vectors_matrix is None or len(self._chunk_ids_order) == 0:
            return []

        q_arr = np.array(query_vector, dtype=np.float32)
        q_norm = float(np.linalg.norm(q_arr))
        if q_norm > 1e-9:
            q_arr = q_arr / q_norm

        # Matrix-vector multiplication for cosine similarities
        sims = np.dot(self._vectors_matrix, q_arr)

        scored: List[Tuple[str, float]] = []
        for cid, sim in zip(self._chunk_ids_order, sims):
            scored.append((cid, float(sim)))

        # Strict tie-breaking: score DESC, chunk_id ASC
        scored.sort(key=lambda item: (-item[1], item[0].encode("utf-8")))
        return scored[:top_k]
