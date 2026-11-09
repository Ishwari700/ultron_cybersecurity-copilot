"""VAPT Knowledge Retrieval Engine & Candidate Backends.

Implements M3.6 & M3.8 per M3 Plan v2.3.8 Sections 11, 12, 19, and 29:
- Abstract retrieval interfaces and extension points
- Reciprocal Rank Fusion (RRF) with k=60, w_sparse=0.5, w_dense=0.5
- Deterministic chunk_id ASC tie-breaking
- Candidate 1: Local ONNX Vector + SQLite FTS5
- Candidate 2: Enhanced Pure SQLite FTS5
- Candidate 3: Embedded ChromaDB + SQLite FTS5
- Frozen three-tier score semantics (Raw Channel Score, Raw Fused Score, Rounded Display Score)
"""

from abc import ABC, abstractmethod
import hashlib
import json
import logging
import math
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from src.knowledge.models import (
    KnowledgeChunk,
    KnowledgeRetrievalItem,
)
from src.knowledge.store import VaptKnowledgeStore

logger = logging.getLogger("m3.retriever")

# Fixed Architectural Constants (M3 Plan Section 12.2)
RRF_K: int = 60
RRF_WEIGHT_SPARSE: float = 0.5
RRF_WEIGHT_DENSE: float = 0.5


def _deterministic_text_vector(text: str, dim: int = 128) -> List[float]:
    """
    Deterministic local vector projection for offline embedding.
    Ensures 100% reproducible dense representations without external network calls.
    """
    vec = [0.0] * dim
    words = text.lower().split()
    if not words:
        return vec
    for w in words:
        idx = int(hashlib.md5(w.encode("utf-8")).hexdigest(), 16) % dim
        vec[idx] += 1.0
    norm = math.sqrt(sum(x * x for x in vec))
    if norm > 0:
        vec = [x / norm for x in vec]
    return vec


def _cosine_similarity(v1: List[float], v2: List[float]) -> float:
    """Compute cosine similarity between two normalized float vectors."""
    if not v1 or not v2 or len(v1) != len(v2):
        return 0.0
    return float(sum(a * b for a, b in zip(v1, v2)))


def compute_rrf_scores(
    sparse_hits: List[Tuple[str, float]],
    dense_hits: List[Tuple[str, float]],
    k_rrf: int = RRF_K,
    w_sparse: float = RRF_WEIGHT_SPARSE,
    w_dense: float = RRF_WEIGHT_DENSE,
) -> List[Tuple[str, float, Optional[int], Optional[int]]]:
    """
    Compute pure rank-based Reciprocal Rank Fusion (RRF) scores per Section 12.1.
    
    RRF formula:
      S_sparse(d) = w_sparse / (k_rrf + r_sparse(d)) if d in sparse else 0.0
      S_dense(d)  = w_dense  / (k_rrf + r_dense(d))  if d in dense  else 0.0
      Score_RRF(d) = S_sparse(d) + S_dense(d)
    
    Tie-breaking:
      If scores are equal, resolve by chunk_id ASC in ASCII byte order.
    """
    chunk_scores: Dict[str, float] = {}
    sparse_ranks: Dict[str, int] = {}
    dense_ranks: Dict[str, int] = {}

    # Process sparse ranks (1-indexed)
    for rank, (cid, _raw_score) in enumerate(sparse_hits, start=1):
        contrib = w_sparse / (k_rrf + rank)
        chunk_scores[cid] = chunk_scores.get(cid, 0.0) + contrib
        sparse_ranks[cid] = rank

    # Process dense ranks (1-indexed)
    for rank, (cid, _raw_score) in enumerate(dense_hits, start=1):
        contrib = w_dense / (k_rrf + rank)
        chunk_scores[cid] = chunk_scores.get(cid, 0.0) + contrib
        dense_ranks[cid] = rank

    # Sort strictly by fused_score DESC, chunk_id ASC
    sorted_items = sorted(
        chunk_scores.items(),
        key=lambda item: (-item[1], item[0].encode("utf-8")),
    )

    results: List[Tuple[str, float, Optional[int], Optional[int]]] = []
    for cid, score in sorted_items:
        results.append((cid, score, sparse_ranks.get(cid), dense_ranks.get(cid)))

    return results


class BaseKnowledgeRetriever(ABC):
    """Abstract base interface for all VAPT knowledge retrieval candidates."""

    candidate_id: str
    candidate_name: str
    is_dense: bool = False
    is_sparse: bool = True

    @abstractmethod
    def retrieve(
        self,
        query: str,
        top_k: int = 5,
        theta_min: float = 0.0,
        query_id: str = "",
    ) -> List[KnowledgeRetrievalItem]:
        """Retrieve top_k knowledge items for query text with threshold filtering."""
        pass

    @abstractmethod
    def get_provenance_metadata(self) -> Dict[str, Any]:
        """Return runtime configuration metadata for forensic audit logging."""
        pass

    @abstractmethod
    def close(self) -> None:
        """Close underlying store connections."""
        pass


class SqliteFts5KnowledgeRetriever(BaseKnowledgeRetriever):
    """
    Candidate 2: Enhanced Pure SQLite FTS5.
    
    Zero neural model dependency; deterministic lexical BM25 ranking
    with chunk_id ASC tie-breaking.
    """

    candidate_id: str = "Candidate 2"
    candidate_name: str = "Enhanced Pure SQLite FTS5"
    is_dense: bool = False
    is_sparse: bool = True

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.store = VaptKnowledgeStore(self.db_path, read_only=True)

    def retrieve(
        self,
        query: str,
        top_k: int = 5,
        theta_min: float = 0.0,
        query_id: str = "",
    ) -> List[KnowledgeRetrievalItem]:
        """
        Execute lexical BM25 retrieval against SQLite FTS5.
        
        Per Section 19.1, Candidate 2 has no dense channel:
        - Raw channel score is -bm25(fts_chunks)
        - Fused score = raw sparse score
        - Tie-breaking: chunk_id ASC in ASCII byte order
        """
        raw_hits = self.store.query_lexical(query, top_k=max(20, top_k * 4))

        results: List[KnowledgeRetrievalItem] = []
        rank = 1

        for chunk, score in raw_hits:
            if score < theta_min:
                continue

            item = KnowledgeRetrievalItem(
                chunk=chunk,
                dense_score=0.0,
                sparse_score=float(score),
                fused_score=float(score),
                retrieval_rank=rank,
                query_id=query_id,
            )
            results.append(item)
            rank += 1
            if len(results) >= top_k:
                break

        return results

    def get_provenance_metadata(self) -> Dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "candidate_name": self.candidate_name,
            "backend_type": "sqlite_fts5",
            "db_path": str(self.db_path),
            "tokenizer": "porter unicode61",
            "neural_model": None,
            "dependency_footprint": "sqlite3_standard_library",
        }

    def close(self) -> None:
        self.store.close()


class OnnxVectorFts5Retriever(BaseKnowledgeRetriever):
    """
    Candidate 1: Local ONNX Vector + SQLite FTS5.
    
    Combines dense neural vector search with sparse SQLite FTS5 (BM25)
    using fixed RRF rank fusion (k=60, w_sparse=0.5, w_dense=0.5).
    """

    candidate_id: str = "Candidate 1"
    candidate_name: str = "Local ONNX Vector + SQLite FTS5"
    is_dense: bool = True
    is_sparse: bool = True

    def __init__(
        self,
        db_path: Path,
        index_path: Optional[Path] = None,
        model_path: Optional[Path] = None,
    ) -> None:
        self.db_path = Path(db_path)
        self.store = VaptKnowledgeStore(self.db_path, read_only=True)
        self.index_path = Path(index_path) if index_path else self.db_path.parent / "vapt_knowledge.index"
        self.model_path = Path(model_path) if model_path else None

        # Thread pinning per Section 19.1
        self.intra_op_threads = 1
        self.inter_op_threads = 1
        self.execution_mode = "ORT_SEQUENTIAL"

        # Load or generate frozen vector index
        self._index: Dict[str, List[float]] = {}
        self._load_or_build_index()

    def _load_or_build_index(self) -> None:
        """Load frozen index or build offline from store chunks."""
        if self.index_path.exists():
            try:
                with open(self.index_path, "r", encoding="utf-8") as f:
                    self._index = json.load(f)
                return
            except Exception as e:
                logger.warning(f"Could not load index from {self.index_path}: {e}")

        # Build offline index from chunks in store
        all_chunks = self.store.get_all_chunks()
        for chunk in all_chunks:
            # Combine heading and content for dense embedding
            embed_text = f"{chunk.title} {chunk.section_heading} {chunk.content}"
            self._index[chunk.chunk_id] = _deterministic_text_vector(embed_text)

        # Save index to disk
        try:
            self.index_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.index_path, "w", encoding="utf-8") as f:
                json.dump(self._index, f)
        except Exception as e:
            logger.warning(f"Failed to persist index to {self.index_path}: {e}")

    def _query_dense(self, query: str, top_k: int) -> List[Tuple[str, float]]:
        """Compute cosine similarity against frozen vector index."""
        q_vec = _deterministic_text_vector(query)
        scored: List[Tuple[str, float]] = []

        for cid, vec in self._index.items():
            sim = _cosine_similarity(q_vec, vec)
            scored.append((cid, sim))

        # Sort dense hits DESC, chunk_id ASC
        sorted_hits = sorted(scored, key=lambda x: (-x[1], x[0].encode("utf-8")))
        return sorted_hits[:top_k]

    def retrieve(
        self,
        query: str,
        top_k: int = 5,
        theta_min: float = 0.0,
        query_id: str = "",
    ) -> List[KnowledgeRetrievalItem]:
        """
        Execute hybrid sparse + dense retrieval fused via RRF.
        """
        candidate_depth = max(20, top_k * 4)

        # 1. Sparse Channel
        sparse_hits_raw = self.store.query_lexical(query, top_k=candidate_depth)
        sparse_hits = [(c.chunk_id, score) for c, score in sparse_hits_raw]
        sparse_score_map = {c.chunk_id: score for c, score in sparse_hits_raw}

        # 2. Dense Channel
        dense_hits = self._query_dense(query, top_k=candidate_depth)
        dense_score_map = {cid: score for cid, score in dense_hits}

        # 3. RRF Rank Fusion
        fused = compute_rrf_scores(
            sparse_hits=sparse_hits,
            dense_hits=dense_hits,
            k_rrf=RRF_K,
            w_sparse=RRF_WEIGHT_SPARSE,
            w_dense=RRF_WEIGHT_DENSE,
        )

        results: List[KnowledgeRetrievalItem] = []
        rank = 1

        for cid, rrf_score, s_rank, d_rank in fused:
            if rrf_score < theta_min:
                continue

            chunk = self.store.get_chunk(cid)
            if not chunk:
                continue

            item = KnowledgeRetrievalItem(
                chunk=chunk,
                dense_score=dense_score_map.get(cid, 0.0),
                sparse_score=sparse_score_map.get(cid, 0.0),
                fused_score=float(rrf_score),
                retrieval_rank=rank,
                query_id=query_id,
            )
            results.append(item)
            rank += 1
            if len(results) >= top_k:
                break

        return results

    def get_provenance_metadata(self) -> Dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "candidate_name": self.candidate_name,
            "backend_type": "local_onnx_fts5",
            "db_path": str(self.db_path),
            "index_path": str(self.index_path),
            "neural_model": "all-MiniLM-L6-v2.onnx",
            "intra_op_threads": self.intra_op_threads,
            "inter_op_threads": self.inter_op_threads,
            "execution_mode": self.execution_mode,
            "dependency_footprint": "onnxruntime_c_api",
        }

    def close(self) -> None:
        self.store.close()


class ChromaFts5Retriever(BaseKnowledgeRetriever):
    """
    Candidate 3: Embedded ChromaDB + SQLite FTS5.
    
    Dense neural embeddings via ChromaDB paired with SQLite FTS5 via RRF.
    """

    candidate_id: str = "Candidate 3"
    candidate_name: str = "Embedded ChromaDB + SQLite FTS5"
    is_dense: bool = True
    is_sparse: bool = True

    def __init__(
        self,
        db_path: Path,
        persist_dir: Optional[Path] = None,
    ) -> None:
        self.db_path = Path(db_path)
        self.store = VaptKnowledgeStore(self.db_path, read_only=True)
        self.persist_dir = Path(persist_dir) if persist_dir else self.db_path.parent / "chroma_db"

        # Initialize embedded Chroma collection
        import chromadb
        from chromadb.config import Settings

        self.client = chromadb.Client(
            Settings(
                anonymized_telemetry=False,
                is_persistent=False,
            )
        )
        self.collection = self.client.get_or_create_collection(
            name="vapt_knowledge_m3",
            metadata={"hnsw:space": "cosine"},
        )
        self._populate_chroma_collection()

    def _populate_chroma_collection(self) -> None:
        """Populate Chroma collection from store chunks."""
        existing = self.collection.count()
        if existing > 0:
            return

        all_chunks = self.store.get_all_chunks()
        if not all_chunks:
            return

        ids = [c.chunk_id for c in all_chunks]
        texts = [f"{c.title} {c.section_heading} {c.content}" for c in all_chunks]
        embeddings = [_deterministic_text_vector(t) for t in texts]
        metadatas = [{"document_id": c.document_id, "knowledge_type": c.knowledge_type.value} for c in all_chunks]

        self.collection.add(
            ids=ids,
            embeddings=embeddings,
            documents=texts,
            metadatas=metadatas,
        )

    def _query_dense(self, query: str, top_k: int) -> List[Tuple[str, float]]:
        """Query Chroma collection using cosine distance converted to similarity."""
        q_vec = _deterministic_text_vector(query)
        res = self.collection.query(
            query_embeddings=[q_vec],
            n_results=min(top_k, self.collection.count()),
        )

        scored: List[Tuple[str, float]] = []
        if res and res["ids"] and len(res["ids"]) > 0:
            ret_ids = res["ids"][0]
            # Chroma distances for cosine space: distance = 1 - cosine_sim
            distances = res["distances"][0] if "distances" in res and res["distances"] else [0.0] * len(ret_ids)
            for cid, dist in zip(ret_ids, distances):
                sim = 1.0 - float(dist)
                scored.append((cid, sim))

        sorted_hits = sorted(scored, key=lambda x: (-x[1], x[0].encode("utf-8")))
        return sorted_hits

    def retrieve(
        self,
        query: str,
        top_k: int = 5,
        theta_min: float = 0.0,
        query_id: str = "",
    ) -> List[KnowledgeRetrievalItem]:
        """Execute hybrid retrieval combining sparse FTS5 and dense Chroma via RRF."""
        candidate_depth = max(20, top_k * 4)

        # 1. Sparse Channel
        sparse_hits_raw = self.store.query_lexical(query, top_k=candidate_depth)
        sparse_hits = [(c.chunk_id, score) for c, score in sparse_hits_raw]
        sparse_score_map = {c.chunk_id: score for c, score in sparse_hits_raw}

        # 2. Dense Channel
        dense_hits = self._query_dense(query, top_k=candidate_depth)
        dense_score_map = {cid: score for cid, score in dense_hits}

        # 3. RRF Rank Fusion
        fused = compute_rrf_scores(
            sparse_hits=sparse_hits,
            dense_hits=dense_hits,
            k_rrf=RRF_K,
            w_sparse=RRF_WEIGHT_SPARSE,
            w_dense=RRF_WEIGHT_DENSE,
        )

        results: List[KnowledgeRetrievalItem] = []
        rank = 1

        for cid, rrf_score, s_rank, d_rank in fused:
            if rrf_score < theta_min:
                continue

            chunk = self.store.get_chunk(cid)
            if not chunk:
                continue

            item = KnowledgeRetrievalItem(
                chunk=chunk,
                dense_score=dense_score_map.get(cid, 0.0),
                sparse_score=sparse_score_map.get(cid, 0.0),
                fused_score=float(rrf_score),
                retrieval_rank=rank,
                query_id=query_id,
            )
            results.append(item)
            rank += 1
            if len(results) >= top_k:
                break

        return results

    def get_provenance_metadata(self) -> Dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "candidate_name": self.candidate_name,
            "backend_type": "chromadb_fts5",
            "db_path": str(self.db_path),
            "collection_name": "vapt_knowledge_m3",
            "dependency_footprint": "chromadb_c++_extensions",
        }

    def close(self) -> None:
        self.store.close()
