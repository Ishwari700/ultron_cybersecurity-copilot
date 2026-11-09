"""Vector store abstraction supporting ChromaDB with standalone local cosine similarity fallback."""

import hashlib
import math
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


def _simple_text_vector(text: str, dim: int = 128) -> List[float]:
    """Deterministic hash-based bag-of-words vector for local offline testing."""
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
    dot = sum(a * b for a, b in zip(v1, v2))
    return float(dot)


class LocalVectorStore:
    """
    Self-contained, local vector store for dense retrieval.
    Compatible with ChromaDB interface but runs 100% offline without external dependencies.
    """

    def __init__(
        self,
        collection_name: str = "evidence_chunks",
        persist_dir: Optional[Path] = None,
        embed_fn: Optional[Callable[[str], List[float]]] = None,
    ) -> None:
        self.collection_name = collection_name
        self.persist_dir = Path(persist_dir) if persist_dir else None
        self.embed_fn = embed_fn or _simple_text_vector
        self._documents: Dict[str, Dict[str, Any]] = {} # id -> {id, text, metadata, vector}

    def add_document(self, doc_id: str, text: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Add or update a document in the vector store."""
        vector = self.embed_fn(text)
        self._documents[doc_id] = {
            "id": doc_id,
            "text": text,
            "metadata": metadata or {},
            "vector": vector,
        }

    def add_documents(self, docs: List[Dict[str, Any]]) -> None:
        """Add a batch of documents [{'id': '...', 'text': '...', 'metadata': {...}}]."""
        for doc in docs:
            self.add_document(doc["id"], doc["text"], doc.get("metadata"))

    def query(self, query_text: str, k: int = 5) -> List[Dict[str, Any]]:
        """Query for top-k semantically similar documents."""
        if not self._documents:
            return []

        query_vec = self.embed_fn(query_text)
        scored: List[Tuple[float, Dict[str, Any]]] = []

        for doc_id, item in self._documents.items():
            sim = _cosine_similarity(query_vec, item["vector"])
            scored.append((sim, item))

        # Sort by similarity descending
        scored.sort(key=lambda x: x[0], reverse=True)
        results: List[Dict[str, Any]] = []
        for rank, (sim, item) in enumerate(scored[:k], start=1):
            results.append({
                "id": item["id"],
                "text": item["text"],
                "metadata": item["metadata"],
                "similarity": round(sim, 4),
                "rank": rank,
            })
        return results
