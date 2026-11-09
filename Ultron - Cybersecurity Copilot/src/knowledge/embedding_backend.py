"""Local Semantic Embedding Backend using all-MiniLM-L6-v2.

Implements M2 Phase 2 & 3:
- Local offline embedding via ONNX runtime
- 384-dimensional dense vectors
- Consistent L2 normalization for cosine similarity
- Batch and single text encoding
- Metadata exposure (model_name, version, dimension, normalization, runtime, device)
- Graceful CPU fallback and error handling
"""

import logging
from typing import Any, Dict, List, Optional
import numpy as np

logger = logging.getLogger("m2.embedding")


class MiniLMEmbeddingBackend:
    """
    Lightweight local embedding backend powered by all-MiniLM-L6-v2 ONNX runtime.
    """

    MODEL_NAME: str = "all-MiniLM-L6-v2"
    MODEL_VERSION: str = "2.0.0"
    EMBEDDING_DIMENSION: int = 384
    NORMALIZATION: str = "L2"
    RUNTIME: str = "onnxruntime"

    def __init__(
        self,
        preferred_providers: Optional[List[str]] = None,
        max_seq_length: int = 256,
    ) -> None:
        self.max_seq_length = max_seq_length
        self._preferred_providers = preferred_providers
        self._model_instance: Any = None
        self._device: str = "CPU"
        self._init_model()

    def _init_model(self) -> None:
        """Initialize the local ONNX model with CPU fallback."""
        try:
            from chromadb.utils.embedding_functions.onnx_mini_lm_l6_v2 import (
                ONNXMiniLM_L6_V2,
            )
            self._model_instance = ONNXMiniLM_L6_V2(
                preferred_providers=self._preferred_providers
            )
            # Detect active provider
            providers = getattr(self._model_instance.model, "get_providers", lambda: ["CPUExecutionProvider"])()
            if any("CUDA" in p for p in providers):
                self._device = "CUDA"
            else:
                self._device = "CPU"
            logger.info(f"Initialized {self.MODEL_NAME} on device={self._device}")
        except Exception as e:
            logger.warning(f"Could not initialize GPU/preferred providers: {e}. Falling back to standard CPU.")
            from chromadb.utils.embedding_functions.onnx_mini_lm_l6_v2 import (
                ONNXMiniLM_L6_V2,
            )
            self._model_instance = ONNXMiniLM_L6_V2(
                preferred_providers=["CPUExecutionProvider"]
            )
            self._device = "CPU"

    @property
    def is_available(self) -> bool:
        """Return True if the underlying model is initialized and functional."""
        return self._model_instance is not None

    @property
    def device(self) -> str:
        return self._device

    @property
    def model_name(self) -> str:
        return self.MODEL_NAME

    @property
    def embedding_dimension(self) -> int:
        return self.EMBEDDING_DIMENSION

    def get_metadata(self) -> Dict[str, Any]:
        """Return runtime configuration metadata for forensic audit logging."""
        return {
            "model_name": self.MODEL_NAME,
            "model_version": self.MODEL_VERSION,
            "embedding_dimension": self.EMBEDDING_DIMENSION,
            "normalization": self.NORMALIZATION,
            "runtime": self.RUNTIME,
            "device": self._device,
            "max_seq_length": self.max_seq_length,
        }

    def embed(self, text: str) -> List[float]:
        """
        Compute normalized 384-d float vector for a single text input.
        Handles empty or whitespace-only strings gracefully.
        """
        results = self.embed_batch([text])
        return results[0]

    def embed_batch(self, texts: List[str], batch_size: int = 32) -> List[List[float]]:
        """
        Compute normalized 384-d float vectors for a batch of text strings.
        Ensures deterministic output and consistent L2 normalization.
        """
        if not texts:
            return []

        # Sanitize empty strings to prevent tokenizer edge failures while preserving index alignment
        sanitized = [t if (t and t.strip()) else " " for t in texts]

        all_vectors: List[List[float]] = []
        for i in range(0, len(sanitized), batch_size):
            chunk = sanitized[i : i + batch_size]
            raw_embeddings = self._model_instance(chunk)
            for vec in raw_embeddings:
                arr = np.array(vec, dtype=np.float32)
                norm = float(np.linalg.norm(arr))
                if norm > 1e-9:
                    arr = arr / norm
                else:
                    arr = np.zeros(self.EMBEDDING_DIMENSION, dtype=np.float32)
                all_vectors.append(arr.tolist())

        return all_vectors
