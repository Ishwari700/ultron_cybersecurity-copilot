"""M11.5 Long Response Subsystem.
Provides practically unlimited long-answer delivery, conservative completeness detection,
deterministic overlap resolution, progressive streaming, and versioned persistence.
"""

from src.response.models import (
    CompletenessState,
    GenerationTermination,
    ResponseChunk,
    ResponseSession,
    ResponseStatus,
    ResponseVersion,
    compute_content_hash,
)
from src.response.completeness import (
    CompletenessDetector,
    CompletenessEvaluation,
    DEFAULT_CHUNK_NUM_CTX,
    DEFAULT_CHUNK_NUM_PREDICT,
    DEFAULT_MAX_CONTINUATION_CHUNKS,
    DEFAULT_MAX_CUMULATIVE_TOKENS,
)
from src.response.merger import (
    OverlapDetectionResult,
    ResponseMerger,
)
from src.response.continuation import (
    ContinuationContextManager,
    ContinuationDecision,
    ContinuationPrompt,
)
from src.response.stream import (
    CancellationToken,
    ResponseStreamHandler,
    StreamEvent,
)
from src.response.persistence import ResponsePersistence
from src.response.metrics import ResponseTelemetry
from src.response.generator import LongResponseEngine
from src.response.errors import (
    ContinuationLimitError,
    ContextExhaustionError,
    OverlapError,
    PersistenceError,
    ResponseEngineError,
    StreamingInterruptedError,
    UserCancelledError,
)

__all__ = [
    "CompletenessDetector",
    "CompletenessEvaluation",
    "CompletenessState",
    "ContinuationContextManager",
    "ContinuationDecision",
    "ContinuationLimitError",
    "ContinuationPrompt",
    "ContextExhaustionError",
    "CancellationToken",
    "DEFAULT_CHUNK_NUM_CTX",
    "DEFAULT_CHUNK_NUM_PREDICT",
    "DEFAULT_MAX_CONTINUATION_CHUNKS",
    "DEFAULT_MAX_CUMULATIVE_TOKENS",
    "GenerationTermination",
    "LongResponseEngine",
    "OverlapDetectionResult",
    "OverlapError",
    "PersistenceError",
    "ResponseChunk",
    "ResponseEngineError",
    "ResponseMerger",
    "ResponsePersistence",
    "ResponseSession",
    "ResponseStatus",
    "ResponseStreamHandler",
    "ResponseTelemetry",
    "ResponseVersion",
    "StreamEvent",
    "StreamingInterruptedError",
    "UserCancelledError",
    "compute_content_hash",
]
