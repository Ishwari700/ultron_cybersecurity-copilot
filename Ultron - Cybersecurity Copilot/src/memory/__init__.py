"""M12 Security Research Memory & Knowledge Management Package.

Exports core models, enums, errors, admission pipeline, retrieval engine,
and adapters.
"""

from src.memory.enums import (
    ConflictType,
    EpistemicStatus,
    FreshnessState,
    LifecycleState,
    MemoryAuthority,
    MemoryNamespace,
    MemorySourceType,
    PromotionStatus,
    SensitivityClassification,
)
from src.memory.errors import (
    AssessmentIsolationViolationError,
    EpistemicViolationError,
    InvalidMemoryPromotionError,
    MemoryAccessDeniedError,
    MemoryAdmissionRejectedError,
    MemoryConflictError,
    MemoryError,
    MemoryPointerError,
    MemoryPoisoningAttemptError,
    SecretPersistenceForbiddenError,
)
from src.memory.models import (
    EvidencePointer,
    MemoryAccessContext,
    MemoryConflict,
    MemoryDeletionRecord,
    MemoryItem,
    MemoryPromotion,
    MemoryRetrievalItem,
    MemoryRetrievalResult,
    MemoryVersion,
    compute_memory_hash,
)
from src.memory.namespaces import NamespaceValidator
from src.memory.sanitizer import MemorySanitizer
from src.memory.provenance import ProvenanceValidator
from src.memory.deduplication import MemoryDeduplicator
from src.memory.conflicts import ConflictDetector
from src.memory.freshness import FreshnessTracker
from src.memory.retention import RetentionManager
from src.memory.isolation import MemoryIsolationEngine
from src.memory.permissions import MemoryPermissionGate
from src.memory.promotion import MemoryPromotionEngine
from src.memory.lifecycle import MemoryLifecycleEngine
from src.memory.deletion import MemoryDeletionEngine
from src.memory.export import MemoryExportEngine
from src.memory.admission import MemoryAdmissionPipeline
from src.memory.ranking import MemoryRanker
from src.memory.persistence import MemoryPersistence
from src.memory.retrieval import HybridMemoryRetriever
from src.memory.metrics import GLOBAL_MEMORY_TELEMETRY, MemoryTelemetry
from src.memory.adapters import EpisodicMemoryAdapters

__all__ = [
    "ConflictType",
    "EpistemicStatus",
    "FreshnessState",
    "LifecycleState",
    "MemoryAuthority",
    "MemoryNamespace",
    "MemorySourceType",
    "PromotionStatus",
    "SensitivityClassification",
    "MemoryError",
    "MemoryAccessDeniedError",
    "AssessmentIsolationViolationError",
    "MemoryAdmissionRejectedError",
    "SecretPersistenceForbiddenError",
    "MemoryPoisoningAttemptError",
    "EpistemicViolationError",
    "InvalidMemoryPromotionError",
    "MemoryConflictError",
    "MemoryPointerError",
    "EvidencePointer",
    "MemoryAccessContext",
    "MemoryConflict",
    "MemoryDeletionRecord",
    "MemoryItem",
    "MemoryPromotion",
    "MemoryRetrievalItem",
    "MemoryRetrievalResult",
    "MemoryVersion",
    "compute_memory_hash",
    "NamespaceValidator",
    "MemorySanitizer",
    "ProvenanceValidator",
    "MemoryDeduplicator",
    "ConflictDetector",
    "FreshnessTracker",
    "RetentionManager",
    "MemoryIsolationEngine",
    "MemoryPermissionGate",
    "MemoryPromotionEngine",
    "MemoryLifecycleEngine",
    "MemoryDeletionEngine",
    "MemoryExportEngine",
    "MemoryAdmissionPipeline",
    "MemoryRanker",
    "MemoryPersistence",
    "HybridMemoryRetriever",
    "GLOBAL_MEMORY_TELEMETRY",
    "MemoryTelemetry",
    "EpisodicMemoryAdapters",
]
