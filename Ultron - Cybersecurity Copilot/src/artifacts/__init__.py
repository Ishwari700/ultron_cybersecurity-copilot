"""Artifact Ingestion and Quarantine Subsystem for Milestone 8."""

from src.artifacts.metadata import (
    ArtifactRecord,
    ArtifactType,
    QuarantineReason,
    QuarantineStatus,
    TrustStatus,
)
from src.artifacts.hashing import (
    compute_sha256_bytes,
    compute_sha256_file,
    verify_sha256,
)
from src.artifacts.quarantine import ArtifactQuarantineManager
from src.artifacts.registry import ArtifactRegistry
from src.artifacts.ingestion import ArtifactIngestionPipeline
from src.artifacts.adapters.android_adapter import AndroidArtifactAdapter
from src.artifacts.adapters.web_api_adapter import WebApiArtifactAdapter

__all__ = [
    "ArtifactRecord",
    "ArtifactType",
    "QuarantineReason",
    "QuarantineStatus",
    "TrustStatus",
    "compute_sha256_bytes",
    "compute_sha256_file",
    "verify_sha256",
    "ArtifactQuarantineManager",
    "ArtifactRegistry",
    "ArtifactIngestionPipeline",
    "AndroidArtifactAdapter",
    "WebApiArtifactAdapter",
]
