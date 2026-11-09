"""Unified Artifact Ingestion Pipeline.

Coordinates:
- Quarantine gate evaluation
- Cryptographic hash provenance
- Assessment-scoped registry storage
- Specialized adapter normalization into canonical observations
"""

from typing import Any, Dict, List, Optional, Tuple

from src.artifacts.adapters.android_adapter import AndroidArtifactAdapter
from src.artifacts.adapters.web_api_adapter import WebApiArtifactAdapter
from src.artifacts.metadata import (
    ArtifactRecord,
    ArtifactType,
    QuarantineReason,
    QuarantineStatus,
    TrustStatus,
)
from src.artifacts.quarantine import ArtifactQuarantineManager
from src.artifacts.registry import ArtifactRegistry
from src.assessment.models import CanonicalObservation


class ArtifactIngestionPipeline:
    """End-to-end ingestion orchestrator for multi-domain security artifacts."""

    def __init__(self, assessment_id: str):
        self.assessment_id = assessment_id
        self.quarantine_manager = ArtifactQuarantineManager(assessment_id)
        self.registry = ArtifactRegistry(assessment_id)

    def ingest(
        self,
        artifact_type: ArtifactType,
        filename: str,
        raw_bytes: bytes,
        mime_type: str = "application/octet-stream",
        source: str = "RESEARCHER_IMPORT",
        metadata: Optional[Dict[str, Any]] = None,
        scope_gate: Optional[Any] = None,
    ) -> Tuple[ArtifactRecord, List[CanonicalObservation]]:
        """
        Ingests artifact through quarantine gate, registry, and normalization adapters.
        Returns: (ArtifactRecord, List[CanonicalObservation])
        """
        # 1. Instantiate baseline record
        record = ArtifactRecord.create(
            assessment_id=self.assessment_id,
            artifact_type=artifact_type,
            filename=filename,
            raw_bytes=raw_bytes,
            mime_type=mime_type,
            source=source,
            metadata=metadata or {},
        )

        # 2. Evaluate quarantine gate
        is_safe, q_reason, q_diag = self.quarantine_manager.evaluate_and_filter(record, raw_bytes)
        if not is_safe:
            quarantined = self.quarantine_manager.isolate(record, q_reason, q_diag)
            return quarantined, []

        # 3. Passed quarantine: mark validated and register
        record.quarantine_status = QuarantineStatus.VALIDATED
        record.trust_status = TrustStatus.UNTRUSTED_EXTERNAL  # Data remains data
        self.registry.register(record)

        # 4. Domain-specific normalization
        observations: List[CanonicalObservation] = []

        if artifact_type in (ArtifactType.APK, ArtifactType.DEX, ArtifactType.SMALI) or (
            artifact_type == ArtifactType.XML and "AndroidManifest.xml" in filename
        ):
            layers, mobile_art, mobile_obs = AndroidArtifactAdapter.process_artifact(record, raw_bytes)
            if mobile_obs:
                observations.append(mobile_obs)

        elif artifact_type in (ArtifactType.HAR, ArtifactType.JSON):
            web_obs = WebApiArtifactAdapter.process_artifact(record, raw_bytes, scope_gate=scope_gate)
            observations.extend(web_obs)

        return record, observations
