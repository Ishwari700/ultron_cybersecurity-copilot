"""Assessment-Scoped Artifact Registry.

Enforces:
- Strict multi-tenant isolation: artifacts cannot cross assessment namespaces (INV-SEC-04, INV-M8-04)
- Verification that quarantined artifacts cannot be queried as valid evidence (INV-M8-09)
"""

from typing import Dict, List, Optional
from src.artifacts.metadata import ArtifactRecord, ArtifactType, QuarantineStatus


class ArtifactRegistry:
    """Manages registered artifacts per assessment namespace."""

    def __init__(self, assessment_id: str):
        self.assessment_id = assessment_id
        self._artifacts: Dict[str, ArtifactRecord] = {}

    def register(self, record: ArtifactRecord) -> None:
        """Registers a validated artifact into the registry."""
        if record.assessment_id != self.assessment_id:
            raise ValueError(
                f"Assessment mismatch: cannot register artifact '{record.artifact_id}' belonging to "
                f"'{record.assessment_id}' in registry for '{self.assessment_id}'"
            )
        self._artifacts[record.artifact_id] = record

    def get_artifact(self, artifact_id: str) -> Optional[ArtifactRecord]:
        """Retrieves an artifact by ID, only if belonging to this assessment."""
        return self._artifacts.get(artifact_id)

    def list_artifacts(
        self,
        artifact_type: Optional[ArtifactType] = None,
        include_quarantined: bool = False,
    ) -> List[ArtifactRecord]:
        """Lists registered artifacts with optional type filter and quarantine exclusion."""
        results = list(self._artifacts.values())
        if not include_quarantined:
            results = [a for a in results if a.quarantine_status != QuarantineStatus.QUARANTINED]
        if artifact_type:
            results = [a for a in results if a.artifact_type == artifact_type]
        return results

    def exists(self, artifact_id: str) -> bool:
        return artifact_id in self._artifacts

    def count(self) -> int:
        return len(self._artifacts)
