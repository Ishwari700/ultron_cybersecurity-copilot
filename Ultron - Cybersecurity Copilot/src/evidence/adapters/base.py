"""Base observation adapter interface converting tool-specific outputs to CanonicalEvidence."""

from abc import ABC, abstractmethod
from typing import Any, List, Optional
from src.evidence.compressor import SemanticCompressor
from src.evidence.models import CanonicalEvidence
from src.evidence.normalizer import PathNormalizer
from src.evidence.vault import RedactionVault


class BaseObservationAdapter(ABC):
    """
    Abstract adapter interface converting scanner/proxy output into
    normalized, redacted, and semantically-compressed CanonicalEvidence.
    """

    def __init__(
        self,
        vault: Optional[RedactionVault] = None,
        compressor: Optional[SemanticCompressor] = None,
    ) -> None:
        self.vault = vault or RedactionVault()
        self.compressor = compressor or SemanticCompressor()
        self.normalizer = PathNormalizer()

    @abstractmethod
    def ingest(self, raw_data: Any, scope_decision_id: Optional[str] = None) -> List[CanonicalEvidence]:
        """Convert tool-specific records into a list of CanonicalEvidence objects."""
        pass
