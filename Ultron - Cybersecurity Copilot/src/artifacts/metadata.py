"""Metadata and Domain Schemas for Artifact Ingestion and Quarantine.

Enforces:
- Cryptographic SHA-256 provenance for all imported artifacts (INV-M8-05)
- Assessment namespace isolation (INV-SEC-04, INV-M8-04)
- Explicit quarantine tracking so malformed artifacts never silently vanish (INV-M8-09)
- Untrusted data boundary: imported data is strictly DATA
"""

from datetime import datetime, timezone
from enum import Enum
import hashlib
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ArtifactType(str, Enum):
    """Supported imported security artifact categories."""
    APK = "APK"
    AAB = "AAB"
    DEX = "DEX"
    SMALI = "SMALI"
    NATIVE_LIBRARY = "NATIVE_LIBRARY"
    ELF = "ELF"
    SO = "SO"
    PE = "PE"
    SOURCE_CODE = "SOURCE_CODE"
    HTTP_CAPTURE = "HTTP_CAPTURE"
    HAR = "HAR"
    PCAP = "PCAP"
    DNS_LOG = "DNS_LOG"
    TLS_CERTIFICATE = "TLS_CERTIFICATE"
    JSON = "JSON"
    XML = "XML"
    HTML = "HTML"
    TEXT = "TEXT"
    BINARY = "BINARY"
    JADX_EXPORT = "JADX_EXPORT"
    GHIDRA_EXPORT = "GHIDRA_EXPORT"
    RADARE2_EXPORT = "RADARE2_EXPORT"
    JADX_OUTPUT = "JADX_OUTPUT"
    GHIDRA_OUTPUT = "GHIDRA_OUTPUT"
    RADARE2_OUTPUT = "RADARE2_OUTPUT"
    DECOMPILER_TEXT = "DECOMPILER_TEXT"
    SYMBOL_FILE = "SYMBOL_FILE"
    FUNCTION_METADATA = "FUNCTION_METADATA"
    OTHER = "OTHER"


class AnalysisStatus(str, Enum):
    """Static analysis lifecycle status for artifacts."""
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    ANALYZED = "ANALYZED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    UNSUPPORTED = "UNSUPPORTED"


class QuarantineStatus(str, Enum):
    """Quarantine states for imported security artifacts."""
    PENDING = "PENDING"
    VALIDATED = "VALIDATED"
    QUARANTINED = "QUARANTINED"
    REJECTED = "REJECTED"


class QuarantineReason(str, Enum):
    """Formal reason taxonomy for quarantining or rejecting artifacts."""
    NONE = "NONE"
    MALFORMED = "MALFORMED"
    UNSUPPORTED = "UNSUPPORTED"
    CORRUPTED = "CORRUPTED"
    SECRET_DETECTED = "SECRET_DETECTED"
    CROSS_ASSESSMENT = "CROSS_ASSESSMENT"
    INVALID_PROVENANCE = "INVALID_PROVENANCE"
    PARSER_FAILURE = "PARSER_FAILURE"
    SECURITY_POLICY = "SECURITY_POLICY"


class TrustStatus(str, Enum):
    """Epistemic trust tier of the artifact source."""
    UNTRUSTED_EXTERNAL = "UNTRUSTED_EXTERNAL"
    VERIFIED_INTERNAL = "VERIFIED_INTERNAL"
    QUARANTINED = "QUARANTINED"


class ArtifactRecord(BaseModel):
    """Canonical descriptor for an ingested security artifact."""
    artifact_id: str
    assessment_id: str
    artifact_type: ArtifactType
    filename: str
    sha256: str
    size_bytes: int
    mime_type: str = "application/octet-stream"
    acquisition_timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source: str = "USER_UPLOAD"
    provenance: Dict[str, Any] = Field(default_factory=dict)
    trust_status: TrustStatus = TrustStatus.UNTRUSTED_EXTERNAL
    quarantine_status: QuarantineStatus = QuarantineStatus.PENDING
    quarantine_reason: QuarantineReason = QuarantineReason.NONE
    quarantine_diagnostics: Optional[Dict[str, Any]] = None
    extracted_layers: Dict[str, str] = Field(default_factory=dict)
    raw_storage_path: Optional[str] = None
    parser_version: str = "1.0.0"
    analysis_status: AnalysisStatus = AnalysisStatus.PENDING
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @property
    def size(self) -> int:
        return self.size_bytes

    @property
    def ingestion_timestamp(self) -> str:
        return self.acquisition_timestamp

    @classmethod
    def create(
        cls,
        assessment_id: str,
        artifact_type: ArtifactType,
        filename: str,
        raw_bytes: bytes,
        mime_type: str = "application/octet-stream",
        source: str = "USER_UPLOAD",
        provenance: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "ArtifactRecord":
        """Deterministic instantiation with cryptographic hash."""
        h = hashlib.sha256(raw_bytes).hexdigest()
        art_id = f"ART-{h[:12].upper()}"
        return cls(
            artifact_id=art_id,
            assessment_id=assessment_id,
            artifact_type=artifact_type,
            filename=filename,
            sha256=h,
            size_bytes=len(raw_bytes),
            mime_type=mime_type,
            source=source,
            provenance=provenance or {"hash": h, "acquired_by": source},
            metadata=metadata or {},
        )
