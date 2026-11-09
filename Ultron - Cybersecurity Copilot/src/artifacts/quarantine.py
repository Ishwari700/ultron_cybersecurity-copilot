"""Artifact Quarantine Gate and Storage Manager.

Enforces:
- Malformed, corrupt, or policy-violating artifacts are isolated into quarantine (INV-M8-09)
- Quarantined artifacts cannot silently become valid evidence
- Preserves raw diagnostics, failure reasons, and cryptographic hash for auditability
"""

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional, Tuple

from src.artifacts.metadata import (
    ArtifactRecord,
    ArtifactType,
    QuarantineReason,
    QuarantineStatus,
    TrustStatus,
)
from src.assessment.secrets import SecretRedactor


class ArtifactQuarantineManager:
    """Evaluates artifact safety and isolates suspicious, corrupt, or invalid inputs."""

    def __init__(self, assessment_id: str):
        self.assessment_id = assessment_id
        self._quarantined_records: Dict[str, ArtifactRecord] = {}

    @property
    def quarantined_records(self) -> Dict[str, ArtifactRecord]:
        return dict(self._quarantined_records)

    def evaluate_and_filter(
        self,
        record: ArtifactRecord,
        raw_bytes: bytes,
    ) -> Tuple[bool, QuarantineReason, Optional[Dict[str, Any]]]:
        """
        Evaluates artifact against safety and integrity policies.
        Returns: (is_safe: bool, reason: QuarantineReason, diagnostics: Optional[Dict])
        """
        # 1. Path traversal or illegal filename check
        fn = record.filename
        if ".." in fn or "%2e%2e" in fn.lower() or "/" in fn or "\\" in fn:
            return (
                False,
                QuarantineReason.SECURITY_POLICY,
                {"error": "Filename contains path traversal sequences or directory separators.", "filename": fn},
            )

        if "\x00" in fn:
            return (
                False,
                QuarantineReason.SECURITY_POLICY,
                {"error": "Filename contains null byte.", "filename": fn},
            )

        # 2. Zero-byte or empty content
        if len(raw_bytes) == 0:
            return (
                False,
                QuarantineReason.CORRUPTED,
                {"error": "Artifact contains 0 bytes (empty file)."},
            )

        # 3. Cross-assessment reference check in metadata
        meta_aid = record.metadata.get("assessment_id")
        if meta_aid and meta_aid != self.assessment_id:
            return (
                False,
                QuarantineReason.CROSS_ASSESSMENT,
                {"error": f"Artifact metadata declares assessment '{meta_aid}', expected '{self.assessment_id}'."},
            )

        # 4. Format-specific integrity checks
        if record.artifact_type in (ArtifactType.JSON, ArtifactType.HAR):
            try:
                text_content = raw_bytes.decode("utf-8")
                if "\x00" in text_content:
                    return (
                        False,
                        QuarantineReason.CORRUPTED,
                        {"error": "Null byte encountered in JSON payload."},
                    )
                parsed = json.loads(text_content)
                if record.artifact_type == ArtifactType.HAR and "log" not in parsed:
                    return (
                        False,
                        QuarantineReason.MALFORMED,
                        {"error": "HAR file missing required root 'log' object."},
                    )
            except Exception as e:
                return (
                    False,
                    QuarantineReason.MALFORMED,
                    {"error": f"JSON parsing failed: {str(e)}"},
                )

        if record.artifact_type == ArtifactType.XML:
            try:
                import xml.etree.ElementTree as ET
                ET.fromstring(raw_bytes.decode("utf-8"))
            except Exception as e:
                return (
                    False,
                    QuarantineReason.MALFORMED,
                    {"error": f"XML parsing failed: {str(e)}"},
                )

        # APK / AAB validation: Valid zip archive (or decompiled XML manifest representation)
        if record.artifact_type in (ArtifactType.APK, ArtifactType.AAB):
            if raw_bytes.strip().startswith(b"<"):
                pass  # Decompiled XML manifest text data
            else:
                if not raw_bytes.startswith(b"PK\x03\x04") and not raw_bytes.startswith(b"PK\x05\x06"):
                    return (
                        False,
                        QuarantineReason.MALFORMED,
                        {"error": "APK/AAB does not have valid ZIP archive magic header."},
                    )
                try:
                    import io
                    import zipfile
                    with zipfile.ZipFile(io.BytesIO(raw_bytes)) as zf:
                        total_uncompressed = 0
                        file_count = len(zf.infolist())
                        if file_count > 10000:
                            return (
                                False,
                                QuarantineReason.SECURITY_POLICY,
                                {"error": f"Excessive file count in archive: {file_count} (limit: 10000)."},
                            )
                        for info in zf.infolist():
                            # Path traversal / zip-slip check
                            if ".." in info.filename or info.filename.startswith("/") or info.filename.startswith("\\") or "\x00" in info.filename:
                                return (
                                    False,
                                    QuarantineReason.SECURITY_POLICY,
                                    {"error": f"ZIP entry contains path traversal sequence: '{info.filename}'"},
                                )
                            total_uncompressed += info.file_size
                        # Decompression bomb check: > 250MB or compression ratio > 100
                        if total_uncompressed > 250 * 1024 * 1024:
                            return (
                                False,
                                QuarantineReason.SECURITY_POLICY,
                                {"error": f"Archive total uncompressed size ({total_uncompressed} bytes) exceeds 250 MB ceiling."},
                            )
                        if len(raw_bytes) > 0 and (total_uncompressed / len(raw_bytes)) > 100.0:
                            return (
                                False,
                                QuarantineReason.SECURITY_POLICY,
                                {"error": f"Archive compression ratio ({total_uncompressed / len(raw_bytes):.1f}:1) exceeds 100:1 limit."},
                            )
                except zipfile.BadZipFile as e:
                    return (
                        False,
                        QuarantineReason.CORRUPTED,
                        {"error": f"Corrupted ZIP archive: {str(e)}"},
                    )
                except Exception as e:
                    return (
                        False,
                        QuarantineReason.MALFORMED,
                        {"error": f"Archive parsing failed: {str(e)}"},
                    )

        # DEX validation: Magic bytes dex\n
        if record.artifact_type == ArtifactType.DEX:
            if not raw_bytes.startswith(b"dex\n"):
                return (
                    False,
                    QuarantineReason.MALFORMED,
                    {"error": "DEX file missing 'dex\\n' magic header."},
                )
            if len(raw_bytes) < 112:  # Minimum DEX header size
                return (
                    False,
                    QuarantineReason.CORRUPTED,
                    {"error": "DEX file truncated (smaller than minimum header size of 112 bytes)."},
                )

        # ELF / SO validation: Magic bytes \x7fELF
        if record.artifact_type in (ArtifactType.ELF, ArtifactType.SO):
            if not raw_bytes.startswith(b"\x7fELF"):
                return (
                    False,
                    QuarantineReason.MALFORMED,
                    {"error": "ELF/SO file missing '\\x7fELF' magic header."},
                )
            if len(raw_bytes) < 52:  # Minimum ELF header size (32-bit ELF is 52 bytes, 64-bit is 64 bytes)
                return (
                    False,
                    QuarantineReason.CORRUPTED,
                    {"error": "ELF file truncated (smaller than minimum header size of 52 bytes)."},
                )

        # PE validation: Magic bytes MZ
        if record.artifact_type == ArtifactType.PE:
            if not raw_bytes.startswith(b"MZ"):
                return (
                    False,
                    QuarantineReason.MALFORMED,
                    {"error": "PE file missing 'MZ' DOS header magic."},
                )
            if len(raw_bytes) < 64:
                return (
                    False,
                    QuarantineReason.CORRUPTED,
                    {"error": "PE file truncated (smaller than DOS header size of 64 bytes)."},
                )

        # 5. Secret detection check for unredacted sensitive keys
        if record.artifact_type in (ArtifactType.TEXT, ArtifactType.SOURCE_CODE, ArtifactType.JSON):
            try:
                sample_text = raw_bytes.decode("utf-8", errors="ignore")
                # Look for high-risk private keys
                if "-----BEGIN RSA PRIVATE KEY-----" in sample_text or "-----BEGIN OPENSSH PRIVATE KEY-----" in sample_text:
                    return (
                        False,
                        QuarantineReason.SECRET_DETECTED,
                        {"error": "Unredacted private key found in artifact body. Must be redacted prior to ingestion."},
                    )
            except Exception:
                pass

        return True, QuarantineReason.NONE, None

    def isolate(
        self,
        record: ArtifactRecord,
        reason: QuarantineReason,
        diagnostics: Optional[Dict[str, Any]] = None,
    ) -> ArtifactRecord:
        """Quarantines the artifact record and stores diagnostic details."""
        record.quarantine_status = QuarantineStatus.QUARANTINED
        record.quarantine_reason = reason
        record.quarantine_diagnostics = diagnostics or {}
        record.trust_status = TrustStatus.QUARANTINED
        self._quarantined_records[record.artifact_id] = record
        return record

    def is_quarantined(self, artifact_id: str) -> bool:
        """Checks if an artifact is currently quarantined."""
        return artifact_id in self._quarantined_records
