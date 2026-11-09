"""Unit tests for Artifact Ingestion, Quarantine, and Multi-Tenant Isolation.

Verifies:
- INV-M8-04: Artifacts cannot cross assessment namespaces.
- INV-M8-05: Imported artifacts must retain cryptographic provenance.
- INV-M8-09: Quarantined artifacts cannot silently become valid evidence.
- Quarantine gate isolates path traversal, corrupt payloads, and cross-assessment tags.
- Honest mobile layer detection for Android artifacts.
"""

import json
import pytest

from src.artifacts.ingestion import ArtifactIngestionPipeline
from src.artifacts.metadata import (
    ArtifactRecord,
    ArtifactType,
    QuarantineReason,
    QuarantineStatus,
)
from src.artifacts.registry import ArtifactRegistry


def test_artifact_provenance_and_hashing():
    pipeline = ArtifactIngestionPipeline("ASM-ART-01")
    raw_sample = b'{"status": "ok", "users": [1, 2, 3]}'

    record, obs_list = pipeline.ingest(
        artifact_type=ArtifactType.JSON,
        filename="api_sample.json",
        raw_bytes=raw_sample,
    )

    assert record.quarantine_status == QuarantineStatus.VALIDATED
    assert record.assessment_id == "ASM-ART-01"
    assert len(record.sha256) == 64
    assert pipeline.registry.exists(record.artifact_id)


def test_cross_assessment_registry_isolation():
    """INV-M8-04: Registry blocks registering or accessing artifacts across assessments."""
    reg_a = ArtifactRegistry("ASM-AAA")
    reg_b = ArtifactRegistry("ASM-BBB")

    rec_a = ArtifactRecord.create(
        assessment_id="ASM-AAA",
        artifact_type=ArtifactType.JSON,
        filename="tenant_a.json",
        raw_bytes=b'{"tenant": "A"}',
    )

    reg_a.register(rec_a)
    assert reg_a.exists(rec_a.artifact_id) is True

    # Attempting to register rec_a into reg_b must raise ValueError
    with pytest.raises(ValueError) as exc:
        reg_b.register(rec_a)
    assert "Assessment mismatch" in str(exc.value)

    # Cannot retrieve from other tenant
    assert reg_b.get_artifact(rec_a.artifact_id) is None


def test_quarantine_path_traversal_filename():
    """Security policy blocks directory traversal in artifact filenames."""
    pipeline = ArtifactIngestionPipeline("ASM-QUAR-01")

    for bad_name in ["../../etc/passwd", "..\\boot.ini", "%2e%2e/secret.json"]:
        record, obs = pipeline.ingest(
            artifact_type=ArtifactType.TEXT,
            filename=bad_name,
            raw_bytes=b"sample payload",
        )
        assert record.quarantine_status == QuarantineStatus.QUARANTINED
        assert record.quarantine_reason == QuarantineReason.SECURITY_POLICY
        assert pipeline.quarantine_manager.is_quarantined(record.artifact_id)
        # Not registered in active registry
        assert pipeline.registry.exists(record.artifact_id) is False
        assert len(obs) == 0


def test_quarantine_corrupted_and_empty_artifacts():
    """Corrupted or 0-byte artifacts fail closed into quarantine."""
    pipeline = ArtifactIngestionPipeline("ASM-QUAR-02")

    # 1. Zero byte file
    rec_empty, obs1 = pipeline.ingest(
        artifact_type=ArtifactType.JSON,
        filename="empty.json",
        raw_bytes=b"",
    )
    assert rec_empty.quarantine_status == QuarantineStatus.QUARANTINED
    assert rec_empty.quarantine_reason == QuarantineReason.CORRUPTED
    assert len(obs1) == 0

    # 2. Malformed JSON
    rec_malformed, obs2 = pipeline.ingest(
        artifact_type=ArtifactType.JSON,
        filename="broken.json",
        raw_bytes=b"{invalid: json broken here",
    )
    assert rec_malformed.quarantine_status == QuarantineStatus.QUARANTINED
    assert rec_malformed.quarantine_reason == QuarantineReason.MALFORMED
    assert len(obs2) == 0


def test_quarantine_cross_assessment_metadata():
    """Artifact metadata claiming another assessment is quarantined."""
    pipeline = ArtifactIngestionPipeline("ASM-PRIMARY")

    rec, obs = pipeline.ingest(
        artifact_type=ArtifactType.JSON,
        filename="cross.json",
        raw_bytes=b'{"valid": true}',
        metadata={"assessment_id": "ASM-OTHER-ORGANIZATION"},
    )
    assert rec.quarantine_status == QuarantineStatus.QUARANTINED
    assert rec.quarantine_reason == QuarantineReason.CROSS_ASSESSMENT
    assert pipeline.registry.exists(rec.artifact_id) is False


def test_quarantine_unredacted_private_keys():
    """Plaintext private keys trigger SECRET_DETECTED quarantine."""
    pipeline = ArtifactIngestionPipeline("ASM-SECRET-01")

    key_payload = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----"
    rec, obs = pipeline.ingest(
        artifact_type=ArtifactType.TEXT,
        filename="id_rsa",
        raw_bytes=key_payload,
    )
    assert rec.quarantine_status == QuarantineStatus.QUARANTINED
    assert rec.quarantine_reason == QuarantineReason.SECRET_DETECTED


def test_android_artifact_honest_layer_reporting():
    """Stand-alone AndroidManifest.xml must report MANIFEST: ANALYZED, but DEX/SMALI: NOT_ANALYZED."""
    pipeline = ArtifactIngestionPipeline("ASM-MOB-01")

    manifest_xml = b"""<?xml version="1.0" encoding="utf-8"?>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.target.corp">
        <application>
            <activity android:name=".MainActivity" android:exported="true" />
        </application>
    </manifest>
    """

    rec, obs_list = pipeline.ingest(
        artifact_type=ArtifactType.XML,
        filename="AndroidManifest.xml",
        raw_bytes=manifest_xml,
    )

    assert rec.quarantine_status == QuarantineStatus.VALIDATED
    assert len(obs_list) == 1
    layers = rec.extracted_layers
    assert layers["MANIFEST"] == "ANALYZED"
    assert layers["DEX"] == "NOT_ANALYZED"
    assert layers["SMALI"] == "NOT_ANALYZED"
    assert layers["NATIVE"] == "NOT_ANALYZED"


def test_har_ingestion_and_secret_redaction():
    """HAR ingestion normalizes entries and redacts authorization tokens."""
    pipeline = ArtifactIngestionPipeline("ASM-WEB-01")

    har_sample = {
        "log": {
            "entries": [
                {
                    "request": {
                        "url": "https://api.targetcorp.com/v1/profile",
                        "method": "GET",
                        "headers": [
                            {"name": "Authorization", "value": "Bearer secret_jwt_token_12345"},
                            {"name": "X-Api-Key", "value": "secret_api_key_abcdef"},
                        ],
                    },
                    "response": {"status": 200, "headers": []},
                }
            ]
        }
    }

    rec, obs_list = pipeline.ingest(
        artifact_type=ArtifactType.HAR,
        filename="traffic.har",
        raw_bytes=json.dumps(har_sample).encode(),
    )

    assert rec.quarantine_status == QuarantineStatus.VALIDATED
    assert len(obs_list) == 1
    obs = obs_list[0]
    headers = obs.normalized_data["headers"]
    header_vals = [h.get("value", "") for h in headers]
    for val in header_vals:
        assert "secret_jwt_token_12345" not in val
        assert "secret_api_key_abcdef" not in val
