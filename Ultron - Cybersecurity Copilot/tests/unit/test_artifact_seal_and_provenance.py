"""
Regression and security invariant tests for:
- Finding 4: Artifact Sealing, Detached Verification & Trust Model
- Finding 5: Live LLM vs Deterministic Simulator Execution Provenance
"""

from pathlib import Path
import pytest

from src.eval.artifact_seal import (
    AutomatedVerification,
    AuthoritativeArtifactSeal,
    ProceduralAttestation,
    create_authoritative_seal,
    verify_authoritative_seal,
)
from src.eval.provenance import EvaluationProvenanceRecord, ExecutionProvenance
from src.knowledge.provenance import CryptographicTrustAuthority


# ===========================================================================
# Finding 4 Tests: Artifact Sealing & Independent Verification
# ===========================================================================

@pytest.fixture
def seal_env(tmp_path: Path):
    """Creates a temporary sandbox of files and keys for artifact seal testing."""
    art1 = tmp_path / "model_weights.bin"
    art1.write_bytes(b"DATA_WEIGHTS_V1")

    art2 = tmp_path / "eval_dataset.json"
    art2.write_text('{"eval_units": [1, 2, 3]}', encoding="utf-8")

    manifest_path = tmp_path / "manifest.json"
    sig_path = tmp_path / "manifest.sig"

    private_key, public_key = CryptographicTrustAuthority.generate_keypair()
    trust_root = CryptographicTrustAuthority.create_trust_root_record(
        key_id="KEY-TEST-01",
        public_key=public_key,
        description="Test Offline Root",
    )

    return {
        "tmp_path": tmp_path,
        "art1": art1,
        "art2": art2,
        "manifest_path": manifest_path,
        "sig_path": sig_path,
        "private_key": private_key,
        "public_key": public_key,
        "trust_root": trust_root,
        "artifacts": {
            "model_weights": art1,
            "eval_dataset": art2,
        },
    }


def test_authoritative_seal_creation_and_valid_verification(seal_env):
    """Valid seal with detached signature verifies with 100% integrity and authenticity."""
    verifications = [
        AutomatedVerification(
            claim_id="model_weights_present",
            target_path=str(seal_env["art1"]),
            verification_method="file_exists_and_sha256",
            status="VERIFIED",
            observed_value="DATA_WEIGHTS_V1",
            expected_value="DATA_WEIGHTS_V1",
            verified_at="2026-09-22T00:00:00Z",
        )
    ]
    attestations = [
        ProceduralAttestation(
            claim_id="offline_boundary",
            statement="All evaluations performed strictly offline without internet access.",
            attestation_type="PROCEDURAL",
            attested_by="lead_evaluator",
            provenance_source="airgap_isolation_checklist_2026.md",
            rationale="Enforces reproducibility without external network drift.",
        )
    ]

    seal, sig = create_authoritative_seal(
        artifact_paths=seal_env["artifacts"],
        verifications=verifications,
        attestations=attestations,
        private_key=seal_env["private_key"],
        output_manifest_path=seal_env["manifest_path"],
        output_signature_path=seal_env["sig_path"],
    )

    assert seal.manifest_digest_sha256 is not None
    assert sig is not None

    # Verify seal
    result = verify_authoritative_seal(
        manifest_path=seal_env["manifest_path"],
        artifact_paths=seal_env["artifacts"],
        signature_path=seal_env["sig_path"],
        trust_root=seal_env["trust_root"],
    )

    assert result.integrity_valid is True
    assert result.authenticity_valid is True
    assert result.manifest_digest_valid is True
    assert result.all_artifacts_present is True
    assert result.signature_status == "VALID"
    assert len(result.tampered_artifacts) == 0


def test_seal_verifier_detects_modified_artifact(seal_env):
    """If an underlying artifact is modified after sealing, verifier reports tampered_artifacts."""
    create_authoritative_seal(
        artifact_paths=seal_env["artifacts"],
        output_manifest_path=seal_env["manifest_path"],
    )

    # Tamper with artifact 1
    seal_env["art1"].write_bytes(b"TAMPERED_WEIGHTS_CONTENT")

    result = verify_authoritative_seal(
        manifest_path=seal_env["manifest_path"],
        artifact_paths=seal_env["artifacts"],
    )

    assert result.integrity_valid is False
    assert "model_weights" in result.tampered_artifacts
    assert any("hash mismatch" in err for err in result.error_messages)


def test_seal_verifier_detects_modified_manifest_digest(seal_env):
    """If manifest payload is altered, canonical digest recomputation detects tampering."""
    seal, _ = create_authoritative_seal(
        artifact_paths=seal_env["artifacts"],
        output_manifest_path=seal_env["manifest_path"],
    )

    # Tamper with manifest file content (modify milestone directly in JSON)
    manifest_text = seal_env["manifest_path"].read_text(encoding="utf-8")
    tampered_text = manifest_text.replace('"milestone": "M5"', '"milestone": "TAMPERED"')
    seal_env["manifest_path"].write_text(tampered_text, encoding="utf-8")

    result = verify_authoritative_seal(
        manifest_path=seal_env["manifest_path"],
        artifact_paths=seal_env["artifacts"],
    )

    assert result.integrity_valid is False
    assert result.manifest_digest_valid is False
    assert any("Manifest digest mismatch" in err for err in result.error_messages)


def test_seal_verifier_detects_invalid_and_missing_signatures(seal_env):
    """Verifier distinguishes valid, invalid, and missing detached signatures."""
    # 1. Create seal with signature
    create_authoritative_seal(
        artifact_paths=seal_env["artifacts"],
        private_key=seal_env["private_key"],
        output_manifest_path=seal_env["manifest_path"],
        output_signature_path=seal_env["sig_path"],
    )

    # Missing signature file
    missing_sig = seal_env["tmp_path"] / "nonexistent.sig"
    res_missing = verify_authoritative_seal(
        manifest_path=seal_env["manifest_path"],
        signature_path=missing_sig,
        trust_root=seal_env["trust_root"],
    )
    assert res_missing.authenticity_valid is False
    assert res_missing.signature_status == "MISSING"

    # Invalid signature file (wrong signature bytes)
    bad_sig = seal_env["tmp_path"] / "bad.sig"
    bad_sig.write_bytes(b"\x00" * 64)
    res_bad = verify_authoritative_seal(
        manifest_path=seal_env["manifest_path"],
        signature_path=bad_sig,
        trust_root=seal_env["trust_root"],
    )
    assert res_bad.authenticity_valid is False
    assert res_bad.signature_status == "INVALID"


# ===========================================================================
# Finding 5 Tests: Execution Provenance Invariants
# ===========================================================================

def test_provenance_live_llm_valid():
    """LIVE_LLM requires live_model_active=True, model_name, inference_count > 0, simulator_active=False."""
    record = EvaluationProvenanceRecord(
        execution_provenance=ExecutionProvenance.LIVE_LLM,
        live_model_active=True,
        model_name="qwen2.5-coder:7b",
        inference_count=5,
        simulator_active=False,
    )
    assert record.execution_provenance == ExecutionProvenance.LIVE_LLM
    assert record.model_name == "qwen2.5-coder:7b"


def test_provenance_rejects_live_llm_with_simulator_without_hybrid():
    """Reject LIVE_LLM if simulator_active=True (must be declared HYBRID)."""
    with pytest.raises(ValueError, match="LIVE_LLM provenance cannot have simulator_active=True; use HYBRID"):
        EvaluationProvenanceRecord(
            execution_provenance=ExecutionProvenance.LIVE_LLM,
            live_model_active=True,
            model_name="qwen2.5-coder:7b",
            inference_count=5,
            simulator_active=True,  # Invalid combination!
        )


def test_provenance_deterministic_simulator_invariants():
    """DETERMINISTIC_SIMULATOR must have simulator_active=True and inference_count=0."""
    record = EvaluationProvenanceRecord(
        execution_provenance=ExecutionProvenance.DETERMINISTIC_SIMULATOR,
        simulator_active=True,
        live_model_active=False,
        inference_count=0,
    )
    assert record.simulator_active is True

    # Cannot claim live model
    with pytest.raises(ValueError, match="DETERMINISTIC_SIMULATOR cannot have live_model_active=True"):
        EvaluationProvenanceRecord(
            execution_provenance=ExecutionProvenance.DETERMINISTIC_SIMULATOR,
            simulator_active=True,
            live_model_active=True,
            inference_count=0,
        )

    # Cannot claim inference count > 0
    with pytest.raises(ValueError, match="DETERMINISTIC_SIMULATOR cannot have inference_count > 0"):
        EvaluationProvenanceRecord(
            execution_provenance=ExecutionProvenance.DETERMINISTIC_SIMULATOR,
            simulator_active=True,
            inference_count=10,
        )


def test_provenance_hermetic_pipeline_invariants():
    """HERMETIC_PIPELINE cannot use live model or simulator."""
    record = EvaluationProvenanceRecord(
        execution_provenance=ExecutionProvenance.HERMETIC_PIPELINE,
        live_model_active=False,
        simulator_active=False,
        inference_count=0,
    )
    assert record.execution_provenance == ExecutionProvenance.HERMETIC_PIPELINE

    with pytest.raises(ValueError, match="HERMETIC_PIPELINE cannot have live_model_active=True"):
        EvaluationProvenanceRecord(
            execution_provenance=ExecutionProvenance.HERMETIC_PIPELINE,
            live_model_active=True,
        )


def test_provenance_hybrid_requires_both():
    """HYBRID requires both simulator_active=True and live_model_active=True."""
    record = EvaluationProvenanceRecord(
        execution_provenance=ExecutionProvenance.HYBRID,
        simulator_active=True,
        live_model_active=True,
        model_name="qwen2.5-coder:7b",
        inference_count=3,
    )
    assert record.execution_provenance == ExecutionProvenance.HYBRID

    with pytest.raises(ValueError, match="HYBRID provenance requires simulator_active=True"):
        EvaluationProvenanceRecord(
            execution_provenance=ExecutionProvenance.HYBRID,
            simulator_active=False,
            live_model_active=True,
            model_name="qwen2.5-coder:7b",
            inference_count=3,
        )
