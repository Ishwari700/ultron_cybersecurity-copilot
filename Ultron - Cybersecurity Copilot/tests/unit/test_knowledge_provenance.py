"""Unit tests for RFC 9162 Merkle tree, JCS, and Ed25519 cryptographic trust."""

import hashlib
import pytest

from src.knowledge.models import (
    CorpusManifest,
    KnowledgeChunk,
    KnowledgeSourceType,
    KnowledgeType,
    TrustRootRecord,
)
from src.knowledge.provenance import (
    EMPTY_TREE_SHA256,
    CryptographicTrustAuthority,
    ProvenanceVerificationError,
    canonical_jcs_serialize,
    compute_canonical_leaf_bytes,
    compute_corpus_merkle_root,
    compute_rfc9162_mth,
)


def test_rfc9162_mth_base_cases():
    """Verify empty tree and single leaf base cases per RFC 9162 Section 2.1.2."""
    # n = 0: SHA-256("")
    empty_root = compute_rfc9162_mth([])
    assert empty_root.hex() == EMPTY_TREE_SHA256

    # n = 1: SHA-256(0x00 || d_0)
    leaf_0 = b"leaf_payload_test"
    single_root = compute_rfc9162_mth([leaf_0])
    expected_single = hashlib.sha256(b"\x00" + leaf_0).digest()
    assert single_root == expected_single


def test_rfc9162_mth_recursive_combination():
    """Verify power-of-two recursive splitting for n > 1."""
    d0 = b"leaf_0"
    d1 = b"leaf_1"
    d2 = b"leaf_2"

    # n = 2: k = 1. MTH = SHA-256(0x01 || MTH(d0) || MTH(d1))
    mth_2 = compute_rfc9162_mth([d0, d1])
    mth_d0 = hashlib.sha256(b"\x00" + d0).digest()
    mth_d1 = hashlib.sha256(b"\x00" + d1).digest()
    expected_2 = hashlib.sha256(b"\x01" + mth_d0 + mth_d1).digest()
    assert mth_2 == expected_2

    # n = 3: k = 2. MTH = SHA-256(0x01 || MTH(d0, d1) || MTH(d2))
    mth_3 = compute_rfc9162_mth([d0, d1, d2])
    mth_d2 = hashlib.sha256(b"\x00" + d2).digest()
    expected_3 = hashlib.sha256(b"\x01" + mth_2 + mth_d2).digest()
    assert mth_3 == expected_3


def test_canonical_leaf_bytes_structure():
    """Verify leaf construction: ChunkHash (32B) || DocHash (32B) || uint16_be(len) || ID."""
    chunk_hash = b"\xaa" * 32
    doc_hash = b"\xbb" * 32
    chunk_id = "CHK-TEST-01"

    leaf = compute_canonical_leaf_bytes(chunk_id, chunk_hash, doc_hash)
    assert len(leaf) == 32 + 32 + 2 + len(chunk_id.encode("utf-8"))
    assert leaf[:32] == chunk_hash
    assert leaf[32:64] == doc_hash


def test_merkle_root_determinism_and_sorting():
    """Verify strict chunk_id ASC ordering and determinism."""
    doc_hashes = {"DOC-01": "aa" * 32, "DOC-02": "bb" * 32}

    c1 = KnowledgeChunk(
        chunk_id="CHK-DOC-01-002-01",
        document_id="DOC-01",
        source_type=KnowledgeSourceType.OWASP_WSTG,
        knowledge_type=KnowledgeType.TESTING_METHODOLOGY,
        title="T1",
        section_heading="S1",
        content="C1",
        token_estimate=10,
        content_hash="11" * 32,
    )
    c2 = KnowledgeChunk(
        chunk_id="CHK-DOC-01-001-01",
        document_id="DOC-01",
        source_type=KnowledgeSourceType.OWASP_WSTG,
        knowledge_type=KnowledgeType.TESTING_METHODOLOGY,
        title="T2",
        section_heading="S2",
        content="C2",
        token_estimate=10,
        content_hash="22" * 32,
    )

    # Calling with [c1, c2] or [c2, c1] must produce identical root
    root1 = compute_corpus_merkle_root([c1, c2], doc_hashes)
    root2 = compute_corpus_merkle_root([c2, c1], doc_hashes)
    assert root1 == root2

    # Duplicate IDs must fail closed
    with pytest.raises(ValueError, match="Duplicate chunk_id"):
        compute_corpus_merkle_root([c1, c1], doc_hashes)


def test_jcs_serialization_determinism():
    """Verify RFC 8785 JSON Canonicalization Scheme sorted keys and compact separators."""
    obj1 = {"b": 2, "a": 1, "nested": {"z": 9, "y": 8}}
    obj2 = {"nested": {"y": 8, "z": 9}, "a": 1, "b": 2}

    jcs1 = canonical_jcs_serialize(obj1)
    jcs2 = canonical_jcs_serialize(obj2)
    assert jcs1 == jcs2
    assert b" " not in jcs1
    assert jcs1 == b'{"a":1,"b":2,"nested":{"y":8,"z":9}}'


def test_ed25519_trust_root_verification_and_signing():
    """Verify Ed25519 key verification, signing, and tamper detection."""
    priv, pub = CryptographicTrustAuthority.generate_keypair()
    trust_root = CryptographicTrustAuthority.create_trust_root_record(
        key_id="KEY-TEST-ROOT",
        public_key=pub,
        description="Test Trust Root",
    )

    # Fingerprint verification
    verified_pub = CryptographicTrustAuthority.verify_trust_root(trust_root)
    assert verified_pub.public_bytes_raw() == pub.public_bytes_raw()

    # Tampered fingerprint fails closed
    corrupt_tr = TrustRootRecord(
        key_id=trust_root.key_id,
        public_key_bytes=trust_root.public_key_bytes,
        public_key_fingerprint="ff" * 32,
        algorithm="Ed25519",
        created_at=trust_root.created_at,
        description="Corrupted Fingerprint",
    )
    with pytest.raises(ProvenanceVerificationError, match="TRUST_ROOT_FINGERPRINT_MISMATCH"):
        CryptographicTrustAuthority.verify_trust_root(corrupt_tr)

    # Manifest signing & verification
    manifest = CorpusManifest(
        manifest_version="3.0.0",
        corpus_version="3.0.0",
        merkle_root="test_root_123",
        document_hashes={},
        chunk_hashes={},
        chunk_count=0,
        document_count=0,
        build_timestamp="2026-09-20T00:00:00Z",
        builder_commit="819b833",
        build_environment="Test",
        toolchain_version="Py3.13",
        chunker_code_hash="codehash",
    )
    sig = CryptographicTrustAuthority.sign_manifest(manifest, priv)
    assert len(sig) == 64

    assert CryptographicTrustAuthority.verify_manifest_signature(
        manifest.model_dump(), sig, trust_root
    )

    # Tampered manifest content fails closed
    tampered_manifest = manifest.model_copy(update={"merkle_root": "corrupted_root"})
    with pytest.raises(ProvenanceVerificationError, match="CORPUS_SIGNATURE_VERIFICATION_FAILED"):
        CryptographicTrustAuthority.verify_manifest_signature(
            tampered_manifest.model_dump(), sig, trust_root
        )
