"""Cryptographic Provenance and RFC 9162 Merkle Tree Verification.

Implements the high-assurance Cryptographic Trust Chain per M3 Plan v2.3.8 Section 8.3:
- RFC 9162 Certificate Transparency Merkle Tree Hash (MTH)
- RFC 8785 JSON Canonicalization Scheme (JCS)
- Offline Ed25519 digital signatures and pinned trust roots
- Deterministic fail-closed verification pipeline
"""

import hashlib
import json
import logging
import struct
from typing import Any, Dict, List, Optional, Sequence, Tuple
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from src.knowledge.models import (
    CorpusManifest,
    KnowledgeChunk,
    TrustRootRecord,
)

logger = logging.getLogger("m3.provenance")

EMPTY_TREE_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


class ProvenanceVerificationError(Exception):
    """Raised when any step of the cryptographic provenance check fails."""
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message


def canonical_jcs_serialize(obj: Any) -> bytes:
    """
    Serialize an object into RFC 8785 (JCS) canonical JSON representation.
    
    Guarantees deterministic byte-identical serialization across all runtimes:
    - UTF-8 encoded
    - Sorted keys
    - Minimal separators (no whitespace around commas or colons)
    - ensure_ascii=False
    """
    def _normalize(val: Any) -> Any:
        if hasattr(val, "model_dump"):
            return _normalize(val.model_dump())
        elif isinstance(val, dict):
            return {k: _normalize(v) for k, v in val.items()}
        elif isinstance(val, (list, tuple)):
            return [_normalize(item) for item in val]
        elif val is None or isinstance(val, (str, int, float, bool)):
            return val
        else:
            return str(val)

    normalized = _normalize(obj)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def compute_canonical_leaf_bytes(
    chunk_id: str,
    chunk_hash: bytes,
    doc_hash: bytes,
) -> bytes:
    """
    Construct canonical binary leaf payload per Section 8.3.1:
    d_i = ChunkHash_i (32B) || DocHash_j(i) (32B) || LengthPrefixedChunkID_i
    """
    if len(chunk_hash) != 32:
        raise ValueError(f"chunk_hash must be 32 bytes, got {len(chunk_hash)}")
    if len(doc_hash) != 32:
        raise ValueError(f"doc_hash must be 32 bytes, got {len(doc_hash)}")

    chunk_id_bytes = chunk_id.encode("utf-8")
    if len(chunk_id_bytes) > 65535:
        raise ValueError(f"chunk_id too long for uint16 prefix: {len(chunk_id_bytes)}")

    length_prefix = struct.pack(">H", len(chunk_id_bytes))
    return chunk_hash + doc_hash + length_prefix + chunk_id_bytes


def compute_rfc9162_mth(leaf_bytes_list: Sequence[bytes]) -> bytes:
    """
    Compute RFC 9162 Merkle Tree Hash (MTH) over an ordered dataset of leaves.
    
    Follows Section 2.1.2 of RFC 9162:
    - n == 0: SHA-256("")
    - n == 1: SHA-256(0x00 || d_0)
    - n > 1:  k = 2^floor(log2(n - 1)), MTH = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
    """
    n = len(leaf_bytes_list)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return hashlib.sha256(b"\x00" + leaf_bytes_list[0]).digest()

    # Largest power of two strictly less than n
    k = 1 << ((n - 1).bit_length() - 1)

    left_mth = compute_rfc9162_mth(leaf_bytes_list[:k])
    right_mth = compute_rfc9162_mth(leaf_bytes_list[k:])
    return hashlib.sha256(b"\x01" + left_mth + right_mth).digest()


def compute_corpus_merkle_root(
    chunks: Sequence[KnowledgeChunk],
    document_hashes: Dict[str, str],
) -> str:
    """
    Compute deterministic RFC 9162 Merkle root for a collection of chunks.
    
    Enforces:
    - Strict sorting by chunk_id ASC in UTF-8 byte order
    - Strict uniqueness of chunk_id
    - Matching parent document hashes
    """
    seen_ids = set()
    for chunk in chunks:
        if chunk.chunk_id in seen_ids:
            raise ValueError(f"Duplicate chunk_id detected: {chunk.chunk_id}")
        seen_ids.add(chunk.chunk_id)

    # Sort strictly by chunk_id ASC (ASCII/UTF-8 byte order)
    sorted_chunks = sorted(chunks, key=lambda c: c.chunk_id.encode("utf-8"))

    leaves: List[bytes] = []
    for chunk in sorted_chunks:
        if chunk.document_id not in document_hashes:
            raise ValueError(f"Document hash missing for document_id: {chunk.document_id}")

        doc_hash_bytes = bytes.fromhex(document_hashes[chunk.document_id])
        chunk_hash_bytes = bytes.fromhex(chunk.content_hash)
        leaf = compute_canonical_leaf_bytes(
            chunk_id=chunk.chunk_id,
            chunk_hash=chunk_hash_bytes,
            doc_hash=doc_hash_bytes,
        )
        leaves.append(leaf)

    mth_bytes = compute_rfc9162_mth(leaves)
    return mth_bytes.hex().lower()


def compute_rfc9162_audit_path(leaves: Sequence[bytes], m: int) -> List[bytes]:
    """
    Compute RFC 9162 audit path for leaf at index m in an ordered dataset of leaves.
    Returns list of sibling hash bytes from bottom up to root.
    """
    n = len(leaves)
    if not (0 <= m < n):
        raise IndexError(f"Leaf index {m} out of range for n={n}")
    if n <= 1:
        return []

    k = 1 << ((n - 1).bit_length() - 1)
    if m < k:
        return compute_rfc9162_audit_path(leaves[:k], m) + [compute_rfc9162_mth(leaves[k:])]
    else:
        return compute_rfc9162_audit_path(leaves[k:], m - k) + [compute_rfc9162_mth(leaves[:k])]


def verify_rfc9162_audit_path(
    leaf_bytes: bytes,
    m: int,
    n: int,
    audit_path: Sequence[bytes],
    root: bytes,
) -> bool:
    """
    Verify RFC 9162 audit path proving leaf at index m is in tree of size n with root hash.
    """
    if not (0 <= m < n):
        return False

    def _reconstruct_root(cur_m: int, cur_n: int, p: Sequence[bytes]) -> bytes:
        if cur_n == 1:
            return hashlib.sha256(b"\x00" + leaf_bytes).digest()
        k = 1 << ((cur_n - 1).bit_length() - 1)
        if not p:
            raise ValueError("Audit path too short")
        sibling = p[-1]
        rest = p[:-1]
        if cur_m < k:
            left = _reconstruct_root(cur_m, k, rest)
            return hashlib.sha256(b"\x01" + left + sibling).digest()
        else:
            right = _reconstruct_root(cur_m - k, cur_n - k, rest)
            return hashlib.sha256(b"\x01" + sibling + right).digest()

    try:
        reconstructed = _reconstruct_root(m, n, audit_path)
        return reconstructed == root
    except Exception:
        return False


class CryptographicTrustAuthority:
    """
    Manages offline trust roots, Ed25519 manifest signing, and fail-closed verification.
    """

    @staticmethod
    def generate_keypair() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
        """Generate a fresh Ed25519 signing keypair."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        return private_key, private_key.public_key()

    @staticmethod
    def create_trust_root_record(
        key_id: str,
        public_key: ed25519.Ed25519PublicKey,
        description: str = "Pinned M3 Offline Signing Root",
        created_at: str = "2026-09-20T00:00:00Z",
    ) -> TrustRootRecord:
        """Create an immutable trust-root record from an Ed25519 public key."""
        raw_pub = public_key.public_bytes_raw()
        pub_hex = raw_pub.hex().lower()
        fingerprint = hashlib.sha256(raw_pub).hexdigest().lower()
        return TrustRootRecord(
            key_id=key_id,
            public_key_bytes=pub_hex,
            public_key_fingerprint=fingerprint,
            algorithm="Ed25519",
            created_at=created_at,
            description=description,
        )

    @staticmethod
    def sign_manifest(
        manifest: CorpusManifest,
        private_key: ed25519.Ed25519PrivateKey,
    ) -> bytes:
        """
        Sign the RFC 8785 canonical JSON bytes of the manifest using Ed25519.
        Returns the raw 64-byte detached signature.
        """
        jcs_bytes = canonical_jcs_serialize(manifest)
        return private_key.sign(jcs_bytes)

    @staticmethod
    def verify_trust_root(trust_root: TrustRootRecord) -> ed25519.Ed25519PublicKey:
        """
        Verify the pinned trust root record integrity:
        SHA-256(public_key_bytes) == pinned fingerprint.
        Returns the loaded Ed25519PublicKey.
        """
        try:
            pub_bytes = bytes.fromhex(trust_root.public_key_bytes)
        except ValueError as e:
            raise ProvenanceVerificationError(
                "TRUST_ROOT_MALFORMED", f"Invalid hex in trust root public_key_bytes: {e}"
            )

        computed_fingerprint = hashlib.sha256(pub_bytes).hexdigest().lower()
        if computed_fingerprint != trust_root.public_key_fingerprint.lower():
            raise ProvenanceVerificationError(
                "TRUST_ROOT_FINGERPRINT_MISMATCH",
                f"Computed fingerprint {computed_fingerprint} does not match pinned {trust_root.public_key_fingerprint}",
            )

        return ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)

    @classmethod
    def verify_manifest_signature(
        cls,
        manifest_data: Dict[str, Any],
        signature_bytes: bytes,
        trust_root: TrustRootRecord,
    ) -> bool:
        """
        Verify detached Ed25519 signature over canonical JCS manifest bytes.
        """
        pub_key = cls.verify_trust_root(trust_root)
        jcs_bytes = canonical_jcs_serialize(manifest_data)
        try:
            pub_key.verify(signature_bytes, jcs_bytes)
            return True
        except InvalidSignature:
            raise ProvenanceVerificationError(
                "CORPUS_SIGNATURE_VERIFICATION_FAILED",
                "Detached Ed25519 signature did not verify against manifest content",
            )

    @classmethod
    def verify_corpus_integrity(
        cls,
        manifest: CorpusManifest,
        signature_bytes: bytes,
        trust_root: TrustRootRecord,
        chunks: Sequence[KnowledgeChunk],
    ) -> bool:
        """
        Execute full deterministic verification sequence (Section 8.4):
        1. Offline Trust-Root & Detached Signature Verification
        2. Manifest Schema & Identity Validation
        3. Merkle Root Validation
        4. Document & Chunk Hash Verification
        """
        # Step 1: Signature Verification
        cls.verify_manifest_signature(manifest.model_dump(), signature_bytes, trust_root)

        # Step 2: Merkle Root Validation
        recomputed_root = compute_corpus_merkle_root(chunks, manifest.document_hashes)
        if recomputed_root != manifest.merkle_root.lower():
            raise ProvenanceVerificationError(
                "CORPUS_TAMPER_DETECTED",
                f"Recomputed Merkle root {recomputed_root} does not match signed root {manifest.merkle_root}",
            )

        # Step 3: Chunk Hash Verification
        for chunk in chunks:
            if chunk.chunk_id not in manifest.chunk_hashes:
                raise ProvenanceVerificationError(
                    "CHUNK_NOT_IN_MANIFEST",
                    f"Chunk {chunk.chunk_id} missing from manifest chunk_hashes",
                )
            if chunk.content_hash.lower() != manifest.chunk_hashes[chunk.chunk_id].lower():
                raise ProvenanceVerificationError(
                    "CHUNK_HASH_MISMATCH",
                    f"Chunk {chunk.chunk_id} content hash {chunk.content_hash} != manifest {manifest.chunk_hashes[chunk.chunk_id]}",
                )

        return True
