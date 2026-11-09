"""Cryptographic Provenance and Hashing Utilities for Artifact Ingestion."""

import hashlib
from pathlib import Path
from typing import Union


def compute_sha256_bytes(data: bytes) -> str:
    """Computes SHA-256 hex digest for in-memory bytes."""
    return hashlib.sha256(data).hexdigest()


def compute_sha256_file(filepath: Union[str, Path]) -> str:
    """Computes SHA-256 hex digest for a file on disk."""
    p = Path(filepath)
    if not p.is_file():
        raise FileNotFoundError(f"File '{filepath}' does not exist.")
    hasher = hashlib.sha256()
    with open(p, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def verify_sha256(data: bytes, expected_hash: str) -> bool:
    """Verifies data matches expected SHA-256 hash."""
    return compute_sha256_bytes(data).lower() == expected_hash.lower()
