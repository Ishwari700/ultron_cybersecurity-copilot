"""Shared safe, atomic artifact writing mechanism.

Provides atomic per-file replacement, staging validation, fsync,
SHA-256 calculation from exact serialized bytes, and cleanup on failure.
"""

import hashlib
import json
import math
import os
from pathlib import Path
import tempfile
from typing import Any, Dict, Optional, Tuple


class AtomicWriteError(Exception):
    """Raised when an atomic write or validation fails."""
    pass


def atomic_write_bytes(
    dest_path: Path,
    data: bytes,
    fsync: bool = True,
    temp_prefix: str = ".tmp_",
) -> str:
    """Atomically writes binary data to dest_path using same-directory staging.

    1. Writes to a temporary file in dest_path.parent (same filesystem).
    2. Flushes and calls os.fsync where supported.
    3. Computes SHA-256 digest from the exact serialized bytes.
    4. Atomically replaces dest_path using os.replace.
    5. Cleans up temporary file on failure without corrupting dest_path.

    Returns:
        Hex-encoded SHA-256 digest of the written bytes.
    """
    dest_path = Path(dest_path).resolve()
    dest_dir = dest_path.parent
    dest_dir.mkdir(parents=True, exist_ok=True)

    sha256_hash = hashlib.sha256(data).hexdigest()

    # Create temporary file in the destination directory to ensure same-filesystem atomic replace
    temp_file = tempfile.NamedTemporaryFile(
        dir=dest_dir,
        prefix=temp_prefix,
        suffix=".tmp",
        delete=False,
    )
    temp_path = Path(temp_file.name)

    try:
        temp_file.write(data)
        temp_file.flush()
        if fsync:
            try:
                os.fsync(temp_file.fileno())
            except (OSError, AttributeError):
                pass
        temp_file.close()

        # Atomic replacement on destination
        os.replace(temp_path, dest_path)
        return sha256_hash

    except Exception as exc:
        if temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass
        raise AtomicWriteError(f"Failed to atomically write bytes to {dest_path}: {exc}") from exc


def atomic_write_json(
    dest_path: Path,
    data: Any,
    indent: int = 2,
    fsync: bool = True,
    validate_staged: bool = True,
    write_checksum_sidecar: bool = False,
) -> Tuple[str, Optional[Path]]:
    """Atomically serializes and writes JSON data with staging validation and optional sidecar.

    1. Serializes complete data to UTF-8 bytes before touching disk.
    2. Optionally validates staged JSON by round-trip parsing.
    3. Atomically replaces destination JSON file.
    4. If write_checksum_sidecar=True, atomically writes <filename>.sha256 sidecar.

    Returns:
        (sha256_hash, sidecar_path_or_none)
    """
    dest_path = Path(dest_path).resolve()

    try:
        json_str = json.dumps(data, indent=indent, ensure_ascii=False)
        json_bytes = json_str.encode("utf-8")
    except Exception as exc:
        raise AtomicWriteError(f"JSON serialization failed for {dest_path}: {exc}") from exc

    if validate_staged:
        try:
            # Staging validation
            json.loads(json_str)
        except Exception as exc:
            raise AtomicWriteError(f"Staged JSON validation failed for {dest_path}: {exc}") from exc

    # Atomic write JSON
    sha256_digest = atomic_write_bytes(dest_path, json_bytes, fsync=fsync)

    sidecar_path = None
    if write_checksum_sidecar:
        sidecar_path = dest_path.parent / (dest_path.name + ".sha256")
        sidecar_bytes = sha256_digest.encode("utf-8")
        atomic_write_bytes(sidecar_path, sidecar_bytes, fsync=fsync)

    return sha256_digest, sidecar_path


def clean_orphaned_tmp_files(directory: Path, prefix: str = ".tmp_") -> int:
    """Removes leftover temporary files from interrupted runs in directory."""
    directory = Path(directory).resolve()
    if not directory.exists() or not directory.is_dir():
        return 0

    cleaned = 0
    for child in directory.iterdir():
        if child.is_file() and child.name.startswith(prefix) and child.name.endswith(".tmp"):
            try:
                child.unlink()
                cleaned += 1
            except OSError:
                pass
    return cleaned


def verify_artifact_checksum(file_path: Path, sidecar_path: Optional[Path] = None) -> Tuple[bool, str, Optional[str]]:
    """Verifies that a file's actual byte SHA-256 matches its sidecar checksum.

    Returns:
        (matches, actual_hash, expected_hash_or_none)
    """
    file_path = Path(file_path).resolve()
    if not file_path.exists():
        return False, "", None

    actual_hash = hashlib.sha256(file_path.read_bytes()).hexdigest()

    if sidecar_path is None:
        sidecar_path = file_path.parent / (file_path.name + ".sha256")
    else:
        sidecar_path = Path(sidecar_path).resolve()

    if not sidecar_path.exists():
        return False, actual_hash, None

    expected_hash = sidecar_path.read_text(encoding="utf-8").strip()
    return (actual_hash == expected_hash), actual_hash, expected_hash
