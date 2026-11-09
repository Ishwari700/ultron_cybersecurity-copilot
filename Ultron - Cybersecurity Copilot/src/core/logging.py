"""Structured logging and tamper-evident chained audit logging for the Bug Bounty Research Platform."""

import hashlib
import json
import logging
import os
from pathlib import Path
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

GENESIS_PREVIOUS_HASH = "0" * 64


class CrossProcessAuditLock:
    """
    OS-level cross-process advisory lock compatible with Windows and POSIX.
    Uses filelock if available, with robust msvcrt (Windows) / fcntl (POSIX) fallback.
    """
    def __init__(self, lock_file_path: Path, timeout: float = 30.0) -> None:
        self.lock_file_path = Path(lock_file_path)
        self.timeout = timeout
        self._filelock_instance = None
        self._fd = None

    def __enter__(self):
        # 1. Try filelock package if installed
        try:
            from filelock import FileLock
            self._filelock_instance = FileLock(str(self.lock_file_path), timeout=self.timeout)
            self._filelock_instance.acquire()
            return self
        except ImportError:
            pass

        # 2. Native OS fallback
        deadline = time.monotonic() + self.timeout
        self.lock_file_path.parent.mkdir(parents=True, exist_ok=True)

        if sys.platform == "win32":
            import msvcrt
            while True:
                try:
                    self._fd = os.open(str(self.lock_file_path), os.O_RDWR | os.O_CREAT)
                    msvcrt.locking(self._fd, msvcrt.LK_NBLCK, 1)
                    return self
                except (OSError, IOError):
                    if self._fd is not None:
                        try:
                            os.close(self._fd)
                        except Exception:
                            pass
                        self._fd = None
                    if time.monotonic() >= deadline:
                        raise TimeoutError(f"Could not acquire cross-process lock on {self.lock_file_path} within {self.timeout}s")
                    time.sleep(0.01)
        else:
            import fcntl
            while True:
                try:
                    self._fd = os.open(str(self.lock_file_path), os.O_RDWR | os.O_CREAT)
                    fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    return self
                except (OSError, IOError):
                    if self._fd is not None:
                        try:
                            os.close(self._fd)
                        except Exception:
                            pass
                        self._fd = None
                    if time.monotonic() >= deadline:
                        raise TimeoutError(f"Could not acquire cross-process lock on {self.lock_file_path} within {self.timeout}s")
                    time.sleep(0.01)

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._filelock_instance is not None:
            try:
                self._filelock_instance.release()
            except Exception:
                pass
            self._filelock_instance = None
            return False

        if self._fd is not None:
            if sys.platform == "win32":
                import msvcrt
                try:
                    msvcrt.locking(self._fd, msvcrt.LK_UNLCK, 1)
                except Exception:
                    pass
            else:
                import fcntl
                try:
                    fcntl.flock(self._fd, fcntl.LOCK_UN)
                except Exception:
                    pass
            try:
                os.close(self._fd)
            except Exception:
                pass
            self._fd = None
        return False


def get_logger(name: str, level: str = "INFO") -> logging.Logger:
    """Obtain a structured console and file logger."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(getattr(logging, level.upper(), logging.INFO))
        ch = logging.StreamHandler()
        ch.setLevel(getattr(logging, level.upper(), logging.INFO))
        formatter = logging.Formatter(
            '{"timestamp": "%(asctime)s", "logger": "%(name)s", "level": "%(levelname)s", "message": "%(message)s"}'
        )
        ch.setFormatter(formatter)
        logger.addHandler(ch)
    return logger


class AuditLogVerificationResult(BaseModel):
    """Result of independent verification of the chained audit log."""
    valid: bool
    total_records: int
    tampered_records: List[int] = Field(default_factory=list)
    tampering_types: List[str] = Field(default_factory=list)
    error_messages: List[str] = Field(default_factory=list)


class AuditLogger:
    """
    Append-only tamper-evident chained audit logger recording every state transition,
    scope decision, tool invocation, and human verification decision.

    Integrity Model:
    Each record binds:
    - sequence_number (strictly monotonically increasing)
    - previous_record_hash (cryptographic hash chain back to genesis)
    - timestamp, actor, event_type, subject_id, states, evidence_ref
    - canonical payload_hash
    - canonical record_hash covering ALL top-level security fields

    Detects:
    - In-place modifications
    - Record deletions
    - Record insertions / replays
    - Record reorderings
    - Record replacements

    Security Trust Boundary & Threat Model:
    The hash chain provides tamper evidence against modification, insertion, deletion,
    or reordering of records while preserving the trusted chain anchor (genesis hash).
    It does not protect against an attacker with root or full filesystem write access
    who can replace both the entire log file and its genesis anchor. Protection against
    unbounded filesystem-level administrator compromise requires external trust anchors
    (e.g., write-once/append-only storage, periodic signed detached checkpoints, or
    remote syslog/SIEM forwarding).
    """

    def __init__(self, audit_file_path: Path, lock_timeout: float = 30.0) -> None:
        self.audit_file_path = Path(audit_file_path)
        self.lock_file_path = self.audit_file_path.with_suffix(self.audit_file_path.suffix + ".lock")
        self.audit_file_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.lock_timeout = lock_timeout

        # Initialize chain state under both in-process lock and OS file lock
        with self._lock:
            with CrossProcessAuditLock(self.lock_file_path, timeout=self.lock_timeout):
                self._current_sequence, self._last_record_hash = self._read_tail_state()

    def _read_tail_state(self) -> Tuple[int, str]:
        """Scan authoritative tail record from disk to resume sequence and hash chain."""
        if not self.audit_file_path.exists() or self.audit_file_path.stat().st_size == 0:
            return 0, GENESIS_PREVIOUS_HASH

        try:
            with open(self.audit_file_path, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                chunk_size = min(size, 8192)
                f.seek(-chunk_size, 2)
                raw_chunk = f.read()
                lines = raw_chunk.split(b"\n")
                for line in reversed(lines):
                    line = line.strip()
                    if line:
                        rec = json.loads(line.decode("utf-8"))
                        if "sequence_number" in rec and "record_hash" in rec:
                            return rec["sequence_number"], rec["record_hash"]
        except Exception:
            pass

        last_seq = 0
        last_hash = GENESIS_PREVIOUS_HASH
        try:
            with open(self.audit_file_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                        if "sequence_number" in rec and "record_hash" in rec:
                            last_seq = rec["sequence_number"]
                            last_hash = rec["record_hash"]
                    except Exception:
                        continue
        except Exception:
            pass

        return last_seq, last_hash

    @staticmethod
    def compute_canonical_hash(data: Dict[str, Any]) -> str:
        """Compute SHA256 digest over canonical JSON representation."""
        serialized = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def log_event(
        self,
        event_type: str,
        actor: str,
        subject_id: str,
        previous_state: Optional[str] = None,
        new_state: Optional[str] = None,
        evidence_ref: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        investigation_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Record a chained, tamper-evident audit record to the JSONL log file.
        Enforces cross-process file locking, authoritative tail state derivation,
        atomic appending, and physical disk flush.
        """
        now = datetime.now(timezone.utc).isoformat()
        payload = dict(details or {})
        
        # Determine and bind investigation_id if applicable
        bound_inv_id = investigation_id or payload.get("investigation_id")
        if not bound_inv_id and subject_id and (subject_id.startswith("INV-") or subject_id.startswith("inv-")):
            bound_inv_id = subject_id
        if bound_inv_id:
            payload["investigation_id"] = bound_inv_id

        payload_hash = self.compute_canonical_hash(payload)

        with self._lock:
            with CrossProcessAuditLock(self.lock_file_path, timeout=self.lock_timeout):
                # 1. Authoritative tail read under OS lock
                last_seq, last_hash = self._read_tail_state()
                sequence_number = last_seq + 1
                previous_record_hash = last_hash

                # 2. Body containing all security-relevant fields to be hashed
                record_body: Dict[str, Any] = {
                    "sequence_number": sequence_number,
                    "previous_record_hash": previous_record_hash,
                    "timestamp": now,
                    "event_type": event_type,
                    "actor": actor,
                    "subject_id": subject_id,
                    "previous_state": previous_state,
                    "new_state": new_state,
                    "evidence_ref": evidence_ref,
                    "payload_hash": payload_hash,
                }

                # 3. Canonical record hash covering all security-relevant metadata
                record_hash = self.compute_canonical_hash(record_body)

                # 4. Complete record written to disk
                record: Dict[str, Any] = {
                    **record_body,
                    "record_hash": record_hash,
                    "details": payload,
                }
                if bound_inv_id:
                    record["investigation_id"] = bound_inv_id

                line = json.dumps(record, sort_keys=True, default=str) + "\n"
                with open(self.audit_file_path, "a", encoding="utf-8") as f:
                    f.write(line)
                    f.flush()
                    try:
                        os.fsync(f.fileno())
                    except (AttributeError, OSError):
                        pass

                self._current_sequence = sequence_number
                self._last_record_hash = record_hash

        return record

    def read_records(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Read audit records from the log file in chronological order."""
        records: List[Dict[str, Any]] = []
        if not self.audit_file_path.exists():
            return records

        with self._lock:
            with CrossProcessAuditLock(self.lock_file_path, timeout=self.lock_timeout):
                with open(self.audit_file_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                records.append(json.loads(line))
                            except json.JSONDecodeError:
                                continue
        if limit:
            return records[-limit:]
        return records

    def read_records_for_investigation(
        self,
        investigation_id: str,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Read audit records strictly matching a specific investigation ID."""
        all_records = self.read_records()
        target_inv = str(investigation_id).strip()
        filtered = [
            r for r in all_records
            if r.get("investigation_id") == target_inv
            or r.get("details", {}).get("investigation_id") == target_inv
            or r.get("subject_id") == target_inv
        ]
        if limit:
            return filtered[-limit:]
        return filtered



def verify_audit_log(audit_file_path: Path) -> AuditLogVerificationResult:
    """
    Independently verifies the integrity and cryptographic hash chain of an audit log.
    Detects record modification, deletion, insertion, reordering, and replacement.
    """
    if not audit_file_path.exists():
        return AuditLogVerificationResult(
            valid=True,
            total_records=0,
            tampered_records=[],
            tampering_types=[],
            error_messages=["Audit file does not exist (empty log)."],
        )

    expected_prev_hash = GENESIS_PREVIOUS_HASH
    expected_seq = 1
    tampered_records: List[int] = []
    tampering_types: List[str] = []
    errors: List[str] = []
    total_records = 0

    lock_file = audit_file_path.with_suffix(audit_file_path.suffix + ".lock")
    with CrossProcessAuditLock(lock_file):
        with open(audit_file_path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                total_records += 1

                try:
                    rec = json.loads(line)
                except Exception as e:
                    tampered_records.append(line_num)
                    tampering_types.append("MALFORMED_JSON")
                    errors.append(f"Line {line_num}: Malformed JSON: {e}")
                    continue

                seq = rec.get("sequence_number")
                prev_hash = rec.get("previous_record_hash")
                rec_hash = rec.get("record_hash")
                payload_hash = rec.get("payload_hash")
                details = rec.get("details", {})

                # 1. Check sequence monotonicity
                if seq != expected_seq:
                    tampered_records.append(line_num)
                    if seq is not None and seq > expected_seq:
                        tampering_types.append("DELETION")
                        errors.append(f"Line {line_num}: Sequence gap detected (expected {expected_seq}, got {seq}): record deleted")
                    else:
                        tampering_types.append("REORDERING_OR_INSERTION")
                        errors.append(f"Line {line_num}: Sequence mismatch (expected {expected_seq}, got {seq})")

                # 2. Check hash chain continuity
                if prev_hash != expected_prev_hash:
                    tampered_records.append(line_num)
                    tampering_types.append("CHAIN_BROKEN_OR_REPLACED")
                    errors.append(
                        f"Line {line_num}: Hash chain broken (expected prev {expected_prev_hash[:12]}..., got {str(prev_hash)[:12]}...)"
                    )

                # 3. Check payload hash integrity
                computed_payload_hash = AuditLogger.compute_canonical_hash(details)
                if payload_hash != computed_payload_hash:
                    tampered_records.append(line_num)
                    tampering_types.append("MODIFICATION")
                    errors.append(f"Line {line_num}: Details payload hash mismatch")

                # 4. Recompute canonical record hash
                record_body: Dict[str, Any] = {
                    "sequence_number": seq,
                    "previous_record_hash": prev_hash,
                    "timestamp": rec.get("timestamp"),
                    "event_type": rec.get("event_type"),
                    "actor": rec.get("actor"),
                    "subject_id": rec.get("subject_id"),
                    "previous_state": rec.get("previous_state"),
                    "new_state": rec.get("new_state"),
                    "evidence_ref": rec.get("evidence_ref"),
                    "payload_hash": payload_hash,
                }
                computed_record_hash = AuditLogger.compute_canonical_hash(record_body)
                if rec_hash != computed_record_hash:
                    tampered_records.append(line_num)
                    tampering_types.append("MODIFICATION")
                    errors.append(f"Line {line_num}: Canonical record hash mismatch (tampered content)")

                # Advance expected chain state
                expected_seq = (seq + 1) if seq is not None else (expected_seq + 1)
                expected_prev_hash = rec_hash if rec_hash else "INVALID_PREV"

    valid = len(tampered_records) == 0
    return AuditLogVerificationResult(
        valid=valid,
        total_records=total_records,
        tampered_records=list(set(tampered_records)),
        tampering_types=list(set(tampering_types)),
        error_messages=errors,
    )
