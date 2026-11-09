"""SQLite persistence manager for M12 Security Research Memory Subsystem.

Manages transactional schema, FTS5 lexical index, dense vector index,
version history, conflict tracking, and audit tombstones.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional
import numpy as np

from src.database.manager import DatabaseManager
from src.memory.enums import (
    ConflictType,
    EpistemicStatus,
    LifecycleState,
    MemoryAuthority,
    MemoryNamespace,
    MemorySourceType,
    PromotionStatus,
    SensitivityClassification,
)
from src.memory.models import (
    EvidencePointer,
    MemoryConflict,
    MemoryDeletionRecord,
    MemoryItem,
    MemoryPromotion,
    MemoryVersion,
)


class MemoryPersistence:
    """
    Manages SQLite storage and indexing for research memory.
    """

    DDL_SCHEMA = """
    CREATE TABLE IF NOT EXISTS memory_items (
        memory_id               TEXT PRIMARY KEY,
        namespace               TEXT NOT NULL,
        owner_id                TEXT NOT NULL,
        tenant_id               TEXT NOT NULL,
        assessment_id           TEXT,
        source_type             TEXT NOT NULL,
        epistemic_status        TEXT NOT NULL,
        authority_level         TEXT NOT NULL,
        content                 TEXT NOT NULL,
        normalized_content      TEXT NOT NULL,
        title                   TEXT,
        summary                 TEXT,
        confidence              REAL DEFAULT 1.0,
        created_at              TEXT NOT NULL,
        updated_at              TEXT NOT NULL,
        last_accessed_at        TEXT,
        source_timestamp        TEXT,
        provenance_references   TEXT, -- JSON list
        evidence_references     TEXT, -- JSON list
        content_hash            TEXT NOT NULL,
        version                 INTEGER DEFAULT 1,
        supersedes              TEXT,
        superseded_by           TEXT,
        retention_expiry        TEXT,
        sensitivity_classification TEXT NOT NULL,
        sanitization_status     TEXT NOT NULL,
        promotion_status        TEXT NOT NULL,
        lifecycle_state         TEXT NOT NULL,
        is_tombstone            INTEGER DEFAULT 0,
        metadata_json           TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_mem_ns ON memory_items(namespace);
    CREATE INDEX IF NOT EXISTS idx_mem_tenant ON memory_items(tenant_id);
    CREATE INDEX IF NOT EXISTS idx_mem_assessment ON memory_items(assessment_id);
    CREATE INDEX IF NOT EXISTS idx_mem_status ON memory_items(lifecycle_state, is_tombstone);
    CREATE INDEX IF NOT EXISTS idx_mem_hash ON memory_items(content_hash);

    CREATE TABLE IF NOT EXISTS memory_versions (
        version_id              TEXT PRIMARY KEY,
        memory_id               TEXT NOT NULL,
        version_number          INTEGER NOT NULL,
        content                 TEXT NOT NULL,
        content_hash            TEXT NOT NULL,
        epistemic_status        TEXT NOT NULL,
        authority_level         TEXT NOT NULL,
        created_at              TEXT NOT NULL,
        superseded_by           TEXT,
        change_rationale        TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_mem_ver ON memory_versions(memory_id, version_number);

    CREATE TABLE IF NOT EXISTS memory_pointers (
        pointer_id              TEXT PRIMARY KEY,
        memory_id               TEXT NOT NULL,
        target_evidence_id      TEXT NOT NULL,
        assessment_id           TEXT NOT NULL,
        evidence_type           TEXT NOT NULL,
        evidence_digest         TEXT NOT NULL,
        is_broken               INTEGER DEFAULT 0,
        verified_at             TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS memory_conflicts (
        conflict_id             TEXT PRIMARY KEY,
        conflict_type           TEXT NOT NULL,
        memory_id_a             TEXT NOT NULL,
        memory_id_b             TEXT NOT NULL,
        description             TEXT NOT NULL,
        detected_at             TEXT NOT NULL,
        resolution_status       TEXT NOT NULL,
        resolution_notes        TEXT
    );

    CREATE TABLE IF NOT EXISTS memory_promotions (
        promotion_id            TEXT PRIMARY KEY,
        memory_id               TEXT NOT NULL,
        requester_id            TEXT NOT NULL,
        reviewer_id             TEXT,
        source_namespace        TEXT NOT NULL,
        target_namespace        TEXT NOT NULL,
        status                  TEXT NOT NULL,
        justification           TEXT NOT NULL,
        requested_at            TEXT NOT NULL,
        reviewed_at             TEXT,
        audit_event_id          TEXT
    );

    CREATE TABLE IF NOT EXISTS memory_tombstones (
        tombstone_id            TEXT PRIMARY KEY,
        memory_id               TEXT NOT NULL,
        namespace               TEXT NOT NULL,
        assessment_id           TEXT,
        deleted_by              TEXT NOT NULL,
        deleted_at              TEXT NOT NULL,
        reason                  TEXT NOT NULL,
        content_hash            TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS memory_embeddings (
        memory_id               TEXT PRIMARY KEY,
        dimension               INTEGER NOT NULL,
        vector_json             TEXT NOT NULL,
        updated_at              TEXT NOT NULL
    );
    """

    FTS_SCHEMA = """
    CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts USING fts5(
        memory_id UNINDEXED,
        title,
        summary,
        content,
        tokenize = 'unicode61'
    );
    """

    def __init__(self, db_manager: DatabaseManager) -> None:
        self.db_manager = db_manager
        self.initialize_schema()

    def initialize_schema(self) -> None:
        """Initializes tables and FTS5 virtual table."""
        with self.db_manager.get_connection() as conn:
            conn.executescript(self.DDL_SCHEMA)
            try:
                conn.executescript(self.FTS_SCHEMA)
            except sqlite3.OperationalError:
                # FTS table may already exist
                pass
            conn.commit()

    def save_item(self, item: MemoryItem) -> None:
        """Persists or updates a MemoryItem and updates FTS index."""
        with self.db_manager.get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO memory_items (
                    memory_id, namespace, owner_id, tenant_id, assessment_id,
                    source_type, epistemic_status, authority_level, content,
                    normalized_content, title, summary, confidence, created_at,
                    updated_at, last_accessed_at, source_timestamp,
                    provenance_references, evidence_references, content_hash,
                    version, supersedes, superseded_by, retention_expiry,
                    sensitivity_classification, sanitization_status, promotion_status,
                    lifecycle_state, is_tombstone, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    item.memory_id,
                    item.namespace.value,
                    item.owner_id,
                    item.tenant_id,
                    item.assessment_id,
                    item.source_type.value,
                    item.epistemic_status.value,
                    item.authority_level.value,
                    item.content,
                    item.normalized_content,
                    item.title,
                    item.summary,
                    item.confidence,
                    item.created_at,
                    item.updated_at,
                    item.last_accessed_at,
                    item.source_timestamp,
                    json.dumps(item.provenance_references),
                    json.dumps(item.evidence_references),
                    item.content_hash,
                    item.version,
                    item.supersedes,
                    item.superseded_by,
                    item.retention_expiry,
                    item.sensitivity_classification.value,
                    item.sanitization_status,
                    item.promotion_status.value,
                    item.lifecycle_state.value,
                    1 if item.is_tombstone else 0,
                    json.dumps(item.metadata),
                ),
            )

            # Update FTS5 index (delete existing entry if any, then insert)
            conn.execute("DELETE FROM memory_fts WHERE memory_id = ?", (item.memory_id,))
            if not item.is_tombstone and item.lifecycle_state.value != "DELETED":
                conn.execute(
                    "INSERT INTO memory_fts (memory_id, title, summary, content) VALUES (?, ?, ?, ?)",
                    (item.memory_id, item.title, item.summary, item.content),
                )

            # Persist any evidence pointers
            for ptr in item.evidence_pointers:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO memory_pointers (
                        pointer_id, memory_id, target_evidence_id, assessment_id,
                        evidence_type, evidence_digest, is_broken, verified_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        ptr.pointer_id,
                        ptr.memory_id,
                        ptr.target_evidence_id,
                        ptr.assessment_id,
                        ptr.evidence_type,
                        ptr.evidence_digest,
                        1 if ptr.is_broken else 0,
                        ptr.verified_at,
                    ),
                )

            conn.commit()

    def get_item(self, memory_id: str) -> Optional[MemoryItem]:
        """Loads a MemoryItem by memory_id."""
        with self.db_manager.get_connection() as conn:
            cursor = conn.execute("SELECT * FROM memory_items WHERE memory_id = ?", (memory_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_item(row, conn)

    def list_items(self, where_clause: str = "1=1", params: Optional[List[Any]] = None) -> List[MemoryItem]:
        """Queries memory_items with given SQL clause."""
        with self.db_manager.get_connection() as conn:
            cursor = conn.execute(f"SELECT * FROM memory_items WHERE {where_clause}", params or [])
            rows = cursor.fetchall()
            return [self._row_to_item(row, conn) for row in rows]

    def _row_to_item(self, row: sqlite3.Row, conn: sqlite3.Connection) -> MemoryItem:
        """Helper to construct MemoryItem from database row."""
        mem_id = row["memory_id"]
        # Load pointers
        p_cursor = conn.execute("SELECT * FROM memory_pointers WHERE memory_id = ?", (mem_id,))
        p_rows = p_cursor.fetchall()
        pointers = [
            EvidencePointer(
                pointer_id=pr["pointer_id"],
                memory_id=pr["memory_id"],
                target_evidence_id=pr["target_evidence_id"],
                assessment_id=pr["assessment_id"],
                evidence_type=pr["evidence_type"],
                evidence_digest=pr["evidence_digest"],
                is_broken=bool(pr["is_broken"]),
                verified_at=pr["verified_at"],
            )
            for pr in p_rows
        ]

        return MemoryItem(
            memory_id=row["memory_id"],
            namespace=MemoryNamespace(row["namespace"]),
            owner_id=row["owner_id"],
            tenant_id=row["tenant_id"],
            assessment_id=row["assessment_id"],
            source_type=MemorySourceType(row["source_type"]),
            epistemic_status=EpistemicStatus(row["epistemic_status"]),
            authority_level=MemoryAuthority(row["authority_level"]),
            content=row["content"],
            normalized_content=row["normalized_content"],
            title=row["title"] or "",
            summary=row["summary"] or "",
            confidence=row["confidence"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            last_accessed_at=row["last_accessed_at"],
            source_timestamp=row["source_timestamp"],
            provenance_references=json.loads(row["provenance_references"] or "[]"),
            evidence_references=json.loads(row["evidence_references"] or "[]"),
            evidence_pointers=pointers,
            content_hash=row["content_hash"],
            version=row["version"],
            supersedes=row["supersedes"],
            superseded_by=row["superseded_by"],
            retention_expiry=row["retention_expiry"],
            sensitivity_classification=SensitivityClassification(row["sensitivity_classification"]),
            sanitization_status=row["sanitization_status"],
            promotion_status=PromotionStatus(row["promotion_status"]),
            lifecycle_state=LifecycleState(row["lifecycle_state"]),
            is_tombstone=bool(row["is_tombstone"]),
            metadata=json.loads(row["metadata_json"] or "{}"),
        )

    def search_fts5(self, query: str, limit: int = 20) -> List[Dict[str, Any]]:
        """Executes BM25 sparse lexical search via FTS5."""
        clean_q = "".join(c for c in query if c.isalnum() or c.isspace()).strip()
        if not clean_q:
            return []

        fts_query = f"{clean_q}*"
        with self.db_manager.get_connection() as conn:
            try:
                cursor = conn.execute(
                    """
                    SELECT memory_id, rank
                    FROM memory_fts
                    WHERE memory_fts MATCH ?
                    ORDER BY rank
                    LIMIT ?
                    """,
                    (fts_query, limit),
                )
                return [{"memory_id": row["memory_id"], "rank": row["rank"]} for row in cursor.fetchall()]
            except Exception:
                return []

    def save_embedding(self, memory_id: str, vector: List[float]) -> None:
        """Stores dense embedding vector for a memory item."""
        with self.db_manager.get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO memory_embeddings (memory_id, dimension, vector_json, updated_at)
                VALUES (?, ?, ?, ?)
                """,
                (
                    memory_id,
                    len(vector),
                    json.dumps(vector),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            conn.commit()

    def get_all_embeddings(self) -> Dict[str, List[float]]:
        """Returns all persisted embeddings mapped by memory_id."""
        with self.db_manager.get_connection() as conn:
            cursor = conn.execute("SELECT memory_id, vector_json FROM memory_embeddings")
            result: Dict[str, List[float]] = {}
            for row in cursor.fetchall():
                result[row["memory_id"]] = json.loads(row["vector_json"])
            return result

    def delete_item_index(self, memory_id: str) -> None:
        """Removes an item from FTS and embedding indexes upon deletion."""
        with self.db_manager.get_connection() as conn:
            conn.execute("DELETE FROM memory_fts WHERE memory_id = ?", (memory_id,))
            conn.execute("DELETE FROM memory_embeddings WHERE memory_id = ?", (memory_id,))
            conn.commit()

    def save_version(self, version: MemoryVersion) -> None:
        """Persists historical snapshot."""
        with self.db_manager.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO memory_versions (
                    version_id, memory_id, version_number, content, content_hash,
                    epistemic_status, authority_level, created_at, superseded_by, change_rationale
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    version.version_id,
                    version.memory_id,
                    version.version_number,
                    version.content,
                    version.content_hash,
                    version.epistemic_status.value,
                    version.authority_level.value,
                    version.created_at,
                    version.superseded_by,
                    version.change_rationale,
                ),
            )
            conn.commit()

    def list_versions(self, memory_id: str) -> List[MemoryVersion]:
        """Loads historical versions for an item."""
        with self.db_manager.get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM memory_versions WHERE memory_id = ? ORDER BY version_number ASC",
                (memory_id,),
            )
            return [
                MemoryVersion(
                    version_id=r["version_id"],
                    memory_id=r["memory_id"],
                    version_number=r["version_number"],
                    content=r["content"],
                    content_hash=r["content_hash"],
                    epistemic_status=EpistemicStatus(r["epistemic_status"]),
                    authority_level=MemoryAuthority(r["authority_level"]),
                    created_at=r["created_at"],
                    superseded_by=r["superseded_by"],
                    change_rationale=r["change_rationale"] or "",
                )
                for r in cursor.fetchall()
            ]

    def save_conflict(self, conflict: MemoryConflict) -> None:
        """Persists conflict record."""
        with self.db_manager.get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO memory_conflicts (
                    conflict_id, conflict_type, memory_id_a, memory_id_b,
                    description, detected_at, resolution_status, resolution_notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    conflict.conflict_id,
                    conflict.conflict_type.value,
                    conflict.memory_id_a,
                    conflict.memory_id_b,
                    conflict.description,
                    conflict.detected_at,
                    conflict.resolution_status,
                    conflict.resolution_notes,
                ),
            )
            conn.commit()

    def list_conflicts(self, memory_id: Optional[str] = None) -> List[MemoryConflict]:
        """Lists active conflict records."""
        with self.db_manager.get_connection() as conn:
            if memory_id:
                cursor = conn.execute(
                    "SELECT * FROM memory_conflicts WHERE memory_id_a = ? OR memory_id_b = ?",
                    (memory_id, memory_id),
                )
            else:
                cursor = conn.execute("SELECT * FROM memory_conflicts")
            return [
                MemoryConflict(
                    conflict_id=r["conflict_id"],
                    conflict_type=ConflictType(r["conflict_type"]),
                    memory_id_a=r["memory_id_a"],
                    memory_id_b=r["memory_id_b"],
                    description=r["description"],
                    detected_at=r["detected_at"],
                    resolution_status=r["resolution_status"],
                    resolution_notes=r["resolution_notes"],
                )
                for r in cursor.fetchall()
            ]

    def save_tombstone(self, tombstone: MemoryDeletionRecord) -> None:
        """Persists deletion tombstone."""
        with self.db_manager.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO memory_tombstones (
                    tombstone_id, memory_id, namespace, assessment_id, deleted_by, deleted_at, reason, content_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    tombstone.tombstone_id,
                    tombstone.memory_id,
                    tombstone.namespace.value,
                    tombstone.assessment_id,
                    tombstone.deleted_by,
                    tombstone.deleted_at,
                    tombstone.reason,
                    tombstone.content_hash,
                ),
            )
            conn.commit()

    def save_promotion(self, promotion: MemoryPromotion) -> None:
        """Persists promotion workflow record."""
        with self.db_manager.get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO memory_promotions (
                    promotion_id, memory_id, requester_id, reviewer_id,
                    source_namespace, target_namespace, status, justification,
                    requested_at, reviewed_at, audit_event_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    promotion.promotion_id,
                    promotion.memory_id,
                    promotion.requester_id,
                    promotion.reviewer_id,
                    promotion.source_namespace.value,
                    promotion.target_namespace.value,
                    promotion.status.value,
                    promotion.justification,
                    promotion.requested_at,
                    promotion.reviewed_at,
                    promotion.audit_event_id,
                ),
            )
            conn.commit()
