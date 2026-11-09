"""Dedicated VAPT Knowledge Store (SQLite + FTS5).

Implements M3.5 per M3 Plan v2.3.8:
- Physical isolation from Target-Evidence store (evidence.db)
- Canonical document and chunk tables
- SQLite FTS5 full-text indexing with Porter stemming
- Deterministic lexical ranking with chunk_id tie-breaking
- Read-only connection mode for production runtime
"""

from datetime import datetime, timezone
import json
import logging
import re
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from src.knowledge.models import (
    KnowledgeChunk,
    KnowledgeDocumentFrontmatter,
    KnowledgeSourceType,
    KnowledgeType,
)

logger = logging.getLogger("m3.store")


class VaptStoreError(Exception):
    """Raised on store isolation violations or storage failures."""
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message


class VaptKnowledgeStore:
    """
    Dedicated storage engine for the VAPT security knowledge corpus.
    
    CRITICAL ARCHITECTURAL RULE:
    Strictly isolated from evidence.db. Under no circumstances may this store
    connect to or manipulate target evidence data.
    """

    def __init__(self, db_path: Path, read_only: bool = False) -> None:
        self.db_path = Path(db_path)
        self.read_only = read_only

        # Dual Store Separation Invariant Check
        if self.db_path.name.lower() == "evidence.db":
            raise VaptStoreError(
                "DUAL_STORE_SEPARATION_VIOLATION",
                "Cannot open evidence.db as VAPT knowledge store; target evidence and methodology must remain isolated.",
            )

        if not self.read_only:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
            self._init_schema()
        else:
            if not self.db_path.exists():
                raise VaptStoreError(
                    "DATABASE_NOT_FOUND",
                    f"Knowledge database does not exist at {self.db_path}",
                )
            # Open in read-only URI mode to prevent accidental runtime mutation
            uri = f"file:{self.db_path.resolve().as_posix()}?mode=ro"
            self.conn = sqlite3.connect(uri, uri=True, check_same_thread=False)

        self.conn.row_factory = sqlite3.Row

    def _init_schema(self) -> None:
        """Initialize relational and FTS5 tables."""
        with self.conn:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS documents (
                    document_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    source_name TEXT NOT NULL,
                    source_version TEXT NOT NULL,
                    source_url TEXT NOT NULL,
                    license TEXT NOT NULL,
                    author TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    normalized_body TEXT NOT NULL
                )
            """)

            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS chunks (
                    chunk_id TEXT PRIMARY KEY,
                    document_id TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    knowledge_type TEXT NOT NULL,
                    category_tags TEXT NOT NULL,
                    title TEXT NOT NULL,
                    section_heading TEXT NOT NULL,
                    content TEXT NOT NULL,
                    token_estimate INTEGER NOT NULL,
                    content_hash TEXT NOT NULL,
                    trust_tier TEXT NOT NULL,
                    FOREIGN KEY(document_id) REFERENCES documents(document_id)
                )
            """)

            # SQLite FTS5 virtual table for lexical retrieval
            self.conn.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS fts_chunks USING fts5(
                    chunk_id UNINDEXED,
                    title,
                    section_heading,
                    content,
                    category_tags,
                    tokenize = 'porter unicode61'
                )
            """)

            # Persistent source registry for user-controlled textbooks and documents
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS knowledge_sources (
                    source_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    authority_level TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    format TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    original_checksum TEXT NOT NULL,
                    page_count INTEGER DEFAULT 0,
                    chunk_count INTEGER DEFAULT 0,
                    status TEXT NOT NULL,
                    error_message TEXT,
                    metadata_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            self.conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_ksource_hash ON knowledge_sources(content_hash)
            """)
            self.conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_ksource_status ON knowledge_sources(status)
            """)

            # Persistent ingestion job queue and checkpoint store
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS ingestion_jobs (
                    job_id TEXT PRIMARY KEY,
                    source_id TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    title TEXT,
                    authority_level TEXT NOT NULL,
                    status TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    queue_position INTEGER DEFAULT 0,
                    total_pages INTEGER DEFAULT 0,
                    completed_pages INTEGER DEFAULT 0,
                    total_chunks INTEGER DEFAULT 0,
                    completed_chunks INTEGER DEFAULT 0,
                    checkpoint_json TEXT NOT NULL DEFAULT '{}',
                    error_message TEXT,
                    retry_count INTEGER DEFAULT 0,
                    cancellation_requested INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    updated_at TEXT NOT NULL,
                    completed_at TEXT
                )
            """)
            self.conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_ijob_status ON ingestion_jobs(status)
            """)
            self.conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_ijob_source ON ingestion_jobs(source_id)
            """)

    def insert_document(
        self,
        frontmatter: KnowledgeDocumentFrontmatter,
        normalized_body: str,
    ) -> None:
        """Insert or replace a corpus document record."""
        if self.read_only:
            raise VaptStoreError("READ_ONLY_VIOLATION", "Cannot insert into read-only store")

        with self.conn:
            self.conn.execute(
                """
                INSERT OR REPLACE INTO documents (
                    document_id, title, source_name, source_version,
                    source_url, license, author, content_hash, normalized_body
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    frontmatter.document_id,
                    frontmatter.title,
                    frontmatter.source_name,
                    frontmatter.source_version,
                    frontmatter.source_url,
                    frontmatter.license,
                    frontmatter.author,
                    frontmatter.content_hash,
                    normalized_body,
                ),
            )

    def insert_chunks(self, chunks: Sequence[KnowledgeChunk]) -> None:
        """Insert chunks and synchronize FTS5 index."""
        if self.read_only:
            raise VaptStoreError("READ_ONLY_VIOLATION", "Cannot insert into read-only store")

        with self.conn:
            for chunk in chunks:
                tags_json = json.dumps(chunk.category_tags)
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO chunks (
                        chunk_id, document_id, source_type, knowledge_type,
                        category_tags, title, section_heading, content,
                        token_estimate, content_hash, trust_tier
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        chunk.chunk_id,
                        chunk.document_id,
                        chunk.source_type.value,
                        chunk.knowledge_type.value,
                        tags_json,
                        chunk.title,
                        chunk.section_heading,
                        chunk.content,
                        chunk.token_estimate,
                        chunk.content_hash,
                        chunk.trust_tier,
                    ),
                )

                # Update FTS5 index
                self.conn.execute(
                    "DELETE FROM fts_chunks WHERE chunk_id = ?",
                    (chunk.chunk_id,),
                )
                self.conn.execute(
                    """
                    INSERT INTO fts_chunks (
                        chunk_id, title, section_heading, content, category_tags
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        chunk.chunk_id,
                        chunk.title,
                        chunk.section_heading,
                        chunk.content,
                        " ".join(chunk.category_tags),
                    ),
                )

    def get_chunk(self, chunk_id: str) -> Optional[KnowledgeChunk]:
        """Fetch chunk by ID."""
        cursor = self.conn.execute(
            """
            SELECT chunk_id, document_id, source_type, knowledge_type,
                   category_tags, title, section_heading, content,
                   token_estimate, content_hash, trust_tier
            FROM chunks WHERE chunk_id = ?
            """,
            (chunk_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None

        return self._row_to_chunk(row)

    def get_document(self, document_id: str) -> Optional[Dict[str, Any]]:
        """Fetch document metadata by ID."""
        cursor = self.conn.execute(
            "SELECT * FROM documents WHERE document_id = ?",
            (document_id,),
        )
        row = cursor.fetchone()
        return dict(row) if row else None

    def get_all_chunks(self) -> List[KnowledgeChunk]:
        """Fetch all chunks ordered strictly by chunk_id ASC."""
        cursor = self.conn.execute(
            """
            SELECT chunk_id, document_id, source_type, knowledge_type,
                   category_tags, title, section_heading, content,
                   token_estimate, content_hash, trust_tier
            FROM chunks ORDER BY chunk_id ASC
            """
        )
        return [self._row_to_chunk(row) for row in cursor.fetchall()]

    def get_chunk_count(self) -> int:
        """Return total number of chunks stored."""
        cursor = self.conn.execute("SELECT COUNT(*) FROM chunks")
        return int(cursor.fetchone()[0])

    def get_document_count(self) -> int:
        """Return total number of documents stored."""
        cursor = self.conn.execute("SELECT COUNT(*) FROM documents")
        return int(cursor.fetchone()[0])

    def query_lexical(
        self,
        query_text: str,
        top_k: int = 20,
    ) -> List[Tuple[KnowledgeChunk, float]]:
        """
        Execute FTS5 BM25 search with deterministic tie-breaking.
        
        Returns list of (KnowledgeChunk, score) pairs, where score is higher-is-better (-bm25),
        ordered strictly by score DESC, chunk_id ASC.
        """
        sanitized_query = self._sanitize_fts5_query(query_text)
        if not sanitized_query:
            return []

        # In SQLite FTS5, bm25() returns negative numbers where smaller/more negative is better.
        # We invert it (-bm25) so higher is better.
        # Chunk-level tie-breaking: chunk_id ASC per Section 19.1.
        sql = """
            SELECT c.chunk_id, c.document_id, c.source_type, c.knowledge_type,
                   c.category_tags, c.title, c.section_heading, c.content,
                   c.token_estimate, c.content_hash, c.trust_tier,
                   (-bm25(fts_chunks)) AS lexical_score
            FROM fts_chunks
            JOIN chunks c ON fts_chunks.chunk_id = c.chunk_id
            WHERE fts_chunks MATCH ?
            ORDER BY lexical_score DESC, c.chunk_id ASC
            LIMIT ?
        """
        try:
            cursor = self.conn.execute(sql, (sanitized_query, top_k))
            rows = cursor.fetchall()
        except sqlite3.OperationalError as e:
            logger.warning(f"FTS5 query error on query '{sanitized_query}': {e}")
            return []

        results: List[Tuple[KnowledgeChunk, float]] = []
        for row in rows:
            chunk = self._row_to_chunk(row)
            score = float(row["lexical_score"])
            results.append((chunk, score))
        return results

    @staticmethod
    def _sanitize_fts5_query(query_text: str) -> str:
        """
        Sanitize freeform query text for safe FTS5 MATCH syntax:
        - Extract alphanumeric words
        - Join with OR or standard token match
        """
        raw_tokens = re.findall(r"\b[a-zA-Z0-9_\-]{2,}\b", query_text)
        if not raw_tokens:
            return ""
        # Quote any token containing a hyphen so FTS5 doesn't parse it as column negation
        tokens = [f'"{t}"' if "-" in t else t for t in raw_tokens]
        # Match any of the extracted significant terms
        return " OR ".join(tokens)

    @staticmethod
    def _row_to_chunk(row: sqlite3.Row) -> KnowledgeChunk:
        """Convert a database row into a KnowledgeChunk model."""
        tags = json.loads(row["category_tags"])
        return KnowledgeChunk(
            schema_version="3.0.0",
            chunk_id=row["chunk_id"],
            document_id=row["document_id"],
            source_type=KnowledgeSourceType(row["source_type"]),
            knowledge_type=KnowledgeType(row["knowledge_type"]),
            category_tags=tags,
            title=row["title"],
            section_heading=row["section_heading"],
            content=row["content"],
            token_estimate=int(row["token_estimate"]),
            content_hash=row["content_hash"],
            trust_tier=row["trust_tier"],
        )

    def insert_source(
        self,
        source_id: str,
        title: str,
        source_type: str,
        authority_level: str,
        filename: str,
        format: str,
        content_hash: str,
        original_checksum: str,
        page_count: int = 0,
        chunk_count: int = 0,
        status: str = "REGISTERED",
        error_message: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Insert or update a registered knowledge source record."""
        if self.read_only:
            raise VaptStoreError("READ_ONLY_VIOLATION", "Cannot insert into read-only store")

        now = json.dumps(metadata or {})
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).isoformat()

        with self.conn:
            self.conn.execute(
                """
                INSERT OR REPLACE INTO knowledge_sources (
                    source_id, title, source_type, authority_level,
                    filename, format, content_hash, original_checksum,
                    page_count, chunk_count, status, error_message,
                    metadata_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    source_id, title, source_type, authority_level,
                    filename, format, content_hash, original_checksum,
                    page_count, chunk_count, status, error_message,
                    now, ts, ts
                ),
            )

    def update_source_status(
        self,
        source_id: str,
        status: str,
        error_message: Optional[str] = None,
        chunk_count: Optional[int] = None,
        page_count: Optional[int] = None,
    ) -> None:
        """Atomically update processing state of a registered source."""
        if self.read_only:
            raise VaptStoreError("READ_ONLY_VIOLATION", "Cannot update read-only store")

        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).isoformat()

        with self.conn:
            if chunk_count is not None and page_count is not None:
                self.conn.execute(
                    """
                    UPDATE knowledge_sources
                    SET status = ?, error_message = ?, chunk_count = ?, page_count = ?, updated_at = ?
                    WHERE source_id = ?
                    """,
                    (status, error_message, chunk_count, page_count, ts, source_id),
                )
            elif chunk_count is not None:
                self.conn.execute(
                    """
                    UPDATE knowledge_sources
                    SET status = ?, error_message = ?, chunk_count = ?, updated_at = ?
                    WHERE source_id = ?
                    """,
                    (status, error_message, chunk_count, ts, source_id),
                )
            else:
                self.conn.execute(
                    """
                    UPDATE knowledge_sources
                    SET status = ?, error_message = ?, updated_at = ?
                    WHERE source_id = ?
                    """,
                    (status, error_message, ts, source_id),
                )

    def get_source(self, source_id: str) -> Optional[Dict[str, Any]]:
        """Fetch registered source details by ID."""
        cursor = self.conn.execute(
            "SELECT * FROM knowledge_sources WHERE source_id = ?",
            (source_id,),
        )
        row = cursor.fetchone()
        return dict(row) if row else None

    def get_source_by_hash(self, content_hash: str) -> Optional[Dict[str, Any]]:
        """Fetch active source by content hash to enforce deduplication."""
        cursor = self.conn.execute(
            "SELECT * FROM knowledge_sources WHERE content_hash = ? AND status != 'DEACTIVATED'",
            (content_hash,),
        )
        row = cursor.fetchone()
        return dict(row) if row else None

    def list_sources(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """List registered sources ordered by creation time DESC."""
        if status:
            cursor = self.conn.execute(
                "SELECT * FROM knowledge_sources WHERE status = ? ORDER BY created_at DESC",
                (status,),
            )
        else:
            cursor = self.conn.execute(
                "SELECT * FROM knowledge_sources ORDER BY created_at DESC"
            )
        return [dict(r) for r in cursor.fetchall()]

    def deactivate_source(self, source_id: str) -> bool:
        """Deactivate a source and remove its chunks from current retrieval."""
        if self.read_only:
            raise VaptStoreError("READ_ONLY_VIOLATION", "Cannot deactivate in read-only store")

        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).isoformat()

        with self.conn:
            # Update status in sources registry
            cursor = self.conn.execute(
                "UPDATE knowledge_sources SET status = 'DEACTIVATED', updated_at = ? WHERE source_id = ?",
                (ts, source_id),
            )
            if cursor.rowcount == 0:
                return False

            # Remove associated chunks from FTS5 index to prevent retrieval contamination
            self.conn.execute(
                """
                DELETE FROM fts_chunks
                WHERE chunk_id IN (
                    SELECT chunk_id FROM chunks WHERE document_id = ?
                )
                """,
                (f"DOC-{source_id}",),
            )
        return True

    def delete_source(self, source_id: str) -> bool:
        """Atomically delete source, documents, and chunks."""
        if self.read_only:
            raise VaptStoreError("READ_ONLY_VIOLATION", "Cannot delete from read-only store")

        doc_id = f"DOC-{source_id}"
        with self.conn:
            self.conn.execute(
                "DELETE FROM fts_chunks WHERE chunk_id IN (SELECT chunk_id FROM chunks WHERE document_id = ?)",
                (doc_id,),
            )
            self.conn.execute("DELETE FROM chunks WHERE document_id = ?", (doc_id,))
            self.conn.execute("DELETE FROM documents WHERE document_id = ?", (doc_id,))
            cursor = self.conn.execute("DELETE FROM knowledge_sources WHERE source_id = ?", (source_id,))
            return cursor.rowcount > 0

    def get_chunks_for_document(self, document_id: str) -> List[KnowledgeChunk]:
        """Fetch all chunks associated with a specific document ID."""
        cursor = self.conn.execute(
            """
            SELECT chunk_id, document_id, source_type, knowledge_type,
                   category_tags, title, section_heading, content,
                   token_estimate, content_hash, trust_tier
            FROM chunks WHERE document_id = ? ORDER BY chunk_id ASC
            """,
            (document_id,),
        )
        return [self._row_to_chunk(row) for row in cursor.fetchall()]

    # -------------------------------------------------------------------------
    # Ingestion Job Queue & Persistence
    # -------------------------------------------------------------------------

    def insert_ingestion_job(self, job_dict: Dict[str, Any]) -> None:
        """Insert or replace an ingestion job record."""
        now = datetime.now(timezone.utc).isoformat()
        checkpoint = job_dict.get("checkpoint_json")
        if isinstance(checkpoint, dict):
            checkpoint = json.dumps(checkpoint)
        elif not checkpoint:
            checkpoint = "{}"

        with self.conn:
            self.conn.execute(
                """
                INSERT OR REPLACE INTO ingestion_jobs (
                    job_id, source_id, filename, title, authority_level,
                    status, phase, queue_position, total_pages, completed_pages,
                    total_chunks, completed_chunks, checkpoint_json, error_message,
                    retry_count, cancellation_requested, created_at, started_at,
                    updated_at, completed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    job_dict["job_id"],
                    job_dict["source_id"],
                    job_dict["filename"],
                    job_dict.get("title"),
                    job_dict.get("authority_level", "USER_OWNED"),
                    job_dict.get("status", "QUEUED"),
                    job_dict.get("phase", "QUEUED"),
                    job_dict.get("queue_position", 0),
                    job_dict.get("total_pages", 0),
                    job_dict.get("completed_pages", 0),
                    job_dict.get("total_chunks", 0),
                    job_dict.get("completed_chunks", 0),
                    checkpoint,
                    job_dict.get("error_message"),
                    job_dict.get("retry_count", 0),
                    1 if job_dict.get("cancellation_requested") else 0,
                    job_dict.get("created_at", now),
                    job_dict.get("started_at"),
                    job_dict.get("updated_at", now),
                    job_dict.get("completed_at"),
                ),
            )

    def update_ingestion_job(self, job_id: str, updates: Dict[str, Any]) -> bool:
        """Update fields on an ingestion job record."""
        if not updates:
            return True
        now = datetime.now(timezone.utc).isoformat()
        set_clauses: List[str] = ["updated_at = ?"]
        params: List[Any] = [now]

        for k, v in updates.items():
            if k in ("job_id", "updated_at"):
                continue
            if k == "checkpoint_json" and isinstance(v, dict):
                v = json.dumps(v)
            elif k == "cancellation_requested":
                v = 1 if v else 0
            set_clauses.append(f"{k} = ?")
            params.append(v)

        params.append(job_id)
        sql = f"UPDATE ingestion_jobs SET {', '.join(set_clauses)} WHERE job_id = ?"
        with self.conn:
            cursor = self.conn.execute(sql, tuple(params))
            return cursor.rowcount > 0

    def get_ingestion_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single ingestion job record."""
        cursor = self.conn.execute("SELECT * FROM ingestion_jobs WHERE job_id = ?", (job_id,))
        row = cursor.fetchone()
        if not row:
            return None
        res = dict(row)
        if isinstance(res.get("checkpoint_json"), str):
            try:
                res["checkpoint_json"] = json.loads(res["checkpoint_json"])
            except Exception:
                res["checkpoint_json"] = {}
        res["cancellation_requested"] = bool(res.get("cancellation_requested", 0))
        return res

    def list_ingestion_jobs(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """List ingestion jobs ordered by created_at ASC (FIFO)."""
        if status:
            cursor = self.conn.execute(
                "SELECT * FROM ingestion_jobs WHERE status = ? ORDER BY queue_position ASC, created_at ASC",
                (status,),
            )
        else:
            cursor = self.conn.execute(
                "SELECT * FROM ingestion_jobs ORDER BY queue_position ASC, created_at ASC"
            )
        jobs: List[Dict[str, Any]] = []
        for row in cursor.fetchall():
            res = dict(row)
            if isinstance(res.get("checkpoint_json"), str):
                try:
                    res["checkpoint_json"] = json.loads(res["checkpoint_json"])
                except Exception:
                    res["checkpoint_json"] = {}
            res["cancellation_requested"] = bool(res.get("cancellation_requested", 0))
            jobs.append(res)
        return jobs

    def delete_ingestion_job(self, job_id: str) -> bool:
        """Remove a job record."""
        with self.conn:
            cursor = self.conn.execute("DELETE FROM ingestion_jobs WHERE job_id = ?", (job_id,))
            return cursor.rowcount > 0

    def close(self) -> None:
        """Close SQLite database connection."""
        if hasattr(self, "conn") and self.conn:
            self.conn.close()
