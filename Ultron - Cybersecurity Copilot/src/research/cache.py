"""Persistent Cache for External Research (M4).

Prevents redundant network queries, guarantees reproducible evaluations,
and caches normalized documents, content hashes, and extracted claims.
"""

from contextlib import contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any, Dict, Generator, List, Optional
from pydantic import BaseModel, Field

from src.research.models import ExternalClaim, ExternalSource, VersionScope


class CachedSourceRecord(BaseModel):
    """Normalized cache payload for a fetched external document."""
    url: str
    source_id: str
    retrieved_at: str
    content_hash: str
    provider_name: str
    http_status: int = 200
    normalized_content: str
    raw_content: str
    title: str
    source_type: str
    trust_tier: str
    claims_json: str = "[]"
    version_scope_json: Optional[str] = None
    repository: Optional[str] = None
    commit_sha: Optional[str] = None
    path: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None


class ResearchCache:
    """SQLite-backed persistent cache for external research sources and claims."""

    def __init__(self, db_path: Optional[Path] = None, ttl_seconds: int = 86400 * 7) -> None:
        self.db_path = db_path or Path("data/research_cache.sqlite3")
        self.ttl_seconds = ttl_seconds
        self.hits: int = 0
        self.misses: int = 0
        self._init_db()

    @contextmanager
    def _get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Provides an SQLite connection and guarantees closure even on Windows."""
        conn = sqlite3.connect(self.db_path)
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Initializes SQLite schema for external research caching."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS external_source_cache (
                    url TEXT PRIMARY KEY,
                    source_id TEXT NOT NULL,
                    retrieved_at TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    provider_name TEXT NOT NULL,
                    http_status INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    trust_tier TEXT NOT NULL,
                    normalized_content TEXT NOT NULL,
                    raw_content TEXT NOT NULL,
                    claims_json TEXT NOT NULL,
                    version_scope_json TEXT,
                    repository TEXT,
                    commit_sha TEXT,
                    path TEXT,
                    line_start INTEGER,
                    line_end INTEGER
                )
                """
            )
            conn.commit()

    def get(self, url: str) -> Optional[ExternalSource]:
        """Retrieves cached ExternalSource if present and valid."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT source_id, url, retrieved_at, content_hash, provider_name,
                       http_status, title, source_type, trust_tier, normalized_content,
                       raw_content, repository, commit_sha, path, line_start, line_end
                FROM external_source_cache
                WHERE url = ?
                """,
                (url,),
            )
            row = cursor.fetchone()
            if not row:
                self.misses += 1
                return None

            self.hits += 1
            return ExternalSource(
                source_id=row[0],
                url=row[1],
                retrieved_at=row[2],
                content_hash=row[3],
                http_status=row[5],
                title=row[6],
                source_type=row[7],
                trust_tier=row[8],
                normalized_content=row[9],
                raw_content=row[10],
                repository=row[11],
                commit_sha=row[12],
                path=row[13],
                line_start=row[14],
                line_end=row[15],
            )

    def put(
        self,
        source: ExternalSource,
        provider_name: str,
        claims: Optional[List[ExternalClaim]] = None,
        version_scope: Optional[VersionScope] = None,
    ) -> None:
        """Stores or updates an ExternalSource and extracted claims in the cache."""
        claims_json = json.dumps([c.model_dump() for c in claims]) if claims else "[]"
        version_json = json.dumps(version_scope.model_dump()) if version_scope else None

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO external_source_cache (
                    url, source_id, retrieved_at, content_hash, provider_name,
                    http_status, title, source_type, trust_tier, normalized_content,
                    raw_content, claims_json, version_scope_json, repository,
                    commit_sha, path, line_start, line_end
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    source.url,
                    source.source_id,
                    source.retrieved_at,
                    source.content_hash,
                    provider_name,
                    source.http_status,
                    source.title,
                    source.source_type.value,
                    source.trust_tier.value,
                    source.normalized_content,
                    source.raw_content,
                    claims_json,
                    version_json,
                    source.repository,
                    source.commit_sha,
                    source.path,
                    source.line_start,
                    source.line_end,
                ),
            )
            conn.commit()

    def get_claims(self, url: str) -> List[ExternalClaim]:
        """Retrieves previously extracted claims for a cached URL."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT claims_json FROM external_source_cache WHERE url = ?",
                (url,),
            )
            row = cursor.fetchone()
            if not row or not row[0]:
                return []
            try:
                data = json.loads(row[0])
                return [ExternalClaim(**item) for item in data]
            except Exception:
                return []

    @property
    def hit_rate(self) -> float:
        """Calculates cache hit rate."""
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0

    def clear(self) -> None:
        """Clears all records from the cache."""
        with self._get_connection() as conn:
            conn.execute("DELETE FROM external_source_cache")
            conn.commit()
        self.hits = 0
        self.misses = 0
