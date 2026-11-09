"""SQLite persistence manager for M11.5 Long Response Subsystem.
Stores response sessions, granular chunk lineage, provenance hashes, and version histories.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional
from src.core.logging import get_logger
from src.evidence.vault import RedactionVault
from src.database.manager import DatabaseManager
from src.response.models import (
    CitationReference,
    EpistemicStatus,
    GenerationTermination,
    ResponseChunk,
    ResponseSession,
    ResponseStatus,
    ResponseVersion,
    RuntimeOutcome,
)
from src.response.errors import PersistenceError

logger = get_logger("ResponsePersistence")


class ResponsePersistence:
    """
    Manages transactional storage and retrieval of response sessions,
    chunks, and historical versions in SQLite.
    """

    DDL_SCHEMA = """
    CREATE TABLE IF NOT EXISTS response_sessions (
        response_id         TEXT PRIMARY KEY,
        investigation_id    TEXT NOT NULL,
        assessment_id       TEXT,
        request_id          TEXT,
        parent_message_id   TEXT,
        model               TEXT NOT NULL,
        cumulative_tokens   INTEGER DEFAULT 0,
        status              TEXT NOT NULL,
        termination_reason  TEXT,
        final_content       TEXT NOT NULL,
        started_at          TEXT NOT NULL,
        completed_at        TEXT,
        active_version      INTEGER DEFAULT 1,
        epistemic_status    TEXT DEFAULT 'MODEL_INFERENCE',
        runtime_outcome     TEXT DEFAULT 'SUCCESS',
        validation_passed   INTEGER DEFAULT 1,
        validation_errors   TEXT,
        citations           TEXT,
        total_duration_seconds REAL DEFAULT 0.0,
        requested_model     TEXT,
        fallback_model      TEXT,
        fallback_used       INTEGER DEFAULT 0,
        fallback_reason     TEXT,
        user_prompt         TEXT
    );

    CREATE TABLE IF NOT EXISTS response_chunks (
        chunk_id            TEXT PRIMARY KEY,
        response_id         TEXT NOT NULL REFERENCES response_sessions(response_id) ON DELETE CASCADE,
        sequence_number     INTEGER NOT NULL,
        content             TEXT NOT NULL,
        raw_content         TEXT NOT NULL,
        content_hash        TEXT NOT NULL,
        token_count         INTEGER DEFAULT 0,
        generation_time     REAL DEFAULT 0.0,
        stop_reason         TEXT NOT NULL,
        created_at          TEXT NOT NULL,
        UNIQUE(response_id, sequence_number)
    );

    CREATE TABLE IF NOT EXISTS response_versions (
        version_id          TEXT PRIMARY KEY,
        response_id         TEXT NOT NULL REFERENCES response_sessions(response_id) ON DELETE CASCADE,
        version_number      INTEGER NOT NULL,
        content             TEXT NOT NULL,
        model               TEXT NOT NULL,
        status              TEXT NOT NULL,
        created_at          TEXT NOT NULL,
        UNIQUE(response_id, version_number)
    );

    CREATE INDEX IF NOT EXISTS idx_response_sessions_inv ON response_sessions(investigation_id);
    CREATE INDEX IF NOT EXISTS idx_response_chunks_session ON response_chunks(response_id, sequence_number);
    CREATE INDEX IF NOT EXISTS idx_response_versions_session ON response_versions(response_id, version_number);
    """

    def __init__(self, db_manager: DatabaseManager) -> None:
        self.db = db_manager
        self.vault = RedactionVault()
        self._initialize_tables()

    def _initialize_tables(self) -> None:
        """Create tables and migrate columns idempotently."""
        with self.db.get_connection() as conn:
            conn.executescript(self.DDL_SCHEMA)
            # Safe column migration for pre-existing tables
            existing_cols = {row["name"] for row in conn.execute("PRAGMA table_info(response_sessions)").fetchall()}
            migrations = [
                ("assessment_id", "TEXT"),
                ("request_id", "TEXT"),
                ("epistemic_status", "TEXT DEFAULT 'MODEL_INFERENCE'"),
                ("runtime_outcome", "TEXT DEFAULT 'SUCCESS'"),
                ("validation_passed", "INTEGER DEFAULT 1"),
                ("validation_errors", "TEXT"),
                ("citations", "TEXT"),
                ("total_duration_seconds", "REAL DEFAULT 0.0"),
                ("requested_model", "TEXT"),
                ("fallback_model", "TEXT"),
                ("fallback_used", "INTEGER DEFAULT 0"),
                ("fallback_reason", "TEXT"),
                ("user_prompt", "TEXT"),
            ]
            for col_name, col_type in migrations:
                if col_name not in existing_cols:
                    try:
                        conn.execute(f"ALTER TABLE response_sessions ADD COLUMN {col_name} {col_type}")
                    except sqlite3.OperationalError:
                        pass
            conn.commit()

    def create_session(self, session: ResponseSession) -> None:
        """Insert new response session transactionally."""
        try:
            with self.db.get_connection() as conn:
                citations_json = json.dumps([c.model_dump() for c in session.citations]) if session.citations else None
                validation_errors_json = json.dumps(session.validation_errors) if session.validation_errors else None
                conn.execute(
                    """
                    INSERT OR REPLACE INTO response_sessions (
                        response_id, investigation_id, assessment_id, request_id,
                        parent_message_id, model, cumulative_tokens, status,
                        termination_reason, final_content, started_at, completed_at,
                        active_version, epistemic_status, runtime_outcome,
                        validation_passed, validation_errors, citations, total_duration_seconds,
                        requested_model, fallback_model, fallback_used, fallback_reason, user_prompt
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        session.response_id,
                        session.investigation_id,
                        session.assessment_id,
                        session.request_id,
                        session.parent_message_id,
                        session.model,
                        session.cumulative_tokens,
                        session.status.value,
                        session.termination_reason.value if session.termination_reason else None,
                        self.vault.redact_text(session.final_content),
                        session.started_at,
                        session.completed_at,
                        session.active_version,
                        session.epistemic_status.value if hasattr(session.epistemic_status, "value") else str(session.epistemic_status),
                        session.runtime_outcome.value if hasattr(session.runtime_outcome, "value") else str(session.runtime_outcome),
                        1 if session.validation_passed else 0,
                        validation_errors_json,
                        citations_json,
                        session.total_duration_seconds,
                        session.requested_model,
                        session.fallback_model,
                        1 if session.fallback_used else 0,
                        session.fallback_reason,
                        session.user_prompt,
                    ),
                )
                conn.commit()
                session.persisted = True
                session.persistence_error = None
        except Exception as e:
            session.persisted = False
            session.persistence_error = str(e)
            logger.error(f"Failed to persist response session {session.response_id}: {e}")
            raise PersistenceError(f"Failed to persist response session {session.response_id}: {e}") from e

    def update_session(
        self,
        response_id: str,
        status: ResponseStatus,
        final_content: str,
        cumulative_tokens: int,
        termination_reason: Optional[GenerationTermination] = None,
        completed_at: Optional[str] = None,
        epistemic_status: Optional[str] = None,
        runtime_outcome: Optional[str] = None,
        validation_passed: Optional[bool] = None,
        validation_errors: Optional[List[str]] = None,
        citations: Optional[List[Any]] = None,
        total_duration_seconds: Optional[float] = None,
    ) -> None:
        """Update session state upon chunk arrival or completion."""
        try:
            with self.db.get_connection() as conn:
                citations_json = json.dumps([c.model_dump() if hasattr(c, "model_dump") else c for c in citations]) if citations is not None else None
                validation_errors_json = json.dumps(validation_errors) if validation_errors is not None else None
                conn.execute(
                    """
                    UPDATE response_sessions
                    SET status = ?,
                        final_content = ?,
                        cumulative_tokens = ?,
                        termination_reason = ?,
                        completed_at = COALESCE(?, completed_at),
                        epistemic_status = COALESCE(?, epistemic_status),
                        runtime_outcome = COALESCE(?, runtime_outcome),
                        validation_passed = COALESCE(?, validation_passed),
                        validation_errors = COALESCE(?, validation_errors),
                        citations = COALESCE(?, citations),
                        total_duration_seconds = COALESCE(?, total_duration_seconds)
                    WHERE response_id = ?
                    """,
                    (
                        status.value,
                        self.vault.redact_text(final_content),
                        cumulative_tokens,
                        termination_reason.value if termination_reason else None,
                        completed_at,
                        epistemic_status,
                        runtime_outcome,
                        (1 if validation_passed else 0) if validation_passed is not None else None,
                        validation_errors_json,
                        citations_json,
                        total_duration_seconds,
                        response_id,
                    ),
                )
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to update response session {response_id}: {e}")
            raise PersistenceError(f"Failed to update response session {response_id}: {e}") from e

    def save_chunk(self, response_id: str, chunk: ResponseChunk) -> None:
        """Insert or replace an individual response chunk with cryptographic hash."""
        with self.db.get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO response_chunks (
                    chunk_id, response_id, sequence_number, content,
                    raw_content, content_hash, token_count, generation_time,
                    stop_reason, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    chunk.chunk_id,
                    response_id,
                    chunk.sequence_number,
                    self.vault.redact_text(chunk.content),
                    self.vault.redact_text(chunk.raw_content),
                    chunk.content_hash,
                    chunk.token_count,
                    chunk.generation_time,
                    chunk.stop_reason,
                    chunk.created_at,
                ),
            )
            conn.commit()

    def save_version(self, version: ResponseVersion) -> None:
        """Persist a discrete generation version for an answer."""
        with self.db.get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO response_versions (
                    version_id, response_id, version_number, content,
                    model, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    version.version_id,
                    version.response_id,
                    version.version_number,
                    self.vault.redact_text(version.content),
                    version.model,
                    version.status.value,
                    version.created_at,
                ),
            )
            conn.commit()

    def get_session(self, response_id: str) -> Optional[ResponseSession]:
        """Load session and associated chunks by response ID."""
        with self.db.get_connection() as conn:
            row = conn.execute("SELECT * FROM response_sessions WHERE response_id = ?", (response_id,)).fetchone()
            if not row:
                return None
            session_dict = dict(row)

            # Fetch chunks
            chunk_rows = conn.execute(
                "SELECT * FROM response_chunks WHERE response_id = ? ORDER BY sequence_number ASC",
                (response_id,),
            ).fetchall()
            chunks = [ResponseChunk(**dict(r)) for r in chunk_rows]

            term_reason = (
                GenerationTermination(session_dict["termination_reason"])
                if session_dict.get("termination_reason")
                else None
            )

            # Parse json-serialized fields
            citations_raw = session_dict.get("citations")
            citations_list = []
            if citations_raw:
                try:
                    c_data = json.loads(citations_raw)
                    citations_list = [CitationReference(**c) for c in c_data]
                except Exception:
                    citations_list = []

            val_errs_raw = session_dict.get("validation_errors")
            val_errs_list = []
            if val_errs_raw:
                try:
                    val_errs_list = json.loads(val_errs_raw)
                except Exception:
                    val_errs_list = []

            epistemic = (
                EpistemicStatus(session_dict["epistemic_status"])
                if session_dict.get("epistemic_status")
                else EpistemicStatus.MODEL_INFERENCE
            )
            runtime_out = (
                RuntimeOutcome(session_dict["runtime_outcome"])
                if session_dict.get("runtime_outcome")
                else RuntimeOutcome.SUCCESS
            )

            return ResponseSession(
                response_id=session_dict["response_id"],
                investigation_id=session_dict["investigation_id"],
                assessment_id=session_dict.get("assessment_id"),
                request_id=session_dict.get("request_id"),
                parent_message_id=session_dict.get("parent_message_id"),
                model=session_dict["model"],
                chunks=chunks,
                cumulative_tokens=session_dict["cumulative_tokens"],
                status=ResponseStatus(session_dict["status"]),
                termination_reason=term_reason,
                final_content=session_dict["final_content"],
                started_at=session_dict["started_at"],
                completed_at=session_dict.get("completed_at"),
                active_version=session_dict.get("active_version", 1),
                epistemic_status=epistemic,
                runtime_outcome=runtime_out,
                validation_passed=bool(session_dict.get("validation_passed", 1)),
                validation_errors=val_errs_list,
                citations=citations_list,
                sources=[c.source_id for c in citations_list],
                continuation_count=max(0, len(chunks) - 1),
                is_truncated=session_dict["status"] in (ResponseStatus.TOKEN_LIMIT.value, ResponseStatus.TIMEOUT.value),
                persisted=True,
                persistence_error=None,
                total_duration_seconds=float(session_dict.get("total_duration_seconds") or 0.0),
                requested_model=session_dict.get("requested_model"),
                fallback_model=session_dict.get("fallback_model"),
                fallback_used=bool(session_dict.get("fallback_used", 0)),
                fallback_reason=session_dict.get("fallback_reason"),
                user_prompt=session_dict.get("user_prompt"),
            )

    def get_chunks(self, response_id: str) -> List[ResponseChunk]:
        """Fetch all chunks for a response session."""
        with self.db.get_connection() as conn:
            chunk_rows = conn.execute(
                "SELECT * FROM response_chunks WHERE response_id = ? ORDER BY sequence_number ASC",
                (response_id,),
            ).fetchall()
            return [ResponseChunk(**dict(r)) for r in chunk_rows]

    def get_versions(self, response_id: str) -> List[ResponseVersion]:
        """Fetch all historical versions for a response session."""
        with self.db.get_connection() as conn:
            v_rows = conn.execute(
                "SELECT * FROM response_versions WHERE response_id = ? ORDER BY version_number ASC",
                (response_id,),
            ).fetchall()
            return [ResponseVersion(**dict(r)) for r in v_rows]
