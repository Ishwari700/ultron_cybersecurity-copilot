"""SQLite database manager for unified evidence.db."""

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional
from src.core.config import DatabaseConfig


class DatabaseManager:
    """
    Manages SQLite connections, schema initialization, and transactional
    integrity for the unified evidence.db database.
    """

    def __init__(self, config: Optional[DatabaseConfig] = None, db_path: Optional[Path] = None) -> None:
        if db_path:
            self.db_path = Path(db_path)
            self.timeout = 30.0
            self.enable_foreign_keys = True
            self.enable_wal = True
        elif isinstance(config, (Path, str)):
            self.db_path = Path(config)
            self.timeout = 30.0
            self.enable_foreign_keys = True
            self.enable_wal = True
        elif config:
            self.db_path = Path(config.db_path)
            self.timeout = config.timeout_seconds
            self.enable_foreign_keys = config.enable_foreign_keys
            self.enable_wal = config.enable_wal_mode
        else:
            self.db_path = Path("data/evidence.db")
            self.timeout = 30.0
            self.enable_foreign_keys = True
            self.enable_wal = True

        if self.db_path != Path(":memory:"):
            self.db_path.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Provide a contextual connection with foreign keys and Row factory enabled."""
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=self.timeout,
        )
        conn.row_factory = sqlite3.Row
        if self.enable_foreign_keys:
            conn.execute("PRAGMA foreign_keys = ON;")
        if self.enable_wal and self.db_path != Path(":memory:"):
            conn.execute("PRAGMA journal_mode = WAL;")
        try:
            yield conn
        finally:
            conn.close()

    def initialize_schema(self, schema_file: Optional[Path] = None) -> None:
        """Execute the DDL schema to initialize or migrate the database."""
        target_file = schema_file or (Path(__file__).parent / "schema.sql")
        with open(target_file, "r", encoding="utf-8") as f:
            ddl = f.read()

        with self.get_connection() as conn:
            conn.executescript(ddl)
            # Setup FTS5 for evidence items keyword search
            conn.executescript("""
                CREATE VIRTUAL TABLE IF NOT EXISTS evidence_fts USING fts5(
                    fact_id UNINDEXED,
                    statement,
                    source_tool UNINDEXED,
                    content='evidence_items',
                    content_rowid='rowid'
                );

                CREATE TRIGGER IF NOT EXISTS trg_evidence_ai AFTER INSERT ON evidence_items BEGIN
                    INSERT INTO evidence_fts(rowid, fact_id, statement, source_tool)
                    VALUES (new.rowid, new.fact_id, new.statement, new.source_tool);
                END;

                CREATE TRIGGER IF NOT EXISTS trg_evidence_ad AFTER DELETE ON evidence_items BEGIN
                    INSERT INTO evidence_fts(evidence_fts, rowid, fact_id, statement, source_tool)
                    VALUES('delete', old.rowid, old.fact_id, old.statement, old.source_tool);
                END;

                CREATE TRIGGER IF NOT EXISTS trg_evidence_au AFTER UPDATE ON evidence_items BEGIN
                    INSERT INTO evidence_fts(evidence_fts, rowid, fact_id, statement, source_tool)
                    VALUES('delete', old.rowid, old.fact_id, old.statement, old.source_tool);
                    INSERT INTO evidence_fts(rowid, fact_id, statement, source_tool)
                    VALUES(new.rowid, new.fact_id, new.statement, new.source_tool);
                END;
            """)
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS dashboard_users (
                    user_id             TEXT PRIMARY KEY,
                    username            TEXT UNIQUE NOT NULL,
                    password_hash       TEXT NOT NULL,
                    role                TEXT NOT NULL CHECK(role IN ('observer', 'reviewer', 'admin')),
                    is_active           INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0, 1)),
                    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_dashboard_users_username ON dashboard_users(username);
            """)
            try:
                conn.execute("ALTER TABLE conversation_messages ADD COLUMN response_id TEXT")
            except sqlite3.OperationalError:
                pass
            try:
                conn.execute("ALTER TABLE conversation_messages ADD COLUMN status TEXT DEFAULT 'COMPLETED'")
            except sqlite3.OperationalError:
                pass
            conn.commit()

    # Scope Decision Operations
    def insert_scope_decision(self, decision: Dict[str, Any]) -> None:
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO scope_decisions (
                    scope_decision_id, decision, requested_url, canonical_host,
                    resolved_addresses, matched_rule, out_of_scope_rule, tool_policy,
                    reason, scope_policy_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    decision["scope_decision_id"],
                    decision["decision"],
                    decision["requested_url"],
                    decision["canonical_host"],
                    json.dumps(decision["resolved_addresses"]) if isinstance(decision["resolved_addresses"], list) else decision["resolved_addresses"],
                    decision.get("matched_rule"),
                    decision.get("out_of_scope_rule"),
                    decision["tool_policy"],
                    decision.get("reason"),
                    decision["scope_policy_version"],
                ),
            )
            conn.commit()

    def get_scope_decision(self, scope_decision_id: str) -> Optional[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.execute("SELECT * FROM scope_decisions WHERE scope_decision_id = ?", (scope_decision_id,))
            row = cursor.fetchone()
            if not row:
                return None
            data = dict(row)
            if data.get("resolved_addresses"):
                try:
                    data["resolved_addresses"] = json.loads(data["resolved_addresses"])
                except Exception:
                    pass
            return data

    # Asset Operations
    def insert_asset(self, asset: Dict[str, Any]) -> None:
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO assets (
                    asset_id, method, host, raw_path, normalized_path,
                    normalization_confidence, http_semantics, application_mutability,
                    liveness, scope_decision_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(asset_id) DO UPDATE SET
                    last_checked_at = CURRENT_TIMESTAMP,
                    liveness = excluded.liveness,
                    application_mutability = CASE WHEN excluded.application_mutability != 'UNKNOWN' THEN excluded.application_mutability ELSE assets.application_mutability END
                """,
                (
                    asset["asset_id"],
                    asset["method"],
                    asset["host"],
                    asset["raw_path"],
                    asset["normalized_path"],
                    asset.get("normalization_confidence", 1.0),
                    asset.get("http_semantics", asset["method"]),
                    asset.get("application_mutability", "UNKNOWN"),
                    asset.get("liveness", "SHADOW_ACTIVE"),
                    asset.get("scope_decision_id"),
                ),
            )
            conn.commit()

    def update_asset_state(self, asset_id: str, field: str, new_value: str) -> None:
        """Update an asset state field and atomically record in asset_state_history."""
        if field not in ("liveness", "application_mutability"):
            raise ValueError(f"Invalid asset history field: {field}")

        _SELECT_QUERIES = {
            "liveness": "SELECT liveness FROM assets WHERE asset_id = ?",
            "application_mutability": "SELECT application_mutability FROM assets WHERE asset_id = ?",
        }
        _UPDATE_QUERIES = {
            "liveness": "UPDATE assets SET liveness = ?, last_checked_at = CURRENT_TIMESTAMP WHERE asset_id = ?",
            "application_mutability": "UPDATE assets SET application_mutability = ?, last_checked_at = CURRENT_TIMESTAMP WHERE asset_id = ?",
        }

        with self.get_connection() as conn:
            cursor = conn.execute(_SELECT_QUERIES[field], (asset_id,))
            row = cursor.fetchone()
            if not row:
                raise ValueError(f"Asset not found: {asset_id}")
            old_value = row[0]

            if old_value != new_value:
                conn.execute(_UPDATE_QUERIES[field], (new_value, asset_id))
                conn.execute(
                    "INSERT INTO asset_state_history (asset_id, field, old_value, new_value) VALUES (?, ?, ?, ?)",
                    (asset_id, field, old_value, new_value),
                )
                conn.commit()

    def get_asset(self, asset_id: str) -> Optional[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.execute("SELECT * FROM assets WHERE asset_id = ?", (asset_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    # Parameter Operations
    def insert_parameter(self, param: Dict[str, Any]) -> None:
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO parameters (
                    param_id, asset_id, param_name, location, content_type,
                    param_type, is_server_volatile
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(asset_id, param_name, location) DO UPDATE SET
                    content_type = excluded.content_type,
                    param_type = excluded.param_type,
                    is_server_volatile = excluded.is_server_volatile
                """,
                (
                    param["param_id"],
                    param["asset_id"],
                    param["param_name"],
                    param["location"],
                    param.get("content_type"),
                    param.get("param_type"),
                    1 if param.get("is_server_volatile") else 0,
                ),
            )
            conn.commit()

    def get_parameters_for_asset(self, asset_id: str) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.execute("SELECT * FROM parameters WHERE asset_id = ?", (asset_id,))
            return [dict(r) for r in cursor.fetchall()]

    # Identity Operations
    def insert_identity(self, identity: Dict[str, Any]) -> None:
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO identities (identity_id, role, session_ref, notes)
                VALUES (?, ?, ?, ?)
                """,
                (
                    identity["identity_id"],
                    identity.get("role"),
                    identity.get("session_ref"),
                    identity.get("notes"),
                ),
            )
            conn.commit()

    def get_identity(self, identity_id: str) -> Optional[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.execute("SELECT * FROM identities WHERE identity_id = ?", (identity_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    # Evidence Item Operations
    def insert_evidence_item(self, item: Dict[str, Any]) -> None:
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO evidence_items (
                    fact_id, certainty, statement, source_tool, source_version,
                    trust, raw_evidence_ref, scope_decision_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    item["fact_id"],
                    item["certainty"],
                    item["statement"],
                    item["source_tool"],
                    item.get("source_version"),
                    item.get("trust", "UNTRUSTED"),
                    item.get("raw_evidence_ref"),
                    item.get("scope_decision_id"),
                ),
            )
            conn.commit()

    def get_evidence_item(self, fact_id: str) -> Optional[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.execute("SELECT * FROM evidence_items WHERE fact_id = ?", (fact_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def query_fts(self, query: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Run BM25 keyword query against evidence_fts."""
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT f.fact_id, f.statement, f.source_tool, bm25(evidence_fts) as rank
                FROM evidence_fts f
                WHERE evidence_fts MATCH ?
                ORDER BY rank
                LIMIT ?
                """,
                (query, limit),
            )
            return [dict(r) for r in cursor.fetchall()]

    # Security Invariants
    def insert_security_invariant(self, invariant: Dict[str, Any]) -> None:
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO security_invariants (
                    invariant_id, description, origin, derived_from, confidence
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    invariant["invariant_id"],
                    invariant["description"],
                    invariant["origin"],
                    json.dumps(invariant.get("derived_from", [])),
                    invariant.get("confidence", "MEDIUM"),
                ),
            )
            conn.commit()

    def get_security_invariant(self, invariant_id: str) -> Optional[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.execute("SELECT * FROM security_invariants WHERE invariant_id = ?", (invariant_id,))
            row = cursor.fetchone()
            if not row:
                return None
            data = dict(row)
            if data.get("derived_from"):
                try:
                    data["derived_from"] = json.loads(data["derived_from"])
                except Exception:
                    pass
            return data

    # Hypotheses Operations
    def insert_hypothesis(self, hypothesis: Dict[str, Any]) -> int:
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO hypotheses (
                    asset_id, category, decision, evidence_state, actor_identity_id,
                    target_identity_id, reasoning_summary, missing_evidence,
                    experiment_proposal, state, evidence_ref, revision
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    hypothesis["asset_id"],
                    hypothesis["category"],
                    hypothesis["decision"],
                    hypothesis["evidence_state"],
                    hypothesis.get("actor_identity_id"),
                    hypothesis.get("target_identity_id"),
                    hypothesis.get("reasoning_summary"),
                    json.dumps(hypothesis.get("missing_evidence", [])),
                    json.dumps(hypothesis["experiment_proposal"]) if isinstance(hypothesis.get("experiment_proposal"), dict) else hypothesis.get("experiment_proposal"),
                    hypothesis.get("state", "New"),
                    hypothesis.get("evidence_ref"),
                    hypothesis.get("revision", 1),
                ),
            )
            conn.commit()
            return int(cursor.lastrowid)

    def get_hypothesis(self, hypothesis_id: int) -> Optional[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.execute("SELECT * FROM hypotheses WHERE id = ?", (hypothesis_id,))
            row = cursor.fetchone()
            if not row:
                return None
            data = dict(row)
            if data.get("missing_evidence"):
                try:
                    data["missing_evidence"] = json.loads(data["missing_evidence"])
                except Exception:
                    pass
            return data

    def update_hypothesis_state(self, hypothesis_id: int, new_state: str, evidence_ref: Optional[str] = None) -> None:
        """Update hypothesis state. Hard triggers enforce evidence, transitions, and verification records."""
        valid_states = {"New", "Under Review", "Confirmed", "Rejected", "Reported"}
        if new_state not in valid_states:
            raise ValueError(f"Invalid hypothesis state: '{new_state}'. Allowed states: {sorted(valid_states)}")

        with self.get_connection() as conn:
            with conn:
                if evidence_ref:
                    conn.execute(
                        "UPDATE hypotheses SET state = ?, evidence_ref = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                        (new_state, evidence_ref, hypothesis_id),
                    )
                else:
                    conn.execute(
                        "UPDATE hypotheses SET state = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                        (new_state, hypothesis_id),
                    )

    def confirm_hypothesis_atomic(
        self,
        hypothesis_id: int,
        actor: str,
        evidence_ref: str,
        dashboard_session_id: str,
        notes: Optional[str] = None,
        verification_id: Optional[str] = None,
    ) -> str:
        """
        Atomically records human verification and transitions hypothesis to Confirmed
        within a single database transaction on the same connection.
        If either operation or trigger fails, rolls back completely.
        """
        if not actor or not actor.strip():
            raise ValueError("Actor identity must not be empty for human verification.")
        if not evidence_ref or len(evidence_ref.strip()) < 5:
            raise ValueError("evidence_ref must be non-empty and at least 5 characters.")
        if not dashboard_session_id or not dashboard_session_id.strip():
            raise ValueError("dashboard_session_id must not be empty.")

        verif_id = (
            verification_id
            or f"VERIF-{hashlib.sha256(f'{hypothesis_id}:{actor}:{dashboard_session_id}'.encode('utf-8')).hexdigest()[:10].upper()}"
        )

        with self.get_connection() as conn:
            with conn:
                # 1. Insert verification record
                conn.execute(
                    """
                    INSERT INTO verifications (
                        verification_id, hypothesis_id, actor, decision, evidence_ref,
                        dashboard_session_id, notes
                    ) VALUES (?, ?, ?, 'confirmed', ?, ?, ?)
                    """,
                    (
                        verif_id,
                        hypothesis_id,
                        actor,
                        evidence_ref,
                        dashboard_session_id,
                        notes,
                    ),
                )

                # 2. Update hypothesis state to Confirmed (database triggers will validate Under Review state and evidence_ref)
                conn.execute(
                    """
                    UPDATE hypotheses
                    SET state = 'Confirmed', evidence_ref = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (evidence_ref, hypothesis_id),
                )

        return verif_id

    # Verification Operations
    def record_verification(self, verification: Dict[str, Any]) -> None:
        """Record human verification decision in verifications table."""
        with self.get_connection() as conn:
            with conn:
                conn.execute(
                    """
                    INSERT INTO verifications (
                        verification_id, hypothesis_id, actor, decision, evidence_ref,
                        dashboard_session_id, notes
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        verification["verification_id"],
                        verification["hypothesis_id"],
                        verification["actor"],
                        verification["decision"],
                        verification["evidence_ref"],
                        verification["dashboard_session_id"],
                        verification.get("notes"),
                    ),
                )

    # -------------------------------------------------------------------------
    # Investigation & Conversation Operations (Phase 12.3)
    # -------------------------------------------------------------------------

    def insert_investigation(self, inv: Dict[str, Any]) -> None:
        """Insert or update a persistent research investigation session."""
        now = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO investigations (
                    investigation_id, name, target_host, scope_status, status, is_demo, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(investigation_id) DO UPDATE SET
                    name = excluded.name,
                    target_host = excluded.target_host,
                    scope_status = excluded.scope_status,
                    status = excluded.status,
                    is_demo = excluded.is_demo,
                    updated_at = excluded.updated_at
                """,
                (
                    inv.get("investigation_id") or inv.get("id"),
                    inv["name"],
                    inv["target_host"],
                    inv.get("scope_status", "ALLOWED"),
                    inv.get("status", "ACTIVE"),
                    1 if inv.get("is_demo") else 0,
                    inv.get("created_at", now),
                    inv.get("updated_at", now),
                ),
            )
            conn.commit()

    def get_investigation(self, investigation_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve investigation metadata by ID."""
        with self.get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM investigations WHERE investigation_id = ?",
                (investigation_id,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            res = dict(row)
            res["id"] = res["investigation_id"]
            res["is_demo"] = bool(res.get("is_demo", 0))
            return res

    def update_investigation(self, investigation_id: str, updates: Dict[str, Any]) -> bool:
        """Update investigation fields such as name or status."""
        allowed_fields = {"name", "status", "scope_status", "updated_at"}
        valid_updates = {k: v for k, v in updates.items() if k in allowed_fields}
        if not valid_updates:
            return False

        if "updated_at" not in valid_updates:
            valid_updates["updated_at"] = datetime.now(timezone.utc).isoformat()

        clauses = [f"{k} = ?" for k in valid_updates.keys()]
        values = list(valid_updates.values()) + [investigation_id]

        with self.get_connection() as conn:
            cursor = conn.execute(
                f"UPDATE investigations SET {', '.join(clauses)} WHERE investigation_id = ?",
                values,
            )
            conn.commit()
            return cursor.rowcount > 0

    def delete_investigation(self, investigation_id: str) -> bool:
        """Permanently delete an investigation and cascading conversation history."""
        with self.get_connection() as conn:
            cursor = conn.execute(
                "DELETE FROM investigations WHERE investigation_id = ?",
                (investigation_id,),
            )
            conn.commit()
            return cursor.rowcount > 0

    def list_investigations(self, include_archived: bool = False, search_query: Optional[str] = None) -> List[Dict[str, Any]]:
        """List persisted investigations with message counts and last activity."""
        query = """
            SELECT 
                i.investigation_id as id,
                i.investigation_id,
                i.name,
                i.target_host,
                i.scope_status,
                i.status,
                i.is_demo,
                i.created_at,
                i.updated_at,
                COUNT(m.id) as message_count,
                COALESCE(MAX(m.created_at), i.updated_at) as last_activity
            FROM investigations i
            LEFT JOIN conversation_messages m ON i.investigation_id = m.investigation_id
        """
        where_clauses = []
        params: List[Any] = []
        if not include_archived:
            where_clauses.append("i.status != 'ARCHIVED'")
        if search_query:
            where_clauses.append("(i.name LIKE ? OR i.target_host LIKE ?)")
            params.extend([f"%{search_query}%", f"%{search_query}%"])
        if where_clauses:
            query += " WHERE " + " AND ".join(where_clauses)
        query += " GROUP BY i.investigation_id ORDER BY last_activity DESC"

        with self.get_connection() as conn:
            cursor = conn.execute(query, params)
            results = []
            for row in cursor.fetchall():
                d = dict(row)
                d["is_demo"] = bool(d.get("is_demo", 0))
                results.append(d)
            return results

    def insert_message(self, msg: Dict[str, Any]) -> None:
        """Persist a conversation message record."""
        structured_data = msg.get("structured_data")
        if structured_data is not None and not isinstance(structured_data, str):
            structured_data = json.dumps(structured_data)

        created_at = msg.get("created_at") or datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            # Check if M11.5 columns exist
            has_response_id = False
            try:
                cols = [r["name"] for r in conn.execute("PRAGMA table_info(conversation_messages)").fetchall()]
                has_response_id = "response_id" in cols
            except Exception:
                pass

            if has_response_id:
                conn.execute(
                    """
                    INSERT INTO conversation_messages (
                        id, investigation_id, sequence_number, sender, content,
                        structured_type, structured_data, delivery_status,
                        cascade_trace_id, model_name, model_digest, response_id, status, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        content = excluded.content,
                        delivery_status = excluded.delivery_status,
                        structured_data = excluded.structured_data,
                        model_name = excluded.model_name,
                        model_digest = excluded.model_digest,
                        response_id = excluded.response_id,
                        status = excluded.status
                    """,
                    (
                        msg["id"],
                        msg["investigation_id"],
                        msg["sequence_number"],
                        msg["sender"],
                        msg["content"],
                        msg.get("structured_type", "NONE"),
                        structured_data,
                        msg.get("delivery_status", "delivered"),
                        msg.get("cascade_trace_id"),
                        msg.get("model_name"),
                        msg.get("model_digest"),
                        msg.get("response_id"),
                        msg.get("status", "COMPLETED"),
                        created_at,
                    ),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO conversation_messages (
                        id, investigation_id, sequence_number, sender, content,
                        structured_type, structured_data, delivery_status,
                        cascade_trace_id, model_name, model_digest, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        delivery_status = excluded.delivery_status,
                        structured_data = excluded.structured_data
                    """,
                    (
                        msg["id"],
                        msg["investigation_id"],
                        msg["sequence_number"],
                        msg["sender"],
                        msg["content"],
                        msg.get("structured_type", "NONE"),
                        structured_data,
                        msg.get("delivery_status", "delivered"),
                        msg.get("cascade_trace_id"),
                        msg.get("model_name"),
                        msg.get("model_digest"),
                        created_at,
                    ),
                )
            # Update parent investigation updated_at
            conn.execute(
                "UPDATE investigations SET updated_at = ? WHERE investigation_id = ?",
                (created_at, msg["investigation_id"]),
            )
            conn.commit()

    def get_messages(self, investigation_id: str, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Retrieve chronological conversation messages for an investigation."""
        with self.get_connection() as conn:
            params: List[Any] = [investigation_id]
            if limit:
                query = """
                    SELECT * FROM (
                        SELECT * FROM conversation_messages 
                        WHERE investigation_id = ? 
                        ORDER BY sequence_number DESC 
                        LIMIT ?
                    ) ORDER BY sequence_number ASC
                """
                params.append(limit)
            else:
                query = """
                    SELECT * FROM conversation_messages 
                    WHERE investigation_id = ? 
                    ORDER BY sequence_number ASC
                """

            cursor = conn.execute(query, params)
            messages = []
            for row in cursor.fetchall():
                d = dict(row)
                if d.get("structured_data"):
                    try:
                        d["structured_data"] = json.loads(d["structured_data"])
                    except Exception:
                        pass
                messages.append(d)
            return messages

    def get_message(self, message_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single message by ID."""
        with self.get_connection() as conn:
            row = conn.execute("SELECT * FROM conversation_messages WHERE id = ?", (message_id,)).fetchone()
            if not row:
                return None
            d = dict(row)
            if d.get("structured_data"):
                try:
                    d["structured_data"] = json.loads(d["structured_data"])
                except Exception:
                    pass
            return d

    def update_message(self, message_id: str, updates: Dict[str, Any]) -> None:
        """Update fields of an existing conversation message."""
        if not updates:
            return
        set_clauses = []
        values = []
        for k, v in updates.items():
            if k == "structured_data" and v is not None and not isinstance(v, str):
                v = json.dumps(v)
            set_clauses.append(f"{k} = ?")
            values.append(v)
        values.append(message_id)
        with self.get_connection() as conn:
            conn.execute(f"UPDATE conversation_messages SET {', '.join(set_clauses)} WHERE id = ?", tuple(values))
            conn.commit()

    def get_message_by_response_id(self, response_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a conversation message by associated response_id."""
        with self.get_connection() as conn:
            row = conn.execute("SELECT * FROM conversation_messages WHERE response_id = ?", (response_id,)).fetchone()
            if not row:
                return None
            d = dict(row)
            if d.get("structured_data"):
                try:
                    d["structured_data"] = json.loads(d["structured_data"])
                except Exception:
                    pass
            return d

    def get_paired_assistant_message(self, user_msg_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve assistant message immediately following a user message in sequence."""
        user_msg = self.get_message(user_msg_id)
        if not user_msg:
            return None
        inv_id = user_msg.get("investigation_id")
        seq = user_msg.get("sequence_number")
        if seq is None or not inv_id:
            return None
        with self.get_connection() as conn:
            row = conn.execute(
                """
                SELECT * FROM conversation_messages
                WHERE investigation_id = ? AND sequence_number > ? AND sender = 'assistant'
                ORDER BY sequence_number ASC LIMIT 1
                """,
                (inv_id, seq),
            ).fetchone()
            if not row:
                return None
            d = dict(row)
            if d.get("structured_data"):
                try:
                    d["structured_data"] = json.loads(d["structured_data"])
                except Exception:
                    pass
            return d

    def supersede_messages_after(self, investigation_id: str, sequence_number: int) -> int:
        """Mark subsequent messages after sequence_number as SUPERSEDED."""
        with self.get_connection() as conn:
            cursor = conn.execute(
                "UPDATE conversation_messages SET status = 'SUPERSEDED' WHERE investigation_id = ? AND sequence_number > ?",
                (investigation_id, sequence_number),
            )
            conn.commit()
            return cursor.rowcount

    def get_message_count(self, investigation_id: str) -> int:
        """Count total messages for an investigation."""
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM conversation_messages WHERE investigation_id = ?",
                (investigation_id,),
            ).fetchone()
            return row[0] if row else 0

    def get_next_sequence_number(self, investigation_id: str) -> int:
        """Get the next deterministic sequence number for an investigation."""
        with self.get_connection() as conn:
            cursor = conn.execute(
                "SELECT COALESCE(MAX(sequence_number), 0) + 1 FROM conversation_messages WHERE investigation_id = ?",
                (investigation_id,),
            )
            row = cursor.fetchone()
            return row[0] if row else 1

    # -------------------------------------------------------------------------
    # Cascade Execution Traces Operations (Phase 12.4)
    # -------------------------------------------------------------------------

    def insert_cascade_trace(self, trace: Dict[str, Any]) -> None:
        """Persist an authoritative runtime cascade execution trace."""
        stages = trace.get("stages", [])
        stages_serialized = [s.model_dump() if hasattr(s, "model_dump") else s for s in stages]
        created_at = trace.get("timestamp") or trace.get("created_at") or datetime.now(timezone.utc).isoformat()

        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO cascade_execution_traces (
                    run_id, investigation_id, user_message_id, assistant_message_id,
                    task_type, target_endpoint, overall_status, routing_decision,
                    escalated, handoff_provenance_hash, total_latency_seconds,
                    stages_json, error_message, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    trace["run_id"],
                    trace.get("investigation_id"),
                    trace.get("user_message_id"),
                    trace.get("assistant_message_id"),
                    trace.get("task_type", "SECURITY_RESEARCH"),
                    trace.get("target_endpoint", ""),
                    trace.get("overall_status", "CASCADE_VERIFIED"),
                    trace.get("routing_decision"),
                    1 if trace.get("escalated") else 0,
                    trace.get("handoff_provenance_hash"),
                    float(trace.get("total_latency_seconds", 0.0)),
                    json.dumps(stages_serialized),
                    trace.get("error_message"),
                    created_at,
                ),
            )
            conn.commit()

    def get_cascade_trace(self, run_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a specific cascade execution trace by its run ID."""
        with self.get_connection() as conn:
            row = conn.execute("SELECT * FROM cascade_execution_traces WHERE run_id = ?", (run_id,)).fetchone()
            if not row:
                return None
            d = dict(row)
            d["escalated"] = bool(d.get("escalated", 0))
            if d.get("stages_json"):
                try:
                    d["stages"] = json.loads(d["stages_json"])
                except Exception:
                    d["stages"] = []
            else:
                d["stages"] = []
            return d

    def list_cascade_traces(self, investigation_id: Optional[str] = None, limit: int = 10) -> List[Dict[str, Any]]:
        """Retrieve recent cascade execution traces, optionally filtered by investigation ID."""
        with self.get_connection() as conn:
            if investigation_id:
                query = "SELECT * FROM cascade_execution_traces WHERE investigation_id = ? ORDER BY created_at DESC LIMIT ?"
                cursor = conn.execute(query, (investigation_id, limit))
            else:
                query = "SELECT * FROM cascade_execution_traces ORDER BY created_at DESC LIMIT ?"
                cursor = conn.execute(query, (limit,))

            traces = []
            for row in cursor.fetchall():
                d = dict(row)
                d["escalated"] = bool(d.get("escalated", 0))
                if d.get("stages_json"):
                    try:
                        d["stages"] = json.loads(d["stages_json"])
                    except Exception:
                        d["stages"] = []
                else:
                    d["stages"] = []
                traces.append(d)
            return traces

    # -------------------------------------------------------------------------
    # Investigation Observations / Evidence (Phase 12.X)
    # -------------------------------------------------------------------------

    def insert_investigation_observation(self, obs: Dict[str, Any]) -> None:
        """Insert or replace an investigation-scoped target observation."""
        req_headers_json = (
            json.dumps(obs.get("request_headers", {}))
            if isinstance(obs.get("request_headers"), dict)
            else obs.get("request_headers")
        )
        resp_headers_json = (
            json.dumps(obs.get("response_headers", {}))
            if isinstance(obs.get("response_headers"), dict)
            else obs.get("response_headers")
        )
        created_at = obs.get("created_at") or datetime.now(timezone.utc).isoformat()

        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO investigation_observations (
                    id, investigation_id, fact_id, asset_id, http_method, host,
                    raw_path, normalized_path, response_status, request_headers,
                    request_body, response_headers, response_body, statement,
                    source_type, source_artifact, researcher_note, transaction_digest,
                    redacted_secret_count, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    obs["id"],
                    obs["investigation_id"],
                    obs["fact_id"],
                    obs["asset_id"],
                    obs["http_method"],
                    obs["host"],
                    obs["raw_path"],
                    obs["normalized_path"],
                    obs["response_status"],
                    req_headers_json,
                    obs.get("request_body", ""),
                    resp_headers_json,
                    obs.get("response_body", ""),
                    obs["statement"],
                    obs.get("source_type", "manual"),
                    obs.get("source_artifact"),
                    obs.get("researcher_note"),
                    obs["transaction_digest"],
                    obs.get("redacted_secret_count", 0),
                    created_at,
                ),
            )
            # Update investigation timestamp
            conn.execute(
                """
                UPDATE investigations
                SET updated_at = CURRENT_TIMESTAMP
                WHERE investigation_id = ?
                """,
                (obs["investigation_id"],),
            )
            conn.commit()

    def get_investigation_observations(
        self, investigation_id: str, limit: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """Retrieve target observations for an investigation, ordered chronologically."""
        with self.get_connection() as conn:
            query = "SELECT * FROM investigation_observations WHERE investigation_id = ? ORDER BY created_at ASC"
            params: List[Any] = [investigation_id]
            if limit:
                query += " LIMIT ?"
                params.append(limit)
            cursor = conn.execute(query, tuple(params))
            results = []
            for row in cursor.fetchall():
                d = dict(row)
                d["method"] = d.get("http_method")
                d["status_code"] = d.get("response_status")
                if d.get("request_headers"):
                    try:
                        d["request_headers"] = json.loads(d["request_headers"])
                    except Exception:
                        pass
                if d.get("response_headers"):
                    try:
                        d["response_headers"] = json.loads(d["response_headers"])
                    except Exception:
                        pass
                results.append(d)
            return results

    def get_investigation_observation(self, observation_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a specific target observation by its ID."""
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM investigation_observations WHERE id = ?", (observation_id,)
            ).fetchone()
            if not row:
                return None
            d = dict(row)
            d["method"] = d.get("http_method")
            d["status_code"] = d.get("response_status")
            if d.get("request_headers"):
                try:
                    d["request_headers"] = json.loads(d["request_headers"])
                except Exception:
                    pass
            if d.get("response_headers"):
                try:
                    d["response_headers"] = json.loads(d["response_headers"])
                except Exception:
                    pass
            return d

    def has_observation_digest(self, investigation_id: str, transaction_digest: str) -> bool:
        """Check if an observation with the given transaction digest already exists in this investigation."""
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT 1 FROM investigation_observations WHERE investigation_id = ? AND transaction_digest = ?",
                (investigation_id, transaction_digest),
            ).fetchone()
            return row is not None

    def get_observation_count(self, investigation_id: str) -> int:
        """Get the count of observations for an investigation."""
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) as cnt FROM investigation_observations WHERE investigation_id = ?",
                (investigation_id,),
            ).fetchone()
            return row["cnt"] if row else 0

    def get_foreign_observation_ids(self, active_investigation_id: str) -> set:
        """Get observation IDs belonging to all other investigations to prevent cross-assessment leakage."""
        with self.get_connection() as conn:
            rows = conn.execute(
                "SELECT id FROM investigation_observations WHERE investigation_id != ?",
                (active_investigation_id,),
            ).fetchall()
            return {r["id"] for r in rows}

    def verify_observation_integrity(self, observation_id: str) -> bool:
        """Verifies canonical content digest of a stored observation to detect tampering."""
        obs = self.get_investigation_observation(observation_id)
        if not obs:
            return False
        stored_digest = obs.get("transaction_digest")
        if not stored_digest:
            return False
        from src.evidence.ingestion.pipeline import compute_canonical_transaction_digest
        computed = compute_canonical_transaction_digest(
            method=obs.get("http_method") or obs.get("method", ""),
            host=obs.get("host", ""),
            path=obs.get("raw_path") or obs.get("path", "/"),
            response_status=int(obs.get("response_status") or obs.get("status_code", 0)),
            request_body=obs.get("request_body") or "",
            response_body=obs.get("response_body") or "",
            request_headers=obs.get("request_headers"),
            response_headers=obs.get("response_headers"),
        )
        return computed == stored_digest

    # -------------------------------------------------------------------------
    # Dashboard User Management (Batch 1.1)
    # -------------------------------------------------------------------------

    def create_user(
        self,
        username: str,
        password_hash: str,
        role: str = "reviewer",
        is_active: bool = True,
    ) -> Dict[str, Any]:
        """Create a new local dashboard user with pre-hashed credentials."""
        clean_user = username.strip().lower()
        clean_role = role.strip().lower()
        if clean_role not in ("observer", "reviewer", "admin"):
            clean_role = "reviewer"
        user_id = f"USR-{hashlib.sha256(clean_user.encode()).hexdigest()[:12].upper()}"
        now_iso = datetime.now(timezone.utc).isoformat()

        with self.get_connection() as conn:
            self._ensure_user_table(conn)
            conn.execute(
                """
                INSERT INTO dashboard_users (user_id, username, password_hash, role, is_active, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (user_id, clean_user, password_hash, clean_role, 1 if is_active else 0, now_iso, now_iso),
            )
            conn.commit()

        return {
            "user_id": user_id,
            "username": clean_user,
            "role": clean_role,
            "is_active": is_active,
            "created_at": now_iso,
        }

    def _ensure_user_table(self, conn: sqlite3.Connection) -> None:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS dashboard_users (
                user_id             TEXT PRIMARY KEY,
                username            TEXT UNIQUE NOT NULL,
                password_hash       TEXT NOT NULL,
                role                TEXT NOT NULL CHECK(role IN ('observer', 'reviewer', 'admin')),
                is_active           INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0, 1)),
                created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_dashboard_users_username ON dashboard_users(username)")

    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        """Retrieve user record by username."""
        clean_user = username.strip().lower()
        with self.get_connection() as conn:
            self._ensure_user_table(conn)
            row = conn.execute(
                "SELECT * FROM dashboard_users WHERE username = ?",
                (clean_user,),
            ).fetchone()
            if not row:
                return None
            d = dict(row)
            d["is_active"] = bool(d["is_active"])
            return d

    def list_users(self) -> List[Dict[str, Any]]:
        """List all users without exposing password hashes."""
        with self.get_connection() as conn:
            rows = conn.execute(
                "SELECT user_id, username, role, is_active, created_at, updated_at FROM dashboard_users ORDER BY username"
            ).fetchall()
            return [
                {
                    "user_id": r["user_id"],
                    "username": r["username"],
                    "role": r["role"],
                    "is_active": bool(r["is_active"]),
                    "created_at": r["created_at"],
                    "updated_at": r["updated_at"],
                }
                for r in rows
            ]

    def update_user_password(self, username: str, password_hash: str) -> bool:
        """Update password hash for a user."""
        clean_user = username.strip().lower()
        now_iso = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            cur = conn.execute(
                "UPDATE dashboard_users SET password_hash = ?, updated_at = ? WHERE username = ?",
                (password_hash, now_iso, clean_user),
            )
            conn.commit()
            return cur.rowcount > 0

    def update_user_role(self, username: str, role: str) -> bool:
        """Update authoritative role for a user."""
        clean_user = username.strip().lower()
        clean_role = role.strip().lower()
        if clean_role not in ("observer", "reviewer", "admin"):
            raise ValueError(f"Invalid role: {role}")
        now_iso = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            cur = conn.execute(
                "UPDATE dashboard_users SET role = ?, updated_at = ? WHERE username = ?",
                (clean_role, now_iso, clean_user),
            )
            conn.commit()
            return cur.rowcount > 0

    def set_user_active(self, username: str, is_active: bool) -> bool:
        """Enable or disable a user account."""
        clean_user = username.strip().lower()
        now_iso = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            cur = conn.execute(
                "UPDATE dashboard_users SET is_active = ?, updated_at = ? WHERE username = ?",
                (1 if is_active else 0, now_iso, clean_user),
            )
            conn.commit()
            return cur.rowcount > 0

    def user_count(self) -> int:
        """Get total number of provisioned users."""
        with self.get_connection() as conn:
            self._ensure_user_table(conn)
            row = conn.execute("SELECT COUNT(*) as cnt FROM dashboard_users").fetchone()
            return row["cnt"] if row else 0


