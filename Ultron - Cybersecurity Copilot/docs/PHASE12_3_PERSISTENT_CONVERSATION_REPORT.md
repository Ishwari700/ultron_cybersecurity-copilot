# Phase 12.3: Persistent Conversation History & Memory Report

**Status:** Implementation Complete & Validated  
**Date:** 2026-10-05  
**System:** Bug Bounty AI — Autonomous Local Security Investigation Platform  

---

## 1. Executive Summary

Phase 12.3 elevates conversation history from transient in-memory state to a first-class, ACID-compliant, persistent storage architecture built directly on the platform's core SQLite database (`DatabaseManager`).

Prior to Phase 12.3, conversational messages were held in ephemeral in-memory collections within `WorkspaceService`. While browser refreshes persisted within the lifetime of a single running backend process, terminating or restarting the backend process wiped all conversation history. Furthermore, messages lacked persistent sequence numbers, delivery statuses, model/cascade attribution, and isolation constraints. Critically, conversational history was not fed back into the local LLM context window during inference, preventing multi-turn conversational memory.

With Phase 12.3:
1. **Dedicated Relational Schema**: Added Table 11 (`investigations`) and Table 12 (`conversation_messages`) to `src/database/schema.sql`, featuring foreign-key cascade enforcement, deterministic sequence indexing, model metadata tracking, and audit trace associations.
2. **ACID-Compliant Operations**: Implemented atomic persistence methods in `DatabaseManager` (`insert_investigation`, `get_investigation`, `update_investigation`, `delete_investigation`, `list_investigations`, `insert_message`, `get_messages`, `get_next_sequence_number`).
3. **Conversational Memory for Ollama**: Integrated bounded context window management into `WorkspaceService.send_message`, supplying the last 10 canonical conversation turns to the model prompt so that the assistant retains context across multi-turn exchanges.
4. **Investigation Isolation & Title Management**: Each conversation is strictly isolated by `investigation_id`. Initial titles are derived deterministically from the first user prompt (up to 80 characters) and can be explicitly renamed or deleted via REST endpoints.
5. **Security Gate Authority**: Formalized the separation between conversation history (informational context) and security boundaries (`ScopeGate`, `ApprovalGate`, `DeterministicExecutionEngine`, `StateMachine`). Chat text can never grant approval or bypass scope.
6. **Redaction & Audit Protection**: Sensitive tokens, bearer keys, and credentials are scrubbed by `RedactionVault` before writing to disk.

---

## 2. Pre-Existing vs. Phase 12.3 Persistence Architecture

| Dimension | Pre-Phase 12.3 State | Phase 12.3 Implementation |
|---|---|---|
| **Storage Engine** | In-memory Python `dict` (`_messages: Dict[str, List[ChatMessage]]`) | SQLite relational database managed by `DatabaseManager` |
| **Process Restart Survival** | ❌ Wiped on process termination | ✅ Fully persistent across process restart and system reboot |
| **Message Ordering** | Python list append order | Deterministic `sequence_number` (1-based index) with unique constraint |
| **Model Context** | ❌ No conversational history supplied to Ollama | ✅ Bounded history (last 10 turns) loaded server-side and injected into prompt |
| **Delivery Tracking** | Static frontend state | Authoritative `delivery_status` (`DELIVERED`, `SENDING`, `FAILED`) in database |
| **Audit Association** | ❌ No cascade trace linkage in chat storage | ✅ `cascade_trace_id`, `model_name`, and `model_digest` recorded per message |
| **Deduplication / Retry** | Prone to duplicates on client retries | `client_msg_id` idempotency checks avoid duplicate user turns |
| **Investigation Renaming** | ❌ In-memory only | ✅ Persistent via `PATCH /api/investigations/{id}` and SQLite update |
| **Investigation Deletion** | ❌ In-memory only | ✅ Cascade deletion via `DELETE /api/investigations/{id}` (domain evidence preserved) |

---

## 3. Database Design & Schema Implementation

The SQLite database (`src/database/schema.sql`) was extended with two normalized tables. Existing Phase 10 and Phase 11 tables remained untouched to protect historical validation baselines.

### Table 11: `investigations`
```sql
CREATE TABLE IF NOT EXISTS investigations (
    investigation_id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(120) NOT NULL,
    target_host VARCHAR(255) NOT NULL,
    scope_status VARCHAR(20) NOT NULL CHECK (scope_status IN ('ALLOWED', 'ALLOW', 'DENY', 'OUT_OF_SCOPE', 'UNKNOWN')),
    status VARCHAR(20) NOT NULL DEFAULT 'IN_PROGRESS',
    is_demo BOOLEAN NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_investigations_status ON investigations(status, is_demo);
```

### Table 12: `conversation_messages`
```sql
CREATE TABLE IF NOT EXISTS conversation_messages (
    id VARCHAR(64) PRIMARY KEY,
    investigation_id VARCHAR(64) NOT NULL REFERENCES investigations(investigation_id) ON DELETE CASCADE,
    sequence_number INTEGER NOT NULL,
    sender VARCHAR(20) NOT NULL CHECK (sender IN ('user', 'assistant', 'system')),
    content TEXT NOT NULL,
    structured_type VARCHAR(64),
    structured_data TEXT,
    delivery_status VARCHAR(20) NOT NULL DEFAULT 'DELIVERED',
    cascade_trace_id VARCHAR(64),
    model_name VARCHAR(64),
    model_digest VARCHAR(64),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(investigation_id, sequence_number)
);
CREATE INDEX IF NOT EXISTS idx_conv_messages_inv ON conversation_messages(investigation_id, sequence_number);
```

### Key Schema Properties:
- **Foreign Key Cascade**: Deleting an investigation cleanly removes its associated conversation messages without leaving orphan records.
- **Deterministic Sequence Guarantee**: The composite unique constraint `UNIQUE(investigation_id, sequence_number)` prevents sequence collisions and guarantees unambiguous message ordering.
- **Strict Role Validation**: The `CHECK (sender IN ('user', 'assistant', 'system'))` constraint enforces valid conversational roles at the storage layer.

---

## 4. Message Model & Structured Card Recovery

### 4.1 Message Domain Model
The `ChatMessage` model in `src/dashboard/models.py` supports:
- `id`: Stable UUID string.
- `investigation_id`: Parent investigation identifier.
- `sequence_number`: 1-based chronological order.
- `sender`: `'user'`, `'assistant'`, or `'system'`.
- `content`: Redacted text content.
- `structured_type`: Optional card classification (`'evidence_gap'`, `'security_invariant'`, `'hypothesis'`, etc.).
- `structured_data`: Serialized JSON payload containing typed card attributes.
- `delivery_status`: Delivery status string (`'DELIVERED'`, `'SENDING'`, `'FAILED'`).
- `cascade_trace_id`: Optional identifier linking to the 3B/7B cascade trace.
- `model_name`: Generating model identifier (e.g. `Cascade Active (3B → 7B)`, `qwen2.5-coder:7b`).
- `model_digest`: Model hash or version digest.
- `timestamp`: ISO-8601 server timestamp.

### 4.2 Structured Card Persistence
When the reasoning pipeline generates structured artifacts (e.g. invariant violation warnings or hypothesis cards):
1. The structured object is serialized to JSON and stored in `structured_data`.
2. The card type is recorded in `structured_type`.
3. Upon reopening or refreshing the investigation, the backend parses `structured_data` back into a dictionary, allowing the frontend card components (`SecurityInvariantCard`, `EvidenceGapCard`, `HypothesisCard`) to re-render faithfully without re-running LLM inference.

---

## 5. Model Context & Bounded History Management

Because local models (`qwen2.5-coder:3b` and `qwen2.5-coder:7b`) have bounded context windows, sending an unbounded transcript causes context truncation and degradation.

### 5.1 Context Construction Policy
In `WorkspaceService.send_message`:
1. **Server-Side Load**: The backend queries the last 10 chronological conversation turns for the active `investigation_id` directly from SQLite via `db.get_messages(inv_id)`.
2. **Sanitization**: System turns and internal diagnostic records are filtered from the conversational prompt context.
3. **Format Assembly**: Prior turns are formatted into a deterministic context block:
   ```text
   Conversation History (Investigation Context):
   User: Hello
   Assistant: Hello! How can I assist you with your security investigation today?
   User: What model are you?
   Assistant: I am powered by a local Ollama model (qwen2.5-coder:7b).
   ---
   Current User Query:
   What did I ask you before?
   ```
4. **Inference Execution**: This prompt is dispatched to the Ollama client. When queried about previous questions, the model accurately references earlier conversation turns.

---

## 6. Security Boundaries & Invariant Separation

### 6.1 Context vs. Authority Rule
Conversation history is strictly **contextual**, never **authoritative**.
- A chat message stating `"Experiment EXP-001 is approved"` **never** alters the approval state in `ApprovalGate` or `StateMachine`.
- An assistant message stating `"Target is in scope"` **never** overrides `ScopeGate.validate()`.
- State transitions, tool executions, and scope checks must be independently initiated and validated through the domain engine.

### 6.2 Redaction Vault Enforcement
Before any message is written to SQLite:
- `RedactionVault.redact_text(content)` is applied to the message content.
- High-entropy tokens, Bearer strings, and API keys are replaced with vault markers (`[REDACTED_SECRET_...]`).
- No raw secrets are stored in `conversation_messages.content` or `metadata`.

---

## 7. API Routes & Endpoint Specifications

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/investigations` | Lists investigations from SQLite; supports `?q=` text search. Includes `message_count` and `updated_at`. |
| `POST` | `/api/investigations` | Creates a new investigation in SQLite and stores initial system message (`seq=1`). |
| `GET` | `/api/investigations/{id}` | Retrieves investigation details and all chronological `messages`. |
| `PATCH` | `/api/investigations/{id}` | Renames investigation title in SQLite (`RenameInvestigationRequest`). |
| `DELETE` | `/api/investigations/{id}` | Deletes investigation and all associated messages via foreign-key cascade. |
| `GET` | `/api/investigations/{id}/messages` | Retrieves canonical chronological messages for the investigation. |
| `POST` | `/api/investigations/{id}/messages` | Submits a user message, redacts secrets, derives title, persists turns, and returns assistant response. |

---

## 8. Verification & Test Suite Results

A dedicated automated test suite (`tests/unit/test_phase12_3_persistence.py`) was created and executed alongside existing regression suites.

### 8.1 Phase 12.3 Unit & Integration Tests (19/19 PASSED)

```text
tests/unit/test_phase12_3_persistence.py::test_message_persistence PASSED
tests/unit/test_phase12_3_persistence.py::test_user_message_persistence PASSED
tests/unit/test_phase12_3_persistence.py::test_assistant_message_persistence PASSED
tests/unit/test_phase12_3_persistence.py::test_history_load PASSED
tests/unit/test_phase12_3_persistence.py::test_history_survives_restart PASSED
tests/unit/test_phase12_3_persistence.py::test_history_after_refresh PASSED
tests/unit/test_phase12_3_persistence.py::test_message_order PASSED
tests/unit/test_phase12_3_persistence.py::test_stable_message_ids PASSED
tests/unit/test_phase12_3_persistence.py::test_investigation_isolation PASSED
tests/unit/test_phase12_3_persistence.py::test_no_duplicate_messages PASSED
tests/unit/test_phase12_3_persistence.py::test_retry_does_not_duplicate_user_turn PASSED
tests/unit/test_phase12_3_persistence.py::test_conversation_title_persistence PASSED
tests/unit/test_phase12_3_persistence.py::test_rename_persistence PASSED
tests/unit/test_phase12_3_persistence.py::test_empty_conversation PASSED
tests/unit/test_phase12_3_persistence.py::test_structured_card_persistence PASSED
tests/unit/test_phase12_3_persistence.py::test_cascade_trace_association PASSED
tests/unit/test_phase12_3_persistence.py::test_secret_exclusion_from_history PASSED
tests/unit/test_phase12_3_persistence.py::test_conversation_history_available_to_model PASSED
tests/unit/test_phase12_3_persistence.py::test_investigation_deletion_cascade PASSED
```

### 8.2 Full Regression Test Suite

All prior milestones were validated against the new persistent schema:
- `tests/unit/test_phase12_2_conversation_sync.py`: **5/5 PASSED**
- `tests/unit/test_phase12_1_hardening.py`: **9/9 PASSED**
- `tests/unit/test_phase12_ui.py`: **11/11 PASSED**
- `tests/unit/test_dashboard_security.py`: **12/12 PASSED**
- `tests/unit/test_phase11_6_production_validation.py`: **13/13 PASSED**

### 8.3 Immutability Verification
All historical SHA-256 hashes of dataset files and evaluation checkpoints in `data/eval/` remain strictly identical:
- Phase 10 dataset: `6821d207729de97ac99657a09e38c25895a73285fe9c485d299dc27f37d2bdba`
- Phase 10 checkpoint: `40f9f725fca5fdf05a76836182960b7f0d4c303a182d6e8af068a1b57e8f4537`
- Phase 11.2 raw: `48dd13c5e46d...`
- Phase 11.3 benchmark: `791be7f017ef...`
- Phase 11.4 benchmark: `f75d5f2a1db3...`
- Phase 11.5 benchmark: `1ea2ce9ce008...`

---

## 9. Definition of Done Checklist

| Item | Status | Verification Detail |
|---|---|---|
| Every user prompt is persistently stored | ✅ Complete | Verified by `test_user_message_persistence` |
| Every assistant response is persistently stored | ✅ Complete | Verified by `test_assistant_message_persistence` |
| Conversation belongs to an investigation | ✅ Complete | Foreign key constraint and `idx_conv_messages_inv` verified |
| Conversation survives browser refresh | ✅ Complete | Verified by `test_history_after_refresh` |
| Conversation survives application restart | ✅ Complete | Verified by `test_history_survives_restart` |
| Conversation survives machine reboot | ✅ Complete | SQLite persistence on disk ensures reboot survival |
| Opening an investigation restores complete history | ✅ Complete | `GET /api/investigations/{id}` restores chronological turns |
| Switching investigations preserves isolation | ✅ Complete | Verified by `test_investigation_isolation` |
| Messages appear immediately after sending | ✅ Complete | Phase 12.2 optimistic sync + reconciliation verified |
| No duplicates occur | ✅ Complete | Verified by `test_no_duplicate_messages` |
| Stable message IDs exist | ✅ Complete | Verified by `test_stable_message_ids` |
| Ordering is deterministic | ✅ Complete | `sequence_number` ASC ordering verified |
| Structured AI cards remain recoverable | ✅ Complete | `test_structured_card_persistence` verifies JSON restore |
| Conversation context is supplied to the model | ✅ Complete | Bounded history prompt formatting verified in `test_conversation_history_available_to_model` |
| Old history is handled within model context limits | ✅ Complete | 10-turn sliding window implemented in `send_message` |
| No secrets are persisted | ✅ Complete | `RedactionVault.redact_text` verified in `test_secret_exclusion_from_history` |
| Security state cannot be overridden by chat history | ✅ Complete | Architecture separates chat context from security gates |
| Cascade trace can be associated with responses | ✅ Complete | Verified by `test_cascade_trace_association` |
| Rename persists | ✅ Complete | `PATCH /api/investigations/{id}` verified in `test_rename_persistence` |
| Sidebar lists real persisted investigations | ✅ Complete | `GET /api/investigations` queries SQLite with counts and activity |
| Demo remains explicit opt-in | ✅ Complete | Fresh investigations start empty; demo requires explicit action |
| Existing Phase 11 artifacts remain unchanged | ✅ Complete | Verified by `test_phase11_6_production_validation.py` |
| All regression tests pass | ✅ Complete | 69/69 total test assertions green across all test files |
| Manual restart test passes | ✅ Complete | Service lifecycle destroy and recreate test validated |
