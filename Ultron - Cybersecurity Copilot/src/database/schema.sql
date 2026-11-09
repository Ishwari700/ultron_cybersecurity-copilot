-- Unified Evidence Database Schema (evidence.db) for v6 Final
PRAGMA foreign_keys = ON;

-- 1. Scope Decisions
CREATE TABLE IF NOT EXISTS scope_decisions (
    scope_decision_id   TEXT PRIMARY KEY,
    decision            TEXT CHECK(decision IN ('ALLOW', 'DENY')) NOT NULL,
    requested_url       TEXT NOT NULL,
    canonical_host      TEXT NOT NULL,
    resolved_addresses  TEXT NOT NULL, -- JSON array of IP strings
    matched_rule        TEXT,
    out_of_scope_rule   TEXT,
    tool_policy         TEXT NOT NULL,
    reason              TEXT,
    timestamp           TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    scope_policy_version TEXT NOT NULL
);

-- 2. Assets (Endpoints)
CREATE TABLE IF NOT EXISTS assets (
    asset_id                TEXT PRIMARY KEY, -- sha256(METHOD + host + normalized_path)
    method                  TEXT CHECK(method IN ('GET','POST','PUT','DELETE','PATCH','OPTIONS','HEAD')) NOT NULL,
    host                    TEXT NOT NULL,
    raw_path                TEXT NOT NULL,
    normalized_path         TEXT NOT NULL,
    normalization_confidence REAL DEFAULT 1.0,
    http_semantics          TEXT CHECK(http_semantics IN ('GET','POST','PUT','DELETE','PATCH','OPTIONS','HEAD')),
    application_mutability  TEXT CHECK(application_mutability IN ('UNKNOWN','READ_ONLY','STATE_CHANGING','DESTRUCTIVE')) DEFAULT 'UNKNOWN',
    liveness                TEXT CHECK(liveness IN ('LIVE_DOCUMENTED','SHADOW_ACTIVE','ZOMBIE_STALE')) DEFAULT 'SHADOW_ACTIVE',
    discovered_at           TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_checked_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    scope_decision_id       TEXT REFERENCES scope_decisions(scope_decision_id)
);

-- 3. Asset State History (Append-only)
CREATE TABLE IF NOT EXISTS asset_state_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id    TEXT NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    field       TEXT NOT NULL CHECK(field IN ('liveness', 'application_mutability')),
    old_value   TEXT,
    new_value   TEXT NOT NULL,
    changed_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 4. Parameters
CREATE TABLE IF NOT EXISTS parameters (
    param_id            TEXT PRIMARY KEY, -- sha256(asset_id + param_name + location)
    asset_id            TEXT NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    param_name          TEXT NOT NULL,
    location            TEXT CHECK(location IN ('query','path','body','header','cookie')) NOT NULL,
    content_type        TEXT,
    param_type          TEXT,
    is_server_volatile  INTEGER DEFAULT 0 CHECK(is_server_volatile IN (0,1)),
    UNIQUE(asset_id, param_name, location)
);

-- 5. Identities (Multi-tenant context for authorization reasoning)
CREATE TABLE IF NOT EXISTS identities (
    identity_id     TEXT PRIMARY KEY, -- e.g. 'user_a', 'user_b_victim', 'admin'
    role            TEXT,
    session_ref     TEXT,             -- Pointer/key reference, NEVER plaintext credentials
    notes           TEXT
);

-- 6. Canonical Evidence Items (Observed & Documented Facts with Provenance)
CREATE TABLE IF NOT EXISTS evidence_items (
    fact_id             TEXT PRIMARY KEY,
    certainty           TEXT CHECK(certainty IN ('OBSERVED','DOCUMENTED','DETERMINISTIC_DERIVATION')) NOT NULL,
    statement           TEXT NOT NULL,
    source_tool         TEXT NOT NULL,
    source_version      TEXT,
    trust               TEXT CHECK(trust IN ('TRUSTED','UNTRUSTED')) DEFAULT 'UNTRUSTED',
    raw_evidence_ref    TEXT,
    scope_decision_id   TEXT REFERENCES scope_decisions(scope_decision_id),
    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 7. Derivations (Audit lineage for deterministic derivations)
CREATE TABLE IF NOT EXISTS derivations (
    derivation_id       TEXT PRIMARY KEY,
    derived_fact_id     TEXT NOT NULL REFERENCES evidence_items(fact_id),
    parent_fact_ids     TEXT NOT NULL, -- JSON array of parent fact IDs
    derivation_rule     TEXT NOT NULL,
    algorithm_version   TEXT NOT NULL,
    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 8. Security Invariants (Epistemic Origin Segregation)
CREATE TABLE IF NOT EXISTS security_invariants (
    invariant_id    TEXT PRIMARY KEY,
    description     TEXT NOT NULL,
    origin          TEXT CHECK(origin IN ('DOCUMENTED', 'OBSERVED', 'DETERMINISTIC_DERIVATION', 'MODEL_PROPOSED')) NOT NULL,
    derived_from    TEXT, -- JSON array of fact_ids or asset_ids
    confidence      TEXT CHECK(confidence IN ('LOW', 'MEDIUM', 'HIGH')),
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 9. Hypotheses
CREATE TABLE IF NOT EXISTS hypotheses (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id              TEXT NOT NULL REFERENCES assets(asset_id),
    category              TEXT NOT NULL,
    decision              TEXT CHECK(decision IN ('NO_RELEVANT_FUNCTIONALITY','INSUFFICIENT_EVIDENCE','HYPOTHESIS')) NOT NULL,
    evidence_state        TEXT CHECK(evidence_state IN ('NONE','WEAK','PARTIAL','STRONG')) NOT NULL,
    actor_identity_id     TEXT REFERENCES identities(identity_id),
    target_identity_id    TEXT REFERENCES identities(identity_id),
    reasoning_summary     TEXT,
    missing_evidence      TEXT, -- JSON array
    experiment_proposal   TEXT, -- JSON or structured string
    state                 TEXT CHECK(state IN ('New','Under Review','Confirmed','Rejected','Reported')) DEFAULT 'New',
    evidence_ref          TEXT,
    revision              INTEGER DEFAULT 1,
    created_at            TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at            TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 10. Verifications (Human Ground Truth Record)
CREATE TABLE IF NOT EXISTS verifications (
    verification_id       TEXT PRIMARY KEY,
    hypothesis_id         INTEGER NOT NULL REFERENCES hypotheses(id),
    actor                 TEXT NOT NULL,
    decision              TEXT CHECK(decision IN ('confirmed','rejected')) NOT NULL,
    evidence_ref          TEXT NOT NULL,
    dashboard_session_id  TEXT NOT NULL,
    notes                 TEXT,
    created_at            TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_assets_liveness ON assets(liveness);
CREATE INDEX IF NOT EXISTS idx_assets_host ON assets(host);
CREATE INDEX IF NOT EXISTS idx_parameters_asset ON parameters(asset_id);
CREATE INDEX IF NOT EXISTS idx_hypotheses_asset ON hypotheses(asset_id);
CREATE INDEX IF NOT EXISTS idx_hypotheses_state ON hypotheses(state);
CREATE INDEX IF NOT EXISTS idx_invariants_origin ON security_invariants(origin);
CREATE INDEX IF NOT EXISTS idx_verifications_hypothesis ON verifications(hypothesis_id);

-- Hard Invariant Triggers

-- Trigger 1: Cannot move to 'Confirmed' without an attached evidence_ref (length >= 5)
CREATE TRIGGER IF NOT EXISTS trg_enforce_evidence_before_confirm
BEFORE UPDATE OF state ON hypotheses
FOR EACH ROW
WHEN NEW.state = 'Confirmed' AND (NEW.evidence_ref IS NULL OR length(trim(NEW.evidence_ref)) < 5)
BEGIN
    SELECT RAISE(ABORT, 'Cannot move hypothesis to Confirmed without an attached evidence_ref.');
END;

-- Trigger 2: Cannot move to 'Confirmed' without an existing matching confirmed row in verifications
CREATE TRIGGER IF NOT EXISTS trg_enforce_verification_record_before_confirm
BEFORE UPDATE OF state ON hypotheses
FOR EACH ROW
WHEN NEW.state = 'Confirmed' AND NOT EXISTS (
    SELECT 1 FROM verifications
    WHERE hypothesis_id = NEW.id AND decision = 'confirmed'
)
BEGIN
    SELECT RAISE(ABORT, 'Cannot move hypothesis to Confirmed without a matching confirmed verifications record.');
END;

-- Trigger 3: Cannot move to 'Reported' unless previously 'Confirmed' with a verified record
CREATE TRIGGER IF NOT EXISTS trg_enforce_confirmed_before_report
BEFORE UPDATE OF state ON hypotheses
FOR EACH ROW
WHEN NEW.state = 'Reported' AND OLD.state NOT IN ('Confirmed', 'Reported')
BEGIN
    SELECT RAISE(ABORT, 'Cannot move hypothesis to Reported without first being in Confirmed state.');
END;

-- Trigger 4: Cannot move to 'Confirmed' unless previously 'Under Review'
CREATE TRIGGER IF NOT EXISTS trg_enforce_under_review_before_confirm
BEFORE UPDATE OF state ON hypotheses
FOR EACH ROW
WHEN NEW.state = 'Confirmed' AND OLD.state NOT IN ('Under Review', 'Confirmed')
BEGIN
    SELECT RAISE(ABORT, 'Cannot move hypothesis to Confirmed without first being in Under Review state.');
END;

-- Trigger 5: Cannot move to 'Under Review' unless previously in 'New'
CREATE TRIGGER IF NOT EXISTS trg_enforce_new_before_under_review
BEFORE UPDATE OF state ON hypotheses
FOR EACH ROW
WHEN NEW.state = 'Under Review' AND OLD.state NOT IN ('New', 'Under Review')
BEGIN
    SELECT RAISE(ABORT, 'Cannot move hypothesis to Under Review without first being in New state.');
END;

-- Trigger 6: Cannot transition away from terminal Reported state
CREATE TRIGGER IF NOT EXISTS trg_enforce_terminal_reported
BEFORE UPDATE OF state ON hypotheses
FOR EACH ROW
WHEN OLD.state = 'Reported' AND NEW.state != 'Reported'
BEGIN
    SELECT RAISE(ABORT, 'Cannot transition away from terminal Reported state.');
END;

-- Trigger 7: Cannot transition away from terminal Rejected state
CREATE TRIGGER IF NOT EXISTS trg_enforce_terminal_rejected
BEFORE UPDATE OF state ON hypotheses
FOR EACH ROW
WHEN OLD.state = 'Rejected' AND NEW.state != 'Rejected'
BEGIN
    SELECT RAISE(ABORT, 'Cannot transition away from terminal Rejected state.');
END;

-- Trigger 8: Cannot reject hypothesis that has already been Confirmed
CREATE TRIGGER IF NOT EXISTS trg_enforce_confirmed_not_rejected
BEFORE UPDATE OF state ON hypotheses
FOR EACH ROW
WHEN NEW.state = 'Rejected' AND OLD.state = 'Confirmed'
BEGIN
    SELECT RAISE(ABORT, 'Cannot reject hypothesis that has already been Confirmed.');
END;

-- 11. Investigations (Persistent Research Sessions / Conversations - Phase 12.3)
CREATE TABLE IF NOT EXISTS investigations (
    investigation_id    TEXT PRIMARY KEY,
    name                TEXT NOT NULL,
    target_host         TEXT NOT NULL,
    scope_status        TEXT CHECK(scope_status IN ('ALLOWED', 'ALLOW', 'DENY', 'OUT_OF_SCOPE', 'UNKNOWN')) DEFAULT 'ALLOWED',
    status              TEXT CHECK(status IN ('ACTIVE', 'ARCHIVED')) DEFAULT 'ACTIVE',
    is_demo             INTEGER DEFAULT 0 CHECK(is_demo IN (0, 1)),
    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 12. Conversation Messages (Persistent Conversation History & Epistemic Turns - Phase 12.3)
CREATE TABLE IF NOT EXISTS conversation_messages (
    id                  TEXT PRIMARY KEY,
    investigation_id    TEXT NOT NULL REFERENCES investigations(investigation_id) ON DELETE CASCADE,
    sequence_number     INTEGER NOT NULL,
    sender              TEXT CHECK(sender IN ('user', 'assistant', 'system')) NOT NULL,
    content             TEXT NOT NULL,
    structured_type     TEXT CHECK(structured_type IN ('INVARIANT', 'HYPOTHESIS', 'EXPERIMENT', 'APPROVAL', 'EXECUTION', 'OBSERVATION', 'AUDIT', 'NONE')) DEFAULT 'NONE',
    structured_data     TEXT,
    delivery_status     TEXT CHECK(delivery_status IN ('sending', 'delivered', 'failed')) DEFAULT 'delivered',
    cascade_trace_id    TEXT,
    model_name          TEXT,
    model_digest        TEXT,
    response_id         TEXT,
    status              TEXT DEFAULT 'COMPLETED',
    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(investigation_id, sequence_number)
);

CREATE INDEX IF NOT EXISTS idx_conv_messages_inv ON conversation_messages(investigation_id, sequence_number);
CREATE INDEX IF NOT EXISTS idx_investigations_status ON investigations(status);

-- 13. Cascade Execution Traces (Runtime Observability - Phase 12.4)
CREATE TABLE IF NOT EXISTS cascade_execution_traces (
    run_id                  TEXT PRIMARY KEY,
    investigation_id        TEXT REFERENCES investigations(investigation_id) ON DELETE CASCADE,
    user_message_id         TEXT,
    assistant_message_id    TEXT,
    task_type               TEXT NOT NULL,
    target_endpoint         TEXT,
    overall_status          TEXT NOT NULL,
    routing_decision        TEXT,
    escalated               INTEGER DEFAULT 0 CHECK(escalated IN (0, 1)),
    handoff_provenance_hash TEXT,
    total_latency_seconds   REAL DEFAULT 0.0,
    stages_json             TEXT NOT NULL,
    error_message           TEXT,
    created_at              TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_cascade_traces_inv ON cascade_execution_traces(investigation_id);

-- 14. Investigation Observations (Target HTTP Evidence - Phase 12.X)
CREATE TABLE IF NOT EXISTS investigation_observations (
    id                      TEXT PRIMARY KEY,
    investigation_id        TEXT NOT NULL REFERENCES investigations(investigation_id) ON DELETE CASCADE,
    fact_id                 TEXT NOT NULL,
    asset_id                TEXT NOT NULL,
    http_method             TEXT NOT NULL,
    host                    TEXT NOT NULL,
    raw_path                TEXT NOT NULL,
    normalized_path         TEXT NOT NULL,
    response_status         INTEGER NOT NULL,
    request_headers         TEXT, -- JSON
    request_body            TEXT,
    response_headers        TEXT, -- JSON
    response_body           TEXT,
    statement               TEXT NOT NULL,
    source_type             TEXT NOT NULL, -- 'har', 'raw_http', 'manual', 'burp'
    source_artifact         TEXT,
    researcher_note         TEXT,
    transaction_digest      TEXT NOT NULL,
    redacted_secret_count   INTEGER DEFAULT 0,
    created_at              TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(investigation_id, transaction_digest)
);

CREATE INDEX IF NOT EXISTS idx_obs_inv ON investigation_observations(investigation_id);
CREATE INDEX IF NOT EXISTS idx_obs_asset ON investigation_observations(asset_id);

-- 15. Dashboard Users & Authentication (Batch 1.1)
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



