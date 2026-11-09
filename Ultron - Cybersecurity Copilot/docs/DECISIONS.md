# Architectural & Design Decisions (v6 Final)

This log records all key architectural choices, evaluating alternatives and codifying chosen options against the authoritative v6 Final specification.

---

### DECISION-001: Strict Phased Hardware Scheduling for Ryzen 5 5600H & RTX 3050
- **Context:** System runs on 6 cores / 12 threads with only 4GB VRAM and 24GB system RAM. Uncontrolled concurrency causes OOM kills, paging, and CPU lockups.
- **Options Considered:**
  1. Real-time asynchronous streaming pipeline (adapters streaming directly to embedding and LLM).
  2. Strict synchronous phased batch execution (Phase 1: Recon/Ingestion [100% CPU] -> Phase 2: Indexing [100% CPU] -> Phase 3: GPU inference [100% GPU]).
- **Chosen Option:** Option 2 (Strict synchronous phased pipeline).
- **Reason:** Guarantees zero contention between heavy CPU text processing / embedding and GPU VRAM loading for Ollama.
- **Affected Components:** `src/core/scheduler.py`, `src/core/config.py`.

---

### DECISION-002: Single Unified SQLite Database (`evidence.db`)
- **Context:** v4 used separate SQLite files (`evidence.db`, `evidence_graph.db`, `findings.db`), preventing foreign key enforcement and transactional atomicity.
- **Options Considered:**
  1. Multi-database setup with application-level integrity.
  2. Single consolidated `evidence.db` with SQLite foreign keys and triggers enabled.
- **Chosen Option:** Option 2.
- **Reason:** v6 Final explicitly requires a single SQLite database to guarantee cross-table referential integrity and transactional consistency for assets, parameters, identities, invariants, hypotheses, and verifications.
- **Affected Components:** `src/database/`.

---

### DECISION-003: Epistemic Invariant Origin Taxonomy
- **Context:** An AI assumption cannot be conflated with ground truth facts without catastrophic hallucination loops.
- **Options Considered:**
  1. Confidence float score (0.0 to 1.0) on facts.
  2. Explicit discrete enum: `DOCUMENTED`, `OBSERVED`, `DETERMINISTIC_DERIVATION`, `MODEL_PROPOSED`.
- **Chosen Option:** Option 2.
- **Reason:** v6 Final mandates strict segregation of facts from model assumptions. A `MODEL_PROPOSED` invariant or delta must never overwrite or masquerade as an observed fact.
- **Affected Components:** `src/invariants/`, `src/database/schema.sql`, `src/hypothesis/`.

---

### DECISION-004: Dual-Model Allocation Strategy (3B vs 7B)
- **Context:** 4GB VRAM ceiling accommodates `qwen2.5-coder:3b` (~2.2GB) comfortably. `qwen2.5-coder:7b` requires ~4.5-5.5GB at Q4_K_M and offloads partially to CPU.
- **Options Considered:**
  1. Run 7B for all pipeline operations.
  2. Run 3B for extraction, classification, taxonomy filtering, and candidate invariant generation; run 7B only on the filtered survivor set for cross-evidence and hypothesis synthesis.
- **Chosen Option:** Option 2.
- **Reason:** Maximizes token throughput and preserves responsiveness while staying within VRAM limits.
- **Affected Components:** `src/engine/`.

---

### DECISION-005: Reversible Secret Redaction Vault
- **Context:** Raw HTTP traffic may contain live API keys, session tokens, or credentials. Scrubbing them completely destroys evidence of real leaks (e.g., SSRF dumping AWS keys), while storing them raw risks leakage in prompts and vector stores.
- **Options Considered:**
  1. Irreversible regex sanitization.
  2. Keyed local secret vault (`Hash -> Raw`) with typed placeholders (`[REDACTED_HIGH_ENTROPY_AWS_KEY_1]`).
- **Chosen Option:** Option 2.
- **Reason:** Model reasons purely over typed placeholders; human verification dashboard reverses placeholders locally when researcher examines confirmed findings.
- **Affected Components:** `src/evidence/redaction.py`.
