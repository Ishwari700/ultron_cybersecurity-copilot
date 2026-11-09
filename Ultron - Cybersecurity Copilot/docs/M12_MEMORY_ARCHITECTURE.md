# M12 Security Research Memory Architecture

## Executive Architectural Summary

The M12 Memory Subsystem provides the security research assistant with a controlled, auditable, and isolated memory of prior investigations, experiments, negative controls, and verified vulnerability patterns.

Crucially: **MEMORY IS A CONTEXT SOURCE, NOT AUTHORITY.**

Memory can never silently become:
1. Authorization or testing scope.
2. Canonical target evidence.
3. Verified finding state.
4. Permission to execute actions or modify assessments.

---

## The Four Logical Planes

```
+-------------------------------------------------------------------------------+
| PLANE 1: GLOBAL KNOWLEDGE (Owned by M9 Knowledge Subsystem)                   |
| - RFCs, CVEs, OWASP, protocols, standard offensive & defensive primitives     |
| - Read-only reference material; immutable from local user memory              |
+-------------------------------------------------------------------------------+
                                      |
                                      v
+-------------------------------------------------------------------------------+
| PLANE 2: USER RESEARCH MEMORY (Reusable across assessments via policy)        |
| - Abstracted testing workflows, negative control lessons, reusable patterns   |
| - Strictly scrubbed of target-specific secrets and raw confidential payloads  |
+-------------------------------------------------------------------------------+
                                      |
                                      v
+-------------------------------------------------------------------------------+
| PLANE 3: ASSESSMENT MEMORY (Strictly isolated per-investigation)              |
| - Working hypotheses, local observations, controlled experiments, gaps        |
| - Strict isolation enforced BEFORE ranking and candidate retrieval            |
+-------------------------------------------------------------------------------+
                                      |
                                      v
+-------------------------------------------------------------------------------+
| PLANE 4: TARGET EVIDENCE (Canonical evidence owned by M0-M11 subsystems)      |
| - Raw HTTP traffic, packet captures, DEX artifacts, audit ledger events      |
| - Authoritative source of truth; memory stores EvidencePointer references     |
+-------------------------------------------------------------------------------+
```

---

## Component Topology (`src/memory/`)

```
src/memory/
├── __init__.py           # Subsystem exports
├── models.py             # Strongly typed schemas (MemoryItem, EvidencePointer, MemoryAccessContext)
├── enums.py              # Strongly typed enumerations (Namespace, EpistemicStatus, Authority, etc.)
├── namespaces.py         # Deterministic namespace policies and read/write access gate
├── admission.py          # 12-stage deterministic admission pipeline
├── sanitizer.py          # Secret redaction and prompt-injection defanging
├── provenance.py         # Origin lineage and epistemic integrity validator
├── deduplication.py      # Exact SHA-256 and Jaccard token near-duplicate detector
├── conflicts.py          # Semantic polarity, stale-vs-new, and hypothesis-vs-observation detector
├── freshness.py          # Freshness tracking and configurable exponential time-decay scoring
├── retention.py          # Retention policies and minimal audit tombstones
├── isolation.py          # Multi-tenant and assessment isolation engine (pre-ranking filters)
├── permissions.py        # Fine-grained read, write, promote, and delete permission gate
├── promotion.py          # Multi-stage human-reviewed promotion engine (candidate -> promoted)
├── lifecycle.py          # Version snapshots and supersession chains (V1 -> V2)
├── deletion.py           # Tombstoning and forgetting actions with active index purge
├── export.py             # Redacted export and untrusted import validation
├── persistence.py        # SQLite relational persistence, schema DDL, and FTS5 index
├── retrieval.py          # Hybrid RRF retrieval engine (SQLite FTS5 BM25 + MiniLM CPU dense)
├── ranking.py            # Authority, freshness, and confidence-weighted ranker
├── adapters.py           # Episodic adapters for M11 experiments, negative controls, and findings
├── metrics.py            # Global memory observability telemetry (zero secrets logged)
└── errors.py             # Typed memory exception hierarchy
```

---

## Storage & Database Architecture

The persistence layer (`src/memory/persistence.py`) extends the local SQLite database without cloud dependencies:

1. **`memory_items`**: Primary store of active and tombstoned memory items with epistemic status, authority level, namespace, tenant, assessment, and sensitivity classification.
2. **`memory_versions`**: Historical immutable snapshots preserving complete change history.
3. **`memory_pointers`**: Relational mapping linking memory items to canonical domain artifacts (`target_evidence_id`, `evidence_digest`, `assessment_id`).
4. **`memory_conflicts`**: Recorded contradictions and disagreements between memories.
5. **`memory_promotions`**: Auditable records of human review and promotion decisions.
6. **`memory_tombstones`**: Minimal audit records of deleted memories (content is purged).
7. **`memory_embeddings`**: High-dimensional dense vector embeddings generated via local CPU MiniLM.
8. **`memory_fts`**: SQLite FTS5 full-text virtual table providing BM25 lexical ranking.

---

## Target Hardware Compliance

The architecture strictly honors the target platform constraints:
- **Processor**: AMD Ryzen 5 5600H (6 cores / 12 threads)
- **RAM**: 24 GB
- **GPU**: NVIDIA GeForce RTX 3050 Laptop GPU (4 GB VRAM)
- **Max Concurrent Inference**: 1
- **Embedding Backend**: CPU-optimized `all-MiniLM-L6-v2` via NumPy cosine similarity. Does not allocate GPU VRAM, reserving 100% of VRAM for the primary Ollama LLM cascade (Qwen 2.5 Coder 3B/7B).
