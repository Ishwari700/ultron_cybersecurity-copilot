# M9 Knowledge Architecture Audit

**Milestone:** M9 — Cybersecurity Knowledge + VAPT RAG  
**Date:** October 8, 2026  
**Audited Modules:** `src/knowledge/`, `src/retrieval/`, `src/research/`, `src/engine/`, `src/copilot/`, `src/eval/`, `src/agents/`

---

## 1. Executive Summary

This audit establishes the exact inventory of existing knowledge, retrieval, research, and grounding components across the repository. In accordance with the foundational instruction **DO NOT REBUILD THE PLATFORM**, all M9 capabilities will extend and reuse these proven components with backward compatibility, maintaining the hard invariant:

$$\text{EXTERNAL\_KNOWLEDGE} \neq \text{TARGET\_EVIDENCE} \quad \text{and} \quad \text{MODEL\_HYPOTHESIS} \neq \text{HUMAN\_VERIFIED\_FINDING}$$

---

## 2. Component Inventory & Audit

### 2.1 Document & Chunk Models
- **Existing Files:** `src/knowledge/models.py`, `src/knowledge/chunker.py`, `src/research/models.py`.
- **Current State:**
  - `KnowledgeDocumentFrontmatter`: Requires document ID, title, source metadata, license, and UTF-8 normalized SHA-256 hash.
  - `KnowledgeChunk`: Deterministic chunk ID (`CHK-{DOC_ID}-{SEC_IDX:03d}-{PART:02d}`), document ID, `KnowledgeSourceType`, `KnowledgeType`, heading, content, token estimate, and chunk content SHA-256 hash.
  - `ExternalSource` & `ExternalClaim`: In `src/research/models.py`, tracks external source URLs, hashes, commit SHAs, line numbers, and trust tiers.
- **M9 Extension Needed:** Canonical M9 unified domain entities: `KnowledgeSource`, `KnowledgeDocument`, `KnowledgeVersion`, `KnowledgeSection`, `KnowledgeClaim`, `KnowledgeReference`, `KnowledgeRelation`, `KnowledgeQuery`, `KnowledgeRetrievalResult`, `KnowledgeAnswer`, `KnowledgeCitation`, `KnowledgeConflict`, `KnowledgeResearchSession`. Authority levels: `AUTHORITATIVE`, `RESEARCH`, `USER_OWNED`.

### 2.2 Embedding & Dense Retrieval
- **Existing Files:** `src/knowledge/minilm_retriever.py`, `src/knowledge/vector_index.py`, `src/retrieval/vector_store.py`.
- **Current State:**
  - Local CPU embedding using `sentence-transformers/all-MiniLM-L6-v2` (384 dimensions).
  - Memory-mapped / NumPy / FAISS-compatible vector indexing.
  - Zero GPU VRAM consumption for embeddings, reserving RTX 3050 4 GB VRAM entirely for Qwen2.5-Coder.
- **M9 Strategy:** Retain `all-MiniLM-L6-v2` on CPU. Add caching for embeddings and deterministic fallbacks.

### 2.3 Sparse & Hybrid Retrieval (FTS5 + Dense + RRF)
- **Existing Files:** `src/knowledge/store.py`, `src/retrieval/hybrid.py`.
- **Current State:**
  - SQLite FTS5 database with Porter tokenizer and BM25 ranking (`knowledge.db`).
  - Strict physical isolation: knowledge corpus SQLite database is physically separate from `evidence.db`.
  - `HybridRetriever`: Combines dense semantic vector search with sparse SQLite FTS5 BM25 search via Reciprocal Rank Fusion (RRF with $k=60$).
  - Enforces hard `exact_parameter_gate`: blocks dense false-substitutions when looking for exact technical identifiers (e.g. `X-Signature-Key`).
- **M9 Strategy:** Extend `HybridRetriever` with authority-weighted scoring, cybersecurity-aware query rewriting, and context budget management.

### 2.4 Provenance & Grounding Validation
- **Existing Files:** `src/knowledge/integrity.py`, `src/research/grounding.py`, `src/assessment/evidence_lineage.py`.
- **Current State:**
  - RFC 9162 Merkle Tree Hash and Ed25519 signature verification on corpus manifests.
  - Grounding validator validates that inferences cite valid external chunks (`CHK-xxx`) or facts (`FACT-xxx`).
  - Epistemic tier validation: `EpistemicTier.TARGET_OBSERVATION` vs `EpistemicTier.GENERAL_VAPT_KNOWLEDGE`.
- **M9 Strategy:** Introduce `CitationEngine` and `KnowledgeClaim` extraction ensuring 0 fabricated citations and full traceability: $\text{Source} \to \text{Document} \to \text{Version} \to \text{Section} \to \text{Chunk} \to \text{Claim} \to \text{Answer}$.

### 2.5 Conflict Detection
- **Existing Files:** `src/research/conflicts.py`.
- **Current State:**
  - Implements 6-class conflict taxonomy: `TRUE_CONFLICT`, `VERSION_CONFLICT`, `TEMPORAL_CHANGE`, `SCOPE_DIFFERENCE`, `TERMINOLOGY_DIFFERENCE`, `APPARENT_CONFLICT`.
  - Claim graph relationships: `SUPPORTS`, `CONTRADICTS`, `REFINES`, `SUPERSEDES`, `APPLIES_TO_VERSION`, `NOT_APPLICABLE_TO_VERSION`.
- **M9 Strategy:** Reuse `SourceConflictEngine` directly in cybersecurity research mode without silent resolution or suppression.

### 2.6 Domain Taxonomy & Intent Routing
- **Existing Files:** `src/copilot/domain.py`, `src/copilot/intent.py`, `src/copilot/registry.py`.
- **Current State:**
  - `SecurityDomain` covers 16 cybersecurity domains (Web, API, Mobile, Binary, Cloud, Network, Windows/AD, Linux, etc.).
  - `CopilotTaskType` and `CopilotMode` classify queries into advisory, reasoning, verification, etc.
- **M9 Strategy:** Add `CYBERSECURITY_KNOWLEDGE_RESEARCH_MODE` as a distinct operating mode with strict isolation from `AUTHORIZED_SECURITY_ASSESSMENT_MODE`.

### 2.7 Knowledge Sufficiency Logic
- **Existing Files:** `src/copilot/sufficiency.py`.
- **Current State:**
  - Multi-signal evaluation: `LOCAL_SUFFICIENT`, `LOCAL_INSUFFICIENT`, `EXTERNAL_RECOMMENDED`, `EXTERNAL_REQUIRED`, `KNOWLEDGE_GAP`.
  - Regex-based indicators for CVEs, RFCs, protocols, version numbers.
- **M9 Strategy:** Extend sufficiency engine to evaluate retrieval density, citation coverage, source authority, and freshness.

### 2.8 3B $\to$ 7B Cascade Orchestrator
- **Existing Files:** `src/engine/cascade_orchestrator.py`, `src/engine/model_invoker.py`.
- **Current State:**
  - Sequential inference with `max_concurrent_inferences = 1`.
  - Deterministic escalation criteria (complexity, domain coverage, code size, ambiguity).
- **M9 Strategy:** Route intent classification, domain routing, query rewriting, and simple explanations to 3B; route multi-source synthesis, conflict resolution, code security review, and deep reasoning to 7B.

---

## 3. Reuse & Extension Plan Matrix

| M9 Requirement | Existing Component | Extension Action |
|---|---|---|
| Domain Model | `src/knowledge/models.py`, `src/research/models.py` | Extend with `KnowledgeSource`, `KnowledgeDocument`, `KnowledgeVersion`, `KnowledgeClaim`, `KnowledgeCitation`, etc. |
| Ingestion & Quarantine | `src/knowledge/chunker.py`, `src/knowledge/integrity.py` | Add user document ingestion (`PDF`, `Markdown`, `TXT`), quarantine gate, deduplication, and version tracking. |
| VAPT Query Bank | N/A (New deliverable) | Create `data/knowledge/vapt_query_bank.json` (100 curated multi-domain queries). |
| Query Rewriter | `src/research/sanitization.py` | Build `CybersecurityQueryRewriter` with CVE/CWE/CAPEC normalization and acronym expansion. |
| Grounding & Citations | `src/research/grounding.py` | Implement `CitationEngine` with strict fabrication detection. |
| Code Security Review | `src/agents/specialized/code_security_analyst.py` | Create standalone knowledge-grounded code analyzer without exploitability assumptions. |
| Research Session | `src/research/` | Create `ResearchSession` state machine supporting multi-turn drill-downs and unresolved questions. |
| Invariants & Isolation | `src/assessment/` | Maintain zero leakage across assessment namespaces and absolute barrier between knowledge and target evidence. |

---

## 4. Conclusion

The existing architecture contains high-quality, mature primitives. M9 will extend these primitives seamlessly rather than rewriting them, ensuring zero regression and 100% adherence to all 18 M9 security invariants.
