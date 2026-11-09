# STAGE C IMPLEMENTATION & SKEPTICAL AUDIT REPORT
## Local-AI Cybersecurity Knowledge Graph Extraction, Validation, and Persistence

**Platform:** Ultron — Cybersecurity Copilot  
**Milestone:** Milestone M9 Stage C / VAPT Knowledge Graph Extraction  
**Initial Implementation Date:** October 18, 2026  
**Skeptical Post-Implementation Audit Date:** October 18, 2026  
**Auditor & Verification Authority:** Ultron Core Engineering & Skeptical Verification Authority  
**Repository Working Directory:** `C:\Projects\Ultron - Cybersecurity Copilot`  
**Git HEAD:** `8a2d32611048b251fe1972025c626cf7ceb61103` (Branch: `master`)

---

## 1. Audit Verdict and Executive Qualification

### **Final Audit Verdict: `STAGE C — PASS WITH QUALIFICATIONS`**
**Descriptive Status:** `LOCAL-AI CYBERSECURITY KNOWLEDGE GRAPH EXTRACTION, DETERMINISTIC PROVENANCE VALIDATION, RELATIONAL GRAPH PERSISTENCE, OPERABLE API/UI INVOCATION, AND GENUINE LOCAL-MODEL EXECUTION VERIFIED; DATA CONTRACTS STRICTLY TYPED; REAL-WORLD SOURCE MATERIAL AND FIXTURE PROVENANCE BOUNDED TO TESTED CONSTRAINTS.`

> [!NOTE]
> All 12 Stage C acceptance gates have been independently audited and verified with zero test assertion weakenings, zero synthetic-as-live fabrications, and full preservation of existing authentication, authorization, and scope invariants.
> 
> **Explicit Qualifications:**
> 1. **Textbook Layout Scope (Carried from Stage B):** Document extraction and chunking are verified against standards-compliant PDF fixtures with physical page boundaries. Compatibility with heterogeneous printed cybersecurity textbooks (multi-column typography, margin notes, complex scan artifacts) remains bounded until authentic authorized publisher files are imported into `data/knowledge/imports/`.
> 2. **Live Smoke Test Page Provenance:** In the live Ollama smoke test (`test_live_ollama_knowledge_graph_extraction`), the chunk metadata explicitly passed `category_tags=["page:25", "format:pdf"]` and heading context to verify that the extraction and validation pipeline deterministically extracts `page_number=25` and attaches it to persisted graph records without trusting the model. The smoke test did not parse a raw multi-page PDF at runtime (which was separately proven in `test_knowledge_parsers.py`).
> 3. **Prompt Injection Boundary:** Untrusted content delimiters (`<<<UNTRUSTED_DOCUMENT_CONTENT>>>`) and system prompts are defense-in-depth mitigations. Deterministic authorization, RBAC, provenance assignment and lack of model execution privileges enforce specific security invariants independently of model output; these controls do not establish that every possible security risk has been eliminated.

---

## 2. Architecture & Operational Data Path

Stage C establishes a strictly bounded, provenance-preserving pipeline transforming already-ingested knowledge chunks into validated graph nodes and edges without permitting the LLM to govern Ultron's operational security controls or invent authoritative metadata.

```
[Ingested Source Chunk in VaptKnowledgeStore]
                         │
                         ▼
   [KnowledgeGraphExtractor.extract_from_chunk]
   ├── Untrusted Prompt Boundary Isolation (<<<UNTRUSTED_DOCUMENT_CONTENT>>>)
   ├── Bounded OllamaRunner Structured Generation (num_predict=1500)
   └── Strict Pydantic Schema Validation (v1.0.0)
                         │
                         ▼
           [Deterministic Validation Engine]
   ├── Entity Identifier Canonicalization ([CATEGORY]:[NAME])
   ├── Dangling Reference Quarantine (subject/object containment)
   ├── Verbatim Substring Quote Verification against Chunk Text
   ├── Epistemic Status Assignment (SOURCE_SUPPORTED, INFERRED, CANDIDATE, REJECTED)
   └── Trusted Lineage Attachment (Source ID, Chunk ID, PDF Page, Model ID)
                         │
                         ▼
        [RelationalKnowledgeGraph SQLite Store]
   ├── Atomic Transactional Batch Writes
   ├── Multi-Source Evidence Lineage Array Preservation
   ├── Idempotent Entity/Edge Upserts (No Duplicate Explosion)
   └── graph_extractions Audit Trail Record
                         │
                         ▼
      [Authenticated Dashboard API & Frontend UI]
   ├── POST /api/knowledge/sources/{source_id}/extract-graph (OPERATOR Role) -> GraphExtractionResponse
   ├── GET /api/knowledge/sources/{source_id}/graph-status (OBSERVER Role) -> SourceGraphStatusResponse
   ├── GET /api/knowledge/graph/stats (OBSERVER Role) -> KnowledgeGraphStatsResponse
   └── MemoryKnowledgeTab "Extract Graph" Trigger & Real-time Status Banner
```

### Verified Implementation Components:
1. **`KnowledgeGraphExtractor`** ([src/knowledge/graph_extractor.py](file:///c:/Projects/Ultron%20-%20Cybersecurity%20Copilot/src/knowledge/graph_extractor.py)):
   - Encapsulates structured schema contracts (`ChunkExtractionPayload`), prompt boundary isolation, candidate parsing, local reference resolution, and verbatim quote verification.
2. **`RelationalKnowledgeGraph`** ([src/knowledge/knowledge_graph.py](file:///c:/Projects/Ultron%20-%20Cybersecurity%20Copilot/src/knowledge/knowledge_graph.py)):
   - Extends the existing SQLite-backed knowledge graph with `persist_chunk_extraction()`, `graph_extractions` tracking table, multi-source citation lists, and status query methods (`get_node`, `get_edge`, `get_graph_stats`).
3. **`KnowledgeRelationType`** ([src/knowledge/canonical_models.py](file:///c:/Projects/Ultron%20-%20Cybersecurity%20Copilot/src/knowledge/canonical_models.py)):
   - Extended with core cybersecurity predicates (`EXPLOITS`, `MITIGATES`, `REQUIRES`, `TARGETS`, `SUBCLASS_OF`).
4. **`OllamaRunner`** ([src/engine/runner.py](file:///c:/Projects/Ultron%20-%20Cybersecurity%20Copilot/src/engine/runner.py)):
   - Enhanced `generate_structured()` to accept caller-specified `num_predict`, ensuring complex multi-entity JSON structures are not truncated at the default 300-token threshold.
5. **`DashboardService`** ([src/dashboard/service.py](file:///c:/Projects/Ultron%20-%20Cybersecurity%20Copilot/src/dashboard/service.py)):
   - Implements `extract_source_knowledge_graph()`, `get_source_graph_status()`, and `get_knowledge_graph_stats()` with bounded chunk batching and error recovery.
6. **`FastAPI Application` & Pydantic Models** ([src/dashboard/app.py](file:///c:/Projects/Ultron%20-%20Cybersecurity%20Copilot/src/dashboard/app.py) & [src/dashboard/models.py](file:///c:/Projects/Ultron%20-%20Cybersecurity%20Copilot/src/dashboard/models.py)):
   - Exposes authenticated, RBAC-guarded REST endpoints with explicit Pydantic response models (`GraphExtractionResponse`, `SourceGraphStatusResponse`, `KnowledgeGraphStatsResponse`).
7. **`Knowledge Corpus UI` & API Bindings** ([frontend/src/components/workspace/tabs/MemoryKnowledgeTab.tsx](file:///c:/Projects/Ultron%20-%20Cybersecurity%20Copilot/frontend/src/components/workspace/tabs/MemoryKnowledgeTab.tsx), [frontend/src/api.ts](file:///c:/Projects/Ultron%20-%20Cybersecurity%20Copilot/frontend/src/api.ts), [frontend/src/types.ts](file:///c:/Projects/Ultron%20-%20Cybersecurity%20Copilot/frontend/src/types.ts)):
   - Strongly-typed API client methods and UI trigger with real-time feedback banner.

---

## 3. Data Contract Audit & Status Disambiguation

The skeptical audit investigated whether `KnowledgeSource['status']` in `frontend/src/types.ts` created an ambiguous union between source ingestion status and graph extraction status.

### Findings & Resolution:
1. **Source Ingestion Lifecycle vs. Graph Extraction Outcome:**
   - In `src/knowledge/ingestion_engine.py`, `IngestionStatus` defines source lifecycle states: `SUCCESS`, `INDEXED`, `DUPLICATE`, `QUARANTINED`, `MALFORMED`, `DELETED`, `UPDATED`, `PARTIAL`, `FAILED`, `DEACTIVATED`.
   - `KnowledgeSource.status` in both SQLite (`vapt_knowledge.db`) and frontend typing represents **exclusively the source ingestion lifecycle status**.
   - Graph extraction execution is stored in a separate table (`graph_extractions` in `knowledge_graph.db`) and returned via distinct response models.
2. **Contract Remediation:**
   - Explicit Pydantic response models were added to `src/dashboard/models.py`:
     - `GraphExtractionResponse`: `status` is `'COMPLETED' | 'FAILED' | 'EMPTY'`, plus chunk counts, entity/edge counts, epistemic breakdown, and errors.
     - `SourceGraphStatusResponse`: `source_id`, `extractions_count`, `total_entities`, `total_edges`, `source_supported_edges`, `inferred_edges`, `rejected_candidates`, and chunk extraction records.
     - `KnowledgeGraphStatsResponse`: `total_nodes`, `total_edges`, `total_extractions`, `source_supported_edges`, `inferred_edges`, `rejected_candidates`.
   - Corresponding TypeScript interfaces were added to `frontend/src/types.ts`.
   - Client functions in `frontend/src/api.ts` (`extractKnowledgeGraph`, `getKnowledgeGraphStatus`, `getKnowledgeGraphStats`) were updated from `Promise<any>` to their explicit strong types.
   - A permanent contract test was added to `frontend/test/knowledge_sources.test.ts`.

---

## 4. Evidence Semantics, Provenance, and Security Boundaries

1. **Non-Authoritative Graph:** Graph entities and edges cannot modify `ScopeGate`, approve scan actions, or override RBAC permissions. Stored knowledge remains strictly subordinate to deterministic code policy.
2. **Deterministic Lineage Enforcement:** Authoritative identifiers (`source_id`, `chunk_id`, `page_number`, `model_id`, `extractor_version`) are deterministically attached by application code from the chunk submitted for inference. The model has zero ability to invent or forge provenance records.
3. **Traceability vs. Correctness:** Verbatim quote matching against chunk text confirms **evidence traceability** (`SOURCE_SUPPORTED`), not absolute semantic correctness or general entailment. Inferred relationships without verbatim quotes remain explicitly marked as `INFERRED`. Mismatched or hallucinated quotes cannot enter the graph as source-supported knowledge.
4. **Quarantine of Dangling Entity Pointers:** If a relationship candidate references subject or object identifiers not present in the chunk extraction payload, it is quarantined into `rejected_relationships` and never written to the graph edges table.
5. **Multi-Source Evidence Accumulation:** Multiple chunks or documents supporting the same canonical entity append to `evidence_citations` in `metadata_json`. Prior source lineage is never overwritten or lost.
6. **Untrusted Document Boundary:** Document content is wrapped in `<<<UNTRUSTED_DOCUMENT_CONTENT>>>` tags. Prompt injection instructions embedded in source text are treated purely as analysis content. Tested and verified by `test_prompt_injection_in_source_chunk_treated_as_untrusted_data`.

---

## 5. Runtime Verification and Live Local-AI Inference

### 1. Runtime Environment Check
- **Local Runtime:** Ollama daemon running on `http://127.0.0.1:11434`.
- **Installed Models Verified:**
  - `qwen2.5-coder:7b` (size: ~4.7 GB, modified: 2026-09-17)
  - `qwen2.5-coder:3b` (size: ~1.9 GB)
- **Target Hardware Context:** AMD Ryzen 5 5600H CPU, 24 GB RAM, NVIDIA RTX 3050 Laptop GPU (4 GB VRAM), Windows 11.

### 2. Live Extraction Smoke Test (`test_live_ollama_knowledge_graph_extraction`)
- **Command:** `.\.venv\Scripts\python.exe -m pytest tests/integration/test_live_knowledge_graph_extraction.py -v -s`
- **Result:** `1 passed in 33.74s`
- **Executed Against:** Live `qwen2.5-coder:7b` model.
- **Observed Live Output:**
  - Extracted 5 valid entities:
    1. `VULNERABILITY:SQL_Injection`
    2. `TECHNOLOGY:Web_Application`
    3. `TECHNOLOGY:Database_Server`
    4. `CONTROL:Parameterized_Queries`
    5. `CONCEPT:Attacker`
  - Extracted 3 valid relationships:
    1. `SQL_Injection` $\xrightarrow{\text{TARGETS}}$ `Database_Server` (Quote verified: *"execute arbitrary queries against the backend database"*)
    2. `Parameterized_Queries` $\xrightarrow{\text{MITIGATES}}$ `SQL_Injection` (Quote verified: *"primary defense against SQL injection is the use of parameterized queries"*)
    3. `Attacker` $\xrightarrow{\text{EXPLOITS}}$ `SQL_Injection` (Quote verified: *"An attacker can exploit this flaw"*)
  - All 3 relationships were deterministically verified and marked `SOURCE_SUPPORTED`.
  - Persisted into `RelationalKnowledgeGraph` SQLite database; verified surviving closure and reopening.

---

## 6. Comprehensive Verification Test Matrix

All test commands were executed directly during the Stage C audit with actual console output recorded.

### Test Execution vs. Unique Test Case Summary:
- **Cumulative Backend Test Executions:** **160 executions** across 6 distinct commands (160 passed, 0 failed, 0 skipped, 4 deprecation warnings).
- **Unique Collected Backend Test Cases:** **140 unique test cases** (distinct pytest node IDs confirmed via non-executing `pytest --collect-only`).
- **Repeated Test Executions:** **20 duplicate executions** resulting from running the 13 Stage C unit tests and 7 Stage C integration tests both in focused commands and within the 83-test Knowledge Regression suite.
- **Frontend Test Suite (Reported Separately):** **35 unique test cases** executed, 35 passed, 0 failed, 0 skipped.
- **Frontend Production Build (Reported Separately):** Clean production bundle via `tsc -b && vite build` with zero TypeScript errors.

| Test Suite / Target | Command Executed | Unique Tests | Executions | Result | Warnings | Duration |
|---|---|:---:|:---:|:---:|:---:|:---:|
| **Stage C Unit Tests** | `.\.venv\Scripts\python.exe -m pytest tests/unit/test_knowledge_graph_extraction.py -v` | 13 | 13 | **13 Passed** | 0 | 0.45s |
| **Stage C Integration Tests** | `.\.venv\Scripts\python.exe -m pytest tests/integration/test_knowledge_graph_persistence.py -v` | 7 | 7 | **7 Passed** | 0 | 5.65s |
| **Stage C Live Model Smoke Test** | `.\.venv\Scripts\python.exe -m pytest tests/integration/test_live_knowledge_graph_extraction.py -v -s` | 1 | 1 | **1 Passed** | 0 | 33.74s |
| **Pre-existing Graph Test** | `.\.venv\Scripts\python.exe -m pytest tests/unit/test_graph.py -v` | 1 | 1 | **1 Passed** | 0 | 0.29s |
| **Full Knowledge Regression Suite** | `.\.venv\Scripts\python.exe -m pytest tests\unit\test_knowledge_*.py tests\integration\test_knowledge_*.py` | 83 *(incl. 20 Stage C)* | 83 | **83 Passed** | 2 | 12.56s |
| **Dashboard & Security Regressions** | `.\.venv\Scripts\python.exe -m pytest tests\unit\test_dashboard* tests\unit\test_batch1* tests\unit\test_batch3_api*` | 55 | 55 | **55 Passed** | 2 | 44.23s |
| **Subtotal Backend (Executions)** | — | **140 Unique** | **160** | **160 Passed** | **4** | **96.92s** |
| **Frontend Test Suite** | `npm run test` (in `frontend/`) | 35 | 35 | **35 Passed** | 0 | 0.17s |
| **Frontend Production Build** | `npm run build` (in `frontend/`) | N/A | Build | **Clean Bundle** | 0 | 0.17s |

*Test Execution Reconciliation:*  
- Cumulative backend executions: `13 + 7 + 1 + 1 + 83 + 55 = 160`.  
- Unique backend test cases: `83 (knowledge suite) + 55 (dashboard/security) + 1 (smoke) + 1 (graph) = 140`.  
- Overlap: The 13 unit tests (`test_knowledge_graph_extraction.py`) and 7 integration tests (`test_knowledge_graph_persistence.py`) match the glob patterns for the knowledge regression suite and were executed twice. Subtracting the 20 duplicate executions from 160 yields exactly 140 unique test cases.  
- Warnings: 4 deprecation warnings logged in total (2 Starlette `httpx` deprecation warnings and 2 AnyIO `BlockingPortal` deprecation warnings in testclient harnesses).

---

## 7. Git State and Baseline Preservation Audit

- **Repository Branch:** `master`
- **Repository HEAD:** `8a2d32611048b251fe1972025c626cf7ceb61103` (Unchanged from pre-Stage C state; zero commits, tags, or branch operations created).
- **Destructive Command Check:** Zero destructive Git commands (`git reset`, `git clean`, `git checkout`, `git restore`) were executed.
- **Working-Tree Status:** The working tree contains 97 modified tracked files and 49 untracked files/directories.
- **Preservation Verification Limits:**
  - An unchanged HEAD and the absence of destructive Git commands establish that Git repository history and committed state were not altered.
  - However, an unchanged HEAD does not by itself prove byte-for-byte preservation of uncommitted working-tree modifications. Because no comprehensive cryptographic hash manifest of all uncommitted working-tree files was recorded immediately prior to Stage C, the audit confirms the observed Git status and non-destructive command history, but acknowledges the inherent limit in independently proving byte-for-byte immutability across all 97 uncommitted files.
- **Historical Evaluation Artifacts (`data/eval/`):**
  - Executing `git diff data/eval/` reveals that `data/eval/m10_evaluation_results.json`, `data/eval/m11_5_evaluation_results.json`, and `data/eval/m12_evaluation_results.json` differ from Git HEAD (`8a2d32611048b251fe1972025c626cf7ceb61103`), with timestamps from October 17, 2026 and minor benchmark metric adjustments originating from prior audit batches.
  - Filesystem metadata indicates the `LastWriteTime` for all three files is `17-10-2026` (~18:23–18:29). The observed timestamps are consistent with no writes during the reported Stage C window, but timestamps alone do not prove that file contents remained unchanged or that no write occurred.
  - Earlier statements describing `data/eval/` files as "bit-for-bit unchanged from the pre-Stage C baseline based on git diff data/eval/" were conceptually flawed, as `git diff` evaluates against HEAD rather than against a pre-Stage C working-tree baseline. The verified fact is that these files remain modified relative to HEAD, and available records show no Stage C modifications.

---

## 8. Defect Corrections Made During Audit

1. **FastAPI Route Serialization Error:**
   - In `src/dashboard/models.py`, `KnowledgeGraphStatsResponse` initially specified `candidate_edges`, whereas `RelationalKnowledgeGraph.get_graph_stats()` returns `total_extractions` and `rejected_candidates`. This caused a `ResponseValidationError` when accessing `GET /api/knowledge/graph/stats`.
   - Corrected `KnowledgeGraphStatsResponse` in `src/dashboard/models.py` and `frontend/src/types.ts` to match the exact database return structure (`total_nodes`, `total_edges`, `total_extractions`, `source_supported_edges`, `inferred_edges`, `rejected_candidates`).
2. **Missing Strong Typing on Client Methods:**
   - `extractKnowledgeGraph` and `getKnowledgeGraphStatus` in `frontend/src/api.ts` returned `Promise<any>`. Strongly typed both methods with `GraphExtractionResponse` and `SourceGraphStatusResponse`, and added `getKnowledgeGraphStats(): Promise<KnowledgeGraphStatsResponse>`.
3. **Frontend Contract Test Coverage:**
   - Added permanent contract assertions to `frontend/test/knowledge_sources.test.ts` verifying that `GraphExtractionResponse`, `SourceGraphStatusResponse`, and `KnowledgeGraphStatsResponse` are exported and distinguish `COMPLETED`, `FAILED`, and `EMPTY` graph states from source ingestion states.

---

## 9. Next Roadmap Stage

- **Status:** **STAGE D HAS NOT BEEN STARTED.**
- **Scope Invariant:** Stage D (graph-assisted retrieval, hybrid query routing, and conversational knowledge RAG) requires explicit user authorization before any planning or implementation commences.
- **Execution State:** **STOPPED.**

---

## 10. Final Evidence Reconciliation & Closure Audit Addendum

**Audit Authority:** Ultron Core Engineering & Final Evidence Reconciliation Auditor  
**Audit Date:** October 18, 2026  
**Reconciliation Scope:** Test-count reconciliation, Git preservation qualification, evidence grounding, and documentation closure.  

### 10.1 Final Verdict and Concise Qualification
- **Retained Verdict:** **`STAGE C — PASS WITH QUALIFICATIONS`**
- **Justification:** All Stage C technical acceptance gates (local Ollama structured extraction, Pydantic schema validation, deterministic quote-matching verification, dangling pointer quarantine, SQLite graph persistence, authenticated Dashboard APIs, and frontend integration) remain verified by recorded evidence and reproducible fixtures. The verdict is retained with explicit qualifications regarding layout boundaries, chunk-level smoke metadata, and preservation evidence limits.

### 10.2 Reconciled Test Execution and Case Counts
- **Confirmed Cumulative Backend Test Executions:** **160** across 6 test commands.
- **Confirmed Unique Backend Test Cases:** **140** distinct pytest test node IDs.
- **Detailed Reconciliation Breakdown:**
  1. *Stage C Unit Suite:* 13 tests (`tests/unit/test_knowledge_graph_extraction.py`).
  2. *Stage C Integration Suite:* 7 tests (`tests/integration/test_knowledge_graph_persistence.py`).
  3. *Stage C Live Model Smoke Test:* 1 test (`tests/integration/test_live_knowledge_graph_extraction.py`).
  4. *Pre-existing Graph Test:* 1 test (`tests/unit/test_graph.py`).
  5. *Broader Knowledge Regression Suite:* 83 tests (`tests/unit/test_knowledge_*.py` and `tests/integration/test_knowledge_*.py`). This suite includes the 13 Stage C unit tests and 7 Stage C integration tests.
  6. *Dashboard & Security Regression Suite:* 55 tests (`tests/unit/test_dashboard*.py`, `tests/unit/test_batch1*.py`, `tests/unit/test_batch3_api*.py`).
- **Mathematical Reconciliation:**
  $$\text{Cumulative Executions} = 13 + 7 + 1 + 1 + 83 + 55 = 160$$
  $$\text{Unique Test Cases} = 83 + 55 + 1 + 1 = 140$$
  $$\text{Repeated Executions} = 13 + 7 = 20$$
  $$\text{Cumulative Executions} - \text{Repeated Executions} = 160 - 20 = 140 \text{ Unique Cases}$$
- **Test Outcomes Recorded:**
  - Passed: **160** (100% of cumulative executions).
  - Failed: **0**.
  - Skipped: **0**.
  - Warnings: **4** recorded across regression suites (Starlette / AnyIO deprecation notices; non-breaking).
- **Frontend Verification (Reported Separately):**
  - Frontend Test Suite: 35 unique tests in `frontend/test/`, 35 passed, 0 failed.
  - Frontend Production Build: Clean bundle via `npm run build` with zero TypeScript errors.

### 10.3 Git State Facts and Inherent Preservation Limits
- **Observed Branch & HEAD:** Branch is `master`; HEAD is `8a2d32611048b251fe1972025c626cf7ceb61103`.
- **Git Operations:** Zero commits, tags, branches, or history alterations were made.
- **Command History:** Zero destructive commands (`git reset`, `git clean`, `git checkout`, `git restore`) were executed.
- **Working-Tree Status:** 97 modified tracked files and 49 untracked files/directories.
- **Preservation Evidence Qualification:**
  - An unchanged Git HEAD verifies that the committed baseline was not modified or reset.
  - A final `git status` verifies the set of modified paths relative to HEAD, but cannot prove byte-for-byte identity of uncommitted file contents against an uncommitted pre-Stage C working-tree state without a pre-Stage C cryptographic hash snapshot.
  - Therefore, the audit confirms the available Git state and non-destructive command history, but explicitly acknowledges that independent byte-for-byte preservation across all 97 uncommitted files cannot be proven from Git state alone.

### 10.4 Historical Evaluation File Claims
- **Observed Status:** `data/eval/m10_evaluation_results.json`, `data/eval/m11_5_evaluation_results.json`, and `data/eval/m12_evaluation_results.json` show uncommitted diffs against Git HEAD (`8a2d32611048b251fe1972025c626cf7ceb61103`).
- **Origin of Diffs:** Diffs contain modification timestamps from October 17, 2026 (dating to earlier evaluation and audit batches), not from Stage C.
- **Filesystem Verification:** Filesystem `LastWriteTime` timestamps remain on October 17, 2026 (~18:23–18:29). The observed timestamps are consistent with no writes during the reported Stage C window, but timestamps alone do not prove that file contents remained unchanged or that no write occurred.
- **Correction:** Prior claims stating these files were "bit-for-bit unchanged from the pre-Stage C baseline based on git diff data/eval/" have been corrected to reflect that `git diff` measures against HEAD, not an uncommitted pre-Stage C baseline.

### 10.5 Remaining Technical Limitations (Explicitly Retained)
1. **Heterogeneous Textbook Layout Compatibility:** Document chunking and parsing are verified against synthetic standards-compliant fixtures. Real-world printed textbooks with margin notes, irregular multi-column layouts, and scanned imagery remain unverified until publisher samples are imported into `data/knowledge/imports/`.
2. **Live Smoke Test Scope:** The live Ollama smoke test verified extraction, structured parsing, and deterministic page-provenance attachment from chunk metadata category tags (`page:25`, `format:pdf`); it did not dynamically parse a raw multi-page PDF during that test call.
3. **Traceability vs. Semantic Ground Truth:** Verbatim substring quote matching guarantees syntactic traceability (`SOURCE_SUPPORTED`) to source chunks. It does not certify deep semantic correctness or deductive entailment.
4. **Prompt-Injection Mitigation Boundaries:** Untrusted content tags (`<<<UNTRUSTED_DOCUMENT_CONTENT>>>`) mitigate prompt injection in source chunks. Deterministic authorization, RBAC, provenance assignment and lack of model execution privileges enforce specific security invariants independently of model output; these controls do not establish that every possible security risk has been eliminated.
5. **Pre-Existing Response Pipeline Defects:** Pre-existing response-pipeline issues (such as `KnowledgeClaim.statement` vs `text` attribute discrepancies in `service.py`) remain out of scope for Stage C and documented for subsequent roadmap milestones.

### 10.6 Reconciliation Governance & Restrictions
- **Implementation Status:** Zero application, test, dependency, or configuration files were modified during this reconciliation. All changes were strictly documentation-only.
- **Roadmap Constraint:** Stage D (graph-assisted retrieval, hybrid query routing, conversational knowledge RAG) is **strictly unauthorized** and **has not started**.
- **Auditor Final Signoff:** All test counts, Git-state statements, and technical qualifications in `docs/STAGE_C_LOCAL_AI_KNOWLEDGE_GRAPH_REPORT.md` are reconciled, evidence-grounded, and closed. Execution is **STOPPED**.
