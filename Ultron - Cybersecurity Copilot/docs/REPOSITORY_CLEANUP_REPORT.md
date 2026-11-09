# Repository Cleanup, Architecture Inventory & Audit Report

**Date:** September 17, 2026  
**Status:** COMPLETE  
**Scope:** Repository Cleanup + Architecture Inventory + Current-vs-Future Documentation + Test Suite Verification  

---

## 1. Executive Summary

This report documents the repository cleanup, architectural inventory, and verification pass performed on the **Local AI-Assisted Bug Bounty Research Platform (V6)** prior to commencing work on the next milestone.

The pass accomplished five key objectives without implementing roadmap features or modifying research evaluation methodology:
1. **Eliminated Obsolete & Temporary Clutter**: Deleted temporary debug SQLite databases, scratch output files, and 7 redundant empty root placeholder directories.
2. **Established Cache Disposition**: Inspected the local cache system, proving that `data/cache/tld_cache/` represents active, offline runtime state required by `tldextract` in `ScopeGate`, and preserved it intact.
3. **Preserved Full EXP-0006 Reproducibility**: Audited and preserved all raw experimental data (N=84 and N=12), scorer code, simulator code, methodology audit documentation, and experiment logs.
4. **Single Authoritative Architecture Reference**: Rebuilt [ARCHITECTURE.md](ARCHITECTURE.md) to authoritatively document the operational status of every subsystem, wiring details, and the current-vs-future boundary without duplicate documentation.
5. **Reconciled Test Verification**: Dynamically collected and executed the entire test suite (**126 total test items**: 106 unit, 20 integration) with zero failures.

---

## 2. Milestone & Artifact Classification

Per strict engineering and research rigor, milestone and evaluation statuses are distinguished as follows:

| Milestone / Artifact | Official Status | Operational Definition |
| :--- | :--- | :--- |
| **Milestone M0** | **Implemented** | Scope Gate (TOCTOU IP pinning, CIDR/RFC1918 blocking, redirect hop evaluation), Redaction Vault (typed placeholders, cross-identity correlation), SQLite schema with integrity triggers, hardware scheduler, and immutable audit logger. |
| **Milestone M1** | **Implemented** | Local LLM inference engine (`qwen2.5-coder:3b` and `7b`), structured JSON schema enforcement, target-evidence RAG (BM25 FTS5 + exact token gate + token budget controller), Grounding Validator, Headless Simulator, and Hypothesis State Machine. |
| **EXP-0006 + Methodology Audit** | **Validated Research Artifact** | Full comparative 5-track ablation benchmark executed across 84 scenarios on live local models, followed by an independent statistical and methodological audit (Wilson 95% CIs, McNemar exact tests, grounding validator ID check, and error attribution). |
| **Milestone M1.5** | **Planned / Finalization Milestone** | Benchmark scenario expansion, test suite freezing, and finalization rigor before starting M2. |
| **Milestone M2** | **Planned** | 3B → 7B Cascade Router, triage predicates, and adaptive model escalation. |

---

## 3. Cache Disposition Analysis

Before executing file operations, an explicit inspection of caching behavior across the repository was conducted:

1. **Root-Level `cache/`**: Does not exist at the repository root. Only `.pytest_cache/` (test runner cache) is present at root.
2. **Location of Active Cache**: The active local cache resides in [`data/cache/tld_cache/`](data/cache/tld_cache/).
3. **Operational Role**:
   - In [`src/scope/gate.py`](src/scope/gate.py) (lines 44–46), `ScopeGate` initializes `tldextract.TLDExtract` with `cache_dir="data/cache/tld_cache"` and `suffix_list_urls=None`.
   - This local snapshot (`publicsuffix.org-tlds/906337bdfc421126a1477ade77793840.tldextract.json`, 166.2 KB) allows `ScopeGate` to compute registered domains and public suffixes completely offline without making outbound network calls to download suffix definitions during scope evaluation.
4. **Disposition Decision**:
   - `data/cache/tld_cache/` is **ACTIVE RUNTIME STATE**.
   - It is correctly located under `data/cache/` and ignored by `.gitignore`.
   - **Preserved intact.** No cache files were deleted, moved, or renamed.

---

## 4. Deletion & Cleanup Log

The following approved temporary and legacy placeholder items were removed:

| Item Path | Type | Size | Rationale |
| :--- | :--- | :--- | :--- |
| `scratch/audit_runner.db` | File | 155.6 KB | Temporary SQLite debug database created during pilot audit. |
| `scratch/audit_10_cases_results.json` | File | 17.9 KB | Temporary debug JSON dump from manual test verification. |
| `applications/` | Directory | 33 B (`.gitkeep`) | Redundant legacy root stub; applications are represented in `src/eval/synthetic_app.py`. |
| `evaluation/` | Directory | 76 B (`.gitkeep`) | Redundant legacy root stub; evaluation pipeline is in `src/eval/`. |
| `evidence/` | Directory | 62 B (`.gitkeep`) | Redundant legacy root stub; evidence engine is in `src/evidence/`. |
| `ground_truth/` | Directory | 72 B (`.gitkeep`) | Redundant legacy root stub; ground truth definitions are strictly isolated in `src/eval/scenarios.py`. |
| `scenarios/` | Directory | 85 B (`.gitkeep`) | Redundant legacy root stub; benchmark scenarios are in `src/eval/scenarios.py` and `data/`. |
| `splits/` | Directory | 44 B (`.gitkeep`) | Redundant legacy root stub; evaluation splits are managed in `src/eval/scenarios.py`. |
| `scripts/` | Directory | 31 B (`.gitkeep`) | Empty legacy root stub with only a `.gitkeep`. |

### Configuration Updates:
- [`.gitignore`](.gitignore): Added `scratch/` under Local data & databases to prevent accidental tracking of temporary debugging scripts and scratch databases.

---

## 5. Preserved EXP-0006 Reproducibility Artifacts

All experimental artifacts and evaluation code required to reproduce, audit, or inspect EXP-0006 remain fully intact:
- [`data/exp0006_full_ablation_results.json`](data/exp0006_full_ablation_results.json) (724.9 KB, full 84-scenario 5-track raw results)
- [`data/pilot_ablation_results.json`](data/pilot_ablation_results.json) (110.1 KB, 12-scenario pilot raw results)
- [`docs/EXP0006_FINAL_METHODOLOGY_AUDIT.md`](docs/EXP0006_FINAL_METHODOLOGY_AUDIT.md) (Independent statistical audit)
- [`docs/REAL_LLM_ABLATION_DESIGN.md`](docs/REAL_LLM_ABLATION_DESIGN.md) & [`docs/REAL_LLM_ABLATION_IMPLEMENTATION.md`](docs/REAL_LLM_ABLATION_IMPLEMENTATION.md)
- [`EXPERIMENT_LOG.md`](EXPERIMENT_LOG.md), [`PHASE0_REPORT.md`](PHASE0_REPORT.md), [`PHASE1_REPORT.md`](PHASE1_REPORT.md)
- All evaluation harness code: `src/eval/` (`ablation.py`, `scenarios.py`, `scorer.py`, `simulator.py`, `retrieval_trace.py`, `synthetic_app.py`, `run_full_ablation.py`, `run_pilot_ablation.py`)

---

## 6. Architecture & Wiring Status Inventory

Every subsystem across `src/` has been verified for its actual wiring and operational status in [ARCHITECTURE.md](ARCHITECTURE.md):

| Subsystem | Primary Implementation Files | Operational Status | Current Wiring / Notes |
| :--- | :--- | :--- | :--- |
| **ScopeGate & Client** | `src/scope/gate.py`, `client.py` | **Implemented and Active** | TOCTOU IP pinning, CIDR filtering, redirect validation, rate limits, disallowed techniques. |
| **RedactionVault** | `src/evidence/vault.py` | **Implemented and Active** | Quarantines secrets into typed placeholders (`[REDACTED_JWT_1]`) while preserving cross-identity correlation. |
| **Compressor & Normalizer** | `src/evidence/compressor.py`, `normalizer.py` | **Implemented and Active** | Samples large JSON lists and truncates long HTTP response bodies for token budgeting. |
| **Observation Adapters** | `src/evidence/adapters/` (Burp, Reqable, PCAPdroid, OpenAPI, Generic) | **Implemented but Unused** | Parsers convert raw proxy captures into canonical `Observation` objects. Tested in `test_adapters.py`. Unused in EXP-0006 (synthetic scenarios); reserved for M4 proxy ingestion. |
| **EvidenceGraph & Workflows** | `src/graph/workflow_engine.py`, `models.py` | **Implemented and Active** | Derives temporal workflows and entity relationships, feeding application models into Track D/E prompt generation. |
| **InvariantEngine** | `src/invariants/engine.py`, `models.py` | **Implemented and Active** | Synthesizes security invariants with epistemic origins (`OBSERVED`, `DOCUMENTED`, `DETERMINISTIC_DERIVATION`). |
| **ScenarioRetriever** | `src/retrieval/hybrid.py`, `budget.py` | **Implemented and Active** | SQLite FTS5 (BM25) full-text retrieval + exact-identifier gating + strict token budget cropping. Fully traced in EXP-0006. |
| **ChromaVectorStore** | `src/retrieval/vector_store.py` | **Partial / Prototype** | ChromaDB wrapper implemented and tested; unused in offline benchmark (which runs purely on FTS5 + exact gate). Reserved for M3 VAPT RAG. |
| **ReasoningRunner** | `src/engine/runner.py`, `models.py` | **Implemented and Active** | Live Ollama runner (`3b` / `7b`), JSON schema enforcement, prompt isolation, and fallbacks. |
| **GroundingValidator** | `src/validation/grounding.py` | **Implemented and Active** | Rejects hallucinated IDs, unparented parameters, and invalid evidence references. |
| **HeadlessSimulator** | `src/eval/simulator.py`, `synthetic_app.py` | **Implemented and Active** | Closed-loop experiment execution returning tri-state outcomes (`SUPPORTING`, `CONTRADICTING`, `UNRESOLVED`). |
| **HypothesisStateMachine** | `src/hypothesis/state_machine.py`, `experiment.py` | **Implemented and Active** | Manages hypothesis transitions and generates discriminative experiment proposals. |
| **Ablation Harness & Scorer** | `src/eval/ablation.py`, `scorer.py`, `scenarios.py` | **Implemented and Active** | 5-track comparative ablation benchmark across 84 scenarios with ground-truth isolation and metric calculation. |
| **Dashboard API** | `src/dashboard/app.py` | **Partial / Prototype** | FastAPI backend with safety confirmation gates implemented and tested; web UI frontend is a prototype awaiting M9. |
| **3B → 7B Cascade Router** | `src/engine/cascade.py` | **Planned** | Roadmap Milestone M2. Dynamic complexity estimation, triage gating, and escalation. |
| **VAPT Knowledge Base RAG** | `src/retrieval/vapt_kb.py` | **Planned** | Roadmap Milestone M3. External methodology, vulnerability pattern, and technique retrieval. |
| **Automated Proxy Ingestion** | `src/evidence/watcher.py` | **Planned** | Roadmap Milestone M4. Live file watcher and streaming ingestion from Burp/Reqable. |
| **Case Memory & Correction** | `src/memory/` | **Planned** | Roadmap Milestone M5. Storing verified mistakes, false-positive corrections, and investigator feedback. |
| **Continuous Learning Loop** | `src/calibration/` | **Planned** | Roadmap Milestones M6–M8. Offline calibration, fine-tuning data generation, and regression tracking. |

---

## 7. Test Suite Execution & Reconciliation

The test suite was executed across all unit and integration test modules:

```bash
# Unit Tests
.venv\Scripts\pytest.exe tests/unit/
# Output: 106 passed, 2 warnings in 3.96s

# Integration Tests (Live Ollama 3B/7B)
.venv\Scripts\pytest.exe tests/integration/
# Output: 19 passed, 1 skipped in 65.89s (0:01:05)

# Total Execution Time: 69.85s (3.96s unit + 65.89s integration)
```

### Complete Test Status
- **Collected Test Items**: **126** (106 unit items across 23 files, 20 integration items across 5 files)
- **Passing**: **125**
- **Skipped**: **1** (`test_live_ablation_pilot.py` skipped dynamically when opt-in flag `V6_REQUIRE_LIVE_OLLAMA` is unset)
- **Failing**: **0**
- **Execution Time**: **3.96s** unit + **65.89s** integration = **69.85s** total
- **Discrepancy Reconciliation**:
  - Baseline `TEST_STATUS.md`: 77 tests
  - Milestone M0 Phase 0 additions: +17 tests
  - Milestone M1 Phase 1 & methodology audit additions: +32 tests
  - Reconciled Total: **126 tests**

---

## 8. Remaining Technical Debt & Next Planning Steps

Before implementing roadmap milestones (M1.5 / M2), the following architectural items should be tracked:

1. **ChromaDB Decoupling**:
   - `ChromaVectorStore` exists as a partial prototype. As long as the platform runs offline benchmarks on FTS5 (BM25), `chromadb` remains optional. When designing Milestone M3 (VAPT Knowledge RAG), formalize whether ChromaDB or an embedded SQLite-vec solution will be the primary vector backend.
2. **Adapter Integration (Milestone M4)**:
   - The 5 observation adapters (`burp`, `generic_http`, `openapi`, `pcapdroid`, `reqable`) are tested but currently decoupled from the live benchmark ingestion pipeline. Milestone M4 should build the live watcher to feed these into `evidence.db`.
3. **Dashboard Web UI (Milestone M9)**:
   - The FastAPI backend in `src/dashboard/app.py` has verified safety verification gates, but the frontend HTML/JS interface remains a prototype stub.
4. **Milestone M1.5 Finalization**:
   - Formalize the expanded scenario suite or test freeze criteria for M1.5 before proceeding to Milestone M2 (Cascade Router).
