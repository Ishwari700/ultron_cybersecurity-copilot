# Milestone 10.5 Repository Inventory & Functional Architecture Audit

**Platform Version:** v10.0.0-deep-android-binary-re  
**Quality Gate:** M10.5 (Mandatory Folder Cleanup + Git Audit Gate)  
**Date:** 2026-10-08  
**Repository Root:** `.` (Relative Discovery)

---

## 1. Executive Summary

Milestone 10.5 establishes a rigorous engineering-quality gate between Milestone 10 (Deep Android & Native Binary Reverse Engineering) and Milestone 11 (Controlled Security Experiment + Safe PoC Engine). 

In accordance with Section 1 of the M10.5 Master Specification, **zero product capabilities or M11 features are introduced**. This inventory catalogs all active packages, test modules, benchmark datasets, configuration assets, and documentation across the platform, establishing strict folder boundaries, canonical ownership, and dependency provenance.

### High-Level Inventory Breakdown
| Directory | Total Files | Primary Role | Ownership & Classification |
| :--- | :--- | :--- | :--- |
| `src/` | 339 | Core Production & Evaluation Engines | Production Code / Ingestion / Reasoning / Evaluation |
| `tests/` | 169 | Automated Test Suite (1,434 collected) | Unit, Integration, Security Invariant, Evaluation Tests |
| `data/` | 265 | Corpora, Evaluation Benchmarks, Models | VAPT Corpus, Benchmark Datasets, Local ONNX Models |
| `docs/` | 84 | Milestone Specifications & Audit Reports | Technical Specifications, Empirical Results, ADRs |
| `reports/` | 20 | Historical Validation & Benchmark Records | Sealed Milestone Attestation Reports |
| `frontend/` | 44 | Local User Interface Web Client | React/Vite/TypeScript Local UI (M12) |
| `config/` | 1 | Platform Hardware & Inference Configuration | Environment, LLM, Database, Vectorstore Settings |
| `taxonomy/` | 1 | Security Vulnerability Taxonomies | Canonical Category & CWE Mappings |
| Root | 17 | Configuration, CI/CD, Top-Level Architecture | Package Metadata, Scope Policy, Startup Scripts |

---

## 2. Source Code Architecture (`src/`)

The `src/` directory is partitioned into 27 modular subsystems reflecting the progression of milestones M0 through M10. Each module adheres to the epistemic separation invariant (`EXTERNAL_KNOWLEDGE != TARGET_EVIDENCE` and `MODEL_HYPOTHESIS != HUMAN_VERIFIED_FINDING`).

### Subsystem Catalog

| Subsystem Path | Module Count | Primary Purpose | Milestone Origin | Production / Eval |
| :--- | :--- | :--- | :--- | :--- |
| `src/agents/` | 15 | Specialized autonomous agents (Recon, Triage, Binary, Mobile, Orchestrator, Falsification, Exploitability) | M7, M10 | Production Code |
| `src/analysis/` | 3 | Cross-artifact unified knowledge graph (`AndroidArtifactGraph`) and static code scanner (`CodeSecurityAnalyzer`) | M9, M10 | Production Code |
| `src/api/` | 1 | FastApi REST endpoints and router (`dashboard_api.py`) | M8, M12 | Production Code |
| `src/artifacts/` | 9 | Artifact registry, quarantine isolation manager (`ArtifactQuarantineManager`), adapters (Android, Web API) | M8, M10 | Production Code |
| `src/assessment/` | 16 | Formal assessment lifecycle, authorization validator (`AuthorizationValidator`), secret redaction, finding validation | M6 | Production Code |
| `src/audit/` | 3 | Cryptographic append-only audit ledger (`AuditLedger`), tamper-detection verification | M6 | Production Code |
| `src/binary/` | 11 | Static ELF/PE binary parsers, dangerous API analyzer, mitigation analyzer, native call graph, tool adapters | M7, M10 | Production Code |
| `src/copilot/` | 9 | Conversational copilot engine, intent routing, token budgeting, contextual tool routing | M5 | Production Code |
| `src/core/` | 4 | Core configuration loader, type definitions, exception hierarchy | M0 | Production Code |
| `src/dashboard/` | 4 | Real-time WebSocket event broadcaster, session management, dashboard models | M8, M12 | Production Code |
| `src/database/` | 3 | SQLite connection manager, WAL mode configuration, schema DDL definitions | M0 | Production Code |
| `src/engine/` | 18 | 3B/7B cascade orchestrator (`CascadeOrchestrator`), decision policy, triage & reasoning runners | M2, M3 | Production Code |
| `src/eval/` | 64 | Benchmark execution harnesses, ablation studies, failure corpus generators (Phases 10, 11, M10) | M2–M10 | Evaluation Harness |
| `src/evidence/` | 16 | Evidence vault, lossy compressor, body normalizer, multi-format proxy ingestion adapters | M1, M4 | Production Code |
| `src/execution/` | 11 | Container sandbox execution interface, command runner, tool abstraction | M7 | Production Code |
| `src/graph/` | 3 | Dynamic attack surface graph, temporal workflow derivation engine | M1, M4 | Production Code |
| `src/hypothesis/` | 4 | Tri-state hypothesis state machine (`HypothesisStateMachine`), experiment proposal generator | M2, M3 | Production Code |
| `src/invariants/` | 3 | Formal security invariant evaluation engine (`InvariantEngine`), epistemic origin tracking | M1, M2 | Production Code |
| `src/investigation/`| 5 | Multi-turn investigation state lifecycle, investigation graph, context summarizer | M5 | Production Code |
| `src/knowledge/` | 27 | VAPT knowledge corpus, canonical models, semantic chunking, vector indexing, MiniLM neural retriever | M3, M9 | Production Code |
| `src/mobile/` | 12 | Static Android APK processor, manifest parser, DEX indexer, smali analyzer, component analyzer, call graph | M7, M10 | Production Code |
| `src/reporting/` | 9 | Multi-format reporting engine (Markdown, HTML, PDF, SARIF, Bug Bounty platforms, ASVS) | M8 | Production Code |
| `src/research/` | 15 | Autonomous external research engine, claims extractor, conflict resolution, provenance tracking | M4 | Production Code |
| `src/retrieval/` | 5 | Hybrid BM25 FTS5 + Dense vector retrieval engine, token budgeting, query rewriter | M2, M3 | Production Code |
| `src/review/` | 6 | Human-in-the-loop review queue, review actions, case state management, decision audit | M8 | Production Code |
| `src/scope/` | 4 | Deterministic ScopeGate (`ScopeGate`), TOCTOU IP pinning, CIDR matching, client policy | M0 | Production Code |
| `src/telemetry/` | 3 | Passive network telemetry ingestion, HTTP request/response normalizer | M6 | Production Code |
| `src/validation/` | 2 | Grounding validator (`GroundingValidator`), hallucinated entity rejector | M2 | Production Code |

---

## 3. Test Organization Audit (`tests/`)

The test suite is structured hierarchically by verification layer. The entire test suite executes deterministically in an offline, air-gapped environment without requiring active external internet access.

| Test Directory | File Count | Classification | Scope and Functionality |
| :--- | :--- | :--- | :--- |
| `tests/unit/` | 141 | UNIT / SECURITY | Individual subsystem unit tests, schema validators, security invariants (M0–M10) |
| `tests/integration/` | 18 | INTEGRATION | End-to-end multi-agent pipelines, cascade flows, real question Q&A, M10 deep analysis |
| `tests/fixtures/` | 4 | FIXTURE | Synthetic vulnerability files, negative controls, and quarantined mock payloads |
| `tests/lab/` | 2 | FIXTURE / HARNESS | Lab harness fixtures simulating multi-tenant corporate infrastructure |
| `tests/evaluation/` | 2 | BENCHMARK | VAPT retrieval benchmark queries and benchmark schema validation documentation |
| Root `tests/` | 2 | CONFIG / HARNESS | `conftest.py` test fixtures, global test configuration |

### Test Classification Breakdown
- **UNIT:** Isolated verification of single functions, parsers, state transitions, and schemas (141 files).
- **INTEGRATION:** Multi-component pipeline execution including Android APK processing, native binary analysis, cascade triage-to-reasoning handoff, and UI API endpoints (18 files).
- **SECURITY / INVARIANT:** Hard boundary verification enforcing strict invariants (`INV-M10-01` to `INV-M10-18`, scope gate pinning, secret redaction, authorization validity) embedded within `tests/unit/` and `tests/integration/`.
- **EVALUATION:** Benchmark accuracy, grounding precision, and retrieval recall evaluators (`tests/evaluation/`).
- **LIVE:** `tests/integration/test_live_ablation_pilot.py` (explicitly flagged and skipped during standard regression runs to preserve offline determinism).

---

## 4. Data and Artifact Inventory (`data/` & `reports/`)

| Directory / File | Size | Classification | Retention Decision | Justification |
| :--- | :--- | :--- | :--- | :--- |
| `data/vapt_corpus/` | ~300 KB | KNOWLEDGE CORPUS | **KEEP (Tracked)** | Authoritative frozen VAPT methodology corpus (ASVS, CWE, WSTG) with Ed25519 signatures. |
| `data/models/all-MiniLM-L6-v2/` | ~1.5 MB | LOCAL MODEL CONFIG | **KEEP (Tracked)** | Tokenizer configs, vocab, and special token maps for MiniLM embedding backend. (Binary `.onnx` weight ignored by `.gitignore`). |
| `data/eval/m10_evaluation_results.json` | ~45 KB | BENCHMARK OUTPUT | **KEEP (Tracked)** | Formal M10 evaluation results demonstrating 100% pass rate across 450 test cases. |
| `data/eval/m5_phase10_full_population_validation.json` | 0.99 MB | BENCHMARK DATASET | **KEEP (Tracked)** | Sealed historical benchmark results establishing baseline reasoning metrics. |
| `data/eval/m4_eval_cache.sqlite3` | 24 KB | REPRODUCIBILITY CACHE | **KEEP (Tracked)** | Offline cache of verified research queries ensuring deterministic reproduction of M4 tests. |
| `data/eval/aborted_m4_8_run_20260921*/` | ~350 KB | HISTORICAL EVIDENCE | **KEEP (Tracked)** | Formally committed historical incident screening records for M4.8 evaluation audit trail. |
| `data/cache/tld_cache/` | ~15 KB | OFFLINE CACHE | **KEEP (Ignored)** | Public suffix list cache allowing offline `tldextract` resolution without DNS queries. |
| `data/cache/phase11_rerun_*/` | ~100 KB | STALE TEMP CACHE | **DELETE / CLEAN** | Stale local test run cache directories from historical Phase 11 tuning (not tracked in Git). |
| `reports/*.json` & `reports/*.md` | ~2.5 MB | AUDIT ATTESTATIONS | **KEEP (Tracked)** | Formal milestone evaluation attestation reports (M1.5, M2, Phase 10, Phase 11). |

---

## 5. Configuration and Metadata Files

| Configuration File | Format | Purpose | Hardcoded Paths Audited |
| :--- | :--- | :--- | :--- |
| `pyproject.toml` | TOML | Project build definition, Python 3.11+ requirement, dependencies, pytest config | Cleaned (Updated to v10.0.0, zero absolute paths) |
| `config/default_config.yaml` | YAML | Hardware limits (24GB RAM, 4GB VRAM), Ollama config, database paths | Cleaned (All paths relative: `data/evidence.db`) |
| `scope.yaml` | YAML | Program scope definition, in-scope domains, rules of engagement | Cleaned (Zero developer-specific paths) |
| `.gitignore` | Text | Git exclusion rules for virtual environments, caches, temporary binaries | Cleaned & Expanded (Includes temporary APK/bin output) |
| `taxonomy/categories.yaml` | YAML | Bug bounty taxonomy classifications and CWE associations | Verified (Standardized schema) |
| `run_local_ui.py` | Python | Local development server launcher for UI and API | Verified (Uses relative imports and env port config) |
| `frontend/package.json` | JSON | Vite/React dependencies for local dashboard client | Verified (Standard lockfile in place) |

---

## 6. Dead & Duplicate Code Analysis

### Class Name Collisions & Disambiguation
1. **`CodeSecurityAnalyzer`**:
   - `src/analysis/code_security_analyzer.py`: Canonical static code regex scanner with CWE mapping and taxonomy resolution (M9).
   - `src/copilot/analysis.py`: Conversational code analysis engine generating hypothesis records for Copilot chat (M5).
   - *Status:* Both retained with explicit package boundaries (`src.analysis` vs `src.copilot.analysis`).
2. **`AssessmentScopeStatus`**:
   - `src/assessment/models.py`: Canonical assessment scope state enum (M6).
   - `src/scope/models.py`: Canonical scope decision object enum (M0).
   - *Status:* Retained as canonical representations in their respective functional domains.
3. **`SecurityInvariant`**:
   - `src/invariants/models.py`: Core system invariant with epistemic origin tracking (`OBSERVED`, `DOCUMENTED`) (M1).
   - `src/assessment/models.py`: Formal assessment framework invariant with secure/violation conditions (M6).
   - *Status:* Distinct semantic models serving distinct subsystems.

### Orphan Module Verification
Import scan confirmed:
- **Total Production Python Modules in `src/`:** 333
- **Modules Successfully Imported:** 333 (100.0%)
- **Import Failures:** 0
- **Unresolved Broken Dependencies:** 0

All 31 modules initially identified as potential orphans are verified as valid CLI entry points (`run_phase11_benchmark.py`, `verify_cascade.py`), decompiler adapters (`pe_analyzer.py`), string scanners (`string_secret_analyzer.py`), or corpus build tools (`builder.py`).
