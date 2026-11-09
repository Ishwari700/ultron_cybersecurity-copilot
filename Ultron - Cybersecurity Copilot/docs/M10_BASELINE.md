# Milestone 10 Baseline Audit and Regression Record

**Date:** 2026-10-08  
**Platform Version:** v9.0.0-cybersecurity-knowledge-rag  
**Target Architecture:**
- CPU: AMD Ryzen 5 5600H (6 cores, 12 threads)
- RAM: 24 GB
- GPU: NVIDIA GeForce RTX 3050 Laptop GPU (4 GB VRAM)
- OS: Windows 11
- Local LLM Runtime: Ollama (`qwen2.5-coder:3b`, `qwen2.5-coder:7b`)
- Concurrency: Sequential inference (`concurrency = 1`)

---

## 1. M0–M9 Regression Baseline

### Test Suite Execution
- **Command:** `.venv\Scripts\pytest -q` + live integration tests (`test_live_cascade_phase8.py`, `test_live_v6_complete_pipeline.py`)
- **Total Test Cases Collected:** 1,418
- **Passed:** 1,407
- **Skipped:** 11
- **Failed / Errors:** 0
- **Regression Status:** 100% PASSED

---

## 2. Existing Components Inventory & Reuse Analysis

### Artifacts Subsystem (`src/artifacts/`)
- `registry.py`: Assessment-scoped `ArtifactRegistry` enforcing namespace isolation (`INV-SEC-04`, `INV-M8-04`). Reusable for all M10 artifact types.
- `metadata.py`: `ArtifactRecord`, `ArtifactType`, `QuarantineStatus`, `QuarantineReason`, `TrustStatus`. Extensible with M10 binary and mobile artifact categories.
- `quarantine.py`: `ArtifactQuarantineManager` evaluating safety policies, path traversal, empty files, and format corruption. Extensible with ZIP slip, ELF/DEX magic validation, and decompression bomb guards.
- `hashing.py`: Cryptographic SHA-256 calculation for byte-level provenance.

### Mobile Subsystem (`src/mobile/`)
- `artifacts.py`: Initial models for `ComponentType`, `AndroidComponent`, `PermissionArtifact`, `DeepLinkArtifact`, `WebViewConfig`, `MobileArtifact`.
- `manifest.py`: Initial `ManifestAnalyzer` for XML parsing. Needs deeper analysis of intent filters, authorities, cleartext traffic, backup flags, and SDK versions.
- `dex.py`: Basic `DexAnalyzer` regex search on strings. Needs native binary DEX bytecode indexing, classes, methods, fields, signatures, and string tables.
- `smali.py`: Instruction-level string matching. Needs structured parsing of invokes, registers, branches, IPC, crypto, and storage.
- `evidence.py`: `MobileEvidenceAdapter` bridging to `CanonicalObservation`.

### Binary Subsystem (`src/binary/`)
- `artifacts.py`: Initial models for `FunctionArtifact`, `SuspiciousSink`, `CallRelationship`, `BinaryArtifact`.
- `functions.py`: Initial `FunctionAnalyzer` with basic C sink dictionary.
- `relationships.py`: `CallGraphAnalyzer` BFS reachability queries.
- `evidence.py`: `BinaryEvidenceAdapter` bridging to `CanonicalObservation`.

### Governance & Security Controls (Must Remain Authoritative)
- `src/scope/gate.py`: `ScopeGate` enforcing target authorization.
- `src/assessment/authorization.py`: `AuthorizationValidator`.
- `src/assessment/validation.py`: `FindingValidator`.
- `src/review/`: `ReviewCase`, `ReviewQueue`, human verification gate.
- `src/audit/ledger.py`: `AuditLedger` tamper-evident logging.
- `src/assessment/secrets.py`: `SecretRedactor` for automated secret scrubbing.
- `src/knowledge/knowledge_graph.py`: SQLite knowledge graph and taxonomy mappings.

---

## 3. Invariants In Force (M0–M10)

- `INV-SEC-01` to `INV-SEC-04`: Scope, authorization, human review, assessment namespace isolation.
- `INV-M8-01` to `INV-M8-10`: Artifact provenance, quarantine isolation, deterministic hashing.
- `INV-M9-01` to `INV-M9-20`: Knowledge retrieval separation, epistemic boundary, anti-poisoning.
- `INV-M10-01` to `INV-M10-18`: Deep Android/binary static analysis invariants (malformed input fail-closed, no autonomous execution, prompt injection as data, tool disagreement preservation, zero fabricated edges, static indicator $\neq$ confirmed vulnerability).
