# Ultron — Autonomous Cybersecurity Intelligence & Analyst Workstation
### Local-First, Evidence-Grounded Security Copilot & Full Assessment Platform

[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-green.svg)](LICENSE)
[![Backend Tests](https://img.shields.io/badge/backend%20tests-124%20passed-brightgreen.svg)](tests/)
[![Frontend Tests](https://img.shields.io/badge/frontend%20tests-36%20passed-brightgreen.svg)](frontend/)
[![Security Invariants](https://img.shields.io/badge/security%20invariants-100%25%20enforced%20(35%2F35)-success.svg)](docs/M13_SECURITY.md)
[![Hardware Target](https://img.shields.io/badge/hardware-Ryzen%205%205600H%20%7C%20RTX%203050%204GB%20%7C%2024GB%20RAM-orange.svg)](#hardware-aware-resource-governance)
[![Local Inference](https://img.shields.io/badge/inference-Ollama%20(Qwen%202.5%20Coder%203B%2F7B)-purple.svg)](#quickstart--installation)

---

**Ultron** is an evidence-grounded, local-first, human-in-the-loop cybersecurity research platform and professional analyst workstation. Engineered to run strictly on consumer hardware without external cloud APIs, third-party telemetry, or unconstrained autonomous execution, Ultron pairs conversational intelligence with mathematically verified security invariants, structured hypotheses, controlled non-destructive experiments, and an end-to-end 12-section Security Assessment Workspace.

---

## Key Highlights

- **Shared Analyst Workstation Shell**: Crisp dark analyst-workstation aesthetic featuring charcoal surfaces, deep navy panels, restrained crimson accents, high-contrast typography, responsive drawers, and a persistent dark/light theme switcher.
- **Two Distinct Operating Workspaces**:
  1. **Copilot Investigations**: Conversational research assistant with multi-turn reasoning, streaming SSE responses, live model attribution, stop/edit-prompt controls, response deduplication, and passive telemetry ingestion.
  2. **Security Assessment Workspace**: Formal, authorized pentesting and bug bounty assessments with strict rules of engagement across 12 dedicated lifecycle tabs.
- **Global Knowledge Lab & Graph-Assisted RAG**:
  - Persistent multi-format textbook and document ingestion (PDF, Markdown, Plain Text) with page-by-page progress reporting.
  - Native embedded CFF Type 1 font decoding (`fonttools` + `pypdf`) with zero font-decoding warnings.
  - Schema-constrained knowledge graph extraction via local Ollama inference (`qwen2.5-coder:7b` and `3b`), with bounded token budgets and adaptive local timeouts.
  - Truthful evidence retrieval with verbatim source quotes, real active chunk citations, and explicit labeling for general-model fallback knowledge (`General model knowledge — not verified against ingested sources`). Never fabricates citations, sources, or page numbers.
- **Strict Concurrency & VRAM Governance**: Single-worker inference gate (`InferenceConcurrencyGate`) with priority scheduling (interactive chat preempts background graph extraction), optimized for consumer laptops with 4 GB GPU VRAM.

---

## Table of Contents

1. [Architecture & System Overview](#architecture--system-overview)
2. [Dual Workspace Architecture](#dual-workspace-architecture)
   - [Copilot Investigations](#1-copilot-investigations)
   - [Security Assessment Workspace (12 Tabs)](#2-security-assessment-workspace-12-tabs)
3. [Global Knowledge Lab & Graph RAG](#global-knowledge-lab--graph-rag)
   - [Textbook Ingestion & CFF Font Support](#textbook-ingestion--cff-font-support)
   - [Knowledge Graph Extraction](#knowledge-graph-extraction)
   - [Epistemic Grounding & Citation Validation](#epistemic-grounding--citation-validation)
4. [Hardware-Aware Resource Governance](#hardware-aware-resource-governance)
5. [Zero-Tolerance Security Invariants](#zero-tolerance-security-invariants)
6. [Repository Structure](#repository-structure)
7. [Quickstart & Installation](#quickstart--installation)
8. [Running Verification Test Suites](#running-verification-test-suites)
9. [Documentation Index](#documentation-index)
10. [Safety, Ethics & Responsible Disclosure](#safety-ethics--responsible-disclosure)

---

## Architecture & System Overview

```text
               Passive Telemetry / Textbook Documents
                                │
                                ▼
               Unified Parser & Redaction Vault
         (Secret Quarantine, Hashing, Normalization)
                                │
        ┌───────────────────────┴───────────────────────┐
        ▼                                               ▼
Copilot Investigations Workspace            Security Assessment Workspace
- Conversational Reasoning Engine           - 12 Lifecycle Assessment Tabs
- Token Budget & Deduplication              - ScopeGate (DNS TOCTOU, IP Pinning)
- Model Attribution & Controls              - Plane A/B Experimentation
- Evidence Context Drawer                   - 13-Point Human Verification Checklist
        │                                               │
        └───────────────────────┬───────────────────────┘
                                │
                                ▼
                     Global Knowledge Lab
           Hybrid RAG (BM25 + ChromaDB Vector Embeddings)
                                ┼
          Knowledge Graph (Nodes, Edges, Provenance Ledger)
                                │
                                ▼
               Inference Concurrency Gate (Priority = 1)
         [Interactive Chat > Background Graph Extraction]
                                │
                                ▼
               Local Ollama Engine (100% Offline)
                • Qwen 2.5 Coder 3B (Triage / Fast)
                • Qwen 2.5 Coder 7B (Deep Synthesis)
```

---

## Dual Workspace Architecture

Ultron provides two purpose-built workspaces sharing a unified application shell without merging underlying security contexts or permissions:

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                             ULTRON ANALYST SHELL                            │
├───────────────────────┬─────────────────────────────────────────────────────┤
│  NAVIGATION           │  WORKSPACE VIEW                                     │
│  ───────────────────  │  ─────────────────────────────────────────────────  │
│  • Copilot            │  [Investigations View]                              │
│    Investigations     │  Multi-turn conversational reasoning, streaming      │
│                       │  responses, stop/edit-prompt controls, traffic intake│
│  • Security           │  ─────────────────────────────────────────────────  │
│    Assessment         │  [12-Tab Assessment Cockpit]                        │
│    Workspace          │  Scope, Attack Surface, Findings, Evidence DAG,     │
│                       │  Hypotheses, Plane A/B Experiments, Human Review    │
│  ───────────────────  │  ─────────────────────────────────────────────────  │
│  • Global Knowledge   │  [Knowledge Lab Drawer]                             │
│    Lab                │  Corpus management, PDF ingestion, graph extraction │
└───────────────────────┴─────────────────────────────────────────────────────┘
```

### 1. Copilot Investigations
- **Conversational Security Copilot**: Context-aware multi-turn reasoning with full investigation session persistence in SQLite.
- **Progressive Streaming & Real-Time Controls**: Server-Sent Events (SSE) streaming with graceful mid-stream Stop generation and inline Turn Edit & Regenerate controls.
- **Intelligent Response Merger**: Automatically prunes repetitive conversational boilerplate, normalizes unclosed code fences, and formats single-line model attribution (`Model: qwen2.5-coder:7b | Runtime: 0.82s`).
- **Telemetry & Traffic Ingestion**: Ingests HTTP traffic from Burp Suite, Reqable, PCAPdroid, and OpenAPI specs, reporting new observations, duplicates, and out-of-scope transactions separately.

### 2. Security Assessment Workspace (12 Tabs)
Organized across 12 formal operational lifecycle sections:
1. **Overview & Lifecycle Dashboard**: Rules of engagement, progress gauges, and real-time activity metrics.
2. **Authorization & Scope Boundaries**: Cryptographic authorization records, permitted domains, IP ranges, rate limits, and live `ScopeGate` preflight testing.
3. **Target Asset Inventory**: Interactive inventory of hostnames, IP addresses, APIs, web applications, and mobile packages with criticality ratings.
4. **Attack Surface & Endpoints**: Discovered HTTP endpoints, methods, authentication requirements, and parameter inventories.
5. **Cryptographic Artifact Registry**: SHA-256 verified artifact storage, quarantine states, and metadata.
6. **Research & Prior Art Knowledge**: Hybrid vector and BM25 search over MITRE ATT&CK, CWE, OWASP, and textbooks.
7. **Hypotheses & Security Invariants**: Active security hypotheses with epistemic origin tracking and grounding validation.
8. **Evidence Lineage Graph & Provenance**: Visual directed acyclic graph (DAG) tracing artifacts to observations and hypotheses.
9. **Controlled Experiments & Safe PoCs**:
   - *Plane A (Safe Lab)*: Automated deterministic execution against headless sandboxes.
   - *Plane B (Safe PoC)*: Non-destructive, human-guided manual reproduction steps with rollback templates.
10. **Findings Review & 13-Point Checklist**: Authoritative human verification modal enforcing all 13 verification criteria.
11. **Executive & Technical Reporting**: Export engine generating executive summaries, compliance matrices, and markdown reports.
12. **Memory, Knowledge & Audit Timeline**: Multi-tier research memory (episodic, semantic, procedural) with an immutable cryptographic audit log.

---

## Global Knowledge Lab & Graph RAG

### Textbook Ingestion & CFF Font Support
- Supports PDF, Markdown, and Plain Text files up to 100 MB.
- Embedded CFF Type 1 fonts (such as MinionPro-Regular commonly used in security books) are decoded via `fonttools` + `pypdf`, preserving complete glyph mapping with zero font-decoding warnings.
- Background persistent ingestion jobs with FIFO queueing, crash recovery, and cancellation support.

### Knowledge Graph Extraction
- Local extraction using Ollama (`qwen2.5-coder:7b` or `qwen2.5-coder:3b`).
- Schema-constrained JSON decoding extracting entities and relationships with exact supporting quotes.
- Workload-bounded generation (`num_predict=700`) with adaptive timeouts (60s for 3B, 120s for 7B).
- Bounded 3-retry handling: failed chunks are recorded in the ledger and can be retried independently without affecting successful extractions or document ingestion status (`INDEXED`).
- Graph integrity auditor detecting orphaned edges, ungrounded citations, and lifecycle staleness.

### Epistemic Grounding & Citation Validation
- Answers are verified against ingested corpus chunks first.
- If corpus evidence is insufficient, local model responses are explicitly disclaimed:
  > *General model knowledge — not verified against ingested sources*
- Fabricated citations, hallucinated document IDs, and synthetic page numbers are structurally rejected.

---

## Hardware-Aware Resource Governance

Ultron is specifically tuned for consumer workstations (e.g., AMD Ryzen 5, 24 GB RAM, NVIDIA GeForce RTX 3050 Laptop GPU with 4 GB VRAM):

- **Inference Concurrency Gate**: Strictly bounds concurrent GPU inference to `1`, preventing VRAM thrashing and CUDA out-of-memory crashes.
- **Priority Preemption**: Background graph extraction yields inference slots immediately when interactive user chat requests arrive.
- **Dual-Model Cascade**:
  - `qwen2.5-coder:3b` (~2.16 GB): Fits 100% in VRAM for high-throughput triage, extraction, and fast exploration (~70+ tokens/s).
  - `qwen2.5-coder:7b` (~5.0 GB): Partial VRAM offload (2.3 GB VRAM + 2.7 GB system RAM) for deep analytical synthesis (~10 tokens/s).

---

## Zero-Tolerance Security Invariants

The platform enforces **35 formal security invariants** across all subsystems:

| Invariant Family | Core Protections | Implementation |
| :--- | :--- | :--- |
| **Scope Invariant** | Fail-closed DNS TOCTOU defense; IP-level socket pinning; blocking of RFC 1918 / loopback addresses; redirect re-evaluation on every hop. | [`src/scope/gate.py`](src/scope/gate.py), [`src/scope/client.py`](src/scope/client.py) |
| **Grounding Invariant** | Zero tolerance for hallucinated identifiers. Every referenced asset, parameter, identity, and evidence ID must resolve to a valid canonical registry node. | [`src/evidence/vault.py`](src/evidence/vault.py) |
| **Epistemic Segregation** | Strict tagging: `DOCUMENTED`, `OBSERVED`, `DETERMINISTIC_DERIVATION`, `MODEL_PROPOSED`. Model outputs are never silently promoted to verified facts. | [`src/knowledge/canonical_models.py`](src/knowledge/canonical_models.py) |
| **Secret Quarantine** | Raw credentials (JWTs, API keys, session cookies) are quarantined into typed placeholders (`[REDACTED_JWT_1]`), preventing secret leakage in prompts or logs. | [`src/evidence/vault.py`](src/evidence/vault.py) |
| **Human Review Authority** | State transitions to `CONFIRMED` or `HUMAN_VERIFIED` require explicit human reviewer credentials and 13-point checklist satisfaction. | [`src/assessment/manager.py`](src/assessment/manager.py) |

---

## Repository Structure

```text
Ultron - Cybersecurity Copilot/
├── docs/                      # Architectural specifications, ADRs, and milestone reports
│   ├── ARCHITECTURE.md        # Foundational system architecture
│   ├── DECISIONS.md           # Architectural Decision Records (ADRs)
│   ├── M13_WORKSPACE_ARCHITECTURE.md
│   ├── M13_SECURITY.md        # Mathematical proofs of the 35 security invariants
│   ├── UI_AND_KNOWLEDGE_QA_REMEDIATION_REPORT.md
│   └── ULTRON_FINAL_ACCEPTANCE_AUDIT_REPORT.md
├── src/                       # Python backend engine
│   ├── assessment/            # Assessment lifecycle manager, RoE, and validation
│   ├── core/                  # Logging, atomic file writes, and integrity gates
│   ├── dashboard/             # FastAPI REST endpoints, auth, and workspace service
│   ├── engine/                # Ollama runner, structured JSON inference, streaming
│   ├── evidence/              # Telemetry adapters, RedactionVault, normalizer
│   ├── knowledge/             # Parsers, VaptKnowledgeStore, KnowledgeGraph, GraphExtractor
│   ├── memory/                # Isolated research memory (episodic, semantic, procedural)
│   ├── response/              # Response generator, merger, citation validator, router
│   ├── retrieval/             # Hybrid BM25 (FTS5) & vector retrieval, query rewriter
│   ├── scope/                 # ScopeGate, DNS TOCTOU resolver, socket IP pinning
│   └── workspace/             # Assessment workspace aggregator and global search
├── frontend/                  # React + TypeScript + Vite + Tailwind analyst dashboard
│   ├── src/
│   │   ├── components/workspace/  # 12 lifecycle tabs and modal dialogs
│   │   ├── api.ts                 # Type-safe backend client
│   │   └── types.ts               # Domain TypeScript interfaces
│   ├── test/                  # Node.js frontend test suites (36 tests)
│   └── package.json
├── tests/                     # Test suites (unit, integration, evaluation)
│   ├── unit/                  # Hermetic unit tests & invariant verification
│   └── integration/           # End-to-end API and pipeline integration tests
├── data/                      # Local data stores (SQLite DBs and logs ignored by git)
│   ├── models/                # Local ONNX embedding models (all-MiniLM-L6-v2)
│   └── vapt_corpus/           # Authoritative OWASP/CWE benchmark corpus
├── pyproject.toml             # Python build configuration and dependencies
├── run_local_ui.py            # Local orchestration script (FastAPI + Vite dev server)
└── README.md
```

---

## Quickstart & Installation

### 1. Prerequisites
- **Operating System**: Windows 10/11, Linux, or macOS
- **Python**: 3.11, 3.12, or 3.13
- **Node.js**: 18.0+
- **Ollama**: Installed and running locally:
  ```bash
  ollama pull qwen2.5-coder:3b
  ollama pull qwen2.5-coder:7b
  ```

### 2. Environment Setup
```powershell
# Clone the repository
git clone https://github.com/HyperJay-456/Ultron-Cybersecurity-Copilot.git
cd "Ultron - Cybersecurity Copilot"

# Create and activate virtual environment
python -m venv .venv
.venv\Scripts\activate      # Windows
# source .venv/bin/activate # Linux / macOS

# Install Python dependencies
pip install -e .
```

### 3. Frontend Setup
```powershell
cd frontend
npm install
npm run build
cd ..
```

### 4. Launch Ultron
You can start both the backend API and frontend workstation concurrently:
```powershell
python run_local_ui.py
```
Or start them individually:
```powershell
# Terminal 1: Backend API
uvicorn src.dashboard.app:app --host 127.0.0.1 --port 8000 --reload

# Terminal 2: Frontend
cd frontend
npm run dev
```
Open your browser at `http://127.0.0.1:5173`.

---

## Running Verification Test Suites

### Backend Unit & Integration Tests
```powershell
# Run all knowledge, graph, and response reliability unit tests (124 tests)
pytest tests/unit/test_persistent_ingestion_jobs.py \
       tests/unit/test_owasp_remediation.py \
       tests/unit/test_response_reliability.py \
       tests/unit/test_knowledge_parsers.py \
       tests/unit/test_knowledge_graph_extraction.py \
       tests/unit/test_knowledge_graph_retrieval.py \
       tests/unit/test_knowledge_graph_auditor.py \
       tests/unit/test_evaluation_isolation.py -v

# Run the formal security invariant verification suite (35 invariants)
pytest tests/unit/test_m13_security_invariants.py -v
```

### Frontend Test Suite
```powershell
npm test --prefix frontend
```

---

## Documentation Index

All technical reports, architecture specifications, and decision records are centralized in the [`docs/`](docs/) directory:

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md): Foundational system architecture.
- [`docs/DECISIONS.md`](docs/DECISIONS.md): Architectural Decision Records (ADRs).
- [`docs/M13_WORKSPACE_ARCHITECTURE.md`](docs/M13_WORKSPACE_ARCHITECTURE.md): Assessment workspace design.
- [`docs/M13_SECURITY.md`](docs/M13_SECURITY.md): Formal proof of all 35 security invariants.
- [`docs/UI_AND_KNOWLEDGE_QA_REMEDIATION_REPORT.md`](docs/UI_AND_KNOWLEDGE_QA_REMEDIATION_REPORT.md): UI and Knowledge Q&A remediation log.
- [`docs/ULTRON_FINAL_ACCEPTANCE_AUDIT_REPORT.md`](docs/ULTRON_FINAL_ACCEPTANCE_AUDIT_REPORT.md): Final acceptance audit and verification evidence.
- [`docs/STAGE_C_LOCAL_AI_KNOWLEDGE_GRAPH_REPORT.md`](docs/STAGE_C_LOCAL_AI_KNOWLEDGE_GRAPH_REPORT.md): Stage C Local AI Knowledge Graph Extraction.
- [`docs/STAGE_D_GRAPH_ASSISTED_RAG_REPORT.md`](docs/STAGE_D_GRAPH_ASSISTED_RAG_REPORT.md): Stage D Graph-Assisted RAG & Retrieval.
- [`docs/STAGE_E_GRAPH_INTEGRITY_REPORT.md`](docs/STAGE_E_GRAPH_INTEGRITY_REPORT.md): Stage E Graph Integrity Auditor.
- [`docs/RESPONSE_RELIABILITY_ANSWER_QUALITY_REPORT.md`](docs/RESPONSE_RELIABILITY_ANSWER_QUALITY_REPORT.md): Response reliability, merger, and citation reports.
- [`docs/REPRODUCIBILITY.md`](docs/REPRODUCIBILITY.md): Reproduction setup guide.
- [`docs/SECURITY_VAULT.md`](docs/SECURITY_VAULT.md): Secret quarantine boundaries and typed redaction.

---

## Safety, Ethics & Responsible Disclosure

This platform is engineered strictly for **authorized security research**, penetration testing within explicit written rules of engagement, and official bug bounty programs:

1. **Authorization Verification**: Operating without a cryptographically valid `AuthorizationRecord` signed by authorized human stakeholders is structurally prevented by software invariants.
2. **Deterministic Scope Containment**: `ScopeGate` prevents out-of-scope network traffic, loopback probes, or private subnet probing through fail-closed IP pinning.
3. **No Autonomous Exploitation**: The platform does not exploit vulnerabilities autonomously. Plane B manual reproduction steps are presented strictly to human operators for manual verification.
4. **Responsible Disclosure**: Reports emphasize defensive remediation, root cause analysis, and coordinated vulnerability disclosure standards.
