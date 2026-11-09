# Architecture: Local AI-Assisted Bug Bounty Research Platform (V6)

## 1. System Overview
The platform is an evidence-grounded, local-first, human-in-the-loop security research assistant designed to operate within strict consumer-hardware constraints (AMD Ryzen 5 5600H, 24GB RAM, NVIDIA RTX 3050 4GB VRAM).

The system explicitly rejects autonomous exploitation. The core scientific workflow follows:

```text
Evidence Ingestion (Provenance & Trust Tagged)
   │
   ▼
Canonical Observation Normalization & Redaction
   │
   ▼
Evidence Graph (Assets, Parameters, Identities, Workflows)
   │
   ▼
Security Invariant Derivation (Epistemic Origin Tagged)
   │
   ▼
Evidence Gap Identification
   │
   ▼
Target-Evidence RAG Context Assembly (Token Budgeted)
   │
   ▼
Security Hypothesis Formulation (Structured Output)
   │
   ▼
Deterministic Grounding Validation (ID & Structural Relationship Checks)
   │
   ▼
Discriminative Experiment Proposal Generation
   │
   ▼
Human Approval & Testing / Headless Simulator
   │
   ▼
New Observed Evidence Ingestion
   │
   ▼
Hypothesis & Invariant Revision (Closed Reasoning Loop)
```

---

## 2. Hard Invariants & Epistemic Boundaries

### Scope Invariant
No network activity occurs without a validated, cryptographically hashed `ScopeDecisionObject`. All hostname destinations are resolved to IP addresses and verified against private/loopback/link-local/reserved blocks (RFC 1918, RFC 3927, RFC 4193, loopback, broadcast) to prevent DNS rebinding (TOCTOU). Outbound HTTP requests pin the resolved IP address directly to the connection socket. Every redirect hop is independently re-evaluated against scope rules.

### Grounding Invariant
The LLM cannot invent canonical identifiers. Every cited asset ID, parameter ID, identity ID, and fact ID must exist within the scenario/application registry or `evidence.db`, and their structural relationships must hold (e.g., a parameter must belong to its referenced parent asset). Any hypothesis referencing invalid IDs is rejected or downgraded to insufficient evidence.

### Epistemic Invariant
Data objects maintain strict segregation across four epistemic origins:
1. `DOCUMENTED`: Explicitly stated in static documentation or OpenAPI specifications.
2. `OBSERVED`: Directly captured from live HTTP/network traffic via adapters.
3. `DETERMINISTIC_DERIVATION`: Mechanically computed by deterministic code (e.g., temporal request adjacency).
4. `MODEL_PROPOSED`: Inferred or hypothesized by the LLM. Model assumptions are never automatically elevated to facts without supporting experimental verification.

### Provenance & Isolation Invariant
External inputs (HTTP response bodies, docs, web pages) are tagged with `source` and `trust: UNTRUSTED`. RAG contexts delimit this untrusted content with boundary markers to ensure the LLM treats them strictly as data, never as system instructions. Hostile prompt-injection attacks contained in target data cannot hijack system behavior.

---

## 3. Hardware & Pipeline Scheduling

To prevent CPU/IO and VRAM contention on the 6-core Ryzen 5 5600H and RTX 3050 (4GB VRAM):
- **Phased & Synchronous Execution**:
  - **Phase 1 (Recon & Ingestion)**: 100% CPU allocation to adapters, normalizers, and redaction vault.
  - **Phase 2 (Indexing & Retrieval)**: 100% CPU allocation to SQLite FTS5 (BM25) full-text indexing and exact-identifier gating.
  - **Phase 3 (Reasoning Sweeps)**: 100% GPU allocation to Ollama (`qwen2.5-coder:3b` for high-volume sweeps; `qwen2.5-coder:7b` for deep reasoning).
- **Context Pinning**: `num_ctx` is pinned to 2048–4096 tokens with deterministic token budgeting (`TokenBudgetController`) to prevent KV-cache VRAM overflow and paging to system RAM.

---

## 4. Subsystem Wiring & Implementation Status

To maintain strict engineering rigor, every subsystem in the repository is audited and classified into one of four operational states:

1. **Implemented and Active**: Wired into the running pipeline, covered by automated tests, and actively used during live operations or benchmark ablation.
2. **Implemented but Unused**: Fully implemented and tested in isolation, but not invoked in the primary EXP-0006 benchmark flow (e.g., live proxy capture adapters awaiting M4).
3. **Partial / Prototype**: Wrapper or partial implementation exists with initial tests, but not yet integrated into the production pipeline.
4. **Planned**: Architectural design defined in roadmaps, but no production code written yet.

### Operational Status Inventory

| Subsystem | Primary Implementation Files | Operational Status | Description & Wiring |
| :--- | :--- | :--- | :--- |
| **ScopeGate & Client** | [`src/scope/gate.py`](src/scope/gate.py), [`src/scope/client.py`](src/scope/client.py) | **Implemented and Active** | TOCTOU IP pinning, CIDR filtering, redirect validation, rate limits, and disallowed techniques enforcement. |
| **RedactionVault** | [`src/evidence/vault.py`](src/evidence/vault.py) | **Implemented and Active** | Quarantines secrets into typed placeholders (`[REDACTED_JWT_1]`) while preserving cross-identity correlation. |
| **Compressor & Normalizer** | [`src/evidence/compressor.py`](src/evidence/compressor.py), [`src/evidence/normalizer.py`](src/evidence/normalizer.py) | **Implemented and Active** | Samples large JSON lists and truncates long HTTP response bodies for deterministic token budgeting. |
| **Observation Adapters** | [`src/evidence/adapters/`](src/evidence/adapters/) (Burp, Reqable, PCAPdroid, OpenAPI, Generic) | **Implemented but Unused** | Parsers convert raw proxy captures into canonical `Observation` objects. Tested in `test_adapters.py`. Unused in EXP-0006 (synthetic scenarios); reserved for M4. |
| **EvidenceGraph & Workflows** | [`src/graph/workflow_engine.py`](src/graph/workflow_engine.py), [`src/graph/models.py`](src/graph/models.py) | **Implemented and Active** | Derives temporal workflows and entity relationships, feeding application models into Track D/E prompt generation. |
| **InvariantEngine** | [`src/invariants/engine.py`](src/invariants/engine.py), [`src/invariants/models.py`](src/invariants/models.py) | **Implemented and Active** | Synthesizes security invariants with epistemic origins (`OBSERVED`, `DOCUMENTED`, `DETERMINISTIC_DERIVATION`). |
| **ScenarioRetriever** | [`src/retrieval/hybrid.py`](src/retrieval/hybrid.py), [`src/retrieval/budget.py`](src/retrieval/budget.py) | **Implemented and Active** | SQLite FTS5 (BM25) full-text retrieval + exact-identifier gating + strict token budget cropping. Fully traced in EXP-0006. |
| **ChromaVectorStore** | [`src/retrieval/vector_store.py`](src/retrieval/vector_store.py) | **Partial / Prototype** | ChromaDB wrapper implemented and tested; unused in offline benchmark (which runs purely on FTS5 + exact gate). Reserved for M3 VAPT RAG. |
| **ReasoningRunner** | [`src/engine/runner.py`](src/engine/runner.py), [`src/engine/models.py`](src/engine/models.py) | **Implemented and Active** | Live Ollama runner (`3b` / `7b`), JSON schema enforcement, prompt isolation, and fallbacks. |
| **GroundingValidator** | [`src/validation/grounding.py`](src/validation/grounding.py) | **Implemented and Active** | Rejects hallucinated IDs, unparented parameters, and invalid evidence references. |
| **HeadlessSimulator** | [`src/eval/simulator.py`](src/eval/simulator.py), [`src/eval/synthetic_app.py`](src/eval/synthetic_app.py) | **Implemented and Active** | Closed-loop experiment execution returning tri-state outcomes (`SUPPORTING`, `CONTRADICTING`, `UNRESOLVED`). |
| **HypothesisStateMachine** | [`src/hypothesis/state_machine.py`](src/hypothesis/state_machine.py), [`src/hypothesis/experiment.py`](src/hypothesis/experiment.py) | **Implemented and Active** | Manages hypothesis transitions and generates discriminative experiment proposals. |
| **Ablation Harness & Scorer** | [`src/eval/ablation.py`](src/eval/ablation.py), [`src/eval/scorer.py`](src/eval/scorer.py), [`src/eval/scenarios.py`](src/eval/scenarios.py) | **Implemented and Active** | 5-track comparative ablation benchmark across 84 scenarios with ground-truth isolation and metric calculation. |
| **Dashboard API** | [`src/dashboard/app.py`](src/dashboard/app.py) | **Partial / Prototype** | FastAPI backend with safety confirmation gates implemented and tested; web UI frontend is a prototype awaiting M9. |
| **3B → 7B Cascade Router** | `src/engine/cascade.py` | **Planned** | Roadmap Milestone M2. Dynamic complexity estimation, triage gating, and escalation. |
| **VAPT Knowledge Base RAG** | `src/retrieval/vapt_kb.py` | **Planned** | Roadmap Milestone M3. External methodology, vulnerability pattern, and technique retrieval. |
| **Automated Proxy Ingestion** | `src/evidence/watcher.py` | **Planned** | Roadmap Milestone M4. Live file watcher and streaming ingestion from Burp/Reqable. |
| **Case Memory & Correction** | `src/memory/` | **Planned** | Roadmap Milestone M5. Storing verified mistakes, false-positive corrections, and investigator feedback. |
| **Continuous Learning Loop** | `src/calibration/` | **Planned** | Roadmap Milestones M6–M8. Offline calibration, fine-tuning data generation, and regression tracking. |

---

## 5. Current vs Future Architecture Boundary

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│ CURRENT VALIDATED SYSTEM (Milestones M0 + M1 + EXP-0006)                     │
│                                                                             │
│  [ScopeGate + Client]      [RedactionVault]         [Evidence.db / SQLite]  │
│  - TOCTOU IP Pinning       - Typed Placeholders     - Hard Triggers         │
│  - Private CIDR blocking   - Identity Correlation   - FTS5 (BM25) Full-text │
│                                                                             │
│  [Evidence Graph]          [Invariant Engine]       [Scenario Retriever]    │
│  - Temporal Workflows      - Epistemic Tagging      - Exact ID Gating       │
│  - Asset/Param Trees       - Invariant Derivation   - Token Budget Cropping │
│                                                                             │
│  [Reasoning Engine]        [Grounding Validator]    [Closed Reasoning Loop] │
│  - Ollama 3B & 7B Live     - Canonical ID check     - Simulator (Tri-state) │
│  - JSON Schema Enforced    - Parentage check        - Hypothesis Revision   │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ FUTURE ROADMAP EXTENSIONS (Milestones M1.5 - M9)                            │
│                                                                             │
│  [Milestone M1.5] Benchmark expansion, test suite freeze, finalization      │
│  [Milestone M2]   3B → 7B Cascade Router & Triage Escalation                │
│  [Milestone M3]   VAPT Knowledge Base RAG & Semantic Retrieval              │
│  [Milestone M4]   Live Proxy Ingestion & Stream Watchers                    │
│  [Milestone M5]   Case Memory & False-Positive Correction Storage           │
│  [Milestones M6-8]Continuous Learning, Offline Calibration & DPO Tuning     │
│  [Milestone M9]   Human-in-the-Loop Web Dashboard Interface                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 6. Security Vault & Secret Boundary

Raw secrets (JWTs, API keys, passwords, session tokens) are quarantined by the `RedactionVault`:
- **Zero Leakage**: Secrets never enter prompts, vector store embeddings, SQLite persistent evidence statements, or ordinary logs.
- **Correlation Preservation**: Consistent typed placeholders (e.g. `[REDACTED_JWT_1]`) maintain identity equivalence across interactions for authorization reasoning without exposing secret material.
- **Detailed Specification**: See [SECURITY_VAULT.md](docs/SECURITY_VAULT.md) for full dataflow diagrams and threat boundaries.

---

## 7. Evaluation & Ablation Methodology

The experimental framework operates across five distinct tracks with strict ground-truth isolation:
- **Track A (Direct LLM)**: Raw prompt without target evidence or structured invariant guidance.
- **Track B (LLM + Unfiltered Evidence RAG)**: Target evidence injected via BM25 retrieval without token budget cropping.
- **Track C (LLM + Target-Evidence RAG)**: BM25 retrieval + exact-identifier gating + strict token budget cropping.
- **Track D (V6 Reasoning Architecture)**: Application model + Security invariants + Target-evidence RAG + Grounding validation.
- **Track E (V6 + Closed Reasoning Loop)**: Track D + Discriminative experiment proposal + Headless simulator execution + Hypothesis revision.

All evaluation metrics are computed using Wilson score 95% confidence intervals and exact McNemar paired contingency tests, fully audited in [EXP0006_FINAL_METHODOLOGY_AUDIT.md](docs/EXP0006_FINAL_METHODOLOGY_AUDIT.md).
