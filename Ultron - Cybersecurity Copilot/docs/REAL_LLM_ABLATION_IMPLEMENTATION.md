# Real Local LLM Ablation Study: Technical Implementation

**Platform**: Local AI-Assisted Bug Bounty Research Platform (v6 Final)  
**Experiment**: EXP-0006  
**Document**: `docs/REAL_LLM_ABLATION_IMPLEMENTATION.md`  
**Date**: September 17, 2026  
**Author**: Antigravity Research Engineering  

---

## 1. Architectural Overview & Hardening Summary

In Phase 1, the synthetic and hand-coded decision heuristics previously in `src/eval/ablation.py` (lines 48–272) were replaced with a genuine, real local LLM-driven reasoning pipeline. The benchmark directly evaluates the core research question:

> *"Under a fixed observable evidence budget, does an explicit `Application Model → Security Invariant → Evidence Gap → Hypothesis → Experiment` architecture improve security-hypothesis precision, appropriate abstention quality, and human investigation efficiency compared to conventional LLM + RAG architectures?"*

---

## 2. Strict Research Integrity: Ground-Truth Isolation

To guarantee scientific validity, the reasoning engine and prompt builders are structurally prohibited from accessing ground truth:

```
                      [ Benchmark Scenario (EvaluationScenario) ]
                                          │
                  ┌───────────────────────┴───────────────────────┐
                  ▼                                               ▼
    [ ObservableScenarioContext ]                      [ DeterministicScorer ]
    - target_asset (method, path)                      - ground_truth_vulnerable
    - parameters (param_id, location)                  - vulnerable_variant
    - initial_evidence (traffic facts)                 - expected_decision
    - identities (user_a, user_b)                                 ▲
    - category_id (e.g. API-BOLA-001)                             │
                  │                                               │
                  ▼                                               │
       [ Tracks A, B, C, D, E ]                                   │
      (Reasoning Engine / Local LLM)                              │
                  │                                               │
                  └────────────── [ Model Decision ] ─────────────┘
                               (HYPOTHESIS / ABSTAIN)
```

### Technical Enforcement Points:
1. **`ObservableScenarioContext` Adapter**:  
   Scenarios are passed through `ObservableScenarioContext.from_scenario(scenario)`. This adapter strictly extracts only public, observable fields. An explicit runtime assertion confirms `ground_truth_vulnerable`, `vulnerable_variant`, and `expected_decision` do not exist on the object.
2. **Zero Oracle Tokens in Prompts**:  
   Unit test `test_ground_truth_cannot_enter_reasoning_inputs` serializes the context dictionary and verifies zero occurrence of `ground_truth`, `vulnerable_variant`, or `expected_decision`.
3. **External Scorer Evaluation**:  
   Ground truth is accessed exclusively by `DeterministicScorer` after model decisions have been emitted and validated.

---

## 3. Systematic Architecture Isolation: Tracks A through E

| Track Name | Reasoning Mechanism | Observable Inputs Provided | What is Explicitly Disabled |
|:---|:---|:---|:---|
| **Track A: Rules Only** | Deterministic static regex/keyword predicates (0 LLM). | Target endpoint path, method, and parameters. | LLM inference, RAG retrieval, state machines, security invariants, experiment feedback. |
| **Track B: RAG + 3B** | `qwen2.5-coder:3b` via Ollama (`temperature=0.0`). | Top-K retrieved evidence chunks + target asset. | Application Model, Security Invariant derivation, Experiment feedback. |
| **Track C: RAG + 7B** | `qwen2.5-coder:7b` via Ollama (`temperature=0.0`). | Top-K retrieved evidence chunks + target asset. | Application Model, Security Invariants, Experiment feedback. |
| **Track D: App Model + Invariants** | `qwen2.5-coder:7b` via Ollama (`temperature=0.0`). | Top-K retrieved evidence + Application Model + Derived Invariants. | Closed-loop execution feedback (proposes experiments, but execution is withheld). |
| **Track E: Full V6 Architecture** | `qwen2.5-coder:7b` via Ollama (`temperature=0.0`). | Top-K retrieved evidence + Application Model + Invariants + Simulator Return. | Nothing. Proposes discriminative experiments, executes against `HeadlessSimulator`, and revises decision via closed loop. |

---

## 4. RAG Verification & Observability Subsystem

For Tracks B through E, retrieval operations are mediated by `ScenarioRetriever` and logged in a structured `RetrievalTrace`:

### Recorded Fields:
1. `retrieval_query`: Exact query string formulated from target endpoint method, path template, and category ID (e.g. `GET /api/v1/invoices/{id} API-BOLA-001`).
2. `retrieved_evidence_ids`: Candidate fact IDs identified (e.g. `["FACT-SAAS_BILLING-BOLA-INV-V"]`).
3. `retrieval_method`: Retrieval algorithm executed (`hybrid_rrf` combining Reciprocal Rank Fusion over SQLite FTS5 BM25 and `LocalVectorStore` dense cosine similarity).
4. `retrieval_ranking`: Ranked list of candidates with individual RRF scores and source tools.
5. `token_budget_cropping`: Explicit token count audit (`input_chunks`, `budgeted_chunks`, `token_budget`).
6. `prompt_evidence_context`: Exact formatted text block inserted into the prompt (`EVIDENCE [FACT-ID] ...`).
7. `zero_results`: Explicit boolean indicating if retrieval returned zero matches, preventing silent fallbacks to ground truth.

---

## 5. Ephemeral Grounding Validation

Model outputs are validated in real time by `GroundingValidator` against an ephemeral in-memory SQLite database initialized per scenario:
- **Asset Existence**: Verifies cited `asset_id` matches the target context.
- **Parameter Parentage**: Confirms cited `parameter_ids` belong to the cited asset.
- **Fact Provenance**: Confirms cited `supporting_evidence_ids` exist in the observable evidence store.
- **Epistemic Constraint**: Enforces `MODEL_PROPOSED` status and blocks forbidden states (`CONFIRMED`, `OBSERVED`).

---

## 6. Hardware Profiling & Latency Baseline

Evaluated on local hardware:
- **Host OS**: Windows 11 (64-bit)
- **CPU**: AMD Ryzen 5 5600H (6 cores, 12 threads)
- **RAM**: 24 GB DDR4
- **GPU**: NVIDIA GeForce RTX 3050 Laptop GPU (4 GB VRAM, Driver: 616.92)
- **Ollama**: v0.34.1 local HTTP daemon

### Profiling Summary:
- **`qwen2.5-coder:3b`**:
  - GPU Residency: 100% VRAM (~2,135 MiB allocated).
  - Inference Latency: **3.98s** average per scenario.
- **`qwen2.5-coder:7b`**:
  - Memory Residency: Hybrid CPU/GPU offload (~4,200 MiB total allocation).
  - Track C (RAG 7B) Latency: **18.26s** average per scenario.
  - Track D (Invariants 7B) Latency: **23.70s** average per scenario.
  - Track E (Full V6, 2 passes + simulator) Latency: **43.21s** average per scenario.
