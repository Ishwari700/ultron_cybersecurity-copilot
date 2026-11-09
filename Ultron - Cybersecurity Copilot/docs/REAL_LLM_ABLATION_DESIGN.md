# Real LLM Ablation Study Design: Scientific Architecture Isolation

**Document**: `docs/REAL_LLM_ABLATION_DESIGN.md`  
**Platform**: Local AI-Assisted Bug Bounty Research Platform (v6 Final)  
**Status**: Authoritative Architectural Design (Phase 0 Deliverable)  
**Author**: Antigravity Research Engineering  

---

## 1. Core Research Question & Integrity Axiom

### 1.1 The Research Question
> *"Under a fixed observable evidence budget, does an explicit `Application Model → Security Invariant → Evidence Gap → Hypothesis → Experiment` architecture improve security-hypothesis precision, appropriate abstention quality, and human investigation efficiency compared to conventional LLM + RAG architectures?"*

### 1.2 The Non-Negotiable Ground-Truth Isolation Axiom

```
                         [ BENCHMARK DATASET ]
                                   │
              ┌────────────────────┴────────────────────┐
              ▼                                         ▼
    [ OBSERVABLE EVIDENCE ]                   [ GROUND TRUTH LABELS ]
   (Traffic, Schemas, Logs)                (vulnerable_variant, is_vuln)
              │                                         │
              ▼                                         │
    [ REASONING ENGINE / LLM ]                          │
   (Tracks A, B, C, D, and E)                           │
              │                                         │
              ▼                                         ▼
      [ MODEL DECISION ] ───────────────► [ BENCHMARK SCORER ]
 (HYPOTHESIS / ABSTENTION)                 (Precision, Yield, F1)
```

**Absolute Invariant**: Ground truth (`scen.ground_truth_vulnerable`, `scen.vulnerable_variant`) flows **ONLY** to the benchmark evaluation scorer. Ground truth **MUST NEVER** enter:
1. Retrieval queries or token budgeting
2. Application model state
3. Security invariant derivation
4. Prompt construction or system context
5. Experiment proposal generation or parameter selection
6. The reasoning model runtime

All tracks must operate exclusively upon the **exact same observable evidence budget** (token count, HTTP interaction facts, OpenAPI schemas).

---

## 2. Fixed Evidence Budget Tiers

To isolate architectural contributions from prompt-stuffing, all tracks are evaluated across three standardized budget tiers:

| Budget Tier | Token Budget (`T_max`) | Retrieval Evidence Chunks (`K_max`) | Max Experiments Allowed (`E_max`) |
| :--- | :--- | :--- | :--- |
| **LOW** | 1,024 tokens | 3 chunks | 1 proposal / execution |
| **MEDIUM** | 2,048 tokens | 5 chunks | 3 proposals / executions |
| **HIGH** | 4,096 tokens | 10 chunks | 5 proposals / executions |

---

## 3. Systematic Architecture Isolation: Tracks A through E

### Track A: Rules-Only Baseline (Zero-LLM Deterministic Heuristic)
* **Objective**: Measure performance of traditional deterministic static predicates (regex matching, keyword detection, URL path heuristics) without an LLM.
* **Input Evidence**: Raw target asset metadata (`method`, `raw_path`, parameters).
* **Available Retrieval**: Disabled.
* **Available Application Model**: Disabled.
* **Available Invariants**: Disabled.
* **Available Experiment Feedback**: Disabled.
* **LLM Model**: None (Pure Python deterministic regex/heuristic matching).
* **Output**: Binary decision (`HYPOTHESIS` if pattern matches known sensitive path patterns, else `NO_RELEVANT_FUNCTIONALITY`).
* **What is Disabled**: LLM inference, semantic retrieval, state machines, invariants, active experimentation.
* **Hypothesized Failure Mode**: High False Positive rate on patched assets matching path keywords; False Negatives on multi-step lifecycle transitions.

---

### Track B: Conventional RAG + 3B Model
* **Objective**: Baseline standard lightweight RAG pipeline with direct traffic chunk retrieval.
* **Input Evidence**: Top-K retrieved evidence statements from `evidence_items` via hybrid BM25 + cosine search within budget `T_max`.
* **Available Retrieval**: Hybrid sparse/dense retrieval over raw traffic logs.
* **Available Application Model**: Disabled (No asset mutability, parameter volatility, or role state).
* **Available Invariants**: Disabled (No documented or derived invariant rules).
* **Available Experiment Feedback**: Disabled.
* **LLM Model**: `qwen2.5-coder:3b` (Local Ollama, temp=0.0).
* **Output**: `HypothesisModelOutput` (decision, reasoning_summary, cited fact IDs).
* **What is Disabled**: Application Model, Security Invariant derivation, Evidence Gap identification, Experiment Simulator loop.
* **Hypothesized Failure Mode**: Semantic pattern matching hallucinating vulnerabilities on patched endpoints; truncation-induced hallucinations under LOW budget.

---

### Track C: Conventional RAG + 7B Model
* **Objective**: Measure whether simply scaling model parameters from 3B to 7B resolves structural hallucination and abstention failures under identical conventional RAG.
* **Input Evidence**: Top-K retrieved evidence statements from `evidence_items` within budget `T_max`.
* **Available Retrieval**: Hybrid sparse/dense retrieval over raw traffic logs.
* **Available Application Model**: Disabled.
* **Available Invariants**: Disabled.
* **Available Experiment Feedback**: Disabled.
* **LLM Model**: `qwen2.5-coder:7b` (Local Ollama, temp=0.0).
* **Output**: `HypothesisModelOutput` (decision, reasoning_summary, cited fact IDs).
* **What is Disabled**: Application Model, Security Invariants, Evidence Gaps, Experiment Simulator loop.
* **Hypothesized Failure Mode**: Improved syntax compliance and grounding fidelity, but persistent inability to discriminate patched vs vulnerable variants without execution feedback.

---

### Track D: RAG + Application Model + Security Invariants (Open-Loop V6)
* **Objective**: Measure the isolated contribution of explicit epistemic abstractions (Application Model + Security Invariants + Evidence Gaps) *without* experiment execution feedback.
* **Input Evidence**: Top-K retrieved evidence + structured Application Model (`mutability`, `liveness`) + derived Security Invariants (`DOCUMENTED`, `DETERMINISTIC_DERIVATION`).
* **Available Retrieval**: Hybrid retrieval with Exact-Parameter Gate (FTS5 identifier protection).
* **Available Application Model**: Enabled (`assets`, `parameters`, `application_mutability`).
* **Available Invariants**: Enabled (`DOCUMENTED` and `DETERMINISTIC_DERIVATION` invariants provided in prompt).
* **Available Experiment Feedback**: Disabled (Proposes experiments, but execution feedback is withheld).
* **LLM Model**: `qwen2.5-coder:7b` (Local Ollama, temp=0.0).
* **Output**: `HypothesisModelOutput` including structured `experiment_proposal` and `missing_evidence`.
* **What is Disabled**: Experiment Simulator execution; observation incorporation.
* **Hypothesized Failure Mode**: Generates highly discriminative experiment proposals and recognizes evidence gaps, but must abstain (`INSUFFICIENT_EVIDENCE`) or produce unconfirmed hypotheses due to missing empirical feedback.

---

### Track E: Full V6 Platform (Closed-Loop Autonomous Invariant Falsification)
* **Objective**: Measure the complete closed-loop architecture where proposed experiments are safely executed against the target environment (Headless Simulator / Scope-Gated API) and observations update the hypothesis state.
* **Input Evidence**: Initial evidence budget + empirical experiment observation returns (`HTTP 200` vs `HTTP 403` vs `HTTP 500`).
* **Available Retrieval**: Full hybrid retrieval with Exact-Parameter Gate.
* **Available Application Model**: Enabled (updated with experiment results).
* **Available Invariants**: Enabled (evaluated against empirical observation).
* **Available Experiment Feedback**: **Enabled** (executes up to `E_max` experiments; observations fed back into reasoning context).
* **LLM Model**: `qwen2.5-coder:7b` (Local Ollama, temp=0.0).
* **Output**: Revised `HypothesisRecord` (`Confirmed`, `Rejected`, or `Abstained`) with verified empirical evidence.
* **What is Disabled**: Nothing. Full closed-loop reasoning pipeline.
* **Hypothesized Behavior**: Near-zero False Positives on patched variants (falsified by HTTP 403/401 observation); appropriate abstention when budget `E_max` is insufficient to resolve multi-step dependencies; high human investigation efficiency.

---

## 4. Track Comparison Matrix

| Architectural Feature | Track A (Rules) | Track B (RAG 3B) | Track C (RAG 7B) | Track D (Open V6) | Track E (Full V6) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Reasoning Model** | None | 3B | 7B | 7B | 7B |
| **Token Budget Parity** | N/A | Enforced | Enforced | Enforced | Enforced |
| **Hybrid Retrieval + Gate** | No | Basic | Basic | Gated | Gated |
| **Application Model** | No | No | No | **Yes** | **Yes** |
| **Security Invariants** | No | No | No | **Yes** | **Yes** |
| **Evidence Gap Detection** | No | No | No | **Yes** | **Yes** |
| **Experiment Proposal** | No | No | No | **Yes** | **Yes** |
| **Simulator Execution Loop**| No | No | No | No | **Yes** |
| **Oracle Isolation** | 100% | 100% | 100% | 100% | 100% |

---

## 5. Statistical Rigor & Metric Reporting

When real LLM ablation is executed in future phases, the evaluation framework must record and report:
1. **Decision Correctness vs Grounding Validity**: Strictly separate canonical ID validity (whether cited IDs exist in the prompt) from factual grounding (whether the evidence logically supports the claim).
2. **Independent Metrics**:
   * Model Decision Precision = $TP / (TP + FP)$
   * Model Decision Recall = $TP / (TP + FN)$
   * Useful Hypothesis Yield = $TP_{\text{useful}} / \text{Total Vulnerable Scenarios}$
   * Appropriate Abstention Rate = $TN_{\text{abstained}} / \text{Total Patched Scenarios}$
3. **Statistical Confidence**: Report Wilson score 95% confidence intervals with explicit sample sizes ($N=20, 50, 100$) and compute paired McNemar contingency tests between Track E and Track C.
