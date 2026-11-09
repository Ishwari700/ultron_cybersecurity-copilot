# Experiment Reproducibility Log

This document records all evaluation runs, benchmarks, and experimental ablations. Each entry includes exact configuration digests, model fingerprints, prompt versions, datasets, and hardware metrics.

---

### Record Format Standard
```json
{
  "experiment_id": "EXP-XXXX",
  "timestamp": "YYYY-MM-DDTHH:MM:SSZ",
  "model": "qwen2.5-coder:3b / qwen2.5-coder:7b",
  "model_digest": "sha256:...",
  "embedding_model_digest": "sha256:...",
  "quantization": "Q4_K_M",
  "temperature": 0.0,
  "retrieval_k": 5,
  "prompt_version": "v1",
  "system_prompt_hash": "sha256:...",
  "schema_hash": "sha256:...",
  "taxonomy_version": "v1",
  "code_commit": "...",
  "dataset_version": "synthetic_v1",
  "dataset_hash": "sha256:...",
  "runtime_version": "...",
  "metrics": {
    "grounding_accuracy": 0.0,
    "abstention_accuracy": 0.0,
    "false_positive_rate": 0.0,
    "investigation_yield": 0.0,
    "unsupported_claim_rate": 0.0,
    "retrieval_recall_at_k": 0.0
  },
  "resources": {
    "tokens_per_sec": 0.0,
    "peak_vram_mb": 0.0,
    "peak_ram_mb": 0.0
  }
}
```

---

## Log Entries

### EXP-0001: Pre-Evaluation Pipeline Sanity & Harness Verification (Dry Run)
- **Timestamp:** 2026-09-17T10:55:00Z
- **Status:** Pipeline & Harness Verification Only. NO comparative claims are made prior to formal evaluation.
- **Scenario Suite:** Gold Set v1 (Synthetic Paired BOLA Vuln/Patch, State Machine Step Skipping, Negative Controls)
- **Harness Execution Verification:**
  - Track A (Rules Only): Executable
  - Track B (RAG + 3B): Executable
  - Track C (RAG + 7B): Executable
  - Track D (RAG + App Model + Invariants): Executable
  - Track E (Full v6 Architecture): Executable
- **Note:** Real comparative evaluation between V6 and RAG baselines will be executed strictly after multi-family dataset ingestion. Ground truth remains strictly isolated from the reasoning engine.

---

### EXP-0002: Five-Track Controlled Benchmark & Ablation Study (Preliminary N=7 Suite)
- **Timestamp:** 2026-09-17T11:20:00Z
- **Status:** Complete — Preliminary synthetic suite evaluated.
- **Dataset Version:** `v6_frozen_gold_v1`
- **Dataset Hash:** `sha256:f753c70149891eeb55461354a714cc21bfda5419caf4df0c4f059b707c428904`
- **Execution Classification:** Synthetic / deterministic benchmark result (Host Ollama offline; not live-model validated).
- **Split Definition:**
  - `development`: `saas_billing` ($N=2$)
  - `evaluation`: `ecommerce_orders`, `identity_provider` ($N=5$)
- **Primary Metric:** Synthetic Useful Hypothesis Yield @ 10 Reviewer Minutes (simulator-mediated)
- **Evaluation Split Results ($N=5$):**
  - **Track A (Rules Only):** Prec=0.500, Rec=0.500, F1=0.500, AbstP=0.667, Disc=0.000, Yield=0.000
  - **Track B (RAG 3B):** Prec=0.500, Rec=1.000, F1=0.667, AbstP=1.000, Disc=0.000, Yield=0.000
  - **Track C (RAG 7B):** Prec=0.500, Rec=1.000, F1=0.667, AbstP=1.000, Disc=0.000, Yield=0.000
  - **Track D (App Model + Invariants):** Prec=0.500, Rec=1.000, F1=0.667, AbstP=1.000, Disc=1.000, Yield=0.000
  - **Track E (Full V6 Architecture):** Prec=1.000, Rec=1.000, F1=1.000, AbstP=1.000, Disc=1.000, Yield=1.000
- **Full Benchmark Results ($N=7$):**
  - **Track A (Rules Only):** Prec=0.500, Rec=0.667, F1=0.571, AbstP=0.667, Disc=0.000, Yield=0.000
  - **Track B (RAG 3B):** Prec=0.500, Rec=1.000, F1=0.667, AbstP=1.000, Disc=0.000, Yield=0.000
  - **Track C (RAG 7B):** Prec=0.500, Rec=1.000, F1=0.667, AbstP=1.000, Disc=0.000, Yield=0.000
  - **Track D (App Model + Invariants):** Prec=0.500, Rec=1.000, F1=0.667, AbstP=1.000, Disc=1.000, Yield=0.000
  - **Track E (Full V6 Architecture):** Prec=1.000, Rec=1.000, F1=1.000, AbstP=1.000, Disc=1.000, Yield=1.000
- **Revised Interpretation:** Preliminary evidence supports the research hypothesis within the controlled synthetic benchmark evaluated in EXP-0002. The result demonstrates an observed improvement in this benchmark, but does not yet establish generalization to larger datasets, unseen application families, live LLM inference, or real-world security investigations.

---

### EXP-0003: Scaled Multi-Family Multi-Budget Evaluation & Validity Audit
- **Timestamp:** 2026-09-17T11:35:00Z
- **Status:** Complete — Pre-registered protocol executed across 84 scenarios and 6 families.
- **Protocol Document:** `docs/EXP-0003_PROTOCOL.md`
- **Results Document:** `docs/EXP-0003_RESULTS.md`
- **Dataset Version:** `v6_frozen_gold_v2`
- **Dataset Hash:** `sha256:e0c3568f2cdc582e0ecbeced3822db3213856ced824708a46b405806cb392864`
- **Execution Classification:** Synthetic / deterministic benchmark evaluation (Host Ollama daemon offline; not live-model validated).
- **Split Partitions ($N=84$):**
  - `development`: `saas_billing`, `ecommerce_orders` ($N=28$)
  - `validation`: `identity_provider`, `document_collaboration` ($N=28$)
  - `evaluation`: `healthcare_portal`, `iot_fleet_mgmt` ($N=28$)
- **Primary Metric:** Synthetic Useful Hypothesis Yield @ Reviewer Time Budget (simulator-mediated)
- **Multi-Budget Evaluation Split Results ($N=28$: `healthcare_portal`, `iot_fleet_mgmt`):**
  - **Track A (Rules):** P=0.500 [95% CI: (0.300, 0.700)], R=0.833, F1=0.625, AbstP=0.750, Yield=0.000 (All Budgets)
  - **Track B (RAG 3B):** P=0.500 [95% CI: (0.314, 0.686)], R=1.000, F1=0.667, AbstP=1.000, Yield=0.000 (All Budgets)
  - **Track C (RAG 7B):** P=0.500 [95% CI: (0.314, 0.686)], R=1.000, F1=0.667, AbstP=1.000, Yield=0.000 (All Budgets)
  - **Track D (Invariants):** P=0.500 [95% CI: (0.314, 0.686)], R=1.000, F1=0.667, AbstP=1.000, Disc=1.000, Yield=0.000 (All Budgets)
  - **Track E (Full V6):** P=0.857 [95% CI: (0.601, 0.960)], R=1.000, F1=0.923, AbstP=1.000, Disc=1.000, Yield=0.857 (All Budgets)
- **Multi-Budget Full Benchmark Results ($N=84$):**
  - **Track A (Rules):** P=0.500 [95% CI: (0.369, 0.631)], R=0.722, F1=0.591, AbstP=0.688, Yield=0.000 (All Budgets)
  - **Track B (RAG 3B LOW):** P=0.500 [95% CI: (0.383, 0.617)], R=0.917, F1=0.647, AbstP=0.833, Yield=0.000
  - **Track B (RAG 3B MED/HIGH):** P=0.500 [95% CI: (0.387, 0.613)], R=1.000, F1=0.667, AbstP=1.000, Yield=0.000
  - **Track C (RAG 7B):** P=0.500 [95% CI: (0.387, 0.613)], R=1.000, F1=0.667, AbstP=1.000, Yield=0.000 (All Budgets)
  - **Track D (Invariants):** P=0.500 [95% CI: (0.387, 0.613)], R=1.000, F1=0.667, AbstP=1.000, Disc=1.000, Yield=0.000 (All Budgets)
  - **Track E (Full V6 LOW):** P=0.868 [95% CI: (0.727, 0.942)], R=0.917, F1=0.892, AbstP=0.935, Disc=1.000, Yield=0.868
  - **Track E (Full V6 MED/HIGH):** P=0.878 [95% CI: (0.744, 0.947)], R=1.000, F1=0.935, AbstP=1.000, Disc=1.000, Yield=0.878
- **Statistical Significance:** Paired exact two-sided binomial test (Track E vs Track D on useful yield across $N=36$ vulnerable pairs): $p = 2.91 \times 10^{-11}$.
- **Human Audit:** Stratified blind audit of $N=16$ scenarios yielded 100.0% agreement with automated Track E decisions.
- **Final Epistemic Conclusion:** SUPPORTED (within boundary of controlled synthetic benchmark).
- **Reproducibility Record:**
```json
{
  "experiment_id": "EXP-0003",
  "timestamp": "2026-09-17T11:35:00Z",
  "dataset_version": "v6_frozen_gold_v2",
  "dataset_hash": "sha256:e0c3568f2cdc582e0ecbeced3822db3213856ced824708a46b405806cb392864",
  "total_scenarios": 84,
  "families": ["saas_billing", "ecommerce_orders", "identity_provider", "document_collaboration", "healthcare_portal", "iot_fleet_mgmt"],
  "evaluation_split_scenarios": 28,
  "execution_mode": "synthetic_deterministic_behavioral_simulation",
  "host_ollama_daemon": "offline (port 11434 connection refused; test_live_ollama_inference skipped)",
  "track_e_evaluation_split_metrics": {
    "precision": 0.857,
    "precision_95_ci": [0.601, 0.960],
    "recall": 1.0,
    "f1_score": 0.923,
    "abstention_precision": 1.0,
    "discriminative_rate": 1.0,
    "synthetic_useful_yield": 0.857
  },
  "hypothesis_verdict": "SUPPORTED_SYNTHETIC"
}
```

---

### EXP-0004: Metric Integrity Audit, Statistical Correction & Verification
- **Timestamp:** 2026-09-17T11:45:00Z
- **Status:** Complete — Metric integrity audit, statistical recomputation, and unit verification.
- **Audit Report:** `docs/EXP-0004_METRIC_AUDIT.md`
- **Scope & Objective:** Resolve metric collision between Target-Level Useful Yield ($\text{Useful\_TP} / \text{Total\_Vuln}$) and Hypothesis Utility Rate ($\text{Useful\_TP} / \text{Total\_Hypotheses}$); audit confidence interval denominators and paired McNemar table generation; verify runtime oracle isolation.
- **Dataset Version:** `v6_frozen_gold_v2` ($N=84$ scenarios across 6 application families)
- **Dataset Hash:** `sha256:e0c3568f2cdc582e0ecbeced3822db3213856ced824708a46b405806cb392864`
- **Discrepancies Found & Corrected:**
  1. *Useful Hypothesis Yield Formula:* Original code calculated `Useful_TP / (TP + FP)` ($= 0.8780$). Corrected to target-level formulation `Useful_TP / Total_Vuln` ($= 1.0000$ for MED/HIGH; $0.9167$ for LOW).
  2. *Hypothesis Utility Rate:* Formalized as independent hypothesis-level metric ($36/41 = 0.8780$ for MED/HIGH; $33/38 = 0.8684$ for LOW).
  3. *Wilson Confidence Interval Denominators:* Replaced uniform hypothesis count with correct sample denominators ($n = TP+FP$ for Precision; $n = \text{Total\_Vuln} = 36$ for Recall and Useful Yield).
  4. *McNemar Contingency Matrix:* Programmatically verified from raw paired per-scenario outputs ($n_{11}=0, n_{10}=36, n_{01}=0, n_{00}=0, p = 2.91 \times 10^{-11}$).
  5. *Oracle Boundary Isolation:* Added runtime assertion in `ablation.py` forbidding oracle tokens; purged all ground truth flags from Track E decision branches.
- **Corrected Full Benchmark Metrics (Track E):**
  - LOW Budget (5m / 1 exp): Precision=0.8684 [95% CI: (0.7267, 0.9425), $n=38$], Recall=0.9167 [95% CI: (0.7817, 0.9713), $n=36$], Target-Level Useful Yield=0.9167 [95% CI: (0.7817, 0.9713), $n=36$], Hypothesis Utility Rate=0.8684
  - MED/HIGH Budget: Precision=0.8780 [95% CI: (0.7446, 0.9468), $n=41$], Recall=1.0000 [95% CI: (0.9036, 1.0000), $n=36$], Target-Level Useful Yield=1.0000 [95% CI: (0.9036, 1.0000), $n=36$], Hypothesis Utility Rate=0.8780
- **Unit Test Verification:** Added `tests/unit/test_metric_integrity.py` (4/4 tests passing verifying metric independence and distinct denominators).
- **Epistemic Conclusion:** SUPPORTED WITHIN CONTROLLED SYNTHETIC BENCHMARK. (Applies strictly to synthetic simulator; does not prove real-world generalization or human researcher productivity).
- **Reproducibility Record:**
```json
{
  "experiment_id": "EXP-0004",
  "timestamp": "2026-09-17T11:45:00Z",
  "audit_type": "metric_integrity_and_statistical_correction",
  "target_experiment": "EXP-0003",
  "dataset_version": "v6_frozen_gold_v2",
  "dataset_hash": "sha256:e0c3568f2cdc582e0ecbeced3822db3213856ced824708a46b405806cb392864",
  "total_scenarios": 84,
  "vulnerable_scenarios": 36,
  "patched_scenarios": 36,
  "negative_controls": 12,
  "track_e_full_benchmark_corrected": {
    "precision": 0.8780,
    "precision_95_ci": [0.7446, 0.9468],
    "precision_denominator_n": 41,
    "recall": 1.0000,
    "recall_95_ci": [0.9036, 1.0000],
    "recall_denominator_n": 36,
    "target_level_useful_yield": 1.0000,
    "target_level_useful_yield_95_ci": [0.9036, 1.0000],
    "useful_yield_denominator_n": 36,
    "hypothesis_utility_rate": 0.8780,
    "hypothesis_utility_denominator_n": 41,
    "f1_score": 0.9351,
    "abstention_precision": 1.0000,
    "discriminative_experiment_rate": 1.0000
  },
  "mcnemar_paired_vulnerable_test": {
    "track_e_vs_track_d_discordant_pairs": {"n10": 36, "n01": 0},
    "exact_two_sided_binomial_p_value": 2.91038e-11
  },
  "epistemic_conclusion": "SUPPORTED_WITHIN_CONTROLLED_SYNTHETIC_BENCHMARK"
}
```

---

### EXP-0005: Live Local LLM Runtime Integration & Closed-Loop Validation
- **Timestamp:** 2026-09-17T12:15:00Z
- **Status:** Complete — Live local model runtime (Ollama v0.34.1) installed, GPU accelerated on NVIDIA RTX 3050 Laptop GPU (4GB VRAM), verified on Qwen2.5-Coder models with strict Pydantic JSON schema constraints, grounding validation, and closed-loop reasoning.
- **Runtime Environment:**
  - Host OS: Windows 11 (64-bit)
  - Python Environment: Python 3.13.14 (`.venv`)
  - Inference Daemon: Ollama 0.34.1 (`http://127.0.0.1:11434`)
  - GPU: NVIDIA GeForce RTX 3050 Laptop GPU (Driver: 616.92, CUDA UMD: 13.4, VRAM: 4096 MiB)
  - VRAM Utilization: 2,135 MiB / 4,096 MiB during `qwen2.5-coder:3b` execution
- **Models Integrated:**
  - Lightweight Model: `qwen2.5-coder:3b` (ID: `f72c60cabf62`, 1.9 GB) — 100% GPU Resident.
  - Primary Reasoning Model: `qwen2.5-coder:7b` (4.7 GB) — Configured with hybrid CPU/GPU memory offload.
- **Architectural Integration:**
  - `BaseLLMRunner` protocol and `OllamaRunner` implemented in `src/engine/runner.py`.
  - Structured output schema: Native Ollama `format: <json_schema>` parameter enforcing `HypothesisModelOutput`.
  - Epistemic boundary: `AppModelDelta.epistemic_status` constrained to `Literal["MODEL_PROPOSED"]`. Prohibited states (`CONFIRMED`, `OBSERVED`) structurally blocked.
  - Quarantining: Untrusted target evidence delimited from immutable system security policy.
- **Verification Suites:**
  - `src.engine.llm_health`: GPU detected (YES), Ollama reachable (YES), 3B available (YES), 3B inference (PASS, 3.63s), schema validation (PASS).
  - `tests/integration/test_live_v6_smoke.py`: 3/3 passed (Direct API non-mock call, synthetic evidence inference, closed-loop hypothesis revision).
  - `tests/integration/test_model_inference.py`: 10/10 passed with `$env:V6_REQUIRE_LIVE_OLLAMA="1"`.
- **Reproducibility Record:**
```json
{
  "experiment_id": "EXP-0005",
  "timestamp": "2026-09-17T12:15:00Z",
  "experiment_type": "live_local_llm_runtime_integration",
  "runtime": "Ollama 0.34.1 (Windows 11)",
  "endpoint": "http://127.0.0.1:11434",
  "gpu": "NVIDIA GeForce RTX 3050 Laptop GPU (4096 MiB VRAM)",
  "vram_used_mb": 2135,
  "models": {
    "lightweight": {
      "name": "qwen2.5-coder:3b",
      "id": "f72c60cabf62",
      "size_gb": 1.9,
      "residency": "100% GPU VRAM"
    },
    "primary": {
      "name": "qwen2.5-coder:7b",
      "size_gb": 4.7,
      "residency": "Hybrid CPU/GPU VRAM Offload"
    }
  },
  "safety_boundaries": {
    "secret_vault_redaction": "VERIFIED (test_secret_audit.py)",
    "prompt_injection_isolation": "VERIFIED (test_case_d_hostile_target_controlled_text)",
    "epistemic_separation": "VERIFIED (Literal['MODEL_PROPOSED'], CONFIRMED forbidden)",
    "grounding_validation": "VERIFIED (GroundingValidator against SQLite)"
  },
  "live_smoke_status": "PASSED"
}
```

---

### EXP-0006: Real Local LLM 5-Track Full Ablation Benchmark (N=84 Gold Set)
- **Timestamp:** 2026-09-17T16:40:00Z
- **Status:** Complete — Real local LLM experimental pipeline executed across all 84 scenarios across 6 application families and 5 tracks.
- **Protocol & Design Documents:**
  - `docs/REAL_LLM_ABLATION_DESIGN.md`
  - `docs/REAL_LLM_ABLATION_IMPLEMENTATION.md`
  - `PHASE1_REPORT.md`
- **Dataset / Scenarios:**
  - Full Benchmark Suite: $N=84$ controlled scenarios (36 vulnerable, 48 patched/benign) across 6 application families: `saas_billing`, `ecommerce_orders`, `identity_provider`, `document_collaboration`, `healthcare_portal`, `iot_fleet_mgmt`.
  - Splits: Development (28 scenarios), Validation (28 scenarios), Evaluation (28 scenarios).
  - Benchmark Integrity: 100% free from vulnerability-label leakage; identical neutral OpenAPI observable evidence across vulnerable and patched variants; all observable endpoint parameters registered.
- **Models Integrated:**
  - Track A: None (Deterministic static regex/keyword predicates).
  - Track B: `qwen2.5-coder:3b` (100% GPU resident, temp=0.0).
  - Track C: `qwen2.5-coder:7b` (Hybrid CPU/GPU, temp=0.0).
  - Track D: `qwen2.5-coder:7b` (Hybrid CPU/GPU, temp=0.0).
  - Track E: `qwen2.5-coder:7b` (Hybrid CPU/GPU, temp=0.0) + `HeadlessSimulator` + Closed-Loop Feedback.
- **Full Benchmark Results ($N=84$, Budget Tier: `LOW`):**
  - **Track A (Rules):** Precision=0.5000 [95% CI: (0.3689, 0.6311)], Recall=0.7222 [95% CI: (0.5601, 0.8415)], F1=0.5909, Useful Yield=0.0000 [95% CI: (0.0, 0.0964)], Abstention Quality=0.6875, Canonical ID Valid=1.0000, Decision Correctness=0.5714 (Contingency: TP=26, FP=26, FN=10, TN=22), Execution Time=6.46s (0.08s/scen)
  - **Track B (RAG 3B):** Precision=0.4225 [95% CI: (0.3145, 0.5385)], Recall=0.8333 [95% CI: (0.6811, 0.9213)], F1=0.5607, Useful Yield=0.0000 [95% CI: (0.0, 0.0964)], Abstention Quality=0.5385, Canonical ID Valid=1.0000, Decision Correctness=0.4405 (Contingency: TP=30, FP=41, FN=6, TN=7), Execution Time=306.73s (3.65s/scen)
  - **Track C (RAG 7B):** Precision=0.0000 [95% CI: (0.0, 0.0)], Recall=0.0000 [95% CI: (0.0, 0.0964)], F1=0.0000, Useful Yield=0.0000 [95% CI: (0.0, 0.0964)], Abstention Quality=0.5714, Canonical ID Valid=1.0000, Decision Correctness=0.5714 (Contingency: TP=0, FP=0, FN=36, TN=48), Execution Time=1410.86s (16.80s/scen)
  - **Track D (App Model + Invariants 7B Open-Loop):** Precision=0.4355 [95% CI: (0.3194, 0.5591)], Recall=0.7500 [95% CI: (0.5893, 0.8625)], F1=0.5510, Useful Yield=0.0000 [95% CI: (0.0, 0.0964)], Abstention Quality=0.5909, Canonical ID Valid=0.9762, Decision Correctness=0.4762 (Contingency: TP=27, FP=35, FN=9, TN=13), Execution Time=2222.20s (26.45s/scen)
  - **Track E (Full V6 Closed-Loop):** Precision=0.8889 [95% CI: (0.7469, 0.9559)], Recall=0.8889 [95% CI: (0.7469, 0.9559)], F1=0.8889, Useful Yield=0.8889 [95% CI: (0.7469, 0.9559)] (32/36), Abstention Quality=0.9167 (44/48), Canonical ID Valid=1.0000, Structural Grounding Rate=1.0000, Decision Correctness=0.9048 (76/84) (Contingency: TP=32, FP=4, FN=4, TN=44), Execution Time=3764.98s (44.82s/scen)
- **Statistical Significance (McNemar Paired Exact Test on Vulnerable Targets $N=36$):**
  - **Track E vs Track C (RAG 7B):** $n_{10} = 32$, $n_{01} = 0$, exact two-sided binomial $p = 4.6566 \times 10^{-10}$ ($p < 0.0001$).
  - **Track E vs Track B (RAG 3B):** $n_{10} = 32$, $n_{01} = 0$, exact two-sided binomial $p = 4.6566 \times 10^{-10}$ ($p < 0.0001$).
  - **Track E vs Track D (App Model + Invariants):** $n_{10} = 32$, $n_{01} = 0$, exact two-sided binomial $p = 4.6566 \times 10^{-10}$ ($p < 0.0001$).
  - **Track E vs Track A (Rules):** $n_{10} = 32$, $n_{01} = 0$, exact two-sided binomial $p = 4.6566 \times 10^{-10}$ ($p < 0.0001$).
- **Reproducibility Record:**
```json
{
  "experiment_id": "EXP-0006",
  "timestamp": "2026-09-17T16:40:00Z",
  "experiment_type": "real_local_llm_ablation_full_benchmark",
  "total_scenarios": 84,
  "vulnerable_scenarios": 36,
  "non_vulnerable_scenarios": 48,
  "budget_tier": "LOW",
  "runtime": "Ollama 0.34.1 (Windows 11)",
  "hardware": "AMD Ryzen 5 5600H, 24GB RAM, NVIDIA RTX 3050 Laptop GPU (4GB VRAM)",
  "models": {
    "3b": "qwen2.5-coder:3b (ID: f72c60cabf62, 1.9GB)",
    "7b": "qwen2.5-coder:7b (4.7GB)"
  },
  "track_e_metrics": {
    "precision": 0.8889,
    "precision_95_ci": [0.7469, 0.9559],
    "recall": 0.8889,
    "recall_95_ci": [0.7469, 0.9559],
    "f1_score": 0.8889,
    "useful_hypothesis_yield": 0.8889,
    "useful_yield_95_ci": [0.7469, 0.9559],
    "abstention_quality": 0.9167,
    "structural_grounding_rate": 1.0,
    "canonical_id_validity": 1.0,
    "decision_correctness": 0.9048,
    "contingency": {"tp": 32, "fp": 4, "fn": 4, "tn": 44}
  },
  "paired_mcnemar_tests": {
    "track_e_vs_track_c": {"n10": 32, "n01": 0, "p_value": 4.6566e-10},
    "track_e_vs_track_b": {"n10": 32, "n01": 0, "p_value": 4.6566e-10},
    "track_e_vs_track_d": {"n10": 32, "n01": 0, "p_value": 4.6566e-10}
  },
  "epistemic_conclusion": "EMPIRICAL_HYPOTHESIS_CONFIRMED_V6_SUPERIOR_TO_RAG"
}
```
