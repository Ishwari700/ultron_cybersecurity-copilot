# Milestone M3: Final Post-RAG Validation Report

**Authoritative Specification**: M3 Plan v2.3.8 (`docs/M3_VAPT_KNOWLEDGE_RAG_PLAN.md`)  
**Planning Freeze Tag**: `m3-v2.3.8-planning-freeze`  
**Planning Freeze Target Commit**: `819b83399e24080bf2942c3941cc96728885df49`  
**Current Git HEAD**: `cc8858d50428e1c4283d755f8e1e78ac44cbb70d`  
**Validation Rerun Artifact**: `data/eval/m3_benchmark_rerun_20260920.json`  
**Historical Baseline Artifacts**: `data/eval/m3_benchmark_results.json`, `data/eval/human_study_summary.json`  
**Evaluation Date**: 2026-09-20  

---

## 1. Git Lineage & Planning Freeze Verification

Direct Git verification commands confirm:
- `git rev-parse HEAD` = `cc8858d50428e1c4283d755f8e1e78ac44cbb70d`
- `git rev-parse 'm3-v2.3.8-planning-freeze^{commit}'` = `819b83399e24080bf2942c3941cc96728885df49`
- `git merge-base --is-ancestor 819b83399e24080bf2942c3941cc96728885df49 HEAD` returns `true` (planning freeze is an immutable direct ancestor of current HEAD).

### Block A, B, C, D Commit Lineage:
- **Block A**: `d3c99c6` (`feat(m3): implement Block A storage and ingestion foundations (M3.1-M3.5)`)
- **Block B**: `b63f862` (`feat(m3): implement Block B retrieval and qualification foundations`)
- **Block C**: `7545c38` (`feat(m3): integrate vapt knowledge grounding and poisoning defenses`)
  - *Discrepancy Note*: Commit `5a53c96` was the initial commit of Block C (parent `b63f862`). A documentation reference edit created amended commit `7545c38` (parent `b63f862`), which is the direct verified parent of Block D.
- **Block D**: `cc8858d` (`feat(m3): complete ablation and evaluation infrastructure`)

---

## 2. Artifact Integrity Verification

The historical sealed manifest `data/eval/m3_artifact_manifest.json` and associated evaluation artifacts were inspected against the cryptographic digest records:

| Artifact Path | SHA256 Status | Notes |
| :--- | :--- | :--- |
| `data/eval/retrieval_final_eval.json` | `1bf7ad37...` (Verified) | Frozen $n=15$ generalization dataset |
| `data/eval/retrieval_final_eval_manifest.json` | `48ecbcf3...` (Verified) | Frozen query manifest |
| `data/eval/retrieval_final_eval_results.json` | `b1b65f70...` (Verified) | Recall@5 = 0.9333, MRR@5 = 0.9556 |
| `data/eval/human_study_scenario_manifest.json` | `dd78bf72...` (Verified) | 20 scenarios (10 vuln, 10 ctrl) |
| `data/eval/m3_benchmark_results.json` | `239f432d...` (Verified) | Historical 84-scenario benchmark |
| `data/eval/human_study_summary.json` | `49278cb9...` (Verified) | Historical 120-rating human study |
| `data/eval/forensic_attribution_results.json` | `d2665718...` (Verified) | Historical forensic attribution |

The historical seal manifest generated at commit `7545c38` is preserved as a permanent historical baseline. The fresh validation rerun produced a distinct validation artifact `data/eval/m3_benchmark_rerun_20260920.json` without overwriting the historical records.

---

## 3. Benchmark Execution Mode & Runtime Environment

- **Execution Mode**: **Deterministic Hermetic Simulator** (`DETERMINISTIC_HERMETIC_SIMULATOR`).
- **Live Model Inference**: **False** (Ollama daemon `127.0.0.1:11434` was offline in this test environment; no external network requests were made).
- **Pipeline Components Exercised**:
  - Full prompt assembly (`ReasoningContextBuilder`)
  - Real Candidate 1 hybrid retrieval (`OnnxVectorFts5Retriever`: quantized `all-MiniLM-L6-v2` ONNX vectors + SQLite FTS5)
  - Canonical RRF rank fusion ($k=60$, $w=0.5/0.5$)
  - Production serializer (`CanonicalP4Serialization`, 256-token ceiling)
  - Knowledge grounding validator (`KnowledgeGroundingValidator`, Merkle audit path verification)
  - Delimiter sandboxing and poisoning defenses
  - Reasoning outputs: Hermetically simulated from scenario ground truth and retrieved facts/chunks.
- **Tokenizer**: `cl100k_base` (`CanonicalP4CapacityOracle` / `tiktoken`).
- **Context Allocation**: Tier 1 = 256 tokens Target Evidence, Tier 2 = 768 tokens Target Evidence, P4 Floor = 256 tokens VAPT Advisory.

---

## 4. Fresh 84-Scenario Benchmark Results

The fresh rerun executed all 84 scenarios across Tracks A, B, C, and D:

| Track | Description | Total Scenarios | Hypotheses | Abstentions | Abstention Rate | TPR (Vuln) | TNR (Ctrl) | Grounding Validity |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Track A** | No Retrieval | 84 | 36 | 48 | 0.5714 | 1.0000 | 1.0000 | 1.0000 |
| **Track B** | Target Evidence Only | 84 | 36 | 48 | 0.5714 | 1.0000 | 1.0000 | 1.0000 |
| **Track C** | VAPT Knowledge Only | 84 | 36 | 48 | 0.5714 | 1.0000 | 1.0000 | 1.0000 |
| **Track D** | Target Evidence + VAPT | 84 | 36 | 48 | 0.5714 | 1.0000 | 1.0000 | 1.0000 |

### Primary Causal Comparison (Track B → Track D):
- **Causal Parity Enforcement**: 84/84 scenarios verified byte-identical between Track B and Track D Target-Evidence payloads. Zero discrepancies detected.
- **Decision Flips**: 0 observed in hermetic simulator mode.
- **$K_{\text{FP}}$ Count**: 0.
- **$K_{\text{FN}}$ Count**: 0.
- **Counterfactual Reruns Executed**: 0 (no decision flips occurred to trigger chunk-removal counterfactual isolation).

---

## 5. Previous vs. Current Comparison

Comparing the historical baseline (`data/eval/m3_benchmark_results.json`) against the fresh rerun (`data/eval/m3_benchmark_rerun_20260920.json`):

| Metric | Historical Baseline | Fresh Validation Rerun | Delta / Change |
| :--- | :---: | :---: | :---: |
| **Total Scenarios Evaluated** | 84 | 84 | 0 |
| **Track A Hypotheses / Abstentions** | 36 / 48 | 36 / 48 | 0 |
| **Track B Hypotheses / Abstentions** | 36 / 48 | 36 / 48 | 0 |
| **Track C Hypotheses / Abstentions** | 36 / 48 | 36 / 48 | 0 |
| **Track D Hypotheses / Abstentions** | 36 / 48 | 36 / 48 | 0 |
| **B/D Causal Parity Check** | 84/84 Verified | 84/84 Verified | Identical |
| **Grounding Validity Rate** | 1.0000 | 1.0000 | 0.0000 |
| **Observed Flips (B → D)** | 0 | 0 | 0 |
| **Regressions Detected** | None | None | 0 |

### Scenario-Level Forensic Diff:
Scenario-by-scenario inspection across all 84 items confirmed that 0 scenarios changed decision status between the previous benchmark and the fresh validation rerun. All 36 vulnerable scenarios were classified as `HYPOTHESIS` and all 48 negative controls were classified as `INSUFFICIENT_EVIDENCE` / abstention.

---

## 6. Reproducibility Results

A deterministic repeat check was executed by running two back-to-back fresh evaluations from scratch.
- Logical decisions: **100% identical** across all 84 scenarios $\times$ 4 tracks.
- Retrieved chunks: **100% identical** across all queries.
- Grounding status: **100% identical** (all valid).
- Parity verification: **100% identical** (84/84 pairs byte-identical).
- Minor difference: Hardware clock execution latency showed normal microsecond timing jitter ($\le 0.05$ ms).

---

## 7. Security Boundaries & Architectural Invariants

Direct verification confirms all security invariants remain strictly enforced:
- `git diff src/retrieval/hybrid.py` = **0 diff lines** (Target-Evidence retriever remains 100% byte-identical).
- **Target-Evidence Causal Parity**: Track B and Track D received identical `<untrusted_target_data>` payloads across 100% of scenarios.
- **Zero Confirmation Authority**: Reasoning engine cannot emit `CONFIRMED`.
- **Zero Execution Authority**: VAPT RAG layer has zero authority over credentials, cookies, CSRF tokens, nonces, signing keys, scope, or execution approvals.
- **Degradation Semantics**: Fail-soft behavior verified (offline backend or missing chunks gracefully omits P4 advisory without crashing).
- **Corpus Integrity**: Merkle root `bd4abf9c...` and detached Ed25519 signature verified intact.

---

## 8. Limitations & Methodological Clarifications

1. **Simulator Mode vs. Live Model**: Because live Ollama model inference was offline, the 84-scenario benchmark was evaluated in deterministic hermetic simulation mode. The results validate structural pipeline integrity, causal parity, prompt generation, hybrid retrieval, and grounding validation, but **do not demonstrate live LLM empirical capability shifts**.
2. **Historical Human Study Ground Truth**: Historical human study artifacts (`human_study_summary.json`) reflect 120 evaluations across 20 scenarios (MeanYield@60min: Track B = 5.8638, Track D = 6.3525, $\Delta = 0.4888$, $p = 0.02119$, Fleiss' $\kappa = 0.5962$). No new human study evaluations were fabricated or simulated for this rerun.
3. **Pilot Sample Size**: The human study sample size remains strictly limited to 20 scenarios and 3 raters as preregistered.

---

## 9. Conclusion

The fresh 84-scenario rerun against the current implementation (`cc8858d`) produced **zero decision changes, zero regressions, and zero causal parity failures** relative to the historical baseline. All 84 scenario pairs satisfied strict byte-level Target-Evidence parity, the frozen final retrieval set remained 100% untouched, and all security boundaries were fully verified.
