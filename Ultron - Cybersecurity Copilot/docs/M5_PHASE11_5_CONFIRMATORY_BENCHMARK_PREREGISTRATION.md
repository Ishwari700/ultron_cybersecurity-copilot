# Milestone M5 Phase 11.5: Population-Level Confirmatory Benchmark Preregistration

**Protocol Identifier**: `M5_PHASE11_5_CONFIRMATORY_BENCHMARK_PREREGISTRATION_V1`  
**Registration Date (UTC)**: 2026-09-29  
**Governance State**: PREREGISTERED PRIOR TO LIVE INFERENCE  
**Status**: ACTIVE & BINDING  

---

## 1. Context & Research Objective

Phase 11.4 established two foundational empirical findings:
1. **Deterministic Security Property Alignment**: Constraining `attack_predicate.security_property` to deterministic category-bound vocabularies eliminated `PROPERTY_CATEGORY_MISMATCH` failures entirely.
2. **Track D Compatibility**: When shielded against lexical hallucinations in structured slots (facts, targets, properties), Track D (dual RAG + cascade handoff) maintained 100% grounding success and 87.5% VTER in diagnostic evaluation.

Phase 11.5 tests whether these architectural findings reproduce at population scale across the complete, frozen 84-scenario benchmark population.

### Governing Research Question:
> *Under a fixed evidence budget, does an explicit Application Model → Security Invariant → Evidence Gap → Hypothesis → Experiment architecture improve security-hypothesis precision, abstention quality, and human investigation efficiency compared with conventional LLM + RAG?*

---

## 2. Confirmatory Hypotheses

### Primary Confirmatory Hypothesis ($H_1$):
Under the four-tier failure recovery architecture, evaluating the full population under **P5-TD** (Track D dual RAG + cascade handoff) will achieve a non-inferior useful vulnerable hypothesis yield compared with **P4-TA** (Track A minimal context) without inducing semantic grounding collapse or schema corruption.

### Secondary Hypotheses:
- **$H_{2a}$ (Grounding Robustness)**: Fact and target identifier shielding will maintain >95% Grounding Success Rate across both Track A and Track D at population scale.
- **$H_{2b}$ (Security Property Alignment)**: Category-bound security property constraints will maintain >95% property compatibility rate across all 10 vulnerability categories.
- **$H_{2c}$ (Control Abstention Quality)**: The architecture will maintain high True Negative Rate (TNR > 80%) on non-vulnerable control scenarios.

---

## 3. Benchmark Population (84 Scenarios)

The evaluation is conducted on the complete frozen Phase 10 population:
- **Total Scenarios**: Exactly 84 scenarios
- **Vulnerable Variants**: Exactly 36 scenarios
- **Patched / Control Variants**: Exactly 48 scenarios
- **Canonical Dataset Digest**: `6821d207729de97ac99657a09e38c25895a73285fe9c485d299dc27f37d2bdba`
- **Vulnerability Categories (10 categories)**:
  `API-BOLA-001`, `API-DEVICE-BOLA-001`, `API-CROSS-TENANT-001`, `API-LIFECYCLE-001`, `API-STATE-001`, `API-ROLE-BOUNDARY-001`, `API-BFLA-001`, `API-BFLA-002`, `API-MULTI-STEP-AUTH-001`, `API-MUTATION-001`, `API-AUTH-NONE`.

---

## 4. Experimental Conditions & Design

Paired within-scenario randomized confirmatory trial:
- **Condition 1 (P4-TA)**: Phase 11.4 P4 architecture on Track A (minimal structural context, zero RAG, zero cascade, all deterministic shielding active).
- **Condition 2 (P5-TD)**: Exact identical analytical architecture on Track D (full cascade handoff + VAPT Knowledge dual RAG + protected handoff, identical deterministic shielding active).
- **Sample Allocation**: 84 scenarios $\times$ 2 conditions = **168 live inference calls**.
- **Randomization Procedure**: Seeded deterministic order generated per scenario:
  ```python
  payload = f"M5_PHASE11_5_ORDER_SEED_42:{scenario_id}".encode("utf-8")
  seed_int = int(hashlib.sha256(payload).hexdigest()[:16], 16)
  rng = random.Random(seed_int)
  conds = ["P4_TRACK_A", "P5_TRACK_D"]
  rng.shuffle(conds)
  ```

---

## 5. Frozen Runtime Configuration

- **Ollama Version**: `v0.34.1` on local loopback `127.0.0.1:11434`
- **Model**: `qwen2.5-coder:7b`
- **Model Digest**: `dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364`
- **Parameters**: `num_ctx = 2048`, `num_predict = 300`, `temperature = 0.0`, `seed = 42`, `keep_alive = 60m`
- **Timeout**: 30.0s hard cutoff with 500ms teardown tolerance.
- **Execution Policy**: Single attempt per cell. Zero retries, zero repairs, zero fallbacks.
- **Network Egress**: Absolute zero external HTTP/HTTPS egress.

---

## 6. Endpoints & Statistical Analysis Plan

### Primary Endpoint:
- **Scenario-Level Useful Vulnerable Hypothesis Yield**: Proportion of vulnerable scenarios (out of 36) producing a fully valid typed experiment proposal asserting the true breach condition.
- **Primary Hypothesis Test**: Paired exact two-sided McNemar test on discordant pairs ($b$ vs $c$):
  $$p = 2 \times \sum_{k=0}^{\min(b, c)} \binom{b+c}{k} 0.5^{b+c}$$

### Required Secondary Metrics (23 Metrics):
1. Candidate HYPOTHESIS attempts
2. Valid typed experiments
3. Population VTER (%)
4. Completed-call VTER (%)
5. Useful vulnerable hypotheses count
6. Correct vulnerable decisions
7. Correct control abstentions
8. True Positive Rate (TPR %)
9. True Negative Rate (TNR %)
10. False Positives (FP)
11. False Negatives (FN)
12. Vulnerable abstention rate (%)
13. Control abstention rate (%)
14. Grounding success rate (%)
15. Schema failure rate (%)
16. Property compatibility rate (%)
17. Polarity failure rate (%)
18. Action incompatibility rate (%)
19. Category incompatibility rate (%)
20. Runtime timeout count
21. Mean latency (ms)
22. Median latency (ms)
23. P95 latency (ms)

---

## 7. Deterministic Failure Taxonomy

- `SP1`: `PROPERTY_MISSING`
- `SP2`: `PROPERTY_OUT_OF_SET`
- `SP3`: `PROPERTY_CATEGORY_MISMATCH`
- `SP4`: `PROPERTY_INVARIANT_MISMATCH`
- `SP5`: `PROPERTY_EVIDENCE_GAP_MISMATCH`
- `SP99`: `PROPERTY_UNRESOLVED`
- `G1`–`G8`: Grounding failure taxonomy
- `SCHEMA_VALIDITY_FAILURE`
- `SEMANTIC_EXPERIMENT_POLARITY_FAILURE`
- `RUNTIME_TIMEOUT`

---

## 8. Stopping Rules

Live inference will immediately STOP if:
1. Canonical Phase 10 dataset digest differs from `6821d207729de97ac99657a09e38c25895a73285fe9c485d299dc27f37d2bdba`.
2. Model digest differs from `dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364`.
3. Unexpected network egress occurs.
4. Total call count deviates from 168.
5. Historical benchmark artifact digests differ from sealed references.

---

## 9. Historical Sealed Artifact Immutability Baseline

- `data/eval/m5_phase10_full_population_validation.json`: `6821d207729de97ac99657a09e38c25895a73285fe9c485d299dc27f37d2bdba`
- `data/eval/m5_phase10_checkpoint.json`: `40f9f725fca5fdf05a76836182960b7f0d4c303a182d6e8af068a1b57e8f4537`
- `data/eval/m5_phase11_4_live_results.json`: `beaa7cad759af8641dd8d8231cc8bd66d95a1d649a757840fc60e91161e59eae`
- `data/eval/m5_phase11_4_manifest.json`: `766ae86cc8a0360f16674fefd7b14ce9ef01b6dfa815d984903815911d1894cb`
- `data/eval/m5_phase11_3_live_results.json`: `72352ee6ebd774e487f389ebd39322dbb169207257232656e3f35d534fe05271`
- `data/eval/m5_phase11_2_live_results.json`: `48dd13c5e46dfc75f2c27ca64dd5efae45b0686043c99d9f19fb0749e05540a9`
