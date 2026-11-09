# M2 Phase 0: Model Environment Validation Report

**Date:** September 18, 2026  
**Platform:** AMD Ryzen 5 5600H, NVIDIA GeForce RTX 3050 Laptop GPU (4096 MiB physical VRAM)  
**Execution Mode:** Milestone M2 Empirical Hardware Gate (`MODEL_ENVIRONMENT_VALIDATION`)  
**Authoritative Plan Reference:** `docs/M1_5_M2_PLAN.md` (Sections 5.1, 6.2, 6.4)

---

## 1. Hardware Environment Identity Check (Step 0)
- **CPU Detected:** AMD Ryzen 5 5600H with Radeon Graphics (6 cores, 12 logical processors)
- **GPU Detected:** NVIDIA GeForce RTX 3050 Laptop GPU, 4096 MiB physical VRAM
- **Reference Spec Match:** **PASS** (Matches reference machine specified in Sections 5.1 / 6.4).

---

## 2. Ollama Server & Model Availability (Step 1)
- **Ollama Version:** `0.34.1` (running locally on `127.0.0.1:11434`)
- **Required Models:**
  - `qwen2.5-coder:3b`:
    - **Tag:** `qwen2.5-coder:3b`
    - **Digest:** `f72c60cabf6237b07f6e632b2c48d533cef25eda2efbd34bed21c5e9c01e6225`
    - **Quantization:** `Q4_K_M`
    - **Parameter Size:** `3.1B`
  - `qwen2.5-coder:7b`:
    - **Tag:** `qwen2.5-coder:7b`
    - **Digest:** `dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364`
    - **Quantization:** `Q4_K_M`
    - **Parameter Size:** `7.6B`
- **Model Availability Verdict:** **PASS**

---

## 3. Generic Structured-Output Mechanism Check (Step 2)
Throwaway JSON schema test (`{"status": "ok", "counter": 42}`):
- `qwen2.5-coder:3b`: Valid schema-conforming JSON returned in `3.74s` (`{"status": "ok", "counter": 42}`).
- `qwen2.5-coder:7b`: Valid schema-conforming JSON returned in `7.36s` (`{"status": "ok", "counter": 42}`).
- **Verdict:** **PASS**

---

## 4. Layer Offload Placement Observations (Step 3)
Inspected from Ollama runtime server logs (`%LOCALAPPDATA%\Ollama\server.log`):
- `qwen2.5-coder:3b`:
  - **Total Layers:** 37
  - **GPU Offload:** 37/37 layers (100.0% GPU offload)
  - **Model Buffer:** 1834.83 MiB in CUDA0 VRAM
- `qwen2.5-coder:7b`:
  - **Total Layers:** 29
  - **GPU Offload:** 12/29 layers to CUDA0 VRAM (41.4%)
  - **CPU Offload:** 17/29 layers to System RAM
  - **Model Buffer:** 1905.36 MiB in CUDA0 VRAM
- **Verdict:** **PASS** (Reflects actual observed allocation on 4GB VRAM envelope).

---

## 5. Mandatory 10-Cycle Memory-Drift Protocol (Step 4)
- **Baseline Memory $M_0$ (quiescent):** VRAM = 931.0 MB, RSS = 102.5 MB

| Cycle | Transition | Quiescent VRAM (MB) | Quiescent RSS (MB) | Reloaded Model | Loaded VRAM (MB) | Loaded RSS (MB) | $T_{\text{load}}$ (s) |
| :---: | :--- | :---: | :---: | :--- | :---: | :---: | :---: |
| 1 | Unload 7B $\to$ Load 3B | 931.0 | 102.5 | `qwen2.5-coder:3b` | 3073.0 | 102.5 | 1.91 |
| 2 | Unload 3B $\to$ Load 7B | 931.0 | 102.5 | `qwen2.5-coder:7b` | 3185.0 | 103.0 | 3.91 |
| 3 | Unload 7B $\to$ Load 3B | 931.0 | 103.0 | `qwen2.5-coder:3b` | 3073.0 | 102.6 | 1.89 |
| 4 | Unload 3B $\to$ Load 7B | 931.0 | 102.6 | `qwen2.5-coder:7b` | 3185.0 | 103.3 | 3.89 |
| 5 | Unload 7B $\to$ Load 3B | 931.0 | 103.0 | `qwen2.5-coder:3b` | 3073.0 | 102.6 | 1.90 |
| 6 | Unload 3B $\to$ Load 7B | 931.0 | 102.6 | `qwen2.5-coder:7b` | 3185.0 | 103.5 | 3.91 |
| 7 | Unload 7B $\to$ Load 3B | 931.0 | 103.5 | `qwen2.5-coder:3b` | 3073.0 | 103.1 | 1.89 |
| 8 | Unload 3B $\to$ Load 7B | 931.0 | 103.1 | `qwen2.5-coder:7b` | 3185.0 | 102.8 | 3.93 |
| 9 | Unload 7B $\to$ Load 3B | 931.0 | 102.8 | `qwen2.5-coder:3b` | 3073.0 | 102.4 | 2.21 |
| 10 | Unload 3B $\to$ Load 7B | 931.0 | 102.5 | `qwen2.5-coder:7b` | 3185.0 | 103.0 | 3.90 |

### Statistical Drift Analysis
- **VRAM OLS Linear Growth Slope:** `0.0000 MB/cycle` (Threshold: $\le 5.0\text{ MB/cycle}$) $\to$ **PASS**
- **VRAM Absolute Endpoint Drift $|M_{10} - M_1|$:** `0.0 MB` (Threshold: $\le 150.0\text{ MB}$) $\to$ **PASS**
- **System RSS OLS Linear Growth Slope:** `0.0263 MB/cycle` (Threshold: $\le 5.0\text{ MB/cycle}$) $\to$ **PASS**
- **System RSS Absolute Endpoint Drift $|M_{10} - M_1|$:** `0.02 MB` (Threshold: $\le 150.0\text{ MB}$) $\to$ **PASS**
- **Memory Drift Verdict:** **PASS** (Zero unbounded memory leakage detected).

---

## 6. Context Saturation & Ceilings (Step 5)
- **Tier 1 (4096 tokens):**
  - Prompt tokens evaluated: 3918
  - Evaluation latency: 7.22s
  - Peak VRAM observed: 3207.0 MB
  - CUDA OOM: **False**
- **Tier 2 (8192 tokens):**
  - Prompt tokens evaluated: 7810
  - Evaluation latency: 18.86s
  - Peak VRAM observed: 3319.0 MB
  - CUDA OOM: **False**
- **Verdict:** **PASS**

---

## 7. Mode 1 Lifecycle Capability Check (Step 6)
Synthetic dummy prompt sequence:
1. **Phase 1 (3B Triage):** Processed 3 synthetic dummy prompts via `qwen2.5-coder:3b` (`keep_alive: 5m`).
2. **Phase 2 (Model Transition):** Explicit unload of 3B (`keep_alive: 0`); VRAM reclaimed from 3073 MB to 931 MB.
3. **Phase 3 (7B Reasoning):** Warm load of `qwen2.5-coder:7b` (`keep_alive: 10m`) and synthetic inference completed in 4.45s.
- **Verdict:** **PASS**

---

## 8. Latency Decomposition (Step 7)
- `qwen2.5-coder:3b`:
  - $T_{\text{load}}$ (cold): `2.790s`
  - $T_{\text{infer}}$ (cold): `0.198s`
  - $T_{\text{load}}$ (warm): `0.004s`
  - $T_{\text{infer}}$ (warm): `0.836s`
  - Prompt eval rate: `1414.6 tokens/sec`
  - Output eval rate: `75.8 tokens/sec`
- `qwen2.5-coder:7b`:
  - $T_{\text{load}}$ (cold): `4.796s`
  - $T_{\text{infer}}$ (cold): `1.477s`
  - $T_{\text{load}}$ (warm): `0.003s`
  - $T_{\text{infer}}$ (warm): `0.918s`
  - Prompt eval rate: `104.2 tokens/sec`
  - Output eval rate: `15.9 tokens/sec`
- **Verdict:** **PASS**

---

## 9. Gate Rule Determination (Step 8)

$$\mathbf{MODEL\_ENVIRONMENT\_VALIDATION:\ PASS}$$

All empirical criteria in Section 6.4 have passed without error, drift, OOM, or platform mismatch.
