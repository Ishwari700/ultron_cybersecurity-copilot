# Live Local LLM Setup Guide: Ollama & Qwen2.5-Coder for V6 Final

This document provides the complete installation, configuration, and operation guide for running real local LLMs within the **Local AI-Assisted Bug Bounty Research Platform (V6 Final)**.

---

## 1. System Requirements & Hardware Context

* **Operating System:** Windows 11 64-bit
* **Processor (CPU):** AMD Ryzen 5 5600H (6 cores, 12 threads)
* **System RAM:** 24 GB DDR4
* **Graphics Hardware (GPU):** NVIDIA GeForce RTX 3050 Laptop GPU (4 GB GDDR6 VRAM)
* **Python Runtime:** Python 3.11+ within `.venv`

---

## 2. Ollama Runtime Installation on Windows 11

### 2.1 Official Installation
Install Ollama directly using the official Windows PowerShell installation script:

```powershell
irm https://ollama.com/install.ps1 | iex
```

Alternatively, download and run the official installer executable `OllamaSetup.exe` from [ollama.com](https://ollama.com/download/windows).

### 2.2 Verifying Installation & Service Startup
Ensure the Ollama service is active and listening exclusively on `127.0.0.1:11434`:

```powershell
# Check binary version
ollama --version

# Check local REST API
curl.exe -s http://127.0.0.1:11434/api/tags
```

> [!CAUTION]
> **Localhost Binding Only:** Never expose Ollama (`0.0.0.0`) to public interfaces. In bug bounty research, untrusted target evidence is processed; the inference endpoint must remain strictly accessible only to `127.0.0.1`.

---

## 3. Pulling Models from Official Registry

The platform uses the official `Qwen2.5-Coder` model family:

```powershell
# Lightweight model (1.9 GB) - extraction, classification, broad sweep
ollama pull qwen2.5-coder:3b

# Primary reasoning model (4.7 GB) - cross-evidence synthesis, experiment proposal
ollama pull qwen2.5-coder:7b
```

Verify installed models:
```powershell
ollama list
```

---

## 4. Hardware VRAM Allocation & Offloading Strategy

The RTX 3050 Laptop GPU possesses **4,096 MiB VRAM**.

| Model | Approximate Size | VRAM Footprint (Q4_K_M) | Execution Strategy |
| :--- | :---: | :---: | :--- |
| **`qwen2.5-coder:3b`** | ~1.9 GB | ~2.3 GB total | **100% GPU Resident.** Fits completely into 4GB VRAM. Fast inference (~30-50 tokens/sec). |
| **`qwen2.5-coder:7b`** | ~4.7 GB | ~5.2 GB total | **Hybrid CPU/GPU Offload.** ~3.2 GB allocated to GPU VRAM, remainder offloaded to high-speed system RAM (24 GB DDR4). |

### Strict Serialization
To avoid VRAM thrashing and CUDA out-of-memory errors on 4GB hardware, the V6 pipeline enforces:
* **`max_concurrent_inferences = 1`**
* Serialized execution between reconnaissance, indexing, and reasoning phases.

---

## 5. Configuration & Environment Variables

Configuration parameters are managed in [config/default_config.yaml](config/default_config.yaml) and can be overridden via environment variables:

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `BBAI_OLLAMA__BASE_URL` | `http://127.0.0.1:11434` | Ollama service endpoint. |
| `BBAI_OLLAMA__PRIMARY_MODEL` | `qwen2.5-coder:7b` | Deep invariant reasoning and experiment proposal model. |
| `BBAI_OLLAMA__LIGHTWEIGHT_MODEL`| `qwen2.5-coder:3b` | Broad-sweep candidate filtering model. |
| `BBAI_OLLAMA__NUM_CTX_3B` | `2048` | Context window tokens for 3B. |
| `BBAI_OLLAMA__NUM_CTX_7B` | `4096` | Context window tokens for 7B. |
| `BBAI_OLLAMA__REQUEST_TIMEOUT_SECONDS` | `120` | HTTP request timeout for generation. |
| `V6_REQUIRE_LIVE_OLLAMA` | `0` | If set to `1`, tests and runner fail if Ollama is unreachable. |

---

## 6. Diagnostic Health Check CLI

Run the diagnostic tool to verify local GPU, Ollama connectivity, model presence, and schema compliance:

```powershell
.venv\Scripts\python.exe -m src.engine.llm_health
```

Expected output:
```text
============================================================
 V6 Final — Local LLM Health & Diagnostic Check
============================================================
GPU detected:           YES (NVIDIA GeForce RTX 3050 Laptop GPU, VRAM: 4096 MiB)
Ollama reachable:       YES (http://127.0.0.1:11434)
3B available (qwen2.5-coder:3b): YES
7B available (qwen2.5-coder:7b): YES
3B inference:           PASS (0.42s latency)
7B inference:           PASS (1.18s latency)
schema validation:      PASS
============================================================
```

---

## 7. Troubleshooting

1. **`connection refused on 127.0.0.1:11434`:**
   Ensure Ollama application is launched from the Windows Start menu or background tray.
2. **`CUDA Out of Memory`:**
   Ensure other GPU-intensive applications (e.g. games, Chrome hardware acceleration) are closed. Ollama automatically manages partial offload if VRAM budget is constrained.
3. **Slow 7B Inference:**
   Expected when partially offloading layers to CPU. Ryzen 5 5600H with 24GB dual-channel DDR4 yields ~8-15 tokens/sec for 7B Q4.
