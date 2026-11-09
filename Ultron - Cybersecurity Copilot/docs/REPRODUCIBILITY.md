# Platform Reproducibility & Fresh Environment Setup Guide

**Platform Version:** v10.0.0-deep-android-binary-re  
**Target Hardware:** AMD Ryzen 5 5600H (6 cores/12 threads), 24 GB RAM, NVIDIA RTX 3050 Laptop GPU (4 GB VRAM ceiling)  
**Operating System:** Windows 11 / Linux (Ubuntu 22.04+) / macOS (Apple Silicon)  
**LLM Runtime:** Ollama (Local Daemon at `http://127.0.0.1:11434`)  
**Determinism Principle:** Zero cloud egress, local-first execution, temperature = 0.0, concurrency = 1.

---

## 1. Prerequisites & System Requirements

### Hardware Limits
- **CPU:** 6 cores minimum (utilized for regex scanning, FTS5 retrieval, APK decompression, and AST parsing).
- **RAM:** 16 GB minimum, 24 GB recommended.
- **GPU VRAM:** 4 GB dedicated VRAM ceiling. Model offload is strictly budgeted:
  - `qwen2.5-coder:3b`: 100% GPU offload (fits within ~1.8 GB VRAM).
  - `qwen2.5-coder:7b`: Layer-split partial offload (~12 layers in VRAM, remaining in system RAM).
  - Embeddings: Forced to CPU to prevent VRAM competition with reasoning models.

### Software Requirements
- **Python:** Version `>= 3.11` (Tested on Python 3.13.14).
- **Git:** Version `>= 2.30`.
- **Node.js (Optional, for Web UI):** Version `>= 18.0` (for `frontend/`).
- **Ollama:** Version `>= 0.3.0` running locally on port 11434.

---

## 2. Virtual Environment Setup

From the repository root:

```bash
# Windows (PowerShell)
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Linux / macOS (Bash)
python3 -m venv .venv
source .venv/bin/activate
```

---

## 3. Dependency Installation

Install the platform in editable development mode with optional ML and dev dependencies:

```bash
# Install core + development + ML dependencies
pip install --upgrade pip setuptools wheel
pip install -e ".[dev,ml]"
```

Verify installed packages:
```bash
pip list
```

---

## 4. Local Ollama & Model Provisioning

The platform operates against local Ollama models. Ensure Ollama is running and download the pinned model tags:

```bash
# Pull the pinned 3B triage model
ollama pull qwen2.5-coder:3b

# Pull the pinned 7B deep reasoning model
ollama pull qwen2.5-coder:7b

# (Optional) Pull the embedding model if using Ollama embeddings
ollama pull nomic-embed-text
```

Verify model availability:
```bash
ollama list
```

---

## 5. Environment Variables & Configuration

The platform functions out-of-the-box using defaults in `config/default_config.yaml`. The following environment variables can be overridden:

| Variable | Default Value | Purpose |
| :--- | :--- | :--- |
| `OLLAMA_BASE_URL` | `http://127.0.0.1:11434` | Ollama daemon endpoint |
| `PLATFORM_ROOT` | `.` (Repository root) | Base directory for data, logs, and database discovery |
| `ENV` | `development` | Runtime environment (`development`, `test`, `production`) |
| `CONCURRENCY_LIMIT` | `1` | Strict inference lock preventing GPU thrashing |
| `OFFLINE_TEST_MODE` | `1` | Pins network adapters and skips live pilot ablations |

---

## 6. Test Suite Execution

Execute the full M0–M10 regression test suite (1,434 collected tests):

```bash
# Run complete test suite quietly
pytest -q

# Run with verbose output and test timing
pytest -v --durations=10

# Run specific milestone test suites
pytest -q tests/unit/test_m10_security_invariants.py
pytest -q tests/integration/test_m10_deep_analysis.py
pytest -q tests/unit/test_m9_security_invariants.py
pytest -q tests/integration/test_m8_integration.py
pytest -q tests/integration/test_m7_integration.py
pytest -q tests/integration/test_m6_integration.py
```

*Note:* `tests/integration/test_live_ablation_pilot.py` is skipped by default unless live hardware benchmarking flags are provided.

---

## 7. Milestone Evaluation & Benchmark Reproduction

Each milestone provides a standalone evaluation script that loads standard datasets and executes deterministic scoring pipelines:

```bash
# Milestone 3 — Knowledge Retrieval & Reasoning Evaluator
python -m src.eval.m3_reasoning_evaluator

# Milestone 5 — Copilot Reasoning & Investigation Evaluator
python -m src.eval.m5_copilot_evaluator

# Milestone 6 — Authorized Security Assessment Evaluator
python -m src.eval.m6_assessment_evaluator

# Milestone 6.1 — Hardening & Unseen Benchmark Evaluator
python -m src.eval.m6_1_assessment_evaluator

# Milestone 7 — Multi-Agent Collaborative Research Evaluator
python -m src.eval.m7_agent_evaluator

# Milestone 8 — Human Review & Action Queue Evaluator
python -m src.eval.m8_evaluator

# Milestone 9 — Cybersecurity Q&A and VAPT Knowledge RAG Evaluator
python -m src.eval.m9_evaluator

# Milestone 10 — Deep Android & Native Binary Reverse Engineering Evaluator
python -m src.eval.m10_evaluator

# Cascade Verification (Validates 3B -> Router -> 7B live pipeline)
python -m src.engine.verify_cascade --verify-cascade
```

---

## 8. External Tool Adapters (Optional)

The platform includes adapters for binary and Android reverse engineering tools (`src/binary/tool_adapters.py`):
- **JADX:** Decompiles APK/DEX into Java source.
- **Ghidra:** Headless decompiler for native ELF/PE binaries.
- **radare2:** Native disassembler and cross-reference analyzer.

**Graceful Degradation Guarantee:**  
If JADX, Ghidra, or radare2 are not installed on the system `PATH`, the platform gracefully falls back to its pure-Python deterministic analyzers (`ManifestAnalyzer`, `DexIndexer`, `SmaliAnalyzer`, `ElfAnalyzer`, `PeAnalyzer`). Tests and evaluations pass 100% without external binaries installed.

---

## 9. Local UI Dashboard (Milestone 12)

To launch the local web user interface:

```bash
# Start backend API and local server
python run_local_ui.py

# Alternatively, start using the batch script (Windows)
.\run_local_ui.bat
```

The web interface will be accessible at `http://127.0.0.1:8000`.
