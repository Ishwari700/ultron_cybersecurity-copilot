# Milestone 10.5 Baseline Audit and Verification Record

**Platform Version:** v10.0.0-deep-android-binary-re  
**Date:** 2026-10-08  
**Audit Purpose:** Pre-cleanup baseline verification prior to folder restructuring, Git audit, and repository hardening for Milestone 11.  

---

## 1. Git State Baseline

- **Current Branch:** `master`
- **HEAD Commit:** `3f80d8e` (`validation: phase 11.6 production pipeline`)
- **Staged Files (Index):** 163 files staged from previous milestones (M6–M9)
- **Unstaged Modified Files:** 7 files (`src/artifacts/adapters/android_adapter.py`, `src/artifacts/metadata.py`, `src/artifacts/quarantine.py`, `src/binary/artifacts.py`, `src/mobile/artifacts.py`, `src/mobile/manifest.py`, `src/mobile/smali.py`)
- **Untracked Files:** 20 files (M10 implementations, datasets, tests, documentation)
- **Repository Size (Excluding `.git/`, `.venv/`, `frontend/node_modules/`):**
  - File Count: 1,491 files
  - Total Size: 133,198,313 bytes (~133.20 MB)

---

## 2. Full Test Suite Regression Baseline

Execution command: `.venv\Scripts\pytest -q`
- **Total Tests Collected:** 1,434
- **Passed:** 1,433
- **Failed:** 0
- **Errors:** 0
- **Skipped:** 1 (`tests\integration\test_live_ablation_pilot.py` - requires live pilot flag)
- **Warnings:** 2 (Starlette/httpx test client deprecation notice)
- **Execution Runtime:** 583.59 seconds (0:09:43)
- **Test Pass Rate:** 100.0% of executable tests

---

## 3. Hardware & Environmental Profile

- **Processor:** AMD Ryzen 5 5600H (6 cores, 12 logical processors)
- **Memory:** 24 GB Physical RAM
- **GPU:** NVIDIA GeForce RTX 3050 Laptop GPU (4 GB VRAM ceiling)
- **Operating System:** Microsoft Windows 11
- **Python Runtime:** Python 3.13.14 (Virtual Environment in `.venv/`)
- **LLM Engine:** Ollama (`qwen2.5-coder:3b`, `qwen2.5-coder:7b`) with `concurrency = 1`
