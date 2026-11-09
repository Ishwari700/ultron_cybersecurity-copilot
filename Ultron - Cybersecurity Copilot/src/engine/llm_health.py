"""LLM Health Check diagnostic CLI for Ollama runtime and Qwen models."""

import json
import os
import subprocess
import sys
import time
from typing import Any, Dict, Optional
import httpx

from src.core.config import load_config
from src.engine.models import HypothesisDecision, HypothesisModelOutput
from src.engine.runner import OllamaRunner, SYSTEM_POLICY_PROMPT


def check_gpu() -> Dict[str, Any]:
    """Check GPU detection via nvidia-smi."""
    try:
        res = subprocess.run(
            ["nvidia-smi", "--query-gpu=name,driver_version,memory.total,memory.used", "--format=csv,noheader"],
            capture_output=True,
            text=True,
            check=True,
        )
        line = res.stdout.strip().split("\n")[0]
        parts = [p.strip() for p in line.split(",")]
        return {
            "detected": True,
            "name": parts[0] if len(parts) > 0 else "Unknown GPU",
            "driver": parts[1] if len(parts) > 1 else "Unknown",
            "vram_total": parts[2] if len(parts) > 2 else "Unknown",
            "vram_used": parts[3] if len(parts) > 3 else "Unknown",
        }
    except Exception:
        return {"detected": False, "name": "None", "driver": "N/A", "vram_total": "N/A", "vram_used": "N/A"}


def run_health_check(base_url: Optional[str] = None) -> int:
    """Run full diagnostic check and print standardized report."""
    cfg = load_config()
    url = (base_url or cfg.ollama.base_url).rstrip("/")

    print("=" * 60)
    print(" V6 Final — Local LLM Health & Diagnostic Check")
    print("=" * 60)

    # 1. GPU Detection
    gpu_info = check_gpu()
    print(f"GPU detected:           {'YES' if gpu_info['detected'] else 'NO'} ({gpu_info['name']}, VRAM: {gpu_info['vram_total']})")

    # 2. Ollama reachable
    ollama_online = False
    installed_models = []
    try:
        with httpx.Client(timeout=3.0) as client:
            resp = client.get(f"{url}/api/tags")
            if resp.status_code == 200:
                ollama_online = True
                data = resp.json()
                installed_models = [m.get("name", "") for m in data.get("models", [])]
    except Exception:
        pass

    print(f"Ollama reachable:       {'YES' if ollama_online else 'NO'} ({url})")

    if not ollama_online:
        print("\n[!] Error: Local Ollama daemon is not responding.")
        print("    Ensure Ollama is started on localhost (default: 127.0.0.1:11434).")
        return 1

    # 3. Model Availability
    model_3b_name = cfg.ollama.lightweight_model
    model_7b_name = cfg.ollama.primary_model

    has_3b = any(model_3b_name in m for m in installed_models)
    has_7b = any(model_7b_name in m for m in installed_models)

    print(f"3B available ({model_3b_name}): {'YES' if has_3b else 'NO'}")
    print(f"7B available ({model_7b_name}): {'YES' if has_7b else 'NO'}")

    schema = HypothesisModelOutput.model_json_schema()
    sample_system = SYSTEM_POLICY_PROMPT
    sample_user = """SECURITY REASONING TASK:
Evaluate target asset against taxonomy category [API-BOLA-001].
Target Asset ID: ASSET-HEALTH-01
Method: GET
Path Template: /api/v1/health

AVAILABLE EVIDENCE:
EVIDENCE [FACT-01] (source: synthetic, trust: UNTRUSTED)
GET /api/v1/health returned 200 OK
"""

    # 4. 3B Inference Test
    pass_3b = False
    if has_3b:
        runner_3b = OllamaRunner(base_url=url, model_name=model_3b_name, num_ctx=2048, timeout_seconds=30)
        t0 = time.perf_counter()
        try:
            out_3b = runner_3b.generate_structured(sample_system, sample_user, schema)
            elapsed_3b = time.perf_counter() - t0
            HypothesisModelOutput.model_validate(out_3b)
            pass_3b = True
            print(f"3B inference:           PASS ({elapsed_3b:.2f}s latency)")
        except Exception as e:
            print(f"3B inference:           FAIL ({e})")
    else:
        print("3B inference:           SKIPPED (Model not pulled)")

    # 5. 7B Inference Test
    pass_7b = False
    if has_7b:
        runner_7b = OllamaRunner(base_url=url, model_name=model_7b_name, num_ctx=2048, timeout_seconds=60)
        t0 = time.perf_counter()
        try:
            out_7b = runner_7b.generate_structured(sample_system, sample_user, schema)
            elapsed_7b = time.perf_counter() - t0
            HypothesisModelOutput.model_validate(out_7b)
            pass_7b = True
            print(f"7B inference:           PASS ({elapsed_7b:.2f}s latency)")
        except Exception as e:
            print(f"7B inference:           FAIL ({e})")
    else:
        print("7B inference:           SKIPPED (Model not pulled)")

    # 6. Schema Validation
    schema_ok = pass_3b or pass_7b
    print(f"schema validation:      {'PASS' if schema_ok else 'FAIL'}")
    print("=" * 60)

    return 0 if (ollama_online and (pass_3b or pass_7b)) else 1


if __name__ == "__main__":
    sys.exit(run_health_check())
