"""Batch 3 Live Model Evaluation Runner with Bounded Resumable Batches.

Executes local Ollama model evaluation on the blinded holdout dataset:
1. Enforces single concurrency (concurrency = 1).
2. Executes bounded batches (20-40 cases per batch).
3. Persists durable atomic checkpoint after every single case.
4. Validates model readiness and tag availability via /api/tags before inference.
5. Incompatible checkpoints (e.g. hash mismatch) are cleanly reset.
6. Reconciles completed cases and writes verified final evaluation results.
"""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import time

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.core.atomic_write import atomic_write_json
from src.eval.batch3_evaluator import Batch3AIEvaluator, RuntimeOutcome
from src.eval.batch3_holdout import DATASET_VERSION, load_blinded_dataset


def run_benchmark_batches(
    model_name: str = "qwen2.5-coder:7b",
    ollama_url: str = "http://127.0.0.1:11434",
    batch_size: int = 30,
    max_batches: int = 10,
) -> None:
    print(f"=== Starting Batch 3 Live Model Benchmark ({model_name}) ===")
    print(f"Ollama URL: {ollama_url}")
    print(f"Batch size: {batch_size} cases per batch, concurrency = 1")

    evaluator = Batch3AIEvaluator(
        mode="live_ollama",
        model_name=model_name,
        ollama_url=ollama_url,
    )

    # 1. Preflight check: model tag availability
    valid_tag, tag_err, err_ro = evaluator._check_ollama_model_tag()
    if not valid_tag:
        print(f"FATAL: Preflight model check failed: {tag_err} ({err_ro})", file=sys.stderr)
        sys.exit(1)
    print(f"Preflight passed: Model tag '{model_name}' verified active on Ollama server.")

    # 2. Inspect blinded dataset
    blinded_cases = load_blinded_dataset(evaluator.blinded_path)
    total_dataset_cases = len(blinded_cases)
    print(f"Loaded {total_dataset_cases} blinded holdout cases from {evaluator.blinded_path}")

    batch_idx = 0
    while batch_idx < max_batches:
        batch_idx += 1
        print(f"\n--- Starting Bounded Batch {batch_idx}/{max_batches} (Limit: {batch_size} new cases) ---")
        
        # Run one bounded batch
        batch_start = time.perf_counter()
        results = evaluator.evaluate_benchmark(
            resume=True,
            max_new_cases=batch_size,
        )
        batch_duration = time.perf_counter() - batch_start

        completed = results.get("cases_completed", 0)
        remaining = results.get("cases_remaining", total_dataset_cases - completed)
        is_complete = results.get("is_complete", False)

        print(f"Batch {batch_idx} completed in {batch_duration:.2f}s.")
        print(f"Progress: {completed}/{total_dataset_cases} cases completed ({remaining} remaining).")
        
        # Display runtime outcomes so far
        ro_counts = results.get("runtime_outcomes", {})
        print(f"Runtime outcomes: {ro_counts}")

        if is_complete or completed >= total_dataset_cases:
            print(f"\n>>> Full benchmark complete! All {total_dataset_cases}/{total_dataset_cases} cases evaluated.")
            break

        if batch_duration < 1.0 and remaining > 0:
            print("Warning: Batch finished unexpectedly fast with cases remaining; breaking to avoid busy loop.")
            break

    # Final summary display
    print("\n================ FINAL BENCHMARK RESULTS ================")
    final_output_path = evaluator.output_path
    if final_output_path.exists():
        final_data = json.loads(final_output_path.read_text(encoding="utf-8"))
        cm = final_data.get("confusion_matrix", {})
        em = final_data.get("error_metrics", {})
        sd = final_data.get("scorable_detection_subset", {})
        
        print(f"Total Cases Evaluated: {final_data.get('total_cases_evaluated')}")
        print(f"Is Complete: {final_data.get('is_complete')}")
        print(f"Conservative Confusion Matrix: TP={cm.get('true_positives')} FP={cm.get('false_positives')} TN={cm.get('true_negatives')} FN={cm.get('false_negatives')}")
        print(f"Conservative Precision: {em.get('precision')} ({em.get('precision_denominator')})")
        print(f"Conservative Recall:    {em.get('recall')} ({em.get('recall_denominator')})")
        print(f"Conservative Specificity: {em.get('specificity')} ({em.get('specificity_denominator')})")
        print(f"Conservative F1:        {em.get('f1_score')}")
        print(f"Abstention Rate:        {em.get('abstention_rate')} ({em.get('abstention_rate_denominator')})")
        print(f"\nScorable Binary Subset (VULNERABILITY_SUPPORTED vs NOT_SUPPORTED):")
        print(f"Candidates: {sd.get('total_scorable_candidates')}, Excluded: {sd.get('excluded_count')}")
        print(f"TP={sd.get('true_positives')} FP={sd.get('false_positives')} TN={sd.get('true_negatives')} FN={sd.get('false_negatives')}")
        print(f"Precision: {sd.get('precision')}, Recall: {sd.get('recall')}, F1: {sd.get('f1_score')}")
        print(f"Output saved to: {final_output_path}")
        print(f"Sidecar: {final_output_path}.sha256")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Batch 3 Live Ollama Evaluation")
    parser.add_argument("--model", default="qwen2.5-coder:7b", help="Model tag name")
    parser.add_argument("--url", default="http://127.0.0.1:11434", help="Ollama server URL")
    parser.add_argument("--batch-size", type=int, default=30, help="Cases per bounded batch")
    parser.add_argument("--max-batches", type=int, default=12, help="Max batches to run")
    args = parser.parse_args()

    run_benchmark_batches(
        model_name=args.model,
        ollama_url=args.url,
        batch_size=args.batch_size,
        max_batches=args.max_batches,
    )
