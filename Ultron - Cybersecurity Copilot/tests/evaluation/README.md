# VAPT Retrieval Benchmark Directory

This directory contains the gold-standard VAPT retrieval evaluation dataset for Phase 0.

- `vapt_retrieval_queries.json`: 100 gold-standard queries with 4-tier relevance ratings, must-retrieve targets, and metadata.
- For full documentation, schema definitions, and labeling methodology, see [`docs/VAPT_RETRIEVAL_BENCHMARK_DATASET.md`](docs/VAPT_RETRIEVAL_BENCHMARK_DATASET.md).
- To run tests:
  ```bash
  .venv\Scripts\python.exe -m pytest tests/unit/test_vapt_benchmark_dataset.py
  ```

## Batch 3 AI Evaluation & Test Integrity Benchmark
- `data/eval/batch3/holdout_dataset_ground_truth.json`: 240 versioned adjudicated cybersecurity evaluation cases across 12 families.
- `data/eval/batch3/holdout_dataset_blinded.json`: Model-facing holdout dataset strictly stripped of labels and rationales.
- To run Batch 3 suite:
  ```bash
  .venv\Scripts\python.exe -m pytest tests/unit/test_batch3_*.py
  ```
- To run the deterministic AI evaluation benchmark:
  ```bash
  .venv\Scripts\python.exe -m src.eval.batch3_evaluator
  ```
