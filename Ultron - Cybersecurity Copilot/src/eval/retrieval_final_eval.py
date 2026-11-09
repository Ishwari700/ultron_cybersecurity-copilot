"""Milestone M3 Phase M3.16: RETRIEVAL_FINAL_EVAL Generalization Evaluation.

Evaluates sealed production retriever (Candidate 1 OnnxVectorFts5Retriever)
on the untouched RETRIEVAL_FINAL_EVAL partition (n=15).
Computes Recall@5, MRR@5, Precision@5, InjectionHit@P4_256, Recall@K_fit
and deterministic query-level bootstrap confidence intervals (B=2000, seed=42).
"""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import random
import time
from typing import Any, Dict, List, Tuple

from src.eval.p4_capacity_oracle import CanonicalP4CapacityOracle
from src.evidence.cascade_models import LosslessStructuralPack
from src.knowledge.models import EvidenceGapType, QueryRendererId
from src.knowledge.query_builder import VaptQueryBuilder
from src.knowledge.retriever import OnnxVectorFts5Retriever


def deterministic_query_bootstrap_ci(
    values: List[float],
    b_resamples: int = 2000,
    seed: int = 42,
    alpha: float = 0.05,
) -> Tuple[float, float, float]:
    """
    Computes point estimate and 95% bootstrap confidence interval
    using deterministic query-level resampling.
    Returns (point_estimate, ci_lower, ci_upper).
    """
    n = len(values)
    if n == 0:
        return 0.0, 0.0, 0.0

    point_estimate = sum(values) / n
    rng = random.Random(seed)

    boot_means: List[float] = []
    for _ in range(b_resamples):
        sample = [values[rng.randint(0, n - 1)] for _ in range(n)]
        boot_means.append(sum(sample) / n)

    boot_means.sort()
    lower_idx = int((alpha / 2.0) * b_resamples)
    upper_idx = int((1.0 - alpha / 2.0) * b_resamples)
    ci_lower = boot_means[lower_idx]
    ci_upper = boot_means[upper_idx]

    return point_estimate, ci_lower, ci_upper


def run_retrieval_final_evaluation(
    dataset_path: Path = Path("data/eval/retrieval_final_eval.json"),
    manifest_path: Path = Path("data/eval/retrieval_final_eval_manifest.json"),
    output_path: Path = Path("data/eval/retrieval_final_eval_results.json"),
    db_path: Path = Path("data/vapt_corpus/vapt_knowledge.db"),
    renderer_id: QueryRendererId = QueryRendererId.RENDERER_S,
    theta_min: float = 0.010,
    top_k: int = 5,
) -> Dict[str, Any]:
    """
    Executes the one-time evaluation on RETRIEVAL_FINAL_EVAL using the sealed production retriever.
    """
    if not dataset_path.exists():
        raise FileNotFoundError(f"Final eval dataset not found at {dataset_path}")

    dataset_bytes = dataset_path.read_bytes()
    dataset_sha256 = hashlib.sha256(dataset_bytes).hexdigest()

    with open(dataset_path, "r", encoding="utf-8") as f:
        fixtures: List[Dict[str, Any]] = json.load(f)

    if manifest_path.exists():
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
            assert manifest["dataset_sha256"].lower() == dataset_sha256.lower(), "Manifest SHA mismatch!"

    retriever = OnnxVectorFts5Retriever(db_path=db_path)
    p4_oracle = CanonicalP4CapacityOracle()

    recalls_at_5: List[float] = []
    mrrs_at_5: List[float] = []
    precisions_at_5: List[float] = []
    injection_hits_256: List[float] = []
    recalls_at_k_fit: List[float] = []
    latencies_ms: List[float] = []

    per_query_results: List[Dict[str, Any]] = []

    for fixture in fixtures:
        query_id = fixture["query_id"]
        pack = LosslessStructuralPack(
            asset_id=f"ASSET-{query_id}",
            endpoint_id=f"EP-{query_id}",
            route_template=fixture["route_template"],
            http_method=fixture["http_method"],
            application_mutability="READ_ONLY" if fixture["http_method"] == "GET" else "STATE_CHANGING",
            has_cross_identity_object_access_success=fixture["has_cross_identity_object_access_success"],
            has_privilege_level_delta=fixture["has_privilege_level_delta"],
        )
        gap_type = EvidenceGapType(fixture["evidence_gap_type"])

        # Parity check
        rendered_query = VaptQueryBuilder.build_query(pack, gap_type, renderer_id)
        expected_query = fixture["expected_rendered_query"][renderer_id.value]
        assert rendered_query == expected_query, f"Parity mismatch on {query_id}"

        t_start = time.perf_counter()
        retrieved = retriever.retrieve(
            query=rendered_query,
            top_k=top_k,
            theta_min=theta_min,
            query_id=query_id,
        )
        latency = (time.perf_counter() - t_start) * 1000.0
        latencies_ms.append(latency)

        gold_ids = set(fixture["acceptable_chunk_ids"])
        retrieved_ids = [item.chunk.chunk_id for item in retrieved]
        matched = set(retrieved_ids) & gold_ids

        # Recall@5
        q_recall = len(matched) / len(gold_ids) if gold_ids else 0.0
        recalls_at_5.append(q_recall)

        # Precision@5
        q_prec = len(matched) / 5.0
        precisions_at_5.append(q_prec)

        # MRR@5
        q_mrr = 0.0
        for rank_idx, r_id in enumerate(retrieved_ids, start=1):
            if r_id in gold_ids:
                q_mrr = 1.0 / rank_idx
                break
        mrrs_at_5.append(q_mrr)

        # InjectionHit@P4_256
        q_hit = 1.0 if p4_oracle.is_injection_hit(retrieved, list(gold_ids), token_budget=256) else 0.0
        injection_hits_256.append(q_hit)

        # Recall@K_fit
        _wire, _tokens, accepted_items = p4_oracle.serialize_pack(retrieved, token_budget=256)
        fitting_ids = {item.chunk.chunk_id for item in accepted_items}
        matched_fit = fitting_ids & gold_ids
        q_recall_fit = len(matched_fit) / len(gold_ids) if gold_ids else 0.0
        recalls_at_k_fit.append(q_recall_fit)

        per_query_results.append({
            "query_id": query_id,
            "rendered_query": rendered_query,
            "retrieved_chunk_ids": retrieved_ids,
            "gold_chunk_ids": list(gold_ids),
            "recall_at_5": round(q_recall, 6),
            "mrr_at_5": round(q_mrr, 6),
            "precision_at_5": round(q_prec, 6),
            "injection_hit_256": int(q_hit),
            "recall_at_k_fit": round(q_recall_fit, 6),
            "latency_ms": round(latency, 2),
        })

    # Compute bootstrap CIs
    r5_pt, r5_lo, r5_hi = deterministic_query_bootstrap_ci(recalls_at_5)
    mrr_pt, mrr_lo, mrr_hi = deterministic_query_bootstrap_ci(mrrs_at_5)
    p5_pt, p5_lo, p5_hi = deterministic_query_bootstrap_ci(precisions_at_5)
    hit_pt, hit_lo, hit_hi = deterministic_query_bootstrap_ci(injection_hits_256)
    kfit_pt, kfit_lo, kfit_hi = deterministic_query_bootstrap_ci(recalls_at_k_fit)

    results_payload = {
        "evaluation_name": "RETRIEVAL_FINAL_EVAL_GENERALIZATION",
        "evaluation_timestamp": datetime.now(timezone.utc).isoformat(),
        "backend": "Candidate 1 (OnnxVectorFts5Retriever)",
        "renderer": renderer_id.value,
        "query_count": len(fixtures),
        "dataset_sha256": dataset_sha256,
        "bootstrap_resamples": 2000,
        "bootstrap_seed": 42,
        "metrics": {
            "recall_at_5": {
                "point_estimate": round(r5_pt, 6),
                "ci_95_lower": round(r5_lo, 6),
                "ci_95_upper": round(r5_hi, 6),
            },
            "mrr_at_5": {
                "point_estimate": round(mrr_pt, 6),
                "ci_95_lower": round(mrr_lo, 6),
                "ci_95_upper": round(mrr_hi, 6),
            },
            "precision_at_5_diagnostic": {
                "point_estimate": round(p5_pt, 6),
                "ci_95_lower": round(p5_lo, 6),
                "ci_95_upper": round(p5_hi, 6),
            },
            "injection_hit_at_p4_256": {
                "point_estimate": round(hit_pt, 6),
                "ci_95_lower": round(hit_lo, 6),
                "ci_95_upper": round(hit_hi, 6),
            },
            "recall_at_k_fit_diagnostic": {
                "point_estimate": round(kfit_pt, 6),
                "ci_95_lower": round(kfit_lo, 6),
                "ci_95_upper": round(kfit_hi, 6),
            },
            "mean_latency_ms": round(sum(latencies_ms) / len(latencies_ms), 3) if latencies_ms else 0.0,
        },
        "per_query_results": per_query_results,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results_payload, f, indent=2, sort_keys=True)

    return results_payload
