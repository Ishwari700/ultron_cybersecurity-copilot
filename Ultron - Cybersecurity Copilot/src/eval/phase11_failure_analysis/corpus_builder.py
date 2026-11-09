"""
Milestone M5 Phase 11.1: Failure Corpus Builder.

Extracts, normalizes, attributes, and serializes call records from historical
benchmarks (Phase 10, Phase 9, Phase 8, Phase 7) into a unified, reproducible
failure corpus JSONL and manifest.
"""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple

from src.eval.phase11_failure_analysis.attribution import attribute_failure
from src.eval.phase11_failure_analysis.taxonomy import (
    FailureAttributionResult,
    FailureCode,
    TAXONOMY_METADATA,
)
from src.eval.scenarios import EvaluationScenario, get_gold_set_scenarios

CORPUS_PIPELINE_VERSION = "1.0.0"
PIPELINE_TIMESTAMP = "2026-09-28T18:00:00Z"

HISTORICAL_SOURCE_CONFIGS = [
    {
        "phase": "PHASE_10",
        "path": "data/eval/m5_phase10_full_population_validation.json",
        "expected_sha256": "6821d207729de97ac99657a09e38c25895a73285fe9c485d299dc27f37d2bdba",
        "is_list": True,
        "record_list_key": None,
    },
    {
        "phase": "PHASE_9",
        "path": "data/eval/m5_phase9_semantic_budget_study.json",
        "expected_sha256": "3c0d3e503c7ed24470b14dfde0bd763c631a9b5dbf70c047bbca72cfaab07f95",
        "is_list": False,
        "record_list_key": "call_records",
    },
    {
        "phase": "PHASE_8",
        "path": "data/eval/m5_phase8_semantic_study.json",
        "expected_sha256": "b1df9a62fb07d76e0abf6e3935ccbabdaa1713f4c594019ae30c9e59567a45c6",
        "is_list": False,
        "record_list_key": "phase_8_2_protocol_study.call_records",
    },
    {
        "phase": "PHASE_7",
        "path": "data/eval/m5_phase7_benchmark_final.json",
        "expected_sha256": "1e0ed90c4aa672f135d2d2f2240a14d22fa0037c03efda33634f4bf10ff0b125",
        "is_list": False,
        "record_list_key": "call_records",
    },
]

SUSPICIOUS_SECRET_PATTERNS = [
    re.compile(r"(?i)(password|secret|api[_-]?key|bearer\s+[a-z0-9_-]{16,})\s*[:=]\s*['\"][^'\"]+['\"]"),
    re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"),  # raw JWT
]


def compute_file_sha256(filepath: str) -> str:
    """Computes SHA-256 digest of a local file."""
    with open(filepath, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def compute_record_checksum(record_dict: Dict[str, Any]) -> str:
    """Computes deterministic SHA-256 checksum of a normalized dictionary."""
    serialized = json.dumps(record_dict, sort_keys=True)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def assert_zero_sensitive_data(text: str, context: str = "") -> None:
    """Fails closed if unredacted secrets or live JWTs appear in text."""
    for pat in SUSPICIOUS_SECRET_PATTERNS:
        match = pat.search(text)
        if match:
            # Allow typed placeholders such as [REDACTED_JWT_1] or [REDACTED_API_KEY]
            matched_str = match.group(0)
            if "REDACTED" not in matched_str:
                raise ValueError(
                    f"Sensitive secret pattern detected in failure corpus ({context}): {matched_str[:30]}..."
                )


def build_corpus_records(
    repo_root: Optional[Path] = None,
    include_historical_exploratory: bool = True,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Builds the failure corpus from authoritative evaluation datasets.
    Returns (corpus_records, manifest).
    """
    if repo_root is None:
        repo_root = Path(__file__).resolve().parent.parent.parent.parent

    # 1. Load Scenarios Metadata Map
    scenarios_list = get_gold_set_scenarios()
    scenario_map: Dict[str, EvaluationScenario] = {s.scenario_id: s for s in scenarios_list}

    corpus_records: List[Dict[str, Any]] = []
    source_manifests: Dict[str, Any] = {}

    configs_to_process = (
        HISTORICAL_SOURCE_CONFIGS if include_historical_exploratory else [HISTORICAL_SOURCE_CONFIGS[0]]
    )

    for cfg in configs_to_process:
        source_rel_path = cfg["path"]
        source_full_path = repo_root / source_rel_path
        if not source_full_path.exists():
            raise FileNotFoundError(f"Authoritative source file missing: {source_full_path}")

        actual_sha = compute_file_sha256(str(source_full_path))
        if actual_sha != cfg["expected_sha256"]:
            raise ValueError(
                f"IMMUTABILITY VIOLATION: Source {source_rel_path} SHA256 mismatch! "
                f"Expected {cfg['expected_sha256']}, got {actual_sha}"
            )

        with open(source_full_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        raw_records: List[Dict[str, Any]] = []
        if cfg["is_list"]:
            raw_records = data
        else:
            key_path = cfg["record_list_key"]
            if "." in key_path:
                parts = key_path.split(".")
                sub = data
                for p in parts:
                    sub = sub.get(p, {})
                raw_records = sub if isinstance(sub, list) else []
            else:
                raw_records = data.get(key_path, [])

        source_manifests[cfg["phase"]] = {
            "source_path": source_rel_path,
            "source_sha256": actual_sha,
            "total_records_extracted": len(raw_records),
        }

        phase_prefix = cfg["phase"].replace("_", "")

        for idx, rec in enumerate(raw_records):
            sid = rec.get("scenario_id") or rec.get("fixture_id") or f"UNKNOWN-SCEN-{idx}"
            scen = scenario_map.get(sid)

            scen_cat_id = scen.category_id if scen else rec.get("category_id")
            scen_vuln = scen.vulnerable_variant if scen else rec.get("vulnerable_variant", False)
            app_family = scen.app_family if scen else "unknown"

            # Execute Deterministic Attribution
            attr_res: FailureAttributionResult = attribute_failure(
                record=rec,
                scenario_category_id=scen_cat_id,
                ground_truth_vulnerable=scen_vuln,
            )

            cid = rec.get("condition_id") or rec.get("condition") or rec.get("track_id") or "UNKNOWN"
            call_idx = rec.get("call_index", idx)

            corpus_id = f"CORPUS-{phase_prefix}-{cid}-{sid}-CALL-{call_idx:03d}"

            # Raw response snippet for audit (truncated to 300 chars, sanitized)
            raw_resp = str(rec.get("raw_response", ""))
            assert_zero_sensitive_data(raw_resp, context=corpus_id)
            snippet = raw_resp[:300] if raw_resp else None

            # Track package
            track_id = rec.get("track_id") or ("TRACK_D" if "D" in str(cid) else "TRACK_A")
            is_rag = "D" in str(cid) or "D" in str(track_id) or "TRACK_D" in str(track_id)
            is_cascade = is_rag or rec.get("cascade_packet") is not None

            # Provenance & Record Checksum
            source_checksum = compute_record_checksum(rec)

            is_useful = attr_res.is_valid_typed and scen_vuln

            normalized_record = {
                "corpus_record_id": corpus_id,
                "provenance": {
                    "source_phase": cfg["phase"],
                    "source_artifact": source_rel_path,
                    "source_artifact_sha256": actual_sha,
                    "source_call_index": call_idx,
                    "source_record_checksum": source_checksum,
                    "corpus_pipeline_version": CORPUS_PIPELINE_VERSION,
                    "extracted_at_utc": PIPELINE_TIMESTAMP,
                },
                "identity": {
                    "scenario_id": sid,
                    "condition_id": cid,
                    "track_id": track_id,
                    "architecture": rec.get("architecture") or ("DETERMINISTIC_EXPERIMENT_SKELETON" if cid in ["C1", "C2"] else "BASELINE"),
                    "app_family": app_family,
                    "target_category_id": scen_cat_id,
                    "vulnerable_variant": scen_vuln,
                },
                "runtime_telemetry": {
                    "model_name": rec.get("model_name", "qwen2.5-coder:7b"),
                    "model_digest": rec.get("model_digest"),
                    "num_ctx": rec.get("num_ctx", 2048),
                    "num_predict": rec.get("num_predict", 300),
                    "temperature": rec.get("temperature", 0.0),
                    "seed": rec.get("seed", 42),
                    "timed_out": bool(rec.get("timed_out", False)),
                    "total_latency_ms": rec.get("total_latency_ms", rec.get("latency_ms")),
                    "inference_latency_ms": rec.get("inference_latency_ms", "unavailable"),
                    "eval_count": rec.get("eval_count"),
                    "prompt_eval_count": rec.get("prompt_eval_count"),
                },
                "context_package": {
                    "context_class": "FULL_CASCADE_RAG" if is_rag else "MINIMAL_STRUCTURAL",
                    "rag_present": is_rag,
                    "cascade_present": is_cascade,
                    "handoff_present": rec.get("handoff_present", True),
                    "evidence_gap_type": rec.get("evidence_gap_type"),
                    "target_asset_id": scen.target_asset.get("asset_id") if scen and hasattr(scen, "target_asset") and isinstance(scen.target_asset, dict) else None,
                },
                "model_output": {
                    "raw_response_snippet": snippet,
                    "candidate_decision": rec.get("candidate_decision"),
                    "final_decision": rec.get("final_decision"),
                    "experiment_action": rec.get("experiment_action") or rec.get("action"),
                    "supporting_outcome": rec.get("supporting_outcome") or rec.get("supporting"),
                    "disproving_outcome": rec.get("disproving_outcome") or rec.get("disproving"),
                },
                "attribution": {
                    "primary_failure_code": attr_res.primary_code.value,
                    "primary_failure_name": attr_res.primary_name,
                    "contributing_failure_codes": [c.value for c in attr_res.contributing_codes],
                    "observed_validator_failure": attr_res.observed_validator_failure,
                    "skeleton_compliant": rec.get("skeleton_compliant"),
                    "polarity_valid": attr_res.is_polarity_valid,
                    "grounding_valid": attr_res.is_grounding_valid,
                    "is_action_compatible": attr_res.is_action_compatible,
                    "is_exact_polarity_inversion": attr_res.is_exact_polarity_inversion,
                    "is_hypothesis_candidate": attr_res.is_hypothesis_candidate,
                    "is_valid_typed_experiment": attr_res.is_valid_typed,
                    "is_useful_vulnerable_hypothesis": is_useful,
                    "details": attr_res.details,
                },
            }

            corpus_records.append(normalized_record)

    # Compile Manifest
    manifest = {
        "manifest_version": "1.0.0",
        "corpus_pipeline_version": CORPUS_PIPELINE_VERSION,
        "created_at_utc": PIPELINE_TIMESTAMP,
        "total_corpus_records": len(corpus_records),
        "source_artifacts": source_manifests,
        "breakdown_by_phase": {},
        "breakdown_by_primary_code": {},
        "breakdown_by_condition": {},
        "taxonomy_reference": {
            code.value: TAXONOMY_METADATA[code]["name"] for code in FailureCode
        },
    }

    # Populate breakdowns
    for r in corpus_records:
        ph = r["provenance"]["source_phase"]
        manifest["breakdown_by_phase"][ph] = manifest["breakdown_by_phase"].get(ph, 0) + 1

        pcode = r["attribution"]["primary_failure_code"]
        manifest["breakdown_by_primary_code"][pcode] = manifest["breakdown_by_primary_code"].get(pcode, 0) + 1

        cid = r["identity"]["condition_id"]
        manifest["breakdown_by_condition"][cid] = manifest["breakdown_by_condition"].get(cid, 0) + 1

    return corpus_records, manifest


def export_failure_corpus(
    output_jsonl_path: str = "data/eval/m5_phase11_1_failure_corpus.jsonl",
    output_manifest_path: str = "data/eval/m5_phase11_1_failure_corpus_manifest.json",
    repo_root: Optional[Path] = None,
) -> Dict[str, Any]:
    """
    Exports the normalized failure corpus to JSONL and manifest.
    Returns summary metadata including file hashes.
    """
    if repo_root is None:
        repo_root = Path(__file__).resolve().parent.parent.parent.parent

    jsonl_file = repo_root / output_jsonl_path
    manifest_file = repo_root / output_manifest_path

    records, manifest = build_corpus_records(repo_root=repo_root)

    # Write JSONL with deterministic sort_keys
    with open(jsonl_file, "w", encoding="utf-8") as f:
        for r in records:
            line = json.dumps(r, sort_keys=True)
            f.write(line + "\n")

    corpus_sha = compute_file_sha256(str(jsonl_file))
    manifest["corpus_file_sha256"] = corpus_sha
    manifest["corpus_file_path"] = output_jsonl_path

    # Write Manifest
    with open(manifest_file, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)

    manifest_sha = compute_file_sha256(str(manifest_file))

    return {
        "total_records": len(records),
        "corpus_jsonl_path": output_jsonl_path,
        "corpus_jsonl_sha256": corpus_sha,
        "manifest_path": output_manifest_path,
        "manifest_sha256": manifest_sha,
        "phase10_records": manifest["breakdown_by_phase"].get("PHASE_10", 0),
    }
