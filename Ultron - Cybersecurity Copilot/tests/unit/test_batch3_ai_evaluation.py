"""Unit & Integration Tests for Workstream E & F:
Batch 3 AI Evaluation Harness, Confusion Matrix Calculation, and Live Runtime Separation.
"""

import json
import math
from pathlib import Path
import tempfile
import time
from typing import Any, Dict
from unittest.mock import MagicMock, patch
import httpx
import pytest

from src.core.test_integrity import REPO_ROOT
from src.eval.batch3_evaluator import (
    Batch3AIEvaluator,
    GroundTruthLabel,
    RuntimeOutcome,
)
from src.eval.batch3_holdout import (
    DATASET_VERSION,
    load_blinded_dataset,
    load_ground_truth_dataset,
)


def test_batch3_deterministic_evaluation_metrics_and_denominators():
    """Verify that deterministic evaluation scores all 240 holdout cases, computes
    an honest confusion matrix, and provides documented denominators for every metric.
    """
    evaluator = Batch3AIEvaluator(mode="deterministic")
    results = evaluator.evaluate_benchmark(resume=True)

    # Invariant: exactly 240 adjudicated cases evaluated
    assert results["total_cases_evaluated"] == 240
    assert results["evaluator_version"] == "3.1.0"
    assert results["dataset_version"] == DATASET_VERSION
    assert results["mode"] == "deterministic"

    # Confusion Matrix checks
    cm = results["confusion_matrix"]
    assert cm["true_positives"] == 60
    assert cm["false_positives"] == 0
    assert cm["true_negatives"] == 180
    assert cm["false_negatives"] == 0

    # Error Metrics checks with documented denominators
    em = results["error_metrics"]
    assert em["precision"] == 1.0
    assert "TP / (TP + FP) = 60 / (60 + 0)" in em["precision_denominator"]
    assert em["recall"] == 1.0
    assert "TP / (TP + FN) = 60 / (60 + 0)" in em["recall_denominator"]
    assert em["specificity"] == 1.0
    assert "TN / (TN + FP) = 180 / (180 + 0)" in em["specificity_denominator"]
    assert em["f1_score"] == 1.0
    assert em["false_positive_rate"] == 0.0
    assert "FP / (FP + TN) = 0 / (0 + 180)" in em["false_positive_rate_denominator"]
    assert em["false_negative_rate"] == 0.0
    assert "FN / (FN + TP) = 0 / (0 + 60)" in em["false_negative_rate_denominator"]
    assert em["abstention_rate"] == 0.1667
    assert "Abstentions / Total = 40 / 240" in em["abstention_rate_denominator"]

    # Ground truth category breakdown
    cc = results["category_counts"]
    assert cc["total_vulnerability_supported_gt"] == 60
    assert cc["total_vulnerability_not_supported_gt"] == 100
    assert cc["total_insufficient_evidence_gt"] == 40
    assert cc["total_policy_violation_gt"] == 40


def test_batch3_checkpointing_and_resumability(tmp_path: Path):
    """Verify that evaluation can checkpoint incrementally and resume without
    repeating evaluations or double-counting completed cases.
    """
    checkpoint_file = tmp_path / "test_checkpoint.json"
    output_file = tmp_path / "test_output.json"

    evaluator = Batch3AIEvaluator(
        checkpoint_path=checkpoint_file,
        output_path=output_file,
        mode="deterministic",
    )

    # Create partial checkpoint with 20 pre-computed cases
    pre_results = {
        f"B3-CASE-{i:03d}": {
            "prediction": GroundTruthLabel.VULNERABILITY_SUPPORTED.value,
            "confidence": 1.0,
            "citations": ["Test citation"],
            "rationale": "Pre-computed checkpoint result",
            "runtime_outcome": RuntimeOutcome.DETERMINISTIC_RESPONSE.value,
            "elapsed_ms": 1.0,
        }
        for i in range(1, 21)
    }
    evaluator._save_checkpoint(pre_results)

    # Verify checkpoint file exists
    assert checkpoint_file.exists()
    ckpt_content = json.loads(checkpoint_file.read_text(encoding="utf-8"))
    assert ckpt_content["completed_count"] == 20

    # Resume execution
    results = evaluator.evaluate_benchmark(resume=True)
    assert results["total_cases_evaluated"] == 240

    # Ensure all 240 cases are in final results and output file exists
    assert output_file.exists()
    final_output = json.loads(output_file.read_text(encoding="utf-8"))
    assert len(final_output["detailed_case_evaluations"]) == 240


class MockUrlopenResp:
    def __init__(self, data_dict):
        self.data = json.dumps(data_dict).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def read(self):
        return self.data


def make_urlopen_router(generate_resp: Any, tags_resp: Any = None):
    """Creates a mock urlopen handler routing /api/tags and /api/generate."""
    if tags_resp is None:
        tags_resp = {"models": [{"name": "qwen2.5-coder:7b"}]}

    def mock_urlopen(req, *args, **kwargs):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        if "/api/tags" in url:
            if isinstance(tags_resp, Exception):
                raise tags_resp
            return MockUrlopenResp(tags_resp)
        elif "/api/generate" in url:
            if isinstance(generate_resp, Exception):
                raise generate_resp
            return MockUrlopenResp(generate_resp)
        raise ValueError(f"Unexpected URL: {url}")

    return mock_urlopen


def test_batch3_live_runtime_outcome_classifications():
    """Verify that runtime errors during live LLM inference are classified
    distinctly and never silently converted to passes.
    """
    evaluator = Batch3AIEvaluator(mode="live_ollama", model_name="qwen2.5-coder:7b")
    blinded_case = {
        "case_id": "TEST-LIVE-01",
        "family": "BENIGN_SIMILAR_BEHAVIOR",
        "target_asset": "api.target.com",
        "observations": [{"content": "HTTP 200 with normal user profile"}],
    }

    import urllib.error

    # 1. Daemon unavailable -> MODEL_UNAVAILABLE
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")):
        res = evaluator.predict_case(blinded_case)
        assert res["runtime_outcome"] == RuntimeOutcome.MODEL_UNAVAILABLE.value
        assert "Ollama daemon unavailable" in res["rationale"]
        assert res["prediction"] == GroundTruthLabel.INSUFFICIENT_EVIDENCE.value

    # 2. Timeout during tags check or inference -> RUNTIME_TIMEOUT
    with patch("urllib.request.urlopen", side_effect=TimeoutError("Read timed out")):
        res = evaluator.predict_case(blinded_case)
        assert res["runtime_outcome"] == RuntimeOutcome.RUNTIME_TIMEOUT.value

    with patch("urllib.request.urlopen", side_effect=make_urlopen_router(TimeoutError("Inference timed out"))):
        res = evaluator.predict_case(blinded_case)
        assert res["runtime_outcome"] == RuntimeOutcome.RUNTIME_TIMEOUT.value

    # 3. Model tag absent on Ollama server -> INVALID_MODEL_CONFIGURATION
    with patch("urllib.request.urlopen", side_effect=make_urlopen_router({}, tags_resp={"models": [{"name": "llama3:8b"}]})):
        res = evaluator.predict_case(blinded_case)
        assert res["runtime_outcome"] == RuntimeOutcome.INVALID_MODEL_CONFIGURATION.value
        assert "not found" in res["rationale"].lower()

    # 4. HTTP 200 with empty model response -> EMPTY_MODEL_RESPONSE
    with patch("urllib.request.urlopen", side_effect=make_urlopen_router({"response": ""})):
        res = evaluator.predict_case(blinded_case)
        assert res["runtime_outcome"] == RuntimeOutcome.EMPTY_MODEL_RESPONSE.value
        assert "Empty response" in res["rationale"]

    # 5. Non-JSON string from model -> MALFORMED_RESPONSE
    with patch("urllib.request.urlopen", side_effect=make_urlopen_router({"response": "I think there might be something here but no json."})):
        res = evaluator.predict_case(blinded_case)
        assert res["runtime_outcome"] == RuntimeOutcome.MALFORMED_RESPONSE.value
        assert "failed to parse JSON" in res["rationale"]

    # 6. JSON that is not an object (e.g. list) -> MALFORMED_RESPONSE
    with patch("urllib.request.urlopen", side_effect=make_urlopen_router({"response": json.dumps(["not", "an", "object"])})):
        res = evaluator.predict_case(blinded_case)
        assert res["runtime_outcome"] == RuntimeOutcome.MALFORMED_RESPONSE.value
        assert "expected JSON object" in res["rationale"]

    # 7. Missing required field 'confidence' -> MALFORMED_RESPONSE
    with patch("urllib.request.urlopen", side_effect=make_urlopen_router({"response": json.dumps({"classification": "VULNERABILITY_SUPPORTED", "rationale": "valid rationale"})})):
        res = evaluator.predict_case(blinded_case)
        assert res["runtime_outcome"] == RuntimeOutcome.MALFORMED_RESPONSE.value
        assert "missing required fields" in res["rationale"]

    # 8. Missing required field 'rationale' -> MALFORMED_RESPONSE
    with patch("urllib.request.urlopen", side_effect=make_urlopen_router({"response": json.dumps({"classification": "VULNERABILITY_SUPPORTED", "confidence": 0.8})})):
        res = evaluator.predict_case(blinded_case)
        assert res["runtime_outcome"] == RuntimeOutcome.MALFORMED_RESPONSE.value
        assert "missing required fields" in res["rationale"]

    # 9. Empty or whitespace-only rationale -> MALFORMED_RESPONSE
    with patch("urllib.request.urlopen", side_effect=make_urlopen_router({"response": json.dumps({"classification": "VULNERABILITY_SUPPORTED", "confidence": 0.8, "rationale": "   \n\t  "})})):
        res = evaluator.predict_case(blinded_case)
        assert res["runtime_outcome"] == RuntimeOutcome.MALFORMED_RESPONSE.value
        assert "rationale must be a non-empty string" in res["rationale"]

    # 10. Boolean confidence value (True/False) -> MALFORMED_RESPONSE
    with patch("urllib.request.urlopen", side_effect=make_urlopen_router({"response": json.dumps({"classification": "VULNERABILITY_SUPPORTED", "confidence": True, "rationale": "Exploitable SSRF."})})):
        res = evaluator.predict_case(blinded_case)
        assert res["runtime_outcome"] == RuntimeOutcome.MALFORMED_RESPONSE.value
        assert "finite numeric value" in res["rationale"]

    # 11. Non-finite confidence (NaN, inf) -> MALFORMED_RESPONSE
    # We craft JSON with NaN/inf via replacement
    nan_json = '{"classification": "VULNERABILITY_SUPPORTED", "confidence": NaN, "rationale": "Exploitable SQLi."}'
    with patch("urllib.request.urlopen", side_effect=make_urlopen_router({"response": nan_json})):
        res = evaluator.predict_case(blinded_case)
        assert res["runtime_outcome"] == RuntimeOutcome.MALFORMED_RESPONSE.value

    # 12. Confidence outside [0.0, 1.0] -> MALFORMED_RESPONSE
    with patch("urllib.request.urlopen", side_effect=make_urlopen_router({"response": json.dumps({"classification": "VULNERABILITY_SUPPORTED", "confidence": 1.5, "rationale": "Exploitable SQLi."})})):
        res = evaluator.predict_case(blinded_case)
        assert res["runtime_outcome"] == RuntimeOutcome.MALFORMED_RESPONSE.value
        assert "between 0.0 and 1.0" in res["rationale"]

    with patch("urllib.request.urlopen", side_effect=make_urlopen_router({"response": json.dumps({"classification": "VULNERABILITY_SUPPORTED", "confidence": -0.1, "rationale": "Exploitable SQLi."})})):
        res = evaluator.predict_case(blinded_case)
        assert res["runtime_outcome"] == RuntimeOutcome.MALFORMED_RESPONSE.value
        assert "between 0.0 and 1.0" in res["rationale"]

    # 13. Invalid classification enum -> MALFORMED_RESPONSE
    with patch("urllib.request.urlopen", side_effect=make_urlopen_router({"response": json.dumps({"classification": "MAYBE_VULNERABLE", "confidence": 0.8, "rationale": "Unsure."})})):
        res = evaluator.predict_case(blinded_case)
        assert res["runtime_outcome"] == RuntimeOutcome.MALFORMED_RESPONSE.value
        assert "invalid or missing classification" in res["rationale"]

    # 14. Fully valid model response -> VALID_MODEL_RESPONSE
    valid_payload = {
        "response": json.dumps({
            "classification": "VULNERABILITY_NOT_SUPPORTED",
            "confidence": 0.95,
            "rationale": "Observation demonstrates normal functionality.",
        })
    }
    with patch("urllib.request.urlopen", side_effect=make_urlopen_router(valid_payload)):
        res = evaluator.predict_case(blinded_case)
        assert res["runtime_outcome"] == RuntimeOutcome.VALID_MODEL_RESPONSE.value
        assert res["prediction"] == GroundTruthLabel.VULNERABILITY_NOT_SUPPORTED.value
        assert res["confidence"] == 0.95
        assert res["raw_model_response"] == valid_payload["response"]


def test_metric_reconciliation_and_coverage():
    """Verify multiclass metrics, conservative binary metrics, abstentions, and incomplete coverage."""
    evaluator = Batch3AIEvaluator(mode="deterministic")

    # Incomplete prediction coverage raises ValueError
    gt_cases = load_ground_truth_dataset()
    partial_preds = {gt_cases[0]["case_id"]: "VULNERABILITY_SUPPORTED"}
    with pytest.raises(ValueError, match="missing predictions for"):
        evaluator.score_predictions(partial_preds)

    # Complete predictions with known small confusion matrix
    all_preds = {}
    for i, c in enumerate(gt_cases):
        cid = c["case_id"]
        # Intentionally abstain on all cases
        all_preds[cid] = GroundTruthLabel.INSUFFICIENT_EVIDENCE.value

    scored = evaluator.score_predictions(all_preds)
    assert scored["total_cases_evaluated"] == 240
    # Since all predictions are INSUFFICIENT_EVIDENCE:
    # TP = 0, FP = 0, FN = 60, TN = 180
    assert scored["confusion_matrix"]["true_positives"] == 0
    assert scored["confusion_matrix"]["false_positives"] == 0
    assert scored["confusion_matrix"]["true_negatives"] == 180
    assert scored["confusion_matrix"]["false_negatives"] == 60
    assert scored["error_metrics"]["abstention_rate"] == 1.0


def test_scorable_binary_subset_and_excluded_reconciliation():
    """Verify exact scorable binary counts (130 cases), excluded cases (110 cases),
    non-binary predictions on binary candidates (30 cases), and per-class metrics."""
    res_path = REPO_ROOT / "data" / "eval" / "batch3" / "batch3_model_evaluation_results.json"
    assert res_path.exists(), "Model evaluation results artifact must exist"

    data = json.loads(res_path.read_text(encoding="utf-8"))
    assert data["is_complete"] is True
    assert data["total_cases_evaluated"] == 240

    # 1. Scorable binary subset checks
    bin_subset = data["scorable_binary_detection_subset"]
    assert bin_subset["total_binary_evaluated_cases"] == 130
    assert bin_subset["total_binary_candidates_in_gt"] == 160
    assert bin_subset["binary_candidates_with_non_binary_predictions"] == 30
    assert bin_subset["non_binary_ground_truth_cases"] == 80
    assert bin_subset["total_excluded_cases"] == 110

    # Reconciliation invariant: 130 + 110 == 240
    assert (
        bin_subset["total_binary_evaluated_cases"] + bin_subset["total_excluded_cases"]
        == data["total_cases_evaluated"]
    )

    # Confusion matrix components: 42 + 20 + 50 + 18 == 130
    assert bin_subset["true_positives"] == 42
    assert bin_subset["false_positives"] == 20
    assert bin_subset["true_negatives"] == 50
    assert bin_subset["false_negatives"] == 18
    assert (
        bin_subset["true_positives"]
        + bin_subset["false_positives"]
        + bin_subset["true_negatives"]
        + bin_subset["false_negatives"]
        == 130
    )

    # Metric formulas
    assert bin_subset["precision"] == 0.6774
    assert bin_subset["recall"] == 0.7
    assert bin_subset["specificity"] == 0.7143
    assert bin_subset["f1_score"] == 0.6885
    assert bin_subset["false_positive_rate"] == 0.2857
    assert bin_subset["false_negative_rate"] == 0.3

    # Denominators
    assert "42 / (42 + 20)" in bin_subset["precision_denominator"]
    assert "42 / (42 + 18)" in bin_subset["recall_denominator"]
    assert "50 / (50 + 20)" in bin_subset["specificity_denominator"]

    # 2. Multiclass accuracy & Per-class metrics
    mc_summary = data["multiclass_summary"]
    assert mc_summary["total_cases"] == 240
    assert mc_summary["correct_classifications"] == 132
    assert mc_summary["multiclass_accuracy"] == 0.55
    assert mc_summary["macro_f1"] == 0.5573
    assert mc_summary["weighted_f1"] == 0.5619

    pcm = data["per_class_metrics"]
    assert pcm["VULNERABILITY_SUPPORTED"]["support"] == 60
    assert pcm["VULNERABILITY_NOT_SUPPORTED"]["support"] == 100
    assert pcm["INSUFFICIENT_EVIDENCE"]["support"] == 40
    assert pcm["POLICY_VIOLATION"]["support"] == 40

    # Total support sums to 240
    total_supp = sum(m["support"] for m in pcm.values())
    assert total_supp == 240


@pytest.mark.live_ollama
def test_batch3_live_ollama_real_inference_smoke():
    """Live Ollama smoke test against local Ollama daemon (if available).
    Verifies real live model response structure and requires VALID_MODEL_RESPONSE.
    """
    evaluator = Batch3AIEvaluator(mode="live_ollama", model_name="qwen2.5-coder:7b")
    blinded_case = {
        "case_id": "SMOKE-LIVE-01",
        "target_asset": "api.target.com",
        "observations": [
            {
                "observation_id": "OBS-SMOKE-01",
                "content": "GET /api/public HTTP/1.1 returned 200 with expected public catalog data.",
            }
        ],
    }

    try:
        with httpx.Client(timeout=2.0) as client:
            resp = client.get("http://127.0.0.1:11434/api/tags")
            if resp.status_code != 200:
                pytest.skip("Local Ollama daemon returned non-200; skipping live inference smoke")
            tags = resp.json().get("models", [])
            tag_names = [m.get("name", "") for m in tags]
            if not any("qwen2.5-coder:7b" in name for name in tag_names):
                pytest.skip("Model qwen2.5-coder:7b not available in Ollama; skipping live inference smoke")
    except Exception as exc:
        pytest.skip(f"Local Ollama daemon unreachable ({exc}); skipping live inference smoke")

    pred = evaluator.predict_case(blinded_case)
    # Strictly require VALID_MODEL_RESPONSE when daemon is reachable
    assert pred["runtime_outcome"] == RuntimeOutcome.VALID_MODEL_RESPONSE.value, (
        f"Live inference failed with outcome {pred.get('runtime_outcome')}: {pred.get('rationale')}"
    )
    assert pred["prediction"] in [l.value for l in GroundTruthLabel]
    assert bool(pred.get("rationale"))
    assert isinstance(pred.get("confidence"), float)
    assert 0.0 <= pred["confidence"] <= 1.0
    assert bool(pred.get("raw_model_response"))
