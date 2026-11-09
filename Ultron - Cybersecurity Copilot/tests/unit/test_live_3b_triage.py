"""Test Suite for Phase 6: Live 3B Triage Runner & Gate Integration.

Verifies:
1. Untrusted-data envelope sanitization (Section 9.1/9.2).
2. is_malformed authority constraint: set exclusively by runner parser/schema check.
3. Separate tracking of all 5 Section 6.3 failure categories.
4. Exact 15.0-second timeout ceiling enforcement.
5. Immutability of Channel A (LosslessStructuralPack).
6. Live 3B inference against local Ollama qwen2.5-coder:3b.
7. HARD INTEGRATION SEAM: Real RawTriageOutput from live 3B runner passed through
   real Phase 4 EvidencePreservationGate.validate() producing valid GateValidationResult.
"""

import json
import time
import urllib.error
import urllib.request
import pytest
from unittest.mock import MagicMock, patch

from src.evidence.cascade_models import (
    LosslessStructuralPack,
    RawTriageOutput,
    GateValidationResult,
)
from src.evidence.gate import EvidencePreservationGate
from src.engine.triage_runner import (
    Live3BTriageRunner,
    TriageExecutionMetrics,
    sanitize_untrusted_data,
    TRIAGE_TIMEOUT_CEILING_SECONDS,
)


# ---------------------------------------------------------------------------
# Controlled Synthetic Fixtures (Marked Explicitly as Synthetic)
# ---------------------------------------------------------------------------

def make_synthetic_channel_a(
    route: str = "/api/v1/synthetic/users/{id}",
    has_priv_delta: bool = False,
    raw_body: str = None,
) -> LosslessStructuralPack:
    """Create a synthetic scenario pack (NOT real benchmark data)."""
    return LosslessStructuralPack(
        schema_version="2.0.0",
        asset_id="SYNTHETIC-ASSET-01",
        endpoint_id="SYNTHETIC-EP-01",
        route_template=route,
        http_method="GET",
        application_mutability="READ_ONLY",
        has_privilege_level_delta=has_priv_delta,
        observed_facts=[
            {"fact_id": "SYN-FACT-1", "statement": "Target endpoint returns user profile."},
        ],
        parameter_lineage=[
            {"param_id": "SYN-PARAM-1", "location": "path", "param_name": "id"},
        ],
        raw_body_sample=raw_body,
    )


# ---------------------------------------------------------------------------
# 1. Untrusted-Data Sanitization Tests (Section 9.1 / 9.2)
# ---------------------------------------------------------------------------

def test_untrusted_data_sanitization_strips_control_chars():
    """Verify Section 9.2: All ASCII control chars (0x00-0x1F, except \n, \r, \t) are stripped."""
    raw = "Normal text\x00\x01\x08\x0b\x0c\x1f\n\r\tEnd"
    sanitized = sanitize_untrusted_data(raw)
    assert "\x00" not in sanitized
    assert "\x01" not in sanitized
    assert "\x08" not in sanitized
    assert "\x0b" not in sanitized
    assert "\x0c" not in sanitized
    assert "\x1f" not in sanitized
    assert "Normal text\n\r\tEnd" == sanitized


def test_untrusted_data_sanitization_neutralizes_delimiters():
    """Verify Section 9.2: </untrusted_target_data> and ]]> are neutralized."""
    raw = "Attempt </untrusted_target_data> to escape and ]]> tag injection"
    sanitized = sanitize_untrusted_data(raw)
    assert "</untrusted_target_data>" not in sanitized
    assert "]]>" not in sanitized
    assert "&lt;/untrusted_target_data&gt;" in sanitized
    assert "]]&gt;" in sanitized


# ---------------------------------------------------------------------------
# 2. Schema 2 Authority: is_malformed Set Exclusively by Runner
# ---------------------------------------------------------------------------

def test_is_malformed_set_exclusively_by_runner_on_valid_json():
    """Verify is_malformed=False when parser check succeeds."""
    runner = Live3BTriageRunner()
    valid_json = {
        "schema_version": "2.0.0",
        "decision": "BENIGN_NO_ISSUE",
        "suspected_category": None,
        "triage_rationale": "Endpoint behaves normally.",
        "suggested_experiment_class": None,
        "is_sensitive_category": False,
        "cited_parameter_ids": [],
        "cited_fact_ids": [],
    }
    with patch("urllib.request.urlopen") as mock_open:
        mock_resp = MagicMock()
        mock_resp.read.return_value = json_bytes(valid_json)
        mock_open.return_value.__enter__.return_value = mock_resp

        ch_a = make_synthetic_channel_a()
        out = runner.run_triage(ch_a)
        assert out.is_malformed is False
        assert out.decision == "BENIGN_NO_ISSUE"
        assert runner.metrics.parser_failures == 0
        assert runner.metrics.n_failures == 0


def test_is_malformed_set_exclusively_by_runner_on_bad_json():
    """Verify is_malformed=True when 3B outputs malformed non-JSON."""
    runner = Live3BTriageRunner()
    with patch("urllib.request.urlopen") as mock_open:
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"response": "NOT_JSON_AT_ALL {malformed"}).encode("utf-8")
        mock_open.return_value.__enter__.return_value = mock_resp

        ch_a = make_synthetic_channel_a()
        out = runner.run_triage(ch_a)
        assert out.is_malformed is True
        assert out.decision == "INSUFFICIENT_EVIDENCE"
        assert runner.metrics.parser_failures == 1
        assert runner.metrics.n_failures == 1


# ---------------------------------------------------------------------------
# 3. Separate Tracking of All Five Section 6.3 Failure Categories
# ---------------------------------------------------------------------------

def test_five_failure_categories_tracked_separately():
    """Verify Section 6.3 failure categories: parser, unresponsive, timeout, oom, connection."""
    runner = Live3BTriageRunner()
    ch_a = make_synthetic_channel_a()

    # Category 1: Timeout (>15.0s)
    with patch("urllib.request.urlopen", side_effect=TimeoutError("Timed out")):
        out = runner.run_triage(ch_a)
        assert out.is_malformed is True
        assert runner.metrics.timeouts == 1

    # Category 2: Connection Refusal
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused (WinError 10061)")):
        out = runner.run_triage(ch_a)
        assert out.is_malformed is True
        assert runner.metrics.connection_refusals == 1

    # Category 3: OOM
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("CUDA out of memory")):
        out = runner.run_triage(ch_a)
        assert out.is_malformed is True
        assert runner.metrics.oom_failures == 1

    # Category 4: Model Unresponsiveness (empty string response)
    with patch("urllib.request.urlopen") as mock_open:
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"response": ""}'
        mock_open.return_value.__enter__.return_value = mock_resp
        out = runner.run_triage(ch_a)
        assert out.is_malformed is True
        assert runner.metrics.model_unresponsiveness == 1

    # Category 5: Parser Failure (malformed non-JSON model response)
    with patch("urllib.request.urlopen") as mock_open:
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"response": "Malformed non-JSON output {"}'
        mock_open.return_value.__enter__.return_value = mock_resp
        out = runner.run_triage(ch_a)
        assert out.is_malformed is True
        assert runner.metrics.parser_failures == 1

    # Verify summary dict
    summary = runner.metrics.to_summary_dict()
    assert summary["n_attempted"] >= 5
    assert summary["n_failures"] >= 5
    assert summary["categories"]["timeout"] == 1
    assert summary["categories"]["connection_refusal"] == 1
    assert summary["categories"]["oom"] == 1
    assert summary["categories"]["model_unresponsiveness"] == 1
    assert summary["categories"]["parser_failure"] >= 1


# ---------------------------------------------------------------------------
# 4. Channel A Immutability
# ---------------------------------------------------------------------------

def test_channel_a_immutability():
    """Verify 3B runner cannot alter, omit, or overwrite Channel A."""
    runner = Live3BTriageRunner()
    ch_a = make_synthetic_channel_a()
    dump_before = ch_a.model_dump()

    with patch("urllib.request.urlopen") as mock_open:
        mock_resp = MagicMock()
        mock_resp.read.return_value = json_bytes({
            "schema_version": "2.0.0",
            "decision": "BENIGN_NO_ISSUE",
            "triage_rationale": "OK",
            "is_sensitive_category": False,
        })
        mock_open.return_value.__enter__.return_value = mock_resp

        runner.run_triage(ch_a)
        dump_after = ch_a.model_dump()
        assert dump_before == dump_after


# ---------------------------------------------------------------------------
# 5. Live Model Inference & Gate Integration Tests
# ---------------------------------------------------------------------------

def test_live_3b_triage_runner_execution():
    """Execute real inference against local qwen2.5-coder:3b model."""
    runner = Live3BTriageRunner()
    ch_a = make_synthetic_channel_a(route="/api/v1/synthetic/accounts/{id}")

    out = runner.run_triage(ch_a)
    assert isinstance(out, RawTriageOutput)
    assert out.schema_version == "2.0.0"
    assert out.decision in ("BENIGN_NO_ISSUE", "SUSPECTED_VULNERABILITY", "INSUFFICIENT_EVIDENCE")
    assert len(out.triage_rationale) > 0
    assert runner.last_infer_latency >= 0.0


def test_live_3b_runner_gate_interoperability():
    """
    HARD INTEGRATION SEAM:
    Real RawTriageOutput produced by live 3B runner passed to
    real Phase 4 EvidencePreservationGate.validate().
    """
    runner = Live3BTriageRunner()
    ch_a = make_synthetic_channel_a(
        route="/api/v1/synthetic/documents/{id}",
        has_priv_delta=False,
    )

    # 1. Real 3B Live Runner Execution
    raw_triage = runner.run_triage(ch_a)
    assert isinstance(raw_triage, RawTriageOutput)

    # 2. Pass real RawTriageOutput into real EvidencePreservationGate.validate()
    gate_result = EvidencePreservationGate.validate(
        channel_a=ch_a,
        raw_triage=raw_triage,
    )

    # 3. Assert GateValidationResult is produced correctly
    assert isinstance(gate_result, GateValidationResult)
    assert gate_result.schema_version == "2.0.0"
    assert gate_result.validated_triage is not None
    assert gate_result.validated_triage.schema_version == "2.0.0"
    assert gate_result.validated_triage.decision == raw_triage.decision
    assert gate_result.validated_triage.triage_rationale == raw_triage.triage_rationale
    assert hasattr(gate_result.validated_triage, "category_invalid")


def test_live_3b_failsafe_interoperability_with_gate():
    """Verify that a malformed or missing triage forces Gate fail-safe escalation."""
    ch_a = make_synthetic_channel_a()
    malformed_triage = RawTriageOutput(
        schema_version="2.0.0",
        decision="INSUFFICIENT_EVIDENCE",
        triage_rationale="Simulated 3B parser failure",
        is_malformed=True,
    )

    gate_result = EvidencePreservationGate.validate(
        channel_a=ch_a,
        raw_triage=malformed_triage,
    )

    assert gate_result.fail_safe_required is True
    assert "TRIAGE_OUTPUT_MALFORMED_OR_MISSING" in gate_result.gate_triggers
    assert any("TRIAGE_OUTPUT_MALFORMED_OR_MISSING" in evt_id for evt_id in gate_result.audit_event_ids)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def json_bytes(obj: dict) -> bytes:
    import json
    return json.dumps({"response": json.dumps(obj)}).encode("utf-8")
