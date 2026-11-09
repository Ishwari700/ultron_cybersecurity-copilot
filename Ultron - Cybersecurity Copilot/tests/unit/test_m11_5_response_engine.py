"""Unit tests for M11.5 Long Response Subsystem.
Verifies completeness detection, overlap removal, continuation framing,
merging, persistence, and telemetry accounting.
"""

from pathlib import Path
import pytest
import sqlite3

from src.database.manager import DatabaseManager
from src.response.completeness import (
    CompletenessDetector,
    CompletenessState,
)
from src.response.continuation import ContinuationContextManager
from src.response.errors import ResponseEngineError
from src.response.generator import LongResponseEngine
from src.response.merger import ResponseMerger
from src.response.metrics import ResponseTelemetry
from src.response.models import (
    GenerationTermination,
    ResponseChunk,
    ResponseSession,
    ResponseStatus,
    compute_content_hash,
)
from src.response.persistence import ResponsePersistence
from src.response.stream import CancellationToken, ResponseStreamHandler


@pytest.fixture
def temp_db(tmp_path: Path) -> DatabaseManager:
    db_file = tmp_path / "test_response.db"
    db = DatabaseManager(db_path=db_file)
    db.initialize_schema()
    return db


# ===========================================================================
# 1. COMPLETENESS DETECTION TESTS
# ===========================================================================

def test_completeness_natural_stop_finished_sentence() -> None:
    detector = CompletenessDetector()
    text = "The target API is vulnerable to BOLA because object ID ownership is not verified."
    eval_res = detector.evaluate(text, stop_reason="stop")
    assert eval_res.state == CompletenessState.COMPLETE
    assert not eval_res.should_continue
    assert eval_res.confidence >= 0.90


def test_completeness_token_limit_mid_sentence() -> None:
    detector = CompletenessDetector()
    text = "The parameter tenant_id can be manipulated by sending an arbitrary uuid in the"
    eval_res = detector.evaluate(text, stop_reason="length")
    assert eval_res.state == CompletenessState.INCOMPLETE
    assert eval_res.should_continue
    assert "Token ceiling reached" in eval_res.rationale


def test_completeness_unclosed_code_fence() -> None:
    detector = CompletenessDetector()
    text = (
        "Here is the reproduction script:\n"
        "```python\n"
        "import requests\n"
        "r = requests.get('https://target.local/api/v1/users/2')\n"
    )
    # Even if model claimed stop reason is 'stop', unclosed code fence MUST force continuation
    eval_res = detector.evaluate(text, stop_reason="stop")
    assert eval_res.state == CompletenessState.INCOMPLETE
    assert eval_res.should_continue
    assert eval_res.signals["unclosed_code_fence"] is True


def test_completeness_dangling_colon() -> None:
    detector = CompletenessDetector()
    text = "To reproduce this security violation, execute the following request:"
    eval_res = detector.evaluate(text, stop_reason="stop")
    assert eval_res.state == CompletenessState.LIKELY_INCOMPLETE
    assert eval_res.should_continue
    assert eval_res.signals["dangling_colon"] is True


def test_completeness_dangling_markdown_heading() -> None:
    detector = CompletenessDetector()
    text = "Executive Summary\n\n## Technical Vulnerability Analysis"
    eval_res = detector.evaluate(text, stop_reason="length")
    assert eval_res.state == CompletenessState.INCOMPLETE
    assert eval_res.should_continue


def test_completeness_unfinished_bullet_list() -> None:
    detector = CompletenessDetector()
    text = "Key observations:\n- Token was missing\n- Route template was mutable\n- "
    eval_res = detector.evaluate(text, stop_reason="length")
    assert eval_res.state == CompletenessState.INCOMPLETE
    assert eval_res.should_continue


def test_completeness_safety_cap_max_chunks() -> None:
    detector = CompletenessDetector(max_continuation_chunks=4)
    text = "Ongoing analysis text that could continue forever..."
    eval_res = detector.evaluate(text, stop_reason="length", chunk_count=4)
    assert not eval_res.should_continue
    assert eval_res.signals["max_chunks_reached"] is True


def test_completeness_safety_cap_max_tokens() -> None:
    detector = CompletenessDetector(max_cumulative_tokens=1000)
    text = "Incomplete text..."
    eval_res = detector.evaluate(text, stop_reason="length", cumulative_tokens=1050)
    assert not eval_res.should_continue
    assert eval_res.signals["max_tokens_reached"] is True


# ===========================================================================
# 2. OVERLAP DETECTION & MERGER TESTS
# ===========================================================================

def test_merger_exact_suffix_prefix_overlap() -> None:
    merger = ResponseMerger()
    chunk1 = "The authentication bearer token must be verified against the public key."
    chunk2 = "public key. If verification fails, an HTTP 401 Unauthorized must be returned."
    merged, res = merger.merge_chunks(chunk1, chunk2)
    assert res.overlap_detected is True
    assert res.overlap_type == "exact"
    assert res.overlap_snippet == "public key."
    assert merged == "The authentication bearer token must be verified against the public key. If verification fails, an HTTP 401 Unauthorized must be returned."


def test_merger_sentence_level_overlap() -> None:
    merger = ResponseMerger()
    chunk1 = "Step 1: Check parameters. Step 2: Validate JWT signature in authorization header."
    chunk2 = "Step 2: Validate JWT signature in authorization header. Step 3: Check authorization scope."
    merged, res = merger.merge_chunks(chunk1, chunk2)
    assert res.overlap_detected is True
    assert res.overlap_type in ("sentence", "exact")
    assert "Step 3: Check authorization scope." in merged
    assert merged.count("Step 2: Validate JWT signature in authorization header.") == 1


def test_merger_meta_preface_stripping() -> None:
    merger = ResponseMerger()
    chunk1 = "The underlying issue is caused by insecure direct object reference in"
    chunk2 = "Continuing from where we left off: in the user profile endpoint `/api/profile`."
    merged, res = merger.merge_chunks(chunk1, chunk2)
    assert "Continuing from where we left off:" not in merged
    assert "/api/profile" in merged


def test_merger_clean_join_no_overlap() -> None:
    merger = ResponseMerger()
    chunk1 = "First paragraph explaining the architecture.\n\n"
    chunk2 = "Second paragraph analyzing the vulnerability surface."
    merged, res = merger.merge_chunks(chunk1, chunk2)
    assert res.overlap_detected is False
    assert merged == chunk1 + chunk2


# ===========================================================================
# 3. CONTINUATION CONTEXT & GUARDS
# ===========================================================================

def test_continuation_guard_rails() -> None:
    ctx_mgr = ContinuationContextManager(max_continuation_chunks=5, max_cumulative_tokens=2000)
    # Within bounds
    dec1 = ctx_mgr.check_guard_rails(current_chunk_count=2, cumulative_tokens=500, repacking_attempts=0)
    assert dec1.allow_continuation is True

    # Exceeded max chunks
    dec2 = ctx_mgr.check_guard_rails(current_chunk_count=5, cumulative_tokens=500, repacking_attempts=0)
    assert dec2.allow_continuation is False
    assert dec2.termination == GenerationTermination.MAX_CHUNKS_REACHED

    # User cancelled
    dec3 = ctx_mgr.check_guard_rails(current_chunk_count=2, cumulative_tokens=500, repacking_attempts=0, user_cancelled=True)
    assert dec3.allow_continuation is False
    assert dec3.termination == GenerationTermination.CLIENT_ABORT


def test_continuation_prompt_construction() -> None:
    ctx_mgr = ContinuationContextManager(suffix_window_chars=100)
    accumulated = "A" * 200 + "Target endpoint `/api/users/99` returned HTTP 200 with tenant invoice."
    prompt_obj = ctx_mgr.build_continuation_prompt(
        system_policy="System: You are an analyst.",
        user_prompt="Analyze tenant isolation",
        accumulated_text=accumulated,
    )
    assert "Resume directly from the exact point" in prompt_obj.prompt_text
    assert "tenant invoice." in prompt_obj.suffix_context
    assert len(prompt_obj.suffix_context) <= 100


# ===========================================================================
# 4. PERSISTENCE & DATA INTEGRITY
# ===========================================================================

def test_response_persistence_full_lifecycle(temp_db: DatabaseManager) -> None:
    persistence = ResponsePersistence(temp_db)

    session = ResponseSession(
        response_id="RESP-TEST-001",
        investigation_id="INV-001",
        model="qwen2.5-coder:7b",
        status=ResponseStatus.GENERATING,
        final_content="Initial partial text",
    )
    persistence.create_session(session)

    chunk1 = ResponseChunk(
        chunk_id="CHK-001-1",
        sequence_number=1,
        content="Part 1 of the explanation.",
        raw_content="Part 1 of the explanation.",
        token_count=100,
        stop_reason="length",
    )
    persistence.save_chunk(session.response_id, chunk1)

    chunk2 = ResponseChunk(
        chunk_id="CHK-001-2",
        sequence_number=2,
        content=" Part 2 of the explanation.",
        raw_content=" Part 2 of the explanation.",
        token_count=80,
        stop_reason="stop",
    )
    persistence.save_chunk(session.response_id, chunk2)

    persistence.update_session(
        response_id=session.response_id,
        status=ResponseStatus.COMPLETED,
        final_content="Part 1 of the explanation. Part 2 of the explanation.",
        cumulative_tokens=180,
        termination_reason=GenerationTermination.NATURAL_STOP,
    )

    loaded = persistence.get_session("RESP-TEST-001")
    assert loaded is not None
    assert loaded.status == ResponseStatus.COMPLETED
    assert loaded.cumulative_tokens == 180
    assert len(loaded.chunks) == 2
    assert loaded.chunks[0].chunk_id == "CHK-001-1"
    assert loaded.chunks[0].content_hash == compute_content_hash("Part 1 of the explanation.")


# ===========================================================================
# 5. TOKEN ACCOUNTING & NEVER TREAT LENGTH AS COMPLETED
# ===========================================================================

def test_engine_never_marks_token_limit_as_completed(temp_db: DatabaseManager) -> None:
    # Custom LLM caller that always hits length ceiling
    def mock_truncated_llm(prompt: str, max_tokens: int):
        return {
            "response": "This is an intentionally cut off sentence because of the token limit and",
            "done_reason": "length",
            "eval_count": max_tokens,
        }

    engine = LongResponseEngine(
        db_manager=temp_db,
        max_continuation_chunks=2,
    )

    session = engine.generate_response(
        investigation_id="INV-TEST",
        user_prompt="Explain vulnerability",
        custom_llm_caller=mock_truncated_llm,
        auto_continue=False,  # Halt at chunk 1 to test explicit status
    )

    assert session.status == ResponseStatus.TOKEN_LIMIT
    assert session.status != ResponseStatus.COMPLETED
    assert session.termination_reason == GenerationTermination.LENGTH_CEILING


# ===========================================================================
# 6. OBSERVABILITY METRICS
# ===========================================================================

def test_telemetry_metrics_tracking() -> None:
    telemetry = ResponseTelemetry.get_instance()
    telemetry.reset()

    telemetry.record_generation_start("RESP-001", "qwen2.5-coder:7b")
    telemetry.record_chunk("RESP-001", 1, 100, 1.2, "length", is_continuation=False)
    telemetry.record_chunk("RESP-001", 2, 80, 0.9, "stop", is_continuation=True)
    telemetry.record_overlap_pruned("RESP-001", 2, 14)
    telemetry.record_completion("RESP-001", 2, 180, "NATURAL_STOP", finalization_latency=2.1)

    metrics = telemetry.get_metrics_snapshot()
    assert metrics["response_generation_count"] == 1
    assert metrics["response_completion_count"] == 1
    assert metrics["response_continuation_count"] == 1
    assert metrics["response_token_limit_count"] == 1
    assert metrics["response_duplicate_overlap_count"] == 1
    assert metrics["response_total_tokens"] == 180
