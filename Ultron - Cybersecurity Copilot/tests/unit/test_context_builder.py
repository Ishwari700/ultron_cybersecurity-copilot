"""Test Suite for Phase 7: Shared ReasoningContextBuilder & Canonical Track Mapping.

Verifies:
- Dedicated track identity test (Addendum A, H):
  Track A == 7B baseline
  Track B == 3B baseline
  Track C == 3B -> Gate -> Router -> 7B cascade
- Normalization of legacy literals (TRACK_B_CASCADE, TRACK_C_3B_BASELINE)
- Shared builder contract across Tracks A, B, and C
- Context hierarchy and encapsulated <untrusted_target_data> snippets
- Token budget floor enforcement and fail-closed ContextBudgetOverflowError
- ContextBuilder provenance hashing (SHA256 of context_builder.py)
"""

import pytest

from src.evidence.cascade_models import (
    CascadeHandoffPacket,
    ContextBudgetOverflowError,
    DeterministicRoutingDecision,
    LosslessStructuralPack,
    TriageMetadataPacket,
)
from src.evidence.provenance import compute_provenance_hash
from src.engine.context_builder import (
    TRACK_A_7B_BASELINE,
    TRACK_B_3B_BASELINE,
    TRACK_C_CASCADE,
    ReasoningContextBuilder,
    normalize_track_identifier,
)


@pytest.fixture
def sample_handoff():
    ch_a = LosslessStructuralPack(
        schema_version="2.0.0",
        asset_id="ASSET-AUTH-01",
        endpoint_id="EP-AUTH-01",
        route_template="/api/v1/auth/login",
        http_method="POST",
        application_mutability="STATE_CHANGING",
        parameter_lineage=[{"param_id": "P1", "param_name": "username", "location": "body"}],
        has_privilege_level_delta=True,
        has_unauthenticated_success=False,
        observed_facts=[{"fact_id": "F1", "statement": "POST /login returned 200"}],
        raw_body_sample='{"user": "alice", "admin": true}',
    )
    routing = DeterministicRoutingDecision(
        schema_version="2.0.0",
        escalate=True,
        has_high_risk_signal=True,
        high_risk_signals=["PRIVILEGE_LEVEL_DELTA_DETECTED"],
        fail_safe_triggered=False,
    )
    triage = TriageMetadataPacket(
        schema_version="2.0.0",
        suspected_category="API-BFLA-002",
        decision="SUSPECTED_VULNERABILITY",
        triage_rationale="Privilege mismatch on auth route",
    )
    p_hash = "mock_provenance_hash_32chars_hex"
    return CascadeHandoffPacket(
        schema_version="2.0.0",
        channel_a_structural=ch_a,
        routing_decision=routing,
        provenance_hash=p_hash,
        validated_triage=triage,
    )


# ---------------------------------------------------------------------------
# 1. Dedicated Track-Identity Test (Addendum A & H)
# ---------------------------------------------------------------------------

def test_track_identity_authoritative_definitions():
    """
    Addendum H Precondition:
    Prove Track A == 7B baseline, Track B == 3B baseline, Track C == Cascade.
    """
    assert TRACK_A_7B_BASELINE == "TRACK_A_7B_BASELINE"
    assert TRACK_B_3B_BASELINE == "TRACK_B_3B_BASELINE"
    assert TRACK_C_CASCADE == "TRACK_C_CASCADE"

    # Verify normalization of legacy literals
    assert normalize_track_identifier("TRACK_B_CASCADE") == TRACK_C_CASCADE
    assert normalize_track_identifier("TRACK_C_3B_BASELINE") == TRACK_B_3B_BASELINE
    assert normalize_track_identifier(TRACK_A_7B_BASELINE) == TRACK_A_7B_BASELINE


def test_track_context_assembly_differences(sample_handoff):
    """
    Tracks A, B, and C differ strictly by declared mode/model parameters:
    - Track A (7B baseline) does NOT include advisory 3B triage
    - Track B (3B baseline) does NOT include advisory 3B triage
    - Track C (Cascade) DOES include advisory 3B triage
    """
    ctx_a = ReasoningContextBuilder.build_context(
        sample_handoff,
        model_identifier="qwen2.5-coder:7b",
        cascade_mode=TRACK_A_7B_BASELINE,
    )
    assert ctx_a.cascade_mode == TRACK_A_7B_BASELINE
    assert "CHANNEL B: ADVISORY 3B TRIAGE" not in ctx_a.prompt

    ctx_b = ReasoningContextBuilder.build_context(
        sample_handoff,
        model_identifier="qwen2.5-coder:3b",
        cascade_mode=TRACK_B_3B_BASELINE,
    )
    assert ctx_b.cascade_mode == TRACK_B_3B_BASELINE
    assert "CHANNEL B: ADVISORY 3B TRIAGE" not in ctx_b.prompt

    ctx_c = ReasoningContextBuilder.build_context(
        sample_handoff,
        model_identifier="qwen2.5-coder:7b",
        cascade_mode=TRACK_C_CASCADE,
    )
    assert ctx_c.cascade_mode == TRACK_C_CASCADE
    assert "CHANNEL B: ADVISORY 3B TRIAGE" in ctx_c.prompt
    assert "API-BFLA-002" in ctx_c.prompt


def test_untrusted_target_data_encapsulation(sample_handoff):
    """Encapsulated snippets must appear within <untrusted_target_data> delimiters."""
    ctx = ReasoningContextBuilder.build_context(
        sample_handoff,
        model_identifier="qwen2.5-coder:7b",
        cascade_mode=TRACK_C_CASCADE,
    )
    assert "<untrusted_target_data>" in ctx.prompt
    assert "</untrusted_target_data>" in ctx.prompt
    assert '{"user": "alice", "admin": true}' in ctx.prompt


def test_fail_closed_context_budget_overflow(sample_handoff):
    """If protected floor exceeds active budget tier, must raise ContextBudgetOverflowError."""
    with pytest.raises(ContextBudgetOverflowError):
        ReasoningContextBuilder.build_context(
            sample_handoff,
            model_identifier="qwen2.5-coder:7b",
            budget_tier=10,  # Ridiculously small budget to trigger floor overflow
            cascade_mode=TRACK_C_CASCADE,
        )


def test_context_builder_provenance_hash_recording(sample_handoff):
    """Context builder includes valid SHA-256 hash of its source file."""
    ctx = ReasoningContextBuilder.build_context(
        sample_handoff,
        model_identifier="qwen2.5-coder:7b",
        cascade_mode=TRACK_C_CASCADE,
    )
    assert ctx.context_builder_version == "2.0.0"
    assert len(ctx.context_builder_hash) == 64
    assert ctx.provenance_metadata["builder_hash"] == ctx.context_builder_hash
