"""Unit tests for M12 Security Research Memory Subsystem."""

from pathlib import Path
import pytest

from src.database.manager import DatabaseManager
from src.memory import (
    EpisodicMemoryAdapters,
    EpistemicStatus,
    FreshnessState,
    GLOBAL_MEMORY_TELEMETRY,
    HybridMemoryRetriever,
    LifecycleState,
    MemoryAccessContext,
    MemoryAdmissionPipeline,
    MemoryAuthority,
    MemoryDeletionEngine,
    MemoryItem,
    MemoryLifecycleEngine,
    MemoryNamespace,
    MemoryPersistence,
    MemoryPromotionEngine,
    MemorySourceType,
    PromotionStatus,
    compute_memory_hash,
)
from src.memory.errors import (
    MemoryAdmissionRejectedError,
    SecretPersistenceForbiddenError,
)


@pytest.fixture
def memory_env(tmp_path: Path):
    db_file = tmp_path / "test_memory_unit.db"
    db = DatabaseManager(db_path=db_file)
    db.initialize_schema()
    persistence = MemoryPersistence(db)
    admission = MemoryAdmissionPipeline()
    retriever = HybridMemoryRetriever(persistence)
    promotion = MemoryPromotionEngine()
    lifecycle = MemoryLifecycleEngine()
    deletion = MemoryDeletionEngine()
    return persistence, admission, retriever, promotion, lifecycle, deletion


def test_admission_chatter_and_trivial_rejection(memory_env):
    """Verify that trivial conversation and fillers are rejected from admission."""
    _, admission, _, _, _, _ = memory_env

    # 1. Trivial greeting
    chatter_item = MemoryItem(
        memory_id="MEM-CHAT-1",
        namespace=MemoryNamespace.ASSESSMENT_LOCAL,
        assessment_id="ASM-01",
        source_type=MemorySourceType.ANALYST_NOTE,
        epistemic_status=EpistemicStatus.OBSERVATION,
        authority_level=MemoryAuthority.USER_PROVIDED,
        content="Hello!",
    )
    with pytest.raises(MemoryAdmissionRejectedError):
        admission.process_candidate(chatter_item)

    # 2. Too short
    short_item = MemoryItem(
        memory_id="MEM-SHORT-1",
        namespace=MemoryNamespace.ASSESSMENT_LOCAL,
        assessment_id="ASM-01",
        source_type=MemorySourceType.ANALYST_NOTE,
        epistemic_status=EpistemicStatus.OBSERVATION,
        authority_level=MemoryAuthority.USER_PROVIDED,
        content="Ok.",
    )
    with pytest.raises(MemoryAdmissionRejectedError):
        admission.process_candidate(short_item)


def test_admission_deduplication(memory_env):
    """Verify that exact hash duplicates are rejected from admission."""
    persistence, admission, _, _, _, _ = memory_env

    item1 = MemoryItem(
        memory_id="MEM-DEDUP-1",
        namespace=MemoryNamespace.ASSESSMENT_LOCAL,
        assessment_id="ASM-01",
        source_type=MemorySourceType.ANALYST_NOTE,
        epistemic_status=EpistemicStatus.OBSERVATION,
        authority_level=MemoryAuthority.USER_PROVIDED,
        content="Discovered sensitive staging endpoint at /internal/v1/staging/health",
    )
    admitted1, _ = admission.process_candidate(item1)
    persistence.save_item(admitted1)

    # Attempt to admit exact same content
    item2 = MemoryItem(
        memory_id="MEM-DEDUP-2",
        namespace=MemoryNamespace.ASSESSMENT_LOCAL,
        assessment_id="ASM-01",
        source_type=MemorySourceType.ANALYST_NOTE,
        epistemic_status=EpistemicStatus.OBSERVATION,
        authority_level=MemoryAuthority.USER_PROVIDED,
        content="Discovered sensitive staging endpoint at /internal/v1/staging/health",
    )
    with pytest.raises(MemoryAdmissionRejectedError, match="exact duplicate"):
        admission.process_candidate(
            item2,
            existing_hashes={item1.memory_id: item1.content_hash},
        )


def test_admission_conflict_detection(memory_env):
    """Verify that contradiction between hypothesis and observation is flagged."""
    persistence, admission, _, _, _, _ = memory_env

    # Existing observation: negative finding
    existing_obs = MemoryItem(
        memory_id="MEM-OBS-1",
        namespace=MemoryNamespace.ASSESSMENT_LOCAL,
        assessment_id="ASM-01",
        source_type=MemorySourceType.EXPERIMENT_OBSERVATION,
        epistemic_status=EpistemicStatus.OBSERVATION,
        authority_level=MemoryAuthority.CANONICAL_OBSERVATION,
        content="The /api/users endpoint is not vulnerable to authorization bypass; request was denied.",
    )
    persistence.save_item(existing_obs)

    # Candidate hypothesis asserting vulnerability
    candidate_hyp = MemoryItem(
        memory_id="MEM-HYP-1",
        namespace=MemoryNamespace.ASSESSMENT_LOCAL,
        assessment_id="ASM-01",
        source_type=MemorySourceType.MODEL_SUMMARY,
        epistemic_status=EpistemicStatus.MODEL_HYPOTHESIS,
        authority_level=MemoryAuthority.MODEL_DERIVED,
        content="Hypothesis that the /api/users endpoint is vulnerable to authorization bypass.",
    )

    admitted, conflict = admission.process_candidate(
        candidate=candidate_hyp,
        existing_items=[existing_obs],
    )
    assert conflict is not None
    assert conflict.memory_id_a == candidate_hyp.memory_id
    assert conflict.memory_id_b == existing_obs.memory_id
    assert "contradicts" in conflict.description.lower() or "polarity" in conflict.description.lower()


def test_episodic_adapters_and_pointers(memory_env):
    """Verify creation and retrieval of experiment, negative control, and verified pattern adapters."""
    persistence, _, retriever, _, _, _ = memory_env

    # 1. Controlled Experiment
    exp_item = EpisodicMemoryAdapters.from_controlled_experiment(
        experiment_id="EXP-101",
        assessment_id="ASM-42",
        hypothesis="Modifying X-User-ID header yields cross-account access",
        experiment_type="HEADER_INJECTION",
        outcome="HTTP 403 Forbidden with invalid token audit event",
        falsified=True,
        evidence_digest="sha256_exp_101_digest",
    )
    persistence.save_item(exp_item)
    assert len(exp_item.evidence_pointers) == 1
    assert exp_item.evidence_pointers[0].target_evidence_id == "EXP-101"

    # 2. Negative Control
    neg_item = EpisodicMemoryAdapters.from_negative_control(
        assessment_id="ASM-42",
        tested_hypothesis="Server was returning cached 200 responses",
        benign_explanation="ETag match on Cloudflare cache rather than dynamic execution",
        control_artifact_digest="sha256_control_digest",
    )
    persistence.save_item(neg_item)
    assert neg_item.namespace == MemoryNamespace.USER_RESEARCH

    # 3. Verified Pattern
    pat_item = EpisodicMemoryAdapters.from_verified_finding_reference(
        finding_id="F-BOLA-202",
        assessment_id="ASM-42",
        vulnerability_type="Broken Object Level Authorization",
        abstracted_reproduction_pattern="Resource ID mutation in PUT /api/v2/items/{id} without tenant claim check",
        finding_digest="sha256_finding_digest",
    )
    persistence.save_item(pat_item)
    assert pat_item.namespace == MemoryNamespace.VERIFIED_PATTERN
    assert pat_item.promotion_status == PromotionStatus.PROMOTED

    # Verify retrieval
    ctx = MemoryAccessContext(assessment_id="ASM-42")
    res = retriever.retrieve("Cloudflare cache ETag", context=ctx)
    assert len(res.items) >= 1
    top_hit = res.items[0]
    assert "Negative Control" in top_hit.memory.content


def test_hybrid_retrieval_and_rrf_scoring(memory_env):
    """Verify hybrid RRF ranking combining sparse FTS5 and dense vectors."""
    persistence, _, retriever, _, _, _ = memory_env

    item_jwt = MemoryItem(
        memory_id="MEM-JWT-01",
        namespace=MemoryNamespace.USER_RESEARCH,
        source_type=MemorySourceType.RESEARCH_PROCEDURE,
        epistemic_status=EpistemicStatus.FACT,
        authority_level=MemoryAuthority.USER_PROVIDED,
        content="JWT header manipulation technique: inspect kid parameter for path traversal to public keys.",
        title="JWT Kid Traversal",
    )
    persistence.save_item(item_jwt)

    # Save dense embedding
    vec = retriever.embedding_backend.embed(item_jwt.content)
    persistence.save_embedding(item_jwt.memory_id, vec)

    ctx = MemoryAccessContext()
    res = retriever.retrieve("kid parameter traversal in JWT", context=ctx, top_k=3)
    assert len(res.items) == 1
    hit = res.items[0]
    assert hit.memory.memory_id == "MEM-JWT-01"
    assert hit.effective_score > 0.0
    citation = hit.compute_citation()
    assert citation["namespace"] == "USER_RESEARCH"
    assert citation["authority_level"] == "USER_PROVIDED"


def test_freshness_decay_multiplier(memory_env):
    """Verify that fresher memories receive higher ranking scores."""
    persistence, _, retriever, _, _, _ = memory_env

    # Old memory (120 days old)
    old_item = MemoryItem(
        memory_id="MEM-OLD-STALE",
        namespace=MemoryNamespace.USER_RESEARCH,
        source_type=MemorySourceType.RESEARCH_PROCEDURE,
        epistemic_status=EpistemicStatus.FACT,
        authority_level=MemoryAuthority.USER_PROVIDED,
        content="Graphql introspection query check for schema leakage.",
        created_at="2026-01-01T00:00:00+00:00",
    )
    persistence.save_item(old_item)
    vec_old = retriever.embedding_backend.embed(old_item.content)
    persistence.save_embedding(old_item.memory_id, vec_old)

    # Fresh memory (today)
    fresh_item = MemoryItem(
        memory_id="MEM-FRESH-NOW",
        namespace=MemoryNamespace.USER_RESEARCH,
        source_type=MemorySourceType.RESEARCH_PROCEDURE,
        epistemic_status=EpistemicStatus.FACT,
        authority_level=MemoryAuthority.USER_PROVIDED,
        content="Graphql introspection query directives on Apollo Server v4.",
        created_at="2026-10-08T00:00:00+00:00",
    )
    persistence.save_item(fresh_item)
    vec_fresh = retriever.embedding_backend.embed(fresh_item.content)
    persistence.save_embedding(fresh_item.memory_id, vec_fresh)

    ctx = MemoryAccessContext()
    res = retriever.retrieve("Graphql introspection query", context=ctx, top_k=2)
    assert len(res.items) == 2
    # Fresh item should rank higher due to freshness multiplier
    assert res.items[0].memory.memory_id == "MEM-FRESH-NOW"
    assert res.items[1].memory.memory_id == "MEM-OLD-STALE"
    assert res.items[0].effective_score > res.items[1].effective_score


def test_memory_telemetry_snapshot():
    """Verify that observability metrics track events accurately without secrets."""
    telemetry = GLOBAL_MEMORY_TELEMETRY
    telemetry.record_admission(success=True)
    telemetry.record_admission(success=False, rejection_reason="secret unredactable")
    telemetry.record_cross_assessment_block()
    telemetry.record_retrieval(count=3, latency_ms=12.5)

    snapshot = telemetry.get_metrics_snapshot()
    assert snapshot["memory_admission_attempts"] >= 2
    assert snapshot["memory_rejection_secret"] >= 1
    assert snapshot["memory_retrieval_cross_assessment_block"] >= 1
    assert snapshot["memory_retrieval_count"] >= 1
    assert snapshot["avg_retrieval_latency_ms"] >= 0.0
