"""Unit Tests for Enhanced Conflict Detection, Claim Graph, and Source Authority (Milestone M5)."""

import pytest
from src.research.conflicts import (
    ClaimRelationshipType,
    ConflictCategory,
    ConflictDetector,
    SourceAuthorityMetadata,
)
from src.research.models import (
    ClaimEpistemicStatus,
    ClaimType,
    ExternalClaim,
    ExternalSource,
    ExternalSourceType,
    TrustTier,
)


def _make_claim(claim_id: str, source_id: str, statement: str) -> ExternalClaim:
    return ExternalClaim(
        claim_id=claim_id,
        source_id=source_id,
        statement=statement,
        claim_type=ClaimType.SECURITY_INVARIANT,
    )


def test_conflict_detection_true_conflict():
    c1 = _make_claim("CLM-01", "SRC-A", "Swagger UI is disabled by default in production builds.")
    c2 = _make_claim("CLM-02", "SRC-B", "Swagger UI remains enabled by default unless explicitly disabled in config.")

    conflicts, updated = ConflictDetector.detect_conflicts([c1, c2])
    assert len(conflicts) == 1
    conf = conflicts[0]
    assert conf.category == ConflictCategory.TRUE_CONFLICT
    assert conf.unresolved is True
    assert "manual verification" in conf.preferred_interpretation.lower()

    # Verify both claims are marked EXTERNAL_CONFLICTED
    assert c1.epistemic_status == ClaimEpistemicStatus.EXTERNAL_CONFLICTED
    assert c2.epistemic_status == ClaimEpistemicStatus.EXTERNAL_CONFLICTED


def test_conflict_detection_temporal_change():
    c1 = _make_claim("CLM-03", "SRC-A", "PKCE is optional for confidential clients in OAuth 2.0.")
    c2 = _make_claim("CLM-04", "SRC-B", "PKCE is required for all clients in OAuth 2.1.")

    conflicts, _ = ConflictDetector.detect_conflicts([c1, c2])
    assert len(conflicts) == 1
    conf = conflicts[0]
    assert conf.category == ConflictCategory.TEMPORAL_CHANGE
    assert "OAuth 2.1" in conf.version_conditions or "OAuth 2.0" in conf.version_conditions
    assert "supersedes" in conf.preferred_interpretation.lower()


def test_conflict_detection_version_conflict():
    c1 = _make_claim("CLM-05", "SRC-A", "Session cookies are set to SameSite None by default.")
    c2 = _make_claim("CLM-06", "SRC-B", "Session cookies are set to SameSite Lax by default starting in v2.0.")

    conflicts, _ = ConflictDetector.detect_conflicts([c1, c2])
    assert len(conflicts) == 1
    conf = conflicts[0]
    assert conf.category == ConflictCategory.VERSION_CONFLICT
    assert conf.version_conditions is not None


def test_conflict_detection_scope_difference():
    c1 = _make_claim("CLM-07", "SRC-A", "Redirect URI prefix matching is permitted for public clients.")
    c2 = _make_claim("CLM-08", "SRC-B", "Redirect URI prefix matching is forbidden for confidential clients.")

    conflicts, _ = ConflictDetector.detect_conflicts([c1, c2])
    assert len(conflicts) == 1
    conf = conflicts[0]
    assert conf.category == ConflictCategory.SCOPE_DIFFERENCE


def test_conflict_detection_terminology_difference():
    c1 = _make_claim("CLM-09", "SRC-A", "Enforce strict whitelist on CORS origin.")
    c2 = _make_claim("CLM-10", "SRC-B", "Enforce strict allowlist on CORS origin.")

    conflicts, _ = ConflictDetector.detect_conflicts([c1, c2])
    assert len(conflicts) == 1
    conf = conflicts[0]
    assert conf.category == ConflictCategory.TERMINOLOGY_DIFFERENCE


def test_claim_graph_edge_generation():
    c1 = _make_claim("CLM-01", "SRC-A", "Swagger UI is disabled by default.")
    c2 = _make_claim("CLM-02", "SRC-B", "Swagger UI remains enabled by default.")
    conflicts, _ = ConflictDetector.detect_conflicts([c1, c2])

    edges = ConflictDetector.build_claim_graph_edges([c1, c2], conflicts)
    assert len(edges) == 1
    assert edges[0].relationship_type == ClaimRelationshipType.CONTRADICTS
    assert edges[0].from_claim_id == "CLM-01"
    assert edges[0].to_claim_id == "CLM-02"


def test_source_authority_metadata():
    auth = SourceAuthorityMetadata(
        source_id="EXT-SRC-001",
        trust_tier=TrustTier.TIER_1,
        publisher="IETF",
        publication_date="2015-09",
        maintainer_status="OFFICIAL_STANDARDS_BODY",
        authority_score=0.98,
    )
    assert auth.trust_tier == TrustTier.TIER_1
    assert auth.authority_score > 0.9
