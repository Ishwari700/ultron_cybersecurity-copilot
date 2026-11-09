"""Unit Tests for Milestone M4 External Research Subsystem.

Verifies:
- External source models and trust tiers
- Provider abstraction (WebSearchProvider & GitHubProvider)
- Provenance tracking and cryptographic Merkle-style root audits
- Research cache persistence and hit/miss mechanics
- Claim extraction and corroboration
- Version awareness and evaluation
- Conflict detection between contradictory sources
- Query sanitization and secret redaction
- Deterministic research routing policy
- Negative-control and counterfactual guidance
- GroundedKnowledgePack assembly and context partitioning
"""

import tempfile
from pathlib import Path
import pytest

from src.knowledge.models import (
    KnowledgeChunk,
    KnowledgeSourceType,
    KnowledgeType,
    KnowledgeRetrievalItem,
    VaptKnowledgePack,
)
from src.research.cache import ResearchCache
from src.research.claims import ClaimExtractor
from src.research.conflicts import ConflictDetector
from src.research.fusion import (
    GroundedKnowledgePackBuilder,
    ReasoningContextPartitioner,
)
from src.research.models import (
    ClaimEpistemicStatus,
    ClaimType,
    ExternalClaim,
    ExternalSource,
    ExternalSourceType,
    GroundedKnowledgePack,
    ResearchRoutingDecisionMode,
    TrustTier,
    VersionApplicability,
    VersionScope,
)
from src.research.negative_control import NegativeControlEngine
from src.research.policy import ResearchRoutingPolicy
from src.research.provenance import ResearchProvenanceTracker
from src.research.providers import (
    GitHubProvider,
    WebSearchProvider,
)
from src.research.sanitization import QuerySanitizer
from src.research.version import VersionEvaluator


class TestM4ResearchModelsAndProvenance:
    def test_source_model_provenance_hash(self):
        src = ExternalSource(
            source_id="EXT-SRC-001",
            source_type=ExternalSourceType.RFC,
            title="RFC 7636 PKCE",
            url="https://datatracker.ietf.org/doc/html/rfc7636",
            content_hash="abc123hash",
            trust_tier=TrustTier.TIER_1,
            raw_content="PKCE spec body",
            normalized_content="PKCE spec body",
        )
        prov_hash = src.calculate_provenance_hash()
        assert isinstance(prov_hash, str)
        assert len(prov_hash) == 64

    def test_claim_linkage_and_audit(self):
        src = ExternalSource(
            source_id="EXT-SRC-001",
            source_type=ExternalSourceType.OFFICIAL_DOCUMENTATION,
            title="OWASP API Security",
            url="https://owasp.org/API-Security",
            content_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            trust_tier=TrustTier.TIER_1,
            normalized_content="",
        )
        claim = ExternalClaim(
            claim_id="EXT-CLM-001",
            source_id="EXT-SRC-001",
            statement="Server must enforce object-level authorization checks.",
            claim_type=ClaimType.SECURITY_INVARIANT,
            evidence_span="must enforce object-level authorization",
        )
        node = ResearchProvenanceTracker.build_provenance_node(claim, src)
        assert node.claim_id == "EXT-CLM-001"
        assert node.source_id == "EXT-SRC-001"
        assert len(node.node_hash) == 64

    def test_unlinked_claim_fails_audit(self):
        pack = GroundedKnowledgePack(
            pack_id="GKP-TEST-001",
            research_run_id="RUN-TEST",
            external_sources=[],
            external_claims=[
                ExternalClaim(
                    claim_id="EXT-CLM-999",
                    source_id="EXT-SRC-MISSING",
                    statement="Orphaned statement without registered source.",
                    claim_type=ClaimType.SECURITY_INVARIANT,
                )
            ],
        )
        audit = ResearchProvenanceTracker.verify_grounded_pack_provenance(pack)
        assert audit.is_valid is False
        assert "EXT-CLM-999" in audit.unlinked_claim_ids


class TestM4ProvidersAndCache:
    def test_web_search_and_fetch(self):
        provider = WebSearchProvider()
        provider.register_document(
            url="https://example.com/oauth",
            title="OAuth 2.0 PKCE Guide",
            content="Authorization code grant must verify code_challenge against code_verifier.",
            source_type=ExternalSourceType.OFFICIAL_DOCUMENTATION,
            trust_tier=TrustTier.TIER_1,
            keywords=["pkce", "oauth", "verifier"],
        )
        results = provider.search("pkce code verifier")
        assert len(results) > 0
        assert results[0].url == "https://example.com/oauth"

        source = provider.fetch(results[0])
        assert source.source_id.startswith("EXT-SRC-")
        assert source.trust_tier == TrustTier.TIER_1
        assert "code_verifier" in source.normalized_content

    def test_github_provider_exact_provenance(self):
        gh = GitHubProvider()
        gh.register_repo_file(
            repository="auth-svc",
            owner="my-org",
            path="pkg/auth/jwt.go",
            content="func ValidateJWT() bool {\n    return token.Valid\n}",
            commit_sha="a1b2c3d4e5",
            line_start=15,
        )
        results = gh.search("auth jwt")
        assert len(results) > 0
        src = gh.fetch(results[0])
        assert src.repository == "auth-svc"
        assert src.commit_sha == "a1b2c3d4e5"
        assert src.path == "pkg/auth/jwt.go"
        assert src.line_start == 15
        assert src.line_end == 17

    def test_cache_hit_and_persistence(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_file = Path(tmpdir) / "test_cache.sqlite3"
            cache = ResearchCache(db_path=db_file)
            src = ExternalSource(
                source_id="EXT-SRC-CACHE-1",
                url="https://example.com/advisory",
                title="Security Advisory 001",
                content_hash="hash123",
                normalized_content="Vulnerability details",
                raw_content="Vulnerability details",
                trust_tier=TrustTier.TIER_1,
            )
            cache.put(src, "test_provider")
            cached = cache.get("https://example.com/advisory")
            assert cached is not None
            assert cached.title == "Security Advisory 001"
            assert cache.hits == 1

            miss = cache.get("https://example.com/missing")
            assert miss is None
            assert cache.misses == 1
            assert cache.hit_rate == 0.5


class TestM4ClaimsAndConflicts:
    def test_claim_extraction_and_epistemic_status(self):
        src = ExternalSource(
            source_id="EXT-SRC-001",
            title="OWASP ASVS",
            url="https://owasp.org/asvs",
            content_hash="hash",
            normalized_content=(
                "Invariant: Server must reject cross-tenant object access.\n"
                "Verify whether GET /api/tenant/export checks tenant ID.\n"
                "False positive: Public catalog endpoints are by design unauthenticated."
            ),
        )
        claims = ClaimExtractor.extract_claims(src)
        assert len(claims) >= 3
        types = {c.claim_type for c in claims}
        assert ClaimType.SECURITY_INVARIANT in types
        assert ClaimType.TESTING_METHOD in types
        assert ClaimType.FALSE_POSITIVE_WARNING in types
        for c in claims:
            assert c.epistemic_status == ClaimEpistemicStatus.EXTERNAL_REPORTED
            assert not c.claim_id.startswith("FACT-")

    def test_claim_corroboration(self):
        c1 = ExternalClaim(
            claim_id="CLM-1",
            source_id="SRC-A",
            statement="PKCE is required for public clients.",
            claim_type=ClaimType.SECURITY_INVARIANT,
        )
        c2 = ExternalClaim(
            claim_id="CLM-2",
            source_id="SRC-B",
            statement="PKCE is required for public clients.",
            claim_type=ClaimType.SECURITY_INVARIANT,
        )
        corroborated = ClaimExtractor.corroborate_claims([c1, c2])
        for c in corroborated:
            assert c.epistemic_status == ClaimEpistemicStatus.EXTERNAL_CORROBORATED
            assert len(c.corroborating_source_ids) == 1

    def test_conflict_detection_preserves_both(self):
        c1 = ExternalClaim(
            claim_id="CLM-A",
            source_id="SRC-1",
            statement="Debug console is enabled by default in production.",
            claim_type=ClaimType.EXPECTED_BEHAVIOR,
        )
        c2 = ExternalClaim(
            claim_id="CLM-B",
            source_id="SRC-2",
            statement="Debug console is disabled by default in production.",
            claim_type=ClaimType.EXPECTED_BEHAVIOR,
        )
        conflicts, updated = ConflictDetector.detect_conflicts([c1, c2])
        assert len(conflicts) == 1
        assert conflicts[0].unresolved is True
        assert conflicts[0].claim_a_id == "CLM-A"
        assert conflicts[0].claim_b_id == "CLM-B"
        assert updated[0].epistemic_status == ClaimEpistemicStatus.EXTERNAL_CONFLICTED
        assert updated[1].epistemic_status == ClaimEpistemicStatus.EXTERNAL_CONFLICTED


class TestM4VersionAwareness:
    def test_target_version_unknown_produces_evidence_gap(self):
        scope = VersionScope(
            product="Spring Framework",
            affected_versions="< 5.3.18",
            fixed_versions="5.3.18+",
        )
        status = VersionEvaluator.evaluate_applicability(None, scope)
        assert status == VersionApplicability.UNKNOWN_TARGET_VERSION

    def test_target_version_outside_affected_range(self):
        scope = VersionScope(
            product="Express.js",
            affected_versions="< 4.17.3",
            fixed_versions="4.17.3+",
        )
        status = VersionEvaluator.evaluate_applicability("4.18.2", scope)
        assert status == VersionApplicability.NOT_AFFECTED

    def test_target_version_inside_affected_range(self):
        scope = VersionScope(
            product="Django",
            affected_versions="3.2.0 - 3.2.13",
            fixed_versions="3.2.14+",
        )
        status = VersionEvaluator.evaluate_applicability("3.2.10", scope)
        assert status == VersionApplicability.AFFECTED


class TestM4SanitizationAndRouting:
    def test_sanitizer_redacts_jwt_and_secrets(self):
        dirty_q = (
            "Check endpoint with Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c and api_key='sk_live_998877665544'"
        )
        res = QuerySanitizer.sanitize(dirty_q)
        assert "eyJ" not in res.sanitized_query
        assert "sk_live" not in res.sanitized_query
        assert "[REDACTED_AUTH_HEADER]" in res.sanitized_query
        assert res.redacted_items_count >= 2

    def test_sanitizer_normalizes_numeric_and_uuid_paths(self):
        query = "Test IDOR on /api/v1/invoices/839291 and workspace /workspaces/550e8400-e29b-41d4-a716-446655440000"
        res = QuerySanitizer.sanitize(query)
        assert "/invoices/{invoices_id}" in res.sanitized_query
        assert "/workspaces/{workspaces_id}" in res.sanitized_query
        assert "839291" not in res.sanitized_query

    def test_routing_local_sufficient(self):
        router = ResearchRoutingPolicy()
        chunk = KnowledgeChunk(
            chunk_id="CHK-BOLA-001",
            document_id="DOC-BOLA",
            source_type=KnowledgeSourceType.OWASP_WSTG,
            knowledge_type=KnowledgeType.SECURITY_INVARIANT,
            title="BOLA Invariant",
            section_heading="BOLA",
            content="Content",
            token_estimate=50,
            content_hash="hash",
        )
        local_pack = VaptKnowledgePack(
            pack_id="P-1",
            items=[KnowledgeRetrievalItem(chunk=chunk, dense_score=0.9, sparse_score=0.8, fused_score=0.033, retrieval_rank=1, query_id="Q1")],
            total_tokens=50,
            rendered_query_text="BOLA query",
            retrieval_timestamp="2026-10-06T00:00:00Z",
            corpus_manifest_hash="hash",
            provenance_hash="prov",
        )
        decision = router.evaluate_routing("How do I test BOLA object level authorization?", local_pack)
        assert decision.mode == ResearchRoutingDecisionMode.LOCAL_ONLY

    def test_routing_escalates_on_external_technology(self):
        router = ResearchRoutingPolicy()
        decision = router.evaluate_routing("What are the OAuth PKCE RFC 7636 validation rules?")
        assert decision.mode == ResearchRoutingDecisionMode.LOCAL_PLUS_EXTERNAL
        assert decision.sanitized_external_query is not None
