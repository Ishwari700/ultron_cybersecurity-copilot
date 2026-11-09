"""External Research & Grounding Data Models (Milestone M4).

Defines formal provenance, source classification, epistemic tiers,
external claims, version metadata, conflict representations, and
grounded knowledge packs.

Enforces fundamental epistemic invariant:
    EXTERNAL_KNOWLEDGE != TARGET_EVIDENCE
"""

from datetime import datetime, timezone
from enum import Enum
import hashlib
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ExternalSourceType(str, Enum):
    """Permitted external technical knowledge source types."""
    OFFICIAL_DOCUMENTATION = "OFFICIAL_DOCUMENTATION"
    RFC = "RFC"
    OWASP = "OWASP"
    CWE = "CWE"
    NIST = "NIST"
    SECURITY_ADVISORY = "SECURITY_ADVISORY"
    VENDOR_ADVISORY = "VENDOR_ADVISORY"
    GITHUB_REPOSITORY = "GITHUB_REPOSITORY"
    GITHUB_CODE = "GITHUB_CODE"
    GITHUB_ISSUE = "GITHUB_ISSUE"
    GITHUB_DISCUSSION = "GITHUB_DISCUSSION"
    TECHNICAL_ARTICLE = "TECHNICAL_ARTICLE"
    SECURITY_RESEARCH = "SECURITY_RESEARCH"
    BLOG = "BLOG"
    UNKNOWN = "UNKNOWN"


class TrustTier(str, Enum):
    """Deterministic source trust tiers (ranking signal, NOT proof of truth)."""
    TIER_1 = "TIER_1"  # Official vendor docs, RFC, OWASP, CWE, NIST, advisories, official repos
    TIER_2 = "TIER_2"  # Established security research, reputable security orgs, maintainer docs
    TIER_3 = "TIER_3"  # Reputable technical blogs, independent security research, conference material
    TIER_4 = "TIER_4"  # Community posts, forums, discussions, unverified sources
    TIER_UNKNOWN = "TIER_UNKNOWN"  # Unknown origin


class ClaimType(str, Enum):
    """Functional categorization of extracted external technical claims."""
    SECURITY_INVARIANT = "SECURITY_INVARIANT"
    VULNERABILITY_DESCRIPTION = "VULNERABILITY_DESCRIPTION"
    TESTING_METHOD = "TESTING_METHOD"
    EXPECTED_BEHAVIOR = "EXPECTED_BEHAVIOR"
    VERSION_CONSTRAINT = "VERSION_CONSTRAINT"
    MITIGATION = "MITIGATION"
    FALSE_POSITIVE_WARNING = "FALSE_POSITIVE_WARNING"
    EXPLOITABILITY_CONDITION = "EXPLOITABILITY_CONDITION"


class ClaimEpistemicStatus(str, Enum):
    """
    Epistemic status of claims extracted from external research.
    External claims can NEVER be promoted to TARGET_FACT.
    """
    EXTERNAL_REPORTED = "EXTERNAL_REPORTED"
    EXTERNAL_CORROBORATED = "EXTERNAL_CORROBORATED"
    EXTERNAL_CONFLICTED = "EXTERNAL_CONFLICTED"
    EXTERNAL_UNVERIFIED = "EXTERNAL_UNVERIFIED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class ResearchRoutingDecisionMode(str, Enum):
    """Deterministic routing mode for external research."""
    LOCAL_ONLY = "LOCAL_ONLY"
    LOCAL_PLUS_EXTERNAL = "LOCAL_PLUS_EXTERNAL"


class VersionApplicability(str, Enum):
    """Status resulting from version matching against target version."""
    AFFECTED = "AFFECTED"
    NOT_AFFECTED = "NOT_AFFECTED"
    UNKNOWN_TARGET_VERSION = "UNKNOWN_TARGET_VERSION"  # Produces EVIDENCE_GAP
    NOT_APPLICABLE = "NOT_APPLICABLE"


class VersionScope(BaseModel):
    """Structured software version constraints and ranges."""
    product: str
    version: Optional[str] = None
    version_range: Optional[str] = None
    release: Optional[str] = None
    commit_sha: Optional[str] = None
    affected_versions: Optional[str] = None
    fixed_versions: Optional[str] = None
    applicability: VersionApplicability = VersionApplicability.UNKNOWN_TARGET_VERSION


class ExternalSource(BaseModel):
    """Provenance-preserving external technical knowledge source."""
    source_id: str = Field(..., description="Deterministic format: EXT-SRC-{hash:08x}")
    source_type: ExternalSourceType = ExternalSourceType.UNKNOWN
    title: str
    url: str
    retrieved_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    content_hash: str = Field(..., description="SHA-256 of UTF-8 normalized content")
    publisher: Optional[str] = None
    author: Optional[str] = None
    publication_date: Optional[str] = None
    last_modified: Optional[str] = None
    version: Optional[str] = None
    repository: Optional[str] = None
    commit_sha: Optional[str] = None
    path: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    license: Optional[str] = None
    trust_tier: TrustTier = TrustTier.TIER_UNKNOWN
    language: str = "en"
    http_status: int = 200
    content_type: str = "text/markdown"
    raw_content: str = ""
    normalized_content: str = ""

    def calculate_provenance_hash(self) -> str:
        """Deterministic SHA-256 of immutable source identifier and content."""
        canonical_str = f"{self.source_id}|{self.url}|{self.content_hash}|{self.commit_sha or ''}|{self.path or ''}"
        return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()


class ExternalClaim(BaseModel):
    """Atomic claim extracted from an external source with full provenance linkage."""
    claim_id: str = Field(..., description="Deterministic format: EXT-CLM-{hash:08x}")
    source_id: str = Field(..., description="References ExternalSource.source_id")
    statement: str
    claim_type: ClaimType
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    evidence_span: str = ""
    version_scope: Optional[VersionScope] = None
    applicability: str = "APPLICABLE"
    epistemic_status: ClaimEpistemicStatus = ClaimEpistemicStatus.EXTERNAL_REPORTED
    corroborating_source_ids: List[str] = Field(default_factory=list)

    def calculate_claim_hash(self) -> str:
        """Deterministic SHA-256 of claim identity, statement, and source linkage."""
        canonical = f"{self.claim_id}|{self.source_id}|{self.claim_type.value}|{self.statement}"
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class ConflictCategory(str, Enum):
    """Categorization of detected disagreements between external sources."""
    TRUE_CONFLICT = "TRUE_CONFLICT"
    VERSION_CONFLICT = "VERSION_CONFLICT"
    TEMPORAL_CHANGE = "TEMPORAL_CHANGE"
    SCOPE_DIFFERENCE = "SCOPE_DIFFERENCE"
    TERMINOLOGY_DIFFERENCE = "TERMINOLOGY_DIFFERENCE"
    APPARENT_CONFLICT = "APPARENT_CONFLICT"


class SourceConflict(BaseModel):
    """Explicit disagreement detected between independent external sources."""
    conflict_id: str = Field(..., description="Deterministic format: CONFLICT-{hash:08x}")
    claim_a_id: str
    claim_b_id: str
    source_a_id: str
    source_b_id: str
    topic: str
    statement_a: str
    statement_b: str
    category: ConflictCategory = ConflictCategory.TRUE_CONFLICT
    version_conditions: Optional[str] = None
    preferred_interpretation: Optional[str] = None
    unresolved: bool = True


class ResearchDecision(BaseModel):
    """Deterministic research routing decision emitted by ResearchRoutingPolicy."""
    decision_id: str
    mode: ResearchRoutingDecisionMode
    reasons: List[str] = Field(default_factory=list)
    local_chunk_count: int = 0
    top_local_score: float = 0.0
    detected_external_need: bool = False
    sanitized_external_query: Optional[str] = None
    target_evidence_facts_cited: List[str] = Field(default_factory=list)


class NegativeControlGuidance(BaseModel):
    """Explicit counterfactual guidance and false-positive indicators."""
    guidance_id: str
    topic: str
    legitimate_explanations: List[str] = Field(default_factory=list)
    negative_control_checks: List[str] = Field(default_factory=list)
    falsification_conditions: List[str] = Field(default_factory=list)
    required_missing_evidence: List[str] = Field(default_factory=list)


class GroundedKnowledgePack(BaseModel):
    """
    Unified knowledge container combining local VAPT methodology,
    verified external technical sources, extracted claims, version constraints,
    conflicts, and counterfactual negative-control guidance.
    
    Target evidence remains in Channel A (TARGET_FACT / TARGET_OBSERVATION).
    """
    pack_id: str
    research_run_id: str
    local_chunk_ids: List[str] = Field(default_factory=list)
    external_sources: List[ExternalSource] = Field(default_factory=list)
    external_claims: List[ExternalClaim] = Field(default_factory=list)
    version_constraints: List[VersionScope] = Field(default_factory=list)
    conflicts: List[SourceConflict] = Field(default_factory=list)
    negative_controls: List[NegativeControlGuidance] = Field(default_factory=list)
    total_token_estimate: int = 0
    provenance_chain_hash: str = ""
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def is_epistemically_isolated(self) -> bool:
        """Verifies that no target evidence tokens (FACT-*) are embedded in knowledge collections."""
        for cid in self.local_chunk_ids:
            if cid.startswith("FACT-"):
                return False
        for s in self.external_sources:
            if s.source_id.startswith("FACT-"):
                return False
        for c in self.external_claims:
            if c.claim_id.startswith("FACT-"):
                return False
        return True
