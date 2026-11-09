"""Knowledge Schemas and Data Models for M3 VAPT Knowledge RAG.

All knowledge schemas are pinned under namespace v3.0.0 per M3 Plan v2.3.8 Section 9.
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class KnowledgeSourceType(str, Enum):
    """Permitted knowledge source classification types."""
    OWASP_WSTG = "OWASP_WSTG"
    OWASP_ASVS = "OWASP_ASVS"
    CWE = "CWE"
    PLATFORM_INVARIANT = "PLATFORM_INVARIANT"


class KnowledgeType(str, Enum):
    """Functional categorization of security knowledge chunks (Milestone M5 Section 13)."""
    SECURITY_INVARIANT = "SECURITY_INVARIANT"
    TESTING_METHODOLOGY = "TESTING_METHODOLOGY"
    EXPERIMENT_PATTERN = "EXPERIMENT_PATTERN"
    NEGATIVE_CONTROL = "NEGATIVE_CONTROL"
    NEGATIVE_CONTROL_GUIDE = "NEGATIVE_CONTROL_GUIDE"
    FALSE_POSITIVE_GUIDANCE = "FALSE_POSITIVE_GUIDANCE"
    VERSION_CONSTRAINT = "VERSION_CONSTRAINT"
    VULNERABILITY_PATTERN = "VULNERABILITY_PATTERN"
    SECURE_CONFIGURATION = "SECURE_CONFIGURATION"
    MITIGATION = "MITIGATION"
    TOOL_GUIDANCE = "TOOL_GUIDANCE"
    PROTOCOL_BEHAVIOR = "PROTOCOL_BEHAVIOR"
    ATTACK_SURFACE_PATTERN = "ATTACK_SURFACE_PATTERN"
    CODE_SECURITY_PATTERN = "CODE_SECURITY_PATTERN"


class EpistemicTier(str, Enum):
    """
    Strict 5-tier epistemic separation per M3 Plan v2.3.8 Section 21.2.
    
    Prevents external general security knowledge from masquerading as verified target evidence.
    """
    TARGET_OBSERVATION = "TARGET_OBSERVATION"      # Verified target facts (FACT-xxx only)
    SECURITY_INVARIANT = "SECURITY_INVARIANT"      # Mandatory endpoint rules
    EVIDENCE_GAP = "EVIDENCE_GAP"                  # Missing observation needed for confirmation
    GENERAL_VAPT_KNOWLEDGE = "GENERAL_VAPT_KNOWLEDGE"  # External methodology (CHK-xxx only)
    MODEL_INFERENCE = "MODEL_INFERENCE"            # 7B synthesized hypothesis / proposed experiment


class EvidenceGapType(str, Enum):
    """
    Closed deterministic enum for evidence gap classification.
    
    Restricted to prevent unconstrained target-controlled text from driving retrieval.
    """
    MISSING_CROSS_IDENTITY_OBJECT_VERIFICATION = "MISSING_CROSS_IDENTITY_OBJECT_VERIFICATION"
    MISSING_ROLE_HIERARCHY_ENFORCEMENT = "MISSING_ROLE_HIERARCHY_ENFORCEMENT"
    MISSING_UNAUTHENTICATED_ACCESS_CHECK = "MISSING_UNAUTHENTICATED_ACCESS_CHECK"
    MISSING_MUTATION_STATE_BOUNDARY = "MISSING_MUTATION_STATE_BOUNDARY"
    MISSING_INPUT_TYPE_TAMPER_CONTROL = "MISSING_INPUT_TYPE_TAMPER_CONTROL"
    MISSING_TENANT_ISOLATION_CHECK = "MISSING_TENANT_ISOLATION_CHECK"


class QueryRendererId(str, Enum):
    """Deterministic query renderers evaluated as orthogonal experimental factors."""
    RENDERER_S = "RENDERER_S"  # Structured pipe-delimited rendering
    RENDERER_N = "RENDERER_N"  # Natural-language deterministic template


class KnowledgeDocumentFrontmatter(BaseModel):
    """Immutable YAML frontmatter contract required for all corpus documents."""
    document_id: str
    title: str
    source_name: str
    source_version: str
    source_url: str
    license: str
    author: str
    content_hash: str = Field(..., description="SHA-256 of UTF-8 normalized markdown body")


class KnowledgeChunk(BaseModel):
    """Atomic unit of retrieval passed to the reasoning context."""
    schema_version: str = "3.0.0"
    chunk_id: str = Field(..., description="Deterministic format: CHK-{DOC_ID}-{SEC_IDX:03d}-{PART:02d}")
    document_id: str
    source_type: KnowledgeSourceType
    knowledge_type: KnowledgeType
    category_tags: List[str] = Field(default_factory=list)
    title: str
    section_heading: str
    content: str
    token_estimate: int
    content_hash: str = Field(..., description="SHA-256 of UTF-8 normalized chunk content")
    trust_tier: str = "CURATED_ADVISORY"


class KnowledgeRetrievalItem(BaseModel):
    """Ranked retrieval candidate with scoring and provenance metadata."""
    chunk: KnowledgeChunk
    dense_score: float = 0.0
    sparse_score: float = 0.0
    fused_score: float = 0.0
    retrieval_rank: int
    query_id: str


class VaptKnowledgePack(BaseModel):
    """Container of retrieved advisory knowledge injected into ReasoningContextBuilder."""
    schema_version: str = "3.0.0"
    pack_id: str
    items: List[KnowledgeRetrievalItem] = Field(default_factory=list)
    total_tokens: int
    rendered_query_text: str  # Explicitly rendered query output string (logging/audit artifact)
    retrieval_timestamp: str
    corpus_manifest_hash: str
    provenance_hash: str  # SHA-256 of all chunk hashes + rendered_query_text
    serialized_p4_wire: str = ""
    epistemic_tier: EpistemicTier = EpistemicTier.GENERAL_VAPT_KNOWLEDGE



class SourceAllowlistEntry(BaseModel):
    """Redistribution allowlist specification for a corpus knowledge source."""
    source_name: str
    source_type: KnowledgeSourceType
    maintainer: str
    target_version: str
    license: str
    redistribution_status: str
    attribution_requirement: str
    canonical_url: Optional[str] = None


class TrustRootRecord(BaseModel):
    """Pinned immutable offline trust-root record for Ed25519 signature verification."""
    key_id: str
    public_key_bytes: str  # 64-character lowercase hex string of 32-byte Ed25519 public key
    public_key_fingerprint: str  # SHA-256 lowercase hex of public_key_bytes
    algorithm: str = "Ed25519"
    created_at: str
    description: str


class CorpusManifest(BaseModel):
    """Signed manifest declaring corpus content identity, Merkle root, and build provenance."""
    manifest_version: str = "3.0.0"
    corpus_version: str
    merkle_root: str = Field(..., description="64-character lowercase hex of RFC 9162 Merkle Tree Hash")
    document_hashes: Dict[str, str] = Field(default_factory=dict)
    chunk_hashes: Dict[str, str] = Field(default_factory=dict)
    chunk_count: int
    document_count: int
    build_timestamp: str
    builder_commit: str
    build_environment: str
    toolchain_version: str
    chunker_version: str = "1.0.0"
    chunker_code_hash: str
    sources: List[Dict[str, Any]] = Field(default_factory=list)
    index_identity: Optional[str] = None


# Canonical M9 Entity Models
from src.knowledge.canonical_models import (
    AuthorityLevel,
    CanonicalSourceType,
    KnowledgeFreshnessStatus,
    KnowledgeRelationType,
    KnowledgeSource,
    KnowledgeVersion,
    KnowledgeDocument,
    KnowledgeSection,
    KnowledgeClaim,
    KnowledgeReference,
    KnowledgeRelation,
    KnowledgeQuery,
    KnowledgeCitation,
    KnowledgeConflict,
    KnowledgeAnswer,
    KnowledgeResearchSession,
)
