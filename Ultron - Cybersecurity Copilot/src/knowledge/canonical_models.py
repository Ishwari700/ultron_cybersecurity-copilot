"""Canonical Cybersecurity Knowledge Domain Models (Milestone M9).

Defines canonical entities and provenance representations for M9:
- KnowledgeSource, KnowledgeDocument, KnowledgeVersion, KnowledgeSection,
  KnowledgeChunk, KnowledgeClaim, KnowledgeReference, KnowledgeRelation,
  KnowledgeQuery, KnowledgeRetrievalResult, KnowledgeAnswer, KnowledgeCitation,
  KnowledgeConflict, KnowledgeResearchSession.

Enforces strict provenance chain:
    SOURCE -> DOCUMENT -> VERSION -> SECTION -> CHUNK -> CLAIM -> ANSWER
and hard epistemic separation:
    EXTERNAL_KNOWLEDGE != TARGET_EVIDENCE
    MODEL_HYPOTHESIS != HUMAN_VERIFIED_FINDING
"""

from datetime import datetime, timezone
from enum import Enum
import hashlib
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AuthorityLevel(str, Enum):
    """Authority tiers for cybersecurity knowledge sources."""
    AUTHORITATIVE = "AUTHORITATIVE"  # OWASP, NIST, MITRE, RFC, official docs, vendor advisories
    RESEARCH = "RESEARCH"            # Academic papers, conference research, technical whitepapers
    USER_OWNED = "USER_OWNED"        # User-uploaded notes, lab writeups, private methodology
    UNKNOWN = "UNKNOWN"


class CanonicalSourceType(str, Enum):
    """Categorization of authoritative, research, and user knowledge sources."""
    # Authoritative
    OWASP = "OWASP"
    NIST = "NIST"
    MITRE_ATTACK = "MITRE_ATTACK"
    CWE = "CWE"
    CAPEC = "CAPEC"
    CVE = "CVE"
    NVD = "NVD"
    CVSS = "CVSS"
    IETF_RFC = "IETF_RFC"
    VENDOR_ADVISORY = "VENDOR_ADVISORY"
    OFFICIAL_DOCS = "OFFICIAL_DOCS"
    ANDROID_SECURITY = "ANDROID_SECURITY"
    MICROSOFT_SECURITY = "MICROSOFT_SECURITY"
    LINUX_SECURITY = "LINUX_SECURITY"
    KUBERNETES_SECURITY = "KUBERNETES_SECURITY"
    CLOUD_SECURITY = "CLOUD_SECURITY"
    
    # Research
    ACADEMIC_PAPER = "ACADEMIC_PAPER"
    CONFERENCE_PUBLICATION = "CONFERENCE_PUBLICATION"
    TECHNICAL_REPORT = "TECHNICAL_REPORT"
    
    # User Owned
    USER_MARKDOWN = "USER_MARKDOWN"
    USER_PDF = "USER_PDF"
    USER_TXT = "USER_TXT"
    USER_DOCX = "USER_DOCX"
    USER_NOTES = "USER_NOTES"
    USER_RESEARCH = "USER_RESEARCH"
    USER_METHODOLOGY = "USER_METHODOLOGY"
    
    UNKNOWN = "UNKNOWN"


class KnowledgeFreshnessStatus(str, Enum):
    """Freshness classification for knowledge."""
    CURRENT = "CURRENT"
    STALE = "STALE"
    OUTDATED_INFORMATION = "OUTDATED_INFORMATION"
    SUPERSEDED = "SUPERSEDED"


class KnowledgeRelationType(str, Enum):
    """Relationships in the knowledge graph."""
    SUPPORTS = "SUPPORTS"
    CONTRADICTS = "CONTRADICTS"
    REFERENCES = "REFERENCES"
    RELATED_TO = "RELATED_TO"
    MAPS_TO_CWE = "MAPS_TO_CWE"
    MAPS_TO_CAPEC = "MAPS_TO_CAPEC"
    MAPS_TO_ATTACK = "MAPS_TO_ATTACK"
    SUPERSEDES = "SUPERSEDES"
    EXPLOITS = "EXPLOITS"
    MITIGATES = "MITIGATES"
    REQUIRES = "REQUIRES"
    TARGETS = "TARGETS"
    SUBCLASS_OF = "SUBCLASS_OF"


class KnowledgeSource(BaseModel):
    """Canonical root source with explicit authority metadata."""
    source_id: str = Field(..., description="Unique deterministic source identifier (e.g. SRC-OWASP-WSTG)")
    source_type: CanonicalSourceType
    authority_level: AuthorityLevel
    publisher: Optional[str] = None
    title: str
    author: Optional[str] = None
    canonical_uri: Optional[str] = None
    version: str = "1.0.0"
    publication_date: Optional[str] = None
    retrieval_date: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    content_hash: str = Field(..., description="SHA-256 of the source content")
    parent_source: Optional[str] = None
    trust_metadata: Dict[str, Any] = Field(default_factory=dict)
    license_metadata: Dict[str, Any] = Field(default_factory=dict)
    status: str = "ACTIVE"
    freshness: KnowledgeFreshnessStatus = KnowledgeFreshnessStatus.CURRENT


class KnowledgeVersion(BaseModel):
    """Version snapshot of a document preserving history without silent replacement."""
    version_id: str = Field(..., description="Deterministic format: VER-{DOC_ID}-{HASH[:8]}")
    document_id: str
    version_number: str
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    content_hash: str
    changelog: Optional[str] = None
    is_current: bool = True


class KnowledgeDocument(BaseModel):
    """Canonical document belonging to a KnowledgeSource."""
    document_id: str = Field(..., description="Unique document identifier (e.g. DOC-OWASP-IDOR)")
    source_id: str
    title: str
    current_version_id: str
    authority_level: AuthorityLevel = AuthorityLevel.AUTHORITATIVE
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    updated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    content_hash: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class KnowledgeSection(BaseModel):
    """Logical section within a document version."""
    section_id: str = Field(..., description="Format: SEC-{DOC_ID}-{IDX:03d}")
    document_id: str
    version_id: str
    heading: str
    level: int = 1
    section_order: int = 0
    content: str
    content_hash: str


class KnowledgeClaim(BaseModel):
    """Structured claim extracted from security knowledge."""
    claim_id: str = Field(..., description="Format: CLAIM-{HASH[:8]}")
    text: str
    epistemic_status: str = "EXTERNAL_REPORTED"
    supporting_chunks: List[str] = Field(default_factory=list)
    contradicting_chunks: List[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0, default=0.90)
    provenance_chain: List[str] = Field(
        default_factory=list,
        description="Chain: [source_id, document_id, version_id, section_id, chunk_id]"
    )

    @property
    def statement(self) -> str:
        """Backward-compatible alias for text."""
        return self.text


class KnowledgeReference(BaseModel):
    """Structured taxonomy reference (CVE, CWE, CAPEC, ATT&CK, RFC)."""
    reference_id: str
    reference_type: str  # "CVE", "CWE", "CAPEC", "ATT&CK", "RFC"
    target_id: str      # e.g., "CWE-89", "CVE-2021-44228"
    title: Optional[str] = None
    url: Optional[str] = None


class KnowledgeRelation(BaseModel):
    """Graph edge between knowledge entities."""
    relation_id: str
    source_id: str
    target_id: str
    relation_type: KnowledgeRelationType
    metadata: Dict[str, Any] = Field(default_factory=dict)


class KnowledgeQuery(BaseModel):
    """Normalized query representation for retrieval."""
    query_id: str
    raw_query: str
    rewritten_query: Optional[str] = None
    domain: str = "GENERAL_VAPT"
    subdomain: Optional[str] = None
    query_intent: str = "EXPLAIN"
    normalized_identifiers: List[str] = Field(default_factory=list)
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class KnowledgeCitation(BaseModel):
    """Verifiable citation linking an answer claim back to source chunk."""
    citation_id: str = Field(..., description="Format: CITE-{HASH[:8]}")
    claim_id: Optional[str] = None
    chunk_id: str
    document_id: str
    source_id: str
    source_title: str
    source_uri: Optional[str] = None
    authority_level: AuthorityLevel = AuthorityLevel.AUTHORITATIVE
    verified: bool = True
    provenance_chain: List[str] = Field(default_factory=list)


class KnowledgeConflict(BaseModel):
    """Structured disagreement between two knowledge sources."""
    conflict_id: str
    category: str  # "TRUE_CONFLICT", "VERSION_CONFLICT", etc.
    claim_a_id: str
    claim_b_id: str
    source_a_id: str
    source_b_id: str
    description: str
    resolution_strategy: str = "EXPLAIN_DISAGREEMENT"


class KnowledgeAnswer(BaseModel):
    """Synthesized response with grounded citations and strict provenance."""
    answer_id: str
    query_id: str
    answer_text: str
    claims: List[KnowledgeClaim] = Field(default_factory=list)
    citations: List[KnowledgeCitation] = Field(default_factory=list)
    sufficiency_status: str = "LOCAL_SUFFICIENT"
    epistemic_tier: str = "GENERAL_VAPT_KNOWLEDGE"
    conflicts_detected: List[Dict[str, Any]] = Field(default_factory=list)
    escalation_level: str = "3B"
    graph_metadata: Optional[Dict[str, Any]] = None
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class KnowledgeResearchSession(BaseModel):
    """Multi-turn cybersecurity research state machine."""
    session_id: str
    initial_question: str
    subquestions: List[str] = Field(default_factory=list)
    retrieved_sources: List[str] = Field(default_factory=list)
    claims: List[KnowledgeClaim] = Field(default_factory=list)
    contradictions: List[KnowledgeConflict] = Field(default_factory=list)
    conclusions: List[str] = Field(default_factory=list)
    evidence_gaps: List[str] = Field(default_factory=list)
    unresolved_questions: List[str] = Field(default_factory=list)
    history: List[Dict[str, Any]] = Field(default_factory=list)
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    updated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


# ---------------------------------------------------------------------------
# Persistent Ingestion Jobs & Graph Extraction Status Models
# ---------------------------------------------------------------------------

MAX_CHUNK_EXTRACTION_ATTEMPTS: int = 3


class IngestionJobStatus(str, Enum):
    """Lifecycle states for durable textbook ingestion jobs."""
    QUEUED = "QUEUED"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class IngestionPhase(str, Enum):
    """Granular stages of textbook parsing, chunking, and search indexing."""
    QUEUED = "QUEUED"
    UPLOADING = "UPLOADING"
    EXTRACTING_PDF_TEXT = "EXTRACTING_PDF_TEXT"
    PARSING_PAGES = "PARSING_PAGES"
    CREATING_CHUNKS = "CREATING_CHUNKS"
    PERSISTING_CHUNKS = "PERSISTING_CHUNKS"
    BUILDING_INDEX = "BUILDING_INDEX"
    FINALIZING = "FINALIZING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class GraphExtractionStatus(str, Enum):
    """Lifecycle states for manual, post-ingestion local-AI graph extraction."""
    NOT_STARTED = "NOT_STARTED"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    PARTIALLY_COMPLETED = "PARTIALLY_COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    PAUSED_FOR_CHAT = "PAUSED_FOR_CHAT"


class IngestionJobRecord(BaseModel):
    """Durable job ledger for background textbook ingestion."""
    job_id: str
    source_id: str
    filename: str
    title: Optional[str] = None
    authority_level: str = "USER_OWNED"
    status: IngestionJobStatus = IngestionJobStatus.QUEUED
    phase: IngestionPhase = IngestionPhase.QUEUED
    queue_position: int = 0
    total_pages: int = 0
    completed_pages: int = 0
    total_chunks: int = 0
    completed_chunks: int = 0
    checkpoint_json: Dict[str, Any] = Field(default_factory=dict)
    error_message: Optional[str] = None
    retry_count: int = 0
    cancellation_requested: bool = False
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    started_at: Optional[str] = None
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: Optional[str] = None

