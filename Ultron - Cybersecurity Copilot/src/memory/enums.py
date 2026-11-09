"""Enumerations for M12 Security Research Memory and Knowledge Management.

Defines namespaces, epistemic statuses, authority hierarchies,
lifecycle states, promotion levels, freshness states, conflict types,
and sensitivity classifications.
"""

from enum import Enum


class MemoryNamespace(str, Enum):
    """
    Deterministic memory namespaces governing access scope and isolation.
    """
    GLOBAL_KNOWLEDGE = "GLOBAL_KNOWLEDGE"        # Plane 1: Stable cybersecurity knowledge (M9)
    USER_RESEARCH = "USER_RESEARCH"              # Plane 2: User's long-lived research memory
    SHARED_RESEARCH = "SHARED_RESEARCH"          # Plane 2: Human-promoted cross-assessment patterns
    ASSESSMENT_LOCAL = "ASSESSMENT_LOCAL"        # Plane 3: Strict per-assessment isolated memory
    VERIFIED_PATTERN = "VERIFIED_PATTERN"        # Abstracted verified findings (human-promoted)
    TARGET_EVIDENCE_POINTER = "TARGET_EVIDENCE_POINTER"  # Plane 4: Pointers to canonical evidence only


class EpistemicStatus(str, Enum):
    """
    Explicit epistemic classification of memory items.
    Prevents unverified hypotheses or claims from silently becoming facts.
    """
    FACT = "FACT"
    OBSERVATION = "OBSERVATION"
    USER_PROVIDED_INFORMATION = "USER_PROVIDED_INFORMATION"
    MODEL_HYPOTHESIS = "MODEL_HYPOTHESIS"
    INFERENCE = "INFERENCE"
    UNVERIFIED_CLAIM = "UNVERIFIED_CLAIM"
    HUMAN_VERIFIED_FINDING = "HUMAN_VERIFIED_FINDING"
    EVIDENCE_GAP = "EVIDENCE_GAP"


class MemoryAuthority(str, Enum):
    """
    Strict authority levels. Never inferred from retrieval frequency or LLM repetition.
    """
    AUTHORITATIVE_EXTERNAL = "AUTHORITATIVE_EXTERNAL"  # RFCs, CVEs, OWASP, standards
    HUMAN_VERIFIED = "HUMAN_VERIFIED"                  # Confirmed by security researcher
    USER_PROVIDED = "USER_PROVIDED"                    # Input provided directly by user
    CANONICAL_OBSERVATION = "CANONICAL_OBSERVATION"    # Raw immutable HTTP/test observation
    CURATED_RESEARCH = "CURATED_RESEARCH"              # Vetted research procedures/patterns
    MODEL_DERIVED = "MODEL_DERIVED"                    # Summaries or inferences by AI
    UNVERIFIED = "UNVERIFIED"                          # Candidate claims without proof


class PromotionStatus(str, Enum):
    """
    Promotion workflow state for cross-assessment research knowledge.
    """
    LOCAL_ONLY = "LOCAL_ONLY"                          # Default for assessment memory
    CANDIDATE = "CANDIDATE"                            # Flagged as candidate for promotion
    HUMAN_REVIEW_REQUIRED = "HUMAN_REVIEW_REQUIRED"    # Awaiting human approval
    PROMOTED = "PROMOTED"                              # Promoted to SHARED_RESEARCH / VERIFIED_PATTERN
    RETIRED = "RETIRED"                                # Deprecated/retired from active use
    REVOKED = "REVOKED"                                # Explicitly rejected or revoked


class FreshnessState(str, Enum):
    """
    Time-sensitive freshness state of a memory item.
    """
    CURRENT = "CURRENT"
    AGING = "AGING"
    STALE = "STALE"
    SUPERSEDED = "SUPERSEDED"
    RETIRED = "RETIRED"
    UNKNOWN = "UNKNOWN"


class LifecycleState(str, Enum):
    """
    Operational lifecycle state of a memory item.
    """
    CREATE = "CREATE"
    ACTIVE = "ACTIVE"
    ARCHIVED = "ARCHIVED"
    EXPORTED = "EXPORTED"
    DELETED = "DELETED"


class MemorySourceType(str, Enum):
    """
    Origin category of the remembered material.
    """
    CONTROLLED_EXPERIMENT = "CONTROLLED_EXPERIMENT"
    FALSIFICATION_REPORT = "FALSIFICATION_REPORT"
    EXPERIMENT_OBSERVATION = "EXPERIMENT_OBSERVATION"
    NEGATIVE_CONTROL = "NEGATIVE_CONTROL"
    EVIDENCE_GAP = "EVIDENCE_GAP"
    REVIEW_DECISION = "REVIEW_DECISION"
    VERIFIED_FINDING_REF = "VERIFIED_FINDING_REF"
    RESEARCH_PROCEDURE = "RESEARCH_PROCEDURE"
    ANALYST_NOTE = "ANALYST_NOTE"
    IMPORT = "IMPORT"
    MODEL_SUMMARY = "MODEL_SUMMARY"


class ConflictType(str, Enum):
    """
    Type of detected contradiction between memory items.
    """
    DIRECT_CONTRADICTION = "DIRECT_CONTRADICTION"
    STALE_VS_NEW = "STALE_VS_NEW"
    SOURCE_DISAGREEMENT = "SOURCE_DISAGREEMENT"
    HYPOTHESIS_VS_OBSERVATION = "HYPOTHESIS_VS_OBSERVATION"


class SensitivityClassification(str, Enum):
    """
    Data sensitivity classification ensuring secrets and raw customer data
    never enter shared research namespaces.
    """
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    RESTRICTED = "RESTRICTED"
    CRITICAL_CONFIDENTIAL = "CRITICAL_CONFIDENTIAL"
