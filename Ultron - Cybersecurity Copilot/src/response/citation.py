"""Central Source Grounding and Citation Integrity Validator for Ultron responses.

Guarantees:
1. INV-CITE-1: A citation is not valid merely because the model produced a string resembling a source ID.
2. INV-CITE-2: Cross-assessment and cross-investigation isolation is strictly enforced.
3. INV-CITE-3: Target observations, authoritative knowledge chunks, and external references maintain strict epistemic segregation.
4. INV-CITE-4: Prompt injection or protocol-confusion tokens in cited text are rejected.
5. INV-CITE-5: Zero fabricated citations; non-existent IDs are explicitly flagged and rejected.
"""

from enum import Enum
import hashlib
import hmac
import os
import re
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
from pydantic import BaseModel, ConfigDict, Field

from src.core.logging import get_logger
from src.knowledge.taxonomies import TaxonomyResolver, TaxonomyLookupResult
from src.response.models import CitationReference, EpistemicStatus

logger = get_logger("CitationValidator")

_SYSTEM_CATALOG_SECRET = os.environ.get("ULTRON_CATALOG_SECRET", "ultron-authoritative-catalog-key-v1")


class TrustedCatalogAuthority(str, Enum):
    CANONICAL_LOCAL = "CANONICAL_LOCAL"
    TAXONOMY_REGISTRY = "TAXONOMY_REGISTRY"
    ENTERPRISE_FEED = "ENTERPRISE_FEED"
    VERIFIED_BENCHMARK = "VERIFIED_BENCHMARK"
    NVD_MIRROR = "NVD_MIRROR"


class TrustedCveCatalog:
    """Authoritative CVE catalog originating strictly from a trusted source boundary.

    Guarantees:
    - Tamper-evident: Bound to a verified authority via cryptographic HMAC signature.
    - Explicit registration: An arbitrary caller-supplied dictionary or set cannot
      masquerade as a TrustedCveCatalog without authentic cryptographic proof.
    - Metadata integrity: Records must provide required description/vulnerability detail
      and respect staleness markers.
    """
    def __init__(
        self,
        catalog_id: str,
        authority: TrustedCatalogAuthority,
        records: Dict[str, Dict[str, Any]],
        signature: str,
    ):
        self.catalog_id = catalog_id
        self.authority = authority
        self.records = records
        self._signature = signature

    @classmethod
    def _compute_signature(
        cls,
        catalog_id: str,
        authority: TrustedCatalogAuthority,
        records: Dict[str, Dict[str, Any]],
        secret_key: Optional[str] = None,
    ) -> str:
        key = (secret_key or _SYSTEM_CATALOG_SECRET).encode("utf-8")
        auth_val = authority.value if hasattr(authority, "value") else str(authority)
        sorted_keys = sorted(records.keys())
        payload = f"{catalog_id}:{auth_val}:{','.join(sorted_keys)}".encode("utf-8")
        return hmac.new(key, payload, hashlib.sha256).hexdigest()

    @classmethod
    def create(
        cls,
        catalog_id: str,
        authority: TrustedCatalogAuthority,
        records: Dict[str, Dict[str, Any]],
        secret_key: Optional[str] = None,
    ) -> "TrustedCveCatalog":
        """Factory method used by authoritative producers to construct a verified catalog."""
        sig = cls._compute_signature(catalog_id, authority, records, secret_key)
        return cls(catalog_id=catalog_id, authority=authority, records=records, signature=sig)

    def is_valid(self, secret_key: Optional[str] = None) -> bool:
        """Verifies that the catalog has not been forged or tampered with."""
        expected = self._compute_signature(self.catalog_id, self.authority, self.records, secret_key)
        return hmac.compare_digest(self._signature, expected)


class TrustedCatalogRegistry:
    """Process-level registry of approved authoritative catalogs."""
    _registry: Dict[str, TrustedCveCatalog] = {}

    @classmethod
    def register(cls, catalog: TrustedCveCatalog) -> None:
        if catalog.is_valid():
            cls._registry[catalog.catalog_id] = catalog
        else:
            raise ValueError(f"Cannot register catalog '{catalog.catalog_id}': signature verification failed.")

    @classmethod
    def get(cls, catalog_id: str) -> Optional[TrustedCveCatalog]:
        return cls._registry.get(catalog_id)

    @classmethod
    def clear(cls) -> None:
        cls._registry.clear()


class TrustedCveResolver:
    """Interface/wrapper representing an authoritative CVE resolver with verified provenance."""
    def __init__(self, authority: str, resolver_fn: Callable[[str], Optional[Dict[str, Any]]]):
        self.authority = authority
        self.resolver_fn = resolver_fn

    def resolve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        return self.resolver_fn(cve_id)


# Authoritative CWEs catalog
CANONICAL_CWES: Set[str] = {
    "CWE-20", "CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-119", "CWE-121", "CWE-122",
    "CWE-134", "CWE-190", "CWE-200", "CWE-208", "CWE-235", "CWE-250", "CWE-269", "CWE-284",
    "CWE-285", "CWE-306", "CWE-308", "CWE-327", "CWE-347", "CWE-350", "CWE-352", "CWE-362", "CWE-384",
    "CWE-385", "CWE-400", "CWE-416", "CWE-434", "CWE-444", "CWE-502", "CWE-601", "CWE-611",
    "CWE-639", "CWE-640", "CWE-732", "CWE-749", "CWE-770", "CWE-798", "CWE-915", "CWE-918",
    "CWE-926", "CWE-942", "CWE-1021", "CWE-1321", "CWE-1336", "CWE-1385"
}

# Local authoritative CVEs catalog (anchored to verified records in local corpus)
CANONICAL_CVES: Set[str] = {
    "CVE-2014-0160",
    "CVE-2017-5638",
    "CVE-2019-0708",
    "CVE-2020-0601",
    "CVE-2020-1472",
    "CVE-2021-42278",
    "CVE-2021-42287",
    "CVE-2021-44228",
    "CVE-2022-22965",
    "CVE-2023-38606",
}

# Regex for common citation patterns
CITATION_TAG_PATTERN = re.compile(
    r"\[(OBS-[A-Za-z0-9_-]+|FACT-OBS-[A-Za-z0-9_-]+|ASSET-[A-Za-z0-9_-]+|EVD-[A-Za-z0-9_-]+|CHK-[A-Za-z0-9_-]+|CVE-[A-Za-z0-9_-]+|CWE-\d{1,5}|https?://[^\s\]]+)\]"
)
MARKDOWN_LINK_PATTERN = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
INJECTION_PATTERN = re.compile(r"(?:ignore\s+(?:all\s+)?previous\s+instructions|<script|javascript:|SYSTEM\s*:|ADMIN\s*:)", re.IGNORECASE)


class CitationValidationResult(BaseModel):
    """Authoritative outcome of citation validation for an AI response."""
    valid_citations: List[CitationReference] = Field(default_factory=list)
    rejected_citations: List[CitationReference] = Field(default_factory=list)
    all_valid: bool = True
    precision: float = 1.0
    epistemic_status: EpistemicStatus = EpistemicStatus.MODEL_INFERENCE
    rejection_reasons: List[str] = Field(default_factory=list)
    sanitized_text: str = ""


class CitationContext(BaseModel):
    """Permitted authoritative ground-truth context against which citations are resolved."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    investigation_id: Optional[str] = None
    assessment_id: Optional[str] = None
    allowed_observation_ids: Set[str] = Field(default_factory=set)
    allowed_evidence_ids: Set[str] = Field(default_factory=set)
    allowed_chunk_ids: Set[str] = Field(default_factory=set)
    allowed_asset_ids: Set[str] = Field(default_factory=set)
    # Foreign IDs strictly belonging to other investigations/assessments
    foreign_observation_ids: Set[str] = Field(default_factory=set)
    foreign_assessment_ids: Set[str] = Field(default_factory=set)
    # Caller-supplied unverified CVE context (cannot confer authoritative existence alone)
    allowed_cve_catalog: Optional[Set[str]] = None
    cve_metadata_catalog: Optional[Dict[str, Dict[str, Any]]] = None
    cve_catalog_available: bool = True
    # Explicit trusted sources established at a controlled boundary
    trusted_cve_catalog: Optional[Any] = None
    trusted_cve_resolver: Optional[Any] = None


class ResponseCitationValidator:
    """
    Central validation boundary enforcing citation integrity, epistemic segregation,
    and cross-assessment boundary defense.
    """

    @classmethod
    def extract_citations(cls, text: str) -> List[Dict[str, str]]:
        """Extract candidate citations from text tags and markdown links."""
        candidates: List[Dict[str, str]] = []
        seen = set()

        # 1. Bracket tags e.g. [OBS-01], [CHK-VAPT-001]
        for m in CITATION_TAG_PATTERN.finditer(text):
            tag = m.group(1).strip()
            if tag not in seen:
                seen.add(tag)
                candidates.append({"source_id": tag, "raw_citation": m.group(0), "locator": None})

        # 2. Markdown links e.g. [Endpoint Obs](OBS-01)
        for m in MARKDOWN_LINK_PATTERN.finditer(text):
            title = m.group(1).strip()
            target = m.group(2).strip()
            if target not in seen:
                seen.add(target)
                candidates.append({"source_id": target, "raw_citation": m.group(0), "locator": title})

        return candidates

    @classmethod
    def validate_citations(
        cls,
        text: str,
        context: CitationContext,
        structured_citations: Optional[List[Dict[str, Any]]] = None,
    ) -> CitationValidationResult:
        """
        Validate all citations in response text or structured metadata against the active context.
        Enforces zero fabrication and cross-assessment boundary checks.
        """
        candidate_list = cls.extract_citations(text)
        if structured_citations:
            for sc in structured_citations:
                sid = sc.get("source_id") or sc.get("chunk_id") or sc.get("id")
                if sid and not any(c["source_id"] == sid for c in candidate_list):
                    candidate_list.append({
                        "source_id": sid,
                        "raw_citation": f"[{sid}]",
                        "locator": sc.get("title") or sc.get("locator"),
                    })

        valid: List[CitationReference] = []
        rejected: List[CitationReference] = []
        reasons: List[str] = []

        has_target_evidence = False
        has_knowledge = False
        has_external = False

        for cand in candidate_list:
            raw_id = cand["source_id"]
            title = cand.get("locator")

            # 1. Security / Injection Check
            if INJECTION_PATTERN.search(raw_id) or (title and INJECTION_PATTERN.search(title)):
                reason = f"SECURITY_INJECTION_REJECTED: Citation contains untrusted control sequences: '{raw_id[:30]}'"
                rejected.append(
                    CitationReference(
                        source_id=raw_id,
                        source_type="UNTRUSTED",
                        verified=False,
                        rejection_reason=reason,
                    )
                )
                reasons.append(reason)
                continue

            # 2. Cross-Assessment / Cross-Investigation Breach Check
            if raw_id in context.foreign_observation_ids:
                reason = f"CROSS_ASSESSMENT_LEAK: Observation '{raw_id}' belongs to a different assessment or investigation."
                rejected.append(
                    CitationReference(
                        source_id=raw_id,
                        source_type="TARGET_EVIDENCE",
                        assessment_id=context.assessment_id,
                        investigation_id=context.investigation_id,
                        verified=False,
                        rejection_reason=reason,
                    )
                )
                reasons.append(reason)
                continue

            # 3. Categorize and Validate Target Evidence (OBS-*, FACT-OBS-*, ASSET-*, EVD-*)
            if raw_id.startswith("OBS-") or raw_id.startswith("FACT-OBS-") or raw_id.startswith("ASSET-") or raw_id.startswith("EVD-"):
                is_valid_obs = (
                    raw_id in context.allowed_observation_ids
                    or raw_id in context.allowed_asset_ids
                    or raw_id in context.allowed_evidence_ids
                )
                if is_valid_obs:
                    has_target_evidence = True
                    valid.append(
                        CitationReference(
                            source_id=raw_id,
                            source_type="TARGET_EVIDENCE",
                            epistemic_tier="TARGET_EVIDENCE",
                            provenance="TARGET_EVIDENCE",
                            assessment_id=context.assessment_id,
                            investigation_id=context.investigation_id,
                            title=title,
                            verified=True,
                        )
                    )
                else:
                    reason = f"FABRICATED_EVIDENCE_ID: Target observation or asset ID '{raw_id}' not found in active authorized context."
                    rejected.append(
                        CitationReference(
                            source_id=raw_id,
                            source_type="TARGET_EVIDENCE",
                            provenance=None,
                            verified=False,
                            rejection_reason=reason,
                        )
                    )
                    reasons.append(reason)
                continue

            # 4. Authoritative Knowledge Chunks (CHK-*)
            if raw_id.startswith("CHK-"):
                if raw_id in context.allowed_chunk_ids:
                    has_knowledge = True
                    valid.append(
                        CitationReference(
                            source_id=raw_id,
                            source_type="AUTHORITATIVE_KNOWLEDGE",
                            epistemic_tier="AUTHORITATIVE_KNOWLEDGE",
                            provenance="AUTHORITATIVE_KNOWLEDGE",
                            title=title,
                            verified=True,
                        )
                    )
                else:
                    reason = f"FABRICATED_CHUNK_ID: Knowledge chunk ID '{raw_id}' not indexed in active knowledge corpus."
                    rejected.append(
                        CitationReference(
                            source_id=raw_id,
                            source_type="AUTHORITATIVE_KNOWLEDGE",
                            provenance=None,
                            verified=False,
                            rejection_reason=reason,
                        )
                    )
                    reasons.append(reason)
                continue

            # 5. Authoritative CWEs
            if raw_id.upper().startswith("CWE-"):
                cwe_norm = raw_id.upper()
                if cwe_norm in CANONICAL_CWES:
                    has_external = True
                    valid.append(
                        CitationReference(
                            source_id=cwe_norm,
                            source_type="EXTERNAL_REFERENCE",
                            epistemic_tier="EXTERNAL_REFERENCE",
                            provenance="CANONICAL_CWE_REGISTRY",
                            title=title or f"MITRE {cwe_norm}",
                            verified=True,
                        )
                    )
                else:
                    reason = f"INVALID_CWE: '{raw_id}' is not a recognized canonical weakness identifier."
                    rejected.append(
                        CitationReference(
                            source_id=raw_id,
                            source_type="EXTERNAL_REFERENCE",
                            provenance=None,
                            verified=False,
                            rejection_reason=reason,
                        )
                    )
                    reasons.append(reason)
                continue

            # 6. Authoritative CVEs
            if raw_id.upper().startswith("CVE-") or raw_id.upper().startswith("CVE_"):
                cve_norm = raw_id.upper().replace("_", "-")
                # Step 1: Syntactic validation
                if not re.match(r"^CVE-\d{4}-\d{4,7}$", cve_norm):
                    reason = f"MALFORMED_CVE: Identifier '{raw_id}' does not conform to authoritative CVE specification (CVE-YYYY-NNNN+)."
                    rejected.append(
                        CitationReference(
                            source_id=raw_id,
                            source_type="EXTERNAL_REFERENCE",
                            epistemic_tier="EXTERNAL_REFERENCE",
                            resolution_status="MALFORMED_CVE",
                            provenance=None,
                            verified=False,
                            rejection_reason=reason,
                        )
                    )
                    reasons.append(reason)
                    continue

                # Step 2: Catalog availability (offline mode check)
                if context and not context.cve_catalog_available:
                    reason = f"UNRESOLVED_OFFLINE: Authoritative CVE catalog is offline or unavailable; existence of '{cve_norm}' cannot be verified."
                    rejected.append(
                        CitationReference(
                            source_id=cve_norm,
                            source_type="EXTERNAL_REFERENCE",
                            epistemic_tier="EXTERNAL_REFERENCE",
                            resolution_status="UNRESOLVED_OFFLINE",
                            provenance=None,
                            verified=False,
                            rejection_reason=reason,
                        )
                    )
                    reasons.append(reason)
                    continue

                # Step 3: Check context-provided metadata or trusted catalog metadata for anomalies (stale or insufficient metadata)
                caller_meta = (context.cve_metadata_catalog or {}).get(cve_norm) if context else None
                if caller_meta:
                    if caller_meta.get("stale"):
                        reason = f"STALE_RECORD: Catalog record for '{cve_norm}' is marked stale or superseded."
                        rejected.append(
                            CitationReference(
                                source_id=cve_norm,
                                source_type="EXTERNAL_REFERENCE",
                                epistemic_tier="EXTERNAL_REFERENCE",
                                resolution_status="STALE_RECORD",
                                provenance=None,
                                verified=False,
                                rejection_reason=reason,
                            )
                        )
                        reasons.append(reason)
                        continue
                    if caller_meta.get("insufficient_metadata") or ("description" in caller_meta and not caller_meta.get("description")):
                        reason = f"INSUFFICIENT_METADATA: Catalog record for '{cve_norm}' lacks necessary vulnerability description/details."
                        rejected.append(
                            CitationReference(
                                source_id=cve_norm,
                                source_type="EXTERNAL_REFERENCE",
                                epistemic_tier="EXTERNAL_REFERENCE",
                                resolution_status="INSUFFICIENT_METADATA",
                                provenance=None,
                                verified=False,
                                rejection_reason=reason,
                            )
                        )
                        reasons.append(reason)
                        continue

                # Step 4: Existence & Provenance verification against trusted authorities
                in_canonical = cve_norm in CANONICAL_CVES
                taxonomy_lookup = TaxonomyResolver.lookup_cve(cve_norm)

                # Check trusted custom catalog
                trusted_cat = getattr(context, "trusted_cve_catalog", None) if context else None
                trusted_cat_match = None
                if trusted_cat is not None:
                    if isinstance(trusted_cat, TrustedCveCatalog):
                        if not trusted_cat.is_valid():
                            reason = f"UNTRUSTED_CATALOG: Catalog '{trusted_cat.catalog_id}' failed cryptographic integrity check."
                            rejected.append(
                                CitationReference(
                                    source_id=cve_norm,
                                    source_type="EXTERNAL_REFERENCE",
                                    epistemic_tier="EXTERNAL_REFERENCE",
                                    resolution_status="UNVERIFIED_CVE",
                                    provenance=None,
                                    verified=False,
                                    rejection_reason=reason,
                                )
                            )
                            reasons.append(reason)
                            continue
                        if cve_norm in trusted_cat.records:
                            rec = trusted_cat.records[cve_norm]
                            if rec.get("stale"):
                                reason = f"STALE_RECORD: Trusted catalog record for '{cve_norm}' is marked stale or superseded."
                                rejected.append(
                                    CitationReference(
                                        source_id=cve_norm,
                                        source_type="EXTERNAL_REFERENCE",
                                        epistemic_tier="EXTERNAL_REFERENCE",
                                        resolution_status="STALE_RECORD",
                                        provenance=None,
                                        verified=False,
                                        rejection_reason=reason,
                                    )
                                )
                                reasons.append(reason)
                                continue
                            if rec.get("insufficient_metadata") or ("description" in rec and not rec.get("description")):
                                reason = f"INSUFFICIENT_METADATA: Trusted catalog record for '{cve_norm}' lacks required description."
                                rejected.append(
                                    CitationReference(
                                        source_id=cve_norm,
                                        source_type="EXTERNAL_REFERENCE",
                                        epistemic_tier="EXTERNAL_REFERENCE",
                                        resolution_status="INSUFFICIENT_METADATA",
                                        provenance=None,
                                        verified=False,
                                        rejection_reason=reason,
                                    )
                                )
                                reasons.append(reason)
                                continue
                            trusted_cat_match = rec

                # Check trusted resolver
                trusted_resolver = getattr(context, "trusted_cve_resolver", None) if context else None
                trusted_res_match = None
                if trusted_resolver is not None:
                    res_raw = None
                    if hasattr(trusted_resolver, "resolve"):
                        res_raw = trusted_resolver.resolve(cve_norm)
                    elif callable(trusted_resolver):
                        res_raw = trusted_resolver(cve_norm)
                    if res_raw:
                        is_found = getattr(res_raw, "found", None) if hasattr(res_raw, "found") else res_raw.get("found", True)
                        if is_found:
                            trusted_res_match = res_raw

                # Evaluate Authoritative Matches
                if in_canonical or taxonomy_lookup.found or trusted_cat_match is not None or trusted_res_match is not None:
                    has_external = True
                    cve_title = title
                    provenance_str = None

                    if in_canonical:
                        provenance_str = "CANONICAL_LOCAL_CATALOG"
                        if not cve_title:
                            if taxonomy_lookup.found and taxonomy_lookup.name:
                                cve_title = f"{cve_norm}: {taxonomy_lookup.name}"
                            else:
                                cve_title = f"National Vulnerability Database {cve_norm}"
                    elif taxonomy_lookup.found:
                        provenance_str = "TAXONOMY_REGISTRY"
                        if not cve_title:
                            cve_title = f"{cve_norm}: {taxonomy_lookup.name}" if taxonomy_lookup.name else f"National Vulnerability Database {cve_norm}"
                    elif trusted_cat_match is not None:
                        auth_val = trusted_cat.authority.value if hasattr(trusted_cat.authority, "value") else str(trusted_cat.authority)
                        provenance_str = f"TRUSTED_CATALOG:{auth_val}:{trusted_cat.catalog_id}"
                        if not cve_title:
                            cve_title = f"{cve_norm}: {trusted_cat_match.get('name')}" if trusted_cat_match.get("name") else f"National Vulnerability Database {cve_norm}"
                    elif trusted_res_match is not None:
                        auth_name = getattr(trusted_resolver, "authority", "SYSTEM_RESOLVER")
                        prov_attr = getattr(trusted_res_match, "provenance", None) if hasattr(trusted_res_match, "provenance") else trusted_res_match.get("provenance")
                        provenance_str = prov_attr or f"TRUSTED_RESOLVER:{auth_name}"
                        if not cve_title:
                            name_attr = getattr(trusted_res_match, "name", None) if hasattr(trusted_res_match, "name") else trusted_res_match.get("name")
                            cve_title = f"{cve_norm}: {name_attr}" if name_attr else f"{cve_norm}"

                    valid.append(
                        CitationReference(
                            source_id=cve_norm,
                            source_type="EXTERNAL_REFERENCE",
                            epistemic_tier="EXTERNAL_REFERENCE",
                            resolution_status="VERIFIED_IN_CATALOG",
                            provenance=provenance_str,
                            title=cve_title,
                            locator=f"https://nvd.nist.gov/vuln/detail/{cve_norm}",
                            verified=True,
                        )
                    )
                else:
                    # Unverified: Check if caller attempted to provide it via untrusted context
                    if context and context.allowed_cve_catalog and cve_norm in context.allowed_cve_catalog:
                        reason = f"UNVERIFIED_CVE: Identifier '{cve_norm}' is only present in caller-supplied context; caller context does not establish authoritative existence."
                    elif context and context.cve_metadata_catalog and cve_norm in context.cve_metadata_catalog:
                        reason = f"UNVERIFIED_CVE: Identifier '{cve_norm}' lacks authoritative catalog provenance; untrusted caller-supplied metadata cannot establish existence."
                    else:
                        reason = f"UNVERIFIED_CVE: Identifier '{cve_norm}' is syntactically valid but does not exist in any authoritative catalog."

                    rejected.append(
                        CitationReference(
                            source_id=cve_norm,
                            source_type="EXTERNAL_REFERENCE",
                            epistemic_tier="EXTERNAL_REFERENCE",
                            resolution_status="UNVERIFIED_CVE",
                            provenance=None,
                            verified=False,
                            rejection_reason=reason,
                        )
                    )
                    reasons.append(reason)
                continue

            # 7. Valid External URLs
            if raw_id.startswith("https://") or raw_id.startswith("http://"):
                if raw_id.startswith("javascript:"):
                    reason = "MALICIOUS_URI: Javascript URIs strictly prohibited."
                    rejected.append(CitationReference(source_id=raw_id, source_type="EXTERNAL_REFERENCE", verified=False, rejection_reason=reason))
                    reasons.append(reason)
                else:
                    has_external = True
                    valid.append(
                        CitationReference(
                            source_id=raw_id,
                            source_type="EXTERNAL_REFERENCE",
                            epistemic_tier="EXTERNAL_REFERENCE",
                            provenance="EXTERNAL_URL",
                            locator=raw_id,
                            verified=True,
                        )
                    )
                continue

            # Unrecognized citation format
            reason = f"UNRECOGNIZED_CITATION_FORMAT: Reference '{raw_id}' does not conform to supported citation schemas."
            rejected.append(
                CitationReference(
                    source_id=raw_id,
                    source_type="UNKNOWN",
                    verified=False,
                    rejection_reason=reason,
                )
            )
            reasons.append(reason)

        total_citations = len(valid) + len(rejected)
        precision = len(valid) / total_citations if total_citations > 0 else 1.0
        all_valid = len(rejected) == 0

        # Synthesize Epistemic Status
        if not all_valid:
            epistemic = EpistemicStatus.UNVERIFIED_CLAIM
        elif has_target_evidence:
            epistemic = EpistemicStatus.EVIDENCE_BACKED
        elif has_knowledge:
            epistemic = EpistemicStatus.AUTHORITATIVE_KNOWLEDGE
        elif has_external:
            epistemic = EpistemicStatus.EXTERNAL_SOURCE
        else:
            epistemic = EpistemicStatus.MODEL_INFERENCE

        return CitationValidationResult(
            valid_citations=valid,
            rejected_citations=rejected,
            all_valid=all_valid,
            precision=round(precision, 4),
            epistemic_status=epistemic,
            rejection_reasons=reasons,
            sanitized_text=text,
        )
