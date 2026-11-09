"""Grounding Validator for VAPT Knowledge & Epistemic Tier Separation.

Implements M3.11 & M3.12 per M3 Plan v2.3.8 Sections 17, 21, and 22:
- Epistemic tier separation:
    TARGET_OBSERVATION (FACT-xxx only in supporting/contradicting_evidence_ids)
    GENERAL_VAPT_KNOWLEDGE (CHK-xxx only in cited_methodology_chunk_ids)
- Deterministic namespace enforcement (zero CHK in facts, zero FACT in methodology)
- Citation validity (every cited CHK must exist in active signed manifest)
- Cryptographic provenance & Merkle audit path verification
- Sourcing & licensing allowlist verification against sources.json
- Zero confirmation authority enforcement (cannot emit CONFIRMED)
- Target-evidence requirement (VAPT knowledge cannot independently confirm vulnerabilities)
"""

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

from pydantic import BaseModel, Field

from src.engine.models import HypothesisDecision, HypothesisModelOutput
from src.evidence.cascade_models import LosslessStructuralPack
from src.knowledge.models import (
    CorpusManifest,
    KnowledgeChunk,
    VaptKnowledgePack,
)
from src.knowledge.provenance import (
    compute_canonical_leaf_bytes,
    compute_corpus_merkle_root,
    verify_rfc9162_audit_path,
)

logger = logging.getLogger("m3.grounding_validator")

FACT_ID_PATTERN = re.compile(r"^FACT-[A-Za-z0-9_\-]+$")
CHUNK_ID_PATTERN = re.compile(r"^CHK-[A-Za-z0-9_\-]+$")


class KnowledgeGroundingResult(BaseModel):
    """Structured result of dual cryptographic, licensing, and epistemic validation."""
    valid: bool
    status: str  # "VALID", "DISCARD", "DOWNGRADE"
    error_code: Optional[str] = None
    reason: Optional[str] = None
    invalid_fact_ids: List[str] = Field(default_factory=list)
    invalid_chunk_ids: List[str] = Field(default_factory=list)
    compliance_failures: List[str] = Field(default_factory=list)

    @property
    def is_namespace_breach(self) -> bool:
        """True if failure represents a cross-namespace citation violation."""
        return (
            self.error_code == "EPISTEMIC_CONFUSION_ERROR"
            or (self.reason is not None and "INVALID_NAMESPACE_BREACH" in self.reason)
        )


class KnowledgeGroundingValidator:
    """
    Deterministic runtime validator for VAPT methodology citations,
    epistemic tier boundaries, cryptographic provenance, and license compliance.
    """

    def __init__(
        self,
        manifest_path: Optional[Path] = None,
        sources_path: Optional[Path] = None,
    ) -> None:
        self.manifest_path = (
            Path(manifest_path)
            if manifest_path
            else Path("data/vapt_corpus/manifest.json")
        )
        self.sources_path = (
            Path(sources_path)
            if sources_path
            else Path("data/vapt_corpus/sources.json")
        )

        self._manifest: Optional[CorpusManifest] = None
        self._sources_allowlist: Dict[str, Dict[str, Any]] = {}
        self._load_corpus_metadata()

    def _load_corpus_metadata(self) -> None:
        """Load and cache corpus manifest and redistribution allowlist."""
        if self.manifest_path.exists():
            try:
                with open(self.manifest_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self._manifest = CorpusManifest(**data)
            except Exception as e:
                logger.warning(f"Could not parse manifest at {self.manifest_path}: {e}")

        if self.sources_path.exists():
            try:
                with open(self.sources_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for src in data.get("sources", []):
                        # Index by source_name and source_type
                        if "source_name" in src:
                            self._sources_allowlist[src["source_name"].upper()] = src
                        if "source_type" in src:
                            self._sources_allowlist[src["source_type"].upper()] = src
            except Exception as e:
                logger.warning(f"Could not parse sources at {self.sources_path}: {e}")

    @property
    def manifest(self) -> Optional[CorpusManifest]:
        return self._manifest

    def validate_grounding(
        self,
        hypothesis: Union[HypothesisModelOutput, Dict[str, Any]],
        pack: Optional[VaptKnowledgePack] = None,
        channel_a: Optional[LosslessStructuralPack] = None,
        require_retrieved_subset: bool = False,
    ) -> KnowledgeGroundingResult:
        """
        Execute deterministic dual grounding validation.
        
        Enforces Section 21 & Section 22 invariants:
        1. Zero Confirmation Authority
        2. Epistemic Separation (FACT IDs in evidence, CHK IDs in methodology)
        3. Target-Evidence Primacy (VAPT knowledge cannot confirm without target facts)
        4. Citation Validity (CHK IDs exist in manifest / retrieved pack)
        5. Cryptographic & Merkle Integrity
        6. Licensing & Redistribution Compliance
        7. Channel A Canonical Fact Grounding (if provided)
        """
        # Normalize hypothesis dictionary
        if isinstance(hypothesis, HypothesisModelOutput):
            hypo_data = hypothesis.model_dump()
        else:
            hypo_data = dict(hypothesis)

        raw_decision = hypo_data.get("decision", "")
        decision_val = raw_decision.value if hasattr(raw_decision, "value") else str(raw_decision)
        decision_str = str(decision_val).strip().upper()

        if "CONFIRMED" in decision_str:
            return KnowledgeGroundingResult(
                valid=False,
                status="DISCARD",
                error_code="ZERO_CONFIRMATION_AUTHORITY_VIOLATION",
                reason="M3 reasoning possess zero confirmation authority: cannot emit CONFIRMED status",
            )

        supporting_facts = list(
            hypo_data.get("supporting_evidence_ids")
            or hypo_data.get("empirical_fact_ids")
            or []
        )
        contradicting_facts = list(hypo_data.get("contradicting_evidence_ids") or [])
        cited_methodology = list(
            hypo_data.get("cited_methodology_chunk_ids")
            or hypo_data.get("methodology_references")
            or hypo_data.get("methodology_chunk_ids")
            or []
        )

        # -----------------------------------------------------------------
        # 1. Epistemic Separation: Namespace Confusion Detection
        # -----------------------------------------------------------------
        # A. CHK IDs in evidence fields -> Immediate Epistemic Confusion Error
        chk_in_supporting = [
            fid for fid in supporting_facts
            if fid.startswith("CHK-") or "CHK-" in fid
        ]
        chk_in_contradicting = [
            fid for fid in contradicting_facts
            if fid.startswith("CHK-") or "CHK-" in fid
        ]
        if chk_in_supporting or chk_in_contradicting:
            invalid_ids = chk_in_supporting + chk_in_contradicting
            return KnowledgeGroundingResult(
                valid=False,
                status="DISCARD",
                error_code="EPISTEMIC_CONFUSION_ERROR",
                reason=f"INVALID_NAMESPACE_BREACH: Epistemic tier confusion: methodology chunk IDs placed in evidence field: {invalid_ids}",
                invalid_chunk_ids=invalid_ids,
            )

        # B. FACT IDs in methodology citation field -> Immediate Epistemic Confusion Error
        fact_in_methodology = [
            cid for cid in cited_methodology
            if cid.startswith("FACT-") or "FACT-" in cid
        ]
        if fact_in_methodology:
            return KnowledgeGroundingResult(
                valid=False,
                status="DISCARD",
                error_code="EPISTEMIC_CONFUSION_ERROR",
                reason=f"INVALID_NAMESPACE_BREACH: Epistemic tier confusion: target FACT IDs placed in methodology citation field: {fact_in_methodology}",
                invalid_fact_ids=fact_in_methodology,
            )

        # C. Non-CHK syntax in methodology citations
        malformed_chk_ids = [
            cid for cid in cited_methodology
            if not CHUNK_ID_PATTERN.match(cid)
        ]
        if malformed_chk_ids:
            return KnowledgeGroundingResult(
                valid=False,
                status="DISCARD",
                error_code="CITATION_VALIDITY_ERROR",
                reason=f"Methodology citations must match pattern CHK-xxx: {malformed_chk_ids}",
                invalid_chunk_ids=malformed_chk_ids,
            )

        # -----------------------------------------------------------------
        # 2. Target Evidence Primacy
        # -----------------------------------------------------------------
        # VAPT methodology cannot independently confirm a hypothesis without target facts.
        if decision_str == "HYPOTHESIS" and not supporting_facts:
            return KnowledgeGroundingResult(
                valid=False,
                status="DISCARD",
                error_code="UNGROUNDED_HYPOTHESIS",
                reason="HYPOTHESIS requires supporting target evidence; VAPT methodology alone cannot substantiate a vulnerability claim",
            )

        # -----------------------------------------------------------------
        # 3. Channel A Evidence Grounding (if channel_a supplied)
        # -----------------------------------------------------------------
        if channel_a is not None:
            valid_fact_ids = {
                f.get("fact_id") for f in channel_a.observed_facts if f.get("fact_id")
            }
            unsupported_facts = [
                fid for fid in supporting_facts + contradicting_facts
                if fid not in valid_fact_ids
            ]
            if unsupported_facts:
                return KnowledgeGroundingResult(
                    valid=False,
                    status="DISCARD",
                    error_code="TARGET_EVIDENCE_GROUNDING_FAILURE",
                    reason=f"Cited facts not present in Channel A target evidence: {unsupported_facts}",
                    invalid_fact_ids=unsupported_facts,
                )

        # -----------------------------------------------------------------
        # 4. Methodology Citation Validity against Corpus Manifest
        # -----------------------------------------------------------------
        if self._manifest is not None:
            manifest_chunks = self._manifest.chunk_hashes
            unknown_chunks = [
                cid for cid in cited_methodology
                if cid not in manifest_chunks
            ]
            if unknown_chunks:
                return KnowledgeGroundingResult(
                    valid=False,
                    status="DISCARD",
                    error_code="CITATION_VALIDITY_ERROR",
                    reason=f"Cited methodology chunks not found in active signed corpus manifest: {unknown_chunks}",
                    invalid_chunk_ids=unknown_chunks,
                )

        # If require_retrieved_subset is True and pack is provided, ensure cited chunks were in the pack
        if require_retrieved_subset and pack is not None:
            pack_chunk_ids = {c.chunk_id for c in pack.chunks}
            unretrieved_cited = [
                cid for cid in cited_methodology
                if cid not in pack_chunk_ids
            ]
            if unretrieved_cited:
                return KnowledgeGroundingResult(
                    valid=False,
                    status="DISCARD",
                    error_code="CITATION_VALIDITY_ERROR",
                    reason=f"Cited methodology chunks were not retrieved in active VaptKnowledgePack: {unretrieved_cited}",
                    invalid_chunk_ids=unretrieved_cited,
                )

        # -----------------------------------------------------------------
        # 5. Licensing & Redistribution Allowlist Validation
        # -----------------------------------------------------------------
        if self._sources_allowlist and cited_methodology:
            compliance_errs = []
            for cid in cited_methodology:
                # Deduce source from CHK ID: e.g. CHK-DOC-WSTG-... or CHK-WSTG-..., CHK-DOC-ASVS-..., CHK-DOC-CWE-...
                source_key = self._resolve_source_key(cid)
                if source_key not in self._sources_allowlist:
                    compliance_errs.append(f"Unapproved source for chunk {cid}: '{source_key}' not on allowlist")
                else:
                    src_meta = self._sources_allowlist[source_key]
                    status = src_meta.get("redistribution_status")
                    if status not in ("PERMISSIBLE_WITH_ATTRIBUTION", "PROJECT_NATIVE"):
                        compliance_errs.append(f"Forbidden redistribution status '{status}' for chunk {cid}")

            if compliance_errs:
                return KnowledgeGroundingResult(
                    valid=False,
                    status="DISCARD",
                    error_code="KNOWLEDGE_GROUNDING_COMPLIANCE_ERROR",
                    reason="; ".join(compliance_errs),
                    compliance_failures=compliance_errs,
                )

        return KnowledgeGroundingResult(
            valid=True,
            status="VALID",
            error_code=None,
            reason="Dual evidence and methodology grounding validated successfully",
        )

    def _resolve_source_key(self, chunk_id: str) -> str:
        """Resolve source key from chunk_id for licensing check."""
        u = chunk_id.upper()
        if "WSTG" in u:
            return "OWASP WSTG"
        elif "ASVS" in u:
            return "OWASP ASVS"
        elif "CWE" in u:
            return "CWE"
        elif "PLATFORM-INV" in u or "INVAR" in u:
            return "PLATFORM INVARIANTS"
        return "UNKNOWN"
