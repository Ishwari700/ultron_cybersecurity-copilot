"""Claim Extraction Layer for External Technical Documents (M4).

Extracts structured technical claims from external sources (RFCs, OWASP, NIST,
GitHub code, Advisories) without dumping unconstrained web text into LLM prompts.

Preserves:
- Exact source linkage (source_id)
- Claim categorization (SECURITY_INVARIANT, TESTING_METHOD, etc.)
- Version scopes
- Evidence spans
- Epistemic status (EXTERNAL_REPORTED / EXTERNAL_CORROBORATED)
"""

import hashlib
import re
from typing import Dict, List, Optional, Tuple

from src.research.models import (
    ClaimEpistemicStatus,
    ClaimType,
    ExternalClaim,
    ExternalSource,
    VersionScope,
)
from src.research.version import VersionEvaluator


class ClaimExtractor:
    """Deterministic extractor of technical claims from verified external sources."""

    INVARIANT_PATTERNS = [
        (re.compile(r"(?:must|shall|required to)\s+([^.\n]+)", re.IGNORECASE), ClaimType.SECURITY_INVARIANT),
        (re.compile(r"(?:reject|deny|forbid|block)\s+([^.\n]+)", re.IGNORECASE), ClaimType.SECURITY_INVARIANT),
        (re.compile(r"invariant:\s*([^.\n]+)", re.IGNORECASE), ClaimType.SECURITY_INVARIANT),
    ]

    TESTING_PATTERNS = [
        (re.compile(r"(?:test|verify|check|inspect)\s+([^.\n]+)", re.IGNORECASE), ClaimType.TESTING_METHOD),
        (re.compile(r"(?:send|request)\s+(?:a\s+)?([A-Z]+)\s+([^.\n]+)", re.IGNORECASE), ClaimType.TESTING_METHOD),
    ]

    VULNERABILITY_PATTERNS = [
        (re.compile(r"(?:vulnerability|flaw|cve-\d+-\d+|bypass|idor|bola)\s*:?\s*([^.\n]+)", re.IGNORECASE), ClaimType.VULNERABILITY_DESCRIPTION),
        (re.compile(r"allows\s+(?:an?\s+)?(?:attacker|user)\s+to\s+([^.\n]+)", re.IGNORECASE), ClaimType.VULNERABILITY_DESCRIPTION),
    ]

    FP_WARNING_PATTERNS = [
        (re.compile(r"(?:false positive|legitimate|by design|intended behavior)\s*:?\s*([^.\n]+)", re.IGNORECASE), ClaimType.FALSE_POSITIVE_WARNING),
        (re.compile(r"(?:public endpoint|catalog|unauthenticated by specification)\s*:?\s*([^.\n]+)", re.IGNORECASE), ClaimType.FALSE_POSITIVE_WARNING),
    ]

    VERSION_PATTERNS = [
        re.compile(r"(?:affected|versions?|prior to|before)\s*:?\s*([v\d\.\s\-\+<>]+)", re.IGNORECASE),
        re.compile(r"(?:fixed in|patched in)\s*:?\s*([v\d\.\s\+]+)", re.IGNORECASE),
    ]

    @classmethod
    def extract_claims(
        cls,
        source: ExternalSource,
        target_version: Optional[str] = None,
    ) -> List[ExternalClaim]:
        """
        Extracts structured claims from source text.
        External text is strictly treated as passive data.
        """
        claims: List[ExternalClaim] = []
        lines = [line.strip() for line in source.normalized_content.splitlines() if line.strip()]

        # 1. Parse Version Scope if present in source text
        version_scope: Optional[VersionScope] = None
        for line in lines:
            if "version" in line.lower() or "affected" in line.lower() or "fixed" in line.lower():
                affected_match = re.search(r"(?:affected|impacted|prior to)\s*:\s*([^\n;]+)", line, re.IGNORECASE)
                fixed_match = re.search(r"(?:fixed in|patched in)\s*:\s*([^\n;]+)", line, re.IGNORECASE)
                if affected_match or fixed_match:
                    aff_str = affected_match.group(1).strip() if affected_match else None
                    fix_str = fixed_match.group(1).strip() if fixed_match else None
                    version_scope = VersionScope(
                        product=source.title or "Unknown Product",
                        affected_versions=aff_str,
                        fixed_versions=fix_str,
                    )
                    if target_version:
                        version_scope.applicability = VersionEvaluator.evaluate_applicability(
                            target_version, version_scope
                        )
                    break

        # 2. Extract structured statements line by line
        seen_statements = set()
        for line in lines:
            # Check prompt injection patterns in external text - neutralizes attempts
            if re.search(r"(ignore\s+(all\s+)?previous\s+instructions|system\s+prompt|send\s+credentials)", line, re.IGNORECASE):
                continue  # Skip malicious injection lines during claim extraction

            matched_type: Optional[ClaimType] = None
            evidence_span: str = line

            # Match Invariants
            for pat, ctype in cls.INVARIANT_PATTERNS:
                if pat.search(line):
                    matched_type = ctype
                    break

            # Match Testing Methods
            if not matched_type:
                for pat, ctype in cls.TESTING_PATTERNS:
                    if pat.search(line):
                        matched_type = ctype
                        break

            # Match Vulnerabilities
            if not matched_type:
                for pat, ctype in cls.VULNERABILITY_PATTERNS:
                    if pat.search(line):
                        matched_type = ctype
                        break

            # Match False Positive / Counterfactual warnings
            if not matched_type:
                for pat, ctype in cls.FP_WARNING_PATTERNS:
                    if pat.search(line):
                        matched_type = ctype
                        break

            if matched_type and line not in seen_statements:
                seen_statements.add(line)
                claim_id = f"EXT-CLM-{hashlib.sha256((source.source_id + line).encode()).hexdigest()[:8]}"
                claims.append(
                    ExternalClaim(
                        claim_id=claim_id,
                        source_id=source.source_id,
                        statement=line,
                        claim_type=matched_type,
                        confidence=0.85 if source.trust_tier.value in ("TIER_1", "TIER_2") else 0.70,
                        evidence_span=evidence_span,
                        version_scope=version_scope,
                        epistemic_status=ClaimEpistemicStatus.EXTERNAL_REPORTED,
                    )
                )

        # If no specific patterns matched, create an EXPECTED_BEHAVIOR summary claim from title / top line
        if not claims and lines:
            first_line = lines[0]
            claim_id = f"EXT-CLM-{hashlib.sha256((source.source_id + first_line).encode()).hexdigest()[:8]}"
            claims.append(
                ExternalClaim(
                    claim_id=claim_id,
                    source_id=source.source_id,
                    statement=first_line,
                    claim_type=ClaimType.EXPECTED_BEHAVIOR,
                    confidence=0.75,
                    evidence_span=first_line,
                    version_scope=version_scope,
                    epistemic_status=ClaimEpistemicStatus.EXTERNAL_REPORTED,
                )
            )

        return claims

    @staticmethod
    def corroborate_claims(claims: List[ExternalClaim]) -> List[ExternalClaim]:
        """
        Identifies independent sources making equivalent claims and marks
        status as EXTERNAL_CORROBORATED.
        
        Invariant: Corroboration increases external confidence but NEVER
        promotes EXTERNAL_KNOWLEDGE into TARGET_FACT!
        """
        statement_sources: Dict[str, List[str]] = {}
        for c in claims:
            # Normalize statement for semantic grouping
            clean = re.sub(r"\W+", " ", c.statement.lower()).strip()
            statement_sources.setdefault(clean, []).append(c.source_id)

        corroborated_claims: List[ExternalClaim] = []
        for c in claims:
            clean = re.sub(r"\W+", " ", c.statement.lower()).strip()
            sources = set(statement_sources.get(clean, []))
            if len(sources) > 1:
                c.epistemic_status = ClaimEpistemicStatus.EXTERNAL_CORROBORATED
                c.corroborating_source_ids = sorted(list(sources - {c.source_id}))
                c.confidence = min(c.confidence + 0.10, 1.0)
            corroborated_claims.append(c)

        return corroborated_claims
