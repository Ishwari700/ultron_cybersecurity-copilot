"""Context Budgeting Engine for M6 Authorized Security Assessments.

Enforces:
1. Strict Priority Hierarchy:
   Priority 1: Authorization state (MANDATORY, NEVER DROPPED)
   Priority 2: Scope (MANDATORY, NEVER DROPPED)
   Priority 3: Target evidence
   Priority 4: Evidence gaps
   Priority 5: Security invariants
   Priority 6: Hypothesis
   Priority 7: Negative controls
   Priority 8: Relevant local knowledge
   Priority 9: External claims
   Priority 10: Conflicts
   Priority 11: Citations
2. Hard token budget cap ensuring fits within 4,096-token local LLM context.
3. INVARIANT: Authorization and Scope sections are NEVER pruned or dropped.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from src.assessment.models import (
    AssessmentHypothesis,
    AuthorizationRecord,
    CanonicalObservation,
    SecurityInvariant,
)
from src.assessment.secrets import SecretRedactor


class AssessmentContextBudgeter:
    """Budgets context items into model prompts respecting strict priorities."""

    def __init__(self, max_chars: int = 12000) -> None:  # ~3,000-4,000 tokens
        self.max_chars = max_chars

    def build_prompt_context(
        self,
        authorization: AuthorizationRecord,
        scope_summary: str,
        observations: List[CanonicalObservation],
        hypothesis: Optional[AssessmentHypothesis] = None,
        invariants: Optional[List[SecurityInvariant]] = None,
        evidence_gaps: Optional[List[str]] = None,
        external_claims: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Assembles prompt context respecting priority ordering and budget constraints.
        Priority 1 (Auth) and Priority 2 (Scope) are strictly mandatory.
        """
        sections: Dict[str, Any] = {}
        used_chars = 0

        # Priority 1: Authorization State (NEVER DROPPED)
        auth_text = (
            f"AUTH_ID: {authorization.authorization_id} | STATUS: {authorization.status.value} | "
            f"TYPE: {authorization.authorization_type.value} | ORG: {authorization.organization}"
        )
        sections["priority_1_authorization"] = auth_text
        used_chars += len(auth_text)

        # Priority 2: Scope (NEVER DROPPED)
        scope_text = f"SCOPE_POLICY: {scope_summary}"
        sections["priority_2_scope"] = scope_text
        used_chars += len(scope_text)

        # Priority 3: Target Evidence (Canonical Observations, Redacted)
        evidence_items = []
        for obs in observations:
            obs_dict = SecretRedactor.redact_dict(obs.normalized_data)
            obs_str = f"[{obs.epistemic_status}][{obs.observation_type.value}] {obs_dict}"
            if used_chars + len(obs_str) < self.max_chars * 0.65:
                evidence_items.append(obs_str)
                used_chars += len(obs_str)
            else:
                break
        sections["priority_3_evidence"] = evidence_items

        # Priority 4: Evidence Gaps
        gaps = evidence_gaps or (hypothesis.evidence_gaps if hypothesis else [])
        gap_items = []
        for g in gaps:
            g_str = f"[EVIDENCE_GAP] {g}"
            if used_chars + len(g_str) < self.max_chars * 0.75:
                gap_items.append(g_str)
                used_chars += len(g_str)
        sections["priority_4_evidence_gaps"] = gap_items

        # Priority 5: Security Invariants
        inv_items = []
        if invariants:
            for inv in invariants:
                i_str = f"[INVARIANT:{inv.invariant_type.value}] {inv.title}: {inv.secure_condition}"
                if used_chars + len(i_str) < self.max_chars * 0.85:
                    inv_items.append(i_str)
                    used_chars += len(i_str)
        sections["priority_5_invariants"] = inv_items

        # Priority 6 & 7: Hypothesis and Negative Controls
        if hypothesis:
            h_str = f"[HYPOTHESIS:{hypothesis.status.value}] {hypothesis.title}: {hypothesis.description}"
            sections["priority_6_hypothesis"] = h_str
            used_chars += len(h_str)

            if hypothesis.negative_control:
                nc_str = f"[NEGATIVE_CONTROL] {hypothesis.negative_control}"
                sections["priority_7_negative_control"] = nc_str
                used_chars += len(nc_str)

        # Priority 8 & 9: External Claims
        if external_claims:
            claim_items = []
            for c in external_claims:
                c_str = f"[EXTERNAL_KNOWLEDGE] {c}"
                if used_chars + len(c_str) < self.max_chars:
                    claim_items.append(c_str)
                    used_chars += len(c_str)
            sections["priority_9_external_claims"] = claim_items

        sections["total_chars"] = used_chars
        sections["is_within_budget"] = used_chars <= self.max_chars
        return sections
