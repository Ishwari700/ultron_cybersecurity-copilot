"""Deterministic Investigation Summary Generator (Milestone M5).

Generates structured investigation metrics directly from workspace state,
preventing LLM hallucination of counts, findings, or verification status.
"""

from typing import Any, Dict, List
from pydantic import BaseModel, Field

from src.investigation.models import (
    EvidenceGapStatus,
    HypothesisStatus,
    InvestigationWorkspace,
)


class InvestigationMetricsSummary(BaseModel):
    """Immutable metrics summary computed from structured workspace state."""
    investigation_id: str
    title: str
    target_host: str
    scope_status: str
    total_observations: int
    total_hypotheses: int
    open_evidence_gaps: int
    recommended_experiments: int
    human_verified_findings: int
    external_research_runs_count: int
    primary_domain: str
    last_updated: str

    def format_text_summary(self) -> str:
        """Renders standard ASCII summary block per Section 48."""
        return (
            f"Investigation: {self.investigation_id}\n"
            f"Title:         {self.title}\n"
            f"Target Host:   {self.target_host} ({self.scope_status})\n"
            f"Domain:        {self.primary_domain}\n"
            f"Evidence:      {self.total_observations} observations\n"
            f"Hypotheses:    {self.total_hypotheses} hypotheses\n"
            f"Open Gaps:     {self.open_evidence_gaps} evidence gaps\n"
            f"Experiments:   {self.recommended_experiments} recommended manual experiments\n"
            f"Findings:      {self.human_verified_findings} human-verified findings\n"
            f"Research Runs: {self.external_research_runs_count} external runs"
        )


class InvestigationSummaryGenerator:
    """Generates verifiable summaries from an InvestigationWorkspace."""

    @classmethod
    def generate_summary(cls, workspace: InvestigationWorkspace) -> InvestigationMetricsSummary:
        """Computes summary statistics directly from workspace arrays."""
        open_gaps = sum(1 for g in workspace.evidence_gaps if g.status == EvidenceGapStatus.OPEN)
        verified_count = len(workspace.findings)

        # Determine primary domain from hypotheses if available
        domains = [h.domain for h in workspace.hypotheses if h.domain]
        primary_domain = max(set(domains), key=domains.count) if domains else "GENERAL_CYBERSECURITY"

        return InvestigationMetricsSummary(
            investigation_id=workspace.investigation_id,
            title=workspace.title,
            target_host=workspace.target_host,
            scope_status=workspace.scope_status,
            total_observations=len(workspace.observations),
            total_hypotheses=len(workspace.hypotheses),
            open_evidence_gaps=open_gaps,
            recommended_experiments=len(workspace.experiments),
            human_verified_findings=verified_count,
            external_research_runs_count=len(workspace.external_research_run_ids),
            primary_domain=primary_domain,
            last_updated=workspace.last_updated,
        )
