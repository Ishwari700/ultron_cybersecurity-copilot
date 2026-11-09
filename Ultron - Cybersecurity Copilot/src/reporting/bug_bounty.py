"""Bug Bounty Platform Report Draft Generator.

Formats verified findings or researcher drafts into standard HackerOne/Bugcrowd submission templates.
Enforces:
- Prominent 'DRAFT — HUMAN REVIEW REQUIRED' notice on all drafts
- Zero automated external submission (copilot is researcher-facing, human in the loop)
- Detailed reproduction steps, evidence references, and remediation guidance
"""

from typing import List, Optional
from src.reporting.models import AssessmentReportData, FindingReportItem


class BugBountyDraftRenderer:
    """Renders individual findings or full reports into bug bounty disclosure drafts."""

    @classmethod
    def render_finding_draft(cls, finding: FindingReportItem, is_draft: bool = True) -> str:
        status_banner = ""
        if is_draft:
            status_banner = "> [!IMPORTANT]\n> **DRAFT — HUMAN REVIEW REQUIRED BEFORE SUBMISSION**\n> This disclosure document is a researcher draft generated for review.\n\n"

        lines = [
            f"# {finding.title}",
            "",
            status_banner,
            f"**Severity:** {finding.severity}  ",
            f"**Affected Asset:** `{finding.asset}`  ",
            f"**Vulnerable Component:** `{finding.affected_component}`  ",
            f"**Verifier Identity:** {finding.verified_by}  ",
            f"**Verification Timestamp:** {finding.verified_at}  ",
            "",
            "## Summary",
            f"{finding.description}",
            "",
            "## Security Impact",
            f"{finding.impact}",
            "",
            "## Steps to Reproduce",
            "1. Set up an authorized testing proxy/environment.",
            f"{finding.reproduction_steps}",
            "",
            "## Supporting Evidence",
        ]

        for ev in finding.evidence:
            lines.append(f"- Observation ID: `{ev}`")
        lines.append("")

        lines.append("## Expected Behavior vs Actual Behavior")
        lines.append("- **Expected:** Access control or security invariant is strictly enforced.")
        lines.append("- **Actual:** Vulnerability pattern allowed unauthorized behavior as documented in evidence.")
        lines.append("")

        lines.append("## Suggested Remediation")
        lines.append(f"{finding.remediation}")
        lines.append("")

        if finding.references:
            lines.append("## References")
            for ref in finding.references:
                lines.append(f"- {ref}")
            lines.append("")

        return "\n".join(lines)

    @classmethod
    def render_report_drafts(cls, data: AssessmentReportData) -> str:
        """Renders all verified findings in an assessment into draft submission markdown."""
        if not data.verified_findings:
            return "> [!NOTE]\n> Zero verified findings available for bug bounty draft generation.\n"

        # By Phase 18, bug bounty exports are drafts requiring human review unless explicitly finalized
        is_draft = True if not getattr(data, "is_finalized", False) else data.is_draft

        drafts: List[str] = []
        for idx, f in enumerate(data.verified_findings, 1):
            drafts.append(f"<!-- SUBMISSION DRAFT {idx} -->\n" + cls.render_finding_draft(f, is_draft=is_draft))

        return "\n\n---\n\n".join(drafts)


# Functional alias for specification parity
generate_bug_bounty_draft = BugBountyDraftRenderer.render_report_drafts

