"""Markdown Report Renderer for Security Assessments.

Generates:
- Professional GitHub-flavored Markdown reports
- Segregated Verified Findings vs Unverified Hypotheses
- Full cryptographic attestation and audit lineage block
- Zero internal chain-of-thought leakage
"""

from src.reporting.models import AssessmentReportData


class MarkdownReportRenderer:
    """Renders AssessmentReportData into structured Markdown."""

    @classmethod
    def render(cls, data: AssessmentReportData) -> str:
        lines = []

        # Title & Metadata
        draft_badge = " [DRAFT — HUMAN REVIEW REQUIRED]" if data.is_draft else ""
        lines.append(f"# Security Assessment Report: {data.assessment_name}{draft_badge}")
        lines.append("")
        lines.append(f"**Organization:** {data.organization}  ")
        lines.append(f"**Assessment ID:** `{data.assessment_id}`  ")
        lines.append(f"**Report ID:** `{data.report_id}`  ")
        lines.append(f"**Authorization Reference:** `{data.authorization_reference}`  ")
        lines.append(f"**Scope Reference:** `{data.scope_reference}`  ")
        lines.append(f"**Generated At:** {data.generated_at}  ")
        lines.append("")
        lines.append("---")
        lines.append("")

        # Executive Summary
        lines.append("## 1. Executive Summary")
        lines.append("")
        lines.append(f"This report presents the findings of the authorized security assessment conducted for **{data.organization}**.")
        lines.append(f"- **Total Verified Findings:** {len(data.verified_findings)}")
        lines.append(f"- **Unverified Hypotheses (Segregated):** {len(data.unverified_hypotheses)}")
        lines.append(f"- **Assets Evaluated:** {len(data.assets_evaluated)}")
        lines.append("")

        # Summary Table
        if data.verified_findings:
            lines.append("### Verified Findings Overview")
            lines.append("")
            lines.append("| ID | Severity | Title | Affected Asset | ASVS Requirement | Verifier |")
            lines.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
            for f in data.verified_findings:
                lines.append(
                    f"| `{f.finding_id}` | **{f.severity}** | {f.title} | `{f.asset}` | {f.asvs_requirement or 'N/A'} | {f.verified_by} |"
                )
            lines.append("")
        else:
            lines.append("> [!NOTE]")
            lines.append("> Zero verified findings were confirmed during this assessment period.")
            lines.append("")

        # Detailed Findings
        lines.append("## 2. Detailed Verified Findings")
        lines.append("")
        for idx, f in enumerate(data.verified_findings, 1):
            lines.append(f"### 2.{idx} [{f.severity}] {f.title}")
            lines.append("")
            lines.append(f"- **Finding ID:** `{f.finding_id}`")
            lines.append(f"- **Epistemic Status:** `{f.epistemic_status}`")
            lines.append(f"- **Affected Asset:** `{f.asset}`")
            lines.append(f"- **Component:** `{f.affected_component}`")
            lines.append(f"- **Human Verifier:** `{f.verified_by}`")
            lines.append(f"- **Verification Timestamp:** `{f.verified_at}`")
            lines.append("")
            lines.append("#### Description")
            lines.append(f"{f.description}")
            lines.append("")
            lines.append("#### Security Impact")
            lines.append(f"{f.impact}")
            lines.append("")
            lines.append("#### Evidence References")
            for ev in f.evidence:
                lines.append(f"- `{ev}`")
            lines.append("")
            lines.append("#### Steps to Reproduce / Verification")
            lines.append(f"{f.reproduction_steps}")
            lines.append("")
            lines.append("#### Suggested Remediation")
            lines.append(f"{f.remediation}")
            lines.append("")
            if f.references:
                lines.append("#### References")
                for ref in f.references:
                    lines.append(f"- {ref}")
                lines.append("")
            lines.append("---")
            lines.append("")

        # Unverified Hypotheses Section (Strict Epistemic Segregation)
        lines.append("## 3. Unverified Hypotheses & Open Inquiries")
        lines.append("")
        lines.append("> [!IMPORTANT]")
        lines.append("> The following items represent analytical model hypotheses or observation gaps that have **NOT** been confirmed through human verification. They are strictly segregated from confirmed findings.")
        lines.append("")
        if data.unverified_hypotheses:
            for idx, h in enumerate(data.unverified_hypotheses, 1):
                lines.append(f"### 3.{idx} [UNVERIFIED] {h.get('title')}")
                lines.append(f"- **Hypothesis ID:** `{h.get('hypothesis_id')}`")
                lines.append(f"- **Domain:** `{h.get('domain')}`")
                lines.append(f"- **Status:** `{h.get('status')}`")
                lines.append(f"- **Negative Control Required:** {h.get('negative_control', 'Not specified')}")
                lines.append("")
        else:
            lines.append("No open unverified hypotheses recorded.")
            lines.append("")

        # Attestation & Cryptographic Integrity Block
        lines.append("## 4. Report Attestation & Integrity")
        lines.append("")
        if data.attestation:
            lines.append(f"- **SHA-256 Digest:** `{data.attestation.sha256_hash}`")
            lines.append(f"- **Attestation Status:** `{data.attestation.signature_status}`")
            lines.append(f"- **Validator Engine Version:** `{data.attestation.validator_version}`")
            lines.append(f"- **Generated At:** `{data.attestation.generated_at}`")
        lines.append("")

        return "\n".join(lines)


# Functional alias for specification parity
generate_markdown_report = MarkdownReportRenderer.render
