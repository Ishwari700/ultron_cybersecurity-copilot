"""OWASP ASVS v4.0.3 Mapping Renderer for Security Assessment Reports.

Enforces:
- Structured mapping from verified findings to ASVS requirements
- The mapping itself is purely informational and does not artificially inflate finding confidence
"""

from typing import Any, Dict, List
from src.reporting.models import AssessmentReportData


class AsvsReportRenderer:
    """Produces structured OWASP Application Security Verification Standard (ASVS) mapping."""

    @classmethod
    def render_mapping(cls, data: AssessmentReportData) -> Dict[str, Any]:
        asvs_matrix: Dict[str, List[Dict[str, Any]]] = {}

        for f in data.verified_findings:
            req = f.asvs_requirement or "V1 Architecture and Threat Modeling"
            if req not in asvs_matrix:
                asvs_matrix[req] = []

            asvs_matrix[req].append({
                "finding_id": f.finding_id,
                "title": f.title,
                "severity": f.severity,
                "asset": f.asset,
                "evidence": f.evidence,
                "verified_by": f.verified_by,
                "verified_at": f.verified_at,
                "remediation": f.remediation,
            })

        return {
            "assessment_id": data.assessment_id,
            "report_id": data.report_id,
            "asvs_version": "4.0.3",
            "asvs_categories_covered": len(asvs_matrix),
            "findings_by_asvs_category": asvs_matrix,
        }

    @classmethod
    def render_markdown(cls, data: AssessmentReportData) -> str:
        mapping = cls.render_mapping(data)
        lines = [
            f"# OWASP ASVS v4.0.3 Compliance Matrix: {data.assessment_name}",
            f"**Report ID:** `{data.report_id}` | **Assessment ID:** `{data.assessment_id}`",
            "",
            "> [!NOTE]",
            "> ASVS requirement mapping is informational and categorizes verified findings against industry standards.",
            "",
        ]

        matrix = mapping["findings_by_asvs_category"]
        if not matrix:
            lines.append("No verified findings to map against ASVS requirements.")
            return "\n".join(lines)

        for cat, items in matrix.items():
            lines.append(f"## {cat}")
            lines.append(f"Violations identified: **{len(items)}**")
            lines.append("")
            for it in items:
                lines.append(f"- **[{it['severity']}] {it['title']}** (`{it['finding_id']}`)")
                lines.append(f"  - Target Asset: `{it['asset']}`")
                lines.append(f"  - Evidence IDs: {', '.join(it['evidence'])}")
                lines.append(f"  - Verifier: {it['verified_by']} at {it['verified_at']}")
            lines.append("")

        return "\n".join(lines)


# Functional alias for specification parity
generate_asvs_mapping = AsvsReportRenderer.render_mapping
