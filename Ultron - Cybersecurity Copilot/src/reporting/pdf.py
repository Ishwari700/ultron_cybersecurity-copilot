"""PDF Report Generator for Security Assessment Reports.

Generates:
- Standards-compliant binary PDF (%PDF-1.4) containing deterministic report metadata
- Preserves finding status, verifier identity, evidence references, and attestation hash
- Pure Python zero-dependency generation for local, offline execution
"""

import io
from typing import List
from src.reporting.models import AssessmentReportData


class PdfReportRenderer:
    """Renders AssessmentReportData into a valid, standalone PDF document."""

    @classmethod
    def render_bytes(cls, data: AssessmentReportData) -> bytes:
        """Generates valid PDF-1.4 binary stream with structured report text."""
        buf = io.BytesIO()

        # PDF header
        buf.write(b"%PDF-1.4\n")
        buf.write(b"%\xe2\xe3\xcf\xd3\n")

        # Prepare text lines to render into PDF
        lines: List[str] = [
            f"SECURITY ASSESSMENT REPORT: {data.assessment_name}",
            f"Organization: {data.organization}",
            f"Assessment ID: {data.assessment_id}",
            f"Report ID: {data.report_id}",
            f"Authorization: {data.authorization_reference}",
            f"Scope Reference: {data.scope_reference}",
            f"Generated: {data.generated_at}",
            "----------------------------------------------------------------------",
            f"EXECUTIVE SUMMARY: {len(data.verified_findings)} Verified Finding(s)",
            "----------------------------------------------------------------------",
        ]

        for idx, f in enumerate(data.verified_findings, 1):
            lines.append(f"FINDING {idx}: [{f.severity}] {f.title}")
            lines.append(f"  ID: {f.finding_id} | Status: {f.epistemic_status}")
            lines.append(f"  Asset: {f.asset} | Component: {f.affected_component}")
            lines.append(f"  Verified By: {f.verified_by} at {f.verified_at}")
            lines.append(f"  Description: {f.description[:120]}...")
            lines.append(f"  Evidence: {', '.join(f.evidence)}")
            lines.append(f"  Remediation: {f.remediation[:120]}...")
            lines.append("")

        if data.attestation:
            lines.append("----------------------------------------------------------------------")
            lines.append(f"ATTESTATION SHA-256: {data.attestation.sha256_hash}")
            lines.append(f"Validator Version: {data.attestation.validator_version} | Status: {data.attestation.signature_status}")

        # Assemble PDF stream commands
        content_stream = io.BytesIO()
        content_stream.write(b"BT\n")
        content_stream.write(b"/F1 10 Tf\n")
        content_stream.write(b"50 750 Td\n")
        content_stream.write(b"14 TL\n")  # leading / line spacing

        for line in lines:
            # Escape PDF parentheses and backslashes
            safe_text = (
                line.replace("\\", "\\\\")
                .replace("(", "\\(")
                .replace(")", "\\)")
                .encode("latin-1", errors="replace")
            )
            content_stream.write(b"(" + safe_text + b") '\n")

        content_stream.write(b"ET\n")
        stream_bytes = content_stream.getvalue()

        # Object tracking for xref table
        offsets = []

        # Object 1: Catalog
        offsets.append(buf.tell())
        buf.write(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")

        # Object 2: Pages
        offsets.append(buf.tell())
        buf.write(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")

        # Object 3: Page
        offsets.append(buf.tell())
        buf.write(
            b"3 0 obj\n"
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n"
        )

        # Object 4: Contents
        offsets.append(buf.tell())
        buf.write(f"4 0 obj\n<< /Length {len(stream_bytes)} >>\nstream\n".encode("ascii"))
        buf.write(stream_bytes)
        buf.write(b"\nendstream\nendobj\n")

        # Object 5: Font
        offsets.append(buf.tell())
        buf.write(b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n")

        # Cross-reference table (xref)
        xref_offset = buf.tell()
        buf.write(b"xref\n0 6\n0000000000 65535 f \n")
        for off in offsets:
            buf.write(f"{off:010d} 00000 n \n".encode("ascii"))

        # Trailer
        buf.write(b"trailer\n<< /Size 6 /Root 1 0 R >>\n")
        buf.write(b"startxref\n")
        buf.write(f"{xref_offset}\n".encode("ascii"))
        buf.write(b"%%EOF\n")

        return buf.getvalue()

    render = render_bytes


# Functional alias for specification parity
generate_pdf_report = PdfReportRenderer.render_bytes
