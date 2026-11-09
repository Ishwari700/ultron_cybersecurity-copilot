"""HTML Report Renderer for Security Assessments.

Generates:
- Self-contained HTML report with responsive styling
- Visual differentiation between Verified Findings, Unverified Hypotheses, and Contested items
- Cryptographic attestation footer
"""

import html
from src.reporting.models import AssessmentReportData


class HtmlReportRenderer:
    """Renders AssessmentReportData into standalone HTML."""

    @classmethod
    def render(cls, data: AssessmentReportData) -> str:
        esc = html.escape

        findings_html = []
        for idx, f in enumerate(data.verified_findings, 1):
            sev_class = f.severity.lower()
            ev_list = "".join(f"<li><code>{esc(e)}</code></li>" for e in f.evidence)
            findings_html.append(f"""
            <div class="finding-card">
                <div class="finding-header">
                    <span class="badge badge-{sev_class}">{esc(f.severity)}</span>
                    <span class="badge badge-verified">HUMAN_VERIFIED</span>
                    <h3>2.{idx} {esc(f.title)}</h3>
                </div>
                <div class="finding-body">
                    <p><strong>Finding ID:</strong> <code>{esc(f.finding_id)}</code> | <strong>Asset:</strong> <code>{esc(f.asset)}</code> | <strong>Verifier:</strong> {esc(f.verified_by)}</p>
                    <h4>Description</h4>
                    <p>{esc(f.description)}</p>
                    <h4>Security Impact</h4>
                    <p>{esc(f.impact)}</p>
                    <h4>Evidence</h4>
                    <ul>{ev_list}</ul>
                    <h4>Verification & Reproduction</h4>
                    <pre><code>{esc(f.reproduction_steps)}</code></pre>
                    <h4>Remediation</h4>
                    <p>{esc(f.remediation)}</p>
                </div>
            </div>
            """)

        unverified_html = []
        for idx, h in enumerate(data.unverified_hypotheses, 1):
            unverified_html.append(f"""
            <div class="hypothesis-card">
                <span class="badge badge-unverified">MODEL_HYPOTHESIS</span>
                <h4>3.{idx} {esc(h.get('title', ''))}</h4>
                <p><strong>ID:</strong> <code>{esc(h.get('hypothesis_id', ''))}</code> | <strong>Domain:</strong> {esc(h.get('domain', ''))}</p>
                <p><strong>Negative Control:</strong> {esc(h.get('negative_control', 'Not specified'))}</p>
            </div>
            """)

        attestation_html = ""
        if data.attestation:
            attestation_html = f"""
            <div class="attestation-box">
                <h4>Report Attestation & Integrity</h4>
                <p><strong>SHA-256 Digest:</strong> <code>{esc(data.attestation.sha256_hash)}</code></p>
                <p><strong>Status:</strong> {esc(data.attestation.signature_status)} | <strong>Validator:</strong> {esc(data.attestation.validator_version)}</p>
            </div>
            """

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Security Assessment Report - {esc(data.organization)}</title>
<style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #1e293b; background: #f8fafc; margin: 0; padding: 24px; }}
    .container {{ max-width: 1000px; margin: 0 auto; background: #ffffff; padding: 32px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
    h1, h2, h3, h4 {{ color: #0f172a; margin-top: 1.5em; }}
    .badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; text-transform: uppercase; }}
    .badge-critical {{ background: #fee2e2; color: #991b1b; }}
    .badge-high {{ background: #ffedd5; color: #9a3412; }}
    .badge-medium {{ background: #fef3c7; color: #92400e; }}
    .badge-low {{ background: #e0f2fe; color: #075985; }}
    .badge-verified {{ background: #dcfce7; color: #166534; }}
    .badge-unverified {{ background: #f1f5f9; color: #475569; border: 1px dashed #94a3b8; }}
    .finding-card {{ border: 1px solid #e2e8f0; border-radius: 6px; padding: 16px; margin-bottom: 20px; }}
    .hypothesis-card {{ border: 1px dashed #cbd5e1; background: #f8fafc; border-radius: 6px; padding: 12px; margin-bottom: 12px; }}
    pre {{ background: #f1f5f9; padding: 12px; border-radius: 4px; overflow-x: auto; }}
    code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 13px; }}
    .attestation-box {{ background: #f8fafc; border-top: 2px solid #cbd5e1; padding: 16px; margin-top: 32px; border-radius: 4px; }}
</style>
</head>
<body>
<div class="container">
    <h1>Security Assessment Report: {esc(data.assessment_name)}</h1>
    <p><strong>Organization:</strong> {esc(data.organization)} | <strong>Report ID:</strong> <code>{esc(data.report_id)}</code></p>
    <hr>
    <h2>1. Executive Summary</h2>
    <p>Total Verified Findings: <strong>{len(data.verified_findings)}</strong> | Evaluated Assets: <strong>{len(data.assets_evaluated)}</strong></p>

    <h2>2. Detailed Verified Findings</h2>
    {"".join(findings_html) if findings_html else "<p>Zero verified findings recorded.</p>"}

    <h2>3. Unverified Hypotheses (Segregated)</h2>
    {"".join(unverified_html) if unverified_html else "<p>No unverified hypotheses.</p>"}

    {attestation_html}
</div>
</body>
</html>"""


# Functional alias for specification parity
generate_html_report = HtmlReportRenderer.render
