"""Formal Security Assessment Report Generator for M6.

Enforces:
1. Complete Report Structure:
   - Executive Summary
   - Assessment Scope
   - Authorization Details
   - Methodology
   - Attack Surface & Asset Inventory
   - Confirmed Findings (HUMAN VERIFIED ONLY)
   - Out-of-Scope Observations
   - Unverified Hypotheses & Evidence Gaps
   - Testing Limitations
2. INVARIANT: Unverified hypotheses are NEVER presented as confirmed findings.
   Only findings passing all 13 FindingValidator checks and marked HUMAN_VERIFIED
   are included in the confirmed findings section.
"""

import html
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from src.assessment.models import (
    AssessmentFinding,
    AssessmentHypothesis,
    AssessmentRecord,
    AssessmentScopeStatus,
    AssetRecord,
    AuthorizationRecord,
    CanonicalObservation,
    FindingVerificationStatus,
)
from src.assessment.attack_surface import AttackSurfaceMap


class AssessmentReportContext(BaseModel):
    """Encapsulates all assessment context necessary for report rendering."""
    assessment: AssessmentRecord
    authorization: AuthorizationRecord
    assets: List[AssetRecord] = Field(default_factory=list)
    observations: List[CanonicalObservation] = Field(default_factory=list)
    attack_surface: Optional[Dict[str, Any]] = None
    hypotheses: List[AssessmentHypothesis] = Field(default_factory=list)
    findings: List[AssessmentFinding] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)


class class_or_instance_method:
    def __init__(self, fn):
        self.fn = fn

    def __get__(self, obj, cls=None):
        if obj is not None:
            def wrapper(*args, **kwargs):
                return self.fn(obj, *args, **kwargs)
            return wrapper
        else:
            def wrapper(*args, **kwargs):
                return self.fn(cls, *args, **kwargs)
            return wrapper


class AssessmentReportGenerator:
    """Renders comprehensive, auditable security assessment reports."""

    def __init__(self, context: Any = None):
        if context is not None:
            if hasattr(context, "record") and hasattr(context, "authorization"):
                self.ctx = self._build_context_from_container(context)
            elif isinstance(context, AssessmentReportContext):
                self.ctx = context
            else:
                self.ctx = context
        else:
            self.ctx = None

    @staticmethod
    def _build_context_from_container(context: Any) -> AssessmentReportContext:
        return AssessmentReportContext(
            assessment=context.record,
            authorization=context.authorization,
            assets=context.asset_graph.get_all_assets() if hasattr(context, "asset_graph") else [],
            observations=context.telemetry_pipeline.get_observations(assessment_id=context.record.assessment_id) if hasattr(context, "telemetry_pipeline") else [],
            attack_surface=context.attack_surface.export_summary() if hasattr(context, "attack_surface") else None,
            hypotheses=list(context.review_workspace.hypotheses.values()) if hasattr(context, "review_workspace") else [],
            findings=list(context.findings.values()) if hasattr(context, "findings") else [],
        )

    def _resolve_context(self, ctx: Optional[Any] = None) -> AssessmentReportContext:
        target = ctx or self.ctx
        if target is None:
            raise ValueError("No context provided for report generation")
        if hasattr(target, "record") and hasattr(target, "authorization"):
            return self._build_context_from_container(target)
        return target

    @class_or_instance_method
    def generate(self_or_cls, *args, **kwargs) -> str:
        """Generates report in requested format (markdown, json, html).

        Supported invocation forms:
        - Class-style:
          - AssessmentReportGenerator.generate(ctx)
          - AssessmentReportGenerator.generate(ctx, "json")
          - AssessmentReportGenerator.generate(ctx, format_type="html")
          - AssessmentReportGenerator.generate(ctx=ctx, format_type="json")
        - Instance-style:
          - gen = AssessmentReportGenerator(ctx)
          - gen.generate()
          - gen.generate("json")
          - gen.generate(format_type="html")
          - gen.generate(override_ctx, "json")
          - gen.generate(ctx=override_ctx, format_type="json")
        """
        fmt = "markdown"
        ctx = None

        if isinstance(self_or_cls, AssessmentReportGenerator):
            if args:
                first = args[0]
                if isinstance(first, str):
                    fmt = first
                    ctx = kwargs.get("ctx") or self_or_cls.ctx
                else:
                    ctx = first
                    fmt = args[1] if len(args) > 1 else kwargs.get("format_type", "markdown")
            else:
                fmt = kwargs.get("format_type", "markdown")
                ctx = kwargs.get("ctx") or self_or_cls.ctx
            resolved_ctx = self_or_cls._resolve_context(ctx)
        else:
            if args:
                ctx = args[0]
                fmt = args[1] if len(args) > 1 else kwargs.get("format_type", "markdown")
            else:
                ctx = kwargs.get("ctx")
                fmt = kwargs.get("format_type", "markdown")

            if ctx is None:
                raise ValueError("No context provided for report generation")
            if hasattr(ctx, "record") and hasattr(ctx, "authorization"):
                resolved_ctx = AssessmentReportGenerator._build_context_from_container(ctx)
            else:
                resolved_ctx = ctx

        return AssessmentReportGenerator._generate_dispatcher(resolved_ctx, format_type=fmt)

    @class_or_instance_method
    def generate_markdown(self_or_cls, *args, **kwargs) -> str:
        """Generates Markdown report via class or instance invocation."""
        if isinstance(self_or_cls, AssessmentReportGenerator):
            ctx = args[0] if args else kwargs.get("ctx")
            resolved_ctx = self_or_cls._resolve_context(ctx)
        else:
            ctx = args[0] if args else kwargs.get("ctx")
            if ctx is None:
                raise ValueError("No context provided for report generation")
            if hasattr(ctx, "record") and hasattr(ctx, "authorization"):
                resolved_ctx = AssessmentReportGenerator._build_context_from_container(ctx)
            else:
                resolved_ctx = ctx
        return AssessmentReportGenerator._generate_markdown_impl(resolved_ctx)

    @class_or_instance_method
    def generate_json(self_or_cls, *args, **kwargs) -> str:
        """Generates JSON report via class or instance invocation."""
        if isinstance(self_or_cls, AssessmentReportGenerator):
            ctx = args[0] if args else kwargs.get("ctx")
            resolved_ctx = self_or_cls._resolve_context(ctx)
        else:
            ctx = args[0] if args else kwargs.get("ctx")
            if ctx is None:
                raise ValueError("No context provided for report generation")
            if hasattr(ctx, "record") and hasattr(ctx, "authorization"):
                resolved_ctx = AssessmentReportGenerator._build_context_from_container(ctx)
            else:
                resolved_ctx = ctx
        return AssessmentReportGenerator._generate_json_impl(resolved_ctx)

    @class_or_instance_method
    def generate_html(self_or_cls, *args, **kwargs) -> str:
        """Generates HTML report via class or instance invocation."""
        if isinstance(self_or_cls, AssessmentReportGenerator):
            ctx = args[0] if args else kwargs.get("ctx")
            resolved_ctx = self_or_cls._resolve_context(ctx)
        else:
            ctx = args[0] if args else kwargs.get("ctx")
            if ctx is None:
                raise ValueError("No context provided for report generation")
            if hasattr(ctx, "record") and hasattr(ctx, "authorization"):
                resolved_ctx = AssessmentReportGenerator._build_context_from_container(ctx)
            else:
                resolved_ctx = ctx
        return AssessmentReportGenerator._generate_html_impl(resolved_ctx)

    @classmethod
    def _generate_dispatcher(cls, ctx: AssessmentReportContext, format_type: str = "markdown") -> str:
        fmt = (format_type or "markdown").lower().strip()
        if fmt in ("markdown", "md"):
            return cls._generate_markdown_impl(ctx)
        elif fmt == "json":
            return cls._generate_json_impl(ctx)
        elif fmt == "html":
            return cls._generate_html_impl(ctx)
        else:
            raise ValueError(
                f"Unsupported report format '{format_type}'. Supported formats: markdown, json, html."
            )

    @classmethod
    def _generate_markdown_impl(cls, ctx: AssessmentReportContext) -> str:
        """Generates GitHub-flavored markdown report."""
        now_iso = datetime.now(timezone.utc).isoformat()

        # Partition findings: HUMAN_VERIFIED vs others
        confirmed_findings = [f for f in ctx.findings if f.verification_status == FindingVerificationStatus.HUMAN_VERIFIED]
        unverified_findings = [f for f in ctx.findings if f.verification_status != FindingVerificationStatus.HUMAN_VERIFIED]
        unverified_hypotheses = [h for h in ctx.hypotheses if h.epistemic_status == "MODEL_HYPOTHESIS"]
        out_of_scope_obs = [o for o in ctx.observations if o.scope_decision != AssessmentScopeStatus.IN_SCOPE]

        md = []
        md.append(f"# Authorized Security Assessment Report: {ctx.assessment.assessment_name}\n")
        md.append(f"**Organization:** {ctx.assessment.organization}  ")
        md.append(f"**Assessment ID:** `{ctx.assessment.assessment_id}`  ")
        md.append(f"**Date Generated:** `{now_iso}`  ")
        md.append(f"**Status:** {ctx.assessment.state.value}\n")

        # 1. Executive Summary
        md.append("## 1. Executive Summary\n")
        md.append(
            f"This authorized security assessment was conducted for **{ctx.assessment.organization}** "
            f"covering defined target assets under explicit rules of engagement. "
            f"A total of **{len(ctx.assets)}** assets were inventoried, producing **{len(ctx.observations)}** "
            f"canonical observations. Testing resulted in **{len(confirmed_findings)}** human-verified security findings "
            f"and **{len(unverified_hypotheses) + len(unverified_findings)}** unverified hypotheses/candidate findings requiring further manual investigation.\n"
        )

        # 2. Authorization
        md.append("## 2. Authorization Details\n")
        md.append(f"- **Authorization ID:** `{ctx.authorization.authorization_id}`")
        md.append(f"- **Authorized By:** {ctx.authorization.authorized_by}")
        md.append(f"- **Engagement Type:** {ctx.authorization.authorization_type.value}")
        md.append(f"- **Validity Window:** `{ctx.authorization.valid_from}` to `{ctx.authorization.valid_until}`")
        md.append(f"- **Authorization Status:** `{ctx.authorization.status.value}`")
        if ctx.authorization.restrictions:
            md.append(f"- **Restrictions:** {', '.join(ctx.authorization.restrictions)}")
        md.append("")

        # 3. Assessment Scope
        md.append("## 3. Assessment Scope\n")
        md.append(f"- **Scope Reference:** `{ctx.authorization.scope_reference}`")
        md.append(f"- **Total Discovered Assets:** {len(ctx.assets)}")
        in_scope_assets = [a for a in ctx.assets if a.scope_status == AssessmentScopeStatus.IN_SCOPE]
        md.append(f"- **In-Scope Targets:** {len(in_scope_assets)}")
        md.append("")

        # 4. Methodology
        md.append("## 4. Methodology\n")
        md.append(
            "Testing adhered strictly to the M6 Authorized Security Assessment Framework:\n"
            "1. **Deterministic Scope & Authorization:** All target interactions fail-closed on unverified targets.\n"
            "2. **Passive Telemetry Normalization:** Network traffic and tool exports normalized into canonical observations.\n"
            "3. **Attack Surface Mapping:** Comprehensive inventory of endpoints, auth boundaries, and exposed services.\n"
            "4. **Hypothesis Formulation & Negative Controls:** Plausible vulnerabilities modeled against formal invariants.\n"
            "5. **Safe Manual Experiments:** Protocols executed exclusively by human researchers (zero autonomous exploit actions).\n"
            "6. **13-Point Finding Validation:** Deterministic checklist required before finding confirmation.\n"
        )

        # 5. Attack Surface & Assets
        md.append("## 5. Attack Surface Summary\n")
        if ctx.attack_surface:
            md.append(f"- **Total Attack Surface Nodes:** {ctx.attack_surface.get('total_nodes', 0)}")
            md.append(f"- **Discovered Technologies:** {', '.join(ctx.attack_surface.get('discovered_technologies', [])) or 'None'}")
            md.append(f"- **Exposed Services:** {ctx.attack_surface.get('exposed_services_count', 0)}")
            md.append(f"- **Endpoints Discovered:** {ctx.attack_surface.get('endpoints_count', 0)}")
        md.append("")

        # 6. Confirmed Findings (HUMAN VERIFIED ONLY)
        md.append("## 6. Confirmed Findings (Human Verified Only)\n")
        if not confirmed_findings:
            md.append("*No security findings have been human-verified and confirmed for this assessment.*\n")
        else:
            for idx, f in enumerate(confirmed_findings, start=1):
                md.append(f"### 6.{idx}. [{f.severity.value}] {f.title}\n")
                md.append(f"- **Finding ID:** `{f.finding_id}`")
                md.append(f"- **Affected Asset:** `{f.asset}`")
                md.append(f"- **Affected Component:** `{f.affected_component}`")
                md.append(f"- **Verification Status:** **{f.verification_status.value}** (Verified by: `{f.verified_by}` at `{f.verified_at}`)")
                md.append(f"- **Security Invariant Violated:** `{f.security_invariant}`")
                md.append(f"\n**Description:**\n{f.description}\n")
                md.append(f"**Security Impact:**\n{f.impact}\n")
                md.append(f"**Root Cause Analysis:**\n{f.root_cause}\n")
                md.append(f"**Remediation Guidance:**\n{f.remediation}\n")
                md.append(f"**Supporting Evidence Lineage:** {', '.join(f.evidence)}\n")

        # 7. Unverified Hypotheses & Evidence Gaps
        md.append("## 7. Unverified Hypotheses & Open Evidence Gaps\n")
        md.append(
            "> [!NOTE]\n"
            "> The following items represent plausible technical hypotheses or observed anomalies that have NOT "
            "> been verified by a human researcher. They MUST NOT be treated as confirmed security findings.\n"
        )
        if not unverified_hypotheses and not unverified_findings:
            md.append("*No open unverified hypotheses.*\n")
        else:
            for idx, h in enumerate(unverified_hypotheses, start=1):
                md.append(f"### 7.{idx}. [HYPOTHESIS - UNVERIFIED] {h.title}\n")
                md.append(f"- **Hypothesis ID:** `{h.hypothesis_id}`")
                md.append(f"- **Domain:** {h.domain} | **Confidence:** {h.confidence:.2f}")
                md.append(f"- **Description:** {h.description}")
                if h.evidence_gaps:
                    md.append(f"- **Required Open Evidence:** {'; '.join(h.evidence_gaps)}")
                if h.negative_control:
                    md.append(f"- **Negative Control:** {h.negative_control}")
                md.append("")

            if unverified_findings:
                md.append("### Unverified Candidate Findings (Quarantined from Confirmed Findings)\n")
                for idx, uf in enumerate(unverified_findings, start=1):
                    md.append(f"- **Candidate {idx}:** [{uf.severity.value}] {uf.title} (`{uf.finding_id}`) - Status: {uf.verification_status.value}")
                md.append("")

        # 8. Out-of-Scope Observations
        md.append("## 8. Out-of-Scope Observations (Excluded)\n")
        md.append(
            f"A total of **{len(out_of_scope_obs)}** observations were recorded outside program scope "
            f"and were strictly quarantined from analysis and findings.\n"
        )

        # 9. Testing Limitations
        md.append("## 9. Testing Limitations & Constraints\n")
        limits = ctx.limitations or [
            "Testing was restricted to non-destructive manual verification.",
            "Denial-of-service and state-destructive testing were strictly prohibited.",
            "All autonomous exploitation was disabled by safety invariants.",
        ]
        for lim in limits:
            md.append(f"- {lim}")
        md.append("")

        return "\n".join(md)

    @classmethod
    def _generate_json_impl(cls, ctx: AssessmentReportContext) -> str:
        """Generates structured JSON report with strict verification separation."""
        now_iso = datetime.now(timezone.utc).isoformat()
        confirmed_findings = [f for f in ctx.findings if f.verification_status == FindingVerificationStatus.HUMAN_VERIFIED]
        unverified_findings = [f for f in ctx.findings if f.verification_status != FindingVerificationStatus.HUMAN_VERIFIED]
        unverified_hypotheses = [h for h in ctx.hypotheses if h.epistemic_status == "MODEL_HYPOTHESIS"]
        out_of_scope_obs = [o for o in ctx.observations if o.scope_decision != AssessmentScopeStatus.IN_SCOPE]
        in_scope_assets = [a for a in ctx.assets if a.scope_status == AssessmentScopeStatus.IN_SCOPE]

        meta = {
            "assessment_id": ctx.assessment.assessment_id,
            "organization": ctx.assessment.organization,
            "assessment_name": ctx.assessment.assessment_name,
            "date_generated": now_iso,
            "status": ctx.assessment.state.value,
            "framework": "M6_AUTHORIZED_SECURITY_ASSESSMENT",
        }

        confirmed_findings_list = [
            {
                "finding_id": f.finding_id,
                "title": f.title,
                "severity": f.severity.value,
                "asset": f.asset,
                "affected_component": f.affected_component,
                "verification_status": f.verification_status.value,
                "verified_by": f.verified_by,
                "verified_at": f.verified_at,
                "security_invariant": f.security_invariant,
                "description": f.description,
                "impact": f.impact,
                "root_cause": f.root_cause,
                "remediation": f.remediation,
                "evidence": f.evidence,
            }
            for f in confirmed_findings
        ]

        unverified_findings_list = [
            {
                "finding_id": uf.finding_id,
                "title": uf.title,
                "severity": uf.severity.value,
                "verification_status": uf.verification_status.value,
                "disclaimer": "UNVERIFIED: Cannot be treated as confirmed security finding.",
            }
            for uf in unverified_findings
        ]

        report_data = {
            "report_metadata": meta,
            "metadata": meta,
            "executive_summary": {
                "total_assets": len(ctx.assets),
                "in_scope_assets": len(in_scope_assets),
                "total_observations": len(ctx.observations),
                "out_of_scope_observations": len(out_of_scope_obs),
                "confirmed_findings_count": len(confirmed_findings),
                "verified_findings_count": len(confirmed_findings),
                "unverified_hypotheses_count": len(unverified_hypotheses),
                "unverified_candidate_findings_count": len(unverified_findings),
                "quarantined_candidate_findings_count": len(unverified_findings),
            },
            "authorization": {
                "authorization_id": ctx.authorization.authorization_id,
                "authorized_by": ctx.authorization.authorized_by,
                "authorization_type": ctx.authorization.authorization_type.value,
                "valid_from": ctx.authorization.valid_from,
                "valid_until": ctx.authorization.valid_until,
                "status": ctx.authorization.status.value,
                "scope_reference": ctx.authorization.scope_reference,
                "restrictions": ctx.authorization.restrictions or [],
            },
            "scope": {
                "scope_reference": ctx.authorization.scope_reference,
                "total_discovered_assets": len(ctx.assets),
                "in_scope_count": len(in_scope_assets),
                "out_of_scope_count": len(ctx.assets) - len(in_scope_assets),
                "assets": [
                    {
                        "asset_id": a.asset_id,
                        "canonical_identifier": a.canonical_identifier,
                        "asset_type": a.asset_type.value if hasattr(a.asset_type, "value") else str(a.asset_type),
                        "scope_status": a.scope_status.value if hasattr(a.scope_status, "value") else str(a.scope_status),
                    }
                    for a in ctx.assets
                ],
            },
            "attack_surface": ctx.attack_surface or {},
            "confirmed_findings": confirmed_findings_list,
            "verified_findings": confirmed_findings_list,
            "unverified_hypotheses": [
                {
                    "hypothesis_id": h.hypothesis_id,
                    "title": h.title,
                    "domain": h.domain,
                    "confidence": h.confidence,
                    "description": h.description,
                    "evidence_gaps": h.evidence_gaps or [],
                    "negative_control": h.negative_control or "",
                    "epistemic_status": "MODEL_HYPOTHESIS_UNVERIFIED",
                }
                for h in unverified_hypotheses
            ],
            "unverified_candidate_findings": unverified_findings_list,
            "quarantined_candidate_findings": unverified_findings_list,
            "limitations": ctx.limitations or [
                "Testing was restricted to non-destructive manual verification.",
                "Denial-of-service and state-destructive testing were strictly prohibited.",
                "All autonomous exploitation was disabled by safety invariants.",
            ],
        }
        return json.dumps(report_data, indent=2, sort_keys=False)

    @classmethod
    def _generate_html_impl(cls, ctx: AssessmentReportContext) -> str:
        """Generates styled, semantic, XSS-safe HTML assessment report."""
        now_iso = datetime.now(timezone.utc).isoformat()
        confirmed_findings = [f for f in ctx.findings if f.verification_status == FindingVerificationStatus.HUMAN_VERIFIED]
        unverified_findings = [f for f in ctx.findings if f.verification_status != FindingVerificationStatus.HUMAN_VERIFIED]
        unverified_hypotheses = [h for h in ctx.hypotheses if h.epistemic_status == "MODEL_HYPOTHESIS"]
        out_of_scope_obs = [o for o in ctx.observations if o.scope_decision != AssessmentScopeStatus.IN_SCOPE]
        in_scope_assets = [a for a in ctx.assets if a.scope_status == AssessmentScopeStatus.IN_SCOPE]

        e = html.escape

        def sev_badge(sev: str) -> str:
            colors = {
                "CRITICAL": "background:#fee2e2;color:#991b1b;border:1px solid #f87171;",
                "HIGH": "background:#ffedd5;color:#9a3412;border:1px solid #fb923c;",
                "MEDIUM": "background:#fef3c7;color:#92400e;border:1px solid #facc15;",
                "LOW": "background:#dbeafe;color:#1e40af;border:1px solid #60a5fa;",
            }
            style = colors.get(sev, "background:#f1f5f9;color:#475569;border:1px solid #cbd5e1;")
            return f'<span style="padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;{style}">{e(sev)}</span>'

        findings_html = []
        if not confirmed_findings:
            findings_html.append('<p><em>No security findings have been human-verified and confirmed for this assessment.</em></p>')
        else:
            for idx, f in enumerate(confirmed_findings, start=1):
                findings_html.append(f"""
                <div class="finding-card">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                        <h3 style="margin:0;font-size:16px;">6.{idx}. {sev_badge(f.severity.value)} {e(f.title)}</h3>
                        <span class="badge badge-human-verified">{e(f.verification_status.value)}</span>
                    </div>
                    <p style="font-size:12px;color:#64748b;margin:0 0 10px 0;">
                        ID: <code>{e(f.finding_id)}</code> &bull; Asset: <strong>{e(f.asset)}</strong> &bull; Component: <strong>{e(f.affected_component)}</strong> &bull; Verified by: <code>{e(f.verified_by or 'HUMAN_REVIEWER')}</code> at <code>{e(f.verified_at or '')}</code>
                    </p>
                    <p><strong>Security Invariant Violated:</strong> <code>{e(f.security_invariant)}</code></p>
                    <p><strong>Description:</strong><br>{e(f.description)}</p>
                    <p><strong>Security Impact:</strong><br>{e(f.impact)}</p>
                    <p><strong>Root Cause Analysis:</strong><br>{e(f.root_cause)}</p>
                    <p><strong>Remediation Guidance:</strong><br>{e(f.remediation)}</p>
                    <p><strong>Supporting Evidence Lineage:</strong> {', '.join(e(ev) for ev in f.evidence)}</p>
                </div>
                """)

        hypotheses_html = []
        if not unverified_hypotheses and not unverified_findings:
            hypotheses_html.append('<p><em>No open unverified hypotheses.</em></p>')
        else:
            for idx, h in enumerate(unverified_hypotheses, start=1):
                gaps = f"<br><strong>Evidence Gaps:</strong> {e('; '.join(h.evidence_gaps))}" if h.evidence_gaps else ""
                neg = f"<br><strong>Negative Control:</strong> {e(h.negative_control)}" if h.negative_control else ""
                hypotheses_html.append(f"""
                <div class="hypothesis-card">
                    <h4 style="margin:0 0 6px 0;font-size:14px;">7.{idx}. [HYPOTHESIS - UNVERIFIED] {e(h.title)}</h4>
                    <p style="font-size:12px;color:#64748b;margin:0 0 6px 0;">ID: <code>{e(h.hypothesis_id)}</code> &bull; Domain: {e(h.domain)} &bull; Confidence: {h.confidence:.2f}</p>
                    <p style="margin:0;">{e(h.description)}{gaps}{neg}</p>
                </div>
                """)

            if unverified_findings:
                hypotheses_html.append('<h4 style="margin-top:16px;">Quarantined Candidate Findings (Not Confirmed)</h4><ul>')
                for uf in unverified_findings:
                    hypotheses_html.append(f"<li>{sev_badge(uf.severity.value)} {e(uf.title)} (<code>{e(uf.finding_id)}</code>) &mdash; Status: {e(uf.verification_status.value)}</li>")
                hypotheses_html.append('</ul>')

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authorized Security Assessment Report: {e(ctx.assessment.assessment_name)}</title>
    <style>
        :root {{
            --bg: #FBFBF9;
            --surface: #FFFFFF;
            --border: #E6E4DF;
            --text-primary: #1F1E1D;
            --text-secondary: #6E6D6A;
            --accent: #2D2C2A;
            --badge-green-bg: #DCFCE7;
            --badge-green-text: #166534;
            --badge-amber-bg: #FEF3C7;
            --badge-amber-text: #92400E;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: var(--bg);
            color: var(--text-primary);
            line-height: 1.6;
            margin: 0;
            padding: 32px;
            max-width: 960px;
            margin-left: auto;
            margin-right: auto;
        }}
        h1, h2, h3, h4 {{ color: var(--text-primary); }}
        .header-box {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 24px; margin-bottom: 24px; }}
        .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; font-size: 13px; margin-top: 12px; }}
        .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; }}
        .badge-human-verified {{ background: var(--badge-green-bg); color: var(--badge-green-text); }}
        .badge-unverified {{ background: var(--badge-amber-bg); color: var(--badge-amber-text); }}
        .finding-card {{ background: var(--surface); border: 2px solid #86efac; border-radius: 8px; padding: 18px; margin-bottom: 16px; }}
        .hypothesis-card {{ background: var(--surface); border: 1px solid var(--border); border-left: 4px solid #f59e0b; border-radius: 6px; padding: 14px; margin-bottom: 12px; font-size: 13px; }}
        .disclaimer-box {{ background: #fffbeb; border: 1px solid #fde68a; border-radius: 6px; padding: 12px 16px; margin: 16px 0; font-size: 13px; color: #92400e; }}
        table {{ width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 13px; }}
        th, td {{ padding: 8px 12px; border: 1px solid var(--border); text-align: left; }}
        th {{ background: #f8fafc; font-weight: 600; }}
        code {{ background: #f1f5f9; padding: 2px 5px; border-radius: 3px; font-family: monospace; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="header-box">
        <h1 style="margin:0 0 8px 0;font-size:22px;">Authorized Security Assessment Report</h1>
        <h2 style="margin:0;font-size:18px;color:var(--text-secondary);font-weight:500;">{e(ctx.assessment.assessment_name)} &bull; {e(ctx.assessment.organization)}</h2>
        <div class="meta-grid">
            <div><strong>Assessment ID:</strong> <code>{e(ctx.assessment.assessment_id)}</code></div>
            <div><strong>Status:</strong> <span class="badge badge-human-verified">{e(ctx.assessment.state.value)}</span></div>
            <div><strong>Date Generated:</strong> <code>{e(now_iso)}</code></div>
            <div><strong>Target Scope:</strong> {len(in_scope_assets)} In-Scope Assets</div>
        </div>
    </div>

    <h2>1. Executive Summary</h2>
    <p>
        This authorized security assessment was conducted for <strong>{e(ctx.assessment.organization)}</strong> covering defined target assets under explicit rules of engagement.
        A total of <strong>{len(ctx.assets)}</strong> assets were inventoried, producing <strong>{len(ctx.observations)}</strong> canonical observations.
        Testing resulted in <strong>{len(confirmed_findings)}</strong> human-verified security findings and <strong>{len(unverified_hypotheses) + len(unverified_findings)}</strong> unverified hypotheses/candidate findings requiring further manual investigation.
    </p>

    <h2>2. Authorization Details</h2>
    <table>
        <tr><th>Authorization ID</th><td><code>{e(ctx.authorization.authorization_id)}</code></td></tr>
        <tr><th>Authorized By</th><td>{e(ctx.authorization.authorized_by)}</td></tr>
        <tr><th>Engagement Type</th><td>{e(ctx.authorization.authorization_type.value)}</td></tr>
        <tr><th>Validity Window</th><td><code>{e(ctx.authorization.valid_from)}</code> to <code>{e(ctx.authorization.valid_until)}</code></td></tr>
        <tr><th>Status</th><td><code>{e(ctx.authorization.status.value)}</code></td></tr>
        <tr><th>Restrictions</th><td>{e(', '.join(ctx.authorization.restrictions) if ctx.authorization.restrictions else 'None')}</td></tr>
    </table>

    <h2>3. Assessment Scope</h2>
    <p><strong>Scope Reference:</strong> <code>{e(ctx.authorization.scope_reference)}</code></p>
    <p><strong>Inventoried Assets:</strong> {len(ctx.assets)} total ({len(in_scope_assets)} in-scope, {len(ctx.assets) - len(in_scope_assets)} out-of-scope)</p>

    <h2>4. Methodology</h2>
    <ol>
        <li><strong>Deterministic Scope &amp; Authorization:</strong> All target interactions fail-closed on unverified targets.</li>
        <li><strong>Passive Telemetry Normalization:</strong> Network traffic and tool exports normalized into canonical observations.</li>
        <li><strong>Attack Surface Mapping:</strong> Comprehensive inventory of endpoints, auth boundaries, and exposed services.</li>
        <li><strong>Hypothesis Formulation &amp; Negative Controls:</strong> Plausible vulnerabilities modeled against formal invariants.</li>
        <li><strong>Safe Manual Experiments:</strong> Protocols executed exclusively by human researchers (zero autonomous exploit actions).</li>
        <li><strong>13-Point Finding Validation:</strong> Deterministic checklist required before finding confirmation.</li>
    </ol>

    <h2>5. Attack Surface Summary</h2>
    <p>Total Nodes: <strong>{ctx.attack_surface.get('total_nodes', 0) if ctx.attack_surface else 0}</strong> &bull; Exposed Services: <strong>{ctx.attack_surface.get('exposed_services_count', 0) if ctx.attack_surface else 0}</strong> &bull; Endpoints Discovered: <strong>{ctx.attack_surface.get('endpoints_count', 0) if ctx.attack_surface else 0}</strong></p>

    <h2>6. Confirmed Findings (Human Verified Only)</h2>
    {''.join(findings_html)}

    <h2>7. Unverified Hypotheses &amp; Open Evidence Gaps</h2>
    <div class="disclaimer-box">
        <strong>Epistemic Notice:</strong> The following items represent plausible technical hypotheses or observed anomalies that have NOT been verified by a human researcher. They MUST NOT be treated as confirmed security findings.
    </div>
    {''.join(hypotheses_html)}

    <h2>8. Out-of-Scope Observations</h2>
    <p>A total of <strong>{len(out_of_scope_obs)}</strong> observations were recorded outside program scope and were strictly quarantined from analysis and findings.</p>

    <h2>9. Testing Limitations &amp; Constraints</h2>
    <ul>
        {''.join(f"<li>{e(lim)}</li>" for lim in (ctx.limitations or ['Testing was restricted to non-destructive manual verification.', 'Denial-of-service and state-destructive testing were strictly prohibited.', 'All autonomous exploitation was disabled by safety invariants.']))}
    </ul>
</body>
</html>"""

