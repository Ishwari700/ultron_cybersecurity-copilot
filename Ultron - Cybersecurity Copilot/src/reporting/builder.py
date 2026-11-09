"""Report Data Builder for Canonical Security Assessment Reports.

Enforces:
- Reports must be generated ONLY from deterministic validated data (INV-M8-06)
- Unverified hypotheses are strictly segregated from verified findings
- Attestation hash computation for report integrity (Phase 19)
"""

from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List, Optional

from src.assessment.manager import AssessmentManager
from src.assessment.models import AssessmentFinding, FindingVerificationStatus
from src.reporting.models import (
    AssessmentReportData,
    FindingReportItem,
    ReportAttestation,
)


ASVS_MAP = {
    "BOLA": "V4.1 General Access Control Design",
    "IDOR": "V4.2 Operation Level Access Control",
    "AUTH": "V2 Authentication Verification",
    "SESSION": "V3 Session Management Verification",
    "XSS": "V5.3 Output Encoding and Injection Prevention",
    "SQL": "V5.3 Output Encoding and Injection Prevention",
    "SSRF": "V12.6 Server-Side Request Forgery Prevention",
    "DESERIALIZATION": "V5.5 Deserialization Prevention",
    "TLS": "V9 Communications Verification",
    "SECRET": "V14 Configuration Verification",
    "ANDROID": "V1.14 Mobile Architecture Requirements",
    "BINARY": "V14 Configuration and Compilation",
}


class ReportDataBuilder:
    """Builds canonical AssessmentReportData from an AssessmentManager instance."""

    @classmethod
    def build_report_data(
        cls,
        manager: AssessmentManager,
        assessment_id: str,
        is_draft: bool = False,
        reviewer_id: Optional[str] = None,
    ) -> AssessmentReportData:
        cont = manager.get_container(assessment_id)
        rec = cont.record

        raw_seed = f"{assessment_id}:{rec.assessment_name}:{datetime.now(timezone.utc).isoformat()}"
        report_id = f"REP-{hashlib.sha256(raw_seed.encode()).hexdigest()[:12].upper()}"

        auth_ref = cont.authorization.authorization_id if cont.authorization else "NONE"
        scope_ref = cont.record.scope_policy_id or "NONE"

        # 1. Process ONLY HUMAN_VERIFIED findings as verified
        verified_items: List[FindingReportItem] = []
        for finding_id, f in cont.findings.items():
            if f.verification_status == FindingVerificationStatus.HUMAN_VERIFIED:
                asvs_req = "V4 Access Control"
                for keyword, asvs_val in ASVS_MAP.items():
                    if keyword in f.title.upper() or keyword in f.security_invariant.upper():
                        asvs_req = asvs_val
                        break

                item = FindingReportItem(
                    finding_id=f.finding_id,
                    title=f.title,
                    severity=f.severity.value,
                    asset=f.asset,
                    affected_component=f.affected_component,
                    description=f.description,
                    impact=f.impact,
                    evidence=list(f.evidence),
                    reproduction_steps=f.reproduction_reference,
                    remediation=f.remediation,
                    references=list(f.references),
                    epistemic_status="HUMAN_VERIFIED_FINDING",
                    verified_by=f.verified_by or reviewer_id or "ANONYMOUS_VERIFIER",
                    verified_at=f.verified_at or datetime.now(timezone.utc).isoformat(),
                    evidence_lineage=list(f.evidence),
                    asvs_requirement=asvs_req,
                )
                verified_items.append(item)

        # 2. Collect unverified hypotheses (explicitly segregated)
        unverified_items: List[Dict[str, Any]] = []
        for h in cont.review_workspace.hypotheses.values():
            unverified_items.append({
                "hypothesis_id": h.hypothesis_id,
                "title": h.title,
                "domain": h.domain,
                "epistemic_status": "MODEL_HYPOTHESIS",
                "status": h.status.value,
                "supporting_observations": h.supporting_observations,
                "negative_control": h.negative_control,
            })

        # 3. Assets evaluated
        assets = [a.canonical_identifier for a in cont.asset_graph.get_all_assets()]

        data = AssessmentReportData(
            report_id=report_id,
            assessment_id=assessment_id,
            organization=rec.organization,
            assessment_name=rec.assessment_name,
            authorization_reference=auth_ref,
            scope_reference=scope_ref,
            is_draft=is_draft,
            verified_findings=verified_items,
            unverified_hypotheses=unverified_items,
            assets_evaluated=assets,
            audit_events_count=len(cont.audit_logger.get_events()) if hasattr(cont.audit_logger, "get_events") else 0,
        )

        # 4. Attestation hash
        h = data.compute_deterministic_hash()
        data.attestation = ReportAttestation(
            report_id=report_id,
            assessment_id=assessment_id,
            sha256_hash=h,
            signature_status="UNSIGNED",
        )
        return data


class ReportBuilder:
    """Convenience wrapper supporting both instance and static invocations."""

    def __init__(self, manager: Optional[AssessmentManager] = None):
        self.manager = manager

    def build_report_data(
        self,
        assessment_id: str,
        is_draft: bool = False,
        reviewer_id: Optional[str] = None,
    ) -> AssessmentReportData:
        if not self.manager:
            raise ValueError("AssessmentManager is required.")
        return ReportDataBuilder.build_report_data(
            manager=self.manager,
            assessment_id=assessment_id,
            is_draft=is_draft,
            reviewer_id=reviewer_id,
        )

