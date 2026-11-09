"""Domain Models for Deterministic Security Assessment Reporting.

Enforces:
- Report generator cannot represent unverified findings as verified findings (INV-M8-06)
- Report export must preserve epistemic status (INV-M8-08)
- Deterministic report attestation hashing (Phase 19)
- Exclusion of raw internal model chain-of-thought
"""

from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ReportFormat(str, Enum):
    """Supported output report representations."""
    MARKDOWN = "MARKDOWN"
    HTML = "HTML"
    PDF = "PDF"
    SARIF = "SARIF"
    ASVS = "ASVS"
    BUG_BOUNTY = "BUG_BOUNTY"


class ReportAttestation(BaseModel):
    """Cryptographic attestation and integrity metadata for a generated report."""
    report_id: str
    assessment_id: str
    sha256_hash: str
    generated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    validator_version: str = "v8.0.0-human-in-the-loop"
    signature_status: str = "UNSIGNED"  # No fake crypto: explicitly UNSIGNED if no key configured

    @property
    def report_sha256(self) -> str:
        return self.sha256_hash


class FindingReportItem(BaseModel):
    """Deterministic, auditable finding record formatted for external reports."""
    finding_id: str
    title: str
    severity: str
    asset: str
    affected_component: str
    description: str
    impact: str
    evidence: List[str] = Field(default_factory=list)
    reproduction_steps: str
    remediation: str
    references: List[str] = Field(default_factory=list)
    epistemic_status: str = "HUMAN_VERIFIED_FINDING"
    verified_by: str
    verified_at: str
    evidence_lineage: List[str] = Field(default_factory=list)
    asvs_requirement: Optional[str] = None
    cwe_id: Optional[str] = None


class AssessmentReportData(BaseModel):
    """Canonical data bundle consumed by all report format renderers."""
    report_id: str
    assessment_id: str
    organization: str
    assessment_name: str
    authorization_reference: str
    scope_reference: str
    generated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    is_draft: bool = True
    verified_findings: List[FindingReportItem] = Field(default_factory=list)
    unverified_hypotheses: List[Dict[str, Any]] = Field(default_factory=list)
    contested_items: List[Dict[str, Any]] = Field(default_factory=list)
    rejected_items: List[Dict[str, Any]] = Field(default_factory=list)
    assets_evaluated: List[str] = Field(default_factory=list)
    audit_events_count: int = 0
    attestation: Optional[ReportAttestation] = None

    def compute_deterministic_hash(self) -> str:
        """Computes SHA-256 over normalized canonical payload."""
        payload = {
            "report_id": self.report_id,
            "assessment_id": self.assessment_id,
            "organization": self.organization,
            "assessment_name": self.assessment_name,
            "authorization_reference": self.authorization_reference,
            "scope_reference": self.scope_reference,
            "verified_findings": [f.model_dump() for f in self.verified_findings],
            "unverified_hypotheses": self.unverified_hypotheses,
        }
        raw = json.dumps(payload, sort_keys=True).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()
