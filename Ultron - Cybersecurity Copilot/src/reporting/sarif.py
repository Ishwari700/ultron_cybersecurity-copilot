"""SARIF v2.1.0 Exporter for Security Assessment Verified Findings.

Enforces:
- Unverified hypotheses MUST NOT appear as confirmed SARIF results (INV-M8-06)
- Only HUMAN_VERIFIED findings are exported into SARIF runs.results
- Standard mapping of severity, rules, locations, and remediation
"""

import json
from typing import Any, Dict, List
from src.reporting.models import AssessmentReportData, FindingReportItem


SEVERITY_LEVEL_MAP = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "none",
}


class SarifReportRenderer:
    """Exports AssessmentReportData into standard OASIS SARIF v2.1.0 JSON."""

    @classmethod
    def render(cls, data: AssessmentReportData) -> Dict[str, Any]:
        rules: List[Dict[str, Any]] = []
        results: List[Dict[str, Any]] = []

        seen_rules = set()

        # ONLY iterate over verified findings
        for f in data.verified_findings:
            rule_id = f"RULE-{f.severity.upper()}-{f.finding_id}"
            if rule_id not in seen_rules:
                seen_rules.add(rule_id)
                rules.append({
                    "id": rule_id,
                    "name": f.title,
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.description},
                    "help": {"text": f"Remediation: {f.remediation}"},
                    "properties": {
                        "category": f.asvs_requirement or "General Security",
                        "precision": "high",
                    },
                })

            result = {
                "ruleId": rule_id,
                "level": SEVERITY_LEVEL_MAP.get(f.severity.upper(), "warning"),
                "message": {"text": f.description},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.asset},
                            "region": {"startLine": 1},
                        },
                        "logicalLocations": [
                            {"name": f.affected_component, "kind": "component"}
                        ],
                    }
                ],
                "properties": {
                    "finding_id": f.finding_id,
                    "epistemic_status": f.epistemic_status,
                    "verified_by": f.verified_by,
                    "verified_at": f.verified_at,
                    "evidence_references": f.evidence,
                    "remediation": f.remediation,
                },
            }
            results.append(result)

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Local-Bug-Bounty-AI",
                            "semanticVersion": "8.0.0",
                            "informationUri": "https://github.com/HyperJay-456/Bug-Bounty-AI",
                            "rules": rules,
                        }
                    },
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": data.generated_at,
                        }
                    ],
                    "results": results,
                }
            ],
        }

    @classmethod
    def render_json(cls, data: AssessmentReportData, indent: int = 2) -> str:
        return json.dumps(cls.render(data), indent=indent)


# Functional alias for specification parity
generate_sarif_report = SarifReportRenderer.render
