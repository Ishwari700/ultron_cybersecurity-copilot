"""Recon Analyst Agent for M7 Attack Surface & Asset Mapping.

Enforces:
1. DISCOVERY != VULNERABILITY: Asset presence does not imply flaw.
2. Identifies exposed services, technologies, endpoints, and inventory gaps.
3. Maps relationships between domains, subdomains, IPs, and services.
4. Generates testable hypotheses with strict required evidence.
"""

from typing import Any, Dict, List
from src.agents.base import BaseAgent
from src.agents.schemas import AgentOutput, AgentTask, AgentType
from src.assessment.models import (
    AssessmentHypothesis,
    EpistemicStatus,
)


class ReconAnalystAgent(BaseAgent):
    """Specialized agent for passive telemetry, asset inventory, and attack surface mapping."""

    def __init__(self, assessment_id: str, agent_id: str = "AGENT-RECON-001") -> None:
        super().__init__(agent_id=agent_id, agent_type=AgentType.RECON, assessment_id=assessment_id)

    def analyze(self, task: AgentTask, context: Dict[str, Any]) -> AgentOutput:
        target = task.target_asset
        observations = context.get("observations", [])
        evidence_ids = [obs.get("observation_id") for obs in observations if isinstance(obs, dict) and "observation_id" in obs]

        discovered_services = []
        exposed_endpoints = []
        technologies = []

        for obs in observations:
            if not isinstance(obs, dict):
                continue
            data = obs.get("normalized_data", {})
            if "service" in data:
                discovered_services.append(f"{data.get('port')}/{data.get('service')}")
            if "url" in data or "path" in data:
                exposed_endpoints.append(data.get("url") or data.get("path"))
            if "tech" in data:
                technologies.append(data.get("tech"))

        hypotheses: List[AssessmentHypothesis] = []
        evidence_gaps: List[str] = []

        # If administrative endpoints are discovered, hypothesize exposure but do NOT declare vulnerable
        admin_matches = [ep for ep in exposed_endpoints if any(a in str(ep).lower() for a in ("/admin", "/dashboard", "/internal", "/actuator"))]
        if admin_matches:
            hyp = AssessmentHypothesis(
                hypothesis_id=f"HYP-RECON-{len(hypotheses)+1:03d}",
                assessment_id=self.assessment_id,
                title=f"Potential Administrative Surface Exposure on {target}",
                description=f"Administrative path {admin_matches[0]} observed in passive telemetry.",
                domain="WEB_APPLICATION",
                supporting_observations=evidence_ids[:3],
                security_invariants=["ACCESS_CONTROL: Administrative endpoints must enforce strong authentication and role authorization."],
                negative_control="Unauthenticated request to admin endpoint must return 401/403 or redirect to login.",
                evidence_gaps=[f"Missing verification of authorization boundary on {admin_matches[0]}."],
            )
            hypotheses.append(hyp)
        else:
            evidence_gaps.append(f"Incomplete endpoint inventory for {target}: passive telemetry lacks authenticated paths.")

        summary = (
            f"Recon analysis for {target}: Discovered {len(discovered_services)} services, "
            f"{len(exposed_endpoints)} endpoints, {len(technologies)} technologies. "
            f"Discovery does not imply vulnerability."
        )

        return AgentOutput(
            agent_id=self.agent_id,
            agent_type=self.agent_type,
            assessment_id=self.assessment_id,
            task_id=task.task_id,
            confidence=0.85,
            epistemic_status=EpistemicStatus.MODEL_HYPOTHESIS,
            hypotheses=hypotheses,
            evidence_gaps=evidence_gaps,
            security_invariants=["INV-RECON-01: DISCOVERY != VULNERABILITY (Asset existence does not prove exploitability)."],
            supporting_evidence=evidence_ids,
            analysis_summary=summary,
        )
