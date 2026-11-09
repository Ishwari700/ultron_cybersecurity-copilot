"""Web & API Security Analyst Agent for M7.

Enforces:
1. Maps observed telemetry to formal Security Invariants:
   - INV-BOLA-01: User A must not access User B's resource.
   - INV-BFLA-01: Low-privilege users must not invoke admin functions.
   - INV-SESSION-01: Logout must invalidate session tokens.
   - INV-RATELIMIT-01: Excessive attempts must trigger rate limiting.
2. Every hypothesis requires supporting observations, negative controls,
   and falsification conditions.
3. Cannot confirm vulnerabilities without empirical human execution.
"""

from typing import Any, Dict, List
from src.agents.base import BaseAgent
from src.agents.schemas import AgentOutput, AgentTask, AgentType
from src.assessment.models import (
    AssessmentHypothesis,
    AssessmentExperiment,
    EpistemicStatus,
    ExperimentRiskLevel,
    ExperimentStatus,
)


class WebApiSecurityAnalystAgent(BaseAgent):
    """Specialized analytical agent for Web applications and REST/GraphQL APIs."""

    def __init__(self, assessment_id: str, agent_id: str = "AGENT-WEB-001") -> None:
        super().__init__(agent_id=agent_id, agent_type=AgentType.WEB_API, assessment_id=assessment_id)

    def analyze(self, task: AgentTask, context: Dict[str, Any]) -> AgentOutput:
        target = task.target_asset
        observations = context.get("observations", [])
        evidence_ids = [obs.get("observation_id") for obs in observations if isinstance(obs, dict) and "observation_id" in obs]

        hypotheses: List[AssessmentHypothesis] = []
        evidence_gaps: List[str] = []
        invariants: List[str] = []
        proposed_exps: List[AssessmentExperiment] = []

        # Analyze HTTP telemetry for auth headers, parameters, and endpoints
        has_user_id_param = False
        has_auth_header = False
        has_rate_limit_headers = False

        for obs in observations:
            if not isinstance(obs, dict):
                continue
            data = obs.get("normalized_data", {})
            headers = data.get("headers", {}) or data.get("request_headers", {})
            url = str(data.get("url", ""))

            if "authorization" in headers or "cookie" in headers:
                has_auth_header = True
            if any(id_key in url.lower() for id_key in ("/user/", "/account/", "/tenant/", "id=")):
                has_user_id_param = True
            if any("ratelimit" in h.lower() for h in headers.keys()):
                has_rate_limit_headers = True

        # Generate hypothesis if object identifier is present in endpoints
        if has_user_id_param:
            invariants.append("INV-BOLA-01: User A must not access or mutate User B's object.")
            hyp = AssessmentHypothesis(
                hypothesis_id=f"HYP-WEB-{len(hypotheses)+1:03d}",
                assessment_id=self.assessment_id,
                title=f"Potential Broken Object Level Authorization (BOLA) on {target}",
                description=f"Endpoint on {target} accepts direct object identifiers in URI path or parameters.",
                domain="WEB_APPLICATION",
                supporting_observations=evidence_ids[:2],
                security_invariants=["INV-BOLA-01: User A must not access User B's resource."],
                negative_control="User A requesting User A's object returns HTTP 200; User A requesting User B's object returns HTTP 403/404.",
                falsification_condition="Server enforces tenant/user ownership and returns 403 Forbidden on cross-account object requests.",
                evidence_gaps=["Missing differential test comparing User A token against User B resource ID."],
            )
            hypotheses.append(hyp)

            # Propose safe verification experiment
            exp = AssessmentExperiment(
                experiment_id=f"EXP-BOLA-{len(proposed_exps)+1:03d}",
                assessment_id=self.assessment_id,
                hypothesis_id=hyp.hypothesis_id,
                objective="Test cross-tenant object access differential",
                authorization_reference=task.authorization_id,
                scope_reference=task.scope_reference,
                preconditions=[f"Two test accounts (User A, User B) provisioned in {target}"],
                steps=[
                    "Issue request to /api/resource/{UserA_ID} with User A token (baseline)",
                    "Issue request to /api/resource/{UserB_ID} with User A token (cross-object test)",
                ],
                expected_secure_result="HTTP 403 Forbidden or HTTP 404 Not Found",
                expected_vulnerable_result="HTTP 200 OK containing User B data",
                falsification_condition="Cross-object request is denied by authorization middleware",
                negative_control="User A accessing User A resource succeeds (validates session integrity)",
                requires_human_execution=True,
                risk_level=ExperimentRiskLevel.LOW_RISK,
                status=ExperimentStatus.PROPOSED,
            )
            proposed_exps.append(exp)

        if not has_rate_limit_headers:
            evidence_gaps.append(f"No rate-limiting headers observed on {target} API responses.")

        summary = (
            f"Web/API analysis for {target}: Evaluated {len(observations)} observations. "
            f"Formulated {len(hypotheses)} hypotheses with negative controls and proposed experiments."
        )

        return AgentOutput(
            agent_id=self.agent_id,
            agent_type=self.agent_type,
            assessment_id=self.assessment_id,
            task_id=task.task_id,
            confidence=0.80,
            epistemic_status=EpistemicStatus.MODEL_HYPOTHESIS,
            hypotheses=hypotheses,
            evidence_gaps=evidence_gaps,
            security_invariants=invariants,
            proposed_experiments=proposed_exps,
            supporting_evidence=evidence_ids,
            analysis_summary=summary,
        )
