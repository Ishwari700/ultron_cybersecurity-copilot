"""Adversarial Falsification Analyst Agent for M7.

Enforces:
1. Independent adversarial reasoning: Actively attempts to DISPROVE candidate hypotheses.
2. Formulates:
   - Alternative explanations (benign behavior, intentional design, caching, mock data)
   - Negative controls (differential baselines)
   - Contradictory scenarios and false-positive root causes
   - Required differential tests
3. Context Independence: Receives candidate hypotheses and raw evidence, but is isolated
   from the originating agent's subjective chain-of-thought to prevent confirmation bias.
4. INVARIANT: Epistemic status remains MODEL_HYPOTHESIS / INFERENCE.
"""

from typing import Any, Dict, List, Optional
from src.agents.base import BaseAgent
from src.agents.schemas import AgentOutput, AgentTask, AgentType
from src.assessment.models import (
    AssessmentExperiment,
    AssessmentHypothesis,
    EpistemicStatus,
    ExperimentRiskLevel,
    ExperimentStatus,
)


class FalsificationAnalystAgent(BaseAgent):
    """Specialized adversarial reasoning agent dedicated to disproving security claims."""

    def __init__(self, assessment_id: str, agent_id: str = "AGENT-FALSIFY-001") -> None:
        super().__init__(agent_id=agent_id, agent_type=AgentType.FALSIFICATION, assessment_id=assessment_id)

    def analyze(self, task: AgentTask, context: Dict[str, Any]) -> AgentOutput:
        target = task.target_asset
        hypotheses_in: List[Dict[str, Any]] = context.get("hypotheses", [])
        observations: List[Dict[str, Any]] = context.get("observations", [])

        falsification_plans: List[Dict[str, Any]] = []
        proposed_exps: List[AssessmentExperiment] = []
        contradictions: List[str] = []
        evidence_gaps: List[str] = []
        alternative_explanations: List[str] = []

        for hyp in hypotheses_in:
            hyp_id = hyp.get("hypothesis_id", "UNKNOWN")
            title = hyp.get("title", "")
            domain = str(hyp.get("domain", "")).upper()
            title_lower = title.lower()

            # 1. Generate Domain-Specific Alternative Explanations & Negative Controls
            alt_expl = []
            falsify_condition = ""
            neg_control = ""
            diff_test = ""

            if "bola" in title_lower or "idor" in title_lower or "authorization" in title_lower:
                alt_expl.append("Resource identifier may be public/shared data intended for multi-tenant read access.")
                alt_expl.append("Server response could be a generic 200 OK with empty body or standard public metadata.")
                neg_control = (
                    "Baseline request with User A session requesting User A object returns valid private data. "
                    "Request with unauthenticated session returns HTTP 401/403."
                )
                falsify_condition = (
                    "User A request to User B resource returns HTTP 403 Forbidden, 404 Not Found, "
                    "or empty sanitized dataset matching public profile permissions."
                )
                diff_test = "Execute identical requests with User A, User B, and Unauthenticated; compare status codes and payload diff."

            elif "bfla" in title_lower or "privilege" in title_lower:
                alt_expl.append("Endpoint routes to user-scoped interface with similar naming conventions (e.g. /admin/help vs /admin/users).")
                alt_expl.append("Operation returns 200 OK but performs a no-op due to background RBAC check.")
                neg_control = "Admin user executes action -> changes persist. Standard user executes action -> changes are rejected or audited."
                falsify_condition = "Backend controller checks user role claims before execution and halts with permission denied."
                diff_test = "Attempt operation as Low-Privilege user and inspect target state to verify no state change occurred."

            elif "sql" in title_lower or "injection" in title_lower:
                alt_expl.append("Error message is a generic application exception or custom error page rather than a database syntax fault.")
                alt_expl.append("Input reflection occurs in static HTML template rather than SQL interpreter.")
                neg_control = "Safe benign character input returns standard page without database exceptions."
                falsify_condition = "Parameterized query execution ensures input is strictly treated as data literal."
                diff_test = "Submit boolean-true vs boolean-false assertions or sleep-based differential timing tests."

            elif "secret" in title_lower or "credential" in title_lower:
                alt_expl.append("Identified string is a public client ID, sample test placeholder, or rotated dummy credential.")
                alt_expl.append("Credential key is scoped strictly to read-only public resources (e.g. Google Maps API public key).")
                neg_control = "Verify if key grants privileged administrative or private data access vs public metadata access."
                falsify_condition = "Attempting privileged API calls with the token fails authentication or returns scope limitation."
                diff_test = "Query token self-inspection or userinfo endpoint in isolated sandbox."

            elif "exported" in title_lower or "component" in title_lower or "intent" in title_lower:
                alt_expl.append("Component declares signature-level or custom permission requirement not captured in initial check.")
                alt_expl.append("Component is an internal broadcast receiver or activity with no sensitive business logic.")
                neg_control = "Invoking intent without expected extra parameters throws safe SecurityException or graceful finish."
                falsify_condition = "Component strictly enforces caller UID or permission before processing payload."
                diff_test = "Launch component via unprivileged third-party test app without custom permissions."

            else:
                alt_expl.append("Observed symptom is standard RFC-compliant behavior or framework default.")
                alt_expl.append("Observed response is generated by an intermediate WAF or reverse proxy rather than the target application.")
                neg_control = "Test identical request against known safe baseline endpoint."
                falsify_condition = "Application applies uniform input sanitization or authorization across all handlers."
                diff_test = "Execute differential request with benign variation and measure response variance."

            alternative_explanations.extend(alt_expl)
            evidence_gaps.append(f"Hypothesis {hyp_id} lacks empirical negative control test: {neg_control}")

            plan = {
                "hypothesis_id": hyp_id,
                "title": title,
                "alternative_explanations": alt_expl,
                "negative_control": neg_control,
                "falsification_condition": falsify_condition,
                "required_differential_test": diff_test,
            }
            falsification_plans.append(plan)
            contradictions.append(f"Adversarial counter-claim for {hyp_id}: {alt_expl[0]}")

            # Formulate safe differential falsification experiment
            exp = AssessmentExperiment(
                experiment_id=f"EXP-FALSIFY-{len(proposed_exps)+1:03d}",
                assessment_id=self.assessment_id,
                hypothesis_id=hyp_id,
                objective=f"Adversarially falsify: {title}",
                authorization_reference=task.authorization_id,
                scope_reference=task.scope_reference,
                preconditions=[f"Baseline access established on {target}"],
                steps=[
                    f"Step 1: Execute Negative Control: {neg_control}",
                    f"Step 2: Differential Test: {diff_test}",
                ],
                expected_secure_result=falsify_condition,
                expected_vulnerable_result=f"Hypothesis confirmed: {title}",
                falsification_condition=falsify_condition,
                negative_control=neg_control,
                requires_human_execution=True,
                risk_level=ExperimentRiskLevel.LOW_RISK,
                status=ExperimentStatus.PROPOSED,
            )
            proposed_exps.append(exp)

        summary = (
            f"Falsification Analysis for {target}: Evaluated {len(hypotheses_in)} candidate hypotheses. "
            f"Formulated {len(alternative_explanations)} alternative benign explanations and {len(proposed_exps)} "
            f"negative-control falsification experiments."
        )

        return AgentOutput(
            agent_id=self.agent_id,
            agent_type=self.agent_type,
            assessment_id=self.assessment_id,
            task_id=task.task_id,
            confidence=0.85,
            epistemic_status=EpistemicStatus.MODEL_HYPOTHESIS,
            hypotheses=[],
            evidence_gaps=evidence_gaps,
            security_invariants=["INV-FALSIFICATION-01: A hypothesis is unverified until rigorous negative controls fail to disprove it."],
            proposed_experiments=proposed_exps,
            supporting_evidence=[],
            contradicting_evidence=contradictions,
            analysis_summary=summary,
            provenance={
                "falsification_plans": falsification_plans,
                "alternative_explanations": alternative_explanations,
            },
        )
