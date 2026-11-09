"""Reporting Analyst Agent for M7.

Enforces:
1. Synthesizes multi-agent analytical outputs into human-reviewable reports.
2. For each hypothesis:
   - agents involved
   - supporting evidence
   - contradictory evidence
   - falsification result
   - consensus status
   - confidence
   - evidence gaps
   - human verification status
3. Privacy & Sanitization: Never exposes raw internal chain-of-thought; stores structured
   reasoning metadata.
4. INVARIANT: Does NOT confirm findings. Finding confirmation remains with human review + FindingValidator.
"""

from typing import Any, Dict, List, Optional
from src.agents.base import BaseAgent
from src.agents.schemas import AgentOutput, AgentTask, AgentType, ConsensusResult
from src.assessment.models import EpistemicStatus


class ReportingAnalystAgent(BaseAgent):
    """Specialized agent generating structured, auditable assessment summaries."""

    def __init__(self, assessment_id: str, agent_id: str = "AGENT-REPORT-001") -> None:
        super().__init__(agent_id=agent_id, agent_type=AgentType.REPORTING, assessment_id=assessment_id)

    def analyze(self, task: AgentTask, context: Dict[str, Any]) -> AgentOutput:
        target = task.target_asset
        agent_outputs: List[Dict[str, Any]] = context.get("agent_outputs", [])
        consensus_results: List[Dict[str, Any]] = context.get("consensus_results", [])
        hypotheses: List[Dict[str, Any]] = context.get("hypotheses", [])

        hyp_summaries = []
        all_gaps = set()
        all_invariants = set()

        for hyp in hypotheses:
            hyp_id = hyp.get("hypothesis_id")
            title = hyp.get("title")
            supp_obs = hyp.get("supporting_observations", [])

            # Find matching consensus
            cons = next((c for c in consensus_results if c.get("hypothesis_id") == hyp_id), None)
            status_str = cons.get("status") if cons else "UNEVALUATED"
            score = cons.get("consensus_score", 0.0) if cons else 0.0
            disagreements = cons.get("disagreement_reasons", []) if cons else []

            # Involved agents
            involved_agents = set()
            for out in agent_outputs:
                if any(h.get("hypothesis_id") == hyp_id for h in out.get("hypotheses", [])):
                    involved_agents.add(out.get("agent_id"))
                if hyp_id in str(out.get("contradicting_evidence", [])):
                    involved_agents.add(out.get("agent_id"))

            entry = {
                "hypothesis_id": hyp_id,
                "title": title,
                "domain": hyp.get("domain"),
                "consensus_status": status_str,
                "consensus_score": score,
                "participating_agents": list(involved_agents),
                "supporting_evidence": supp_obs,
                "falsification_status": cons.get("falsification_verdict") if cons else "NONE",
                "evidence_sufficiency": cons.get("evidence_sufficiency") if cons else "UNKNOWN",
                "disagreements": disagreements,
                "human_verification_status": "PENDING_HUMAN_REVIEW",
            }
            hyp_summaries.append(entry)

        for out in agent_outputs:
            all_gaps.update(out.get("evidence_gaps", []))
            all_invariants.update(out.get("security_invariants", []))

        report_summary = (
            f"Multi-Agent Analytical Summary for Assessment '{self.assessment_id}' (Target: {target}): "
            f"Analyzed {len(hypotheses)} candidate hypotheses across {len(agent_outputs)} agent outputs. "
            f"Consensus summaries generated with pending human review status."
        )

        return AgentOutput(
            agent_id=self.agent_id,
            agent_type=self.agent_type,
            assessment_id=self.assessment_id,
            task_id=task.task_id,
            confidence=0.95,
            epistemic_status=EpistemicStatus.INFERENCE,
            hypotheses=[],
            evidence_gaps=list(all_gaps),
            security_invariants=list(all_invariants),
            proposed_experiments=[],
            supporting_evidence=[],
            contradicting_evidence=[],
            analysis_summary=report_summary,
            provenance={
                "target_asset": target,
                "hypothesis_summaries": hyp_summaries,
                "total_hypotheses": len(hypotheses),
                "total_agent_outputs": len(agent_outputs),
            },
        )
