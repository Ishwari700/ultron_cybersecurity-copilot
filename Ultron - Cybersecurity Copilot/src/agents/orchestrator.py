"""Multi-Agent Orchestrator for M7 Security Research Platform.

Enforces:
1. Coordinates specialized analytical reasoning across domain agents.
2. Manages Directed Acyclic Graph (DAG) task execution with depth bounding (max depth 5).
3. Resource & budget tracking: max agents, max calls, token budgets.
4. Fault tolerance: Records AGENT_FAILURE if an agent crashes; never crashes assessment;
   flags EVIDENCE_REVIEW_INCOMPLETE if critical analysis fails.
5. Multi-agent pipeline:
   Target Telemetry -> Domain Agents -> Evidence Analyst -> Falsification Analyst -> Consensus Engine -> Human Review Package.
6. HARD INVARIANTS:
   - Orchestrator CANNOT authorize targets.
   - Orchestrator CANNOT modify or expand scope.
   - Orchestrator CANNOT execute target actions.
   - Orchestrator CANNOT confirm findings or promote hypotheses to facts.
"""

from datetime import datetime, timezone
import traceback
from typing import Any, Dict, List, Optional, Set, Tuple

from src.agents.base import BaseAgent
from src.agents.budgets import AgentBudgetConfig, AgentBudgetTracker, AgentBudgetExceededError
from src.agents.consensus import MultiAgentConsensusEngine
from src.agents.evidence import EvidenceAnalystAgent
from src.agents.falsification import FalsificationAnalystAgent
from src.agents.reporting import ReportingAnalystAgent
from src.agents.schemas import (
    AgentOutput,
    AgentTask,
    AgentType,
    ConsensusResult,
    ConsensusStatus,
)
from src.assessment.models import AssessmentHypothesis, EpistemicStatus


class OrchestratorSecurityError(Exception):
    """Raised when an illegal operation (e.g. attempting to authorize target or bypass scope) occurs."""
    pass


class AgentOrchestrator:
    """Coordinates analytical reasoning across specialized security agents."""

    def __init__(
        self,
        assessment_id: str,
        budget_config: Optional[AgentBudgetConfig] = None,
    ) -> None:
        self.assessment_id = assessment_id
        self.budget_tracker = AgentBudgetTracker(assessment_id, budget_config)
        self.consensus_engine = MultiAgentConsensusEngine(assessment_id)
        self.agent_registry: Dict[AgentType, BaseAgent] = {}
        self.execution_failures: List[Dict[str, Any]] = []

    def register_agent(self, agent: BaseAgent) -> None:
        """Registers a domain agent instance with the orchestrator."""
        if agent.assessment_id != self.assessment_id:
            raise OrchestratorSecurityError(
                f"Agent {agent.agent_id} bound to assessment '{agent.assessment_id}', "
                f"cannot register with orchestrator for '{self.assessment_id}'."
            )
        self.agent_registry[agent.agent_type] = agent

    def run_assessment_pipeline(
        self,
        target_asset: str,
        authorization_id: str,
        scope_reference: str,
        domain_agent_types: List[AgentType],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Executes a staged DAG analytical workflow:
        Stage 1: Domain Analysis (e.g. Recon, Web, Code, Network, Mobile, Binary)
        Stage 2: Evidence Quality Audit (EvidenceAnalyst)
        Stage 3: Adversarial Falsification (FalsificationAnalyst)
        Stage 4: Evidence-Weighted Consensus
        Stage 5: Reporting Synthesis & Human Review Packaging
        """
        # Ensure default evidence & falsification & reporting agents exist
        if AgentType.EVIDENCE not in self.agent_registry:
            self.register_agent(EvidenceAnalystAgent(self.assessment_id))
        if AgentType.FALSIFICATION not in self.agent_registry:
            self.register_agent(FalsificationAnalystAgent(self.assessment_id))
        if AgentType.REPORTING not in self.agent_registry:
            self.register_agent(ReportingAnalystAgent(self.assessment_id))

        all_outputs: List[AgentOutput] = []
        all_hypotheses: List[AssessmentHypothesis] = []
        stage_records: List[Dict[str, Any]] = []

        # Stage 1: Execute Domain Agents
        for agent_type in domain_agent_types:
            agent = self.agent_registry.get(agent_type)
            if not agent:
                continue

            task = AgentTask(
                task_id=f"TASK-STAGE1-{agent_type.value}",
                agent_type=agent_type,
                assessment_id=self.assessment_id,
                objective=f"Analyze {agent_type.value} security surface on {target_asset}",
                target_asset=target_asset,
                authorization_id=authorization_id,
                scope_reference=scope_reference,
                depth=1,
            )

            out = self._safe_execute_agent(agent, task, context)
            if out:
                all_outputs.append(out)
                all_hypotheses.extend(out.hypotheses)
                stage_records.append({
                    "stage": 1,
                    "agent": agent.agent_id,
                    "type": agent_type.value,
                    "hypotheses_generated": len(out.hypotheses),
                })

        # Stage 2: Evidence Analyst Review
        evidence_agent = self.agent_registry[AgentType.EVIDENCE]
        evidence_task = AgentTask(
            task_id="TASK-STAGE2-EVIDENCE",
            agent_type=AgentType.EVIDENCE,
            assessment_id=self.assessment_id,
            objective="Audit evidence sufficiency and provenance across generated hypotheses",
            target_asset=target_asset,
            authorization_id=authorization_id,
            scope_reference=scope_reference,
            depth=2,
        )
        evidence_context = {
            "hypotheses": [h.model_dump() for h in all_hypotheses],
            "observations": context.get("observations", []),
        }
        evidence_out = self._safe_execute_agent(evidence_agent, evidence_task, evidence_context)
        if evidence_out:
            all_outputs.append(evidence_out)
            stage_records.append({
                "stage": 2,
                "agent": evidence_agent.agent_id,
                "type": AgentType.EVIDENCE.value,
                "verdict": evidence_out.provenance.get("sufficiency_verdict", "UNKNOWN"),
            })

        # Stage 3: Adversarial Falsification Analysis
        # Note: Provide hypotheses and observations, but isolate from Stage 1 reasoning to avoid confirmation bias
        falsification_agent = self.agent_registry[AgentType.FALSIFICATION]
        falsify_task = AgentTask(
            task_id="TASK-STAGE3-FALSIFICATION",
            agent_type=AgentType.FALSIFICATION,
            assessment_id=self.assessment_id,
            objective="Attempt to disprove candidate hypotheses with alternative explanations and negative controls",
            target_asset=target_asset,
            authorization_id=authorization_id,
            scope_reference=scope_reference,
            depth=3,
        )
        falsify_context = {
            "hypotheses": [h.model_dump() for h in all_hypotheses],
            "observations": context.get("observations", []),
            # Isolated: No Stage 1 agent chain-of-thought passed
        }
        falsify_out = self._safe_execute_agent(falsification_agent, falsify_task, falsify_context)
        if falsify_out:
            all_outputs.append(falsify_out)
            stage_records.append({
                "stage": 3,
                "agent": falsification_agent.agent_id,
                "type": AgentType.FALSIFICATION.value,
                "proposed_experiments": len(falsify_out.proposed_experiments),
            })

        # Stage 4: Multi-Agent Consensus Evaluation
        consensus_results: List[ConsensusResult] = []
        observations_raw = context.get("observations", [])
        for hyp in all_hypotheses:
            res = self.consensus_engine.evaluate_hypothesis_consensus(
                hypothesis=hyp,
                agent_outputs=all_outputs,
                canonical_observations=observations_raw,
            )
            consensus_results.append(res)

        # Stage 5: Reporting Synthesis & Packaging
        reporting_agent = self.agent_registry[AgentType.REPORTING]
        report_task = AgentTask(
            task_id="TASK-STAGE5-REPORTING",
            agent_type=AgentType.REPORTING,
            assessment_id=self.assessment_id,
            objective="Synthesize multi-agent analytical summary for human review",
            target_asset=target_asset,
            authorization_id=authorization_id,
            scope_reference=scope_reference,
            depth=4,
        )
        report_context = {
            "hypotheses": [h.model_dump() for h in all_hypotheses],
            "agent_outputs": [o.model_dump() for o in all_outputs],
            "consensus_results": [c.model_dump() for c in consensus_results],
        }
        report_out = self._safe_execute_agent(reporting_agent, report_task, report_context)
        if report_out:
            all_outputs.append(report_out)

        # Packaging for Human Review
        review_incomplete = any(
            f.get("agent_type") in (AgentType.EVIDENCE.value, AgentType.FALSIFICATION.value)
            for f in self.execution_failures
        )

        return {
            "assessment_id": self.assessment_id,
            "target_asset": target_asset,
            "stage_records": stage_records,
            "total_hypotheses": len(all_hypotheses),
            "hypotheses": [h.model_dump() for h in all_hypotheses],
            "consensus_results": [c.model_dump() for c in consensus_results],
            "agent_outputs": [o.model_dump() for o in all_outputs],
            "failures": self.execution_failures,
            "status": "EVIDENCE_REVIEW_INCOMPLETE" if review_incomplete else "ANALYSIS_COMPLETE_PENDING_HUMAN_REVIEW",
            "budget_usage": {
                "calls": self.budget_tracker.agent_calls,
                "active_agents": len(self.budget_tracker.active_agents),
                "token_count": self.budget_tracker.token_count,
            },
        }

    def _safe_execute_agent(
        self,
        agent: BaseAgent,
        task: AgentTask,
        context: Dict[str, Any],
    ) -> Optional[AgentOutput]:
        """Executes an agent with strict budget bounding and failure resilience."""
        try:
            # Budget check
            self.budget_tracker.record_agent_call(
                agent_id=agent.agent_id,
                depth=task.depth,
                estimated_tokens=len(str(context)) // 4 + 100,
            )

            # Execution
            output = agent.run(task, context)
            return output

        except AgentBudgetExceededError as e:
            self.execution_failures.append({
                "agent_id": agent.agent_id,
                "agent_type": agent.agent_type.value,
                "error": f"BUDGET_EXCEEDED: {str(e)}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "assessment_id": self.assessment_id,
                "input_reference": task.task_id,
            })
            return None

        except Exception as e:
            # Agent failure handling (Section 30):
            # Record failure without crashing the whole assessment
            self.execution_failures.append({
                "agent_id": agent.agent_id,
                "agent_type": agent.agent_type.value,
                "error": f"AGENT_FAILURE: {str(e)}",
                "stack_trace": traceback.format_exc(),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "assessment_id": self.assessment_id,
                "input_reference": task.task_id,
            })
            return None
