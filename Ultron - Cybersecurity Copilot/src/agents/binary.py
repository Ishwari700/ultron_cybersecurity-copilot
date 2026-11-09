"""Binary & Reverse Engineering Analyst Agent for M7.

Enforces:
1. Adapts imported decompiled outputs from Ghidra, JADX, and radare2.
2. Models functions, call graphs, dangerous sinks, and inter-procedural reachability.
3. INVARIANT: Decompiler warning != Confirmed vulnerability.
4. Generates structured hypotheses with explicit evidence gaps and test plans.
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
from src.binary.artifacts import BinaryArtifact, CallRelationship
from src.binary.functions import FunctionAnalyzer
from src.binary.relationships import CallGraphAnalyzer


class BinaryReverseEngineeringAgent(BaseAgent):
    """Specialized analytical agent for binary disassemblies, decompilations, and native code."""

    def __init__(self, assessment_id: str, agent_id: str = "AGENT-BIN-001") -> None:
        super().__init__(agent_id=agent_id, agent_type=AgentType.BINARY, assessment_id=assessment_id)

    def analyze(self, task: AgentTask, context: Dict[str, Any]) -> AgentOutput:
        binary_name = task.target_asset
        functions_data = list(context.get("functions", []))
        call_graph_data = list(context.get("call_graph", []))
        observations = context.get("observations", [])
        evidence_ids = [obs.get("observation_id") for obs in observations if isinstance(obs, dict) and "observation_id" in obs]

        for obs in observations:
            if isinstance(obs, dict):
                nd = obs.get("normalized_data", {})
                if "functions" in nd and not functions_data:
                    functions_data.extend(nd.get("functions", []))
                if "call_graph" in nd and not call_graph_data:
                    call_graph_data.extend(nd.get("call_graph", []))

        hypotheses: List[AssessmentHypothesis] = []
        evidence_gaps: List[str] = []
        proposed_exps: List[AssessmentExperiment] = []

        # Parse functions and sinks
        func_artifacts, sinks = FunctionAnalyzer.analyze_functions(functions_data)

        # Build CallGraphAnalyzer
        rels = [CallRelationship(caller=r.get("caller", ""), callee=r.get("callee", "")) for r in call_graph_data]
        cg = CallGraphAnalyzer(rels)

        # Trace reachability from exported functions to dangerous sinks
        for sink in sinks:
            reachable = False
            reaching_export = None
            for func in func_artifacts:
                if func.is_exported:
                    is_reach, path = cg.is_reachable(func.name, sink.function_name)
                    if is_reach:
                        reachable = True
                        reaching_export = func.name
                        break

            hyp = AssessmentHypothesis(
                hypothesis_id=f"HYP-BIN-{len(hypotheses)+1:03d}",
                assessment_id=self.assessment_id,
                title=f"Potential {sink.sink_type} in {binary_name} ({sink.function_name})",
                description=f"Dangerous sink '{sink.instruction_or_call}' identified in decompiled binary.",
                domain="VULNERABILITY_RESEARCH",
                supporting_observations=evidence_ids[:1],
                security_invariants=["MEMORY_SAFETY: Native functions must enforce bounds and memory safety."],
                negative_control="Input within length limits executes safely without crashing process.",
                falsification_condition="Compiler stack canaries, ASLR, or parameter bound checks prevent exploitation.",
                evidence_gaps=[
                    f"Missing dynamic proof of tainted user input control reaching {sink.function_name}."
                    + (f" Path from export {reaching_export} must be tested." if reachable else " No reachability path found.")
                ],
            )
            hypotheses.append(hyp)

            exp = AssessmentExperiment(
                experiment_id=f"EXP-BIN-{len(proposed_exps)+1:03d}",
                assessment_id=self.assessment_id,
                hypothesis_id=hyp.hypothesis_id,
                objective=f"Test input handling on {sink.function_name}",
                authorization_reference=task.authorization_id,
                scope_reference=task.scope_reference,
                steps=[f"Run canary probe input through {reaching_export or sink.function_name}"],
                expected_secure_result="Graceful input rejection without crash",
                expected_vulnerable_result="Memory fault or abnormal termination",
                falsification_condition="Input validated before sink execution",
                negative_control="Benign input processes without crash",
                requires_human_execution=True,
                risk_level=ExperimentRiskLevel.LOW_RISK,
                status=ExperimentStatus.PROPOSED,
            )
            proposed_exps.append(exp)

        summary = (
            f"Binary analysis for {binary_name}: Inspected {len(func_artifacts)} functions and {len(sinks)} dangerous sinks. "
            f"Decompiler warning != exploitability."
        )

        return AgentOutput(
            agent_id=self.agent_id,
            agent_type=self.agent_type,
            assessment_id=self.assessment_id,
            task_id=task.task_id,
            confidence=0.78,
            epistemic_status=EpistemicStatus.MODEL_HYPOTHESIS,
            hypotheses=hypotheses,
            evidence_gaps=evidence_gaps,
            security_invariants=["INV-BIN-01: Decompiler warning != confirmed exploitability."],
            proposed_experiments=proposed_exps,
            supporting_evidence=evidence_ids,
            analysis_summary=summary,
        )
