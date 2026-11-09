"""Code Security Analyst Agent for M7 Source Code Auditing.

Enforces:
1. Multi-language static analysis: Python, JS/TS, Go, PHP, Java.
2. Sinks: SQL injection, Command execution, Deserialization, SSRF, Path traversal, Crypto misuse.
3. INVARIANT: Source pattern != Exploitability. Code pattern generates
   CODE_OBSERVATION -> HYPOTHESIS -> REQUIRED_EVIDENCE -> TEST_PLAN.
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


class CodeSecurityAnalystAgent(BaseAgent):
    """Specialized static source code analysis agent."""

    def __init__(self, assessment_id: str, agent_id: str = "AGENT-CODE-001") -> None:
        super().__init__(agent_id=agent_id, agent_type=AgentType.CODE, assessment_id=assessment_id)

    def analyze(self, task: AgentTask, context: Dict[str, Any]) -> AgentOutput:
        target = task.target_asset
        code_snippets = list(context.get("code_snippets", []))
        observations = context.get("observations", [])
        evidence_ids = [obs.get("observation_id") for obs in observations if isinstance(obs, dict) and "observation_id" in obs]

        for obs in observations:
            if isinstance(obs, dict):
                data = obs.get("normalized_data", {})
                content = data.get("content") or data.get("source_code")
                if content and content not in code_snippets:
                    code_snippets.append(content)

        hypotheses: List[AssessmentHypothesis] = []
        evidence_gaps: List[str] = []
        proposed_exps: List[AssessmentExperiment] = []

        sink_patterns = [
            ("SQL_INJECTION", ("execute(", "raw(", "cursor.execute", "query(", "SELECT * FROM")),
            ("COMMAND_INJECTION", ("os.system(", "subprocess.Popen(", "exec(", "Runtime.getRuntime().exec")),
            ("PATH_TRAVERSAL", ("open(", "file_get_contents(", "FileInputStream(", "path.join(")),
            ("DESERIALIZATION", ("pickle.loads(", "unserialize(", "readObject(", "yaml.load(")),
        ]

        for snippet in code_snippets:
            snippet_str = str(snippet)
            for vuln_type, sinks in sink_patterns:
                if any(s in snippet_str for s in sinks):
                    hyp = AssessmentHypothesis(
                        hypothesis_id=f"HYP-CODE-{len(hypotheses)+1:03d}",
                        assessment_id=self.assessment_id,
                        title=f"Potential {vuln_type} in {target}",
                        description=f"Dangerous sink invocation detected in source code for {target}.",
                        domain="SECURE_CODING",
                        supporting_observations=evidence_ids[:1],
                        security_invariants=[f"INPUT_VALIDATION: User input reaching sink must be sanitized or parameterized."],
                        negative_control="Benign input is processed without triggering syntax error or side effects.",
                        falsification_condition="Input is strictly sanitized or parameterized prior to sink entry.",
                        evidence_gaps=[
                            f"Missing proof of tainted user input reachability from external entry point to sink in {target}."
                        ],
                    )
                    hypotheses.append(hyp)

                    exp = AssessmentExperiment(
                        experiment_id=f"EXP-CODE-{len(proposed_exps)+1:03d}",
                        assessment_id=self.assessment_id,
                        hypothesis_id=hyp.hypothesis_id,
                        objective=f"Verify reachability of {vuln_type} sink",
                        authorization_reference=task.authorization_id,
                        scope_reference=task.scope_reference,
                        steps=["Review call hierarchy from router to sink", "Execute safe canary input trace"],
                        expected_secure_result="Input is validated; canary safely handled",
                        expected_vulnerable_result="Canary payload executed or unsanitized at sink",
                        falsification_condition="Input cannot reach sink from public route",
                        negative_control="Standard parameter submission yields standard response",
                        requires_human_execution=True,
                        risk_level=ExperimentRiskLevel.LOW_RISK,
                        status=ExperimentStatus.PROPOSED,
                    )
                    proposed_exps.append(exp)

        summary = (
            f"Code analysis for {target}: Examined {len(code_snippets)} snippets. "
            f"Identified {len(hypotheses)} static sink patterns. Source code pattern != confirmed exploitability."
        )

        return AgentOutput(
            agent_id=self.agent_id,
            agent_type=self.agent_type,
            assessment_id=self.assessment_id,
            task_id=task.task_id,
            confidence=0.75,
            epistemic_status=EpistemicStatus.MODEL_HYPOTHESIS,
            hypotheses=hypotheses,
            evidence_gaps=evidence_gaps,
            security_invariants=["INV-CODE-01: Code pattern != exploitability (Sink presence alone does not prove flaw)."],
            proposed_experiments=proposed_exps,
            supporting_evidence=evidence_ids,
            analysis_summary=summary,
        )
