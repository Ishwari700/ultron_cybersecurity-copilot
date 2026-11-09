"""Safe Experiment Engine and Command Generation Protocol for M6.

Enforces:
1. Strict Plane Separation:
   AI ANALYSIS PLANE (Reasoning, Design, Hypotheses)
   vs
   TARGET ACTION PLANE (Network requests, Validation, State changes)
2. All proposed experiments default strictly to:
   - requires_human_execution = True
   - destructive_potential = False
3. Non-autonomous execution: High-risk and destructive experiments are NEVER
   executed automatically by the system.
4. Command generator annotates commands with risk level, authorization, scope, and target.
"""

from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List, Optional, Tuple
from src.assessment.models import (
    AssessmentExperiment,
    AssessmentScopeStatus,
    AuthorizationRecord,
    ExperimentRiskLevel,
    ExperimentStatus,
)
from src.scope.gate import ScopeGate
from src.assessment.authorization import AuthorizationValidator


class SafeExperimentEngine:
    """Proposes, validates, and manages verification experiments."""

    def __init__(self, assessment_id: str, scope_gate: ScopeGate) -> None:
        self.assessment_id = assessment_id
        self.scope_gate = scope_gate
        self._experiments: Dict[str, AssessmentExperiment] = {}

    def propose_experiment(
        self,
        hypothesis_id: str,
        objective: str,
        target_asset: str,
        authorization: AuthorizationRecord,
        steps: List[str],
        expected_secure_result: str,
        expected_vulnerable_result: str,
        falsification_condition: str,
        negative_control: str,
        risk_level: ExperimentRiskLevel = ExperimentRiskLevel.PASSIVE,
        preconditions: Optional[List[str]] = None,
        destructive_potential: bool = False,
    ) -> AssessmentExperiment:
        """
        Creates a proposed experiment protocol for human execution.
        Fails closed if authorization is invalid or target is out of scope.
        """
        # 1. Authorization Gate check
        AuthorizationValidator.assert_authorized(authorization, action_name=f"Experiment proposal for {hypothesis_id}")

        # 2. Scope Gate re-check
        scope_res = self.scope_gate.recheck_scope(target_asset, operation_name=f"Experiment proposal for {hypothesis_id}")

        # 3. Disguised attack detection and risk classification hardening
        combined_text = (objective + " " + " ".join(steps)).lower()

        destructive_patterns = [
            "drop table", "rm -rf", "format ", "truncate table", "unlink ",
            "delete from", "curl -x delete", "wipe disk", "dd if=/dev",
            "shred ", "kill -9 -1", "shutdown -h", "reboot now",
        ]
        if any(dp in combined_text for dp in destructive_patterns):
            destructive_potential = True
            risk_level = ExperimentRiskLevel.DESTRUCTIVE

        high_risk_patterns = [
            "password spray", "hydra ", "rockyou", "brute force", "wordlist",
            "credential stuffing", "dictionary attack", "exploit/multi/handler",
            "meterpreter", "reverse shell", "nc -e", "/bin/bash -i", "threads 100",
            "100000 requests", "masscan", "dos attack", "flood",
        ]
        if not destructive_potential and any(hr in combined_text for hr in high_risk_patterns):
            risk_level = ExperimentRiskLevel.HIGH_RISK

        moderate_risk_patterns = [
            "post /transfer", "put /user", "change_password", "grant_admin",
            "elevate", "update_role", "admin=true", "role=admin",
        ]
        if risk_level in (ExperimentRiskLevel.PASSIVE, ExperimentRiskLevel.LOW_RISK) and any(mr in combined_text for mr in moderate_risk_patterns):
            risk_level = ExperimentRiskLevel.MODERATE_RISK

        # Low risk patterns (active probing, port scanning, authenticated testing, intent launching)
        low_risk_patterns = [
            "nmap ", "am start", "with user session", "with tenant",
            "active scan", "probe", "get /admin", "get /api/",
        ]
        if risk_level == ExperimentRiskLevel.PASSIVE and any(lr in combined_text for lr in low_risk_patterns):
            risk_level = ExperimentRiskLevel.LOW_RISK

        if destructive_potential:
            risk_level = ExperimentRiskLevel.DESTRUCTIVE

        seed = f"{self.assessment_id}:{hypothesis_id}:{objective}:{target_asset}"
        exp_id = f"EXP-{hashlib.sha256(seed.encode('utf-8')).hexdigest()[:12].upper()}"

        exp = AssessmentExperiment(
            experiment_id=exp_id,
            assessment_id=self.assessment_id,
            hypothesis_id=hypothesis_id,
            objective=objective,
            authorization_reference=authorization.authorization_id,
            scope_reference=scope_res.matched_rule or "IN_SCOPE",
            preconditions=preconditions or [f"Target {target_asset} verified in active scope"],
            steps=steps,
            expected_secure_result=expected_secure_result,
            expected_vulnerable_result=expected_vulnerable_result,
            falsification_condition=falsification_condition,
            negative_control=negative_control,
            destructive_potential=destructive_potential,
            requires_human_execution=True,  # ALWAYS True in M6
            risk_level=risk_level,
            status=ExperimentStatus.PROPOSED,
        )

        self._experiments[exp_id] = exp
        return exp

    def approve_experiment(self, experiment_id: str, approver_name: str) -> AssessmentExperiment:
        """Explicit human approval of experiment protocol before researcher executes it."""
        if experiment_id not in self._experiments:
            raise KeyError(f"Experiment {experiment_id} not found.")
        exp = self._experiments[experiment_id]
        exp.status = ExperimentStatus.APPROVED
        exp.approved_by = approver_name
        exp.approved_at = datetime.now(timezone.utc).isoformat()
        return exp

    def import_human_result(
        self,
        experiment_id: str,
        result_payload: Dict[str, Any],
        executed_by: str,
    ) -> AssessmentExperiment:
        """
        Imports the empirical result of an experiment executed by a human researcher.
        Requires explicit prior human approval (status == APPROVED).
        """
        if experiment_id not in self._experiments:
            raise KeyError(f"Experiment {experiment_id} not found.")
        exp = self._experiments[experiment_id]
        if exp.status != ExperimentStatus.APPROVED:
            raise ValueError(
                f"Cannot import result for experiment '{experiment_id}' in state {exp.status.value}: "
                f"only 'APPROVED' experiments can receive results. Explicit approval is required before result import."
            )

        if not executed_by or not str(executed_by).strip():
            raise ValueError("Executed_by actor identifier is required.")
        if any(t in str(executed_by).upper() for t in ("LLM", "MODEL", "AI", "AUTO", "BOT", "SYSTEM", "AGENT", "ORCHESTRATOR", "COPILOT")):
            raise ValueError(f"Automated entity '{executed_by}' cannot submit human experiment results.")

        if not isinstance(result_payload, dict):
            raise ValueError("Result payload must be a valid dictionary.")

        exp.status = ExperimentStatus.EXECUTED
        exp.execution_result = result_payload
        exp.result_payload = result_payload
        exp.executed_by = executed_by.strip()
        exp.executed_at = datetime.now(timezone.utc).isoformat()
        return exp

    def generate_safe_command_suggestion(
        self,
        tool: str,
        target_url: str,
        authorization: AuthorizationRecord,
    ) -> Dict[str, Any]:
        """
        Generates safe, non-destructive diagnostic command string with explicit annotations.
        System DOES NOT execute this command. It is provided for human review.
        """
        AuthorizationValidator.assert_authorized(authorization, action_name="Command Generation")
        scope_res = self.scope_gate.recheck_scope(target_url, operation_name="Command Generation")

        t_lower = tool.lower()
        if t_lower == "curl":
            cmd = f"curl -s -I -A 'AuthorizedSecurityAssessment/{authorization.authorization_id}' '{target_url}'"
            risk = ExperimentRiskLevel.PASSIVE
        elif t_lower == "httpx":
            cmd = f"httpx -u '{target_url}' -status-code -title -tech-detect"
            risk = ExperimentRiskLevel.PASSIVE
        elif t_lower == "nmap":
            cmd = f"nmap -sV -T3 -p- '{target_url}'"
            risk = ExperimentRiskLevel.LOW_RISK
        else:
            cmd = f"echo 'Tool {tool} suggestion for {target_url}'"
            risk = ExperimentRiskLevel.LOW_RISK

        return {
            "assessment_id": self.assessment_id,
            "authorization_id": authorization.authorization_id,
            "target": target_url,
            "scope_rule": scope_res.matched_rule,
            "suggested_command": cmd,
            "risk_level": risk.value,
            "execution_mode": "HUMAN_OPERATED_ONLY",
            "notice": "Autonomous command execution is disabled by M6 safety invariant.",
        }
