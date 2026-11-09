"""Network & Protocol Analyst Agent for M7 Infrastructure Auditing.

Enforces:
1. Analyzes DNS, TLS, TCP/UDP metadata, service fingerprints, and PCAP data.
2. INVARIANT: No autonomous network packet generation or scanning.
3. Interprets passive observations and designs safe human-executed experiments.
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


class NetworkProtocolAnalystAgent(BaseAgent):
    """Specialized agent for network infrastructure and protocol analysis."""

    def __init__(self, assessment_id: str, agent_id: str = "AGENT-NET-001") -> None:
        super().__init__(agent_id=agent_id, agent_type=AgentType.NETWORK, assessment_id=assessment_id)

    def analyze(self, task: AgentTask, context: Dict[str, Any]) -> AgentOutput:
        target = task.target_asset
        observations = context.get("observations", [])
        evidence_ids = [obs.get("observation_id") for obs in observations if isinstance(obs, dict) and "observation_id" in obs]

        hypotheses: List[AssessmentHypothesis] = []
        evidence_gaps: List[str] = []
        proposed_exps: List[AssessmentExperiment] = []

        has_weak_tls = False
        has_cleartext = False

        for obs in observations:
            if not isinstance(obs, dict):
                continue
            data = obs.get("normalized_data", {})
            ciphers = data.get("ciphers", [])
            port = data.get("port")
            protocol = str(data.get("protocol", "")).lower()

            if any("rc4" in str(c).lower() or "des" in str(c).lower() or "md5" in str(c).lower() for c in ciphers):
                has_weak_tls = True
            open_ports = data.get("open_ports", [])
            if any(p in (80, 21, 23) for p in open_ports) or port in (80, 21, 23) or protocol in ("http", "ftp", "telnet"):
                has_cleartext = True

        if has_weak_tls:
            hyp = AssessmentHypothesis(
                hypothesis_id=f"HYP-NET-{len(hypotheses)+1:03d}",
                assessment_id=self.assessment_id,
                title=f"Deprecated Cryptographic Ciphers Negotiable on {target}",
                description="Passive TLS observation indicates support for legacy/weak cipher suites.",
                domain="NETWORK_SECURITY",
                supporting_observations=evidence_ids[:1],
                security_invariants=["TLS: Sensitive transit traffic must enforce TLS 1.2+ with modern AEAD cipher suites."],
                negative_control="Client handshake offering modern cipher suites negotiates TLS_AES_256_GCM_SHA384.",
                falsification_condition="Server rejects client handshakes offering exclusively legacy ciphers.",
                evidence_gaps=["Missing active handshake verification of cipher suite negotiation order."],
            )
            hypotheses.append(hyp)

            exp = AssessmentExperiment(
                experiment_id=f"EXP-TLS-{len(proposed_exps)+1:03d}",
                assessment_id=self.assessment_id,
                hypothesis_id=hyp.hypothesis_id,
                objective="Verify TLS cipher negotiation and protocol downgrade resistance",
                authorization_reference=task.authorization_id,
                scope_reference=task.scope_reference,
                steps=[f"openssl s_client -connect {target}:443 -cipher 'ALL:!EXPORT:!LOW'"],
                expected_secure_result="Handshake fails on deprecated suites",
                expected_vulnerable_result="Handshake succeeds with weak cipher",
                falsification_condition="Server strictly enforces secure cipher suites",
                negative_control="Modern client handshake succeeds",
                requires_human_execution=True,
                risk_level=ExperimentRiskLevel.PASSIVE,
                status=ExperimentStatus.PROPOSED,
            )
            proposed_exps.append(exp)

        if has_cleartext:
            hyp_clear = AssessmentHypothesis(
                hypothesis_id=f"HYP-NET-{len(hypotheses)+1:03d}",
                assessment_id=self.assessment_id,
                title=f"Unencrypted Cleartext Protocol Service Exposed on {target}",
                description="Observation reveals cleartext transmission services (FTP/Telnet/HTTP) without transport encryption.",
                domain="NETWORK_SECURITY",
                supporting_observations=evidence_ids[:1],
                security_invariants=["INV-NET-02: Authentication credentials and data in transit must require TLS."],
                negative_control="Service requires STARTTLS or issues mandatory redirect to encrypted port.",
                falsification_condition="Service rejects plaintext session or mandates encryption upgrade.",
                evidence_gaps=["Verify if service enforces mandatory STARTTLS before authentication."],
            )
            hypotheses.append(hyp_clear)

            exp_clear = AssessmentExperiment(
                experiment_id=f"EXP-CLEARTEXT-{len(proposed_exps)+1:03d}",
                assessment_id=self.assessment_id,
                hypothesis_id=hyp_clear.hypothesis_id,
                objective="Test whether service permits plaintext authentication",
                authorization_reference=task.authorization_id,
                scope_reference=task.scope_reference,
                steps=[f"Inspect initial banner and capability flags on {target}"],
                expected_secure_result="Service requires TLS/SSL before auth",
                expected_vulnerable_result="Service accepts cleartext authentication",
                falsification_condition="Service mandates encryption",
                negative_control="Secure TLS connection is supported",
                requires_human_execution=True,
                risk_level=ExperimentRiskLevel.PASSIVE,
                status=ExperimentStatus.PROPOSED,
            )
            proposed_exps.append(exp_clear)
            evidence_gaps.append(f"Cleartext protocol observation on {target}: verify whether transport encryption is enforced.")

        summary = (
            f"Network analysis for {target}: Evaluated {len(observations)} protocol records. "
            f"Formulated {len(hypotheses)} hypotheses. No autonomous scanning performed."
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
            security_invariants=["INV-NET-01: Passive Analysis Only (No autonomous scanning or packet generation)."],
            proposed_experiments=proposed_exps,
            supporting_evidence=evidence_ids,
            analysis_summary=summary,
        )
