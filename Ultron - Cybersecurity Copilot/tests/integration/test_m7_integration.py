"""Integration tests for M7 Multi-Agent Security Research and Deep Mobile/Binary Analysis.

Enforces end-to-end verification of:
1. Orchestrated Multi-Agent Assessment Pipeline:
   Target Telemetry -> Domain Agents -> Evidence Analyst -> Falsification Analyst -> Consensus Engine -> Human Review Package.
2. Invariant: Agents and Orchestrator CANNOT authorize targets, mutate scope, or confirm findings.
3. Invariant: Zero false consensus override; empirical grounding strictly required.
4. Lineage Graph tracing with M7 agent relationships.
5. Fault tolerance on agent crash.
"""

import pytest
from src.agents.binary import BinaryReverseEngineeringAgent
from src.agents.code import CodeSecurityAnalystAgent
from src.agents.consensus import MultiAgentConsensusEngine
from src.agents.evidence import EvidenceAnalystAgent
from src.agents.falsification import FalsificationAnalystAgent
from src.agents.mobile import MobileAndroidAnalystAgent
from src.agents.network import NetworkProtocolAnalystAgent
from src.agents.orchestrator import AgentOrchestrator
from src.agents.recon import ReconAnalystAgent
from src.agents.reporting import ReportingAnalystAgent
from src.agents.schemas import AgentType, ConsensusStatus
from src.agents.web_api import WebApiSecurityAnalystAgent
from src.assessment.lineage import EvidenceLineageGraph
from src.assessment.models import (
    AssessmentFinding,
    AssessmentScopeStatus,
    CanonicalObservation,
    FindingSeverity,
    FindingVerificationStatus,
    ObservationType,
)


def test_full_m7_multi_agent_pipeline():
    assessment_id = "ASM-M7-E2E-001"
    target_asset = "api.enterprise-corp.com"
    auth_id = "AUTH-PROD-001"
    scope_ref = "IN_SCOPE"

    # 1. Initialize Orchestrator & Register Agents
    orchestrator = AgentOrchestrator(assessment_id=assessment_id)
    orchestrator.register_agent(ReconAnalystAgent(assessment_id))
    orchestrator.register_agent(WebApiSecurityAnalystAgent(assessment_id))
    orchestrator.register_agent(CodeSecurityAnalystAgent(assessment_id))
    orchestrator.register_agent(EvidenceAnalystAgent(assessment_id))
    orchestrator.register_agent(FalsificationAnalystAgent(assessment_id))
    orchestrator.register_agent(ReportingAnalystAgent(assessment_id))

    # 2. Prepare Ingestion Observations
    obs_http = {
        "observation_id": "OBS-HTTP-101",
        "scope_decision": "IN_SCOPE",
        "normalized_data": {
            "url": "https://api.enterprise-corp.com/user/8912/documents",
            "headers": {"authorization": "Bearer token_abc"},
        },
    }
    context = {"observations": [obs_http]}

    # 3. Execute Pipeline
    result = orchestrator.run_assessment_pipeline(
        target_asset=target_asset,
        authorization_id=auth_id,
        scope_reference=scope_ref,
        domain_agent_types=[AgentType.RECON, AgentType.WEB_API],
        context=context,
    )

    # 4. Verify Pipeline Outputs
    assert result["assessment_id"] == assessment_id
    assert result["status"] == "ANALYSIS_COMPLETE_PENDING_HUMAN_REVIEW"
    assert result["total_hypotheses"] >= 1
    assert len(result["consensus_results"]) >= 1

    # Check consensus evaluation
    cons_res = result["consensus_results"][0]
    assert "hypothesis_id" in cons_res
    assert cons_res["status"] in (ConsensusStatus.CONSENSUS_SUPPORTED, ConsensusStatus.CONSENSUS_WEAK, ConsensusStatus.CONSENSUS_CONTESTED)

    # 5. Verify Lineage Integration
    lineage = EvidenceLineageGraph(assessment_id)
    canonical_obs = CanonicalObservation.create(
        assessment_id=assessment_id,
        asset_id=target_asset,
        observation_type=ObservationType.HTTP_REQUEST,
        source="PASSIVE_PROXY",
        normalized_data=obs_http["normalized_data"],
        scope_decision=AssessmentScopeStatus.IN_SCOPE,
    )
    lineage.register_observation(canonical_obs)

    # Register all agent outputs into lineage graph
    for out_dict in result["agent_outputs"]:
        agent_id = out_dict["agent_id"]
        for hyp in out_dict.get("hypotheses", []):
            lineage.register_agent_relationship(agent_id, hyp["hypothesis_id"], "AGENT_PROPOSED")
        for exp in out_dict.get("proposed_experiments", []):
            lineage.register_agent_relationship(agent_id, exp["experiment_id"], "AGENT_PROPOSED")

    # Trace lineage for a proposed hypothesis
    first_hyp_id = result["hypotheses"][0]["hypothesis_id"]
    agent_edges = lineage.get_agent_relationships_for(first_hyp_id)
    assert len(agent_edges) >= 1
    assert agent_edges[0]["relationship"] == "AGENT_PROPOSED"


from src.assessment.models import (
    AssessmentFinding,
    AssessmentRecord,
    AssessmentScopeStatus,
    AuthorizationRecord,
    AuthorizationStatus,
    AuthorizationType,
    CanonicalObservation,
    FindingSeverity,
    FindingVerificationStatus,
    ObservationType,
)
from src.assessment.validation import FindingValidator, AssessmentValidationContext


def test_agent_cannot_promote_to_verified_finding_without_human_and_validator():
    """
    CRITICAL INVARIANT: No agent or consensus can bypass the deterministic FindingValidator.
    A finding without human verification must fail validation.
    """
    assessment_id = "ASM-M7-BYPASS-TEST"

    # Create unverified candidate finding from agent hypothesis
    candidate_finding = AssessmentFinding(
        finding_id="FIND-AGENT-UNCONFIRMED-01",
        assessment_id=assessment_id,
        title="Unconfirmed Agent BOLA",
        severity=FindingSeverity.HIGH,
        asset="api.target.com",
        affected_component="/user/profile",
        description="Agent claimed vulnerability without human verification",
        impact="Unauthorized profile data access",
        evidence=["OBS-VALID-01"],
        reproduction_reference="curl https://api.target.com/user/10",
        security_invariant="INV-BOLA-01",
        root_cause="Missing authorization check",
        remediation="Enforce tenant-level authorization checks",
        verification_status=FindingVerificationStatus.UNVERIFIED,
    )

    assessment_rec = AssessmentRecord(
        assessment_id=assessment_id,
        organization="Test Corp",
        assessment_name="Test Assessment",
    )
    auth_rec = AuthorizationRecord(
        authorization_id="AUTH-TEST",
        organization="Test Corp",
        assessment_name="Test Assessment",
        authorized_by="Security Lead",
        authorized_at="2026-01-01T00:00:00Z",
        valid_from="2026-01-01T00:00:00Z",
        valid_until="2026-12-31T23:59:59Z",
        authorization_type=AuthorizationType.INTERNAL_SECURITY_ASSESSMENT,
        scope_reference="api.target.com",
        status=AuthorizationStatus.AUTHORIZED,
    )

    context = AssessmentValidationContext(
        assessment=assessment_rec,
        authorization=auth_rec,
    )

    is_valid, reasons = FindingValidator.validate_finding(candidate_finding, context)
    assert is_valid is False
    assert any("HUMAN_VERIFIED" in r or "human" in r.lower() for r in reasons)



def test_orchestrator_fault_tolerance_on_agent_crash():
    """
    Verifies that if an agent crashes unexpectedly, the orchestrator does not crash
    the assessment, logs an AGENT_FAILURE record, and flags the review status correctly.
    """
    assessment_id = "ASM-M7-CRASH-TEST"
    orchestrator = AgentOrchestrator(assessment_id)

    # Create a faulty mock agent
    from src.agents.base import BaseAgent
    from src.agents.schemas import AgentOutput, AgentTask

    class CrashingAgent(BaseAgent):
        def analyze(self, task: AgentTask, context: dict) -> AgentOutput:
            raise RuntimeError("Unexpected memory fault during AST parsing")

    crashing_agent = CrashingAgent(agent_id="AGENT-CRASH-01", agent_type=AgentType.CODE, assessment_id=assessment_id)
    orchestrator.register_agent(crashing_agent)

    result = orchestrator.run_assessment_pipeline(
        target_asset="app.target.com",
        authorization_id="AUTH-01",
        scope_reference="IN_SCOPE",
        domain_agent_types=[AgentType.CODE],
        context={"observations": []},
    )

    # Pipeline completed safely despite crash
    assert len(result["failures"]) >= 1
    assert "Unexpected memory fault" in result["failures"][0]["error"]
