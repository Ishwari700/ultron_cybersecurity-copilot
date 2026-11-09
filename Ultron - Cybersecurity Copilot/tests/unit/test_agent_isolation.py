"""Unit tests for M7 Cross-Assessment Agent Isolation.

Enforces:
1. Zero cross-assessment leakage invariant.
2. Agents bound to Assessment A cannot process tasks for Assessment B.
3. Orchestrator bound to Assessment A rejects agents bound to Assessment B.
4. Identical targets or assets in distinct assessments remain strictly isolated.
"""

import pytest
from src.agents.base import AgentSecurityViolationError
from src.agents.orchestrator import AgentOrchestrator, OrchestratorSecurityError
from src.agents.recon import ReconAnalystAgent
from src.agents.schemas import AgentTask, AgentType
from src.agents.web_api import WebApiSecurityAnalystAgent


def test_agent_rejects_foreign_assessment_task():
    agent_a = WebApiSecurityAnalystAgent(assessment_id="ASM-ORG1-001")

    foreign_task = AgentTask(
        task_id="TASK-FOREIGN-01",
        agent_type=AgentType.WEB_API,
        assessment_id="ASM-ORG2-999",  # Different assessment!
        objective="Inspect API",
        target_asset="api.example.com",
        authorization_id="AUTH-999",
    )
    context = {"observations": []}

    with pytest.raises(AgentSecurityViolationError, match="CROSS_ASSESSMENT_VIOLATION"):
        agent_a.run(foreign_task, context)


def test_orchestrator_rejects_foreign_agent_registration():
    orchestrator = AgentOrchestrator(assessment_id="ASM-PRIMARY-001")
    foreign_agent = ReconAnalystAgent(assessment_id="ASM-FOREIGN-002")

    with pytest.raises(OrchestratorSecurityError, match="cannot register with orchestrator"):
        orchestrator.register_agent(foreign_agent)


def test_identical_target_multi_tenant_isolation():
    # Two distinct assessments targeting the same asset (e.g. cloud tenant or shared domain)
    agent_tenant1 = WebApiSecurityAnalystAgent(assessment_id="ASM-TENANT-ALPHA")
    agent_tenant2 = WebApiSecurityAnalystAgent(assessment_id="ASM-TENANT-BETA")

    task_alpha = AgentTask(
        task_id="TASK-T1-01",
        agent_type=AgentType.WEB_API,
        assessment_id="ASM-TENANT-ALPHA",
        objective="Analyze tenant alpha endpoints",
        target_asset="shared-gateway.example.com",
        authorization_id="AUTH-ALPHA",
    )
    task_beta = AgentTask(
        task_id="TASK-T2-01",
        agent_type=AgentType.WEB_API,
        assessment_id="ASM-TENANT-BETA",
        objective="Analyze tenant beta endpoints",
        target_asset="shared-gateway.example.com",
        authorization_id="AUTH-BETA",
    )

    out_alpha = agent_tenant1.run(task_alpha, {"observations": []})
    out_beta = agent_tenant2.run(task_beta, {"observations": []})

    assert out_alpha.assessment_id == "ASM-TENANT-ALPHA"
    assert out_beta.assessment_id == "ASM-TENANT-BETA"
    assert out_alpha.provenance["assessment_id"] == "ASM-TENANT-ALPHA"
    assert out_beta.provenance["assessment_id"] == "ASM-TENANT-BETA"

    # Cross execution must fail
    with pytest.raises(AgentSecurityViolationError):
        agent_tenant1.run(task_beta, {"observations": []})

    with pytest.raises(AgentSecurityViolationError):
        agent_tenant2.run(task_alpha, {"observations": []})
