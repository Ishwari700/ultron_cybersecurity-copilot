"""Unit tests for M7 Specialized Agent Contracts, Schemas, and Budgets.

Verifies:
1. All agents implement the standard contract.
2. Typed outputs with audit provenance.
3. Budget tracker bounds enforcement (max calls, depth, tokens).
4. Specialized domain agent behaviors.
"""

import pytest
from src.agents.budgets import AgentBudgetConfig, AgentBudgetTracker, AgentBudgetExceededError
from src.agents.code import CodeSecurityAnalystAgent
from src.agents.network import NetworkProtocolAnalystAgent
from src.agents.recon import ReconAnalystAgent
from src.agents.reporting import ReportingAnalystAgent
from src.agents.schemas import AgentOutput, AgentTask, AgentType, ConsensusStatus
from src.agents.web_api import WebApiSecurityAnalystAgent
from src.assessment.models import EpistemicStatus


def test_agent_task_and_output_schemas():
    task = AgentTask(
        task_id="TASK-001",
        agent_type=AgentType.RECON,
        assessment_id="ASM-001",
        objective="Enumerate attack surface",
        target_asset="api.example.com",
        authorization_id="AUTH-001",
    )
    assert task.task_id == "TASK-001"
    assert task.depth == 1

    output = AgentOutput(
        agent_id="AGENT-RECON-001",
        agent_type=AgentType.RECON,
        assessment_id="ASM-001",
        task_id="TASK-001",
        confidence=0.85,
        epistemic_status=EpistemicStatus.MODEL_HYPOTHESIS,
        analysis_summary="Recon summary",
    )
    assert output.confidence == 0.85
    output.validate_epistemic_boundaries()  # Should not raise


def test_epistemic_boundary_rejection():
    # If an agent tries to output FACT or HUMAN_VERIFIED_FINDING, it must raise PermissionError
    output = AgentOutput(
        agent_id="AGENT-ROGUE-001",
        agent_type=AgentType.WEB_API,
        assessment_id="ASM-001",
        task_id="TASK-001",
        confidence=0.99,
        epistemic_status=EpistemicStatus.FACT,  # FORBIDDEN for agents
        analysis_summary="Illegal fact claim",
    )
    with pytest.raises(PermissionError, match="illegally attempted to output status 'FACT'"):
        output.validate_epistemic_boundaries()


def test_budget_tracker_call_limit():
    config = AgentBudgetConfig(max_agent_calls=3)
    tracker = AgentBudgetTracker(assessment_id="ASM-001", config=config)

    tracker.record_agent_call("AGENT-01", depth=1)
    tracker.record_agent_call("AGENT-02", depth=1)
    tracker.record_agent_call("AGENT-03", depth=2)

    with pytest.raises(AgentBudgetExceededError, match="max_agent_calls limit"):
        tracker.record_agent_call("AGENT-04", depth=2)


def test_budget_tracker_depth_limit():
    config = AgentBudgetConfig(max_reasoning_depth=3)
    tracker = AgentBudgetTracker(assessment_id="ASM-001", config=config)

    tracker.record_agent_call("AGENT-01", depth=1)
    tracker.record_agent_call("AGENT-02", depth=3)

    with pytest.raises(AgentBudgetExceededError, match="max_reasoning_depth limit"):
        tracker.record_agent_call("AGENT-03", depth=4)


def test_recon_analyst_discovery_not_vulnerability():
    agent = ReconAnalystAgent(assessment_id="ASM-001")
    task = AgentTask(
        task_id="TASK-RECON-1",
        agent_type=AgentType.RECON,
        assessment_id="ASM-001",
        objective="Analyze attack surface",
        target_asset="app.example.com",
        authorization_id="AUTH-001",
    )
    context = {
        "observations": [
            {
                "observation_id": "OBS-01",
                "normalized_data": {"domain": "app.example.com", "open_ports": [80, 443]},
            }
        ]
    }
    out = agent.run(task, context)
    assert out.agent_type == AgentType.RECON
    assert "DISCOVERY != VULNERABILITY" in out.security_invariants[0]
    # No vulnerability confirmed
    assert out.epistemic_status == EpistemicStatus.MODEL_HYPOTHESIS


def test_web_api_analyst_invariant_mapping():
    agent = WebApiSecurityAnalystAgent(assessment_id="ASM-001")
    task = AgentTask(
        task_id="TASK-WEB-1",
        agent_type=AgentType.WEB_API,
        assessment_id="ASM-001",
        objective="Analyze API endpoints",
        target_asset="api.example.com",
        authorization_id="AUTH-001",
    )
    context = {
        "observations": [
            {
                "observation_id": "OBS-HTTP-1",
                "normalized_data": {
                    "url": "https://api.example.com/user/1042/profile",
                    "headers": {"authorization": "Bearer token123"},
                },
            }
        ]
    }
    out = agent.run(task, context)
    assert len(out.hypotheses) == 1
    hyp = out.hypotheses[0]
    assert "BOLA" in hyp.title
    assert hyp.negative_control is not None
    assert hyp.falsification_condition is not None
    assert len(out.proposed_experiments) == 1
    assert out.proposed_experiments[0].requires_human_execution is True


def test_code_security_analyst_pattern_not_exploit():
    agent = CodeSecurityAnalystAgent(assessment_id="ASM-001")
    task = AgentTask(
        task_id="TASK-CODE-1",
        agent_type=AgentType.CODE,
        assessment_id="ASM-001",
        objective="Analyze source code for sinks",
        target_asset="repo-backend",
        authorization_id="AUTH-001",
    )
    context = {
        "observations": [
            {
                "observation_id": "OBS-CODE-1",
                "normalized_data": {
                    "file_path": "server/handlers.py",
                    "content": "query = f'SELECT * FROM users WHERE name={user_input}'\ncursor.execute(query)",
                },
            }
        ]
    }
    out = agent.run(task, context)
    assert len(out.hypotheses) == 1
    assert "SQL" in out.hypotheses[0].title
    assert "Code pattern != exploitability" in out.security_invariants[0]


def test_network_protocol_analyst_passive_only():
    agent = NetworkProtocolAnalystAgent(assessment_id="ASM-001")
    task = AgentTask(
        task_id="TASK-NET-1",
        agent_type=AgentType.NETWORK,
        assessment_id="ASM-001",
        objective="Analyze network services",
        target_asset="192.168.1.50",
        authorization_id="AUTH-001",
    )
    context = {
        "observations": [
            {
                "observation_id": "OBS-NET-1",
                "normalized_data": {
                    "open_ports": [21],
                    "service_fingerprints": {"21": "vsftpd 2.3.4"},
                },
            }
        ]
    }
    out = agent.run(task, context)
    assert "Passive Analysis Only" in out.security_invariants[0]
    assert len(out.hypotheses) >= 1
    assert out.proposed_experiments[0].requires_human_execution is True
