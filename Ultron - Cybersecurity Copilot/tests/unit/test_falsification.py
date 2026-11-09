"""Unit tests for M7 Adversarial Falsification Analyst Agent.

Enforces:
1. Active formulation of disproving hypotheses.
2. Generation of negative controls and differential verification experiments.
3. Formulation of alternative non-vulnerable explanations.
4. Epistemic preservation (never outputs FACT or verified finding).
"""

import pytest
from src.agents.falsification import FalsificationAnalystAgent
from src.agents.schemas import AgentTask, AgentType
from src.assessment.models import EpistemicStatus


def test_falsification_agent_generates_negative_controls():
    agent = FalsificationAnalystAgent(assessment_id="ASM-FALS-001")
    task = AgentTask(
        task_id="TASK-FALS-01",
        agent_type=AgentType.FALSIFICATION,
        assessment_id="ASM-FALS-001",
        objective="Falsify BOLA hypothesis",
        target_asset="app.target.com",
        authorization_id="AUTH-001",
    )
    context = {
        "hypotheses": [
            {
                "hypothesis_id": "HYP-001",
                "title": "Potential BOLA on User Profile API",
                "domain": "WEB_APPLICATION",
                "supporting_observations": ["OBS-01"],
            }
        ],
        "observations": [],
    }

    out = agent.run(task, context)

    assert out.agent_type == AgentType.FALSIFICATION
    assert out.epistemic_status == EpistemicStatus.MODEL_HYPOTHESIS
    assert len(out.proposed_experiments) == 1

    exp = out.proposed_experiments[0]
    assert exp.negative_control != ""
    assert exp.falsification_condition != ""
    assert exp.requires_human_execution is True

    plans = out.provenance.get("falsification_plans", [])
    assert len(plans) == 1
    assert len(plans[0]["alternative_explanations"]) > 0


def test_falsification_for_sql_injection():
    agent = FalsificationAnalystAgent(assessment_id="ASM-FALS-001")
    task = AgentTask(
        task_id="TASK-FALS-02",
        agent_type=AgentType.FALSIFICATION,
        assessment_id="ASM-FALS-001",
        objective="Falsify SQL Injection hypothesis",
        target_asset="db-service.corp",
        authorization_id="AUTH-001",
    )
    context = {
        "hypotheses": [
            {
                "hypothesis_id": "HYP-SQL-01",
                "title": "SQL Injection in Search Endpoint",
                "domain": "CODE",
                "supporting_observations": ["OBS-SQL-01"],
            }
        ],
        "observations": [],
    }

    out = agent.run(task, context)
    plans = out.provenance.get("falsification_plans", [])
    assert any("parameterized query" in str(p.get("falsification_condition", "")).lower() for p in plans)
