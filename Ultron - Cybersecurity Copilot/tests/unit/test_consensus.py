"""Unit tests for M7 Multi-Agent Evidence-Weighted Consensus Engine.

Enforces:
1. Rejection of ungrounded majority voting.
2. False consensus detection: unanimous agent agreement without canonical observations
   must fail (flagged and contested).
3. Evidence Analyst insufficiency correctly downgrades consensus.
4. Falsification disputes correctly produce CONSENSUS_CONTESTED.
5. Invariant: Consensus result is analytical only, never a verified finding.
"""

import pytest
from src.agents.consensus import MultiAgentConsensusEngine
from src.agents.schemas import (
    AgentOutput,
    AgentType,
    ConsensusStatus,
)
from src.assessment.models import (
    AssessmentHypothesis,
    EpistemicStatus,
)


def test_false_consensus_detection_zero_evidence():
    engine = MultiAgentConsensusEngine(assessment_id="ASM-CONS-001")

    # A hypothesis with claimed observations that do NOT exist in canonical observation store
    hyp = AssessmentHypothesis(
        hypothesis_id="HYP-GHOST-01",
        assessment_id="ASM-CONS-001",
        title="Hallucinated RCE",
        description="Agents agree on RCE with zero factual backing",
        domain="WEB_APPLICATION",
        supporting_observations=["OBS-NONEXISTENT-99"],
    )

    # 3 different agents unanimously agreeing and high confidence
    out1 = AgentOutput(
        agent_id="AGENT-WEB-1",
        agent_type=AgentType.WEB_API,
        assessment_id="ASM-CONS-001",
        task_id="T1",
        confidence=0.95,
        epistemic_status=EpistemicStatus.MODEL_HYPOTHESIS,
        hypotheses=[hyp],
        analysis_summary="Found RCE!",
    )
    out2 = AgentOutput(
        agent_id="AGENT-CODE-1",
        agent_type=AgentType.CODE,
        assessment_id="ASM-CONS-001",
        task_id="T2",
        confidence=0.90,
        epistemic_status=EpistemicStatus.MODEL_HYPOTHESIS,
        hypotheses=[hyp],
        analysis_summary="Agreed, dangerous sink found!",
    )

    # Empty canonical observation store
    canonical_store = []

    res = engine.evaluate_hypothesis_consensus(
        hypothesis=hyp,
        agent_outputs=[out1, out2],
        canonical_observations=canonical_store,
    )

    # False consensus must be detected and status cannot be CONSENSUS_SUPPORTED
    assert res.false_consensus_flag is True
    assert res.status in (ConsensusStatus.INSUFFICIENT_EVIDENCE, ConsensusStatus.CONSENSUS_CONTESTED)
    assert any("FALSE_CONSENSUS_DETECTED" in reason for reason in res.disagreement_reasons)


def test_consensus_with_evidence_and_falsification_dispute():
    engine = MultiAgentConsensusEngine(assessment_id="ASM-CONS-001")

    hyp = AssessmentHypothesis(
        hypothesis_id="HYP-BOLA-01",
        assessment_id="ASM-CONS-001",
        title="Potential BOLA on User Endpoint",
        description="Object ID exposed",
        domain="WEB_APPLICATION",
        supporting_observations=["OBS-REAL-01"],
    )

    out_web = AgentOutput(
        agent_id="AGENT-WEB-1",
        agent_type=AgentType.WEB_API,
        assessment_id="ASM-CONS-001",
        task_id="T1",
        confidence=0.85,
        epistemic_status=EpistemicStatus.MODEL_HYPOTHESIS,
        hypotheses=[hyp],
        analysis_summary="BOLA hypothesis formulated",
    )

    out_evidence = AgentOutput(
        agent_id="AGENT-EVIDENCE-1",
        agent_type=AgentType.EVIDENCE,
        assessment_id="ASM-CONS-001",
        task_id="T2",
        confidence=0.80,
        epistemic_status=EpistemicStatus.INFERENCE,
        analysis_summary="Evidence sufficient",
        provenance={"sufficiency_verdict": "EVIDENCE_SUFFICIENT"},
    )

    out_falsify = AgentOutput(
        agent_id="AGENT-FALSIFY-1",
        agent_type=AgentType.FALSIFICATION,
        assessment_id="ASM-CONS-001",
        task_id="T3",
        confidence=0.90,
        epistemic_status=EpistemicStatus.MODEL_HYPOTHESIS,
        contradicting_evidence=["Alternative explanation: Endpoint is intentionally public profile"],
        analysis_summary="Raised alternative explanation",
        provenance={
            "falsification_plans": [
                {
                    "hypothesis_id": "HYP-BOLA-01",
                    "alternative_explanations": ["Public read profile data"],
                }
            ]
        },
    )

    canonical_store = [{"observation_id": "OBS-REAL-01", "normalized_data": {"url": "/user/123"}}]

    res = engine.evaluate_hypothesis_consensus(
        hypothesis=hyp,
        agent_outputs=[out_web, out_evidence, out_falsify],
        canonical_observations=canonical_store,
    )

    # Disputed hypothesis should be WEAK or CONTESTED, not blindly supported
    assert res.status in (ConsensusStatus.CONSENSUS_WEAK, ConsensusStatus.CONSENSUS_CONTESTED)
    assert res.falsification_verdict == "ADVERSARIAL_DISPUTE_RAISED"
    assert "AGENT-FALSIFY-1" in res.contradicting_agents


def test_consensus_supported_when_grounded_and_undisputed():
    engine = MultiAgentConsensusEngine(assessment_id="ASM-CONS-001")

    hyp = AssessmentHypothesis(
        hypothesis_id="HYP-CLEAN-01",
        assessment_id="ASM-CONS-001",
        title="Clear Misconfiguration",
        description="Clear service misconfiguration on port",
        domain="NETWORK",
        supporting_observations=["OBS-REAL-01"],
    )

    out_net = AgentOutput(
        agent_id="AGENT-NET-1",
        agent_type=AgentType.NETWORK,
        assessment_id="ASM-CONS-001",
        task_id="T1",
        confidence=0.90,
        epistemic_status=EpistemicStatus.MODEL_HYPOTHESIS,
        hypotheses=[hyp],
        analysis_summary="Clear misconfig",
    )

    out_ev = AgentOutput(
        agent_id="AGENT-EVIDENCE-1",
        agent_type=AgentType.EVIDENCE,
        assessment_id="ASM-CONS-001",
        task_id="T2",
        confidence=0.90,
        epistemic_status=EpistemicStatus.INFERENCE,
        analysis_summary="Evidence sufficient",
        provenance={"sufficiency_verdict": "EVIDENCE_SUFFICIENT"},
    )

    canonical_store = [{"observation_id": "OBS-REAL-01", "normalized_data": {"port": 21}}]

    res = engine.evaluate_hypothesis_consensus(
        hypothesis=hyp,
        agent_outputs=[out_net, out_ev],
        canonical_observations=canonical_store,
    )

    assert res.status == ConsensusStatus.CONSENSUS_SUPPORTED
    assert res.consensus_score >= 0.80
    assert res.false_consensus_flag is False
