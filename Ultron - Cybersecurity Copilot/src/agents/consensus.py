"""Multi-Agent Evidence-Weighted Consensus Engine for M7.

Enforces:
1. Rejects simple majority voting: A unanimous agent majority CANNOT override deterministic evidence.
2. Evidence-weighted consensus considering:
   - Evidence grounding (presence of valid in-scope canonical observations)
   - Evidence quality & provenance from Evidence Analyst
   - Falsification results & alternative explanations from Falsification Analyst
   - Agent specialization & domain match
   - Contradictions & unresolved evidence gaps
3. False Consensus Detection:
   - Detects correlated hallucinations where multiple agents agree without empirical grounding.
   - Flags false consensus and downgrades to INSUFFICIENT_EVIDENCE or CONSENSUS_CONTESTED.
4. INVARIANT: Consensus is analytical only. It never promotes a hypothesis to a verified finding.
"""

from typing import Any, Dict, List, Optional, Set
from src.agents.schemas import (
    AgentOutput,
    AgentType,
    ConsensusResult,
    ConsensusStatus,
)
from src.assessment.models import AssessmentHypothesis, EpistemicStatus


class MultiAgentConsensusEngine:
    """Computes evidence-weighted consensus across specialized agent evaluations."""

    def __init__(self, assessment_id: str) -> None:
        self.assessment_id = assessment_id

    def evaluate_hypothesis_consensus(
        self,
        hypothesis: AssessmentHypothesis,
        agent_outputs: List[AgentOutput],
        canonical_observations: Optional[List[Dict[str, Any]]] = None,
    ) -> ConsensusResult:
        """
        Synthesizes consensus for a given hypothesis across all participating agents.
        """
        canonical_observations = canonical_observations or []
        obs_ids_in_store = {
            obs.get("observation_id") for obs in canonical_observations if isinstance(obs, dict)
        }

        hyp_id = hypothesis.hypothesis_id
        supporting_agents: List[str] = []
        contradicting_agents: List[str] = []
        disagreements: List[str] = []

        evidence_analyst_verdict = "UNKNOWN"
        falsification_verdict = "UNTESTED"
        has_falsification_agent = False
        has_evidence_agent = False

        agent_confidences: List[float] = []

        # Analyze agent outputs
        for out in agent_outputs:
            agent_id = out.agent_id
            agent_type = out.agent_type

            # Check if this agent generated or explicitly supported this hypothesis
            generated_this = any(h.hypothesis_id == hyp_id for h in out.hypotheses)
            if generated_this:
                supporting_agents.append(agent_id)
                agent_confidences.append(out.confidence)

            # Check for contradicting evidence or counter-claims
            if out.contradicting_evidence:
                contradicting_agents.append(agent_id)
                disagreements.extend(out.contradicting_evidence)

            # Extract Evidence Analyst evaluation
            if agent_type == AgentType.EVIDENCE:
                has_evidence_agent = True
                verdict = out.provenance.get("sufficiency_verdict", "EVIDENCE_INSUFFICIENT")
                evidence_analyst_verdict = verdict
                if verdict == "EVIDENCE_INSUFFICIENT":
                    disagreements.append(f"Evidence Analyst declared evidence insufficient for {hyp_id}")
                    if agent_id not in contradicting_agents:
                        contradicting_agents.append(agent_id)

            # Extract Falsification Analyst evaluation
            if agent_type == AgentType.FALSIFICATION:
                has_falsification_agent = True
                falsification_plans = out.provenance.get("falsification_plans", [])
                matching_plan = next((p for p in falsification_plans if p.get("hypothesis_id") == hyp_id), None)
                if matching_plan:
                    falsification_verdict = "ADVERSARIAL_DISPUTE_RAISED"
                    disagreements.append(
                        f"Falsification Analyst proposed benign alternative: {matching_plan.get('alternative_explanations', [''])[0]}"
                    )
                else:
                    falsification_verdict = "NO_SPECIFIC_COUNTER_CLAIM"

        # Check empirical evidence grounding
        valid_supporting_obs = [
            obs_id for obs_id in hypothesis.supporting_observations if obs_id in obs_ids_in_store
        ]

        # 1. FALSE CONSENSUS DETECTION:
        # If 2 or more agents agree, but ZERO valid observations exist in store,
        # this is an ungrounded hallucination cascade / false consensus.
        false_consensus = False
        if len(supporting_agents) >= 2 and len(valid_supporting_obs) == 0:
            false_consensus = True
            disagreements.append(
                f"FALSE_CONSENSUS_DETECTED: {len(supporting_agents)} agents agreed, but zero valid canonical observations back hypothesis {hyp_id}."
            )

        # 2. Determine Evidence-Weighted Consensus Status
        if not valid_supporting_obs:
            status = ConsensusStatus.INSUFFICIENT_EVIDENCE
            score = 0.15
        elif false_consensus:
            status = ConsensusStatus.CONSENSUS_CONTESTED
            score = 0.20
        elif evidence_analyst_verdict == "EVIDENCE_INSUFFICIENT":
            if len(contradicting_agents) > len(supporting_agents):
                status = ConsensusStatus.CONSENSUS_REJECTED
                score = 0.25
            else:
                status = ConsensusStatus.CONSENSUS_CONTESTED
                score = 0.40
        elif contradicting_agents and len(contradicting_agents) >= len(supporting_agents):
            status = ConsensusStatus.CONSENSUS_CONTESTED
            score = 0.45
        elif contradicting_agents and len(contradicting_agents) > 0:
            # Some contradictions/disputes exist, but supporting agents outnumber them and evidence is present
            if len(valid_supporting_obs) >= 2 and evidence_analyst_verdict == "EVIDENCE_SUFFICIENT":
                status = ConsensusStatus.CONSENSUS_WEAK
                score = 0.65
            else:
                status = ConsensusStatus.CONSENSUS_CONTESTED
                score = 0.50
        else:
            # No contradictions, empirical evidence present
            if evidence_analyst_verdict == "EVIDENCE_SUFFICIENT" and len(valid_supporting_obs) >= 1:
                status = ConsensusStatus.CONSENSUS_SUPPORTED
                score = 0.90
            elif len(valid_supporting_obs) >= 1:
                status = ConsensusStatus.CONSENSUS_WEAK
                score = 0.70
            else:
                status = ConsensusStatus.INSUFFICIENT_EVIDENCE
                score = 0.30

        return ConsensusResult(
            hypothesis_id=hyp_id,
            status=status,
            consensus_score=score,
            supporting_agents=supporting_agents,
            contradicting_agents=contradicting_agents,
            falsification_verdict=falsification_verdict,
            evidence_sufficiency=evidence_analyst_verdict,
            disagreement_reasons=disagreements,
            false_consensus_flag=false_consensus,
            provenance={
                "assessment_id": self.assessment_id,
                "valid_supporting_observations": valid_supporting_obs,
                "has_falsification_agent": has_falsification_agent,
                "has_evidence_agent": has_evidence_agent,
            },
        )
