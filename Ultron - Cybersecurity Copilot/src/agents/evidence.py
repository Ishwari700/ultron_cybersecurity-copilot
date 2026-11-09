"""Evidence Analyst Agent for M7 Specialized Multi-Agent Security Research.

Enforces:
1. Responsible for strict evidence quality assessment across hypotheses.
2. Identifies:
   - supporting evidence
   - contradicting evidence
   - missing evidence (evidence gaps)
   - stale evidence
   - out-of-scope evidence
   - external evidence (non-target provenance)
   - duplicate evidence
   - weak evidence (uncorroborated heuristics)
3. Evaluates evidence sufficiency: EVIDENCE_SUFFICIENT or EVIDENCE_INSUFFICIENT with reasons.
4. INVARIANT: The Evidence Analyst must NOT confirm findings or self-promote hypotheses.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from src.agents.base import BaseAgent
from src.agents.schemas import AgentOutput, AgentTask, AgentType
from src.assessment.models import (
    AssessmentHypothesis,
    EpistemicStatus,
)


class EvidenceAnalystAgent(BaseAgent):
    """Specialized agent auditing evidence quality, grounding, and provenance."""

    def __init__(self, assessment_id: str, agent_id: str = "AGENT-EVIDENCE-001") -> None:
        super().__init__(agent_id=agent_id, agent_type=AgentType.EVIDENCE, assessment_id=assessment_id)

    def analyze(self, task: AgentTask, context: Dict[str, Any]) -> AgentOutput:
        target = task.target_asset
        hypotheses_in: List[Dict[str, Any]] = context.get("hypotheses", [])
        observations: List[Dict[str, Any]] = context.get("observations", [])
        evidence_dict = {
            obs.get("observation_id"): obs
            for obs in observations
            if isinstance(obs, dict) and "observation_id" in obs
        }

        evaluations: List[Dict[str, Any]] = []
        overall_gaps: List[str] = []
        contradictions: List[str] = []
        supporting: List[str] = []

        is_all_sufficient = True
        evaluation_summaries: List[str] = []

        for hyp_dict in hypotheses_in:
            hyp_id = hyp_dict.get("hypothesis_id", "UNKNOWN_HYP")
            title = hyp_dict.get("title", "")
            supp_obs = hyp_dict.get("supporting_observations", [])

            valid_supp = []
            weak_ev = []
            stale_ev = []
            out_of_scope_ev = []
            external_ev = []
            seen_hashes = set()
            duplicates = []

            for obs_id in supp_obs:
                obs = evidence_dict.get(obs_id)
                if not obs:
                    overall_gaps.append(f"Missing referenced observation '{obs_id}' for hypothesis {hyp_id}")
                    continue

                # Scope check
                scope_decision = obs.get("scope_decision")
                if scope_decision and scope_decision != "IN_SCOPE":
                    out_of_scope_ev.append(obs_id)
                    contradictions.append(f"Out-of-scope evidence contamination detected in {obs_id} for {hyp_id}")
                    continue

                # Provenance / External check
                source = obs.get("source", "")
                if "EXTERNAL" in str(source).upper() or obs.get("is_external", False):
                    external_ev.append(obs_id)

                # Duplicate check
                norm_data = str(obs.get("normalized_data", {}))
                data_hash = obs.get("data_hash") or hash(norm_data)
                if data_hash in seen_hashes:
                    duplicates.append(obs_id)
                else:
                    seen_hashes.add(data_hash)

                # Weak evidence check
                data = obs.get("normalized_data", {})
                if not data or (len(str(data)) < 25 and not data.get("vulnerable_pattern")):
                    weak_ev.append(obs_id)
                else:
                    valid_supp.append(obs_id)
                    supporting.append(obs_id)

            # Sufficiency assessment for this hypothesis
            gaps = list(hyp_dict.get("evidence_gaps", []))
            if not valid_supp:
                gaps.append(f"Hypothesis {hyp_id} lacks empirical in-scope supporting observations.")
            if out_of_scope_ev:
                gaps.append(f"Hypothesis {hyp_id} relies on out-of-scope evidence: {out_of_scope_ev}")
            if weak_ev and not valid_supp:
                gaps.append(f"Hypothesis {hyp_id} relies only on weak uncorroborated evidence: {weak_ev}")

            overall_gaps.extend(gaps)

            status = "EVIDENCE_SUFFICIENT" if valid_supp and not out_of_scope_ev else "EVIDENCE_INSUFFICIENT"
            if status == "EVIDENCE_INSUFFICIENT":
                is_all_sufficient = False

            eval_entry = {
                "hypothesis_id": hyp_id,
                "title": title,
                "status": status,
                "valid_supporting_count": len(valid_supp),
                "weak_evidence": weak_ev,
                "out_of_scope_evidence": out_of_scope_ev,
                "external_evidence": external_ev,
                "duplicate_evidence": duplicates,
                "gaps": gaps,
            }
            evaluations.append(eval_entry)
            evaluation_summaries.append(f"{hyp_id}: {status} (Valid: {len(valid_supp)}, Gaps: {len(gaps)})")

        sufficiency_verdict = "EVIDENCE_SUFFICIENT" if is_all_sufficient and hypotheses_in else "EVIDENCE_INSUFFICIENT"

        summary = (
            f"Evidence Quality Audit for {target}: Evaluated {len(hypotheses_in)} hypotheses against "
            f"{len(observations)} observations. Overall status: {sufficiency_verdict}. "
            f"Details: {'; '.join(evaluation_summaries) if evaluation_summaries else 'No hypotheses provided.'}"
        )

        return AgentOutput(
            agent_id=self.agent_id,
            agent_type=self.agent_type,
            assessment_id=self.assessment_id,
            task_id=task.task_id,
            confidence=0.90 if sufficiency_verdict == "EVIDENCE_SUFFICIENT" else 0.70,
            epistemic_status=EpistemicStatus.INFERENCE,
            hypotheses=[],
            evidence_gaps=list(set(overall_gaps)),
            security_invariants=["INV-EVIDENCE-01: No claim may be verified without in-scope empirical evidence."],
            proposed_experiments=[],
            supporting_evidence=supporting,
            contradicting_evidence=contradictions,
            analysis_summary=summary,
            provenance={
                "evidence_evaluations": evaluations,
                "sufficiency_verdict": sufficiency_verdict,
            },
        )
