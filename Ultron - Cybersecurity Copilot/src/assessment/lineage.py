"""Auditable Evidence Lineage Graph for M6 Authorized Security Assessments.

Enforces:
1. Strict Provenance Chain:
   Observation -> Evidence -> Hypothesis -> Experiment -> Result -> Finding
2. Auditable lineage verification for every confirmed finding.
3. INVARIANT: A finding without an unbroken, valid evidence lineage must fail validation.
"""

from typing import Any, Dict, List, Optional, Set, Tuple
from src.assessment.models import (
    AssessmentFinding,
    AssessmentHypothesis,
    AssessmentExperiment,
    CanonicalObservation,
    AssessmentScopeStatus,
)


class LineageValidationError(Exception):
    """Raised when evidence lineage chain is incomplete, broken, or contains out-of-scope evidence."""
    pass


class EvidenceLineageGraph:
    """Manages and verifies the causal lineage DAG from raw observation to verified finding."""

    def __init__(self, assessment_id: str) -> None:
        self.assessment_id = assessment_id
        self._observations: Dict[str, CanonicalObservation] = {}
        self._hypotheses: Dict[str, AssessmentHypothesis] = {}
        self._experiments: Dict[str, AssessmentExperiment] = {}
        self._findings: Dict[str, AssessmentFinding] = {}

        # Edges
        self._obs_to_hyp: Dict[str, Set[str]] = {}  # obs_id -> set of hyp_ids
        self._hyp_to_exp: Dict[str, Set[str]] = {}  # hyp_id -> set of exp_ids
        self._exp_to_obs: Dict[str, Set[str]] = {}  # exp_id -> set of result obs_ids
        self._obs_to_find: Dict[str, Set[str]] = {} # obs_id -> set of find_ids
        self._hyp_to_find: Dict[str, Set[str]] = {} # hyp_id -> set of find_ids

        # M7 Multi-Agent Relationships
        # AGENT_ANALYZED, AGENT_SUPPORTS, AGENT_CONTRADICTS, AGENT_PROPOSED, AGENT_REFUTED, AGENT_DEPENDS_ON
        self._agent_relationships: List[Dict[str, str]] = []

    def register_agent_relationship(self, source_id: str, target_id: str, relationship: str) -> None:
        """Records an auditable relationship between an agent and an assessment entity."""
        valid_rels = {
            "AGENT_ANALYZED",
            "AGENT_SUPPORTS",
            "AGENT_CONTRADICTS",
            "AGENT_PROPOSED",
            "AGENT_REFUTED",
            "AGENT_DEPENDS_ON",
        }
        if relationship not in valid_rels:
            raise ValueError(f"Invalid agent relationship '{relationship}'. Must be one of {valid_rels}")
        self._agent_relationships.append({
            "source_id": source_id,
            "target_id": target_id,
            "relationship": relationship,
        })

    def register_agent_output(self, output: Any) -> None:
        """Extracts and registers causal lineage edges from a structured AgentOutput."""
        agent_id = getattr(output, "agent_id", str(output))
        # Hypotheses proposed
        for hyp in getattr(output, "hypotheses", []):
            h_id = getattr(hyp, "hypothesis_id", str(hyp))
            self.register_agent_relationship(agent_id, h_id, "AGENT_PROPOSED")
        # Experiments proposed
        for exp in getattr(output, "proposed_experiments", []):
            e_id = getattr(exp, "experiment_id", str(exp))
            self.register_agent_relationship(agent_id, e_id, "AGENT_PROPOSED")
        # Supporting evidence
        for supp in getattr(output, "supporting_evidence", []):
            self.register_agent_relationship(agent_id, supp, "AGENT_SUPPORTS")
        # Contradicting evidence
        for contra in getattr(output, "contradicting_evidence", []):
            self.register_agent_relationship(agent_id, contra, "AGENT_CONTRADICTS")

    def get_agent_relationships_for(self, item_id: str) -> List[Dict[str, str]]:
        """Returns all agent lineage relationships referencing the given item ID."""
        return [
            edge for edge in self._agent_relationships
            if edge["source_id"] == item_id or edge["target_id"] == item_id
        ]

    def register_observation(self, obs: CanonicalObservation) -> None:
        self._observations[obs.observation_id] = obs

    def register_hypothesis(self, hyp: AssessmentHypothesis) -> None:
        self._hypotheses[hyp.hypothesis_id] = hyp
        for obs_id in hyp.supporting_observations:
            if obs_id not in self._obs_to_hyp:
                self._obs_to_hyp[obs_id] = set()
            self._obs_to_hyp[obs_id].add(hyp.hypothesis_id)

    def register_experiment(self, exp: AssessmentExperiment) -> None:
        self._experiments[exp.experiment_id] = exp
        if exp.hypothesis_id not in self._hyp_to_exp:
            self._hyp_to_exp[exp.hypothesis_id] = set()
        self._hyp_to_exp[exp.hypothesis_id].add(exp.experiment_id)

    def register_finding(self, finding: AssessmentFinding, hypothesis_id: Optional[str] = None) -> None:
        self._findings[finding.finding_id] = finding
        for obs_id in finding.evidence:
            if obs_id not in self._obs_to_find:
                self._obs_to_find[obs_id] = set()
            self._obs_to_find[obs_id].add(finding.finding_id)
        if hypothesis_id:
            if hypothesis_id not in self._hyp_to_find:
                self._hyp_to_find[hypothesis_id] = set()
            self._hyp_to_find[hypothesis_id].add(finding.finding_id)

    def validate_lineage(self, finding: AssessmentFinding) -> Tuple[bool, List[str]]:
        """
        Validates complete unbroken lineage for a candidate finding.
        Returns (is_valid: bool, issues: List[str]).
        Fails closed on any gap or out-of-scope contamination.
        """
        issues = []

        if not finding.evidence:
            issues.append("LINEAGE_ERROR: Finding contains zero supporting evidence references.")
            return False, issues

        # Verify each evidence reference exists and is an in-scope observation
        valid_obs_count = 0
        for ev_id in finding.evidence:
            if ev_id not in self._observations:
                issues.append(f"LINEAGE_ERROR: Evidence ID '{ev_id}' not found in canonical observation store.")
                continue

            obs = self._observations[ev_id]
            if obs.scope_decision != AssessmentScopeStatus.IN_SCOPE:
                issues.append(
                    f"SCOPE_CONTAMINATION: Evidence '{ev_id}' is tagged '{obs.scope_decision.value}', "
                    f"cannot support a confirmed finding."
                )
                continue

            if obs.epistemic_status not in ("FACT", "OBSERVATION"):
                issues.append(
                    f"EPISTEMIC_CONTAMINATION: Evidence '{ev_id}' has epistemic status '{obs.epistemic_status}', "
                    f"must be FACT or OBSERVATION."
                )
                continue

            valid_obs_count += 1

        if valid_obs_count == 0:
            issues.append("LINEAGE_ERROR: Finding has no valid, in-scope canonical observations.")
            return False, issues

        # Verify hypothesis connection
        linked_hyp_ids = [
            h_id for h_id, f_set in self._hyp_to_find.items() if finding.finding_id in f_set
        ]
        if linked_hyp_ids:
            for hid in linked_hyp_ids:
                if hid not in self._hypotheses:
                    issues.append(f"LINEAGE_ERROR: Linked hypothesis '{hid}' does not exist.")

        return len(issues) == 0, issues
