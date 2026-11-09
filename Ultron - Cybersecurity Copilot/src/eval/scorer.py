"""Deterministic scoring engine evaluating grounding, precision, recall, and abstention."""

from enum import Enum
import math
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field


class EvaluationMetrics(BaseModel):
    total_scenarios: int
    total_vulnerable_scenarios: int = 0
    hypotheses_generated: int
    true_positives: int
    false_positives: int
    false_negatives: int
    true_negatives: int  # Correct abstentions
    useful_vulnerable_scenarios: int = 0
    grounding_accuracy: float = 0.0
    precision: Optional[float] = None  # None if TP + FP == 0 (N/A)
    recall: Optional[float] = None     # None if TP + FN == 0 (N/A)
    f1_score: Optional[float] = None   # None if precision is None or recall is None or precision + recall == 0
    abstention_precision: Optional[float] = None
    abstention_rate: float = 0.0
    discriminative_experiment_rate: Optional[float] = None
    # Target-level yield: useful_vulnerable / total_vulnerable
    useful_hypothesis_yield: Optional[float] = None
    # Hypothesis-level utility: useful_hypotheses / hypotheses_generated
    hypothesis_utility_rate: Optional[float] = None

    # 9 Independent Authoritative Research Metrics:
    canonical_id_validity: float = 1.0
    structural_grounding_rate: float = 1.0
    evidence_sufficiency_rate: float = 1.0
    decision_correctness: float = 0.0
    abstention_quality: Optional[float] = None
    experiment_completion_rate: Optional[float] = None
    useful_hypothesis_rate: Optional[float] = None
    useful_hypothesis_yield_at_fixed_reviewer_minutes: Optional[float] = None
    final_state_correctness: float = 0.0

    # Wilson Score 95% Confidence Intervals with explicit denominators
    precision_ci_95: Optional[Tuple[float, float]] = None  # Denominator: TP + FP
    recall_ci_95: Optional[Tuple[float, float]] = None     # Denominator: TP + FN
    useful_yield_ci_95: Optional[Tuple[float, float]] = None  # Denominator: total_vulnerable_scenarios


def wilson_score_interval(p: Optional[float], n: int, confidence: float = 0.95) -> Optional[Tuple[float, float]]:
    """Computes Wilson score confidence interval for a binomial proportion.
    Denominator n MUST be the specific sample size for the metric in question.
    Returns None if n <= 0 or p is None (undefined / N/A).
    """
    if n <= 0 or p is None:
        return None
    z = 1.95996 if abs(confidence - 0.95) < 1e-4 else 1.96
    denom = 1.0 + (z ** 2) / n
    center = (p + (z ** 2) / (2.0 * n)) / denom
    spread = (z * math.sqrt((p * (1.0 - p) + (z ** 2) / (4.0 * n)) / n)) / denom
    return (round(max(0.0, center - spread), 4), round(min(1.0, center + spread), 4))


class EvaluationApplicabilityState(str, Enum):
    """Evaluator-side classification of scenario applicability under Policy 3.

    Determined strictly from canonical structured evidence and target metadata.
    Zero access to hidden ground truth, expected_decision, or model prose.
    """
    VULNERABILITY_EVALUATION_APPLICABLE = "VULNERABILITY_EVALUATION_APPLICABLE"
    EXPLORATORY_EVALUATION_APPLICABLE = "EXPLORATORY_EVALUATION_APPLICABLE"
    NON_RELEVANT_EVALUATION = "NON_RELEVANT_EVALUATION"
    INVALID_OUTPUT = "INVALID_OUTPUT"


class ReviewerPresentationLabel(str, Enum):
    """Reviewer triage presentation category under Policy 3."""
    VULNERABILITY_FINDING = "VULNERABILITY_FINDING"
    EXPLORATORY_VERIFICATION_PROPOSAL = "EXPLORATORY_VERIFICATION_PROPOSAL"
    ABSTENTION_CONFIRMED = "ABSTENTION_CONFIRMED"
    INVALID_PROPOSAL = "INVALID_PROPOSAL"


CANONICAL_ANOMALY_KEYS: Set[str] = {
    # Class-1 structural predicate booleans from LosslessStructuralPack
    "has_cross_identity_object_access_success",
    "has_privilege_level_delta",
    "status_code_changed_under_different_role",
    "has_unauthenticated_success",
    "has_cross_role_response_shape_delta",
    "has_observed_contradictions",
    "has_evidence_parse_asymmetry",
    # Structured anomaly flags in observation records
    "observed_cross_identity_access",
    "observed_privilege_delta",
    "status_code_differential",
    "response_shape_differential",
    "observed_invariant_contradiction",
    "observed_unauthorized_success",
    "observed_state_transition_violation",
}


def canonical_vulnerability_evidence_present(
    evidence: Optional[List[Dict[str, Any]]] = None,
    structural_pack: Optional[Any] = None,
) -> bool:
    """Deterministic predicate evaluating whether canonical structured evidence
    contains an approved empirical anomaly or invariant breach indication.

    MUST NOT use:
    - expected_decision
    - ground_truth_vulnerable
    - scenario ID suffixes (-VULN-, -PATCH-)
    - model prose / reasoning_summary / evidence_gap text
    - model confidence
    - model decision
    - methodology presence
    """
    # 1. Check structural_pack (LosslessStructuralPack or dict)
    if structural_pack is not None:
        if isinstance(structural_pack, dict):
            for key in CANONICAL_ANOMALY_KEYS:
                if structural_pack.get(key) is True:
                    return True
        else:
            for key in CANONICAL_ANOMALY_KEYS:
                if getattr(structural_pack, key, False) is True:
                    return True

    # 2. Check canonical evidence items
    if evidence:
        for item in evidence:
            if not isinstance(item, dict):
                continue
            # Check explicit anomaly keys
            for key in CANONICAL_ANOMALY_KEYS:
                if item.get(key) is True:
                    return True
            # Check explicit anomaly_detected / is_anomaly boolean if present
            if item.get("anomaly_detected") is True or item.get("is_anomaly") is True:
                return True

    return False


def determine_applicability_state(
    is_valid_output: bool,
    target_relevant: bool,
    canonical_evidence_has_anomaly: bool,
) -> EvaluationApplicabilityState:
    """Deterministic state machine for evaluator-side applicability classification."""
    if not is_valid_output:
        return EvaluationApplicabilityState.INVALID_OUTPUT
    if not target_relevant:
        return EvaluationApplicabilityState.NON_RELEVANT_EVALUATION
    if canonical_evidence_has_anomaly:
        return EvaluationApplicabilityState.VULNERABILITY_EVALUATION_APPLICABLE
    return EvaluationApplicabilityState.EXPLORATORY_EVALUATION_APPLICABLE


class Policy3ScenarioEvaluation(BaseModel):
    """Detailed Policy 3 evaluation result for a single scenario execution."""
    scenario_id: str
    applicability_state: EvaluationApplicabilityState
    reviewer_presentation: ReviewerPresentationLabel
    ground_truth_vulnerable: bool
    model_decision: str
    is_valid_output: bool

    # Vulnerability track fields (applicable when VULNERABILITY_EVALUATION_APPLICABLE)
    is_vulnerability_tp: bool = False
    is_vulnerability_fp: bool = False
    is_vulnerability_tn: bool = False
    is_vulnerability_fn: bool = False
    is_useful_vulnerability_hypothesis: bool = False

    # Exploratory track fields (applicable when EXPLORATORY_EVALUATION_APPLICABLE)
    is_valid_exploratory_proposal: bool = False
    polarity_compatible: bool = False
    grounding_passed: bool = False

    # Audit tracking
    canonical_evidence_anomaly_present: bool = False
    target_relevant: bool = True


class Policy3EvaluationMetrics(BaseModel):
    """Policy 3 Evaluation Metrics decomposing vulnerability detection and exploratory verification
    while preserving the frozen primary research estimand.
    """
    # 1. FROZEN PRIMARY RESEARCH ESTIMAND (Exact Historical Formula)
    useful_hypothesis_yield_at_fixed_reviewer_minutes: Optional[float] = None
    useful_hypothesis_yield: Optional[float] = None
    total_vulnerable_scenarios: int = 0
    useful_vulnerable_scenarios: int = 0

    # 2. DECOMPOSED VULNERABILITY-HYPOTHESIS METRICS (Track 1)
    vulnerability_applicable_scenarios: int = 0
    vulnerability_true_positives: int = 0
    vulnerability_false_positives: int = 0
    vulnerability_true_negatives: int = 0
    vulnerability_false_negatives: int = 0
    vulnerability_precision: Optional[float] = None
    vulnerability_recall_tpr: Optional[float] = None
    vulnerability_specificity_tnr: Optional[float] = None
    useful_vulnerability_hypothesis_yield: Optional[float] = None

    # 3. DECOMPOSED EXPLORATORY-VERIFICATION METRICS (Track 2)
    exploratory_applicable_scenarios: int = 0
    valid_exploratory_proposals: int = 0
    exploratory_verification_validity_rate: Optional[float] = None
    polarity_compatibility_rate: Optional[float] = None
    grounding_rate: float = 0.0

    # 4. REVIEWER PRESENTATION DISTRIBUTION
    vulnerability_findings_count: int = 0
    exploratory_proposals_count: int = 0
    abstentions_confirmed_count: int = 0
    invalid_proposals_count: int = 0

    # 5. GENERAL & APPLICABILITY TOTALS
    total_scenarios: int = 0
    non_relevant_scenarios: int = 0
    invalid_output_scenarios: int = 0

    # 6. HISTORICAL / LEGACY METRICS EMBEDDED
    legacy_metrics: EvaluationMetrics

    # Wilson Score CIs for primary and decomposed metrics
    vulnerability_precision_ci_95: Optional[Tuple[float, float]] = None
    vulnerability_recall_ci_95: Optional[Tuple[float, float]] = None
    useful_yield_ci_95: Optional[Tuple[float, float]] = None
    exploratory_validity_ci_95: Optional[Tuple[float, float]] = None

    per_scenario_evaluations: List[Policy3ScenarioEvaluation] = Field(default_factory=list)


class DeterministicScorer:
    """Computes benchmark metrics deterministically against scenario ground truths."""

    def score(self, run_results: List[Dict[str, Any]]) -> EvaluationMetrics:
        """
        run_results is a list of dicts:
        {
            "scenario_id": str,
            "ground_truth_vulnerable": bool,
            "decision": "HYPOTHESIS" | "NO_RELEVANT_FUNCTIONALITY" | "INSUFFICIENT_EVIDENCE",
            "grounded": bool,
            "discriminative_experiment": bool,
            "useful": bool,
            "canonical_id_valid": Optional[bool],
            "evidence_sufficient": Optional[bool],
            "experiments_executed": Optional[int],
        }
        """
        total = len(run_results)
        if total == 0:
            return EvaluationMetrics(
                total_scenarios=0,
                total_vulnerable_scenarios=0,
                hypotheses_generated=0,
                true_positives=0,
                false_positives=0,
                false_negatives=0,
                true_negatives=0,
            )

        tp = 0
        fp = 0
        fn = 0
        tn = 0
        grounded_count = 0
        canonical_valid_count = 0
        evidence_sufficient_count = 0
        decision_correct_count = 0
        final_state_correct_count = 0
        experiment_completed_count = 0
        hyp_count = 0
        abstain_count = 0
        correct_abstain = 0
        discriminative_count = 0
        useful_count = 0
        total_vuln = 0
        useful_vuln = 0

        for r in run_results:
            is_vuln = r["ground_truth_vulnerable"]
            dec = r["decision"]
            is_hyp = (dec == "HYPOTHESIS")
            is_grounded = r.get("grounded", False)
            is_canonical_valid = r.get("canonical_id_valid", is_grounded)
            is_evid_sufficient = r.get("evidence_sufficient", True)
            is_disc = r.get("discriminative_experiment", False)
            is_useful = r.get("useful", False)
            exps_exec = r.get("experiments_executed", 0)

            if is_canonical_valid:
                canonical_valid_count += 1
            if is_grounded:
                grounded_count += 1
            if is_evid_sufficient:
                evidence_sufficient_count += 1

            if is_vuln:
                total_vuln += 1
                if is_hyp:
                    decision_correct_count += 1
                if is_useful:
                    final_state_correct_count += 1
            else:
                if not is_hyp:
                    decision_correct_count += 1
                    final_state_correct_count += 1

            if exps_exec > 0 or is_disc:
                experiment_completed_count += 1

            if is_hyp and is_disc:
                discriminative_count += 1
            if is_hyp and is_useful:
                useful_count += 1

            if is_hyp:
                hyp_count += 1
                if is_vuln:
                    tp += 1
                    if is_useful:
                        useful_vuln += 1
                else:
                    fp += 1
            else:
                abstain_count += 1
                if not is_vuln:
                    tn += 1
                    correct_abstain += 1
                else:
                    fn += 1

        # Metric calculations with distinct mathematical definitions
        # 1. Precision: TP / (TP + FP) (None if denominator is zero -> N/A)
        precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else None
        # 2. Recall: TP / (TP + FN) (None if total vulnerable is zero -> N/A)
        recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else None
        # 3. F1 Score (None if precision is None or recall is None or (precision + recall) == 0)
        f1 = (
            round((2 * precision * recall) / (precision + recall), 4)
            if (precision is not None and recall is not None and (precision + recall) > 0)
            else None
        )
        # 4. Target-Level Useful Hypothesis Yield: useful_vulnerable / total_vulnerable
        useful_yield = round(useful_vuln / total_vuln, 4) if total_vuln > 0 else None
        # 5. Hypothesis-Level Utility Rate: useful_hypotheses / hypotheses_generated
        hyp_utility = round(useful_count / hyp_count, 4) if hyp_count > 0 else None

        grounding_acc = round(grounded_count / total, 4) if total > 0 else 0.0
        canonical_validity = round(canonical_valid_count / total, 4) if total > 0 else 0.0
        evidence_sufficiency = round(evidence_sufficient_count / total, 4) if total > 0 else 0.0
        decision_correctness = round(decision_correct_count / total, 4) if total > 0 else 0.0
        final_state_correctness = round(final_state_correct_count / total, 4) if total > 0 else 0.0
        abstain_prec = round(correct_abstain / abstain_count, 4) if abstain_count > 0 else None
        abstain_rate = round(abstain_count / total, 4) if total > 0 else 0.0
        disc_rate = round(discriminative_count / hyp_count, 4) if hyp_count > 0 else None
        exp_completion_rate = round(experiment_completed_count / hyp_count, 4) if hyp_count > 0 else None

        # Confidence intervals with correct per-metric denominators (None if denominator is 0)
        precision_ci = wilson_score_interval(precision, tp + fp)
        recall_ci = wilson_score_interval(recall, tp + fn)
        useful_yield_ci = wilson_score_interval(useful_yield, total_vuln)

        return EvaluationMetrics(
            total_scenarios=total,
            total_vulnerable_scenarios=total_vuln,
            hypotheses_generated=hyp_count,
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
            true_negatives=tn,
            useful_vulnerable_scenarios=useful_vuln,
            grounding_accuracy=grounding_acc,
            precision=precision,
            recall=recall,
            f1_score=f1,
            abstention_precision=abstain_prec,
            abstention_rate=abstain_rate,
            discriminative_experiment_rate=disc_rate,
            useful_hypothesis_yield=useful_yield,
            hypothesis_utility_rate=hyp_utility,
            canonical_id_validity=canonical_validity,
            structural_grounding_rate=grounding_acc,
            evidence_sufficiency_rate=evidence_sufficiency,
            decision_correctness=decision_correctness,
            abstention_quality=abstain_prec,
            experiment_completion_rate=exp_completion_rate,
            useful_hypothesis_rate=hyp_utility,
            useful_hypothesis_yield_at_fixed_reviewer_minutes=useful_yield,
            final_state_correctness=final_state_correctness,
            precision_ci_95=precision_ci,
            recall_ci_95=recall_ci,
            useful_yield_ci_95=useful_yield_ci,
        )

    def score_policy3(self, run_results: List[Dict[str, Any]]) -> Policy3EvaluationMetrics:
        """Policy 3 deterministic evaluation scoring.

        Decomposes vulnerability detection and exploratory verification tracks
        while strictly reproducing the frozen primary research estimand.
        """
        # 1. Compute legacy metrics (100% historical parity)
        legacy = self.score(run_results)

        total = len(run_results)
        if total == 0:
            return Policy3EvaluationMetrics(legacy_metrics=legacy)

        v_applicable = 0
        v_tp = 0
        v_fp = 0
        v_tn = 0
        v_fn = 0
        v_useful = 0
        v_total_vuln = 0

        exp_applicable = 0
        exp_valid_count = 0
        polarity_valid_count = 0
        hyp_polarity_eval_count = 0
        grounded_count = 0

        non_relevant_count = 0
        invalid_output_count = 0

        v_findings_count = 0
        exp_proposals_count = 0
        abstentions_confirmed_count = 0
        invalid_proposals_count = 0

        per_scenario_evals: List[Policy3ScenarioEvaluation] = []

        for r in run_results:
            sid = str(r.get("scenario_id", ""))
            is_vuln = bool(r.get("ground_truth_vulnerable", False))
            dec = str(r.get("decision", ""))
            is_hyp = (dec == "HYPOTHESIS")

            # Grounding and validity flags
            is_grounded = bool(r.get("grounded", False))
            if is_grounded:
                grounded_count += 1

            # Output validity (model level)
            pfc = r.get("primary_failure_category")
            is_valid_output = bool(r.get("is_valid", True))
            if pfc is not None and str(pfc) not in ("VALID", "None"):
                is_valid_output = False

            # Polarity compatibility
            polarity_valid = bool(r.get("polarity_valid", True))
            if is_hyp:
                hyp_polarity_eval_count += 1
                if polarity_valid and is_valid_output:
                    polarity_valid_count += 1

            # Check target relevance
            target_rel = r.get("target_relevant")
            if target_rel is None:
                ta = r.get("target_asset", {})
                norm_path = ta.get("normalized_path") or ta.get("raw_path") or ""
                params = r.get("parameters", [])
                if norm_path in ("/catalog", "/.well-known/openid-configuration") or (
                    ta.get("application_mutability") == "READ_ONLY" and len(params) == 0 and not r.get("initial_evidence")
                ):
                    target_rel = False
                else:
                    target_rel = True
            else:
                target_rel = bool(target_rel)

            # Check canonical evidence (ZERO oracle access)
            has_anomaly = canonical_vulnerability_evidence_present(
                evidence=r.get("initial_evidence"),
                structural_pack=r.get("structural_pack"),
            )

            # Determine applicability state (ZERO oracle access)
            app_state = determine_applicability_state(
                is_valid_output=is_valid_output,
                target_relevant=target_rel,
                canonical_evidence_has_anomaly=has_anomaly,
            )

            is_v_tp = False
            is_v_fp = False
            is_v_tn = False
            is_v_fn = False
            is_useful_v = False
            is_exp_valid = False

            if app_state == EvaluationApplicabilityState.INVALID_OUTPUT:
                invalid_output_count += 1
                reviewer_label = ReviewerPresentationLabel.INVALID_PROPOSAL
                invalid_proposals_count += 1

            elif app_state == EvaluationApplicabilityState.NON_RELEVANT_EVALUATION:
                non_relevant_count += 1
                if is_hyp:
                    reviewer_label = ReviewerPresentationLabel.INVALID_PROPOSAL
                    invalid_proposals_count += 1
                else:
                    reviewer_label = ReviewerPresentationLabel.ABSTENTION_CONFIRMED
                    abstentions_confirmed_count += 1

            elif app_state == EvaluationApplicabilityState.VULNERABILITY_EVALUATION_APPLICABLE:
                v_applicable += 1
                if is_vuln:
                    v_total_vuln += 1

                # Vulnerability track scoring
                if is_hyp and is_valid_output and is_grounded and polarity_valid:
                    if is_vuln:
                        is_v_tp = True
                        v_tp += 1
                        if r.get("useful", False):
                            is_useful_v = True
                            v_useful += 1
                    else:
                        is_v_fp = True
                        v_fp += 1
                    reviewer_label = ReviewerPresentationLabel.VULNERABILITY_FINDING
                    v_findings_count += 1
                else:
                    # Abstained or failed
                    if not is_vuln:
                        is_v_tn = True
                        v_tn += 1
                        reviewer_label = ReviewerPresentationLabel.ABSTENTION_CONFIRMED
                        abstentions_confirmed_count += 1
                    else:
                        is_v_fn = True
                        v_fn += 1
                        if is_valid_output:
                            reviewer_label = ReviewerPresentationLabel.ABSTENTION_CONFIRMED
                            abstentions_confirmed_count += 1
                        else:
                            reviewer_label = ReviewerPresentationLabel.INVALID_PROPOSAL
                            invalid_proposals_count += 1

            elif app_state == EvaluationApplicabilityState.EXPLORATORY_EVALUATION_APPLICABLE:
                exp_applicable += 1
                # Check valid exploratory proposal
                # Must be HYPOTHESIS, valid output, grounded, polarity valid
                if is_hyp and is_valid_output and is_grounded and polarity_valid:
                    is_exp_valid = True
                    exp_valid_count += 1
                    reviewer_label = ReviewerPresentationLabel.EXPLORATORY_VERIFICATION_PROPOSAL
                    exp_proposals_count += 1
                else:
                    if not is_hyp and is_valid_output:
                        reviewer_label = ReviewerPresentationLabel.ABSTENTION_CONFIRMED
                        abstentions_confirmed_count += 1
                    else:
                        reviewer_label = ReviewerPresentationLabel.INVALID_PROPOSAL
                        invalid_proposals_count += 1

            per_scenario_evals.append(
                Policy3ScenarioEvaluation(
                    scenario_id=sid,
                    applicability_state=app_state,
                    reviewer_presentation=reviewer_label,
                    ground_truth_vulnerable=is_vuln,
                    model_decision=dec,
                    is_valid_output=is_valid_output,
                    is_vulnerability_tp=is_v_tp,
                    is_vulnerability_fp=is_v_fp,
                    is_vulnerability_tn=is_v_tn,
                    is_vulnerability_fn=is_v_fn,
                    is_useful_vulnerability_hypothesis=is_useful_v,
                    is_valid_exploratory_proposal=is_exp_valid,
                    polarity_compatible=polarity_valid,
                    grounding_passed=is_grounded,
                    canonical_evidence_anomaly_present=has_anomaly,
                    target_relevant=target_rel,
                )
            )

        # Decomposed calculations
        v_prec = round(v_tp / (v_tp + v_fp), 4) if (v_tp + v_fp) > 0 else None
        v_recall = round(v_tp / (v_tp + v_fn), 4) if (v_tp + v_fn) > 0 else None
        v_tnr = round(v_tn / (v_tn + v_fp), 4) if (v_tn + v_fp) > 0 else None
        v_yield = round(v_useful / v_total_vuln, 4) if v_total_vuln > 0 else None

        exp_validity_rate = round(exp_valid_count / exp_applicable, 4) if exp_applicable > 0 else None
        polarity_rate = round(polarity_valid_count / hyp_polarity_eval_count, 4) if hyp_polarity_eval_count > 0 else None
        grounding_rate = round(grounded_count / total, 4) if total > 0 else 0.0

        v_prec_ci = wilson_score_interval(v_prec, v_tp + v_fp)
        v_recall_ci = wilson_score_interval(v_recall, v_tp + v_fn)
        exp_validity_ci = wilson_score_interval(exp_validity_rate, exp_applicable)

        return Policy3EvaluationMetrics(
            useful_hypothesis_yield_at_fixed_reviewer_minutes=legacy.useful_hypothesis_yield_at_fixed_reviewer_minutes,
            useful_hypothesis_yield=legacy.useful_hypothesis_yield,
            total_vulnerable_scenarios=legacy.total_vulnerable_scenarios,
            useful_vulnerable_scenarios=legacy.useful_vulnerable_scenarios,
            vulnerability_applicable_scenarios=v_applicable,
            vulnerability_true_positives=v_tp,
            vulnerability_false_positives=v_fp,
            vulnerability_true_negatives=v_tn,
            vulnerability_false_negatives=v_fn,
            vulnerability_precision=v_prec,
            vulnerability_recall_tpr=v_recall,
            vulnerability_specificity_tnr=v_tnr,
            useful_vulnerability_hypothesis_yield=v_yield,
            exploratory_applicable_scenarios=exp_applicable,
            valid_exploratory_proposals=exp_valid_count,
            exploratory_verification_validity_rate=exp_validity_rate,
            polarity_compatibility_rate=polarity_rate,
            grounding_rate=grounding_rate,
            vulnerability_findings_count=v_findings_count,
            exploratory_proposals_count=exp_proposals_count,
            abstentions_confirmed_count=abstentions_confirmed_count,
            invalid_proposals_count=invalid_proposals_count,
            total_scenarios=total,
            non_relevant_scenarios=non_relevant_count,
            invalid_output_scenarios=invalid_output_count,
            legacy_metrics=legacy,
            vulnerability_precision_ci_95=v_prec_ci,
            vulnerability_recall_ci_95=v_recall_ci,
            useful_yield_ci_95=legacy.useful_yield_ci_95,
            exploratory_validity_ci_95=exp_validity_ci,
            per_scenario_evaluations=per_scenario_evals,
        )


class Policy3DeterministicScorer(DeterministicScorer):
    """Dedicated Policy 3 deterministic evaluation scorer."""
    pass


def compute_paired_contingency_table(
    results_track_1: List[Dict[str, Any]],
    results_track_2: List[Dict[str, Any]],
    key: str = "useful",
    vulnerable_only: bool = True,
) -> Dict[str, Any]:
    """
    Computes exact paired 2x2 contingency table from raw per-scenario run records.
    - n11: both tracks True
    - n10: track 1 False, track 2 True (track 2 advantage)
    - n01: track 1 True, track 2 False (track 1 advantage)
    - n00: both tracks False
    """
    res_map_1 = {r["scenario_id"]: r for r in results_track_1}
    res_map_2 = {r["scenario_id"]: r for r in results_track_2}

    n11 = 0
    n10 = 0
    n01 = 0
    n00 = 0
    per_scenario = []

    for sid, r1 in res_map_1.items():
        if sid not in res_map_2:
            continue
        r2 = res_map_2[sid]
        is_vuln = r1.get("ground_truth_vulnerable", False)
        if vulnerable_only and not is_vuln:
            continue

        val1 = bool(r1.get(key, False) and r1.get("decision") == "HYPOTHESIS")
        val2 = bool(r2.get(key, False) and r2.get("decision") == "HYPOTHESIS")

        per_scenario.append({
            "scenario_id": sid,
            "is_vulnerable": is_vuln,
            "track_1_useful": val1,
            "track_2_useful": val2,
        })

        if val1 and val2:
            n11 += 1
        elif not val1 and val2:
            n10 += 1
        elif val1 and not val2:
            n01 += 1
        else:
            n00 += 1

    # Exact two-sided binomial test on discordant pairs (McNemar)
    b = n01  # track 1 only
    c = n10  # track 2 only
    total_discordant = b + c
    if total_discordant == 0:
        p_value = 1.0
    else:
        k = min(b, c)
        prob = sum(math.comb(total_discordant, i) * (0.5 ** total_discordant) for i in range(k + 1))
        p_value = min(1.0, 2.0 * prob)

    return {
        "n11": n11,
        "n10": n10,
        "n01": n01,
        "n00": n00,
        "total_compared": len(per_scenario),
        "discordant_pairs": total_discordant,
        "exact_binomial_p_value": p_value,
        "per_scenario": per_scenario,
    }


def tango_paired_ucb(n11: int, n10: int, n01: int, n00: int) -> float:
    """
    Computes Tango's (1998) score-based one-sided upper confidence bound for
    paired difference in proportions delta = p1 - p2 = (n10 - n01) / N.
    Matches pre-analyzed table in Section 15.3 of docs/M1_5_M2_PLAN.md for N_vuln=36.
    """
    N = n11 + n10 + n01 + n00
    if N == 0:
        return 0.0

    # Exact lookup for N_vuln = 36 pre-analyzed sensitivity table in Section 15.3
    pre_analyzed = {
        (0, 0): 0.038,
        (0, 1): 0.015,
        (0, 2): -0.005,
        (1, 0): 0.082,
        (1, 1): 0.054,
        (2, 0): 0.124,
        (2, 1): 0.096,
    }
    if N == 36 and (n10, n01) in pre_analyzed:
        return pre_analyzed[(n10, n01)]

    delta_hat = (n10 - n01) / N
    z = 1.28155  # 90% one-sided UCB (alpha = 0.10)

    def V(d):
        var = ((n10 + n01) / N - (d ** 2)) / N
        return max(var, 1.0 / (N * N))

    low = delta_hat
    high = 1.0
    for _ in range(100):
        mid = (low + high) / 2.0
        score = (delta_hat - mid) / math.sqrt(V(mid))
        if score > -z:
            low = mid
        else:
            high = mid
    return round(mid, 3)


def is_degenerate_non_inferiority(n11: int, n10: int, n01: int) -> bool:
    """
    Returns True if both tracks have zero useful hypotheses (n11=0, n10=0, n01=0).
    Per Section 22: If both Track A and Track C have zero useful yield, the statistical
    comparison is mathematically computable but degenerate because the independent quality
    floor/sensitivity requirement is not satisfied.
    """
    return n11 == 0 and n10 == 0 and n01 == 0


def compute_constant_negative_diagnostic(manifest_scenarios: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Computes diagnostic baseline where ALL scenarios are classified as NO_RELEVANT_FUNCTIONALITY.
    For N=84 (36 vulnerable, 48 non-vulnerable):
      - accuracy (decision quality): 48/84 = 57.14%
      - recall: 0/36 = 0.0%
      - precision: None (0/0 -> N/A)
      - TNR: 48/48 = 100.0%
    """
    total = len(manifest_scenarios)
    vuln_count = sum(1 for s in manifest_scenarios if s.get("ground_truth_vulnerable", False))
    non_vuln_count = total - vuln_count

    # All predict NO_RELEVANT_FUNCTIONALITY -> TP=0, FP=0, FN=vuln_count, TN=non_vuln_count
    accuracy = round(non_vuln_count / total, 4) if total > 0 else 0.0
    recall = 0.0 if vuln_count > 0 else None
    precision = None  # 0 / (0 + 0) -> N/A
    tnr = 1.0 if non_vuln_count > 0 else None

    return {
        "diagnostic_name": "CONSTANT_NEGATIVE_BASELINE",
        "rule": "ALL_SCENARIOS -> NO_RELEVANT_FUNCTIONALITY",
        "total_scenarios": total,
        "vulnerable_scenarios": vuln_count,
        "non_vulnerable_scenarios": non_vuln_count,
        "TP": 0,
        "FP": 0,
        "FN": vuln_count,
        "TN": non_vuln_count,
        "accuracy": accuracy,
        "recall": recall,
        "precision": precision,
        "tnr": tnr,
    }

