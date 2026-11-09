"""M3 Controlled Retrieval -> Reasoning Evaluation Engine.

Executes and measures:
- Configuration A: No RAG (Target Evidence -> 3B -> 7B)
- Configuration B: FTS5 (Target Evidence -> FTS5 -> Knowledge Pack -> 3B -> 7B)
- Configuration C: Old Baseline (Target Evidence -> Pseudo-Dense MD5 + FTS5 -> Knowledge Pack -> 3B -> 7B)
- Configuration D: MiniLM Hybrid (Target Evidence -> MiniLM + FTS5 + RRF -> Knowledge Pack -> 3B -> 7B)
- Configuration E: MiniLM Dense Only (Target Evidence -> MiniLM Dense -> Knowledge Pack -> 3B -> 7B)

Compares:
- 3B-only Triage vs 3B -> 7B Cascade
- Evaluates across all 7 reasoning rubric dimensions (0-4 scale) and unsupported claim rates
- Measures retrieval latencies, inference latencies, escalation rates, and resource usage
"""

import json
import logging
from pathlib import Path
import re
import statistics
import time
from typing import Any, Dict, List, Optional, Tuple

from src.engine.context_builder import ReasoningContextBuilder
from src.engine.models import OutputProtocolIdentifier
from src.engine.reasoning_runner import Live7BReasoningRunner
from src.engine.router import DeterministicRouter
from src.engine.triage_runner import Live3BTriageRunner
from src.eval.m3_reasoning_schema import (
    DifficultyLevel,
    M3CaseEvaluationResult,
    M3ConfigurationSummary,
    M3ReasoningCase,
    M3ReasoningDataset,
    M3ReasoningOutput,
    M3ScoringRubric,
    ReasoningDecision,
    RetrievalConfigId,
)
from src.evidence.cascade_models import (
    CascadeHandoffPacket,
    LosslessStructuralPack,
)
from src.evidence.gate import EvidencePreservationGate
from src.evidence.provenance import compute_provenance_hash
from src.knowledge.minilm_retriever import (
    MiniLmDenseOnlyRetriever,
    MiniLmVectorFts5Retriever,
)
from src.knowledge.models import KnowledgeRetrievalItem, VaptKnowledgePack
from src.knowledge.retriever import (
    BaseKnowledgeRetriever,
    OnnxVectorFts5Retriever,
)
from src.knowledge.serializer import ProductionP4Serializer
from src.knowledge.store import VaptKnowledgeStore

logger = logging.getLogger("m3.evaluator")


class Fts5OnlyRetriever(BaseKnowledgeRetriever):
    """Pure SQLite FTS5 lexical BM25 retriever for Configuration B."""
    candidate_id: str = "Candidate FTS5 Only"
    candidate_name: str = "Pure SQLite FTS5 Lexical Search"
    is_dense: bool = False
    is_sparse: bool = True

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.store = VaptKnowledgeStore(self.db_path, read_only=True)

    def retrieve(
        self,
        query: str,
        top_k: int = 5,
        theta_min: float = 0.0,
        query_id: str = "",
    ) -> List[KnowledgeRetrievalItem]:
        raw_hits = self.store.query_lexical(query, top_k=top_k)
        results: List[KnowledgeRetrievalItem] = []
        rank = 1
        for chunk, score in raw_hits:
            if score < theta_min:
                continue
            item = KnowledgeRetrievalItem(
                chunk=chunk,
                dense_score=0.0,
                sparse_score=float(score),
                fused_score=float(score),
                retrieval_rank=rank,
                query_id=query_id,
            )
            results.append(item)
            rank += 1
        return results

    def close(self) -> None:
        self.store.close()

    def get_provenance_metadata(self) -> Dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "candidate_name": self.candidate_name,
            "backend_type": "sqlite_fts5_bm25",
            "db_path": str(self.db_path),
        }


def score_reasoning_output(
    case: M3ReasoningCase,
    output: M3ReasoningOutput,
    is_3b_only: bool = False,
) -> M3ScoringRubric:
    """
    Score a structured reasoning output against the frozen gold case expectations.
    Enforces a strict 0.0 - 4.0 point scale across all 7 dimensions.
    """
    combined_text = (
        f"{output.hypothesis} {output.security_invariant} {output.evidence_gap or ''} "
        f"{output.manual_experiment} {output.falsification} {output.raw_response}"
    ).lower()

    # 1. Hypothesis Correctness (0 - 4)
    hyp_score = 0.0
    dec_str = output.decision.upper()
    exp_dec_str = case.expected_decision.value.upper()

    if case.is_negative_control:
        # For negative control, reporting HYPOTHESIS is a severe false alarm
        if dec_str == "NO_RELEVANT_FUNCTIONALITY":
            hyp_score = 4.0
        elif dec_str == "INSUFFICIENT_EVIDENCE":
            hyp_score = 2.5
        else:
            hyp_score = 0.0
    else:
        # For vulnerable or gap cases
        if dec_str == exp_dec_str:
            hyp_score += 2.0
        elif dec_str == "HYPOTHESIS" and exp_dec_str == "INSUFFICIENT_EVIDENCE":
            hyp_score += 1.0
        elif dec_str == "INSUFFICIENT_EVIDENCE" and exp_dec_str == "HYPOTHESIS":
            hyp_score += 1.0

        # Check concept alignment
        concept_terms = [
            t.lower()
            for t in re.split(r"\W+", case.expected_security_concept)
            if len(t) > 3 and t.lower() not in ("cwe", "broken", "level", "access", "control")
        ]
        if any(term in combined_text for term in concept_terms):
            hyp_score += 1.0
        elif case.security_domain.lower() in combined_text:
            hyp_score += 0.5

        # Check target endpoint/route reference
        route = case.target_evidence.get("route_template", "").lower()
        if route and route in combined_text:
            hyp_score += 1.0
        elif case.target_evidence.get("asset_id", "").lower() in combined_text:
            hyp_score += 0.5

    hyp_score = min(4.0, max(0.0, hyp_score))

    # 2. Evidence Grounding (0 - 4)
    ground_score = 2.0
    valid_fact_ids = {
        f.get("fact_id")
        for f in case.target_evidence.get("observed_facts", [])
        if f.get("fact_id")
    }
    cited_facts = set(output.empirical_facts)

    if cited_facts:
        unsupported_facts = cited_facts - valid_fact_ids
        if not unsupported_facts and cited_facts.issubset(valid_fact_ids):
            ground_score += 1.5
        elif unsupported_facts:
            ground_score -= min(2.0, len(unsupported_facts) * 0.5)

    # Check for hallucinated attack vectors not in evidence
    hallucinated_vectors = ["sql injection", "sqli", "cross-site scripting", "xss", "ssrf", "remote code execution", "rce"]
    for vec in hallucinated_vectors:
        if vec in combined_text and vec not in case.expected_security_concept.lower():
            ground_score -= 1.0

    ground_score = min(4.0, max(0.0, ground_score))

    # 3. Evidence-Gap Quality (0 - 4)
    gap_score = 2.0
    if case.is_evidence_gap:
        if dec_str == "INSUFFICIENT_EVIDENCE":
            gap_score = 3.5
            # Bonus if evidence_gap field explicitly mentions missing evidence
            if output.evidence_gap and len(output.evidence_gap.strip()) > 10:
                gap_score = 4.0
        else:
            # Overclaimed hypothesis on evidence gap
            gap_score = 1.0
    else:
        # On normal case, correctly identifying evidence completeness or minor gap is acceptable
        if output.evidence_gap:
            gap_score = 3.0
        else:
            gap_score = 3.5

    # 4. Security Invariant Correctness (0 - 4)
    inv_score = 1.0
    inv_keywords = ["invariant", "tenant", "authorization", "ownership", "boundary", "isolation", "role", "permission", "capability", "immutable", "public"]
    matched_inv_kw = sum(1 for kw in inv_keywords if kw in (output.security_invariant or "").lower())
    if matched_inv_kw >= 3:
        inv_score = 4.0
    elif matched_inv_kw >= 2:
        inv_score = 3.0
    elif matched_inv_kw >= 1:
        inv_score = 2.0
    else:
        inv_score = 1.0

    # 5. Experiment Quality (0 - 4)
    exp_score = 1.0
    if case.is_negative_control:
        # Negative control does not require offensive testing
        exp_score = 4.0
    else:
        exp_text = output.manual_experiment.lower()
        action_indicators = ["request", "send", "substitute", "replace", "token", "header", "get", "post", "parameter", "replay", "compare", "verify", "observe"]
        matched_actions = sum(1 for a in action_indicators if a in exp_text)
        if matched_actions >= 4 and len(exp_text) > 30:
            exp_score = 4.0
        elif matched_actions >= 2:
            exp_score = 3.0
        elif matched_actions >= 1:
            exp_score = 2.0
        else:
            exp_score = 1.0

    # 6. Falsification Quality (0 - 4)
    fals_score = 1.0
    fals_text = (f"{output.falsification} {output.expected_secure_result}").lower()
    disproof_indicators = ["403", "404", "401", "forbidden", "denied", "reject", "unauthorized", "fail", "disprove", "error"]
    matched_disproof = sum(1 for d in disproof_indicators if d in fals_text)
    if matched_disproof >= 2 and len(fals_text) > 15:
        fals_score = 4.0
    elif matched_disproof >= 1:
        fals_score = 3.0
    elif "not" in fals_text:
        fals_score = 2.0
    else:
        fals_score = 1.0

    # 7. False-Positive Resistance (0 - 4)
    fp_score = 4.0
    if case.is_negative_control:
        if dec_str == "NO_RELEVANT_FUNCTIONALITY":
            fp_score = 4.0
        elif dec_str == "INSUFFICIENT_EVIDENCE":
            fp_score = 2.5
        else:
            fp_score = 0.0  # False alarm
    elif case.is_evidence_gap:
        if dec_str == "INSUFFICIENT_EVIDENCE":
            fp_score = 4.0
        elif dec_str == "HYPOTHESIS":
            fp_score = 1.5

    # 8. Unsupported Claim Rate
    unsupported_count = 0
    for forbidden in case.forbidden_or_unsupported_conclusions:
        # Check if words from forbidden conclusion are asserted
        keywords = [w.lower() for w in re.split(r"\W+", forbidden) if len(w) > 4]
        if keywords and all(kw in combined_text for kw in keywords[:2]):
            unsupported_count += 1

    total_claims = max(1, len(output.empirical_facts) + 2)
    unsupported_rate = round(unsupported_count / total_claims, 4)

    return M3ScoringRubric(
        hypothesis_correctness=round(hyp_score, 2),
        evidence_grounding=round(ground_score, 2),
        evidence_gap_quality=round(gap_score, 2),
        security_invariant_correctness=round(inv_score, 2),
        experiment_quality=round(exp_score, 2),
        falsification_quality=round(fals_score, 2),
        false_positive_resistance=round(fp_score, 2),
        unsupported_claim_count=unsupported_count,
        total_claims_count=total_claims,
        unsupported_claim_rate=unsupported_rate,
    )


class M3ReasoningEvaluator:
    """
    Controlled evaluation harness testing VAPT retrieval impact on 3B and 7B reasoning.
    """

    def __init__(
        self,
        db_path: Path = Path("data/vapt_corpus/vapt_knowledge.db"),
        index_path: Path = Path("data/vapt_corpus/vapt_knowledge_minilm.index"),
        ollama_url: str = "http://127.0.0.1:11434",
    ) -> None:
        self.db_path = Path(db_path)
        self.index_path = Path(index_path)
        self.ollama_url = ollama_url

        self.serializer = ProductionP4Serializer()
        self.triage_runner = Live3BTriageRunner(ollama_url=self.ollama_url)
        self.reasoning_runner = Live7BReasoningRunner(ollama_url=self.ollama_url)

        # Initialize candidate retrievers
        self.retrievers: Dict[str, Optional[BaseKnowledgeRetriever]] = {
            RetrievalConfigId.CONFIG_A_NO_RAG.value: None,
            RetrievalConfigId.CONFIG_B_FTS5.value: Fts5OnlyRetriever(self.db_path),
            RetrievalConfigId.CONFIG_C_OLD_BASELINE.value: OnnxVectorFts5Retriever(self.db_path),
            RetrievalConfigId.CONFIG_D_MINILM_HYBRID.value: MiniLmVectorFts5Retriever(self.db_path, self.index_path),
            RetrievalConfigId.CONFIG_E_MINILM_DENSE.value: MiniLmDenseOnlyRetriever(self.db_path, self.index_path),
        }

    def _convert_case_to_structural_pack(self, case: M3ReasoningCase) -> LosslessStructuralPack:
        """Construct LosslessStructuralPack from target evidence dict."""
        te = case.target_evidence
        raw_auth_delta = te.get("auth_header_delta", False)
        auth_delta_bool = bool(raw_auth_delta and raw_auth_delta != "None") if isinstance(raw_auth_delta, str) else bool(raw_auth_delta)

        return LosslessStructuralPack(
            asset_id=te.get("asset_id", "ASSET-UNKNOWN"),
            endpoint_id=te.get("endpoint_id", "EP-UNKNOWN"),
            route_template=te.get("route_template", "/api/v1/unknown"),
            http_method=te.get("http_method", "GET"),
            application_mutability=te.get("application_mutability", "READ"),
            observed_facts=te.get("observed_facts", []),
            parameter_lineage=te.get("parameter_lineage", []),
            has_cross_identity_object_access_success=te.get("has_cross_identity_object_access_success", False),
            has_privilege_level_delta=te.get("has_privilege_level_delta", False),
            has_unauthenticated_success=te.get("has_unauthenticated_success", False),
            status_code_changed_under_different_role=te.get("status_code_changed_under_different_role", False),
            has_cross_role_response_shape_delta=te.get("has_cross_role_response_shape_delta", False),
            has_evidence_parse_asymmetry=te.get("has_evidence_parse_asymmetry", False),
            auth_header_delta=auth_delta_bool,
        )

    def evaluate_case(
        self,
        case: M3ReasoningCase,
        config_id: str,
        force_cascade_to_7b: bool = True,
    ) -> Tuple[M3CaseEvaluationResult, Optional[M3CaseEvaluationResult]]:
        """
        Evaluate a single case under specified retrieval configuration.
        Returns (cascade_result, triage_only_result).
        """
        channel_a = self._convert_case_to_structural_pack(case)
        retriever = self.retrievers.get(config_id)

        # 1. Retrieval Channel
        retrieved_items: List[KnowledgeRetrievalItem] = []
        ret_latency_ms = 0.0
        vapt_pack: Optional[VaptKnowledgePack] = None

        if retriever is not None:
            t0 = time.perf_counter()
            retrieved_items = retriever.retrieve(case.user_query, top_k=3, theta_min=0.0)
            ret_latency_ms = (time.perf_counter() - t0) * 1000.0

            if retrieved_items:
                vapt_pack = self.serializer.build_knowledge_pack(
                    retrieval_items=retrieved_items,
                    token_budget=256,
                    retrieval_query=case.user_query,
                )

        retrieved_chunk_ids = [item.chunk.chunk_id for item in retrieved_items]

        # 2. Stage 1: 3B Preliminary Triage
        t0 = time.perf_counter()
        raw_triage = self.triage_runner.run_triage(channel_a)
        triage_duration_s = time.perf_counter() - t0

        # Construct 3B-only output
        triage_decision_mapped = "HYPOTHESIS"
        if raw_triage and raw_triage.decision:
            if "BENIGN" in raw_triage.decision:
                triage_decision_mapped = "NO_RELEVANT_FUNCTIONALITY"
            elif "SUSPECTED" in raw_triage.decision or "IMPACT" in raw_triage.decision:
                triage_decision_mapped = "HYPOTHESIS"
            else:
                triage_decision_mapped = "INSUFFICIENT_EVIDENCE"

        output_3b = M3ReasoningOutput(
            hypothesis=raw_triage.triage_rationale if raw_triage else "3B triage failed",
            security_invariant=f"Suspected Category: {raw_triage.suspected_category if raw_triage else 'None'}",
            evidence_gap=None,
            manual_experiment=f"Suggested class: {raw_triage.suggested_experiment_class if raw_triage else 'None'}",
            expected_secure_result="403 Forbidden",
            expected_vulnerable_result="200 OK",
            falsification="Test rejects unauthorized mutation",
            decision=triage_decision_mapped,
            confidence=0.75 if (raw_triage and not raw_triage.is_malformed) else 0.0,
            empirical_facts=[f["fact_id"] for f in channel_a.observed_facts if "fact_id" in f],
            methodology_references=[],
            raw_response=raw_triage.triage_rationale if raw_triage else "",
        )
        scores_3b = score_reasoning_output(case, output_3b, is_3b_only=True)
        res_3b_only = M3CaseEvaluationResult(
            reasoning_case_id=case.reasoning_case_id,
            configuration_id=config_id,
            execution_pipeline="3B_ONLY",
            model_3b="qwen2.5-coder:3b",
            model_7b=None,
            escalated_to_7b=False,
            retrieved_chunk_ids=retrieved_chunk_ids,
            retrieval_latency_ms=round(ret_latency_ms, 2),
            inference_latency_3b_s=round(triage_duration_s, 3),
            inference_latency_7b_s=0.0,
            total_latency_s=round(triage_duration_s, 3),
            structured_output=output_3b,
            scores=scores_3b,
            decision_match=(output_3b.decision == case.expected_decision.value),
            evaluation_notes=f"3B triage decision: {raw_triage.decision if raw_triage else 'None'}",
        )

        # 3. Stage 2: Gate & Deterministic Routing
        gate_res = EvidencePreservationGate.validate(channel_a=channel_a, raw_triage=raw_triage)
        routing_decision = DeterministicRouter.evaluate_escalation(diff=channel_a, gate_result=gate_res)

        escalate = routing_decision.escalate or force_cascade_to_7b

        # 4. Stage 3: Handoff & 7B Deep Reasoning
        res_7b: Optional[M3CaseEvaluationResult] = None
        if escalate:
            p_hash = compute_provenance_hash(channel_a, gate_res, routing_decision)
            handoff = CascadeHandoffPacket(
                schema_version="2.0.0",
                channel_a_structural=channel_a,
                routing_decision=routing_decision,
                provenance_hash=p_hash,
                validated_triage=gate_res.validated_triage,
            )

            # Assemble Context using ReasoningContextBuilder
            cascade_mode = "TRACK_D" if vapt_pack is not None else "TRACK_B"
            ctx = ReasoningContextBuilder.build_context(
                handoff_packet=handoff,
                model_identifier="qwen2.5-coder:7b",
                cascade_mode=cascade_mode,
                vapt_pack=vapt_pack,
                enable_i2_namespace_partitioning=True,
                output_protocol=OutputProtocolIdentifier.JSON_BAIR,
            )

            t0 = time.perf_counter()
            run_7b_out = self.reasoning_runner.run_reasoning(ctx, channel_a=channel_a)
            infer_7b_s = time.perf_counter() - t0

            # Parse structured hypothesis
            hyp_dict = run_7b_out.get("hypothesis") or {}
            output_7b = M3ReasoningOutput(
                hypothesis=hyp_dict.get("reasoning_summary") or hyp_dict.get("falsification_description") or hyp_dict.get("invariant") or "7B execution succeeded",
                security_invariant=hyp_dict.get("invariant", ""),
                evidence_gap=hyp_dict.get("evidence_gap"),
                manual_experiment=hyp_dict.get("falsification_description") or hyp_dict.get("experiment_proposal") or "",
                expected_secure_result=str(hyp_dict.get("disproving_outcome", "403 Forbidden")),
                expected_vulnerable_result=str(hyp_dict.get("supporting_outcome", "200 OK")),
                falsification=str(hyp_dict.get("disproving_outcome", "")) + " " + str(hyp_dict.get("falsification_description", "")),
                decision=str(hyp_dict.get("decision", "HYPOTHESIS")).upper(),
                confidence=0.85 if run_7b_out.get("status") == "SUCCESS" else 0.0,
                empirical_facts=hyp_dict.get("empirical_facts", []) or hyp_dict.get("supporting_evidence_ids", []),
                methodology_references=hyp_dict.get("methodology_references", []),
                reasoning_trace_metadata=hyp_dict,
                raw_response=run_7b_out.get("raw_response", ""),
            )

            scores_7b = score_reasoning_output(case, output_7b, is_3b_only=False)
            total_lat = triage_duration_s + infer_7b_s + (ret_latency_ms / 1000.0)

            res_7b = M3CaseEvaluationResult(
                reasoning_case_id=case.reasoning_case_id,
                configuration_id=config_id,
                execution_pipeline="CASCADE_3B_7B",
                model_3b="qwen2.5-coder:3b",
                model_7b="qwen2.5-coder:7b",
                escalated_to_7b=True,
                retrieved_chunk_ids=retrieved_chunk_ids,
                retrieval_latency_ms=round(ret_latency_ms, 2),
                inference_latency_3b_s=round(triage_duration_s, 3),
                inference_latency_7b_s=round(infer_7b_s, 3),
                total_latency_s=round(total_lat, 3),
                structured_output=output_7b,
                scores=scores_7b,
                decision_match=(output_7b.decision == case.expected_decision.value),
                evaluation_notes=f"7B decision: {output_7b.decision}",
            )
        else:
            res_7b = res_3b_only

        return res_7b, res_3b_only

    def evaluate_configuration(
        self,
        dataset: M3ReasoningDataset,
        config_id: str,
        config_name: str,
    ) -> Tuple[M3ConfigurationSummary, List[M3CaseEvaluationResult], List[M3CaseEvaluationResult]]:
        """
        Evaluate all cases in dataset under given configuration.
        Returns (summary, cascade_results, triage_results).
        """
        cascade_results: List[M3CaseEvaluationResult] = []
        triage_results: List[M3CaseEvaluationResult] = []

        logger.info(f"Evaluating {config_id} ({config_name}) across {dataset.total_cases} cases...")
        for case in dataset.cases:
            c_res, t_res = self.evaluate_case(case, config_id=config_id)
            cascade_results.append(c_res)
            if t_res:
                triage_results.append(t_res)

        # Compute summary metrics for cascade_results
        n = len(cascade_results)
        comp_scores = [r.scores.composite_reasoning_score for r in cascade_results]
        hyp_scores = [r.scores.hypothesis_correctness for r in cascade_results]
        gnd_scores = [r.scores.evidence_grounding for r in cascade_results]
        gap_scores = [r.scores.evidence_gap_quality for r in cascade_results]
        inv_scores = [r.scores.security_invariant_correctness for r in cascade_results]
        exp_scores = [r.scores.experiment_quality for r in cascade_results]
        fals_scores = [r.scores.falsification_quality for r in cascade_results]
        fp_scores = [r.scores.false_positive_resistance for r in cascade_results]
        unsupp_rates = [r.scores.unsupported_claim_rate for r in cascade_results]
        dec_matches = sum(1 for r in cascade_results if r.decision_match)
        escalations = sum(1 for r in cascade_results if r.escalated_to_7b)
        ret_lats = [r.retrieval_latency_ms for r in cascade_results]
        tot_lats = [r.total_latency_s for r in cascade_results]

        summary = M3ConfigurationSummary(
            configuration_id=config_id,
            configuration_name=config_name,
            execution_pipeline="CASCADE_3B_7B",
            total_cases=n,
            mean_composite_score=round(statistics.mean(comp_scores), 3),
            mean_hypothesis_correctness=round(statistics.mean(hyp_scores), 3),
            mean_evidence_grounding=round(statistics.mean(gnd_scores), 3),
            mean_evidence_gap_quality=round(statistics.mean(gap_scores), 3),
            mean_security_invariant_correctness=round(statistics.mean(inv_scores), 3),
            mean_experiment_quality=round(statistics.mean(exp_scores), 3),
            mean_falsification_quality=round(statistics.mean(fals_scores), 3),
            mean_false_positive_resistance=round(statistics.mean(fp_scores), 3),
            mean_unsupported_claim_rate=round(statistics.mean(unsupp_rates), 4),
            decision_accuracy=round(dec_matches / n, 4),
            escalation_rate=round(escalations / n, 4),
            mean_retrieval_latency_ms=round(statistics.mean(ret_lats), 2),
            mean_reasoning_latency_s=round(statistics.mean(tot_lats), 3),
        )

        return summary, cascade_results, triage_results
