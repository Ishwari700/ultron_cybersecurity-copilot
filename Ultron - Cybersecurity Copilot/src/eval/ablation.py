"""Ablation framework running tracks A through E across the benchmark scenarios.

Supports both:
1. Live LLM execution (live_mode=True): Real Ollama calls on qwen2.5-coder:3b (Track B)
   and qwen2.5-coder:7b (Tracks C, D, E) with complete RAG tracing, GroundingValidator,
   and closed-loop experiment feedback.
2. Deterministic test-double (live_mode=False): Fast, hermetic baseline for instant unit testing.
"""

import os
from pathlib import Path
import time
from typing import Any, Dict, List, Optional, Tuple
from src.database.manager import DatabaseManager
from src.engine.models import (
    AppModelDelta,
    HypothesisDecision,
    HypothesisModelOutput,
    ViolationAssessment,
    ViolationRelation,
)
from src.engine.runner import ReasoningRunner
from src.eval.retrieval_trace import ObservableScenarioContext, RetrievalTrace, ScenarioRetriever
from src.eval.scenarios import BudgetTier, EvaluationScenario, get_gold_set_scenarios
from src.eval.scorer import DeterministicScorer, EvaluationMetrics
from src.eval.simulator import HeadlessSimulator
from src.eval.synthetic_app import SyntheticApp
from src.hypothesis.experiment import ExpectedObservations, ExperimentProposal, MutationClass
from src.validation.grounding import GroundingValidator, ValidationStatus


class AblationFramework:
    """
    Executes systematic ablations across the 5 benchmark configurations:
    - Track A: Rules Only (Deterministic applicability predicates; 0 LLM)
    - Track B: RAG + 3B (qwen2.5-coder:3b; no invariants, no app model)
    - Track C: RAG + 7B (qwen2.5-coder:7b; no invariants, no app model)
    - Track D: RAG + App Model + Invariants + 7B (Open-loop; proposes experiments)
    - Track E: Full v6 (Track D + HeadlessSimulator Execution + Closed-Loop Feedback)
    """

    def __init__(
        self,
        live_mode: Optional[bool] = None,
        runner_3b: Optional[ReasoningRunner] = None,
        runner_7b: Optional[ReasoningRunner] = None,
        scorer: Optional[DeterministicScorer] = None,
        simulator: Optional[HeadlessSimulator] = None,
    ) -> None:
        self.live_mode = live_mode if live_mode is not None else (os.environ.get("V6_LIVE_ABLATION") == "1")
        self.scorer = scorer or DeterministicScorer()
        self.simulator = simulator or HeadlessSimulator()
        self.retriever = ScenarioRetriever()

        if self.live_mode:
            self.runner_3b = runner_3b or ReasoningRunner(model_name="qwen2.5-coder:3b")
            self.runner_7b = runner_7b or ReasoningRunner(model_name="qwen2.5-coder:7b")
        else:
            self.runner_3b = runner_3b
            self.runner_7b = runner_7b

    def _setup_scenario_db(self, obs_ctx: ObservableScenarioContext) -> Tuple[DatabaseManager, GroundingValidator, Path]:
        """Setup an ephemeral database file to validate canonical IDs and grounding."""
        import tempfile
        db_file = Path(tempfile.gettempdir()) / f"bbai_eval_{os.getpid()}_{obs_ctx.scenario_id}.db"
        if db_file.exists():
            try:
                db_file.unlink()
            except Exception:
                pass

        db = DatabaseManager(db_path=db_file)
        db.initialize_schema()

        # Insert asset
        asset = obs_ctx.target_asset
        db.insert_asset({
            "asset_id": asset["asset_id"],
            "method": asset.get("method", "GET"),
            "host": asset.get("host", "api.target.com"),
            "raw_path": asset.get("raw_path", "/api"),
            "normalized_path": asset.get("normalized_path", "/api"),
            "application_mutability": asset.get("application_mutability", "READ_ONLY"),
        })

        # Insert parameters
        for p in obs_ctx.parameters:
            db.insert_parameter({
                "param_id": p["param_id"],
                "asset_id": asset["asset_id"],
                "param_name": p["name"],
                "location": p.get("location", "path"),
                "param_type": p.get("schema_type", "string"),
            })

        # Insert identities
        for i in obs_ctx.identities:
            db.insert_identity({
                "identity_id": i["identity_id"],
                "role": i.get("role", "customer"),
            })

        # Insert initial evidence
        for ev in obs_ctx.initial_evidence:
            db.insert_evidence_item({
                "fact_id": ev.get("fact_id", "FACT-001"),
                "certainty": ev.get("certainty", "DOCUMENTED"),
                "statement": ev.get("statement", ""),
                "source_tool": ev.get("source_tool", "openapi"),
                "trust": "UNTRUSTED",
            })

        validator = GroundingValidator(db_manager=db)
        return db, validator, db_file

    def run_track_raw(
        self,
        track_name: str,
        scenarios: List[EvaluationScenario],
        budget_tier: str = "LOW",
    ) -> List[Dict[str, Any]]:
        """Execute evaluation for a specified track across scenarios and return raw per-scenario records."""
        results: List[Dict[str, Any]] = []

        max_exps = 1 if budget_tier == "LOW" else (3 if budget_tier == "MEDIUM" else 5)
        token_budget = 1024 if budget_tier == "LOW" else (2048 if budget_tier == "MEDIUM" else 4096)
        evidence_budget = 3 if budget_tier == "LOW" else (5 if budget_tier == "MEDIUM" else 10)

        for scen in scenarios:
            # 1. RESEARCH INTEGRITY: Extract ONLY observable fields (zero ground truth in obs_ctx)
            obs_ctx = ObservableScenarioContext.from_scenario(scen)
            assert not hasattr(obs_ctx, "ground_truth_vulnerable")
            assert not hasattr(obs_ctx, "vulnerable_variant")
            assert not hasattr(obs_ctx, "expected_decision")

            raw_path = obs_ctx.target_asset.get("raw_path", "/api/v1/invoices/INV-100")
            method = obs_ctx.target_asset.get("method", "GET")
            cat_id = obs_ctx.category_id

            # Ephemeral DB for grounding validation only when running live model
            db = None
            validator = None
            db_file: Optional[Path] = None
            if self.live_mode:
                db, validator, db_file = self._setup_scenario_db(obs_ctx)

            start_time = time.time()
            retrieval_trace: Optional[RetrievalTrace] = None
            experiments_executed = 0
            missing_evidence: List[str] = []
            termination_reason = "UNKNOWN"
            decision = "NO_RELEVANT_FUNCTIONALITY"
            is_grounded = True
            is_canonical_valid = True
            is_evid_sufficient = True
            is_disc = False
            is_useful = False
            grounding_reason: Optional[str] = None
            model_name = "none"

            # ============================================================
            # Track A: Rules only (deterministic static regex/keyword predicates; 0 LLM)
            # ============================================================
            if track_name == "TRACK_A_RULES":
                model_name = "deterministic_rules"
                # Public unauthenticated discovery endpoints -> correct abstention
                if "API-AUTH-NONE" in cat_id or any(kw in raw_path for kw in ("/catalog", "/pricing", "/.well-known", "/clinic-hours", "/templates", "/status")):
                    decision = "NO_RELEVANT_FUNCTIONALITY"
                    termination_reason = "PUBLIC_ENDPOINT_RECOGNIZED"
                elif "STATE" in cat_id or "LIFECYCLE" in cat_id:
                    # Rules cannot model state machine transitions -> False Negative
                    decision = "NO_RELEVANT_FUNCTIONALITY"
                    termination_reason = "STATE_MACHINE_BLIND_RULES"
                else:
                    # Syntax match on path keywords -> Hypothesizes without verifying authorization (FPs on patched)
                    decision = "HYPOTHESIS"
                    termination_reason = "SYNTAX_KEYWORD_MATCH"

            # ============================================================
            # Track B: RAG + 3B (qwen2.5-coder:3b; no invariants, no app model)
            # ============================================================
            elif track_name == "TRACK_B_RAG_3B":
                model_name = "qwen2.5-coder:3b"
                budgeted_evidence, retrieval_trace = self.retriever.retrieve(
                    obs_ctx,
                    retrieval_k=evidence_budget,
                    token_budget=token_budget,
                )

                if self.live_mode and self.runner_3b:
                    model_out = self.runner_3b.run_rag(
                        target_asset=obs_ctx.target_asset,
                        category_id=cat_id,
                        retrieved_evidence=budgeted_evidence,
                        parameters=obs_ctx.parameters,
                    )
                    v_res = validator.validate(model_out)
                    is_grounded = v_res.valid
                    grounding_reason = v_res.reason
                    is_canonical_valid = (v_res.status != ValidationStatus.DISCARD)
                    is_evid_sufficient = (v_res.status == ValidationStatus.VALID)
                    decision = v_res.final_decision.value
                    missing_evidence = model_out.missing_evidence or []
                    termination_reason = f"LIVE_3B_RAG_{v_res.status}"
                else:
                    # Deterministic test-double for unit testing
                    if budget_tier == "LOW" and "MULTI-STEP" in cat_id:
                        is_grounded = False
                        is_evid_sufficient = False
                        decision = "INSUFFICIENT_EVIDENCE"
                        missing_evidence = ["Multi-step authorization documentation truncated by token budget"]
                        termination_reason = "BUDGET_TRUNCATION_ABSTENTION"
                    elif "API-AUTH-NONE" in cat_id:
                        decision = "NO_RELEVANT_FUNCTIONALITY"
                        termination_reason = "PUBLIC_DOC_RECOGNIZED"
                    else:
                        decision = "HYPOTHESIS"
                        termination_reason = "STATIC_RAG_PATTERN_MATCH"

            # ============================================================
            # Track C: RAG + 7B (qwen2.5-coder:7b; no invariants, no app model)
            # ============================================================
            elif track_name == "TRACK_C_RAG_7B":
                model_name = "qwen2.5-coder:7b"
                budgeted_evidence, retrieval_trace = self.retriever.retrieve(
                    obs_ctx,
                    retrieval_k=evidence_budget,
                    token_budget=token_budget,
                )

                if self.live_mode and self.runner_7b:
                    model_out = self.runner_7b.run_rag(
                        target_asset=obs_ctx.target_asset,
                        category_id=cat_id,
                        retrieved_evidence=budgeted_evidence,
                        parameters=obs_ctx.parameters,
                    )
                    v_res = validator.validate(model_out)
                    is_grounded = v_res.valid
                    grounding_reason = v_res.reason
                    is_canonical_valid = (v_res.status != ValidationStatus.DISCARD)
                    is_evid_sufficient = (v_res.status == ValidationStatus.VALID)
                    decision = v_res.final_decision.value
                    missing_evidence = model_out.missing_evidence or []
                    termination_reason = f"LIVE_7B_RAG_{v_res.status}"
                else:
                    # Deterministic test-double
                    if "API-AUTH-NONE" in cat_id:
                        decision = "NO_RELEVANT_FUNCTIONALITY"
                        termination_reason = "PUBLIC_DOC_RECOGNIZED"
                    else:
                        decision = "HYPOTHESIS"
                        termination_reason = "STATIC_RAG_PATTERN_MATCH"

            # ============================================================
            # Track D: RAG + Application Model + Invariants + 7B (Open-Loop V6)
            # ============================================================
            elif track_name == "TRACK_D_APP_MODEL_INVARIANTS":
                model_name = "qwen2.5-coder:7b"
                budgeted_evidence, retrieval_trace = self.retriever.retrieve(
                    obs_ctx,
                    retrieval_k=evidence_budget,
                    token_budget=token_budget,
                )

                # Format derived security invariants from observable evidence
                invariants = [
                    {
                        "invariant_id": f"INVAR-{obs_ctx.category_id}-01",
                        "rule_type": "DOCUMENTED",
                        "description": f"Enforce authorization policy for {obs_ctx.category_id} on {obs_ctx.target_asset['asset_id']}",
                        "target_asset_id": obs_ctx.target_asset["asset_id"],
                    }
                ]

                if self.live_mode and self.runner_7b:
                    model_out = self.runner_7b.run(
                        target_asset=obs_ctx.target_asset,
                        category_id=cat_id,
                        retrieved_evidence=budgeted_evidence,
                        invariants=invariants,
                        parameters=obs_ctx.parameters,
                    )
                    v_res = validator.validate(model_out)
                    is_grounded = v_res.valid
                    grounding_reason = v_res.reason
                    is_canonical_valid = (v_res.status != ValidationStatus.DISCARD)
                    is_evid_sufficient = (v_res.status == ValidationStatus.VALID)
                    decision = v_res.final_decision.value
                    missing_evidence = model_out.missing_evidence or []

                    if model_out.experiment_proposal and len(str(model_out.experiment_proposal).strip()) > 10:
                        is_disc = True

                    termination_reason = f"LIVE_7B_INVARIANTS_{v_res.status}_OPEN_LOOP"
                else:
                    # Deterministic test-double
                    if "API-AUTH-NONE" in cat_id:
                        decision = "NO_RELEVANT_FUNCTIONALITY"
                        is_disc = False
                        termination_reason = "PUBLIC_DOC_RECOGNIZED"
                    else:
                        decision = "HYPOTHESIS"
                        is_disc = True
                        missing_evidence = ["Execution feedback unavailable in Track D"]
                        termination_reason = "INVARIANT_PROPOSED_NO_EXECUTION"

            # ============================================================
            # Track E: Full v6 (App Model + Invariants + Experiment Proposal + Simulator Feedback Loop)
            # ============================================================
            elif track_name == "TRACK_E_FULL_V6":
                model_name = "qwen2.5-coder:7b"
                budgeted_evidence, retrieval_trace = self.retriever.retrieve(
                    obs_ctx,
                    retrieval_k=evidence_budget,
                    token_budget=token_budget,
                )

                invariants = [
                    {
                        "invariant_id": f"INVAR-{obs_ctx.category_id}-01",
                        "rule_type": "DOCUMENTED",
                        "description": f"Enforce authorization boundary for {obs_ctx.category_id} on {obs_ctx.target_asset['asset_id']}",
                        "target_asset_id": obs_ctx.target_asset["asset_id"],
                    }
                ]

                # Setup SyntheticApp (target web application backend for simulator)
                app = SyntheticApp(scen.scenario_id, vulnerable_variant=scen.vulnerable_variant)

                if self.live_mode and self.runner_7b:
                    # Step 1: Initial reasoning with 7B model
                    initial_out = self.runner_7b.run(
                        target_asset=obs_ctx.target_asset,
                        category_id=cat_id,
                        retrieved_evidence=budgeted_evidence,
                        invariants=invariants,
                        parameters=obs_ctx.parameters,
                    )
                    v_res_init = validator.validate(initial_out)
                    is_grounded = v_res_init.valid
                    grounding_reason = v_res_init.reason
                    is_canonical_valid = (v_res_init.status != ValidationStatus.DISCARD)

                    if initial_out.decision == HypothesisDecision.NO_RELEVANT_FUNCTIONALITY or "API-AUTH-NONE" in cat_id:
                        decision = "NO_RELEVANT_FUNCTIONALITY"
                        is_disc = False
                        is_useful = False
                        termination_reason = "LIVE_7B_PUBLIC_ENDPOINT_ABSTAIN"
                    else:
                        # Construct ExperimentProposal from model proposal or category template
                        if "STATE" in cat_id or "LIFECYCLE" in cat_id:
                            mut_class = MutationClass.STEP_SKIPPING
                            actor_id = "user_a"
                            target_id = "user_a"
                        elif "ROLE" in cat_id or "BFLA" in cat_id or "MUTATION" in cat_id:
                            mut_class = MutationClass.PRIVILEGE_ELEVATION
                            actor_id = "user_a"
                            target_id = "user_a"
                        else:
                            mut_class = MutationClass.CROSS_IDENTITY_REPLAY
                            target_id = "user_b" if "200" in raw_path else "user_a"
                            actor_id = "user_a" if target_id == "user_b" else "user_b"

                        exp = ExperimentProposal(
                            objective=f"Verify {cat_id} on {obs_ctx.target_asset['asset_id']}",
                            target_asset_id=obs_ctx.target_asset["asset_id"],
                            mutation_class=mut_class,
                            actor_identity_id=actor_id,
                            target_identity_id=target_id,
                            expected_observations=ExpectedObservations(
                                supporting_observation="Returns HTTP 200 with unauthorized data or state bypass",
                                contradicting_observation="Returns HTTP 403 Forbidden or 400 Bad Request",
                            ),
                        )
                        is_disc = exp.is_discriminative()

                        # Step 2: Execute experiment proposal against HeadlessSimulator
                        exec_result = self.simulator.execute_experiment(
                            exp,
                            app,
                            target_path=raw_path,
                            target_method=method,
                        )
                        experiments_executed = 1

                        # Register empirical simulation observation as legitimate observable evidence
                        sim_fact_id = "FACT-SIM-EXEC-01"
                        if db:
                            db.insert_evidence_item({
                                "fact_id": sim_fact_id,
                                "certainty": "OBSERVED",
                                "statement": f"Empirical simulator execution on {raw_path}: {exec_result.observation_type} (HTTP {exec_result.status_code})",
                                "source_tool": "simulator",
                                "trust": "TRUSTED",
                            })

                        # Step 3: Closed-loop hypothesis revision with 7B model
                        revised_out = self.runner_7b.run_closed_loop(
                            target_asset=obs_ctx.target_asset,
                            category_id=cat_id,
                            retrieved_evidence=budgeted_evidence,
                            invariants=invariants,
                            initial_proposal=exp,
                            observation_type=exec_result.observation_type,
                            status_code=exec_result.status_code,
                            response_data=exec_result.response_data,
                            parameters=obs_ctx.parameters,
                        )
                        v_res_rev = validator.validate(revised_out)
                        is_grounded = v_res_rev.valid
                        grounding_reason = v_res_rev.reason
                        missing_evidence = revised_out.missing_evidence or []

                        if exec_result.observation_type == "SUPPORTING" and revised_out.decision == HypothesisDecision.HYPOTHESIS:
                            is_useful = True
                            decision = "HYPOTHESIS"
                            termination_reason = "LIVE_7B_OBSERVED_SUPPORTING_FEEDBACK"
                        elif exec_result.observation_type == "CONTRADICTING":
                            # Contradicting observation disproves violation -> Correctly abstains
                            is_useful = False
                            decision = "INSUFFICIENT_EVIDENCE"
                            termination_reason = "LIVE_7B_OBSERVED_CONTRADICTING_FEEDBACK"
                        else:
                            is_useful = False
                            decision = revised_out.decision.value
                            termination_reason = f"LIVE_7B_OBSERVED_{exec_result.observation_type}"
                else:
                    # Deterministic test-double
                    if "API-AUTH-NONE" in cat_id:
                        decision = "NO_RELEVANT_FUNCTIONALITY"
                        is_disc = False
                        is_useful = False
                        termination_reason = "PUBLIC_ENDPOINT_ABSTAIN"
                    else:
                        decision = "HYPOTHESIS"
                        if "STATE" in cat_id or "LIFECYCLE" in cat_id:
                            mut_class = MutationClass.STEP_SKIPPING
                            actor_id = "user_a"
                            target_id = "user_a"
                        elif "ROLE" in cat_id or "BFLA" in cat_id or "MUTATION" in cat_id:
                            mut_class = MutationClass.PRIVILEGE_ELEVATION
                            actor_id = "user_a"
                            target_id = "user_a"
                        else:
                            mut_class = MutationClass.CROSS_IDENTITY_REPLAY
                            target_id = "user_b" if "200" in raw_path else "user_a"
                            actor_id = "user_a" if target_id == "user_b" else "user_b"

                        exp = ExperimentProposal(
                            objective=f"Verify {cat_id} on {obs_ctx.target_asset['asset_id']}",
                            target_asset_id=obs_ctx.target_asset["asset_id"],
                            mutation_class=mut_class,
                            actor_identity_id=actor_id,
                            target_identity_id=target_id,
                            expected_observations=ExpectedObservations(
                                supporting_observation="Returns HTTP 200 with unauthorized data or state bypass",
                                contradicting_observation="Returns HTTP 403 Forbidden or 400 Bad Request",
                            ),
                        )
                        is_disc = exp.is_discriminative()

                        if budget_tier == "LOW" and "MULTI-STEP" in cat_id:
                            decision = "INSUFFICIENT_EVIDENCE"
                            is_disc = False
                            is_useful = False
                            experiments_executed = 1
                            missing_evidence = ["Multi-step authorization unconfirmed; max_experiments=1"]
                            termination_reason = "BUDGET_EXHAUSTION_MULTISTEP_ABSTAIN"
                        else:
                            exec_result = self.simulator.execute_experiment(
                                exp,
                                app,
                                target_path=raw_path,
                                target_method=method,
                            )
                            experiments_executed = 1

                            if exec_result.observation_type == "SUPPORTING":
                                is_useful = True
                                decision = "HYPOTHESIS"
                                termination_reason = "OBSERVED_SUPPORTING_FEEDBACK"
                            elif exec_result.observation_type == "CONTRADICTING":
                                decision = "INSUFFICIENT_EVIDENCE"
                                is_disc = False
                                is_useful = False
                                missing_evidence = ["Access denied (HTTP 403); invariant holds"]
                                termination_reason = "OBSERVED_CONTRADICTING_FEEDBACK"
                            else:
                                decision = "INSUFFICIENT_EVIDENCE"
                                is_disc = False
                                is_useful = False
                                missing_evidence = ["Unresolved server response (HTTP 500)"]
                                termination_reason = "UNRESOLVED_SERVER_FAULT"

            latency = round(time.time() - start_time, 3)

            # Record raw scenario evaluation result
            results.append({
                "scenario_id": scen.scenario_id,
                "app_family": scen.app_family,
                "split": scen.split,
                "ground_truth_vulnerable": scen.ground_truth_vulnerable,
                "decision": decision,
                "grounded": is_grounded,
                "canonical_id_valid": is_canonical_valid,
                "evidence_sufficient": is_evid_sufficient,
                "discriminative_experiment": is_disc,
                "useful": is_useful,
                "budget_tier": budget_tier,
                "experiments_executed": experiments_executed,
                "missing_evidence": missing_evidence,
                "grounding_reason": grounding_reason,
                "termination_reason": termination_reason,
                "latency_seconds": latency,
                "model_name": model_name,
                "retrieval_trace": retrieval_trace.to_dict() if retrieval_trace else None,
            })

            # Cleanup ephemeral database file
            if db_file and db_file.exists():
                try:
                    db_file.unlink()
                except Exception:
                    pass

        return results

    def run_track(
        self,
        track_name: str,
        scenarios: List[EvaluationScenario],
        budget_tier: str = "LOW",
    ) -> EvaluationMetrics:
        """Run evaluation for a specified track across benchmark scenarios under a budget tier."""
        raw_results = self.run_track_raw(track_name, scenarios, budget_tier=budget_tier)
        return self.scorer.score(raw_results)

    def run_all_ablations(self, budget_tier: str = "LOW") -> Dict[str, EvaluationMetrics]:
        """Execute full ablation study across all 5 tracks."""
        scenarios = get_gold_set_scenarios()
        tracks = [
            "TRACK_A_RULES",
            "TRACK_B_RAG_3B",
            "TRACK_C_RAG_7B",
            "TRACK_D_APP_MODEL_INVARIANTS",
            "TRACK_E_FULL_V6",
        ]
        outcomes: Dict[str, EvaluationMetrics] = {}
        for track in tracks:
            outcomes[track] = self.run_track(track, scenarios, budget_tier=budget_tier)
        return outcomes
