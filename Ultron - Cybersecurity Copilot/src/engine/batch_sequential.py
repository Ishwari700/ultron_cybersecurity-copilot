"""Mode 1: Batch-Sequential Cascade Execution Scaffolding (Section 6.1 & Phase 9).

Orchestrates the 3-phase batch execution lifecycle:
    Phase 1: 3B Triage Sweep across candidate scenarios & survivor set computation.
    Phase 2: Model Transition (3B unload, 7B warm load, load latency recording).
    Phase 3: 7B Deep Reasoning Sweep over escalated survivors.

Instrumented with:
    - Decoupled Latency Decomposition (MODEL_LOAD_LATENCY, MODEL_INFERENCE_LATENCY, END_TO_END_DECISION_LATENCY).
    - 3B Operational Health & SLO Monitoring (3B_FAILURE_RATE, diagnostic metrics, SLO alert).
"""

import time
from typing import Any, Callable, Dict, List, Optional
from pydantic import BaseModel, Field

from src.evidence.cascade_models import (
    CascadeHandoffPacket,
    DeterministicRoutingDecision,
    GateValidationResult,
    LosslessStructuralPack,
    RawTriageOutput,
)
from src.evidence.gate import EvidencePreservationGate
from src.evidence.provenance import compute_provenance_hash
from src.engine.context_builder import TRACK_C_CASCADE, ReasoningContextBuilder
from src.engine.router import DeterministicRouter

# ---------------------------------------------------------------------------
# Section 6.3 3B Health & Availability SLO Constants (MANDATORY)
# ---------------------------------------------------------------------------
SLO_TARGET_MAX_FAILURE_RATE = 0.05  # Target: 3B_FAILURE_RATE <= 5.0%
SLO_DIAGNOSTIC_ALERT_THRESHOLD = 0.02  # > 2.0% logs operational performance warning
SLO_OPERATIONAL_VIOLATION_THRESHOLD = 0.05  # > 5.0% flags operational efficiency SLO violation


class BatchExecutionRecord(BaseModel):
    """Result record for a single scenario executed through the cascade."""
    scenario_id: str
    channel_a: LosslessStructuralPack
    raw_triage: Optional[RawTriageOutput] = None
    gate_result: GateValidationResult
    routing_decision: DeterministicRoutingDecision
    handoff_packet: Optional[CascadeHandoffPacket] = None
    reasoning_hypothesis: Optional[Dict[str, Any]] = None
    model_load_latency: float = 0.0
    model_inference_latency: float = 0.0
    end_to_end_decision_latency: float = 0.0


class BatchSweepSummary(BaseModel):
    """Aggregated metrics and diagnostics for a complete Mode 1 sweep."""
    total_scenarios: int
    triage_attempted: int
    triage_failures: int
    failure_rate_3b: float  # 3B_FAILURE_RATE
    slo_alert_triggered: bool = False
    slo_violation: bool = False
    survivor_count: int
    escalation_rate: float
    total_7b_calls: int
    records: List[BatchExecutionRecord] = Field(default_factory=list)


class BatchSequentialPipeline:
    """
    Mode 1 Batch-Sequential Pipeline Engine.
    Executes decoupled batch phases without live Ollama dependency when supplied with runners or mocks.
    """

    def __init__(
        self,
        triage_runner_fn: Optional[Callable[[LosslessStructuralPack], Optional[RawTriageOutput]]] = None,
        reasoning_runner_fn: Optional[Callable[[Any], Dict[str, Any]]] = None,
        model_transition_fn: Optional[Callable[[], float]] = None,
    ) -> None:
        self.triage_runner = triage_runner_fn
        self.reasoning_runner = reasoning_runner_fn
        self.model_transition = model_transition_fn or (lambda: 0.0)

    def run_sweep(
        self,
        scenarios: List[Dict[str, Any]],
        registered_categories: Optional[set] = None,
    ) -> BatchSweepSummary:
        """
        Execute full Mode 1 Batch-Sequential sweep over scenarios.
        Each scenario dict has {"scenario_id": str, "channel_a": LosslessStructuralPack}.
        """
        records: List[BatchExecutionRecord] = []
        triage_attempted = len(scenarios)
        triage_failures = 0

        # ===================================================================
        # Phase 1: 3B Triage Sweep
        # ===================================================================
        survivors: List[BatchExecutionRecord] = []

        for item in scenarios:
            sc_id = item["scenario_id"]
            ch_a = item["channel_a"]
            t_start = time.perf_counter()

            # Execute 3B Triage (or mock)
            raw_triage: Optional[RawTriageOutput] = None
            t3b_infer_time = 0.0
            triage_failed = False
            if self.triage_runner:
                t0 = time.perf_counter()
                try:
                    raw_triage = self.triage_runner(ch_a)
                except Exception:
                    raw_triage = None
                    triage_failed = True
                t3b_infer_time = time.perf_counter() - t0

            if raw_triage is None or raw_triage.is_malformed:
                triage_failed = True

            if triage_failed:
                triage_failures += 1

            # Gate validation
            gate_res = EvidencePreservationGate.validate(
                channel_a=ch_a,
                raw_triage=raw_triage,
                registered_categories=registered_categories,
            )

            # Deterministic routing
            decision = DeterministicRouter.evaluate_escalation(ch_a, gate_res)

            # Build handoff packet
            p_hash = compute_provenance_hash(ch_a, gate_res, decision)
            handoff = CascadeHandoffPacket(
                schema_version="2.0.0",
                channel_a_structural=ch_a,
                routing_decision=decision,
                provenance_hash=p_hash,
                validated_triage=gate_res.validated_triage,
            )

            t_decision = time.perf_counter() - t_start

            record = BatchExecutionRecord(
                scenario_id=sc_id,
                channel_a=ch_a,
                raw_triage=raw_triage,
                gate_result=gate_res,
                routing_decision=decision,
                handoff_packet=handoff,
                model_inference_latency=t3b_infer_time,
                end_to_end_decision_latency=t_decision,
            )
            records.append(record)

            if decision.escalate:
                survivors.append(record)

        # Compute 3B Health SLO (Section 6.3)
        failure_rate = (triage_failures / triage_attempted) if triage_attempted > 0 else 0.0
        slo_alert = failure_rate > SLO_DIAGNOSTIC_ALERT_THRESHOLD
        slo_violation = failure_rate > SLO_OPERATIONAL_VIOLATION_THRESHOLD

        # ===================================================================
        # Phase 2: Model Transition
        # ===================================================================
        load_latency = 0.0
        if survivors:
            t_trans_start = time.perf_counter()
            load_latency = self.model_transition()
            if load_latency <= 0.0:
                load_latency = time.perf_counter() - t_trans_start

        # ===================================================================
        # Phase 3: 7B Deep Reasoning Sweep over Survivor Set
        # ===================================================================
        for surv in survivors:
            surv.model_load_latency = load_latency
            t7_start = time.perf_counter()

            # Build Reasoning Context
            ctx = ReasoningContextBuilder.build_context(
                surv.handoff_packet,
                model_identifier="qwen2.5-coder:7b",
                cascade_mode=TRACK_C_CASCADE,
            )

            # Invoke 7B Runner (or mock)
            if self.reasoning_runner:
                try:
                    import inspect
                    sig = inspect.signature(self.reasoning_runner)
                    if len(sig.parameters) >= 2:
                        hyp = self.reasoning_runner(ctx, surv.channel_a)
                    else:
                        hyp = self.reasoning_runner(ctx)
                except TimeoutError as te:
                    hyp = {
                        "status": "EXECUTION_FAILURE",
                        "failure_type": "HARDWARE_TIMEOUT",
                        "error": f"7B inference timed out: {te}",
                    }
                except Exception as e:
                    hyp = {
                        "status": "EXECUTION_FAILURE",
                        "failure_type": "OTHER_IMPLEMENTATION_FAILURE",
                        "error": str(e),
                    }
                surv.reasoning_hypothesis = hyp

            t7_infer = time.perf_counter() - t7_start
            surv.model_inference_latency += t7_infer
            surv.end_to_end_decision_latency += (load_latency + t7_infer)

        survivor_count = len(survivors)
        escalation_rate = (survivor_count / len(scenarios)) if scenarios else 0.0

        return BatchSweepSummary(
            total_scenarios=len(scenarios),
            triage_attempted=triage_attempted,
            triage_failures=triage_failures,
            failure_rate_3b=failure_rate,
            slo_alert_triggered=slo_alert,
            slo_violation=slo_violation,
            survivor_count=survivor_count,
            escalation_rate=escalation_rate,
            total_7b_calls=survivor_count,
            records=records,
        )
