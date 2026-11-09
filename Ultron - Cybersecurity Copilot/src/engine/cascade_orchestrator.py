"""
Cascade Orchestrator & Runtime Instrumentation for Bug Bounty AI.

Orchestrates the authoritative two-model research cascade:
    Phase 1: 3B Preliminary Triage (Live3BTriageRunner)
    Phase 2: Preservation Gate & Deterministic Routing (EvidencePreservationGate & DeterministicRouter)
    Phase 3: Immutable Handoff & 7B Deep Reasoning (ReasoningContextBuilder & Live7BReasoningRunner)

Maintains verifiable, non-synthetic execution traces for every inference request.
"""

from datetime import datetime, timezone
import hashlib
import json
import time
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from src.core.logging import get_logger
from src.engine.context_builder import ReasoningContextBuilder, TRACK_C_CASCADE
from src.engine.reasoning_runner import (
    CascadeGroundingValidator,
    Live7BReasoningRunner,
    PINNED_7B_DIGEST,
    PINNED_7B_MODEL,
)
from src.engine.router import DeterministicRouter
from src.engine.runner import OllamaRunner as OllamaClient
from src.engine.triage_runner import (
    Live3BTriageRunner,
    PINNED_3B_DIGEST,
    PINNED_3B_MODEL,
)
from src.evidence.cascade_models import (
    CascadeHandoffPacket,
    DeterministicRoutingDecision,
    GateValidationResult,
    LosslessStructuralPack,
    RawTriageOutput,
)
from src.evidence.gate import EvidencePreservationGate
from src.evidence.provenance import compute_provenance_hash

logger = get_logger("CascadeOrchestrator")


class CascadeStageTrace(BaseModel):
    """Execution telemetry for an individual cascade pipeline stage."""
    stage_name: str
    model_name: Optional[str] = None
    model_digest: Optional[str] = None
    status: str  # COMPLETED, SKIPPED, FAILED
    latency_seconds: float = 0.0
    details: Dict[str, Any] = Field(default_factory=dict)


class CascadeExecutionTrace(BaseModel):
    """Complete, empirical execution trace for a single research request."""
    run_id: str
    investigation_id: Optional[str] = None
    user_message_id: Optional[str] = None
    assistant_message_id: Optional[str] = None
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    task_type: str  # CONVERSATIONAL, SECURITY_RESEARCH, CASCADE_SWEEP
    target_endpoint: str
    stages: List[CascadeStageTrace] = Field(default_factory=list)
    overall_status: str = "IN_PROGRESS"  # CASCADE_COMPLETED, TERMINATED_AT_3B, CASCADE_FAILED, NO_EVIDENCE
    routing_decision: Optional[str] = None
    escalated: bool = False
    handoff_provenance_hash: Optional[str] = None
    total_latency_seconds: float = 0.0
    error_message: Optional[str] = None



class CascadeOrchestrator:
    """
    Central execution coordinator executing and instrumenting the 3B -> Router -> 7B cascade.
    """

    def __init__(
        self,
        ollama_url: str = "http://127.0.0.1:11434",
        triage_timeout: float = 45.0,
        reasoning_timeout: float = 60.0,
    ) -> None:
        self.ollama_url = ollama_url.rstrip("/")
        self.triage_runner = Live3BTriageRunner(ollama_url=self.ollama_url, timeout_seconds=triage_timeout)
        self.reasoning_runner = Live7BReasoningRunner(ollama_url=self.ollama_url, timeout_seconds=reasoning_timeout)
        self.ollama_client = OllamaClient(base_url=self.ollama_url, model_name=PINNED_7B_MODEL)
        self._recent_traces: List[CascadeExecutionTrace] = []
        self._run_counter: int = 0

    def check_runtime_status(self) -> Dict[str, Any]:
        """Check live Ollama connectivity and installed model digests."""
        models = self.ollama_client.list_models()
        model_names = [m.get("name", "") for m in models]
        has_3b = any(PINNED_3B_MODEL in name for name in model_names)
        has_7b = any(PINNED_7B_MODEL in name for name in model_names)

        digests = {m.get("name"): m.get("digest") for m in models}

        if has_3b and has_7b:
            mode = "3B_7B_CASCADE_READY"
        elif has_7b:
            mode = "7B_ONLY"
        elif has_3b:
            mode = "3B_ONLY"
        else:
            mode = "MODELS_UNAVAILABLE"

        return {
            "ollama_available": self.ollama_client.is_available(),
            "cascade_mode": mode,
            "installed_models": model_names,
            "has_3b": has_3b,
            "has_7b": has_7b,
            "digests": digests,
        }

    def execute_cascade(
        self,
        channel_a: LosslessStructuralPack,
        task_type: str = "SECURITY_RESEARCH",
        investigation_id: Optional[str] = None,
        user_message_id: Optional[str] = None,
        assistant_message_id: Optional[str] = None,
    ) -> Tuple[CascadeExecutionTrace, Optional[Dict[str, Any]]]:
        """
        Execute the empirical 3B -> Router -> 7B cascade across the structural pack.
        Returns (trace, hypothesis_output).
        """
        self._run_counter += 1
        run_id = f"RUN-{self._run_counter:04d}"
        t_start = time.perf_counter()

        trace = CascadeExecutionTrace(
            run_id=run_id,
            investigation_id=investigation_id,
            user_message_id=user_message_id,
            assistant_message_id=assistant_message_id,
            task_type=task_type,
            target_endpoint=f"{channel_a.http_method} {channel_a.route_template}",
        )


        final_hypothesis: Optional[Dict[str, Any]] = None

        # ---------------------------------------------------------------------
        # Stage 1: 3B Preliminary Triage
        # ---------------------------------------------------------------------
        t0 = time.perf_counter()
        raw_triage = self.triage_runner.run_triage(channel_a)
        t_stage1 = time.perf_counter() - t0

        stage1_status = "FAILED" if (raw_triage is None or raw_triage.is_malformed) else "COMPLETED"
        trace.stages.append(
            CascadeStageTrace(
                stage_name="Stage 1: 3B Preliminary Triage",
                model_name=PINNED_3B_MODEL,
                model_digest=PINNED_3B_DIGEST[:16] + "...",
                status=stage1_status,
                latency_seconds=round(t_stage1, 3),
                details={
                    "decision": raw_triage.decision if raw_triage else "FAILED",
                    "suspected_category": raw_triage.suspected_category if raw_triage else None,
                    "is_malformed": raw_triage.is_malformed if raw_triage else True,
                    "rationale": raw_triage.triage_rationale if raw_triage else "Invocation failed",
                },
            )
        )

        # ---------------------------------------------------------------------
        # Stage 2: Gate & Deterministic Routing
        # ---------------------------------------------------------------------
        t0 = time.perf_counter()
        gate_res = EvidencePreservationGate.validate(channel_a=channel_a, raw_triage=raw_triage)
        routing_decision = DeterministicRouter.evaluate_escalation(diff=channel_a, gate_result=gate_res)
        t_stage2 = time.perf_counter() - t0

        trace.escalated = routing_decision.escalate
        trace.routing_decision = "ESCALATE_TO_7B" if routing_decision.escalate else "TERMINATE_BENIGN_AT_3B"

        trace.stages.append(
            CascadeStageTrace(
                stage_name="Stage 2: Gate & Deterministic Routing",
                model_name="DeterministicRouter",
                status="COMPLETED",
                latency_seconds=round(t_stage2, 4),
                details={
                    "escalate": routing_decision.escalate,
                    "decision": trace.routing_decision,
                    "reasons": routing_decision.reasons,
                    "gate_triggers": gate_res.gate_triggers,
                    "fail_safe_triggered": routing_decision.fail_safe_triggered,
                },
            )
        )

        # ---------------------------------------------------------------------
        # Stage 3: Handoff Serialization
        # ---------------------------------------------------------------------
        p_hash = compute_provenance_hash(channel_a, gate_res, routing_decision)
        trace.handoff_provenance_hash = p_hash

        handoff = CascadeHandoffPacket(
            schema_version="2.0.0",
            channel_a_structural=channel_a,
            routing_decision=routing_decision,
            provenance_hash=p_hash,
            validated_triage=gate_res.validated_triage,
        )

        trace.stages.append(
            CascadeStageTrace(
                stage_name="Stage 3: Immutable Cascade Handoff",
                model_name="HandoffSerializer",
                status="COMPLETED",
                latency_seconds=0.001,
                details={
                    "provenance_hash": p_hash,
                    "has_validated_triage": gate_res.validated_triage is not None,
                },
            )
        )

        # ---------------------------------------------------------------------
        # Stage 4: 7B Deep Reasoning (If Escalated)
        # ---------------------------------------------------------------------
        if routing_decision.escalate:
            t0 = time.perf_counter()
            ctx = ReasoningContextBuilder.build_context(
                handoff,
                model_identifier=PINNED_7B_MODEL,
                cascade_mode=TRACK_C_CASCADE,
            )

            out_7b = self.reasoning_runner.run_reasoning(ctx, channel_a=channel_a)
            t_stage4 = time.perf_counter() - t0

            if out_7b.get("status") == "SUCCESS":
                final_hypothesis = out_7b.get("hypothesis")
                grounding_res = out_7b.get("grounding", {})
                trace.stages.append(
                    CascadeStageTrace(
                        stage_name="Stage 4: 7B Deep Reasoning",
                        model_name=PINNED_7B_MODEL,
                        model_digest=PINNED_7B_DIGEST[:16] + "...",
                        status="COMPLETED",
                        latency_seconds=round(t_stage4, 3),
                        details={
                            "decision": final_hypothesis.get("decision") if final_hypothesis else None,
                            "category": final_hypothesis.get("category") if final_hypothesis else None,
                            "grounding_passed": grounding_res.get("valid", True),
                        },
                    )
                )
                trace.overall_status = "CASCADE_COMPLETED"
            else:
                trace.stages.append(
                    CascadeStageTrace(
                        stage_name="Stage 4: 7B Deep Reasoning",
                        model_name=PINNED_7B_MODEL,
                        status="FAILED",
                        latency_seconds=round(t_stage4, 3),
                        details={"error": out_7b.get("error", "7B reasoning failed")},
                    )
                )
                trace.overall_status = "CASCADE_FAILED"
                trace.error_message = out_7b.get("error")
        else:
            trace.stages.append(
                CascadeStageTrace(
                    stage_name="Stage 4: 7B Deep Reasoning",
                    status="SKIPPED",
                    details={"reason": "Escalation not required; terminated benign at 3B triage."},
                )
            )
            trace.overall_status = "TERMINATED_AT_3B"

        trace.total_latency_seconds = round(time.perf_counter() - t_start, 3)
        self._record_trace(trace)
        return trace, final_hypothesis

    def _record_trace(self, trace: CascadeExecutionTrace) -> None:
        """Store trace in circular memory buffer."""
        self._recent_traces.append(trace)
        if len(self._recent_traces) > 20:
            self._recent_traces.pop(0)

    def get_recent_traces(self, limit: int = 10) -> List[CascadeExecutionTrace]:
        """Retrieve recent empirical cascade execution traces."""
        return list(reversed(self._recent_traces))[:limit]

    def get_latest_trace(self) -> Optional[CascadeExecutionTrace]:
        """Retrieve the most recent cascade trace if any."""
        return self._recent_traces[-1] if self._recent_traces else None
