"""Core Long Response Engine orchestrating chunk generation, automatic continuation,
overlap resolution, completeness evaluation, and persistent lineage.
"""

from datetime import datetime, timezone
import secrets
import time
from typing import Any, Callable, Dict, List, Optional
from src.core.logging import get_logger
from src.evidence.vault import RedactionVault
from src.database.manager import DatabaseManager
from src.response.citation import CitationContext, ResponseCitationValidator
from src.response.completeness import (
    CompletenessDetector,
    DEFAULT_CHUNK_NUM_CTX,
    DEFAULT_CHUNK_NUM_PREDICT,
    DEFAULT_MAX_CONTINUATION_CHUNKS,
    DEFAULT_MAX_CUMULATIVE_TOKENS,
)
from src.response.continuation import ContinuationContextManager
from src.response.errors import (
    ContinuationLimitError,
    ResponseEngineError,
    UserCancelledError,
)
from src.response.merger import ResponseMerger
from src.response.metrics import ResponseTelemetry
from src.response.models import (
    CitationReference,
    CompletenessState,
    EpistemicStatus,
    GenerationTermination,
    ResponseChunk,
    ResponseSession,
    ResponseStatus,
    ResponseValidationReport,
    ResponseVersion,
    RuntimeOutcome,
    compute_content_hash,
)
from src.response.persistence import ResponsePersistence
from src.response.routing import InferenceConcurrencyGate, ModelRouter, TaskType
from src.response.stream import CancellationToken, ResponseStreamHandler, StreamEvent

logger = get_logger("LongResponseEngine")

DEFAULT_SYSTEM_POLICY = (
    "You are Ultron, a rigorous local security research assistant. "
    "You operate strictly locally on the researcher's workstation. "
    "You assist researchers in analyzing target evidence, modeling application behavior, "
    "identifying security invariants, formulating hypotheses, and preparing experiments for human review. "
    "Respond helpfully, accurately, and naturally to technical cybersecurity inquiries. "
    "Do NOT fabricate target endpoints, pretend evidence exists, or invent findings."
)


DEFAULT_CHUNK_TIMEOUT = 120.0


class LongResponseEngine:
    """
    Production response delivery engine for long cybersecurity analyses.
    Eliminates silent truncation by coordinating bounded multi-chunk generation,
    overlap pruning, and deterministic provenance recording.
    """

    def __init__(
        self,
        db_manager: DatabaseManager,
        ollama_client: Optional[Any] = None,
        max_continuation_chunks: int = DEFAULT_MAX_CONTINUATION_CHUNKS,
        max_cumulative_tokens: int = DEFAULT_MAX_CUMULATIVE_TOKENS,
        chunk_num_predict: int = DEFAULT_CHUNK_NUM_PREDICT,
        chunk_num_ctx: int = DEFAULT_CHUNK_NUM_CTX,
        timeout_seconds: float = DEFAULT_CHUNK_TIMEOUT,
        custom_llm_caller: Optional[Callable[[str, int], Dict[str, Any]]] = None,
    ) -> None:
        self.db_manager = db_manager
        self.persistence = ResponsePersistence(db_manager)
        self.ollama_client = ollama_client
        self.custom_llm_caller = custom_llm_caller
        self.max_continuation_chunks = max_continuation_chunks
        self.max_cumulative_tokens = max_cumulative_tokens
        self.chunk_num_predict = chunk_num_predict
        self.chunk_num_ctx = chunk_num_ctx
        self.timeout_seconds = timeout_seconds

        self.completeness_detector = CompletenessDetector(
            max_continuation_chunks=max_continuation_chunks,
            max_cumulative_tokens=max_cumulative_tokens,
        )
        self.merger = ResponseMerger()
        self.context_manager = ContinuationContextManager(
            max_continuation_chunks=max_continuation_chunks,
            max_cumulative_tokens=max_cumulative_tokens,
        )
        self.telemetry = ResponseTelemetry.get_instance()
        self.vault = RedactionVault()

    @staticmethod
    def _balance_code_fences(text: str) -> str:
        """Ensure all opened markdown code blocks (```) are closed upon truncation."""
        if not text:
            return text
        fence_count = text.count("```")
        if fence_count % 2 != 0:
            return text + "\n```\n"
        return text

    def generate_response(
        self,
        investigation_id: str,
        user_prompt: str,
        system_policy: Optional[str] = None,
        parent_message_id: Optional[str] = None,
        model_name: str = "qwen2.5-coder:7b",
        cancellation_token: Optional[CancellationToken] = None,
        stream_callback: Optional[Callable[[StreamEvent], None]] = None,
        auto_continue: bool = True,
        temperature: float = 0.7,
        custom_llm_caller: Optional[Callable[[str, int], Dict[str, Any]]] = None,
        request_id: Optional[str] = None,
        assessment_id: Optional[str] = None,
        citation_context: Optional[CitationContext] = None,
        task_type: TaskType = TaskType.CONVERSATIONAL_QA,
        response_id: Optional[str] = None,
    ) -> ResponseSession:
        """
        Execute full response generation with progressive chunk continuation.
        Ensures that responses ending on token ceilings automatically continue
        up to configured safety limits, and are never falsely marked as completed.
        """
        cancel_token = cancellation_token or CancellationToken()
        stream_handler = ResponseStreamHandler(cancel_token)
        response_id = response_id or f"RESP-{secrets.token_hex(6).upper()}"
        effective_system_policy = system_policy or DEFAULT_SYSTEM_POLICY
        effective_custom_llm = custom_llm_caller or getattr(self, "custom_llm_caller", None)

        # Model routing & readiness check
        if effective_custom_llm:
            is_ready = True
            status_reason = "AVAILABLE"
            actual_model = model_name
            requested_model = model_name
            fallback_model = None
            fallback_used = False
            fallback_reason = None
        else:
            decision = ModelRouter.route_task(
                task_type=task_type,
                ollama_client=self.ollama_client,
                override_model=model_name if model_name != "qwen2.5-coder:7b" else None,
            )
            is_ready = decision.runtime_available
            status_reason = decision.runtime_status
            actual_model = decision.selected_model
            requested_model = decision.configured_model
            fallback_model = decision.fallback_model
            fallback_used = decision.fallback_used
            fallback_reason = decision.fallback_reason

        now_iso = datetime.now(timezone.utc).isoformat()
        session = ResponseSession(
            response_id=response_id,
            investigation_id=investigation_id,
            assessment_id=assessment_id,
            request_id=request_id,
            parent_message_id=parent_message_id,
            model=actual_model,
            requested_model=requested_model,
            fallback_model=fallback_model,
            fallback_used=fallback_used,
            fallback_reason=fallback_reason,
            user_prompt=user_prompt,
            chunks=[],
            cumulative_tokens=0,
            status=ResponseStatus.GENERATING,
            termination_reason=None,
            final_content="",
            started_at=now_iso,
            epistemic_status=EpistemicStatus.MODEL_INFERENCE,
            runtime_outcome=RuntimeOutcome.SUCCESS if is_ready else RuntimeOutcome.DAEMON_UNAVAILABLE,
            model_config_params={
                "temperature": temperature,
                "num_predict": self.chunk_num_predict,
                "num_ctx": self.chunk_num_ctx,
                "timeout_seconds": self.timeout_seconds,
            },
        )
        self.persistence.create_session(session)
        self.telemetry.record_generation_start(response_id, actual_model)

        if stream_callback:
            stream_callback(stream_handler.emit_status(ResponseStatus.GENERATING))

        accumulated_text = ""
        chunk_sequence = 1
        repacking_attempts = 0
        final_termination = GenerationTermination.NATURAL_STOP
        final_status = ResponseStatus.COMPLETED
        t0_total = time.perf_counter()

        # If LLM is offline and no custom mock caller is provided, fail honestly
        if not is_ready and not effective_custom_llm:
            final_status = ResponseStatus.SERVICE_UNAVAILABLE
            final_termination = GenerationTermination.DAEMON_UNAVAILABLE
            session.runtime_outcome = RuntimeOutcome.DAEMON_UNAVAILABLE
            accumulated_text = (
                f"The local language model inference service (Ollama on 127.0.0.1:11434) is currently offline or unreachable. "
                f"Details: {status_reason}. Please ensure Ollama is running (`ollama serve`) and `{model_name}` is pulled."
            )
            session.final_content = accumulated_text
            session.status = final_status
            session.termination_reason = final_termination
            session.completed_at = datetime.now(timezone.utc).isoformat()
            self.persistence.update_session(
                response_id=response_id,
                status=final_status,
                final_content=accumulated_text,
                cumulative_tokens=0,
                termination_reason=final_termination,
                completed_at=session.completed_at,
                runtime_outcome=session.runtime_outcome.value,
            )
            if stream_callback:
                stream_callback(
                    stream_handler.emit_error(
                        response_id, f"Inference engine offline: {status_reason}", accumulated_text
                    )
                )
            return session

        # Concurrency Gate: Bound local GPU VRAM to concurrency 1
        gate = InferenceConcurrencyGate.get_instance()
        slot_acquired = gate.acquire(timeout=min(self.timeout_seconds, 60.0))
        if not slot_acquired:
            final_status = ResponseStatus.TIMEOUT
            final_termination = GenerationTermination.TIMEOUT_ABORT
            session.runtime_outcome = RuntimeOutcome.TIMEOUT
            accumulated_text = "Inference concurrency ceiling reached: local hardware inference slot busy."
            session.final_content = accumulated_text
            session.status = final_status
            session.termination_reason = final_termination
            session.completed_at = datetime.now(timezone.utc).isoformat()
            self.persistence.update_session(
                response_id=response_id,
                status=final_status,
                final_content=accumulated_text,
                cumulative_tokens=0,
                termination_reason=final_termination,
                completed_at=session.completed_at,
                runtime_outcome=session.runtime_outcome.value,
            )
            return session

        try:
            while chunk_sequence <= self.max_continuation_chunks:
                # 1. Check user cancellation
                if cancel_token.is_cancelled:
                    final_status = ResponseStatus.USER_STOPPED
                    final_termination = GenerationTermination.CLIENT_ABORT
                    self.telemetry.record_user_stop(response_id, session.cumulative_tokens)
                    if stream_callback:
                        stream_callback(
                            stream_handler.emit_stopped(
                                response_id, accumulated_text, session.cumulative_tokens
                            )
                        )
                    break

                # 2. Check safety / resource bounds
                guard_decision = self.context_manager.check_guard_rails(
                    current_chunk_count=chunk_sequence,
                    cumulative_tokens=session.cumulative_tokens,
                    repacking_attempts=repacking_attempts,
                    user_cancelled=cancel_token.is_cancelled,
                )
                if not guard_decision.allow_continuation and chunk_sequence > 1:
                    final_status = guard_decision.target_status
                    final_termination = guard_decision.termination or GenerationTermination.SAFETY_BOUND_EXCEEDED
                    break

                # 3. Assemble prompt for chunk
                is_continuation = chunk_sequence > 1
                if is_continuation:
                    cont_prompt_obj = self.context_manager.build_continuation_prompt(
                        system_policy=effective_system_policy,
                        user_prompt=user_prompt,
                        accumulated_text=accumulated_text,
                    )
                    current_prompt = cont_prompt_obj.prompt_text
                    if stream_callback:
                        stream_callback(stream_handler.emit_status(ResponseStatus.CONTINUING))
                else:
                    current_prompt = (
                        f"{effective_system_policy}\n\n"
                        f"User: {user_prompt}\n"
                        f"Assistant:"
                    )

                # 4. Invoke LLM for chunk
                chunk_t0 = time.perf_counter()
                raw_text = ""
                stop_reason = "stop"
                eval_tokens = 0

                try:
                    if effective_custom_llm:
                        llm_res = effective_custom_llm(current_prompt, self.chunk_num_predict)
                        raw_text = llm_res.get("response", "")
                        stop_reason = llm_res.get("done_reason", "stop")
                        eval_tokens = llm_res.get("eval_count", len(raw_text.split()))
                    elif self.ollama_client and self.ollama_client.is_available():
                        resp = self.ollama_client.generate_raw(
                            prompt=current_prompt,
                            temperature=temperature,
                            num_predict=self.chunk_num_predict,
                            num_ctx=self.chunk_num_ctx,
                            timeout_seconds=self.timeout_seconds,
                            cancellation_token=cancel_token,
                        )
                        raw_text = resp.get("response", "")
                        stop_reason = resp.get("done_reason", "stop")
                        eval_tokens = resp.get("eval_count", len(raw_text.split()))
                    else:
                        final_status = ResponseStatus.SERVICE_UNAVAILABLE
                        final_termination = GenerationTermination.DAEMON_UNAVAILABLE
                        raw_text = ""
                        break

                except AttributeError:
                    raise
                except TimeoutError as te:
                    self.telemetry.record_timeout(response_id, time.perf_counter() - chunk_t0)
                    final_status = ResponseStatus.TIMEOUT
                    final_termination = GenerationTermination.TIMEOUT_ABORT
                    session.runtime_outcome = RuntimeOutcome.TIMEOUT
                    if stream_callback:
                        stream_callback(
                            stream_handler.emit_error(
                                response_id, f"Inference timed out: {te}", accumulated_text
                            )
                        )
                    break
                except Exception as e:
                    self.telemetry.record_error(response_id, str(e))
                    final_status = ResponseStatus.ERROR
                    final_termination = GenerationTermination.ENGINE_ERROR
                    session.runtime_outcome = RuntimeOutcome.ENGINE_ERROR
                    if stream_callback:
                        stream_callback(
                            stream_handler.emit_error(
                                response_id, f"Inference engine failure: {e}", accumulated_text
                            )
                        )
                    break

                chunk_latency = time.perf_counter() - chunk_t0

                # Immediate user cancellation check after inference
                if cancel_token.is_cancelled or stop_reason == "abort":
                    final_status = ResponseStatus.USER_STOPPED
                    final_termination = GenerationTermination.CLIENT_ABORT
                    self.telemetry.record_user_stop(response_id, session.cumulative_tokens)
                    if stream_callback:
                        stream_callback(
                            stream_handler.emit_stopped(
                                response_id, accumulated_text, session.cumulative_tokens
                            )
                        )
                    break

                # Empty chunk detection
                if not raw_text.strip():
                    if chunk_sequence == 1:
                        final_status = ResponseStatus.ERROR
                        final_termination = GenerationTermination.ENGINE_ERROR
                        accumulated_text = "Model returned empty response."
                    break

                # 5. Overlap detection and chunk merging
                if is_continuation:
                    merged_text, overlap_res = self.merger.merge_chunks(accumulated_text, raw_text)
                    if overlap_res.overlap_detected:
                        self.telemetry.record_overlap_pruned(
                            response_id, chunk_sequence, overlap_res.overlap_length
                        )
                    cleaned_chunk_content = overlap_res.cleaned_chunk
                    accumulated_text = self.merger.deduplicate_response_content(merged_text)
                else:
                    cleaned_chunk_content = raw_text
                    accumulated_text = self.merger.deduplicate_response_content(raw_text)

                # 6. Record Chunk
                chunk_id = f"CHK-{response_id}-{chunk_sequence}"
                chunk_obj = ResponseChunk(
                    chunk_id=chunk_id,
                    sequence_number=chunk_sequence,
                    content=cleaned_chunk_content,
                    raw_content=raw_text,
                    content_hash=compute_content_hash(cleaned_chunk_content),
                    token_count=eval_tokens,
                    generation_time=round(chunk_latency, 4),
                    stop_reason=stop_reason,
                )
                session.add_chunk(chunk_obj)
                self.persistence.save_chunk(response_id, chunk_obj)
                self.telemetry.record_chunk(
                    session_id=response_id,
                    chunk_index=chunk_sequence,
                    tokens=eval_tokens,
                    latency=chunk_latency,
                    stop_reason=stop_reason,
                    is_continuation=is_continuation,
                )

                if stream_callback:
                    stream_callback(
                        stream_handler.emit_chunk_complete(
                            chunk_id, chunk_sequence, eval_tokens, stop_reason
                        )
                    )

                # 7. Multi-Signal Completeness Evaluation
                eval_result = self.completeness_detector.evaluate(
                    text=accumulated_text,
                    stop_reason=stop_reason,
                    cumulative_tokens=session.cumulative_tokens,
                    chunk_count=chunk_sequence,
                )

                # 8. Determine if continuation is warranted
                if eval_result.should_continue and auto_continue:
                    if chunk_sequence >= self.max_continuation_chunks:
                        final_status = ResponseStatus.TOKEN_LIMIT
                        final_termination = GenerationTermination.LENGTH_CEILING
                        break
                    # If stop reason was length, proceed with next chunk
                    chunk_sequence += 1
                    session.status = ResponseStatus.CONTINUING
                    self.persistence.update_session(
                        response_id=response_id,
                        status=ResponseStatus.CONTINUING,
                        final_content=accumulated_text,
                        cumulative_tokens=session.cumulative_tokens,
                    )
                    continue
                else:
                    # Natural completion or continuation halted
                    if stop_reason == "length" or eval_result.should_continue or eval_result.state == CompletenessState.INCOMPLETE:
                        final_status = ResponseStatus.TOKEN_LIMIT
                        final_termination = GenerationTermination.LENGTH_CEILING
                    elif eval_result.state in (
                        CompletenessState.COMPLETE,
                        CompletenessState.LIKELY_COMPLETE,
                    ):
                        final_status = ResponseStatus.COMPLETED
                        final_termination = GenerationTermination.NATURAL_STOP
                    else:
                        final_status = ResponseStatus.TOKEN_LIMIT
                        final_termination = GenerationTermination.LENGTH_CEILING
                    break
        finally:
            gate.release()

        # Enforce TOKEN_LIMIT if generation terminated while content was structurally incomplete
        if final_status == ResponseStatus.COMPLETED and eval_result is not None:
            if stop_reason == "length" or eval_result.should_continue or eval_result.state == CompletenessState.INCOMPLETE:
                final_status = ResponseStatus.TOKEN_LIMIT
                final_termination = GenerationTermination.LENGTH_CEILING

        # Balance unclosed code blocks so rendering and exports don't break
        if accumulated_text.count("```") % 2 != 0:
            accumulated_text += "\n```"
            session.is_truncated = True

        if final_status == ResponseStatus.TOKEN_LIMIT:
            session.is_truncated = True

        # Citation validation and epistemic grounding
        if citation_context:
            cite_res = ResponseCitationValidator.validate_citations(accumulated_text, citation_context)
            session.citations = cite_res.valid_citations
            session.sources = [c.source_id for c in cite_res.valid_citations]
            session.epistemic_status = cite_res.epistemic_status
            if not cite_res.all_valid:
                session.validation_passed = False
                session.validation_errors = cite_res.rejection_reasons
                if final_status == ResponseStatus.COMPLETED:
                    final_status = ResponseStatus.VALIDATION_FAILED
                    final_termination = GenerationTermination.VALIDATION_ERROR

        # Finalization
        total_latency = time.perf_counter() - t0_total
        completed_iso = datetime.now(timezone.utc).isoformat()
        balanced_text = self._balance_code_fences(accumulated_text)
        session.status = final_status
        session.termination_reason = final_termination
        session.final_content = balanced_text
        session.completed_at = completed_iso
        session.total_duration_seconds = round(total_latency, 4)

        self.persistence.update_session(
            response_id=response_id,
            status=final_status,
            final_content=balanced_text,
            cumulative_tokens=session.cumulative_tokens,
            termination_reason=final_termination,
            completed_at=completed_iso,
            epistemic_status=session.epistemic_status.value,
            runtime_outcome=session.runtime_outcome.value,
            validation_passed=session.validation_passed,
            validation_errors=session.validation_errors,
            citations=session.citations,
            total_duration_seconds=session.total_duration_seconds,
        )

        # Record Initial Version (v1)
        version_obj = ResponseVersion(
            version_id=f"VER-{response_id}-1",
            response_id=response_id,
            version_number=1,
            content=accumulated_text,
            model=model_name,
            status=final_status,
        )
        self.persistence.save_version(version_obj)

        self.telemetry.record_completion(
            session_id=response_id,
            total_chunks=len(session.chunks),
            total_tokens=session.cumulative_tokens,
            termination_reason=final_termination.value,
            finalization_latency=total_latency,
        )

        if stream_callback and final_status == ResponseStatus.COMPLETED:
            stream_callback(
                stream_handler.emit_complete(
                    response_id, accumulated_text, session.cumulative_tokens
                )
            )

        return session

    def continue_response(
        self,
        response_id: str,
        user_prompt: str,
        system_policy: Optional[str] = None,
        custom_llm_caller: Optional[Callable[[str, int], Dict[str, Any]]] = None,
        citation_context: Optional[CitationContext] = None,
        cancellation_token: Optional[CancellationToken] = None,
    ) -> ResponseSession:
        """
        Explicit manual continuation for when an answer was halted by safety caps
        or auto-continuation was paused, and researcher requests to continue.
        """
        session = self.persistence.get_session(response_id)
        if not session:
            raise ResponseEngineError(f"Response session {response_id} not found")

        if cancellation_token and cancellation_token.is_cancelled:
            session.status = ResponseStatus.USER_STOPPED
            session.termination_reason = GenerationTermination.CLIENT_ABORT
            self.persistence.update_session(
                response_id=response_id,
                status=ResponseStatus.USER_STOPPED,
                final_content=session.final_content,
                cumulative_tokens=session.cumulative_tokens,
                termination_reason=GenerationTermination.CLIENT_ABORT,
                completed_at=datetime.now(timezone.utc).isoformat(),
            )
            return session

        current_chunk_count = len(session.chunks)
        next_chunk_seq = current_chunk_count + 1
        effective_system_policy = system_policy or DEFAULT_SYSTEM_POLICY

        # Mark session as continuing in persistence
        self.persistence.update_session(
            response_id=response_id,
            status=ResponseStatus.CONTINUING,
            final_content=session.final_content,
            cumulative_tokens=session.cumulative_tokens,
            termination_reason=session.termination_reason,
        )

        cont_prompt_obj = self.context_manager.build_continuation_prompt(
            system_policy=effective_system_policy,
            user_prompt=user_prompt,
            accumulated_text=session.final_content,
        )

        chunk_t0 = time.perf_counter()
        raw_text = ""
        stop_reason = "stop"
        eval_tokens = 0

        # Concurrency Gate
        gate = InferenceConcurrencyGate.get_instance()
        slot_acquired = gate.acquire(timeout=min(self.timeout_seconds, 60.0))
        if not slot_acquired:
            raise ResponseEngineError("Inference concurrency ceiling reached: local hardware slot busy")

        effective_custom_llm = custom_llm_caller or getattr(self, "custom_llm_caller", None)
        try:
            if effective_custom_llm:
                res = effective_custom_llm(cont_prompt_obj.prompt_text, self.chunk_num_predict)
                raw_text = res.get("response", "")
                stop_reason = res.get("done_reason", "stop")
                eval_tokens = res.get("eval_count", len(raw_text.split()))
            elif self.ollama_client and self.ollama_client.is_available():
                resp = self.ollama_client.generate_raw(
                    prompt=cont_prompt_obj.prompt_text,
                    temperature=0.7,
                    num_predict=self.chunk_num_predict,
                    num_ctx=self.chunk_num_ctx,
                    timeout_seconds=30.0,
                    cancellation_token=cancellation_token,
                )
                raw_text = resp.get("response", "")
                stop_reason = resp.get("done_reason", "stop")
                eval_tokens = resp.get("eval_count", len(raw_text.split()))
            else:
                session.status = ResponseStatus.SERVICE_UNAVAILABLE
                session.termination_reason = GenerationTermination.DAEMON_UNAVAILABLE
                session.runtime_outcome = RuntimeOutcome.DAEMON_UNAVAILABLE
                self.persistence.update_session(
                    response_id=response_id,
                    status=ResponseStatus.SERVICE_UNAVAILABLE,
                    final_content=session.final_content,
                    cumulative_tokens=session.cumulative_tokens,
                    termination_reason=GenerationTermination.DAEMON_UNAVAILABLE,
                    runtime_outcome=RuntimeOutcome.DAEMON_UNAVAILABLE.value,
                )
                return session
        finally:
            gate.release()

        # Immediate cancellation check upon completion of inference call
        if (cancellation_token and cancellation_token.is_cancelled) or stop_reason == "abort":
            session.status = ResponseStatus.USER_STOPPED
            session.termination_reason = GenerationTermination.CLIENT_ABORT
            self.persistence.update_session(
                response_id=response_id,
                status=ResponseStatus.USER_STOPPED,
                final_content=session.final_content,
                cumulative_tokens=session.cumulative_tokens,
                termination_reason=GenerationTermination.CLIENT_ABORT,
                completed_at=datetime.now(timezone.utc).isoformat(),
            )
            return session

        chunk_latency = time.perf_counter() - chunk_t0

        merged_text, overlap_res = self.merger.merge_chunks(session.final_content, raw_text)
        merged_text = self.merger.deduplicate_response_content(merged_text)
        if overlap_res.overlap_detected:
            self.telemetry.record_overlap_pruned(
                response_id, next_chunk_seq, overlap_res.overlap_length
            )

        chunk_id = f"CHK-{response_id}-{next_chunk_seq}"
        chunk_obj = ResponseChunk(
            chunk_id=chunk_id,
            sequence_number=next_chunk_seq,
            content=overlap_res.cleaned_chunk,
            raw_content=raw_text,
            content_hash=compute_content_hash(overlap_res.cleaned_chunk),
            token_count=eval_tokens,
            generation_time=round(chunk_latency, 4),
            stop_reason=stop_reason,
        )
        session.add_chunk(chunk_obj)
        session.final_content = merged_text
        self.persistence.save_chunk(response_id, chunk_obj)

        eval_result = self.completeness_detector.evaluate(
            text=merged_text,
            stop_reason=stop_reason,
            cumulative_tokens=session.cumulative_tokens,
            chunk_count=next_chunk_seq,
        )

        new_status = (
            ResponseStatus.COMPLETED
            if eval_result.state in (CompletenessState.COMPLETE, CompletenessState.LIKELY_COMPLETE)
            else ResponseStatus.TOKEN_LIMIT
        )
        term_reason = (
            GenerationTermination.NATURAL_STOP
            if new_status == ResponseStatus.COMPLETED
            else GenerationTermination.LENGTH_CEILING
        )

        if new_status == ResponseStatus.TOKEN_LIMIT:
            session.is_truncated = True

        # Balance unclosed code blocks
        if merged_text.count("```") % 2 != 0:
            merged_text += "\n```"
            session.is_truncated = True

        # Citation validation
        if citation_context:
            cite_res = ResponseCitationValidator.validate_citations(merged_text, citation_context)
            session.citations = cite_res.valid_citations
            session.sources = [c.source_id for c in cite_res.valid_citations]
            session.epistemic_status = cite_res.epistemic_status
            if not cite_res.all_valid:
                session.validation_passed = False
                session.validation_errors = cite_res.rejection_reasons
                if new_status == ResponseStatus.COMPLETED:
                    new_status = ResponseStatus.VALIDATION_FAILED
                    term_reason = GenerationTermination.VALIDATION_ERROR

        session.status = new_status
        session.termination_reason = term_reason
        self.persistence.update_session(
            response_id=response_id,
            status=new_status,
            final_content=merged_text,
            cumulative_tokens=session.cumulative_tokens,
            termination_reason=term_reason,
            epistemic_status=session.epistemic_status.value,
            runtime_outcome=session.runtime_outcome.value,
            validation_passed=session.validation_passed,
            validation_errors=session.validation_errors,
            citations=session.citations,
        )

        return session

    def regenerate_response(
        self,
        response_id: str,
        user_prompt: str,
        system_policy: Optional[str] = None,
        custom_llm_caller: Optional[Callable[[str, int], Dict[str, Any]]] = None,
    ) -> ResponseSession:
        """
        Regenerate response from scratch, preserving prior generation as a historical
        version and generating a fresh answer without destroying canonical lineage.
        """
        existing_session = self.persistence.get_session(response_id)
        if not existing_session:
            raise ResponseEngineError(f"Cannot regenerate nonexistent session {response_id}")

        existing_versions = self.persistence.get_versions(response_id)
        next_ver_num = len(existing_versions) + 1

        # Generate fresh response
        new_session = self.generate_response(
            investigation_id=existing_session.investigation_id,
            user_prompt=user_prompt,
            system_policy=system_policy,
            parent_message_id=existing_session.parent_message_id,
            model_name=existing_session.model,
            custom_llm_caller=custom_llm_caller,
        )

        # Record as next version of the original session
        new_version_obj = ResponseVersion(
            version_id=f"VER-{response_id}-{next_ver_num}",
            response_id=response_id,
            version_number=next_ver_num,
            content=new_session.final_content,
            model=new_session.model,
            status=new_session.status,
        )
        self.persistence.save_version(new_version_obj)

        return new_session
