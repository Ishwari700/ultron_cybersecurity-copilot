"""Continuation context framing, loop guards, and prompt engineering for M11.5 Long Response Subsystem.
Maintains seamless response flow without restarting answers or exceeding local hardware memory envelopes.
"""

from dataclasses import dataclass
import re
from typing import Optional, Tuple
from pydantic import BaseModel
from src.response.models import GenerationTermination, ResponseStatus


class ContinuationPrompt(BaseModel):
    """Structured continuation prompt payload with bounded context window."""
    prompt_text: str
    suffix_context: str
    repacking_performed: bool = False


class ContinuationDecision(BaseModel):
    """Decision whether continuation should proceed."""
    allow_continuation: bool
    reason: str
    termination: Optional[GenerationTermination] = None
    target_status: ResponseStatus = ResponseStatus.CONTINUING


class ContinuationContextManager:
    """
    Manages context framing, token budgets, and prompt assembly
    for seamless continuation across multiple sequential chunks.
    """

    DEFAULT_SUFFIX_WINDOW_CHARS = 800  # ~200 tokens of trailing context

    def __init__(
        self,
        suffix_window_chars: int = DEFAULT_SUFFIX_WINDOW_CHARS,
        max_continuation_chunks: int = 8,
        max_cumulative_tokens: int = 4096,
        max_repacking_attempts: int = 3,
    ) -> None:
        self.suffix_window_chars = suffix_window_chars
        self.max_continuation_chunks = max_continuation_chunks
        self.max_cumulative_tokens = max_cumulative_tokens
        self.max_repacking_attempts = max_repacking_attempts

    def check_guard_rails(
        self,
        current_chunk_count: int,
        cumulative_tokens: int,
        repacking_attempts: int,
        user_cancelled: bool = False,
    ) -> ContinuationDecision:
        """Evaluate hard safety and resource ceilings before initiating continuation."""
        if user_cancelled:
            return ContinuationDecision(
                allow_continuation=False,
                reason="User cancelled response generation",
                termination=GenerationTermination.CLIENT_ABORT,
                target_status=ResponseStatus.USER_STOPPED,
            )

        if current_chunk_count >= self.max_continuation_chunks:
            return ContinuationDecision(
                allow_continuation=False,
                reason=f"Reached maximum continuation chunk cap ({self.max_continuation_chunks})",
                termination=GenerationTermination.MAX_CHUNKS_REACHED,
                target_status=ResponseStatus.TOKEN_LIMIT,
            )

        if cumulative_tokens >= self.max_cumulative_tokens:
            return ContinuationDecision(
                allow_continuation=False,
                reason=f"Reached maximum cumulative tokens cap ({self.max_cumulative_tokens})",
                termination=GenerationTermination.SAFETY_BOUND_EXCEEDED,
                target_status=ResponseStatus.TOKEN_LIMIT,
            )

        if repacking_attempts >= self.max_repacking_attempts:
            return ContinuationDecision(
                allow_continuation=False,
                reason=f"Reached maximum context repacking attempts ({self.max_repacking_attempts})",
                termination=GenerationTermination.CONTEXT_EXHAUSTION,
                target_status=ResponseStatus.CONTEXT_LIMIT,
            )

        return ContinuationDecision(
            allow_continuation=True,
            reason="Continuation approved within hardware and safety bounds",
            termination=None,
            target_status=ResponseStatus.CONTINUING,
        )

    def extract_suffix_context(self, accumulated_text: str) -> str:
        """Extract bounded trailing window of prior text to anchor continuation."""
        if not accumulated_text:
            return ""
        if len(accumulated_text) <= self.suffix_window_chars:
            return accumulated_text
        return accumulated_text[-self.suffix_window_chars:]

    def build_continuation_prompt(
        self,
        system_policy: str,
        user_prompt: str,
        accumulated_text: str,
        target_asset: Optional[str] = None,
    ) -> ContinuationPrompt:
        """
        Assemble tight continuation prompt instructing model to resume directly
        from the exact boundary point without duplication or meta-text.
        """
        suffix = self.extract_suffix_context(accumulated_text)

        # Detect if we ended inside an open code block
        code_fence_count = len(re.findall(r"(?<!\\)```", accumulated_text))
        inside_code_block = (code_fence_count % 2) != 0

        code_block_guidance = (
            "You are currently INSIDE an unclosed markdown code block. "
            "Resume typing the code immediately without repeating the opening backticks. "
            "Close the code block with ``` when code finishes."
            if inside_code_block
            else ""
        )

        prompt = (
            f"{system_policy}\n\n"
            f"Original Request:\n{user_prompt}\n\n"
            f"[CONTINUATION DIRECTIVE]\n"
            f"Your prior response was interrupted by an execution token ceiling.\n"
            f"CRITICAL INSTRUCTIONS:\n"
            f"1. Resume directly from the exact point where the text below stops.\n"
            f"2. DO NOT restart the explanation. DO NOT summarize what came before.\n"
            f"3. DO NOT repeat the last sentence or phrase.\n"
            f"4. DO NOT include meta-commentary, greetings, or prefixes like 'Continuing...'.\n"
            f"{code_block_guidance}\n\n"
            f"--- TEXT PRIOR TO INTERRUPTION ---\n"
            f"{suffix}\n"
            f"--- END OF PRIOR TEXT ---\n\n"
            f"Resume immediately from above without repeating:"
        )

        return ContinuationPrompt(
            prompt_text=prompt,
            suffix_context=suffix,
            repacking_performed=False,
        )
