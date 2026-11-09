"""Conservative multi-signal completeness detector for M11.5 Long Response Subsystem.
Evaluates model stop reason, structural markdown, code fences, bracket balance,
and punctuation to distinguish natural completion from premature token-limit truncation.
"""

from dataclasses import dataclass, field
import re
from typing import Any, Dict, Optional
from pydantic import BaseModel
from src.response.models import CompletenessState

# Default configuration bounds tailored for local hardware (Ryzen 5 5600H, 4GB VRAM)
DEFAULT_MAX_CONTINUATION_CHUNKS = 8
DEFAULT_MAX_CUMULATIVE_TOKENS = 4096
DEFAULT_MAX_CONTEXT_REPACKING_ATTEMPTS = 3
DEFAULT_CHUNK_NUM_PREDICT = 512
DEFAULT_CHUNK_NUM_CTX = 4096


class CompletenessEvaluation(BaseModel):
    """Result of multi-signal completeness analysis."""
    state: CompletenessState
    confidence: float
    should_continue: bool
    rationale: str
    signals: Dict[str, Any] = field(default_factory=dict)


class CompletenessDetector:
    """
    Conservative completeness detector evaluating syntactic, semantic,
    and runtime signals to determine whether an answer requires continuation.
    """

    def __init__(
        self,
        max_continuation_chunks: int = DEFAULT_MAX_CONTINUATION_CHUNKS,
        max_cumulative_tokens: int = DEFAULT_MAX_CUMULATIVE_TOKENS,
    ) -> None:
        self.max_continuation_chunks = max_continuation_chunks
        self.max_cumulative_tokens = max_cumulative_tokens

    def evaluate(
        self,
        text: str,
        stop_reason: Optional[str] = None,
        cumulative_tokens: int = 0,
        chunk_count: int = 1,
    ) -> CompletenessEvaluation:
        """
        Evaluate completeness across multiple signals.
        Returns a typed CompletenessEvaluation with state and continuation decision.
        """
        stripped = text.strip() if text else ""
        if not stripped:
            return CompletenessEvaluation(
                state=CompletenessState.INCOMPLETE,
                confidence=1.0,
                should_continue=False,
                rationale="Response text is empty; inference yielded no content",
                signals={"empty": True},
            )

        signals: Dict[str, Any] = {}
        signals["stop_reason"] = stop_reason

        # 1. Code fence balance (```)
        code_fence_count = len(re.findall(r"(?<!\\)```", text))
        unclosed_code_fence = (code_fence_count % 2) != 0
        signals["code_fence_count"] = code_fence_count
        signals["unclosed_code_fence"] = unclosed_code_fence

        # 2. Dangling markdown headings (e.g., "# " or "## Vulnerability Analysis" without body)
        lines = stripped.split("\n")
        last_line = lines[-1].strip() if lines else ""
        dangling_heading = bool(re.match(r"^#{1,6}\s*$", last_line)) or (
            bool(re.match(r"^#{1,6}\s+[A-Za-z0-9_ -]+$", last_line)) and len(lines) > 1 and stop_reason == "length"
        )
        signals["dangling_heading"] = dangling_heading

        # 3. Unfinished bullet or numbered lists (e.g. trailing "1. " or "- ")
        unfinished_list = bool(re.search(r"(\n|^)([-*+]|\d+\.)\s*$", stripped))
        signals["unfinished_list"] = unfinished_list

        # 4. Dangling colon (e.g., "The following payload illustrates the exploit:")
        dangling_colon = stripped.endswith(":") or stripped.endswith(":-")
        signals["dangling_colon"] = dangling_colon

        # 5. Incomplete markdown table (e.g. table header separator row with no body, or unclosed row)
        incomplete_table = False
        if "|" in last_line:
            # If row doesn't end with '|' or is separator row '|---|---|'
            if not last_line.endswith("|") or re.match(r"^\|(\s*:?-+:?\s*\|)+$", last_line):
                incomplete_table = True
        signals["incomplete_table"] = incomplete_table

        # 6. Bracket balances for structured code / JSON / dictionaries
        open_curly = text.count("{") - text.count("}")
        open_square = text.count("[") - text.count("]")
        open_paren = text.count("(") - text.count(")")
        signals["open_curly"] = open_curly
        signals["open_square"] = open_square
        signals["open_paren"] = open_paren

        # 7. Terminal punctuation
        ends_with_terminal_punct = bool(re.search(r"([.!?]|\.\.\.|[\"'\)\]\}])\s*$", stripped))
        ends_with_alphanumeric = bool(re.search(r"[A-Za-z0-9]$", stripped))
        ends_with_comma_or_dash = bool(re.search(r"[,;/\-]\s*$", stripped))
        signals["ends_with_terminal_punct"] = ends_with_terminal_punct
        signals["ends_with_alphanumeric"] = ends_with_alphanumeric
        signals["ends_with_comma_or_dash"] = ends_with_comma_or_dash

        # Check safety caps
        is_structurally_incomplete = (
            unclosed_code_fence
            or dangling_heading
            or unfinished_list
            or dangling_colon
            or incomplete_table
            or stop_reason == "length"
            or ends_with_comma_or_dash
            or (ends_with_alphanumeric and not ends_with_terminal_punct)
        )

        if chunk_count >= self.max_continuation_chunks:
            signals["max_chunks_reached"] = True
            return CompletenessEvaluation(
                state=CompletenessState.INCOMPLETE if is_structurally_incomplete else CompletenessState.COMPLETE,
                confidence=0.95,
                should_continue=False,
                rationale=(
                    f"Hard safety bound reached: max chunks ({self.max_continuation_chunks}) reached with incomplete response"
                    if is_structurally_incomplete
                    else f"Hard safety bound reached: max chunks ({self.max_continuation_chunks}) reached"
                ),
                signals=signals,
            )

        if cumulative_tokens >= self.max_cumulative_tokens:
            signals["max_tokens_reached"] = True
            return CompletenessEvaluation(
                state=CompletenessState.INCOMPLETE if is_structurally_incomplete else CompletenessState.COMPLETE,
                confidence=0.95,
                should_continue=False,
                rationale=(
                    f"Hard safety bound reached: max tokens ({self.max_cumulative_tokens}) reached with incomplete response"
                    if is_structurally_incomplete
                    else f"Hard safety bound reached: max tokens ({self.max_cumulative_tokens}) reached"
                ),
                signals=signals,
            )

        # Decision synthesis
        # Rule A: Unclosed code fence is an unambiguous signal of mid-generation truncation
        if unclosed_code_fence:
            return CompletenessEvaluation(
                state=CompletenessState.INCOMPLETE,
                confidence=0.98,
                should_continue=True,
                rationale="Unmatched markdown code fence (odd number of triple backticks)",
                signals=signals,
            )

        # Rule B: Dangling heading or dangling list item
        if dangling_heading or unfinished_list:
            return CompletenessEvaluation(
                state=CompletenessState.INCOMPLETE,
                confidence=0.95,
                should_continue=True,
                rationale="Dangling markdown heading or unfinished list item at output boundary",
                signals=signals,
            )

        # Rule C: Model explicitly hit token ceiling (length)
        if stop_reason == "length":
            if dangling_colon or ends_with_comma_or_dash or ends_with_alphanumeric or incomplete_table:
                return CompletenessEvaluation(
                    state=CompletenessState.INCOMPLETE,
                    confidence=0.96,
                    should_continue=True,
                    rationale="Token ceiling reached (stop_reason=length) with incomplete sentence or structure",
                    signals=signals,
                )
            elif open_curly > 0 or open_square > 0:
                return CompletenessEvaluation(
                    state=CompletenessState.INCOMPLETE,
                    confidence=0.92,
                    should_continue=True,
                    rationale="Token ceiling reached with unclosed JSON/code brackets",
                    signals=signals,
                )
            else:
                # Stopped on length, even if punctuation looks okay, it might have been cut off between sentences
                return CompletenessEvaluation(
                    state=CompletenessState.LIKELY_INCOMPLETE,
                    confidence=0.75,
                    should_continue=True,
                    rationale="Token ceiling reached (stop_reason=length) at sentence boundary",
                    signals=signals,
                )

        # Rule D: Model signaled natural stop (stop_reason == 'stop')
        if stop_reason == "stop":
            if dangling_colon:
                # Dangling colon even with stop reason is likely incomplete
                return CompletenessEvaluation(
                    state=CompletenessState.LIKELY_INCOMPLETE,
                    confidence=0.80,
                    should_continue=True,
                    rationale="Model reported stop, but ended on a dangling colon expecting continuation",
                    signals=signals,
                )
            elif incomplete_table:
                return CompletenessEvaluation(
                    state=CompletenessState.LIKELY_INCOMPLETE,
                    confidence=0.78,
                    should_continue=True,
                    rationale="Model reported stop, but markdown table was left unclosed",
                    signals=signals,
                )
            elif ends_with_terminal_punct or stripped.endswith("```"):
                return CompletenessEvaluation(
                    state=CompletenessState.COMPLETE,
                    confidence=0.98,
                    should_continue=False,
                    rationale="Natural model stop reached with valid terminal punctuation and balanced structures",
                    signals=signals,
                )
            else:
                return CompletenessEvaluation(
                    state=CompletenessState.LIKELY_COMPLETE,
                    confidence=0.85,
                    should_continue=False,
                    rationale="Natural model stop reached with acceptable trailing structure",
                    signals=signals,
                )

        # Rule E: No stop reason provided (static text analysis)
        if dangling_colon or ends_with_comma_or_dash:
            return CompletenessEvaluation(
                state=CompletenessState.LIKELY_INCOMPLETE,
                confidence=0.85,
                should_continue=True,
                rationale="Text terminates with dangling colon or connector punctuation",
                signals=signals,
            )
        elif ends_with_alphanumeric and not ends_with_terminal_punct:
            return CompletenessEvaluation(
                state=CompletenessState.LIKELY_INCOMPLETE,
                confidence=0.75,
                should_continue=True,
                rationale="Text terminates abruptly on alphanumeric token without closing punctuation",
                signals=signals,
            )
        elif ends_with_terminal_punct:
            return CompletenessEvaluation(
                state=CompletenessState.COMPLETE,
                confidence=0.90,
                should_continue=False,
                rationale="Text terminates with standard closing punctuation and balanced structures",
                signals=signals,
            )

        return CompletenessEvaluation(
            state=CompletenessState.UNKNOWN,
            confidence=0.50,
            should_continue=False,
            rationale="Ambiguous structural signals",
            signals=signals,
        )
