"""Deterministic Token Budget Controller ensuring prompts fit within the fixed context window."""

import json
import re
import urllib.error
import urllib.request
from enum import Enum
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable


class TokenCountMode(str, Enum):
    """Explicit token counting modes indicating precision and source."""
    EXACT_TOKENIZER = "EXACT_TOKENIZER"
    REMOTE_TOKENIZER_UNAVAILABLE = "REMOTE_TOKENIZER_UNAVAILABLE"
    CALIBRATED_HEURISTIC = "CALIBRATED_HEURISTIC"
    CHAR_HEURISTIC = "CHAR_HEURISTIC"


@runtime_checkable
class TokenizerProtocol(Protocol):
    """Protocol for tokenizers providing exact or calibrated token counting."""

    def count_tokens(self, text: str) -> int:
        ...

    @property
    def is_exact(self) -> bool:
        ...

    @property
    def mode(self) -> str:
        ...


class BaseTokenizer(ABC):
    """Abstract base class for tokenizers."""

    @abstractmethod
    def count_tokens(self, text: str) -> int:
        """Return token count for input text."""
        pass

    @property
    @abstractmethod
    def is_exact(self) -> bool:
        """Whether this tokenizer provides exact model-matched token counts."""
        pass

    @property
    def mode(self) -> str:
        """Return token counting mode label."""
        return TokenCountMode.EXACT_TOKENIZER.value if self.is_exact else TokenCountMode.CALIBRATED_HEURISTIC.value


class CalibratedHeuristicTokenizer(BaseTokenizer):
    """
    Calibrated heuristic tokenizer that distinguishes natural language, JSON,
    code identifiers, and Unicode characters to avoid context overflow.
    """

    CODE_PUNCT_PATTERN = re.compile(r'[{}\[\]:,;"\'`=<>!&|+\-*/\\%^~]')

    def __init__(self, base_chars_per_token: float = 3.5, safety_margin: float = 1.1) -> None:
        self.base_chars_per_token = base_chars_per_token
        self.safety_margin = safety_margin

    @property
    def is_exact(self) -> bool:
        return False

    @property
    def mode(self) -> str:
        return TokenCountMode.CALIBRATED_HEURISTIC.value

    def count_tokens(self, text: str) -> int:
        if not text:
            return 0

        # Account for high density punctuation in JSON/code
        punct_count = len(self.CODE_PUNCT_PATTERN.findall(text))
        char_len = len(text)

        # High-punctuation or JSON payload has higher token density (~2.4 - 3.0 chars/tok)
        punct_ratio = punct_count / max(1, char_len)
        if punct_ratio > 0.15:
            effective_cpt = max(2.2, self.base_chars_per_token * 0.75)
        elif punct_ratio > 0.08:
            effective_cpt = max(2.8, self.base_chars_per_token * 0.88)
        else:
            effective_cpt = self.base_chars_per_token

        # Non-ASCII/multibyte characters consume multiple tokens per char in BPE
        non_ascii_count = sum(1 for c in text if ord(c) > 127)
        raw_estimate = (char_len / effective_cpt) + (non_ascii_count * 0.8)

        adjusted = int(raw_estimate * self.safety_margin)
        return max(1, adjusted)


class FastTokenizerAdapter(BaseTokenizer):
    """Adapter wrapping HuggingFace/tokenizers library tokenizers."""

    def __init__(self, tokenizer_instance: Any) -> None:
        self._tokenizer = tokenizer_instance

    @property
    def is_exact(self) -> bool:
        return True

    @property
    def mode(self) -> str:
        return TokenCountMode.EXACT_TOKENIZER.value

    def count_tokens(self, text: str) -> int:
        if not text:
            return 0
        try:
            encoding = self._tokenizer.encode(text)
            if hasattr(encoding, "ids"):
                return len(encoding.ids)
            elif isinstance(encoding, list):
                return len(encoding)
        except Exception:
            pass
        return max(1, int(len(text) / 3.5))


class OllamaRemoteTokenizer(BaseTokenizer):
    """Queries Ollama's native /api/tokenize endpoint when daemon is available."""

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model_name: str = "qwen2.5-coder:7b",
        timeout_seconds: float = 2.0,
        fallback: Optional[BaseTokenizer] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model_name = model_name
        self.timeout = timeout_seconds
        self.fallback = fallback or CalibratedHeuristicTokenizer()
        self._exact_mode_active: bool = False
        self._last_error: Optional[str] = None

    @property
    def is_exact(self) -> bool:
        return self._exact_mode_active

    @property
    def mode(self) -> str:
        return (
            TokenCountMode.EXACT_TOKENIZER.value
            if self._exact_mode_active
            else TokenCountMode.REMOTE_TOKENIZER_UNAVAILABLE.value
        )

    def count_tokens(self, text: str) -> int:
        if not text:
            return 0
        try:
            req_data = json.dumps({"model": self.model_name, "prompt": text}).encode("utf-8")
            req = urllib.request.Request(
                f"{self.base_url}/api/tokenize",
                data=req_data,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                tokens = data.get("tokens")
                if isinstance(tokens, list):
                    self._exact_mode_active = True
                    self._last_error = None
                    return len(tokens)
                else:
                    raise ValueError(f"Malformed tokenizer response: 'tokens' field is {type(tokens)}")
        except Exception as e:
            # Fall back to calibrated heuristic when endpoint is unavailable, 404, timed out, or response is malformed
            self._exact_mode_active = False
            self._last_error = str(e)
        return self.fallback.count_tokens(text)


class TokenBudgetController:
    """
    Computes context budgets for Qwen models and crops ranked retrieval results
    deterministically using tokenizer-aware counting to prevent silent Ollama truncations.
    """

    def __init__(
        self,
        tokenizer: Optional[TokenizerProtocol] = None,
        chars_per_token: float = 3.5,
    ) -> None:
        self.chars_per_token = chars_per_token
        self.tokenizer: Optional[TokenizerProtocol] = tokenizer
        self._cache: Dict[str, int] = {}
        self._cache_max_size = 512

    @property
    def is_exact(self) -> bool:
        return getattr(self.tokenizer, "is_exact", False) if self.tokenizer else False

    @property
    def token_count_mode(self) -> str:
        if self.tokenizer is not None:
            if hasattr(self.tokenizer, "mode"):
                return self.tokenizer.mode
            return TokenCountMode.EXACT_TOKENIZER.value if self.is_exact else TokenCountMode.CALIBRATED_HEURISTIC.value
        return TokenCountMode.CHAR_HEURISTIC.value

    def count_tokens(self, text: str) -> int:
        """Count tokens using active tokenizer or character heuristic."""
        if not text:
            return 0
        if self.tokenizer is not None:
            if len(text) < 4096 and text in self._cache:
                return self._cache[text]
            count = self.tokenizer.count_tokens(text)
            if len(text) < 4096:
                if len(self._cache) >= self._cache_max_size:
                    self._cache.clear()
                self._cache[text] = count
            return count
        return max(1, int(len(text) / self.chars_per_token))

    def estimate_tokens(self, text: str) -> int:
        """Backwards compatible token estimation method."""
        return self.count_tokens(text)

    def calculate_evidence_budget(
        self,
        num_ctx: int,
        system_prompt: str,
        schema_definition: str,
        max_output_tokens: int = 500,
        safety_headroom_tokens: int = 150,
    ) -> int:
        """
        Calculate remaining token budget specifically allocated for retrieved evidence:
        budget = num_ctx - prompt_tokens - schema_tokens - max_output_tokens - headroom
        """
        system_tokens = self.count_tokens(system_prompt)
        schema_tokens = self.count_tokens(schema_definition)
        overhead = system_tokens + schema_tokens + max_output_tokens + safety_headroom_tokens
        remaining = num_ctx - overhead
        return max(0, remaining)

    def crop_chunks_to_budget(
        self,
        ranked_chunks: List[Dict[str, Any]],
        token_budget: int,
        text_key: str = "statement",
    ) -> List[Dict[str, Any]]:
        """
        Crop lowest-ranked chunks so total evidence remains strictly within the token budget.
        """
        current_tokens = 0
        accepted_chunks: List[Dict[str, Any]] = []

        for chunk in ranked_chunks:
            chunk_text = str(chunk.get(text_key, ""))
            chunk_tokens = self.count_tokens(chunk_text)

            if current_tokens + chunk_tokens <= token_budget:
                accepted_chunks.append(chunk)
                current_tokens += chunk_tokens
            else:
                # Discard lowest-ranked chunk rather than cutting it in half mid-statement
                break

        return accepted_chunks

