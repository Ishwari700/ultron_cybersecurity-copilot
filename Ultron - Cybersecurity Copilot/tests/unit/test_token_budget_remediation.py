"""Regression tests for tokenizer-aware token budgeting (Finding 14 remediation)."""

import json
import pytest
from src.retrieval.budget import (
    BaseTokenizer,
    CalibratedHeuristicTokenizer,
    FastTokenizerAdapter,
    OllamaRemoteTokenizer,
    TokenBudgetController,
)


class DummyExactTokenizer(BaseTokenizer):
    """Deterministic exact test tokenizer counting whitespace-split tokens."""

    @property
    def is_exact(self) -> bool:
        return True

    def count_tokens(self, text: str) -> int:
        if not text:
            return 0
        return len(text.split())


def test_calibrated_heuristic_tokenizer_json_code_density():
    """Verify that JSON and code punctuation receive calibrated token density adjustments."""
    tokenizer = CalibratedHeuristicTokenizer(base_chars_per_token=3.5, safety_margin=1.0)

    # 101 characters of English prose
    prose = "The security analyst reviewed the application authorization logic and found an unprotected endpoint!."
    # 101 characters of dense JSON
    json_text = '{"auth":false,"headers":{"x-api-key":"abc","role":"admin"},"endpoints":["/a","/b","/c"],"status":200}'

    assert len(prose) == len(json_text)

    prose_tokens = tokenizer.count_tokens(prose)
    json_tokens = tokenizer.count_tokens(json_text)

    # JSON with high punctuation density must yield significantly higher token count
    assert json_tokens > prose_tokens
    assert tokenizer.is_exact is False


def test_calibrated_heuristic_tokenizer_unicode_overhead():
    """Verify that multibyte Unicode sequences receive appropriate token overhead weighting."""
    tokenizer = CalibratedHeuristicTokenizer(base_chars_per_token=3.5, safety_margin=1.0)

    ascii_text = "Hello world secure token"
    unicode_text = "Hello world \u3053\u3093\u306b\u3061\u306f token"  # Japanese characters

    ascii_tokens = tokenizer.count_tokens(ascii_text)
    unicode_tokens = tokenizer.count_tokens(unicode_text)

    assert unicode_tokens > ascii_tokens


def test_fast_tokenizer_adapter():
    """Verify FastTokenizerAdapter correctly extracts token counts and reports is_exact=True."""
    class MockHFTokenizer:
        def encode(self, text):
            class Encoding:
                ids = [101, 2054, 2003, 102]
            return Encoding()

    adapter = FastTokenizerAdapter(MockHFTokenizer())
    assert adapter.is_exact is True
    assert adapter.count_tokens("Arbitrary input text") == 4
    assert adapter.count_tokens("") == 0


def test_ollama_remote_tokenizer_fallback_when_offline():
    """Verify OllamaRemoteTokenizer safely falls back to calibrated heuristic when offline and reports mode."""
    # Port 65530 is closed, testing graceful fallback without unhandled exception
    tokenizer = OllamaRemoteTokenizer(
        base_url="http://127.0.0.1:65530",
        model_name="qwen2.5-coder:7b",
        timeout_seconds=0.2,
    )
    tokens = tokenizer.count_tokens("SELECT * FROM users WHERE id = 1;")
    assert tokens > 0
    # Must NOT claim exactness when offline!
    assert tokenizer.is_exact is False
    assert tokenizer.mode == "REMOTE_TOKENIZER_UNAVAILABLE"

    # TokenBudgetController must also reflect fallback mode
    controller = TokenBudgetController(tokenizer=tokenizer)
    assert controller.is_exact is False
    assert controller.token_count_mode == "REMOTE_TOKENIZER_UNAVAILABLE"


def test_ollama_remote_tokenizer_exact_when_endpoint_available(monkeypatch):
    """Verify OllamaRemoteTokenizer reports is_exact=True and EXACT_TOKENIZER when remote responds."""
    import io
    import urllib.request

    class MockResponse:
        def __init__(self, data: bytes):
            self._data = data
        def read(self):
            return self._data
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass

    def mock_urlopen(req, timeout=None):
        return MockResponse(json.dumps({"tokens": [101, 2054, 2003, 1037, 3231, 102]}).encode("utf-8"))

    monkeypatch.setattr("src.retrieval.budget.urllib.request.urlopen", mock_urlopen)

    tokenizer = OllamaRemoteTokenizer(base_url="http://mock-ollama:11434")
    count = tokenizer.count_tokens("This is a test prompt")
    assert tokenizer._last_error is None, f"Failed with: {tokenizer._last_error}"
    assert count == 6
    assert tokenizer.is_exact is True
    assert tokenizer.mode == "EXACT_TOKENIZER"

    controller = TokenBudgetController(tokenizer=tokenizer)
    assert controller.is_exact is True
    assert controller.token_count_mode == "EXACT_TOKENIZER"


def test_ollama_remote_tokenizer_http_404_activates_fallback(monkeypatch):
    """Verify HTTP 404 on /api/tokenize activates heuristic fallback and reports REMOTE_TOKENIZER_UNAVAILABLE."""
    import urllib.error
    import urllib.request

    def mock_urlopen_404(req, timeout=None):
        raise urllib.error.HTTPError(
            url=req.full_url,
            code=404,
            msg="Not Found",
            hdrs={},
            fp=None,
        )

    monkeypatch.setattr("src.retrieval.budget.urllib.request.urlopen", mock_urlopen_404)

    tokenizer = OllamaRemoteTokenizer(base_url="http://mock-ollama:11434")
    # Query code payload
    count = tokenizer.count_tokens("def authenticate(user, token): return True")
    assert count > 0
    # Must accurately report fallback
    assert tokenizer.is_exact is False
    assert tokenizer.mode == "REMOTE_TOKENIZER_UNAVAILABLE"

    controller = TokenBudgetController(tokenizer=tokenizer)
    assert controller.is_exact is False
    assert controller.token_count_mode == "REMOTE_TOKENIZER_UNAVAILABLE"


def test_ollama_remote_tokenizer_timeout_and_malformed_response(monkeypatch):
    """Verify timeouts and malformed JSON payloads fail safely to fallback."""
    import urllib.request

    tokenizer = OllamaRemoteTokenizer(base_url="http://mock-ollama:11434")

    # 1. Timeout
    def mock_urlopen_timeout(req, timeout=None):
        raise TimeoutError("Connection timed out")

    monkeypatch.setattr("src.retrieval.budget.urllib.request.urlopen", mock_urlopen_timeout)
    tokens_timeout = tokenizer.count_tokens("timeout test")
    assert tokens_timeout > 0
    assert tokenizer.is_exact is False
    assert tokenizer.mode == "REMOTE_TOKENIZER_UNAVAILABLE"

    # 2. Malformed JSON (missing 'tokens' key)
    class MockMalformedResponse:
        def read(self):
            return b'{"error": "model not loaded"}'
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass

    def mock_urlopen_malformed(req, timeout=None):
        return MockMalformedResponse()

    monkeypatch.setattr("src.retrieval.budget.urllib.request.urlopen", mock_urlopen_malformed)
    tokens_malformed = tokenizer.count_tokens("malformed test")
    assert tokens_malformed > 0
    assert tokenizer.is_exact is False
    assert tokenizer.mode == "REMOTE_TOKENIZER_UNAVAILABLE"


def test_budget_enforcement_using_fallback_estimate():
    """Verify conservative budget calculation and evidence cropping using fallback estimate."""
    fallback_tok = CalibratedHeuristicTokenizer(base_chars_per_token=3.5, safety_margin=1.1)
    controller = TokenBudgetController(tokenizer=fallback_tok)

    # Budget calculation: 2048 ctx - 400 prompt - 200 schema - 500 max_out - 150 headroom = 798 tokens
    budget = controller.calculate_evidence_budget(
        num_ctx=2048,
        system_prompt="You are a vulnerability analyst." * 10,
        schema_definition='{"type": "object"}' * 10,
        max_output_tokens=500,
        safety_headroom_tokens=150,
    )
    assert budget > 0

    chunks = [
        {"statement": "Evidence item 1: " + "A" * 100},
        {"statement": "Evidence item 2: " + "B" * 200},
        {"statement": "Evidence item 3: " + "C" * 3000},  # Very large chunk
    ]
    cropped = controller.crop_chunks_to_budget(chunks, token_budget=budget)
    assert len(cropped) >= 1
    # Total accepted tokens must not exceed budget
    total_tokens = sum(controller.count_tokens(c["statement"]) for c in cropped)
    assert total_tokens <= budget


def test_budget_controller_modes_and_caching():
    """Verify TokenBudgetController correctly tracks mode and caches frequent string counts."""
    # 1. Exact mode
    exact_tok = DummyExactTokenizer()
    controller_exact = TokenBudgetController(tokenizer=exact_tok)
    assert controller_exact.is_exact is True
    assert controller_exact.token_count_mode == "EXACT_TOKENIZER"

    # Count tokens
    assert controller_exact.count_tokens("one two three four") == 4
    # Cache hit
    assert controller_exact.count_tokens("one two three four") == 4

    # 2. Calibrated Heuristic mode
    controller_calibrated = TokenBudgetController(tokenizer=CalibratedHeuristicTokenizer())
    assert controller_calibrated.is_exact is False
    assert controller_calibrated.token_count_mode == "CALIBRATED_HEURISTIC"

    # 3. Default Char Heuristic mode (backward compatibility)
    controller_char = TokenBudgetController()
    assert controller_char.is_exact is False
    assert controller_char.token_count_mode == "CHAR_HEURISTIC"


def test_budget_controller_cropping_with_exact_tokenizer():
    """Verify deterministic cropping with an exact tokenizer."""
    exact_tok = DummyExactTokenizer()
    controller = TokenBudgetController(tokenizer=exact_tok)

    chunks = [
        {"statement": "word " * 10},  # 10 tokens
        {"statement": "word " * 20},  # 20 tokens
        {"statement": "word " * 30},  # 30 tokens
    ]

    # Budget 35 tokens -> chunk 1 (10) + chunk 2 (20) = 30 <= 35; chunk 3 (30) doesn't fit
    cropped = controller.crop_chunks_to_budget(chunks, token_budget=35)
    assert len(cropped) == 2
    assert cropped[0]["statement"] == "word " * 10
    assert cropped[1]["statement"] == "word " * 20

